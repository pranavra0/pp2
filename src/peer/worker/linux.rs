use std::{
    collections::{BTreeMap, btree_map::Entry},
    io,
    path::Path,
    process::{Command, Stdio},
    rc::Rc,
    sync::mpsc::{self, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use rquickjs::{
    CatchResultExt, Context, Ctx, Function, Module, Runtime, Value,
    loader::{ImportAttributes, Loader, Resolver},
    module::Declared,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};
use serde::{Deserialize, Serialize};

use crate::{
    Block, Cluster, Data, Grant, Hash, Limits, LocalityPolicy, StoreAccess, capability::Authority,
};

use super::{Output, PeerError, Result, Work};
use crate::peer::{
    content::{self, JavaScript, Kind, MAX_CODE, MAX_MODULES},
    protocol::{self, Metrics},
};

const WORKER_DEADLINE: Duration = Duration::from_secs(3);
const GUEST_DEADLINE: Duration = Duration::from_secs(2);
const JS_MEMORY: usize = 32 * 1024 * 1024;
const MAX_DIAGNOSTIC: usize = 2048;

#[derive(Serialize, Deserialize)]
enum WorkerReply {
    Complete(Vec<u8>, Metrics),
    Failed(String),
    Timeout,
}

pub(super) fn run(path: &Path, work: Work, check: impl Fn() -> Result<()>) -> Result<Output> {
    let started = Instant::now();
    let mut child = Command::new(path)
        .arg("__worker")
        .arg(std::process::id().to_string())
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut to = child.stdin.take().expect("stdin is piped");
    let mut from = child.stdout.take().expect("stdout is piped");
    thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker_io = thread::Builder::new().spawn_scoped(scope, move || {
            let result = protocol::send(&mut to, &work).and_then(|_| {
                drop(to);
                protocol::receive::<WorkerReply>(&mut from).map(|(reply, _)| reply)
            });
            let _ = sender.send(result);
        });
        let result = (|| {
            worker_io?;
            loop {
                check()?;
                let time = WORKER_DEADLINE
                    .checked_sub(started.elapsed())
                    .ok_or(PeerError::Timeout)?;
                match receiver.recv_timeout(time.min(Duration::from_millis(25))) {
                    Ok(reply) => return reply.map_err(|_| worker_exit()),
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => return Err(worker_exit()),
                }
            }
        })();
        // Reap even when pipe I/O or thread creation fails. The worker cannot spawn descendants.
        let _ = child.kill();
        child.wait()?;
        match result? {
            WorkerReply::Complete(value, metrics) => Ok(Output { value, metrics }),
            WorkerReply::Failed(message) => Err(PeerError::Guest(message)),
            WorkerReply::Timeout => Err(PeerError::Timeout),
        }
    })
}

fn worker_exit() -> PeerError {
    PeerError::Guest("worker exited without a result".into())
}

pub(super) fn main(parent: u32) -> Result<()> {
    // SAFETY: prctl takes integer arguments for this option.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: getppid takes no arguments. Check after installing the signal for startup races.
    if unsafe { libc::getppid() } as u32 != parent {
        return Err(PeerError::Cancelled);
    }
    isolate()?;
    let (work, _) = protocol::receive(&mut io::stdin().lock())?;
    let reply = match evaluate(work) {
        Ok(Output { value, metrics }) => WorkerReply::Complete(value, metrics),
        Err(PeerError::Timeout | PeerError::Runtime(crate::Error::Timeout)) => WorkerReply::Timeout,
        Err(error) => {
            let mut message = error.to_string();
            message.truncate(message.floor_char_boundary(MAX_DIAGNOSTIC));
            WorkerReply::Failed(message)
        }
    };
    protocol::send(&mut io::stdout().lock(), &reply)?;
    Ok(())
}

fn isolate() -> Result<()> {
    fn limit(resource: libc::__rlimit_resource_t, maximum: libc::rlim_t) -> io::Result<()> {
        let limit = libc::rlimit {
            rlim_cur: maximum,
            rlim_max: maximum,
        };
        // SAFETY: the kernel copies this initialized struct synchronously.
        if unsafe { libc::setrlimit(resource, &limit) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    // SAFETY: this subprocess is single-threaded and its only intended descriptors are 0–2.
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: prctl takes integer arguments here. Disable same-UID process inspection and dumps.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    limit(libc::RLIMIT_CORE, 0)?;
    limit(libc::RLIMIT_AS, 256 * 1024 * 1024)?;
    limit(libc::RLIMIT_CPU, 3)?;
    limit(libc::RLIMIT_FSIZE, 0)?;

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = [
        libc::SYS_brk,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_futex,
        libc::SYS_clock_gettime,
        libc::SYS_gettimeofday,
        libc::SYS_getrandom,
        libc::SYS_rt_sigreturn,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ]
    .into_iter()
    .map(|number| (number, Vec::new()))
    .collect();
    let masked = |index, mask, value| {
        SeccompCondition::new(
            index,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(mask),
            value,
        )
    };
    let fd = |number| SeccompCondition::new(0, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, number);
    let map_error = |err: seccompiler::BackendError| PeerError::Guest(err.to_string());
    rules.insert(
        libc::SYS_read,
        vec![SeccompRule::new(vec![fd(0).map_err(map_error)?]).map_err(map_error)?],
    );
    rules.insert(
        libc::SYS_write,
        vec![SeccompRule::new(vec![fd(1).map_err(map_error)?]).map_err(map_error)?],
    );
    let non_exec = masked(2, libc::PROT_EXEC as u64, 0).map_err(map_error)?;
    let anonymous =
        masked(3, libc::MAP_ANONYMOUS as u64, libc::MAP_ANONYMOUS as u64).map_err(map_error)?;
    rules.insert(
        libc::SYS_mmap,
        vec![SeccompRule::new(vec![non_exec.clone(), anonymous]).map_err(map_error)?],
    );
    rules.insert(
        libc::SYS_mprotect,
        vec![SeccompRule::new(vec![non_exec]).map_err(map_error)?],
    );
    let arch = std::env::consts::ARCH.try_into().map_err(map_error)?;
    let filter: BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        arch,
    )
    .map_err(map_error)?
    .try_into()
    .map_err(map_error)?;
    seccompiler::apply_filter(&filter).map_err(|err| PeerError::Guest(err.to_string()))?;
    Ok(())
}

fn evaluate(mut work: Work) -> Result<Output> {
    let started = Instant::now();
    if work.code.len() > MAX_MODULES
        || work.code.iter().map(|(_, x)| x.len()).sum::<usize>() > MAX_CODE
    {
        return Err(PeerError::Limit("module graph"));
    }
    let (state_kind, _) = content::inspect(work.state_hash, &work.state)?;
    if state_kind != Kind::Data {
        return Err(PeerError::Value("expected state data".into()));
    }
    let at = work
        .code
        .iter()
        .position(|(hash, _)| *hash == work.program)
        .ok_or(PeerError::Missing(work.program))?;
    let (_, root) = work.code.swap_remove(at);
    let (value, fuel, memory) = match content::inspect(work.program, &root)?.0 {
        Kind::Data => return Err(PeerError::Value("expected program".into())),
        Kind::Aeb => {
            if !work.code.is_empty() || Data::from_bytes(&work.input)? != Data::Nil {
                return Err(PeerError::Value(
                    "binary programs use captures and a store grant".into(),
                ));
            }
            let mut local = Cluster::new();
            let node = local.add_node()?;
            local.import(node, work.program, root)?;
            local.import(node, work.state_hash, work.state)?;
            let grant = Grant::new(
                &local.issuer,
                node,
                Authority::Store {
                    roots: [work.state_hash].into_iter().collect(),
                    access: StoreAccess::Read,
                },
            );
            let limits = Limits::default();
            let report = local.run(
                node,
                work.program,
                &[grant],
                limits,
                LocalityPolicy::default(),
            )?;
            (
                report.value,
                Some(report.fuel_used),
                report.allocated_bytes as u64,
            )
        }
        Kind::JavaScript => evaluate_javascript(work, &root, started)?,
    };
    Ok(Output {
        value: value.to_bytes()?,
        metrics: Metrics {
            fuel,
            memory,
            elapsed_ms: protocol::elapsed_ms(started),
        },
    })
}

type Modules = Rc<BTreeMap<String, JavaScript>>;

struct Manifest(Modules);

impl Resolver for Manifest {
    fn resolve<'js>(
        &mut self,
        _: &Ctx<'js>,
        base: &str,
        name: &str,
        attributes: Option<ImportAttributes<'js>>,
    ) -> rquickjs::Result<String> {
        let allowed = attributes.is_none()
            && self.0.get(base).is_some_and(|module| {
                name.strip_prefix("pp2:")
                    .and_then(|hex| hex.parse::<Hash>().ok())
                    .is_some_and(|hash| module.imports.contains(&hash) && self.0.contains_key(name))
            });
        if allowed {
            Ok(name.to_owned())
        } else {
            Err(rquickjs::Error::new_resolving(base, name))
        }
    }
}

impl Loader for Manifest {
    fn load<'js>(
        &mut self,
        ctx: &Ctx<'js>,
        name: &str,
        _: Option<ImportAttributes<'js>>,
    ) -> rquickjs::Result<Module<'js, Declared>> {
        let module = self
            .0
            .get(name)
            .ok_or_else(|| rquickjs::Error::new_loading(name))?;
        Module::declare(ctx.clone(), name, module.source.as_bytes())
    }
}

fn evaluate_javascript(
    work: Work,
    root: &[u8],
    started: Instant,
) -> Result<(Data, Option<u64>, u64)> {
    let mut modules = BTreeMap::new();
    let root_name = format!("pp2:{}", work.program);
    modules.insert(root_name.clone(), JavaScript::from_bytes(root)?);
    for (hash, bytes) in work.code {
        if content::inspect(hash, &bytes)?.0 != Kind::JavaScript {
            return Err(PeerError::Value("expected JavaScript dependency".into()));
        }
        let Entry::Vacant(entry) = modules.entry(format!("pp2:{hash}")) else {
            return Err(PeerError::Value("duplicate module".into()));
        };
        entry.insert(JavaScript::from_bytes(&bytes)?);
    }
    let modules = Rc::new(modules);
    let Block::Data(state) = Block::from_bytes(&work.state)? else {
        unreachable!("state kind was verified")
    };
    let input = Data::from_bytes(&work.input)?;
    let state = content::data_to_json(&state)?.to_string();
    let input = content::data_to_json(&input)?.to_string();
    let runtime = Runtime::new().map_err(js_error)?;
    runtime.set_memory_limit(JS_MEMORY);
    runtime.set_max_stack_size(512 * 1024);
    runtime.set_interrupt_handler(Some(Box::new(move || started.elapsed() >= GUEST_DEADLINE)));
    runtime.set_loader(Manifest(modules.clone()), Manifest(modules.clone()));
    let context = Context::full(&runtime).map_err(js_error)?;
    let bytes = context.with(|ctx| {
        let invoke = || -> rquickjs::Result<String> {
            let replacer: Function = ctx.eval(r#"(() => {
                'use strict';
                for (const key of ['Date', 'Temporal', 'performance', 'SharedArrayBuffer', 'Atomics', 'WeakRef', 'FinalizationRegistry']) delete globalThis[key];
                delete Math.random;
                const safeInteger = Number.isSafeInteger, Type = TypeError;
                return (_, value) => {
                    switch (typeof value) {
                        case 'object': case 'string': case 'boolean': return value;
                        case 'number': if (safeInteger(value)) return value;
                    }
                    throw new Type('results must consist of JSON data and safe integers');
                };
            })()"#)?;
            let (module, loaded) = Module::declare(ctx.clone(), root_name.as_str(), modules[&root_name].source.as_bytes())?.eval()?;
            loaded.finish::<()>()?;
            let entry: Function = module.get("default")?;
            let result: Value = entry.call((ctx.json_parse(state.as_bytes())?, ctx.json_parse(input.as_bytes())?))?;
            let result = match result.as_promise() {
                Some(promise) => promise.finish::<Value>()?,
                None => result,
            };
            ctx.json_stringify_replacer(result, replacer)?.ok_or(rquickjs::Error::Unknown)?.to_string()
        };
        invoke().catch(&ctx).map_err(js_error)
    });
    if started.elapsed() >= GUEST_DEADLINE {
        return Err(PeerError::Timeout);
    }
    let bytes = bytes?;
    if bytes.len() > Block::MAX_BYTES {
        return Err(PeerError::Limit("JSON result bytes"));
    }
    let json = serde_json::from_str(&bytes).map_err(|err| PeerError::Value(err.to_string()))?;
    let value = content::data_from_json(json)?;
    Ok((
        value,
        None,
        runtime.memory_usage().malloc_size.max(0) as u64,
    ))
}

fn js_error(err: impl std::fmt::Display) -> PeerError {
    PeerError::Guest(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn operating_system_denies_files_and_sockets() {
        const PROBE: &str = "PP2_SANDBOX_SYSCALL_TEST";
        match std::env::var(PROBE).as_deref() {
            Ok("file") => {
                isolate().unwrap();
                let _ = std::fs::File::open("/etc/hostname");
                std::process::exit(0);
            }
            Ok("socket") => {
                isolate().unwrap();
                let _ = std::net::TcpListener::bind("127.0.0.1:0");
                std::process::exit(0);
            }
            _ => {}
        }
        for probe in ["file", "socket"] {
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    concat!(
                        module_path!(),
                        "::operating_system_denies_files_and_sockets"
                    )
                    .trim_start_matches("pp2::"),
                ])
                .env(PROBE, probe)
                .stdout(Stdio::null())
                .status()
                .unwrap();
            assert_eq!(status.signal(), Some(libc::SIGSYS), "{probe}");
        }
    }
}
