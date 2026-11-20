use super::{JavaScript, Package, PeerError, Result, protocol};
use crate::Hash;
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
use std::{
    collections::BTreeMap,
    io,
    path::Path,
    process::{Command, Stdio},
    rc::Rc,
    time::{Duration, Instant},
};
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

fn js_error(err: impl std::fmt::Display) -> PeerError {
    PeerError::Guest(err.to_string())
}

#[derive(Serialize, Deserialize)]
pub(super) struct Work {
    pub program: Hash,
    pub code: Package,
    pub state: String,
    pub input: String,
}

pub(super) fn run(path: &Path, work: Work) -> Result<String> {
    let mut child = Command::new(path)
        .args(["__worker", &std::process::id().to_string()])
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let reply = (|| {
        protocol::send(&mut child.stdin.take().unwrap(), &work)?;
        let reply = protocol::receive::<std::result::Result<String, String>>(
            &mut child.stdout.take().unwrap(),
        )?;
        reply.map_err(PeerError::Guest)
    })();
    let _ = child.kill();
    child.wait()?;
    reply
}

pub fn main(parent: u32) -> Result<()> {
    // Arm the hard deadline before seccomp. SIGALRM also covers blocked guest jobs.
    unsafe {
        libc::alarm(4);
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
            || libc::getppid() as u32 != parent
        {
            return Err(PeerError::Invalid("worker parent unavailable"));
        }
    }
    isolate()?;
    let work = protocol::receive(&mut io::stdin().lock())?;
    let reply = execute(work).map_err(|err| {
        let mut message = err.to_string();
        message.truncate(message.floor_char_boundary(2048));
        message
    });
    protocol::send(&mut io::stdout().lock(), &reply)?;
    Ok(())
}

fn execute(work: Work) -> Result<String> {
    let mut modules = BTreeMap::new();
    for (hash, bytes) in work.code {
        if hash != Hash::digest(&bytes) {
            return Err(PeerError::Invalid("module hash mismatch"));
        }
        modules.insert(format!("pp2:{hash}"), JavaScript::from_bytes(&bytes)?);
    }
    let root = format!("pp2:{}", work.program);
    let modules = Rc::new(modules);
    let source = &modules
        .get(&root)
        .ok_or(PeerError::Invalid("missing entry module"))?
        .source;
    let runtime = Runtime::new().map_err(js_error)?;
    runtime.set_memory_limit(32 * 1024 * 1024);
    runtime.set_max_stack_size(512 * 1024);
    let deadline = Instant::now() + Duration::from_secs(2);
    runtime.set_interrupt_handler(Some(Box::new(move || Instant::now() >= deadline)));
    runtime.set_loader(Manifest(modules.clone()), Manifest(modules.clone()));
    let context = Context::full(&runtime).map_err(js_error)?;
    context.with(|ctx| {
        let invoke = || -> rquickjs::Result<String> {
            ctx.eval::<(), _>(
                r#"
                for (const key of ['Date', 'Temporal', 'performance', 'SharedArrayBuffer',
                                    'Atomics', 'WeakRef', 'FinalizationRegistry']) {
                    delete globalThis[key];
                }
                delete Math.random;
            "#,
            )?;
            let state = ctx.json_parse(work.state)?;
            let input = ctx.json_parse(work.input)?;
            let (module, loaded) = Module::declare(ctx.clone(), root, source.as_bytes())?.eval()?;
            loaded.finish::<()>()?;
            let entry: Function = module.get("default")?;
            let value: Value = entry.call((state, input))?;
            let result = match value.as_promise() {
                Some(promise) => promise.finish::<Value>()?,
                None => value,
            };
            ctx.json_stringify(result)?
                .ok_or(rquickjs::Error::Unknown)?
                .to_string()
        };
        let result = invoke().catch(&ctx).map_err(js_error)?;
        if result.len() > super::content::MAX_BYTES {
            return Err(PeerError::Limit("result bytes"));
        }
        Ok(result)
    })
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
