use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufRead, BufReader},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

use pp2::{
    Data, Hash,
    peer::{
        Access, Binding, BindingSet, Client, Credentials, DiscoveryConfig, Evaluation,
        EvaluationMode, GraphBudget, GraphEvaluation, JavaScript, PeerEndpoint, PeerError,
        PeerIdentity, PeerNetwork, PeerStore, Server, compile_typescript, data_from_json,
    },
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const USAGE: &str = "Usage: pp2 app <command>
  native <command>
  install DB PEER_ID|PEER_CERT SUBSCRIPTIONS_JSON
  status DB APPLICATION
  unsubscribe DB APPLICATION SUBSCRIPTION
  remove DB APPLICATION
  init MANIFEST DIRECTORY [--discovery]
  run DIRECTORY [INPUT_JSON]
  serve PEER_DIRECTORY [BIND]
  invoke CLIENT_DIRECTORY [INPUT_JSON]";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    root: Root,
    peers: BTreeMap<String, PeerSpec>,
    modules: BTreeMap<String, ModuleSpec>,
    budget: GraphBudget,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerSpec {
    address: Option<SocketAddr>,
    #[serde(default)]
    collections: BTreeMap<String, Option<PathBuf>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ModuleSpec {
    source: PathBuf,
    #[serde(default)]
    imports: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    peer: String,
    collection: String,
    module: String,
    capabilities: BTreeMap<String, Target>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    peer: String,
    collection: String,
    module: String,
    #[serde(default)]
    write: bool,
}

#[derive(Serialize, Deserialize)]
struct Deployment {
    root: String,
    peers: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct PeerProfile {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    stable: bool,
    peer: String,
    address: Option<SocketAddr>,
    routes: BTreeMap<String, Route>,
    holder: Option<Hash>,
    grant: Option<Hash>,
    program: Option<Hash>,
    directory: BTreeMap<String, PeerIdentityEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PeerIdentityEntry {
    address: Option<SocketAddr>,
    fingerprint: Hash,
}

#[derive(Serialize, Deserialize)]
struct Route {
    peer: String,
    grant: Hash,
    program: Hash,
    access: Access,
}

#[derive(Serialize, Deserialize)]
struct ClientProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_id: Option<Hash>,
    root: String,
    address: Option<SocketAddr>,
    grant: Hash,
    program: Hash,
    budget: GraphBudget,
    capabilities: Vec<String>,
}

pub fn run(args: &[std::ffi::OsString]) -> Result<()> {
    let args: Vec<_> = args
        .iter()
        .map(|arg| arg.to_str().ok_or(USAGE))
        .collect::<std::result::Result<_, _>>()?;
    match args.as_slice() {
        [] | ["--help" | "-h"] => println!("{USAGE}"),
        ["native", commands @ ..] => crate::native_cli::run(commands)?,
        ["install", db, cert, manifest] => PeerStore::open(db)?
            .install_application(holder_id(cert)?, read_json(Path::new(manifest))?)?,
        ["status", db, application] => {
            let status = PeerStore::open(db)?.application_status(application)?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        ["unsubscribe", db, application, subscription] => {
            PeerStore::open(db)?.revoke_subscription(application, subscription)?;
        }
        ["remove", db, application] => {
            let mut store = PeerStore::open(db)?;
            store.remove_application(application)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&store.application_status(application)?)?
            );
        }
        ["init", manifest, directory, flags @ ..] if matches!(flags, [] | ["--discovery"]) => {
            init(Path::new(manifest), Path::new(directory), !flags.is_empty())?;
        }
        ["run", directory, rest @ ..] if rest.len() <= 1 => {
            run_local(Path::new(directory), rest.first().copied())?;
        }
        ["serve", directory, bind @ ..] if bind.len() <= 1 => serve(
            Path::new(directory),
            false,
            BTreeMap::new(),
            bind.first().map(|bind| bind.parse()).transpose()?,
        )?,
        ["invoke", directory, rest @ ..] if rest.len() <= 1 => {
            invoke(Path::new(directory), rest.first().copied(), None)?;
        }
        ["__serve", directory, addresses, parent] => {
            local_lifetime(parent.parse()?)?;
            serve(
                Path::new(directory),
                true,
                serde_json::from_str(addresses)?,
                None,
            )?;
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn local_lifetime(parent: u32) -> Result<()> {
    // SAFETY: prctl takes integer arguments for this option and getppid takes none.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { libc::getppid() } as u32 != parent {
        return Err("application launcher exited".into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn local_lifetime(_: u32) -> Result<()> {
    Err("peer server requires Linux".into())
}

fn init(path: &Path, directory: &Path, stable: bool) -> Result<()> {
    let manifest: Manifest = read_json(path)?;
    let sources = path.parent().unwrap_or(Path::new("."));
    let mut addresses = BTreeSet::new();
    for (peer, spec) in &manifest.peers {
        if peer.len() > 32
            || peer.is_empty()
            || !peer.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || peer == "client"
            || peer == "admin"
        {
            return Err(format!("invalid peer name {peer:?}").into());
        }
        if let Some(address) = spec.address
            && (address.port() == 0 || address.ip().is_unspecified() || !addresses.insert(address))
        {
            return Err(format!("expected a unique reachable peer endpoint for {peer}").into());
        }
    }
    let Manifest {
        root,
        peers,
        modules,
        budget,
    } = manifest;
    budget.validate()?;
    let mut packaged = BTreeMap::new();
    let mut pending = BTreeSet::new();
    for module in modules.keys() {
        package(module, &modules, sources, &mut pending, &mut packaged)?;
    }
    for (peer, collection, module) in std::iter::once((&root.peer, &root.collection, &root.module))
        .chain(
            root.capabilities
                .values()
                .map(|target| (&target.peer, &target.collection, &target.module)),
        )
    {
        if peers
            .get(peer)
            .is_none_or(|spec| !spec.collections.contains_key(collection))
            || !packaged.contains_key(module)
        {
            return Err(format!(
                "unknown peer, collection or module for {peer}/{collection}/{module}"
            )
            .into());
        }
    }
    pp2::peer::validate_binding_names(&root.capabilities.keys().cloned().collect::<Vec<_>>())?;

    private_dir(directory)?;
    let result = (|| -> Result<()> {
        let admin = directory.join("admin");
        if !stable {
            private_dir(&admin)?;
            self_signed_certificate(&admin, "/CN=pp2-development", "ca.key", "ca.pem")?;
        }
        let client_dir = directory.join("client");
        private_dir(&client_dir)?;
        let holder = if stable {
            PeerIdentity::generate(client_dir.join("identity.key"))?
        } else {
            certificate(&admin, &client_dir, "client", false)?;
            Credentials::fingerprint(client_dir.join("peer.pem"))?
        };
        let mut directory_entries = BTreeMap::new();
        for (peer, spec) in &peers {
            let dir = directory.join(peer);
            let fingerprint = if stable {
                node_init(&dir)?
            } else {
                private_dir(&dir)?;
                certificate(&admin, &dir, peer, true)?;
                Credentials::fingerprint(dir.join("peer.pem"))?
            };
            directory_entries.insert(
                peer.clone(),
                PeerIdentityEntry {
                    address: spec.address,
                    fingerprint,
                },
            );
        }
        let executor = directory_entries[&root.peer].fingerprint;
        for (peer, spec) in &peers {
            let mut store = PeerStore::open(directory.join(peer).join("peer.db"))?;
            for (collection, file) in &spec.collections {
                let file = file
                    .as_ref()
                    .map(|path| File::open(sources.join(path)))
                    .transpose()?;
                seed(&mut store, collection, file)?;
            }
            let mut required = BTreeSet::new();
            if peer == &root.peer {
                required.extend(modules.keys());
            } else {
                let mut pending: Vec<_> = root
                    .capabilities
                    .values()
                    .filter(|target| &target.peer == peer)
                    .map(|target| &target.module)
                    .collect();
                while let Some(name) = pending.pop() {
                    if required.insert(name) {
                        pending.extend(modules[name].imports.values());
                    }
                }
            }
            for name in &required {
                let (hash, bytes) = &packaged[*name];
                store.import(*hash, bytes)?;
            }
            for name in required {
                let hash = packaged[name].0;
                Client::fetch_program(&mut store, &[], hash)?;
                store.publish(hash)?;
            }
        }
        let mut store = PeerStore::open(directory.join(&root.peer).join("peer.db"))?;
        let program = packaged[&root.module].0;
        let grant = store.issue(&root.collection, holder, Access::Read, Some(program))?;
        let mut routes = BTreeMap::new();
        for (name, target) in root.capabilities {
            let program = packaged[&target.module].0;
            let access = if target.write {
                Access::Write
            } else {
                Access::Read
            };
            let grant = PeerStore::open(directory.join(&target.peer).join("peer.db"))?.issue(
                &target.collection,
                executor,
                access,
                Some(program),
            )?;
            routes.insert(
                name,
                Route {
                    peer: target.peer,
                    grant,
                    program,
                    access,
                },
            );
        }
        write_json(
            &client_dir.join("profile.json"),
            &ClientProfile {
                root_id: stable.then_some(executor),
                root: root.peer.clone(),
                address: peers[&root.peer].address,
                grant,
                program,
                budget,
                capabilities: routes.keys().cloned().collect(),
            },
        )?;
        for (peer, spec) in &peers {
            let is_root = root.peer == *peer;
            write_json(
                &directory.join(peer).join("profile.json"),
                &PeerProfile {
                    stable,
                    peer: peer.clone(),
                    address: spec.address,
                    routes: if is_root {
                        std::mem::take(&mut routes)
                    } else {
                        BTreeMap::new()
                    },
                    holder: is_root.then_some(holder),
                    grant: is_root.then_some(grant),
                    program: is_root.then_some(program),
                    directory: directory_entries.clone(),
                },
            )?;
        }
        write_json(
            &directory.join("deployment.json"),
            &Deployment {
                root: root.peer,
                peers: peers.into_keys().collect(),
            },
        )
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(directory);
    }
    result?;
    println!("{}", directory.display());
    Ok(())
}

pub(crate) fn package(
    name: &str,
    modules: &BTreeMap<String, ModuleSpec>,
    source_dir: &Path,
    pending: &mut BTreeSet<String>,
    done: &mut BTreeMap<String, (Hash, Vec<u8>)>,
) -> Result<Hash> {
    if let Some((hash, _)) = done.get(name) {
        return Ok(*hash);
    }
    let module = modules
        .get(name)
        .ok_or_else(|| format!("unknown module {name:?}"))?;
    if pending.len() >= 32 || !pending.insert(name.to_owned()) {
        return Err("application module graph is too deep or cyclic".into());
    }
    let mut aliases = BTreeMap::new();
    for (alias, dependency) in &module.imports {
        aliases.insert(
            alias.clone(),
            package(dependency, modules, source_dir, pending, done)?,
        );
    }
    let path = source_dir.join(&module.source);
    let typescript = matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("ts" | "mts")
    );
    let source = if typescript {
        compile_typescript(&path, &aliases)?
    } else {
        if !aliases.is_empty() {
            return Err("application import aliases require TypeScript modules".into());
        }
        fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?
    };
    let bytes = JavaScript {
        source,
        imports: aliases.into_values().collect(),
    }
    .to_bytes()?;
    let hash = Hash::digest(&bytes);
    done.insert(name.to_owned(), (hash, bytes));
    pending.remove(name);
    Ok(hash)
}

pub(crate) fn seed(store: &mut PeerStore, name: &str, file: Option<File>) -> Result<()> {
    let entries = file
        .into_iter()
        .flat_map(|file| BufReader::new(file).lines())
        .map(|line| {
            let (key, json): (String, serde_json::Value) =
                serde_json::from_str(&line?).map_err(|err| PeerError::Value(err.to_string()))?;
            Ok((key, data_from_json(json)?))
        });
    store.create_collection(name, entries)?;
    Ok(())
}

#[cfg(unix)]
fn private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn private_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)
}

fn certificate(admin: &Path, directory: &Path, name: &str, is_peer: bool) -> Result<()> {
    let admin = admin.canonicalize()?;
    fs::copy(admin.join("ca.pem"), directory.join("ca.pem"))?;
    openssl(Command::new("openssl").current_dir(directory).args([
        "req",
        "-new",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-subj",
        &format!("/CN=pp2-{name}"),
        "-keyout",
        "peer.key",
        "-out",
        "request.csr",
    ]))?;
    let usage = if is_peer {
        format!("extendedKeyUsage=clientAuth,serverAuth\nsubjectAltName=DNS:pp2-{name}\n")
    } else {
        "extendedKeyUsage=clientAuth\n".into()
    };
    fs::write(directory.join("usage.ext"), usage)?;
    openssl(
        Command::new("openssl")
            .current_dir(directory)
            .args(["x509", "-req", "-in", "request.csr", "-CA"])
            .arg(admin.join("ca.pem"))
            .arg("-CAkey")
            .arg(admin.join("ca.key"))
            .args([
                "-CAcreateserial",
                "-days",
                "30",
                "-extfile",
                "usage.ext",
                "-out",
                "peer.pem",
            ]),
    )?;
    fs::remove_file(directory.join("request.csr"))?;
    fs::remove_file(directory.join("usage.ext"))?;
    Ok(())
}

fn self_signed_certificate(dir: &Path, subject: &str, key: &str, cert: &str) -> Result<()> {
    openssl(Command::new("openssl").current_dir(dir).args([
        "req",
        "-new",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-days",
        "30",
        "-subj",
        subject,
        "-keyout",
        key,
        "-out",
        cert,
    ]))
}

fn openssl(command: &mut Command) -> Result<()> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!(
            "OpenSSL: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(())
}

pub(crate) fn node_init(dir: &Path) -> Result<Hash> {
    private_dir(dir)?;
    let result = (|| -> Result<Hash> {
        let id = PeerIdentity::generate(dir.join("identity.key"))?;
        self_signed_certificate(dir, "/CN=pp2-transport", "peer.key", "peer.pem")?;
        Ok(id)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(dir);
    }
    result
}

pub(crate) fn holder_id(holder: &str) -> Result<Hash> {
    if let Ok(id) = holder.parse() {
        Ok(id)
    } else {
        Ok(Credentials::fingerprint(holder)?)
    }
}

pub(crate) fn network(dir: &Path) -> Result<PeerNetwork> {
    let settings: DiscoveryConfig = match File::open(dir.join("discovery.json")) {
        Ok(file) => read_document(file)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => DiscoveryConfig::default(),
        Err(error) => return Err(error.into()),
    };
    Ok(PeerNetwork::new(
        PeerIdentity::load(dir.join("identity.key"))?,
        settings,
    )?)
}

pub(crate) fn credentials(dir: &Path) -> Credentials {
    Credentials {
        ca: dir.join("ca.pem"),
        certificate: dir.join("peer.pem"),
        key: dir.join("peer.key"),
    }
}

fn serve(
    dir: &Path,
    local: bool,
    mut addresses: BTreeMap<String, SocketAddr>,
    bind: Option<SocketAddr>,
) -> Result<()> {
    let profile: PeerProfile = read_json(&dir.join("profile.json"))?;
    let bind = if local {
        addresses
            .get(&profile.peer)
            .copied()
            .unwrap_or("127.0.0.1:0".parse()?)
    } else if let Some(bind) = bind.or(profile.address) {
        bind
    } else if profile.stable {
        "0.0.0.0:0".parse()?
    } else {
        return Err("missing deployment address".into());
    };
    let listener = TcpListener::bind(bind)?;
    if local {
        addresses.insert(profile.peer.clone(), listener.local_addr()?);
    }
    let credentials = credentials(dir);
    let endpoints = profile
        .directory
        .iter()
        .filter_map(|(name, peer)| {
            addresses
                .get(name)
                .copied()
                .or(peer.address)
                .map(|address| PeerEndpoint {
                    address,
                    name: format!("pp2-{name}"),
                    fingerprint: peer.fingerprint,
                })
        })
        .collect();
    let mut sets = Vec::new();
    if let (Some(holder), Some(grant), Some(program)) =
        (profile.holder, profile.grant, profile.program)
    {
        let mut capabilities = BTreeMap::new();
        for (name, route) in profile.routes {
            let peer = profile
                .directory
                .get(&route.peer)
                .ok_or_else(|| format!("missing directory entry for {}", route.peer))?;
            capabilities.insert(
                name,
                Binding {
                    peer: peer.fingerprint,
                    grant: route.grant,
                    program: route.program,
                    access: route.access,
                },
            );
        }
        sets.push(BindingSet {
            holder,
            grant,
            program,
            capabilities,
        });
    }
    let server = if profile.stable {
        Server::new_discovered(
            dir.join("peer.db"),
            std::env::current_exe()?,
            &credentials,
            network(dir)?,
        )?
    } else {
        Server::new(dir.join("peer.db"), std::env::current_exe()?, &credentials)?
    }
    .with_graph(&credentials, sets, endpoints)?;
    println!("{}", listener.local_addr()?);
    server.serve(listener)?;
    Ok(())
}

struct Daemon(Child);

impl Daemon {
    fn start(dir: &Path, addresses: &BTreeMap<String, SocketAddr>) -> Result<(Self, SocketAddr)> {
        let mut process = Self(
            Command::new(std::env::current_exe()?)
                .args(["app", "__serve"])
                .arg(dir)
                .arg(serde_json::to_string(addresses)?)
                .arg(std::process::id().to_string())
                .stdout(Stdio::piped())
                .spawn()?,
        );
        let stdout = process
            .0
            .stdout
            .take()
            .ok_or("missing peer readiness pipe")?;
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line)?;
        let address = line
            .trim()
            .parse()
            .map_err(|_| format!("peer {} failed to start", dir.display()))?;
        Ok((process, address))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run_local(dir: &Path, input: Option<&str>) -> Result<()> {
    let deployment: Deployment = read_json(&dir.join("deployment.json"))?;
    let sockets = deployment
        .peers
        .iter()
        .map(|peer| Ok((peer.clone(), TcpListener::bind("127.0.0.1:0")?)))
        .collect::<Result<Vec<_>>>()?;
    let addresses = sockets
        .iter()
        .map(|(name, socket)| Ok((name.clone(), socket.local_addr()?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut peers = Vec::new();
    for (peer, socket) in sockets {
        drop(socket);
        peers.push(Daemon::start(&dir.join(peer), &addresses)?.0);
    }
    invoke(
        &dir.join("client"),
        input,
        Some(addresses[&deployment.root]),
    )
}

fn invoke(dir: &Path, input: Option<&str>, address: Option<SocketAddr>) -> Result<()> {
    let profile: ClientProfile = read_json(&dir.join("profile.json"))?;
    let address = address.or(profile.address);
    let client = if let Some(id) = profile.root_id {
        Client::for_peer(&network(dir)?, id, address)
    } else {
        Client::new(
            address.ok_or("missing deployment address for root peer")?,
            format!("pp2-{}", profile.root),
            &credentials(dir),
        )?
    };
    let input = match input {
        Some(input) => data_from_json(serde_json::from_str(input)?)?,
        None => Data::Nil,
    };
    let report = client.run_graph(
        GraphEvaluation {
            evaluation: Evaluation {
                grant: profile.grant,
                program: profile.program,
                mode: EvaluationMode::Read,
                input: &input,
                packages: None,
            },
            budget: profile.budget,
            bindings: &profile.capabilities,
        },
        None,
    )?;
    crate::peer_cli::print_graph(report)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_reader(File::open(path)?)?)
}

fn write_json(path: &Path, data: &impl Serialize) -> Result<()> {
    let mut file = fs::OpenOptions::new();
    file.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        file.mode(0o600);
    }
    serde_json::to_writer_pretty(file.open(path)?, data)?;
    Ok(())
}

pub(crate) fn read_document<T: DeserializeOwned>(file: File) -> Result<T> {
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take(pp2::Block::MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > pp2::Block::MAX_BYTES {
        return Err("configuration exceeds block size".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}
