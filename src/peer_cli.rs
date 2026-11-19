use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::OsString,
    fs::{self, File},
    io::Read,
    net::TcpListener,
    path::Path,
};

use pp2::{
    Block, Hash,
    peer::{
        Access, BindingSet, Client, Credentials, Evaluation, EvaluationMode, GraphBudget,
        GraphEvaluation, JavaScript, PeerStore, Server, compile_typescript, data_from_json,
        data_to_json,
    },
};

const USAGE: &str = "Usage: pp2 peer <command>
  serve DB BIND CA CERT KEY [GRAPH_CONFIG]
  fingerprint CERT
  pack SOURCE OUTPUT [HASH | SPECIFIER=HASH ...]
  put DB BLOCK [--publish]
  publish DB HASH
  unpublish DB HASH
  fetch DB ADDRESS NAME CA CERT KEY HASH
  fetch-program DB ADDRESS NAME CA CERT KEY HASH [--publish]
  ref-init DB REFERENCE JSON_FILE
  collection-init DB REFERENCE [ENTRIES_NDJSON]
  issue DB REFERENCE HOLDER_CERT reader|writer [PROGRAM]
  delegate ADDRESS NAME CA CERT KEY GRANT HOLDER_CERT reader|writer [PROGRAM]
  revoke DB GRANT
  gc DB
  read DB|- ADDRESS NAME CA CERT KEY GRANT PROGRAM JSON_FILE
  update DB|- ADDRESS NAME CA CERT KEY GRANT PROGRAM JSON_FILE REVISION OPERATION
  graph-read DB|- ADDRESS NAME CA CERT KEY GRANT PROGRAM JSON_FILE BUDGET_JSON [CAPABILITY ...]
  graph-update DB|- ADDRESS NAME CA CERT KEY GRANT PROGRAM JSON_FILE BUDGET_JSON REVISION OPERATION";

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub fn run(args: &[OsString]) -> Result<()> {
    let args = args
        .iter()
        .map(|arg| arg.to_str().ok_or("expected UTF-8 argument"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    match args.as_slice() {
        [] | ["--help" | "-h"] => println!("{USAGE}"),
        ["serve", db, bind, ca, cert, key, config @ ..] if config.len() <= 1 => {
            let creds = credentials(ca, cert, key);
            let mut server = Server::new(db, std::env::current_exe()?, &creds)?;
            if let Some(path) = config.first() {
                let graph: GraphConfig = serde_json::from_slice(&read(Path::new(path))?)?;
                server = server.with_graph(&creds, graph.bindings, graph.brokers)?;
            }
            let listener = TcpListener::bind(bind)?;
            println!("listening on {}", listener.local_addr()?);
            server.serve(listener)?;
        }
        ["fingerprint", cert] => println!("{}", Credentials::fingerprint(cert)?),
        ["pack", source, output, imports @ ..] => {
            let path = Path::new(source);
            let is_typescript = matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("ts" | "mts")
            );
            let mut hashes = BTreeSet::new();
            let mut aliases = BTreeMap::new();
            for import in imports {
                if let Some((specifier, hash)) = import.rsplit_once('=') {
                    if !is_typescript || specifier.is_empty() {
                        return Err(
                            "SPECIFIER=HASH requires a TypeScript source and a nonempty specifier"
                                .into(),
                        );
                    }
                    let hash: Hash = hash.parse()?;
                    if aliases.insert(specifier.to_owned(), hash).is_some() {
                        return Err(format!("duplicate module specifier {specifier:?}").into());
                    }
                    hashes.insert(hash);
                } else {
                    hashes.insert(import.parse()?);
                }
            }
            let source = if is_typescript {
                compile_typescript(path, &aliases)?
            } else {
                String::from_utf8(read(path)?)?
            };
            let bytes = JavaScript {
                source,
                imports: hashes,
            }
            .to_bytes()?;
            fs::write(output, &bytes)?;
            println!("{}", Hash::digest(&bytes));
        }
        ["put", db, file, flags @ ..] if matches!(flags, [] | ["--publish"]) => {
            let mut store = PeerStore::open(db)?;
            let hash = store.put(&read(file)?)?;
            if !flags.is_empty() {
                store.publish(hash)?;
            }
            println!("{hash}");
        }
        ["publish", db, hash] => PeerStore::open(db)?.publish(hash.parse()?)?,
        ["unpublish", db, hash] => println!("{}", PeerStore::open(db)?.unpublish(hash.parse()?)?),
        ["fetch", db, address, name, ca, cert, key, hash] => {
            let client = client(address, name, ca, cert, key)?;
            let bytes = Client::fetch_into(&mut PeerStore::open(db)?, &[client], hash.parse()?)?;
            println!("{} bytes", bytes.len());
        }
        [
            "fetch-program",
            db,
            address,
            name,
            ca,
            cert,
            key,
            hash,
            flags @ ..,
        ] if matches!(flags, [] | ["--publish"]) => {
            let mut store = PeerStore::open(db)?;
            let client = client(address, name, ca, cert, key)?;
            let hashes = Client::fetch_program(&mut store, &[client], hash.parse()?)?;
            for hash in hashes {
                if !flags.is_empty() {
                    store.publish(hash)?;
                }
                println!("{hash}");
            }
        }
        ["ref-init", db, reference, json] => {
            let revision = PeerStore::open(db)?.create_ref(reference, &read_json(json)?)?;
            println!("{} {}", revision.number, revision.hash);
        }
        ["collection-init", db, reference, entries @ ..] if entries.len() <= 1 => {
            let file = entries.first().map(File::open).transpose()?;
            crate::app_cli::seed(&mut PeerStore::open(db)?, reference, file)?;
        }
        ["issue", db, reference, holder, level, program @ ..] if program.len() <= 1 => {
            let token = PeerStore::open(db)?.issue(
                reference,
                Credentials::fingerprint(holder)?,
                access(level)?,
                optional_hash(program)?,
            )?;
            println!("{token}");
        }
        [
            "delegate",
            address,
            name,
            ca,
            cert,
            key,
            grant,
            holder,
            level,
            program @ ..,
        ] if program.len() <= 1 => {
            let token = client(address, name, ca, cert, key)?.delegate(
                grant.parse()?,
                Credentials::fingerprint(holder)?,
                access(level)?,
                optional_hash(program)?,
            )?;
            println!("{token}");
        }
        ["revoke", db, grant] => println!("{}", PeerStore::open(db)?.revoke(grant.parse()?)?),
        ["gc", db] => println!("{} blocks removed", PeerStore::open(db)?.collect()?),
        [
            "read" | "update",
            db,
            address,
            name,
            ca,
            cert,
            key,
            grant,
            program,
            file,
            rest @ ..,
        ] => {
            let mode = match (args[0], rest) {
                ("read", []) => EvaluationMode::Read,
                ("update", [revision, operation]) => EvaluationMode::Update {
                    expected_revision: revision.parse()?,
                    operation: operation.parse()?,
                },
                _ => return Err(USAGE.into()),
            };
            let packages = (*db != "-").then(|| PeerStore::open(db)).transpose()?;
            let report = client(address, name, ca, cert, key)?.evaluate(Evaluation {
                grant: grant.parse()?,
                program: program.parse()?,
                mode,
                input: &read_json(file)?,
                packages: packages.as_ref(),
            })?;
            let value = data_to_json(&report.value)?;
            println!(
                "{}",
                serde_json::json!({"revision": report.revision, "value": value,
                "request_bytes": report.request_bytes, "response_bytes": report.response_bytes,
                "elapsed_ms": report.elapsed_ms, "worker_ms": report.worker_ms,
                "fuel": report.fuel, "memory_bytes": report.memory_bytes})
            );
        }
        [
            command @ ("graph-read" | "graph-update"),
            db,
            address,
            name,
            ca,
            cert,
            key,
            grant,
            program,
            file,
            budget,
            rest @ ..,
        ] => {
            let (mode, bindings) = match (*command, rest) {
                ("graph-read", names) => (
                    EvaluationMode::Read,
                    names.iter().map(|s| (*s).into()).collect(),
                ),
                ("graph-update", [revision, operation]) => (
                    EvaluationMode::Update {
                        expected_revision: revision.parse()?,
                        operation: operation.parse()?,
                    },
                    Vec::new(),
                ),
                _ => return Err(USAGE.into()),
            };
            let budget: GraphBudget = serde_json::from_str(budget)?;
            let packages = (*db != "-").then(|| PeerStore::open(db)).transpose()?;
            let report = client(address, name, ca, cert, key)?.run_graph(
                GraphEvaluation {
                    evaluation: Evaluation {
                        grant: grant.parse()?,
                        program: program.parse()?,
                        mode,
                        input: &read_json(file)?,
                        packages: packages.as_ref(),
                    },
                    budget,
                    bindings: &bindings,
                },
                None,
            )?;
            print_graph(report)?;
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphConfig {
    #[serde(default)]
    bindings: Vec<BindingSet>,
    #[serde(default)]
    brokers: BTreeSet<Hash>,
}

pub(crate) fn print_graph(report: pp2::peer::GraphReport) -> Result<()> {
    println!(
        "{}",
        serde_json::json!({
            "value": data_to_json(&report.value)?, "revision": report.revision,
            "elapsed_us": report.elapsed_us, "request_bytes": report.request_bytes,
            "response_bytes": report.response_bytes, "graph": report.graph,
        })
    );
    Ok(())
}

fn credentials(ca: &str, cert: &str, key: &str) -> Credentials {
    Credentials {
        ca: ca.into(),
        certificate: cert.into(),
        key: key.into(),
    }
}

fn client(address: &str, name: &str, ca: &str, cert: &str, key: &str) -> Result<Client> {
    Ok(Client::new(
        address.parse()?,
        name,
        &credentials(ca, cert, key),
    )?)
}

fn access(input: &str) -> Result<Access> {
    match input {
        "reader" => Ok(Access::Read),
        "writer" => Ok(Access::Write),
        _ => Err("expected reader or writer".into()),
    }
}

fn optional_hash(values: &[&str]) -> Result<Option<Hash>> {
    Ok(values.first().map(|s| s.parse()).transpose()?)
}

fn read(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(Block::MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > Block::MAX_BYTES {
        return Err("file exceeds block size".into());
    }
    Ok(bytes)
}

fn read_json(path: &str) -> Result<pp2::Data> {
    Ok(data_from_json(serde_json::from_slice(&read(path)?)?)?)
}
