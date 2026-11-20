use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::OsString,
    fs::{self, File},
    io::Read,
    net::{SocketAddr, TcpListener},
    path::Path,
};

use pp2::{
    Block, Hash,
    peer::{
        Access, BindingSet, Client, Credentials, DurableEvaluation, Evaluation, EvaluationMode,
        GraphBudget, GraphEvaluation, JavaScript, JobStatus, PeerEndpoint, PeerIdentity, PeerStore,
        Server, compile_typescript, data_from_json, data_to_json, serve_rendezvous,
    },
};

use crate::app_cli::{holder_id, network, node_init};

const USAGE: &str = "Usage: pp2 peer <command>
  serve DB BIND CA CERT KEY [GRAPH_CONFIG]
  serve-network DB BIND NODE_DIRECTORY [GRAPH_CONFIG]
  rendezvous BIND [--relay]
  node-init NODE_DIRECTORY
  replica <command>
  identity-new IDENTITY_KEY
  identity IDENTITY_KEY
  connect NODE_DIRECTORY PEER_ID[@ADDRESS] OPERATION [OPERATION_ARGS ...]
  find NODE_DIRECTORY DB HASH [--publish]
  find-graph NODE_DIRECTORY DB HASH [--publish]
  find-program NODE_DIRECTORY DB HASH [--publish]
  fingerprint CERT
  pack SOURCE OUTPUT [HASH | SPECIFIER=HASH ...]
  put DB BLOCK [--publish]
  publish DB HASH [--graph]
  unpublish DB HASH
  fetch DB ADDRESS NAME CA CERT KEY HASH
  fetch-graph DB ADDRESS NAME CA CERT KEY HASH [--publish]
  fetch-program DB ADDRESS NAME CA CERT KEY HASH [--publish]
  ref-init DB REFERENCE JSON_FILE
  collection-init DB REFERENCE [ENTRIES_NDJSON]
  clock-init DB REFERENCE
  issue DB REFERENCE PEER_ID|HOLDER_CERT reader|writer [PROGRAM]
  issue-compute DB PEER_ID|HOLDER_CERT PROGRAM
  issue-reaction-writer DB REFERENCE PEER_ID|HOLDER_CERT PROGRAM
  delegate ADDRESS NAME CA CERT KEY GRANT PEER_ID|HOLDER_CERT reader|writer [PROGRAM]
  attenuate ADDRESS NAME CA CERT KEY GRANT PEER_ID|HOLDER_CERT reader|writer PROGRAM BUDGET_JSON EXPIRES_AT_MS
  revoke DB GRANT
  gc DB
  read DB|- ADDRESS NAME CA CERT KEY GRANT PROGRAM JSON_FILE
  update DB|- ADDRESS NAME CA CERT KEY GRANT PROGRAM JSON_FILE REVISION OPERATION
  replica-read|revision-read|replica-update DB|- ADDRESS NAME CA CERT KEY GRANT PROGRAM JSON_FILE [REVISION_ID | REVISION OPERATION [--merge]]
  graph-local NODE_DIRECTORY DB GRANT PROGRAM JSON_FILE BUDGET_JSON [--update REVISION OPERATION]
  graph-read DB|- ADDRESS NAME CA CERT KEY GRANT PROGRAM JSON_FILE BUDGET_JSON [CAPABILITY ...]
  graph-update DB|- ADDRESS NAME CA CERT KEY GRANT PROGRAM JSON_FILE BUDGET_JSON REVISION OPERATION
  graph-replica-read|graph-revision-read|graph-replica-update DB|- ADDRESS NAME CA CERT KEY GRANT PROGRAM JSON_FILE BUDGET_JSON [REVISION_ID | REVISION OPERATION [--merge]]
  job-submit DB|- ADDRESS NAME CA CERT KEY GRANT PROGRAM JSON_FILE BUDGET_JSON JOB_ID EXPIRES_AT_MS [--replica | --revision REVISION_ID] [CAPABILITY ... | --delegated FILE]
  job-submit DB|- ADDRESS NAME CA CERT KEY GRANT PROGRAM JSON_FILE BUDGET_JSON JOB_ID EXPIRES_AT_MS [--replica] --update REVISION OPERATION [--merge]
  job-status ADDRESS NAME CA CERT KEY JOB_ID
  job-cancel ADDRESS NAME CA CERT KEY JOB_ID";

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub fn run(args: &[OsString]) -> Result<()> {
    let args = args
        .iter()
        .map(|arg| arg.to_str().ok_or("expected UTF-8 argument"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if let ["replica", rest @ ..] = args.as_slice() {
        return crate::replica_cli::run(rest);
    }
    if let ["connect", directory, target, command, operands @ ..] = args.as_slice() {
        let (id, fallback) = peer_target(target)?;
        let mut args = vec![*command];
        let operands = match *command {
            "fetch"
            | "fetch-graph"
            | "fetch-program"
            | "read"
            | "update"
            | "graph-read"
            | "graph-update"
            | "replica-read"
            | "revision-read"
            | "replica-update"
            | "graph-replica-read"
            | "graph-revision-read"
            | "graph-replica-update"
            | "job-submit" => {
                let (db, rest) = operands.split_first().ok_or(USAGE)?;
                args.push(*db);
                rest
            }
            "delegate" | "attenuate" | "job-status" | "job-cancel" => operands,
            _ => return Err(USAGE.into()),
        };
        args.extend(["-"; 5]);
        args.extend(operands);
        let client = Client::for_peer(&network(Path::new(directory))?, id, fallback);
        return run_command(&args, Some(client));
    }
    run_command(&args, None)
}

pub(crate) fn peer_target(input: &str) -> Result<(Hash, Option<SocketAddr>)> {
    Ok(match input.split_once('@') {
        Some((peer, address)) => (peer.parse()?, Some(address.parse()?)),
        None => (input.parse()?, None),
    })
}

fn run_command(args: &[&str], stable: Option<Client>) -> Result<()> {
    let client = |address: &str, name: &str, ca: &str, cert: &str, key: &str| -> Result<Client> {
        if let Some(client) = &stable {
            return Ok(client.clone());
        }
        Ok(Client::new(
            address.parse()?,
            name,
            &credentials(ca, cert, key),
        )?)
    };
    match args {
        [] | ["--help" | "-h"] => println!("{USAGE}"),
        ["serve", db, bind, ca, cert, key, config @ ..] if config.len() <= 1 => {
            let creds = credentials(ca, cert, key);
            let server = Server::new(db, std::env::current_exe()?, &creds)?;
            serve(server, &creds, bind, config.first().copied())?;
        }
        ["serve-network", db, bind, directory, config @ ..] if config.len() <= 1 => {
            let directory = Path::new(directory);
            let creds = crate::app_cli::credentials(directory);
            let server =
                Server::new_discovered(db, std::env::current_exe()?, &creds, network(directory)?)?;
            serve(server, &creds, bind, config.first().copied())?;
        }
        ["rendezvous", bind, flags @ ..] if matches!(flags, [] | ["--relay"]) => {
            serve_rendezvous(listening(bind)?, !flags.is_empty())?;
        }
        ["node-init", directory] => println!("{}", node_init(Path::new(directory))?),
        ["identity-new", key] => println!("{}", PeerIdentity::generate(key)?),
        ["identity", key] => println!("{}", PeerIdentity::load(key)?.id()),
        [
            command @ ("find" | "find-program" | "find-graph"),
            directory,
            db,
            hash,
            flags @ ..,
        ] if matches!(flags, [] | ["--publish"]) => {
            let mut cache = PeerStore::open(db)?;
            let network = network(Path::new(directory))?;
            let hash = hash.parse()?;
            let hashes = match *command {
                "find-graph" => Client::fetch_discovered_graph(&mut cache, &network, hash)?,
                "find-program" => Client::fetch_discovered_program(&mut cache, &network, hash)?,
                _ => {
                    Client::fetch_discovered(&mut cache, &network, hash)?;
                    vec![hash]
                }
            };
            if !flags.is_empty() {
                if *command == "find" {
                    cache.publish(hash)?;
                } else {
                    cache.publish_graph(hash)?;
                }
            }
            for hash in hashes {
                println!("{hash}");
            }
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
        ["publish", db, hash, "--graph"] => PeerStore::open(db)?.publish_graph(hash.parse()?)?,
        ["unpublish", db, hash] => println!("{}", PeerStore::open(db)?.unpublish(hash.parse()?)?),
        ["fetch", db, address, name, ca, cert, key, hash] => {
            let client = client(address, name, ca, cert, key)?;
            let bytes = Client::fetch_into(&mut PeerStore::open(db)?, &[client], hash.parse()?)?;
            println!("{} bytes", bytes.len());
        }
        [
            command @ ("fetch-graph" | "fetch-program"),
            db,
            address,
            name,
            ca,
            cert,
            key,
            hash,
            flags @ ..,
        ] if matches!(flags, [] | ["--publish"]) => {
            let mut cache = PeerStore::open(db)?;
            let sources = [client(address, name, ca, cert, key)?];
            let root = hash.parse()?;
            let hashes = if *command == "fetch-graph" {
                Client::fetch_graph(&mut cache, &sources, root)?
            } else {
                Client::fetch_program(&mut cache, &sources, root)?
            };
            if !flags.is_empty() {
                cache.publish_graph(root)?;
            }
            for hash in hashes {
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
        ["clock-init", db, reference] => {
            PeerStore::open(db)?.create_host_resource(reference, pp2::peer::Clock::resource())?;
        }
        ["issue", db, reference, holder, level, program @ ..] if program.len() <= 1 => {
            let token = PeerStore::open(db)?.issue(
                reference,
                holder_id(holder)?,
                access(level)?,
                optional_hash(program)?,
            )?;
            println!("{token}");
        }
        ["issue-compute", db, holder, program] => {
            println!(
                "{}",
                PeerStore::open(db)?.issue_compute(holder_id(holder)?, program.parse()?)?
            );
        }
        ["issue-reaction-writer", db, reference, holder, program] => {
            let token = PeerStore::open(db)?.issue_reaction_writer(
                reference,
                holder_id(holder)?,
                program.parse()?,
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
                holder_id(holder)?,
                access(level)?,
                optional_hash(program)?,
            )?;
            println!("{token}");
        }
        ["revoke", db, grant] => println!("{}", PeerStore::open(db)?.revoke(grant.parse()?)?),
        [
            "attenuate",
            address,
            name,
            ca,
            cert,
            key,
            grant,
            holder,
            level,
            program,
            budget,
            expires,
        ] => {
            let token = client(address, name, ca, cert, key)?.attenuate(
                grant.parse()?,
                holder_id(holder)?,
                access(level)?,
                program.parse()?,
                serde_json::from_str(budget)?,
                expires.parse()?,
            )?;
            println!("{token}");
        }
        ["gc", db] => println!("{} blocks removed", PeerStore::open(db)?.collect()?),
        [
            "read" | "update" | "replica-read" | "revision-read" | "replica-update",
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
            let mode = evaluation_mode(args[0], rest)?;
            let packages = (*db != "-").then(|| PeerStore::open(db)).transpose()?;
            let report = client(address, name, ca, cert, key)?.evaluate(Evaluation {
                grant: grant.parse()?,
                program: program.parse()?,
                mode,
                input: &read_json(file)?,
                packages: packages.as_ref(),
            })?;
            let mut result = serde_json::json!({"revision": report.revision,
                "value": data_to_json(&report.value)?,
                "request_bytes": report.request_bytes, "response_bytes": report.response_bytes,
                "elapsed_ms": report.elapsed_ms, "worker_ms": report.worker_ms,
                "fuel": report.fuel, "memory_bytes": report.memory_bytes});
            if let Some(view) = report.view {
                result["view"] = view.to_json();
            }
            println!("{result}");
        }
        [
            "graph-local",
            directory,
            db,
            grant,
            program,
            file,
            budget,
            rest @ ..,
        ] => {
            let mode = match rest {
                [] => EvaluationMode::Read,
                ["--update", args @ ..] => evaluation_mode("update", args)?,
                _ => return Err(USAGE.into()),
            };
            let directory = Path::new(directory);
            let server = Server::new_discovered(
                db,
                std::env::current_exe()?,
                &crate::app_cli::credentials(directory),
                network(directory)?,
            )?;
            print_graph(server.evaluate_local(GraphEvaluation {
                evaluation: Evaluation {
                    grant: grant.parse()?,
                    program: program.parse()?,
                    mode,
                    input: &read_json(file)?,
                    packages: None,
                },
                budget: serde_json::from_str(budget)?,
                bindings: &[],
            })?)?;
        }
        [
            command @ ("graph-read"
            | "graph-update"
            | "graph-replica-read"
            | "graph-revision-read"
            | "graph-replica-update"),
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
            let command = command.strip_prefix("graph-").ok_or(USAGE)?;
            let (mode, bindings) = match (command, rest) {
                ("read" | "replica-read", names) => (
                    evaluation_mode(command, &[])?,
                    names.iter().map(|s| (*s).into()).collect(),
                ),
                ("revision-read", [revision, names @ ..]) => (
                    evaluation_mode(command, &[*revision])?,
                    names.iter().map(|s| (*s).into()).collect(),
                ),
                _ => (evaluation_mode(command, rest)?, Vec::new()),
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
        [
            "job-submit",
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
            id,
            expires,
            rest @ ..,
        ] => {
            let (read_mode, rest) = match rest {
                ["--replica", rest @ ..] => (EvaluationMode::ReadReplica, rest),
                ["--revision", id, rest @ ..] => (EvaluationMode::ReadRevision(id.parse()?), rest),
                rest => (EvaluationMode::Read, rest),
            };
            let (mode, bindings, delegated) = match rest {
                ["--delegated", path] => (
                    read_mode,
                    Vec::new(),
                    Some(serde_json::from_slice(&read(Path::new(path))?)?),
                ),
                ["--update", args @ ..] => {
                    let command = match read_mode {
                        EvaluationMode::Read => "update",
                        EvaluationMode::ReadReplica => "replica-update",
                        _ => return Err(USAGE.into()),
                    };
                    (evaluation_mode(command, args)?, Vec::new(), None)
                }
                names => (
                    read_mode,
                    names.iter().map(|name| (*name).to_owned()).collect(),
                    None,
                ),
            };
            let packages = (*db != "-").then(|| PeerStore::open(db)).transpose()?;
            let request = DurableEvaluation {
                id: id.parse()?,
                expires_at_ms: expires.parse()?,
                graph: GraphEvaluation {
                    evaluation: Evaluation {
                        grant: grant.parse()?,
                        program: program.parse()?,
                        mode,
                        input: &read_json(file)?,
                        packages: packages.as_ref(),
                    },
                    budget: serde_json::from_str(budget)?,
                    bindings: &bindings,
                },
            };
            let client = client(address, name, ca, cert, key)?;
            let status = match delegated {
                Some(bindings) => client.submit_delegated_job(request, bindings)?,
                None => client.submit_job(request)?,
            };
            print_job(status)?;
        }
        [
            command @ ("job-status" | "job-cancel"),
            address,
            name,
            ca,
            cert,
            key,
            id,
        ] => {
            let client = client(address, name, ca, cert, key)?;
            let id = id.parse()?;
            let status = if *command == "job-status" {
                client.job_status(id)?
            } else {
                client.cancel_job(id)?
            };
            print_job(status)?;
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn serve(server: Server, creds: &Credentials, bind: &str, config: Option<&str>) -> Result<()> {
    let server = if let Some(path) = config {
        let graph: GraphConfig = serde_json::from_slice(&read(path)?)?;
        server.with_graph(creds, graph.bindings, graph.peers)?
    } else {
        server
    };
    let listener = listening(bind)?;
    Ok(server.serve(listener)?)
}

fn listening(bind: &str) -> Result<TcpListener> {
    let listener = TcpListener::bind(bind)?;
    println!("listening on {}", listener.local_addr()?);
    Ok(listener)
}

fn print_job(status: JobStatus) -> Result<()> {
    use serde_json::json;
    let value = match status {
        JobStatus::Pending => json!({"state":"pending"}),
        JobStatus::Running => json!({"state":"running"}),
        JobStatus::Completed {
            revision,
            value,
            graph,
        } => {
            json!({"state":"completed", "revision":revision, "value":data_to_json(&value)?, "graph":graph})
        }
        JobStatus::ResourceCompleted {
            revision,
            value,
            graph,
            view,
        } => {
            json!({"state":"completed", "revision":revision, "value":data_to_json(&value)?, "graph":graph, "view":view.to_json()})
        }
        JobStatus::Failed(error) => json!({"state":"failed", "error":error.to_string()}),
        JobStatus::Cancelled => json!({"state":"cancelled"}),
        JobStatus::Expired => json!({"state":"expired"}),
    };
    println!("{value}");
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphConfig {
    #[serde(default)]
    bindings: Vec<BindingSet>,
    #[serde(default)]
    peers: Vec<PeerEndpoint>,
}

fn evaluation_mode(command: &str, rest: &[&str]) -> Result<EvaluationMode> {
    Ok(match (command, rest) {
        ("read", []) => EvaluationMode::Read,
        ("replica-read", []) => EvaluationMode::ReadReplica,
        ("revision-read", [id]) => EvaluationMode::ReadRevision(id.parse()?),
        ("update", [revision, operation]) => EvaluationMode::Update {
            expected_revision: revision.parse()?,
            operation: operation.parse()?,
        },
        ("replica-update", [revision, operation] | [revision, operation, "--merge"]) => {
            EvaluationMode::UpdateReplica {
                expected_revision: revision.parse()?,
                operation: operation.parse()?,
                merge: rest.len() == 3,
            }
        }
        _ => return Err(USAGE.into()),
    })
}

pub(crate) fn print_graph(report: pp2::peer::GraphReport) -> Result<()> {
    let mut result = serde_json::json!({
        "value": data_to_json(&report.value)?, "revision": report.revision,
        "elapsed_us": report.elapsed_us, "request_bytes": report.request_bytes,
        "response_bytes": report.response_bytes, "graph": report.graph,
    });
    if let Some(view) = report.view {
        result["view"] = view.to_json();
    }
    println!("{result}");
    Ok(())
}

fn credentials(ca: &str, cert: &str, key: &str) -> Credentials {
    Credentials {
        ca: ca.into(),
        certificate: cert.into(),
        key: key.into(),
    }
}

pub(crate) fn access(input: &str) -> Result<Access> {
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
