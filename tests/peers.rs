#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Barrier,
    thread,
    time::{Duration, Instant},
};

use pp2::{
    Block, Data, Expr, Hash, Program,
    peer::{
        self, Access, Cancellation, Client, Credentials, Evaluation, EvaluationMode, JavaScript,
        PeerError, PeerStore, RemoteReport,
    },
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut id = [0; 32];
        getrandom::fill(&mut id).unwrap();
        let path = std::env::temp_dir().join(format!("pp2-test-{}", Hash(id)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Daemon(Child, SocketAddr);
impl Daemon {
    fn launch(path: &Path, db: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pp2"))
            .args(["peer", "serve"])
            .arg(db)
            .arg("127.0.0.1:0")
            .args(["ca.pem", "server.pem", "server.key"])
            .current_dir(path)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        let address = ready
            .strip_prefix("listening on ")
            .unwrap_or_else(|| panic!("server did not start: {ready:?}"))
            .trim()
            .parse()
            .unwrap();
        Self(child, address)
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn certificates(path: &Path) {
    let output = Command::new("sh").args(["-eu", "-c", r#"
        openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=pp2-test -keyout ca.key -out ca.pem
        for name in server writer reader stranger; do
            openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$name" -keyout "$name.key" -out "$name.csr"
            if [ "$name" = server ]; then
                printf '%s\n' 'subjectAltName=DNS:localhost' 'extendedKeyUsage=serverAuth' > extensions
            else
                printf '%s\n' 'extendedKeyUsage=clientAuth' > extensions
            fi
            openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile extensions -out "$name.pem"
        done
        openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=rogue -keyout rogue.key -out rogue.pem
    "#]).current_dir(path).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn credentials(path: &Path, name: &str) -> Credentials {
    Credentials {
        ca: path.join("ca.pem"),
        certificate: path.join(format!("{name}.pem")),
        key: path.join(format!("{name}.key")),
    }
}
fn client(path: &Path, daemon: &Daemon, name: &str) -> Client {
    Client::new(daemon.1, "localhost", &credentials(path, name)).unwrap()
}
fn pack(store: &mut PeerStore, source: impl Into<String>, imports: BTreeSet<Hash>) -> Hash {
    store
        .put(
            &JavaScript {
                source: source.into(),
                imports,
            }
            .to_bytes()
            .unwrap(),
        )
        .unwrap()
}
fn run(
    client: &Client,
    grant: Hash,
    program: Hash,
    packages: Option<&PeerStore>,
    input: &Data,
    mode: EvaluationMode,
) -> Result<RemoteReport, PeerError> {
    client.evaluate(Evaluation {
        grant,
        program,
        packages,
        input,
        mode,
    })
}
fn json(value: serde_json::Value) -> Data {
    peer::data_from_json(value).unwrap()
}

#[test]
fn database_identity_rejects_unrelated_files() {
    let dir = Temp::new();
    let database = dir.0.join("unrelated.db");
    let existing = rusqlite::Connection::open(&database).unwrap();
    existing
        .execute_batch("CREATE TABLE entries (label TEXT); INSERT INTO entries VALUES ('keep');")
        .unwrap();
    let original = fs::read(&database).unwrap();
    assert!(matches!(
        PeerStore::open(&database),
        Err(PeerError::Unsupported(_))
    ));
    assert_eq!(fs::read(database).unwrap(), original);
}

#[test]
fn real_peers_exchange_code_enforce_authority_and_recover_state() {
    let dir = Temp::new();
    let path = &dir.0;
    certificates(path);
    let database = path.join("storage.db");
    let mut store = PeerStore::open(&database).unwrap();
    let mut packages = PeerStore::open(path.join("programs.db")).unwrap();
    let revision = store.create_ref("counter", &Data::Int(7)).unwrap();
    let writer_fp = Credentials::fingerprint(path.join("writer.pem")).unwrap();
    let reader_fp = Credentials::fingerprint(path.join("reader.pem")).unwrap();
    let grant = store
        .issue("counter", writer_fp, Access::Write, None)
        .unwrap();
    let helper = pack(
        &mut packages,
        "export const add = (a, b) => a + b;",
        BTreeSet::new(),
    );
    let increment = pack(
        &mut packages,
        format!(
            "import {{add}} from 'pp2:{helper}'; export default (state, amount) => ({{next: add(state, amount), value: add(state, amount)}});"
        ),
        BTreeSet::from([helper]),
    );
    let read = pack(
        &mut packages,
        "export default value => value;",
        BTreeSet::new(),
    );
    let private = pack(
        &mut store,
        "export default () => 'private source';",
        BTreeSet::new(),
    );
    let rogue_import = pack(
        &mut packages,
        format!("import code from 'pp2:{private}'; export default () => code.toString();"),
        BTreeSet::from([private]),
    );
    let isolate = pack(
        &mut packages,
        "export default () => [typeof process, typeof require, typeof fetch, typeof Date, typeof Math.random];",
        BTreeSet::new(),
    );
    let blocked_import = pack(
        &mut packages,
        "export default async () => await import('file:///etc/hostname');",
        BTreeSet::new(),
    );
    let bad_update = pack(
        &mut packages,
        "export default s => ({ next: s + 9000 });",
        BTreeSet::new(),
    );
    let loop_forever = pack(
        &mut packages,
        "export default () => { for (;;) {} };",
        BTreeSet::new(),
    );
    let cancelled_program = pack(
        &mut packages,
        "export default () => { while (true) {} };",
        BTreeSet::new(),
    );
    let too_much = pack(
        &mut packages,
        "export default () => new Uint8Array(64 * 1024 * 1024).length;",
        BTreeSet::new(),
    );
    let legacy = packages
        .put(
            &Program::new(
                Expr::Read(
                    Box::new(Expr::Cap(0)),
                    Box::new(Expr::StoreRoot(Box::new(Expr::Cap(0)))),
                ),
                vec![],
            )
            .to_bytes()
            .unwrap(),
        )
        .unwrap();
    let missing_root = Hash::digest(b"absent Merkle child");
    let attempted_state = Block::Data(Data::Link(missing_root)).hash().unwrap();
    let incomplete = packages
        .put(
            &Program::new(
                Expr::Literal(Data::Record(BTreeMap::from([
                    ("next".into(), Data::Link(missing_root)),
                    ("value".into(), Data::Nil),
                ]))),
                vec![],
            )
            .to_bytes()
            .unwrap(),
        )
        .unwrap();
    let daemon = Daemon::launch(path, &database);
    let writer = client(path, &daemon, "writer");
    let reader = client(path, &daemon, "reader");
    let stranger = client(path, &daemon, "stranger");
    let rogue = client(path, &daemon, "rogue");
    let wrong_name = Client::new(daemon.1, "other-host", &credentials(path, "writer")).unwrap();
    assert!(rogue.fetch(private).is_err());
    assert!(wrong_name.fetch(private).is_err());
    assert!(matches!(
        writer.fetch(revision.hash),
        Err(PeerError::Missing(_))
    ));
    let read_only = writer
        .delegate(grant, reader_fp, Access::Read, Some(read))
        .unwrap();
    assert!(matches!(
        reader.delegate(read_only, reader_fp, Access::Write, None),
        Err(PeerError::Denied)
    ));
    assert!(matches!(
        reader.delegate(read_only, reader_fp, Access::Read, Some(private)),
        Err(PeerError::Denied)
    ));
    assert!(matches!(
        run(
            &stranger,
            grant,
            read,
            Some(&packages),
            &Data::Nil,
            EvaluationMode::Read
        ),
        Err(PeerError::Denied)
    ));
    assert!(matches!(
        run(
            &writer,
            Hash([0; 32]),
            read,
            Some(&packages),
            &Data::Nil,
            EvaluationMode::Read
        ),
        Err(PeerError::Denied)
    ));
    assert!(
        matches!(run(&writer, grant, rogue_import, Some(&packages), &Data::Nil, EvaluationMode::Read), Err(PeerError::Missing(hash)) if hash == private)
    );
    assert!(matches!(
        run(
            &writer,
            grant,
            blocked_import,
            Some(&packages),
            &Data::Nil,
            EvaluationMode::Read
        ),
        Err(PeerError::Guest(_))
    ));
    assert_eq!(
        run(
            &writer,
            grant,
            isolate,
            Some(&packages),
            &Data::Nil,
            EvaluationMode::Read
        )
        .unwrap()
        .value,
        json(serde_json::json!([
            "undefined",
            "undefined",
            "undefined",
            "undefined",
            "undefined"
        ]))
    );
    let aeb = run(
        &writer,
        grant,
        legacy,
        Some(&packages),
        &Data::Nil,
        EvaluationMode::Read,
    )
    .unwrap();
    assert_eq!(aeb.value, Data::Int(7));
    assert!(aeb.fuel.is_some());
    let read_mode = EvaluationMode::Read;
    let update = EvaluationMode::Update {
        expected_revision: 0,
        operation: Hash([1; 32]),
    };
    assert!(matches!(
        run(
            &reader,
            read_only,
            increment,
            Some(&packages),
            &Data::Int(4),
            update
        ),
        Err(PeerError::Denied)
    ));
    assert!(matches!(
        run(
            &writer,
            grant,
            bad_update,
            Some(&packages),
            &Data::Nil,
            update
        ),
        Err(PeerError::Value(_))
    ));
    assert!(matches!(
        run(&writer, grant, incomplete, Some(&packages), &Data::Nil, update),
        Err(PeerError::Missing(hash)) if hash == missing_root
    ));
    assert_eq!(store.get(attempted_state).unwrap(), None);
    assert!(matches!(
        run(
            &writer,
            grant,
            too_much,
            Some(&packages),
            &Data::Nil,
            read_mode
        ),
        Err(PeerError::Guest(_))
    ));
    assert_eq!(store.reference("counter").unwrap().unwrap(), revision);
    let first = run(
        &writer,
        grant,
        increment,
        Some(&packages),
        &Data::Int(4),
        update,
    )
    .unwrap();
    assert_eq!((first.revision, first.value), (1, Data::Int(11)));
    assert!(first.worker_ms.is_some());
    assert!(matches!(
        run(&writer, grant, increment, None, &Data::Int(9), update),
        Err(PeerError::Value(_))
    ));
    let warm = run(&writer, grant, increment, None, &Data::Int(4), update).unwrap();
    assert!(warm.worker_ms.is_none());
    assert!(warm.request_bytes < first.request_bytes);
    assert_eq!((warm.revision, warm.value), (1, Data::Int(11)));
    assert_eq!(
        run(
            &reader,
            read_only,
            read,
            Some(&packages),
            &Data::Nil,
            read_mode
        )
        .unwrap()
        .value,
        Data::Int(11)
    );
    assert!(matches!(
        run(&reader, read_only, increment, None, &Data::Nil, read_mode),
        Err(PeerError::Denied)
    ));

    let barrier = Barrier::new(2);
    let (one, two) = thread::scope(|scope| {
        let compete = |id| {
            barrier.wait();
            run(
                &writer,
                grant,
                increment,
                None,
                &Data::Int(1),
                EvaluationMode::Update {
                    expected_revision: 1,
                    operation: Hash([id; 32]),
                },
            )
        };
        let one = scope.spawn(move || compete(2));
        let two = scope.spawn(move || compete(3));
        (one.join().unwrap(), two.join().unwrap())
    });
    assert!(one.is_ok() ^ two.is_ok());
    assert!(matches!(one.and(two), Err(PeerError::Conflict(2))));
    assert!(matches!(
        run(
            &writer,
            grant,
            loop_forever,
            Some(&packages),
            &Data::Nil,
            read_mode
        ),
        Err(PeerError::Timeout)
    ));
    let cancellation = Cancellation::default();
    thread::scope(|scope| {
        let pending = scope.spawn(|| {
            let packages = PeerStore::open(path.join("programs.db")).unwrap();
            writer.evaluate_cancellable(
                Evaluation {
                    grant,
                    program: cancelled_program,
                    packages: Some(&packages),
                    input: &Data::Nil,
                    mode: EvaluationMode::Update {
                        expected_revision: 2,
                        operation: Hash([4; 32]),
                    },
                },
                &cancellation,
            )
        });
        let wait_until = Instant::now() + Duration::from_secs(2);
        while store.get(cancelled_program).unwrap().is_none() {
            assert!(
                Instant::now() < wait_until,
                "evaluation did not accept its program"
            );
            thread::sleep(Duration::from_millis(5));
        }
        cancellation.cancel();
        assert!(matches!(pending.join().unwrap(), Err(PeerError::Cancelled)));
    });
    assert_eq!(store.reference("counter").unwrap().unwrap().number, 2);

    // A broken connection does not hold the accept loop or mutate a reference.
    drop(std::net::TcpStream::connect(daemon.1).unwrap());
    drop(daemon);
    let daemon = Daemon::launch(path, &database);
    let writer = client(path, &daemon, "writer");
    let reader = client(path, &daemon, "reader");
    let replay = run(&writer, grant, increment, None, &Data::Int(4), update).unwrap();
    assert_eq!((replay.revision, replay.value), (1, Data::Int(11)));
    assert_eq!(
        run(&writer, grant, legacy, None, &Data::Nil, read_mode)
            .unwrap()
            .value,
        Data::Int(12)
    );
    assert!(store.revoke(grant).unwrap());
    assert!(matches!(
        run(&reader, read_only, read, None, &Data::Nil, read_mode),
        Err(PeerError::Denied)
    ));

    let bytes = Block::Data(Data::Text("public peer content".into()))
        .to_bytes()
        .unwrap();
    let public = Hash::digest(&bytes);
    let origin_db = path.join("origin.db");
    let mut origin_store = PeerStore::open(&origin_db).unwrap();
    origin_store.import(public, &bytes).unwrap();
    origin_store.publish(public).unwrap();
    let origin = Daemon::launch(path, &origin_db);
    let origin_client = client(path, &origin, "reader");
    assert_eq!(
        Client::fetch_into(&mut store, &[reader.clone(), origin_client.clone()], public).unwrap(),
        bytes
    );
    store.publish(public).unwrap();
    origin_store.unpublish(public).unwrap();
    origin_store.collect().unwrap();
    assert!(matches!(
        origin_client.fetch(public),
        Err(PeerError::Missing(_))
    ));
    drop(origin);
    assert_eq!(reader.fetch(public).unwrap(), bytes);
    let current = store.reference("counter").unwrap().unwrap();
    assert_eq!(current.number, 2);
    assert!(store.collect().unwrap() > 0);
    assert_eq!(store.get(revision.hash).unwrap(), None);
    assert_eq!(
        Block::from_bytes(&store.get(current.hash).unwrap().unwrap()).unwrap(),
        Block::Data(Data::Int(12))
    );
}

#[test]
fn indexed_effects_are_bounded_and_commit_with_their_receipt() {
    use pp2::peer::{GraphBudget, GraphEvaluation};
    use serde_json::json as j;

    let temp = Temp::new();
    certificates(&temp.0);
    let db = temp.0.join("collection.db");
    let mut store = PeerStore::open(&db).unwrap();
    store
        .create_collection(
            "stock",
            (0..4_000).map(|i| Ok((format!("stock/{i:04}"), Data::Text("x".repeat(128))))),
        )
        .unwrap();
    store
        .create_collection("other", [Ok(("secret".into(), Data::Int(42)))])
        .unwrap();
    let program = pack(
        &mut store,
        r#"
        export default async ({storage}, input) => {
            if (input.task === 'update') {
                await storage.put('stock/0000', null);
                const wasPresent = await storage.delete('stock/0001');
                if (input.abort) throw new Error('rollback');
                return {wasPresent, entry: await storage.get('stock/0000')};
            }
            if (input.task === 'overflow') {
                for (let i = 0; i < 129; i++) await storage.get('stock/0000');
                return false;
            }
            return {
                page: await storage.scan({prefix: 'stock/', after: input.after, limit: 2}),
                secret: await storage.get('secret'),
            };
        };
    "#,
        BTreeSet::new(),
    );
    let holder = Credentials::fingerprint(temp.0.join("writer.pem")).unwrap();
    let read = store
        .issue("stock", holder, Access::Read, Some(program))
        .unwrap();
    let write = store
        .issue("stock", holder, Access::Write, Some(program))
        .unwrap();
    let daemon = Daemon::launch(&temp.0, &db);
    let client = client(&temp.0, &daemon, "writer");
    let invoke = |grant, input, mode, packages| {
        client.run_graph(
            GraphEvaluation {
                evaluation: Evaluation {
                    grant,
                    program,
                    mode,
                    input: &json(input),
                    packages,
                },
                bindings: &[],
                budget: GraphBudget {
                    timeout_ms: 3000,
                    calls: 0,
                    depth: 0,
                },
            },
            None,
        )
    };
    let first = invoke(read, j!({}), EvaluationMode::Read, Some(&store)).unwrap();
    let first = peer::data_to_json(&first.value).unwrap();
    assert_eq!(first["page"]["next"], "stock/0001");
    assert_eq!(first["page"]["entries"][0][0], "stock/0000");
    assert_eq!(first["secret"], j!({"found":false}));
    let last = invoke(read, j!({"after":"stock/3997"}), EvaluationMode::Read, None).unwrap();
    assert_eq!(
        peer::data_to_json(&last.value).unwrap()["page"]["next"],
        j!(null)
    );

    let update = EvaluationMode::Update {
        expected_revision: 0,
        operation: Hash([5; 32]),
    };
    assert!(matches!(
        invoke(read, j!({"task":"update"}), update, None),
        Err(PeerError::Denied)
    ));
    assert!(matches!(
        invoke(write, j!({"task":"update","abort":true}), update, None),
        Err(PeerError::Guest(message)) if message.contains("rollback")
    ));
    assert_eq!(store.reference("stock").unwrap().unwrap().number, 0);
    let report = invoke(write, j!({"task":"update"}), update, None).unwrap();
    assert_eq!(report.revision, 1);
    assert_eq!(
        report.value,
        json(j!({"wasPresent":true,"entry":{"found":true,"value":null}}))
    );
    assert!(matches!(
        invoke(write, j!({"task":"update","abort":true}), update, None),
        Err(PeerError::Value(_))
    ));
    let changed = invoke(read, j!({}), EvaluationMode::Read, None).unwrap();
    assert_eq!(
        peer::data_to_json(&changed.value).unwrap()["page"]["entries"][1][0],
        "stock/0002"
    );
    assert!(matches!(
        invoke(read, j!({"task":"overflow"}), EvaluationMode::Read, None),
        Err(PeerError::Value(_))
    ));
    drop(daemon);
    store.collect().unwrap();
    let daemon = Daemon::launch(&temp.0, &db);
    let client = Client::new(daemon.1, "localhost", &credentials(&temp.0, "writer")).unwrap();
    let receipt = client
        .run_graph(
            GraphEvaluation {
                evaluation: Evaluation {
                    grant: write,
                    program,
                    mode: update,
                    input: &json(j!({"task":"update"})),
                    packages: None,
                },
                bindings: &[],
                budget: GraphBudget {
                    timeout_ms: 1500,
                    calls: 0,
                    depth: 0,
                },
            },
            None,
        )
        .unwrap();
    assert_eq!(receipt.revision, 1);
    assert_eq!(receipt.value, report.value);
    assert_eq!(receipt.graph.worker_busy_us, 0);
}

#[test]
fn three_peers_enforce_delegation_budgets_and_cancel_a_descendant() {
    use pp2::peer::{GraphBudget, GraphEvaluation};
    use serde_json::json as j;

    let temp = Temp::new();
    let workspace = temp.0.join("deployment");
    let manifest = temp.0.join("app.json");
    fs::write(
        &manifest,
        j!({
            "root": {"peer":"root", "collection":"stock", "module":"stock", "capabilities":{
                "west":{"peer":"west","collection":"stock","module":"stock"},
                "east":{"peer":"east","collection":"stock","module":"stock","write":true}
            }},
            "budget":{"timeout_ms":4000,"calls":2,"depth":2},
            "modules":{"stock":{"source":"stock.mjs"}},
            "peers":{
                "root":{"collections":{"stock":null}},
                "east":{"collections":{"stock":"east.ndjson"}},
                "west":{"collections":{"stock":"west.ndjson"}}
            }
        })
        .to_string(),
    )
    .unwrap();
    fs::write(temp.0.join("east.ndjson"), "[\"stock\",7]\n").unwrap();
    fs::write(temp.0.join("west.ndjson"), "[\"stock\",5]\n").unwrap();
    fs::write(
        temp.0.join("stock.mjs"),
        r#"
        export default async ({capabilities, storage, evaluate}, input) => {
            const {east, west} = capabilities;
            switch (input.task) {
            case 'get':
                return (await storage.get('stock')).value;
            case 'nested':
                return (await storage.get('stock')).value +
                    (await evaluate(east, {task:'get'}, {calls: 0})).value;
            case 'delegate':
                return (await evaluate(west, {task:'nested'}, {
                    calls: 1, delegate: input.share ? [east] : [],
                })).value;
            case 'forgery':
                return await evaluate({}, {task:'get'}, {calls: 0});
            case 'serialize':
                return [east];
            case 'write':
                await storage.put('stock', input.value);
                if (input.spin) while (true) {}
                return (await storage.get('stock')).value;
            case 'route-write':
                try {
                    return await evaluate(east, input.write, {
                        calls: 0, update: {revision: input.revision, operation: input.operation},
                        timeoutMs: input.timeout ?? null,
                    });
                } catch (err) {
                    return {error: err.code};
                }
            default:
                const results = await Promise.all([
                    evaluate(west, {task:'get'}, {calls:0}),
                    evaluate(east, {task:'get'}, {calls:0}),
                ]);
                return results[0].value + results[1].value;
            }
        };
    "#,
    )
    .unwrap();
    let binary = env!("CARGO_BIN_EXE_pp2");
    let output = Command::new(binary)
        .args(["app", "init"])
        .arg(&manifest)
        .arg(&workspace)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let spawn = |name: &str, addresses| {
        let mut child = Command::new(binary)
            .args(["app", "__serve"])
            .arg(workspace.join(name))
            .arg(serde_json::to_string(&addresses).unwrap())
            .arg(std::process::id().to_string())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        Daemon(child, line.trim().parse().unwrap())
    };
    let west = spawn("west", BTreeMap::<String, SocketAddr>::new());
    let east = spawn("east", BTreeMap::new());
    let root = spawn(
        "root",
        BTreeMap::from([("west".into(), west.1), ("east".into(), east.1)]),
    );
    let dir = workspace.join("client");
    let creds = Credentials {
        ca: dir.join("ca.pem"),
        certificate: dir.join("peer.pem"),
        key: dir.join("peer.key"),
    };
    let profile: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("profile.json")).unwrap()).unwrap();
    let program: Hash = serde_json::from_value(profile["program"].clone()).unwrap();
    let grant: Hash = serde_json::from_value(profile["grant"].clone()).unwrap();
    let client = Client::new(root.1, "pp2-root", &creds).unwrap();
    let bindings: Vec<String> = vec!["west".into(), "east".into()];
    let request = |grant, input, calls, depth, cancellation: Option<Cancellation>| {
        client.run_graph(
            GraphEvaluation {
                evaluation: Evaluation {
                    grant,
                    program,
                    mode: EvaluationMode::Read,
                    input: &json(input),
                    packages: None,
                },
                bindings: &bindings,
                budget: GraphBudget {
                    timeout_ms: 4000,
                    calls,
                    depth,
                },
            },
            cancellation.as_ref(),
        )
    };
    let direct = request(grant, j!({}), 2, 1, None).unwrap();
    assert_eq!(direct.value, Data::Int(12));
    assert_eq!(direct.graph.remote_calls, 2);
    assert_eq!(direct.graph.storage_effects, 2);
    let delegated = request(grant, j!({"task":"delegate","share":true}), 2, 2, None).unwrap();
    assert_eq!(delegated.value, direct.value);
    assert_eq!(delegated.graph.remote_calls, 2);
    assert!(delegated.graph.remote_request_bytes < direct.graph.remote_request_bytes);
    for (input, calls, depth) in [
        (j!({"task":"delegate","share":false}), 2, 2),
        (j!({"task":"delegate","share":true}), 2, 1),
        (j!({"task":"delegate","share":true}), 1, 2),
        (j!({"task":"forgery"}), 2, 2),
        (j!({"task":"serialize"}), 2, 2),
    ] {
        assert!(matches!(
            request(grant, input, calls, depth, None),
            Err(PeerError::Guest(_))
        ));
    }
    let alternate = PeerStore::open(workspace.join("root/peer.db"))
        .unwrap()
        .issue(
            "stock",
            Credentials::fingerprint(&creds.certificate).unwrap(),
            Access::Read,
            Some(program),
        )
        .unwrap();
    assert!(matches!(
        request(alternate, j!({}), 2, 2, None),
        Err(PeerError::Denied)
    ));

    let operation = Hash([9; 32]).to_string();
    let spin = j!({"task":"route-write","write":{"task":"write","value":99,"spin":true},
                   "revision":0,"operation":operation});
    let east_db = workspace.join("east/peer.db");
    let probe = rusqlite::Connection::open(&east_db).unwrap();
    probe.busy_timeout(Duration::ZERO).unwrap();
    let lock = || {
        if probe.execute_batch("BEGIN IMMEDIATE").is_err() {
            return false;
        }
        probe.execute_batch("ROLLBACK").unwrap();
        true
    };
    thread::scope(|scope| {
        let cancel = Cancellation::default();
        let cancelled = cancel.clone();
        let spin = spin.clone();
        let request = &request;
        let running = scope.spawn(move || request(grant, spin, 1, 1, Some(cancelled)));
        let started = Instant::now();
        while lock() && started.elapsed() < Duration::from_secs(1) {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(!lock(), "the descendant never opened an update");
        cancel.cancel();
        assert!(matches!(running.join().unwrap(), Err(PeerError::Cancelled)));
        let started = Instant::now();
        while !lock() && started.elapsed() < Duration::from_secs(1) {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(lock(), "cancellation did not reach the descendant");
    });
    let mut deadline = spin;
    deadline["timeout"] = j!(100);
    let timed = request(grant, deadline, 1, 1, None).unwrap();
    assert_eq!(timed.value, json(j!({"error":"timeout"})));
    let mut east_store = PeerStore::open(&east_db).unwrap();
    assert_eq!(east_store.reference("stock").unwrap().unwrap().number, 0);
    let write = j!({"task":"route-write","write":{"task":"write","value":8},
                    "revision":0,"operation":operation});
    let updated = request(grant, write.clone(), 1, 1, None).unwrap();
    assert_eq!(updated.value, json(j!({"revision":1,"value":8})));
    let replayed = request(grant, write, 1, 1, None).unwrap();
    assert_eq!(replayed.value, updated.value);
    let east_profile: serde_json::Value =
        serde_json::from_slice(&fs::read(workspace.join("root/profile.json")).unwrap()).unwrap();
    let east_grant =
        serde_json::from_value(east_profile["routes"]["east"]["grant"].clone()).unwrap();
    assert!(east_store.revoke(east_grant).unwrap());
    assert!(matches!(
        request(grant, j!({"task":"delegate","share":true}), 2, 2, None),
        Err(PeerError::Guest(message)) if message.contains("denied")
    ));
}

#[test]
fn version_one_databases_keep_their_snapshot_references() {
    let dir = Temp::new();
    let database = dir.0.join("old.db");
    let mut store = PeerStore::open(&database).unwrap();
    let revision = store.create_ref("old", &Data::Int(71)).unwrap();
    drop(store);
    {
        let old = rusqlite::Connection::open(&database).unwrap();
        old.execute_batch("DROP TABLE entries; DROP TABLE collections; PRAGMA user_version = 1;")
            .unwrap();
    }
    let mut store = PeerStore::open(&database).unwrap();
    assert_eq!(
        store.read_ref("old").unwrap(),
        Some((revision, Data::Int(71)))
    );
    store
        .create_collection("new", [Ok(("counter".into(), Data::Int(5)))])
        .unwrap();
    assert!(store.read_ref("new").is_err());
    assert_eq!(
        store.read_ref("old").unwrap(),
        Some((revision, Data::Int(71)))
    );
}
