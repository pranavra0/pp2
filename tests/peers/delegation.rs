use super::*;

#[test]
fn three_peers_enforce_delegation_budgets_and_cancel_a_descendant() {
    use pp2::peer::{DurableEvaluation, GraphBudget, GraphEvaluation, JobStatus};
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
        export default async ({capabilities, storage, evaluate, evaluateAll}, input) => {
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
            case 'batch':
                try {
                    const results = await evaluateAll([
                        {capability: east, input: {task:'get'}},
                        {capability: input.forge ? {} : west, input: {task:'get'}},
                    ]);
                    return results.map(result => result.value);
                } catch (err) {
                    return {error: err.code ?? 'invalid'};
                }
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
    let sockets =
        ["west", "east", "root"].map(|name| (name, TcpListener::bind("127.0.0.1:0").unwrap()));
    let addresses = sockets
        .iter()
        .map(|(name, socket)| (name.to_string(), socket.local_addr().unwrap()))
        .collect::<BTreeMap<_, _>>();
    let [_west, _east, root] = sockets.map(|(name, socket)| {
        drop(socket);
        spawn(name, addresses.clone())
    });
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
    let batch = request(grant, j!({"task":"batch"}), 2, 1, None).unwrap();
    assert_eq!(batch.value, json(j!([7, 5])));
    assert_eq!(batch.graph.remote_calls, 2);
    assert_eq!(batch.graph.storage_effects, 2);
    let too_many = request(grant, j!({"task":"batch"}), 1, 1, None).unwrap();
    assert_eq!(too_many.value, json(j!({"error":"invalid"})));
    assert_eq!(too_many.graph.remote_calls, 0);
    let forged = request(grant, j!({"task":"batch","forge":true}), 2, 1, None).unwrap();
    assert_eq!(forged.value, json(j!({"error":"invalid"})));
    assert_eq!(forged.graph.remote_calls, 0);
    let delegated = request(grant, j!({"task":"delegate","share":true}), 2, 2, None).unwrap();
    assert_eq!(delegated.value, direct.value);
    assert_eq!(delegated.graph.remote_calls, 2);
    assert_eq!(delegated.graph.storage_effects, 2);
    assert!(delegated.graph.remote_request_bytes > 0);
    let id = Hash([42; 32]);
    let expires_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 10_000;
    let status = client
        .submit_job(DurableEvaluation {
            id,
            expires_at_ms,
            graph: GraphEvaluation {
                evaluation: Evaluation {
                    grant,
                    program,
                    mode: EvaluationMode::Read,
                    input: &json(j!({"task":"delegate","share":true})),
                    packages: None,
                },
                budget: GraphBudget {
                    timeout_ms: 4000,
                    calls: 2,
                    depth: 2,
                },
                bindings: &bindings,
            },
        })
        .unwrap();
    assert!(matches!(status, JobStatus::Pending));
    let started = Instant::now();
    loop {
        match client.job_status(id).unwrap() {
            JobStatus::Pending | JobStatus::Running => {
                assert!(started.elapsed() < Duration::from_secs(5));
                thread::sleep(Duration::from_millis(20));
            }
            JobStatus::Completed { value, graph, .. } => {
                assert_eq!(value, direct.value);
                assert_eq!(graph.remote_calls, 2);
                break;
            }
            status => panic!("durable nested graph failed: {status:?}"),
        }
    }
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
    let denied = request(grant, j!({"task":"batch"}), 2, 1, None).unwrap();
    assert_eq!(denied.value, json(j!({"error":"denied"})));
    assert_eq!(denied.graph.remote_failures, 1);
    assert!(matches!(
        request(grant, j!({"task":"delegate","share":true}), 2, 2, None),
        Err(PeerError::Guest(message)) if message.contains("denied")
    ));
}
