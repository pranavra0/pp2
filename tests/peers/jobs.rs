use super::*;

fn drop_tls_reply(listener: TcpListener, destination: SocketAddr) -> thread::JoinHandle<()> {
    use std::{
        io::{Read, Write},
        net::{Shutdown, TcpStream},
        sync::atomic::{AtomicBool, Ordering},
    };

    fn record(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        let mut header = [0; 5];
        stream.read_exact(&mut header)?;
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut record = header.to_vec();
        record.resize(5 + len, 0);
        stream.read_exact(&mut record[5..])?;
        Ok(record)
    }

    thread::spawn(move || {
        let (mut downstream, _) = listener.accept().unwrap();
        let mut upstream = TcpStream::connect(destination).unwrap();
        let mut reader = downstream.try_clone().unwrap();
        let mut writer = upstream.try_clone().unwrap();
        let sent_finished = AtomicBool::new(false);
        thread::scope(|scope| {
            scope.spawn(|| {
                while let Ok(record) = record(&mut reader) {
                    if record[0] == 23 {
                        sent_finished.store(true, Ordering::Release);
                    }
                    if writer.write_all(&record).is_err() {
                        break;
                    }
                }
            });
            loop {
                let record = record(&mut upstream).unwrap();
                if sent_finished.load(Ordering::Acquire) {
                    break;
                }
                downstream.write_all(&record).unwrap();
            }
            let _ = downstream.shutdown(Shutdown::Both);
            let _ = upstream.shutdown(Shutdown::Both);
        });
    })
}

#[test]
fn autonomous_job_recovers_between_independently_administered_peers() {
    use pp2::peer::{
        Binding, DurableEvaluation, GraphBudget, GraphEvaluation, JobStatus, PeerEndpoint,
    };
    use serde_json::json as j;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(Instant::now() < deadline, "condition did not become true");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn terminal(client: &Client, id: Hash) -> JobStatus {
        let mut result = JobStatus::Pending;
        until(|| {
            result = client.job_status(id).unwrap();
            !matches!(result, JobStatus::Pending | JobStatus::Running)
        });
        result
    }

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path();
    certificates(path);
    let output = Command::new("sh").args(["-eu", "-c", r#"
        for name in a b c; do
            openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes                 -subj "/CN=$name" -keyout "$name.key" -out "$name.csr"
            printf 'extendedKeyUsage=clientAuth,serverAuth\nsubjectAltName=DNS:%s\n' "$name" > extensions
            openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial                 -days 2 -extfile extensions -out "$name.pem"
        done
    "#]).current_dir(path).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let sockets = ["a", "b", "c"].map(|name| (name, TcpListener::bind("127.0.0.1:0").unwrap()));
    let addresses: BTreeMap<_, _> = sockets
        .iter()
        .map(|(name, socket)| (*name, socket.local_addr().unwrap()))
        .collect();
    drop(sockets);
    let fingerprint =
        |name: &str| Credentials::fingerprint(credentials(path, name).certificate).unwrap();
    let a = fingerprint("a");
    let b = fingerprint("b");
    let c = fingerprint("c");
    let other = fingerprint("stranger");
    let peers = vec![
        PeerEndpoint {
            address: addresses["a"],
            name: "a".into(),
            fingerprint: a,
        },
        PeerEndpoint {
            address: addresses["c"],
            name: "c".into(),
            fingerprint: c,
        },
        PeerEndpoint {
            address: addresses["a"],
            name: "a".into(),
            fingerprint: other,
        },
    ];
    fs::write(path.join("b.json"), j!({"peers": peers}).to_string()).unwrap();
    let launch = |name: &str| {
        let mut process = Command::new(env!("CARGO_BIN_EXE_pp2"));
        process.args([
            "peer",
            "serve",
            &format!("{name}.db"),
            &addresses[name].to_string(),
            "ca.pem",
            &format!("{name}.pem"),
            &format!("{name}.key"),
        ]);
        if name == "b" {
            process.arg("b.json");
        }
        Daemon::from_child(
            process
                .current_dir(path)
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        )
    };
    let mut a_store = PeerStore::open(path.join("a.db")).unwrap();
    let mut b_store = PeerStore::open(path.join("b.db")).unwrap();
    let c_db = path.join("c.db");
    let mut c_store = PeerStore::open(&c_db).unwrap();
    c_store
        .create_collection("counter", [Ok(("value".into(), Data::Int(10)))])
        .unwrap();
    let program_b = pack(
        &mut a_store,
        r#"
        const local = 6;
        export default async ({capabilities, evaluate, blocks, storage, resource}, input) => {
            if (blocks || storage || resource) throw Error("unexpected resource");
            const remote = await evaluate(capabilities.remote, input, {
                calls: input.calls ?? 0,
                update: input.operation ? {revision: 0, operation: input.operation} : null,
            });
            return {local, remote: remote.value};
        }
    "#,
        BTreeSet::new(),
    );
    let program_c = pack(
        &mut c_store,
        r#"
        export default async ({storage}, input) => {
            const row = await storage.get('value');
            if (!input.operation) return row.value;
            const next = row.value + input.add;
            await storage.put('value', next);
            let checksum = 0;
            for (let i = 0; i < input.work; i++) checksum = Math.imul(checksum + 1, 16777619);
            if (!Number.isInteger(checksum)) throw Error("invalid checksum");
            return next;
        }
    "#,
        BTreeSet::new(),
    );
    c_store.publish(program_c).unwrap();
    let grant_b = b_store.issue_compute(a, program_b).unwrap();
    let other_grant = b_store.issue_compute(other, program_b).unwrap();
    let grant_c = c_store
        .issue("counter", a, Access::Write, Some(program_c))
        .unwrap();
    let read_grant = c_store
        .issue("counter", a, Access::Read, Some(program_c))
        .unwrap();

    let daemon_a = launch("a");
    let mut daemon_b = launch("b");
    let mut daemon_c = launch("c");
    let client_c = Client::new(addresses["c"], "c", &credentials(path, "a")).unwrap();
    let connect_b =
        |name: &str| Client::new(addresses["b"], "b", &credentials(path, name)).unwrap();
    let expires = now() + 30_000;
    let leaf = GraphBudget {
        timeout_ms: 1_800,
        calls: 0,
        depth: 0,
    };
    let budget = GraphBudget {
        timeout_ms: 1_800,
        calls: 1,
        depth: 1,
    };
    let token = client_c
        .attenuate(grant_c, b, Access::Write, program_c, leaf, expires)
        .unwrap();
    assert_eq!(
        token,
        client_c
            .attenuate(grant_c, b, Access::Write, program_c, leaf, expires)
            .unwrap()
    );
    assert!(matches!(
        client_c.attenuate(read_grant, b, Access::Write, program_c, leaf, expires),
        Err(PeerError::Denied)
    ));
    assert!(matches!(
        client_c.attenuate(grant_c, b, Access::Read, program_b, leaf, expires),
        Err(PeerError::Denied)
    ));
    let read_token = client_c
        .attenuate(read_grant, b, Access::Read, program_c, leaf, expires)
        .unwrap();
    let binding = Binding {
        peer: c,
        grant: token,
        program: program_c,
        access: Access::Write,
    };
    let id = Hash([10; 32]);
    let input = json(j!({"add": 4, "work": 1_000_000, "operation": Hash([11; 32]).to_string()}));
    let submit = |client: &Client, grant, id, input, binding, budget, expires_at_ms| {
        client.submit_delegated_job(
            DurableEvaluation {
                id,
                expires_at_ms,
                graph: GraphEvaluation {
                    evaluation: Evaluation {
                        grant,
                        program: program_b,
                        mode: EvaluationMode::Read,
                        input,
                        packages: Some(&a_store),
                    },
                    budget,
                    bindings: &[],
                },
            },
            BTreeMap::from([("remote".into(), binding)]),
        )
    };

    b_store.create_collection("private", []).unwrap();
    let private = b_store
        .issue("private", a, Access::Read, Some(program_b))
        .unwrap();
    assert!(matches!(
        submit(
            &connect_b("a"),
            private,
            id,
            &input,
            binding.clone(),
            budget,
            expires
        ),
        Err(PeerError::Denied)
    ));

    // C is unreachable at submission. A exits before B can execute the remote effect.
    drop(daemon_c);
    let client_a = connect_b("a");
    assert!(matches!(
        submit(
            &client_a,
            grant_b,
            id,
            &input,
            binding.clone(),
            budget,
            expires
        )
        .unwrap(),
        JobStatus::Pending
    ));
    drop(client_a);
    drop(daemon_a);
    let b_db = rusqlite::Connection::open(path.join("b.db")).unwrap();
    let journal = || {
        b_db.query_row(
            "SELECT count(*) FROM job_effects WHERE id=?1 AND child IS NOT NULL AND result IS NULL",
            [&id.0[..]],
            |row| row.get::<_, u32>(0),
        )
        .unwrap()
    };
    until(|| journal() == 1);
    b_store.collect().unwrap();
    assert!(
        b_store.get(program_b).unwrap().is_some(),
        "queued program must survive collection"
    );
    drop(daemon_b);
    daemon_b = launch("b");

    // Kill the destination inside an update transaction. It must recover the accepted job.
    let locks = rusqlite::Connection::open(&c_db).unwrap();
    locks.busy_timeout(Duration::ZERO).unwrap();
    let writing = || {
        if locks.execute_batch("BEGIN IMMEDIATE").is_err() {
            return true;
        }
        locks.execute_batch("ROLLBACK").unwrap();
        false
    };
    let wait_for_update = || {
        until(|| {
            let running: bool = locks
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM jobs WHERE state=1)",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            running && writing()
        })
    };
    daemon_c = launch("c");
    wait_for_update();
    drop(daemon_c);
    assert_eq!(c_store.reference("counter").unwrap().unwrap().number, 0);

    // Pause B until C commits so the remote result cannot be journaled by B. Reboot both
    // peers. The same child identity must recover the committed result, including its revision.
    // SAFETY: the test owns this live child process. Drop kills and reaps it while stopped.
    assert_eq!(
        unsafe { libc::kill(daemon_b.0.id() as i32, libc::SIGSTOP) },
        0
    );
    daemon_c = launch("c");
    until(|| c_store.reference("counter").unwrap().unwrap().number == 1);
    assert_eq!(journal(), 1);
    drop(daemon_b);
    drop(daemon_c);
    daemon_c = launch("c");
    daemon_b = launch("b");
    let client_a = connect_b("a");
    let client_other = connect_b("stranger");
    assert!(matches!(
        client_other.job_status(id),
        Err(PeerError::Denied)
    ));
    let completed = terminal(&client_a, id);
    assert!(
        matches!(completed, JobStatus::Completed { revision: 0, value, graph }
        if value == json(j!({"local": 6, "remote": 14})) && graph.remote_calls == 1)
    );
    assert!(matches!(
        submit(
            &client_a,
            grant_b,
            id,
            &input,
            binding.clone(),
            budget,
            expires
        )
        .unwrap(),
        JobStatus::Completed { .. }
    ));
    assert!(matches!(
        submit(
            &client_a,
            grant_b,
            id,
            &Data::Nil,
            binding.clone(),
            budget,
            expires
        ),
        Err(PeerError::Value(_))
    ));
    assert_eq!(c_store.reference("counter").unwrap().unwrap().number, 1);

    // The target independently enforces the presenter, token, program, access and graph budget.
    let empty = json(j!({}));
    let deep = json(j!({"calls": 1}));
    let wider = GraphBudget {
        timeout_ms: 1_800,
        calls: 2,
        depth: 2,
    };
    for (ordinal, client, grant, data, capability, allowance) in [
        (
            20,
            &client_other,
            other_grant,
            &empty,
            binding.clone(),
            budget,
        ),
        (
            21,
            &client_a,
            grant_b,
            &empty,
            Binding {
                grant: Hash([99; 32]),
                ..binding.clone()
            },
            budget,
        ),
        (
            22,
            &client_a,
            grant_b,
            &empty,
            Binding {
                program: program_b,
                ..binding.clone()
            },
            budget,
        ),
        (
            23,
            &client_a,
            grant_b,
            &input,
            Binding {
                grant: read_token,
                ..binding.clone()
            },
            budget,
        ),
        (24, &client_a, grant_b, &deep, binding.clone(), wider),
    ] {
        let id = Hash([ordinal; 32]);
        submit(client, grant, id, data, capability, allowance, expires).unwrap();
        assert!(
            matches!(terminal(client, id), JobStatus::Failed(PeerError::Guest(message))
            if message.contains("denied"))
        );
    }

    // A revoked child cannot be recovered by replaying its attenuation request.
    assert!(c_store.revoke(read_token).unwrap());
    assert!(matches!(
        client_c.attenuate(read_grant, b, Access::Read, program_c, leaf, expires),
        Err(PeerError::Denied)
    ));
    assert!(c_store.revoke(grant_c).unwrap());
    let revoked = Hash([25; 32]);
    submit(
        &client_a,
        grant_b,
        revoked,
        &empty,
        binding.clone(),
        budget,
        expires,
    )
    .unwrap();
    assert!(
        matches!(terminal(&client_a, revoked), JobStatus::Failed(PeerError::Guest(message))
        if message.contains("denied"))
    );

    // Lose the acknowledgment after B accepts a submission. The same identity recovers it.
    drop(daemon_c);
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxied = Client::new(proxy.local_addr().unwrap(), "b", &credentials(path, "a")).unwrap();
    let relay = drop_tls_reply(proxy, addresses["b"]);
    let lost = Hash([27; 32]);
    assert!(matches!(
        submit(
            &proxied,
            grant_b,
            lost,
            &empty,
            binding.clone(),
            budget,
            expires
        ),
        Err(PeerError::Io(_))
    ));
    relay.join().unwrap();
    assert!(matches!(
        submit(
            &client_a,
            grant_b,
            lost,
            &empty,
            binding.clone(),
            budget,
            expires
        )
        .unwrap(),
        JobStatus::Pending | JobStatus::Running
    ));
    assert!(matches!(
        client_a.cancel_job(lost).unwrap(),
        JobStatus::Cancelled
    ));

    // A disconnected target keeps jobs pending, within the durable admission quota.
    let expiry = now() + 450;
    let expires_id = Hash([26; 32]);
    submit(
        &client_a,
        grant_b,
        expires_id,
        &empty,
        binding.clone(),
        budget,
        expiry,
    )
    .unwrap();
    assert!(matches!(
        terminal(&client_a, expires_id),
        JobStatus::Expired
    ));
    let enqueue = |n| {
        let mut result = Err(PeerError::Busy);
        until(|| {
            result = submit(
                &client_a,
                grant_b,
                Hash([n; 32]),
                &empty,
                binding.clone(),
                budget,
                expires,
            );
            !matches!(result, Err(PeerError::Busy))
        });
        result
    };
    for n in 50..82 {
        enqueue(n).unwrap();
    }
    assert!(matches!(
        enqueue(82),
        Err(PeerError::Value(message)) if message.contains("active jobs")
    ));
    assert!(matches!(
        client_a.cancel_job(Hash([50; 32])).unwrap(),
        JobStatus::Cancelled
    ));
    enqueue(82).unwrap();
    assert!(matches!(
        client_a.job_status(Hash([50; 32])).unwrap(),
        JobStatus::Cancelled
    ));
    assert!(b_store.revoke(grant_b).unwrap());
    assert!(matches!(
        terminal(&client_a, Hash([82; 32])),
        JobStatus::Failed(PeerError::Denied)
    ));
    assert!(matches!(
        client_a.job_status(id).unwrap(),
        JobStatus::Completed { .. }
    ));
    drop(daemon_b);
}
