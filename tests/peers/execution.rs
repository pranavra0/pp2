use super::*;

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
