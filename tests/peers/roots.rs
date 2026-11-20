use super::*;

#[test]
fn ordered_map_evaluates_at_home_with_atomic_roots_and_private_links() {
    use pp2::peer::{DurableEvaluation, GraphBudget, GraphEvaluation, JobStatus, Server};
    use serde_json::json as j;

    let temp = tempfile::tempdir().unwrap();
    certificates(temp.path());
    let db = temp.path().join("map.db");
    let mut store = PeerStore::open(&db).unwrap();
    let initial = store.create_ref("map", &Data::Nil).unwrap();
    let private = store
        .create_ref("private", &Data::Text("private elsewhere".into()))
        .unwrap();
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/ordered-map");
    let library = pack(
        &mut store,
        peer::compile_typescript(&example.join("map.ts"), &BTreeMap::new()).unwrap(),
        BTreeSet::new(),
    );
    let entry = pack(
        &mut store,
        peer::compile_typescript(
            &example.join("entry.ts"),
            &BTreeMap::from([("./map.js".into(), library)]),
        )
        .unwrap(),
        BTreeSet::from([library]),
    );
    let program = pack(
        &mut store,
        format!(
            r#"import map from 'pp2:{entry}';
            export default async (pp2, input) => {{
                if (input.type === 'probe') return pp2.blocks.read(input.hash);
                if (input.type === 'abort') {{
                    await pp2.blocks.setRoot(await pp2.blocks.write('discard'));
                    throw new Error('discard');
                }}
                if (input.type === 'batch') {{
                    for (const [key, value] of input.entries) {{
                        await map(pp2, {{type: 'put', key, value}});
                    }}
                    return true;
                }}
                return map(pp2, input);
            }};"#
        ),
        BTreeSet::from([entry]),
    );
    store.publish_all(&[program, entry, library]).unwrap();
    let server_cert = credentials(temp.path(), "server");
    let local_id = Credentials::fingerprint(&server_cert.certificate).unwrap();
    let remote_id = Credentials::fingerprint(temp.path().join("writer.pem")).unwrap();
    let local = store
        .issue("map", local_id, Access::Write, Some(program))
        .unwrap();
    let remote = store
        .issue("map", remote_id, Access::Write, Some(program))
        .unwrap();
    fn request(
        grant: Hash,
        program: Hash,
        input: &Data,
        mode: EvaluationMode,
    ) -> GraphEvaluation<'_> {
        GraphEvaluation {
            evaluation: Evaluation {
                grant,
                program,
                packages: None,
                input,
                mode,
            },
            budget: GraphBudget {
                timeout_ms: 3000,
                calls: 0,
                depth: 0,
            },
            bindings: &[],
        }
    }
    let update = |revision| EvaluationMode::Update {
        expected_revision: revision,
        operation: Hash::digest(&revision.to_be_bytes()),
    };
    let server = Server::new(&db, env!("CARGO_BIN_EXE_pp2"), &server_cert).unwrap();
    let first =
        json(j!({"type":"batch","entries":[["delta",4],["alpha",null],["charlie",3],["bravo",2]]}));
    let report = server
        .evaluate_local(request(local, program, &first, update(0)))
        .unwrap();
    assert_eq!(report.revision, 1);
    assert_eq!(report.request_bytes, 0);
    let one = store.reference("map").unwrap().unwrap();
    assert_ne!(one.hash, initial.hash);

    let daemon = Daemon::launch(temp.path(), &db);
    let client = client(temp.path(), &daemon, "writer");
    let invoke = |input, mode| client.run_graph(request(remote, program, &json(input), mode), None);
    let abort = j!({"type":"abort"});
    assert!(
        matches!(invoke(abort, update(1)), Err(PeerError::Guest(message)) if message.contains("discard"))
    );
    assert_eq!(store.reference("map").unwrap(), Some(one));
    let discarded = Block::Data(Data::Text("discard".into())).hash().unwrap();
    assert!(store.get(discarded).unwrap().is_none());

    for hash in [private.hash, discarded] {
        assert!(matches!(
            invoke(j!({"type":"probe","hash":hash.to_string()}), EvaluationMode::Read),
            Err(PeerError::Guest(message)) if message.contains("denied")
        ));
    }
    assert!(matches!(client.fetch(one.hash), Err(PeerError::Missing(_))));
    let scan = invoke(j!({"type":"scan","limit":2}), EvaluationMode::Read).unwrap();
    assert_eq!(
        scan.value,
        json(j!({"entries":[["alpha",null],["bravo",2]],"next":"bravo"}))
    );
    assert_eq!(
        invoke(
            j!({"type":"scan","after":"bravo","before":"delta"}),
            EvaluationMode::Read
        )
        .unwrap()
        .value,
        json(j!({"entries":[["charlie",3]],"next":null}))
    );

    let removal = j!({"type":"remove","key":"charlie"});
    assert_eq!(
        invoke(removal.clone(), update(1)).unwrap().value,
        Data::Bool(true)
    );
    let fourth = json(j!({"type":"put","key":"echo","value":5}));
    let job_id = Hash([99; 32]);
    let status = client
        .submit_job(DurableEvaluation {
            id: job_id,
            expires_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
                + 10_000,
            graph: request(remote, program, &fourth, update(2)),
        })
        .unwrap();
    assert!(matches!(status, JobStatus::Pending));
    let started = Instant::now();
    loop {
        match client.job_status(job_id).unwrap() {
            JobStatus::Completed {
                revision: 3,
                value: Data::Bool(true),
                ..
            } => break,
            JobStatus::Pending | JobStatus::Running
                if started.elapsed() < Duration::from_secs(5) =>
            {
                thread::sleep(Duration::from_millis(20));
            }
            status => panic!("root update job failed: {status:?}"),
        }
    }

    drop(daemon);
    store.collect().unwrap();
    assert!(store.get(one.hash).unwrap().is_none());
    let daemon = Daemon::launch(temp.path(), &db);
    let client = Client::new(daemon.1, "localhost", &credentials(temp.path(), "writer")).unwrap();
    let replay = client
        .run_graph(request(remote, program, &json(removal), update(1)), None)
        .unwrap();
    assert_eq!(replay.revision, 2);
    assert_eq!(replay.value, Data::Bool(true));
    assert_eq!(replay.graph.storage_effects, 0);
    let current = client
        .run_graph(
            request(
                remote,
                program,
                &json(j!({"type":"scan"})),
                EvaluationMode::Read,
            ),
            None,
        )
        .unwrap();
    assert_eq!(current.revision, 3);
    assert_eq!(
        current.value,
        json(j!({"entries":[["alpha",null],["bravo",2],["delta",4],["echo",5]],"next":null}))
    );
    let head = store.reference("map").unwrap().unwrap().hash;
    let mut cache = PeerStore::open(":memory:").unwrap();
    store.publish(head).unwrap();
    assert!(matches!(
        Client::fetch_graph(&mut cache, std::slice::from_ref(&client), head),
        Err(PeerError::Missing(_))
    ));
    assert!(cache.get(head).unwrap().is_none());
    store.publish_graph(head).unwrap();
    let graph = Client::fetch_graph(&mut cache, std::slice::from_ref(&client), head).unwrap();
    assert_eq!(graph.len(), 4);
    let Block::Data(root) = Block::from_bytes(&cache.get(head).unwrap().unwrap()).unwrap() else {
        panic!("expected a data block");
    };
    assert_eq!(cache.create_ref("copy", &root).unwrap().hash, head);
    assert!(matches!(
        client.fetch(private.hash),
        Err(PeerError::Missing(_))
    ));
}
