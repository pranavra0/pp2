use super::*;

#[test]
fn indexed_effects_are_bounded_and_commit_with_their_receipt() {
    use pp2::peer::{GraphBudget, GraphEvaluation};
    use serde_json::json as j;

    let temp = tempfile::tempdir().unwrap();
    certificates(temp.path());
    let db = temp.path().join("collection.db");
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
    let holder = Credentials::fingerprint(temp.path().join("writer.pem")).unwrap();
    let read = store
        .issue("stock", holder, Access::Read, Some(program))
        .unwrap();
    let write = store
        .issue("stock", holder, Access::Write, Some(program))
        .unwrap();
    let daemon = Daemon::launch(temp.path(), &db);
    let client = client(temp.path(), &daemon, "writer");
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
    let daemon = Daemon::launch(temp.path(), &db);
    let client = Client::new(daemon.1, "localhost", &credentials(temp.path(), "writer")).unwrap();
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
