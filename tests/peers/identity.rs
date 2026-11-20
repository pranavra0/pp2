use super::*;

#[test]
fn a_bound_read_prefers_an_authorized_replica_and_survives_owner_loss() {
    use pp2::peer::{
        Binding, BindingSet, DurableEvaluation, GraphBudget, GraphEvaluation, JobStatus,
        PeerEndpoint, ReplicaAccess, ResourceMode, Server,
    };
    use serde_json::json as j;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path();
    certificates(path);
    let creds = credentials(path, "server");
    let settings = DiscoveryConfig {
        lan: false,
        ..Default::default()
    };
    let network = |name: &str| {
        let dir = path.join(name);
        fs::create_dir(&dir).unwrap();
        fs::copy(&creds.certificate, dir.join("peer.pem")).unwrap();
        fs::copy(&creds.key, dir.join("peer.key")).unwrap();
        let key = dir.join("identity.key");
        PeerIdentity::generate(&key).unwrap();
        fs::write(
            dir.join("discovery.json"),
            serde_json::to_vec(&settings).unwrap(),
        )
        .unwrap();
        PeerNetwork::new(PeerIdentity::load(key).unwrap(), settings.clone()).unwrap()
    };
    let owner = network("owner");
    let replica = network("replica");
    let caller = network("caller");
    let worker = env!("CARGO_BIN_EXE_pp2");
    let launch = |name: &str, db: &Path, config: Option<&Path>| {
        Daemon::from_child(
            Command::new(worker)
                .args(["peer", "serve-network"])
                .arg(db)
                .arg("127.0.0.1:0")
                .arg(path.join(name))
                .args(config)
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        )
    };
    let owner_db = path.join("owner.db");
    let replica_db = path.join("replica.db");
    let mut origin = PeerStore::open(&owner_db).unwrap();
    let mut copy = PeerStore::open(&replica_db).unwrap();
    let owner_key = PeerIdentity::load(path.join("owner/identity.key")).unwrap();
    origin
        .create_collection("stock", [Ok(("lamp".into(), Data::Int(7)))])
        .unwrap();
    let source = r#"export default async ({storage}, input) => {
        if (input !== null) await storage.put('lamp', input);
        return (await storage.get('lamp')).value;
    }"#;
    let query = pack(&mut origin, source, BTreeSet::new());
    assert_eq!(pack(&mut copy, source, BTreeSet::new()), query);
    origin.publish(query).unwrap();
    copy.publish(query).unwrap();
    let resource = origin
        .share_replica(&owner_key, "stock", ResourceMode::SingleWriter)
        .unwrap();
    origin
        .approve_replica(
            &owner_key,
            resource,
            replica.id(),
            ReplicaAccess::Read,
            Some(query),
        )
        .unwrap();
    copy.follow_replica(replica.id(), owner.id(), resource, "mirror")
        .unwrap();
    let primary = Binding {
        peer: owner.id(),
        grant: origin
            .issue("stock", replica.id(), Access::Read, Some(query))
            .unwrap(),
        program: query,
        access: Access::Read,
    };
    let owner_daemon = launch("owner", &owner_db, None);
    let owner_client = Client::for_peer(&replica, owner.id(), Some(owner_daemon.1));
    while owner_client
        .sync_replica(&mut copy, resource)
        .unwrap()
        .pending
    {}
    let initial_head = copy.replica_status(resource).unwrap().heads[0];
    let local_grant = copy
        .issue("mirror", replica.id(), Access::Read, Some(query))
        .unwrap();
    let wrong_grant = copy.issue_compute(replica.id(), query).unwrap();
    assert!(matches!(
        copy.prefer_replica_reads(replica.id(), &primary, resource, wrong_grant),
        Err(PeerError::Denied)
    ));
    copy.prefer_replica_reads(replica.id(), &primary, resource, local_grant)
        .unwrap();

    let entry = pack(
        &mut copy,
        r#"
        export default async ({capabilities, evaluate}, consistency) =>
            evaluate(capabilities.stock, null, {consistency});
    "#,
        BTreeSet::new(),
    );
    copy.publish(entry).unwrap();
    let local_entry = copy.issue_compute(replica.id(), entry).unwrap();
    let caller_entry = copy.issue_compute(caller.id(), entry).unwrap();
    let sets = [replica.id(), caller.id()]
        .into_iter()
        .zip([local_entry, caller_entry])
        .map(|(holder, grant)| BindingSet {
            holder,
            grant,
            program: entry,
            capabilities: BTreeMap::from([("stock".into(), primary.clone())]),
        })
        .collect::<Vec<_>>();
    let peers = vec![PeerEndpoint {
        address: owner_daemon.1,
        name: String::new(),
        fingerprint: owner.id(),
    }];
    let config = path.join("bindings.json");
    fs::write(
        &config,
        serde_json::to_vec(&j!({"bindings": sets, "peers": peers})).unwrap(),
    )
    .unwrap();
    let local = Server::new_discovered(&replica_db, worker, &creds, replica.clone())
        .unwrap()
        .with_graph(&creds, sets, peers)
        .unwrap();
    let names = ["stock".into()];
    let budget = GraphBudget {
        timeout_ms: 3000,
        calls: 1,
        depth: 1,
    };
    assert!(matches!(
        owner_client.run_graph(
            GraphEvaluation {
                evaluation: Evaluation {
                    grant: primary.grant,
                    program: query,
                    packages: None,
                    input: &Data::Nil,
                    mode: EvaluationMode::ReadResource {
                        resource: Hash::digest(b"different resource"),
                        consistency: peer::Consistency::Replica,
                    },
                },
                budget: GraphBudget {
                    calls: 0,
                    depth: 0,
                    ..budget
                },
                bindings: &[],
            },
            None
        ),
        Err(PeerError::Denied)
    ));
    let invocation = |grant| GraphEvaluation {
        evaluation: Evaluation {
            grant,
            program: entry,
            packages: None,
            input: &Data::Nil,
            mode: EvaluationMode::Read,
        },
        budget,
        bindings: &names,
    };
    let read = |consistency: &str, value, remote_calls| {
        let request = invocation(local_entry);
        let report = local
            .evaluate_local(GraphEvaluation {
                evaluation: Evaluation {
                    input: &Data::Text(consistency.into()),
                    ..request.evaluation
                },
                ..request
            })
            .unwrap();
        let data = peer::data_to_json(&report.value).unwrap();
        assert_eq!(data["value"], j!(value));
        assert_eq!(data["view"]["resource"], j!(resource.to_string()));
        assert_eq!(report.graph.remote_calls, remote_calls);
    };
    read("replica", 7, 0);
    assert!(copy.revoke(local_grant).unwrap());
    read("replica", 7, 1);
    let local_grant = copy
        .issue("mirror", replica.id(), Access::Read, Some(query))
        .unwrap();
    copy.prefer_replica_reads(replica.id(), &primary, resource, local_grant)
        .unwrap();

    let writer = origin
        .issue("stock", owner.id(), Access::Write, Some(query))
        .unwrap();
    let owner_server = Server::new_discovered(&owner_db, worker, &creds, owner.clone()).unwrap();
    let written = owner_server
        .evaluate_local(GraphEvaluation {
            evaluation: Evaluation {
                grant: writer,
                program: query,
                packages: None,
                input: &Data::Int(12),
                mode: EvaluationMode::Update {
                    expected_revision: 0,
                    operation: Hash::digest(b"restock"),
                },
            },
            budget: GraphBudget {
                calls: 0,
                depth: 0,
                ..budget
            },
            bindings: &[],
        })
        .unwrap();
    let next = written.view.unwrap().revision.unwrap().to_string();
    read("authoritative", 12, 1);
    read(&next, 12, 1);
    read(&initial_head.to_string(), 7, 0);
    while owner_client
        .sync_replica(&mut copy, resource)
        .unwrap()
        .pending
    {}
    drop(owner_daemon);
    read("replica", 12, 0);
    read(&next, 12, 0);

    let replica_daemon = launch("replica", &replica_db, Some(&config));
    let client = Client::for_peer(&caller, replica.id(), Some(replica_daemon.1));
    let id = Hash::digest(b"offline job");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let input = Data::Text("replica".into());
    let request = invocation(caller_entry);
    client
        .submit_job(DurableEvaluation {
            id,
            expires_at_ms: now.as_millis() as u64 + 10000,
            graph: GraphEvaluation {
                evaluation: Evaluation {
                    input: &input,
                    ..request.evaluation
                },
                ..request
            },
        })
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match client.job_status(id).unwrap() {
            JobStatus::Pending | JobStatus::Running if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(25));
            }
            JobStatus::Completed { value, graph, .. } => {
                assert_eq!(peer::data_to_json(&value).unwrap()["value"], j!(12));
                assert_eq!(graph.remote_calls, 0);
                assert_eq!(graph.remote_request_bytes, 0);
                break;
            }
            status => panic!("unexpected job status {status:?}"),
        }
    }
}

#[test]
fn database_identity_rejects_unrelated_files() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("unrelated.db");
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
fn stable_grant_survives_transport_certificate_replacement_and_respects_identity_revocation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    certificates(path);
    let database = path.join("storage.db");
    let server_id = PeerIdentity::generate(path.join("identity.key")).unwrap();
    let caller_key = path.join("caller.key");
    let caller_id = PeerIdentity::generate(&caller_key).unwrap();
    let caller = PeerNetwork::new(
        PeerIdentity::load(caller_key).unwrap(),
        DiscoveryConfig {
            lan: false,
            ..Default::default()
        },
    )
    .unwrap();

    let mut store = PeerStore::open(&database).unwrap();
    let revision = store.create_ref("private", &Data::Int(7)).unwrap();
    let program = pack(
        &mut store,
        "export default state => state;",
        BTreeSet::new(),
    );
    store.publish(program).unwrap();
    let grant = store
        .issue("private", caller_id, Access::Read, Some(program))
        .unwrap();
    let launch = |certificate: &str, revoked: BTreeSet<Hash>| {
        fs::copy(
            path.join(format!("{certificate}.pem")),
            path.join("peer.pem"),
        )
        .unwrap();
        fs::copy(
            path.join(format!("{certificate}.key")),
            path.join("peer.key"),
        )
        .unwrap();
        let settings = DiscoveryConfig {
            lan: false,
            revoked,
            ..Default::default()
        };
        fs::write(
            path.join("discovery.json"),
            serde_json::to_vec(&settings).unwrap(),
        )
        .unwrap();
        Daemon::from_child(
            Command::new(env!("CARGO_BIN_EXE_pp2"))
                .args(["peer", "serve-network"])
                .arg(&database)
                .arg("127.0.0.1:0")
                .arg(path)
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        )
    };
    for certificate in ["server", "rogue"] {
        let daemon = launch(certificate, BTreeSet::new());
        let client = Client::for_peer(&caller, server_id, Some(daemon.1));
        assert_eq!(
            run(
                &client,
                grant,
                program,
                None,
                &Data::Nil,
                EvaluationMode::Read
            )
            .unwrap()
            .value,
            Data::Int(7),
        );
        assert!(
            matches!(client.fetch(revision.hash), Err(PeerError::Missing(hash)) if hash == revision.hash)
        );
        let wrong_peer = Client::for_peer(&caller, caller_id, Some(daemon.1));
        assert!(
            matches!(wrong_peer.fetch(program), Err(PeerError::PeerUnavailable(id)) if id == caller_id)
        );
    }

    let daemon = launch("rogue", BTreeSet::from([caller_id]));
    let client = Client::for_peer(&caller, server_id, Some(daemon.1));
    assert!(matches!(
        run(
            &client,
            grant,
            program,
            None,
            &Data::Nil,
            EvaluationMode::Read
        ),
        Err(PeerError::Denied),
    ));
}

#[test]
fn version_one_databases_keep_their_snapshot_references() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("old.db");
    let mut store = PeerStore::open(&database).unwrap();
    let revision = store.create_ref("old", &Data::Int(71)).unwrap();
    drop(store);
    {
        let old = rusqlite::Connection::open(&database).unwrap();
        old.execute_batch(
            "DROP TABLE replica_reads; DROP TABLE replica_private; DROP TABLE replica_pending; DROP TABLE replica_routes; DROP TABLE replica_parents;
             DROP TABLE replica_versions; DROP TABLE replicas; DROP INDEX edges_child;
             ALTER TABLE receipts DROP COLUMN view; ALTER TABLE jobs DROP COLUMN replica_grant;
             DROP TABLE native_bindings; DROP TABLE native_installations; DROP TABLE host_resources;
             DROP TABLE job_effects; DROP TABLE job_blocks; DROP TABLE jobs;
             DROP VIEW subscription_authority; DROP TABLE subscriptions;
             DROP TABLE applications; DROP TABLE change_events; DROP TABLE reaction_writers;
             DROP TABLE graph_forward_replays; DROP TABLE graph_grants;
             DROP TABLE entries; DROP TABLE collections; PRAGMA user_version = 1;",
        )
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

// Relay a TLS 1.3 handshake, then suppress the server's first reply. The client completes
// the handshake before sending its request. Receiving the withheld record proves it was handled.
