use std::collections::BTreeMap;

use pp2::{
    Binary, Block, BlockKind, Cluster, Data, Error, Event, Expr, Grant, Hash, Limits, Link,
    LocalityPolicy, NodeId, Placement, Program, Result, Route, RunReport, StoreAccess,
};

fn put_program(cluster: &mut Cluster, node: NodeId, expr: Expr) -> Hash {
    cluster
        .put(node, &Block::Program(Program::new(expr, vec![])))
        .unwrap()
}

fn put_data(cluster: &mut Cluster, node: NodeId, data: Data) -> Hash {
    cluster.put(node, &Block::Data(data)).unwrap()
}

fn run(cluster: &mut Cluster, node: NodeId, program: Hash, grants: &[Grant]) -> Result<RunReport> {
    cluster.run(
        node,
        program,
        grants,
        Limits::default(),
        LocalityPolicy::default(),
    )
}

fn read_root() -> Expr {
    Expr::Read(
        Box::new(Expr::Cap(0)),
        Box::new(Expr::StoreRoot(Box::new(Expr::Cap(0)))),
    )
}

fn remote(slot: u16, target: Placement) -> Expr {
    Expr::Remote(Box::new(Expr::Cap(slot)), target)
}

fn link(latency_ms: u64, bytes_per_ms: u64, lan: bool) -> Link {
    Link {
        latency_ms,
        bytes_per_ms,
        lan,
    }
}

#[test]
fn content_hash_is_stable_and_lexical_captures_are_portable() {
    let literal = Program::new(Expr::Literal(Data::Int(41)), vec![]);
    assert_eq!(
        literal.hash().unwrap().to_string(),
        "3d2c00177fb5764cad5d6fc4f9b8c6543eaba731e57c23c94122df9739cbd582"
    );
    assert_ne!(
        literal.hash().unwrap(),
        Block::Data(Data::Int(41)).hash().unwrap()
    );
    let program = Program::new(
        Expr::Let(
            Box::new(Expr::Capture(0)),
            Box::new(Expr::Apply(
                Box::new(Expr::Lambda(Box::new(Expr::Binary(
                    Binary::Add,
                    Box::new(Expr::Var(0)),
                    Box::new(Expr::Var(1)),
                )))),
                Box::new(Expr::Literal(Data::Int(1))),
            )),
        ),
        vec![Data::Int(41)],
    );
    let wire = program.to_bytes().unwrap();
    assert_eq!(Program::from_bytes(&wire).unwrap(), program);
    let mut changed = program.clone();
    changed.captures[0] = Data::Int(42);
    assert_ne!(program.hash().unwrap(), changed.hash().unwrap());

    let mut cluster = Cluster::new();
    let a = cluster.add_node().unwrap();
    let b = cluster.add_node().unwrap();
    let hash = program.hash().unwrap();
    cluster.import(a, hash, wire.clone()).unwrap();
    cluster.import(b, hash, wire).unwrap();
    let report = run(&mut cluster, a, hash, &[]).unwrap();
    assert_eq!(report.value, Data::Int(42));
    assert_eq!(run(&mut cluster, b, hash, &[]).unwrap(), report);
}

#[test]
fn record_encoding_is_canonical_and_malformed_frames_fail_closed() {
    let a = ("a".to_owned(), Data::Bool(true));
    let z = ("z".to_owned(), Data::Nil);
    let first = Block::Data(Data::Record(BTreeMap::from([a.clone(), z.clone()])));
    let second = Block::Data(Data::Record(BTreeMap::from([z, a])));
    let bytes = first.to_bytes().unwrap();
    assert_eq!(bytes, second.to_bytes().unwrap());
    assert_eq!(Block::from_bytes(&bytes).unwrap(), first);
    for prefix in 0..bytes.len() {
        assert!(matches!(
            Block::from_bytes(&bytes[..prefix]),
            Err(Error::Wire(_))
        ));
    }
    let mut unsorted = bytes.clone();
    unsorted[14] = b'z';
    unsorted[20] = b'a';
    let mut duplicate = bytes.clone();
    duplicate[20] = b'a';
    let mut trailing = bytes;
    trailing.push(0);
    for frame in [&unsorted, &duplicate, &trailing] {
        assert!(matches!(Block::from_bytes(frame), Err(Error::Wire(_))));
    }
    assert!(matches!(
        Data::from_bytes(b"AEV1\x05\xff\xff\xff\xff"),
        Err(Error::Wire(_))
    ));
    assert!(matches!(
        Data::from_bytes(b"AEV1\x04\0\0\0\x01\xff"),
        Err(Error::Wire(_))
    ));
    assert!(matches!(Data::from_bytes(b"AEV1\x08"), Err(Error::Wire(_))));
    assert!(matches!(
        Program::from_bytes(b"AEB1\x01\0\0\0\0\xff"),
        Err(Error::Wire(_))
    ));
    assert!(matches!(
        Block::from_bytes(&vec![0; Block::MAX_BYTES + 1]),
        Err(Error::Wire(_))
    ));

    let depth = (0..40).fold(Data::Nil, |data, _| Data::List(vec![data]));
    assert!(matches!(depth.to_bytes(), Err(Error::Wire(_))));
}

#[test]
fn missing_capabilities_and_forged_data_confer_no_authority() {
    let mut cluster = Cluster::new();
    let a = cluster.add_node().unwrap();
    let b = cluster.add_node().unwrap();
    let data = put_data(&mut cluster, a, Data::Int(42));
    let hash = Box::new(Expr::Literal(Data::Link(data)));
    let cap = Box::new(Expr::Cap(0));
    let target = Placement {
        node: b,
        data,
        program: data,
    };
    for expr in [
        Expr::Read(cap.clone(), hash.clone()),
        Expr::Pin(cap.clone(), hash.clone()),
        Expr::Clock(cap.clone()),
        Expr::Here(cap.clone()),
        remote(0, target),
        Expr::Log(cap, Box::new(Expr::Literal(Data::Text("test".into())))),
    ] {
        let program = put_program(&mut cluster, a, expr);
        assert_eq!(
            run(&mut cluster, a, program, &[]),
            Err(Error::MissingCapability(0))
        );
    }
    let forged = put_program(&mut cluster, a, Expr::Read(hash.clone(), hash));
    assert_eq!(
        run(&mut cluster, a, forged, &[]),
        Err(Error::Type("a capability handle"))
    );
    let cap_only = put_program(&mut cluster, a, Expr::Cap(0));
    let grant = cluster.grant_store(a, [data], StoreAccess::Read).unwrap();
    assert_eq!(
        run(&mut cluster, a, cap_only, &[grant]),
        Err(Error::Type("portable data"))
    );
    assert_eq!(cluster.events().count(), 0);
}

#[test]
fn attenuation_narrows_hashes_and_permits_no_pin_or_replay() {
    let mut cluster = Cluster::new();
    let a = cluster.add_node().unwrap();
    let b = cluster.add_node().unwrap();
    let public = put_data(&mut cluster, a, Data::Int(42));
    let other = put_data(&mut cluster, a, Data::Int(7));
    let parent = cluster
        .grant_store(a, [public, other], StoreAccess::ReadAndPin)
        .unwrap();
    let child = cluster
        .attenuate_store(a, &parent, [public], StoreAccess::Read)
        .unwrap();
    assert!(matches!(
        cluster.attenuate_store(a, &child, [other], StoreAccess::Read),
        Err(Error::Denied(_))
    ));
    assert!(matches!(
        cluster.attenuate_store(a, &child, [public], StoreAccess::ReadAndPin),
        Err(Error::Denied(_))
    ));

    let read = put_program(&mut cluster, a, read_root());
    assert_eq!(
        run(&mut cluster, a, read, std::slice::from_ref(&child))
            .unwrap()
            .value,
        Data::Int(42)
    );
    let other_read = put_program(
        &mut cluster,
        a,
        Expr::Read(
            Box::new(Expr::Cap(0)),
            Box::new(Expr::Literal(Data::Link(other))),
        ),
    );
    assert!(matches!(
        run(&mut cluster, a, other_read, std::slice::from_ref(&child)),
        Err(Error::Denied(_))
    ));
    let pin = put_program(
        &mut cluster,
        a,
        Expr::Pin(
            Box::new(Expr::Cap(0)),
            Box::new(Expr::Literal(Data::Link(public))),
        ),
    );
    assert!(matches!(
        run(&mut cluster, a, pin, std::slice::from_ref(&child)),
        Err(Error::Denied(_))
    ));
    assert!(matches!(
        run(&mut cluster, b, read, std::slice::from_ref(&child)),
        Err(Error::Denied(_))
    ));
    let mut foreign = Cluster::new();
    assert_eq!(foreign.add_node().unwrap(), a);
    assert!(matches!(
        run(&mut foreign, a, read, &[child]),
        Err(Error::Denied(_))
    ));

    assert_eq!(
        run(&mut cluster, a, pin, &[parent]).unwrap().value,
        Data::Link(public)
    );
    cluster.collect(a).unwrap();
    assert!(cluster.has(a, public).unwrap());
    assert!(!cluster.has(a, other).unwrap());
}

#[test]
fn clock_and_log_are_explicit_and_kind_checked() {
    let mut cluster = Cluster::new();
    let node = cluster.add_node().unwrap();
    let text = "evaluation completed";
    let code = put_program(
        &mut cluster,
        node,
        Expr::Let(
            Box::new(Expr::Log(
                Box::new(Expr::Cap(0)),
                Box::new(Expr::Literal(Data::Text(text.into()))),
            )),
            Box::new(Expr::Clock(Box::new(Expr::Cap(1)))),
        ),
    );
    let clock = cluster.grant_clock(node).unwrap();
    let log = cluster.grant_log(node, "diagnostics").unwrap();
    assert!(matches!(
        run(&mut cluster, node, code, &[clock.clone(), log.clone()]),
        Err(Error::Denied(_))
    ));
    assert_eq!(cluster.events().count(), 0);
    assert_eq!(
        run(&mut cluster, node, code, &[log, clock]).unwrap().value,
        Data::Int(0)
    );
    assert!(
        matches!(cluster.events().next(), Some(Event::Log { stream, message, .. }) if stream.as_ref() == "diagnostics" && message == text)
    );
}

#[test]
fn storage_side_filter_and_fold_exchange_code_and_result_only() {
    let mut cluster = Cluster::new();
    let a = cluster.add_node().unwrap();
    let b = cluster.add_node().unwrap();
    cluster.connect(a, b, link(3, 4096, true)).unwrap();
    let data = put_data(
        &mut cluster,
        b,
        Data::List((1..=512).map(Data::Int).collect()),
    );
    cluster.pin(b, data).unwrap();
    let predicate = Expr::Lambda(Box::new(Expr::Binary(
        Binary::Greater,
        Box::new(Expr::Var(0)),
        Box::new(Expr::Capture(0)),
    )));
    let filtered = Expr::Filter(Box::new(read_root()), Box::new(predicate));
    let step = Expr::Lambda(Box::new(Expr::Lambda(Box::new(Expr::Binary(
        Binary::Add,
        Box::new(Expr::Var(1)),
        Box::new(Expr::Var(0)),
    )))));
    let code = Program::new(
        Expr::Fold(
            Box::new(filtered),
            Box::new(Expr::Literal(Data::Int(0))),
            Box::new(step),
        ),
        vec![Data::Int(510)],
    );
    let code_bytes = code.to_bytes().unwrap().len();
    let program = cluster.put(a, &Block::Program(code)).unwrap();
    cluster.gossip_round();
    let target = Placement {
        node: b,
        data,
        program,
    };
    let driver = put_program(&mut cluster, a, remote(0, target));
    let grant = cluster.grant_net(a, &[Route::new(target, vec![])]).unwrap();
    let report = run(&mut cluster, a, driver, &[grant]).unwrap();
    assert_eq!(report.value, Data::Int(1023));
    assert_eq!(report.elapsed_ms, 12);
    assert!(!cluster.has(a, data).unwrap());
    assert!(cluster.has(b, program).unwrap());
    let events: Vec<_> = cluster.events().collect();
    assert_eq!(events.len(), 3);
    assert_eq!(
        events[0],
        &Event::EvalRequest {
            from: a,
            to: b,
            data,
            program,
            bytes: 70
        }
    );
    assert_eq!(
        events[1],
        &Event::BlockTransfer {
            from: a,
            to: b,
            hash: program,
            kind: BlockKind::Program,
            bytes: code_bytes,
            elapsed_ms: 4
        }
    );
    assert_eq!(
        events[2],
        &Event::EvalReply {
            from: b,
            to: a,
            bytes: 13
        }
    );
}

#[test]
fn remote_data_must_be_resident_and_remote_grants_cannot_pin() {
    let mut cluster = Cluster::new();
    let a = cluster.add_node().unwrap();
    let b = cluster.add_node().unwrap();
    cluster.connect(a, b, link(2, 8192, true)).unwrap();
    let data = put_data(&mut cluster, a, Data::Int(1));
    let request_pin = Expr::Pin(
        Box::new(Expr::Cap(0)),
        Box::new(Expr::StoreRoot(Box::new(Expr::Cap(0)))),
    );
    let program = put_program(&mut cluster, b, request_pin);
    let target = Placement {
        node: b,
        data,
        program,
    };
    let driver = put_program(&mut cluster, a, remote(0, target));
    let grant = cluster.grant_net(a, &[Route::new(target, vec![])]).unwrap();
    cluster.gossip_round();
    assert_eq!(
        run(&mut cluster, a, driver, std::slice::from_ref(&grant)),
        Err(Error::MissingBlock {
            node: b,
            hash: data
        })
    );
    assert!(!cluster.has(b, data).unwrap());
    assert_eq!(cluster.fetch(b, data).unwrap(), Some(a));
    assert!(matches!(
        run(&mut cluster, a, driver, &[grant]),
        Err(Error::Denied(_))
    ));
    assert!(cluster.collect(b).unwrap().contains(&data));
}

#[test]
fn delegation_is_exact_and_locality_rejects_a_nested_wan_request() {
    let mut cluster = Cluster::new();
    let a = cluster.add_node().unwrap();
    let b = cluster.add_node().unwrap();
    let c = cluster.add_node().unwrap();
    cluster.connect(a, b, link(3, 4096, true)).unwrap();
    cluster.connect(b, c, link(120, 4096, false)).unwrap();
    let c_target = Placement {
        node: c,
        data: put_data(&mut cluster, c, Data::Int(20)),
        program: put_program(&mut cluster, c, read_root()),
    };
    let b_target = Placement {
        node: b,
        data: put_data(&mut cluster, b, Data::Int(1)),
        program: put_program(&mut cluster, b, remote(1, c_target)),
    };
    let driver = put_program(&mut cluster, a, remote(0, b_target));
    let no_delegation = cluster
        .grant_net(a, &[Route::new(b_target, vec![])])
        .unwrap();
    assert_eq!(
        run(&mut cluster, a, driver, &[no_delegation]),
        Err(Error::MissingCapability(1))
    );
    let wrong_target = Placement {
        data: b_target.data,
        ..c_target
    };
    let wrong_route = cluster
        .grant_net(
            a,
            &[Route::new(b_target, vec![Route::new(wrong_target, vec![])])],
        )
        .unwrap();
    assert!(matches!(
        run(&mut cluster, a, driver, &[wrong_route]),
        Err(Error::Denied(_))
    ));
    cluster.clear_events();
    let routes = cluster
        .grant_net(
            a,
            &[Route::new(b_target, vec![Route::new(c_target, vec![])])],
        )
        .unwrap();
    assert_eq!(
        run(&mut cluster, a, driver, std::slice::from_ref(&routes)),
        Err(Error::Locality {
            from: b,
            to: c,
            hops: 2,
            rtt_ms: 246
        })
    );
    assert_eq!(cluster.events().count(), 1);
    assert!(
        matches!(cluster.events().next(), Some(Event::EvalRequest { from, to, .. }) if *from == a && *to == b)
    );
    let overridden = LocalityPolicy {
        max_hops: 2,
        max_chain_rtt_ms: 246,
    };
    assert_eq!(
        cluster
            .run(a, driver, &[routes], Limits::default(), overridden)
            .unwrap()
            .value,
        Data::Int(20)
    );
}

#[test]
fn metering_covers_recursive_reductions_allocations_and_transport() {
    let mut cluster = Cluster::new();
    let a = cluster.add_node().unwrap();
    let b = cluster.add_node().unwrap();
    cluster.connect(a, b, link(30, 4096, false)).unwrap();
    let self_call = Expr::Lambda(Box::new(Expr::Apply(
        Box::new(Expr::Var(0)),
        Box::new(Expr::Var(0)),
    )));
    let recursion = put_program(
        &mut cluster,
        a,
        Expr::Apply(Box::new(self_call.clone()), Box::new(self_call)),
    );
    let defaults = Limits::default();
    let policy = LocalityPolicy::default();
    assert_eq!(run(&mut cluster, a, recursion, &[]), Err(Error::Stack));
    assert_eq!(
        cluster.run(
            a,
            recursion,
            &[],
            Limits {
                fuel: 12,
                ..defaults
            },
            policy
        ),
        Err(Error::Fuel)
    );
    assert_eq!(
        cluster.run(
            a,
            recursion,
            &[],
            Limits {
                memory_bytes: 1,
                ..defaults
            },
            policy
        ),
        Err(Error::Memory)
    );
    assert_eq!(
        cluster.run(
            a,
            recursion,
            &[],
            Limits {
                timeout_ms: 0,
                ..defaults
            },
            policy
        ),
        Err(Error::Timeout)
    );

    let target = Placement {
        node: b,
        data: put_data(&mut cluster, b, Data::Int(1)),
        program: put_program(&mut cluster, b, read_root()),
    };
    let grant = cluster.grant_net(a, &[Route::new(target, vec![])]).unwrap();
    let driver = put_program(&mut cluster, a, remote(0, target));
    let destination_grant = cluster
        .grant_store(b, [target.data], StoreAccess::Read)
        .unwrap();
    let destination = run(&mut cluster, b, target.program, &[destination_grant]).unwrap();
    let chain_limits = Limits {
        fuel: destination.fuel_used,
        ..defaults
    };
    assert_eq!(
        cluster.run(
            a,
            driver,
            std::slice::from_ref(&grant),
            chain_limits,
            policy
        ),
        Err(Error::Fuel)
    );
    assert!(
        cluster
            .events()
            .all(|event| !matches!(event, Event::EvalReply { .. }))
    );
    cluster.clear_events();
    assert_eq!(
        cluster.run(
            a,
            driver,
            &[grant],
            Limits {
                timeout_ms: 50,
                ..defaults
            },
            policy
        ),
        Err(Error::Timeout)
    );
    assert!(matches!(
        cluster.events().next(),
        Some(Event::EvalRequest { .. })
    ));
    assert_eq!(cluster.events().count(), 1);
}

#[test]
fn closure_chains_can_be_released_without_recursive_heap_destruction() {
    let mut cluster = Cluster::new();
    let node = cluster.add_node().unwrap();
    let step = Expr::Lambda(Box::new(Expr::Lambda(Box::new(Expr::Lambda(Box::new(
        Expr::Var(2),
    ))))));
    let fold = Expr::Fold(
        Box::new(Expr::Literal(Data::List(vec![Data::Nil; 12_000]))),
        Box::new(Expr::Lambda(Box::new(Expr::Var(0)))),
        Box::new(step),
    );
    let code = put_program(
        &mut cluster,
        node,
        Expr::Let(Box::new(fold), Box::new(Expr::Literal(Data::Int(1)))),
    );
    assert_eq!(
        run(&mut cluster, node, code, &[]).unwrap().value,
        Data::Int(1)
    );
}

#[test]
fn gossip_relays_inventory_and_withdrawals_across_two_edges() {
    let mut cluster = Cluster::new();
    let a = cluster.add_node().unwrap();
    let b = cluster.add_node().unwrap();
    let c = cluster.add_node().unwrap();
    cluster.connect(a, b, link(2, 1024, true)).unwrap();
    cluster.connect(b, c, link(3, 1024, true)).unwrap();
    let data = put_data(&mut cluster, c, Data::Int(42));
    cluster.gossip_round();
    assert!(cluster.advertised_peers(a, data).unwrap().is_empty());
    cluster.gossip_round();
    assert_eq!(cluster.advertised_peers(a, data).unwrap(), vec![c]);
    assert_eq!(
        cluster.fetch(a, data),
        Err(Error::UnavailableBlock {
            node: a,
            hash: data
        })
    );
    assert_eq!(cluster.fetch(b, data).unwrap(), Some(c));
    assert_eq!(cluster.collect(c).unwrap(), vec![data]);
    cluster.gossip_round();
    cluster.gossip_round();
    assert_eq!(cluster.advertised_peers(a, data).unwrap(), vec![b]);
    assert_eq!(cluster.fetch(a, data).unwrap(), Some(b));
    assert_eq!(cluster.fetch(a, data).unwrap(), None);
}

#[test]
fn peer_selection_accounts_for_bandwidth_and_falls_back_after_collection() {
    let mut cluster = Cluster::new();
    let a = cluster.add_node().unwrap();
    let lan = cluster.add_node().unwrap();
    let wan = cluster.add_node().unwrap();
    cluster.connect(a, lan, link(1, 64, true)).unwrap();
    cluster.connect(a, wan, link(30, 1024, false)).unwrap();
    let large = Block::Data(Data::Text("block".repeat(2000)));
    let large_hash = cluster.put(lan, &large).unwrap();
    assert_eq!(cluster.put(wan, &large).unwrap(), large_hash);
    let small = put_data(&mut cluster, lan, Data::Int(42));
    assert_eq!(put_data(&mut cluster, wan, Data::Int(42)), small);
    cluster.gossip_round();
    assert_eq!(cluster.fetch(a, large_hash).unwrap(), Some(wan));
    assert_eq!(cluster.fetch(a, small).unwrap(), Some(lan));
    assert_eq!(cluster.fetch(a, large_hash).unwrap(), None);
    cluster.collect(a).unwrap();
    cluster.collect(lan).unwrap();
    assert_eq!(cluster.advertised_peers(a, small).unwrap(), vec![lan, wan]);
    assert_eq!(cluster.fetch(a, small).unwrap(), Some(wan));

    let bytes = large.to_bytes().unwrap();
    assert!(
        matches!(cluster.import(a, small, bytes), Err(Error::Integrity { expected, actual }) if expected == small && actual == large_hash)
    );
}

#[test]
fn gc_keeps_merkle_dependencies_and_active_capability_roots() {
    let mut cluster = Cluster::new();
    let node = cluster.add_node().unwrap();
    let missing_block = Block::Data(Data::Text("child".into()));
    let child = missing_block.hash().unwrap();
    let root = put_data(&mut cluster, node, Data::List(vec![Data::Link(child)]));
    let other = put_data(&mut cluster, node, Data::Int(42));
    let program = Program::new(Expr::Literal(Data::Link(root)), vec![Data::Link(other)]);
    let code = cluster.put(node, &Block::Program(program)).unwrap();
    assert_eq!(
        cluster.pin(node, code),
        Err(Error::IncompleteGraph {
            node,
            missing: child
        })
    );
    assert!(matches!(
        cluster.grant_store(node, [root], StoreAccess::Read),
        Err(Error::IncompleteGraph { .. })
    ));
    assert_eq!(cluster.put(node, &missing_block).unwrap(), child);
    cluster.pin(node, code).unwrap();
    let active = cluster
        .grant_store(node, [root], StoreAccess::Read)
        .unwrap();
    let garbage = put_data(&mut cluster, node, Data::Int(1));
    assert_eq!(cluster.collect(node).unwrap(), vec![garbage]);
    assert!(cluster.unpin(node, code).unwrap());
    let removed = cluster.collect(node).unwrap();
    assert_eq!(removed.len(), 2);
    assert!(removed.contains(&other) && removed.contains(&code));
    assert!(cluster.has(node, root).unwrap() && cluster.has(node, child).unwrap());
    drop(active);
    let removed = cluster.collect(node).unwrap();
    assert_eq!(removed.len(), 2);
    assert!(removed.contains(&root) && removed.contains(&child));
}
