use std::{collections::BTreeMap, error::Error as StdError};

use pp2::{
    Binary, Block, BlockKind, Cluster, Data, Error, Event, Expr, Grant, Hash, Limits, Link,
    LocalityPolicy, NodeId, Placement, Program, Result, Route, RunReport, StoreAccess,
};

type Scenario = fn() -> Result<()>;

pub fn run(selected: Option<&str>) -> std::result::Result<(), Box<dyn StdError>> {
    let scenarios: [(&str, Scenario); 5] = [
        ("sandbox", sandbox),
        ("placement", placement),
        ("locality", locality),
        ("gossip", gossip),
        ("gc", gc),
    ];
    if let Some(name) = selected {
        let (_, scenario) = scenarios
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .ok_or("unknown scenario (choose sandbox, placement, locality, gossip, or gc)")?;
        scenario()?;
    } else {
        for (_, scenario) in scenarios {
            scenario()?;
            println!();
        }
    }
    Ok(())
}

fn store_program(cluster: &mut Cluster, node: NodeId, expr: Expr) -> Result<Hash> {
    cluster.put(node, &Block::Program(Program::new(expr, Vec::new())))
}

fn execute(cluster: &mut Cluster, node: NodeId, hash: Hash, grants: &[Grant]) -> Result<RunReport> {
    cluster.run(
        node,
        hash,
        grants,
        Limits::default(),
        LocalityPolicy::default(),
    )
}

fn sandbox() -> Result<()> {
    let mut cluster = Cluster::new();
    let a = cluster.add_node()?;
    let b = cluster.add_node()?;
    let data = cluster.put(a, &Block::Data(Data::Int(7)))?;
    let target = Placement {
        node: b,
        data,
        program: data,
    };
    let hash = Expr::Literal(Data::Link(data));
    let read = Expr::Read(Box::new(Expr::Cap(0)), Box::new(hash.clone()));
    let attempts = [
        ("store read", read.clone()),
        (
            "remote evaluation",
            Expr::Remote(Box::new(Expr::Cap(0)), target),
        ),
        ("clock read", Expr::Clock(Box::new(Expr::Cap(0)))),
        (
            "log write",
            Expr::Log(
                Box::new(Expr::Cap(0)),
                Box::new(Expr::Literal(Data::Text("message".into()))),
            ),
        ),
    ];
    println!("Sandbox at node {a}");
    for (name, expr) in attempts {
        let code = store_program(&mut cluster, a, expr)?;
        let error = execute(&mut cluster, a, code, &[]).unwrap_err();
        assert_eq!(error, Error::MissingCapability(0));
        println!("  {name}: {error}");
    }
    let forged = store_program(
        &mut cluster,
        a,
        Expr::Read(Box::new(hash.clone()), Box::new(hash)),
    )?;
    let error = execute(&mut cluster, a, forged, &[]).unwrap_err();
    assert_eq!(error, Error::Type("a capability handle"));
    println!("  content hash used as a handle: {error}");
    let full = cluster.grant_store(a, [data], StoreAccess::ReadAndPin)?;
    let read_only = cluster.attenuate_store(a, &full, [data], StoreAccess::Read)?;
    let program = store_program(&mut cluster, a, read)?;
    let value = execute(&mut cluster, a, program, &[read_only])?.value;
    assert_eq!(value, Data::Int(7));
    println!("  read with an explicit read-only grant: {value:?}");
    Ok(())
}

fn sum_above(cutoff: i64) -> Program {
    let amount = || Expr::Field(Box::new(Expr::Var(0)), "amount".into());
    let data = Expr::Read(
        Box::new(Expr::Cap(0)),
        Box::new(Expr::StoreRoot(Box::new(Expr::Cap(0)))),
    );
    let predicate = Expr::Lambda(Box::new(Expr::Binary(
        Binary::Greater,
        Box::new(amount()),
        Box::new(Expr::Capture(0)),
    )));
    let filtered = Expr::Filter(Box::new(data), Box::new(predicate));
    let add = Expr::Lambda(Box::new(Expr::Lambda(Box::new(Expr::Binary(
        Binary::Add,
        Box::new(Expr::Var(1)),
        Box::new(amount()),
    )))));
    Program::new(
        Expr::Fold(
            Box::new(filtered),
            Box::new(Expr::Literal(Data::Int(0))),
            Box::new(add),
        ),
        vec![Data::Int(cutoff)],
    )
}

fn placement() -> Result<()> {
    let mut cluster = Cluster::new();
    let a = cluster.add_node()?;
    let b = cluster.add_node()?;
    cluster.connect(
        a,
        b,
        Link {
            latency_ms: 3,
            bytes_per_ms: 4096,
            lan: true,
        },
    )?;
    let rows = Block::Data(Data::List(
        (1..=1024)
            .map(|amount| Data::Record(BTreeMap::from([("amount".into(), Data::Int(amount))])))
            .collect(),
    ));
    let dataset = cluster.put(b, &rows)?;
    cluster.pin(b, dataset)?;
    let code = cluster.put(a, &Block::Program(sum_above(1000)))?;
    cluster.gossip_round();
    let target = Placement {
        node: b,
        data: dataset,
        program: code,
    };
    let grant = cluster.grant_net(a, &[Route::new(target, vec![])])?;
    let launch = store_program(
        &mut cluster,
        a,
        Expr::Remote(Box::new(Expr::Cap(0)), target),
    )?;
    let report = execute(&mut cluster, a, launch, &[grant])?;
    assert_eq!(report.value, Data::Int(24_300));
    assert!(!cluster.has(a, dataset)?);
    println!("Storage-side filter and sum from node {a} to node {b}");
    for event in cluster.events() {
        match event {
            Event::EvalRequest { bytes, .. } => {
                println!("  {bytes} B request carrying dataset and program hashes")
            }
            Event::BlockTransfer {
                kind: BlockKind::Program,
                bytes,
                ..
            } => println!("  {bytes} B of program and captures fetched by node {b}"),
            Event::EvalReply { bytes, .. } => {
                println!("  {bytes} B reply containing {:?}", report.value)
            }
            _ => {}
        }
    }
    println!(
        "  {} B dataset stayed pinned at node {b}",
        rows.to_bytes()?.len()
    );
    println!(
        "  {} fuel, {} charged bytes, {} ms simulated transport",
        report.fuel_used, report.allocated_bytes, report.elapsed_ms
    );
    Ok(())
}

fn locality() -> Result<()> {
    let mut cluster = Cluster::new();
    let a = cluster.add_node()?;
    let b = cluster.add_node()?;
    let c = cluster.add_node()?;
    cluster.connect(
        a,
        b,
        Link {
            latency_ms: 3,
            bytes_per_ms: 4096,
            lan: true,
        },
    )?;
    cluster.connect(
        b,
        c,
        Link {
            latency_ms: 120,
            bytes_per_ms: 128,
            lan: false,
        },
    )?;
    let data_b = cluster.put(b, &Block::Data(Data::Int(10)))?;
    let data_c = cluster.put(c, &Block::Data(Data::Int(20)))?;
    let read = Expr::Read(
        Box::new(Expr::Cap(0)),
        Box::new(Expr::StoreRoot(Box::new(Expr::Cap(0)))),
    );
    let c_target = Placement {
        node: c,
        data: data_c,
        program: store_program(&mut cluster, c, read)?,
    };
    let b_target = Placement {
        node: b,
        data: data_b,
        program: store_program(
            &mut cluster,
            b,
            Expr::Remote(Box::new(Expr::Cap(1)), c_target),
        )?,
    };
    let grant = cluster.grant_net(
        a,
        &[Route::new(b_target, vec![Route::new(c_target, vec![])])],
    )?;
    let launch = store_program(
        &mut cluster,
        a,
        Expr::Remote(Box::new(Expr::Cap(0)), b_target),
    )?;
    let error = execute(&mut cluster, a, launch, &[grant]).unwrap_err();
    assert_eq!(
        error,
        Error::Locality {
            from: b,
            to: c,
            hops: 2,
            rtt_ms: 246
        }
    );
    assert_eq!(
        cluster
            .events()
            .filter(|event| matches!(event, Event::EvalRequest { .. }))
            .count(),
        1
    );
    println!("Nested storage evaluation from node {a} through {b} toward {c}");
    println!("  {error}");
    Ok(())
}

fn gossip() -> Result<()> {
    let mut cluster = Cluster::new();
    let a = cluster.add_node()?;
    let lan = cluster.add_node()?;
    let remote = cluster.add_node()?;
    let wan_link = Link {
        latency_ms: 120,
        bytes_per_ms: 128,
        lan: false,
    };
    cluster.connect(
        a,
        lan,
        Link {
            latency_ms: 2,
            bytes_per_ms: 8192,
            lan: true,
        },
    )?;
    cluster.connect(a, remote, wan_link)?;
    cluster.connect(lan, remote, wan_link)?;
    let code = store_program(&mut cluster, remote, Expr::Literal(Data::Int(1)))?;
    let data = cluster.put(remote, &Block::Data(Data::Text("peer data".into())))?;
    cluster.gossip_round();
    for hash in [code, data] {
        assert_eq!(cluster.fetch(lan, hash)?, Some(remote));
    }
    cluster.gossip_round();
    for hash in [code, data] {
        assert_eq!(cluster.fetch(a, hash)?, Some(lan));
    }
    let updated = Program::new(
        Expr::Apply(
            Box::new(Expr::Lambda(Box::new(Expr::Binary(
                Binary::Add,
                Box::new(Expr::Var(0)),
                Box::new(Expr::Capture(0)),
            )))),
            Box::new(Expr::Literal(Data::Int(1))),
        ),
        vec![Data::Int(1)],
    );
    let update = cluster.put(remote, &Block::Program(updated))?;
    let manifest = cluster.put(
        remote,
        &Block::Data(Data::Record(BTreeMap::from([
            ("code".into(), Data::Link(update)),
            ("version".into(), Data::Int(2)),
        ]))),
    )?;
    cluster.gossip_round();
    for hash in [update, manifest] {
        assert_eq!(cluster.fetch(lan, hash)?, Some(remote));
    }
    cluster.gossip_round();
    let sources = cluster.advertised_peers(a, update)?;
    assert_eq!(sources, vec![lan, remote]);
    let source = cluster.fetch(a, update)?;
    assert_eq!(source, Some(lan));
    assert_eq!(cluster.fetch(a, manifest)?, Some(lan));
    cluster.pin(a, manifest)?;
    let value = execute(&mut cluster, a, update, &[])?.value;
    assert_eq!(value, Data::Int(2));
    println!("Peer distribution of a program, data, and an update manifest");
    println!("  node {remote} seeded node {lan}, which relayed the blocks to node {a}");
    println!("  update sources {lan} (2 ms LAN) and {remote} (120 ms WAN)");
    println!("  node {a} chose {lan} and ran the updated function: {value:?}");
    Ok(())
}

fn gc() -> Result<()> {
    let mut cluster = Cluster::new();
    let node = cluster.add_node()?;
    let child = cluster.put(node, &Block::Data(Data::Int(1)))?;
    let root = cluster.put(node, &Block::Data(Data::List(vec![Data::Link(child)])))?;
    let leased = cluster.put(node, &Block::Data(Data::Int(2)))?;
    let temporary = cluster.put(node, &Block::Data(Data::Int(3)))?;
    cluster.pin(node, root)?;
    let grant = cluster.grant_store(node, [leased], StoreAccess::Read)?;
    let removed = cluster.collect(node)?;
    assert_eq!(removed, vec![temporary]);
    assert!(cluster.has(node, child)? && cluster.has(node, root)? && cluster.has(node, leased)?);
    println!("Collecting node {node}");
    println!(
        "  removed one unpinned block and kept the pinned root, its child, and the live grant's block"
    );
    drop(grant);
    assert_eq!(cluster.collect(node)?, vec![leased]);
    println!("  released the grant and collected its block on the next sweep");
    Ok(())
}
