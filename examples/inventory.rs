mod support;

use std::{collections::BTreeMap, env};

use pp2::{
    Data, Hash,
    peer::{EvaluationMode, PeerStore, data_from_json},
};
use serde_json::{Map, Value, json};
use support::{Profile, Result, install, report, sources};

const USAGE: &str = "Usage: inventory <command>
  package CACHE_DB
  init STORAGE_DB REFERENCE ITEM QUANTITY
  status PROFILE
  reserve PROFILE REVISION RESERVATION ITEM QUANTITY
  release PROFILE REVISION RESERVATION";

fn main() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    let args: Vec<_> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["package", db] => {
            let mut store = PeerStore::open(db)?;
            let sources = sources(&[
                ("state.ts", include_str!("stock/state.ts")),
                ("read.ts", include_str!("stock/read.ts")),
                ("write.ts", include_str!("stock/write.ts")),
            ])?;
            let imports = BTreeMap::new();
            let read = install(&mut store, &sources.path().join("read.ts"), &imports)?;
            let write = install(&mut store, &sources.path().join("write.ts"), &imports)?;
            println!(
                "{}",
                json!({"read": read.to_string(), "write": write.to_string()})
            );
        }
        ["init", db, reference, item, quantity] => {
            if item.is_empty()
                || item.len() > 80
                || !item
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            {
                return Err("invalid stock item".into());
            }
            let stock = Map::from_iter([(format!("@{item}"), json!(quantity.parse::<u64>()?))]);
            let value = data_from_json(json!({"stock": stock, "reservations": {}}))?;
            PeerStore::open(db)?.create_ref(reference, &value)?;
        }
        ["status", path] => {
            let profile = Profile::load(path)?;
            let reply = profile.evaluate(&profile.cache()?, &Data::Nil, EvaluationMode::Read)?;
            println!("{}", report(&reply)?);
        }
        ["reserve", path, revision, id, item, quantity] => {
            update(
                path,
                revision,
                json!({"type": "reserve", "id": id, "item": item, "quantity": quantity.parse::<u64>()?}),
            )?;
        }
        ["release", path, revision, id] => {
            update(path, revision, json!({"type": "release", "id": id}))?;
        }
        [] | ["--help" | "-h"] => println!("{USAGE}"),
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn update(path: &str, revision: &str, input: Value) -> Result<()> {
    let profile = Profile::load(path)?;
    let expected_revision: u64 = revision.parse()?;
    let input = data_from_json(input)?;
    let mut key = profile.scope(true)?.0.to_vec();
    key.extend(expected_revision.to_be_bytes());
    key.extend(input.to_bytes()?);
    let mode = EvaluationMode::Update {
        expected_revision,
        operation: Hash::digest(&key),
    };
    let reply = profile.evaluate(&profile.cache()?, &input, mode)?;
    println!("{}", report(&reply)?);
    Ok(())
}
