mod support;

use std::{collections::BTreeMap, env, fs::File, io::Read};

use pp2::{
    Block, Data, Hash,
    peer::{EvaluationMode, PeerError, PeerStore, RECEIPT_WINDOW, Revision, data_from_json},
};
use serde_json::json;
use support::{Profile, Result, install, report, sources};

const USAGE: &str = "Usage: document_library <command>
  package CACHE_DB
  init STORAGE_DB REFERENCE
  search PROFILE QUERY
  show PROFILE ID
  status PROFILE
  add PROFILE ID TITLE TEXT_FILE
  remove PROFILE ID
  sync PROFILE";

fn main() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    let args: Vec<_> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["package", db] => {
            let mut store = PeerStore::open(db)?;
            let sources = sources(&[
                ("index.ts", include_str!("library/index.ts")),
                ("read.ts", include_str!("library/read.ts")),
                ("write.ts", include_str!("library/write.ts")),
            ])?;
            let base = install(
                &mut store,
                &sources.path().join("index.ts"),
                &BTreeMap::new(),
            )?;
            let imports = BTreeMap::from([("./index.js".into(), base)]);
            let read = install(&mut store, &sources.path().join("read.ts"), &imports)?;
            let write = install(&mut store, &sources.path().join("write.ts"), &imports)?;
            println!(
                "{}",
                json!({"index": base.to_string(), "read": read.to_string(), "write": write.to_string()})
            );
        }
        ["init", db, reference] => {
            let value = data_from_json(json!({"documents": {}, "index": {}}))?;
            PeerStore::open(db)?.create_ref(reference, &value)?;
        }
        ["add", profile, id, title, path] => {
            check_id(id)?;
            let mut text = String::new();
            File::open(path)?.take(64_001).read_to_string(&mut text)?;
            if text.len() > 64_000 || title.encode_utf16().count() > 500 {
                return Err("document exceeds 64,000 bytes or title exceeds 500 characters".into());
            }
            stage(
                &Profile::load(profile)?,
                data_from_json(json!({"type": "add", "id": id, "title": title, "text": text}))?,
            )?;
        }
        ["remove", profile, id] => {
            check_id(id)?;
            stage(
                &Profile::load(profile)?,
                data_from_json(json!({"type": "remove", "id": id}))?,
            )?;
        }
        ["search", path, text] => query(
            &Profile::load(path)?,
            data_from_json(json!({"type": "search", "text": text}))?,
        )?,
        ["show", path, id] => query(
            &Profile::load(path)?,
            data_from_json(json!({"type": "show", "id": id}))?,
        )?,
        ["status", path] => query(&Profile::load(path)?, summary())?,
        ["sync", path] => sync(&Profile::load(path)?)?,
        [] | ["--help" | "-h"] => println!("{USAGE}"),
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn check_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 80
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err("invalid document ID".into());
    }
    Ok(())
}

fn summary() -> Data {
    Data::Record(BTreeMap::from([(
        "type".into(),
        Data::Text("summary".into()),
    )]))
}

fn query(profile: &Profile, query: Data) -> Result<()> {
    let mut store = profile.cache()?;
    let mut cache_key = profile.scope(false)?.0.to_vec();
    cache_key.extend(query.to_bytes()?);
    let reference = format!("query-{}", Hash::digest(&cache_key));
    let displayed = match profile.evaluate(&store, &query, EvaluationMode::Read) {
        Ok(reply) => {
            let cached = Data::List(vec![
                Data::Int(reply.revision.try_into()?),
                reply.value.clone(),
            ]);
            loop {
                let result = match store.read_ref(&reference)? {
                    Some((revision, Data::List(old))) => {
                        if matches!(old.first(), Some(Data::Int(n)) if *n >= reply.revision as i64)
                        {
                            break;
                        }
                        store.replace_ref(&reference, revision.number, cached.clone())
                    }
                    Some(_) => return Err("invalid cached result".into()),
                    None => store.create_ref(&reference, &cached),
                };
                if changed(result)? {
                    break;
                }
            }
            let mut displayed = report(&reply)?;
            displayed["cached"] = json!(false);
            displayed
        }
        Err(error @ (PeerError::Io(_) | PeerError::Timeout | PeerError::Busy)) => {
            let Some((_, Data::List(cached))) = store.read_ref(&reference)? else {
                return Err(error.into());
            };
            let [Data::Int(revision), value] = cached.as_slice() else {
                return Err("invalid cached result".into());
            };
            json!({"revision": revision, "value": pp2::peer::data_to_json(value)?, "cached": true})
        }
        Err(error) => return Err(error.into()),
    };
    println!("{displayed}");
    Ok(())
}

struct Edit {
    operation: Hash,
    input: Hash,
    expected: Option<u64>,
}

impl Edit {
    fn decode(value: &Data) -> Result<Self> {
        let Data::List(fields) = value else {
            return Err("invalid journal edit".into());
        };
        let [Data::Text(id), Data::Link(input), expected] = fields.as_slice() else {
            return Err("invalid journal edit".into());
        };
        let expected = match expected {
            Data::Nil => None,
            Data::Int(revision) => Some(u64::try_from(*revision)?),
            _ => return Err("invalid journal revision".into()),
        };
        Ok(Self {
            operation: id.parse()?,
            input: *input,
            expected,
        })
    }

    fn encode(&self) -> Data {
        Data::List(vec![
            Data::Text(self.operation.to_string()),
            Data::Link(self.input),
            self.expected.map_or(Data::Nil, |n| Data::Int(n as i64)),
        ])
    }
}

fn queue(store: &mut PeerStore, name: &str) -> Result<(Revision, Vec<Data>)> {
    loop {
        match store.read_ref(name)? {
            Some((revision, Data::List(values))) => return Ok((revision, values)),
            Some(_) => return Err("invalid edit journal".into()),
            None => {
                changed(store.create_ref(name, &Data::List(vec![])))?;
            }
        }
    }
}

fn stage(profile: &Profile, input: Data) -> Result<()> {
    let name = format!("edits-{}", profile.scope(true)?);
    let mut store = profile.cache()?;
    let mut id = [0; 32];
    getrandom::fill(&mut id).map_err(|err| std::io::Error::other(err.to_string()))?;
    let bytes = Block::Data(input).to_bytes()?;
    let edit = Edit {
        operation: Hash(id),
        input: Hash::digest(&bytes),
        expected: None,
    };
    loop {
        let (revision, mut values) = queue(&mut store, &name)?;
        store.import(edit.input, &bytes)?;
        values.push(edit.encode());
        let result = store.replace_ref(&name, revision.number, Data::List(values));
        if matches!(result, Err(PeerError::Missing(hash)) if hash == edit.input) {
            continue;
        }
        if changed(result)? {
            break;
        }
    }
    println!("{}", edit.operation);
    Ok(())
}

fn sync(profile: &Profile) -> Result<()> {
    let name = format!("edits-{}", profile.scope(true)?);
    let mut store = profile.cache()?;
    loop {
        let (revision, mut values) = queue(&mut store, &name)?;
        let Some(head) = values.first_mut() else {
            return Ok(());
        };
        let mut edit = Edit::decode(head)?;
        let Some(expected) = edit.expected else {
            let snapshot = profile.evaluate(&store, &summary(), EvaluationMode::Read)?;
            edit.expected = Some(snapshot.revision);
            *head = edit.encode();
            changed(store.replace_ref(&name, revision.number, Data::List(values)))?;
            continue;
        };
        let Some(bytes) = store.get(edit.input)? else {
            if store.reference(&name)? != Some(revision) {
                continue;
            }
            return Err(PeerError::Missing(edit.input).into());
        };
        let Block::Data(input) = Block::from_bytes(&bytes)? else {
            return Err("invalid journal input".into());
        };
        let mode = EvaluationMode::Update {
            expected_revision: expected,
            operation: edit.operation,
        };
        match profile.evaluate(&store, &input, mode) {
            Ok(reply) => {
                values.remove(0);
                if changed(store.replace_ref(&name, revision.number, Data::List(values)))? {
                    println!("{}", report(&reply)?);
                }
            }
            Err(PeerError::Conflict(current))
                if current > expected && current - expected <= RECEIPT_WINDOW =>
            {
                edit.expected = Some(current);
                *head = edit.encode();
                changed(store.replace_ref(&name, revision.number, Data::List(values)))?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn changed(result: std::result::Result<Revision, PeerError>) -> Result<bool> {
    match result {
        Ok(_) => Ok(true),
        Err(PeerError::Conflict(_) | PeerError::ReferenceExists(_)) => Ok(false),
        Err(error) => Err(error.into()),
    }
}
