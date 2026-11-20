use std::collections::BTreeSet;

use serde_json::Value;

use crate::{Block, BlockKind, Data, Error, Hash, wire};

use super::{PeerError, Result};

pub(super) const MAGIC: &[u8; 4] = b"PPJ1";
pub(super) const MAX_MODULES: usize = 32;
pub(super) const MAX_CODE: usize = 512 * 1024;
const MAX_SAFE_INT: u64 = (1 << 53) - 1;

/// An ECMAScript module and its explicitly declared content-addressed imports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JavaScript {
    pub source: String,
    pub imports: BTreeSet<Hash>,
}

impl JavaScript {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if self.imports.len() >= MAX_MODULES {
            return Err(PeerError::Limit("module imports"));
        }
        let header = 5 + 32 * self.imports.len();
        if self.source.len() > Block::MAX_BYTES - header {
            return Err(PeerError::Limit("module bytes"));
        }
        let mut bytes = Vec::with_capacity(header + self.source.len());
        bytes.extend(MAGIC);
        bytes.push(self.imports.len() as u8);
        for hash in &self.imports {
            bytes.extend(hash.0);
        }
        bytes.extend(self.source.as_bytes());
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if !bytes.starts_with(MAGIC) || !(5..=Block::MAX_BYTES).contains(&bytes.len()) {
            return Err(Error::Wire("invalid JavaScript block").into());
        }
        let count = usize::from(bytes[4]);
        let end = 5 + 32 * count;
        if count >= MAX_MODULES || bytes.len() < end {
            return Err(Error::Wire("invalid JavaScript imports").into());
        }
        let mut imports = BTreeSet::new();
        for chunk in bytes[5..end].chunks_exact(32) {
            let hash = Hash(chunk.try_into().expect("chunk length is fixed"));
            if imports.last().is_some_and(|last| *last >= hash) {
                return Err(Error::Wire("JavaScript imports must be sorted and unique").into());
            }
            imports.insert(hash);
        }
        let source = std::str::from_utf8(&bytes[end..])
            .map_err(|_| Error::Wire("invalid JavaScript UTF-8"))?;
        Ok(Self {
            source: source.to_owned(),
            imports,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Kind {
    Data,
    Aeb,
    JavaScript,
}

pub(super) fn inspect(expected: Hash, bytes: &[u8]) -> Result<(Kind, BTreeSet<Hash>)> {
    if bytes.len() > Block::MAX_BYTES {
        return Err(PeerError::Limit("content block bytes"));
    }
    let actual = Hash::digest(bytes);
    if actual != expected {
        return Err(Error::Integrity { expected, actual }.into());
    }
    if bytes.starts_with(MAGIC) {
        return Ok((Kind::JavaScript, JavaScript::from_bytes(bytes)?.imports));
    }
    let (kind, links) = wire::inspect_block(bytes)?;
    Ok((
        match kind {
            BlockKind::Data => Kind::Data,
            BlockKind::Program => Kind::Aeb,
        },
        links,
    ))
}

pub(super) fn load_code(
    root: Hash,
    allow_missing: bool,
    mut get: impl FnMut(Hash) -> Result<Option<Vec<u8>>>,
) -> Result<Vec<(Hash, Vec<u8>)>> {
    let mut seen = BTreeSet::new();
    let mut pending = vec![root];
    let mut graph = Vec::new();
    let mut bytes_left = MAX_CODE;
    while let Some(hash) = pending.pop() {
        if !seen.insert(hash) {
            continue;
        }
        if seen.len() > MAX_MODULES {
            return Err(PeerError::Limit("module graph count"));
        }
        let Some(bytes) = get(hash)? else {
            if allow_missing {
                continue;
            }
            return Err(PeerError::Missing(hash));
        };
        bytes_left = bytes_left
            .checked_sub(bytes.len())
            .ok_or(PeerError::Limit("module graph bytes"))?;
        match inspect(hash, &bytes)? {
            (Kind::JavaScript, imports) => pending.extend(imports),
            (Kind::Aeb, _) if hash == root => {}
            _ => {
                return Err(PeerError::Value(
                    "unexpected block kind in module graph".into(),
                ));
            }
        }
        graph.push((hash, bytes));
    }
    Ok(graph)
}

/// Converts JSON into pp2 data. Integers must be exactly representable in JavaScript.
pub fn data_from_json(value: Value) -> Result<Data> {
    fn convert(value: Value, depth: usize) -> Result<Data> {
        wire::check_depth(depth)?;
        let next = depth + 1;
        Ok(match value {
            Value::Null => Data::Nil,
            Value::Bool(x) => Data::Bool(x),
            Value::Number(x) => Data::Int(
                x.as_i64()
                    .filter(|n| n.unsigned_abs() <= MAX_SAFE_INT)
                    .ok_or_else(|| PeerError::Value("expected a safe integer".into()))?,
            ),
            Value::String(x) => Data::Text(x),
            Value::Array(xs) => Data::List(
                xs.into_iter()
                    .map(|x| convert(x, next))
                    .collect::<Result<_>>()?,
            ),
            Value::Object(xs) => Data::Record(
                xs.into_iter()
                    .map(|(k, x)| Ok((k, convert(x, next)?)))
                    .collect::<Result<_>>()?,
            ),
        })
    }
    let data = convert(value, 0)?;
    wire::value_size(&data)?;
    Ok(data)
}

/// Converts the JSON-compatible subset of pp2 data into JSON.
pub fn data_to_json(data: &Data) -> Result<Value> {
    fn convert(data: &Data) -> Result<Value> {
        Ok(match data {
            Data::Nil => Value::Null,
            Data::Bool(x) => Value::Bool(*x),
            Data::Int(x) if x.unsigned_abs() <= MAX_SAFE_INT => Value::Number((*x).into()),
            Data::Text(x) => Value::String(x.clone()),
            Data::List(xs) => Value::Array(xs.iter().map(convert).collect::<Result<_>>()?),
            Data::Record(xs) => Value::Object(
                xs.iter()
                    .map(|(k, x)| Ok((k.clone(), convert(x)?)))
                    .collect::<Result<_>>()?,
            ),
            _ => return Err(PeerError::Value("expected JSON-compatible data".into())),
        })
    }
    wire::value_size(data)?;
    convert(data)
}
