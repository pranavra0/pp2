//! Author-side compilation. Peers receive ordinary content-addressed ECMAScript modules.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    path::Path,
    process::Command,
};

use serde::Deserialize;

use crate::{Block, Hash};

use super::{JavaScript, PeerError, Result, content};

/// Strictly type-checks one TypeScript module and emits ES2022 for packaging.
/// Relative runtime imports can be linked to existing pp2 blocks using exact specifier aliases.
/// Dependencies used solely for types are read during compilation and erased from the output.
/// Requires Node.js and the TypeScript package in the source or working directory's module tree.
pub fn compile_typescript(source: &Path, aliases: &BTreeMap<String, Hash>) -> Result<String> {
    let aliases: BTreeMap<_, _> = aliases
        .iter()
        .map(|(specifier, hash)| (specifier, format!("pp2:{hash}")))
        .collect();
    let aliases = serde_json::to_string(&aliases).expect("string map is JSON serializable");
    let bytes = compile(source, &aliases)?;
    if bytes.len() > Block::MAX_BYTES {
        return Err(PeerError::Limit("compiled module bytes"));
    }
    String::from_utf8(bytes).map_err(|err| PeerError::TypeScript(err.to_string()))
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Part {
    Source(String),
    Dependency(usize),
}

/// Links a relative ESM source graph into pp2 blocks, with the entry block last.
pub fn package_source(source: &Path) -> Result<Vec<(Hash, Vec<u8>)>> {
    let output = compile(source, "graph")?;
    let modules: Vec<Vec<Part>> =
        serde_json::from_slice(&output).map_err(|err| PeerError::TypeScript(err.to_string()))?;
    if modules.is_empty() || modules.len() > content::MAX_MODULES {
        return Err(PeerError::Limit("module graph count"));
    }
    let mut blocks: Vec<(Hash, Vec<u8>)> = Vec::with_capacity(modules.len());
    let mut remaining = content::MAX_CODE;
    for parts in modules {
        let mut source = String::new();
        let mut imports = BTreeSet::new();
        for part in parts {
            match part {
                Part::Source(text) => source.push_str(&text),
                Part::Dependency(index) => {
                    let &(hash, _) = blocks
                        .get(index)
                        .ok_or_else(|| PeerError::TypeScript("invalid module dependency".into()))?;
                    imports.insert(hash);
                    source.push_str(&format!("\"pp2:{hash}\""));
                }
            }
        }
        let bytes = JavaScript { source, imports }.to_bytes()?;
        remaining = remaining
            .checked_sub(bytes.len())
            .ok_or(PeerError::Limit("module graph bytes"))?;
        blocks.push((Hash::digest(&bytes), bytes));
    }
    Ok(blocks)
}

fn compile(source: &Path, mode: &str) -> Result<Vec<u8>> {
    let output = Command::new("node")
        .args([
            "--input-type=commonjs",
            "-e",
            include_str!("typescript.cjs"),
            "--",
        ])
        .arg(source)
        .arg(mode)
        .output()
        .map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                PeerError::TypeScript(
                    "install Node.js and run npm ci to enable TypeScript packaging".into(),
                )
            } else {
                err.into()
            }
        })?;

    if !output.status.success() {
        return Err(PeerError::TypeScript(
            String::from_utf8_lossy(&output.stderr).trim_end().into(),
        ));
    }
    Ok(output.stdout)
}
