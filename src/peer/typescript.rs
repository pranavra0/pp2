//! Author-side compilation. Peers receive ordinary content-addressed ECMAScript modules.

use std::{collections::BTreeMap, io, path::Path, process::Command};

use crate::{Block, Hash};

use super::{PeerError, Result};

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
    let output = Command::new("node")
        .args([
            "--input-type=commonjs",
            "-e",
            include_str!("typescript.cjs"),
            "--",
        ])
        .arg(source)
        .arg(aliases)
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
    if output.stdout.len() > Block::MAX_BYTES {
        return Err(PeerError::Limit("compiled module bytes"));
    }
    String::from_utf8(output.stdout).map_err(|err| PeerError::TypeScript(err.to_string()))
}
