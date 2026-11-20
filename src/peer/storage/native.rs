use std::collections::BTreeMap;

use crate::peer::{Binding, NativeInstallation, NativePackage};

use super::*;

pub(super) const SCHEMA: &str = "
CREATE TABLE host_resources (
    ref TEXT PRIMARY KEY REFERENCES collections(ref),
    provider TEXT NOT NULL, configuration BLOB NOT NULL
) WITHOUT ROWID;
CREATE TABLE native_installations (
    id BLOB PRIMARY KEY,
    package BLOB NOT NULL REFERENCES blocks(hash),
    ref TEXT NOT NULL UNIQUE REFERENCES collections(ref),
    entry BLOB NOT NULL,
    writer BLOB NOT NULL
) WITHOUT ROWID;
CREATE TABLE native_bindings (
    installation BLOB REFERENCES native_installations(id) ON DELETE CASCADE,
    name TEXT, binding BLOB NOT NULL, PRIMARY KEY(installation, name)
) WITHOUT ROWID;
PRAGMA user_version = 5;
";

pub(in crate::peer) struct NativeExecution {
    pub installation: NativeInstallation,
    pub entry: Hash,
    pub writer: Hash,
    pub code: Vec<(Hash, Vec<u8>)>,
}

impl PeerStore {
    /// Installs the exact manifest approved by the local administrator.
    pub fn install_native(&mut self, approved: &NativePackage) -> Result<Hash> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let package = validate_package(&tx, approved)?;
        let mut id = [0; 32];
        getrandom::fill(&mut id).map_err(|error| std::io::Error::other(error.to_string()))?;
        let id = Hash(id);
        let reference = format!("native.{id}");
        create_collection(&tx, &reference, [])?;
        let (entry, writer) = issue(&tx, id, &reference, approved.entry)?;
        tx.execute(
            "INSERT INTO native_installations VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &id.0[..],
                &package.0[..],
                reference,
                &entry.0[..],
                &writer.0[..]
            ],
        )?;
        tx.commit()?;
        Ok(id)
    }

    pub fn native_installation(&self, id: Hash) -> Result<NativeInstallation> {
        let tx = self.0.unchecked_transaction()?;
        let (package, _, _, _) = installed(&tx, id)?;
        details(&tx, id, package)
    }

    pub fn native_installations(&self) -> Result<Vec<Hash>> {
        let mut statement = self
            .0
            .prepare("SELECT id FROM native_installations ORDER BY id")?;
        Ok(statement
            .query_map([], |row| Ok(Hash(row.get(0)?)))?
            .collect::<std::result::Result<_, _>>()?)
    }

    /// Replaces an approved package and keeps grants only for identical named requests.
    pub fn update_native(
        &mut self,
        id: Hash,
        previous: Hash,
        approved: &NativePackage,
    ) -> Result<()> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let (package, reference, entry, writer) = installed(&tx, id)?;
        require_package(package, previous)?;
        let next = validate_package(&tx, approved)?;
        if next == package {
            return Ok(());
        }
        let old = details(&tx, id, package)?;
        for name in old.bindings.keys() {
            if old.manifest.bindings.get(name) != approved.bindings.get(name) {
                tx.execute(
                    "DELETE FROM native_bindings WHERE installation=?1 AND name=?2",
                    params![&id.0[..], name],
                )?;
            }
        }
        revoke(&tx, entry, writer)?;
        let (entry, writer) = issue(&tx, id, &reference, approved.entry)?;
        tx.execute(
            "UPDATE native_installations SET package=?2, entry=?3, writer=?4 WHERE id=?1",
            params![&id.0[..], &next.0[..], &entry.0[..], &writer.0[..]],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Connects an issuer's grant to an approved named request. A missing grant disconnects it.
    pub fn bind_native(
        &mut self,
        id: Hash,
        expected_package: Hash,
        name: &str,
        binding: Option<Binding>,
    ) -> Result<()> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let (package, reference, entry, writer) = installed(&tx, id)?;
        require_package(package, expected_package)?;
        let manifest = manifest(&tx, package)?;
        let request = manifest.bindings.get(name).ok_or(PeerError::Denied)?;
        if let Some(binding) = binding {
            if binding.program != request.program || binding.access != request.access {
                return Err(PeerError::Denied);
            }
            tx.execute(
                "INSERT INTO native_bindings VALUES (?1, ?2, ?3)
                 ON CONFLICT(installation, name) DO UPDATE SET binding=excluded.binding",
                params![&id.0[..], name, protocol::encode(&binding)?],
            )?;
        } else {
            tx.execute(
                "DELETE FROM native_bindings WHERE installation=?1 AND name=?2",
                params![&id.0[..], name],
            )?;
        }
        revoke(&tx, entry, writer)?;
        let (entry, writer) = issue(&tx, id, &reference, manifest.entry)?;
        tx.execute(
            "UPDATE native_installations SET entry=?2, writer=?3 WHERE id=?1",
            params![&id.0[..], &entry.0[..], &writer.0[..]],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Revokes the installation's local grants and deletes its private state and bindings.
    pub fn remove_native(&mut self, id: Hash) -> Result<()> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let (_, reference, entry, writer) = installed(&tx, id)?;
        revoke(&tx, entry, writer)?;
        tx.execute("DELETE FROM native_installations WHERE id=?1", [&id.0[..]])?;
        tx.execute("DELETE FROM entries WHERE ref=?1", [&reference])?;
        tx.execute("DELETE FROM change_events WHERE ref=?1", [&reference])?;
        tx.execute("DELETE FROM collections WHERE ref=?1", [&reference])?;
        tx.execute("DELETE FROM refs WHERE name=?1", [&reference])?;
        tx.commit()?;
        Ok(())
    }

    pub(in crate::peer) fn native_execution(&self, id: Hash) -> Result<NativeExecution> {
        let tx = self.0.unchecked_transaction()?;
        let (package, _, entry, writer) = installed(&tx, id)?;
        let installation = details(&tx, id, package)?;
        let code =
            NativePackage::load_program(installation.manifest.entry, |hash| get(&tx, hash, false))?;
        Ok(NativeExecution {
            installation,
            entry,
            writer,
            code,
        })
    }
}

fn validate_package(conn: &Connection, manifest: &NativePackage) -> Result<Hash> {
    let bytes = manifest.to_bytes()?;
    let hash = Hash::digest(&bytes);
    for program in manifest.programs() {
        NativePackage::load_program(program, |hash| get(conn, hash, false))?;
    }
    insert(conn, hash, &bytes)?;
    Ok(hash)
}

fn installed(conn: &Connection, id: Hash) -> Result<(Hash, String, Hash, Hash)> {
    conn.query_row(
        "SELECT package, ref, entry, writer FROM native_installations WHERE id=?1",
        [&id.0[..]],
        |row| {
            Ok((
                Hash(row.get(0)?),
                row.get(1)?,
                Hash(row.get(2)?),
                Hash(row.get(3)?),
            ))
        },
    )
    .optional()?
    .ok_or_else(|| PeerError::Value(format!("unknown native installation {id}")))
}

fn manifest(conn: &Connection, package: Hash) -> Result<NativePackage> {
    NativePackage::from_bytes(&get(conn, package, false)?.ok_or(PeerError::Missing(package))?)
}

fn details(conn: &Connection, id: Hash, package: Hash) -> Result<NativeInstallation> {
    let mut query = conn
        .prepare("SELECT name, binding FROM native_bindings WHERE installation=?1 ORDER BY name")?;
    let mut rows = query.query([&id.0[..]])?;
    let mut bindings = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let bytes: Vec<u8> = row.get(1)?;
        bindings.insert(row.get(0)?, protocol::decode(&bytes)?);
    }
    Ok(NativeInstallation {
        id,
        package,
        manifest: manifest(conn, package)?,
        bindings,
    })
}

fn require_package(actual: Hash, expected: Hash) -> Result<()> {
    if actual != expected {
        return Err(PeerError::Value("the installed package changed".into()));
    }
    Ok(())
}

fn issue(conn: &Connection, holder: Hash, reference: &str, program: Hash) -> Result<(Hash, Hash)> {
    let mut grant = Authority {
        reference: reference.into(),
        access: Access::Read,
        program: Some(program),
        depth: 0,
        graph: None,
        reaction_writer: false,
    };
    let entry = insert_grant(conn, holder, &grant, None)?;
    grant.access = Access::Write;
    let writer = insert_grant(conn, holder, &grant, None)?;
    Ok((entry, writer))
}

fn revoke(conn: &Connection, entry: Hash, writer: Hash) -> Result<()> {
    conn.execute(
        "DELETE FROM grants WHERE id IN (?1, ?2)",
        params![&entry.0[..], &writer.0[..]],
    )?;
    applications::revoke_unauthorized(conn)?;
    Ok(())
}
