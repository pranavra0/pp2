use super::*;

pub(super) struct Roots {
    pub(super) current: Hash,
    pub(super) next: Option<Hash>,
    pub(super) heads: Vec<(Hash, Hash)>,
    visible: BTreeSet<Hash>,
}

impl Roots {
    pub(super) fn new(current: Hash, heads: Vec<(Hash, Hash)>) -> Self {
        let visible = std::iter::once(current)
            .chain(heads.iter().map(|&(_, root)| root))
            .collect();
        Self {
            current,
            next: None,
            heads,
            visible,
        }
    }

    pub(super) fn effect(
        &mut self,
        conn: &Connection,
        write: bool,
        effect: Effect,
    ) -> Result<Vec<u8>> {
        let reply = match effect {
            Effect::ReadBlock(hash) => {
                self.check(hash)?;
                let bytes = get(conn, hash, false)?.ok_or(PeerError::Missing(hash))?;
                let Block::Data(block) = Block::from_bytes(&bytes)? else {
                    return Err(PeerError::Denied);
                };
                // A snapshot can also hold ordinary portable data. Its links are
                // disclosed only through the explicit block layout.
                let (value, children) = unpack(block)?;
                let reply = Data::Record(BTreeMap::from([
                    ("value".into(), value),
                    (
                        "children".into(),
                        Data::List(
                            children
                                .iter()
                                .map(|hash| Data::Text(hash.to_string()))
                                .collect(),
                        ),
                    ),
                ]));
                let bytes = reply.to_bytes()?;
                content::data_to_json(&reply)?;
                self.visible.extend(children);
                return Ok(bytes);
            }
            Effect::WriteBlock(bytes, children) if write => {
                let value = Data::from_bytes(&bytes)?;
                content::data_to_json(&value)?;
                for &child in &children {
                    self.check(child)?;
                }
                let block = if children.is_empty() {
                    value
                } else {
                    Data::List(vec![
                        value,
                        Data::List(children.into_iter().map(Data::Link).collect()),
                    ])
                };
                let block = Block::Data(block).to_bytes()?;
                let hash = Hash::digest(&block);
                insert(conn, hash, &block)?;
                self.visible.insert(hash);
                Data::Text(hash.to_string())
            }
            Effect::SetRoot(hash) if write => {
                self.check(hash)?;
                let bytes = get(conn, hash, false)?.ok_or(PeerError::Missing(hash))?;
                if content::inspect(hash, &bytes)?.0 != Kind::Data {
                    return Err(PeerError::Denied);
                }
                self.next = Some(hash);
                Data::Text(hash.to_string())
            }
            _ => return Err(PeerError::Denied),
        };
        Ok(reply.to_bytes()?)
    }

    fn check(&self, hash: Hash) -> Result<()> {
        if self.visible.contains(&hash) {
            Ok(())
        } else {
            Err(PeerError::Denied)
        }
    }
}

fn unpack(block: Data) -> Result<(Data, Vec<Hash>)> {
    // A JSON value cannot contain a Merkle link, so this layout cannot
    // collide with an ordinary payload.
    if let Data::List(items) = &block
        && let [_, Data::List(links)] = items.as_slice()
        && matches!(links.first(), Some(Data::Link(_)))
    {
        let children = links
            .iter()
            .map(|link| match link {
                Data::Link(hash) => Ok(*hash),
                _ => Err(PeerError::Denied),
            })
            .collect::<Result<_>>()?;
        let Data::List(mut items) = block else {
            unreachable!()
        };
        return Ok((items.swap_remove(0), children));
    }
    Ok((block, Vec::new()))
}
