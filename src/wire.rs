use std::collections::{BTreeMap, BTreeSet};

use crate::{Binary, Block, Data, Error, Expr, Hash, NodeId, Placement, Program, Result};

pub(crate) const MAX_BYTES: usize = 256 * 1024;
pub(crate) const MAX_ITEMS: usize = 16_384;
const MAX_DEPTH: usize = 32;
const BLOCK_MAGIC: &[u8] = b"AEB1";
const VALUE_MAGIC: &[u8] = b"AEV1";
const REQUEST_MAGIC: &[u8] = b"AER1";

struct Writer {
    len: usize,
    bytes: Option<Vec<u8>>,
}

impl Writer {
    fn new() -> Self {
        Self {
            len: 0,
            bytes: Some(Vec::new()),
        }
    }

    fn raw(&mut self, bytes: &[u8]) -> Result<()> {
        self.len += bytes.len().min(MAX_BYTES + 1);
        if self.len > MAX_BYTES {
            return Err(Error::Wire("message exceeds byte limit"));
        }
        if let Some(out) = &mut self.bytes {
            out.extend_from_slice(bytes);
        }
        Ok(())
    }

    fn tag(&mut self, tag: u8) -> Result<()> {
        self.raw(&[tag])
    }

    fn count(&mut self, count: usize) -> Result<()> {
        if count > MAX_ITEMS {
            return Err(Error::Wire("collection exceeds item limit"));
        }
        self.raw(&(count as u32).to_be_bytes())
    }

    fn text(&mut self, text: &str) -> Result<()> {
        if text.len() > MAX_BYTES {
            return Err(Error::Wire("text exceeds byte limit"));
        }
        self.raw(&(text.len() as u32).to_be_bytes())?;
        self.raw(text.as_bytes())
    }

    fn placement(&mut self, placement: Placement) -> Result<()> {
        self.raw(&placement.node.0.to_be_bytes())?;
        self.raw(&placement.data.0)?;
        self.raw(&placement.program.0)
    }

    fn data(&mut self, data: &Data, depth: usize) -> Result<()> {
        check_depth(depth)?;
        match data {
            Data::Nil => self.tag(0),
            Data::Bool(false) => self.tag(1),
            Data::Bool(true) => self.tag(2),
            Data::Int(number) => {
                self.tag(3)?;
                self.raw(&number.to_be_bytes())
            }
            Data::Text(text) => {
                self.tag(4)?;
                self.text(text)
            }
            Data::List(items) => {
                self.tag(5)?;
                self.count(items.len())?;
                for value in items {
                    self.data(value, depth + 1)?;
                }
                Ok(())
            }
            Data::Record(fields) => {
                self.tag(6)?;
                self.count(fields.len())?;
                for (key, value) in fields {
                    self.text(key)?;
                    self.data(value, depth + 1)?;
                }
                Ok(())
            }
            Data::Link(hash) => {
                self.tag(7)?;
                self.raw(&hash.0)
            }
        }
    }

    fn expr(&mut self, expr: &Expr, depth: usize) -> Result<()> {
        check_depth(depth)?;
        let child_depth = depth + 1;
        match expr {
            Expr::Literal(data) => {
                self.tag(0)?;
                self.data(data, child_depth)
            }
            Expr::Var(index) | Expr::Capture(index) | Expr::Cap(index) => {
                self.tag(match expr {
                    Expr::Var(_) => 1,
                    Expr::Capture(_) => 2,
                    _ => 13,
                })?;
                self.raw(&index.to_be_bytes())
            }
            Expr::Lambda(body) | Expr::Clock(body) => {
                self.tag(if matches!(expr, Expr::Lambda(_)) {
                    3
                } else {
                    16
                })?;
                self.expr(body, child_depth)
            }
            Expr::Apply(a, b)
            | Expr::Let(a, b)
            | Expr::Filter(a, b)
            | Expr::Read(a, b)
            | Expr::Pin(a, b)
            | Expr::Log(a, b) => {
                self.tag(match expr {
                    Expr::Apply(..) => 4,
                    Expr::Let(..) => 5,
                    Expr::Filter(..) => 11,
                    Expr::Read(..) => 14,
                    Expr::Pin(..) => 15,
                    _ => 17,
                })?;
                self.expr(a, child_depth)?;
                self.expr(b, child_depth)
            }
            Expr::If(a, b, c) | Expr::Fold(a, b, c) => {
                self.tag(if matches!(expr, Expr::If(..)) { 6 } else { 12 })?;
                self.expr(a, child_depth)?;
                self.expr(b, child_depth)?;
                self.expr(c, child_depth)
            }
            Expr::Binary(op, a, b) => {
                self.tag(7)?;
                self.tag(match op {
                    Binary::Add => 0,
                    Binary::Greater => 1,
                    Binary::Equal => 2,
                })?;
                self.expr(a, child_depth)?;
                self.expr(b, child_depth)
            }
            Expr::Field(record, key) => {
                self.tag(8)?;
                self.expr(record, child_depth)?;
                self.text(key)
            }
            Expr::List(items) => {
                self.tag(9)?;
                self.count(items.len())?;
                for item in items {
                    self.expr(item, child_depth)?;
                }
                Ok(())
            }
            Expr::Record(fields) => {
                self.tag(10)?;
                self.count(fields.len())?;
                for (key, value) in fields {
                    self.text(key)?;
                    self.expr(value, child_depth)?;
                }
                Ok(())
            }
            Expr::Here(cap) | Expr::StoreRoot(cap) => {
                self.tag(if matches!(expr, Expr::Here(_)) {
                    18
                } else {
                    20
                })?;
                self.expr(cap, child_depth)
            }
            Expr::Remote(cap, placement) => {
                self.tag(19)?;
                self.expr(cap, child_depth)?;
                self.placement(*placement)
            }
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes.expect("writer is in encoding mode")
    }
}

struct Reader<'a> {
    rest: &'a [u8],
    links: Option<BTreeSet<Hash>>,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], magic: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::Wire("message exceeds byte limit"));
        }
        let rest = bytes
            .strip_prefix(magic)
            .ok_or(Error::Wire("unknown frame type or version"))?;
        Ok(Self { rest, links: None })
    }

    fn raw(&mut self, count: usize) -> Result<&'a [u8]> {
        let (head, tail) = self
            .rest
            .split_at_checked(count)
            .ok_or(Error::Wire("truncated message"))?;
        self.rest = tail;
        Ok(head)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.raw(N)?.try_into().expect("fixed width read"))
    }

    fn tag(&mut self) -> Result<u8> {
        Ok(self.fixed::<1>()?[0])
    }

    fn index(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    fn count(&mut self, min_item_bytes: usize) -> Result<usize> {
        let count = u32::from_be_bytes(self.fixed()?) as usize;
        if count > MAX_ITEMS || count > self.rest.len() / min_item_bytes {
            return Err(Error::Wire("invalid collection length"));
        }
        Ok(count)
    }

    fn text(&mut self) -> Result<&'a str> {
        let len = u32::from_be_bytes(self.fixed()?) as usize;
        std::str::from_utf8(self.raw(len)?).map_err(|_| Error::Wire("invalid UTF-8"))
    }

    fn placement(&mut self) -> Result<Placement> {
        Ok(Placement {
            node: NodeId(self.index()?),
            data: Hash(self.fixed()?),
            program: Hash(self.fixed()?),
        })
    }

    fn record<T>(
        &mut self,
        mut value: impl FnMut(&mut Self) -> Result<T>,
    ) -> Result<BTreeMap<String, T>> {
        let count = self.count(5)?;
        let mut fields = BTreeMap::new();
        let mut previous = None;
        for _ in 0..count {
            let key = self.text()?;
            if previous.is_some_and(|last| last >= key) {
                return Err(Error::Wire("record keys must be unique and sorted"));
            }
            previous = Some(key);
            fields.insert(key.to_owned(), value(self)?);
        }
        Ok(fields)
    }

    fn sequence<T>(&mut self, mut value: impl FnMut(&mut Self) -> Result<T>) -> Result<Vec<T>> {
        let count = self.count(1)?;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(value(self)?);
        }
        Ok(items)
    }

    fn data(&mut self, depth: usize) -> Result<Data> {
        check_depth(depth)?;
        Ok(match self.tag()? {
            0 => Data::Nil,
            1 => Data::Bool(false),
            2 => Data::Bool(true),
            3 => Data::Int(i64::from_be_bytes(self.fixed()?)),
            4 => Data::Text(self.text()?.to_owned()),
            5 => Data::List(self.sequence(|reader| reader.data(depth + 1))?),
            6 => Data::Record(self.record(|reader| reader.data(depth + 1))?),
            7 => {
                let hash = Hash(self.fixed()?);
                if let Some(links) = &mut self.links {
                    links.insert(hash);
                }
                Data::Link(hash)
            }
            _ => return Err(Error::Wire("unknown data tag")),
        })
    }

    fn expr(&mut self, depth: usize) -> Result<Expr> {
        check_depth(depth)?;
        let opcode = self.tag()?;
        let mut child = || self.expr(depth + 1).map(Box::new);
        Ok(match opcode {
            0 => Expr::Literal(self.data(depth + 1)?),
            1 => Expr::Var(self.index()?),
            2 => Expr::Capture(self.index()?),
            3 => Expr::Lambda(child()?),
            4 => Expr::Apply(child()?, child()?),
            5 => Expr::Let(child()?, child()?),
            6 => Expr::If(child()?, child()?, child()?),
            7 => {
                let op = match self.tag()? {
                    0 => Binary::Add,
                    1 => Binary::Greater,
                    2 => Binary::Equal,
                    _ => return Err(Error::Wire("unknown binary operator")),
                };
                Expr::Binary(
                    op,
                    Box::new(self.expr(depth + 1)?),
                    Box::new(self.expr(depth + 1)?),
                )
            }
            8 => Expr::Field(child()?, self.text()?.to_owned()),
            9 => Expr::List(self.sequence(|reader| reader.expr(depth + 1))?),
            10 => Expr::Record(self.record(|reader| reader.expr(depth + 1))?),
            11 => Expr::Filter(child()?, child()?),
            12 => Expr::Fold(child()?, child()?, child()?),
            13 => Expr::Cap(self.index()?),
            14 => Expr::Read(child()?, child()?),
            15 => Expr::Pin(child()?, child()?),
            16 => Expr::Clock(child()?),
            17 => Expr::Log(child()?, child()?),
            18 => Expr::Here(child()?),
            19 => Expr::Remote(child()?, self.placement()?),
            20 => Expr::StoreRoot(child()?),
            _ => return Err(Error::Wire("unknown expression opcode")),
        })
    }

    fn block(&mut self) -> Result<Block> {
        match self.tag()? {
            0 => Ok(Block::Data(self.data(0)?)),
            1 => {
                let captures = self.sequence(|reader| reader.data(0))?;
                let expr = self.expr(0)?;
                Ok(Block::Program(Program::new(expr, captures)))
            }
            _ => Err(Error::Wire("unknown block type")),
        }
    }

    fn finish(&self) -> Result<()> {
        if !self.rest.is_empty() {
            return Err(Error::Wire("trailing bytes"));
        }
        Ok(())
    }
}

pub(crate) fn check_depth(depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Error::Wire("message exceeds nesting limit"));
    }
    Ok(())
}

pub(crate) fn encode_data_block(data: &Data) -> Result<Vec<u8>> {
    let mut out = Writer::new();
    out.raw(BLOCK_MAGIC)?;
    out.tag(0)?;
    out.data(data, 0)?;
    Ok(out.finish())
}

pub(crate) fn encode_program(program: &Program) -> Result<Vec<u8>> {
    let mut out = Writer::new();
    out.raw(BLOCK_MAGIC)?;
    out.tag(1)?;
    out.count(program.captures.len())?;
    for capture in &program.captures {
        out.data(capture, 0)?;
    }
    out.expr(&program.expr, 0)?;
    Ok(out.finish())
}

pub(crate) fn decode_block(bytes: &[u8]) -> Result<Block> {
    let mut reader = Reader::new(bytes, BLOCK_MAGIC)?;
    let block = reader.block()?;
    reader.finish()?;
    Ok(block)
}

pub(crate) fn inspect_block(bytes: &[u8]) -> Result<(crate::BlockKind, BTreeSet<Hash>)> {
    let mut reader = Reader::new(bytes, BLOCK_MAGIC)?;
    reader.links = Some(BTreeSet::new());
    let kind = reader.block()?.kind();
    reader.finish()?;
    Ok((kind, reader.links.expect("reader is collecting links")))
}

pub(crate) fn encode_value(value: &Data) -> Result<Vec<u8>> {
    let mut out = Writer::new();
    out.raw(VALUE_MAGIC)?;
    out.data(value, 0)?;
    Ok(out.finish())
}

pub(crate) fn value_size(value: &Data) -> Result<usize> {
    let mut out = Writer {
        len: 0,
        bytes: None,
    };
    out.raw(VALUE_MAGIC)?;
    out.data(value, 0)?;
    Ok(out.len)
}

pub(crate) fn decode_value(bytes: &[u8]) -> Result<Data> {
    let mut reader = Reader::new(bytes, VALUE_MAGIC)?;
    let value = reader.data(0)?;
    reader.finish()?;
    Ok(value)
}

pub(crate) fn encode_request(placement: Placement) -> Result<Vec<u8>> {
    let mut out = Writer::new();
    out.raw(REQUEST_MAGIC)?;
    out.placement(placement)?;
    Ok(out.finish())
}

pub(crate) fn decode_request(bytes: &[u8]) -> Result<Placement> {
    let mut reader = Reader::new(bytes, REQUEST_MAGIC)?;
    let placement = reader.placement()?;
    reader.finish()?;
    Ok(placement)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placement_request_has_a_fixed_layout() {
        let placement = Placement {
            node: NodeId(256),
            data: Hash([0x11; 32]),
            program: Hash([0x22; 32]),
        };
        let mut frame = b"AER1\x01\0".to_vec();
        frame.extend_from_slice(&[0x11; 32]);
        frame.extend_from_slice(&[0x22; 32]);
        assert_eq!(encode_request(placement).unwrap(), frame);
        assert_eq!(decode_request(&frame).unwrap(), placement);
        assert!(decode_request(&frame[..frame.len() - 1]).is_err());
        frame.push(0);
        assert!(decode_request(&frame).is_err());
    }

    #[test]
    fn decode_depth_is_bounded_independently_of_the_encoder() {
        let mut frame = b"AEV1".to_vec();
        for _ in 0..MAX_DEPTH {
            frame.extend_from_slice(b"\x05\0\0\0\x01");
        }
        frame.push(0);
        let value = decode_value(&frame).unwrap();
        assert_eq!(encode_value(&value).unwrap(), frame);
        frame.splice(4..4, *b"\x05\0\0\0\x01");
        assert!(matches!(
            decode_value(&frame),
            Err(Error::Wire("message exceeds nesting limit"))
        ));
    }
}
