use std::{collections::BTreeMap, fmt, str::FromStr};

use sha2::{Digest, Sha256};

use crate::{Error, Result, wire};

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn digest(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(out, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Hash {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        if input.len() != 64 || !input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::Wire("expected a 64-character hexadecimal hash"));
        }
        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16)
                .map_err(|_| Error::Wire("invalid hexadecimal hash"))?;
        }
        Ok(Self(bytes))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub u16);

impl fmt::Display for NodeId {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Data {
    Nil,
    Bool(bool),
    Int(i64),
    Text(String),
    List(Vec<Data>),
    Record(BTreeMap<String, Data>),
    /// A strong Merkle edge when embedded in a content block.
    Link(Hash),
}

impl Data {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        wire::encode_value(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        wire::decode_value(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binary {
    Add,
    Greater,
    Equal,
}

/// Evaluation placement. Its hashes are network locators, with no local Merkle edges.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Placement {
    pub node: NodeId,
    pub data: Hash,
    pub program: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    Literal(Data),
    /// De Bruijn index, with zero referring to the innermost binding.
    Var(u16),
    Capture(u16),
    Lambda(Box<Expr>),
    Apply(Box<Expr>, Box<Expr>),
    Let(Box<Expr>, Box<Expr>),
    If(Box<Expr>, Box<Expr>, Box<Expr>),
    Binary(Binary, Box<Expr>, Box<Expr>),
    Field(Box<Expr>, String),
    List(Vec<Expr>),
    Record(BTreeMap<String, Expr>),
    Filter(Box<Expr>, Box<Expr>),
    /// Applies a curried `(accumulator) -> (element) -> accumulator` function.
    Fold(Box<Expr>, Box<Expr>, Box<Expr>),
    Cap(u16),
    Read(Box<Expr>, Box<Expr>),
    Pin(Box<Expr>, Box<Expr>),
    Clock(Box<Expr>),
    Log(Box<Expr>, Box<Expr>),
    Here(Box<Expr>),
    Remote(Box<Expr>, Placement),
    StoreRoot(Box<Expr>),
}

/// An expression plus an immutable, portable capture environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    pub expr: Expr,
    pub captures: Vec<Data>,
}

impl Program {
    pub fn new(expr: Expr, captures: Vec<Data>) -> Self {
        Self { expr, captures }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        wire::encode_program(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        match Block::from_bytes(bytes)? {
            Block::Program(program) => Ok(program),
            Block::Data(_) => Err(Error::Wire("expected code block")),
        }
    }

    pub fn hash(&self) -> Result<Hash> {
        Ok(Hash::digest(&self.to_bytes()?))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockKind {
    Data,
    Program,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    Data(Data),
    Program(Program),
}

impl Block {
    pub const MAX_BYTES: usize = wire::MAX_BYTES;

    pub fn kind(&self) -> BlockKind {
        match self {
            Self::Data(_) => BlockKind::Data,
            Self::Program(_) => BlockKind::Program,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Data(data) => wire::encode_data_block(data),
            Self::Program(program) => program.to_bytes(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        wire::decode_block(bytes)
    }

    pub fn hash(&self) -> Result<Hash> {
        Ok(Hash::digest(&self.to_bytes()?))
    }
}
