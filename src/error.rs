use std::{error, fmt};

use crate::{Hash, NodeId};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Wire(&'static str),
    Integrity {
        expected: Hash,
        actual: Hash,
    },
    UnknownNode(NodeId),
    InvalidLink,
    MissingLink {
        from: NodeId,
        to: NodeId,
    },
    MissingBlock {
        node: NodeId,
        hash: Hash,
    },
    UnavailableBlock {
        node: NodeId,
        hash: Hash,
    },
    WrongBlockKind {
        hash: Hash,
    },
    IncompleteGraph {
        node: NodeId,
        missing: Hash,
    },
    MissingCapability(u16),
    Denied(&'static str),
    Type(&'static str),
    Unbound(u16),
    MissingCapture(u16),
    MissingField(String),
    Overflow,
    Fuel,
    Memory,
    Timeout,
    Stack,
    Locality {
        from: NodeId,
        to: NodeId,
        hops: u16,
        rtt_ms: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(reason) => write!(f, "invalid wire value: {reason}"),
            Self::Integrity { expected, actual } => {
                write!(f, "block hash mismatch: expected {expected}, got {actual}")
            }
            Self::UnknownNode(node) => write!(f, "unknown node {node}"),
            Self::InvalidLink => {
                write!(f, "a link needs distinct endpoints and positive bandwidth")
            }
            Self::MissingLink { from, to } => write!(f, "no link from {from} to {to}"),
            Self::MissingBlock { node, hash } => write!(f, "block {hash} is absent at node {node}"),
            Self::UnavailableBlock { node, hash } => {
                write!(
                    f,
                    "node {node} has no reachable advertised source for {hash}"
                )
            }
            Self::WrongBlockKind { hash } => write!(f, "unexpected kind for block {hash}"),
            Self::IncompleteGraph { node, missing } => {
                write!(
                    f,
                    "node {node} cannot retain a graph with missing block {missing}"
                )
            }
            Self::MissingCapability(slot) => write!(f, "capability slot {slot} was not granted"),
            Self::Denied(reason) => write!(f, "capability denied: {reason}"),
            Self::Type(expected) => write!(f, "expected {expected}"),
            Self::Unbound(index) => write!(f, "unbound lexical variable {index}"),
            Self::MissingCapture(index) => write!(f, "missing capture {index}"),
            Self::MissingField(name) => write!(f, "missing field {name:?}"),
            Self::Overflow => write!(f, "integer overflow"),
            Self::Fuel => write!(f, "evaluation exhausted its fuel"),
            Self::Memory => write!(f, "evaluation exhausted its allocation budget"),
            Self::Timeout => write!(f, "evaluation exceeded its deadline"),
            Self::Stack => write!(f, "evaluation exceeded its nesting limit"),
            Self::Locality {
                from,
                to,
                hops,
                rtt_ms,
            } => {
                write!(
                    f,
                    "locality policy blocked {from} -> {to}: {hops} hops, {rtt_ms} ms path RTT"
                )
            }
        }
    }
}

impl error::Error for Error {}
