//! Hosted pp2 runtime, authenticated peers, and an in-process test simulator.

mod capability;
mod cluster;
mod error;
mod ir;
pub mod peer;
mod store;
mod vm;
mod wire;

pub use capability::{Grant, Route, StoreAccess};
pub use cluster::{Cluster, Event, Link, LocalityPolicy, RunReport};
pub use error::{Error, Result};
pub use ir::{Binary, Block, BlockKind, Data, Expr, Hash, NodeId, Placement, Program};
pub use vm::Limits;
