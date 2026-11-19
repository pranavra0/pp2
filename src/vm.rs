use std::{
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    Binary, Block, BlockKind, Cluster, Data, Error, Event, Expr, Grant, Hash, LocalityPolicy,
    NodeId, Placement, Program, Result, RunReport, StoreAccess,
    capability::{Authority, RoutesInner},
    wire,
};

// Bounds native stack use through guest calls and nested dispatch.
const MAX_VM_DEPTH: usize = 64;
const MAX_LOG_BYTES: usize = 4096;
const VALUE_SLOT: usize = 128;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub fuel: u64,
    /// Cumulative charged allocations across the entire evaluation chain.
    pub memory_bytes: usize,
    /// Independent limits for host wall time and simulated transport time.
    pub timeout_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            fuel: 250_000,
            memory_bytes: 128 * 1024 * 1024,
            timeout_ms: 2_000,
        }
    }
}

struct Budget {
    limits: Limits,
    remaining_fuel: u64,
    allocated: usize,
    started: Instant,
    elapsed_ms: u64,
}

impl Budget {
    fn check_time(&self) -> Result<()> {
        if self.started.elapsed() >= Duration::from_millis(self.limits.timeout_ms)
            || self.elapsed_ms > self.limits.timeout_ms
        {
            return Err(Error::Timeout);
        }
        Ok(())
    }

    fn tick(&mut self, cost: u64) -> Result<()> {
        self.check_time()?;
        self.remaining_fuel = self.remaining_fuel.checked_sub(cost).ok_or(Error::Fuel)?;
        Ok(())
    }

    fn allocate(&mut self, bytes: usize) -> Result<()> {
        self.check_time()?;
        let total = self.allocated.checked_add(bytes).ok_or(Error::Memory)?;
        if total > self.limits.memory_bytes {
            return Err(Error::Memory);
        }
        self.allocated = total;
        Ok(())
    }

    fn bytes(&mut self, bytes: usize) -> Result<()> {
        self.tick(1 + bytes as u64 / 32)
    }

    fn decode(&mut self, bytes: usize) -> Result<()> {
        // Bounded wire values may expand into AST nodes, vectors, maps and link indexes.
        self.bytes(bytes)?;
        self.allocate(bytes.saturating_mul(256).saturating_add(VALUE_SLOT))
    }

    fn transport(&mut self, ms: u64) -> Result<()> {
        self.elapsed_ms = self.elapsed_ms.saturating_add(ms);
        self.check_time()
    }
}

#[derive(Clone)]
enum Value {
    Data(Rc<Data>),
    Function(usize),
    Capability(Grant),
}

impl Value {
    fn data(self) -> Result<Rc<Data>> {
        match self {
            Self::Data(data) => Ok(data),
            _ => Err(Error::Type("portable data")),
        }
    }

    fn cap(self) -> Result<Grant> {
        match self {
            Self::Capability(grant) => Ok(grant),
            _ => Err(Error::Type("a capability handle")),
        }
    }
}

type Env = Option<usize>;

struct Binding {
    value: Value,
    parent: Env,
}

#[derive(Clone, Copy)]
struct Function<'code> {
    body: &'code Expr,
    env: Env,
}

// Indexes keep closure chains from using the host stack when the heap is dropped.
#[derive(Default)]
struct Heap<'code> {
    bindings: Vec<Binding>,
    functions: Vec<Function<'code>>,
}

#[derive(Clone, Copy, Default)]
struct Path {
    hops: u16,
    rtt_ms: u64,
}

struct Frame<'code> {
    node: NodeId,
    captures: &'code [Data],
    grants: &'code [Grant],
    path: Path,
}

pub(crate) struct Vm<'host> {
    cluster: &'host mut Cluster,
    budget: Budget,
    locality: LocalityPolicy,
}

impl<'host> Vm<'host> {
    pub(crate) fn new(
        cluster: &'host mut Cluster,
        limits: Limits,
        locality: LocalityPolicy,
    ) -> Self {
        Self {
            cluster,
            budget: Budget {
                limits,
                remaining_fuel: limits.fuel,
                allocated: 0,
                started: Instant::now(),
                elapsed_ms: 0,
            },
            locality,
        }
    }

    pub(crate) fn run(
        mut self,
        node: NodeId,
        program: Hash,
        grants: &[Grant],
    ) -> Result<RunReport> {
        let value = self.run_block(node, program, grants, Path::default(), 0)?;
        self.budget.bytes(wire::value_size(&value)?)?;
        Ok(RunReport {
            value,
            fuel_used: self.budget.limits.fuel - self.budget.remaining_fuel,
            allocated_bytes: self.budget.allocated,
            elapsed_ms: self.budget.elapsed_ms,
        })
    }

    fn run_block(
        &mut self,
        node: NodeId,
        hash: Hash,
        grants: &[Grant],
        path: Path,
        depth: usize,
    ) -> Result<Data> {
        let entry = self.cluster.entry(node, hash)?;
        if entry.kind != BlockKind::Program {
            return Err(Error::WrongBlockKind { hash });
        }
        self.budget.decode(entry.bytes.len())?;
        let program = Program::from_bytes(&entry.bytes)?;
        let frame = Frame {
            node,
            captures: &program.captures,
            grants,
            path,
        };
        let data = self
            .eval(&program.expr, None, &frame, &mut Heap::default(), depth)?
            .data()?;
        Ok(Rc::into_inner(data).expect("the evaluation heap has been released"))
    }

    fn heap_data(&mut self, data: Data) -> Result<Value> {
        self.budget.allocate(VALUE_SLOT)?;
        Ok(Value::Data(Rc::new(data)))
    }

    fn copy_value(&mut self, data: &Data) -> Result<Value> {
        let copy = self.copy_data(data, 0)?;
        self.heap_data(copy)
    }

    fn copy_data(&mut self, data: &Data, depth: usize) -> Result<Data> {
        self.budget.tick(1)?;
        wire::check_depth(depth)?;
        Ok(match data {
            Data::Nil => Data::Nil,
            Data::Bool(value) => Data::Bool(*value),
            Data::Int(value) => Data::Int(*value),
            Data::Link(hash) => Data::Link(*hash),
            Data::Text(text) => Data::Text(self.copy_text(text)?),
            Data::List(values) => {
                self.list_space(values.len())?;
                let mut list = Vec::with_capacity(values.len());
                for value in values {
                    list.push(self.copy_data(value, depth + 1)?);
                }
                Data::List(list)
            }
            Data::Record(values) => {
                self.record_space(values.len())?;
                let mut record = BTreeMap::new();
                for (key, value) in values {
                    record.insert(self.copy_text(key)?, self.copy_data(value, depth + 1)?);
                }
                Data::Record(record)
            }
        })
    }

    fn list_space(&mut self, count: usize) -> Result<()> {
        self.budget.allocate(count * std::mem::size_of::<Data>())
    }

    fn record_space(&mut self, count: usize) -> Result<()> {
        self.budget.allocate(1024 + count * 192)
    }

    fn copy_text(&mut self, text: &str) -> Result<String> {
        self.budget.bytes(text.len())?;
        self.budget.allocate(text.len())?;
        Ok(text.to_owned())
    }

    fn bind(&mut self, heap: &mut Heap<'_>, env: Env, value: Value) -> Result<Env> {
        self.budget.allocate(VALUE_SLOT)?;
        let index = heap.bindings.len();
        heap.bindings.push(Binding { value, parent: env });
        Ok(Some(index))
    }

    fn apply<'code>(
        &mut self,
        function: &Value,
        arg: Value,
        frame: &Frame<'code>,
        heap: &mut Heap<'code>,
        depth: usize,
    ) -> Result<Value> {
        let Value::Function(index) = function else {
            return Err(Error::Type("a function"));
        };
        let function = heap.functions[*index];
        let env = self.bind(heap, function.env, arg)?;
        self.eval(function.body, env, frame, heap, depth)
    }

    fn eval<'code>(
        &mut self,
        expr: &'code Expr,
        env: Env,
        frame: &Frame<'code>,
        heap: &mut Heap<'code>,
        depth: usize,
    ) -> Result<Value> {
        if depth >= MAX_VM_DEPTH {
            return Err(Error::Stack);
        }
        self.budget.tick(1)?;
        let next = depth + 1;
        match expr {
            Expr::Literal(data) => self.copy_value(data),
            Expr::Var(index) => {
                let mut current = env;
                for _ in 0..*index {
                    self.budget.tick(1)?;
                    current = heap.bindings[current.ok_or(Error::Unbound(*index))?].parent;
                }
                Ok(heap.bindings[current.ok_or(Error::Unbound(*index))?]
                    .value
                    .clone())
            }
            Expr::Capture(index) => {
                let data = frame
                    .captures
                    .get(usize::from(*index))
                    .ok_or(Error::MissingCapture(*index))?;
                self.copy_value(data)
            }
            Expr::Lambda(body) => {
                self.budget.allocate(VALUE_SLOT)?;
                let index = heap.functions.len();
                heap.functions.push(Function { body, env });
                Ok(Value::Function(index))
            }
            Expr::Cap(slot) => frame
                .grants
                .get(usize::from(*slot))
                .cloned()
                .map(Value::Capability)
                .ok_or(Error::MissingCapability(*slot)),
            Expr::Apply(..) | Expr::Let(..) | Expr::If(..) | Expr::Binary(..) => {
                self.eval_flow(expr, env, frame, heap, next)
            }
            Expr::Field(..)
            | Expr::List(..)
            | Expr::Record(..)
            | Expr::Filter(..)
            | Expr::Fold(..) => self.eval_collection(expr, env, frame, heap, next),
            Expr::Read(..)
            | Expr::Pin(..)
            | Expr::Clock(..)
            | Expr::Log(..)
            | Expr::Here(..)
            | Expr::Remote(..)
            | Expr::StoreRoot(..) => self.eval_effect(expr, env, frame, heap, next),
        }
    }

    fn eval_flow<'code>(
        &mut self,
        expr: &'code Expr,
        env: Env,
        frame: &Frame<'code>,
        heap: &mut Heap<'code>,
        next: usize,
    ) -> Result<Value> {
        match expr {
            Expr::Apply(function, arg) => {
                let function = self.eval(function, env, frame, heap, next)?;
                let arg = self.eval(arg, env, frame, heap, next)?;
                self.apply(&function, arg, frame, heap, next)
            }
            Expr::Let(value, body) => {
                let value = self.eval(value, env, frame, heap, next)?;
                let extended = self.bind(heap, env, value)?;
                self.eval(body, extended, frame, heap, next)
            }
            Expr::If(condition, yes, no) => {
                let condition = self.eval(condition, env, frame, heap, next)?.data()?;
                let branch = if boolean(&condition)? { yes } else { no };
                self.eval(branch, env, frame, heap, next)
            }
            Expr::Binary(op, a, b) => {
                let a = self.eval(a, env, frame, heap, next)?.data()?;
                let b = self.eval(b, env, frame, heap, next)?.data()?;
                let result = match op {
                    Binary::Add => Data::Int(
                        integer(&a)?
                            .checked_add(integer(&b)?)
                            .ok_or(Error::Overflow)?,
                    ),
                    Binary::Greater => Data::Bool(integer(&a)? > integer(&b)?),
                    Binary::Equal => Data::Bool(self.equal(&a, &b)?),
                };
                self.heap_data(result)
            }
            _ => unreachable!("opcode classified by eval"),
        }
    }

    fn eval_collection<'code>(
        &mut self,
        expr: &'code Expr,
        env: Env,
        frame: &Frame<'code>,
        heap: &mut Heap<'code>,
        next: usize,
    ) -> Result<Value> {
        match expr {
            Expr::Field(record, key) => {
                let record = self.eval(record, env, frame, heap, next)?.data()?;
                let Data::Record(fields) = record.as_ref() else {
                    return Err(Error::Type("a record"));
                };
                self.budget.bytes(key.len())?;
                let Some(value) = fields.get(key) else {
                    return Err(Error::MissingField(self.copy_text(key)?));
                };
                self.copy_value(value)
            }
            Expr::List(items) => {
                self.list_space(items.len())?;
                let mut result = Vec::with_capacity(items.len());
                for item in items {
                    let value = self.eval(item, env, frame, heap, next)?.data()?;
                    result.push(self.copy_data(&value, 1)?);
                }
                self.heap_data(Data::List(result))
            }
            Expr::Record(fields) => {
                self.record_space(fields.len())?;
                let mut result = BTreeMap::new();
                for (key, value) in fields {
                    let value = self.eval(value, env, frame, heap, next)?.data()?;
                    result.insert(self.copy_text(key)?, self.copy_data(&value, 1)?);
                }
                self.heap_data(Data::Record(result))
            }
            Expr::Filter(list, predicate) => {
                let list = self.eval(list, env, frame, heap, next)?.data()?;
                let predicate = self.eval(predicate, env, frame, heap, next)?;
                let items = sequence(&list)?;
                self.list_space(items.len())?;
                let mut filtered = Vec::with_capacity(items.len());
                for item in items {
                    let arg = self.copy_value(item)?;
                    let keep = self.apply(&predicate, arg, frame, heap, next)?.data()?;
                    if boolean(&keep)? {
                        filtered.push(self.copy_data(item, 1)?);
                    }
                }
                self.heap_data(Data::List(filtered))
            }
            Expr::Fold(list, initial, step) => {
                let list = self.eval(list, env, frame, heap, next)?.data()?;
                let mut acc = self.eval(initial, env, frame, heap, next)?;
                let step = self.eval(step, env, frame, heap, next)?;
                for item in sequence(&list)? {
                    let partial = self.apply(&step, acc, frame, heap, next)?;
                    let arg = self.copy_value(item)?;
                    acc = self.apply(&partial, arg, frame, heap, next)?;
                }
                Ok(acc)
            }
            _ => unreachable!("opcode classified by eval"),
        }
    }

    fn eval_effect<'code>(
        &mut self,
        expr: &'code Expr,
        env: Env,
        frame: &Frame<'code>,
        heap: &mut Heap<'code>,
        next: usize,
    ) -> Result<Value> {
        match expr {
            Expr::Read(cap, hash) => {
                let cap = self.eval(cap, env, frame, heap, next)?.cap()?;
                let hash = link(self.eval(hash, env, frame, heap, next)?.data()?.as_ref())?;
                cap.store(hash, StoreAccess::Read)?;
                self.read(frame.node, hash)
            }
            Expr::Pin(cap, hash) => {
                let cap = self.eval(cap, env, frame, heap, next)?.cap()?;
                let hash = link(self.eval(hash, env, frame, heap, next)?.data()?.as_ref())?;
                cap.store(hash, StoreAccess::ReadAndPin)?;
                self.budget.allocate(1024)?;
                let result = self.heap_data(Data::Link(hash))?;
                self.cluster.store_mut(frame.node)?.pin_leased(hash);
                Ok(result)
            }
            Expr::Clock(cap) => {
                self.eval(cap, env, frame, heap, next)?.cap()?.clock()?;
                let elapsed = i64::try_from(self.budget.elapsed_ms).map_err(|_| Error::Overflow)?;
                self.heap_data(Data::Int(elapsed))
            }
            Expr::Log(cap, message) => {
                let stream = self.eval(cap, env, frame, heap, next)?.cap()?.log()?;
                let message = self.eval(message, env, frame, heap, next)?.data()?;
                let Data::Text(message) = message.as_ref() else {
                    return Err(Error::Type("text"));
                };
                if message.len() > MAX_LOG_BYTES {
                    return Err(Error::Denied("log message exceeds size limit"));
                }
                self.budget.allocate(VALUE_SLOT)?;
                let message = self.copy_text(message)?;
                let result = self.heap_data(Data::Nil)?;
                self.cluster.record(Event::Log {
                    node: frame.node,
                    stream,
                    message,
                });
                Ok(result)
            }
            Expr::Here(cap) => {
                let cap = self.eval(cap, env, frame, heap, next)?.cap()?;
                self.heap_data(Data::Int(i64::from(cap.0.node.0)))
            }
            Expr::Remote(cap, placement) => {
                let onward = self
                    .eval(cap, env, frame, heap, next)?
                    .cap()?
                    .route(*placement)?;
                let result = self.dispatch(frame.node, *placement, onward, frame.path, next)?;
                self.heap_data(result)
            }
            Expr::StoreRoot(cap) => {
                let cap = self.eval(cap, env, frame, heap, next)?.cap()?;
                let Authority::Store { roots, .. } = &cap.0.authority else {
                    return Err(Error::Denied("expected a store grant"));
                };
                if roots.len() != 1 {
                    return Err(Error::Denied("expected exactly one store root"));
                }
                self.heap_data(Data::Link(*roots.first().expect("scope has one root")))
            }
            _ => unreachable!("opcode classified by eval"),
        }
    }

    fn equal(&mut self, a: &Data, b: &Data) -> Result<bool> {
        if matches!(a, Data::List(_) | Data::Record(_))
            || matches!(b, Data::List(_) | Data::Record(_))
        {
            return Err(Error::Type("scalar operands for equality"));
        }
        if let (Data::Text(a), Data::Text(b)) = (a, b) {
            self.budget.bytes(a.len().min(b.len()))?;
        }
        Ok(a == b)
    }

    fn read(&mut self, node: NodeId, hash: Hash) -> Result<Value> {
        let entry = self.cluster.entry(node, hash)?;
        if entry.kind != BlockKind::Data {
            return Err(Error::WrongBlockKind { hash });
        }
        self.budget.decode(entry.bytes.len())?;
        let Block::Data(data) = Block::from_bytes(&entry.bytes)? else {
            unreachable!("store validated the block kind");
        };
        self.heap_data(data)
    }

    fn dispatch(
        &mut self,
        from: NodeId,
        target: Placement,
        onward: Arc<RoutesInner>,
        path: Path,
        depth: usize,
    ) -> Result<Data> {
        let hop = self.cluster.link(from, target.node)?;
        let path = Path {
            hops: path.hops.saturating_add(1),
            rtt_ms: path.rtt_ms.saturating_add(hop.latency_ms.saturating_mul(2)),
        };
        if path.hops > self.locality.max_hops
            || (path.hops > 1 && path.rtt_ms > self.locality.max_chain_rtt_ms)
        {
            return Err(Error::Locality {
                from,
                to: target.node,
                hops: path.hops,
                rtt_ms: path.rtt_ms,
            });
        }
        self.budget.allocate(1536)?;
        let request = wire::encode_request(target)?;
        self.budget.transport(hop.transfer_ms(request.len()))?;
        self.budget.bytes(request.len())?;
        self.cluster.record(Event::EvalRequest {
            from,
            to: target.node,
            data: target.data,
            program: target.program,
            bytes: request.len(),
        });
        let Placement {
            node,
            data,
            program,
        } = wire::decode_request(&request)?;
        if self.cluster.entry(node, data)?.kind != BlockKind::Data {
            return Err(Error::WrongBlockKind { hash: data });
        }
        if !self.cluster.has(node, program)? {
            self.budget
                .tick(1 + self.cluster.neighbor_count(node)? as u64)?;
            let transfer = self.cluster.offer(node, program)?;
            if transfer.kind() != BlockKind::Program {
                return Err(Error::WrongBlockKind { hash: program });
            }
            self.budget.transport(transfer.elapsed_ms)?;
            self.budget.decode(transfer.len())?;
            self.budget.allocate(transfer.len())?;
            self.cluster.receive(transfer)?;
        }
        // A synchronous evaluation keeps the resident data alive, and this slot is read-only.
        let store = Grant::new(
            &self.cluster.issuer,
            node,
            Authority::Store {
                roots: BTreeSet::from([data]),
                access: StoreAccess::Read,
            },
        );
        let mut grants = vec![store];
        if !onward.0.is_empty() {
            grants.push(Grant::new(
                &self.cluster.issuer,
                node,
                Authority::Net(onward),
            ));
        }
        let result = self.run_block(node, program, &grants, path, depth)?;
        let reply_len = wire::value_size(&result)?;
        self.budget.bytes(reply_len)?;
        self.budget
            .allocate(reply_len.saturating_mul(2).saturating_add(VALUE_SLOT))?;
        let reply = result.to_bytes()?;
        self.budget.transport(hop.transfer_ms(reply.len()))?;
        self.budget.decode(reply.len())?;
        self.cluster.record(Event::EvalReply {
            from: node,
            to: from,
            bytes: reply.len(),
        });
        Data::from_bytes(&reply)
    }
}

fn boolean(data: &Data) -> Result<bool> {
    match data {
        Data::Bool(value) => Ok(*value),
        _ => Err(Error::Type("a boolean")),
    }
}

fn integer(data: &Data) -> Result<i64> {
    match data {
        Data::Int(value) => Ok(*value),
        _ => Err(Error::Type("an integer")),
    }
}

fn sequence(data: &Data) -> Result<&[Data]> {
    match data {
        Data::List(items) => Ok(items),
        _ => Err(Error::Type("a list")),
    }
}

fn link(data: &Data) -> Result<Hash> {
    match data {
        Data::Link(hash) => Ok(*hash),
        _ => Err(Error::Type("a content hash")),
    }
}
