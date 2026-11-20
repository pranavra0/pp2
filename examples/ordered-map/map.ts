export type Value = null | boolean | number | string | Value[] | {[key: string]: Value};

export interface Blocks {
    readonly root: string;
    read(hash: string): Promise<{value: Value; children: string[]}>;
    write(value: Value, children?: string[]): Promise<string>;
    setRoot(hash: string): Promise<void>;
}

interface Link {
    hash: string;
    height: number;
}

interface Node {
    key: string;
    value: Value;
    left: Link | null;
    right: Link | null;
}

const height = (link: Link | null) => link?.height ?? 0;

function checkKey(key: string): void {
    if (typeof key !== 'string' || key.length === 0 || key.length > 512) {
        throw new TypeError('expected a key of 1–512 JavaScript code units');
    }
}

async function load(blocks: Blocks, hash: string): Promise<Node | null> {
    const {value, children} = await blocks.read(hash);
    if (value === null && children.length === 0) return null;
    if (!Array.isArray(value) || value.length !== 4) throw new Error('invalid map node');
    const [key, item, left, right] = value;
    if (typeof key !== 'string' || item === undefined ||
        typeof left !== 'number' || typeof right !== 'number' ||
        !Number.isSafeInteger(left) || !Number.isSafeInteger(right) ||
        left < 0 || right < 0 || Math.abs(left - right) > 1 ||
        children.length !== Number(left > 0) + Number(right > 0)) {
        throw new Error('invalid map node');
    }
    return {
        key,
        value: item,
        left: left > 0 ? {hash: children[0]!, height: left} : null,
        right: right > 0 ? {hash: children[left > 0 ? 1 : 0]!, height: right} : null,
    };
}

async function loadChild(blocks: Blocks, link: Link): Promise<Node> {
    const node = await load(blocks, link.hash);
    if (!node || 1 + Math.max(height(node.left), height(node.right)) !== link.height) {
        throw new Error('invalid map child');
    }
    return node;
}

async function store(blocks: Blocks, {key, value, left, right}: Node): Promise<Link> {
    const children = [];
    if (left) children.push(left.hash);
    if (right) children.push(right.hash);
    const hash = await blocks.write([key, value, height(left), height(right)], children);
    return {hash, height: 1 + Math.max(height(left), height(right))};
}

async function rotate(blocks: Blocks, node: Node, side: 'left' | 'right'): Promise<Link> {
    const opposite = side === 'left' ? 'right' : 'left';
    const heavy = await loadChild(blocks, node[side]!);
    if (height(heavy[side]) >= height(heavy[opposite])) {
        const inward = await store(blocks, {...node, [side]: heavy[opposite]});
        return store(blocks, {...heavy, [opposite]: inward});
    }
    const pivot = await loadChild(blocks, heavy[opposite]!);
    const outward = await store(blocks, {...heavy, [opposite]: pivot[side]});
    const inward = await store(blocks, {...node, [side]: pivot[opposite]});
    return store(blocks, {...pivot, [side]: outward, [opposite]: inward});
}

function balance(blocks: Blocks, node: Node): Promise<Link> {
    const difference = height(node.left) - height(node.right);
    if (difference > 1) return rotate(blocks, node, 'left');
    if (difference < -1) return rotate(blocks, node, 'right');
    return store(blocks, node);
}

export async function get(blocks: Blocks, key: string): Promise<{found: false} | {found: true; value: Value}> {
    checkKey(key);
    let node = await load(blocks, blocks.root);
    while (node) {
        if (key === node.key) return {found: true, value: node.value};
        const link = key < node.key ? node.left : node.right;
        node = link && await loadChild(blocks, link);
    }
    return {found: false};
}

export async function put(blocks: Blocks, key: string, value: Value): Promise<void> {
    checkKey(key);
    if (JSON.stringify([key, value]).length > 32 * 1024) {
        throw new TypeError('map entry exceeds 32,768 JSON code units');
    }
    async function insert(node: Node | null): Promise<Link> {
        if (!node) return store(blocks, {key, value, left: null, right: null});
        if (node.key === key) return store(blocks, {...node, value});
        const side = key < node.key ? 'left' : 'right';
        const link = node[side];
        const child = await insert(link && await loadChild(blocks, link));
        return balance(blocks, {...node, [side]: child});
    }
    const root = await insert(await load(blocks, blocks.root));
    await blocks.setRoot(root.hash);
}

export async function remove(blocks: Blocks, key: string): Promise<boolean> {
    checkKey(key);
    async function takeFirst(node: Node): Promise<{first: Node; rest: Link | null}> {
        if (!node.left) return {first: node, rest: node.right};
        const {first, rest} = await takeFirst(await loadChild(blocks, node.left));
        return {first, rest: await balance(blocks, {...node, left: rest})};
    }
    async function erase(node: Node): Promise<Link | null | undefined> {
        if (key === node.key) {
            if (!node.left || !node.right) return node.left ?? node.right;
            const {first, rest} = await takeFirst(await loadChild(blocks, node.right));
            return balance(blocks, {...first, left: node.left, right: rest});
        }
        const side = key < node.key ? 'left' : 'right';
        const link = node[side];
        if (!link) return undefined;
        const child = await erase(await loadChild(blocks, link));
        if (child === undefined) return undefined;
        return balance(blocks, {...node, [side]: child});
    }
    const current = await load(blocks, blocks.root);
    if (!current) return false;
    const root = await erase(current);
    if (root === undefined) return false;
    await blocks.setRoot(root ? root.hash : await blocks.write(null));
    return true;
}

export async function scan(blocks: Blocks, {after = null, before = null, limit = 24}: {
    after?: string | null;
    before?: string | null;
    limit?: number;
} = {}): Promise<{entries: [string, Value][]; next: string | null}> {
    if (after !== null) checkKey(after);
    if (before !== null) checkKey(before);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 48) {
        throw new TypeError('expected a page size of 1–48');
    }
    const entries: [string, Value][] = [];
    let more = false;
    let remaining = 56 * 1024;
    async function visit(node: Node): Promise<void> {
        if (after === null || node.key > after) {
            if (node.left) await visit(await loadChild(blocks, node.left));
            if (more || (before !== null && node.key >= before)) return;
            const pair: [string, Value] = [node.key, node.value];
            const size = JSON.stringify(pair).length + 1;
            if (entries.length === limit || size > remaining) {
                more = true;
                return;
            }
            remaining -= size;
            entries.push(pair);
        }
        if (node.right && (before === null || node.key < before)) {
            await visit(await loadChild(blocks, node.right));
        }
    }
    const root = await load(blocks, blocks.root);
    if (root) await visit(root);
    return {entries, next: more ? entries.at(-1)?.[0] ?? null : null};
}
