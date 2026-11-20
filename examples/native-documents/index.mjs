const prefix = 'document/';
const maxDocuments = 32;
const maxDirectories = 20;

function words(text) {
    return (text.toLowerCase().match(/[a-z0-9]{1,64}/g) ?? []);
}

async function* documents(storage) {
    let after = null;
    do {
        const page = await storage.scan({prefix, after, limit: maxDocuments});
        yield* page.entries;
        after = page.next;
    } while (after !== null);
}

async function refresh({storage, resource, call}) {
    const pending = [''];
    const found = new Set();
    let visited = 0;
    while (pending.length) {
        const directory = pending.pop();
        if (++visited > maxDirectories) throw new Error('Directory limit exceeded');
        let after = null;
        do {
            const page = await call(resource, 'list', {path: directory, after});
            for (const [name, kind] of page.entries) {
                const path = directory ? directory + '/' + name : name;
                if (kind === 'directory') {
                    if (visited + pending.length >= maxDirectories) throw new Error('Directory limit exceeded');
                    pending.push(path);
                } else if (/\.(md|txt)$/i.test(name)) {
                    if (found.size >= maxDocuments) throw new Error('Document limit exceeded');
                    const text = await call(resource, 'readText', {path});
                    const key = prefix + path;
                    found.add(key);
                    await storage.put(key, [...new Set(words(text))]);
                }
            }
            after = page.next;
        } while (after !== null);
    }
    for await (const [key] of documents(storage)) {
        if (!found.has(key)) await storage.delete(key);
    }
    await storage.put('count', found.size);
    return found.size;
}

export default async function index(guest, request) {
    const {storage} = guest;
    switch (request.type) {
        case 'status': {
            const count = await storage.get('count');
            return count.found ? count.value : 0;
        }
        case 'index':
            return refresh(guest);
        case 'search': {
            if (typeof request.query !== 'string' || request.query.length > 80) throw new Error('Invalid query');
            const terms = words(request.query);
            const matches = [];
            if (terms.length) {
                for await (const [key, tokens] of documents(storage)) {
                    if (terms.every(term => tokens.includes(term))) matches.push(key.slice(prefix.length));
                }
            }
            return matches;
        }
        default:
            throw new Error('Unknown document operation');
    }
}
