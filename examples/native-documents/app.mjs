const options = {calls: 0};
const response = (...lines) => ({lines});
const offline = new Set(['peer-unavailable', 'timeout', 'busy']);

function results(paths, revision, cache = false) {
    const status = cache ? 'Offline cache' : 'Index';
    return response(status + ' revision ' + revision + ' · ' + paths.length + (paths.length === 1 ? ' match' : ' matches'),
        ...paths.map(path => path.replace(/[\r\n]/g, ' ')));
}

export default async function app({call, capabilities, evaluate, resource, storage}, input) {
    if (resource === null) {
        await storage.put(input.key, input.result);
        return true;
    }
    const event = await call(resource, 'event');
    const line = event.text.trim();
    if (line === '' || line === 'help') {
        return response('Document search', 'index', 'search WORDS', '.quit');
    }
    if (!capabilities.documents) return response('Connect the documents grant to search or index.');
    if (line === 'index') {
        try {
            const current = await evaluate(capabilities.documents, {type: 'status'}, options);
            const indexed = await evaluate(capabilities.documents, {type: 'index'}, {
                calls: 0,
                update: {revision: current.revision, operation: event.id},
            });
            return response('Indexed ' + indexed.value + (indexed.value === 1 ? ' document' : ' documents') + ' at revision ' + indexed.revision);
        } catch (error) {
            return response('Index refresh failed · ' + error.message);
        }
    }
    if (!line.startsWith('search ')) return response('Enter index, search WORDS, or help.');
    const query = line.slice(7).toLowerCase().trim();
    if (!query || query.length > 80) return response('Enter a query of 1–80 characters.');
    const key = 'search/' + query;
    let result;
    try {
        result = await evaluate(capabilities.documents, {type: 'search', query}, {
            calls: 0,
            timeoutMs: 2000,
        });
    } catch (error) {
        if (!offline.has(error.code)) return response('Search failed · ' + error.message);
        const cached = await storage.get(key);
        if (!cached.found) return response('Documents are offline. This query has no cached result.');
        return results(cached.value.value, cached.value.revision, true);
    }
    try {
        await evaluate(capabilities.state, {key, result}, {
            calls: 0,
            update: {revision: storage.revision, operation: event.id},
        });
    } catch (error) {
        return response(...results(result.value, result.revision).lines, 'Cache write failed · ' + error.message);
    }
    return results(result.value, result.revision);
}
