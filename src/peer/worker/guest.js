(rpc, names, writeStorage, hasResource, revision) => {
    'use strict';

    const create = Object.create;
    const freeze = Object.freeze;
    const integer = Number.isSafeInteger;
    const parse = JSON.parse;
    const stringify = JSON.stringify;
    const Type = TypeError;
    const Failure = Error;
    const slots = new WeakMap();
    const get = slots.get.bind(slots);
    const has = slots.has.bind(slots);
    const isArray = Array.isArray;

    function replacer(_, value) {
        switch (typeof value) {
            case 'object':
                if (!has(value)) return value;
                throw new Type('capabilities cannot cross a data boundary');
            case 'string': case 'boolean': return value;
            case 'number': if (integer(value)) return value;
        }
        throw new Type('expected JSON data and safe integers');
    }

    const resource = hasResource ? freeze(create(null)) : null;
    if (hasResource) slots.set(resource, "");
    const capabilities = create(null);
    for (const name of names) {
        const cap = freeze(create(null));
        slots.set(cap, name);
        capabilities[name] = cap;
    }
    freeze(capabilities);

    function slot(capability) {
        const name = get(capability);
        if (!name) throw new Type('expected a capability from this invocation');
        return name;
    }

    function bounded(value) {
        if (!integer(value) || value < 0 || value > 65535) throw new Type('expected a bounded integer');
        return value;
    }

    function text(value) {
        if (typeof value !== 'string') throw new Type('expected a string');
        return value;
    }

    let pending = 0;
    async function request(kind, key, payload, aux, limit, timeout, revision, operation) {
        pending++;
        try {
            // Yield to the QuickJS job queue. Effects run in submission order.
            await null;
            const reply = parse(rpc([kind, key, payload, aux, limit, timeout, revision, operation]));
            if (!reply.ok) {
                const error = new Failure(reply.message);
                error.code = reply.code;
                if (reply.code === 'conflict') error.revision = reply.revision;
                throw error;
            }
            return reply.value;
        } finally {
            pending--;
        }
    }

    const currentRevision = Number(revision);
    const storage = freeze({
        get revision() {
            if (!integer(currentRevision)) throw new Type('revision exceeds the JavaScript safe integer range');
            return currentRevision;
        },
        async get(key) {
            return request('get', text(key), '', '', 0, 0, '', '');
        },
        async scan({prefix = '', after = null, limit = 64} = {}) {
            if (after === '') throw new Type('expected a nonempty cursor');
            return request('scan', text(prefix), after === null ? '' : text(after), '', bounded(limit), 0, '', '');
        },
        async put(key, value) {
            if (!writeStorage) throw new Type('expected an update invocation');
            return request('put', text(key), stringify(value, replacer), '', 0, 0, '', '');
        },
        async delete(key) {
            if (!writeStorage) throw new Type('expected an update invocation');
            return request('delete', text(key), '', '', 0, 0, '', '');
        },
    });

    const guest = freeze({
        storage,
        capabilities,
        resource,
        async call(capability, operation, input = null) {
            if (capability !== resource || resource === null) throw new Type('expected a host capability from this invocation');
            return request('host', text(operation), stringify(input, replacer), '', 0, 0, '', '');
        },
        async evaluate(capability, input, {calls, delegate = [], timeoutMs = null, update = null}) {
            if (!isArray(delegate) || delegate.length > 16) throw new Type('expected a bounded list of capabilities');
            let names = '';
            for (let i = 0; i < delegate.length; i++) {
                names += (i ? ',' : '') + slot(delegate[i]);
            }
            if (update !== null && (!integer(update.revision) || update.revision < 0)) {
                throw new Type('expected an update revision');
            }
            if (timeoutMs === 0) throw new Type('expected a positive child deadline');
            return request(
                'evaluate', slot(capability), stringify(input, replacer), names,
                bounded(calls), timeoutMs === null ? 0 : bounded(timeoutMs), update === null ? '' : '' + update.revision,
                update === null ? '' : text(update.operation),
            );
        },
    });

    return [guest, replacer, () => {
        if (pending !== 0) throw new Type('all pending effects must settle before returning');
    }];
}
