import {get, put, remove, scan} from './map.js';
import type {Blocks, Value} from './map.js';

type Request =
    | {type: 'get'; key: string}
    | {type: 'put'; key: string; value: Value}
    | {type: 'remove'; key: string}
    | {type: 'scan'; after?: string | null; before?: string | null; limit?: number};

export default async function evaluate({blocks}: {blocks: Blocks}, request: Request) {
    switch (request.type) {
        case 'get': return get(blocks, request.key);
        case 'put': await put(blocks, request.key, request.value); return true;
        case 'remove': return remove(blocks, request.key);
        case 'scan': return scan(blocks, request);
        default: throw new TypeError('expected get, put, remove, or scan');
    }
}
