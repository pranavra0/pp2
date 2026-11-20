/** The subset of the collection and directory APIs used by the indexer. */
export interface DirectoryGuest {
    resource: object;
    call(resource: object, operation: 'readText', input: {path: string}): Promise<string>;
    call(resource: object, operation: 'list', input: {path: string; after: string | null}):
        Promise<{entries: [string, string][]; next: string | null}>;
    storage: {
        get(key: string): Promise<{found: boolean; value?: unknown}>;
        put(key: string, value: number | string[]): Promise<unknown>;
        delete(key: string): Promise<unknown>;
        scan(options: {prefix: string; after: string | null; limit: number}):
            Promise<{entries: [string, unknown][]; next: string | null}>;
    };
}
