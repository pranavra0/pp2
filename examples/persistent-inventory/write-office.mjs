export default async function writeOffice({storage}, {sku, quantity, revision, event}) {
    if (typeof sku !== 'string' || !/^[a-z0-9-]{1,64}$/.test(sku)
        || !Number.isSafeInteger(quantity) || quantity < 0
        || typeof revision !== 'string' || !/^[0-9]+$/.test(revision)
        || typeof event !== 'string' || !/^[0-9a-f]{64}$/.test(event)) {
        throw new Error('invalid warehouse movement');
    }
    const key = 'warehouse/' + sku;
    const previous = await storage.get(key);
    if (previous.found && BigInt(previous.value.revision) >= BigInt(revision)) {
        return previous.value;
    }
    const projection = {quantity, revision, event};
    await storage.put(key, projection);
    return projection;
}
