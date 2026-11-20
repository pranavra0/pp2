export default async function setStock({storage}, {sku, quantity}) {
    if (typeof sku !== 'string' || !/^[a-z0-9-]{1,64}$/.test(sku)
        || !Number.isSafeInteger(quantity) || quantity < 0) {
        throw new Error('expected a SKU and a nonnegative stock quantity');
    }
    const sequence = await storage.get('sequence');
    const revision = (sequence.found ? sequence.value : 0) + 1;
    await storage.put('sequence', revision);
    await storage.put('stock/' + sku, quantity);
    await storage.put('movement/' + revision, {sku, quantity});
    return {sku, quantity};
}
