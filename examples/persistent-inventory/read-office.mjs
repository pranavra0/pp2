export default async function readOffice({storage}, sku) {
    // The office also installs an observer to show that projection writes do not retrigger it.
    if (typeof sku !== 'string') throw new Error('expected a SKU');
    const item = await storage.get('warehouse/' + sku);
    return item.found ? item.value : null;
}
