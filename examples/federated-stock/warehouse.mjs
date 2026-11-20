export default async function warehouse(pp2, {sku}) {
    const {storage} = pp2;
    if (typeof sku !== 'string' || !/^[a-z0-9-]{1,64}$/.test(sku)) {
        throw new Error('expected a product SKU');
    }

    const prefix = `stock/${sku}/`;
    let after = null;
    let total = 0;
    do {
        const page = await storage.scan({prefix, after, limit: 16});
        for (const [, quantity] of page.entries) total += quantity;
        after = page.next;
    } while (after !== null);

    return total;
}
