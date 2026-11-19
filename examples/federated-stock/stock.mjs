export default async function stock(pp2, {sku, viaWest}) {
    const {storage, capabilities, evaluate} = pp2;
    if (typeof sku !== 'string' || !/^[a-z0-9-]{1,64}$/.test(sku)) {
        throw new Error('expected a product SKU');
    }

    const threshold = await storage.get(`minimum/${sku}`);
    let west;
    let east;
    if (viaWest) {
        const report = await evaluate(capabilities.west, {sku}, {
            calls: 1,
            delegate: [capabilities.east],
        });
        [west, east] = report.value;
    } else {
        const [westReport, eastReport] = await Promise.all([
            evaluate(capabilities.west, {sku}, {calls: 0}),
            evaluate(capabilities.east, {sku}, {calls: 0}),
        ]);
        [west] = westReport.value;
        [east] = eastReport.value;
    }

    const total = west + east;
    return {total, belowMinimum: threshold.found && total < threshold.value, warehouses: {west, east}};
}
