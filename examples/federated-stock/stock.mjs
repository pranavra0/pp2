export default async function stock({capabilities, evaluate, evaluateAll}, {sku, serial}) {
    if (typeof sku !== 'string' || !/^[a-z0-9-]{1,64}$/.test(sku)) {
        throw new Error('expected a product SKU');
    }

    const reads = [capabilities.minimum, capabilities.west, capabilities.east]
        .map(capability => ({capability, input: {sku}}));
    const reports = [];
    if (serial) {
        for (const {capability, input} of reads) {
            reports.push(await evaluate(capability, input, {calls: 0}));
        }
    } else {
        reports.push(...await evaluateAll(reads));
    }
    const [{value: minimum}, {value: west}, {value: east}] = reports;
    const total = west + east;
    return {total, belowMinimum: minimum.found && total < minimum.value, warehouses: {west, east}};
}
