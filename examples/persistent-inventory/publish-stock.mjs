export default async function publishStock({storage, capabilities, evaluate}, event) {
    // Retain the per-revision movement so that a replay builds the same remote request.
    const movement = await storage.get('movement/' + event.revision);
    if (!movement.found) throw new Error('warehouse movement is missing');
    const input = {...movement.value, revision: event.revision, event: event.id};
    for (let attempt = 0; attempt < 3; attempt++) {
        const office = await evaluate(capabilities.readOffice, input.sku, {calls: 0});
        try {
            return (await evaluate(capabilities.writeOffice, input, {
                calls: 0,
                update: {revision: office.revision, operation: event.id},
            })).value;
        } catch (error) {
            if (error.code !== 'conflict' || attempt === 2) throw error;
        }
    }
}
