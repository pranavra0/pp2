export default async function publishStock({capabilities, evaluate}, event) {
    const movement = await evaluate(capabilities.movement, event.revision, {calls: 0});
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
