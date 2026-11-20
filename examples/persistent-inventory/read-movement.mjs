export default async function readMovement({storage}, revision) {
    const movement = await storage.get('movement/' + revision);
    if (!movement.found) throw new Error('warehouse movement is missing');
    return movement.value;
}
