export default async function sum({storage, capabilities, evaluate}, key) {
    const local = await storage.get(key);
    const remote = await evaluate(capabilities.remote, key, {calls: 0});
    return local.value + remote.value;
}
