export default async function sum({capabilities, evaluate}, {key, local}) {
    const remote = await evaluate(capabilities.remote, key, {calls: 0});
    return local + remote.value;
}
