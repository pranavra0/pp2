export default async function read({storage}, key) {
    return (await storage.get(key)).value;
}
