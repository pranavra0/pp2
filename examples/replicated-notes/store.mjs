export default async function notes(pp2, input) {
    switch (input.command) {
        case 'list': {
            const result = await pp2.storage.scan({limit: 32});
            if (result.next !== null) throw new Error('Too many titles for this notes example');
            return result.entries;
        }
        case 'set':
            await pp2.storage.put(input.title, [input.text]);
            return null;
        case 'merge':
            // The app sends the union of all branch keys, including the selected branch.
            for (const [title, values] of input.notes) await pp2.storage.put(title, values);
            return null;
        default:
            throw new Error('Unknown notes operation');
    }
}
