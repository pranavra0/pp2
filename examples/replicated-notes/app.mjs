const usage = [
    'list',
    'show TITLE',
    'set TITLE TEXT',
    'merge',
    'resolve TITLE TEXT',
];

function combine(branches) {
    const notes = new Map();
    for (const {value: entries} of branches) {
        for (const [title, alternatives] of entries) {
            const values = notes.get(title) ?? new Set();
            for (const text of alternatives) values.add(text);
            notes.set(title, values);
        }
    }
    return [...notes].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
        .map(([title, alternatives]) => [title, [...alternatives].sort()]);
}

export default async function main(pp2) {
    const event = await pp2.call(pp2.resource, 'event');
    const match = /^(list|merge|show|set|resolve)(?: ([a-zA-Z0-9_-]{1,48})(?: (.+))?)?$/.exec(event.text);
    if (!match) return {lines: usage};
    const [, command, title, text] = match;
    if ((command === 'list' || command === 'merge') && title
        || command === 'show' && (!title || text)
        || (command === 'set' || command === 'resolve') && (!text || text.length > 160)) {
        return {lines: usage};
    }

    const store = (input, consistency = 'replica', update = null) =>
        pp2.evaluate(pp2.capabilities.notes, input, {calls: 0, consistency, update});

    const current = await store({command: 'list'});
    const {heads, revision: selected} = current.view;
    if (heads.length > 8) return {lines: ['Too many concurrent branches for this notes example.']};
    const branches = [current];
    for (const head of heads) {
        if (head !== selected) branches.push(await store({command: 'list'}, head));
    }
    const notes = combine(branches);

    if (command === 'list') {
        return {lines: notes.map(([key, values]) => values.length > 1
            ? key + ': conflict (' + values.length + ' versions)'
            : key + ': ' + values[0].slice(0, 96))};
    }
    if (command === 'show') {
        return {lines: notes.find(([key]) => key === title)?.[1] ?? ['No such note.']};
    }
    if (command === 'merge') {
        if (heads.length === 1) return {lines: ['The replica has one head.']};
        if (notes.length > 32) return {lines: ['This notes example can store 32 titles in a merged revision.']};
        await store({command: 'merge', notes}, 'replica', {
            revision: current.revision, operation: event.id, merge: true,
        });
        return {lines: ['Merged branches. Conflicting note texts are preserved.']};
    }
    if (heads.length > 1) return {lines: ['Merge the concurrent branches before editing.']};
    const previous = notes.find(([key]) => key === title);
    if (previous?.[1].length > 1 && command === 'set') {
        return {lines: ['This note has conflicting versions. Use resolve TITLE TEXT.']};
    }
    if (command === 'resolve' && !(previous?.[1].length > 1)) {
        return {lines: ['This note has no unresolved conflict.']};
    }
    if (!previous && notes.length === 32) return {lines: ['This notes example can store 32 titles.']};
    await store({command: 'set', title, text}, 'replica', {
        revision: current.revision, operation: event.id,
    });
    return {lines: [command === 'resolve' ? 'Resolved ' + title : 'Saved ' + title]};
}
