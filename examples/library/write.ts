import { checkId, keys } from './index.js';
import type { LibraryDocument, LibraryState } from './index.js';

type Edit = Pick<LibraryDocument, 'id'> & (
  { type: 'add'; title: string; text: string } | { type: 'remove' }
);
type Update = { next: LibraryState; value: { id: string; changed: boolean } };

export default function write(state: LibraryState, edit: Edit): Update {
  if (edit.type !== 'add' && edit.type !== 'remove') throw new TypeError('unknown document edit');
  checkId(edit.id);
  const { documents, index } = state;
  const key = '@' + edit.id;
  const previous = documents[key];
  if (previous !== undefined) {
    for (const term of keys(previous)) {
      const postings = index[term];
      if (!postings) throw new Error('document is missing from the index');
      const remaining = postings.filter(id => id !== edit.id);
      if (remaining.length) index[term] = remaining;
      else delete index[term];
    }
    delete documents[key];
  }
  if (edit.type === 'add') {
    if (typeof edit.title !== 'string' || edit.title.length > 500 ||
        typeof edit.text !== 'string' || edit.text.length > 64_000) {
      throw new TypeError('expected a title and document text within the size limits');
    }
    const document = { id: edit.id, title: edit.title, text: edit.text };
    documents[key] = document;
    for (const term of keys(document)) (index[term] ??= []).push(edit.id);
  }
  return { next: state, value: { id: edit.id, changed: edit.type === 'add' || previous !== undefined } };
}
