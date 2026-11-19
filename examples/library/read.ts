import { checkId, terms } from './index.js';
import type { LibraryDocument, LibraryState } from './index.js';

type Query = { type: 'summary' } | { type: 'show'; id: string } | { type: 'search'; text: string };
type SearchHit = Pick<LibraryDocument, 'id' | 'title'>;
type QueryResult = { documents: number } | LibraryDocument | SearchHit[] | null;

export default function read({ documents, index }: LibraryState, query: Query): QueryResult {
  switch (query.type) {
    case 'summary':
      return { documents: Object.keys(documents).length };
    case 'show':
      checkId(query.id);
      return documents['@' + query.id] ?? null;
    case 'search': {
      if (typeof query.text !== 'string' || query.text.length > 1000) {
        throw new TypeError('query must contain at most 1000 characters');
      }
      const postings = terms(query.text).map(word => index['#' + word] ?? []);
      postings.sort((a, b) => a.length - b.length);
      const [first = [], ...rest] = postings;
      const other = rest.map(ids => new Set(ids));
      return first.filter(id => other.every(ids => ids.has(id))).sort().slice(0, 50)
        .map(id => {
          const document = documents['@' + id];
          if (!document) throw new Error('index references a missing document');
          return { id, title: document.title };
        });
    }
    default: throw new TypeError('unknown document query');
  }
}
