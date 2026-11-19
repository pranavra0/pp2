// The index and documents occupy one reference so their updates commit together.
export interface LibraryDocument {
  id: string;
  title: string;
  text: string;
}

export interface LibraryState {
  documents: Record<string, LibraryDocument>;
  index: Record<string, string[]>;
}

export function terms(text: string): string[] {
  return [...new Set(text.normalize('NFKC').toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? [])];
}

export function checkId(id: string): void {
  if (typeof id !== 'string' || !/^[a-zA-Z0-9_-]{1,80}$/.test(id)) {
    throw new TypeError('document ID must contain 1–80 letters, digits, underscores or hyphens');
  }
}

export function keys(document: LibraryDocument): string[] {
  return terms(document.title + ' ' + document.text).map(term => '#' + term);
}
