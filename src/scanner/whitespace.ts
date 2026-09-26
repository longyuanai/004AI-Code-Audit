// The whitespace set shared with the Python stack (contracts/fingerprint.json,
// `canonicalWhitespace`). It is spelled out instead of using `\s` because
// JavaScript and Python disagree on six code points (U+FEFF vs U+001C-U+001F,
// U+0085) and both follow their engine's Unicode version.
export const CANONICAL_WHITESPACE_CODE_POINTS: readonly number[] = [
  0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x0020, 0x00a0, 0x1680,
  0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a,
  0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff,
];

/** Regex character-class body (no brackets), for composing larger classes. */
export const WHITESPACE_CHARS = CANONICAL_WHITESPACE_CODE_POINTS
  .map(cp => `\\u${cp.toString(16).padStart(4, '0')}`)
  .join('');
