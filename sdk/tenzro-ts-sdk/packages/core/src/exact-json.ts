/** JSON whose integers stay exact: amounts beyond 2^53 are carried as bigints. */

/** `value` as JSON, with every bigint written as an integer literal. */
export function stringifyExact(value: unknown): string {
  const marked = JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? `\u0000big:${v.toString()}` : v));
  return marked.replace(/"\\u0000big:(-?\d+)"/g, "$1");
}

/**
 * Parses JSON keeping every integer exact: an integer literal past 2^53 (a
 * u64 amount as the node writes it) comes back as a bigint, every other
 * value as `JSON.parse` returns it.
 */
export function parseExact(text: string): unknown {
  const tag = `\u0000big${Math.random().toString(36).slice(2)}:`;
  let out = "";
  let from = 0;
  let marked = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x22) {
      // Skip the string, escapes included.
      for (i++; i < text.length && text.charCodeAt(i) !== 0x22; i++) if (text.charCodeAt(i) === 0x5c) i++;
      continue;
    }
    if (c !== 0x2d && (c < 0x30 || c > 0x39)) continue;
    let j = i + 1;
    while (j < text.length && /[0-9.eE+-]/.test(text[j])) j++;
    const literal = text.slice(i, j);
    if (/^-?\d+$/.test(literal) && !Number.isSafeInteger(Number(literal))) {
      out += text.slice(from, i) + JSON.stringify(tag + literal);
      from = j;
      marked = true;
    }
    i = j - 1;
  }
  if (!marked) return JSON.parse(text);
  return JSON.parse(out + text.slice(from), (_k, v) =>
    typeof v === "string" && v.startsWith(tag) ? BigInt(v.slice(tag.length)) : v,
  );
}
