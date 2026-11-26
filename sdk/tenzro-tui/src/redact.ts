// Everything the console draws or prints that came from outside it (the node
// URL the person passed, an error's text) goes through `redact` first. The
// `Shown` type is the proof: the header, the plain report and a reading's
// error accept nothing else, so an unredacted string does not compile.

/** Text that has been through `redact` and may be drawn or printed. */
export type Shown = string & { readonly __shown: unique symbol };

const MASK = "***";

/** Names whose value is a credential wherever they appear as `name=value` or `name: value`. */
const PAIR_NAME = "access_token|refresh_token|token|api[_-]?key|apikey|secret|password|passwd|pwd|jwt|credential|private[_-]?key";
/** Query and fragment parameters whose value is a credential: the pair names, and the short ones a URL uses. */
const PARAM_NAME = `${PAIR_NAME}|key|auth|authorization|signature|sig`;

const RULES: [RegExp, string][] = [
  // user:password@ in a URL
  [/\b([a-z][a-z0-9+.-]*:\/\/)[^\s\/?#@]+@/gi, `$1${MASK}@`],
  // ?token=..., &api_key=..., #access_token=...
  [new RegExp(`([?&#](?:${PARAM_NAME})=)[^&#\\s]+`, "gi"), `$1${MASK}`],
  // Authorization header values
  [/\b(Bearer|DPoP|Basic)\s+[A-Za-z0-9._~+\/=-]{8,}/g, `$1 ${MASK}`],
  // A JWT anywhere
  [/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g, MASK],
  // password: ..., secret=..., "token": "..."
  [new RegExp(`\\b(${PAIR_NAME})("?\\s*[:=]\\s*"?)[^\\s"&#,;]+`, "gi"), `$1$2${MASK}`],
];

/** `text` with every credential it carries masked. Public values (addresses, DIDs, hashes) are left alone. */
export function redact(text: string): Shown {
  let out = text;
  for (const [pattern, to] of RULES) out = out.replace(pattern, to);
  return out as Shown;
}
