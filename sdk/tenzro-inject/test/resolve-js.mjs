// The package is compiled for bundlers, which resolve extensionless relative
// imports; Node does not. This hook appends ".js" to relative specifiers that
// lack an extension so the tests can import dist/ directly.
import { register } from "node:module";

register(
  "data:text/javascript," +
    encodeURIComponent(`
export async function resolve(specifier, context, next) {
  if ((specifier.startsWith("./") || specifier.startsWith("../")) && !/\\.[a-z]+$/.test(specifier)) {
    return next(specifier + ".js", context);
  }
  return next(specifier, context);
}
`),
  import.meta.url,
);
