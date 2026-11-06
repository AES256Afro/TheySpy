// Numbers that arrive in a path, a query string or a body. Without these, "abc" became NaN, went
// into a statement or a date, and the owner saw "Something went wrong on the server" with SQLite's
// "datatype mismatch" in the log. A malformed number is the caller's mistake: say which one it is.
//
// Only plain digits are taken from text. "0x10" is a number to JavaScript and nobody else, and an
// id or a limit is written in decimal everywhere TheySpy produces one.

/** @param {unknown} value @returns {number | null} */
function wholeNumber(value) {
  if (typeof value === "number") return Number.isInteger(value) && value >= 0 ? value : null;
  if (typeof value === "string" && /^\d{1,15}$/.test(value)) return Number(value);
  return null;
}

/**
 * A whole number from a path parameter or a request body; a 400 that names the parameter otherwise.
 * @param {unknown} value @param {string} name @returns {number}
 */
export function intParam(value, name) {
  const n = wholeNumber(value);
  if (n === null) throw Object.assign(new Error(`${name} must be a whole number`), { status: 400 });
  return n;
}

/**
 * A whole number from a query string: the fallback when it is absent, a 400 when it is not a
 * number, and clamped to the range the route can answer when it is.
 * @param {unknown} value
 * @param {{ name: string, fallback: number, min?: number, max?: number }} options
 * @returns {number}
 */
export function intQuery(value, { name, fallback, min = 0, max = Number.MAX_SAFE_INTEGER }) {
  if (value === undefined || value === "") return fallback;
  const n = wholeNumber(value);
  if (n === null) throw Object.assign(new Error(`${name} must be a whole number`), { status: 400 });
  return Math.min(Math.max(n, min), max);
}
