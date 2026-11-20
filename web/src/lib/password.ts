/**
 * Password and passphrase generator.
 *
 * Every draw uses crypto.getRandomValues with rejection sampling, so the
 * distribution is uniform — a plain modulo would quietly bias the result.
 */

const LOWER = "abcdefghijkmnopqrstuvwxyz"; // no l
const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // no I, O
const DIGITS = "23456789"; // no 0, 1
const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?";
const AMBIGUOUS = "lIO01";

export interface PasswordOptions {
  length: number;
  lower: boolean;
  upper: boolean;
  digits: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
}

export const defaultPasswordOptions: PasswordOptions = {
  length: 20,
  lower: true,
  upper: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: true,
};

function alphabet(opts: PasswordOptions): string {
  let chars = "";
  if (opts.lower) chars += opts.excludeAmbiguous ? LOWER : LOWER + "l";
  if (opts.upper) chars += opts.excludeAmbiguous ? UPPER : UPPER + "IO";
  if (opts.digits) chars += opts.excludeAmbiguous ? DIGITS : DIGITS + "01";
  if (opts.symbols) chars += SYMBOLS;
  if (opts.excludeAmbiguous) {
    chars = [...chars].filter((c) => !AMBIGUOUS.includes(c)).join("");
  }
  return chars;
}

/** randomIndex draws a uniform integer in [0, max) without modulo bias. */
function randomIndex(max: number): number {
  if (max <= 0) throw new Error("empty alphabet");
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % max;
  }
}

export function generatePassword(opts: PasswordOptions): string {
  const chars = alphabet(opts);
  if (chars.length === 0) return "";
  const length = Math.max(4, Math.min(128, opts.length));
  let out = "";
  for (let i = 0; i < length; i++) out += chars[randomIndex(chars.length)];
  return out;
}

/** entropyBits is log2(alphabet^length), the honest figure for a random draw. */
export function entropyBits(opts: PasswordOptions): number {
  const size = alphabet(opts).length;
  if (size <= 1) return 0;
  return Math.round(Math.log2(size) * Math.max(4, Math.min(128, opts.length)));
}

export function entropyLabel(bits: number): { label: string; tone: "weak" | "fair" | "strong" } {
  if (bits < 60) return { label: `${bits} bits`, tone: "weak" };
  if (bits < 90) return { label: `${bits} bits`, tone: "fair" };
  return { label: `${bits} bits`, tone: "strong" };
}
