import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * The sources themselves, checked for the damage a careless edit leaves.
 *
 * A control character inside JSX is not a syntax error, it is not a lint
 * error, and it does not show in a diff or in a terminal: it reaches the DOM
 * as an invisible character inside a heading. One got into a table header
 * through a bad search-and-replace and shipped. This is the cheapest way to
 * make sure the next one does not.
 */
function sources(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      out.push(...sources(path));
    } else if (/\.(ts|tsx|css|html)$/.test(name)) {
      out.push(path);
    }
  }
  return out;
}

describe("the sources", () => {
  it("contain no control characters", () => {
    const offenders: string[] = [];
    for (const path of sources(join(import.meta.dirname, "."))) {
      const text = readFileSync(path, "utf8");
      for (let i = 0; i < text.length; i++) {
        const code = text.charCodeAt(i);
        // Tab, newline and carriage return are the only ones that belong.
        if (code < 32 && code !== 9 && code !== 10 && code !== 13) {
          const line = text.slice(0, i).split("\n").length;
          offenders.push(`${path}:${line}: U+${code.toString(16).padStart(4, "0")}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});
