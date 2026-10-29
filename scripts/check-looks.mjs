import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { lookContrastFailures } from "../shared/contrast.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));

/** Every look must be readable: text, muted text, links, buttons and severity badges at WCAG AA. */
export function contrastProblems(looksFile = JSON.parse(readFileSync(path.join(root, "shared/looks.json"), "utf8"))) {
  return looksFile.looks.flatMap((look) => lookContrastFailures(look).map((failure) => `${look.id}: ${failure.pair} is ${failure.ratio}:1, needs ${failure.needs}:1`));
}

const colourLiteral = /#[0-9a-f]{3,8}\b|\brgba?\s*\(|\bhsla?\s*\(|\b(?:white|black)\b(?=\s*[;,)])/gi;

/**
 * Colours belong in shared/looks.json only. Anything written straight into the UI would ignore the
 * chosen look, so the check fails on any colour literal in src/ (tests excluded).
 * @param {string} [directory]
 */
export function colourLiterals(directory = path.join(root, "src")) {
  const found = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const file = path.join(dir, name);
      if (statSync(file).isDirectory()) { walk(file); continue; }
      if (!/\.(css|ts|tsx)$/.test(name) || /\.test\.tsx?$/.test(name) || name.endsWith(".d.ts")) continue;
      readFileSync(file, "utf8").split("\n").forEach((line, index) => {
        const code = line.replace(/\/\/.*$|\/\*.*?\*\//g, "");
        for (const match of code.matchAll(colourLiteral)) found.push(`${path.relative(root, file)}:${index + 1}: ${match[0]}`);
      });
    }
  };
  walk(directory);
  return found;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const problems = [...contrastProblems(), ...colourLiterals().map((hit) => `hard-coded colour ${hit} (use a token from shared/looks.json)`)];
  if (problems.length) {
    console.error(problems.join("\n"));
    process.exit(1);
  }
  console.log("Looks: every look passes WCAG AA, and src/ has no hard-coded colours.");
}
