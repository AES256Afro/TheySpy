import js from "@eslint/js";
import globals from "globals";

/** Server and scripts are plain ESM JavaScript; the UI is type-checked by tsc in `npm run build`. */
export default [
  { ignores: ["dist/**", "node_modules/**", "docs/**", "data/**"] },
  js.configs.recommended,
  {
    files: ["server/**/*.mjs", "scripts/**/*.mjs", "eslint.config.mjs"],
    languageOptions: { ecmaVersion: 2025, sourceType: "module", globals: { ...globals.node } },
    rules: {
      "no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrors: "none" }],
      "no-empty": ["error", { allowEmptyCatch: true }],
    },
  },
];
