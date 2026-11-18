// Config ESLint del módulo scan-node (versionada; no se descarga de internet).
// Una sola corrida: el normalizador separa por ruleId →
//   security/*  → SAST de seguridad. "error" = alta señal (HIGH en policy.yml),
//                 "warn" = más ruidosa (MEDIUM).
//   el resto     → lógica (lista en policy.yml, MEDIUM) o calidad (LOW).
// Las severidades error/warn de las reglas que NO son security/* no importan:
// la clasifica policy.yml.
import js from "@eslint/js";
import security from "eslint-plugin-security";
import globals from "globals";

const comunes = {
  ecmaVersion: "latest",
  globals: { ...globals.node },
};

export default [
  {
    ignores: ["**/node_modules/**", "**/dist/**", "**/build/**", "**/coverage/**", "**/*.min.js"],
  },
  {
    files: ["**/*.js", "**/*.mjs"],
    languageOptions: { ...comunes, sourceType: "module" },
  },
  {
    files: ["**/*.cjs"],
    languageOptions: { ...comunes, sourceType: "commonjs" },
  },
  {
    files: ["**/*.js", "**/*.cjs", "**/*.mjs"],
    linterOptions: { reportUnusedDisableDirectives: "off" },
    plugins: { security },
    rules: {
      ...js.configs.recommended.rules,

      // ── Seguridad, alta señal → "error" (HIGH) ─────────────────────────
      "security/detect-eval-with-expression": "error",
      "security/detect-child-process": "error",
      "security/detect-non-literal-require": "error",
      "security/detect-bidi-characters": "error",
      "security/detect-disable-mustache-escape": "error",
      "security/detect-no-csrf-before-method-override": "error",

      // ── Seguridad, más ruidosa → "warn" (MEDIUM) ───────────────────────
      "security/detect-unsafe-regex": "warn",
      "security/detect-non-literal-regexp": "warn",
      "security/detect-non-literal-fs-filename": "warn",
      "security/detect-pseudoRandomBytes": "warn",
      "security/detect-possible-timing-attacks": "warn",
      "security/detect-buffer-noassert": "warn",
      "security/detect-new-buffer": "warn",
      "security/detect-invisible-characters": "warn",

      // Apagada: marca casi cualquier obj[variable]; su ruido taparía lo real.
      "security/detect-object-injection": "off",
    },
  },
];
