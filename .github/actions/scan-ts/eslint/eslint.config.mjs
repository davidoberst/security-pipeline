// Config ESLint del módulo scan-ts (versionada; no se descarga de internet).
// Parser de TypeScript SIN type-checking: NO hay parserOptions.project / projectService,
// porque eso exige instalar las dependencias y tipos del repo (regla de oro: nunca se instalan).
// Una sola corrida: el normalizador separa por ruleId →
//   security/*            → SAST de seguridad. "error" = alta señal (HIGH en policy.yml),
//                           "warn" = más ruidosa (MEDIUM).
//   @typescript-eslint/* y el resto → lógica (lista en policy.yml, MEDIUM) o calidad (LOW).
import js from "@eslint/js";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import security from "eslint-plugin-security";
import globals from "globals";

const ARCHIVOS_TS = ["**/*.ts", "**/*.tsx", "**/*.mts", "**/*.cts"];

export default [
  {
    ignores: ["**/node_modules/**", "**/dist/**", "**/build/**", "**/coverage/**", "**/*.d.ts"],
  },
  {
    files: ARCHIVOS_TS,
    languageOptions: {
      parser: tsParser,
      parserOptions: { ecmaVersion: "latest", sourceType: "module", ecmaFeatures: { jsx: true } },
      globals: { ...globals.node },
    },
    linterOptions: { reportUnusedDisableDirectives: "off" },
    plugins: { "@typescript-eslint": tsPlugin, security },
    rules: {
      ...js.configs.recommended.rules,
      // Ajustes oficiales de typescript-eslint para TS: apaga reglas core que el
      // compilador ya cubre (no-undef, no-redeclare…) y que darían falsos positivos.
      ...tsPlugin.configs["eslint-recommended"].overrides[0].rules,
      // Reglas recomendadas SIN type-checking.
      ...tsPlugin.configs.recommended.rules,
      // …pero aquí NO corre tsc: se reactivan las reglas core de bug real que ese ajuste
      // apaga "porque el compilador ya lo detecta" y que en TS no dan falsos positivos.
      // (no-undef / no-redeclare / no-dupe-class-members siguen apagadas: tipos y overloads.)
      "no-unreachable": "error",
      "no-const-assign": "error",
      "no-dupe-keys": "error",
      "no-func-assign": "error",
      "no-import-assign": "error",
      "no-class-assign": "error",
      "getter-return": "error",
      "no-setter-return": "error",
      "no-unsafe-negation": "error",
      "constructor-super": "error",
      "no-this-before-super": "error",

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
