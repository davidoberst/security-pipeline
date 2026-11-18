# bypass-log/

Registro de **overrides del security gate**: PRs que se mergearon aunque el job
`security-gate` los había **bloqueado** (alguien con permiso de bypass forzó el merge).

- Lo escribe automáticamente el bot (`.github/workflows/bypass-log.yml`) al cerrarse
  un PR mergeado cuyo gate terminó en rojo. Un merge con el gate en verde no genera nada.
- Un archivo JSON por bypass: `<fecha>-<commit corto>.json`, con el PR, el autor, quién
  hizo el bypass, la hora (UTC-5), los hallazgos que bloqueaban y la corrida del gate.
- Las ediciones manuales requieren revisión de seguridad (CODEOWNERS).

Este registro es una ayuda para revisar y dar seguimiento; **no** es inmutable. La fuente
de verdad es el **audit log de GitHub** (organización / repositorio), que registra los
bypasses de reglas de protección.
