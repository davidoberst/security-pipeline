
# CI/CD Security Pipeline (DevSecOps Gate)

Pipeline de seguridad en GitHub Actions que escanea cada Pull Request y bloquea el
merge cuando **se introducen** vulnerabilidades CRITICAL/HIGH. Es modular: un
orquestador detecta lenguajes, lanza escáneres independientes y una única pieza
—el *security gate*— decide si el PR pasa o no.
-El CI/CD detecta el lenguaje de el repositorio o del PR y ejecuta herramientas segun lenguaje detectado 
-Se escanea todo el repositorio para ver un panorama completo de vulnerabilidades activas (solo bloquea PRs pero avisa de vulnerabilidas acumuladas no incluidas en el PR)


> **Repositorio de laboratorio.** Todo lo que hay en `samples/` es código
> **vulnerable a propósito y ficticio**, usado para probar el pipeline. No se
> despliega nada.

---

## 1. Reglas de oro (invariantes de diseño)

Estas reglas definen el comportamiento y **no deben romperse** al editar:

1. **Solo `security-gate` puede hacer fallar el pipeline.** Todos los módulos de
   escaneo corren con `continue-on-error: true` y sus scripts terminan siempre en
   `exit 0`. Si un escáner se cae, el gate lo reporta como "ERROR de herramienta"
   pero **no bloquea**.
2. **Solo bloquean hallazgos CRITICAL/HIGH.** MEDIUM avisa (va a backlog con SLA);
   LOW/INFO solo informan. Está forzado en código: aunque `policy.yml` pida
   bloquear otra severidad, el gate lo degrada a "avisa".
3. **Solo bloquea lo NUEVO del PR.** Un CRITICAL/HIGH que ya existía en el repo
   (deuda preexistente) avisa, no bloquea. Se calcula con el diff del PR
   (`origin/<base>...HEAD`).
4. **JSON nativo, nunca SARIF.** Cada herramienta emite su JSON y un normalizador
   lo traduce a un formato común. (No se usa SARIF-upload.)
5. **Versiones fijas (pinned).** Toda herramienta y toda GitHub Action se fija por
   versión/hash. Se instala descargando el binario + verificación de checksum, o
   por el sumdb de Go / el lockfile de npm.
6. **Los escáneres nunca instalan las dependencias del repo.** Se audita lo que
   está declarado (lockfiles, manifiestos), no se ejecuta código del proyecto.

---

## 2. Estructura de archivos (dónde está cada cosa)

```
security-pipeline/
├─ .github/
│  ├─ workflows/
│  │  └─ security.yml                 # ORQUESTADOR: triggers, jobs, orden de ejecución
│  └─ actions/                        # cada carpeta = una "composite action"
│     ├─ detect-languages/
│     │  └─ action.yml                # detecta Python/Go/Node por archivos marcadores
│     ├─ scan-common/
│     │  ├─ action.yml                # Gitleaks + Trivy fs + Semgrep (todo repo)
│     │  ├─ gitleaks.toml             # reglas/allowlist de secretos
│     │  └─ semgrep-rules/            # ruleset Semgrep VERSIONADO (no se baja de internet)
│     │     ├─ python.yml
│     │     ├─ go.yml
│     │     └─ js.yml
│     ├─ scan-python/
│     │  └─ action.yml                # Bandit + pip-audit + Ruff
│     ├─ scan-go/
│     │  ├─ action.yml                # gosec + govulncheck + staticcheck
│     │  ├─ por_modulo.sh             # corre cada herramienta una vez por go.mod
│     │  └─ combinar.py               # une las salidas por módulo en un solo JSON
│     ├─ scan-node/
│     │  ├─ action.yml                # ESLint(+security) + osv-scanner
│     │  └─ eslint/
│     │     ├─ eslint.config.mjs      # config ESLint versionada
│     │     ├─ eslint-tools.package.json       # deps de ESLint (NO es un proyecto del repo)
│     │     └─ eslint-tools.package-lock.json  # lock con integridad
│     └─ security-gate/
│        ├─ action.yml                # descarga artifacts, corre gate.py, comenta el PR
│        ├─ gate.py                   # NÚCLEO: decide y renderiza la salida
│        ├─ normalizers.py            # JSON de cada herramienta → formato común + dedup
│        └─ explicaciones.yml         # textos legibles por regla/CWE (qué es/riesgo/arreglo)
├─ gate-config/
│  └─ policy.yml                      # severidades por herramienta, SLA, acciones
├─ .security-exceptions.yml           # falsos positivos / riesgos aceptados (gobernado por CODEOWNERS)
├─ CODEOWNERS                         # quién aprueba cambios al pipeline
├─ samples/                           # código vulnerable FICTICIO para probar
│  ├─ python/   (vuln_sql.py, fake_secret.py, dead_code.py, requirements.txt)
│  ├─ go/       (main.go, go.mod, go.sum)
│  ├─ node/     (index.js, package.json, package-lock.json)
│  └─ Dockerfile.bad
└─ README.md
```

**Nombres a recordar:**
- Cada módulo sube un *artifact* llamado igual que su carpeta (`scan-common`,
  `scan-python`, `scan-go`, `scan-node`).
- Los reportes se escriben FUERA del workspace, en
  `$RUNNER_TEMP/security-reports/<modulo>/`, para que ningún escáner lea el reporte
  de otro.

---

## 3. Cómo se dispara (triggers)

Definidos en `security.yml` → `on:`

| Evento | Cuándo | Qué hace el gate |
|---|---|---|
| `pull_request` | al abrir/actualizar un PR | compara el diff y **bloquea** lo nuevo CRITICAL/HIGH |
| `push` a `main` | tras un merge | escanea todo; nada es "nuevo" → inventario, no bloquea |
| `schedule` (cron `0 6 * * *`, 01:00 Colombia) | diario | igual que push; Gitleaks con historial completo |
| `workflow_dispatch` | manual | permite forzar lenguajes y `tratar_todo_como_nuevo` (laboratorio) |

---

## 4. Flujo de ejecución (los jobs)

```
          ┌─────────────┐
          │   detect    │  detecta lenguajes (outputs: python/go/node/markers)
          └──────┬──────┘
                 │
     ┌───────────┼───────────────┬───────────────┐
     ▼           ▼               ▼               ▼
┌─────────┐ ┌──────────┐   ┌──────────┐   ┌──────────┐
│scan-    │ │scan-     │   │scan-go   │   │scan-node │   ← continue-on-error
│common   │ │python    │   │(si go)   │   │(si node) │     (NUNCA tumban el pipeline)
│(siempre)│ │(si python)│  └──────────┘   └──────────┘
└─────────┘ └──────────┘
     └───────────┴───────────────┴───────────────┘
                 │  (cada uno sube su artifact scan-*)
                 ▼
          ┌─────────────┐
          │security-gate│  ← ÚNICO job sin continue-on-error.
          └─────────────┘     Descarga los artifacts, normaliza, decide,
                              comenta en el PR y hace exit 1 si bloquea.
```

- `scan-common` **siempre** corre (no depende de `detect`).
- `scan-python/go/node` corren solo si `detect` marcó ese lenguaje (`if:`).
- `security-gate` tiene `needs: [detect, scan-common, scan-python, scan-go, scan-node]`
  y `if: always()`, para evaluar aunque algún escáner falle.
- `expected-modules` (lo que el gate "esperaba" que corriera) se arma con
  `format()` a partir de los outputs de `detect`; si un módulo esperado no subió
  reporte, la CLI lo muestra como "✗ sin reporte".

---

## 5. Los módulos de escaneo

Todos siguen el **mismo contrato**: instalan herramientas con versión fija, corren
cada una con `set +e` (captura el exit pero no falla), escriben en
`$RUNNER_TEMP/security-reports/<modulo>/`:

- `<herramienta>.json` → salida nativa
- `<herramienta>.exit` → código de salida (o `skip`)
- `<herramienta>.stderr.log` → errores
- `status.json` → resumen del módulo (lo que lee el gate)

Y suben todo como artifact. **`status.json`** marca cada herramienta como:
- `ok` → produjo JSON válido (aunque el exit sea ≠ 0; p. ej. "encontré hallazgos")
- `error` → no generó JSON o es inválido → **no bloquea**, pero se ve en la CLI
- `omitido` (`skip`) → no aplicaba (p. ej. no había `requirements.txt`)

### 5.1 `scan-common` (siempre)
| Herramienta | Qué detecta | Versión |
|---|---|---|
| **Gitleaks** | secretos/credenciales en código e historial git | 8.30.1 |
| **Trivy fs** | CVE de dependencias + misconfig de Dockerfile (`--scanners vuln,misconfig`) | 0.76.0 |
| **Semgrep** | SAST con el ruleset **local** de `semgrep-rules/` | 1.181.0 |

Gitleaks ajusta el rango según el evento: en PR solo los commits del PR
(`origin/<base>..HEAD`); en push desde el commit anterior; en schedule, historial
completo.

### 5.2 `scan-python` (si hay `requirements.txt`/`pyproject.toml`/`Pipfile`)
| Herramienta | Qué detecta | Versión |
|---|---|---|
| **Bandit** | SAST de seguridad | 1.9.4 |
| **pip-audit** | CVE de dependencias (audita `requirements*.txt`, `--no-deps`) | 2.10.1 |
| **Ruff** | lógica/calidad (bugs reales = MEDIUM; estilo = LOW) | 0.17.1 |

### 5.3 `scan-go` (si hay `go.mod`)
| Herramienta | Qué detecta | Versión |
|---|---|---|
| **gosec** | SAST de seguridad | 2.30.0 |
| **govulncheck** | CVE **alcanzables** (analiza llamadas reales) | 1.9.0 |
| **staticcheck** | lógica/calidad (SA* = bugs) | 0.8.2 (honnef.co/go/tools) |

Go corre con `GOTOOLCHAIN=local` (Go 1.27) y **una vez por cada `go.mod`**:
`por_modulo.sh` ejecuta la herramienta dentro de cada módulo y `combinar.py` une las
salidas en `{"modulos": [{"dir": ..., "resultado": <json>}]}`.
> ⚠️ **Limitación conocida (monorepo):** si UN módulo falla, `combinar.py` no escribe
> el JSON de esa herramienta → se pierde su cobertura en TODOS los módulos de esa
> corrida. Para el lab (un módulo) no se dispara. Antes de un repo con varios
> `go.mod`, conviene pasar a estado por-módulo.

### 5.4 `scan-node` (si hay `package.json` SIN `tsconfig.json`)
| Herramienta | Qué detecta | Versión |
|---|---|---|
| **ESLint + eslint-plugin-security** | SAST (reglas `security/*`) + lógica/calidad, en una corrida | fijado en `eslint-tools.package-lock.json` |
| **osv-scanner** | CVE de dependencias npm (lee lockfiles) | 2.7.0 |

ESLint usa `eslint.config.mjs` versionado. Las reglas `security/*` en `"error"` =
alta señal (HIGH); en `"warn"` = más ruidosas (MEDIUM). `detect-object-injection`
está apagada (puro ruido).

---

## 6. El gate (`security-gate/gate.py`)

Es el cerebro. Lee los `status.json` de los artifacts y, por cada hallazgo, ejecuta
este pipeline interno (ver `main()`):

1. **`cargar()`** — por cada herramienta `ok`, llama a su normalizador y acumula
   hallazgos en el formato común.
2. **`deduplicar()`** — une el mismo CVE/paquete visto por varias herramientas
   (p. ej. Trivy + govulncheck) y el mismo secreto visto por dos reglas.
3. **`explicar()`** — rellena "qué es / riesgo / arreglo" desde `explicaciones.yml`
   (por regla, por CWE o genérico por clase). En CVE siempre usa el texto genérico
   ("actualiza la dependencia").
4. **`marcar_nuevo()`** — decide si el hallazgo es nuevo:
   - en PR: ¿su línea está en el diff `origin/<base>...HEAD`? (Gitleaks siempre
     cuenta como nuevo porque ya escanea solo los commits del PR)
   - fuera de PR (push/schedule/manual): todo se trata como deuda existente.
5. **`decidir()`** — aplica `policy.yml`: severidad → acción. Bloquea solo si
   `nuevo AND severidad ∈ {CRITICAL, HIGH}`.
6. **`aplicar_excepcion()`** — si hay una excepción **vigente** en
   `.security-exceptions.yml` que calce, el hallazgo deja de bloquear (la excepción
   gana al bloqueo). Una excepción **vencida** vuelve a bloquear con una nota.
7. **`render()`** — arma la CLI (log del job + summary + comentario del PR).

`action.yml` del gate: descarga los artifacts (`pattern: scan-*`), instala PyYAML
fijo, corre `gate.py`, publica un **único comentario** en el PR (lo actualiza en
cada corrida) y, según el resultado, hace `exit 1` (bloqueado) o `exit 0`.

### Salidas que escribe el gate (en `OUT_DIR`)
`cli.txt` (log), `summary.md` (resumen de la corrida), `comment.md` (comentario del
PR), `findings.json` (hallazgos normalizados) y `decision.json`
(`{resultado, bloquean, modo}`).

---

## 7. Formato común y normalizadores (`normalizers.py`)

Cada herramienta tiene **una función** que convierte su JSON nativo a un dict común
vía `nuevo_hallazgo(...)`. Campos clave: `herramienta(s)`, `regla`, `severidad`,
`archivo`, `linea`, `cwe`, `clase` (`sast`/`cve`/`secreto`/`config`/`logica`/
`calidad`), `paquete`, `version`, `fix`, `ids`.

`deduplicar()` une por:
- **CVE**: mismo paquete + misma versión (comparada sin la `v` inicial que usa Go) +
  IDs en común. Conserva la severidad de la herramienta que sí la reporta.
- **secreto**: mismo archivo + línea + commit.

---

## 8. Configuración editable

### `gate-config/policy.yml`
Lo que ajustas **sin tocar código**:
- `acciones`: qué hace cada severidad (CRITICAL/HIGH `bloquea`; MEDIUM `avisa`;
  LOW/INFO `informa`). Poner `bloquea` en otra severidad se ignora con warning.
- `solo_nuevos: true`: solo lo nuevo bloquea.
- `sla_dias`: plazos de backlog por severidad (7/30/90/180).
- `severidades`: cómo se traduce la escala de **cada herramienta** a
  CRITICAL/HIGH/MEDIUM/LOW/INFO. `_otro` = valor por defecto.

### `security-gate/explicaciones.yml`
Textos legibles (qué es / riesgo / arreglo) indexados por `regla`, por `cwe` o
`genericos` por clase. Editable sin tocar la lógica.

### `.security-exceptions.yml` (falsos positivos / riesgos aceptados)
Cambios aquí **requieren aprobación de CODEOWNERS**. Formato de cada entrada:

```yaml
exceptions:
  - id: nombre-corto                 # para identificarla en la CLI
    regla: B608                      # id de la regla TAL COMO lo muestra la CLI (OBLIGATORIO)
    archivo: samples/python/x.py     # ruta exacta, sin comodines (OBLIGATORIO)
    linea: 8                         # opcional; sin ella aplica a todo el archivo
    razon: "por qué no es explotable o por qué se acepta"   # (OBLIGATORIO)
    aprobado_por: davidoberst
    creado: 2026-11-17
    vence: 2027-01-01                # (OBLIGATORIO) desde el día siguiente deja de aplicar
    tipo: falso_positivo             # falso_positivo | riesgo_aceptado
```
Una entrada inválida (sin campo obligatorio, fecha mal escrita, tipo desconocido) se
**ignora con warning** y no exceptúa nada. Al vencer, el hallazgo vuelve a bloquear.

---

## 9. Modos de operación (`SECURITY_GATE_MODE`)

Variable de repo/organización que entra como `mode` al gate:

- **`enforce`** (default) — evalúa y **bloquea** de verdad.
- **`report`** — evalúa y **muestra lo que bloquearía, pero no falla** (shadow mode,
  ideal para introducir el gate en un repo nuevo sin frenar al equipo).
- **`off`** — no evalúa.

---

## 10. Protección de rama y gobernanza

El bloqueo del gate solo sirve si `main` está protegida. En **Settings → Rules →
Rulesets**:
- **Require status checks** → el job `security-gate` debe pasar.
- **Require review from Code Owners** → cambios al pipeline los revisa quien figure
  en `CODEOWNERS`.
- **Bypass list** → "válvula de emergencia". Solo quienes estén en la lista pueden
  mergear saltándose el gate (override). El audit log de GitHub registra el bypass y
  es inmutable.

`CODEOWNERS` protege `.github/workflows/`, `.github/actions/`, `gate-config/`,
`.security-exceptions.yml` y `CODEOWNERS` (hoy → `@davidoberst`; en corporativo →
`@juanbustos67`).

---

## 11. Anatomía de la salida

El gate agrupa los hallazgos en secciones, en este orden:

1. **LO QUE BLOQUEA EL PR** — nuevos CRITICAL/HIGH del commit. Es lo único que debe
   corregirse para mergear.
2. **EXCEPCIONES ACTIVAS** — calzaron con una excepción firmada; no bloquean.
3. **TAMBIÉN INTRODUCIDAS POR ESTE COMMIT** — nuevos MEDIUM/LOW; no bloquean pero
   deben corregirse.
4. **VULNERABILIDADES YA EXISTENTES EN EL REPOSITORIO** — deuda preexistente; no la
   introdujo este commit y no bloquea el PR.

Campo por hallazgo `¿Introducido por este commit?` (en PR) o `¿Hallazgo nuevo?`
(fuera de PR), más `Tipo/Archivo/Qué es/Riesgo/Arreglo` y la flecha de decisión
(`→ BLOQUEA` / `→ AVISA` / `→ INFORMA`). Los textos cambian de redacción según sea
PR, push/nocturno o modo report.

---

## 12. Probar en local

El gate se puede correr fuera de Actions con variables de entorno. La bandera clave:

- `TREAT_ALL_AS_NEW=true` → trata todo hallazgo como nuevo (para ver el bloqueo sin
  un PR real).

Se le pasan `REPORTS_DIR` (carpeta con los `scan-*/status.json`), `POLICY`,
`EXCEPTIONS`, `MODE`, `EVENT`, `BASE_REF`, `OUT_DIR`, etc. (ver `contexto()` y
`action.yml` del gate para la lista completa).

---

## 13. Cómo agregar un lenguaje nuevo (guía de edición)

Patrón probado con Go y Node. Para un lenguaje `X`:

1. **Módulo de escaneo** — crea `.github/actions/scan-X/action.yml` copiando el
   molde de `scan-python` (el más simple): instala herramientas con **versión fija**,
   corre cada una con `set +e`, escribe `<tool>.json` + `.exit` + `.stderr.log`,
   genera `status.json` con el **mismo bloque** de los demás, y sube el artifact
   `scan-X`. Recuerda: `exit 0` siempre.
2. **Detección** — en `detect-languages/action.yml` agrega el archivo marcador de
   `X`, su salida `x=true/false` y su entrada en `markers`.
3. **Orquestador** — en `security.yml`: agrega el job `scan-X`
   (`needs: detect`, `if: needs.detect.outputs.x == 'true'`, `continue-on-error`),
   súmalo al `needs:` del gate y al `format()` de `expected-modules`.
4. **Normalizadores** — en `normalizers.py`, una función por herramienta que
   devuelva `nuevo_hallazgo(...)`. Regístralas en `gate.py`:
   `NORMALIZADORES`, `NOMBRE_LARGO`, `NOMBRE_CORTO` y `MODULOS`.
5. **Política** — en `policy.yml`, el bloque `severidades:` con el mapeo de escala de
   cada herramienta nueva.
6. **Textos (opcional)** — en `explicaciones.yml`, entradas por regla/CWE.
7. **Semgrep (opcional)** — reglas en `scan-common/semgrep-rules/X.yml` si aplican.
8. **Sample** — agrega `samples/X/` con vulnerabilidades ficticias para probar que
   bloquea.

---

## 14. Lenguajes

- **Soportados:** Python, Go, Node (JS backend). Común a todos: secretos (Gitleaks),
  CVE (Trivy), SAST (Semgrep).
- **Pendientes:** TypeScript (frontend), IaC (Terraform/HCL con Checkov), Shell
  (ShellCheck).

---

## 15. Convenciones

- **Lenguaje de la CLI:** español. Íconos de severidad: 🔴 CRITICAL · 🟠 HIGH ·
  🟡 MEDIUM · 🔵 LOW · ⚪ INFO.
- **Clases de hallazgo:** `sast`, `cve`, `secreto`, `config`, `logica`, `calidad`.
- **Severidad estimada:** cuando una herramienta no reporta severidad (pip-audit,
  govulncheck, osv-scanner), se usa la de Trivy para el mismo CVE; si Trivy no lo
  vio, un valor por defecto de `policy.yml`, marcado como "severidad estimada".
