#!/usr/bin/env python3
"""Security gate del laboratorio (secciones 5 y 6 de la especificación).

Lee los reportes JSON que suben los módulos scan-*, normaliza cada hallazgo, aplica
gate-config/policy.yml y genera la CLI de la sección 6. Escribe en OUT_DIR:
cli.txt, summary.md, comment.md, findings.json y decision.json.
La salida con código 1 la decide action.yml leyendo el resultado.
"""
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import normalizers as N  # noqa: E402

BLOQUEABLES = ("CRITICAL", "HIGH")   # nada fuera de esto bloquea, diga lo que diga policy.yml
ORDEN_SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
ICONO_SEV = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
CATEGORIAS = {"seguridad": ("🔒", "SEGURIDAD"), "logica": ("⚙️", "LÓGICA"), "calidad": ("🧹", "CALIDAD")}
MODULOS = [("scan-common", "común"), ("scan-python", "python"), ("scan-go", "go"), ("scan-node", "node")]
NOMBRE_LARGO = {"gitleaks": "Gitleaks", "trivy": "Trivy fs", "semgrep": "Semgrep",
                "bandit": "Bandit", "pip-audit": "pip-audit", "ruff": "Ruff"}
NOMBRE_CORTO = {**NOMBRE_LARGO, "trivy": "Trivy"}
NORMALIZADORES = {"gitleaks": N.gitleaks, "trivy": N.trivy, "semgrep": N.semgrep,
                  "bandit": N.bandit, "pip-audit": N.pip_audit, "ruff": N.ruff}
DOBLE, SIMPLE = "═" * 60, "─" * 60
MARCA_COMENTARIO = "<!-- security-gate-lab -->"
LIMITE_COMENTARIO = 60000            # GitHub admite ~65k caracteres por comentario
CAMPOS_SALIDA = ["herramienta", "herramientas", "regla", "categoria", "subtipo", "severidad",
                 "severidad_estimada", "archivo", "linea", "cwe", "titulo", "que_es", "riesgo",
                 "arreglo", "nuevo", "commit", "accion", "bloquea", "sla", "paquete", "version", "fix"]


def env(nombre, defecto=""):
    return os.environ.get(nombre, defecto).strip()


def aviso(msg):
    print(f"::warning title=security-gate::{msg}")


# ── Contexto y entrada ────────────────────────────────────────────────────
def contexto():
    evento, pr, ref = env("EVENT"), env("PR_NUMBER"), env("REF_NAME")
    etiqueta = {"pull_request": f"PR #{pr}", "push": f"push · {ref}", "schedule": "nocturno",
                "workflow_dispatch": f"manual · {ref}"}.get(evento, evento or "local")
    return {"evento": evento, "etiqueta": etiqueta, "repo": env("REPO", "repo-local"),
            "base": env("BASE_REF"), "run_url": env("RUN_URL"), "markers": env("MARKERS"),
            "esperados": env("EXPECTED_MODULES", "scan-common").split(),
            "todo_nuevo": env("TREAT_ALL_AS_NEW").lower() == "true"}


def validar_politica(pol):
    acciones = {str(k).upper(): v for k, v in (pol.get("acciones") or {}).items()}
    for sev, accion in list(acciones.items()):
        if accion == "bloquea" and sev not in BLOQUEABLES:
            aviso(f"policy.yml pide bloquear {sev}; solo CRITICAL/HIGH pueden bloquear → se trata como 'avisa'")
            acciones[sev] = "avisa"
    pol["acciones"] = acciones
    return pol


def cargar(reports, sev_pol):
    estados, hallazgos = {}, []
    for status_file in sorted(Path(reports).glob("*/status.json")):
        carpeta = status_file.parent
        try:
            st = json.loads(status_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            aviso(f"status.json ilegible en {carpeta.name}: {e}")
            continue
        estados[st.get("modulo", carpeta.name)] = st
        for t in st.get("herramientas", []):
            fn = NORMALIZADORES.get(t.get("herramienta"))
            if t.get("estado") != "ok" or fn is None:
                continue
            try:
                data = json.loads((carpeta / t["reporte"]).read_text(encoding="utf-8"))
                hallazgos += fn(data, sev_pol)
            except Exception as e:  # formato inesperado = error de herramienta, NO bloquea
                t["estado"], t["detalle"] = "error", f"el gate no pudo interpretar su JSON: {e}"
                aviso(f"{t['herramienta']}: {t['detalle']}")
    return estados, hallazgos


# ── Explicación legible ───────────────────────────────────────────────────
class _Seguro(dict):
    def __missing__(self, clave):
        return ""


def _fmt(plantilla, h):
    if not plantilla:
        return ""
    return str(plantilla).format_map(_Seguro({k: "" if v is None else v for k, v in h.items()})).strip()


def _buscar_regla(reglas, rid):
    if rid in reglas:
        return reglas[rid]
    return next((v for k, v in reglas.items() if rid.endswith("." + k)), {})


def explicar(h, cat):
    regla = _buscar_regla(cat.get("reglas") or {}, h["regla"])
    h["cwe"] = regla.get("cwe") or h["cwe"]
    por_cwe = (cat.get("cwe") or {}).get(h["cwe"], {})
    gen = (cat.get("genericos") or {}).get(h["clase"], {})
    for k in ("titulo", "subtipo", "categoria"):
        h[k] = regla.get(k) or h.get(k) or por_cwe.get(k) or gen.get(k) or ""
    h["titulo"] = h["titulo"] or h["mensaje"] or h["regla"]
    for k in ("que_es", "riesgo", "arreglo"):
        claves = ["arreglo_sin_fix", k] if (k == "arreglo" and h["clase"] == "cve" and not h["fix"]) else [k]
        plantilla = next((fuente[c] for c in claves for fuente in (regla, por_cwe, gen) if fuente.get(c)), "")
        h[k] = _fmt(plantilla, h) or h["mensaje"] or "—"


# ── ¿Es nuevo? ────────────────────────────────────────────────────────────
def lineas_cambiadas(base):
    """{archivo: {líneas añadidas/modificadas}} del PR, o None si no se pudo calcular."""
    cmd = ["git", "-c", "core.quotepath=off", "diff", "--unified=0", "--no-color", "--no-ext-diff",
           f"origin/{base}...HEAD"]
    try:
        salida = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", check=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        aviso(f"no se pudo calcular el diff contra origin/{base} ({e}); todo se trata como nuevo")
        return None
    cambios, actual = {}, None
    for linea in salida.splitlines():
        if linea.startswith("+++ "):
            ruta = linea[4:]
            actual = None if ruta == "/dev/null" else (ruta[2:] if ruta.startswith("b/") else ruta)
            if actual:
                cambios.setdefault(actual, set())
        elif linea.startswith("@@") and actual:
            m = re.search(r"\+(\d+)(?:,(\d+))?", linea)
            if m:
                inicio, n = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
                cambios[actual].update(range(inicio, inicio + n))
    return cambios


def commit_de(archivo, linea):
    try:
        salida = subprocess.run(["git", "blame", "--porcelain", "-L", f"{linea},{linea}", "HEAD", "--", archivo],
                                capture_output=True, text=True, check=True).stdout
        sha = salida.split(" ", 1)[0]
        return "" if not sha or set(sha) <= {"0"} else sha[:7]
    except (OSError, subprocess.CalledProcessError):
        return ""


def marcar_nuevo(h, ctx, cambios):
    if ctx["todo_nuevo"]:
        h["nuevo"] = True
    elif ctx["evento"] != "pull_request":
        h["nuevo"] = False                       # push / nocturno / manual: todo es deuda existente
    elif cambios is None or "gitleaks" in h["herramientas"]:
        h["nuevo"] = True                        # Gitleaks en PR ya escanea solo los commits del PR
    elif h["linea"]:
        h["nuevo"] = int(h["linea"]) in cambios.get(h["archivo"], ())
    else:
        h["nuevo"] = h["archivo"] in cambios
    if h["nuevo"] and not h["commit"] and h["archivo"] and h["linea"]:
        h["commit"] = commit_de(h["archivo"], h["linea"])


# ── Política ──────────────────────────────────────────────────────────────
def decidir(h, pol):
    sev = h["severidad"]
    accion = pol["acciones"].get(sev, "avisa")
    h["deuda"] = accion == "bloquea" and not h["nuevo"] and pol.get("solo_nuevos", True)
    if h["deuda"]:
        accion = "avisa"
    h["accion"] = accion
    h["bloquea"] = accion == "bloquea" and sev in BLOQUEABLES
    h["sla"] = (pol.get("sla_dias") or {}).get(sev) if accion == "avisa" else None


# ── Render de la CLI (sección 6) ──────────────────────────────────────────
def campo(etiqueta, valor):
    prefijo = f"    {etiqueta + ':':<9}"
    return textwrap.fill(str(valor), width=110, initial_indent=prefijo, subsequent_indent=" " * len(prefijo),
                         break_long_words=False, break_on_hyphens=False)


def flecha(h, modo):
    if h["bloquea"]:
        return "→ BLOQUEARÍA (modo report: no se bloquea)" if modo == "report" else "→ BLOQUEA"
    if h["accion"] == "avisa":
        sla = f"SLA {h['sla']} días" if h["sla"] else "sin SLA"
        return f"→ AVISA · backlog ({'deuda preexistente, ' if h['deuda'] else ''}{sla})"
    return "→ INFORMA"


def bloque(n, h, modo):
    icono_cat, nombre_cat = CATEGORIAS.get(h["categoria"], CATEGORIAS["seguridad"])
    herramientas = ", ".join(NOMBRE_CORTO.get(t, t) for t in h["herramientas"])
    subtipo = f" ({h['subtipo']})" if h["subtipo"] else ""
    tipo = f"{h['titulo']} ({h['cwe']})" if h["cwe"] else h["titulo"]
    if h["severidad_estimada"]:
        tipo += " · severidad estimada (la herramienta no la reporta)"
    if h["nuevo"]:
        nuevo = f"Sí (commit {h['commit']})" if h["commit"] else "Sí"
    else:
        nuevo = "No (deuda preexistente)"
    return "\n".join([
        f"{ICONO_SEV.get(h['severidad'], '⚪')} [{n}] {h['severidad']} · {icono_cat} {nombre_cat}{subtipo}   [{herramientas}]",
        campo("Tipo", tipo),
        campo("Archivo", f"{h['archivo']}:{h['linea']}" if h["linea"] else (h["archivo"] or "—")),
        campo("Qué es", h["que_es"]),
        campo("Riesgo", h["riesgo"]),
        campo("Nuevo", nuevo),
        campo("Arreglo", h["arreglo"]),
        "    " + flecha(h, modo),
    ])


def lenguajes(markers):
    if not markers or markers == "ninguno":
        return "ninguno (solo escáneres comunes)"
    return " · ".join(p.strip()[:1].upper() + p.strip()[1:] for p in markers.split(";") if p.strip())


def escaneres(estados, esperados):
    lineas, errores = [], []
    for modulo, grupo in MODULOS:
        st = estados.get(modulo)
        etiqueta = f"    {'[' + grupo + ']':<10}"
        if st is None:
            if modulo in esperados:
                lineas.append(f"{etiqueta}✗ sin reporte (el job {modulo} falló o no subió su artifact)")
                errores.append(f"{modulo}: sin reporte")
            continue
        items = []
        for t in st.get("herramientas", []):
            nombre = NOMBRE_LARGO.get(t["herramienta"], t["herramienta"])
            items.append(f"{nombre} " + {"ok": "✓", "omitido": "– omitido"}.get(t["estado"], "✗ ERROR"))
            if t["estado"] == "error":
                errores.append(f"{nombre}: {t.get('detalle', '')}".replace("\n", " ")[:180])
        lineas.append(etiqueta + "   ".join(items))
    return lineas, errores


def resultado(modo, n):
    s = "" if n == 1 else "s"
    if modo == "report":
        if n:
            return [f"  RESULTADO: ⚠️ MODO REPORT — habría bloqueado {n} hallazgo{s} HIGH/CRITICAL nuevo{s}",
                    "             (SECURITY_GATE_MODE=report: no se bloquea)"]
        return ["  RESULTADO: ✅ APROBADO (modo report) — sin hallazgos HIGH/CRITICAL nuevos"]
    if n:
        return [f"  RESULTADO: ❌ BLOQUEADO — {n} hallazgo{s} HIGH/CRITICAL nuevo{s}"]
    return ["  RESULTADO: ✅ APROBADO — sin hallazgos HIGH/CRITICAL nuevos"]


def pie_artifacts(ctx, modulos):
    lineas = ["  Salida cruda de cada escáner (JSON originales), como respaldo:",
              f"    Artifacts de esta corrida → {modulos}"]
    if ctx["run_url"]:
        lineas.append(f"    {ctx['run_url']}")
    return lineas


def render(ctx, modo, estados, hallazgos):
    bloq = [h for h in hallazgos if h["bloquea"]]
    otros = [h for h in hallazgos if not h["bloquea"]]
    esc, errores = escaneres(estados, ctx["esperados"])
    L = [DOBLE, f"  SECURITY GATE · {ctx['etiqueta']} · {ctx['repo']}", DOBLE, "",
         f"  Lenguaje detectado: {lenguajes(ctx['markers'])}", "", "  Escáneres ejecutados:", *esc]
    if errores:
        L += ["", "  ⚠️  Errores de herramienta (NO bloquean, pero esos resultados faltan):"]
        L += [f"     - {e}" for e in errores]
    L += ["", SIMPLE, *resultado(modo, len(bloq)), SIMPLE, ""]
    n = 0
    for h in bloq:
        n += 1
        L += [bloque(n, h, modo), ""]
    if not bloq:
        L += ["  (sin hallazgos HIGH/CRITICAL nuevos)", ""]
    L += [SIMPLE, "  OTROS HALLAZGOS (no bloquean, pero deben corregirse)", SIMPLE, ""]
    for h in otros:
        n += 1
        L += [bloque(n, h, modo), ""]
    if not otros:
        L += ["  (ninguno)", ""]
    cuenta = {s: sum(1 for h in hallazgos if h["severidad"] == s) for s in ORDEN_SEV}
    resumen = " · ".join(f"{cuenta[s]} {s}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
    if cuenta["INFO"]:
        resumen += f" · {cuenta['INFO']} INFO"
    linea_bloquea = (f"  Bloquea: 0 (modo report; habrían bloqueado {len(bloq)})" if modo == "report"
                     else f"  Bloquea: {len(bloq)} (los HIGH/CRITICAL nuevos)")
    modulos = ", ".join(m for m, _ in MODULOS if m in estados) or "ninguno"
    L += [SIMPLE, f"  Resumen: {resumen}", linea_bloquea, "",
          f"  ¿Crees que {'[1]' if bloq else '[n]'} es un falso positivo?",
          "  → Agrega la excepción en .security-exceptions.yml (razón + vencimiento).",
          "    La revisa seguridad (CODEOWNERS).", "",
          *pie_artifacts(ctx, modulos), DOBLE]
    return "\n".join(L)


def render_off(ctx):
    return "\n".join([DOBLE, f"  SECURITY GATE · {ctx['etiqueta']} · {ctx['repo']}", DOBLE, "",
                      "  RESULTADO: ⏸️ GATE APAGADO (SECURITY_GATE_MODE=off) — no se evaluó nada", "",
                      *pie_artifacts(ctx, "scan-*"), DOBLE])


def markdown(titulo, cli, limite=None):
    cuerpo = cli.replace("```", "ˋˋˋ")
    if limite and len(cuerpo) > limite:
        cuerpo = cuerpo[:limite] + "\n\n… (recortado por el límite de GitHub: la salida completa está en el summary de la corrida)"
    return f"### {titulo}\n\n```text\n{cuerpo}\n```\n"


# ── Main ──────────────────────────────────────────────────────────────────
def main():
    out = Path(env("OUT_DIR", "gate-out"))
    out.mkdir(parents=True, exist_ok=True)
    ctx = contexto()
    modo = env("MODE", "enforce").lower() or "enforce"
    if modo not in ("enforce", "report", "off"):
        aviso(f"SECURITY_GATE_MODE='{modo}' no es válido; se usa enforce")
        modo = "enforce"

    hallazgos, bloquean = [], 0
    if modo == "off":
        cli, res, titulo = render_off(ctx), "off", "⏸️ Security gate apagado"
    else:
        pol = validar_politica(yaml.safe_load(Path(env("POLICY", "gate-config/policy.yml")).read_text(encoding="utf-8")) or {})
        cat = yaml.safe_load((Path(__file__).resolve().parent / "explicaciones.yml").read_text(encoding="utf-8")) or {}
        estados, hallazgos = cargar(env("REPORTS_DIR", "reports"), pol.get("severidades") or {})
        hallazgos = N.deduplicar(hallazgos)
        cambios = (lineas_cambiadas(ctx["base"])
                   if ctx["evento"] == "pull_request" and not ctx["todo_nuevo"] else {})
        for h in hallazgos:
            explicar(h, cat)
            marcar_nuevo(h, ctx, cambios)
            decidir(h, pol)
        hallazgos.sort(key=lambda h: (ORDEN_SEV.get(h["severidad"], 9), not h["nuevo"], h["archivo"], h["linea"] or 0))
        bloquean = sum(1 for h in hallazgos if h["bloquea"])
        cli = render(ctx, modo, estados, hallazgos)
        if modo == "report":
            res = "report"
            titulo = (f"⚠️ Security gate (modo report): habría bloqueado {bloquean}" if bloquean
                      else "✅ Security gate: APROBADO (modo report)")
        else:
            res = "bloqueado" if bloquean else "aprobado"
            titulo = (f"❌ Security gate: BLOQUEADO — {bloquean} HIGH/CRITICAL nuevo{'s' if bloquean != 1 else ''}"
                      if bloquean else "✅ Security gate: APROBADO")

    print(cli)                                               # 1) log del job
    (out / "cli.txt").write_text(cli + "\n", encoding="utf-8")
    (out / "summary.md").write_text(markdown(titulo, cli), encoding="utf-8")       # 2) summary
    (out / "comment.md").write_text(MARCA_COMENTARIO + "\n" + markdown(titulo, cli, LIMITE_COMENTARIO),
                                    encoding="utf-8")                              # 3) comentario PR
    (out / "findings.json").write_text(json.dumps([{k: h.get(k) for k in CAMPOS_SALIDA} for h in hallazgos],
                                                  indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "decision.json").write_text(json.dumps({"resultado": res, "bloquean": bloquean, "modo": modo}),
                                       encoding="utf-8")
    if env("GITHUB_OUTPUT"):
        with open(env("GITHUB_OUTPUT"), "a", encoding="utf-8") as f:
            f.write(f"resultado={res}\nbloquean={bloquean}\n")


if __name__ == "__main__":
    main()
