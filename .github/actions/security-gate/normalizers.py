"""Adaptadores por herramienta: JSON nativo → hallazgo en formato común (sección 5.1).

Cada función recibe el JSON ya parseado y la tabla 'severidades' de policy.yml, y
devuelve una lista de dicts. La explicación legible (qué es / riesgo / arreglo) la
agrega gate.py desde explicaciones.yml.
"""
import os
import re
from pathlib import Path

_EXCLUIR = {".git", "node_modules", ".venv", "venv", "vendor"}


def nuevo_hallazgo(**campos):
    h = {"herramienta": "", "herramientas": [], "regla": "", "categoria": "seguridad", "subtipo": "",
         "severidad": "MEDIUM", "archivo": "", "linea": None, "cwe": "", "titulo": "", "mensaje": "",
         "clase": "sast", "paquete": "", "version": "", "fix": "", "ids": [], "commit": "",
         "severidad_estimada": False}
    h.update(campos)
    h["herramientas"] = h["herramientas"] or [h["herramienta"]]
    return h


def severidad(tabla, valor, defecto="MEDIUM"):
    """Traduce la escala de la herramienta a la común usando la tabla de policy.yml."""
    if isinstance(tabla, str):
        return tabla.upper()
    tabla = tabla or {}
    return str(tabla.get(str(valor or "").upper(), tabla.get("_otro", defecto))).upper()


def ruta_relativa(ruta):
    """Ruta relativa al repo, venga como venga ('./x', absoluta del runner, Windows...)."""
    if not ruta:
        return ""
    p = str(ruta).replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    if p.startswith("/") or re.match(r"^[A-Za-z]:/", p):
        ws = os.environ.get("GITHUB_WORKSPACE", "").replace("\\", "/").rstrip("/")
        if ws and p.startswith(ws + "/"):
            return p[len(ws) + 1:]
        partes = p.split("/")
        for i in range(1, len(partes)):          # el sufijo más largo que exista en el checkout
            candidato = "/".join(partes[i:])
            if candidato and Path(candidato).exists():
                return candidato
    return p


def _nombre_pkg(nombre):
    return re.sub(r"[-_.]+", "-", nombre or "").lower()


def linea_de_dependencia(archivo, paquete):
    """Línea donde se declara la dependencia (para mostrarla y para saber si es nueva)."""
    if not archivo or not paquete:
        return None
    try:
        lineas = Path(archivo).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    objetivo = _nombre_pkg(paquete)
    for i, linea in enumerate(lineas, 1):        # requirements.txt
        m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", linea.split("#", 1)[0])
        if m and _nombre_pkg(m.group(1)) == objetivo:
            return i
    for i, linea in enumerate(lineas, 1):        # package.json, go.mod, etc.
        if re.search(rf'(^|[\s"/]){re.escape(paquete)}([\s"@]|$)', linea):
            return i
    return None


def archivos_requirements():
    encontrados = []
    for raiz, dirs, archivos in os.walk("."):
        dirs[:] = [d for d in dirs if d not in _EXCLUIR]
        for a in archivos:
            if a.startswith("requirements") and a.endswith(".txt"):
                encontrados.append(ruta_relativa(os.path.join(raiz, a)))
    return sorted(encontrados)


# ── Gitleaks ──────────────────────────────────────────────────────────────
def gitleaks(data, sev):
    return [nuevo_hallazgo(
        herramienta="gitleaks", regla=f.get("RuleID", ""), clase="secreto", subtipo="secreto",
        severidad=severidad(sev.get("gitleaks", "CRITICAL"), None, "CRITICAL"),
        archivo=ruta_relativa(f.get("File")), linea=f.get("StartLine"), cwe="CWE-798",
        titulo=f.get("Description") or "Secreto en el código", mensaje=f.get("Description", ""),
        commit=(f.get("Commit") or "")[:7]) for f in (data or [])]


# ── Trivy fs (CVE de dependencias + misconfig) ────────────────────────────
def trivy(data, sev):
    out = []
    for r in (data or {}).get("Results") or []:
        target = ruta_relativa(r.get("Target", ""))
        for v in r.get("Vulnerabilities") or []:
            vid, pkg, ver = v.get("VulnerabilityID", ""), v.get("PkgName", ""), v.get("InstalledVersion", "")
            out.append(nuevo_hallazgo(
                herramienta="trivy", regla=vid, clase="cve", subtipo="dependencia",
                severidad=severidad(sev.get("trivy"), v.get("Severity")),
                archivo=target, linea=linea_de_dependencia(target, pkg),
                cwe=(v.get("CweIDs") or [""])[0], titulo=f"{vid} en {pkg} {ver}",
                mensaje=v.get("Title") or (v.get("Description") or "")[:200],
                paquete=pkg, version=ver, fix=v.get("FixedVersion", ""),
                ids=[vid] + list(v.get("VendorIDs") or [])))
        for m in r.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            out.append(nuevo_hallazgo(
                herramienta="trivy", regla=m.get("ID", ""), clase="config", subtipo="configuración",
                severidad=severidad(sev.get("trivy"), m.get("Severity")),
                archivo=target, linea=(m.get("CauseMetadata") or {}).get("StartLine"),
                titulo=m.get("Title", ""), mensaje=m.get("Message") or m.get("Description", ""),
                fix=m.get("Resolution", "")))
    return out


# ── Semgrep ───────────────────────────────────────────────────────────────
_CAT_SEMGREP = {"security": "seguridad", "correctness": "logica", "performance": "logica",
                "best-practice": "calidad", "maintainability": "calidad", "portability": "calidad"}


def _id_semgrep(rid):
    """Semgrep antepone la ruta del ruleset local al id; nos quedamos con 'lab.…'."""
    m = re.search(r"(?:^|\.)(lab\..+)$", rid or "")
    return m.group(1) if m else (rid or "")


def semgrep(data, sev):
    out = []
    for r in (data or {}).get("results") or []:
        extra = r.get("extra") or {}
        md = extra.get("metadata") or {}
        cwe = md.get("cwe") or ""
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else ""
        out.append(nuevo_hallazgo(
            herramienta="semgrep", regla=_id_semgrep(r.get("check_id")),
            categoria=_CAT_SEMGREP.get(str(md.get("category", "")).lower(), "seguridad"),
            severidad=severidad(sev.get("semgrep"), extra.get("severity")),
            archivo=ruta_relativa(r.get("path")), linea=(r.get("start") or {}).get("line"),
            cwe=str(cwe).split(":", 1)[0].strip(),
            mensaje=" ".join(str(extra.get("message", "")).split())))
    return out


# ── Bandit ────────────────────────────────────────────────────────────────
def bandit(data, sev):
    out = []
    for r in (data or {}).get("results") or []:
        cwe = (r.get("issue_cwe") or {}).get("id")
        out.append(nuevo_hallazgo(
            herramienta="bandit", regla=r.get("test_id", ""), clase="sast",
            severidad=severidad(sev.get("bandit"), r.get("issue_severity")),
            archivo=ruta_relativa(r.get("filename")), linea=r.get("line_number"),
            cwe=f"CWE-{cwe}" if cwe else "", titulo=r.get("test_name", ""),
            mensaje=r.get("issue_text", "")))
    return out


# ── pip-audit (no trae severidad ni archivo) ──────────────────────────────
def pip_audit(data, sev):
    reqs = archivos_requirements()
    out = []
    for dep in (data or {}).get("dependencies") or []:
        nombre, version = dep.get("name", ""), dep.get("version", "")
        archivo, linea = "", None
        for req in reqs:
            linea = linea_de_dependencia(req, nombre)
            if linea:
                archivo = req
                break
        for v in dep.get("vulns") or []:
            ids = [v.get("id", "")] + list(v.get("aliases") or [])
            cve = next((i for i in ids if i.startswith("CVE-")), ids[0])
            out.append(nuevo_hallazgo(
                herramienta="pip-audit", regla=cve, clase="cve", subtipo="dependencia",
                severidad=severidad(sev.get("pip-audit", "MEDIUM"), None), severidad_estimada=True,
                archivo=archivo, linea=linea, titulo=f"{cve} en {nombre} {version}",
                mensaje=" ".join((v.get("description") or "").split())[:200],
                paquete=nombre, version=version, fix=", ".join(v.get("fix_versions") or []), ids=ids))
    return out


# ── Ruff (no trae severidad) ──────────────────────────────────────────────
def ruff(data, sev):
    conf = sev.get("ruff") or {}
    prefijos = tuple(conf.get("logica_prefijos") or ())
    out = []
    for r in data or []:
        codigo = r.get("code") or "E999"         # errores de sintaxis vienen sin código
        es_logica = codigo.startswith(prefijos) if prefijos else False
        out.append(nuevo_hallazgo(
            herramienta="ruff", regla=codigo,
            categoria="logica" if es_logica else "calidad", clase="logica" if es_logica else "calidad",
            severidad=str(conf.get("logica_severidad" if es_logica else "severidad", "LOW")).upper(),
            archivo=ruta_relativa(r.get("filename")), linea=(r.get("location") or {}).get("row"),
            mensaje=r.get("message", "")))
    return out


# ── Deduplicación ─────────────────────────────────────────────────────────
def deduplicar(hallazgos):
    """Une el mismo CVE/paquete visto por varias herramientas (Trivy + pip-audit) y el
    mismo secreto detectado por dos reglas en la misma línea. Se conserva la severidad
    de la herramienta que sí la reporta."""
    resultado = []
    for h in hallazgos:
        par = None
        if h["clase"] == "cve":
            par = next((o for o in resultado if o["clase"] == "cve"
                        and _nombre_pkg(o["paquete"]) == _nombre_pkg(h["paquete"])
                        and o["version"] == h["version"] and set(o["ids"]) & set(h["ids"])), None)
        elif h["clase"] == "secreto":
            par = next((o for o in resultado if o["clase"] == "secreto" and o["archivo"] == h["archivo"]
                        and o["linea"] == h["linea"] and o["commit"] == h["commit"]), None)
        if par is None:
            resultado.append(h)
            continue
        if par["severidad_estimada"] and not h["severidad_estimada"]:
            par.update(severidad=h["severidad"], severidad_estimada=False)
        par["herramientas"] += [t for t in h["herramientas"] if t not in par["herramientas"]]
        par["ids"] += [i for i in h["ids"] if i not in par["ids"]]
        for k in ("fix", "linea", "archivo", "cwe", "mensaje"):
            par[k] = par[k] or h[k]
    return resultado
