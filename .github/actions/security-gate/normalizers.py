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


def _version(v):
    """Go escribe v0.3.7; otras fuentes podrían escribir 0.3.7."""
    return str(v or "").strip().lstrip("vV")


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
        ids=[f.get("RuleID", "")],                # al deduplicar se conservan todas las reglas
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


# ── Utilidades Go / Node ──────────────────────────────────────────────────
def _modulos(data):
    """scan-go corre cada herramienta una vez por go.mod y envuelve las salidas:
    {"modulos": [{"dir": "samples/go", "resultado": <JSON nativo>}]}."""
    for m in (data or {}).get("modulos") or []:
        yield (m.get("dir") or ".").replace("\\", "/").strip("/") or ".", m.get("resultado")


def _en_modulo(modulo, ruta):
    """Las herramientas Go reportan rutas absolutas o relativas al módulo."""
    if not ruta:
        return ""
    p = str(ruta).replace("\\", "/")
    if p.startswith("/") or re.match(r"^[A-Za-z]:/", p):
        return ruta_relativa(p)
    return ruta_relativa(p if modulo == "." else f"{modulo}/{p}")


def _primera_linea(valor):
    m = re.match(r"\s*(\d+)", str(valor or ""))
    return int(m.group(1)) if m else None


def _logica_o_calidad(herramienta, regla, conf, es_logica, **campos):
    return nuevo_hallazgo(
        herramienta=herramienta, regla=regla,
        categoria="logica" if es_logica else "calidad", clase="logica" if es_logica else "calidad",
        severidad=str(conf.get("logica_severidad" if es_logica else "severidad", "LOW")).upper(), **campos)


# ── gosec ─────────────────────────────────────────────────────────────────
def gosec(data, sev):
    out = []
    for modulo, r in _modulos(data):
        for i in (r or {}).get("Issues") or []:
            cwe = (i.get("cwe") or {}).get("id")
            out.append(nuevo_hallazgo(
                herramienta="gosec", regla=i.get("rule_id", ""), clase="sast",
                severidad=severidad(sev.get("gosec"), i.get("severity")),
                archivo=_en_modulo(modulo, i.get("file")), linea=_primera_linea(i.get("line")),
                cwe=f"CWE-{cwe}" if cwe else "", mensaje=i.get("details", "")))
    return out


# ── govulncheck (solo CVE ALCANZABLES; no trae severidad) ─────────────────
def _linea_go_mod(archivo, modulo_go):
    if modulo_go != "stdlib":
        return linea_de_dependencia(archivo, modulo_go)
    try:                                         # stdlib → la directiva "go 1.x"
        for n, linea in enumerate(Path(archivo).read_text(encoding="utf-8").splitlines(), 1):
            if re.match(r"\s*(go|toolchain)\s+\S", linea):
                return n
    except OSError:
        pass
    return None


def govulncheck(data, sev):
    out = []
    for modulo, eventos in _modulos(data):
        osv = {e["osv"]["id"]: e["osv"] for e in eventos or [] if isinstance(e, dict) and "osv" in e}
        vistos = set()
        for e in eventos or []:
            f = (e or {}).get("finding") if isinstance(e, dict) else None
            traza = (f or {}).get("trace") or []
            if not traza or not traza[0].get("function"):
                continue                         # importado pero no llamado → lo cubre Trivy
            mod, ver = traza[0].get("module", ""), traza[0].get("version", "")
            if (f["osv"], mod) in vistos:
                continue
            vistos.add((f["osv"], mod))
            meta = osv.get(f["osv"], {})
            ids = [f["osv"]] + list(meta.get("aliases") or [])
            cve = next((i for i in ids if i.startswith("CVE-")), ids[0])
            go_mod = ruta_relativa("go.mod" if modulo == "." else f"{modulo}/go.mod")
            out.append(nuevo_hallazgo(
                herramienta="govulncheck", regla=cve, clase="cve", subtipo="dependencia",
                severidad=severidad(sev.get("govulncheck", "MEDIUM"), None), severidad_estimada=True,
                archivo=go_mod, linea=_linea_go_mod(go_mod, mod),
                titulo=f"{cve} en {mod} {ver}",
                mensaje=" ".join((meta.get("summary") or meta.get("details") or "").split())[:200]
                        + f" (alcanzable: {traza[0].get('package', '')}.{traza[0]['function']})",
                paquete=mod, version=ver, fix=f.get("fixed_version", ""), ids=ids))
    return out


# ── staticcheck (no trae severidad útil) ──────────────────────────────────
def staticcheck(data, sev):
    conf = sev.get("staticcheck") or {}
    prefijos = tuple(conf.get("logica_prefijos") or ())
    out = []
    for modulo, items in _modulos(data):
        for r in items or []:
            codigo = r.get("code") or "compile"
            loc = r.get("location") or {}
            out.append(_logica_o_calidad(
                "staticcheck", codigo, conf, codigo.startswith(prefijos) if prefijos else False,
                archivo=_en_modulo(modulo, loc.get("file")), linea=loc.get("line"),
                mensaje=r.get("message", "")))
    return out


# ── ESLint (una corrida; se separa por ruleId) ────────────────────────────
_SEV_ESLINT = {2: "ERROR", 1: "WARNING"}


def eslint(data, sev):
    conf = sev.get("eslint") or {}
    logica = set(conf.get("logica_reglas") or ())
    out = []
    for f in data or []:
        archivo = ruta_relativa(f.get("filePath"))
        for m in f.get("messages") or []:
            regla = m.get("ruleId") or "parse-error"   # error de parseo: el archivo no se analizó
            comunes = {"archivo": archivo, "linea": m.get("line"), "mensaje": m.get("message", "")}
            if regla.startswith("security/"):
                out.append(nuevo_hallazgo(
                    herramienta="eslint", regla=regla, clase="sast",
                    severidad=severidad(conf.get("seguridad"), _SEV_ESLINT.get(m.get("severity"))), **comunes))
            else:
                out.append(_logica_o_calidad("eslint", regla, conf, regla in logica, **comunes))
    return out


# ── osv-scanner (CVE npm; no trae severidad en la escala común) ──────────
def _fix_osv(vulns, nombre):
    fixes = []
    for v in vulns:
        for a in v.get("affected") or []:
            if (a.get("package") or {}).get("name") not in (None, nombre):
                continue
            for r in a.get("ranges") or []:
                fixes += [e["fixed"] for e in r.get("events") or [] if e.get("fixed")]
    return ", ".join(dict.fromkeys(fixes))


def osv_scanner(data, sev):
    out = []
    for res in (data or {}).get("results") or []:
        archivo = ruta_relativa((res.get("source") or {}).get("path"))
        for p in res.get("packages") or []:
            pkg = p.get("package") or {}
            nombre, version = pkg.get("name", ""), pkg.get("version", "")
            por_id = {v.get("id"): v for v in p.get("vulnerabilities") or []}
            grupos = p.get("groups") or [{"ids": [i], "aliases": []} for i in por_id]
            for g in grupos:
                vulns = [por_id[i] for i in g.get("ids") or [] if i in por_id]
                ids = list(dict.fromkeys(list(g.get("ids") or []) + list(g.get("aliases") or [])
                                         + [a for v in vulns for a in v.get("aliases") or []]))
                if not ids:
                    continue
                cve = next((i for i in ids if i.startswith("CVE-")), ids[0])
                cwes = [c for v in vulns for c in (v.get("database_specific") or {}).get("cwe_ids") or []]
                out.append(nuevo_hallazgo(
                    herramienta="osv-scanner", regla=cve, clase="cve", subtipo="dependencia",
                    severidad=severidad(sev.get("osv-scanner", "MEDIUM"), None), severidad_estimada=True,
                    archivo=archivo, linea=linea_de_dependencia(archivo, nombre),
                    cwe=cwes[0] if cwes else "", titulo=f"{cve} en {nombre} {version}",
                    mensaje=" ".join(((vulns[0].get("summary") or vulns[0].get("details") or "") if vulns else "").split())[:200],
                    paquete=nombre, version=version, fix=_fix_osv(vulns, nombre), ids=ids))
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
                        and _version(o["version"]) == _version(h["version"])
                        and set(o["ids"]) & set(h["ids"])), None)
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
