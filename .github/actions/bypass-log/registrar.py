"""Registra un bypass del security gate: un PR mergeado aunque el gate lo bloqueó.

Escribe bypass-log/<fecha>-<commit corto>.json. Solo biblioteca estándar.
Idempotente: si el archivo ya existe (re-run del workflow) no hace nada.

Entrada (variables de entorno):
  PR_NUMBER, HEAD_SHA, PR_AUTOR (pull_request.user.login),
  BYPASS_POR (pull_request.merged_by.login), MERGED_AT (ISO 8601, opcional),
  RUN_URL (corrida del gate), REPORT_DIR (carpeta del artifact security-gate-report,
  con findings.json y decision.json), LOG_DIR (default: bypass-log).
Salida: imprime la ruta escrita; si GITHUB_OUTPUT existe, escribe
  archivo=<ruta> y escrito=true|false.
Códigos: 0 siempre salvo entrada inválida (2). Nunca tumba el workflow por un
  findings.json ilegible: registra el bypass con la lista vacía y un aviso.
"""
import json
import os
import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

COLOMBIA = timezone(timedelta(hours=-5), "COT")   # UTC-5, sin horario de verano
CAMPOS = ("regla", "severidad", "archivo", "linea")


def aviso(msg):
    print(f"::warning title=bypass-log::{msg}")


def salida(**kv):
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.writelines(f"{k}={v}\n" for k, v in kv.items())


def momento(merged_at):
    """Hora del merge en UTC-5 (estable entre re-runs); si no llega, la hora actual."""
    try:
        t = datetime.fromisoformat(merged_at)       # Python ≥ 3.11 acepta la "Z"
    except (AttributeError, ValueError):
        t = datetime.now(UTC)
    return t.astimezone(COLOMBIA)


def leer_json(ruta):
    try:
        return json.loads(Path(ruta).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        aviso(f"{ruta} ilegible: {e}")
        return None


def omitidos(findings):
    """Solo los hallazgos que realmente bloqueaban."""
    out = []
    for h in findings if isinstance(findings, list) else []:
        if not isinstance(h, dict) or h.get("bloquea") is not True:
            continue
        herramientas = h.get("herramientas") or []
        out.append({**{k: h.get(k) for k in CAMPOS},
                    "herramienta": herramientas[0] if herramientas else ""})
    return out


def main():
    env = os.environ.get
    pr, sha = env("PR_NUMBER", "").strip(), env("HEAD_SHA", "").strip()
    if not pr.isdigit() or len(sha) < 7:
        print(f"::error title=bypass-log::entrada inválida (PR_NUMBER={pr!r}, HEAD_SHA={sha!r})")
        return 2
    corto = sha[:7]
    t = momento(env("MERGED_AT", ""))
    fecha = t.strftime("%Y-%m-%d")
    destino = Path(env("LOG_DIR", "bypass-log")) / f"{fecha}-{corto}.json"
    if destino.exists():
        print(f"{destino} ya existe (re-run): no se duplica")
        salida(archivo=destino.as_posix(), escrito="false")
        return 0

    rep = Path(env("REPORT_DIR", "gate-report"))
    decision = leer_json(rep / "decision.json") or {}
    findings = leer_json(rep / "findings.json")
    if findings is None:
        aviso("no hay findings.json en el artifact del gate: se registra el bypass sin la lista de hallazgos")
    # "bloqueado" = el gate decidió bloquear. Sin decision.json el job falló sin decidir
    # (error interno): igual era un check en rojo que alguien saltó.
    resultado = decision.get("resultado") or "error (el gate no emitió decisión)"

    registro = {
        "pr": int(pr),
        "commit": corto,
        "autor": env("PR_AUTOR", ""),
        "bypass_por": env("BYPASS_POR", ""),
        "fecha": fecha,
        "hora": t.strftime("%H:%M:%S") + "-05:00",
        "resultado_gate": resultado,
        "hallazgos_omitidos": omitidos(findings),
        "run_url": env("RUN_URL", ""),
    }
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_text(json.dumps(registro, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(destino.as_posix())
    salida(archivo=destino.as_posix(), escrito="true")
    return 0


if __name__ == "__main__":
    sys.exit(main())
