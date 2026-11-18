#!/usr/bin/env python3
"""Une las salidas por módulo (una por go.mod) de UNA herramienta en <herramienta>.json.

Uso: combinar.py <herramienta> <formato> <exit_ok> <out_dir> <partes_dir>
  formato:  json   → la salida es un único documento JSON (gosec)
            stream → objetos JSON concatenados o ndjson (govulncheck, staticcheck)
  exit_ok:  códigos de salida aceptables separados por coma (p. ej. "0,1")
  partes_dir contiene, por módulo N: N.dir (ruta del módulo), N.out, N.exit, N.err

Escribe en out_dir el mismo contrato que el resto de los módulos:
  <herramienta>.json        {"modulos": [{"dir": ..., "resultado": ...}]}
  <herramienta>.exit        códigos de salida de cada módulo, separados por coma
  <herramienta>.stderr.log  stderr de cada módulo
Si ALGÚN módulo falla (exit no aceptado o salida no parseable) NO se escribe el
.json → status.json marca la herramienta como "error" (no bloquea, pero se ve).
"""
import json
import sys
from pathlib import Path


def leer_stream(texto):
    dec, i, objetos = json.JSONDecoder(), 0, []
    while True:
        while i < len(texto) and texto[i].isspace():
            i += 1
        if i >= len(texto):
            return objetos
        obj, i = dec.raw_decode(texto, i)
        objetos.append(obj)


def main():
    herramienta, formato, exit_ok, out_dir, partes = sys.argv[1:6]
    aceptados = {c.strip() for c in exit_ok.split(",") if c.strip()}
    out, partes = Path(out_dir), Path(partes)
    modulos, codigos, logs, fallos = [], [], [], []
    for marca in sorted(partes.glob("*.dir"), key=lambda p: int(p.stem)):
        n = marca.stem
        modulo = marca.read_text(encoding="utf-8").strip()
        codigo = (partes / f"{n}.exit").read_text().strip() if (partes / f"{n}.exit").exists() else "?"
        err = partes / f"{n}.err"
        if err.exists() and err.stat().st_size:
            logs.append(f"── {modulo} (exit {codigo})\n" + err.read_text(encoding="utf-8", errors="replace").strip())
        codigos.append(codigo)
        if codigo not in aceptados:
            fallos.append(f"{modulo}: exit {codigo}")
            continue
        try:
            texto = (partes / f"{n}.out").read_text(encoding="utf-8")
            resultado = leer_stream(texto) if formato == "stream" else json.loads(texto)
        except (OSError, ValueError, UnicodeDecodeError) as e:
            fallos.append(f"{modulo}: salida ilegible ({e})")
            continue
        modulos.append({"dir": modulo, "resultado": resultado})

    if fallos:
        logs.insert(0, "falló en: " + "; ".join(fallos))
    (out / f"{herramienta}.stderr.log").write_text("\n".join(logs) + "\n", encoding="utf-8")
    (out / f"{herramienta}.exit").write_text(",".join(codigos) or "?", encoding="utf-8")
    if not fallos:
        (out / f"{herramienta}.json").write_text(json.dumps({"modulos": modulos}, ensure_ascii=False),
                                                 encoding="utf-8")
    print(f"{herramienta}: {len(modulos)} módulo(s) ok" + (f", {len(fallos)} con error" if fallos else ""))


if __name__ == "__main__":
    main()
