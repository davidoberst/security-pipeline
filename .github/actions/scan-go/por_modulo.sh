#!/usr/bin/env bash
# Uso: por_modulo.sh <herramienta> <formato> <exit_ok> <comando...>
# Corre <comando> dentro de cada módulo Go listado en $MODULOS y une las salidas
# con combinar.py en $OUT/<herramienta>.json. NUNCA falla.
set -u
herr=$1 formato=$2 ok=$3
shift 3
partes="$RUNNER_TEMP/scan-go-partes/$herr"
rm -rf "$partes"
mkdir -p "$partes"

if [ ! -s "$MODULOS" ]; then
  echo "sin módulos Go con código (go.mod + archivos .go)" > "$OUT/$herr.stderr.log"
  echo skip > "$OUT/$herr.exit"
  exit 0
fi

n=0
while IFS= read -r mod; do
  n=$((n + 1))
  echo "$mod" > "$partes/$n.dir"
  echo "$herr · $mod"
  ( cd "$mod" && "$@" ) > "$partes/$n.out" 2> "$partes/$n.err"
  echo $? > "$partes/$n.exit"
done < "$MODULOS"

python3 "$(dirname "$0")/combinar.py" "$herr" "$formato" "$ok" "$OUT" "$partes" \
  || echo "::warning title=scan-go::no se pudo combinar la salida de $herr"
exit 0
