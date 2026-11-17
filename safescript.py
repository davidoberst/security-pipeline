# Verify what does the pipeline when the code is secure 

import ast
import hashlib
import json
import os
import re
import sqlite3
import subprocess
from flask import Flask, jsonify, request

app = Flask(__name__)

# 1. Gestión segura de secretos: lectura desde variables de entorno
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")


# 2. Algoritmo criptográfico robusto con salt (PBKDF2-HMAC-SHA256)
def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
  if salt is None:
    salt = os.urandom(16)
  key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)
  return key.hex(), salt.hex()


# 3. Prevención de SQL Injection mediante consultas parametrizadas
@app.route("/user")
def get_user():
  username = request.args.get("username", "")
  if not username or len(username) > 50:
    return jsonify({"error": "Parámetro username inválido"}), 400

  with sqlite3.connect("users.db") as conn:
    cursor = conn.cursor()
    # El placeholder (?) evita que la entrada altere la estructura SQL
    cursor.execute(
        "SELECT id, username FROM users WHERE username = ?", (username,)
    )
    rows = cursor.fetchall()

  return jsonify({"users": rows})


# 4. Prevención de OS Command Injection: validación estricta + shell=False
@app.route("/ping")
def ping_host():
  host = request.args.get("host", "")
  # Lista blanca: solo permite dominios válidos o direcciones IPv4
  if not re.match(r"^[a-zA-Z0-9.-]{1,253}$", host) or host.startswith("-"):
    return jsonify({"error": "Host inválido"}), 400

  try:
    # Lista de argumentos sin invocar una shell del sistema
    output = subprocess.check_output(
        ["ping", "-c", "1", host],
        shell=False,
        timeout=5,
        text=True,
    )
    return jsonify({"output": output})
  except subprocess.SubprocessError:
    return jsonify({"error": "No se pudo completar el ping"}), 502


# 5. Serialización segura con JSON en lugar de pickle
@app.route("/load", methods=["POST"])
def load_data():
  try:
    data = json.loads(request.get_data(as_text=True))
    return jsonify({"received": data})
  except json.JSONDecodeError:
    return jsonify({"error": "JSON malformado"}), 400


# 6. Evaluación segura de literales con ast.literal_eval en lugar de eval
@app.route("/calc")
def calculate():
  expr = request.args.get("expr", "")
  try:
    # Solo evalúa estructuras de datos básicas (números, cadenas, listas), nunca código ejecutable
    result = ast.literal_eval(expr)
    if not isinstance(result, (int, float)):
      return jsonify({"error": "Solo se permiten valores numéricos"}), 400
    return jsonify({"result": result})
  except (ValueError, SyntaxError):
    return jsonify({"error": "Expresión inválida"}), 400


if __name__ == "__main__":
  # 7. Debug desactivado y enlace restringido a localhost (usar Gunicorn/uWSGI en producción)
  debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
  app.run(host="127.0.0.1", port=5000, debug=debug_mode)
