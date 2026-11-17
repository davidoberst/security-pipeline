#codigo vulnerable aproposito para testear 

import hashlib
import os
import pickle
import sqlite3
import subprocess
from flask import Flask, request

app = Flask(__name__)

# 1. Hardcoded Secrets (Escáneres de secretos / SAST)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_PASSWORD = "SuperSecretPassword123!"

# 2. Uso de algoritmo criptográfico débil (CWE-327)
def hash_password(password):
  return hashlib.md5(password.encode()).hexdigest()

# 3. Inyección SQL / SQL Injection (CWE-89)
@app.route("/user")
def get_user():
  username = request.args.get("username")
  conn = sqlite3.connect("users.db")
  cursor = conn.cursor()
  # Concatenación directa de entrada del usuario en la consulta
  query = f"SELECT * FROM users WHERE username = '{username}'"
  cursor.execute(query)
  return str(cursor.fetchall())

# 4. Inyección de comandos / OS Command Injection (CWE-78)
@app.route("/ping")
def ping_host():
  host = request.args.get("host")
  # Uso de shell=True con entrada no sanitizada
  output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
  return output

# 5. Deserialización insegura (CWE-502)
@app.route("/load", methods=["POST"])
def load_data():
  raw_data = request.get_data()
  # pickle.loads permite ejecución remota de código (RCE) con payloads maliciosos
  obj = pickle.loads(raw_data)
  return str(obj)

# 6. Evaluación dinámica de código / Code Injection (CWE-94)
@app.route("/calc")
def calculate():
  expr = request.args.get("expr")
  return str(eval(expr))

if __name__ == "__main__":
  # 7. Modo debug activo en producción y exposición en todas las interfaces (CWE-215 / CWE-605)
  app.run(host="0.0.0.0", port=5000, debug=True)
