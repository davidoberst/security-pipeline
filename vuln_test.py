"""
Script de prueba para pipelines de seguridad (SAST y Secret Scanning).
ADVERTENCIA: Contiene vulnerabilidades críticas intencionales. No ejecutar en producción.
"""

import os
import sqlite3
import subprocess
import yaml  # PyYAML inseguro si se usa yaml.load sin SafeLoader
import requests

# --- 1. SECRETOS HARDCODEADOS (Para Secret Scanning) ---
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_URL = "postgres://admin:SuperSecretPassword123@localhost:5432/prod_db"
JWT_SECRET = "super-secret-jwt-token-key-change-me-123456"
STRIPE_API_KEY = "sk_live_51NzXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"


def inicializar_db():
    conn = sqlite3.connect("usuarios.db")
    cursor = conn.cursor()
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)"
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users (id, username, role) VALUES (1, 'admin', 'administrator')"
    )
    conn.commit()
    return conn, cursor


# --- 2. INYECCIÓN SQL (SAST / DAST) ---
def buscar_usuario(username_input):
    conn, cursor = inicializar_db()
    # VULNERABILIDAD: Concatenación directa de strings permite SQL Injection
    query = f"SELECT * FROM users WHERE username = '{username_input}'"
    print(f"Ejecutando query insegura: {query}")
    try:
        cursor.execute(query)
        resultado = cursor.fetchall()
        conn.close()
        return resultado
    except Exception as e:
        conn.close()
        return str(e)


# --- 3. INYECCIÓN DE COMANDOS (SAST) ---
def realizar_diagnostico(host_input):
    # VULNERABILIDAD: Uso de shell=True con entrada de usuario sin sanitizar (Command Injection)
    comando = f"ping -c 1 {host_input}"
    print(f"Ejecutando comando del sistema: {comando}")
    try:
        resultado = subprocess.check_output(comando, shell=True, text=True)
        return resultado
    except subprocess.CalledProcessError as e:
        return f"Error ejecutando comando: {e}"


# --- 4. DESERIALIZACIÓN INSEGURA (SAST) ---
def cargar_configuracion_yaml(ruta_archivo):
    if not os.path.exists(ruta_archivo):
        return "Archivo no encontrado"

    with open(ruta_archivo, "r") as f:
        contenido = f.read()

    # VULNERABILIDAD: yaml.load sin SafeLoader permite ejecución de código arbitrario (RCE)
    config = yaml.load(contenido)
    return config


if __name__ == "__main__":
    print("--- Aplicación Vulnerable Iniciada ---")
    # Ejemplo de uso simulado
    # buscar_usuario("admin")
    # realizar_diagnostico("8.8.8.8")
