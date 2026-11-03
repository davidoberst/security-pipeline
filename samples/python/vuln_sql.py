"""MUESTRA FICTICIA — SQL injection a propósito, para Bandit (B608) y Semgrep."""
import sqlite3


def buscar_cliente_demo(conn: sqlite3.Connection, nombre: str):
    cursor = conn.cursor()
    # VULNERABLE A PROPÓSITO: el input se concatena dentro del SQL.
    query = "SELECT id, nombre FROM clientes_demo WHERE nombre = '" + nombre + "'"
    cursor.execute(query)
    return cursor.fetchall()
