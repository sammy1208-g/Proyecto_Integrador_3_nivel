"""Base de datos SQLite del servicio de autenticación."""
import os
import sqlite3
from contextlib import contextmanager

RUTA_BD = os.environ.get("AUTH_DB", os.path.join(os.path.dirname(__file__), "..", "auth.db"))

ESQUEMA = """
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    correo TEXT NOT NULL UNIQUE,
    rol TEXT NOT NULL CHECK (rol IN ('usuario', 'administrador')),
    activo INTEGER NOT NULL DEFAULT 1,
    clave_hash TEXT NOT NULL,
    intentos_fallidos INTEGER NOT NULL DEFAULT 0,
    bloqueado_hasta TEXT
);
CREATE TABLE IF NOT EXISTS auditoria (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha TEXT NOT NULL,
    evento TEXT NOT NULL,
    correo TEXT,
    detalle TEXT
);
"""


@contextmanager
def conexion():
    con = sqlite3.connect(RUTA_BD)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def iniciar_bd():
    with conexion() as con:
        con.executescript(ESQUEMA)
