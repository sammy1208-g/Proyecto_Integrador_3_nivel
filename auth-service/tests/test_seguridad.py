"""Pruebas de seguridad de la Fase 3 (PS-01, PS-02, PS-03, PS-06, PS-07 y relacionadas).

Se usan datos de prueba. No se guardan contraseñas reales.
"""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app import db, seguridad
from app.main import app

ADMIN = ("admin@empresa.com", "ClaveAdmin-123")
ANA = ("ana.torres@empresa.com", "ClaveAna-4567")
LUIS = ("luis.q@empresa.com", "ClaveAna-4567")  # misma clave que Ana a propósito (PS-07)


@pytest.fixture(scope="module")
def cliente():
    db.iniciar_bd()
    with db.conexion() as con:
        con.execute("DELETE FROM usuarios")
        con.execute("DELETE FROM auditoria")
        con.execute(
            "INSERT INTO usuarios (nombre, correo, rol, clave_hash) VALUES (?, ?, 'administrador', ?)",
            ("Administrador", ADMIN[0], seguridad.hashear_clave(ADMIN[1])),
        )
    with TestClient(app) as c:
        yield c


def entrar(c, cred):
    return c.post("/auth/login", json={"correo": cred[0], "clave": cred[1]})


def cabecera(token):
    return {"Authorization": f"Bearer {token}"}


def registrar(c, token, nombre, cred, rol="usuario"):
    return c.post(
        "/auth/registrar",
        headers=cabecera(token),
        json={"nombre": nombre, "correo": cred[0], "clave": cred[1], "rol": rol},
    )


def test_ps00_admin_registra_usuarios(cliente):
    """Positiva: el administrador registra usuarios (acceso permitido, RF-SEC-02)."""
    token = entrar(cliente, ADMIN).json()["token"]
    assert registrar(cliente, token, "Ana Torres", ANA).status_code == 201
    assert registrar(cliente, token, "Luis Q", LUIS).status_code == 201


def test_ps01_login_correcto(cliente):
    """PS-01 (+): credenciales correctas devuelven una sesión válida."""
    r = entrar(cliente, ANA)
    assert r.status_code == 200
    assert r.json()["token"]
    sesion = cliente.get("/auth/me", headers=cabecera(r.json()["token"]))
    assert sesion.status_code == 200 and sesion.json()["correo"] == ANA[0]


def test_ps02_credenciales_invalidas_mensaje_generico(cliente):
    """PS-02 (-): clave incorrecta y correo inexistente dan exactamente el mismo mensaje."""
    mala_clave = entrar(cliente, (ANA[0], "otra-clave-mala"))
    sin_correo = entrar(cliente, ("nadie@empresa.com", "otra-clave-mala"))
    assert mala_clave.status_code == 401 and sin_correo.status_code == 401
    assert mala_clave.json() == sin_correo.json()
    assert "token" not in mala_clave.json()


def test_ps03_bloqueo_tras_5_intentos(cliente):
    """PS-03 (-): 5 fallos seguidos bloquean la cuenta; el 6.º intento con la clave correcta se rechaza."""
    for _ in range(5):
        assert entrar(cliente, (LUIS[0], "clave-incorrecta")).status_code == 401
    sexto = entrar(cliente, LUIS)  # clave correcta, pero la cuenta está bloqueada
    assert sexto.status_code == 401
    assert "token" not in sexto.json()


def test_ps04_sin_sesion_rechazado(cliente):
    """RF-SEC-01 (-): sin token no se accede a recursos protegidos."""
    assert cliente.get("/auth/me").status_code == 401
    assert cliente.get("/admin/auditoria").status_code == 401


def test_ps04b_token_vencido_rechazado(cliente):
    """Negativa: un token vencido se rechaza."""
    from datetime import datetime, timedelta, timezone
    import jwt

    vencido = jwt.encode(
        {"sub": ANA[0], "rol": "usuario", "exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
        seguridad._clave_secreta(),
        algorithm=seguridad.ALGORITMO,
    )
    assert cliente.get("/auth/me", headers=cabecera(vencido)).status_code == 401


def test_ps06_usuario_comun_no_registra(cliente):
    """PS-06 (-): un usuario común recibe 403 y no se crea nada (autorización)."""
    token = entrar(cliente, ANA).json()["token"]  # autenticado correctamente...
    r = registrar(cliente, token, "Intruso", ("intruso@empresa.com", "ClaveIntruso-1"))
    assert r.status_code == 403  # ...pero sin permiso
    with db.conexion() as con:
        assert con.execute("SELECT 1 FROM usuarios WHERE correo = 'intruso@empresa.com'").fetchone() is None
    assert cliente.get("/admin/auditoria", headers=cabecera(token)).status_code == 403


def test_ps07_hash_con_sal_unica(cliente):
    """PS-07 (+): ninguna clave está en texto plano y dos claves iguales dan hashes distintos."""
    with db.conexion() as con:
        filas = {f["correo"]: f["clave_hash"] for f in con.execute("SELECT correo, clave_hash FROM usuarios")}
    assert filas[ANA[0]] != filas[LUIS[0]]  # misma contraseña, hashes distintos (sal única)
    for correo, hash_guardado in filas.items():
        assert hash_guardado.startswith("$argon2id$")
        assert ANA[1] not in hash_guardado and ADMIN[1] not in hash_guardado
    assert seguridad.verificar_clave(ANA[1], filas[ANA[0]]) is True


def test_correo_duplicado_409(cliente):
    token = entrar(cliente, ADMIN).json()["token"]
    assert registrar(cliente, token, "Ana otra vez", ANA).status_code == 409


def test_auditoria_no_guarda_claves(cliente):
    token = entrar(cliente, ADMIN).json()["token"]
    eventos = cliente.get("/admin/auditoria", headers=cabecera(token)).json()
    texto = str(eventos)
    assert "LOGIN_EXITOSO" in texto and "LOGIN_FALLIDO" in texto and "ACCESO_DENEGADO" in texto
    for clave in (ADMIN[1], ANA[1], "clave-incorrecta", "otra-clave-mala"):
        assert clave not in texto
