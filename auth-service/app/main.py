"""Servicio de autenticación (FastAPI) del sistema de correos internos.

Controles de la Fase 2 que implementa:
  C-02 autenticación con mensaje genérico y bloqueo de cuenta (RF-SEC-01)
  C-03 contraseñas con hash Argon2id y sal única (RF-SEC-03)
  C-04 autorización por rol de administrador (RF-SEC-02)
  Registro de eventos en la tabla de auditoría (sin contraseñas ni mensajes).
"""
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from . import db, seguridad

MAX_INTENTOS = 5
MINUTOS_BLOQUEO = 15
MENSAJE_GENERICO = "Correo o contraseña incorrectos."

@asynccontextmanager
async def ciclo_de_vida(app: FastAPI):
    db.iniciar_bd()
    yield


app = FastAPI(title="Servicio de autenticación - Correo interno", lifespan=ciclo_de_vida)
esquema_bearer = HTTPBearer(auto_error=False)


def ahora() -> datetime:
    return datetime.now(timezone.utc)


def auditar(con, evento: str, correo: str | None, detalle: str = ""):
    """Guarda el evento. Nunca se registran contraseñas ni contenido de mensajes."""
    con.execute(
        "INSERT INTO auditoria (fecha, evento, correo, detalle) VALUES (?, ?, ?, ?)",
        (ahora().isoformat(timespec="seconds"), evento, correo, detalle),
    )


class DatosLogin(BaseModel):
    correo: str
    clave: str


class DatosRegistro(BaseModel):
    nombre: str = Field(min_length=1, max_length=100)
    correo: str = Field(max_length=150)
    clave: str = Field(min_length=8, max_length=128)
    rol: str = "usuario"


# ---------- Autenticación: ¿quién es el usuario? ----------

def usuario_actual(credenciales: HTTPAuthorizationCredentials | None = Depends(esquema_bearer)):
    """Valida el token de sesión. Sin token, o con token inválido o vencido, responde 401."""
    if credenciales is None:
        raise HTTPException(status_code=401, detail="Se requiere iniciar sesión.")
    try:
        datos = seguridad.leer_token(credenciales.credentials)
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Sesión inválida o vencida. Inicie sesión de nuevo.")
    with db.conexion() as con:
        fila = con.execute("SELECT * FROM usuarios WHERE correo = ?", (datos["sub"],)).fetchone()
    if fila is None or not fila["activo"]:
        raise HTTPException(status_code=401, detail="Sesión inválida o vencida. Inicie sesión de nuevo.")
    return {"id": fila["id"], "nombre": fila["nombre"], "correo": fila["correo"], "rol": fila["rol"]}


# ---------- Autorización: ¿qué puede hacer? ----------

def solo_administrador(usuario=Depends(usuario_actual)):
    if usuario["rol"] != "administrador":
        with db.conexion() as con:
            auditar(con, "ACCESO_DENEGADO", usuario["correo"], "Intento de usar función de administrador")
        raise HTTPException(status_code=403, detail="No tiene permisos para esta acción.")
    return usuario


# ---------- Endpoints ----------

@app.post("/auth/login")
def login(datos: DatosLogin):
    correo = datos.correo.strip().lower()
    with db.conexion() as con:
        fila = con.execute("SELECT * FROM usuarios WHERE correo = ?", (correo,)).fetchone()

        # Correo no registrado: se gasta el mismo tiempo y se responde igual que con clave incorrecta.
        if fila is None:
            seguridad.verificar_clave(datos.clave, seguridad.HASH_FALSO)
            auditar(con, "LOGIN_FALLIDO", correo, "Correo no registrado")
            con.commit()
            raise HTTPException(status_code=401, detail=MENSAJE_GENERICO)

        # Cuenta bloqueada: se rechaza incluso con la clave correcta.
        if fila["bloqueado_hasta"] and datetime.fromisoformat(fila["bloqueado_hasta"]) > ahora():
            auditar(con, "LOGIN_BLOQUEADO", correo, "Intento durante el bloqueo")
            con.commit()
            raise HTTPException(status_code=401, detail=MENSAJE_GENERICO)

        clave_ok = seguridad.verificar_clave(datos.clave, fila["clave_hash"])

        if not clave_ok or not fila["activo"]:
            intentos = fila["intentos_fallidos"] + 1
            bloqueo = None
            detalle = f"Intento fallido {intentos} de {MAX_INTENTOS}"
            if intentos >= MAX_INTENTOS:
                bloqueo = (ahora() + timedelta(minutes=MINUTOS_BLOQUEO)).isoformat()
                intentos = 0
                detalle = f"Cuenta bloqueada {MINUTOS_BLOQUEO} minutos"
            con.execute(
                "UPDATE usuarios SET intentos_fallidos = ?, bloqueado_hasta = ? WHERE id = ?",
                (intentos, bloqueo, fila["id"]),
            )
            auditar(con, "LOGIN_FALLIDO", correo, detalle)
            con.commit()
            raise HTTPException(status_code=401, detail=MENSAJE_GENERICO)

        # Credenciales correctas: se reinician los contadores y se emite la sesión.
        con.execute(
            "UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = ?", (fila["id"],)
        )
        auditar(con, "LOGIN_EXITOSO", correo)
        token = seguridad.crear_token(correo, fila["rol"])

    return {"token": token, "tipo": "bearer", "rol": fila["rol"], "expira_en_minutos": seguridad.MINUTOS_SESION}


@app.get("/auth/me")
def quien_soy(usuario=Depends(usuario_actual)):
    """Recurso protegido: cualquier usuario autenticado puede verlo (acceso permitido)."""
    return usuario


@app.post("/auth/registrar", status_code=201)
def registrar(datos: DatosRegistro, admin=Depends(solo_administrador)):
    """Solo el administrador puede crear usuarios (RF-SEC-02)."""
    correo = datos.correo.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", correo):
        raise HTTPException(status_code=400, detail="El correo no es válido.")
    if datos.rol not in ("usuario", "administrador"):
        raise HTTPException(status_code=400, detail="Rol no válido.")
    with db.conexion() as con:
        existe = con.execute("SELECT 1 FROM usuarios WHERE correo = ?", (correo,)).fetchone()
        if existe:
            raise HTTPException(status_code=409, detail="Ese correo ya está registrado.")
        con.execute(
            "INSERT INTO usuarios (nombre, correo, rol, clave_hash) VALUES (?, ?, ?, ?)",
            (datos.nombre.strip(), correo, datos.rol, seguridad.hashear_clave(datos.clave)),
        )
        auditar(con, "USUARIO_REGISTRADO", correo, f"Creado por {admin['correo']} con rol {datos.rol}")
    return {"mensaje": "Usuario registrado.", "correo": correo, "rol": datos.rol}


@app.get("/admin/auditoria")
def ver_auditoria(admin=Depends(solo_administrador)):
    """Solo el administrador consulta los registros de auditoría."""
    with db.conexion() as con:
        filas = con.execute("SELECT fecha, evento, correo, detalle FROM auditoria ORDER BY id DESC LIMIT 50").fetchall()
    return [dict(f) for f in filas]
