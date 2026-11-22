"""Funciones de seguridad: hash de contraseñas (Argon2id) y tokens de sesión (JWT)."""
import os
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

# Argon2id genera una sal aleatoria única por cada contraseña y la guarda dentro del hash.
_hasher = PasswordHasher()

ALGORITMO = "HS256"
MINUTOS_SESION = 15


def _clave_secreta() -> str:
    clave = os.environ.get("AUTH_SECRET")
    if not clave or len(clave) < 32:
        raise RuntimeError(
            "Falta la variable de entorno AUTH_SECRET (mínimo 32 caracteres). "
            "No se guarda en el código ni en el repositorio."
        )
    return clave


def hashear_clave(clave: str) -> str:
    return _hasher.hash(clave)


def verificar_clave(clave: str, hash_guardado: str) -> bool:
    try:
        return _hasher.verify(hash_guardado, clave)
    except (VerifyMismatchError, InvalidHashError):
        return False


# Hash falso para gastar el mismo tiempo cuando el correo no existe (evita deducir correos por tiempo).
HASH_FALSO = _hasher.hash("clave-falsa-para-igualar-tiempos")


def crear_token(correo: str, rol: str) -> str:
    ahora = datetime.now(timezone.utc)
    datos = {"sub": correo, "rol": rol, "iat": ahora, "exp": ahora + timedelta(minutes=MINUTOS_SESION)}
    return jwt.encode(datos, _clave_secreta(), algorithm=ALGORITMO)


def leer_token(token: str) -> dict:
    """Devuelve los datos del token o lanza jwt.InvalidTokenError (incluye token vencido)."""
    return jwt.decode(token, _clave_secreta(), algorithms=[ALGORITMO])
