"""Crea el primer administrador. La contraseña se escribe por teclado, no queda en el código."""
import getpass
import sys

from app import db, seguridad


def main():
    db.iniciar_bd()
    nombre = input("Nombre del administrador: ").strip()
    correo = input("Correo del administrador: ").strip().lower()
    clave = getpass.getpass("Contraseña (mínimo 8 caracteres, no se muestra): ")
    if len(clave) < 8:
        print("La contraseña es muy corta.")
        sys.exit(1)
    with db.conexion() as con:
        if con.execute("SELECT 1 FROM usuarios WHERE correo = ?", (correo,)).fetchone():
            print("Ese correo ya existe.")
            sys.exit(1)
        con.execute(
            "INSERT INTO usuarios (nombre, correo, rol, clave_hash) VALUES (?, ?, 'administrador', ?)",
            (nombre, correo, seguridad.hashear_clave(clave)),
        )
    print("Administrador creado.")


if __name__ == "__main__":
    main()
