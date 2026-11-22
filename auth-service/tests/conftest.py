import os
import tempfile

os.environ.setdefault("AUTH_SECRET", "clave-de-prueba-solo-para-tests-0123456789abcdef")
_dir = tempfile.mkdtemp()
os.environ["AUTH_DB"] = os.path.join(_dir, "pruebas.db")
