from flask import Flask, request, jsonify
import srp
import sqlite3
import os
from flask_cors import CORS 

# crear instancia de aplicación Flask
app = Flask(__name__)

# Configurar CORS globalmente. la librería añadirá todos los
# encabezados necesarios (Access-Control-Allow-Origin, etc.) tanto en
# respuestas normales como en OPTIONS preflight. el `origins="*"`
# acepta solicitudes desde `chrome-extension://…` y cualquier otro origen.
# Si prefieres un control más fino, puedes decorar rutas con
# `@cross_origin`.
CORS(app, origins="*", methods=["GET","POST","PUT","DELETE","OPTIONS"],
     allow_headers=["Content-Type","Authorization"], expose_headers=["Content-Type"],
     max_age=3600)

### almacenamientos simples en memoria (no apto para producción)
### capa de persistencia (SQLite)

# sesiones SRP activas almacenadas en memoria; cada entrada mapea un nombre
# de usuario a un objeto srp.Verifier para una autenticación en progreso.
# Son temporales y se eliminan una vez que /auth/finish se completa.
ACTIVE_SESSIONS = {}

# ruta al archivo de base de datos SQLite, se puede cambiar con la variable DB_PATH
DB_PATH = os.environ.get("DB_PATH", "data.db")

# conexión compartida: check_same_thread=False permite flask multihilo
_db_conn = None

# obtener una conexión sqlite compartida; usar una única conexión entre
# hilos (check_same_thread=False) evita problemas de bloqueo en esta
# aplicación simple. Las filas se devuelven como objetos tipo dict.
def get_db():
    global _db_conn
    if _db_conn is None:
        _db_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _db_conn.row_factory = sqlite3.Row
    return _db_conn

# inicializar tablas de base de datos si no existen; seguro de llamar
# múltiples veces (CREATE TABLE IF NOT EXISTS). Se ejecuta una vez al iniciar.
def init_db():
    db = get_db()
    c = db.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        salt BLOB NOT NULL,
        vkey BLOB NOT NULL
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS passwords (
        username TEXT NOT NULL,
        id TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY(username,id)
    )""")
    db.commit()

# llamar a inicialización inmediatamente cuando se importa el módulo
init_db()

# mapeo en memoria de token bearer a (usuario, expiración). Los tokens
# son efímeros y no persisten después de un reinicio. La capa TLS los
# protege en tránsito.
TOKEN_DB = {}
# remanente del diseño anterior en memoria; el código actual no lo usa.
PASSWORD_DB = {}

# duración durante la cual un token bearer generado es válido (segundos)
TOKEN_TTL = 60 * 60  # 1 hora

import secrets, time
from functools import wraps

@app.post("/register")
def register():
    # recibir nombre de usuario, salt y verificador (vkey) creados por el cliente
    # usando srp.create_salted_verification_key
    data = request.json
    username = data["username"]
    salt = bytes.fromhex(data["salt"])
    vkey = bytes.fromhex(data["vkey"])

    # almacenar las credenciales en la base de datos; sobrescribe registro existente
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO users(username,salt,vkey) VALUES (?,?,?)",
        (username, salt, vkey)
    )
    db.commit()
    return jsonify({"status": "ok"})


@app.post("/auth/start")
def auth_start():
    # el cliente comienza la autenticación enviando su valor público A
    data = request.json
    username = data["username"]
    A = bytes.fromhex(data["A"])

    # recuperar el salt y clave verificadora almacenados para este usuario
    db = get_db()
    row = db.execute("SELECT salt,vkey FROM users WHERE username=?", (username,)).fetchone()
    if row is None:
        return jsonify({"error": "user_not_found"}), 404
    salt = row["salt"]
    vkey = row["vkey"]

    # crear verificador para computar B público del servidor y verificar prueba después
    svr = srp.Verifier(username, salt, vkey, A)
    s, B = svr.get_challenge()

    if s is None or B is None:
        return jsonify({"error": "challenge_failed"}), 400

    # mantener el objeto verificador hasta que el cliente responda al desafío
    ACTIVE_SESSIONS[username] = svr

    return jsonify({
        "salt": s.hex(),
        "B": B.hex()
    })


# global error handler to ensure we always return JSON rather than HTML stacktraces
@app.errorhandler(Exception)
def handle_exception(e):
    # log to stderr for debugging
    app.logger.exception("Unhandled exception")
    return jsonify({"error": "internal_server_error", "message": str(e)}), 500


@app.post("/auth/finish")
def auth_finish():
    # el cliente envía prueba M para completar el protocolo SRP
    data = request.json
    username = data["username"]
    M = bytes.fromhex(data["M"])

    if username not in ACTIVE_SESSIONS:
        return jsonify({"error": "no_active_session"}), 400

    svr = ACTIVE_SESSIONS[username]

    HAMK = svr.verify_session(M)
    if HAMK is None:
        return jsonify({"error": "auth_failed"}), 403

    # limpiar la sesión SRP temporal
    del ACTIVE_SESSIONS[username]

    # emitir token bearer para solicitudes API autenticadas posteriores
    token = _generate_token(username)
    print(token)

    return jsonify({
        "HAMK": HAMK.hex(),
        "token": token
    })


#### funciones auxiliares para tokens y decoración

def _generate_token(username: str) -> str:
    token = secrets.token_hex(32)
    expiry = time.time() + TOKEN_TTL
    TOKEN_DB[token] = (username, expiry)
    return token

def _verify_token(token: str):
    entry = TOKEN_DB.get(token)
    if not entry:
        return None
    username, expiry = entry
    if time.time() > expiry:
        # expirado, eliminar
        del TOKEN_DB[token]
        return None
    return username

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing_token"}), 401
        token = auth.split(" ", 1)[1]
        user = _verify_token(token)
        if user is None:
            return jsonify({"error": "invalid_or_expired_token"}), 401
        # attach username to request for convenience
        request.username = user
        return f(*args, **kwargs)
    return decorated


### endpoints para gestión de contraseñas

@app.get("/passwords")
@require_token
def get_passwords():
    # obtener todas las contraseñas almacenadas para el usuario autenticado
    db = get_db()
    rows = db.execute(
        "SELECT id,value FROM passwords WHERE username=?",
        (request.username,)
    ).fetchall()
    return jsonify({r["id"]: r["value"] for r in rows})

@app.post("/passwords")
@require_token
def add_password():
    # crear una nueva entrada de contraseña cifrada
    data = request.json
    entry_id = data.get("id")
    value = data.get("value")
    if entry_id is None or value is None:
        return jsonify({"error": "missing_fields"}), 400
    db = get_db()
    try:
        db.execute(
            "INSERT INTO passwords(username,id,value) VALUES (?,?,?)",
            (request.username, entry_id, value)
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "exists"}), 400
    return jsonify({"status": "ok"})

@app.put("/passwords/<entry_id>")
@require_token
def update_password(entry_id):
    # modificar una entrada existente
    data = request.json
    value = data.get("value")
    if value is None:
        return jsonify({"error": "missing_value"}), 400
    db = get_db()
    cur = db.execute(
        "SELECT 1 FROM passwords WHERE username=? AND id=?",
        (request.username, entry_id)
    )
    if cur.fetchone() is None:
        return jsonify({"error": "not_found"}), 404
    db.execute(
        "UPDATE passwords SET value=? WHERE username=? AND id=?",
        (value, request.username, entry_id)
    )
    db.commit()
    return jsonify({"status": "ok"})

@app.delete("/passwords/<entry_id>")
@require_token
def delete_password(entry_id):
    # eliminar una entrada por id
    db = get_db()
    cur = db.execute(
        "SELECT 1 FROM passwords WHERE username=? AND id=?",
        (request.username, entry_id)
    )
    if cur.fetchone() is None:
        return jsonify({"error": "not_found"}), 404
    db.execute(
        "DELETE FROM passwords WHERE username=? AND id=?",
        (request.username, entry_id)
    )
    db.commit()
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # enlazar a 0.0.0.0 para que el servidor sea accesible desde fuera del contenedor
    host = "0.0.0.0"
    port = int(os.environ.get("PORT", 4134))
    use_https = os.environ.get("USE_HTTPS", "0") in ("1", "true", "True")
    if use_https:
        # 'adhoc' genera un certificado autofirmado en cada ejecución;
        # para producción montar archivos de certificado
        # app.run(host=host, port=port, ssl_context="adhoc")
        app.run(host=host, port=port)
    else:
        app.run(host=host, port=port)
