import os
import re
import ast
import sqlite3
import subprocess
import hashlib
import logging
from flask import Flask, request, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# ---------------- Load Environment ----------------

load_dotenv()

# ---------------- Config ----------------
app = Flask(__name__)


SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("❌ SECRET_KEY not set! Please define it in .env")

app.config["SECRET_KEY"] = SECRET_KEY

SAFE_DIR = os.path.realpath(os.environ.get("SAFE_FILES_DIR", "./files"))
os.makedirs(SAFE_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_db_connection():
    conn = sqlite3.connect("users.db", timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


_allowed_nodes = {
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.Num, ast.Constant,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Pow, ast.Mod,
    ast.USub, ast.UAdd, ast.Load, ast.Tuple, ast.Expr
}

def _check_node(node):
    if type(node) not in _allowed_nodes:
        raise ValueError(f"Disallowed node: {type(node).__name__}")
    for child in ast.iter_child_nodes(node):
        _check_node(child)

def safe_eval(expr: str):
    if not re.match(r'^[0-9\.\+\-\*\/\%\(\)\s\^]+$', expr):
        raise ValueError("Expression contains invalid characters.")
    expr = expr.replace("^", "**")
    try:
        node = ast.parse(expr, mode='eval')
        _check_node(node)
        compiled = compile(node, "<safe_eval>", "eval")
        return eval(compiled, {"__builtins__": {}})  # nosec B307
    except Exception as e:
        raise ValueError(f"Invalid expression: {e}")

# ---------------- Endpoints ----------------

@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Welcome to the DevSecOps API"}, 200

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json(force=True)
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""

        if not username or not password:
            return {"status": "error", "message": "username and password required"}, 400

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()

        if row and check_password_hash(row["password_hash"], password):
            return {"status": "success", "user": username}, 200
        else:
            return {"status": "error", "message": "Invalid credentials"}, 401
    except Exception as e:
        logger.exception("login error")
        return {"status": "error", "message": "Internal server error"}, 500

@app.route("/ping", methods=["POST"])
def ping():
    try:
        data = request.get_json(force=True)
        host = (data.get("host") or "").strip()
        if not host:
            return {"output": ""}, 400

        if len(host) > 255 or not re.match(r'^[A-Za-z0-9\.\-]+$', host):
            return {"output": "invalid host"}, 400

        try:
            output = subprocess.check_output(["ping", "-c", "1", host], stderr=subprocess.STDOUT, timeout=5)
            return {"output": output.decode(errors="ignore")}, 200
        except subprocess.CalledProcessError as e:
            return {"output": e.output.decode(errors="ignore")}, 400
        except subprocess.TimeoutExpired:
            return {"output": "ping timeout"}, 504
    except Exception as e:
        logger.exception("ping error")
        return {"output": "Internal server error"}, 500

@app.route("/compute", methods=["POST"])
def compute():
    try:
        data = request.get_json(force=True)
        expression = (data.get("expression") or "1+1").strip()
        try:
            result = safe_eval(expression)
        except ValueError as ve:
            return {"result": str(ve)}, 400
        return {"result": result}, 200
    except Exception as e:
        logger.exception("compute error")
        return {"result": "Internal server error"}, 500

@app.route("/hash", methods=["POST"])
def hash_password():
    try:
        data = request.get_json(force=True)
        pwd = data.get("password") or "admin"

        # legacy md5 (kept for compatibility) -- still computed but note it's insecure
        md5_hash = hashlib.md5(pwd.encode()).hexdigest()  # nosec B324

        # secure hash for actual storage/use
        secure_hash = generate_password_hash(pwd)  # PBKDF2:sha256

        return {"md5": md5_hash, "secure_hash": secure_hash}, 200
    except Exception as e:
        logger.exception("hash error")
        return {"md5": "", "secure_hash": ""}, 500

@app.route("/readfile", methods=["POST"])
def readfile():
    try:
        data = request.get_json(force=True)
        filename = (data.get("filename") or "test.txt").strip()

        if ".." in filename or filename.startswith("/") or filename.startswith("\\"):
            return {"content": "invalid filename"}, 400

        requested = os.path.realpath(os.path.join(SAFE_DIR, filename))
        if not requested.startswith(os.path.realpath(SAFE_DIR)):
            return {"content": "invalid filename (outside safe dir)"}, 400

        if not os.path.exists(requested) or not os.path.isfile(requested):
            return {"content": "file not found"}, 404

        with open(requested, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        return {"content": content}, 200
    except Exception as e:
        logger.exception("readfile error")
        return {"content": "Internal server error"}, 500

@app.route("/debug", methods=["GET"])
def debug():
    try:
        enabled = os.environ.get("FLASK_DEBUG_ENDPOINT", "0") == "1"
        if not enabled:
            abort(404)

        if request.remote_addr not in ("127.0.0.1", "::1", "localhost"):
            abort(403)

        env_items = {}
        for i, (k, v) in enumerate(os.environ.items()):
            if i >= 10:
                break
            if any(s in k.upper() for s in ("KEY", "SECRET", "PASS", "TOKEN")):
                env_items[k] = "<hidden>"
            else:
                env_items[k] = v

        return {
            "debug": True,
            "secret_key": "<hidden>",
            "environment": env_items
        }, 200
    except Exception as e:
        logger.exception("debug error")
        return {"debug": False, "secret_key": "", "environment": {}}, 500

# -------------- DB init helper --------------
def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )""")
    cur.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if not cur.fetchone():
        cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    ("admin", generate_password_hash("admin")))
        logger.info("Created demo user 'admin' (password 'admin') - change it!")
    conn.commit()
    conn.close()

# -------------- Run --------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)  # nosec B104
