from flask import Flask, request, jsonify
import sqlite3
import subprocess
import bcrypt
import os
import re
from functools import wraps
import logging

app = Flask(__name__)

# Configuration sécurisée
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise RuntimeError("FLASK_SECRET_KEY must be set in environment variables")

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Connexion sécurisée à la base de données
def get_db_connection():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    # Activer les contraintes de clé étrangère
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

# Décorateur pour validation JSON
def require_json(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
        return f(*args, **kwargs)
    return decorated_function

# Décorateur pour limiter les données sensibles en production
def production_safe(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if os.environ.get('FLASK_ENV') == 'production':
            return jsonify({"error": "Endpoint disabled in production"}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login", methods=["POST"])
@require_json
def login():
    try:
        data = request.get_json()
        
        # Validation des données
        username = data.get("username", "").strip()
        password = data.get("password", "")
        
        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400
        
        if len(username) > 50 or len(password) > 100:
            return jsonify({"error": "Input too long"}), 400
        
        # Requête paramétrée pour éviter l'injection SQL
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            # Vérification avec bcrypt (hashing sécurisé)
            stored_hash = user["password_hash"].encode('utf-8')
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                logger.info(f"Successful login for user: {username}")
                return jsonify({
                    "status": "success", 
                    "user": username,
                    "message": "Login successful"
                })
        
        # Réponse générique pour éviter l'user enumeration
        logger.warning(f"Failed login attempt for username: {username}")
        return jsonify({"error": "Invalid credentials"}), 401
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/ping", methods=["POST"])
@require_json
def ping():
    try:
        data = request.get_json()
        host = data.get("host", "").strip()
        
        if not host:
            return jsonify({"error": "Host parameter is required"}), 400
        
        # Validation stricte de l'input
        # Autorise uniquement les hostnames et IPs valides
        host_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$'
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        if not (re.match(host_pattern, host) or re.match(ip_pattern, host)):
            return jsonify({"error": "Invalid host format"}), 400
        
        # Vérifier que chaque octet d'IP est valide
        if re.match(ip_pattern, host):
            octets = host.split('.')
            for octet in octets:
                if not 0 <= int(octet) <= 255:
                    return jsonify({"error": "Invalid IP address"}), 400
        
        # Commande sécurisée sans shell=True et avec timeout
        cmd = ["ping", "-c", "1", "-W", "2", host]
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            if result.returncode == 0:
                return jsonify({
                    "status": "success",
                    "output": result.stdout
                })
            else:
                return jsonify({
                    "status": "error",
                    "output": result.stderr
                }), 400
                
        except subprocess.TimeoutExpired:
            return jsonify({"error": "Ping timeout"}), 408
            
    except Exception as e:
        logger.error(f"Ping error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/hash", methods=["POST"])
@require_json
def hash_password():
    try:
        data = request.get_json()
        password = data.get("password", "")
        
        if not password:
            return jsonify({"error": "Password is required"}), 400
        
        if len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400
        
        # Utilisation de bcrypt (hashing sécurisé avec salt)
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        
        return jsonify({
            "status": "success",
            "algorithm": "bcrypt",
            "hash": hashed.decode('utf-8')
        })
        
    except Exception as e:
        logger.error(f"Hash error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/readfile", methods=["POST"])
@require_json
@production_safe  # Désactivé en production
def readfile():
    try:
        data = request.get_json()
        filename = data.get("filename", "").strip()
        
        if not filename:
            return jsonify({"error": "Filename is required"}), 400
        
        # Validation stricte du nom de fichier
        # N'autorise que les fichiers texte dans un répertoire spécifique
        if not re.match(r'^[a-zA-Z0-9_-]+\.txt$', filename):
            return jsonify({"error": "Invalid filename"}), 400
        
        # Chemin sécurisé - lecture uniquement depuis le répertoire autorisé
        safe_dir = os.path.join(os.getcwd(), "safe_files")
        os.makedirs(safe_dir, exist_ok=True)
        
        file_path = os.path.join(safe_dir, filename)
        
        # Vérification du chemin pour éviter les path traversals
        if not os.path.commonpath([safe_dir, os.path.realpath(file_path)]) == safe_dir:
            return jsonify({"error": "Invalid file path"}), 403
        
        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404
        
        # Limiter la taille du fichier
        if os.path.getsize(file_path) > 1024 * 1024:  # 1MB max
            return jsonify({"error": "File too large"}), 413
        
        with open(file_path, "r", encoding='utf-8') as f:
            content = f.read(5000)  # Lire seulement les 5000 premiers caractères
        
        return jsonify({
            "status": "success",
            "filename": filename,
            "content": content
        })
        
    except Exception as e:
        logger.error(f"Readfile error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/health", methods=["GET"])
def health_check():
    """Endpoint de vérification de santé"""
    return jsonify({
        "status": "healthy",
        "service": "DevSecOps API",
        "version": "1.0.0"
    })

@app.route("/", methods=["GET"])
def index():
    """Endpoint racine"""
    return jsonify({
        "message": "DevSecOps Secure API",
        "endpoints": {
            "POST /login": "User authentication",
            "POST /ping": "Ping a host (with validation)",
            "POST /hash": "Secure password hashing",
            "POST /readfile": "Read text files (dev only)",
            "GET /health": "Health check",
            "GET /": "This information"
        },
        "security": {
            "sql_injection": "protected",
            "command_injection": "protected",
            "path_traversal": "protected",
            "secure_hashing": "bcrypt",
            "input_validation": "enabled"
        }
    })

# Gestionnaire d'erreurs global
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    # Configuration de sécurité pour le serveur de développement
    app.run(
        host="127.0.0.1",  # Ne pas utiliser 0.0.0.0 en développement
        port=5000,
        debug=False  # Désactiver debug en production
    )