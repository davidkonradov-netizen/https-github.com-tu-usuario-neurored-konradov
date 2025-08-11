# NeuroRed-Konradov-V3.1
Página web para desarrolladores marginados sin tarjetas de crédito 

# app.py
import os
import jwt
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template_string
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv

if os.path.exists(".env"):
    load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
bcrypt = Bcrypt(app)

# Nodos cuánticos simulados
nodes = [{"id": f"node-{i}", "status": "active", "gpu": "nvidia-a100"} for i in range(3)]

# Credenciales seguras
ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH')

# Decorador JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token faltante'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['user']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Login seguro
@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth:
        return jsonify({'error': 'Autenticación requerida'}), 401
    if auth.username == ADMIN_USER and bcrypt.check_password_hash(ADMIN_PASSWORD_HASH, auth.password):
        token = jwt.encode({
            'user': auth.username,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({'error': 'Credenciales inválidas'}), 401

# Interfaz web
@app.route("/")
@token_required
def home(current_user):
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>NeuroRed Konradov</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { background: #0d1117; color: #c9d1d9; font-family: 'Courier New', monospace; margin: 20px; }
            h1 { color: #58a6ff; }
            .node-card {
                background: #161b22;
                border-left: 4px solid #2ea44f;
                margin: 15px 0;
                padding: 15px;
                border-radius: 6px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.2);
            }
            .footer { margin-top: 40px; font-size: 0.8em; color: #8b949e; }
        </style>
    </head>
    <body>
        <h1> NeuroRed Konradov - Bienvenido, {{ user }}</h1>
        <div id="nodes">
            {% for node in nodes %}
            <div class="node-card">
                <h3>{{ node.id }} </h3>
                <p><strong>GPU:</strong> {{ node.gpu }}</p>
                <p><strong>Status:</strong> {{ node.status }}</p>
            </div>
            {% endfor %}
        </div>
        <div class="footer">
            Desplegado con <a href="https://railway.app" style="color:#58a6ff;">Railway</a> en 60 segundos. 💨
        </div>
    </body>
    </html>
    ''', nodes=nodes, user=current_user)

# API
@app.route("/api/nodes")
@token_required
def get_nodes(current_user):
    return jsonify({
        "nodes": nodes,
        "status": "online",
        "user": current_user,
        "timestamp": datetime.utcnow().isoformat()
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port)


    flask==2.3.3
gunicorn==21.2.0
PyJWT==2.8.0
flask-bcrypt==1.0.1
python-dotenv==1.0.1



web: gunicorn app


ADMIN_USER=admin
ADMIN_PASSWORD_HASH=$2b$12$eIA6kj7.a9M2t9uZ7L3qOeW9Zz8v6qJ5rK2p3oR1qY0uV1Z1X1Y1Z1
SECRET_KEY=ac4f8d2e1b7f4a9c8e6d5b4a3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b



from flask_bcrypt import generate_password_hash
print(generate_password_hash("tu_contraseña").decode('utf-8'))



{
  "variables": [
    {
      "key": "ADMIN_USER",
      "value": "admin",
      "isSecret": false
    },
    {
      "key": "ADMIN_PASSWORD_HASH",
      "value": "",
      "isSecret": true
    },
    {
      "key": "SECRET_KEY",
      "value": "",
      "isSecret": true,
      "generateValue": true
    }
  ]
}



# 🚀 NeuroRed Konradov

Backend Flask con autenticación JWT, hashing seguro con **bcrypt**, y simulación de nodos cuánticos.  
Despliega en segundos con Railway.

## 🔐 Seguridad
- Contraseñas hasheadas con `bcrypt`
- Tokens JWT con expiración
- Variables de entorno protegidas

## 🛠️ Variables requeridas
- `ADMIN_USER`: Usuario de acceso (ej: `admin`)
- `ADMIN_PASSWORD_HASH`: Contraseña hasheada (usa `bcrypt` para generarla)
- `SECRET_KEY`: Clave secreta para JWT (generada automáticamente en Railway)

👉 **Despliega en un clic:**

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/https://github.com/tu-usuario/neurored-konradov)

> Reemplaza `tu-usuario` con tu nombre de usuario de GitHub.

