from flask import Flask, request, jsonify
import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
import bcrypt
import pymysql
from pymysql.cursors import DictCursor
import os
import json

app = Flask(__name__)

app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', '127.0.0.1')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', '')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'casnav')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'CasNav_Marinha_Do_Brasil')
app.config['JWT_EXPIRE_MINUTES'] = int(os.getenv('JWT_EXPIRE_MINUTES', 30))

#  CONEXÃO AO BANCO DE DADOS
def get_db():
    return pymysql.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DB'],
        cursorclass=DictCursor
    )

def log_event(event_type, data):
    log_entry = {
        'event': event_type,
        'data': data,
        'timestamp': datetime.now().isoformat()
    }
    with open('app.log', 'a') as log_file:
        log_file.write(json.dumps(log_entry) + '\n')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split()[1]
        
        if not token:
            log_event('access_attempt', {
                'status': 'failed',
                'reason': 'Token ausente',
                'path': request.path
            })
            return jsonify({'error': 'Token de acesso ausente'}), 400
                
        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user = {
                'user_id': data['user_id'],
                'username': data['username']
            }
        except jwt.ExpiredSignatureError:
            log_event('access_attempt', {
                'status': 'failed',
                'reason': 'Token expirado',
                'path': request.path
            })
            return jsonify({'error': 'Token expirado'}), 400
        
        except jwt.InvalidTokenError:
            log_event('access_attempt', {
                'status': 'failed',
                'reason': 'Token inválido',
                'path': request.path
            })
            return jsonify({'error': 'Token inválido'}), 400
        
        return f(current_user, *args, **kwargs)

    return decorated

#  REGISTRO DO USUÁRIO NO SISTEMA
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Usuário e senha são obrigatórios!'}), 400

    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                return jsonify({'error': 'Usuário já existe!'}), 400
    finally:
        conn.close()

    password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (%s, %s)",
                (username, password.decode('utf-8'))
            )
            user_id = cursor.lastrowid
        conn.commit()
    finally:
        conn.close()

    log_event('user_registered', {'user_id': user_id, 'username': username})

    return jsonify({
        'message': 'Usuário registrado com sucesso!',
        'user_id': user_id
    }), 200


#  LOGIN DO USUÁRIO NO SISTEMA
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Usuário e senha obrigatórios!'}), 400

    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

            if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                return jsonify({'error': 'Dados inválidos'}), 400
    finally:
        conn.close()

    token_payload = {
        'user_id': user['id'],
        'username': user['username'],
        'exp': datetime.now(timezone.utc) + timedelta(hours=app.config['JWT_EXPIRE_MINUTES'])
    }
    token = jwt.encode(token_payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')

    log_event('user_login', {
        'user_id': user['id'],
        'username': username,
        'token': token
    })

    return jsonify({
        'message': 'Login realizado com sucesso!',
        'token': token,
        'user_id': user['id']
    })

#  TESTANDO TOKEN DO USUÁRIO CRIADO EM UMA ROTA PROTEGIDA
@app.route('/protected', methods=['GET'])
@token_required
def protected_route(current_user):
    
    log_event('protected_access', {
        'user_id': current_user['user_id'],
        'username': current_user['username'],
        'status': 'success'
    })
    
    return jsonify({
        'message': 'Acesso liberado',
        'user': {
            'id': current_user['user_id'],
            'username': current_user['username']
        },
        'timestamp': datetime.now(timezone.utc).isoformat()
    })

#  DESLOGANDO O USUÁRIO DO SISTEMA
@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    token = request.headers['Authorization'].split()[1]
    
    log_event('user_logout', {
        'user_id': current_user['user_id'],
        'username': current_user['username'],
        'token': token,
        'status': 'success'
    })
    
    return jsonify({
        'message': 'Desconectado com sucesso!',
        'user_id': current_user['user_id']
    })  
    
# Rota para a página principal
@app.route('/')
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Sistema de Autenticação</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            .container { display: flex; gap: 20px; }
            .auth-forms { flex: 1; }
            .logs { flex: 2; }
            form { margin-bottom: 15px; padding: 15px; background: #f5f5f5; border-radius: 5px; }
            input, button { padding: 8px; margin: 5px 0; width: 100%; box-sizing: border-box; }
            button { background: #4CAF50; color: white; border: none; cursor: pointer; }
            button:hover { background: #45a049; }
            #logOutput { 
                background: #333; 
                color: #0f0; 
                padding: 10px; 
                border-radius: 5px; 
                height: 500px; 
                overflow-y: auto; 
                white-space: pre-wrap;
                font-family: monospace;
            }
            .log-entry { margin-bottom: 10px; }
            .timestamp { color: #aaa; }
        </style>
    </head>
    <body>
        <h1>Sistema de Autenticação</h1>
        <div class="container">
            <div class="auth-forms">
                <h2>Registro</h2>
                <form id="registerForm">
                    <input type="text" id="regUsername" placeholder="Username" required>
                    <input type="password" id="regPassword" placeholder="Password" required>
                    <button type="submit">Registrar</button>
                </form>

                <h2>Login</h2>
                <form id="loginForm">
                    <input type="text" id="loginUsername" placeholder="Username" required>
                    <input type="password" id="loginPassword" placeholder="Password" required>
                    <button type="submit">Login</button>
                </form>

                <h2>Ações</h2>
                <button id="protectedBtn" disabled>Acessar Rota Protegida</button>
                <button id="logoutBtn" disabled>Logout</button>
            </div>

            <div class="logs">
                <h2>Log de Eventos</h2>
                <div id="logOutput"></div>
            </div>
        </div>

        <script>
            let currentToken = null;
            const logOutput = document.getElementById('logOutput');
            
            function addLog(message, data) {
                const timestamp = new Date().toISOString();
                const logEntry = document.createElement('div');
                logEntry.className = 'log-entry';
                logEntry.innerHTML = `
                    <div class="timestamp">${timestamp}</div>
                    <div>${message}</div>
                    <pre>${JSON.stringify(data, null, 2)}</pre>
                `;
                logOutput.prepend(logEntry);
            }

            // Registrar usuário
            document.getElementById('registerForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const username = document.getElementById('regUsername').value;
                const password = document.getElementById('regPassword').value;
                
                try {
                    const response = await fetch('/register', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password })
                    });
                    const data = await response.json();
                    addLog('Registro:', data);
                } catch (error) {
                    addLog('Erro no registro:', { error: error.message });
                }
            });

            // Login
            document.getElementById('loginForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const username = document.getElementById('loginUsername').value;
                const password = document.getElementById('loginPassword').value;
                
                try {
                    const response = await fetch('/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password })
                    });
                    const data = await response.json();
                    
                    if (data.token) {
                        currentToken = data.token;
                        document.getElementById('protectedBtn').disabled = false;
                        document.getElementById('logoutBtn').disabled = false;
                    }
                    
                    addLog('Login:', data);
                } catch (error) {
                    addLog('Erro no login:', { error: error.message });
                }
            });

            // Rota protegida
            document.getElementById('protectedBtn').addEventListener('click', async () => {
                if (!currentToken) return;
                
                try {
                    const response = await fetch('/protected', {
                        method: 'GET',
                        headers: { 'Authorization': `Bearer ${currentToken}` }
                    });
                    const data = await response.json();
                    addLog('Rota Protegida:', data);
                } catch (error) {
                    addLog('Erro na rota protegida:', { error: error.message });
                }
            });

            // Logout
            document.getElementById('logoutBtn').addEventListener('click', async () => {
                if (!currentToken) return;
                
                try {
                    const response = await fetch('/logout', {
                        method: 'POST',
                        headers: { 'Authorization': `Bearer ${currentToken}` }
                    });
                    const data = await response.json();
                    
                    currentToken = null;
                    document.getElementById('protectedBtn').disabled = true;
                    document.getElementById('logoutBtn').disabled = true;
                    
                    addLog('Logout:', data);
                } catch (error) {
                    addLog('Erro no logout:', { error: error.message });
                }
            });
        </script>
    </body>
    </html>
    """  

if __name__ == '__main__':
    app.run(debug=True)