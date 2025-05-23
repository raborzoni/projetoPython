import jwt
import os
from flask import Flask, jsonify, request
from datetime import datetime, timedelta, timezone

SECRET_KEY = os.getenv('SECRET_KEY', 'CasNav_Marinha_Do_Brasil')

app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({"message": "Olá CASNAV. Me aguardem!"})

@app.route('/login', methods=['POST'])
def login():
    dados = request.get_json()

    if 'usuario' not in dados or 'senha' not in dados:
        return jsonify({"message": "Usuário ou senha inválidos"}), 400

    if not dados:
        return jsonify(message="Dados de login não fornecidos!"), 400
    if "usuario" not in dados or "senha" not in dados:
        return jsonify(message="Campos 'usuario' e 'senha' são obrigatórios!"), 400
    if dados["usuario"] == "admin" and dados["senha"] == "admin":
        token = jwt.encode(
            {
                "user": dados["usuario"], 
                "exp": datetime.now(timezone.utc) + timedelta(minutes=30)
                },
            SECRET_KEY,
            algorithm="HS256"
        )
        return jsonify(token=token)
    
    return jsonify(message="Credenciais inválidas!"), 401


@app.route("/protected", methods=["GET"])
def protected():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify(message="Token é necessário!"), 403

    parts = auth_header.split()
    if parts[0].lower() != 'bearer' or len(parts) != 2:
        return jsonify(message="Cabeçalho de autorização malformado!"), 401
    token = parts[1]

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify(message=f"Bem-vindo, {decoded['user']}!")
    except jwt.ExpiredSignatureError:
        return jsonify(message="Token expirado! Faça login novamente."), 401
    except jwt.InvalidTokenError:
        return jsonify(message="Token inválido!"), 403
    
    

if __name__ == '__main__':
    app.run(debug=True)