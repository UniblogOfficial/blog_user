from flask import Flask, request, Response, jsonify
from email_validator import validate_email, EmailNotValidError
from flask_jwt_extended import JWTManager, create_access_token, \
                                jwt_required, get_jwt_identity
from app.database.db import initialize_db
from app.database.models import User
from flasgger import Swagger
from datetime import datetime

import bcrypt

app = Flask(__name__)
app.config['MONGODB_SETTINGS'] = {
    'host': 'mongodb://localhost/users'
}
initialize_db(app)

app.config['SECRET_KEY'] = 'super-secret'
app.config['JWT_SECRET_KEY'] = app.config['SECRET_KEY']
app.config['JWT_ACCESS_TOKEN_EXPRESS'] = False

swagger = Swagger(app)

jwt = JWTManager(app)


@app.route('/create_user', methods=['POST'])
def create_user():
    if 'email' not in request.get_json() and \
            'password' not in request.get_json():
        return Response(status=401)
    data = request.get_json()
    try:
        valid = validate_email(data['email'])
    except EmailNotValidError:
        return Response('email not validate', status=401)
    data['password'] = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt())
    try:
        user = User(**data).save()
    except Exception:
        return {"data": "Такой пользователь существует"}
    return jsonify(user), 201


@app.route('/login', methods=['POST'])
def loging():
    if not request.get_json().get('email') and not \
            request.get_json().get('password'):
        return Response('', status=401)
    data = request.get_json()
    user = User.objects(email=data['email']).first()
    if bcrypt.checkpw(data['password'].encode('utf-8'),
                                 user.password.encode('utf-8')):
        dt = datetime.now()
        return jsonify({"token": create_access_token(
                                 identity=f"{data['email']}{dt.microsecond}"),
                        "id": user["id"]})
    return Response('error', status=401)


@app.route('/user', methods=['GET'])
@jwt_required()
def user():
    email = get_jwt_identity()
    try:
        user = User.objects(email=email).first()
    except Exception:
        return {"data": "Пользователь не найден"},
    return {"data": user, "id": str(user['id'])}