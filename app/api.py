import random

from flask import Flask, request, Response, jsonify, abort
from email_validator import validate_email, EmailNotValidError
from flask_jwt_extended import JWTManager, create_access_token, \
    jwt_required, get_jwt_identity
from app.database.db import initialize_db
from app.database.models import User, Social
from flasgger import Swagger
from datetime import datetime, timedelta
import imghdr
import string

import bcrypt

app = Flask(__name__)
app.config['MONGODB_SETTINGS'] = {
    'host': 'mongodb://localhost/users'
}
initialize_db(app)

app.config['SECRET_KEY'] = 'super-secret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False

swagger = Swagger(app)

jwt = JWTManager(app)


def validate_data(data: dict) -> ():
    if data.get('email'):
        user = User.objects(email=data['email']).first()
        if user:
            return 0, 'Error Email'
        try:
            valid = validate_email(data['email'])
        except EmailNotValidError:
            return 0, 'EmailNotValidError'
    elif data.get('name'):
        user = User.objects(name=data['name']).first()
        if user:
            return 0, 'Error user'
    return 1, 'ok'


@app.route('/create_user', methods=['POST', 'GET'])
def create_user():
    data = request.get_json()
    if 'email' not in data and \
            'password' not in data:
        return Response(status=401)
    state, messange = validate_data(data)
    if not state:
        return {"code": "401", "state": messange}
    data['password'] = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt())
    # try:
    user = User(**data).save()
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
        token = create_access_token(
            identity=f"{random.choice(string.ascii_letters)}"
                     f"{data['email']}{dt.microsecond}",
            fresh=timedelta(minutes=9999))
        return {"token": token, "id": str(user["id"])}
    return Response('error', status=401)


@app.route('/user/<id_>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def user(id_):
    get_jwt_identity()
    user = User.objects(id=id_).first()
    if not user:
        return {"data": "Пользователь не найден"},
    return {"data": user}


@app.route('/users', methods=['GET'])
@jwt_required()
def users():
    get_jwt_identity()
    users = User.objects()
    return jsonify(users)


@app.route('/user/<id_>', methods=['PUT'])
@jwt_required()
def add_profile_picture(id_):
    get_jwt_identity()
    user = User.objects(id=id_).first()
    if request.files['file']:
        image = request.files['file']
        # if imghdr.what(image.filename) in ('jpeg', 'png', 'gif', 'tiff'):
        user.profile_image.put(image, filename=image.filename)
    else:
        user.update_one(**request.data())
    user.save()
    return jsonify(user), 201
    # else:
    #    return jsonify({"data": "image error"}), 400


@app.route('/user/<id_>/user_social', methods=['POST'])
@jwt_required()
def add_social(id_):
    get_jwt_identity()
    data = request.get_json()
    user = User.objects(id=id_).first()
    social = Social(**data).save()
    user.social.append(social)
    User().save()
