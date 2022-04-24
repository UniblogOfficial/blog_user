import random

from flask import Flask, request, Response, jsonify, abort
from email_validator import validate_email, EmailNotValidError
from flask_jwt_extended import JWTManager, create_access_token, \
    jwt_required, get_jwt_identity
from flask_restx import Api, Resource, fields
from app.database.db import initialize_db
from app.database.models import User, Social
from datetime import datetime, timedelta

import imghdr
import string

import bcrypt
import tempfile

app = Flask(__name__)
app.config['MONGODB_SETTINGS'] = {
    'host': 'mongodb://localhost/users'
}
initialize_db(app)

app.config['SECRET_KEY'] = 'super-secret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False

jwt = JWTManager(app)
api = Api(app)


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


@api.route('/create_user', endpoint='create_user')
@api.doc(params={'email': 'User email',
                 'password': 'User password'})
class CreateUser(Resource):
    @staticmethod
    def post():
        data = request.get_json()
        if 'email' not in data and \
                'password' not in data:
            return Response(status=401)
        state, messange = validate_data(data)
        if not state:
            return {"code": "401", "state": messange}
        data['password'] = bcrypt.hashpw(data['password'].encode(),
                                         bcrypt.gensalt())
        user = User(**data).save()
        return jsonify(user), 201


@api.route('/logging', endpoint='logging')
@api.doc(params={'email': 'User email',
                 'password': 'User password'})
class Logging(Resource):
    @staticmethod
    def post():
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


@api.route('/user/<id_>', endpoint='user-id')
@api.doc()
class UserId(Resource):
    @jwt_required()
    def get(self, id_):
        get_jwt_identity()
        user = User.objects(id=id_).first()
        if not user:
            return {"data": "Пользователь не найден"},
        return jsonify(user)

    @staticmethod
    def put():
        pass

    @staticmethod
    def delete():
        pass


@api.route('/users', endpoint='users')
@api.doc()
class Users(Resource):
    @jwt_required()
    def get(self):
        get_jwt_identity()
        users = User.objects()
        return jsonify(users)


@api.route('/user/<id_>/image', endpoint='user-image')
@api.doc(params={'id': 'user id',
                 'file': 'file image'})
class UserPicture(Resource):
    @staticmethod
    @jwt_required()
    def put(id_):
        get_jwt_identity()
        user = User.objects(id=id_).first()
        if request.files['file']:
            temp = tempfile.TemporaryDirectory()
            image = request.files['file']
            image.save(f"{image.filename}")
            if not imghdr.what(f"{image.filename}") in ('jpeg', 'png', 'gif', 'tiff'):
                return {"data": "image error"}, 400
        else:
            user.update_one(**request.data())
        user.save()
        return jsonify(user)


@api.route('/user/<id_>/user_social', endpoint='user-social')
@api.doc(params={'id': 'User id',
                 'data_social': '?'})
class Social(Resource):
    @jwt_required()
    def post(self, id_):
        get_jwt_identity()
        data = request.get_json()
        user = User.objects(id=id_).first()
        social = Social(**data).save()
        user.social.append(social)
        User().save()
