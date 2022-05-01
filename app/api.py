import random

from flask import Flask, request, Response, jsonify, redirect
from email_validator import validate_email, EmailNotValidError
from flask_jwt_extended import JWTManager, create_access_token, \
    jwt_required, get_jwt_identity
from flask_restx import Api, Resource
from app.database.db import initialize_db
from app.database.models import User, Social
from datetime import datetime, timedelta
from collections import defaultdict

import imghdr
import string

import bcrypt
import tempfile
import requests

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


@api.route('/api/auth/registr', endpoint='create_user')
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
        return jsonify(user)


@api.route('/api/auth/login', endpoint='logging')
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


# /api/auth/me
@api.route('/user/<id_>', endpoint='user-id')
@api.doc()
class UserId(Resource):
    @staticmethod
    def get(id_):
        user = User.objects(id=id_).first()
        profile_image = user.profile_image.read()
        content_type = user.profile_image.content_type()

        # user.update(file)
        if not user:
            return {"data": "Пользователь не найден"},
        return jsonify(content_type)

    @jwt_required()
    @staticmethod
    def put(id_):
        data = request.get_json()
        get_jwt_identity()
        user = User.objects(id=id_).update(**data)
        user.reload()
        return jsonify(user)

    @jwt_required()
    @staticmethod
    def delete():
        pass


@api.route('/api/users', endpoint='users')
@api.doc()
class Users(Resource):
    @staticmethod
    def get():
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
        image = request.files.get('file')
        if request.files['file']:
            temp = tempfile.TemporaryDirectory()
            image.save(f"{image.filename}")
            if not imghdr.what(f"{image.filename}") in ('jpeg', 'png', 'gif', 'tiff'):
                return {"data": "image error"}, 400
        else:
            user.profile_image.put(image, image.filename)
        user.save()
        return jsonify(user)


@api.route('/api/multilink/<string:id_>')
class Multilink(Resource):
    STR_ = 'my.uniblog.'

    @api.doc()
    @staticmethod
    def get(id_):
        user = User.objects(id=id_).first()
        profile_image = user.profile_image.read()
        #content_type = user.profile_image.content_type
        return jsonify(profile_image)


    @api.doc(params={'url': 'http://vk.com.user12918', 'name': 'str', 'type': 'vk, telegram, ...'})
    def put(self, id_):
        data = request.get_json()
        user = User.objects(id=id_)
        data.setdefault('title', f'{self.STR_}{data["name"]}')
        call = requests.get(data["url"])
        if not call is 200:
            return Response('non found', status=404)
        else:
            user = User.objects.get(id=id_)
            social = Social(**data)
            user.social.append(social)
            user.save()
            return jsonify(user)
