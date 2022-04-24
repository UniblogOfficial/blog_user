from .db import db


class Social(db.Document):
    social_name = db.StringField()
    #user = db.ReferenceField(User)
    login = db.StringField()
    password = db.StringField()
    token = db.StringField()


class User(db.Document):
    profile_image = db.FileField()
    name = db.StringField(unique=True)
    password = db.StringField(required=True, selected=False)
    email = db.EmailField(unique=True, required=True)
    social = db.ListField(db.ReferenceField(Social))

