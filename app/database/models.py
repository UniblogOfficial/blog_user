from .db import db


class Social(db.EmbeddedDocument):
    name = db.StringField()
    type = db.StringField()
    url = db.URLField(unique=True)
    title = db.StringField()
    #social_name = db.StringField()
    #user = db.ReferenceField(User)
    #addres = db.StringField(unique=True)
    #user_id = db.StringField(unique=True)
    #data = db.DictField(db.StringField())
    #login = db.StringField()
    #password = db.StringField()
    #acces_token = db.StringField()
    #jwt_token = db.StringField()


class User(db.Document):
    profile_image = db.FileField()
    name = db.StringField(unique=True)
    password = db.StringField(required=True, selected=False)
    email = db.EmailField(unique=True, required=True)
    social = db.ListField(db.EmbeddedDocumentField(Social))

