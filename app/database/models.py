from .db import db

class User(db.Document):
    #id =
    #profile_image =
    #user_id =
    name = db.StringField(unique=True)
    password = db.StringField()
    email = db.StringField(unique=True, required=True)
    #frends_liist
    #sicial
