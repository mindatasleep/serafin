from passlib.hash import pbkdf2_sha256 as sha256
from datetime import datetime


from . import db, swagger

@swagger.model
class ApplicationModel(db.Model):
    """Table model for Application
    """
    
    __tablename__ = 'applications'

    id = db.Column(db.Integer, primary_key = True)
    appname = db.Column(db.String(20), unique=True, nullable=False)
    url_app = db.Column(db.String(200), unique=True, nullable=True)
    url_image = db.Column(db.String(200), unique=True, nullable=True)
    description = db.Column(db.String(200), unique=True, nullable=True)
    url_ftp = db.Column(db.String(200), unique=True, nullable=True)


    @classmethod
    def find_by_appname(cls, appname):
        return cls.query.filter_by(appname = appname).first()


    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'appname': x.appname,
                'url_app': x.url_app,
                'url_image': x.url_image,
                'description': x.description,
                'url_ftp': x.url_ftp
            }
        return {'applications': list(map(lambda x: to_json(x), ApplicationModel.query.all()))}

    @classmethod
    def update_app(cls, data):
        application_to_modify = ApplicationModel.query.filter_by(
            appname=data['appname']).update(dict(
                url_app = data['url_app'],
                url_image = data['url_image'],
                description = data['description'],
                url_ftp = data['url_ftp']
            ))
        db.session.commit()

    @classmethod
    def delete_app(cls, appname):
        ApplicationModel.query.filter(ApplicationModel.appname==appname).delete
        db.session.commit()
        

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

@swagger.model
class UserModel(db.Model):
    """Table model for User.
    """

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(20), nullable=False)
    token = db.Column(db.String(20), nullable=True)
    lastcall = db.Column(db.DateTime, nullable=True, default = datetime.utcnow)
    role = db.Column(db.String(20), nullable=True)



    @classmethod
    def update_lastcall_time(cls):
        try:
            _update_lastcall_time = db.session.query(cls).update().values(lastcall = datetime.utcnow)
            db.session.commit()
            return {'message': 'Updated lastcall time.'}
        except:
            return {'message': 'Error updating lastcall time.'}

    @classmethod
    def update_token(cls, token):
        try:
            _update_token_value = db.session.query(cls).update().values(token = token)
            db.session.commit()
            return {'message': 'Updated token.'}
        except:
            return {'message': 'Error updating token.'}

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username = username).first()

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'username': x.username,
                'password': x.password,
                'role': x.role
            }
        return {'users': list(map(lambda x: to_json(x), UserModel.query.all()))}

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} rows deleted.'.format(num_rows_deleted)}
        except:
            return {'message': 'Error deleting users.'}

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
