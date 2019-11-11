from flask import Flask, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from functools import wraps
from flask_jwt_extended import get_current_user, verify_jwt_in_request
from flask_restful import reqparse
from flask_restful_swagger import swagger
from flask_restful import Api


# Flask app attached to API object [enables swagger]
app = Flask(__name__)
# api = Api(app)
api = swagger.docs(Api(app), apiVersion='0.1')
# Token manager
jwt = JWTManager(app)

app.config['SECRET_KEY'] = 'YOUR_SECRET_KEY'
app.config['JWT_SECRET_KEY'] = 'YOUR_JWT_SECRET_KEY'

# Parse return arguments
parser = reqparse.RequestParser()
parser.add_argument('username', required = False)
parser.add_argument('password', required = False)
parser.add_argument('role', required = False)
parser.add_argument('rolename', required = False)
parser.add_argument('appname', required = False)
parser.add_argument('url_app', required = False)
parser.add_argument('url_image', required = False)
parser.add_argument('description', required = False)
parser.add_argument('url_ftp', required = False)

# MySQL configuration
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:newpassword@localhost/updb2'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:newpassword@localhost:3308/updb'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sqlite.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)

# Decorator to require 'ADMIN' role status
def admin_required(fn):
    # Wrapper to assert user has ADMIN role.
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # verify_jwt_in_request()
        # user = get_current_user()
        data = parser.parse_args()
        print(data)

        if data['role'] == 'ADMIN':
            return fn(*args, *kwargs)
        return {'message': 'Admin priviledge required.'}, 403

    return wrapper
