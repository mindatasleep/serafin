from functools import wraps

from flask import Flask, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, reqparse
from flasgger import Swagger, swag_from
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)


app = Flask(__name__)
api = Api(app)
swagger = Swagger(app)


# Setup the Flask-JWT-Extended extension
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
jwt = JWTManager(app)


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


# Configure Database
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