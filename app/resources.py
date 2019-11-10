import re

from flask import jsonify
from flask_restful import Resource, reqparse
from flask_jwt_extended import create_access_token, create_refresh_token,\
    jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt
from flask_restful_swagger import swagger

from .models import UserModel,  ApplicationModel
from . import admin_required, parser



class ApplicationRegistration(Resource):
    "Application Registration"

    @swagger.operation()
    @jwt_required
    def get(self):
        try:
            current_user = get_jwt_identity()

            return {'message': 'Logged in as {}.'.format(current_user),
                    'applications': ApplicationModel.return_all()}, 200
        except:
            return {'message': 'Error attempting to view application.'}, 500
    
    @swagger.operation()
    @jwt_required
    @admin_required
    def post(self):

        data = parser.parse_args()

        if ApplicationModel.find_by_appname(data['appname']):
            return {'message': 'Application {} already exists.'.format(data['appname'])}

        new_application = ApplicationModel(
            appname = data['appname'],
            url_app = data['url_app'],
            url_image = data['url_image'],
            description = data['description'],
            url_ftp = data['url_ftp']
        )

        try:
            new_application.save_to_db()
            return {'message': 'Application {} created.'.format(data['appname'])}
        except:
            return {'message': 'Error attempting to create application {}.'.format(data['appname'])}, 500

    @swagger.operation()
    @jwt_required
    @admin_required
    def put(self):
        data = parser.parse_args()

        if ApplicationModel.find_by_appname(data['appname']):
            try:
                ApplicationModel.update_app(data)
                return {'message': 'Application {} modified.'.format(data['appname'])}
            except:
                return {'message': 'Error attempting to modify application {}.'.format(data['appname'])}, 500
        else:
            return {'message': 'Cannot find application {}'.format(data['appname'])}
        

    @swagger.operation()
    @jwt_required
    @admin_required
    def delete(self):
        data = parser.parse_args()

        if ApplicationModel.find_by_appname(data['appname']):
            try:
                ApplicationModel.delete_app(data['appname'])
                return {'message': 'Application {} deleted.'.format(data['appname'])}
            except:
                return {'message': 'Error attempting to delete application {}.'.format(data['appname'])}
        else:
            return {'message': 'Cannot find application {}.'.format(data['appname'])}
        

class UserRegistration(Resource):
    "User Registration"

    @swagger.operation()
    def post(self):
        data = parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return {'message': 'User {} already exists.'.format(data['username'])}

        # Assert that password must contain a letter, a number, 
        # and have a length between 8 and 20 characters.
        if re.match(r"^(?=.*[\d])(?i)(?=.*[A-Z])[\w\d@#$]{8,20}$",\
        data['password']):
            pass
        else:
            return {'message': 'Error attempting to create password.',
                    'tip': 'Password must contain a letter, a number, and have a length between 8 and 20 characters.'}, 500

        new_user = UserModel(
            username = data['username'],
            password = UserModel.generate_hash(data['password']),
            role = data['role']
        )

        try:
            new_user.save_to_db()
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return {
                'message': 'User {} created.'.format(data['username']),
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        except:
            return {'message': 'Error attempting to create username {}.'.format(data['username'])}, 500


class UserLogin(Resource):
    "User Login"

    @swagger.operation()
    def post(self):
        data = parser.parse_args()
        current_user = UserModel.find_by_username(data['username'])

        # Does user name match existing?
        if not current_user:
            return {'message': 'User {} does not exist.'.format(data['username'])}

        # Does password match the user's password on record?
        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            
            # Assign access_token to current_user
            current_user.access_token = access_token
            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        else:
            return {'message': 'Incorrect credential combination.'}

      
class AllUsers(Resource):
    "All users"

    @swagger.operation()
    def get(self):
        return UserModel.return_all()

    @swagger.operation()
    @jwt_required
    @admin_required
    def delete(self):
        return UserModel.delete_all()
      
      
class SecretResource(Resource):
    """ Test secret resource can only be accessed with JWT token and ADMIN role.
    """
    @jwt_required
    @admin_required
    def get(self):
        return {
            'answer': 'Successful test response for secret resource. '
        }
