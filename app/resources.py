import re

from flask import jsonify
from flask_restful import Resource, reqparse
from flask_jwt_extended import create_access_token, create_refresh_token,\
    jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt,\
    get_current_user, get_jwt_claims
from flask_restful_swagger import swagger

from .models import UserModel,  ApplicationModel, RoleModel
from . import parser, db, jwt


def is_admin():
    """Look up identity of Token's username, and check for ADMIN role.
    """
    claims = get_jwt_claims()
    # If User is of ADMIN role
    if UserModel.isadmin(claims['identity']):
        return True
    # Else if Token belongs to a User with a role other than ADMIN
    else:
        return False


@jwt.user_claims_loader
def add_claims_to_access_token(identity):
    """Assign claims to the access tokens, pass the identity of token owner.
    """
    return {'identity': identity}


class UserLogin(Resource):
    """User Login
    """

    def post(self):
        """
        User Login
        Log into application with username and password.
        ---
        consumes:
            - application/json
        parameters:
            - name: body
              in: body
              schema:
                type: object
                required:
                    - username
                    - password
                properties:
                    username:
                        type: string
                    password:
                        type: string
                    
        responses:
            200:
                description: Create User successfully
                schema:
                    id: User
                    properties:
                        message:
                            type: string
                            description: The name of the user
                            default: Default Username
            500:
                description: Login error
                schema:
                    id: User
                    properties:
                    message:
                        type: string
                        description: Error description
                        default: Default
        """
        data = parser.parse_args()
        current_user = UserModel.find_by_username(data['username'])

        # Does user name match existing?
        if not current_user:
            return {'message': 'User {} does not exist.'.format(data['username'])}

        # Does password match the user's password on record?
        if UserModel.verify_hash(data['password'], current_user.password):
            # access_token = create_access_token(identity = data['username'])
            # refresh_token = create_refresh_token(identity = data['username'])
            access_token = create_access_token(data['username'])
            refresh_token = create_refresh_token(data['username'])
            
            # Assign access_token to current_user and update last call time
            current_user.update_token(access_token)
            current_user.update_lastcall_time()
            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        else:
            return {'message': 'Incorrect credential combination.'}

      
class AllUsers(Resource):
    """All users
    """

    def post(self):
        """
        Create User
        Description.
        ---
        consumes:
            - application/json
        parameters:
            - name: body
              in: body
              schema:
                type: object
                required:
                    - username
                    - password
                    - role
                properties:
                    username:
                        type: string
                    password:
                        type: string
                    role:
                        type: string
                    
        responses:
            200:
                description: Create User successfully
                schema:
                    id: User
                    properties:
                        message:
                            type: string
                            description: The name of the user
                            default: Default Username
                        access_token:
                            type: string
                            description: JWT access token
                            default: access_token
                        refresh_token:
                            type: string
                            description: JWT refresh token
                            default: refresh_token
            500:
                description: Error creating User
                schema:
                    id: User
                    properties:
                    message:
                        type: string
                        description: Error description
                        default: Default
        """
        data = parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return {'message': 'User {} already exists.'.format(data['username'])}

        # Assert that password must contain a letter, a number, 
        # and have a length between 8 and 20 characters.
        if re.match(r"^(?=.*[\d])(?i)(?=.*[A-Z])[\w\d@#$]{8,20}$", data['password']):
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
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            new_user.token = access_token
            new_user.save_to_db()
            return {
                'message': 'User {} created.'.format(data['username']),
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        except:
            return {'message': 'Error attempting to create username {}.'.format(data['username'])}, 500

    def get(self):
        """
        View all users
        Description.
        ---
        responses:
            200:
                description: Showing users (password encrypted)
                schema:
                    id: User
                    properties:
                    username:
                    type: string
                    description: The names of the user
                    default: Default Username
            500:
                description: Error showing users
                schema:
                    id: User
                    properties:
                        message:
                            type: string
                            description: Error description
                            default: Default
        """
        return UserModel.return_all()


    @jwt_required
    def put(self):
        """
        Edit user
        Token must be active AND belong to a user of role ADMIN
        ---
        consumes:
            - application/json
        parameters:
            - name: body
              in: body
              schema:
                type: object
                required:
                    - username
                properties:
                    username:
                        type: string
                    password:
                        type: string
                    role:
                        type: string
            - name: Authorization
              in: header
              schema:
                type: object
                required:
                    - access_token
                properties:
                    access_token:
                        type: string
        responses:
            200:
                description: Edit user
                schema:
                    id: User
                    properties:
                    username:
                    type: string
                    description: The names of the user
                    default: Default Username
            500:
                description: Error editing user
                schema:
                    id: User
                    properties:
                        message:
                            type: string
                            description: Error description
                            default: Default

        """

        # User to edit
        data = parser.parse_args()

        # Access the identity of the current user with get_jwt_claims()
        claims = get_jwt_claims()
        print('####claims \nin fn', claims)
        print('claims: ', claims)
      
        # Is admin()
        if is_admin():
            pass
        else:
            return {'message': 'Admin priviledge required.'}, 403


        # If the User with username exists
        if UserModel.find_by_username(data['username']):
            try:
                UserModel.update_user(data)
                return {'message': 'User {} modified.'.format(data['username'])}
            except:
                return {'message': 'Error attempting to modify user {}.'.format(data['username'])}, 500
        else:
            return {'message': 'Cannot find username {}'.format(data['username'])}


    @jwt_required
    def delete(self):
        """
        file: swagger.yml
        """
                # Is admin()
        if is_admin():
            pass
        else:
            return {'message': 'Admin priviledge required.'}, 403


        return UserModel.delete_all()
      

class ApplicationRegistration(Resource):
    """Application Registration
    """

    @jwt_required
    def get(self):
        """View all applications"""
        try:
            current_user = get_jwt_identity()

            return {'message': 'Logged in as {}.'.format(current_user),
                    'applications': ApplicationModel.return_all()}, 200
        except:
            return {'message': 'Error attempting to view applications.'}, 500
    
    @jwt_required
    def post(self):
        """Create application"""
        # Is admin()
        if is_admin():
            pass
        else:
            return {'message': 'Admin priviledge required.'}, 403

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

    @jwt_required    
    def put(self):
        """Edit application"""
        # Is admin()
        if is_admin():
            pass
        else:
            return {'message': 'Admin priviledge required.'}, 403

        data = parser.parse_args()

        if ApplicationModel.find_by_appname(data['appname']):
            try:
                ApplicationModel.update_app(data)
                return {'message': 'Application {} modified.'.format(data['appname'])}
            except:
                return {'message': 'Error attempting to modify application {}.'.format(data['appname'])}, 500
        else:
            return {'message': 'Cannot find application {}'.format(data['appname'])}
        


    @jwt_required
    def delete(self):
        """Delete application"""
        data = parser.parse_args()

        if ApplicationModel.find_by_appname(data['appname']):
            try:
                ApplicationModel.delete_app(data['appname'])
                return {'message': 'Application {} deleted.'.format(data['appname'])}
            except:
                return {'message': 'Error attempting to delete application {}.'.format(data['appname'])}
        else:
            return {'message': 'Cannot find application {}.'.format(data['appname'])}
        

class AllRoles(Resource):
    """All Roles"""

    def get(self):
        """View all roles"""
        try:
            current_user = get_jwt_identity()

            return {'message': 'Logged in as {}.'.format(current_user),
                    'applications': RoleModel.return_all()}, 200
        except:
            return {'message': 'Error attempting to view roles.'}, 500
    
    @jwt_required
    def post(self):
        """Create role"""
        # Is admin()
        if is_admin():
            pass
        else:
            return {'message': 'Admin priviledge required.'}, 403


        data = parser.parse_args()

        if RoleModel.find_by_rolename(data['rolename']):
            return {'message': 'Role {} already exists.'.format(data['rolename'])}

        new_role = RoleModel(
            rolename = data['rolename'],
        )

        try:
            new_role.save_to_db()
            return {'message': 'Role {} created.'.format(data['rolename'])}
        except:
            return {'message': 'Error attempting to create role {}.'.format(data['rolename'])}, 500

    @jwt_required
    def put(self):
        """Edit role"""

        # Is admin()
        if is_admin():
            pass
        else:
            return {'message': 'Admin priviledge required.'}, 403


        data = parser.parse_args()

        if RoleModel.find_by_rolename(data['rolename']):
            try:
                RoleModel.update_role(data)
                return {'message': 'Application {} modified.'.format(data['rolename'])}
            except:
                return {'message': 'Error attempting to modify application {}.'.format(data['rolename'])}, 500
        else:
            return {'message': 'Cannot find role {}'.format(data['rolename'])}
        


    @jwt_required
    def delete(self):
        """Delete role"""
        # Is admin()
        if is_admin():
            pass
        else:
            return {'message': 'Admin priviledge required.'}, 403

        data = parser.parse_args()

        if RoleModel.find_by_rolename(data['rolename']):
            try:
                RoleModel.delete_app(data['rolename'])
                return {'message': 'Role {} deleted.'.format(data['rolename'])}
            except:
                return {'message': 'Error attempting to delete role {}.'.format(data['rolename'])}
        else:
            return {'message': 'Cannot find role {}.'.format(data['rolename'])}
