from functools import wraps

from flask import Flask, jsonify
from flasgger import Swagger, swag_from
from flask_restful import Api, Resource
from flask_jwt_extended import create_access_token, create_refresh_token,\
    jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt,\
    get_current_user, get_jwt_claims
from . import models, resources

from . import app, api, Swagger, db, jwt


api.add_resource(resources.UserLogin, '/login')
api.add_resource(resources.AllUsers, '/user')
api.add_resource(resources.AllRoles, '/role')
api.add_resource(resources.AllApplications, '/app')


# Instantiate tables in database
@app.before_first_request
def create_tables():
    db.create_all()




if __name__=="__main__":
    app.run(debug=True)
