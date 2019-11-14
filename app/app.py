from flask import Flask, jsonify
from flasgger import Swagger, swag_from
from flask_restful import Api, Resource
from . import models, resources

from . import app, api, Swagger, db


api.add_resource(resources.UserLogin, '/login')
api.add_resource(resources.AllUsers, '/user')


# Instantiate tables in database
@app.before_first_request
def create_tables():
    db.create_all()


if __name__=="__main__":
    app.run(debug=True)
