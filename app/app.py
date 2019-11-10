from flask import Flask

from . import app, db, jwt, api
from . import models, resources, views

# Routes
api.add_resource(resources.UserRegistration, '/registration')
api.add_resource(resources.UserLogin, '/login')
api.add_resource(resources.AllUsers, '/users')
api.add_resource(resources.SecretResource, '/secret')
api.add_resource(resources.ApplicationRegistration, '/application')

# Instantiate tables in database
@app.before_first_request
def create_tables():
    db.create_all()


if __name__=='__main__':
    app.run(debug=True)
