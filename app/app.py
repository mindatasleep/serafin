from flask import Flask

from . import app, db, jwt, api
from . import models, resources

# Routes
api.add_resource(resources.UserLogin, '/login')
api.add_resource(resources.AllUsers, '/users')
api.add_resource(resources.AllRoles, '/roles')
api.add_resource(resources.ApplicationRegistration, '/application')

# Instantiate tables in database
@app.before_first_request
def create_tables():
    db.create_all()

# Shell
@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': models.UserModel}


if __name__=='__main__':
    app.run(debug=True)
    db.session.commit()