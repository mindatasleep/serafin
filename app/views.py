from flask import render_template, request, jsonify
from flask_jwt_extended import get_current_user, get_jwt_identity,\
    verify_jwt_in_request, jwt_required

from . import app, jwt, admin_required
from .resources import parser
from app.forms import LoginForm, RegistrationForm


@app.route('/index')
def index():
    
    # data = parser.parse_args()
    data = {
            "username": "admin",
            "password": "password"
            }

    username = data['username']
    password = data['password']

    return render_template('index.html', title='Index', 
                            username=username, password=password)

@app.route('/login_page')
def login_page():
    form = LoginForm()
    return render_template('login_page.html', title='Login.', form=form)

# Todo: add @jwt decorator
@app.route('/registration_page')
def registration_page():
    form = RegistrationForm()
    return render_template('registration_page.html', title='Create user', form=form)

@app.route('/applications')
def applications_page():
    data = parser.parse_args()
    print(data)
    # Access the identity of the current user
    # current_user = get_jwt_identity()
    return jsonify(logged_in_as=data['username'], role=data['role']), 200
    
    # return render_template('applications_page.html', title = 'Apps')
    