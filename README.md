# Web service application

An API to create and modify user accounts which create and modify applications. A user account has a role. Only ADMIN roles can modify the role of user accounts. Only accounts with a valid token can modify applications.

### Specify MySQL database
Set database URI in `app/__init__.py` as `dialect+driver://user:pass@host:port/db`.

### Tokens
The app uses JWT for authentication. Access tokens are given to user accounts upon login (`create_access_token()`). The returned token must be added to request headers as `Authorization: Bearer <access_token>` in order to be granted access to protected resources.

Tokens expire after 15 minutes. The `jwt_required()` decorator to protects endpoints. Once a token expires, a user must log in again to retrieve a fresh token. Tokens are added to a blacklist if a user logs out. Further functionality could be developed to implement a token refreshing function.

## Execute app
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python3 -m app.app
```

## Run app interactively in shell
```
flask shell
```

## Swagger API documentation
Interactive HTML
```
http://127.0.0.1:5000/api/spec.html
```
JSON
```
http://127.0.0.1:5000/api/spec.json
```

## Inspect API
Inspect API using `https://inspector.swagger.io/` or `https://www.getpostman.com/`.

In Swagger terms, `paths` are endpoints (resources) that the API exposes, such as `/users` or `/login`, and `operations` are the HTTP methods used to manipulate these paths, such as `GET`, `POST` or `DELETE`.

## Sample walkthrough
### Register user
#### Request
`POST http://0.0.0.0:5000/users`
#### Body
```
{
    "username": "admin",
    "password": "password12321",
    "role": "ADMIN"
}
```
### Login
#### Request
`POST http://0.0.0.0:5000/login`
#### Body
```
{
    "username": "admin",
    "password": "password12321"
}
```
#### Response
The response will look like:
```
{
    "message": "User admin2 created.",
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1NzM0MTE2MjAsIm5iZiI6MTU3MzQxMTYyMCwianRpIjoiMmM5ZjI4ZjUtNjg0Zi00MDUxLThlYTYtZmFhM2RhNGRiODVhIiwiZXhwIjoxNTczNDEyNTIwLCJpZGVudGl0eSI6ImFkbWluMiIsImZyZXNoIjpmYWxzZSwidHlwZSI6ImFjY2VzcyJ9.c_OBh4GmB852IuCqmhfzx7VBfahGyPvjY5FMdzwcSMM",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1NzM0MTE2MjAsIm5iZiI6MTU3MzQxMTYyMCwianRpIjoiNGM0MjE3NmUtMDg4MC00M2E0LWI0ZTEtYmI0MTNjMDMzMzhkIiwiZXhwIjoxNTc2MDAzNjIwLCJpZGVudGl0eSI6ImFkbWluMiIsInR5cGUiOiJyZWZyZXNoIn0.UNbyPxjKVEsPUj2UUEfrMtwIN3PFHcr_FbvS3SwHiNY"
}
```

Include the Token in the header:
`Authorization: Bearer <access_token>`

### Create Application
#### Request
`POST http://127.0.0.1:5000/applicationregistration`
#### Body
{
    "appname": "anapp",
    "url_app": "newrl",
    "url_image": "newurl",
    "description": null,
    "url_ftp": null
}


## Dockerized MySQL
```
docker-compose -f db/docker-compose.yml up -d
docker-compose -f db/docker-compose.yml down -d
```

Set credentials in `app/__init__.py`.
KOslEd93b3wqaGak0HN3l2aNUJ&



# References
https://codeburst.io/jwt-authorization-in-flask-c63c1acf4eeb
