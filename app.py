import os
import click
from dotenv import load_dotenv
from flask_cors import CORS
from flask import Flask, render_template
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_marshmallow import Marshmallow
from werkzeug.security import generate_password_hash
from models import User
from db import db
load_dotenv()

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("SQLALCHEMY_DATABASE_URI")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config["JWT_SECRET_KEY"] = "rebeca"

db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
ma = Marshmallow(app)


@app.cli.command("create-admin")
@click.argument("username")
@click.argument("password")
def create_admin(username, password):
    """Crea un usuario administrador."""
    password_hasheada = generate_password_hash(password)
    admin_user = User(username=username, password_hash=password_hasheada, is_admin=True)
    db.session.add(admin_user)
    db.session.commit()
    print(f"Usuario administrador '{username}' creado exitosamente.")


# Para crear un nuevo admin se debe escribir en terminal:
# flask create-admin "usuario" "contraseña" (comillas inclusive)


@app.route("/")
def index():
    return render_template("index.html")


from views import register_blueprints

register_blueprints(app)

CORS(app)

if __name__ == "__main__":
    app.run(debug=True)
