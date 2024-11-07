from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from models import User
from schemas import UserSchema, UserMinimalSchema
from app import db
from flask_jwt_extended import jwt_required, get_jwt, create_access_token

# Definición del Blueprint para vistas de autenticación y administración de usuarios
auth_view_bp = Blueprint("auth_view", __name__)


@auth_view_bp.route("/login", methods=["POST"])
def login_view():
    data = request.get_json()

    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"msg": "Faltan datos"}), 400

    username = data['username']
    password = data['password']
    print(f"Intentando login con: {username}")  #verifica si llega el usuario

    user = User.query.filter_by(username=username).first()
    if user:
        print(f"Usuario encontrado: {user.username}")
    else:
        print(f"Usuario no encontrado")

    if user and check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity={"id": user.id, "is_admin": user.is_admin})
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "Credenciales incorrectas"}), 401



@auth_view_bp.route('/register', methods=['POST'])
def register_view():
    data = request.get_json()

    # Verificar que los datos necesarios estén presentes
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Nombre de usuario y contraseña son requeridos"}), 400

    username = data['username']
    password = data['password']

    # Generar el hash de la contraseña
    password_hash = generate_password_hash(password)

    try:
        # Crear el nuevo usuario con el hash de la contraseña
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "Usuario creado exitosamente", "user": new_user.username}), 201
    except Exception as e:
        return jsonify({"message": "Error en el servidor: " + str(e)}), 500

@auth_view_bp.route("/usuarios", methods=["GET"])
def lista_usuarios():
    """Lista todos los usuarios. Solo accesible para administradores."""
    if not session.get("is_admin"):
        flash("No tienes permisos para acceder a esta página.")
        return redirect(url_for("auth_view.login_view"))

    usuarios = User.query.all()
    return render_template("usuarios.html", usuarios=usuarios)


@auth_view_bp.route("/admin", methods=["GET", "POST"])
def admin_view():
    """Vista de administración para crear usuarios. Solo accesible para administradores."""
    if not session.get("is_admin"):
        flash("No tienes permisos para acceder a esta página.")
        return redirect(url_for("auth_view.login_view"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed_password = generate_password_hash(password)

        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Usuario creado con éxito.")

    usuarios = User.query.all()
    return render_template("admin.html", usuarios=usuarios)


@auth_view_bp.route("/delete_user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    """Elimina un usuario. Solo accesible para administradores."""
    if not session.get("is_admin"):
        flash("No tienes permisos para eliminar usuarios.")
        return redirect(url_for("auth_view.admin_view"))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash("Usuario eliminado con éxito.")
    return redirect(url_for("auth_view.admin_view"))


@auth_view_bp.route("/users", methods=["POST"])
@jwt_required()
def create_user():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"msg": "No data provided"}), 400

        # Crear el usuario
        user = User(username=data['username'], password=data['password'])
        db.session.add(user)
        db.session.commit()

        # Devolver una respuesta JSON válida
        return jsonify({"msg": "Usuario creado correctamente", "user": user.username}), 201
    except Exception as e:
        return jsonify({"msg": f"Error al crear el usuario: {str(e)}"}), 500
