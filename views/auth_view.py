from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from models import User
from schemas import UserSchema, UserMinimalSchema
from app import db
from flask_jwt_extended import jwt_required, get_jwt, create_access_token
from base64 import b64decode


# Definición del Blueprint para vistas de autenticación y administración de usuarios
auth_view_bp = Blueprint("auth_view", __name__)


@auth_view_bp.route("/login", methods=["POST"])
def login_view():
    # Verificar si el encabezado Authorization contiene credenciales en formato Basic
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Basic "):
        return jsonify({"msg": "Autenticación requerida"}), 401

    # Decodificar las credenciales de Base64
    encoded_credentials = auth_header.split(" ")[1]
    decoded_credentials = b64decode(encoded_credentials).decode("utf-8")
    
    # Separar el nombre de usuario y la contraseña
    username, password = decoded_credentials.split(":")

    # Intentar encontrar al usuario
    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password_hash, password):
        # Generar el token JWT
        access_token = create_access_token(identity={"id": user.id, "is_admin": user.is_admin})
        return jsonify({"Token": access_token}), 200
    else:
        return jsonify({"msg": "Credenciales incorrectas"}), 401


@auth_view_bp.route('/users', methods=['POST'])
def register_view():
    data = request.get_json()

    # Validación de entrada
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Nombre de usuario y contraseña son requeridos"}), 400

    username = data['username']
    password = data['password']

    # Generar el hash de la contraseña
    password_hash = generate_password_hash(password)

    # Verificar si el usuario ya existe
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "El nombre de usuario ya está en uso"}), 409

    try:
        # Crear el nuevo usuario
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            "message": "Usuario creado exitosamente",
            "user": {
                "username": new_user.username
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Error en el servidor: {str(e)}"}), 500
    

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

@auth_view_bp.route("/users", methods=["GET", "POST"])
@jwt_required()
def user():
    additional_data = get_jwt()
    administrador = additional_data.get("administrador", False)

    # Endpoint POST para crear usuario
    if request.method == "POST":
        if administrador:
            data = request.get_json()
            username = data.get("nombre_usuario")
            password = data.get("password")

            # Verificar si el usuario ya existe
            si_existe_usuario = User.query.filter_by(username=username).first()
            if si_existe_usuario:
                return jsonify({"Error": "El nombre de usuario ya existe."}), 400

            # Crear hash de la contraseña y agregar el usuario
            password_hasheada = generate_password_hash(password, method="pbkdf2", salt_length=8)
            nuevo_usuario = User(username=username, password_hash=password_hasheada)
            db.session.add(nuevo_usuario)
            db.session.commit()

            return jsonify({"Usuario Creado": username}), 201
        return jsonify({"Mensaje": "UD no está habilitado para crear un usuario."}), 403

    # Endpoint GET para listar usuarios
    usuarios = User.query.all()
    user_schema = UserSchema(many=True) if administrador else UserMinimalSchema(many=True)
    result = user_schema.dump(usuarios)
    print("Datos enviados al frontend:", result)  # Imprime los datos enviados al frontend

    return jsonify(result)


@auth_view_bp.route("/users/<int:id>", methods=["PUT"])
@jwt_required()
def update_user(id):
    additional_data = get_jwt()
    administrador = additional_data.get("administrador", False)

    if administrador:
        data = request.get_json()
        usuario = User.query.get_or_404(id)

        # Actualizar el nombre de usuario 
        if "nombre_usuario" in data:
            usuario.username = data["nombre_usuario"]
        try:
            db.session.commit()
            return jsonify({"Mensaje": "Usuario actualizado correctamente."}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"Error": "Ocurrió un error al actualizar el usuario.", "detalle": str(e)}), 500

    return jsonify({"Mensaje": "UD no está habilitado para actualizar un usuario."}), 403


@auth_view_bp.route("/users/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_user(id):
    additional_data = get_jwt()
    administrador = additional_data.get("administrador", False)

    if administrador:
        usuario = User.query.get_or_404(id)
        try:
            db.session.delete(usuario)
            db.session.commit()
            return jsonify({"Mensaje": "Usuario eliminado correctamente."}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"Error": "Ocurrió un error al eliminar el usuario.", "detalle": str(e)}), 500

    return jsonify({"Mensaje": "UD no está habilitado para eliminar un usuario."}), 403


