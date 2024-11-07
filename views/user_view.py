from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from models import User
from werkzeug.security import generate_password_hash
from app import db

user_bp = Blueprint("user_bp", __name__)


@user_bp.route("/usuarios", methods=["GET"])
def lista_usuarios():
    # Solo los administradores pueden acceder
    if not session.get("is_admin"):
        return redirect(url_for("auth_view.login_view"))

    usuarios = User.query.all()
    return render_template("usuarios.html", usuarios=usuarios)


@user_bp.route("/admin", methods=["GET", "POST"])
def admin_view():
    # Solo administradores pueden acceder
    if not session.get("is_admin"):
        return redirect(url_for("auth_view.login_view"))

    if request.method == "POST":
        # Crear nuevo usuario
        username = request.form["username"]
        password = request.form["password"]
        hashed_password = generate_password_hash(password)

        new_user = User(
            username=username, password_hash=hashed_password, is_admin=False
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Usuario creado con éxito.")

    usuarios = User.query.all()  # Obtener todos los usuarios
    return render_template("admin.html", usuarios=usuarios)


@user_bp.route("/delete_user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if not session.get("is_admin"):
        flash("No tienes permisos para eliminar usuarios.")
        return redirect(url_for("user_bp.admin_view"))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash("Usuario eliminado con éxito.")
    return redirect(url_for("user_bp.admin_view"))
