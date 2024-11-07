from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from services.accesorio_service import AccesorioService
from models import Modelo

# Define un Blueprint para las rutas relacionadas con accesorios
accesorio_bp = Blueprint("accesorio", __name__)
accesorio_service = AccesorioService()  # Instancia del servicio de accesorios


@accesorio_bp.route("/accesorios")
def listar_accesorios():
    """Lista todos los accesorios."""
    accesorios = accesorio_service.listar_accesorios()
    return render_template("accesorios.html", accesorios=accesorios)


@accesorio_bp.route("/accesorio/nuevo", methods=["GET", "POST"])
def nuevo_accesorio():
    """Crea un nuevo accesorio. Solo accesible para usuarios administradores."""
    if not session.get("is_admin"):
        return redirect(url_for("accesorio.listar_accesorios"))

    modelos = Modelo.query.all()  # Obtiene todos los modelos disponibles
    if request.method == "POST":
        tipo = request.form.get("tipo")
        modelo_id = request.form.get("modelo_id")
        if not tipo or not modelo_id:
            flash("Todos los campos son requeridos", "error")
        else:
            accesorio_service.crear_accesorio(tipo, modelo_id)
            flash("Accesorio creado con éxito", "success")
            return redirect(url_for("accesorio.listar_accesorios"))
    return render_template("accesorio_form.html", modelos=modelos)


@accesorio_bp.route("/accesorio/editar/<int:id>", methods=["GET", "POST"])
def editar_accesorio(id):
    """Edita un accesorio existente. Solo accesible para usuarios administradores."""
    if not session.get("is_admin"):
        return redirect(url_for("accesorio.listar_accesorios"))

    accesorio = accesorio_service.repository.get_by_id(
        id
    )  # Obtiene el accesorio por ID
    modelos = Modelo.query.all()  # Obtiene todos los modelos disponibles
    if request.method == "POST":
        tipo = request.form.get("tipo")
        modelo_id = request.form.get("modelo_id")
        if not tipo or not modelo_id:
            flash("Todos los campos son requeridos", "error")
        else:
            accesorio_service.editar_accesorio(id, tipo, modelo_id)
            flash("Accesorio actualizado con éxito", "success")
            return redirect(url_for("accesorio.listar_accesorios"))
    return render_template("accesorio_form.html", accesorio=accesorio, modelos=modelos)


@accesorio_bp.route("/accesorio/borrar/<int:id>", methods=["POST"])
def borrar_accesorio(id):
    """Elimina un accesorio. Solo accesible para usuarios administradores."""
    if not session.get("is_admin"):
        return redirect(url_for("accesorio.listar_accesorios"))

    accesorio_service.eliminar_accesorio(id)  # Elimina el accesorio por ID
    flash("Accesorio eliminado con éxito", "success")
    return redirect(url_for("accesorio.listar_accesorios"))
