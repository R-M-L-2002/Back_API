from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from services.modelo_service import ModeloService
from models import Fabricante

modelo_bp = Blueprint("modelo", __name__)
modelo_service = ModeloService()


@modelo_bp.route("/modelos")
def listar_modelos():
    """Lista todos los modelos."""
    modelos = modelo_service.listar_modelos()
    return render_template("listar_modelos.html", modelos=modelos)


@modelo_bp.route("/modelo/crear", methods=["GET", "POST"])
def crear_modelo():
    """Crea un nuevo modelo."""
    if not session.get("is_admin"):
        return redirect(url_for("modelo.listar_modelos"))

    fabricantes = Fabricante.query.all()
    if request.method == "POST":
        nombre = request.form.get("nombre")
        fabricante_id = request.form.get("fabricante_id")
        if not nombre or not fabricante_id:
            flash("Todos los campos son requeridos", "error")
        else:
            modelo_service.crear_modelo(nombre, fabricante_id)
            flash("Modelo creado con éxito", "success")
            return redirect(url_for("modelo.listar_modelos"))

    return render_template("crear_modelo.html", fabricantes=fabricantes)


@modelo_bp.route("/modelo/editar/<int:id>", methods=["GET", "POST"])
def editar_modelo(id):
    """Edita un modelo existente."""
    if not session.get("is_admin"):
        return redirect(url_for("modelo.listar_modelos"))

    modelo = modelo_service.repository.get_by_id(id)
    if modelo is None:
        flash("Modelo no encontrado", "error")
        return redirect(url_for("modelo.listar_modelos"))

    fabricantes = Fabricante.query.all()
    if request.method == "POST":
        nombre = request.form.get("nombre")
        fabricante_id = request.form.get("fabricante_id")
        if not nombre or not fabricante_id:
            flash("Todos los campos son requeridos", "error")
        else:
            modelo_service.editar_modelo(id, nombre, fabricante_id)
            flash("Modelo actualizado con éxito", "success")
            return redirect(url_for("modelo.listar_modelos"))

    return render_template("editar_modelo.html", modelo=modelo, fabricantes=fabricantes)


@modelo_bp.route("/modelo/eliminar/<int:id>", methods=["POST"])
def eliminar_modelo(id):
    """Elimina un modelo."""
    if not session.get("is_admin"):
        return redirect(url_for("modelo.listar_modelos"))

    modelo_service.eliminar_modelo(id)
    flash("Modelo eliminado con éxito", "success")
    return redirect(url_for("modelo.listar_modelos"))
