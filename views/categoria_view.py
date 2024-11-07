from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from services.categoria_service import CategoriaService

# Definición del Blueprint para la gestión de categorías
categoria_bp = Blueprint("categoria", __name__)
categoria_service = CategoriaService()


@categoria_bp.route("/categorias")
def listar_categorias():
    """Muestra una lista de todas las categorías."""
    categorias = categoria_service.listar_categorias()
    return render_template("categorias.html", categorias=categorias)


@categoria_bp.route("/categoria/nueva", methods=["GET", "POST"])
def nueva_categoria():
    """Crea una nueva categoría. Solo accesible para administradores."""
    if not session.get("is_admin"):
        return redirect(url_for("categoria.listar_categorias"))

    if request.method == "POST":
        nombre = request.form.get("nombre")
        if not nombre:
            flash("El nombre es requerido", "error")
        else:
            categoria_service.crear_categoria(nombre)
            flash("Categoría creada con éxito", "success")
            return redirect(url_for("categoria.listar_categorias"))
    return render_template("categoria_form.html")


@categoria_bp.route("/categoria/editar/<int:id>", methods=["GET", "POST"])
def editar_categoria(id):
    """Edita una categoría existente. Solo accesible para administradores."""
    if not session.get("is_admin"):
        return redirect(url_for("categoria.listar_categorias"))

    categorias = categoria_service.listar_categorias()
    categoria = next((c for c in categorias if c.id == id), None)

    if categoria is None:
        flash("Categoría no encontrada", "error")
        return redirect(url_for("categoria.listar_categorias"))

    if request.method == "POST":
        nombre = request.form.get("nombre")
        if not nombre:
            flash("El nombre es requerido", "error")
        else:
            categoria_service.editar_categoria(id, nombre)
            flash("Categoría actualizada con éxito", "success")
            return redirect(url_for("categoria.listar_categorias"))

    return render_template("categoria_form.html", categoria=categoria)


@categoria_bp.route("/categoria/borrar/<int:id>", methods=["POST"])
def borrar_categoria(id):
    """Elimina una categoría. Solo accesible para administradores."""
    if not session.get("is_admin"):
        return redirect(url_for("categoria.listar_categorias"))

    categoria_service.eliminar_categoria(id)
    flash("Categoría eliminada con éxito", "success")
    return redirect(url_for("categoria.listar_categorias"))
