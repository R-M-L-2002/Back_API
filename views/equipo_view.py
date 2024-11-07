from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from services.equipo_service import EquipoService
from models import Categoria, Marca, Modelo, Caracteristica, Accesorio

equipo_bp = Blueprint("equipo", __name__)
equipo_service = EquipoService()


@equipo_bp.route("/equipos")
def listar_equipos():
    """Lista todos los equipos."""
    equipos = equipo_service.listar_equipos()
    return render_template("equipos.html", equipos=equipos)


@equipo_bp.route("/equipo/nuevo", methods=["GET", "POST"])
def crear_equipo():
    """Crea un nuevo equipo."""
    if not session.get("is_admin"):
        return redirect(url_for("equipo.listar_equipos"))

    categorias = Categoria.query.all()
    marcas = Marca.query.all()
    modelos = Modelo.query.all()
    caracteristicas = Caracteristica.query.all()
    accesorios = Accesorio.query.all()

    if request.method == "POST":
        nombre = request.form.get("nombre")
        precio = request.form.get("precio")
        categoria_id = request.form.get("categoria_id")
        marca_id = request.form.get("marca_id")
        modelo_id = request.form.get("modelo_id")
        caracteristica_id = request.form.get("caracteristica_id")
        accesorio_id = request.form.get("accesorio_id")

        if (
            not nombre
            or not precio
            or not categoria_id
            or not marca_id
            or not modelo_id
            or not caracteristica_id
            or not accesorio_id
        ):
            flash("Todos los campos son requeridos", "error")
        else:
            equipo_service.crear_equipo(
                nombre,
                precio,
                categoria_id,
                marca_id,
                modelo_id,
                caracteristica_id,
                accesorio_id,
            )
            flash("Equipo creado con éxito", "success")
            return redirect(url_for("equipo.listar_equipos"))

    return render_template(
        "equipo_form.html",
        categorias=categorias,
        marcas=marcas,
        modelos=modelos,
        caracteristicas=caracteristicas,
        accesorios=accesorios,
    )


@equipo_bp.route("/equipo/editar/<int:id>", methods=["GET", "POST"])
def editar_equipo(id):
    """Edita un equipo existente."""
    if not session.get("is_admin"):
        return redirect(url_for("equipo.listar_equipos"))

    equipo = equipo_service.repository.get_by_id(id)
    categorias = Categoria.query.all()
    marcas = Marca.query.all()
    modelos = Modelo.query.all()
    caracteristicas = Caracteristica.query.all()
    accesorios = Accesorio.query.all()

    if request.method == "POST":
        nombre = request.form.get("nombre")
        precio = request.form.get("precio")
        categoria_id = request.form.get("categoria_id")
        marca_id = request.form.get("marca_id")
        modelo_id = request.form.get("modelo_id")
        caracteristica_id = request.form.get("caracteristica_id")
        accesorio_id = request.form.get("accesorio_id")

        if (
            not nombre
            or not precio
            or not categoria_id
            or not marca_id
            or not modelo_id
            or not caracteristica_id
            or not accesorio_id
        ):
            flash("Todos los campos son requeridos", "error")
        else:
            equipo_service.editar_equipo(
                id,
                nombre,
                precio,
                categoria_id,
                marca_id,
                modelo_id,
                caracteristica_id,
                accesorio_id,
            )
            flash("Equipo actualizado con éxito", "success")
            return redirect(url_for("equipo.listar_equipos"))

    return render_template(
        "equipo_form.html",
        equipo=equipo,
        categorias=categorias,
        marcas=marcas,
        modelos=modelos,
        caracteristicas=caracteristicas,
        accesorios=accesorios,
    )


@equipo_bp.route("/equipo/borrar/<int:id>", methods=["POST"])
def borrar_equipo(id):
    """Elimina un equipo."""
    if not session.get("is_admin"):
        return redirect(url_for("equipo.listar_equipos"))

    equipo_service.eliminar_equipo(id)
    flash("Equipo eliminado con éxito", "success")
    return redirect(url_for("equipo.listar_equipos"))
