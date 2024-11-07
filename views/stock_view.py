from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from services.stock_service import StockService
from models import Equipo

stock_bp = Blueprint("stock", __name__)
stock_service = StockService()


@stock_bp.route("/stocks")
def listar_stocks():
    """Lista todos los stocks."""
    stocks = stock_service.listar_stocks()
    return render_template("stocks.html", stocks=stocks)


@stock_bp.route("/stock/nuevo", methods=["GET", "POST"])
def nuevo_stock():
    """Crea un nuevo stock."""
    if not session.get("is_admin"):
        return redirect(url_for("stock.listar_stocks"))

    equipos = Equipo.query.all()
    if request.method == "POST":
        cantidad = request.form.get("cantidad")
        ubicacion = request.form.get("ubicacion")
        equipo_id = request.form.get("equipo_id")
        if not cantidad or not ubicacion or not equipo_id:
            flash("Todos los campos son requeridos", "error")
        else:
            stock_service.crear_stock(cantidad, ubicacion, equipo_id)
            flash("Stock creado con éxito", "success")
            return redirect(url_for("stock.listar_stocks"))

    return render_template("stock_form.html", equipos=equipos)


@stock_bp.route("/stock/editar/<int:id>", methods=["GET", "POST"])
def editar_stock(id):
    """Edita un stock existente."""
    if not session.get("is_admin"):
        return redirect(url_for("stock.listar_stocks"))

    stock = stock_service.repository.get_by_id(id)
    equipos = Equipo.query.all()
    if request.method == "POST":
        cantidad = request.form.get("cantidad")
        ubicacion = request.form.get("ubicacion")
        equipo_id = request.form.get("equipo_id")
        if not cantidad or not ubicacion or not equipo_id:
            flash("Todos los campos son requeridos", "error")
        else:
            stock_service.editar_stock(id, cantidad, ubicacion, equipo_id)
            flash("Stock actualizado con éxito", "success")
            return redirect(url_for("stock.listar_stocks"))

    return render_template("stock_form.html", stock=stock, equipos=equipos)


@stock_bp.route("/stock/borrar/<int:id>", methods=["POST"])
def borrar_stock(id):
    """Elimina un stock."""
    if not session.get("is_admin"):
        return redirect(url_for("stock.listar_stocks"))

    stock_service.eliminar_stock(id)
    flash("Stock eliminado con éxito", "success")
    return redirect(url_for("stock.listar_stocks"))
