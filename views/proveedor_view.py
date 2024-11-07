from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from services.proveedor_service import ProveedorService

proveedor_bp = Blueprint("proveedor", __name__)
proveedor_service = ProveedorService()


@proveedor_bp.route("/proveedores")
def listar_proveedores():
    """Listar todos los proveedores."""
    proveedores = proveedor_service.listar_proveedores()
    return render_template("proveedores.html", proveedores=proveedores)


@proveedor_bp.route("/proveedor/nuevo", methods=["GET", "POST"])
def nuevo_proveedor():
    """Agregar un nuevo proveedor."""
    if not session.get("is_admin"):
        return redirect(url_for("proveedor.listar_proveedores"))

    if request.method == "POST":
        nombre = request.form.get("nombre")
        contacto = request.form.get("contacto")
        if not nombre or not contacto:
            flash("Todos los campos son requeridos", "error")
        else:
            proveedor_service.crear_proveedor(nombre, contacto)
            flash("Proveedor creado con éxito", "success")
            return redirect(url_for("proveedor.listar_proveedores"))
    return render_template("proveedor_form.html")


@proveedor_bp.route("/proveedor/editar/<int:id>", methods=["GET", "POST"])
def editar_proveedor(id):
    """Editar Proveedor."""
    if not session.get("is_admin"):
        return redirect(url_for("proveedor.listar_proveedores"))

    proveedor = proveedor_service.repository.get_by_id(id)
    if request.method == "POST":
        nombre = request.form.get("nombre")
        contacto = request.form.get("contacto")
        if not nombre or not contacto:
            flash("Todos los campos son requeridos", "error")
        else:
            proveedor_service.editar_proveedor(id, nombre, contacto)
            flash("Proveedor actualizado con éxito", "success")
            return redirect(url_for("proveedor.listar_proveedores"))
    return render_template("proveedor_form.html", proveedor=proveedor)


@proveedor_bp.route("/proveedor/borrar/<int:id>", methods=["POST"])
def borrar_proveedor(id):
    """Borrar Proveedor."""
    if not session.get("is_admin"):
        return redirect(url_for("proveedor.listar_proveedores"))

    proveedor_service.eliminar_proveedor(id)
    flash("Proveedor eliminado con éxito", "success")
    return redirect(url_for("proveedor.listar_proveedores"))
