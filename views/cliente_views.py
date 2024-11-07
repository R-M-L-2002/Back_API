from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from services.cliente_service import ClienteService

# Define un Blueprint para la gestión de clientes
cliente_bp = Blueprint("cliente", __name__)
cliente_service = ClienteService()


@cliente_bp.route("/clientes")
def listar_clientes():
    """Muestra una lista de todos los clientes."""
    clientes = cliente_service.listar_clientes()
    return render_template("clientes.html", clientes=clientes)


@cliente_bp.route("/cliente/nuevo", methods=["GET", "POST"])
def nuevo_cliente():
    """Crea un nuevo cliente. Solo accesible para administradores."""
    # Verifica que el usuario tenga permisos de administrador
    if not session.get("is_admin"):
        return redirect(url_for("cliente.listar_clientes"))

    # Procesa el formulario de creación de cliente
    if request.method == "POST":
        nombre = request.form.get("nombre")
        if not nombre:
            flash("El nombre es requerido", "error")
        else:
            cliente_service.crear_cliente(nombre)
            flash("Cliente creado con éxito", "success")
            return redirect(url_for("cliente.listar_clientes"))
    return render_template("cliente_form.html")


@cliente_bp.route("/cliente/editar/<int:id>", methods=["GET", "POST"])
def editar_cliente(id):
    """Edita un cliente existente. Solo accesible para administradores."""
    if not session.get("is_admin"):
        return redirect(url_for("cliente.listar_clientes"))

    # Obtiene el cliente a editar a partir del ID
    cliente = cliente_service.repository.get_by_id(id)
    if request.method == "POST":
        nombre = request.form.get("nombre")
        if not nombre:
            flash("El nombre es requerido", "error")
        else:
            cliente_service.editar_cliente(id, nombre)
            flash("Cliente actualizado con éxito", "success")
            return redirect(url_for("cliente.listar_clientes"))
    return render_template("cliente_form.html", cliente=cliente)


@cliente_bp.route("/cliente/borrar/<int:id>", methods=["POST"])
def borrar_cliente(id):
    """Elimina un cliente. Solo accesible para administradores."""
    if not session.get("is_admin"):
        return redirect(url_for("cliente.listar_clientes"))

    cliente_service.eliminar_cliente(id)
    flash("Cliente eliminado con éxito", "success")
    return redirect(url_for("cliente.listar_clientes"))
