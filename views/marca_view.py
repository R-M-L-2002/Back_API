from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, make_response
from app import db
from schemas import MarcaSchema, MarcaMinimalSchema
from flask_jwt_extended import get_jwt, jwt_required
from models import Marca
marca_bp = Blueprint("marca", __name__)



# Ruta para obtener todas las marcas (GET), agregar una nueva marca (POST)
@marca_bp.route("/marca", methods=["GET", "POST"])
@jwt_required()  # Requiere autenticación mediante un token JWT
def marcas():
    additional_data = get_jwt()
    administrador = additional_data.get("administrador", True)

    # Crear una nueva marca en la base de datos
    if request.method == "POST":
        if administrador:  # Solo los administradores pueden crear una marca
            data = request.get_json()
            nueva_marca = Marca(
                nombre=data.get("nombre")
            )

            db.session.add(nueva_marca)
            db.session.commit()
            return make_response(MarcaSchema().dump(nueva_marca), 201)
        return jsonify({"Mensaje": "Ud no está habilitado para crear una marca."}), 403

    # Consulta todos los registros de la tabla Marca
    marcas = Marca.query.all()
    # Si el usuario es administrador, devuelve todos los detalles de cada marca
    if administrador:
        return MarcaSchema().dump(marcas, many=True)
    # Si no es administrador, usa el esquema mínimo con menos detalles
    else:
        return MarcaMinimalSchema().dump(marcas, many=True)

# Ruta para actualizar o eliminar una marca específica (PUT, DELETE)
@marca_bp.route("/marca/<int:id>", methods=["PUT", "DELETE"])
@jwt_required()  # Requiere autenticación mediante un token JWT
def actualizar_marca(id):
    additional_data = get_jwt()
    administrador = additional_data.get("administrador", True)

    if not administrador:  # Solo los administradores pueden modificar o eliminar marcas
        return jsonify({"Mensaje": "Usted no está habilitado para modificar o eliminar esta marca."}), 403

    # Obtener la marca por su ID
    marca = Marca.query.get(id)
    if not marca:
        return jsonify({"Mensaje": "Marca no encontrada"}), 404

    # Si el método es DELETE, eliminar la marca permanentemente
    if request.method == "DELETE":
        db.session.delete(marca)
        db.session.commit()
        return jsonify({"Mensaje": "Marca eliminada permanentemente"}), 200

    # Si el método es PUT, actualizar los campos de la marca
    if request.method == "PUT":
        data = request.get_json()
        marca.nombre = data.get("nombre", marca.nombre)  # Si no se pasa un nuevo nombre, se mantiene el actual

        db.session.commit()
        return make_response(MarcaSchema().dump(marca), 200)
