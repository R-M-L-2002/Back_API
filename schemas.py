from app import ma
from models import (
    Marca,
    Fabricante,
    Modelo,
    Categoria,
    Caracteristica,
    Stock,
    Proveedor,
    Accesorio,
    Equipo,
    Cliente,
    User,
)


class MarcaSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Marca

    id = ma.auto_field()
    nombre = ma.auto_field(required=True)


class FabricanteSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Fabricante

    id = ma.auto_field()
    nombre = ma.auto_field(required=True)
    pais_origen = ma.auto_field(required=True)


class ModeloSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Modelo

    id = ma.auto_field()
    nombre = ma.auto_field(required=True)
    fabricante_id = ma.auto_field(required=True)


class CategoriaSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Categoria

    id = ma.auto_field()
    nombre = ma.auto_field(required=True)


class CaracteristicaSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Caracteristica

    class Meta:
        model = Categoria

    id = ma.auto_field()
    nombre = ma.auto_field(required=True)


class CaracteristicaSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Caracteristica

    id = ma.auto_field()
    tipo = ma.auto_field(required=True)
    descripcion = ma.auto_field(required=True)
    modelo_id = ma.auto_field(required=True)


class StockSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Stock

    id = ma.auto_field()
    cantidad = ma.auto_field(required=True)
    ubicacion = ma.auto_field(required=True)
    equipo_id = ma.auto_field(required=True)
    disponible = ma.auto_field()


class ProveedorSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Proveedor

    id = ma.auto_field()
    nombre = ma.auto_field(required=True)
    contacto = ma.auto_field(required=True)


class AccesorioSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Accesorio

    id = ma.auto_field()
    tipo = ma.auto_field(required=True)
    modelo_id = ma.auto_field(required=True)


class EquipoSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Equipo

    id = ma.auto_field()
    nombre = ma.auto_field(required=True)
    precio = ma.auto_field(required=True)
    categoria_id = ma.auto_field(required=True)
    marca_id = ma.auto_field(required=True)
    modelo_id = ma.auto_field(required=True)
    caracteristica_id = ma.auto_field(required=True)
    accesorio_id = ma.auto_field(required=False)


class ClienteSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Cliente

    id = ma.auto_field()
    nombre = ma.auto_field(required=True)


class UserSchema(ma.SQLAlchemySchema):
    class Meta:
        model = User

    id = ma.auto_field()
    username = ma.auto_field()
    password_hash = ma.auto_field()
    is_admin = ma.auto_field()


class UserMinimalSchema(ma.SQLAlchemySchema):
    class Meta:
        model = User

    username = ma.auto_field()
