from db import db
from werkzeug.security import generate_password_hash, check_password_hash


class Marca(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)

    equipos = db.relationship("Equipo", backref="marca", lazy=True)

    def __str__(self) -> str:
        return self.nombre


class Fabricante(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    pais_origen = db.Column(db.String(100), nullable=False)

    modelos = db.relationship("Modelo", backref="fabricante", lazy=True)

    def __str__(self) -> str:
        return self.nombre


class Modelo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    fabricante_id = db.Column(
        db.Integer, db.ForeignKey("fabricante.id"), nullable=False
    )

    equipos = db.relationship("Equipo", backref="modelo", lazy=True)
    caracteristicas = db.relationship("Caracteristica", backref="modelo", lazy=True)
    accesorios = db.relationship("Accesorio", backref="modelo", lazy=True)

    def __str__(self) -> str:
        return self.nombre


class Categoria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)

    equipos = db.relationship("Equipo", backref="categoria", lazy=True)

    def __str__(self) -> str:
        return self.nombre


class Caracteristica(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.String(200), nullable=False)
    modelo_id = db.Column(db.Integer, db.ForeignKey("modelo.id"), nullable=False)

    equipos = db.relationship("Equipo", backref="caracteristica", lazy=True)

    def __str__(self) -> str:
        return self.tipo


class Stock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cantidad = db.Column(db.Integer, nullable=False)
    ubicacion = db.Column(db.String(100), nullable=False)
    equipo_id = db.Column(db.Integer, db.ForeignKey("equipo.id"), nullable=False)
    disponible = db.Column(db.Boolean, default=True)

    equipo = db.relationship("Equipo", back_populates="stocks")

    def __str__(self) -> str:
        return str(self.id)


class Proveedor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    contacto = db.Column(db.String(100), nullable=False)

    def __str__(self) -> str:
        return self.nombre


class Accesorio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(100), nullable=False)
    modelo_id = db.Column(db.Integer, db.ForeignKey("modelo.id"), nullable=False)

    equipos = db.relationship("Equipo", backref="accesorio", lazy=True)

    def __str__(self) -> str:
        return self.tipo


class Equipo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    precio = db.Column(db.Float, nullable=False)
    categoria_id = db.Column(db.Integer, db.ForeignKey("categoria.id"), nullable=False)
    marca_id = db.Column(db.Integer, db.ForeignKey("marca.id"), nullable=False)
    modelo_id = db.Column(db.Integer, db.ForeignKey("modelo.id"), nullable=False)
    caracteristica_id = db.Column(
        db.Integer, db.ForeignKey("caracteristica.id"), nullable=False
    )
    accesorio_id = db.Column(db.Integer, db.ForeignKey("accesorio.id"), nullable=True)

    stocks = db.relationship("Stock", back_populates="equipo")

    def __str__(self) -> str:
        return str(self.id)


class Cliente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)

    def __str__(self) -> str:
        return self.nombre


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return dict(username=self.username, password=self.password_hash)
