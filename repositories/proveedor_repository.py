from models import Proveedor
from app import db


class ProveedorRepository:
    def get_all(self):
        return Proveedor.query.all()

    def get_by_id(self, proveedor_id):
        return Proveedor.query.get(proveedor_id)

    def add(self, proveedor):
        db.session.add(proveedor)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self, proveedor):
        db.session.delete(proveedor)
        db.session.commit()
