from models import Marca
from app import db


class MarcaRepository:
    def get_all(self):
        return Marca.query.all()

    def get_by_id(self, marca_id):
        return Marca.query.get(marca_id)

    def add(self, marca):
        db.session.add(marca)
        db.session.commit()

    def update(self, marca):
        db.session.commit()

    def delete(self, marca):
        db.session.delete(marca)
        db.session.commit()
