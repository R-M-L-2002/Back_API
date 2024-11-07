from models import Modelo
from app import db


class ModeloRepository:
    def get_all(self):
        return Modelo.query.all()

    def get_by_id(self, modelo_id):
        return Modelo.query.get(modelo_id)

    def add(self, modelo):
        db.session.add(modelo)
        db.session.commit()

    def update(self, modelo):
        db.session.commit()

    def delete(self, modelo):
        db.session.delete(modelo)
        db.session.commit()
