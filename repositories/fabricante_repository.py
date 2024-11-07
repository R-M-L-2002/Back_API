from models import Fabricante
from app import db


class FabricanteRepository:
    def get_all(self):
        return Fabricante.query.all()

    def get_by_id(self, fabricante_id):
        return Fabricante.query.get(fabricante_id)

    def add(self, fabricante):
        db.session.add(fabricante)
        db.session.commit()

    def update(self, fabricante):
        db.session.commit()

    def delete(self, fabricante):
        db.session.delete(fabricante)
        db.session.commit()
