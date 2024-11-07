from models import Equipo
from app import db


class EquipoRepository:
    def get_all(self):
        return Equipo.query.all()

    def get_by_id(self, equipo_id):
        return Equipo.query.get(equipo_id)

    def add(self, equipo):
        db.session.add(equipo)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self, equipo):
        db.session.delete(equipo)
        db.session.commit()
