from models import Caracteristica
from app import db


class CaracteristicaRepository:
    def get_all(self):
        return Caracteristica.query.all()

    def get_by_id(self, caracteristica_id):
        return Caracteristica.query.get(caracteristica_id)

    def add(self, caracteristica):
        db.session.add(caracteristica)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self, caracteristica):
        db.session.delete(caracteristica)
        db.session.commit()
