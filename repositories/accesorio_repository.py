from models import Accesorio
from app import db


class AccesorioRepository:
    def get_all(self):
        return Accesorio.query.all()

    def get_by_id(self, accesorio_id):
        return Accesorio.query.get(accesorio_id)

    def add(self, accesorio):
        db.session.add(accesorio)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self, accesorio):
        db.session.delete(accesorio)
        db.session.commit()
