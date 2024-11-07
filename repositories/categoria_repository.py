from models import Categoria
from app import db


class CategoriaRepository:
    def get_all(self):
        return Categoria.query.all()

    def get_by_id(self, categoria_id):
        return Categoria.query.get(categoria_id)

    def add(self, categoria):
        db.session.add(categoria)
        db.session.commit()

    def update(self, categoria):
        db.session.commit()

    def delete(self, categoria):
        db.session.delete(categoria)
        db.session.commit()
