from repositories.categoria_repository import CategoriaRepository
from models import Categoria


class CategoriaService:
    def __init__(self):
        self.repository = CategoriaRepository()

    def listar_categorias(self):
        return self.repository.get_all()

    def crear_categoria(self, nombre):
        nueva_categoria = Categoria(nombre=nombre)
        self.repository.add(nueva_categoria)

    def editar_categoria(self, categoria_id, nombre):
        categoria = self.repository.get_by_id(categoria_id)
        if categoria:
            categoria.nombre = nombre
            self.repository.update(categoria)

    def eliminar_categoria(self, categoria_id):
        categoria = self.repository.get_by_id(categoria_id)
        if categoria:
            self.repository.delete(categoria)
