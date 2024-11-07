from repositories.marca_repository import MarcaRepository
from models import Marca


class MarcaService:
    def __init__(self):
        self.repository = MarcaRepository()

    def listar_marcas(self):
        return self.repository.get_all()

    def crear_marca(self, nombre):
        nueva_marca = Marca(nombre=nombre)
        self.repository.add(nueva_marca)

    def editar_marca(self, marca_id, nombre):
        marca = self.repository.get_by_id(marca_id)
        if marca:
            marca.nombre = nombre
            self.repository.update(marca)

    def eliminar_marca(self, marca_id):
        marca = self.repository.get_by_id(marca_id)
        if marca:
            self.repository.delete(marca)
