from repositories.modelo_repository import ModeloRepository
from models import Modelo


class ModeloService:
    def __init__(self):
        self.repository = ModeloRepository()

    def listar_modelos(self):
        return self.repository.get_all()

    def crear_modelo(self, nombre, fabricante_id):
        nuevo_modelo = Modelo(nombre=nombre, fabricante_id=fabricante_id)
        self.repository.add(nuevo_modelo)

    def editar_modelo(self, modelo_id, nombre, fabricante_id):
        modelo = self.repository.get_by_id(modelo_id)
        if modelo:
            modelo.nombre = nombre
            modelo.fabricante_id = fabricante_id
            self.repository.update(modelo)

    def eliminar_modelo(self, modelo_id):
        modelo = self.repository.get_by_id(modelo_id)
        if modelo:
            self.repository.delete(modelo)
