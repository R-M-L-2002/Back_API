from repositories.caracteristica_repository import CaracteristicaRepository
from models import Caracteristica


class CaracteristicaService:
    def __init__(self):
        self.repository = CaracteristicaRepository()

    def listar_caracteristicas(self):
        return self.repository.get_all()

    def crear_caracteristica(self, tipo, descripcion, modelo_id):
        nueva_caracteristica = Caracteristica(
            tipo=tipo, descripcion=descripcion, modelo_id=modelo_id
        )
        self.repository.add(nueva_caracteristica)

    def editar_caracteristica(self, caracteristica_id, tipo, descripcion, modelo_id):
        caracteristica = self.repository.get_by_id(caracteristica_id)
        if caracteristica:
            caracteristica.tipo = tipo
            caracteristica.descripcion = descripcion
            caracteristica.modelo_id = modelo_id
            self.repository.update()

    def eliminar_caracteristica(self, caracteristica_id):
        caracteristica = self.repository.get_by_id(caracteristica_id)
        if caracteristica:
            self.repository.delete(caracteristica)
