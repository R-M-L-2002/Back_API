from repositories.fabricante_repository import FabricanteRepository
from models import Fabricante


class FabricanteService:
    def __init__(self):
        self.repository = FabricanteRepository()

    def listar_fabricantes(self):
        return self.repository.get_all()

    def crear_fabricante(self, nombre, pais_origen):
        nuevo_fabricante = Fabricante(nombre=nombre, pais_origen=pais_origen)
        self.repository.add(nuevo_fabricante)

    def editar_fabricante(self, fabricante_id, nombre, pais_origen):
        fabricante = self.repository.get_by_id(fabricante_id)
        if fabricante:
            fabricante.nombre = nombre
            fabricante.pais_origen = pais_origen
            self.repository.update(fabricante)

    def eliminar_fabricante(self, fabricante_id):
        fabricante = self.repository.get_by_id(fabricante_id)
        if fabricante:
            self.repository.delete(fabricante)
