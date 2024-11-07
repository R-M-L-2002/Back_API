from repositories.equipo_repository import EquipoRepository
from models import Equipo


class EquipoService:
    def __init__(self):
        self.repository = EquipoRepository()

    def listar_equipos(self):
        return self.repository.get_all()

    def crear_equipo(
        self,
        nombre,
        precio,
        categoria_id,
        marca_id,
        modelo_id,
        caracteristica_id,
        accesorio_id,
    ):
        nuevo_equipo = Equipo(
            nombre=nombre,
            precio=precio,
            categoria_id=categoria_id,
            marca_id=marca_id,
            modelo_id=modelo_id,
            caracteristica_id=caracteristica_id,
            accesorio_id=accesorio_id,
        )
        self.repository.add(nuevo_equipo)

    def editar_equipo(
        self,
        equipo_id,
        nombre,
        precio,
        categoria_id,
        marca_id,
        modelo_id,
        caracteristica_id,
        accesorio_id,
    ):
        equipo = self.repository.get_by_id(equipo_id)
        if equipo:
            equipo.nombre = nombre
            equipo.precio = precio
            equipo.categoria_id = categoria_id
            equipo.marca_id = marca_id
            equipo.modelo_id = modelo_id
            equipo.caracteristica_id = caracteristica_id
            equipo.accesorio_id = accesorio_id
            self.repository.update()

    def eliminar_equipo(self, equipo_id):
        equipo = self.repository.get_by_id(equipo_id)
        if equipo:
            self.repository.delete(equipo)
