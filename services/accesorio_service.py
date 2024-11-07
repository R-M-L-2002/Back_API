from repositories.accesorio_repository import AccesorioRepository
from models import Accesorio


class AccesorioService:
    def __init__(self):
        self.repository = AccesorioRepository()

    def listar_accesorios(self):
        return self.repository.get_all()

    def crear_accesorio(self, tipo, modelo_id):
        nuevo_accesorio = Accesorio(tipo=tipo, modelo_id=modelo_id)
        self.repository.add(nuevo_accesorio)

    def editar_accesorio(self, accesorio_id, tipo, modelo_id):
        accesorio = self.repository.get_by_id(accesorio_id)
        if accesorio:
            accesorio.tipo = tipo
            accesorio.modelo_id = modelo_id
            self.repository.update()

    def eliminar_accesorio(self, accesorio_id):
        accesorio = self.repository.get_by_id(accesorio_id)
        if accesorio:
            self.repository.delete(accesorio)
