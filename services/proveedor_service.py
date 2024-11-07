from repositories.proveedor_repository import ProveedorRepository
from models import Proveedor


class ProveedorService:
    def __init__(self):
        self.repository = ProveedorRepository()

    def listar_proveedores(self):
        return self.repository.get_all()

    def crear_proveedor(self, nombre, contacto):
        nuevo_proveedor = Proveedor(nombre=nombre, contacto=contacto)
        self.repository.add(nuevo_proveedor)

    def editar_proveedor(self, proveedor_id, nombre, contacto):
        proveedor = self.repository.get_by_id(proveedor_id)
        if proveedor:
            proveedor.nombre = nombre
            proveedor.contacto = contacto
            self.repository.update()

    def eliminar_proveedor(self, proveedor_id):
        proveedor = self.repository.get_by_id(proveedor_id)
        if proveedor:
            self.repository.delete(proveedor)
