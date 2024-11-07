from repositories.cliente_repository import ClienteRepository
from models import Cliente


class ClienteService:
    def __init__(self):
        self.repository = ClienteRepository()

    def listar_clientes(self):
        return self.repository.get_all()

    def crear_cliente(self, nombre):
        nuevo_cliente = Cliente(nombre=nombre)
        self.repository.add(nuevo_cliente)

    def editar_cliente(self, cliente_id, nombre):
        cliente = self.repository.get_by_id(cliente_id)
        if cliente:
            cliente.nombre = nombre
            self.repository.update()

    def eliminar_cliente(self, cliente_id):
        cliente = self.repository.get_by_id(cliente_id)
        if cliente:
            self.repository.delete(cliente)
