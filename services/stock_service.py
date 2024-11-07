from repositories.stock_repository import StockRepository
from models import Stock


class StockService:
    def __init__(self):
        self.repository = StockRepository()

    def listar_stocks(self):
        return self.repository.get_all()

    def crear_stock(self, cantidad, ubicacion, equipo_id):
        nuevo_stock = Stock(cantidad=cantidad, ubicacion=ubicacion, equipo_id=equipo_id)
        self.repository.add(nuevo_stock)

    def editar_stock(self, stock_id, cantidad, ubicacion, equipo_id):
        stock = self.repository.get_by_id(stock_id)
        if stock:
            stock.cantidad = cantidad
            stock.ubicacion = ubicacion
            stock.equipo_id = equipo_id
            self.repository.update()

    def eliminar_stock(self, stock_id):
        stock = self.repository.get_by_id(stock_id)
        if stock:
            self.repository.delete(stock)
