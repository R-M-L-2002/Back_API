from models import Stock
from app import db


class StockRepository:
    def get_all(self):
        return Stock.query.all()

    def get_by_id(self, stock_id):
        return Stock.query.get(stock_id)

    def add(self, stock):
        db.session.add(stock)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self, stock):
        db.session.delete(stock)
        db.session.commit()
