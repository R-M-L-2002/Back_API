from views.marca_view import marca_bp
from views.fabricante_view import fabricante_bp
from views.auth_view import auth_view_bp
from views.categoria_view import categoria_bp
from views.caracteristica_view import caracteristica_bp
from views.stock_view import stock_bp
from views.proveedor_view import proveedor_bp
from views.accesorio_view import accesorio_bp
from views.equipo_view import equipo_bp
from views.modelo_view import modelo_bp
from views.cliente_views import cliente_bp
from views.user_view import user_bp


def register_blueprints(app):
    app.register_blueprint(marca_bp)
    app.register_blueprint(fabricante_bp)
    app.register_blueprint(auth_view_bp)
    app.register_blueprint(categoria_bp)
    app.register_blueprint(caracteristica_bp)
    app.register_blueprint(stock_bp)
    app.register_blueprint(proveedor_bp)
    app.register_blueprint(accesorio_bp)
    app.register_blueprint(equipo_bp)
    app.register_blueprint(modelo_bp)
    app.register_blueprint(cliente_bp)
    app.register_blueprint(user_bp)
