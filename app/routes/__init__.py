from flask import Blueprint

def register_routes(app):
    from .update_credentials import update_credentials_bp
    from .update_port import update_port_bp
    from .statistics import statistics_bp    
    from .update_domains import update_domains_bp
    from .get_logs import logs_bp
    
    app.register_blueprint(update_credentials_bp, url_prefix='/update_credentials')
    app.register_blueprint(update_port_bp, url_prefix='/update_port')
    app.register_blueprint(statistics_bp, url_prefix='/statistics')
    app.register_blueprint(update_domains_bp, url_prefix='/update_domains')
    app.register_blueprint(logs_bp, url_prefix='/logs')
     
