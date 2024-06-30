from flask import Blueprint, request, jsonify
from app.services.squid import update_squid_port

update_port_bp = Blueprint('update_port', __name__)

@update_port_bp.route('/', methods=['POST'], strict_slashes=False)
def update_port():
    data = request.json
    ip_ports = data['ip_ports']
    
    updated_ports = []
    for ip_port in ip_ports:
        ip, old_port, username = ip_port.split(':')
        new_port = update_squid_port(ip, old_port, username)
        updated_ports.append(f"{ip}:{new_port}")
    
    return jsonify({'status': 'success', 'updated_ports': updated_ports}) 
