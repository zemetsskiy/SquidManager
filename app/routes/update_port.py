from flask import Blueprint, request, jsonify
from app.services.squid import update_squid_port

update_port_bp = Blueprint('update_port', __name__)

@update_port_bp.route('/', methods=['POST'], strict_slashes=False)
def update_port():
    data = request.json
    ip = data['ip']
    old_port = data['port']
    username = data['username']
    new_port = update_squid_port(ip, old_port, username)
    return jsonify({'status': 'success', 'new_port': new_port})
