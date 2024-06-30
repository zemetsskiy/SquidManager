from flask import Blueprint, request, jsonify
from app.services.squid import update_proxies_credentials

update_credentials_bp = Blueprint('update_credentials', __name__)

@update_credentials_bp.route('/', methods=['POST'], strict_slashes=False)
def update_credentials():
    try:
        data = request.json
        proxies = data['proxies']
        username = data['username']
        password = data['password']
        
        update_proxies_credentials(proxies, username, password)
        
        return jsonify({'status': 'success', 'message': 'Credentials updated successfully'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
