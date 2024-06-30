from flask import Blueprint, jsonify
from app.services.utils import generate_statistics

statistics_bp = Blueprint('statistics', __name__)

@statistics_bp.route('/', methods=['GET'])
def get_statistics():
    log_file = '/var/log/squid/access.log'
    try:
        stats = generate_statistics(log_file)
        if stats is None:
            return jsonify({'status': 'error', 'message': 'Permission denied to access log file'}), 403
        return jsonify({'status': 'success', 'data': stats})
    
    except RuntimeError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
