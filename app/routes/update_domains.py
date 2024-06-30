from flask import Flask, Blueprint, request, jsonify
from app.services.squid import update_blocked_domains

update_domains_bp = Blueprint('update_domains', __name__)

@update_domains_bp.route('/add', methods=['POST'])
def add_domain():
    try:
        data = request.json
        domain = data.get('domain')

        if not domain:
            raise ValueError('Missing required parameter: domain')

        success, error_message = update_blocked_domains('add',domain)

        if success:
            return jsonify({'status': 'success', 'message': f'Added domain {domain} to blocked list'}), 200
        else:
            raise RuntimeError(f'Failed to add domain {domain}: {error_message}')

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@update_domains_bp.route('/delete', methods=['POST'])
def delete_domain():
    try:
        data = request.json
        domain = data.get('domain')

        if not domain:
            raise ValueError('Missing required parameter: domain')

        success, error_message = update_blocked_domains('delete',domain)

        if success:
            return jsonify({'status': 'success', 'message': f'Deleted domain {domain} from blocked list'}), 200
        else:
            raise RuntimeError(f'Failed to delete domain {domain}: {error_message}')

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
