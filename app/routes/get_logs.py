from flask import Blueprint, request, jsonify
import subprocess

logs_bp = Blueprint('logs', __name__)

@logs_bp.route('/get_logs', methods=['GET'])
def get_logs():
    try:
        num_logs = request.args.get('num_logs', default=10, type=int)
        command = f"sudo tail -n {num_logs} /var/log/squid/access.log"
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)

        logs = result.stdout.splitlines()
        return jsonify({'status': 'success', 'logs': logs})

    except subprocess.CalledProcessError as e:
        error_message = f"Error running tail command: {e.stderr}"
        return jsonify({'status': 'error', 'message': error_message}), 500

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
