from flask import Flask, request, jsonify
import os
import random
import subprocess

app = Flask(__name__)

def generate_new_port(exclude_ports):
    while True:
        port = random.randint(1000, 9999)
        if port not in exclude_ports:
            return port

def update_squid_config(ip, old_port):
    new_port = generate_new_port([7777, old_port])
    ip_underscored = ip.replace('.', '_')
    
    with open('/etc/squid/squid.conf', 'r') as file:
        lines = file.readlines()

    # Новые строки конфигурации
    new_http_port = f"http_port {ip}:{new_port}\n"
    new_acl_ip = f"acl ip_{ip_underscored} myip {ip}\n"
    new_acl_port = f"acl port_{new_port} localport {new_port}\n"
    new_http_access_allow = f"http_access allow ip_{ip_underscored} port_{new_port}\n"
    new_http_access_deny = f"http_access deny ip_{ip_underscored} !port_{new_port}\n"

    # Удаление всех строк, связанных с конкретным IP и старым портом
    new_lines = []
    for line in lines:
        if (f"http_port {ip}:{old_port}" in line or
            f"http_access allow ip_{ip_underscored} port_{old_port}" in line or
            f"http_access deny ip_{ip_underscored} !port_{old_port}" in line):
            continue
        new_lines.append(line)

    # Вставка новых строк конфигурации в нужные места
    http_port_inserted = False
    acl_ip_inserted = False
    acl_port_inserted = False
    http_access_allow_inserted = False
    http_access_deny_inserted = False

    final_lines = []
    for line in new_lines:
        final_lines.append(line)
        if not http_port_inserted and line.startswith("http_port"):
            final_lines.append(new_http_port)
            http_port_inserted = True
        elif not acl_ip_inserted and line.startswith("acl ip_"):
            final_lines.append(new_acl_ip)
            acl_ip_inserted = True
        elif not acl_port_inserted and line.startswith("acl port_"):
            final_lines.append(new_acl_port)
            acl_port_inserted = True
        elif not http_access_allow_inserted and line.startswith("http_access allow"):
            final_lines.append(new_http_access_allow)
            http_access_allow_inserted = True
        elif not http_access_deny_inserted and line.startswith("# Deny specific IP on other ports"):
            final_lines.append(new_http_access_deny)
            http_access_deny_inserted = True

    # Если какие-то строки не были вставлены
    if not http_port_inserted:
        final_lines.append(new_http_port)
    if not acl_ip_inserted:
        final_lines.append(new_acl_ip)
    if not acl_port_inserted:
        final_lines.append(new_acl_port)
    if not http_access_allow_inserted:
        final_lines.append(new_http_access_allow)
    if not http_access_deny_inserted:
        final_lines.append(new_http_access_deny)

    # Запись в файл конфигурации с использованием sudo
    new_config = ''.join(final_lines)
    process = subprocess.Popen(['sudo', 'tee', '/etc/squid/squid.conf'], stdin=subprocess.PIPE)
    process.communicate(input=new_config.encode())

    # Проверка конфигурации Squid перед перезапуском
    result = subprocess.run(['sudo', 'squid', '-k', 'parse'], capture_output=True, text=True)
    if result.returncode != 0:
        return f"Squid configuration error: {result.stderr}"

    os.system('sudo systemctl restart squid')
    return new_port

@app.route('/update_port', methods=['POST'])
def update_port():
    data = request.json
    ip = data['ip']
    old_port = data['port']
    new_port = update_squid_config(ip, old_port)
    if isinstance(new_port, str) and new_port.startswith("Squid configuration error"):
        return jsonify({'status': 'error', 'message': new_port}), 400
    return jsonify({'status': 'success', 'new_port': new_port})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
