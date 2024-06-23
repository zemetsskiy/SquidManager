from flask import Flask, request, jsonify
import os
import crypt
import subprocess
import random
import re
import shlex
from collections import defaultdict
from datetime import datetime

app = Flask(__name__)

def generate_new_port(exclude_ports):
    while True:
        port = random.randint(1000, 9999)
        if port not in exclude_ports:
            return port

def parse_squid_logs(log_file):
    traffic_by_ip_port = defaultdict(int)
    request_count_by_ip = defaultdict(int)
    response_times_by_ip = defaultdict(list)
    status_codes = defaultdict(int)
    domains = defaultdict(int)
    request_types = defaultdict(int)

    try:
        cmd = f"sudo cat {shlex.quote(log_file)}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        result.check_returncode()
        log_data = result.stdout.splitlines()
        
        for line in log_data:
            parts = re.split(r'\s+', line)
            if len(parts) < 10:
                continue

            timestamp = float(parts[0])
            response_time = int(parts[1])
            client_ip = parts[2]
            status_code = parts[3].split('/')[1]
            data_size = int(parts[4])
            method = parts[5]
            domain = parts[6].split(':')[0]
            user = parts[7]
            target_ip = parts[8]

            ip_port = f"{client_ip}:{parts[6].split(':')[1]}"

            traffic_by_ip_port[ip_port] += data_size
            request_count_by_ip[client_ip] += 1
            response_times_by_ip[client_ip].append(response_time)
            status_codes[status_code] += 1
            domains[domain] += 1
            request_types[method] += 1

    except subprocess.CalledProcessError as e:
        print(f"Permission error: {e}")
        return None

    return {
        "traffic_by_ip_port": traffic_by_ip_port,
        "request_count_by_ip": request_count_by_ip,
        "response_times_by_ip": response_times_by_ip,
        "status_codes": status_codes,
        "domains": domains,
        "request_types": request_types
    }

def generate_statistics(log_file):
    data = parse_squid_logs(log_file)
    if data is None:
        return None
    
    statistics = {
        "bandwidth_usage": sum(data["traffic_by_ip_port"].values()) / (1024 * 1024 * 1024),  # GB
        "total_requests": sum(data["request_count_by_ip"].values()),
        "average_concurrency": sum(len(times) for times in data["response_times_by_ip"].values()) / len(data["response_times_by_ip"]),
        "requests_per_second": sum(data["request_count_by_ip"].values()) / 3600,  #  1 час
        "bandwidth_per_request": sum(data["traffic_by_ip_port"].values()) / sum(data["request_count_by_ip"].values()) / 1024,  # KB
        "request_stats": {
            "http": data["request_types"].get("CONNECT", 0),
            "socks": data["request_types"].get("GET", 0) + data["request_types"].get("POST", 0)
        },
        "request_type": data["request_types"],
        "status_codes": data["status_codes"],
        "domains": data["domains"]
    }
    
    return statistics

@app.route('/statistics', methods=['GET'])
def get_statistics():
    log_file = '/var/log/squid/access.log'
    stats = generate_statistics(log_file)
    if stats is None:
        return jsonify({'status': 'error', 'message': 'Permission denied to access log file'}), 403
    return jsonify({'status': 'success', 'data': stats})


def update_squid_password(username: str, password: str) -> None:
    """Обновление пароля пользователя в файле паролей Squid."""
    hashed_password = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
    with open('/etc/squid/passwd', 'r') as file:
        lines = file.readlines()
    
    updated = False
    new_lines = []
    for line in lines:
        if line.startswith(username + ":"):
            new_lines.append(f"{username}:{hashed_password}\n")
            updated = True
        else:
            new_lines.append(line)
    
    if not updated:
        new_lines.append(f"{username}:{hashed_password}\n")
    
    # Запись в файл паролей с использованием sudo
    process = subprocess.Popen(['sudo', 'tee', '/etc/squid/passwd'], stdin=subprocess.PIPE)
    process.communicate(input=''.join(new_lines).encode())

def update_squid_port(ip, old_port):
    new_port = generate_new_port([7777, old_port])
    ip_underscored = ip.replace('.', '_')
    
    with open('/etc/squid/squid.conf', 'r') as file:
        lines = file.readlines()

    # Новые строки конфигурации
    new_http_port = f"http_port {ip}:{new_port}\n"
    new_acl_ip = f"acl ip_{ip_underscored}_{new_port} myip {ip}\n"
    new_acl_port = f"acl port_{new_port} localport {new_port}\n"
    new_http_access_allow = f"http_access allow Arni_users ip_{ip_underscored}_{new_port} port_{new_port}\n"
    new_http_access_deny = f"http_access deny ip_{ip_underscored}_{new_port} !port_{new_port}\n"
    new_outgoing_address = f"tcp_outgoing_address {ip} ip_{ip_underscored}_{new_port}\n"
 
   # Удаление всех строк, связанных с конкретным IP и старым портом
    new_lines = []
    for line in lines:
        if (f"http_port {ip}:{old_port}" in line or
            f"http_access allow Arni_users ip_{ip_underscored}_{old_port}" in line or
            f"http_access deny ip_{ip_underscored}_{old_port}" in line or
	    f"acl ip_{ip_underscored}_{old_port} myip {ip}" in line or
	    f"tcp_outgoing_address {ip} ip_{ip_underscored}_{old_port}" in line):
            continue
        new_lines.append(line)

    # Вставка новых строк конфигурации в нужные места
    http_port_inserted = False
    acl_ip_inserted = False
    acl_port_inserted = False
    http_access_allow_inserted = False
    http_access_deny_inserted = False
    outgoing_address_inserted = False

    final_lines = []
    for line in new_lines:
        final_lines.append(line)
        if not http_port_inserted and line.strip() == "# Port configuration":
            final_lines.append(new_http_port)
            http_port_inserted = True
        elif not acl_ip_inserted and line.strip() == "acl Arni_users proxy_auth Arni":
            final_lines.append(new_acl_ip)
            acl_ip_inserted = True
        elif not acl_port_inserted and line.strip().startswith("acl ip_") and "myip" in line:
            final_lines.append(new_acl_port)
            acl_port_inserted = True
        elif not http_access_allow_inserted and line.strip() == "# Allow specific IP on specific ports with specific users":
            final_lines.append(new_http_access_allow)
            http_access_allow_inserted = True
        elif not http_access_deny_inserted and line.strip() == "# Deny specific IP on other ports":
            final_lines.append(new_http_access_deny)
            http_access_deny_inserted = True
        elif not outgoing_address_inserted and line.strip() == "# Outgoing address configuration":
            final_lines.append(new_outgoing_address)
            outgoing_address_inserted = True

    new_config = ''.join(final_lines)
    process = subprocess.Popen(['sudo', 'tee', '/etc/squid/squid.conf'], stdin=subprocess.PIPE)
    process.communicate(input=new_config.encode())

    os.system('sudo squid -k reconfigure')
    return new_port

def update_squid_acl(proxies: list, username: str) -> None:
    """Добавление правил ACL в конфигурацию Squid для сопоставления прокси и логинов."""
    with open('/etc/squid/squid.conf', 'r') as file:
        lines = file.readlines()

    new_lines = []
    for line in lines:
        if any(re.search(rf"http_access allow \S+_users ip_{proxy.split(':')[0].replace('.', '_')}_{proxy.split(':')[1]} port_{proxy.split(':')[1]}", line) or
               re.search(rf"http_access deny \S+_users !port_{proxy.split(':')[1]}", line) for proxy in proxies):
            continue
        new_lines.append(line)

    final_lines = []
    inserted_acl_user = False
    inserted_http_access_allow = False
    inserted_http_access_deny = False

    for line in new_lines:
        final_lines.append(line)
        
        if not inserted_acl_user and line.strip() == "acl Arni_users proxy_auth Arni":
            final_lines.append(f"acl {username}_users proxy_auth {username}\n")
            inserted_acl_user = True
        
        if not inserted_http_access_allow and line.strip() == "# Allow specific IP on specific ports with specific users":
            for proxy in proxies:
                ip, port = proxy.split(':')
                ip_underscored = ip.replace('.', '_')
                final_lines.append(f"http_access allow {username}_users ip_{ip_underscored}_{port} port_{port}\n")
            inserted_http_access_allow = True
        
        if not inserted_http_access_deny and any(line.strip() == f"http_access deny ip_{proxy.split(':')[0].replace('.', '_')}_{proxy.split(':')[1]} !port_{proxy.split(':')[1]}" for proxy in proxies):
            for proxy in proxies:
                ip, port = proxy.split(':')
                ip_underscored = ip.replace('.', '_')
                final_lines.append(f"http_access deny {username}_users !port_{port}\n")
            inserted_http_access_deny = True

    new_config = ''.join(final_lines)
    process = subprocess.Popen(['sudo', 'tee', '/etc/squid/squid.conf'], stdin=subprocess.PIPE)
    process.communicate(input=new_config.encode())

    os.system('sudo squid -k reconfigure')

@app.route('/update_port', methods=['POST'])
def update_port():
    data = request.json
    ip = data['ip']
    old_port = data['port']
    new_port = update_squid_port(ip, old_port)
    return jsonify({'status': 'success', 'new_port': new_port})

def update_proxies_credentials(proxies: list, username: str, password: str) -> None:
    """Обновление учетных данных для прокси."""
    update_squid_password(username, password)
    update_squid_acl(proxies, username)

@app.route('/update_credentials', methods=['POST'])
def update_credentials():
    """Маршрут для обновления логина и пароля для массива прокси."""
    data = request.json
    proxies = data['proxies']
    username = data['username']
    password = data['password']
    
    update_proxies_credentials(proxies, username, password)
    
    return jsonify({'status': 'success', 'message': 'Credentials updated successfully'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
