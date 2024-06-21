from flask import Flask, request, jsonify
import os
import crypt
import subprocess
import random
import re

app = Flask(__name__)

def generate_new_port(exclude_ports):
    while True:
        port = random.randint(1000, 9999)
        if port not in exclude_ports:
            return port

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

    # Удаление всех строк, связанных с конкретным IP и старым портом
    new_lines = []
    for line in lines:
        if (f"http_port {ip}:{old_port}" in line or
            f"http_access allow Arni_users ip_{ip_underscored}_{old_port}" in line or
            f"http_access deny ip_{ip_underscored}_{old_port}" in line or
	    f"acl ip_{ip_underscored}_{old_port} myip {ip}" in line):
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

    # Запись в файл конфигурации с использованием sudo
    new_config = ''.join(final_lines)
    process = subprocess.Popen(['sudo', 'tee', '/etc/squid/squid.conf'], stdin=subprocess.PIPE)
    process.communicate(input=new_config.encode())

    os.system('sudo systemctl restart squid')
    return new_port

def update_squid_acl(proxies: list, username: str) -> None:
    """Добавление правил ACL в конфигурацию Squid для сопоставления прокси и логинов."""
    with open('/etc/squid/squid.conf', 'r') as file:
        lines = file.readlines()

    # Удаление всех строк, связанных с предыдущими пользователями для указанных прокси
    new_lines = []
    for line in lines:
        # Удаление строк вида 'http_access allow Arni_users ip_194_87_134_2_4032 port_4032' с использованием регулярных выражений
        if any(re.search(rf"http_access allow \S+ ip_{proxy.split(':')[0].replace('.', '_')}_{proxy.split(':')[1]} port_{proxy.split(':')[1]}", line) for proxy in proxies):
            continue
        new_lines.append(line)

    # Новые строки ACL для каждого прокси
    final_lines = []
    inserted_acl_user = False
    inserted_http_access_allow = False
    inserted_http_access_deny = False

    for line in new_lines:
        final_lines.append(line)
        
        # Вставка строки acl {username}_users proxy_auth {username} после acl Arni_users proxy_auth Arni
        if not inserted_acl_user and line.strip() == "acl Arni_users proxy_auth Arni":
            final_lines.append(f"acl {username}_users proxy_auth {username}\n")
            inserted_acl_user = True
        
        # Вставка строк http_access allow {username}_users ip_{ip_underscored}_{port} port_{port} после # Allow specific IP on specific ports with specific users
        if not inserted_http_access_allow and line.strip() == "# Allow specific IP on specific ports with specific users":
            for proxy in proxies:
                ip, port = proxy.split(':')
                ip_underscored = ip.replace('.', '_')
                final_lines.append(f"http_access allow {username}_users ip_{ip_underscored}_{port} port_{port}\n")
            inserted_http_access_allow = True
        
        # Вставка строк http_access deny {username}_users !port_{port} после http_access deny ip_{ip.replace('.', '_')}_{port} !port_{port}
        if not inserted_http_access_deny and any(line.strip() == f"http_access deny ip_{proxy.split(':')[0].replace('.', '_')}_{proxy.split(':')[1]} !port_{proxy.split(':')[1]}" for proxy in proxies):
            for proxy in proxies:
                ip, port = proxy.split(':')
                ip_underscored = ip.replace('.', '_')
                final_lines.append(f"http_access deny {username}_users !port_{port}\n")
            inserted_http_access_deny = True

    # Запись в файл конфигурации с использованием sudo
    new_config = ''.join(final_lines)
    process = subprocess.Popen(['sudo', 'tee', '/etc/squid/squid.conf'], stdin=subprocess.PIPE)
    process.communicate(input=new_config.encode())

    os.system('sudo systemctl restart squid')


def update_proxies_credentials(proxies: list, username: str, password: str) -> None:
    """Обновление конфигурации и паролей для массива прокси."""
    update_squid_password(username, password)
    update_squid_acl(proxies, username)

@app.route('/update_port', methods=['POST'])
def update_port():
    data = request.json
    ip = data['ip']
    old_port = data['port']
    new_port = update_squid_port(ip, old_port)
    return jsonify({'status': 'success', 'new_port': new_port})


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
