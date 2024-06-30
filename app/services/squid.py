import re
import os
import subprocess
import crypt
import random
import shlex
from collections import defaultdict
from app.services.utils import generate_new_port

def update_squid_password(username: str, password: str) -> None:
    """Обновление пароля пользователя в файле паролей Squid."""
    try:
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
        
        process = subprocess.Popen(['sudo', 'tee', '/etc/squid/passwd'], stdin=subprocess.PIPE)
        process.communicate(input=''.join(new_lines).encode())

    except Exception as e:
        raise RuntimeError(f"Error updating password: {str(e)}")

def update_squid_port(ip, old_port, username: str):
    try:
        new_port = generate_new_port([7777, int(old_port)])
        ip_underscored = ip.replace('.', '_')

        with open('/etc/squid/squid.conf', 'r') as file:
            lines = file.readlines()

        new_http_port = f"http_port {ip}:{new_port}\n"
        new_acl_ip = f"acl ip_{ip_underscored}_{new_port} myip {ip}\n"
        new_acl_port = f"acl port_{new_port} localport {new_port}\n"
        new_http_access_allow = f"http_access allow {username}_users ip_{ip_underscored}_{new_port} port_{new_port}\n"
        new_http_access_deny = f"http_access deny ip_{ip_underscored}_{new_port} !port_{new_port}\n"
        new_outgoing_address = f"tcp_outgoing_address {ip} ip_{ip_underscored}_{new_port}\n"

        new_lines = []
        regex_pattern = rf"http_access allow \S+_users ip_{ip_underscored}_{old_port} port_{old_port}"
        for line in lines:
            if (f"http_port {ip}:{old_port}" in line or
                f"http_access allow {username}_users ip_{ip_underscored}_{old_port}" in line or
                f"http_access deny ip_{ip_underscored}_{old_port}" in line or
                f"acl ip_{ip_underscored}_{old_port} myip {ip}" in line or
                f"tcp_outgoing_address {ip} ip_{ip_underscored}_{old_port}" in line or
                re.search(regex_pattern, line)):
                continue
            new_lines.append(line)

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
        return jsonify({'status': 'success', 'new_port': new_port})

    except Exception as e:
        raise RuntimeError(f"Error updating port: {str(e)}")

def update_squid_acl(proxies: list, username: str) -> None:
    try:
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

    except Exception as e:
        raise RuntimeError(f"{str(e)}")

def update_proxies_credentials(proxies: list, username: str, password: str) -> None:
    try:
        update_squid_password(username, password)
        update_squid_acl(proxies, username)
    except Exception as e:
        raise RuntimeError(f"Error updating credentials: {str(e)}")

def update_blocked_domains(action, domain):
    try:
        if action == 'add':
            cmd = f"echo '{domain}' | sudo tee -a /etc/squid/blocked_domains.txt > /dev/null"
            subprocess.run(cmd, shell=True, check=True)
        elif action == 'delete':
            cmd = f"sudo sed -i '/^{domain}$/d' /etc/squid/blocked_domains.txt"
            subprocess.run(cmd, shell=True, check=True)

        subprocess.run(['sudo', 'squid', '-k', 'reconfigure'], check=True)

        return True, None

    except Exception as e:
        error_message = str(e)
        return False, error_message
