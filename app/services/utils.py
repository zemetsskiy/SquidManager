import subprocess
import re
import shlex
import random

from collections import defaultdict

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
        "requests_per_second": sum(data["request_count_by_ip"].values()) / 3600,  # 1 час
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
