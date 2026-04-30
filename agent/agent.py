import psutil
import requests
import time
import socket
import os
import sys
import datetime

# --- CONFIGURACIÓN DE ALTA PRECISIÓN ---
INTERVAL = 2 
CONFIG_FILE = "config.txt"
DEFAULT_IP = "localhost"

if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "r") as f:
        SERVER_IP = f.read().strip()
else:
    with open(CONFIG_FILE, "w") as f:
        f.write(DEFAULT_IP)
    SERVER_IP = DEFAULT_IP

SERVER_URL = f"http://{SERVER_IP}:8000/metrics"

# Inicialización
last_net_io = psutil.net_io_counters()
last_time = time.time()
CPU_CORES = psutil.cpu_count() or 1 # Obtener número de núcleos

def get_top_processes():
    processes = []
    # Filtros para procesos que no queremos ver (Inactividad, Interrupciones, etc.)
    IGNORE_LIST = ["System Idle Process", "Idle", "Registry", "Interrupts"]
    
    for proc in psutil.process_iter(['name', 'cpu_percent', 'memory_percent']):
        try:
            p_name = proc.info['name']
            if p_name in IGNORE_LIST:
                continue
                
            # Normalizar CPU por número de núcleos para que el tope sea 100%
            cpu_norm = proc.info['cpu_percent'] / CPU_CORES
            
            processes.append({
                "name": p_name,
                "cpu": cpu_norm,
                "ram": proc.info['memory_percent']
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
    # Ordenar por impacto real (CPU normalizado)
    top = sorted(processes, key=lambda x: x['cpu'], reverse=True)[:5]
    return [{"name": p['name'], "cpu": round(p['cpu'], 2), "ram": round(p['ram'], 2)} for p in top]

def get_network_speed():
    global last_net_io, last_time
    current_net_io = psutil.net_io_counters()
    current_time = time.time()
    elapsed = current_time - last_time
    if elapsed <= 0: elapsed = 1
    
    sent = (current_net_io.bytes_sent - last_net_io.bytes_sent) / elapsed
    recv = (current_net_io.bytes_recv - last_net_io.bytes_recv) / elapsed
    
    last_net_io = current_net_io
    last_time = current_time
    return {"sent_kb": round(sent / 1024, 2), "recv_kb": round(recv / 1024, 2)}

def get_metrics():
    try:
        # psutil.cpu_percent con interval=1 es lo más preciso para el total
        cpu_total = psutil.cpu_percent(interval=1)
        ram = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
        uptime = str(datetime.datetime.now() - boot_time).split('.')[0]
        
        return {
            "hostname": socket.gethostname(),
            "cpu_usage": round(cpu_total, 2),
            "ram_usage": round(ram.percent, 2),
            "disk_usage": round(disk.percent, 2),
            "uptime": uptime,
            "network": get_network_speed(),
            "processes": get_top_processes(),
            "timestamp": time.time()
        }
    except Exception as e:
        print(f"Error: {e}"); return None

def execute_command(cmd):
    if cmd == "shutdown": os.system("shutdown /s /t 60")
    elif cmd == "restart": os.system("shutdown /r /t 60")
    elif cmd == "msg": os.system('msg * "SENTINEL: Revisa tu equipo"')

def main():
    print(f"--- Sentinel Agent v6 (Normalized) en {socket.gethostname()} ---")
    
    while True:
        metrics = get_metrics()
        if metrics:
            try:
                response = requests.post(SERVER_URL, json=metrics, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    for cmd in data.get("commands", []):
                        execute_command(cmd)
            except Exception: pass
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
