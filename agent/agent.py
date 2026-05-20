import psutil
import requests
import time
import socket
import os
import datetime
import subprocess
import platform
import ctypes
import sys
import threading

try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
except:
    pass

# --- CONFIGURACIÓN ---
INTERVAL = 5 
DEFAULT_IP = "localhost"

if getattr(sys, 'frozen', False):
    exe_dir = os.path.dirname(sys.executable)
else:
    exe_dir = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(exe_dir, "config.txt")

if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "r") as f:
        config_val = f.read().strip()
else:
    config_val = DEFAULT_IP

# Detectar inteligentemente si config.txt tiene una URL completa (para producción en Render) o local
if config_val.startswith("http://") or config_val.startswith("https://"):
    if config_val.endswith("/"):
        config_val = config_val[:-1]
    SERVER_URL = config_val if config_val.endswith("/metrics") else f"{config_val}/metrics"
else:
    SERVER_URL = f"http://{config_val}:8000/metrics"

import urllib.parse
try:
    parsed_url = urllib.parse.urlparse(SERVER_URL)
    server_hostname = parsed_url.hostname or "127.0.0.1"
    SERVER_IP = socket.gethostbyname(server_hostname)
except Exception:
    SERVER_IP = "127.0.0.1"

CPU_CORES = psutil.cpu_count() or 1

def run_cmd(cmd):
    try: 
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        if res.returncode != 0:
            print(f"[ERROR] ejecutando comando: {res.stderr.strip()}")
        return res.stdout.strip()
    except subprocess.TimeoutExpired:
        print(f"[ERROR] Comando expiro por limite de tiempo (10s): {cmd}")
        return ""
    except Exception as e: 
        print(f"[EXCEPCION]: {e}")
        return ""

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_single_instance():
    mutex_name = "Local\\SentinelAgentMutex_Unique_12345"
    kernel32 = ctypes.windll.kernel32
    mutex = kernel32.CreateMutexW(None, True, mutex_name)
    last_error = kernel32.GetLastError()
    if last_error == 183:  # ERROR_ALREADY_EXISTS
        print("[-] Otra instancia del agente ya está en ejecución. Saliendo...")
        sys.exit(0)
    return mutex

KNOWN_USBS = set()
LAST_NET_IO = None
try:
    for p in psutil.disk_partitions(all=False):
        if 'cdrom' not in p.opts and p.device and len(p.device) >= 2 and p.device[1] == ':':
            drive = p.device[0].upper() + ":"
            KNOWN_USBS.add(drive)
except: pass

CURRENT_QUARANTINE = False

def mostrar_mensaje_cuarentena():
    try:
        ctypes.windll.user32.MessageBoxW(
            0,
            "ATENCIÓN:\n\nEste equipo ha sido aislado temporalmente de la red por el sistema de seguridad Sentinel debido a una amenaza crítica detectada.\n\nPor favor, contacte con soporte si el problema persiste.",
            "Sentinel EDR - Alerta de Seguridad",
            0x10 | 0x0
        )
    except:
        pass

def handle_quarantine(enable):
    global CURRENT_QUARANTINE
    if enable == CURRENT_QUARANTINE: return
    
    if enable:
        print("🚨 INICIANDO CUARENTENA DE RED...")
        
        # Mostrar alerta visual en un hilo separado de forma asíncrona
        threading.Thread(target=mostrar_mensaje_cuarentena, daemon=True).start()
        
        import socket
        import urllib.parse
        try:
            parsed_url = urllib.parse.urlparse(SERVER_URL)
            server_hostname = parsed_url.hostname or "127.0.0.1"
            current_server_ip = socket.gethostbyname(server_hostname)
        except Exception:
            current_server_ip = SERVER_IP
            
        # 1. Asegurar que el Firewall esté habilitado y bloquear todo por defecto (Entrante y Saliente)
        run_cmd('powershell -Command "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -OutboundConnections Block -InboundConnections Block"')
        
        # 2. Crear reglas temporales de Permitir para el Servidor y DNS (para seguir comunicando con la consola)
        run_cmd(f'powershell -Command "New-NetFirewallRule -DisplayName \'SentinelAllowServer\' -Direction Outbound -RemoteAddress {current_server_ip} -Action Allow"')
        run_cmd(f'powershell -Command "New-NetFirewallRule -DisplayName \'SentinelAllowServerIn\' -Direction Inbound -RemoteAddress {current_server_ip} -Action Allow"')
        run_cmd('powershell -Command "New-NetFirewallRule -DisplayName \'SentinelAllowDNS\' -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow"')
        run_cmd('powershell -Command "New-NetFirewallRule -DisplayName \'SentinelAllowDNSTCP\' -Direction Outbound -Protocol TCP -RemotePort 53 -Action Allow"')
    else:
        print("✅ LEVANTANDO CUARENTENA...")
        # 1. Restaurar comportamiento por defecto (Permitir conexiones salientes e inbound por defecto)
        run_cmd('powershell -Command "Set-NetFirewallProfile -Profile Domain,Private,Public -OutboundConnections Allow -InboundConnections NotConfigured"')
        
        # 2. Limpiar reglas temporales
        run_cmd('powershell -Command "Remove-NetFirewallRule -DisplayName \'SentinelAllowServer\'; Remove-NetFirewallRule -DisplayName \'SentinelAllowServerIn\'; Remove-NetFirewallRule -DisplayName \'SentinelAllowDNS\'; Remove-NetFirewallRule -DisplayName \'SentinelAllowDNSTCP\'"')
    
    CURRENT_QUARANTINE = enable

def check_advanced_threats(conns_list, upload_speed, download_speed):
    new_alerts = []
    
    # 1. Threat Intel (Suspicious Ports)
    suspicious_ports = {'4444', '666', '1337', '3389', '6666'}
    for c in conns_list:
        try:
            port = c.split(':')[-1]
            if port in suspicious_ports:
                new_alerts.append({"level": "CRITICAL", "desc": f"CONEXIÓN SOSPECHOSA a puerto de riesgo {c}"})
        except: pass
            
    # 2. Heurística (Powershell ofuscado)
    try:
        for p in psutil.process_iter(['name', 'cmdline']):
            if p.info['name'] in ['powershell.exe', 'cmd.exe'] and p.info['cmdline']:
                cmd = ' '.join(p.info['cmdline']).lower()
                if any(x in cmd for x in ['-enc', '-encodedcommand', 'bypass', 'hidden']):
                    new_alerts.append({"level": "CRITICAL", "desc": "COMANDO MALICIOSO DETECTADO: PowerShell ofuscado/oculto"})
    except: pass
    
    # 3. Anti Brute-Force (Event ID 4625)
    try:
        failed_logins = run_cmd('wevtutil qe Security /q:"*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 600000]]]" /c:5 /f:text')
        if failed_logins and "Event ID: 4625" in failed_logins:
            new_alerts.append({"level": "CRITICAL", "desc": "MÚLTIPLES INTENTOS DE LOGIN FALLIDOS: Posible ataque de fuerza bruta"})
    except: pass
    
    # 4. USB Monitor (Unidades externas y pendrives)
    try:
        current_usbs = set()
        for p in psutil.disk_partitions(all=False):
            if 'cdrom' not in p.opts and p.device and len(p.device) >= 2 and p.device[1] == ':':
                drive = p.device[0].upper() + ":"
                current_usbs.add(drive)
                
        new_usbs = current_usbs - KNOWN_USBS
        for u in new_usbs:
            new_alerts.append({"level": "CRITICAL", "desc": f"ALERTA ALMACENAMIENTO: Nuevo disco/USB conectado ({u})"})
            KNOWN_USBS.add(u)
            
        removed_usbs = KNOWN_USBS - current_usbs
        for u in removed_usbs:
            new_alerts.append({"level": "WARNING", "desc": f"ALMACENAMIENTO EXTRAÍDO: Disco/USB desconectado ({u})"})
            KNOWN_USBS.remove(u)
    except: pass

    # 5. Network Bandwidth Monitor (Subida/Bajada inusual para exfiltración o minería)
    # Umbral de subida: 15 MB/s (15360 KB/s)
    # Umbral de bajada: 30 MB/s (30720 KB/s)
    if upload_speed > 15360:
        new_alerts.append({"level": "CRITICAL", "desc": f"TRÁFICO INUSUAL (SUBIDA): Transmitiendo a {round(upload_speed/1024, 2)} MB/s. Posible exfiltración o malware."})
    if download_speed > 30720:
        new_alerts.append({"level": "WARNING", "desc": f"TRÁFICO INUSUAL (BAJADA): Descargando a {round(download_speed/1024, 2)} MB/s. Alto consumo de red."})

    return new_alerts

DNS_CACHE = {}
LAST_DISCOVERY_TIME = 0
CACHED_DEVICES = []

def resolve_hostname(ip):
    if ip in DNS_CACHE:
        return DNS_CACHE[ip]
    try:
        socket.setdefaulttimeout(0.5)
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = ""
    DNS_CACHE[ip] = hostname
    return hostname

def get_device_type(hostname, ip):
    h = hostname.lower()
    if "printer" in h or "epson" in h or "hp" in h or "canon" in h:
        return "Printer"
    elif "phone" in h or "android" in h or "iphone" in h or "mobile" in h:
        return "Mobile"
    elif "router" in h or "gateway" in h or ip.endswith(".1") or ip.endswith(".254"):
        return "Router"
    elif "tv" in h or "smarttv" in h or "television" in h:
        return "TV"
    elif "server" in h or "nas" in h or "db" in h:
        return "Server"
    elif h:
        return "PC/Laptop"
    return "Generic"

def get_discovered_devices():
    global LAST_DISCOVERY_TIME, CACHED_DEVICES
    current_time = time.time()
    
    if current_time - LAST_DISCOVERY_TIME < 60 and CACHED_DEVICES:
        return CACHED_DEVICES
        
    import re
    import concurrent.futures
    
    # 1. Barrido de subred local por sockets para poblar la caché ARP del sistema operativo
    try:
        ips_to_scan = []
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    if ip.startswith("127.") or ip.startswith("169.254."):
                        continue
                    octets = ip.split(".")
                    if len(octets) == 4:
                        base = f"{octets[0]}.{octets[1]}.{octets[2]}"
                        for i in range(1, 255):
                            scan_ip = f"{base}.{i}"
                            if scan_ip != ip:
                                ips_to_scan.append(scan_ip)
        ips_to_scan = list(set(ips_to_scan))
        if ips_to_scan:
            def probe_ip(ip_addr):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.1) # 100ms
                    s.connect_ex((ip_addr, 135))
                    s.close()
                except:
                    pass
            with concurrent.futures.ThreadPoolExecutor(max_workers=80) as sweep_executor:
                sweep_executor.map(probe_ip, ips_to_scan)
    except Exception as scan_err:
        print(f"[ERROR] Barrido de subred fallido: {scan_err}")

    devices = []
    try:
        output = subprocess.run("arp -a", shell=True, capture_output=True, text=True, timeout=5).stdout
        pattern = re.compile(r"^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+([0-9a-fA-F:-]{17})\s+(\w+)", re.MULTILINE)
        found = pattern.findall(output)
        
        candidates = []
        for ip, mac, _type in found:
            mac_std = mac.replace("-", ":").upper()
            octets = ip.split(".")
            if len(octets) != 4:
                continue
            first_octet = int(octets[0])
            last_octet = int(octets[3])
            
            if first_octet >= 224 and first_octet <= 239:
                continue
            if last_octet == 255:
                continue
            if ip in ["255.255.255.255", "127.0.0.1", "0.0.0.0"]:
                continue
            
            candidates.append((ip, mac_std))
        
        seen_ips = set()
        unique_candidates = []
        for ip, mac in candidates:
            if ip not in seen_ips:
                seen_ips.add(ip)
                unique_candidates.append((ip, mac))
        
        unique_candidates = unique_candidates[:100]
        
        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(0.5)
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
                futures = {executor.submit(resolve_hostname, ip): (ip, mac) for ip, mac in unique_candidates}
                for future in concurrent.futures.as_completed(futures):
                    ip, mac = futures[future]
                    try:
                        hostname = future.result()
                    except Exception:
                        hostname = ""
                    
                    device_type = get_device_type(hostname, ip)
                    devices.append({
                        "ip": ip,
                        "mac": mac,
                        "hostname": hostname or ip,
                        "type": device_type
                    })
        finally:
            socket.setdefaulttimeout(orig_timeout)
            
    except Exception as e:
        print(f"[ERROR] En descubrimiento de red: {e}")
        
    if devices:
        CACHED_DEVICES = devices
        LAST_DISCOVERY_TIME = current_time
        
    return CACHED_DEVICES

def get_system_audit():
    # Información amigable (Nombres comerciales reales)
    os_info = run_cmd('wmic os get Caption').replace('Caption', '').strip()
    if not os_info: os_info = f"{platform.system()} {platform.release()}"
    
    cpu_info = run_cmd('wmic cpu get Name').replace('Name', '').strip()
    if not cpu_info: cpu_info = platform.processor()
    
    ram_raw = round(psutil.virtual_memory().total / (1024**3), 0)
    disk_total_raw = round(psutil.disk_usage('/').total / (1024**3), 0)
    
    # Batería
    try:
        batt = psutil.sensors_battery()
        battery_pct = f"{round(batt.percent)}" if batt else "N/A"
    except:
        battery_pct = "N/A"

    # Estados de Seguridad (PowerShell)
    fw_active = "False" not in run_cmd('powershell -Command "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled"')
    av_active = "True" in run_cmd('powershell -Command "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"')
    
    # Licencia (WMIC es lo único lento, lo dejamos al final)
    license_raw = run_cmd('wmic path SoftwareLicensingProduct where "Name like \'%Windows%\' and PartialProductKey is not null" get LicenseStatus')
    license_active = "1" in license_raw

    inventory = {
        "os": os_info,
        "cpu": cpu_info,
        "ram_total": f"{ram_raw} GB",
        "disk_total": f"{disk_total_raw} GB",
        "battery": battery_pct,
        "fw_active": fw_active,
        "av_active": av_active,
        "license_active": license_active,
        "discovered_devices": get_discovered_devices()
    }

    alerts = []
    if not fw_active: alerts.append({"level": "CRITICAL", "desc": "FIREWALL APAGADO"})
    if not av_active: alerts.append({"level": "CRITICAL", "desc": "ANTIVIRUS APAGADO"})
    
    # Debug en consola para que el usuario vea qué se envía
    print(f"📊 Audit: OS={os_info} | RAM={ram_raw}GB | BAT={battery_pct}")
    
    return inventory, alerts

def get_top_processes():
    processes = []
    try:
        for proc in psutil.process_iter(['name', 'cpu_percent']):
            try:
                if proc.info['name'] in ["Idle", "System Idle Process"]: continue
                processes.append({"name": proc.info['name'], "cpu": proc.info['cpu_percent'] / CPU_CORES})
            except: pass
    except: pass
    return sorted(processes, key=lambda x: x['cpu'], reverse=True)[:5]

def get_metrics():
    global LAST_NET_IO
    try:
        # Calcular velocidad de subida/bajada de red
        upload_speed = 0.0 # KB/s
        download_speed = 0.0 # KB/s
        try:
            current_io = psutil.net_io_counters()
            current_time = time.time()
            if LAST_NET_IO is not None:
                last_sent, last_recv, last_time = LAST_NET_IO
                time_diff = current_time - last_time
                if time_diff > 0:
                    upload_speed = round(((current_io.bytes_sent - last_sent) / 1024) / time_diff, 2)
                    download_speed = round(((current_io.bytes_recv - last_recv) / 1024) / time_diff, 2)
            LAST_NET_IO = (current_io.bytes_sent, current_io.bytes_recv, current_time)
        except Exception as e:
            print(f"Error midiendo red: {e}")

        inventory, alerts = get_system_audit()
        inventory["upload_speed"] = f"{upload_speed} KB/s"
        inventory["download_speed"] = f"{download_speed} KB/s"
        
        cpu_total = psutil.cpu_percent(interval=1)
        
        # Conexiones activas
        conns = []
        try:
            for c in psutil.net_connections(kind='inet'):
                if c.status == 'ESTABLISHED' and c.raddr:
                    ip = c.raddr.ip if hasattr(c.raddr, 'ip') else c.raddr[0]
                    port = c.raddr.port if hasattr(c.raddr, 'port') else c.raddr[1]
                    if not ip.startswith('127.') and not ip.startswith('0.'):
                        try:
                            pname = psutil.Process(c.pid).name() if c.pid else "Unknown"
                            conns.append(f"{pname} ➜ {ip}:{port}")
                        except:
                            conns.append(f"Unknown ➜ {ip}:{port}")
        except: pass

        conns_list = list(set(conns))[:10]
        alerts.extend(check_advanced_threats(conns_list, upload_speed, download_speed))
        
        return {
            "hostname": socket.gethostname(),
            "cpu_usage": round(cpu_total, 2),
            "ram_usage": round(psutil.virtual_memory().percent, 2),
            "disk_usage": round(psutil.disk_usage('/').percent, 2),
            "uptime": str(datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())).split('.')[0],
            "network": inventory, 
            "processes": get_top_processes(),
            "security_alerts": alerts,
            "active_connections": conns_list,
            "timestamp": time.time()
        }
    except Exception as e:
        print(f"Error: {e}")
        return None

def check_and_install_persistence():
    # Solo instalar persistencia en produccion si es ejecutable
    if not getattr(sys, 'frozen', False):
        return
    
    current_exe = sys.executable
    appdata = os.getenv("LOCALAPPDATA")
    target_dir = os.path.join(appdata, "SentinelAgent")
    target_exe = os.path.join(target_dir, "SentinelAgent.exe")
    
    if os.path.abspath(current_exe).lower() != os.path.abspath(target_exe).lower():
        try:
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)
            
            import shutil
            # Copiar ejecutable
            shutil.copy2(current_exe, target_exe)
            
            # Copiar config.txt
            config_source = os.path.join(os.path.dirname(current_exe), "config.txt")
            config_target = os.path.join(target_dir, "config.txt")
            if os.path.exists(config_source):
                shutil.copy2(config_source, config_target)
            else:
                with open(config_target, "w") as f:
                    f.write("https://edr-sentinel-x.onrender.com")
            
            # Limpiar clave de registro antigua (HKCU Run) si existe
            import winreg as reg
            try:
                key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, reg.KEY_SET_VALUE)
                reg.DeleteValue(key, "SentinelAgent")
                reg.CloseKey(key)
            except:
                pass
            
            # Registrar inicio automático silencioso mediante Tarea Programada de Windows (bypassea UAC en arranque)
            task_cmd = f'schtasks /create /tn "SentinelAgent" /tr "\\"{target_exe}\\"" /sc onlogon /rl highest /f'
            subprocess.run(task_cmd, shell=True, capture_output=True)
            
            # Lanzar el proceso persistente y cerrar el actual
            os.startfile(target_exe)
            sys.exit(0)
        except Exception as e:
            print(f"[-] Error registrando persistencia: {e}")

agent_mutex = None

def main():
    global agent_mutex
    agent_mutex = check_single_instance()
    
    print(f"--- Sentinel Master Agent v9.0 ---")
    if not is_admin():
        print("[*] Solicitando permisos de ADMINISTRADOR...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()
    
    # Auto instalar en inicio en segundo plano al ejecutar por primera vez
    check_and_install_persistence()
    print("[+] Agente ejecutándose con privilegios de ADMINISTRADOR.")
    while True:
        try:
            data = get_metrics()
            res = requests.post(SERVER_URL, json=data, timeout=3)
            
            if res.status_code == 200:
                rj = res.json()
                quarantine_requested = rj.get("quarantine", False)
                if quarantine_requested:
                    print(f"📡 Status: QUARANTINE ACTIVE")
                handle_quarantine(quarantine_requested)
                
        except Exception as e:
            print(f"Error enviando métricas: {e}")
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
