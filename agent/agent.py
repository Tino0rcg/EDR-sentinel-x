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
CPU_CORES = psutil.cpu_count() or 1

def run_cmd(cmd):
    try: 
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if res.returncode != 0:
            print(f"[ERROR] ejecutando comando: {res.stderr.strip()}")
        return res.stdout.strip()
    except Exception as e: 
        print(f"[EXCEPCION]: {e}")
        return ""

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

KNOWN_USBS = set()
try:
    for p in psutil.disk_partitions(all=False):
        if 'cdrom' not in p.opts:
            KNOWN_USBS.add(p.device)
except: pass

CURRENT_QUARANTINE = False

def handle_quarantine(enable):
    global CURRENT_QUARANTINE
    if enable == CURRENT_QUARANTINE: return
    
    if enable:
        print("🚨 INICIANDO CUARENTENA DE RED...")
        run_cmd(f'powershell -Command "New-NetFirewallRule -DisplayName \'SentinelBlockAll\' -Direction Outbound -Action Block; New-NetFirewallRule -DisplayName \'SentinelBlockAllIn\' -Direction Inbound -Action Block; New-NetFirewallRule -DisplayName \'SentinelAllowServer\' -Direction Outbound -RemoteAddress {SERVER_IP} -Action Allow; New-NetFirewallRule -DisplayName \'SentinelAllowServerIn\' -Direction Inbound -RemoteAddress {SERVER_IP} -Action Allow"')
    else:
        print("✅ LEVANTANDO CUARENTENA...")
        run_cmd('powershell -Command "Remove-NetFirewallRule -DisplayName \'SentinelBlockAll\'; Remove-NetFirewallRule -DisplayName \'SentinelBlockAllIn\'; Remove-NetFirewallRule -DisplayName \'SentinelAllowServer\'; Remove-NetFirewallRule -DisplayName \'SentinelAllowServerIn\'"')
    
    CURRENT_QUARANTINE = enable

def check_advanced_threats(conns_list):
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
            if 'cdrom' not in p.opts:
                current_usbs.add(p.device)
                
        new_usbs = current_usbs - KNOWN_USBS
        for u in new_usbs:
            new_alerts.append({"level": "CRITICAL", "desc": f"ALERTA ALMACENAMIENTO: Nuevo disco/USB conectado ({u})"})
            KNOWN_USBS.add(u)
            
        removed_usbs = KNOWN_USBS - current_usbs
        for u in removed_usbs:
            new_alerts.append({"level": "WARNING", "desc": f"ALMACENAMIENTO EXTRAÍDO: Disco/USB desconectado ({u})"})
            KNOWN_USBS.remove(u)
    except: pass

    return new_alerts

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
        "license_active": license_active
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
    try:
        inventory, alerts = get_system_audit()
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
        alerts.extend(check_advanced_threats(conns_list))
        
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
            
            # Registrar inicio automático en Windows Registry (Run)
            import winreg as reg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key = reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_SET_VALUE)
            reg.SetValueEx(key, "SentinelAgent", 0, reg.REG_SZ, f'"{target_exe}"')
            reg.CloseKey(key)
            
            # Lanzar el proceso persistente y cerrar el actual
            os.startfile(target_exe)
            sys.exit(0)
        except Exception as e:
            print(f"[-] Error registrando persistencia: {e}")

def main():
    print(f"--- Sentinel Master Agent v4.8 ---")
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
