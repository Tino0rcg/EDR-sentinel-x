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

config_val = DEFAULT_IP
COMPANY_NAME = "Default Company"

if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
        if len(lines) >= 2:
            config_val = lines[0]
            COMPANY_NAME = lines[1]
        elif len(lines) == 1:
            config_val = lines[0]
            COMPANY_NAME = "Default Company"
    except Exception as e:
        print(f"[ERROR] cargando config.txt: {e}")
else:
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write(f"http://localhost:8000\nDefault Company\n")
    except:
        pass

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

LAST_DISCOVERY_TIME = 0
CACHED_DEVICES = []
DNS_CACHE = {}

def get_vendor_by_mac(mac):
    clean_mac = mac.replace(":", "").replace("-", "").upper()[:6]
    OUI_DATABASE = {
        # Cisco & Network
        "00000C": "Cisco", "000142": "Cisco", "000784": "Cisco", 
        "001A2B": "TP-Link", "14CC20": "TP-Link", "18A6C7": "TP-Link", "74DA38": "TP-Link", "50C7BF": "TP-Link", "F4EC38": "TP-Link",
        "3085A9": "TP-Link",
        
        # Synology & Servers
        "001132": "Synology", "00223A": "Synology", "D89EF3": "Synology",
        "001788": "Philips", "00E04C": "Realtek", "B827EB": "Raspberry Pi", "3A8024": "Raspberry Pi",
        
        # Printers
        "000480": "HP", "000802": "HP", "308D99": "HP", "CC3E5F": "HP", "F8BC12": "HP",
        "001A4B": "Epson", "0026AB": "Epson", "000085": "Canon", "001A8C": "Canon",
        
        # PCs & Servers
        "001861": "Dell", "001A92": "Dell", "00219B": "Dell", "74867A": "Dell", "A41F72": "Dell",
        "001422": "Dell", "002564": "Dell", "B8AC6F": "Dell",
        "001C25": "Intel", "001E64": "Intel", "909F43": "Intel",
        "000C29": "VMware", "005056": "VMware",
        "00037A": "Acer", "001E68": "Acer", "001E8C": "ASUS", "002618": "ASUS",
        "001617": "MSI", "0A0027": "VirtualBox VM", "525400": "QEMU/KVM VM",
        
        # Apple (Phones, iPads, Macs)
        "000393": "Apple", "000502": "Apple", "000A27": "Apple", "34159E": "Apple", "7CC537": "Apple", "F0EF86": "Apple",
        "000D93": "Apple", "0010FA": "Apple", "001451": "Apple", "0016CB": "Apple", "0017F2": "Apple", 
        "0019E3": "Apple", "001B63": "Apple", "001CB3": "Apple", "001D4F": "Apple", "001E52": "Apple", 
        
        # Samsung (Phones, TVs)
        "0007AB": "Samsung", "000F73": "Samsung", "ECE09B": "Samsung", "FCF136": "Samsung",
        "001247": "Samsung", "0015B9": "Samsung", "0017C5": "Samsung", "00187A": "Samsung", "001A8A": "Samsung",
        
        # Xiaomi (Phones)
        "1C12B0": "Xiaomi", "286C07": "Xiaomi", "3480B3": "Xiaomi", "50EC50": "Xiaomi", "640980": "Xiaomi", "D4619D": "Xiaomi",
        
        # Huawei
        "001E10": "Huawei", "0022A1": "Huawei", "24DF6A": "Huawei", "34CDBE": "Huawei", "64167F": "Huawei", "00E0FC": "Huawei",
        
        # Motorola
        "000A28": "Motorola", "0015A3": "Motorola", "002091": "Motorola", "3CD0F8": "Motorola",
        
        # Google
        "3C5AB4": "Google", "D8EB97": "Google", "F88FCA": "Google", "001A11": "Google",
        
        # Oppo, Vivo, OnePlus
        "AC83F3": "Oppo", "C8AE9C": "Oppo", "D4A148": "Oppo",
        "34E0CF": "Vivo", "702ED5": "Vivo", "807ABF": "Vivo",
        "E8B4C8": "OnePlus", "94E1AC": "OnePlus", "64A2F9": "OnePlus"
    }
    return OUI_DATABASE.get(clean_mac, "Desconocido")

def query_netbios(ip):
    query = b'\xa2\x48\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01'
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.12)
        s.sendto(query, (ip, 137))
        data, addr = s.recvfrom(1024)
        s.close()
        if len(data) > 56:
            num_names = data[56]
            offset = 57
            for i in range(num_names):
                name_bytes = data[offset:offset+15].strip()
                name = name_bytes.decode('latin1', errors='ignore').strip()
                name_type = data[offset+15]
                if name_type in [0x00, 0x20] and name:
                    cleaned = ''.join(c for c in name if c.isalnum() or c in '-_')
                    if cleaned:
                        return cleaned
                offset += 18
    except:
        pass
    return None

def query_mdns(ip):
    # Enviar una consulta mDNS inversa (DNS PTR para la IP invertida) directamente al puerto 5353 del host
    try:
        octets = ip.split('.')
        if len(octets) != 4: return None
        rev_domain = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"
        parts = rev_domain.split('.')
        qname = b''
        for part in parts:
            qname += bytes([len(part)]) + part.encode('utf-8')
        qname += b'\x00'
        
        # Transaction ID (0), Flags (0), Questions (1), Answers (0), Authority (0), Additional (0)
        # Type (PTR = 12), Class (IN = 1)
        packet = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + qname + b'\x00\x0c\x80\x01'
        
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.15) # timeout corto
        s.sendto(packet, (ip, 5353))
        data, addr = s.recvfrom(1024)
        s.close()
        
        if len(data) > 12:
            decoded = data.decode('latin1', errors='ignore')
            import re
            # Buscar cualquier nombre que termine en .local en la respuesta mDNS
            match = re.search(r'([a-zA-Z0-9\-]+)\.local', decoded)
            if match:
                # Retornar el nombre limpio sin .local
                return match.group(1)
    except:
        pass
    return None

def resolve_hostname_dns(ip):
    if ip in DNS_CACHE:
        return DNS_CACHE[ip]
    try:
        socket.setdefaulttimeout(0.12)
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = ""
    DNS_CACHE[ip] = hostname
    return hostname

def query_http_title(ip):
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except:
        pass
    
    import html
    # Intentar puertos 80 y 443
    for proto, port in [("http", 80), ("https", 443)]:
        try:
            url = f"{proto}://{ip}"
            res = requests.get(url, timeout=0.8, verify=False)
            if res.status_code == 200:
                text_content = res.text
                import re
                match = re.search(r'<title\b[^>]*>(.*?)</title>', text_content, re.IGNORECASE | re.DOTALL)
                if match:
                    title = match.group(1).strip()
                    title = html.unescape(title)
                    title = re.sub(r'\s+', ' ', title)
                    if title and not any(x in title.lower() for x in ["error", "404", "not found", "403", "forbidden"]):
                        return title
        except:
            pass
    return None

SSDP_CACHED_MODELS = {}
MDNS_CACHED_NAMES = {}

APPLE_MODELS = {
    # iPhones
    "iPhone10,1": "iPhone 8", "iPhone10,4": "iPhone 8",
    "iPhone10,2": "iPhone 8 Plus", "iPhone10,5": "iPhone 8 Plus",
    "iPhone10,3": "iPhone X", "iPhone10,6": "iPhone X",
    "iPhone11,2": "iPhone XS", "iPhone11,4": "iPhone XS Max",
    "iPhone11,6": "iPhone XS Max", "iPhone11,8": "iPhone XR",
    "iPhone12,1": "iPhone 11", "iPhone12,3": "iPhone 11 Pro",
    "iPhone12,5": "iPhone 11 Pro Max", "iPhone12,8": "iPhone SE (2nd Gen)",
    "iPhone13,1": "iPhone 12 mini", "iPhone13,2": "iPhone 12",
    "iPhone13,3": "iPhone 12 Pro", "iPhone13,4": "iPhone 12 Pro Max",
    "iPhone14,2": "iPhone 13 Pro", "iPhone14,3": "iPhone 13 Pro Max",
    "iPhone14,4": "iPhone 13 mini", "iPhone14,5": "iPhone 13",
    "iPhone14,6": "iPhone SE (3rd Gen)", "iPhone14,7": "iPhone 14",
    "iPhone14,8": "iPhone 14 Plus", "iPhone15,2": "iPhone 14 Pro",
    "iPhone15,3": "iPhone 14 Pro Max", "iPhone15,4": "iPhone 15",
    "iPhone15,5": "iPhone 15 Plus", "iPhone16,1": "iPhone 15 Pro",
    "iPhone16,2": "iPhone 15 Pro Max", "iPhone17,1": "iPhone 16 Pro",
    "iPhone17,2": "iPhone 16 Pro Max", "iPhone17,3": "iPhone 16",
    "iPhone17,4": "iPhone 16 Plus",
    
    # iPads
    "iPad11,1": "iPad mini (5th Gen)", "iPad11,2": "iPad mini (5th Gen)",
    "iPad11,3": "iPad Air (3rd Gen)", "iPad11,4": "iPad Air (3rd Gen)",
    "iPad11,6": "iPad (8th Gen)", "iPad11,7": "iPad (8th Gen)",
    "iPad12,1": "iPad (9th Gen)", "iPad12,2": "iPad (9th Gen)",
    "iPad13,1": "iPad Air (4th Gen)", "iPad13,2": "iPad Air (4th Gen)",
    "iPad13,4": "iPad Pro 11-inch (3rd Gen)", "iPad13,16": "iPad Air (5th Gen)",
    "iPad13,18": "iPad (10th Gen)", "iPad14,1": "iPad mini (6th Gen)",
    "iPad14,2": "iPad mini (6th Gen)"
}

def is_locally_administered_mac(mac):
    clean = mac.replace(":", "").replace("-", "").upper()
    if len(clean) >= 2:
        second_char = clean[1]
        if second_char in ['2', '6', 'A', 'E']:
            return True
    return False

def query_apple_model(ip, hostname):
    # Enviar consulta mDNS TXT al puerto 5353 del host para obtener el modelo exacto
    try:
        domain = f"{hostname}._device-info._tcp.local"
        parts = domain.split('.')
        qname = b''
        for part in parts:
            qname += bytes([len(part)]) + part.encode('utf-8')
        qname += b'\x00'
        
        # Transaction ID, Flags, Questions (1), Answers (0), Authority (0), Additional (0)
        # QTYPE: TXT (16), QCLASS: IN (1)
        packet = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + qname + b'\x00\x10\x80\x01'
        
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.18)
        s.sendto(packet, (ip, 5353))
        data, addr = s.recvfrom(1024)
        s.close()
        
        if len(data) > 12:
            decoded = data.decode('latin1', errors='ignore')
            import re
            match = re.search(r'model=([a-zA-Z0-9,]+)', decoded)
            if match:
                model_id = match.group(1)
                # Traducir modelo si existe en nuestro diccionario
                return APPLE_MODELS.get(model_id, model_id)
    except:
        pass
    return None

def query_google_cast_info(ip):
    # Los dispositivos Android TV/Chromecast exponen su info en el puerto 8008
    try:
        url = f"http://{ip}:8008/setup/eureka_info"
        res = requests.get(url, timeout=0.2)
        if res.status_code == 200:
            info = res.json()
            model = info.get("model_name", "")
            friendly = info.get("name", "")
            if model:
                return f"{model} ({friendly})" if friendly else model
    except:
        pass
    return None

def query_mdns_unicast_services(ip):
    # Enviar consultas unicast mDNS de PTR directamente a la IP del dispositivo para saltar bloqueos multicast
    services = [
        b'\x0b_googlecast\x04_tcp\x05local\x00',           # Android Cast
        b'\x0f_apple-mobdev2\x04_tcp\x05local\x00',         # iOS Mobile Device
        b'\x08_airplay\x04_tcp\x05local\x00'                # AirPlay
    ]
    for qname in services:
        try:
            packet = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + qname + b'\x00\x0c\x80\x01'
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(('', 5353))
            except:
                pass
            s.settimeout(0.2)
            s.sendto(packet, (ip, 5353))
            data, addr = s.recvfrom(1024)
            s.close()
            
            if len(data) > 12:
                decoded = data.decode('latin1', errors='ignore')
                import re
                
                # Extraer modelo si está en las cabeceras TXT (ej: model=iPhone13,3)
                model = ""
                model_match = re.search(r'model=([a-zA-Z0-9,]+)', decoded)
                if model_match:
                    model_id = model_match.group(1)
                    model = APPLE_MODELS.get(model_id, model_id)
                
                # Extraer nombre descriptivo (ej: iPhone-de-Juan.local)
                friendly = ""
                matches = re.findall(r'([a-zA-Z0-9\-]+)\.local', decoded)
                for m in matches:
                    cleaned_m = m.replace("-", " ").strip()
                    if m.lower() not in ["googlecast", "apple-mobdev2", "airplay", "local", "device-info", "_googlecast", "_apple-mobdev2", "services", "_services"]:
                        friendly = cleaned_m
                        break
                        
                if model or friendly:
                    return {"model": model, "friendly": friendly}
        except:
            pass
    return None

def get_local_ip():
    try:
        temp_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_s.connect(("8.8.8.8", 80))
        ip = temp_s.getsockname()[0]
        temp_s.close()
        return ip
    except:
        return "0.0.0.0"

def background_ssdp_discover():
    # Descubrimiento UPnP/SSDP Multicast para recuperar marcas y modelos (Samsung, LG, Huawei, impresoras, etc.)
    global SSDP_CACHED_MODELS
    msg = (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 1\r\n'
        'ST: ssdp:all\r\n'
        '\r\n'
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.settimeout(1.0)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        
        local_ip = get_local_ip()
        if local_ip != "0.0.0.0":
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
            
        s.sendto(msg.encode('utf-8'), ('239.255.255.250', 1900))
        while True:
            try:
                data, addr = s.recvfrom(2048)
                ip = addr[0]
                text = data.decode('utf-8', errors='ignore')
                headers = {}
                for line in text.split('\r\n'):
                    if ':' in line:
                        parts = line.split(':', 1)
                        headers[parts[0].upper().strip()] = parts[1].strip()
                
                location = headers.get('LOCATION', '')
                if location and ip not in SSDP_CACHED_MODELS:
                    try:
                        res = requests.get(location, timeout=0.18)
                        if res.status_code == 200:
                            xml = res.text
                            import re
                            friendly_match = re.search(r'<friendlyName>(.*?)</friendlyName>', xml, re.I)
                            model_match = re.search(r'<modelName>(.*?)</modelName>', xml, re.I)
                            model_desc_match = re.search(r'<modelDescription>(.*?)</modelDescription>', xml, re.I)
                            
                            friendly = friendly_match.group(1).strip() if friendly_match else ""
                            model = model_match.group(1).strip() if model_match else ""
                            desc = model_desc_match.group(1).strip() if model_desc_match else ""
                            
                            if friendly or model:
                                SSDP_CACHED_MODELS[ip] = {
                                    "friendly": friendly,
                                    "model": model,
                                    "desc": desc
                                }
                    except:
                        pass
            except socket.timeout:
                break
    except:
        pass

def background_mdns_discover():
    global MDNS_CACHED_NAMES
    # Servicios comunes en iPhones, iPads y dispositivos móviles Android/Casting/Spotify
    services = [
        b'\x09_services\x07_dns-sd\x04_udp\x05local\x00',   # PTR _services._dns-sd._udp.local
        b'\x0b_googlecast\x04_tcp\x05local\x00',           # PTR _googlecast._tcp.local
        b'\x0f_apple-mobdev2\x04_tcp\x05local\x00',         # PTR _apple-mobdev2._tcp.local
        b'\x08_airplay\x04_tcp\x05local\x00',                # PTR _airplay._tcp.local
        b'\x10_spotify-connect\x04_tcp\x05local\x00',       # PTR _spotify-connect._tcp.local
        b'\x0f_companion-link\x04_tcp\x05local\x00',         # PTR _companion-link._tcp.local
        b'\x04_ipp\x04_tcp\x05local\x00',                    # PTR _ipp._tcp.local
        b'\x0c_workstation\x04_tcp\x05local\x00'             # PTR _workstation._tcp.local
    ]
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(0.4)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        
        local_ip = get_local_ip()
        if local_ip != "0.0.0.0":
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
            
        try:
            s.bind(('', 5353))
        except Exception as bind_err:
            print(f"[WARNING] No se pudo enlazar a 5353: {bind_err}")
            
        # Unirse al grupo multicast 224.0.0.251
        import struct
        mreq = struct.pack("4sl", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except:
            pass
            
        for qname in services:
            # Transaction ID, Flags, Questions (1), Answers (0), Authority (0), Additional (0)
            # QTYPE: PTR (12), QCLASS: IN (1) con bit QU activo
            packet = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + qname + b'\x00\x0c\x80\x01'
            s.sendto(packet, ('224.0.0.251', 5353))
            
        start_time = time.time()
        s.settimeout(0.15)
        while time.time() - start_time < 1.5:
            try:
                data, addr = s.recvfrom(2048)
                ip = addr[0]
                decoded = data.decode('latin1', errors='ignore')
                import re
                
                # Extraer modelo si está en las cabeceras TXT (ej: model=iPhone13,3)
                model_match = re.search(r'model=([a-zA-Z0-9,]+)', decoded)
                if model_match:
                    model_id = model_match.group(1)
                    friendly_model = APPLE_MODELS.get(model_id, model_id)
                    if ip not in MDNS_CACHED_NAMES:
                        MDNS_CACHED_NAMES[ip] = {}
                    MDNS_CACHED_NAMES[ip]["model"] = friendly_model
                
                # Extraer nombre descriptivo (ej: iPhone-de-Juan.local)
                matches = re.findall(r'([a-zA-Z0-9\-]+)\.local', decoded)
                for m in matches:
                    cleaned_m = m.replace("-", " ").strip()
                    if m.lower() not in ["_services", "_dns-sd", "_udp", "_tcp", "local", "googlecast", "apple-mobdev2", "airplay", "device-info", "workstation", "_googlecast", "_apple-mobdev2", "_airplay", "services", "companion-link", "_companion-link", "spotify-connect", "_spotify-connect", "ipp", "_ipp"]:
                        if ip not in MDNS_CACHED_NAMES:
                            MDNS_CACHED_NAMES[ip] = {}
                        MDNS_CACHED_NAMES[ip]["name"] = cleaned_m
            except socket.timeout:
                continue
            except:
                pass
        s.close()
    except Exception as e:
        print(f"Error en background_mdns_discover: {e}")

def generate_fallback_mobile_name(mac, ip):
    vendor = get_vendor_by_mac(mac)
    if vendor == "Móvil (MAC Privada)":
        return f"Móvil (MAC Privada: {ip})"
    elif vendor != "Desconocido":
        return f"Dispositivo {vendor} ({ip})"
    else:
        return f"Dispositivo Móvil ({ip})"

def detect_device_details(ip, mac):
    # 1. Obtener Nombre de Host (NetBIOS -> mDNS Unicast -> mDNS Multicast Caché -> HTTP Title -> DNS)
    name = query_netbios(ip)
    if not name:
        name = query_mdns(ip)
    if not name and ip in MDNS_CACHED_NAMES:
        name = MDNS_CACHED_NAMES[ip].get("name", "")
    if not name:
        name = query_http_title(ip)
    if not name:
        name = resolve_hostname_dns(ip)
    if name == ip:
        name = ""
    
    # 2. Fabricante
    vendor = get_vendor_by_mac(mac)
    is_random_mac = is_locally_administered_mac(mac)
    if is_random_mac and vendor == "Desconocido":
        vendor = "Móvil (MAC Privada)"
    
    # 3. Escaneo rápido de firmas
    ports = [22, 80, 135, 445, 631, 9100, 8008]
    open_ports = []
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.06) # 60ms por puerto para hacerlo veloz
            res = s.connect_ex((ip, p))
            s.close()
            if res == 0:
                open_ports.append(p)
        except:
            pass
            
    # 4. Intentar resolver modelo exacto de celular/tablet/cast
    exact_model = ""
    
    # Consultar mDNS Multicast Caché primero
    if ip in MDNS_CACHED_NAMES:
        exact_model = MDNS_CACHED_NAMES[ip].get("model", "")
        friendly = MDNS_CACHED_NAMES[ip].get("name", "")
        # Si tiene un nombre que parece marca (como iPhone, Galaxy, Pixel, etc.)
        if not exact_model and friendly:
            f_lower = friendly.lower()
            if any(x in f_lower for x in ["iphone", "ipad", "galaxy", "xiaomi", "redmi", "huawei", "moto", "pixel", "oneplus"]):
                exact_model = friendly
                
    # Si no lo encontramos en la caché multicast, hacer una consulta unicast mDNS directa!
    if not exact_model:
        unicast_res = query_mdns_unicast_services(ip)
        if unicast_res:
            exact_model = unicast_res.get("model", "")
            friendly = unicast_res.get("friendly", "")
            if not exact_model and friendly:
                exact_model = friendly
            if friendly:
                if ip not in MDNS_CACHED_NAMES:
                    MDNS_CACHED_NAMES[ip] = {}
                MDNS_CACHED_NAMES[ip]["name"] = friendly
                if exact_model:
                    MDNS_CACHED_NAMES[ip]["model"] = exact_model
    
    # Heurística Apple: Si resolvimos un nombre de Apple, consultar modelo exacto vía mDNS TXT
    if not exact_model and name and ("iphone" in name.lower() or "ipad" in name.lower() or vendor == "Apple" or "macbook" in name.lower()):
        apple_res = query_apple_model(ip, name)
        if apple_res:
            exact_model = apple_res
            
    # Heurística Google Cast:
    if not exact_model and 8008 in open_ports:
        cast_res = query_google_cast_info(ip)
        if cast_res:
            exact_model = cast_res
            
    # Heurística UPnP / SSDP:
    if not exact_model and ip in SSDP_CACHED_MODELS:
        info = SSDP_CACHED_MODELS[ip]
        friendly = info.get("friendly", "")
        model = info.get("model", "")
        desc = info.get("desc", "")
        
        # Limpiar modelos comunes para móviles (como Samsung, LG, Huawei)
        if "galaxy" in friendly.lower() or "sm-" in model.lower() or "huawei" in friendly.lower():
            exact_model = f"Samsung {model}" if model.upper().startswith("SM-") else friendly
        elif friendly:
            exact_model = friendly
        elif model:
            exact_model = model
            
    # 5. Clasificación
    device_type = "Generic"
    
    # Clasificación por servicios/puertos
    if 9100 in open_ports or 631 in open_ports:
        device_type = "Printer"
    elif 8008 in open_ports or "tv" in (exact_model or name or "").lower():
        device_type = "TV"
    elif 445 in open_ports or 135 in open_ports:
        device_type = "PC/Laptop"
    elif 22 in open_ports:
        if vendor in ["Cisco", "TP-Link", "Ubiquiti", "Netgear"]:
            device_type = "Router"
        else:
            device_type = "Server"
            
    # Clasificación por fabricante (OUI)
    if device_type == "Generic":
        if vendor in ["HP", "Canon", "Epson", "Brother"]:
            device_type = "Printer"
        elif vendor in ["Cisco", "TP-Link", "Ubiquiti", "Netgear", "Linksys"]:
            device_type = "Router"
        elif vendor == "Raspberry Pi":
            device_type = "Server"
        elif vendor in ["Sony", "Samsung Electronics", "LG Electronics"]:
            device_type = "TV"
        elif vendor in ["Xiaomi", "Huawei", "Motorola", "Google", "Oppo", "Vivo", "OnePlus", "Móvil (MAC Privada)"]:
            device_type = "Mobile"
        elif vendor == "Apple":
            # Si es Apple y no tiene puertos típicos de PC (135/445) ni SSH (22), asumimos móvil (iPhone/iPad)
            if not any(p in open_ports for p in [22, 135, 445]):
                device_type = "Mobile"
            else:
                device_type = "PC/Laptop"
        elif "VMware" in vendor or "VirtualBox" in vendor or "QEMU" in vendor:
            device_type = "PC/Laptop"
            
    # Clasificación por palabras clave en el nombre
    name_lower = (exact_model or name or "").lower()
    if name_lower:
        if any(x in name_lower for x in ["printer", "canon", "epson", "hp-", "deskjet", "brother", "impresora"]):
            device_type = "Printer"
        elif any(x in name_lower for x in ["phone", "android", "iphone", "ipad", "mobile", "movil", "celular", "galaxy", "xiaomi", "redmi", "huawei", "moto", "pixel"]):
            device_type = "Mobile"
        elif any(x in name_lower for x in ["router", "gateway", "firewall", "switch", "ap-"]):
            device_type = "Router"
        elif any(x in name_lower for x in ["tv", "smarttv", "television", "roku", "chromecast", "firestick"]):
            device_type = "TV"
        elif any(x in name_lower for x in ["server", "nas", "db-", "sql", "controller", "ad-", "dns"]):
            device_type = "Server"
            
    # Heurística de descarte final para Móviles:
    # Si el fabricante es un conocido vendedor de celulares o es MAC aleatoria de Wi-Fi sin puertos abiertos
    if device_type == "Generic" and len(open_ports) == 0:
        if vendor in ["Apple", "Samsung", "Xiaomi", "Huawei", "Motorola", "Google", "Oppo", "Vivo", "OnePlus", "Móvil (MAC Privada)"]:
            device_type = "Mobile"
            
    # Clasificación por IP
    if ip.endswith(".1") or ip.endswith(".254"):
        device_type = "Router"
        
    # Establecer nombre de visualización final
    display_name = exact_model
    # Si tenemos modelo y friendly name amigable, combinarlos
    if exact_model and ip in MDNS_CACHED_NAMES:
        friendly = MDNS_CACHED_NAMES[ip].get("name", "")
        if friendly and friendly.lower() != exact_model.lower() and exact_model.lower() not in friendly.lower():
            display_name = f"{exact_model} ({friendly})"
            
    if not display_name:
        display_name = name
    if not display_name:
        if vendor == "Móvil (MAC Privada)":
            display_name = f"Dispositivo Móvil ({ip})"
        elif vendor != "Desconocido":
            display_name = f"{vendor} ({ip})"
        else:
            display_name = ip
            
    if device_type == "Mobile" and (not display_name or "dispositivo" in display_name.lower()):
        display_name = generate_fallback_mobile_name(mac, ip)
            
    return {
        "ip": ip,
        "mac": mac,
        "hostname": display_name,
        "type": device_type
    }

def ping_device(ip):
    try:
        # En Windows, -n 1 envía un ping, -w 80 define 80ms de timeout
        subprocess.run(f"ping -n 1 -w 80 {ip}", shell=True, capture_output=True)
    except:
        pass

def get_discovered_devices():
    global LAST_DISCOVERY_TIME, CACHED_DEVICES
    current_time = time.time()
    
    # Cachear descubrimientos durante 60 segundos
    if current_time - LAST_DISCOVERY_TIME < 60 and CACHED_DEVICES:
        return CACHED_DEVICES
        
    import re
    import concurrent.futures
    
    # 0. Lanzar descubrimiento SSDP y mDNS multicast en paralelo para marcas/modelos
    try:
        ssdp_thread = threading.Thread(target=background_ssdp_discover)
        ssdp_thread.daemon = True
        ssdp_thread.start()
        
        mdns_thread = threading.Thread(target=background_mdns_discover)
        mdns_thread.daemon = True
        mdns_thread.start()
    except Exception as ssdp_err:
        print(f"[ERROR] Hilo SSDP/mDNS fallido: {ssdp_err}")
        
    # 1. Barrido de subred por pings concurrentes rápidos (llena la tabla ARP de Windows)
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
            # Enviar pings en paralelo para llenar la tabla ARP rápidamente
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ping_executor:
                ping_executor.map(ping_device, ips_to_scan)
    except Exception as sweep_err:
        print(f"[ERROR] Sweep de pings fallido: {sweep_err}")

    devices = []
    try:
        # 2. Leer la tabla ARP del sistema operativo
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
            
            if first_octet >= 224 and first_octet <= 239: # Ignorar multicast
                continue
            if last_octet == 255: # Ignorar broadcast
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
        
        # Limitar a los primeros 100 por rendimiento
        unique_candidates = unique_candidates[:100]
        
        # 3. Analizar concurrentemente cada equipo para sacar fabricante, nombre y tipo
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:
                futures = {executor.submit(detect_device_details, ip, mac): (ip, mac) for ip, mac in unique_candidates}
                for future in concurrent.futures.as_completed(futures):
                    try:
                        dev = future.result()
                        if dev:
                            devices.append(dev)
                    except:
                        pass
        except Exception as t_err:
            print(f"[ERROR] En análisis concurrente ARP: {t_err}")
            
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
            "timestamp": time.time(),
            "company_name": COMPANY_NAME
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

def ensure_firewall_rules():
    if not is_admin():
        return
    try:
        exe_path = sys.executable
        # Verificar si la regla existe
        check_cmd = 'netsh advfirewall firewall show rule name="SentinelAgentFirewall"'
        res = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
        if "no hay reglas" in res.stdout.lower() or "no rules match" in res.stdout.lower() or res.returncode != 0:
            add_cmd = f'netsh advfirewall firewall add rule name="SentinelAgentFirewall" dir=in action=allow program="{exe_path}" enable=yes'
            subprocess.run(add_cmd, shell=True, capture_output=True)
            print("[+] Regla de Firewall registrada con éxito para el agente.")
    except Exception as e:
        print(f"[-] Error al registrar regla de Firewall: {e}")

agent_mutex = None

def main():
    global agent_mutex
    agent_mutex = check_single_instance()
    
    print(f"--- Sentinel Master Agent v9.0 ---")
    print(f"[+] Empresa a monitorear: {COMPANY_NAME}")
    if not is_admin() and "--no-uac" not in sys.argv:
        print("[*] Solicitando permisos de ADMINISTRADOR...")
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit()
        except Exception as e:
            print(f"[-] No se pudo elevar privilegios: {e}. Continuando en modo usuario...")
    
    # Auto instalar en inicio en segundo plano al ejecutar por primera vez
    if is_admin():
        check_and_install_persistence()
        ensure_firewall_rules()
        print("[+] Agente ejecutándose con privilegios de ADMINISTRADOR.")
    else:
        print("[+] Agente ejecutándose en modo USUARIO (sin persistencia).")
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
