from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import time
import os
import sys
from dotenv import load_dotenv

try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass

load_dotenv()
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, Float, String, ForeignKey, DateTime, JSON
from sqlalchemy.orm import sessionmaker, Session, declarative_base
import datetime
import bcrypt
import smtplib
from email.mime.text import MIMEText
from contextlib import asynccontextmanager
import asyncio

# --- DB ---
SQLALCHEMY_DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./sentinel.db").strip()
if SQLALCHEMY_DATABASE_URL.startswith("postgres://"):
    SQLALCHEMY_DATABASE_URL = SQLALCHEMY_DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Auto-inyectar sslmode=require para conexiones seguras en la nube (como Supabase)
if SQLALCHEMY_DATABASE_URL.startswith("postgresql://") and "sslmode" not in SQLALCHEMY_DATABASE_URL:
    if "?" in SQLALCHEMY_DATABASE_URL:
        SQLALCHEMY_DATABASE_URL += "&sslmode=require"
    else:
        SQLALCHEMY_DATABASE_URL += "?sslmode=require"

if "sqlite" in SQLALCHEMY_DATABASE_URL:
    engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- CONFIG SMTP ---
SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp-relay.brevo.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER", "a2a279001@smtp-brevo.com")
SMTP_PASS = os.environ.get("SMTP_PASS", "")  
ENABLE_EMAILS = os.environ.get("ENABLE_EMAILS", "True").lower() == "true"

# Memoria en RAM para de-duplicación (persiste aunque borres la DB)
ALERT_MEMORY = {} 

# Models
class CompanyDB(Base):
    __tablename__ = "companies"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)

class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True); email = Column(String, unique=True); hashed_password = Column(String); role = Column(String, default="USER")

class DeviceDB(Base):
    __tablename__ = "devices"
    hostname = Column(String, primary_key=True); last_seen = Column(DateTime); status = Column(String); active_connections = Column(JSON); quarantine = Column(Integer, default=0); network_map = Column(JSON)
    company_id = Column(Integer, ForeignKey("companies.id", ondelete="CASCADE"), nullable=True)

class MetricDB(Base):
    __tablename__ = "metrics"
    id = Column(Integer, primary_key=True); hostname = Column(String); cpu_usage = Column(Float); ram_usage = Column(Float); disk_usage = Column(Float); uptime = Column(String); network = Column(JSON); processes = Column(JSON); timestamp = Column(Float)
    company_id = Column(Integer, nullable=True)

class AlertDB(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True); hostname = Column(String); message = Column(String); level = Column(String); timestamp = Column(Float)
    company_id = Column(Integer, nullable=True)
    snapshot = Column(String, nullable=True)

class NetworkProbeDB(Base):
    __tablename__ = "network_probes"
    id = Column(Integer, primary_key=True)
    ip = Column(String, nullable=False)
    hostname = Column(String, nullable=True)
    latency_ms = Column(Float, nullable=True)   # None = offline
    open_ports = Column(JSON, nullable=True)     # list of {port, service, risk}
    mac = Column(String, nullable=True)
    device_type = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    timestamp = Column(Float, nullable=False)
    reporter_hostname = Column(String, nullable=True)  # which agent reported this

try:
    Base.metadata.create_all(bind=engine)
    print("✅ Base de datos inicializada correctamente.")
except Exception as db_err:
    print(f"❌ Error al inicializar la base de datos: {db_err}")

def send_email_task(subject, body, urgent=False):
    if not ENABLE_EMAILS: return
    try:
        msg = MIMEText(body); prefix = "🛑 SEGURIDAD" if urgent else "🚨 SISTEMA"
        msg['Subject'] = f"{prefix}: {subject}"; msg['From'] = SMTP_USER; msg['To'] = SMTP_USER # Enviar a admin por defecto
        # Para enviar a todos, se sacaría de UserDB aquí
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as s:
            s.starttls(); s.login(SMTP_USER, SMTP_PASS); s.send_message(msg)
    except: pass

def analyze_predictions(hostname: str):
    db = SessionLocal()
    try:
        metrics = db.query(MetricDB).filter(MetricDB.hostname == hostname).order_by(MetricDB.timestamp.desc()).limit(20).all()
        if len(metrics) < 10: return
        
        # Obtener el company_id del dispositivo
        device = db.query(DeviceDB).filter(DeviceDB.hostname == hostname).first()
        company_id = device.company_id if device else None
        
        # Check CPU Saturation
        high_cpu_count = sum(1 for m in metrics if m.cpu_usage > 90)
        if high_cpu_count >= 15:
            mem_key = f"{hostname}_PRED_CPU"
            if time.time() - ALERT_MEMORY.get(mem_key, 0) > 86400:
                db.add(AlertDB(hostname=hostname, message="Saturación crítica de CPU prolongada. Riesgo de cuelgue inminente.", level="PREDICTIVE", timestamp=time.time(), company_id=company_id))
                ALERT_MEMORY[mem_key] = time.time()
                
        # Check RAM Saturation
        high_ram_count = sum(1 for m in metrics if m.ram_usage > 90)
        if high_ram_count >= 15:
            mem_key = f"{hostname}_PRED_RAM"
            if time.time() - ALERT_MEMORY.get(mem_key, 0) > 86400:
                db.add(AlertDB(hostname=hostname, message="Memoria RAM al límite prolongado. Riesgo de fallo (OOM).", level="PREDICTIVE", timestamp=time.time(), company_id=company_id))
                ALERT_MEMORY[mem_key] = time.time()

        # Check Disk Growth
        oldest = metrics[-1]
        newest = metrics[0]
        time_diff = newest.timestamp - oldest.timestamp
        disk_diff = newest.disk_usage - oldest.disk_usage
        
        if time_diff > 0 and disk_diff > 0:
            growth_rate_per_sec = disk_diff / time_diff
            growth_rate_per_day = growth_rate_per_sec * 86400
            
            if growth_rate_per_day > 0.5:
                days_to_full = (100 - newest.disk_usage) / growth_rate_per_day
                if days_to_full < 14:
                    mem_key = f"{hostname}_PRED_DISK"
                    if time.time() - ALERT_MEMORY.get(mem_key, 0) > 86400:
                        db.add(AlertDB(hostname=hostname, message=f"El disco se llenará al 100% en aprox. {int(days_to_full)} días.", level="PREDICTIVE", timestamp=time.time(), company_id=company_id))
                        ALERT_MEMORY[mem_key] = time.time()
        db.commit()
    except Exception as e:
        print(f"Error en predicciones: {e}")
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        db = SessionLocal()
        try:
            from sqlalchemy import text
            db.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR DEFAULT 'USER'"))
            db.commit()
        except:
            db.rollback()
        try:
            from sqlalchemy import text
            db.execute(text("ALTER TABLE devices ADD COLUMN quarantine INTEGER DEFAULT 0"))
            db.commit()
        except:
            db.rollback()
        try:
            from sqlalchemy import text
            db.execute(text("ALTER TABLE devices ADD COLUMN active_connections JSON"))
            db.commit()
        except:
            db.rollback()
        try:
            from sqlalchemy import text
            db.execute(text("ALTER TABLE devices ADD COLUMN network_map JSON"))
            db.commit()
        except:
            db.rollback()
        try:
            from sqlalchemy import text
            db.execute(text("ALTER TABLE devices ADD COLUMN company_id INTEGER"))
            db.commit()
        except:
            db.rollback()
        try:
            from sqlalchemy import text
            db.execute(text("ALTER TABLE metrics ADD COLUMN company_id INTEGER"))
            db.commit()
        except:
            db.rollback()
        try:
            from sqlalchemy import text
            db.execute(text("ALTER TABLE alerts ADD COLUMN company_id INTEGER"))
            db.commit()
        except:
            db.rollback()
        try:
            from sqlalchemy import text
            db.execute(text("ALTER TABLE alerts ADD COLUMN snapshot TEXT"))
            db.commit()
        except:
            db.rollback()

        if db.query(UserDB).count() == 0:
            h = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
            db.add(UserDB(email="admin@sentinel.com", hashed_password=h, role="ADMIN")); db.commit()
        else:
            admin = db.query(UserDB).filter(UserDB.email == "admin@sentinel.com").first()
            if admin and admin.role != "ADMIN":
                admin.role = "ADMIN"
                db.commit()
        db.close()
    except Exception as e:
        print(f"⚠️ Error durante las migraciones de inicio: {e}")
    yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class Metrics(BaseModel):
    hostname: str; cpu_usage: float; ram_usage: float; disk_usage: float
    uptime: Optional[str] = "N/A"; network: Optional[Dict[str, Any]] = {}
    processes: Optional[List[Any]] = []; security_alerts: Optional[List[Any]] = []
    active_connections: Optional[List[str]] = []; timestamp: float
    company_name: Optional[str] = None

@app.post("/metrics")
async def post_metrics(data: Metrics, background_tasks: BackgroundTasks):
    db = SessionLocal()
    try:
        # Resolver empresa
        company_id = None
        cname = data.company_name or "Default Company"
        comp = db.query(CompanyDB).filter(CompanyDB.name == cname).first()
        if not comp:
            comp = CompanyDB(name=cname)
            db.add(comp)
            db.commit()
            db.refresh(comp)
        company_id = comp.id

        d = db.query(DeviceDB).filter(DeviceDB.hostname == data.hostname).first()
        if not d:
            d = DeviceDB(hostname=data.hostname)
            db.add(d)
        d.status = "ONLINE"
        d.last_seen = datetime.datetime.utcnow()
        d.active_connections = data.active_connections
        d.company_id = company_id
        if isinstance(data.network, dict):
            d.network_map = data.network.get("discovered_devices", [])
        is_quarantined = d.quarantine == 1
        
        # PROCESAR AMENAZAS CON FILTRO DRÁSTICO
        for threat in data.security_alerts:
            level = threat.get('level', 'INFO')
            if level == "INFO":
                continue
                
            mem_key = f"{data.hostname}_{threat['desc']}"
            last_alert_time = ALERT_MEMORY.get(mem_key, 0)
            is_status_alert = any(k in threat['desc'].upper() for k in ["FIREWALL", "ANTIVIRUS", "LICENCIA", "DISCO"])
            
            if is_status_alert or (time.time() - last_alert_time > 3600): 
                snapshot_data = threat.get('snapshot')
                db.add(AlertDB(hostname=data.hostname, message=threat['desc'], level=level, timestamp=data.timestamp, company_id=company_id, snapshot=snapshot_data))
                ALERT_MEMORY[mem_key] = time.time()
                background_tasks.add_task(send_email_task, f"Amenaza en {data.hostname} ({cname})", threat['desc'], True)
                print(f"🛑 [SERVER] Alerta CRÍTICA registrada (Silencio activado por 1h)")
        
        metric_dict = data.dict(exclude={'security_alerts', 'active_connections', 'company_name'})
        db.add(MetricDB(**metric_dict, company_id=company_id))
        if is_quarantined:
            print(f"🛡️ [QUARANTINE] Enviando bloqueo activo a {data.hostname}")
            
        db.commit()
        background_tasks.add_task(analyze_predictions, data.hostname)
    finally: db.close()
    return {"status": "ok", "quarantine": bool(is_quarantined)}

@app.get("/alerts")
def get_alerts(company_id: Optional[int] = None):
    db = SessionLocal()
    query = db.query(AlertDB)
    if company_id is not None:
        query = query.filter(AlertDB.company_id == company_id)
    data = query.order_by(AlertDB.timestamp.desc()).limit(100).all()
    db.close()
    return data

@app.delete("/alerts/{alert_id}")
def delete_alert(alert_id: int):
    db = SessionLocal()
    a = db.query(AlertDB).filter(AlertDB.id == alert_id).first()
    if a:
        db.delete(a)
        db.commit()
    db.close()
    return {"status": "ok"}

@app.delete("/alerts")
def clear_alerts():
    db = SessionLocal(); db.query(AlertDB).delete(); db.commit(); db.close(); return {"status": "ok"}

# --- COMPANIES ENDPOINTS ---
@app.get("/companies")
def get_companies():
    db = SessionLocal()
    companies = db.query(CompanyDB).all()
    res = []
    for c in companies:
        devices_count = db.query(DeviceDB).filter(DeviceDB.company_id == c.id).count()
        alerts_count = db.query(AlertDB).filter(AlertDB.company_id == c.id).count()
        res.append({
            "id": c.id,
            "name": c.name,
            "devices_count": devices_count,
            "alerts_count": alerts_count
        })
    db.close()
    return res

@app.post("/companies")
def create_company(data: Dict[str, str]):
    db = SessionLocal()
    name = data.get("name")
    if not name:
        db.close()
        raise HTTPException(status_code=400, detail="Name is required")
    existing = db.query(CompanyDB).filter(CompanyDB.name == name).first()
    if existing:
        db.close()
        raise HTTPException(status_code=400, detail="Company already exists")
    c = CompanyDB(name=name)
    db.add(c)
    db.commit()
    db.refresh(c)
    db.close()
    return {"status": "ok", "id": c.id, "name": c.name}

@app.delete("/companies/{company_id}")
def delete_company(company_id: int):
    db = SessionLocal()
    c = db.query(CompanyDB).filter(CompanyDB.id == company_id).first()
    if not c:
        db.close()
        raise HTTPException(status_code=404, detail="Company not found")
    
    # Cascade delete devices, metrics, and alerts for this company
    db.query(AlertDB).filter(AlertDB.company_id == company_id).delete()
    db.query(MetricDB).filter(MetricDB.company_id == company_id).delete()
    db.query(DeviceDB).filter(DeviceDB.company_id == company_id).delete()
    db.delete(c)
    db.commit()
    db.close()
    return {"status": "ok"}

@app.get("/devices")
def get_devices(company_id: Optional[int] = None):
    db = SessionLocal()
    if company_id is not None:
        devices = db.query(DeviceDB).filter(DeviceDB.company_id == company_id).all()
    else:
        devices = db.query(DeviceDB).all()
    now = datetime.datetime.utcnow()
    updated = False
    for d in devices:
        if d.last_seen and (now - d.last_seen).total_seconds() > 15:
            if d.status != "OFFLINE":
                d.status = "OFFLINE"
                updated = True
    if updated:
        db.commit()
    
    # Volver a cargar para retornar datos actualizados
    if company_id is not None:
        data = db.query(DeviceDB).filter(DeviceDB.company_id == company_id).all()
    else:
        data = db.query(DeviceDB).all()
    db.close()
    return data

@app.post("/quarantine/{hostname}")
def toggle_quarantine(hostname: str, data: Dict[str, Any]):
    db = SessionLocal()
    d = db.query(DeviceDB).filter(DeviceDB.hostname == hostname).first()
    if not d:
        db.close()
        raise HTTPException(status_code=404)
    d.quarantine = 1 if data.get("enable") else 0
    db.commit()
    db.close()
    return {"status": "ok"}

@app.post("/login")
def login(data: Dict[str, str]):
    db = SessionLocal(); u = db.query(UserDB).filter(UserDB.email == data["email"]).first()
    res = (u and bcrypt.checkpw(data["password"].encode(), u.hashed_password.encode()))
    if not res: 
        db.close()
        raise HTTPException(status_code=401)
    role = u.role
    email = u.email
    db.close()
    return {"status": "ok", "role": role, "email": email}

@app.get("/users")
def get_users():
    db = SessionLocal(); data = db.query(UserDB).all(); db.close()
    return [{"id": u.id, "email": u.email, "role": u.role} for u in data]

@app.post("/users")
def create_user(data: Dict[str, str]):
    db = SessionLocal()
    if db.query(UserDB).filter(UserDB.email == data["email"]).first():
        db.close()
        raise HTTPException(status_code=400, detail="User already exists")
    h = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt()).decode()
    db.add(UserDB(email=data["email"], hashed_password=h, role=data.get("role", "USER")))
    db.commit()
    db.close()
    return {"status": "ok"}

@app.delete("/users/{user_id}")
def delete_user(user_id: int):
    db = SessionLocal()
    u = db.query(UserDB).filter(UserDB.id == user_id).first()
    if u:
        db.delete(u)
        db.commit()
    db.close()
    return {"status": "ok"}

@app.get("/metrics/{hostname}")
def get_metrics(hostname: str):
    db = SessionLocal(); data = db.query(MetricDB).filter(MetricDB.hostname == hostname).order_by(MetricDB.timestamp.desc()).limit(50).all(); db.close(); return data

class NetworkProbe(BaseModel):
    ip: str
    hostname: Optional[str] = None
    latency_ms: Optional[float] = None
    open_ports: Optional[List[Any]] = []
    mac: Optional[str] = None
    device_type: Optional[str] = None
    vendor: Optional[str] = None
    timestamp: float
    reporter_hostname: Optional[str] = None

@app.post("/network-probe")
def post_network_probe(probes: List[NetworkProbe]):
    db = SessionLocal()
    try:
        for probe in probes:
            db.add(NetworkProbeDB(
                ip=probe.ip,
                hostname=probe.hostname,
                latency_ms=probe.latency_ms,
                open_ports=probe.open_ports,
                mac=probe.mac,
                device_type=probe.device_type,
                vendor=probe.vendor,
                timestamp=probe.timestamp,
                reporter_hostname=probe.reporter_hostname
            ))
        db.commit()
    finally:
        db.close()
    return {"status": "ok"}

@app.get("/network-probe/{ip}")
def get_network_probe(ip: str):
    """Get the last 60 probe records for a given IP (for latency history chart)"""
    encoded_ip = ip.replace("_", ".")
    db = SessionLocal()
    data = db.query(NetworkProbeDB).filter(NetworkProbeDB.ip == encoded_ip).order_by(NetworkProbeDB.timestamp.desc()).limit(60).all()
    db.close()
    return list(reversed(data))

@app.get("/network-probes/latest")
def get_latest_probes():
    """Get the most recent probe for every known IP"""
    db = SessionLocal()
    from sqlalchemy import text
    rows = db.execute(text("""
        SELECT np.* FROM network_probes np
        INNER JOIN (
            SELECT ip, MAX(timestamp) as max_ts FROM network_probes GROUP BY ip
        ) latest ON np.ip = latest.ip AND np.timestamp = latest.max_ts
    """)).fetchall()
    db.close()
    result = []
    for r in rows:
        result.append({
            "id": r.id, "ip": r.ip, "hostname": r.hostname,
            "latency_ms": r.latency_ms, "open_ports": r.open_ports,
            "mac": r.mac, "device_type": r.device_type, "vendor": r.vendor,
            "timestamp": r.timestamp, "reporter_hostname": r.reporter_hostname
        })
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
