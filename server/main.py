from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import time
import os
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
SQLALCHEMY_DATABASE_URL = "sqlite:///./sentinel.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class DeviceDB(Base):
    __tablename__ = "devices"
    hostname = Column(String, primary_key=True, index=True)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String, default="ONLINE")

class MetricDB(Base):
    __tablename__ = "metrics"
    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, ForeignKey("devices.hostname"))
    cpu_usage = Column(Float); ram_usage = Column(Float); disk_usage = Column(Float)
    uptime = Column(String); network = Column(JSON); processes = Column(JSON)
    timestamp = Column(Float)

class AlertDB(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String); message = Column(String); level = Column(String)
    timestamp = Column(Float)

Base.metadata.create_all(bind=engine)

# Tasks
async def monitor_offline_devices():
    while True:
        db = SessionLocal()
        try:
            timeout = datetime.datetime.utcnow() - datetime.timedelta(seconds=20)
            offline = db.query(DeviceDB).filter(DeviceDB.last_seen < timeout, DeviceDB.status == "ONLINE").all()
            for d in offline:
                d.status = "OFFLINE"
                db.add(AlertDB(hostname=d.hostname, message=f"Desconectado: {d.hostname}", level="CRITICAL", timestamp=time.time()))
                db.commit()
        finally: db.close()
        await asyncio.sleep(10)

@asynccontextmanager
async def lifespan(app: FastAPI):
    db = SessionLocal()
    try:
        if db.query(UserDB).count() == 0:
            h = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
            db.add(UserDB(email="admin@sentinel.com", hashed_password=h))
            db.commit()
    finally: db.close()
    asyncio.create_task(monitor_offline_devices())
    yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# Pydantic
class CreateUser(BaseModel): email: str; password: str
class Metrics(BaseModel):
    hostname: str; cpu_usage: float; ram_usage: float; disk_usage: float
    uptime: Optional[str] = "N/A"; network: Optional[Dict[str, Any]] = {}; processes: Optional[List[Any]] = []; timestamp: float

# Routes
@app.post("/login")
def login(data: Dict[str, str], db: Session = Depends(get_db)):
    u = db.query(UserDB).filter(UserDB.email == data["email"]).first()
    if not u or not bcrypt.checkpw(data["password"].encode(), u.hashed_password.encode()):
        raise HTTPException(status_code=401, detail="Error")
    return {"status": "ok"}

@app.get("/users")
def get_users(db: Session = Depends(get_db)):
    return db.query(UserDB).all()

@app.post("/users")
def create_user(data: CreateUser, db: Session = Depends(get_db)):
    if db.query(UserDB).filter(UserDB.email == data.email).first():
        raise HTTPException(status_code=400, detail="El correo ya existe")
    h = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
    db.add(UserDB(email=data.email, hashed_password=h))
    db.commit()
    return {"status": "ok"}

@app.delete("/users/{uid}")
def delete_user(uid: int, db: Session = Depends(get_db)):
    u = db.query(UserDB).filter(UserDB.id == uid).first()
    if u: db.delete(u); db.commit()
    return {"status": "ok"}

@app.post("/metrics")
def post_metrics(data: Metrics, db: Session = Depends(get_db)):
    d = db.query(DeviceDB).filter(DeviceDB.hostname == data.hostname).first()
    if not d: d = DeviceDB(hostname=data.hostname); db.add(d)
    d.status = "ONLINE"; d.last_seen = datetime.datetime.utcnow()
    db.add(MetricDB(**data.dict()))
    db.commit()
    return {"status": "ok", "commands": []}

@app.get("/devices")
def get_devices(db: Session = Depends(get_db)):
    return db.query(DeviceDB).all()

@app.get("/metrics/{hostname}")
def get_metrics(hostname: str, db: Session = Depends(get_db)):
    return db.query(MetricDB).filter(MetricDB.hostname == hostname).order_by(MetricDB.timestamp.desc()).limit(100).all()

@app.get("/history/{hostname}")
def get_history(hostname: str, db: Session = Depends(get_db)):
    return db.query(MetricDB).filter(MetricDB.hostname == hostname).order_by(MetricDB.timestamp.desc()).limit(500).all()

@app.get("/alerts")
def get_alerts(db: Session = Depends(get_db)):
    return db.query(AlertDB).order_by(AlertDB.timestamp.desc()).limit(50).all()

if __name__ == "__main__":
    import uvicorn
    p = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=p)
