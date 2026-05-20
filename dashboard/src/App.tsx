import React, { useEffect, useState } from 'react';
import { Activity, Cpu, Database, HardDrive, Monitor, AlertCircle, Server, Shield, Zap, LayoutDashboard, Settings, Bell, ChevronRight, ChevronLeft, Globe, Lock, User, LogOut, ArrowUp, ArrowDown, Clock, List, History, Mail, UserPlus, Trash2, ShieldAlert, Wifi, Info, CheckCircle2, XCircle, ShieldCheck, Battery, Eye, EyeOff, Network } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { NetworkMapView } from './NetworkMapView';
import { NetworkScannerView } from './NetworkScannerView';

interface DiscoveredDevice {
  ip: string;
  mac: string;
  hostname: string;
  type: string;
}

interface Device { 
  hostname: string; 
  last_seen: string; 
  status: 'ONLINE' | 'OFFLINE'; 
  active_connections?: string[]; 
  quarantine?: number; 
  network_map?: DiscoveredDevice[]; 
}
interface Metric { hostname: string; cpu_usage: number; ram_usage: number; disk_usage: number; uptime: string; network: any; processes: any[]; security_alerts: any[]; active_connections: string[]; timestamp: number; }

const API_URL = (import.meta.env.VITE_API_URL && !import.meta.env.VITE_API_URL.includes('dashboard.render.com'))
  ? import.meta.env.VITE_API_URL
  : (typeof window !== 'undefined' && window.location.hostname.includes('vercel.app') ? 'https://edr-sentinel-x.onrender.com' : 'http://localhost:8000');

const App = () => {
  const [metrics, setMetrics] = useState<Metric[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<string | null>(null);
  const [view, setView] = useState<'global' | 'dashboard' | 'security' | 'users' | 'network_map' | 'network_scanner'>('global');
  const [expandedProcs, setExpandedProcs] = useState(false);
  const [expandedConns, setExpandedConns] = useState(false);
  const [activeEngineInfo, setActiveEngineInfo] = useState<number | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [isAuthenticated, setIsAuthenticated] = useState(localStorage.getItem('sentinel_auth') === 'true');
  const [currentUser, setCurrentUser] = useState(localStorage.getItem('sentinel_user') || '');
  const [currentUserRole, setCurrentUserRole] = useState(localStorage.getItem('sentinel_role') || 'USER');
  const [showLogin, setShowLogin] = useState(false);

  const safeFetch = async (url: string) => { try { const res = await fetch(url); return res.ok ? await res.json() : null; } catch (e) { return null; } };
  const fetchAlerts = async () => { const d = await safeFetch(`${API_URL}/alerts`); if (d) setAlerts(d); };
  const fetchDevices = async () => { const d = await safeFetch(`${API_URL}/devices`); if (Array.isArray(d)) { setDevices(d); } };
  
  const fetchMetrics = async () => {
    if (!isAuthenticated || !selectedDevice) return;
    const d = await safeFetch(`${API_URL}/metrics/${selectedDevice}`);
    if (Array.isArray(d)) setMetrics(d.sort((a:any, b:any) => a.timestamp - b.timestamp));
  };

  const handleToggleQuarantine = async (hostname: string, enable: boolean) => {
      if (!confirm(enable ? "¿Estás seguro de aislar este equipo de la red?" : "¿Estás seguro de levantar el aislamiento de red?")) return;
      try {
          const res = await fetch(`${API_URL}/quarantine/${hostname}`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ enable })
          });
          if (res.ok) fetchDevices();
      } catch(e) {}
  };

  const handleDeleteAlert = async (id: number) => {
      try {
          const res = await fetch(`${API_URL}/alerts/${id}`, { method: 'DELETE' });
          if (res.ok) fetchAlerts();
      } catch(e) {}
  };

  useEffect(() => { if (isAuthenticated) { fetchDevices(); fetchAlerts(); const i = setInterval(() => { fetchDevices(); fetchAlerts(); }, 3000); return () => clearInterval(i); } }, [isAuthenticated]);
  useEffect(() => {
    if (devices.length > 0 && !selectedDevice) {
      setSelectedDevice(devices[0].hostname);
    }
  }, [devices, selectedDevice]);
  useEffect(() => { if (isAuthenticated && selectedDevice) { fetchMetrics(); const i = setInterval(fetchMetrics, 2000); return () => clearInterval(i); } }, [selectedDevice, isAuthenticated]);

  const latest = metrics.length > 0 ? metrics[metrics.length - 1] : null;
  const inventory = latest?.network || {};
  const currentDeviceObj = devices.find(d => d.hostname === selectedDevice);
  const deviceAlerts = Array.isArray(alerts) ? alerts.filter(a => a.hostname === selectedDevice) : [];
  
  const fwActive = inventory.fw_active !== false; 
  const avActive = inventory.av_active !== false;
  const licenseActive = inventory.license_active !== false;

  const predictiveAlerts = Array.isArray(alerts) ? alerts.filter(a => a.level === 'PREDICTIVE') : [];
  const filteredDevices = devices.filter(d => d?.hostname?.toLowerCase().includes(searchQuery?.toLowerCase() || ''));

  const realThreats = deviceAlerts.filter(a => 
    a.level === 'CRITICAL' && 
    !a?.message?.includes("FIREWALL") && 
    !a?.message?.includes("ANTIVIRUS") &&
    !a?.message?.includes("LICENCIA")
  );

  const EDR_ENGINES = [
      { id: 1, title: "Threat Intel (Red)", subtitle: "Escaneando Puertos", icon: <ShieldAlert className="text-green-500 mx-auto mb-2" size={24}/>, desc: "Vigila el tráfico de red en tiempo real. Si detecta que alguna de tus aplicaciones intenta abrir puertos secretos y peligrosos usados comúnmente por troyanos y malware (como 4444, 1337 o 666), te enviará una Alerta Crítica al instante." },
      { id: 2, title: "Anti Fuerza Bruta", subtitle: "Monitor de Logins", icon: <Lock className="text-green-500 mx-auto mb-2" size={24}/>, desc: "Lee silenciosamente el Visor de Eventos de Seguridad de Windows. Si detecta que han ocurrido múltiples intentos fallidos de inicio de sesión en los últimos 10 minutos (ya sea local o por Escritorio Remoto), alerta sobre un posible ataque de fuerza bruta." },
      { id: 3, title: "Heurística Procesos", subtitle: "Análisis de Ofuscación", icon: <Activity className="text-green-500 mx-auto mb-2" size={24}/>, desc: "Analiza el comportamiento de los programas. Si detecta herramientas del sistema (como PowerShell) intentando ocultar su ventana o ejecutando código ilegible y encriptado, lo bloquea y lo marca como un ataque 'Fileless' malicioso." },
      { id: 4, title: "Control USB", subtitle: "Detección de Hardware", icon: <HardDrive className="text-green-500 mx-auto mb-2" size={24}/>, desc: "Memoriza el hardware conectado. Si de repente alguien conecta una nueva memoria USB o disco externo no autorizado para extraer datos (o inyectar un BadUSB), el sistema registra la infracción y te avisa inmediatamente." }
  ];

  if (!isAuthenticated) {
      if (showLogin) return <Login onLogin={(email: string, role: string) => { 
          setIsAuthenticated(true); 
          setCurrentUser(email); 
          setCurrentUserRole(role);
          localStorage.setItem('sentinel_auth', 'true');
          localStorage.setItem('sentinel_user', email);
          localStorage.setItem('sentinel_role', role);
      }} onBack={() => setShowLogin(false)} />;
      return <Landing onLoginClick={() => setShowLogin(true)} />;
  }

  return (
    <div className="h-screen w-full text-white flex bg-[#010102] font-sans overflow-hidden">
      {/* LATERAL IZQUIERDA */}
      <aside className="w-64 bg-black/40 border-r border-white/5 p-6 flex flex-col z-20">
        <div className="flex flex-col items-center gap-3 mb-10 text-blue-500 font-black italic text-2xl tracking-tighter"><img src="https://raw.githubusercontent.com/Tino0rcg/sentinel/main/ChatGPT%20Image%2014%20may%202026%2C%2011_28_18%20p.m..png" alt="Sentinel Logo" className="h-24 mix-blend-screen" style={{ WebkitMaskImage: 'radial-gradient(circle, white 35%, transparent 75%)', maskImage: 'radial-gradient(circle, white 35%, transparent 75%)' }} /> SENTINEL-X</div>
        <nav className="space-y-1 mb-8">
          <NavItem icon={<Globe size={18}/>} label="Vista Global" active={view === 'global'} onClick={() => { setView('global'); setSelectedDevice(null); }} />
          <NavItem icon={<Network size={18}/>} label="Mapa de Red" active={view === 'network_map'} onClick={() => { setView('network_map'); setSelectedDevice(null); }} />
          <NavItem icon={<Wifi size={18}/>} label="Dispositivos en Red" active={view === 'network_scanner'} onClick={() => { setView('network_scanner'); setSelectedDevice(null); }} />
          <NavItem icon={<LayoutDashboard size={18}/>} label="Dashboard" active={view === 'dashboard'} onClick={() => setView('dashboard')} />
          <NavItem icon={<ShieldAlert size={18}/>} label="Seguridad" active={view === 'security'} onClick={() => setView('security')} badge={realThreats.length} />
          {currentUserRole === 'ADMIN' && (
             <NavItem icon={<UserPlus size={18}/>} label="Gestión Usuarios" active={view === 'users'} onClick={() => { setView('users'); setSelectedDevice(null); }} />
          )}
        </nav>
        <div className="flex-1 overflow-y-auto space-y-1">
          <p className="text-[10px] font-black opacity-20 mb-4 px-2 uppercase">Equipos Conectados</p>
          <input type="text" placeholder="Buscar equipo..." className="w-full bg-white/5 border border-white/10 p-2 mb-4 rounded-xl text-xs text-white" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} />
          {filteredDevices.map(d => (
            <button key={d.hostname} onClick={() => { setSelectedDevice(d.hostname); setView('dashboard'); }} className={`w-full flex items-center gap-3 p-3 rounded-xl transition-all ${selectedDevice === d.hostname ? 'bg-blue-600/20 text-blue-400' : 'opacity-40 hover:opacity-100'}`}>
              <div className={`w-2 h-2 rounded-full ${d.status === 'ONLINE' ? 'bg-green-500' : 'bg-red-500'}`}></div>
              <span className="text-xs font-bold truncate">{d.hostname}</span>
            </button>
          ))}
        </div>
        <div className="mt-auto pt-6 border-t border-white/5 flex items-center gap-3 overflow-hidden">
           <div className="w-8 h-8 rounded-full bg-blue-500/10 flex items-center justify-center text-blue-500 font-black text-xs uppercase">{currentUser?.charAt(0) || 'U'}</div>
           <div className="flex-1 text-[10px] font-bold opacity-30 truncate">{currentUser}</div>
           <button onClick={() => {
              localStorage.removeItem('sentinel_auth');
              localStorage.removeItem('sentinel_user');
              localStorage.removeItem('sentinel_role');
              setIsAuthenticated(false);
           }} className="text-white/20 hover:text-red-500 transition-colors p-2 rounded-xl hover:bg-white/5" title="Cerrar sesión">
              <LogOut size={16} />
           </button>
        </div>
      </aside>

      {/* CONTENIDO CENTRAL */}
      <main className="flex-1 flex overflow-hidden">
        {view === 'network_map' ? (
          <NetworkMapView 
              devices={devices} 
              onToggleQuarantine={handleToggleQuarantine} 
              currentUserRole={currentUserRole} 
          />
        ) : view === 'network_scanner' ? (
          <NetworkScannerView 
              devices={devices} 
              onRefresh={fetchDevices} 
          />
        ) : (
          <div className="flex-1 p-10 overflow-y-auto bg-[#010102]">
            <div className="max-w-6xl mx-auto">
              <header className="mb-10 flex justify-between items-end">
                 <div>
                    <div className="text-blue-500 text-[10px] font-black tracking-widest mb-1 uppercase">SISTEMA EDR ACTIVO</div>
                    <h2 className="text-6xl font-black tracking-tighter">{view === 'global' ? 'Vista Global' : view === 'users' ? 'Gestión de Personal' : selectedDevice}</h2>
                 </div>
                 {view !== 'global' && view !== 'users' && (
                 <div className="flex flex-col items-end gap-3">
                    {currentUserRole === 'ADMIN' && currentDeviceObj && (
                        <button onClick={() => handleToggleQuarantine(currentDeviceObj.hostname, !currentDeviceObj.quarantine)} className={`px-4 py-2 rounded-xl text-[10px] font-black transition-all ${currentDeviceObj.quarantine ? 'bg-red-500 hover:bg-red-600 text-white animate-pulse shadow-lg shadow-red-500/20' : 'bg-transparent hover:bg-white/5 text-red-500 border border-red-500/20 hover:border-red-500/50'}`}>
                           {currentDeviceObj.quarantine ? '⛔ LEVANTAR CUARENTENA' : '🚨 AISLAR EQUIPO'}
                        </button>
                    )}
                    <div className="flex gap-2">
                        <StatusIcon icon={<Shield size={16}/>} label="AV" active={avActive} />
                        <StatusIcon icon={<Lock size={16}/>} label="FW" active={fwActive} />
                        <StatusIcon icon={<Battery size={16}/>} label="BAT" active={true} info={inventory.battery !== 'N/A' ? `${inventory.battery}%` : 'N/A'} />
                    </div>
                 </div>
               )}
            </header>

            {view === 'global' ? (
               <div className="space-y-8">
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                      <div className="bg-white/5 p-6 rounded-[32px] border border-white/5 text-center shadow-lg">
                          <p className="text-[10px] font-black opacity-30 uppercase tracking-widest mb-2">Equipos Totales</p>
                          <div className="text-4xl font-black">{devices.length}</div>
                      </div>
                      <div className="bg-white/5 p-6 rounded-[32px] border border-white/5 text-center shadow-lg">
                          <p className="text-[10px] font-black opacity-30 uppercase tracking-widest mb-2 text-green-500">En Línea</p>
                          <div className="text-4xl font-black text-green-500">{devices.filter(d => d.status === 'ONLINE').length}</div>
                      </div>
                      <div className="bg-white/5 p-6 rounded-[32px] border border-white/5 text-center shadow-lg">
                          <p className="text-[10px] font-black opacity-30 uppercase tracking-widest mb-2 text-red-500">Inactivos</p>
                          <div className="text-4xl font-black text-red-500">{devices.filter(d => d.status === 'OFFLINE').length}</div>
                      </div>
                      <div className="bg-white/5 p-6 rounded-[32px] border border-white/5 text-center shadow-lg">
                          <p className="text-[10px] font-black opacity-30 uppercase tracking-widest mb-2 text-orange-500">Alertas Predictivas</p>
                          <div className="text-4xl font-black text-orange-500">{predictiveAlerts.length}</div>
                      </div>
                  </div>
                  
                  {predictiveAlerts.length > 0 && (
                      <div className="bg-orange-500/10 border border-orange-500/20 p-8 rounded-[40px] shadow-2xl">
                          <h3 className="text-xl font-black mb-6 text-orange-500 flex items-center gap-2"><Clock size={20}/> Pronóstico de Salud (Predictivo)</h3>
                          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                              {predictiveAlerts.map((a, i) => (
                                  <div key={i} className="bg-white/5 p-4 rounded-2xl border border-white/10 flex items-start gap-4">
                                      <div className="text-orange-500 mt-1"><AlertCircle size={20}/></div>
                                      <div>
                                          <div className="text-xs font-black uppercase text-white/50 mb-1">{a.hostname}</div>
                                          <div className="text-sm font-bold">{a.message}</div>
                                          <div className="text-[9px] font-black uppercase opacity-30 mt-2">{new Date(a.timestamp * 1000).toLocaleString()}</div>
                                      </div>
                                  </div>
                              ))}
                          </div>
                      </div>
                  )}

                  <div className="bg-white/5 border border-white/5 p-8 rounded-[40px] shadow-2xl">
                      <h3 className="text-sm font-black opacity-30 uppercase mb-6 flex items-center gap-2"><Monitor size={16}/> Flota de Equipos</h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                          {devices.map(d => (
                              <button key={d.hostname} onClick={() => { setSelectedDevice(d.hostname); setView('dashboard'); }} className="p-4 bg-black/40 border border-white/5 rounded-2xl flex items-center justify-between hover:bg-white/5 transition-colors">
                                  <div className="flex items-center gap-3">
                                      <div className={`w-2 h-2 rounded-full ${d.status === 'ONLINE' ? 'bg-green-500' : 'bg-red-500'}`}></div>
                                      <span className="text-sm font-bold">{d.hostname}</span>
                                  </div>
                                  <ChevronRight size={16} className="text-white/20"/>
                              </button>
                          ))}
                      </div>
                  </div>

                  <div className="bg-white/5 border border-white/5 p-8 rounded-[40px] shadow-2xl mt-8">
                       <h3 className="text-sm font-black opacity-30 uppercase mb-6 flex items-center gap-2"><Zap size={16}/> Motores EDR Avanzados (En Línea)</h3>
                       <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                           {EDR_ENGINES.map(engine => (
                               <button 
                                   key={engine.id}
                                   onClick={() => setActiveEngineInfo(activeEngineInfo === engine.id ? null : engine.id)}
                                   className={`p-4 bg-black/40 border rounded-2xl text-center shadow-lg transition-all outline-none ${activeEngineInfo === engine.id ? 'border-green-500/50 bg-green-500/10 shadow-green-500/20' : 'border-green-500/20 shadow-green-500/5 hover:bg-white/5 hover:border-green-500/40'}`}
                               >
                                   {engine.icon}
                                   <div className="text-xs font-bold text-white">{engine.title}</div>
                                   <div className="text-[9px] opacity-40 uppercase mt-1">{engine.subtitle}</div>
                               </button>
                           ))}
                       </div>
                       {activeEngineInfo && (
                           <div className="mt-6 p-8 bg-[#010102] border border-green-500/30 rounded-[32px] animate-in fade-in slide-in-from-top-4 shadow-2xl shadow-green-500/10">
                               {EDR_ENGINES.filter(e => e.id === activeEngineInfo).map(e => (
                                   <div key={e.id} className="flex gap-6 items-start">
                                       <div className="mt-2 opacity-50">{e.icon}</div>
                                       <div className="text-left">
                                           <h4 className="font-black text-green-500 text-xl mb-3 tracking-tight">{e.title}</h4>
                                           <p className="text-sm text-white/70 leading-relaxed font-medium">{e.desc}</p>
                                       </div>
                                   </div>
                               ))}
                           </div>
                       )}
                   </div>
               </div>
             ) : view === 'users' ? (
                <UsersView API_URL={API_URL} />
            ) : view === 'security' ? (
               <div className="bg-white/5 border border-white/10 p-8 rounded-[40px] shadow-2xl">
                  <h3 className="text-xl font-black mb-8 flex items-center gap-2 text-red-500"><AlertCircle size={24}/> Alertas de Seguridad</h3>
                  <div className="space-y-3">
                     {deviceAlerts.map((a, i) => (
                        <div key={i} className={`p-6 rounded-3xl border flex justify-between items-start ${a.level === 'CRITICAL' ? 'bg-red-500/10 border-red-500/20' : a.level === 'WARNING' ? 'bg-orange-500/10 border-orange-500/20' : 'bg-white/5 border-white/10'}`}>
                           <div>
                               <p className="font-bold text-lg">{a.message}</p>
                               <p className="text-[10px] opacity-30 mt-2 font-black uppercase">{new Date(a.timestamp * 1000).toLocaleString()}</p>
                           </div>
                           <button onClick={() => handleDeleteAlert(a.id)} className="text-white/20 hover:text-green-500 transition-colors p-2 rounded-full hover:bg-white/5" title="Marcar como resuelta">
                               <CheckCircle2 size={24}/>
                           </button>
                        </div>
                     ))}
                     {deviceAlerts.length === 0 && <div className="py-20 text-center opacity-20 italic">No hay registros de seguridad.</div>}
                  </div>
               </div>
            ) : (
               <div className="space-y-8">
                  {/* MÉTRICAS TOP */}
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                    <StatCard label="CPU" value={latest?.cpu_usage} color="blue" />
                    <StatCard label="RAM" value={latest?.ram_usage} color="purple" />
                    <StatCard label="DISCO" value={latest?.disk_usage} color="orange" />
                    <div className="bg-white/5 border border-white/5 rounded-[32px] p-6 flex flex-col justify-around text-center">
                       <div><p className="text-[9px] font-black opacity-20 mb-1 uppercase">Seguridad</p><span className={`text-xl font-black ${realThreats.length > 0 || !fwActive || !avActive ? 'text-red-500 animate-pulse' : 'text-green-500'}`}>{realThreats.length > 0 || !fwActive || !avActive ? 'REVISIÓN' : 'ÓPTIMO'}</span></div>
                       <div className="pt-3 border-t border-white/5"><p className="text-[9px] font-black opacity-20 mb-1 uppercase">Estado PC</p><span className={`text-xl font-black ${latest?.cpu_usage > 90 ? 'text-orange-500' : 'text-blue-400'}`}>{latest?.cpu_usage > 90 ? 'CRÍTICO' : 'ESTABLE'}</span></div>
                    </div>
                  </div>

                  {/* ANCHO DE BANDA EN TIEMPO REAL */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="bg-white/5 border border-white/5 rounded-[32px] p-6 flex items-center justify-between shadow-lg relative overflow-hidden group hover:border-blue-500/30 transition-all">
                          <div className="flex items-center gap-4">
                              <div className="w-12 h-12 bg-blue-500/10 rounded-2xl flex items-center justify-center text-blue-400 group-hover:scale-110 transition-transform">
                                  <ArrowDown size={24} />
                              </div>
                              <div>
                                  <p className="text-[10px] font-black opacity-30 uppercase tracking-widest">Tráfico de Bajada (Download)</p>
                                  <h4 className="text-3xl font-black mt-1 text-white">{inventory.download_speed || '0.0 KB/s'}</h4>
                              </div>
                          </div>
                          <div className="text-[10px] font-black px-3 py-1 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
                              RECIBIENDO
                          </div>
                      </div>
                      <div className="bg-white/5 border border-white/5 rounded-[32px] p-6 flex items-center justify-between shadow-lg relative overflow-hidden group hover:border-purple-500/30 transition-all">
                          <div className="flex items-center gap-4">
                              <div className="w-12 h-12 bg-purple-500/10 rounded-2xl flex items-center justify-center text-purple-400 group-hover:scale-110 transition-transform">
                                  <ArrowUp size={24} />
                              </div>
                              <div>
                                  <p className="text-[10px] font-black opacity-30 uppercase tracking-widest">Tráfico de Subida (Upload)</p>
                                  <h4 className="text-3xl font-black mt-1 text-white">{inventory.upload_speed || '0.0 KB/s'}</h4>
                              </div>
                          </div>
                          <div className="text-[10px] font-black px-3 py-1 rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/20">
                              ENVIANDO
                          </div>
                      </div>
                  </div>

                  {/* GRÁFICA */}
                  <div className="bg-white/5 border border-white/5 rounded-[40px] p-10 h-[320px]">
                     <h3 className="font-black mb-8 flex items-center gap-2"><Activity size={20}/> Historial de Rendimiento</h3>
                     <ResponsiveContainer width="100%" height="80%">
                         <AreaChart data={metrics}>
                             <Tooltip 
                                 contentStyle={{ backgroundColor: 'rgba(0,0,0,0.8)', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '16px', color: '#fff' }}
                                 itemStyle={{ fontSize: '12px', fontWeight: '900' }}
                                 labelStyle={{ display: 'none' }}
                                 formatter={(value: number, name: string) => [`${value}%`, name === 'cpu_usage' ? 'CPU' : 'RAM']}
                             />
                             <Area type="monotone" dataKey="cpu_usage" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.1} strokeWidth={4} />
                             <Area type="monotone" dataKey="ram_usage" stroke="#a855f7" fill="transparent" strokeWidth={4} />
                         </AreaChart>
                     </ResponsiveContainer>
                  </div>

                  {/* PROCESOS Y RED */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 pb-10">
                     <div className="bg-white/5 border border-white/5 rounded-[40px] p-8">
                         <h3 className="text-xs font-black opacity-30 mb-6 uppercase flex items-center gap-2"><List size={14}/> Procesos Top</h3>
                         <div className="space-y-2">{(expandedProcs ? latest?.processes : latest?.processes?.slice(0, 5))?.map((p:any, i:number) => (
                            <div key={i} className="flex justify-between p-4 bg-white/5 rounded-2xl border border-white/5 text-xs font-bold"><span>{p.name}</span><span className="text-blue-500">{p.cpu.toFixed(1)}%</span></div>
                         ))}
                         {latest?.processes && latest.processes.length > 5 && (
                             <button onClick={() => setExpandedProcs(!expandedProcs)} className="w-full mt-2 p-3 text-[10px] font-black uppercase tracking-widest text-white/30 hover:text-white hover:bg-white/5 rounded-xl transition-colors border border-transparent hover:border-white/10">
                                 {expandedProcs ? 'Ocultar Lista' : `Expandir ${latest.processes.length - 5} Más`}
                             </button>
                         )}
                         </div>
                     </div>
                      <div className="bg-white/5 border border-white/5 rounded-[40px] p-8">
                          <div className="flex justify-between items-center mb-6">
                              <h3 className="text-xs font-black opacity-30 uppercase flex items-center gap-2"><Globe size={14}/> Conexiones Red</h3>
                              <div className="flex gap-4 text-[10px] font-black">
                                  <span className="flex items-center gap-1 text-blue-400"><ArrowUp size={12}/> {inventory.upload_speed || '0 KB/s'}</span>
                                  <span className="flex items-center gap-1 text-purple-400"><ArrowDown size={12}/> {inventory.download_speed || '0 KB/s'}</span>
                              </div>
                          </div>
                         <div className="space-y-2">{(expandedConns ? currentDeviceObj?.active_connections : currentDeviceObj?.active_connections?.slice(0, 5))?.map((conn:string, i:number) => (
                            <div key={i} className="p-4 bg-white/5 rounded-2xl border border-white/5 text-[10px] font-black text-white/40">{conn}</div>
                         ))}
                         {currentDeviceObj?.active_connections && currentDeviceObj.active_connections.length > 5 && (
                             <button onClick={() => setExpandedConns(!expandedConns)} className="w-full mt-2 p-3 text-[10px] font-black uppercase tracking-widest text-white/30 hover:text-white hover:bg-white/5 rounded-xl transition-colors border border-transparent hover:border-white/10">
                                 {expandedConns ? 'Ocultar Lista' : `Expandir ${currentDeviceObj.active_connections.length - 5} Más`}
                             </button>
                         )}
                        {(!currentDeviceObj?.active_connections || currentDeviceObj.active_connections.length === 0) && (
                            <div className="text-center opacity-30 italic text-xs py-4">No hay conexiones registradas</div>
                        )}
                        </div>
                     </div>
                  </div>
               </div>
            )}
            </div>
          </div>
        )}

        {/* AUDITORÍA DERECHA */}
        {view !== 'global' && view !== 'network_map' && view !== 'users' && (
        <aside className="w-80 bg-black/40 border-l border-white/5 p-8 flex flex-col overflow-y-auto">
           <h3 className="text-[10px] font-black mb-8 opacity-40 tracking-widest uppercase">Auditoría Técnica</h3>
           <div className="space-y-8">
              <AuditItem label="Sistema Operativo" value={inventory.os} icon={<Monitor size={16}/>} />
              <AuditItem label="Procesador" value={inventory.cpu} icon={<Cpu size={16}/>} />
              <AuditItem label="Memoria Instalada" value={inventory.ram_total} icon={<Database size={16}/>} />
              <AuditItem label="Almacenamiento (Disco)" value={inventory.disk_total || 'N/A'} icon={<HardDrive size={16}/>} />
              <AuditItem label="Estado Batería" value={inventory.battery !== 'N/A' ? `${inventory.battery}%` : 'Desktop / AC'} icon={<Battery size={16}/>} />
              <AuditItem label="Ancho de Banda (Subida)" value={inventory.upload_speed || '0.0 KB/s'} icon={<ArrowUp size={16} className="text-blue-400"/>} />
              <AuditItem label="Ancho de Banda (Bajada)" value={inventory.download_speed || '0.0 KB/s'} icon={<ArrowDown size={16} className="text-purple-400"/>} />
              
              <div className="pt-10 border-t border-white/5">
                 <p className="text-[10px] font-black opacity-20 mb-6 uppercase">Escudos Activos</p>
                 <ShieldRow label="Windows Defender" active={avActive} />
                 <ShieldRow label="Firewall Activo" active={fwActive} />
                 <ShieldRow label="Licencia Original" active={licenseActive} />
              </div>
           </div>
           <div className="mt-auto p-6 bg-blue-600/10 border border-blue-500/20 rounded-[32px] text-center">
              <ShieldCheck className="mx-auto mb-3 text-blue-500" size={24} />
              <div className="text-[10px] font-black text-blue-500 uppercase tracking-widest">Sentinel 360</div>
              <div className="text-[8px] font-bold opacity-30 mt-1 uppercase">Hardware & Software Verified</div>
           </div>
        </aside>
        )}
      </main>
      <style dangerouslySetInnerHTML={{ __html: `* { font-family: 'Outfit', sans-serif; } body { background: #010102; margin: 0; overflow: hidden; }`}} />
    </div>
  );
};

const StatCard = ({ label, value, color }: any) => (
  <div className="bg-white/5 border border-white/5 rounded-[32px] p-6 text-center shadow-lg">
    <p className="text-[9px] font-black opacity-20 mb-2 uppercase tracking-widest">{label}</p>
    <div className="flex items-baseline justify-center gap-1"><span className="text-3xl font-black">{value || '0'}</span><span className="text-xs opacity-20 font-bold">%</span></div>
    <div className="mt-4 h-1.5 w-full bg-white/5 rounded-full overflow-hidden"><div className={`h-full bg-${color}-500`} style={{width: `${value}%`}}></div></div>
  </div>
);

const AuditItem = ({ label, value, icon }: any) => (
  <div className="flex gap-4">
    <div className="w-10 h-10 bg-white/5 rounded-2xl flex items-center justify-center text-white/40">{icon}</div>
    <div className="flex-1 overflow-hidden"><p className="text-[8px] font-black opacity-20 uppercase mb-0.5">{label}</p><p className="text-xs font-bold text-white/80 leading-tight truncate">{value || '---'}</p></div>
  </div>
);

const ShieldRow = ({ label, active }: any) => (
  <div className="flex items-center justify-between mb-4">
    <span className="text-xs font-bold text-white/40">{label}</span>
    {active ? <CheckCircle2 size={16} className="text-green-500" /> : <XCircle size={16} className="text-red-500 animate-pulse" />}
  </div>
);

const StatusIcon = ({ icon, label, active, info }: any) => (
  <div className={`p-3 rounded-2xl border flex flex-col items-center gap-1 ${active ? 'bg-green-500/10 border-green-500/20 text-green-500' : 'bg-red-500/10 border-red-500/20 text-red-500'}`}>
    {icon} <span className="text-[8px] font-black uppercase">{info || label}</span>
  </div>
);

const Landing = ({ onLoginClick }: any) => (
  <div className="min-h-screen w-full bg-[#010102] text-white relative overflow-x-hidden font-sans selection:bg-blue-500/30 pb-20">
    {/* Fondo Estrellado / Grid */}
    <div className="absolute inset-0 bg-[linear-gradient(to_right,#ffffff0a_1px,transparent_1px),linear-gradient(to_bottom,#ffffff0a_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)]"></div>

    <div className="absolute top-10 left-10 flex items-center gap-4 z-50">
        <img src="https://raw.githubusercontent.com/Tino0rcg/sentinel/main/ChatGPT%20Image%2014%20may%202026%2C%2011_28_18%20p.m..png" alt="Sentinel Logo" className="h-20 md:h-28 mix-blend-screen hover:scale-105 transition-transform" style={{ WebkitMaskImage: 'radial-gradient(circle, white 35%, transparent 75%)', maskImage: 'radial-gradient(circle, white 35%, transparent 75%)' }} />
        <span className="text-white font-black italic tracking-tighter text-3xl">SENTINEL-X</span>
    </div>

    {/* Efectos de Luz */}
    <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-blue-600/20 blur-[150px] rounded-full pointer-events-none"></div>
    <div className="absolute bottom-0 right-0 w-[600px] h-[600px] bg-purple-600/10 blur-[120px] rounded-full pointer-events-none"></div>

    <div className="relative z-10 flex flex-col items-center pt-24 px-6 max-w-7xl mx-auto">
      <div className="inline-flex items-center gap-3 px-6 py-3 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs md:text-sm font-black uppercase tracking-widest mb-12 shadow-[0_0_30px_rgba(59,130,246,0.15)] animate-in slide-in-from-top-4 duration-700">
        <div className="w-2 h-2 rounded-full bg-blue-400 animate-ping"></div> Plataforma EDR Activa
      </div>
      
      <h1 className="text-6xl md:text-[7rem] font-black tracking-tighter mb-8 leading-[0.9] text-center animate-in fade-in slide-in-from-bottom-8 duration-700 delay-100">
        Monitoreo Inteligente <br/>
        <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-indigo-500 to-purple-500">Para tu Infraestructura.</span>
      </h1>
      
      <p className="text-lg md:text-2xl text-white/50 mb-16 max-w-3xl mx-auto font-medium text-center leading-relaxed animate-in fade-in slide-in-from-bottom-8 duration-700 delay-200">
        Anticipa fallos críticos, aísla amenazas en milisegundos y mantén el control absoluto de tu flota corporativa con la inteligencia artificial más avanzada del mercado.
      </p>

      <div className="flex flex-col sm:flex-row gap-6 animate-in fade-in zoom-in-95 duration-700 delay-300 w-full sm:w-auto">
          <button onClick={onLoginClick} className="bg-white text-black hover:bg-gray-200 px-10 py-5 rounded-[2rem] font-black text-lg transition-all shadow-2xl flex items-center justify-center gap-3 hover:scale-105 w-full sm:w-auto">
            Acceso al Sistema <ChevronRight size={24} />
          </button>
      </div>

      {/* Bento Grid de Características */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-32 w-full animate-in fade-in duration-1000 delay-500 relative">
          <div className="bg-gradient-to-b from-white/5 to-transparent border border-white/10 p-10 rounded-[40px] backdrop-blur-sm hover:border-blue-500/30 transition-colors group">
              <ShieldAlert className="text-blue-500 mb-8 group-hover:scale-110 transition-transform" size={48}/>
              <h3 className="text-2xl font-black mb-4">Threat Intelligence</h3>
              <p className="text-white/40 font-medium leading-relaxed">Análisis heurístico avanzado que detecta y bloquea comandos ofuscados, intentos de fuerza bruta y conexiones peligrosas de red.</p>
          </div>
          <div className="bg-gradient-to-b from-white/5 to-transparent border border-white/10 p-10 rounded-[40px] backdrop-blur-sm hover:border-purple-500/30 transition-colors group">
              <Activity className="text-purple-500 mb-8 group-hover:scale-110 transition-transform" size={48}/>
              <h3 className="text-2xl font-black mb-4">Auditoría Predictiva</h3>
              <p className="text-white/40 font-medium leading-relaxed">Modelos estadísticos aplicados al hardware. Predice fallos de almacenamiento y desbordamientos de memoria antes de que ocurran.</p>
          </div>
          <div className="bg-gradient-to-b from-white/5 to-transparent border border-white/10 p-10 rounded-[40px] backdrop-blur-sm hover:border-blue-500/30 transition-colors group">
              <Lock className="text-blue-500 mb-8 group-hover:scale-110 transition-transform" size={48}/>
              <h3 className="text-2xl font-black mb-4">Aislamiento Cero</h3>
              <p className="text-white/40 font-medium leading-relaxed">Cuarentena remota con un solo clic. Corta el acceso a internet de cualquier equipo infectado de forma instantánea sin perder telemetría.</p>
          </div>
      </div>
    </div>

    {/* Copyright Fijo */}
    <div className="fixed bottom-6 w-full text-center z-50 pointer-events-none">
        <p className="text-white/30 text-[9px] font-black tracking-[0.3em] uppercase">
            © 2026 Online System — Todos los derechos reservados.
        </p>
    </div>
  </div>
);

const Login = ({ onLogin, onBack }: any) => {
  const [data, setData] = useState({ email: '', password: '' });
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      if (res.ok) {
        const json = await res.json();
        onLogin(json.email, json.role);
      } else {
        alert("Credenciales inválidas");
      }
    } catch (e) {
      alert("Error de conexión con el servidor");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="h-screen w-full bg-[#010102] flex overflow-hidden font-sans">
      {/* LADO IZQUIERDO: Branding & Visuals */}
      <div className="hidden lg:flex w-1/2 relative bg-[#020205] border-r border-white/5 items-center justify-center p-20 overflow-hidden">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_30%,#1e3a8a_0%,transparent_50%)] opacity-20"></div>
          <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 mix-blend-soft-light"></div>
          
          <div className="relative z-10 text-center animate-in fade-in slide-in-from-left-8 duration-1000">
              <img 
                src="https://raw.githubusercontent.com/Tino0rcg/sentinel/main/ChatGPT%20Image%2014%20may%202026%2C%2011_28_18%20p.m..png" 
                alt="Sentinel Logo" 
                className="h-64 mx-auto mb-12 drop-shadow-[0_0_50px_rgba(59,130,246,0.2)] mix-blend-screen" 
                style={{ WebkitMaskImage: 'radial-gradient(circle, white 35%, transparent 75%)', maskImage: 'radial-gradient(circle, white 35%, transparent 75%)' }}
              />
              <h2 className="text-5xl font-black tracking-tighter italic text-white mb-4">SENTINEL-X</h2>
              <div className="h-1 w-24 bg-blue-600 mx-auto rounded-full mb-8"></div>
              <p className="text-white/40 text-lg font-medium max-w-sm mx-auto leading-relaxed">
                  Protección de infraestructuras críticas y monitoreo de flota en tiempo real con inteligencia predictiva.
              </p>
          </div>
          
          <div className="absolute bottom-10 left-10 text-white/10 text-xs font-bold tracking-[0.5em]">
              S.E.N.T.I.N.E.L VERSION 2.0.26
          </div>
      </div>

      {/* LADO DERECHO: Formulario de Login */}
      <div className="w-full lg:w-1/2 flex flex-col items-center justify-center p-8 md:p-20 relative">
        <button 
          onClick={onBack} 
          className="absolute top-10 right-10 text-white/30 hover:text-white transition-all flex items-center gap-2 text-xs font-black tracking-widest group"
        >
          VOLVER AL INICIO <ChevronRight size={16} className="group-hover:translate-x-1 transition-transform" />
        </button>

        <div className="w-full max-w-md animate-in fade-in slide-in-from-bottom-6 duration-700">
          <div className="mb-12">
            <h3 className="text-4xl font-black mb-3">Bienvenido.</h3>
            <p className="text-white/40 font-medium">Ingresa tus credenciales para acceder al centro de comando de seguridad.</p>
          </div>

          <form onSubmit={handleLogin} className="space-y-6">
            <div className="space-y-2">
              <label className="text-[10px] font-black text-white/30 uppercase tracking-[0.2em] ml-1">Identidad Digital</label>
              <div className="relative group">
                <User className="absolute left-5 top-1/2 -translate-y-1/2 text-blue-500 z-10" size={24} />
                <input 
                  type="email" 
                  placeholder="admin@sentinel.com" 
                  required 
                  onChange={e => setData({...data, email: e.target.value})} 
                  className="w-full bg-white/[0.03] border border-white/10 p-5 pl-14 rounded-2xl text-white outline-none focus:border-blue-500 focus:bg-blue-500/5 transition-all text-sm font-medium" 
                />
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-[10px] font-black text-white/30 uppercase tracking-[0.2em] ml-1">Clave de Acceso</label>
              <div className="relative group">
                <Lock className="absolute left-5 top-1/2 -translate-y-1/2 text-blue-500 z-10" size={24} />
                <input 
                  type={showPassword ? "text" : "password"} 
                  placeholder="••••••••" 
                  required 
                  onChange={e => setData({...data, password: e.target.value})} 
                  className="w-full bg-white/[0.03] border border-white/10 p-5 pl-14 pr-14 rounded-2xl text-white outline-none focus:border-blue-500 focus:bg-blue-500/5 transition-all text-sm font-medium" 
                />
                <button 
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-5 top-1/2 -translate-y-1/2 text-blue-500 hover:text-blue-400 transition-colors z-20"
                >
                  {showPassword ? <EyeOff size={22} /> : <Eye size={22} />}
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between text-xs font-bold text-white/30 px-1">
                <label className="flex items-center gap-2 cursor-pointer hover:text-white transition-colors">
                    <input type="checkbox" className="rounded border-white/10 bg-white/5" /> Recordarme
                </label>
            </div>

            <button 
              type="submit" 
              disabled={loading}
              className="w-full bg-blue-600 p-6 rounded-2xl font-black text-white hover:bg-blue-500 transition-all shadow-2xl shadow-blue-600/30 active:scale-[0.99] disabled:opacity-50 flex items-center justify-center gap-3 text-lg"
            >
              {loading ? (
                  <Activity size={24} className="animate-spin" />
              ) : (
                  <>AUTENTICAR IDENTIDAD <ChevronRight size={20} /></>
              )}
            </button>
          </form>

          <div className="mt-20 pt-10 border-t border-white/5 flex items-center justify-between opacity-20 group hover:opacity-100 transition-opacity">
              <div className="text-[9px] font-black tracking-widest uppercase">Encriptación RSA 4096-bit</div>
              <div className="text-[9px] font-black tracking-widest uppercase">Online System © 2026</div>
          </div>
        </div>
      </div>
    </div>
  );
};

const UsersView = ({ API_URL }: any) => {
    const [usersList, setUsersList] = useState<any[]>([]);
    const [newUser, setNewUser] = useState({ email: '', password: 'sentinel123', role: 'USER' });

    const fetchUsersList = async () => {
        try {
            const res = await fetch(`${API_URL}/users`);
            if (res.ok) setUsersList(await res.json());
        } catch(e) {}
    };

    useEffect(() => { fetchUsersList(); }, []);

    const handleCreateUser = async (e: any) => {
        e.preventDefault();
        try {
            const res = await fetch(`${API_URL}/users`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(newUser)
            });
            if (res.ok) {
                fetchUsersList();
                setNewUser({ email: '', password: 'sentinel123', role: 'USER' });
                alert("Usuario creado exitosamente");
            } else {
                alert("Error: El usuario probablemente ya existe.");
            }
        } catch(e) {
            alert("Error de red");
        }
    };

    const handleDeleteUser = async (id: number) => {
        if (!confirm("¿Eliminar usuario definitivamente?")) return;
        try {
            const res = await fetch(`${API_URL}/users/${id}`, { method: 'DELETE' });
            if (res.ok) fetchUsersList();
        } catch(e) {}
    };

    return (
        <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <div className="bg-white/5 border border-white/10 p-8 rounded-[40px] shadow-2xl">
                <h3 className="text-xl font-black mb-8 flex items-center gap-2 text-blue-500"><UserPlus size={24}/> Crear Nuevo Usuario</h3>
                <form onSubmit={handleCreateUser} className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
                    <div>
                        <label className="text-[10px] font-black opacity-30 uppercase block mb-2">Email del Usuario</label>
                        <input type="email" required value={newUser.email} onChange={e => setNewUser({...newUser, email: e.target.value})} className="w-full bg-black/40 border border-white/10 p-4 rounded-2xl text-sm outline-none focus:border-blue-500" placeholder="usuario@empresa.com" />
                    </div>
                    <div>
                        <label className="text-[10px] font-black opacity-30 uppercase block mb-2">Contraseña Inicial</label>
                        <input type="text" required value={newUser.password} onChange={e => setNewUser({...newUser, password: e.target.value})} className="w-full bg-black/40 border border-white/10 p-4 rounded-2xl text-sm outline-none focus:border-blue-500" />
                    </div>
                    <div>
                        <label className="text-[10px] font-black opacity-30 uppercase block mb-2">Permisos (Rol)</label>
                        <select value={newUser.role} onChange={e => setNewUser({...newUser, role: e.target.value})} className="w-full bg-black/40 border border-white/10 p-4 rounded-2xl text-sm text-white outline-none focus:border-blue-500 appearance-none">
                            <option value="USER">Usuario (Visualizador)</option>
                            <option value="ADMIN">Administrador (Control Total)</option>
                        </select>
                    </div>
                    <button type="submit" className="bg-blue-600 text-white font-black p-4 rounded-2xl hover:bg-blue-500 transition-colors shadow-lg shadow-blue-500/20">CREAR PERFIL</button>
                </form>
            </div>

            <div className="bg-white/5 border border-white/10 p-8 rounded-[40px] shadow-2xl">
                <h3 className="text-xl font-black mb-8 flex items-center gap-2"><User size={24}/> Personal Autorizado</h3>
                <div className="space-y-3">
                    {usersList.map((u, i) => (
                        <div key={i} className="flex items-center justify-between p-5 bg-black/40 rounded-3xl border border-white/5 hover:border-white/10 transition-colors">
                            <div>
                                <div className="font-bold text-lg">{u.email}</div>
                                <div className={`text-[10px] font-black uppercase mt-1 tracking-widest ${u.role === 'ADMIN' ? 'text-red-500' : 'text-blue-500'}`}>{u.role}</div>
                            </div>
                            <button onClick={() => handleDeleteUser(u.id)} className="w-12 h-12 rounded-2xl flex items-center justify-center bg-red-500/10 text-red-500 hover:bg-red-500 hover:text-white transition-all"><Trash2 size={20}/></button>
                        </div>
                    ))}
                    {usersList.length === 0 && <p className="text-center opacity-30 italic">No hay usuarios registrados</p>}
                </div>
            </div>
        </div>
    );
};

const NavItem = ({ icon, label, active, onClick, badge }: any) => (
  <button onClick={onClick} className={`w-full flex items-center gap-4 p-4 rounded-2xl ${active ? 'bg-white/10 text-white font-black' : 'text-white/30 hover:bg-white/5'}`}>
    {icon} <span className="text-sm">{label}</span>
    {badge > 0 && <span className="ml-auto bg-red-600 text-[10px] px-2 py-0.5 rounded-full">{badge}</span>}
  </button>
);

export default App;
