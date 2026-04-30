import React, { useEffect, useState } from 'react';
import { Activity, Cpu, Database, HardDrive, Monitor, AlertCircle, Server, Shield, Zap, LayoutDashboard, Settings, Bell, ChevronRight, Globe, Lock, User, LogOut, ArrowUp, ArrowDown, Clock, List, History, Mail, UserPlus, Trash2, CheckCircle } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface Device { hostname: string; last_seen: string; status: 'ONLINE' | 'OFFLINE'; }
interface Metric { hostname: string; cpu_usage: number; ram_usage: number; disk_usage: number; uptime: string; network: { sent_kb: number; recv_kb: number }; processes: { name: string; cpu: number; ram: number }[]; timestamp: number; }
interface UserProfile { id: number; email: string; }

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const App = () => {
  const [metrics, setMetrics] = useState<Metric[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<string | null>(null);
  const [view, setView] = useState<'dashboard' | 'alerts' | 'history' | 'users'>('dashboard');
  const [isAuthenticated, setIsAuthenticated] = useState(localStorage.getItem('sentinel_auth') === 'true');
  const [currentUser, setCurrentUser] = useState(localStorage.getItem('sentinel_user') || '');
  const [loginData, setLoginData] = useState({ email: '', password: '' });
  const [newUser, setNewUser] = useState({ email: '', password: '' });
  const [loginError, setLoginError] = useState('');

  const fetchUsers = async () => {
    try {
      const res = await fetch(`${API_URL}/users`);
      const data = await res.json();
      setUsers(data);
    } catch (e) { console.error(e); }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch(`${API_URL}/users`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newUser)
      });
      if (res.ok) {
        setNewUser({ email: '', password: '' });
        fetchUsers();
        alert("✅ Usuario creado con éxito");
      } else {
        const err = await res.json();
        alert(`❌ Error: ${err.detail || 'Error desconocido'}`);
      }
    } catch (e) { alert("❌ Error de conexión"); }
  };

  const deleteUser = async (id: number) => {
    if (!confirm("¿Eliminar este perfil?")) return;
    try {
      await fetch(`${API_URL}/users/${id}`, { method: 'DELETE' });
      fetchUsers();
    } catch (e) { console.error(e); }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(loginData)
      });
      if (res.ok) {
        localStorage.setItem('sentinel_auth', 'true');
        localStorage.setItem('sentinel_user', loginData.email);
        setCurrentUser(loginData.email);
        setIsAuthenticated(true);
      } else { setLoginError('Error de acceso'); }
    } catch (e) { setLoginError('Error de servidor'); }
  };

  const handleLogout = () => {
    localStorage.removeItem('sentinel_auth');
    localStorage.removeItem('sentinel_user');
    setIsAuthenticated(false);
  };

  const fetchDevices = async () => {
    if (!isAuthenticated) return;
    try {
      const res = await fetch(`${API_URL}/devices`);
      const data = await res.json();
      setDevices(data);
      if (data.length > 0 && !selectedDevice) setSelectedDevice(data[0].hostname);
    } catch (e) { console.error(e); }
  };

  const fetchMetrics = async () => {
    if (!isAuthenticated || !selectedDevice) return;
    const endpoint = view === 'history' ? `${API_URL}/history/${selectedDevice}` : `${API_URL}/metrics/${selectedDevice}`;
    try {
      const res = await fetch(endpoint);
      const data = await res.json();
      setMetrics(data.sort((a:any, b:any) => a.timestamp - b.timestamp));
    } catch (e) { console.error(e); }
  };

  useEffect(() => {
    if (isAuthenticated) {
      fetchDevices();
      fetchUsers();
      const interval = setInterval(() => { fetchDevices(); }, 3000);
      return () => clearInterval(interval);
    }
  }, [isAuthenticated]);

  useEffect(() => {
    if (isAuthenticated) {
      fetchMetrics();
      const interval = setInterval(fetchMetrics, 2000);
      return () => clearInterval(interval);
    }
  }, [selectedDevice, isAuthenticated, view]);

  const latest = metrics.length > 0 ? metrics[metrics.length - 1] : null;

  if (!isAuthenticated) {
    return (
      <div className="h-screen w-full text-white flex overflow-hidden bg-[#020203] font-sans relative">
        <form onSubmit={handleLogin} className="w-full max-w-md bg-white/5 border border-white/10 p-10 rounded-[40px] backdrop-blur-2xl z-10 shadow-2xl m-auto">
          <div className="flex justify-center mb-8"><div className="w-16 h-16 bg-blue-600 rounded-2xl flex items-center justify-center shadow-xl shadow-blue-500/20"><Shield size={32} className="text-white" /></div></div>
          <h2 className="text-3xl font-black text-center mb-2 text-white">Sentinel Pro</h2>
          <div className="space-y-4 mt-8">
            <input type="email" placeholder="Correo" value={loginData.email} onChange={(e) => setLoginData({...loginData, email: e.target.value})} className="w-full bg-white/5 border border-white/10 rounded-2xl py-5 px-6 text-white" />
            <input type="password" placeholder="Contraseña" value={loginData.password} onChange={(e) => setLoginData({...loginData, password: e.target.value})} className="w-full bg-white/5 border border-white/10 rounded-2xl py-5 px-6 text-white" />
          </div>
          {loginError && <p className="text-red-500 text-xs mt-4 text-center font-bold">{loginError}</p>}
          <button type="submit" className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-5 rounded-2xl mt-8 transition-all shadow-lg shadow-blue-600/20">Entrar</button>
        </form>
      </div>
    );
  }

  return (
    <div className="h-screen w-full text-white flex overflow-hidden bg-[#020203] font-sans relative">
      <aside className="w-72 bg-black/40 backdrop-blur-3xl border-r border-white/10 p-8 flex flex-col z-20 h-full">
        <div className="flex items-center gap-3 mb-12">
          <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl flex items-center justify-center"><Shield size={22} /></div>
          <h1 className="text-xl font-black tracking-tight text-white">SENTINEL</h1>
        </div>
        
        <nav className="space-y-1 mb-10">
          <SidebarBtn icon={<LayoutDashboard size={18} />} label="Dashboard" active={view === 'dashboard'} onClick={() => setView('dashboard')} />
          <SidebarBtn icon={<History size={18} />} label="Historial" active={view === 'history'} onClick={() => setView('history')} />
          <SidebarBtn icon={<Settings size={18} />} label="Usuarios" active={view === 'users'} onClick={() => setView('users')} />
        </nav>

        <div className="space-y-3 pt-6 border-t border-white/5 flex-1 overflow-y-auto">
          <p className="text-white/20 text-[10px] font-black uppercase tracking-widest mb-2 px-2">Dispositivos</p>
          {devices.map(d => (
            <button key={d.hostname} onClick={() => setSelectedDevice(d.hostname)} className={`w-full flex items-center gap-3 px-4 py-3 rounded-2xl transition-all ${selectedDevice === d.hostname ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' : 'text-white/40 hover:bg-white/5'}`}>
              <div className={`w-2 h-2 rounded-full ${d.status === 'ONLINE' ? 'bg-green-500 shadow-[0_0_10px_#22c55e]' : 'bg-red-500'}`}></div>
              <span className="text-sm font-bold truncate">{d.hostname}</span>
            </button>
          ))}
        </div>

        {/* PERFIL ACTIVO */}
        <div className="mt-auto pt-6 border-t border-white/5">
           <div className="bg-white/5 p-4 rounded-[24px] flex items-center gap-3 border border-white/5">
              <div className="w-10 h-10 bg-blue-500/10 rounded-full flex items-center justify-center text-blue-400 font-black border border-blue-500/20 uppercase">
                {currentUser[0] || 'A'}
              </div>
              <div className="flex-1 overflow-hidden">
                <p className="text-[10px] font-black text-white/20 uppercase tracking-widest">Sesión Activa</p>
                <p className="text-xs font-bold text-white truncate">{currentUser}</p>
              </div>
              <button onClick={handleLogout} className="text-red-500/40 hover:text-red-500 transition-all">
                <LogOut size={16} />
              </button>
           </div>
        </div>
      </aside>

      <main className="flex-1 h-full overflow-y-auto z-10 p-12 scroll-smooth">
        <div className="max-w-7xl mx-auto">
          {view === 'users' ? (
            <div className="space-y-10 animate-in fade-in duration-500">
              <header><h2 className="text-5xl font-black tracking-tighter text-white">Gestión de Perfiles</h2><p className="text-white/40 mt-2">Crea cuentas para tu equipo de TI.</p></header>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">
                <div className="bg-white/5 border border-white/10 p-10 rounded-[40px] backdrop-blur-md">
                  <h3 className="text-xl font-black mb-6 flex items-center gap-2"><UserPlus size={20} /> Nuevo Administrador</h3>
                  <form onSubmit={handleCreateUser} className="space-y-4">
                    <input type="email" placeholder="Email del usuario" value={newUser.email} onChange={(e) => setNewUser({...newUser, email: e.target.value})} className="w-full bg-white/5 border border-white/10 rounded-2xl py-4 px-6 text-white focus:border-blue-500/50 transition-all" required />
                    <input type="password" placeholder="Contraseña" value={newUser.password} onChange={(e) => setNewUser({...newUser, password: e.target.value})} className="w-full bg-white/5 border border-white/10 rounded-2xl py-4 px-6 text-white focus:border-blue-500/50 transition-all" required />
                    <button type="submit" className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-4 rounded-2xl transition-all">Registrar Usuario</button>
                  </form>
                </div>
                <div className="bg-white/5 border border-white/10 p-10 rounded-[40px] backdrop-blur-md">
                   <h3 className="text-xl font-black mb-6">Usuarios Activos</h3>
                   <div className="space-y-3">
                      {Array.isArray(users) && users.map(u => (
                        <div key={u.id} className="flex justify-between items-center p-4 bg-white/5 rounded-2xl border border-white/5">
                           <div className="flex items-center gap-3">
                             <div className="w-8 h-8 rounded-full bg-blue-500/20 flex items-center justify-center text-blue-400 font-bold uppercase">
                               {u.email ? u.email[0] : '?'}
                             </div>
                             <span className="text-sm font-bold text-white/70">{u.email}</span>
                           </div>
                           <button onClick={() => deleteUser(u.id)} className="text-red-500/40 hover:text-red-500 transition-all"><Trash2 size={18} /></button>
                        </div>
                      ))}
                   </div>
                </div>
              </div>
            </div>
          ) : (
            <>
              <header className="mb-12 flex justify-between items-end">
                <div>
                  <div className="flex items-center gap-2 text-blue-400 text-[10px] font-black uppercase tracking-widest mb-2"><Zap size={12} fill="currentColor" /> {view === 'history' ? 'Análisis Histórico' : 'Monitoreo en Vivo'}</div>
                  <h2 className="text-5xl font-black tracking-tighter text-white">{selectedDevice || 'Cargando...'}</h2>
                </div>
                {latest && <div className="text-white/20 text-xs font-black uppercase tracking-[0.2em]">Nodo Online desde: {latest.uptime}</div>}
              </header>

              <div className="space-y-8 animate-in fade-in duration-700">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                  <MetricCard label="CPU" value={latest?.cpu_usage.toFixed(2) || '0.00'} icon={<Cpu size={20} />} color="blue" />
                  <MetricCard label="RAM" value={latest?.ram_usage.toFixed(2) || '0.00'} icon={<Database size={20} />} color="purple" />
                  <div className="bg-white/5 border border-white/10 rounded-[32px] p-6 flex flex-col justify-center backdrop-blur-md">
                     <div className="flex justify-between text-[10px] font-black text-white/20 uppercase mb-2"><span>Network Traffic</span> <Globe size={12} /></div>
                     <div className="text-sm font-black flex flex-col gap-1">
                        <div className="text-blue-400 flex justify-between"><span>DOWNLOAD</span> <span>{latest?.network.recv_kb.toFixed(2) || '0.00'} KB/S</span></div>
                        <div className="text-purple-400 flex justify-between"><span>UPLOAD</span> <span>{latest?.network.sent_kb.toFixed(2) || '0.00'} KB/S</span></div>
                     </div>
                  </div>
                  <div className="bg-white/5 border border-white/10 rounded-[32px] p-6 flex flex-col justify-center items-center backdrop-blur-md text-center">
                     <span className={`text-2xl font-black ${latest?.cpu_usage > 90 ? 'text-red-500 animate-pulse' : 'text-green-400'}`}>{latest?.cpu_usage > 90 ? 'CRÍTICO' : 'ESTABLE'}</span>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                  <div className="lg:col-span-2 bg-white/5 border border-white/10 p-10 rounded-[40px] backdrop-blur-md">
                    <h3 className="text-xl font-black text-white mb-8 flex items-center gap-2"><Activity size={20} /> Telemetría del Sistema</h3>
                    <div className="h-[350px]">
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={metrics}>
                          <defs><linearGradient id="c" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/><stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/></linearGradient></defs>
                          <CartesianGrid strokeDasharray="3 3" stroke="#ffffff05" vertical={false} />
                          <Tooltip contentStyle={{background:'#000', border:'1px solid #ffffff10', borderRadius:'24px', padding:'20px'}} />
                          <XAxis dataKey="timestamp" hide />
                          <Area type="monotone" dataKey="cpu_usage" stroke="#3b82f6" fill="url(#c)" strokeWidth={4} name="CPU %" />
                          <Area type="monotone" dataKey="ram_usage" stroke="#a855f7" fill="transparent" strokeWidth={4} name="RAM %" />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                  <div className="bg-white/5 border border-white/10 p-8 rounded-[40px] backdrop-blur-md flex flex-col h-full">
                    <h3 className="font-black text-lg mb-6 flex items-center gap-2"><List size={18} /> Procesos</h3>
                    <div className="space-y-3 flex-1 overflow-y-auto pr-2">
                      {latest?.processes.map((p, i) => (
                        <div key={i} className="flex items-center justify-between p-4 bg-white/5 rounded-2xl border border-white/5 hover:bg-white/10 transition-all group">
                          <span className="text-xs font-bold text-white/70 truncate w-24 group-hover:text-white">{p.name}</span>
                          <span className="text-[10px] font-black text-blue-400 bg-blue-500/10 px-2 py-1 rounded-lg">{p.cpu.toFixed(1)}%</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </>
          )}
        </div>
      </main>

      <style dangerouslySetInnerHTML={{ __html: `
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;800;900&display=swap');
        * { font-family: 'Outfit', sans-serif; box-sizing: border-box; }
        body { background: #020203; margin: 0; overflow: hidden; }
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-thumb { background: #ffffff10; border-radius: 10px; }
        ::-webkit-scrollbar-thumb:hover { background: #ffffff20; }
      `}} />
    </div>
  );
};

const SidebarBtn = ({ icon, label, active, onClick }: any) => (
  <button onClick={onClick} className={`w-full flex items-center gap-4 px-4 py-4 rounded-2xl transition-all ${active ? 'bg-white/10 text-white font-black shadow-lg shadow-black/20' : 'text-white/30 hover:text-white hover:bg-white/5'}`}>
    {icon} <span className="text-sm">{label}</span>
  </button>
);

const MetricCard = ({ label, value, icon, color }: any) => (
  <div className="bg-white/5 border border-white/10 rounded-[32px] p-6 hover:bg-white/[0.08] transition-all group">
    <div className="flex justify-between mb-4">
      <div className={`p-2 rounded-xl bg-${color}-500/10 text-${color}-400 border border-${color}-500/20 group-hover:scale-110 transition-transform`}>{icon}</div>
      <span className="text-[10px] font-black text-white/20 uppercase tracking-[0.2em]">{label}</span>
    </div>
    <div className="flex items-end gap-1"><h4 className="text-4xl font-black text-white tracking-tighter">{value}</h4><span className="text-xs font-bold text-white/20 mb-2">%</span></div>
  </div>
);

export default App;
