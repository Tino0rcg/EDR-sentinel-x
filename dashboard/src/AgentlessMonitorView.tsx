import React, { useEffect, useState, useRef } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Wifi, WifiOff, Shield, ShieldAlert, Activity, Lock, Globe, Server, AlertTriangle, CheckCircle2, Clock, Cpu, Zap, Eye } from 'lucide-react';

interface OpenPort {
  port: number;
  service: string;
  risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  desc: string;
}

interface ProbeRecord {
  id: number;
  ip: string;
  hostname: string;
  latency_ms: number | null;
  open_ports: OpenPort[];
  mac: string;
  device_type: string;
  vendor: string;
  timestamp: number;
  reporter_hostname: string;
}

interface AgentlessViewProps {
  device: {
    hostname: string;
    ip: string;
    mac: string;
    type: string;
  };
  API_URL: string;
}

const RISK_CONFIG = {
  CRITICAL: { color: '#ef4444', bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', label: 'CRÍTICO' },
  HIGH:     { color: '#f97316', bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-400', label: 'ALTO' },
  MEDIUM:   { color: '#eab308', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', text: 'text-yellow-400', label: 'MEDIO' },
  LOW:      { color: '#22c55e', bg: 'bg-green-500/10', border: 'border-green-500/30', text: 'text-green-400', label: 'BAJO' },
};

function LatencyGauge({ ms }: { ms: number | null }) {
  const radius = 60;
  const stroke = 8;
  const normalizedRadius = radius - stroke / 2;
  const circumference = 2 * Math.PI * normalizedRadius;
  const maxMs = 200;
  const pct = ms !== null ? Math.min(ms / maxMs, 1) : 1;
  
  const color = ms === null ? '#6b7280' 
    : ms < 20 ? '#22c55e' 
    : ms < 60 ? '#84cc16' 
    : ms < 100 ? '#eab308' 
    : ms < 150 ? '#f97316' 
    : '#ef4444';

  const label = ms === null ? 'OFFLINE' : ms < 20 ? 'EXCELENTE' : ms < 60 ? 'ÓPTIMA' : ms < 100 ? 'BUENA' : ms < 150 ? 'REGULAR' : 'MALA';
  const dashOffset = circumference * (1 - pct);

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width: radius * 2, height: radius * 2 }}>
        <svg width={radius * 2} height={radius * 2} style={{ transform: 'rotate(-90deg)' }}>
          <circle cx={radius} cy={radius} r={normalizedRadius} stroke="rgba(255,255,255,0.05)" strokeWidth={stroke} fill="transparent" />
          <circle
            cx={radius} cy={radius} r={normalizedRadius}
            stroke={color} strokeWidth={stroke} fill="transparent"
            strokeDasharray={`${circumference}`}
            strokeDashoffset={dashOffset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 0.6s ease, stroke 0.4s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          {ms !== null ? (
            <>
              <span className="text-2xl font-black text-white">{ms}</span>
              <span className="text-[9px] font-black opacity-40 uppercase">ms</span>
            </>
          ) : (
            <WifiOff size={24} className="text-gray-500" />
          )}
        </div>
      </div>
      <span className="text-[10px] font-black uppercase tracking-widest" style={{ color }}>{label}</span>
    </div>
  );
}

const CustomTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    const val = payload[0].value;
    return (
      <div className="bg-black/80 border border-white/10 rounded-xl px-3 py-2 text-xs">
        <p className="font-black text-white">{val !== null && val !== undefined ? `${val} ms` : 'OFFLINE'}</p>
      </div>
    );
  }
  return null;
};

export function AgentlessMonitorView({ device, API_URL }: AgentlessViewProps) {
  const [history, setHistory] = useState<ProbeRecord[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [lastProbe, setLastProbe] = useState<ProbeRecord | null>(null);
  const [pulseActive, setPulseActive] = useState(false);
  const intervalRef = useRef<any>(null);

  const fetchProbes = async () => {
    try {
      const encodedIp = device.ip.replace(/\./g, '_');
      const res = await fetch(`${API_URL}/network-probe/${encodedIp}`);
      if (res.ok) {
        const data: ProbeRecord[] = await res.json();
        if (data.length > 0) {
          setHistory(data);
          setLastProbe(data[data.length - 1]);
          setPulseActive(true);
          setTimeout(() => setPulseActive(false), 700);
        }
      }
    } catch {}
    setIsLoading(false);
  };

  useEffect(() => {
    fetchProbes();
    intervalRef.current = setInterval(fetchProbes, 15000);
    return () => clearInterval(intervalRef.current);
  }, [device.ip]);

  const chartData = history.map((h, i) => ({
    t: new Date(h.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    ms: h.latency_ms,
  }));

  const avgLatency = history.filter(h => h.latency_ms !== null).length > 0
    ? Math.round(history.filter(h => h.latency_ms !== null).reduce((a, b) => a + (b.latency_ms || 0), 0) / history.filter(h => h.latency_ms !== null).length)
    : null;

  const maxLatency = history.filter(h => h.latency_ms !== null).length > 0
    ? Math.round(Math.max(...history.filter(h => h.latency_ms !== null).map(h => h.latency_ms!)))
    : null;

  const uptimePct = history.length > 0
    ? Math.round((history.filter(h => h.latency_ms !== null).length / history.length) * 100)
    : 0;

  const openPorts: OpenPort[] = lastProbe?.open_ports || [];
  const criticalPorts = openPorts.filter(p => p.risk === 'CRITICAL');
  const highPorts = openPorts.filter(p => p.risk === 'HIGH');
  const isOnline = lastProbe?.latency_ms !== null && lastProbe?.latency_ms !== undefined;

  const latencyColor = lastProbe?.latency_ms !== null && lastProbe?.latency_ms !== undefined
    ? lastProbe.latency_ms < 20 ? '#22c55e'
    : lastProbe.latency_ms < 60 ? '#84cc16'
    : lastProbe.latency_ms < 100 ? '#eab308'
    : '#ef4444'
    : '#6b7280';

  const securityScore = isOnline
    ? Math.max(0, 100 - (criticalPorts.length * 30) - (highPorts.length * 15) - (openPorts.filter(p => p.risk === 'MEDIUM').length * 5))
    : 0;

  const secColor = securityScore >= 80 ? '#22c55e' : securityScore >= 50 ? '#eab308' : '#ef4444';

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-40 gap-4">
        <div className="w-16 h-16 rounded-full border-4 border-blue-500/20 border-t-blue-500 animate-spin" />
        <p className="text-white/40 font-bold animate-pulse">Iniciando radar de red...</p>
      </div>
    );
  }

  if (history.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-40 gap-6 text-center">
        <div className="relative">
          <div className="w-24 h-24 rounded-full bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
            <Activity size={36} className="text-blue-500/60" />
          </div>
          <div className="absolute inset-0 rounded-full border border-blue-500/20 animate-ping" />
        </div>
        <div>
          <p className="text-white font-bold text-lg">Esperando primer análisis</p>
          <p className="text-white/40 text-sm mt-1">El agente central iniciará el monitoreo en ~30 segundos</p>
          <p className="text-white/20 text-xs mt-2 font-mono">{device.ip}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* HEADER HERO */}
      <div className="relative overflow-hidden bg-gradient-to-br from-black via-slate-950 to-black border border-white/5 rounded-[40px] p-8">
        {/* BG Glow */}
        <div className="absolute top-0 right-0 w-96 h-96 rounded-full blur-[120px] opacity-10"
          style={{ background: isOnline ? '#3b82f6' : '#6b7280' }} />
        
        <div className="relative z-10 flex flex-wrap items-center justify-between gap-6">
          {/* Status + Latency */}
          <div className="flex items-center gap-8">
            <div className="relative">
              <LatencyGauge ms={lastProbe?.latency_ms ?? null} />
              {isOnline && (
                <div className={`absolute -top-1 -right-1 w-4 h-4 rounded-full bg-green-500 border-2 border-black ${pulseActive ? 'animate-ping' : ''}`} />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <div className="w-2 h-2 rounded-full" style={{ background: isOnline ? '#22c55e' : '#6b7280', boxShadow: isOnline ? '0 0 8px #22c55e' : 'none' }} />
                <span className="text-[10px] font-black uppercase tracking-widest opacity-40">{isOnline ? 'En línea' : 'Sin respuesta'}</span>
              </div>
              <h2 className="text-2xl font-black text-white">{lastProbe?.hostname || device.hostname}</h2>
              <p className="text-sm font-mono opacity-40 mt-0.5">{device.ip} · {lastProbe?.mac || device.mac}</p>
              <p className="text-xs opacity-30 mt-0.5">{lastProbe?.vendor || '—'} · {lastProbe?.device_type || device.type}</p>
            </div>
          </div>

          {/* Stats Row */}
          <div className="flex gap-4 flex-wrap">
            {[
              { label: 'Latencia Prom.', value: avgLatency !== null ? `${avgLatency} ms` : '—', icon: <Activity size={16} />, color: latencyColor },
              { label: 'Latencia Máx.', value: maxLatency !== null ? `${maxLatency} ms` : '—', icon: <Zap size={16} />, color: '#f97316' },
              { label: 'Uptime', value: `${uptimePct}%`, icon: <Clock size={16} />, color: uptimePct > 90 ? '#22c55e' : '#ef4444' },
              { label: 'Puertos Abiertos', value: `${openPorts.length}`, icon: <Eye size={16} />, color: openPorts.length === 0 ? '#22c55e' : openPorts.length < 4 ? '#eab308' : '#ef4444' },
            ].map((s, i) => (
              <div key={i} className="bg-white/5 border border-white/5 rounded-2xl px-5 py-3 min-w-[100px] text-center">
                <div className="flex items-center justify-center gap-1 mb-1 opacity-40" style={{ color: s.color }}>{s.icon}</div>
                <p className="text-xl font-black text-white" style={{ color: s.color }}>{s.value}</p>
                <p className="text-[9px] font-black uppercase opacity-30 mt-0.5">{s.label}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* LATENCY CHART */}
      <div className="bg-white/5 border border-white/5 rounded-[32px] p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="font-black text-white flex items-center gap-2">
            <Activity size={18} className="text-blue-400" /> Latencia en Tiempo Real
          </h3>
          <span className="text-[9px] font-black uppercase opacity-20">últimas {history.length} mediciones</span>
        </div>
        <ResponsiveContainer width="100%" height={180}>
          <AreaChart data={chartData} margin={{ top: 5, right: 10, bottom: 0, left: -10 }}>
            <defs>
              <linearGradient id="latGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={latencyColor} stopOpacity={0.3} />
                <stop offset="95%" stopColor={latencyColor} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="rgba(255,255,255,0.03)" strokeDasharray="3 3" />
            <XAxis dataKey="t" tick={{ fill: 'rgba(255,255,255,0.2)', fontSize: 9 }} />
            <YAxis tick={{ fill: 'rgba(255,255,255,0.2)', fontSize: 9 }} unit="ms" />
            <Tooltip content={<CustomTooltip />} />
            <Area type="monotone" dataKey="ms" stroke={latencyColor} strokeWidth={2.5} fill="url(#latGrad)" dot={false} connectNulls={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* SECURITY SCORE + PORT AUDIT */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Security Score */}
        <div className="bg-white/5 border border-white/5 rounded-[32px] p-6 flex flex-col items-center justify-center gap-4">
          <p className="text-[10px] font-black uppercase opacity-30 tracking-widest">Puntuación de Seguridad</p>
          <div className="relative">
            {/* Donut */}
            <svg width={120} height={120} style={{ transform: 'rotate(-90deg)' }}>
              <circle cx={60} cy={60} r={52} stroke="rgba(255,255,255,0.05)" strokeWidth={10} fill="transparent" />
              <circle
                cx={60} cy={60} r={52}
                stroke={secColor}
                strokeWidth={10}
                fill="transparent"
                strokeDasharray={`${2 * Math.PI * 52}`}
                strokeDashoffset={`${2 * Math.PI * 52 * (1 - securityScore / 100)}`}
                strokeLinecap="round"
                style={{ transition: 'stroke-dashoffset 1s ease, stroke 0.5s ease' }}
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-3xl font-black" style={{ color: secColor }}>{securityScore}</span>
              <span className="text-[9px] font-black opacity-30">/100</span>
            </div>
          </div>
          <div className="text-center">
            <p className="font-black" style={{ color: secColor }}>
              {securityScore >= 80 ? '🛡️ SEGURO' : securityScore >= 50 ? '⚠️ REVISIÓN' : '🔴 RIESGO ALTO'}
            </p>
            {criticalPorts.length > 0 && (
              <p className="text-[10px] text-red-400 mt-1">{criticalPorts.length} puerto(s) crítico(s)</p>
            )}
          </div>
        </div>

        {/* Port Audit */}
        <div className="md:col-span-2 bg-white/5 border border-white/5 rounded-[32px] p-6">
          <h3 className="font-black text-white flex items-center gap-2 mb-4">
            <Lock size={18} className="text-purple-400" /> Auditoría de Puertos
          </h3>
          {openPorts.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10 gap-3">
              <CheckCircle2 size={32} className="text-green-500" />
              <p className="text-green-400 font-bold">Sin puertos expuestos</p>
              <p className="text-white/30 text-xs">El equipo no tiene servicios visibles en la red local</p>
            </div>
          ) : (
            <div className="space-y-2 max-h-60 overflow-y-auto pr-1 custom-scroll">
              {openPorts.sort((a, b) => {
                const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
                return order[a.risk] - order[b.risk];
              }).map((p, i) => {
                const cfg = RISK_CONFIG[p.risk];
                return (
                  <div key={i} className={`flex items-center gap-3 p-3 rounded-2xl border ${cfg.bg} ${cfg.border}`}>
                    <div className="w-12 h-12 rounded-xl flex items-center justify-center font-black text-sm" style={{ background: `${cfg.color}20`, color: cfg.color }}>
                      {p.port}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-sm text-white">{p.service}</span>
                        <span className={`text-[9px] font-black uppercase px-2 py-0.5 rounded-full ${cfg.bg} ${cfg.text} border ${cfg.border}`}>
                          {cfg.label}
                        </span>
                      </div>
                      <p className="text-xs opacity-40 mt-0.5 truncate">{p.desc}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* UPTIME HISTORY BAR */}
      <div className="bg-white/5 border border-white/5 rounded-[32px] p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-black text-white flex items-center gap-2">
            <Globe size={18} className="text-teal-400" /> Historial de Disponibilidad
          </h3>
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-black opacity-20 uppercase">{history.length} muestras</span>
            <div className={`px-3 py-1 rounded-xl text-[10px] font-black uppercase ${uptimePct >= 95 ? 'bg-green-500/10 text-green-400' : uptimePct >= 80 ? 'bg-yellow-500/10 text-yellow-400' : 'bg-red-500/10 text-red-400'}`}>
              {uptimePct}% uptime
            </div>
          </div>
        </div>
        <div className="flex gap-0.5 flex-wrap">
          {history.map((h, i) => {
            const online = h.latency_ms !== null;
            const ms = h.latency_ms || 0;
            const barColor = !online ? '#374151'
              : ms < 20 ? '#22c55e'
              : ms < 60 ? '#84cc16'
              : ms < 100 ? '#eab308'
              : ms < 150 ? '#f97316'
              : '#ef4444';
            return (
              <div
                key={i}
                title={online ? `${ms} ms · ${new Date(h.timestamp * 1000).toLocaleTimeString()}` : `OFFLINE · ${new Date(h.timestamp * 1000).toLocaleTimeString()}`}
                className="rounded-sm cursor-pointer hover:opacity-80 transition-opacity"
                style={{ width: 8, height: 32, background: barColor }}
              />
            );
          })}
        </div>
        <div className="flex items-center gap-4 mt-3">
          {[['< 20ms', '#22c55e', 'Excelente'], ['< 60ms', '#84cc16', 'Óptima'], ['< 100ms', '#eab308', 'Buena'], ['> 100ms', '#f97316', 'Mala'], ['OFFLINE', '#374151', 'Sin respuesta']].map(([label, color, text]) => (
            <div key={label} className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded-sm" style={{ background: color }} />
              <span className="text-[9px] opacity-30 font-black uppercase">{text}</span>
            </div>
          ))}
        </div>
      </div>

      {/* CRITICAL ALERTS */}
      {criticalPorts.length > 0 && (
        <div className="bg-red-500/5 border border-red-500/20 rounded-[32px] p-6">
          <h3 className="font-black text-red-400 flex items-center gap-2 mb-4">
            <ShieldAlert size={18} /> Vulnerabilidades Críticas Detectadas
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {criticalPorts.map((p, i) => (
              <div key={i} className="bg-red-500/10 border border-red-500/30 rounded-2xl p-4 flex items-start gap-3">
                <AlertTriangle size={20} className="text-red-400 mt-0.5 shrink-0" />
                <div>
                  <p className="font-bold text-red-300">Puerto {p.port} · {p.service}</p>
                  <p className="text-red-400/70 text-xs mt-0.5">{p.desc}</p>
                  <p className="text-red-400/50 text-xs mt-1 font-black uppercase">⚠️ Requiere acción inmediata</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* FOOTER INFO */}
      <div className="text-center pb-2">
        <p className="text-[9px] font-black opacity-20 uppercase tracking-widest">
          Monitoreado por agente central · Actualiza cada 15s · IP {device.ip}
          {lastProbe?.reporter_hostname ? ` · Reporter: ${lastProbe.reporter_hostname}` : ''}
        </p>
      </div>
    </div>
  );
}
