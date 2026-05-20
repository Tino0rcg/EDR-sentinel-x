import React, { useState, useMemo } from 'react';
import { 
  Wifi, Tv, Smartphone, Printer, Monitor, Server, Cpu, 
  Search, RefreshCw, X, HelpCircle, Info, Network, AlertCircle
} from 'lucide-react';

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

interface NetworkScannerViewProps {
  devices: Device[];
  onRefresh: () => Promise<void>;
}

// Mapeo local ultra-rápido de OUI (MAC Prefixes) a Marcas de Fabricantes
const getMacVendor = (mac: string): string => {
  if (!mac) return 'Desconocido';
  const prefix = mac.replace(/[:-]/g, '').slice(0, 6).toUpperCase();
  
  const OUI_MAP: Record<string, string> = {
    // Apple
    '000393': 'Apple', '000502': 'Apple', '000A27': 'Apple', '000D93': 'Apple', '0010FA': 'Apple', 
    '001451': 'Apple', '0016CB': 'Apple', '0017F2': 'Apple', '0019E3': 'Apple', '001B63': 'Apple', 
    '001CB3': 'Apple', '001D4F': 'Apple', '001E52': 'Apple', '001EC2': 'Apple', '001F5B': 'Apple', 
    '001FF3': 'Apple', '0021E9': 'Apple', '002241': 'Apple', '002312': 'Apple', '002332': 'Apple', 
    '00236C': 'Apple', '002436': 'Apple', '002500': 'Apple', '34159E': 'Apple', '3C0754': 'Apple', 
    '3CD0F8': 'Apple', '403004': 'Apple', '48437C': 'Apple', '542696': 'Apple', '5855CA': 'Apple', 
    '600308': 'Apple', '64200C': 'Apple', '680908': 'Apple', '701124': 'Apple', '748114': 'Apple', 
    '7831C1': 'Apple', '7CC537': 'Apple', '800184': 'Apple', '842999': 'Apple', '88196B': 'Apple', 
    '8C2937': 'Apple', '9027E4': 'Apple', '94103F': 'Apple', '9801A7': 'Apple', '9C04EB': 'Apple', 
    'A43135': 'Apple', 'A82066': 'Apple', 'AC162D': 'Apple', 'B03495': 'Apple', 'B418D1': 'Apple', 
    'B8098A': 'Apple', 'BC3BAF': 'Apple', 'C01ADA': 'Apple', 'C42C03': 'Apple', 'C81EE7': 'Apple', 
    'CC088D': 'Apple', 'D0034B': 'Apple', 'D428B2': 'Apple', 'D8004D': 'Apple', 'E03F49': 'Apple', 
    'E425E9': 'Apple', 'E8040B': 'Apple', 'F01898': 'Apple', 'F40F24': 'Apple', 'F81EDF': 'Apple', 
    'FC1D43': 'Apple', '1C5A6B': 'Apple', '38EC11': 'Apple', 'F0EF86': 'Apple',
    
    // Samsung
    '0007AB': 'Samsung', '000F73': 'Samsung', '001247': 'Samsung', '0015B9': 'Samsung', '0017C5': 'Samsung', 
    '00187A': 'Samsung', '001A8A': 'Samsung', '1432D1': 'Samsung', '38EC12': 'Samsung', '484487': 'Samsung', 
    '5056A8': 'Samsung', '7840E4': 'Samsung', '84253F': 'Samsung', '88308A': 'Samsung', '946372': 'Samsung', 
    'A00798': 'Samsung', 'AC5AF0': 'Samsung', 'B857D8': 'Samsung', 'BCEE5D': 'Samsung', 'C4731E': 'Samsung', 
    'D059E4': 'Samsung', 'ECE09B': 'Samsung', 'FCF136': 'Samsung', '90B686': 'Samsung', 'A80600': 'Samsung',

    // HP (Hewlett-Packard)
    '000480': 'HP', '000802': 'HP', '000F20': 'HP', '00110A': 'HP', '001321': 'HP', '001560': 'HP', 
    '001708': 'HP', '0019BB': 'HP', '001B3F': 'HP', '001E0B': 'HP', '0020EA': 'HP', '002264': 'HP', 
    '002481': 'HP', '002655': 'HP', '0CC47A': 'HP', '101F74': 'HP', '1C98EC': 'HP', '2C4138': 'HP', 
    '308D99': 'HP', '3CD92B': 'HP', '40A8F0': 'HP', '480FCF': 'HP', '5065F3': 'HP', '5820B1': 'HP', 
    '60EB69': 'HP', '68B599': 'HP', '70106F': 'HP', '7446A0': 'HP', '7C8BCA': 'HP', '843497': 'HP', 
    '8CEC4B': 'HP', '9457A5': 'HP', '9C8E99': 'HP', 'A45D36': 'HP', 'AC162C': 'HP', 'B499BA': 'HP', 
    'BC305B': 'HP', 'C4346B': 'HP', 'CC3E5F': 'HP', 'D4C9EF': 'HP', 'E0DB55': 'HP', 'E83935': 'HP', 
    'F0921C': 'HP', 'F8BC12': 'HP', 'FC3FDB': 'HP',

    // Cisco
    '00000C': 'Cisco', '000142': 'Cisco', '000163': 'Cisco', '000196': 'Cisco', '000216': 'Cisco', 
    '00024A': 'Cisco', '0002B9': 'Cisco', '0002FC': 'Cisco', '000331': 'Cisco', '00036B': 'Cisco', 
    '0003E3': 'Cisco', '000427': 'Cisco', '00044D': 'Cisco', '00049A': 'Cisco', '0004C0': 'Cisco', 
    '0004DD': 'Cisco', '000500': 'Cisco', '000531': 'Cisco', '00055E': 'Cisco', '000573': 'Cisco', 
    '00059A': 'Cisco', '000628': 'Cisco', '000652': 'Cisco', '0006C1': 'Cisco', '00070D': 'Cisco', 
    '000750': 'Cisco', '000784': 'Cisco', '0007B3': 'Cisco', '0007EC': 'Cisco', '000820': 'Cisco',

    // TP-Link
    '001A2B': 'TP-Link', '14CC20': 'TP-Link', '18A6C7': 'TP-Link', '18D6C7': 'TP-Link', '3085A9': 'TP-Link', 
    '3C46D8': 'TP-Link', '403F8C': 'TP-Link', '503EAA': 'TP-Link', '50C7BF': 'TP-Link', '54A050': 'TP-Link', 
    '704F57': 'TP-Link', '74DA38': 'TP-Link', '7844FD': 'TP-Link', '8416F9': 'TP-Link', '84C9B2': 'TP-Link', 
    '98DE8F': 'TP-Link', 'A42BB0': 'TP-Link', 'B0487B': 'TP-Link', 'C025E9': 'TP-Link', 'C04A00': 'TP-Link', 
    'D85D4C': 'TP-Link', 'E894F6': 'TP-Link', 'F4EC38': 'TP-Link',

    // Synology
    '001132': 'Synology', '00223A': 'Synology', 'D89EF3': 'Synology',

    // Philips / Philips Hue
    '001788': 'Philips',

    // Realtek
    '00E04C': 'Realtek',

    // Raspberry Pi Foundation
    'B827EB': 'Raspberry Pi', '3A8024': 'Raspberry Pi', 'E45F01': 'Raspberry Pi',

    // Intel Corporation
    '00016C': 'Intel', '0002B3': 'Intel', '000347': 'Intel', '000423': 'Intel', '0008A1': 'Intel', 
    '000C86': 'Intel', '001302': 'Intel', '001500': 'Intel', '001676': 'Intel', '001A3A': 'Intel', 
    '001C25': 'Intel', '001E64': 'Intel', '00216A': 'Intel', '909F43': 'Intel', 'A4C494': 'Intel',

    // VMware / Virtual Machines
    '000C29': 'VMware VM', '005056': 'VMware VM', '000569': 'VMware VM', '001C14': 'VMware VM',
    '080027': 'VirtualBox VM', '00155D': 'Hyper-V VM',

    // Xiaomi
    '3C15C2': 'Xiaomi', '584498': 'Xiaomi', '640980': 'Xiaomi', '7C1D11': 'Xiaomi', '9C99A0': 'Xiaomi', 
    'ACF108': 'Xiaomi', 'C40BCA': 'Xiaomi', 'E4F89C': 'Xiaomi', 'FC64BA': 'Xiaomi',

    // Huawei
    '001882': 'Huawei', '0022A1': 'Huawei', '24DF6A': 'Huawei', '340A33': 'Huawei', '4C1FCC': 'Huawei', 
    '5439DF': 'Huawei', '781D4A': 'Huawei', 'A4B6FC': 'Huawei', 'AC853D': 'Huawei', 'C07009': 'Huawei',

    // Sony
    '000E08': 'Sony', '001315': 'Sony', '0015C1': 'Sony', '0019C5': 'Sony', '001D0D': 'Sony', 
    '001E3D': 'Sony', '047D7B': 'Sony', '10604B': 'Sony', '30F9ED': 'Sony', '3C0771': 'Sony', 
    '542758': 'Sony', '709E29': 'Sony', '806871': 'Sony', 'AC9E17': 'Sony', 'BCF5AC': 'Sony',
    
    // Google / Google Nest
    '3C5A37': 'Google', 'D824BD': 'Google', 'E4F042': 'Google', 'F80F41': 'Google', '48D6D5': 'Google',
    
    // Dell
    '000874': 'Dell', '000F1F': 'Dell', '001422': 'Dell', '001D09': 'Dell', '00219B': 'Dell', 
    '0023AE': 'Dell', '002564': 'Dell', '14FEB5': 'Dell', '24B6FD': 'Dell', '3417EB': 'Dell', 
    '74867A': 'Dell', '847BEB': 'Dell', '90B11C': 'Dell', 'A41F72': 'Dell', 'D4BED9': 'Dell',

    // Lenovo
    '0012FE': 'Lenovo', '00508B': 'Lenovo', '081196': 'Lenovo', '207C8F': 'Lenovo', '3C970E': 'Lenovo', 
    '605718': 'Lenovo', '70F395': 'Lenovo', 'A48D25': 'Lenovo', 'D48564': 'Lenovo',

    // Amazon
    '00FC8B': 'Amazon', '18742E': 'Amazon', '3C5C80': 'Amazon', '40B4CD': 'Amazon', '50A72F': 'Amazon', 
    '747548': 'Amazon', '84D6D0': 'Amazon', 'A0D05B': 'Amazon', 'AC63BE': 'Amazon', 'D0E140': 'Amazon'
  };

  return OUI_MAP[prefix] || 'Genérico';
};

export const NetworkScannerView: React.FC<NetworkScannerViewProps> = ({ devices, onRefresh }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [isRefreshing, setIsRefreshing] = useState(false);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      await onRefresh();
    } catch (e) {
      console.error(e);
    } finally {
      setTimeout(() => setIsRefreshing(false), 800);
    }
  };

  // Recopilar, normalizar y deduplicar todos los dispositivos de todas las subredes
  const allDiscoveredDevices = useMemo(() => {
    const listMap = new Map<string, { 
      ip: string; 
      mac: string; 
      hostname: string; 
      type: string; 
      discoveredBy: string[]; 
      brand: string;
    }>();

    devices.forEach((agent) => {
      // 1. Agregar el propio agente como un dispositivo descubierto de tipo PC/Laptop
      const agentIp = agent.hostname; // A veces el hostname es el IP, busquemos si lo tiene
      const agentMac = 'EDR-AGENT';
      const agentKey = `agent-${agent.hostname}`;
      
      // Intentamos poblar los datos propios del agente
      listMap.set(agentKey, {
        ip: agent.status === 'ONLINE' ? 'Consola EDR' : 'Offline',
        mac: agentMac,
        hostname: agent.hostname,
        type: 'PC/Laptop',
        discoveredBy: ['Agente EDR (Self)'],
        brand: 'Sentinel Agent'
      });

      // 2. Procesar dispositivos escaneados por este agente
      if (Array.isArray(agent.network_map)) {
        agent.network_map.forEach((d) => {
          const macUpper = d.mac.replace(/-Ref/g, '').replace(/-/g, ':').toUpperCase();
          const key = macUpper || d.ip; // Usar MAC o IP como clave de deduplicación

          // Validar si el dispositivo descubierto es un agente ya registrado
          const isAgent = devices.some(a => 
            a.hostname.toLowerCase() === d.hostname.toLowerCase() || 
            a.hostname.toLowerCase() === d.ip.toLowerCase()
          );

          if (isAgent) return; // Si es un agente, lo omitimos porque ya se agregó en el paso 1

          const brand = getMacVendor(macUpper);
          
          if (listMap.has(key)) {
            const existing = listMap.get(key)!;
            if (!existing.discoveredBy.includes(agent.hostname)) {
              existing.discoveredBy.push(agent.hostname);
            }
          } else {
            listMap.set(key, {
              ip: d.ip,
              mac: macUpper,
              hostname: d.hostname || d.ip,
              type: d.type || 'Generic',
              discoveredBy: [agent.hostname],
              brand: brand
            });
          }
        });
      }
    });

    return Array.from(listMap.values());
  }, [devices]);

  // Filtrado y Búsqueda
  const filteredDiscovered = useMemo(() => {
    return allDiscoveredDevices.filter((d) => {
      const matchesSearch = 
        d.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
        d.ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
        d.mac.toLowerCase().includes(searchQuery.toLowerCase()) ||
        d.brand.toLowerCase().includes(searchQuery.toLowerCase()) ||
        d.discoveredBy.some(agent => agent.toLowerCase().includes(searchQuery.toLowerCase()));

      let matchesType = true;
      if (filterType !== 'all') {
        matchesType = d.type === filterType;
      }

      return matchesSearch && matchesType;
    });
  }, [allDiscoveredDevices, searchQuery, filterType]);

  // Estadísticas del escaneo
  const stats = useMemo(() => {
    const total = allDiscoveredDevices.length;
    const routers = allDiscoveredDevices.filter(d => d.type === 'Router').length;
    const computers = allDiscoveredDevices.filter(d => d.type === 'PC/Laptop' || d.type === 'Server').length;
    const mobiles = allDiscoveredDevices.filter(d => d.type === 'Mobile').length;
    const printersAndTvs = allDiscoveredDevices.filter(d => d.type === 'Printer' || d.type === 'TV').length;
    const generics = total - routers - computers - mobiles - printersAndTvs;

    return { total, routers, computers, mobiles, printersAndTvs, generics };
  }, [allDiscoveredDevices]);

  // Iconos y colores por tipo de dispositivo
  const getDeviceIconAndStyle = (type: string) => {
    const iconSize = 22;
    switch (type) {
      case 'Router':
        return {
          icon: <Wifi size={iconSize} className="text-cyan-400" />,
          bgColor: 'from-cyan-600/20 to-blue-600/5',
          borderColor: 'border-cyan-500/20 hover:border-cyan-500/50',
          glow: 'shadow-cyan-500/10'
        };
      case 'TV':
        return {
          icon: <Tv size={iconSize} className="text-purple-400" />,
          bgColor: 'from-purple-600/20 to-pink-600/5',
          borderColor: 'border-purple-500/20 hover:border-purple-500/50',
          glow: 'shadow-purple-500/10'
        };
      case 'Mobile':
        return {
          icon: <Smartphone size={iconSize} className="text-orange-400" />,
          bgColor: 'from-orange-600/20 to-amber-600/5',
          borderColor: 'border-orange-500/20 hover:border-orange-500/50',
          glow: 'shadow-orange-500/10'
        };
      case 'Printer':
        return {
          icon: <Printer size={iconSize} className="text-yellow-400" />,
          bgColor: 'from-yellow-600/20 to-amber-600/5',
          borderColor: 'border-yellow-500/20 hover:border-yellow-500/50',
          glow: 'shadow-yellow-500/10'
        };
      case 'Server':
        return {
          icon: <Server size={iconSize} className="text-blue-400" />,
          bgColor: 'from-blue-600/20 to-indigo-600/5',
          borderColor: 'border-blue-500/20 hover:border-blue-500/50',
          glow: 'shadow-blue-500/10'
        };
      case 'PC/Laptop':
        return {
          icon: <Monitor size={iconSize} className="text-green-400" />,
          bgColor: 'from-green-600/20 to-emerald-600/5',
          borderColor: 'border-green-500/20 hover:border-green-500/50',
          glow: 'shadow-green-500/10'
        };
      default:
        return {
          icon: <Cpu size={iconSize} className="text-slate-400" />,
          bgColor: 'from-slate-700/20 to-slate-800/5',
          borderColor: 'border-slate-500/20 hover:border-slate-500/50',
          glow: 'shadow-slate-500/5'
        };
    }
  };

  return (
    <div className="flex-1 p-10 overflow-y-auto bg-[#010102] w-full max-w-6xl mx-auto space-y-8 select-none">
      
      {/* HEADER */}
      <header className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 mb-4">
        <div>
          <div className="text-blue-500 text-[10px] font-black tracking-widest mb-1 uppercase flex items-center gap-2">
            <Network size={12} className="animate-pulse" /> TELEMETRÍA DE RED EN TIEMPO REAL
          </div>
          <h2 className="text-5xl font-black tracking-tighter">Dispositivos en Red</h2>
          <p className="text-xs text-white/40 mt-1 font-medium max-w-xl">
            Todos los dispositivos cableados (Ethernet) e inalámbricos (Wi-Fi) detectados por el sistema de sensores EDR de Sentinel.
          </p>
        </div>
        
        {/* Acciones */}
        <div className="flex items-center gap-3">
          <button
            onClick={handleRefresh}
            disabled={isRefreshing}
            className="px-5 py-3 rounded-2xl bg-white/5 border border-white/10 hover:bg-white/10 text-xs font-black transition-all flex items-center gap-2 text-white/80 hover:text-white"
          >
            <RefreshCw size={14} className={isRefreshing ? 'animate-spin' : ''} /> 
            {isRefreshing ? 'SINCRONIZANDO...' : 'ACTUALIZAR CONSOLA'}
          </button>
        </div>
      </header>

      {/* METRIC CARDS / STATS GRID */}
      <div className="grid grid-cols-2 lg:grid-cols-6 gap-4">
        <StatCard label="Dispositivos" value={stats.total} icon={<Network size={14} className="text-blue-500" />} />
        <StatCard label="Routers" value={stats.routers} icon={<Wifi size={14} className="text-cyan-400" />} />
        <StatCard label="Computadores" value={stats.computers} icon={<Monitor size={14} className="text-green-400" />} />
        <StatCard label="Móviles" value={stats.mobiles} icon={<Smartphone size={14} className="text-orange-400" />} />
        <StatCard label="Multimedia" value={stats.printersAndTvs} icon={<Tv size={14} className="text-purple-400" />} />
        <StatCard label="Otros" value={stats.generics} icon={<Cpu size={14} className="text-slate-400" />} />
      </div>

      {/* AVISO INFORMATIVO */}
      <div className="bg-blue-600/10 border border-blue-500/20 p-5 rounded-[2rem] flex gap-4 items-start shadow-xl">
        <Info className="text-blue-500 mt-1 flex-shrink-0" size={20} />
        <div>
          <p className="text-xs font-bold text-white/90">Escaneo de Red Activo en Segundo Plano</p>
          <p className="text-[10px] text-white/50 leading-relaxed font-medium mt-1">
            Los agentes realizan un barrido automático de red cada 60 segundos buscando dispositivos activos en su subred a través de sockets TCP a puertos comunes (135 y 80), lo que permite registrar smartphones, Smart TVs e impresoras sin importar el sistema operativo ni el tipo de conexión.
          </p>
        </div>
      </div>

      {/* FILTROS Y BÚSQUEDA */}
      <div className="flex flex-col md:flex-row gap-4 justify-between items-center bg-white/[0.02] border border-white/5 p-6 rounded-3xl backdrop-blur-xl">
        <div className="flex flex-wrap gap-2 w-full md:w-auto">
          {['all', 'Router', 'PC/Laptop', 'Mobile', 'Printer', 'TV', 'Generic'].map((type) => (
            <button
              key={type}
              onClick={() => setFilterType(type)}
              className={`px-4 py-2.5 rounded-xl text-xs font-bold transition-all ${
                filterType === type 
                  ? 'bg-blue-600 text-white font-black shadow-lg shadow-blue-500/20' 
                  : 'bg-white/5 text-white/40 hover:bg-white/10 hover:text-white'
              }`}
            >
              {type === 'all' && 'Todos'}
              {type === 'Router' && 'Routers'}
              {type === 'PC/Laptop' && 'Computadores'}
              {type === 'Mobile' && 'Móviles'}
              {type === 'Printer' && 'Impresoras'}
              {type === 'TV' && 'Smart TVs'}
              {type === 'Generic' && 'Otros / Genéricos'}
            </button>
          ))}
        </div>

        {/* Campo de búsqueda */}
        <div className="relative w-full md:w-80">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-white/20" size={14} />
          <input
            type="text"
            placeholder="Buscar por IP, MAC, Marca..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-black/40 border border-white/10 pl-10 pr-10 py-3 rounded-2xl text-xs text-white outline-none focus:border-blue-500/50 focus:bg-[#0c0c12] transition-all font-medium"
          />
          {searchQuery && (
            <button 
              onClick={() => setSearchQuery('')}
              className="absolute right-4 top-1/2 -translate-y-1/2 text-white/30 hover:text-white"
            >
              <X size={12} />
            </button>
          )}
        </div>
      </div>

      {/* DISPOSITIVOS GRID */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredDiscovered.map((device, i) => {
          const style = getDeviceIconAndStyle(device.type);
          
          return (
            <div 
              key={device.mac + '-' + device.ip + '-' + i}
              className={`bg-gradient-to-b ${style.bgColor} border ${style.borderColor} p-6 rounded-[32px] backdrop-blur-md shadow-2xl flex flex-col justify-between group hover:scale-[1.02] hover:-translate-y-1 transition-all duration-300 relative overflow-hidden`}
            >
              {/* Círculo de glow de fondo */}
              <div className="absolute -top-12 -right-12 w-28 h-28 bg-white/5 rounded-full blur-2xl group-hover:bg-white/10 transition-colors"></div>

              <div>
                {/* Header de la tarjeta */}
                <div className="flex justify-between items-start mb-5">
                  <div className={`p-3.5 bg-black/40 rounded-2xl border ${style.borderColor} ${style.glow} flex items-center justify-center`}>
                    {style.icon}
                  </div>
                  <div className="text-right">
                    <span className="text-[9px] font-black uppercase tracking-widest text-white/30 block mb-0.5">Clasificación</span>
                    <span className="px-2.5 py-1 rounded-full text-[9px] font-black bg-white/5 text-white/80 border border-white/10">
                      {device.type === 'PC/Laptop' ? 'PC / LAPTOP' : device.type.toUpperCase()}
                    </span>
                  </div>
                </div>

                {/* Hostname o Nombre del dispositivo */}
                <h4 className="text-lg font-black text-white leading-snug tracking-tight truncate max-w-[200px]" title={device.hostname}>
                  {device.hostname}
                </h4>

                {/* Marca / Fabricante */}
                <p className="text-[10px] font-black text-blue-400 mt-1 tracking-wider uppercase">
                  {device.brand}
                </p>

                {/* Tabla de especificaciones */}
                <div className="mt-5 space-y-2 border-t border-white/5 pt-4 text-[11px] font-semibold text-white/50">
                  <div className="flex justify-between items-center">
                    <span>Dirección IP</span>
                    <span className="font-bold text-white/80 tracking-wide select-text">{device.ip}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span>Dirección MAC</span>
                    <span className="font-bold text-white/80 tracking-wide select-text">{device.mac}</span>
                  </div>
                </div>
              </div>

              {/* Pie de la tarjeta: Descubridores */}
              <div className="mt-6 border-t border-white/5 pt-4">
                <span className="text-[9px] font-black uppercase tracking-widest text-white/30 block mb-2">Sensor de Detección</span>
                <div className="flex flex-wrap gap-1.5">
                  {device.discoveredBy.map((agent, agentIdx) => (
                    <span 
                      key={agentIdx}
                      className="px-2.5 py-1 rounded-lg text-[9px] font-black bg-blue-500/10 border border-blue-500/20 text-blue-400"
                    >
                      {agent}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          );
        })}

        {filteredDiscovered.length === 0 && (
          <div className="col-span-full py-24 text-center border border-white/5 bg-white/[0.01] rounded-[40px] flex flex-col items-center justify-center">
            <AlertCircle size={40} className="text-white/20 mb-4 animate-bounce" />
            <p className="font-black text-lg text-white/60">No se encontraron dispositivos</p>
            <p className="text-xs text-white/30 mt-1 max-w-sm font-medium">
              Intenta cambiar los filtros o realiza una búsqueda diferente. Asegúrate de tener al menos un agente Sentinel en línea para poblar la red local.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

interface StatCardProps {
  label: string;
  value: number;
  icon: React.ReactNode;
}

const StatCard: React.FC<StatCardProps> = ({ label, value, icon }) => (
  <div className="bg-white/5 border border-white/5 rounded-3xl p-5 flex flex-col justify-between hover:bg-white/10 hover:border-white/10 transition-colors shadow-lg">
    <div className="flex items-center justify-between">
      <span className="text-[9px] font-black text-white/30 uppercase tracking-widest">{label}</span>
      <div className="p-1.5 bg-white/5 rounded-lg">{icon}</div>
    </div>
    <div className="text-3xl font-black text-white mt-4 tracking-tighter">{value}</div>
  </div>
);
