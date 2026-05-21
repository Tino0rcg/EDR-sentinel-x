import React, { useState, useMemo, useRef, useEffect } from 'react';
import { 
  Server, Monitor, Wifi, Tv, Smartphone, Printer, Cpu, 
  ShieldAlert, Lock, Unlock, Search, RefreshCw, X, HelpCircle, 
  Eye, Layout, MousePointer, Info, Network, PowerOff
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

interface NetworkMapViewProps {
  devices: Device[];
  onToggleQuarantine: (hostname: string, enable: boolean) => Promise<void>;
  currentUserRole: string;
}

interface GraphNode {
  id: string;
  label: string;
  type: 'server' | 'agent' | 'discovered' | 'Router';
  status: 'ONLINE' | 'OFFLINE';
  deviceType?: string;
  quarantine?: boolean;
  ip?: string;
  mac?: string;
  discoveredBy?: string;
  originalDevice?: Device;
}

interface GraphLink {
  source: string;
  target: string;
  id: string;
  type: 'server-agent' | 'agent-device' | 'agent-agent';
}

export const NetworkMapView: React.FC<NetworkMapViewProps> = ({
  devices,
  onToggleQuarantine,
  currentUserRole
}) => {
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [draggedNodeId, setDraggedNodeId] = useState<string | null>(null);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [panStart, setPanStart] = useState({ x: 0, y: 0 });
  const [nodePositions, setNodePositions] = useState<Record<string, { x: number; y: number }>>({});
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [showHelp, setShowHelp] = useState(false);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [showGrid, setShowGrid] = useState(true);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

  const containerRef = useRef<SVGSVGElement | null>(null);

  // ResizeObserver para centrar el mapa y adaptarlo a toda la pantalla
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const observer = new ResizeObserver((entries) => {
      for (let entry of entries) {
        setDimensions({
          width: entry.contentRect.width || 800,
          height: entry.contentRect.height || 600
        });
      }
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  // Construir nodos y enlaces dinámicamente
  const { nodes, links } = useMemo(() => {
    const listNodes: GraphNode[] = [];
    const listLinks: GraphLink[] = [];

    // 1. Nodo Servidor Central
    listNodes.push({
      id: 'server-console',
      label: 'Sentinel Server',
      type: 'server',
      status: 'ONLINE'
    });

    // Detectar routers centrales únicos
    const centralRouters = new Map<string, DiscoveredDevice & { discoveredBy: string[] }>();
    devices.forEach((device) => {
      if (device.status === 'ONLINE' && Array.isArray(device.network_map)) {
        device.network_map.forEach((d) => {
          if (d.type === 'Router') {
            const existing = centralRouters.get(d.ip);
            if (existing) {
              if (!existing.discoveredBy.includes(device.hostname)) {
                existing.discoveredBy.push(device.hostname);
              }
            } else {
              centralRouters.set(d.ip, {
                ...d,
                discoveredBy: [device.hostname]
              });
            }
          }
        });
      }
    });

    // Crear nodos de núcleo para cada router central
    centralRouters.forEach((router, ip) => {
      listNodes.push({
        id: `central-router-${ip}`,
        label: router.hostname || `Router (${ip})`,
        type: 'Router',
        status: 'ONLINE',
        deviceType: 'Router',
        ip: router.ip,
        mac: router.mac,
        discoveredBy: router.discoveredBy.join(', ')
      });

      // Conectar Servidor -> Router
      listLinks.push({
        id: `server-router-${ip}`,
        source: 'server-console',
        target: `central-router-${ip}`,
        type: 'server-agent'
      });
    });

    const addedDiscoveredNodes = new Map<string, GraphNode>();

    devices.forEach((device) => {
      // 2. Nodos Agentes
      listNodes.push({
        id: device.hostname,
        label: device.hostname,
        type: 'agent',
        status: device.status,
        quarantine: device.quarantine === 1,
        originalDevice: device
      });

      // Conectar Agente a los Routers Centrales (o al Servidor si no hay routers)
      if (centralRouters.size > 0) {
        centralRouters.forEach((router, ip) => {
          listLinks.push({
            id: `router-agent-${ip}-${device.hostname}`,
            source: `central-router-${ip}`,
            target: device.hostname,
            type: 'server-agent'
          });
        });
      } else {
        // Enlace por defecto: Servidor -> Agente
        listLinks.push({
          id: `server-${device.hostname}`,
          source: 'server-console',
          target: device.hostname,
          type: 'server-agent'
        });
      }

      // 3. Nodos Descubiertos (solo si el agente está ONLINE y tiene mapa de red)
      if (device.status === 'ONLINE' && Array.isArray(device.network_map)) {
        device.network_map.forEach((d) => {
          // Filtrar routers para evitar duplicados como hojas secundarias
          if (d.type === 'Router') return;

          // Validar si el dispositivo descubierto es en realidad otro agente
          const matchedAgent = devices.find(agent => 
            agent.hostname.toLowerCase() === d.hostname.toLowerCase() || 
            agent.hostname.toLowerCase() === d.ip.toLowerCase()
          );

          if (matchedAgent) {
            // Dibujar un enlace peer-to-peer de adyacencia si es un agente diferente
            if (matchedAgent.hostname !== device.hostname) {
              const linkId = `peer-${device.hostname}-${matchedAgent.hostname}`;
              const reverseLinkId = `peer-${matchedAgent.hostname}-${device.hostname}`;
              if (!listLinks.some(l => l.id === linkId || l.id === reverseLinkId)) {
                listLinks.push({
                  id: linkId,
                  source: device.hostname,
                  target: matchedAgent.hostname,
                  type: 'agent-agent'
                });
              }
            }
            return;
          }

          const nodeId = `discovered-${d.ip}`;
          
          if (!addedDiscoveredNodes.has(nodeId)) {
            const newNode: GraphNode = {
              id: nodeId,
              label: d.hostname || d.ip,
              type: 'discovered',
              status: 'ONLINE',
              deviceType: d.type,
              ip: d.ip,
              mac: d.mac,
              discoveredBy: device.hostname
            };
            addedDiscoveredNodes.set(nodeId, newNode);
            listNodes.push(newNode);
          } else {
            const existingNode = addedDiscoveredNodes.get(nodeId)!;
            if (existingNode.discoveredBy && !existingNode.discoveredBy.split(', ').includes(device.hostname)) {
              existingNode.discoveredBy += `, ${device.hostname}`;
            }
          }

          // Enlace: Agente -> Dispositivo Descubierto
          listLinks.push({
            id: `${device.hostname}-${nodeId}`,
            source: device.hostname,
            target: nodeId,
            type: 'agent-device'
          });
        });
      }
    });

    return { nodes: listNodes, links: listLinks };
  }, [devices]);

  // Inicializar posiciones con un diseño radial distribuido
  useEffect(() => {
    const initialPositions: Record<string, { x: number; y: number }> = {};
    const cx = dimensions.width / 2;
    const cy = dimensions.height / 2;

    // Detectar routers centrales
    const centralRouterNodes = nodes.filter(n => n.type === 'Router');
    const K = centralRouterNodes.length;

    if (K === 0) {
      // Si no hay routers: Servidor en el centro exacto
      initialPositions['server-console'] = { x: cx, y: cy };
    } else if (K === 1) {
      // Si hay 1 router: Router en el centro exacto, Servidor desplazado arriba a (cx, cy - 140)
      initialPositions[centralRouterNodes[0].id] = { x: cx, y: cy };
      initialPositions['server-console'] = { x: cx, y: cy - 140 };
    } else {
      // Si hay múltiples routers: Servidor desplazado arriba a (cx, cy - 150)
      // Routers en anillo central de radio 60 alrededor del centro
      initialPositions['server-console'] = { x: cx, y: cy - 150 };
      centralRouterNodes.forEach((router, idx) => {
        const theta = (2 * Math.PI * idx) / K;
        initialPositions[router.id] = {
          x: cx + 60 * Math.cos(theta),
          y: cy + 60 * Math.sin(theta)
        };
      });
    }

    // Filtrar agentes
    const agents = nodes.filter(n => n.type === 'agent');
    const N = agents.length;

    agents.forEach((agent, i) => {
      const theta = (2 * Math.PI * i) / (N || 1);
      const R1 = 240; // radio aumentado para dar espacio al núcleo
      const ax = cx + R1 * Math.cos(theta);
      const ay = cy + R1 * Math.sin(theta);
      
      initialPositions[agent.id] = { x: ax, y: ay };

      // Filtrar dispositivos descubiertos cuyo primer descubridor sea este agente
      const discovered = nodes.filter(n => {
        if (n.type !== 'discovered' || !n.discoveredBy) return false;
        const primaryDiscoverer = n.discoveredBy.split(', ')[0];
        return primaryDiscoverer === agent.id;
      });
      const M = discovered.length;

      discovered.forEach((dev, j) => {
        // Distribuir en abanico hacia afuera del centro
        const spread = Math.PI / 2.5; // ángulo de apertura del abanico
        const startAngle = theta - spread / 2;
        const arcAngle = M > 1 ? startAngle + (j * spread) / (M - 1) : theta;
        const R2 = 120;
        
        initialPositions[dev.id] = {
          x: ax + R2 * Math.cos(arcAngle),
          y: ay + R2 * Math.sin(arcAngle)
        };
      });
    });

    // Solo actualizar posiciones que no existan ya (para no perder el drag-and-drop del usuario)
    setNodePositions(prev => {
      const next = { ...prev };
      let changed = false;
      Object.keys(initialPositions).forEach((id) => {
        if (!next[id]) {
          next[id] = initialPositions[id];
          changed = true;
        }
      });
      return changed ? next : prev;
    });
  }, [nodes, dimensions]);

  // Manejar Drag and Drop de Nodos
  const handleNodeMouseDown = (e: React.MouseEvent, nodeId: string) => {
    e.stopPropagation();
    setSelectedNodeId(nodeId);
    setDraggedNodeId(nodeId);
    setDragStart({ x: e.clientX, y: e.clientY });
  };

  // Manejar Desplazamiento (Pan) del mapa
  const handleBgMouseDown = (e: React.MouseEvent) => {
    if (e.button === 0) { // Click izquierdo
      setIsPanning(true);
      setPanStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (draggedNodeId) {
      // Mover Nodo
      const dx = (e.clientX - dragStart.x) / zoom;
      const dy = (e.clientY - dragStart.y) / zoom;

      setNodePositions(prev => {
        const currentPos = prev[draggedNodeId] || { x: 350, y: 300 };
        return {
          ...prev,
          [draggedNodeId]: {
            x: currentPos.x + dx,
            y: currentPos.y + dy
          }
        };
      });
      setDragStart({ x: e.clientX, y: e.clientY });
    } else if (isPanning) {
      // Mover fondo (Pan)
      setPan({
        x: e.clientX - panStart.x,
        y: e.clientY - panStart.y
      });
    }
  };

  const handleMouseUpOrLeave = () => {
    setDraggedNodeId(null);
    setIsPanning(false);
  };

  // Manejar Zoom (Rueda del ratón)
  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const zoomFactor = 1.1;
    const newZoom = e.deltaY < 0 ? zoom * zoomFactor : zoom / zoomFactor;
    // Límites de zoom
    setZoom(Math.max(0.3, Math.min(3, newZoom)));
  };

  // Filtrado y Búsqueda: calcula qué nodos coinciden
  const nodeMatchesFilter = useMemo(() => {
    const matches: Record<string, boolean> = {};

    nodes.forEach((node) => {
      let matchQuery = true;
      let matchType = true;

      // Filtro por Búsqueda de Texto
      if (searchQuery.trim() !== '') {
        const query = searchQuery.toLowerCase();
        const labelMatch = node.label.toLowerCase().includes(query);
        const ipMatch = node.ip ? node.ip.includes(query) : false;
        const macMatch = node.mac ? node.mac.toLowerCase().includes(query) : false;
        const agentMatch = node.discoveredBy ? node.discoveredBy.toLowerCase().includes(query) : false;
        matchQuery = labelMatch || ipMatch || macMatch || agentMatch;
      }

      // Filtro por tipo de dispositivo
      if (filterType !== 'all') {
        if (node.type === 'server') {
          matchType = false;
        } else if (node.type === 'Router') {
          matchType = filterType === 'Router';
        } else if (node.type === 'agent') {
          // El agente siempre se muestra si algún dispositivo descubierto o router de núcleo coincide
          const hasMatchingChild = nodes.some(
            c => (c.type === 'discovered' || c.type === 'Router') && 
                 c.discoveredBy?.split(', ').includes(node.id) && 
                 c.deviceType === filterType
          );
          matchType = hasMatchingChild;
        } else if (node.type === 'discovered') {
          matchType = node.deviceType === filterType;
        }
      }

      matches[node.id] = matchQuery && matchType;
    });

    // Asegurar que si un nodo descubierto o router central coincide, sus agentes descubridores y el servidor también se resalten
    nodes.forEach((node) => {
      if ((node.type === 'discovered' || node.type === 'Router') && matches[node.id]) {
        if (node.discoveredBy) {
          node.discoveredBy.split(', ').forEach(agentId => {
            matches[agentId] = true;
          });
        }
        matches['server-console'] = true;
      }
      if (node.type === 'agent' && matches[node.id]) {
        matches['server-console'] = true;
      }
    });

    return matches;
  }, [nodes, searchQuery, filterType]);

  // Nodo actualmente seleccionado para inspección
  const selectedNode = useMemo(() => {
    if (!selectedNodeId) return null;
    return nodes.find(n => n.id === selectedNodeId) || null;
  }, [selectedNodeId, nodes]);

  // Iconos por tipo de dispositivo
  const getNodeIcon = (type: string, deviceType?: string, status?: string, q?: boolean) => {
    const size = 18;
    if (type === 'Router') return <Wifi size={24} className="text-cyan-400 animate-pulse" />;
    if (type === 'server') return <Server size={22} className="text-blue-400" />;
    
    if (type === 'agent') {
      if (q) return <ShieldAlert size={20} className="text-red-500 animate-pulse" />;
      return <Monitor size={20} className={status === 'ONLINE' ? 'text-green-400' : 'text-gray-500'} />;
    }

    // Dispositivos descubiertos
    switch (deviceType) {
      case 'Router': return <Wifi size={size} className="text-cyan-400" />;
      case 'TV': return <Tv size={size} className="text-purple-400" />;
      case 'Mobile': return <Smartphone size={size} className="text-orange-400" />;
      case 'Printer': return <Printer size={size} className="text-yellow-400" />;
      case 'Server': return <Server size={size} className="text-blue-400" />;
      case 'PC/Laptop': return <Monitor size={size} className="text-green-400" />;
      default: return <Cpu size={size} className="text-white/60" />;
    }
  };

  const getIconOffset = (nodeType: string) => {
    if (nodeType === 'Router') return -12;
    if (nodeType === 'server') return -11;
    if (nodeType === 'agent') return -10;
    return -9; // discovered
  };

  // Color de borde de los nodos
  const getNodeColor = (node: GraphNode) => {
    if (node.type === 'Router') return 'from-cyan-500 to-cyan-700 shadow-cyan-500/50';
    if (node.type === 'server') return 'from-blue-600 to-indigo-600 shadow-blue-500/50';
    if (node.type === 'agent') {
      if (node.quarantine) return 'from-red-600 to-orange-600 shadow-red-500/50 animate-pulse';
      return node.status === 'ONLINE' 
        ? 'from-green-600 to-emerald-600 shadow-green-500/50' 
        : 'from-gray-700 to-slate-800 shadow-gray-500/20';
    }
    
    // Dispositivos descubiertos
    switch (node.deviceType) {
      case 'Router': return 'from-cyan-600 to-blue-600';
      case 'TV': return 'from-purple-600 to-pink-600';
      case 'Mobile': return 'from-orange-600 to-amber-600';
      case 'Printer': return 'from-yellow-600 to-amber-600';
      case 'Server': return 'from-indigo-600 to-blue-600';
      default: return 'from-slate-700 to-slate-800';
    }
  };

  const resetLayout = () => {
    setNodePositions({});
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  // Métricas de red consolidadas
  const metrics = useMemo(() => {
    const totalAgents = devices.length;
    const onlineAgents = devices.filter(d => d.status === 'ONLINE').length;
    const offlineAgents = totalAgents - onlineAgents;
    const quarantined = devices.filter(d => d.quarantine === 1).length;
    const totalDiscovered = nodes.filter(n => n.type === 'discovered').length;
    const totalRouters = nodes.filter(n => n.type === 'Router').length;

    return {
      totalAgents,
      onlineAgents,
      offlineAgents,
      quarantined,
      totalDiscovered,
      totalRouters
    };
  }, [devices, nodes]);

  return (
    <div className="h-full w-full flex flex-col relative overflow-hidden bg-[#010102]">
      {/* BARRA SUPERIOR DE FILTROS */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-6 bg-black/30 border-b border-white/5 backdrop-blur-md z-10">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-blue-600/10 border border-blue-500/20 rounded-2xl text-blue-500">
            <Network size={20} />
          </div>
          <div>
            <h3 className="text-lg font-black tracking-tight">Topología de Red</h3>
            <p className="text-[10px] text-white/40 uppercase tracking-wider font-bold">Mapa interactivo de la infraestructura</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* Selector de Tipo */}
          <div className="relative">
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="bg-white/5 border border-white/10 px-4 py-2.5 rounded-xl text-xs font-bold text-white outline-none focus:border-blue-500/50 appearance-none pr-8 cursor-pointer"
            >
              <option value="all" className="bg-[#0c0c12]">Todos los Dispositivos</option>
              <option value="Router" className="bg-[#0c0c12]">Routers/Gateways</option>
              <option value="PC/Laptop" className="bg-[#0c0c12]">Portátiles y PCs</option>
              <option value="Printer" className="bg-[#0c0c12]">Impresoras</option>
              <option value="Mobile" className="bg-[#0c0c12]">Dispositivos Móviles</option>
              <option value="TV" className="bg-[#0c0c12]">Smart TVs</option>
              <option value="Server" className="bg-[#0c0c12]">Servidores</option>
              <option value="Generic" className="bg-[#0c0c12]">Genéricos / Otros</option>
            </select>
            <div className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none text-white/30 text-[8px]">▼</div>
          </div>

          {/* Buscador */}
          <div className="relative w-60">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-white/30" size={14} />
            <input
              type="text"
              placeholder="Buscar por IP, Hostname..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-white/5 border border-white/10 pl-9 pr-4 py-2.5 rounded-xl text-xs text-white outline-none focus:border-blue-500/50"
            />
            {searchQuery && (
              <button 
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-white/30 hover:text-white"
              >
                <X size={12} />
              </button>
            )}
          </div>

          {/* Acciones del mapa */}
          <button
            onClick={resetLayout}
            title="Restaurar mapa"
            className="p-2.5 bg-white/5 border border-white/10 rounded-xl hover:bg-white/10 transition-colors text-white/60 hover:text-white"
          >
            <RefreshCw size={14} />
          </button>

          <button
            onClick={() => setShowHelp(!showHelp)}
            title="Ayuda de controles"
            className="p-2.5 bg-white/5 border border-white/10 rounded-xl hover:bg-white/10 transition-colors text-white/60 hover:text-white"
          >
            <HelpCircle size={14} />
          </button>
        </div>
      </div>

      {/* ÁREA DEL MAPA (SVG INTERACTIVO) */}
      <div className="flex-1 w-full relative cursor-grab active:cursor-grabbing select-none overflow-hidden">
        {/* Panel de Estadísticas Flotante Premium */}
        <div className="absolute top-4 right-4 p-4 bg-black/60 border border-white/5 backdrop-blur-xl rounded-2xl z-10 space-y-3 shadow-2xl min-w-[200px] text-xs pointer-events-auto transition-all duration-300">
          <div className="flex items-center justify-between border-b border-white/5 pb-2">
            <span className="font-black text-white/50 uppercase tracking-widest text-[9px]">Monitoreo de Red</span>
            <div className="flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${metrics.quarantined > 0 ? 'bg-red-500 animate-ping' : 'bg-emerald-500 animate-pulse'}`} />
              <span className="text-[10px] font-bold text-white/80">{metrics.quarantined > 0 ? 'Alerta' : 'Protegida'}</span>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3 text-[11px]">
            <div>
              <p className="text-white/40 text-[9px] uppercase font-bold">Agentes EDR</p>
              <p className="text-base font-black text-white mt-0.5">
                {metrics.onlineAgents}<span className="text-white/30 text-xs font-normal"> / {metrics.totalAgents}</span>
              </p>
            </div>
            <div>
              <p className="text-white/40 text-[9px] uppercase font-bold">Descubiertos</p>
              <p className="text-base font-black text-cyan-400 mt-0.5">{metrics.totalDiscovered}</p>
            </div>
            <div>
              <p className="text-white/40 text-[9px] uppercase font-bold">Routers Núcleo</p>
              <p className="text-base font-black text-blue-400 mt-0.5">{metrics.totalRouters}</p>
            </div>
            <div>
              <p className="text-white/40 text-[9px] uppercase font-bold">Aislados</p>
              <p className={`text-base font-black mt-0.5 ${metrics.quarantined > 0 ? 'text-red-500 animate-pulse' : 'text-white/50'}`}>
                {metrics.quarantined}
              </p>
            </div>
          </div>
          
          {/* Botón rápido para activar/desactivar la retícula */}
          <div className="flex items-center justify-between pt-2 border-t border-white/5">
            <span className="text-white/40 text-[9px] uppercase font-bold">Ver Cuadrícula</span>
            <button
              onClick={() => setShowGrid(!showGrid)}
              className={`px-2.5 py-1 rounded-md text-[9px] font-black transition-all ${
                showGrid ? 'bg-[#22d3ee]/20 text-[#22d3ee] border border-[#22d3ee]/30' : 'bg-white/5 text-white/40 border border-white/10'
              }`}
            >
              {showGrid ? 'ACTIVA' : 'INACTIVA'}
            </button>
          </div>
        </div>

        {/* Panel de ayuda flotante */}
        {showHelp && (
          <div className="absolute top-4 left-4 p-5 bg-black/80 border border-white/10 backdrop-blur-xl rounded-2xl text-[11px] text-white/70 max-w-xs z-10 space-y-3 shadow-2xl">
            <div className="flex justify-between items-center mb-1">
              <span className="font-bold text-white uppercase tracking-wider">Controles del Mapa</span>
              <button onClick={() => setShowHelp(false)} className="text-white/40 hover:text-white"><X size={14} /></button>
            </div>
            <div className="flex gap-3 items-center">
              <MousePointer size={16} className="text-blue-500 flex-shrink-0" />
              <span><strong>Click Izquierdo:</strong> Selecciona un equipo para inspeccionar sus detalles.</span>
            </div>
            <div className="flex gap-3 items-center">
              <Layout size={16} className="text-blue-500 flex-shrink-0" />
              <span><strong>Arrastrar Fondo:</strong> Desplazarse por el mapa (Pan).</span>
            </div>
            <div className="flex gap-3 items-center">
              <Eye size={16} className="text-blue-500 flex-shrink-0" />
              <span><strong>Rueda del ratón:</strong> Hacer zoom in / zoom out.</span>
            </div>
            <div className="flex gap-3 items-center">
              <RefreshCw size={16} className="text-blue-500 flex-shrink-0" />
              <span><strong>Arrastrar Nodos:</strong> Puedes reubicar cualquier equipo para personalizar la vista.</span>
            </div>
          </div>
        )}

        {/* CONTENEDOR SVG PRINCIPAL */}
        <svg
          ref={containerRef}
          className="w-full h-full"
          onMouseDown={handleBgMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUpOrLeave}
          onMouseLeave={handleMouseUpOrLeave}
          onWheel={handleWheel}
        >
          {/* DEFINICIÓN DE FILTROS (GLOWS, GRADIENTES, PUNTAS DE FLECHA) */}
          <defs>
            <filter id="glow-heavy" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="6" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
            <filter id="glow-light" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
            {/* Patrón de Cuadrícula Tecnológica */}
            <pattern id="grid-pattern" width="50" height="50" patternUnits="userSpaceOnUse">
              <path d="M 50 0 L 0 0 0 50" fill="none" stroke="rgba(255, 255, 255, 0.035)" strokeWidth="1" />
              <circle cx="50" cy="50" r="1.5" fill="rgba(34, 211, 238, 0.15)" />
            </pattern>
            {/* Punta de Flecha para Enlaces */}
            <marker
              id="arrow"
              viewBox="0 0 10 10"
              refX="22"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(255,255,255,0.15)" />
            </marker>
          </defs>

          {/* GRUPO CON TRANSFORMACIONES DE PAN & ZOOM */}
          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
            {/* Cuadrícula de fondo */}
            {showGrid && (
              <rect
                x="-5000"
                y="-5000"
                width="10000"
                height="10000"
                fill="url(#grid-pattern)"
                className="pointer-events-none"
              />
            )}
            {/* ENLACES / CONEXIONES */}
            {links.map((link) => {
              const sourcePos = nodePositions[link.source];
              const targetPos = nodePositions[link.target];
              if (!sourcePos || !targetPos) return null;

              const isSourceMatch = nodeMatchesFilter[link.source];
              const isTargetMatch = nodeMatchesFilter[link.target];
              const isFaded = !isSourceMatch || !isTargetMatch;

              const isRouterLink = link.source.startsWith('central-router-') || link.target.startsWith('central-router-');

              // Cálculos de Spotlight (Foco por Hover)
              const hasHoveredNode = hoveredNodeId !== null;
              const isLinkConnectedToHovered = link.source === hoveredNodeId || link.target === hoveredNodeId;
              
              let opacityValue = isFaded ? 0.05 : 1;
              if (hasHoveredNode) {
                opacityValue = isLinkConnectedToHovered ? 0.95 : 0.04;
              }

              // Acelerar animación si el enlace conecta con el nodo en hover
              const animDuration = isLinkConnectedToHovered 
                ? (isRouterLink ? "1.8s" : "2.5s") 
                : (isRouterLink ? "4s" : "6s");

              return (
                <g key={link.id} className="transition-all duration-300">
                  {/* Línea de fondo del enlace */}
                  <line
                    x1={sourcePos.x}
                    y1={sourcePos.y}
                    x2={targetPos.x}
                    y2={targetPos.y}
                    stroke={
                      isRouterLink
                        ? 'rgba(34, 211, 238, 0.25)'
                        : link.type === 'server-agent'
                        ? 'rgba(59, 130, 246, 0.2)'
                        : link.type === 'agent-agent'
                        ? 'rgba(168, 85, 247, 0.25)'
                        : 'rgba(16, 185, 129, 0.08)'
                    }
                    strokeWidth={isRouterLink ? 3.5 : link.type === 'server-agent' ? 3 : link.type === 'agent-agent' ? 2 : 1.5}
                    className="transition-all duration-300"
                    opacity={opacityValue}
                  />

                  {/* Línea animada (pulso de datos) para enlaces activos/resaltados */}
                  {(!isFaded && (!hasHoveredNode || isLinkConnectedToHovered)) && (
                    <line
                      x1={sourcePos.x}
                      y1={sourcePos.y}
                      x2={targetPos.x}
                      y2={targetPos.y}
                      stroke={
                        isRouterLink
                          ? '#22d3ee'
                          : link.type === 'server-agent'
                          ? '#3b82f6'
                          : link.type === 'agent-agent'
                          ? '#a855f7'
                          : '#10b981'
                      }
                      strokeWidth={isRouterLink ? 3.5 : link.type === 'server-agent' ? 2 : 1}
                      strokeDasharray="6, 15"
                      opacity={0.7}
                    >
                      <animate
                        attributeName="stroke-dashoffset"
                        values="100;0"
                        dur={animDuration}
                        repeatCount="indefinite"
                      />
                    </line>
                  )}
                </g>
              );
            })}

            {/* NODOS */}
            {nodes.map((node) => {
              const pos = nodePositions[node.id] || { x: 350, y: 300 };
              const isMatch = nodeMatchesFilter[node.id];
              const isSelected = selectedNodeId === node.id;
              
              // Estilo del tamaño según tipo de nodo
              let radius = 24;
              if (node.type === 'server') radius = 30;
              else if (node.type === 'agent') radius = 26;
              else if (node.type === 'Router') radius = 32;

              // Cálculos de Spotlight (Foco por Hover)
              const hasHoveredNode = hoveredNodeId !== null;
              const isNodeHovered = node.id === hoveredNodeId;
              const isConnectedToHovered = links.some(l => 
                (l.source === hoveredNodeId && l.target === node.id) || 
                (l.target === hoveredNodeId && l.source === node.id)
              );

              // Opacidad según si coincide con filtros y Spotlight
              let opacityValue = isMatch ? 1 : 0.25;
              if (hasHoveredNode) {
                if (isNodeHovered || isConnectedToHovered || node.type === 'server') {
                  opacityValue = 1;
                } else {
                  opacityValue = 0.12; // Atenuar nodos no relacionados
                }
              }

              // Escala de transformación al hacer hover
              const scaleValue = isNodeHovered ? 1.15 : 1;

              return (
                <g
                  key={node.id}
                  transform={`translate(${pos.x}, ${pos.y}) scale(${scaleValue})`}
                  onMouseDown={(e) => handleNodeMouseDown(e, node.id)}
                  onMouseEnter={() => setHoveredNodeId(node.id)}
                  onMouseLeave={() => setHoveredNodeId(null)}
                  className="cursor-pointer select-none group transition-all duration-300 ease-out"
                  opacity={opacityValue}
                >
                  {/* Efecto Glow exterior para nodos seleccionados o críticos */}
                  {(isSelected || (isNodeHovered && hasHoveredNode)) && (
                    <circle
                      r={radius + 8}
                      className={`transition-all duration-300 ${node.type === 'Router' ? "fill-cyan-500/10 stroke-cyan-500/35" : "fill-blue-500/10 stroke-blue-500/35"}`}
                      strokeWidth={1.5}
                      filter="url(#glow-heavy)"
                    />
                  )}

                  {node.quarantine && (
                    <circle
                      r={radius + 6}
                      className="fill-red-500/5 stroke-red-500/40"
                      strokeWidth={1.5}
                      filter="url(#glow-light)"
                    >
                      <animate
                        attributeName="r"
                        values={`${radius + 3};${radius + 9};${radius + 3}`}
                        dur="2s"
                        repeatCount="indefinite"
                      />
                    </circle>
                  )}

                  {/* Anillo de pulso exclusivo para routers centrales */}
                  {node.type === 'Router' && (
                    <circle
                      r={radius + 8}
                      className="fill-cyan-500/5 stroke-cyan-400/40"
                      strokeWidth={1.5}
                      filter="url(#glow-light)"
                    >
                      <animate
                        attributeName="r"
                        values={`${radius + 4};${radius + 14};${radius + 4}`}
                        dur="2.5s"
                        repeatCount="indefinite"
                      />
                    </circle>
                  )}

                  {/* Círculo Principal de Fondo con Gradiente */}
                  <circle
                    r={radius}
                    fill="url(#node-grad)"
                    className={`stroke-white/10 group-hover:stroke-white/40 transition-colors shadow-2xl`}
                    strokeWidth={isSelected ? 2.5 : 1}
                    style={{
                      fill: `url(#grad-${node.id})`
                    }}
                  />

                  {/* Gradiente Local para este Nodo específico */}
                  <defs>
                    <radialGradient id={`grad-${node.id}`} cx="30%" cy="30%" r="70%">
                      <stop 
                        offset="0%" 
                        stopColor={
                          node.type === 'Router' ? '#22d3ee' :
                          node.type === 'server' ? '#60a5fa' : 
                          node.type === 'agent' ? (node.quarantine ? '#f87171' : node.status === 'ONLINE' ? '#34d399' : '#94a3b8') : 
                          '#c084fc'
                        } 
                      />
                      <stop 
                        offset="100%" 
                        stopColor={
                          node.type === 'Router' ? '#0e7490' :
                          node.type === 'server' ? '#1e3a8a' : 
                          node.type === 'agent' ? (node.quarantine ? '#991b1b' : node.status === 'ONLINE' ? '#065f46' : '#334155') : 
                          '#581c87'
                        } 
                      />
                    </radialGradient>
                  </defs>

                  {/* Icono del Dispositivo */}
                  <g transform="translate(0, 0)" className="text-white flex items-center justify-center pointer-events-none">
                    {/* Pequeño offset para centrar el icono dentro del círculo */}
                    <g transform={`translate(${getIconOffset(node.type)}, ${getIconOffset(node.type)})`}>
                      {getNodeIcon(node.type, node.deviceType, node.status, node.quarantine)}
                    </g>
                  </g>

                  {/* Etiqueta de Texto Inferior */}
                  <text
                    y={radius + 18}
                    textAnchor="middle"
                    className="fill-white/80 font-black tracking-tight text-[10px] pointer-events-none drop-shadow-[0_2px_4px_rgba(0,0,0,0.8)]"
                  >
                    {node.label}
                  </text>

                  {/* Mini Indicador de Estado para Agentes */}
                  {node.type === 'agent' && (
                    <circle
                      cx={radius - 6}
                      cy={-radius + 6}
                      r={4}
                      className={node.status === 'ONLINE' ? 'fill-green-400 stroke-black/50' : 'fill-red-500 stroke-black/50'}
                      strokeWidth={1}
                    />
                  )}
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {/* PANEL LATERAL DE DETALLES (GLASSMORPHIC) */}
      {selectedNode && (
        <aside className="absolute right-0 top-0 bottom-0 w-80 bg-black/60 border-l border-white/10 backdrop-blur-2xl p-6 flex flex-col z-20 shadow-2xl transition-all duration-300 animate-in slide-in-from-right-8">
          {/* Header */}
          <div className="flex justify-between items-start mb-6">
            <div>
              <div className="text-blue-500 text-[9px] font-black tracking-widest uppercase mb-1">Inspección de Nodo</div>
              <h4 className="text-xl font-black text-white leading-tight truncate max-w-[200px]">{selectedNode.label}</h4>
            </div>
            <button
              onClick={() => setSelectedNodeId(null)}
              className="p-1.5 bg-white/5 border border-white/10 rounded-xl text-white/50 hover:text-white hover:bg-white/10 transition-all"
            >
              <X size={16} />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto space-y-6 pr-1">
            {/* Identificación principal */}
            <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-4 flex items-center gap-4">
              <div className="w-12 h-12 bg-white/5 rounded-2xl flex items-center justify-center">
                {getNodeIcon(selectedNode.type, selectedNode.deviceType, selectedNode.status, selectedNode.quarantine)}
              </div>
              <div>
                <p className="text-[9px] font-black opacity-30 uppercase">Categoría</p>
                <p className="text-sm font-bold text-white">
                  {selectedNode.type === 'server'
                    ? 'Servidor Central'
                    : selectedNode.type === 'Router'
                    ? 'Router Principal (Puerta de Enlace)'
                    : selectedNode.type === 'agent'
                    ? 'Agente de Seguridad'
                    : `Descubierto: ${selectedNode.deviceType}`}
                </p>
              </div>
            </div>

            {/* Detalles Técnicos */}
            <div className="space-y-4">
              <p className="text-[10px] font-black opacity-20 uppercase tracking-widest border-b border-white/5 pb-2">Información Técnica</p>
              
              {selectedNode.type === 'server' && (
                <DetailRow label="Dirección de Consola" value="Servidor Local" />
              )}

              {selectedNode.type === 'agent' && selectedNode.originalDevice && (
                <>
                  <DetailRow label="Hostname del PC" value={selectedNode.originalDevice.hostname} />
                  <DetailRow label="Estado EDR" value={selectedNode.originalDevice.status} valueColor={selectedNode.originalDevice.status === 'ONLINE' ? 'text-green-400' : 'text-red-500'} />
                  <DetailRow 
                    label="Aislamiento (Quarantine)" 
                    value={selectedNode.originalDevice.quarantine === 1 ? 'AISLADO / CORTADO' : 'CONECTADO A LA RED'} 
                    valueColor={selectedNode.originalDevice.quarantine === 1 ? 'text-red-400 animate-pulse font-black' : 'text-green-400'} 
                  />
                  <DetailRow label="Última Sincronización" value={new Date(selectedNode.originalDevice.last_seen).toLocaleString()} />
                  {selectedNode.originalDevice.active_connections && (
                    <DetailRow label="Conexiones Activas" value={`${selectedNode.originalDevice.active_connections.length} establecidas`} />
                  )}
                  {selectedNode.originalDevice.network_map && (
                    <DetailRow label="Vecinos en Red local" value={`${selectedNode.originalDevice.network_map.length} dispositivos`} />
                  )}
                </>
              )}

              {(selectedNode.type === 'discovered' || selectedNode.type === 'Router') && (
                <>
                  <DetailRow label="Dirección IP" value={selectedNode.ip || '---'} />
                  <DetailRow label="Dirección MAC" value={selectedNode.mac || '---'} />
                  <DetailRow label="Tipo Clasificado" value={selectedNode.deviceType || 'Genérico'} />
                  <DetailRow label="Descubierto por" value={selectedNode.discoveredBy || '---'} valueColor="text-blue-400" />
                </>
              )}
            </div>

            {/* Acciones de Control EDR */}
            {selectedNode.type === 'agent' && selectedNode.originalDevice && (
              <div className="pt-6 border-t border-white/5 space-y-3">
                <p className="text-[10px] font-black opacity-20 uppercase tracking-widest">Acciones de EDR</p>
                {currentUserRole === 'ADMIN' ? (
                  <button
                    onClick={async () => {
                      if (!selectedNode.originalDevice) return;
                      const enable = selectedNode.originalDevice.quarantine !== 1;
                      await onToggleQuarantine(selectedNode.id, enable);
                      // Forzar actualizar el panel lateral
                      setSelectedNodeId(null);
                    }}
                    className={`w-full p-4 rounded-2xl text-xs font-black transition-all flex items-center justify-center gap-2 ${
                      selectedNode.originalDevice.quarantine === 1
                        ? 'bg-green-600 hover:bg-green-500 text-white'
                        : 'bg-red-500/10 hover:bg-red-500 text-red-500 hover:text-white border border-red-500/20'
                    }`}
                  >
                    {selectedNode.originalDevice.quarantine === 1 ? (
                      <>
                        <Unlock size={14} /> LEVANTAR CUARENTENA
                      </>
                    ) : (
                      <>
                        <Lock size={14} /> AISLAR DISPOSITIVO
                      </>
                    )}
                  </button>
                ) : (
                  <div className="p-4 bg-white/5 border border-white/5 rounded-2xl flex items-start gap-3">
                    <PowerOff size={16} className="text-red-500 mt-0.5 flex-shrink-0" />
                    <p className="text-[10px] text-white/50 leading-relaxed">
                      Requiere permisos de <strong>ADMINISTRADOR</strong> para realizar acciones de mitigación y aislamiento de red en este equipo.
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>
        </aside>
      )}
    </div>
  );
};

interface DetailRowProps {
  label: string;
  value: string;
  valueColor?: string;
}

const DetailRow: React.FC<DetailRowProps> = ({ label, value, valueColor = 'text-white/80' }) => (
  <div className="flex justify-between items-baseline gap-2 text-xs py-1">
    <span className="text-white/40 font-semibold">{label}</span>
    <span className={`font-bold text-right truncate max-w-[150px] ${valueColor}`} title={value}>{value}</span>
  </div>
);
