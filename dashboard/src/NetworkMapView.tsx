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
  type: 'server' | 'agent' | 'discovered';
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
  type: 'server-agent' | 'agent-device';
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

  const containerRef = useRef<SVGSVGElement | null>(null);

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

      // Enlace: Servidor -> Agente
      listLinks.push({
        id: `server-${device.hostname}`,
        source: 'server-console',
        target: device.hostname,
        type: 'server-agent'
      });

      // 3. Nodos Descubiertos (solo si el agente está ONLINE y tiene mapa de red)
      if (device.status === 'ONLINE' && Array.isArray(device.network_map)) {
        device.network_map.forEach((d) => {
          const nodeId = `${device.hostname}-discovered-${d.ip}`;
          listNodes.push({
            id: nodeId,
            label: d.hostname || d.ip,
            type: 'discovered',
            status: 'ONLINE',
            deviceType: d.type,
            ip: d.ip,
            mac: d.mac,
            discoveredBy: device.hostname
          });

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
    const cx = 380;
    const cy = 300;

    // Posición del servidor central
    initialPositions['server-console'] = { x: cx, y: cy };

    // Filtrar agentes
    const agents = nodes.filter(n => n.type === 'agent');
    const N = agents.length;

    agents.forEach((agent, i) => {
      const theta = (2 * Math.PI * i) / (N || 1);
      const R1 = 180;
      const ax = cx + R1 * Math.cos(theta);
      const ay = cy + R1 * Math.sin(theta);
      
      initialPositions[agent.id] = { x: ax, y: ay };

      // Filtrar dispositivos descubiertos por este agente
      const discovered = nodes.filter(n => n.type === 'discovered' && n.discoveredBy === agent.id);
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
  }, [nodes]);

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
        } else if (node.type === 'agent') {
          // El agente siempre se muestra si algún dispositivo descubierto coincide
          const hasMatchingChild = nodes.some(
            c => c.type === 'discovered' && c.discoveredBy === node.id && c.deviceType === filterType
          );
          matchType = hasMatchingChild;
        } else if (node.type === 'discovered') {
          matchType = node.deviceType === filterType;
        }
      }

      matches[node.id] = matchQuery && matchType;
    });

    // Asegurar que si un nodo descubierto coincide, su agente padre y el servidor también se resalten
    nodes.forEach((node) => {
      if (node.type === 'discovered' && matches[node.id]) {
        if (node.discoveredBy) {
          matches[node.discoveredBy] = true;
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

  // Color de borde de los nodos
  const getNodeColor = (node: GraphNode) => {
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
            {/* ENLACES / CONEXIONES */}
            {links.map((link) => {
              const sourcePos = nodePositions[link.source];
              const targetPos = nodePositions[link.target];
              if (!sourcePos || !targetPos) return null;

              const isSourceMatch = nodeMatchesFilter[link.source];
              const isTargetMatch = nodeMatchesFilter[link.target];
              const isFaded = !isSourceMatch || !isTargetMatch;

              return (
                <g key={link.id}>
                  {/* Línea de fondo del enlace */}
                  <line
                    x1={sourcePos.x}
                    y1={sourcePos.y}
                    x2={targetPos.x}
                    y2={targetPos.y}
                    stroke={link.type === 'server-agent' ? 'rgba(59, 130, 246, 0.2)' : 'rgba(255, 255, 255, 0.08)'}
                    strokeWidth={link.type === 'server-agent' ? 3 : 1.5}
                    className="transition-all duration-300"
                    opacity={isFaded ? 0.1 : 1}
                  />

                  {/* Línea animada (pulso de datos) para enlaces activos/resaltados */}
                  {!isFaded && (
                    <line
                      x1={sourcePos.x}
                      y1={sourcePos.y}
                      x2={targetPos.x}
                      y2={targetPos.y}
                      stroke={link.type === 'server-agent' ? '#3b82f6' : '#a855f7'}
                      strokeWidth={link.type === 'server-agent' ? 2 : 1}
                      strokeDasharray="6, 15"
                      opacity={0.6}
                    >
                      <animate
                        attributeName="stroke-dashoffset"
                        values="100;0"
                        dur="6s"
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

              return (
                <g
                  key={node.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  onMouseDown={(e) => handleNodeMouseDown(e, node.id)}
                  className="cursor-pointer select-none group"
                  opacity={isMatch ? 1 : 0.25}
                >
                  {/* Efecto Glow exterior para nodos seleccionados o críticos */}
                  {isSelected && (
                    <circle
                      r={radius + 8}
                      className="fill-blue-500/10 stroke-blue-500/30"
                      strokeWidth={1}
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

                  {/* Círculo Principal de Fondo con Gradiente */}
                  <circle
                    r={radius}
                    fill="url(#node-grad)"
                    className={`stroke-white/10 hover:stroke-white/30 transition-colors shadow-2xl`}
                    strokeWidth={isSelected ? 2 : 1}
                    style={{
                      fill: `url(#grad-${node.id})`
                    }}
                  />

                  {/* Gradiente Local para este Nodo específico */}
                  <defs>
                    <radialGradient id={`grad-${node.id}`} cx="30%" cy="30%" r="70%">
                      <stop offset="0%" stopColor={node.type === 'server' ? '#60a5fa' : node.type === 'agent' ? (node.quarantine ? '#f87171' : node.status === 'ONLINE' ? '#34d399' : '#94a3b8') : '#c084fc'} />
                      <stop offset="100%" stopColor={node.type === 'server' ? '#1e3a8a' : node.type === 'agent' ? (node.quarantine ? '#991b1b' : node.status === 'ONLINE' ? '#065f46' : '#334155') : '#581c87'} />
                    </radialGradient>
                  </defs>

                  {/* Icono del Dispositivo */}
                  <g transform="translate(0, 0)" className="text-white flex items-center justify-center pointer-events-none">
                    {/* Pequeño offset para centrar el icono dentro del círculo */}
                    <g transform="translate(-10, -10)">
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
                <p className="text-sm font-bold text-white capitalize">
                  {selectedNode.type === 'server' ? 'Servidor Central' : selectedNode.type === 'agent' ? 'Agente de Seguridad' : `Descubierto: ${selectedNode.deviceType}`}
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

              {selectedNode.type === 'discovered' && (
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
