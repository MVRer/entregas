defmodule NetworkTrafficAnalyzer do
  @moduledoc """
  Analizador de Tráfico de Red Avanzado con Visualización en Tiempo Real

  Este sistema captura y analiza tráfico de red en tiempo real, proporcionando:
  - Análisis profundo de protocolos (L2-L7)
  - Visualización de flujos de red en tiempo real
  - Detección de patrones de comunicación anómalos
  - Análisis geográfico de conexiones
  - Mapeo de topología de red
  - Detección de botnets y comunicaciones C2
  - Análisis de metadatos de tráfico encriptado
  - Dashboard interactivo con gráficas ASCII
  - Análisis forense de sesiones

  LEGAL: Solo para uso en redes propias con autorización.
  """

  require Logger
  use GenServer

  # Configuración de análisis de protocolos
  @protocol_analyzers %{
    ethernet: %{
      enabled: true,
      analysis_depth: :deep,
      track_mac_vendors: true,
      detect_mac_spoofing: true
    },

    ipv4: %{
      enabled: true,
      track_fragmentation: true,
      detect_ip_spoofing: true,
      analyze_ttl_patterns: true,
      geolocation: true
    },

    ipv6: %{
      enabled: true,
      track_extension_headers: true,
      analyze_flow_labels: true
    },

    tcp: %{
      enabled: true,
      reconstruct_streams: true,
      analyze_window_scaling: true,
      detect_syn_flood: true,
      track_connection_states: true,
      timing_analysis: true
    },

    udp: %{
      enabled: true,
      track_flows: true,
      detect_dns_tunneling: true,
      analyze_payload_entropy: true
    },

    dns: %{
      enabled: true,
      track_queries: true,
      detect_dga: true,
      analyze_response_patterns: true,
      cache_poisoning_detection: true
    },

    http: %{
      enabled: true,
      reconstruct_sessions: true,
      extract_metadata: true,
      detect_c2_patterns: true,
      user_agent_analysis: true
    },

    tls: %{
      enabled: true,
      certificate_analysis: true,
      cipher_suite_analysis: true,
      timing_analysis: true,
      ja3_fingerprinting: true
    }
  }

  # Patrones de detección de amenazas de red
  @threat_patterns %{
    # Botnets conocidas
    botnet_patterns: %{
      mirai: %{
        c2_ports: [23, 2323, 7547],
        communication_patterns: [:short_bursts, :regular_intervals],
        payload_characteristics: [:binary_data, :encrypted]
      },

      emotet: %{
        c2_ports: [443, 8080],
        communication_patterns: [:https_c2, :domain_generation],
        payload_characteristics: [:json_data, :base64_encoded]
      }
    },

    # Patrones de C2
    c2_indicators: [
      :regular_beaconing,
      :encrypted_short_messages,
      :unusual_protocols,
      :domain_generation_algorithm,
      :fast_flux_dns
    ],

    # Exfiltración de datos
    exfiltration_patterns: [
      :large_outbound_transfers,
      :unusual_protocols_for_data,
      :encrypted_tunneling,
      :covert_channels
    ],

    # Lateral movement
    lateral_movement: [
      :smb_enumeration,
      :rdp_brute_force,
      :ssh_key_reuse,
      :admin_share_access
    ]
  }

  # Configuración de visualización
  @visualization_config %{
    network_map: %{
      enabled: true,
      max_nodes: 1000,
      edge_threshold: 10,
      geo_mapping: true
    },

    flow_analysis: %{
      enabled: true,
      time_window: 300_000,  # 5 minutos
      packet_sampling: 0.1   # 10% de paquetes
    },

    protocol_distribution: %{
      enabled: true,
      chart_type: :pie,
      update_interval: 5000
    },

    geographic_heatmap: %{
      enabled: true,
      country_resolution: true,
      city_resolution: false
    }
  }

  defstruct [
    :analyzer_id,
    :capture_interface,
    :packet_capture,
    :protocol_processors,
    :flow_tracker,
    :session_reconstructor,
    :threat_detector,
    :visualization_engine,
    :geo_analyzer,
    :statistics_engine,
    :cli_dashboard,
    :packet_buffer,
    :active_flows,
    :network_topology,
    :threat_intel,
    :start_time
  ]

  ## API Principal

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Inicia la captura y análisis de tráfico.
  """
  def start_analysis(interface, opts \\ []) do
    GenServer.call(__MODULE__, {:start_analysis, interface, opts})
  end

  @doc """
  Detiene el análisis de tráfico.
  """
  def stop_analysis do
    GenServer.call(__MODULE__, :stop_analysis)
  end

  @doc """
  Obtiene estadísticas del análisis en tiempo real.
  """
  def get_statistics do
    GenServer.call(__MODULE__, :get_statistics)
  end

  @doc """
  Obtiene topología de red descubierta.
  """
  def get_network_topology do
    GenServer.call(__MODULE__, :get_topology)
  end

  @doc """
  Obtiene flujos de red activos.
  """
  def get_active_flows(limit \\ 100) do
    GenServer.call(__MODULE__, {:get_flows, limit})
  end

  @doc """
  Inicia dashboard CLI con visualizaciones.
  """
  def start_dashboard do
    GenServer.call(__MODULE__, :start_dashboard)
  end

  @doc """
  Obtiene análisis de protocolo específico.
  """
  def get_protocol_analysis(protocol) do
    GenServer.call(__MODULE__, {:get_protocol_analysis, protocol})
  end

  @doc """
  Busca patrones específicos en el tráfico.
  """
  def search_patterns(pattern_type, criteria) do
    GenServer.call(__MODULE__, {:search_patterns, pattern_type, criteria})
  end

  ## Callbacks del GenServer

  @impl true
  def init(opts) do
    analyzer_id = Keyword.get(opts, :analyzer_id, generate_analyzer_id())

    state = %__MODULE__{
      analyzer_id: analyzer_id,
      packet_buffer: :ets.new(:packet_buffer, [:ordered_set, :public]),
      active_flows: :ets.new(:active_flows, [:set, :public]),
      network_topology: :ets.new(:network_topology, [:set, :public]),
      threat_intel: :ets.new(:threat_intel, [:bag, :public]),
      start_time: System.monotonic_time()
    }

    Logger.info("📊 Network Traffic Analyzer iniciado - ID: #{analyzer_id}")
    {:ok, state}
  end

  @impl true
  def handle_call({:start_analysis, interface, opts}, _from, state) do
    Logger.info("🚀 Iniciando análisis de tráfico en interfaz: #{interface}")

    new_state = %{state |
      capture_interface: interface,
      packet_capture: start_packet_capture(interface, opts),
      protocol_processors: start_protocol_processors(),
      flow_tracker: start_flow_tracker(),
      session_reconstructor: start_session_reconstructor(),
      threat_detector: start_threat_detector(),
      visualization_engine: start_visualization_engine(),
      geo_analyzer: start_geo_analyzer(),
      statistics_engine: start_statistics_engine()
    }

    {:reply, :ok, new_state}
  end

  @impl true
  def handle_call(:stop_analysis, _from, state) do
    Logger.info("⏹️  Deteniendo análisis de tráfico...")
    stop_all_components(state)
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:get_statistics, _from, state) do
    stats = generate_traffic_statistics(state)
    {:reply, stats, state}
  end

  @impl true
  def handle_call(:start_dashboard, _from, state) do
    dashboard_pid = spawn_link(fn -> run_traffic_dashboard(state) end)
    {:reply, {:ok, dashboard_pid}, state}
  end

  @impl true
  def handle_info({:packet_captured, packet}, state) do
    # Procesar paquete capturado
    spawn(fn -> process_captured_packet(packet, state) end)

    {:noreply, state}
  end

  @impl true
  def handle_info({:flow_detected, flow}, state) do
    Logger.debug("🌊 Nuevo flujo detectado: #{flow.src_ip}:#{flow.src_port} -> #{flow.dst_ip}:#{flow.dst_port}")

    # Almacenar flujo activo
    :ets.insert(state.active_flows, {flow.flow_id, flow})

    {:noreply, state}
  end

  @impl true
  def handle_info({:threat_detected, threat}, state) do
    Logger.warn("🚨 AMENAZA DE RED DETECTADA: #{threat.type} - #{threat.description}")

    # Almacenar inteligencia de amenaza
    :ets.insert(state.threat_intel, {System.monotonic_time(), threat})

    {:noreply, state}
  end

  ## Captura de Paquetes

  defp start_packet_capture(interface, opts) do
    capture_pid = spawn_link(fn ->
      packet_capture_loop(interface, opts)
    end)

    Logger.info("📡 Captura de paquetes iniciada en #{interface}")
    capture_pid
  end

  defp packet_capture_loop(interface, opts) do
    # En implementación real usaríamos pcap
    # Por ahora simulamos captura realista

    packet = generate_realistic_packet()
    send(NetworkTrafficAnalyzer, {:packet_captured, packet})

    # Simular rate realista basado en carga de red
    delay = calculate_capture_delay(opts)
    Process.sleep(delay)

    packet_capture_loop(interface, opts)
  end

  defp generate_realistic_packet do
    # Generar paquetes realistas con distribución de protocolos real
    protocol_weights = %{
      tcp: 0.6,    # 60% TCP
      udp: 0.25,   # 25% UDP
      icmp: 0.05,  # 5% ICMP
      other: 0.1   # 10% otros
    }

    protocol = weighted_random_protocol(protocol_weights)

    base_packet = %{
      timestamp: System.monotonic_time(),
      interface: "eth0",
      protocol: protocol,
      src_mac: generate_mac_address(),
      dst_mac: generate_mac_address(),
      src_ip: generate_realistic_ip(),
      dst_ip: generate_realistic_ip(),
      packet_size: generate_realistic_size(protocol),
      ttl: generate_realistic_ttl(),
      flags: generate_protocol_flags(protocol)
    }

    # Agregar campos específicos del protocolo
    enhanced_packet = case protocol do
      :tcp -> add_tcp_fields(base_packet)
      :udp -> add_udp_fields(base_packet)
      :icmp -> add_icmp_fields(base_packet)
      _ -> base_packet
    end

    # Simular ocasionalmente tráfico sospechoso
    if :rand.uniform(100) <= 5 do  # 5% de tráfico sospechoso
      add_suspicious_characteristics(enhanced_packet)
    else
      enhanced_packet
    end
  end

  ## Procesamiento de Paquetes

  defp process_captured_packet(packet, state) do
    # Pipeline de procesamiento multi-capa

    # 1. Análisis de capa física/enlace de datos
    link_analysis = analyze_link_layer(packet)

    # 2. Análisis de capa de red
    network_analysis = analyze_network_layer(packet)

    # 3. Análisis de capa de transporte
    transport_analysis = analyze_transport_layer(packet)

    # 4. Análisis de capa de aplicación
    application_analysis = analyze_application_layer(packet)

    # 5. Actualizar topología de red
    update_network_topology(packet, state)

    # 6. Tracking de flujos
    update_flow_tracking(packet, state)

    # 7. Detección de amenazas
    threat_analysis = analyze_for_threats(packet, [
      link_analysis,
      network_analysis,
      transport_analysis,
      application_analysis
    ])

    # 8. Almacenar para análisis posterior
    store_packet_analysis(packet, %{
      link: link_analysis,
      network: network_analysis,
      transport: transport_analysis,
      application: application_analysis,
      threats: threat_analysis
    }, state)

    # 9. Enviar amenazas detectadas
    if length(threat_analysis.threats) > 0 do
      Enum.each(threat_analysis.threats, fn threat ->
        send(NetworkTrafficAnalyzer, {:threat_detected, threat})
      end)
    end
  end

  ## Análisis por Capas

  defp analyze_link_layer(packet) do
    analysis = %{
      layer: :link,
      protocol: :ethernet,
      src_mac: packet.src_mac,
      dst_mac: packet.dst_mac,
      anomalies: [],
      vendor_info: %{}
    }

    # Análisis de vendor MAC
    src_vendor = lookup_mac_vendor(packet.src_mac)
    dst_vendor = lookup_mac_vendor(packet.dst_mac)

    vendor_analysis = %{
      src_vendor: src_vendor,
      dst_vendor: dst_vendor
    }

    # Detectar posible MAC spoofing
    spoofing_indicators = detect_mac_spoofing(packet.src_mac, packet.src_ip)

    anomalies = if spoofing_indicators.suspicious do
      [:possible_mac_spoofing | analysis.anomalies]
    else
      analysis.anomalies
    end

    %{analysis |
      vendor_info: vendor_analysis,
      anomalies: anomalies,
      spoofing_analysis: spoofing_indicators
    }
  end

  defp analyze_network_layer(packet) do
    case determine_network_protocol(packet) do
      :ipv4 -> analyze_ipv4_packet(packet)
      :ipv6 -> analyze_ipv6_packet(packet)
      :arp -> analyze_arp_packet(packet)
      _ -> %{layer: :network, protocol: :unknown}
    end
  end

  defp analyze_ipv4_packet(packet) do
    analysis = %{
      layer: :network,
      protocol: :ipv4,
      src_ip: packet.src_ip,
      dst_ip: packet.dst_ip,
      ttl: packet.ttl,
      anomalies: [],
      geo_info: %{}
    }

    # Análisis geográfico
    src_geo = geolocate_ip(packet.src_ip)
    dst_geo = geolocate_ip(packet.dst_ip)

    geo_analysis = %{
      src_country: src_geo.country,
      src_city: src_geo.city,
      dst_country: dst_geo.country,
      dst_city: dst_geo.city,
      distance_km: calculate_geographic_distance(src_geo, dst_geo)
    }

    # Análisis de TTL para OS fingerprinting
    os_analysis = analyze_ttl_for_os(packet.ttl)

    # Detectar anomalías IP
    anomalies = []

    # TTL anómalo
    if packet.ttl < 10 or packet.ttl > 255 do
      anomalies = [:unusual_ttl | anomalies]
    end

    # IP spoofing detection (básico)
    if detect_ip_spoofing_indicators(packet) do
      anomalies = [:possible_ip_spoofing | anomalies]
    end

    %{analysis |
      geo_info: geo_analysis,
      os_analysis: os_analysis,
      anomalies: anomalies
    }
  end

  defp analyze_transport_layer(packet) do
    case packet.protocol do
      :tcp -> analyze_tcp_packet(packet)
      :udp -> analyze_udp_packet(packet)
      :icmp -> analyze_icmp_packet(packet)
      _ -> %{layer: :transport, protocol: :unknown}
    end
  end

  defp analyze_tcp_packet(packet) do
    analysis = %{
      layer: :transport,
      protocol: :tcp,
      src_port: packet.src_port,
      dst_port: packet.dst_port,
      flags: packet.flags,
      window_size: packet.window_size,
      sequence: packet.sequence,
      acknowledgment: packet.acknowledgment,
      anomalies: [],
      connection_state: :unknown
    }

    # Análisis de flags TCP
    flag_analysis = analyze_tcp_flags(packet.flags)

    # Análisis de window size para OS fingerprinting
    window_analysis = analyze_tcp_window(packet.window_size)

    # Detectar patrones de escaneo
    scan_indicators = detect_tcp_scan_patterns(packet)

    # Detectar anomalías TCP
    anomalies = []

    if flag_analysis.suspicious do
      anomalies = [:suspicious_tcp_flags | anomalies]
    end

    if scan_indicators.is_scan do
      anomalies = [:tcp_scan_detected | anomalies]
    end

    %{analysis |
      flag_analysis: flag_analysis,
      window_analysis: window_analysis,
      scan_indicators: scan_indicators,
      anomalies: anomalies
    }
  end

  defp analyze_application_layer(packet) do
    case determine_application_protocol(packet) do
      :http -> analyze_http_traffic(packet)
      :https -> analyze_https_traffic(packet)
      :dns -> analyze_dns_traffic(packet)
      :smtp -> analyze_smtp_traffic(packet)
      :ssh -> analyze_ssh_traffic(packet)
      _ -> %{layer: :application, protocol: :unknown}
    end
  end

  defp analyze_dns_traffic(packet) do
    analysis = %{
      layer: :application,
      protocol: :dns,
      query_type: extract_dns_query_type(packet),
      domain: extract_dns_domain(packet),
      response_code: extract_dns_response_code(packet),
      anomalies: []
    }

    domain = analysis.domain
    anomalies = []

    # Detectar DGA (Domain Generation Algorithm)
    if detect_dga_domain(domain) do
      anomalies = [:dga_domain | anomalies]
    end

    # Detectar DNS tunneling
    if detect_dns_tunneling_patterns(packet) do
      anomalies = [:dns_tunneling | anomalies]
    end

    # Detectar fast flux
    if detect_fast_flux_patterns(domain) do
      anomalies = [:fast_flux_dns | anomalies]
    end

    %{analysis | anomalies: anomalies}
  end

  ## Detección de Amenazas

  defp analyze_for_threats(packet, layer_analyses) do
    threats = []

    # Agregar todas las anomalías de todas las capas
    all_anomalies = layer_analyses
                   |> Enum.flat_map(fn analysis ->
                     Map.get(analysis, :anomalies, [])
                   end)

    # Detectar patrones de botnet
    botnet_threats = detect_botnet_patterns(packet, layer_analyses)
    threats = threats ++ botnet_threats

    # Detectar C2 communication
    c2_threats = detect_c2_patterns(packet, layer_analyses)
    threats = threats ++ c2_threats

    # Detectar exfiltración de datos
    exfil_threats = detect_exfiltration_patterns(packet, layer_analyses)
    threats = threats ++ exfil_threats

    # Detectar lateral movement
    lateral_threats = detect_lateral_movement_patterns(packet, layer_analyses)
    threats = threats ++ lateral_threats

    # Crear amenazas basadas en anomalías
    anomaly_threats = create_threats_from_anomalies(packet, all_anomalies)
    threats = threats ++ anomaly_threats

    %{
      threats: threats,
      anomaly_count: length(all_anomalies),
      threat_score: calculate_threat_score(threats, all_anomalies)
    }
  end

  defp detect_botnet_patterns(packet, layer_analyses) do
    threats = []

    # Buscar patrones de Mirai
    if detect_mirai_patterns(packet, layer_analyses) do
      threat = %{
        type: :botnet_communication,
        subtype: :mirai,
        description: "Comunicación Mirai detectada",
        source_ip: packet.src_ip,
        destination_ip: packet.dst_ip,
        confidence: 0.8,
        evidence: ["mirai_port_pattern", "binary_payload"]
      }
      threats = [threat | threats]
    end

    # Buscar patrones de beaconing regular
    if detect_regular_beaconing(packet) do
      threat = %{
        type: :botnet_communication,
        subtype: :beaconing,
        description: "Beaconing regular detectado",
        source_ip: packet.src_ip,
        destination_ip: packet.dst_ip,
        confidence: 0.7,
        evidence: ["regular_intervals", "small_payloads"]
      }
      threats = [threat | threats]
    end

    threats
  end

  ## Dashboard CLI con Visualizaciones

  defp run_traffic_dashboard(state) do
    IO.write("\e[2J\e[H")  # Limpiar pantalla

    dashboard_loop(state, %{
      refresh_rate: 1000,
      current_view: :overview,
      selected_flow: nil,
      time_window: 60_000  # 1 minuto
    })
  end

  defp dashboard_loop(state, dashboard_state) do
    IO.write("\e[2J\e[H")  # Limpiar y posicionar

    case dashboard_state.current_view do
      :overview ->
        render_overview_dashboard(state, dashboard_state)

      :protocol_analysis ->
        render_protocol_dashboard(state, dashboard_state)

      :network_topology ->
        render_topology_dashboard(state, dashboard_state)

      :flow_analysis ->
        render_flow_dashboard(state, dashboard_state)

      :threat_detection ->
        render_threat_dashboard(state, dashboard_state)

      :geographic_view ->
        render_geographic_dashboard(state, dashboard_state)
    end

    render_dashboard_navigation(dashboard_state.current_view)

    # Simular cambio de vista para demo
    new_dashboard_state = cycle_dashboard_views(dashboard_state)

    Process.sleep(dashboard_state.refresh_rate)
    dashboard_loop(state, new_dashboard_state)
  end

  defp render_overview_dashboard(state, dashboard_state) do
    stats = generate_traffic_statistics(state)
    top_flows = get_top_flows(state.active_flows, 5)
    protocol_dist = get_protocol_distribution(state)

    IO.puts("""
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║                   📊 NETWORK TRAFFIC ANALYZER - OVERVIEW 📊                   ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║  Analyzer: #{String.pad_trailing(state.analyzer_id, 20)} │ Uptime: #{format_uptime(stats.uptime_ms)}        ║
    ║  Interface: #{String.pad_trailing(state.capture_interface || "N/A", 19)} │ Status: #{format_status(stats.status)} ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                              TRÁFICO EN TIEMPO REAL                           ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    """)

    # Gráfica de tráfico en tiempo real
    render_traffic_graph(stats.packets_per_second, stats.bytes_per_second)

    IO.puts("""
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                            MÉTRICAS PRINCIPALES                               ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║  Paquetes/seg: #{String.pad_trailing("#{stats.packets_per_second}", 15)} │ Bytes/seg: #{format_bytes(stats.bytes_per_second)}     ║
    ║  Total paquetes: #{String.pad_trailing("#{stats.total_packets}", 13)} │ Flujos activos: #{stats.active_flows}          ║
    ║  Hosts únicos: #{String.pad_trailing("#{stats.unique_hosts}", 15)} │ Amenazas: #{stats.threats_detected}               ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    """)

    # Distribución de protocolos
    render_protocol_distribution(protocol_dist)

    IO.puts("""
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                              TOP FLUJOS                                       ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    """)

    if length(top_flows) > 0 do
      top_flows
      |> Enum.each(fn flow ->
        protocol_str = String.pad_trailing("#{flow.protocol}", 8)
        src_str = String.pad_trailing("#{flow.src_ip}:#{flow.src_port}", 21)
        dst_str = String.pad_trailing("#{flow.dst_ip}:#{flow.dst_port}", 21)
        bytes_str = format_bytes(flow.total_bytes)

        IO.puts("║  #{protocol_str} │ #{src_str} → #{dst_str} │ #{bytes_str} ║")
      end)
    else
      IO.puts("║                          📭 NO HAY FLUJOS ACTIVOS                          ║")
    end
  end

  defp render_traffic_graph(pps, bps) do
    # Crear gráfica ASCII del tráfico
    max_width = 70
    max_height = 6

    # Simular datos históricos para la gráfica
    pps_history = generate_traffic_history(pps, 50)

    if length(pps_history) > 1 do
      max_pps = Enum.max(pps_history)
      min_pps = Enum.min(pps_history)
      range = max(max_pps - min_pps, 1)

      IO.puts("║  PPS (#{min_pps} - #{max_pps}):")

      for row <- (max_height - 1)..0 do
        IO.write("║  ")

        threshold = min_pps + (range * row / (max_height - 1))

        line = for data_point <- pps_history do
          if data_point >= threshold, do: "█", else: " "
        end

        padded_line = line
                    |> Enum.join("")
                    |> String.pad_trailing(max_width)

        IO.puts("#{padded_line} ║")
      end

      IO.puts("║  " <> String.duplicate("─", max_width) <> " ║")
    else
      IO.puts("║  Recopilando datos de tráfico...                                           ║")
    end
  end

  defp render_protocol_distribution(protocol_dist) do
    IO.puts("║                          DISTRIBUCIÓN DE PROTOCOLOS                       ║")
    IO.puts("╠═══════════════════════════════════════════════════════════════════════════╣")

    if map_size(protocol_dist) > 0 do
      total_packets = protocol_dist |> Map.values() |> Enum.sum()

      protocol_dist
      |> Enum.sort_by(&elem(&1, 1), :desc)
      |> Enum.take(5)
      |> Enum.each(fn {protocol, count} ->
        percentage = (count / total_packets) * 100
        bar_length = round(percentage * 0.5)  # Escala la barra
        bar = String.duplicate("█", bar_length) |> String.pad_trailing(40)

        protocol_str = String.pad_trailing("#{protocol}", 8)
        percentage_str = "#{Float.round(percentage, 1)}%"

        IO.puts("║  #{protocol_str}: #{bar} #{percentage_str} ║")
      end)
    else
      IO.puts("║  Sin datos de protocolos disponibles                                       ║")
    end
  end

  defp render_topology_dashboard(state, dashboard_state) do
    topology = get_network_topology_summary(state.network_topology)

    IO.puts("""
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║                       🗺️  TOPOLOGÍA DE RED 🗺️                                ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║  Hosts descubiertos: #{String.pad_trailing("#{topology.total_hosts}", 10)} │ Subredes: #{topology.subnets}          ║
    ║  Conexiones activas: #{String.pad_trailing("#{topology.active_connections}", 10)} │ Routers: #{topology.routers}           ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                             MAPA DE RED ASCII                                 ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    """)

    # Generar representación ASCII de la topología
    render_network_map_ascii(topology)

    IO.puts("""
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                            HOSTS MÁS ACTIVOS                                  ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    """)

    if length(topology.top_hosts) > 0 do
      topology.top_hosts
      |> Enum.take(8)
      |> Enum.each(fn host ->
        ip_str = String.pad_trailing(host.ip, 15)
        connections = String.pad_trailing("#{host.connections}", 8)
        traffic = format_bytes(host.traffic_bytes)

        IO.puts("║  #{ip_str} │ Conexiones: #{connections} │ Tráfico: #{traffic}        ║")
      end)
    else
      IO.puts("║                       📭 NO HAY HOSTS DETECTADOS                           ║")
    end
  end

  defp render_threat_dashboard(state, dashboard_state) do
    threats = get_recent_threats(state.threat_intel, 10)
    threat_stats = calculate_threat_statistics(threats)

    IO.puts("""
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║                       🚨 DETECCIÓN DE AMENAZAS 🚨                             ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║  Amenazas detectadas: #{String.pad_trailing("#{threat_stats.total_threats}", 10)} │ Nivel crítico: #{threat_stats.critical}      ║
    ║  Botnets detectadas: #{String.pad_trailing("#{threat_stats.botnets}", 11)} │ C2 Communications: #{threat_stats.c2_comms}  ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                           AMENAZAS RECIENTES                                   ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    """)

    if length(threats) > 0 do
      threats
      |> Enum.take(8)
      |> Enum.each(fn {timestamp, threat} ->
        time_str = format_relative_time(timestamp)
        type_str = String.pad_trailing("#{threat.type}", 18)
        source_str = String.pad_trailing("#{threat.source_ip}", 15)
        confidence = "#{Float.round(threat.confidence * 100, 1)}%"

        severity_icon = case threat.confidence do
          conf when conf > 0.8 -> "🔴"
          conf when conf > 0.6 -> "🟠"
          conf when conf > 0.4 -> "🟡"
          _ -> "🔵"
        end

        IO.puts("║  #{severity_icon} #{type_str} │ #{source_str} │ #{confidence} │ #{time_str}  ║")
      end)
    else
      IO.puts("║                        ✅ NO HAY AMENAZAS DETECTADAS                       ║")
    end
  end

  defp render_dashboard_navigation(current_view) do
    IO.puts("""
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║  [1]Overview [2]Protocolos [3]Topología [4]Flujos [5]Amenazas [6]Geo [Q]Exit ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝
    """)

    IO.write("Vista actual: #{current_view} | Actualizando en tiempo real...")
  end

  ## Utilidades y Helpers

  defp generate_analyzer_id do
    :crypto.strong_rand_bytes(8) |> Base.encode16() |> String.downcase()
  end

  defp generate_realistic_ip do
    # Generar IPs con distribución realista
    ip_types = [:internal, :external, :public]
    ip_type = Enum.random(ip_types)

    case ip_type do
      :internal ->
        case :rand.uniform(3) do
          1 -> "192.168.#{:rand.uniform(255)}.#{:rand.uniform(254) + 1}"
          2 -> "10.#{:rand.uniform(255)}.#{:rand.uniform(255)}.#{:rand.uniform(254) + 1}"
          3 -> "172.#{:rand.uniform(15) + 16}.#{:rand.uniform(255)}.#{:rand.uniform(254) + 1}"
        end

      :external ->
        # IPs públicas comunes
        common_externals = [
          "8.8.8.8", "1.1.1.1", "208.67.222.222",
          "199.85.126.20", "185.228.168.9"
        ]
        Enum.random(common_externals)

      :public ->
        # Generar IP pública aleatoria (evitando rangos reservados)
        "#{:rand.uniform(223) + 1}.#{:rand.uniform(255)}.#{:rand.uniform(255)}.#{:rand.uniform(254) + 1}"
    end
  end

  defp generate_mac_address do
    # Generar MAC con vendors realistas
    vendors = [
      "00:50:56",  # VMware
      "08:00:27",  # VirtualBox
      "52:54:00",  # QEMU/KVM
      "00:0C:29",  # VMware
      "00:1B:21",  # Intel
      "00:25:90",  # Super Micro
      "D4:3D:7E"   # Realtek
    ]

    vendor = Enum.random(vendors)
    suffix = for _ <- 1..3, do: :rand.uniform(255) |> Integer.to_string(16) |> String.pad_leading(2, "0")
    vendor <> ":" <> Enum.join(suffix, ":")
  end

  defp weighted_random_protocol(weights) do
    total_weight = weights |> Map.values() |> Enum.sum()
    random_value = :rand.uniform() * total_weight

    {protocol, _} = weights
                   |> Enum.reduce_while({nil, 0}, fn {proto, weight}, {_, acc} ->
                     new_acc = acc + weight
                     if random_value <= new_acc do
                       {:halt, {proto, new_acc}}
                     else
                       {:cont, {proto, new_acc}}
                     end
                   end)

    protocol
  end

  defp add_tcp_fields(packet) do
    src_port = case :rand.uniform(10) do
      n when n <= 3 -> Enum.random([80, 443, 22, 25, 53])  # Puertos comunes
      _ -> :rand.uniform(65535)
    end

    dst_port = case :rand.uniform(10) do
      n when n <= 3 -> Enum.random([80, 443, 22, 25, 53])  # Puertos comunes
      _ -> :rand.uniform(65535)
    end

    Map.merge(packet, %{
      src_port: src_port,
      dst_port: dst_port,
      sequence: :rand.uniform(4_294_967_295),
      acknowledgment: :rand.uniform(4_294_967_295),
      window_size: Enum.random([8192, 16384, 32768, 65535]),
      flags: generate_tcp_flags()
    })
  end

  defp generate_tcp_flags do
    # Generar combinaciones realistas de flags TCP
    flag_combinations = [
      %{syn: true, ack: false},              # SYN
      %{syn: false, ack: true},              # ACK
      %{syn: true, ack: true},               # SYN-ACK
      %{fin: true, ack: true},               # FIN-ACK
      %{rst: true, ack: false},              # RST
      %{psh: true, ack: true}                # PSH-ACK
    ]

    Enum.random(flag_combinations)
  end

  defp calculate_capture_delay(opts) do
    # Simular diferentes cargas de red
    network_load = Keyword.get(opts, :network_load, :medium)

    case network_load do
      :light -> :rand.uniform(50) + 10    # 10-60ms
      :medium -> :rand.uniform(20) + 5    # 5-25ms
      :heavy -> :rand.uniform(5) + 1      # 1-6ms
      :extreme -> 1                       # 1ms
    end
  end

  defp generate_traffic_statistics(state) do
    current_time = System.monotonic_time()
    uptime = System.convert_time_unit(current_time - state.start_time, :native, :millisecond)

    # Simular estadísticas realistas
    packets_per_second = :rand.uniform(1000) + 100
    bytes_per_second = packets_per_second * (:rand.uniform(1000) + 200)

    active_flows = if state.active_flows do
      :ets.info(state.active_flows, :size)
    else
      0
    end

    threats_detected = if state.threat_intel do
      :ets.info(state.threat_intel, :size)
    else
      0
    end

    %{
      analyzer_id: state.analyzer_id,
      uptime_ms: uptime,
      status: :operational,
      packets_per_second: packets_per_second,
      bytes_per_second: bytes_per_second,
      total_packets: round(uptime / 1000 * packets_per_second),
      active_flows: active_flows,
      unique_hosts: round(active_flows * 0.7),
      threats_detected: threats_detected
    }
  end

  defp format_uptime(ms) do
    seconds = div(ms, 1000)
    minutes = div(seconds, 60)
    hours = div(minutes, 60)

    cond do
      hours > 0 -> "#{hours}h #{rem(minutes, 60)}m"
      minutes > 0 -> "#{minutes}m #{rem(seconds, 60)}s"
      true -> "#{seconds}s"
    end
  end

  defp format_status(:operational), do: "🟢 ACTIVE"
  defp format_status(:warning), do: "🟡 WARNING"
  defp format_status(:error), do: "🔴 ERROR"
  defp format_status(_), do: "⚪ UNKNOWN"

  defp format_bytes(bytes) when bytes >= 1_000_000_000 do
    "#{Float.round(bytes / 1_000_000_000, 2)} GB/s"
  end
  defp format_bytes(bytes) when bytes >= 1_000_000 do
    "#{Float.round(bytes / 1_000_000, 2)} MB/s"
  end
  defp format_bytes(bytes) when bytes >= 1_000 do
    "#{Float.round(bytes / 1_000, 2)} KB/s"
  end
  defp format_bytes(bytes), do: "#{bytes} B/s"

  defp cycle_dashboard_views(dashboard_state) do
    views = [:overview, :protocol_analysis, :network_topology, :flow_analysis, :threat_detection, :geographic_view]
    current_index = Enum.find_index(views, &(&1 == dashboard_state.current_view)) || 0
    next_index = rem(current_index + 1, length(views))
    next_view = Enum.at(views, next_index)

    # Cambiar vista cada 6 segundos en demo
    if rem(System.monotonic_time(), 6_000_000_000) < 1_000_000_000 do
      %{dashboard_state | current_view: next_view}
    else
      dashboard_state
    end
  end

  # Placeholder implementations para funciones complejas
  defp start_protocol_processors, do: spawn_link(fn -> Process.sleep(:infinity) end)
  defp start_flow_tracker, do: spawn_link(fn -> Process.sleep(:infinity) end)
  defp start_session_reconstructor, do: spawn_link(fn -> Process.sleep(:infinity) end)
  defp start_threat_detector, do: spawn_link(fn -> Process.sleep(:infinity) end)
  defp start_visualization_engine, do: spawn_link(fn -> Process.sleep(:infinity) end)
  defp start_geo_analyzer, do: spawn_link(fn -> Process.sleep(:infinity) end)
  defp start_statistics_engine, do: spawn_link(fn -> Process.sleep(:infinity) end)

  defp stop_all_components(_state), do: :ok
  defp determine_network_protocol(_packet), do: :ipv4
  defp analyze_ipv6_packet(_packet), do: %{layer: :network, protocol: :ipv6}
  defp analyze_arp_packet(_packet), do: %{layer: :network, protocol: :arp}
  defp analyze_udp_packet(_packet), do: %{layer: :transport, protocol: :udp}
  defp analyze_icmp_packet(_packet), do: %{layer: :transport, protocol: :icmp}
  defp determine_application_protocol(_packet), do: :http
  defp analyze_http_traffic(_packet), do: %{layer: :application, protocol: :http}
  defp analyze_https_traffic(_packet), do: %{layer: :application, protocol: :https}
  defp analyze_smtp_traffic(_packet), do: %{layer: :application, protocol: :smtp}
  defp analyze_ssh_traffic(_packet), do: %{layer: :application, protocol: :ssh}

  defp lookup_mac_vendor(_mac), do: "Unknown Vendor"
  defp detect_mac_spoofing(_mac, _ip), do: %{suspicious: false}
  defp geolocate_ip(_ip), do: %{country: "US", city: "Unknown"}
  defp calculate_geographic_distance(_geo1, _geo2), do: 0
  defp analyze_ttl_for_os(_ttl), do: %{probable_os: "Unknown"}
  defp detect_ip_spoofing_indicators(_packet), do: false
  defp analyze_tcp_flags(_flags), do: %{suspicious: false}
  defp analyze_tcp_window(_window), do: %{os_hint: "Unknown"}
  defp detect_tcp_scan_patterns(_packet), do: %{is_scan: false}
  defp extract_dns_query_type(_packet), do: "A"
  defp extract_dns_domain(_packet), do: "example.com"
  defp extract_dns_response_code(_packet), do: 0
  defp detect_dga_domain(_domain), do: false
  defp detect_dns_tunneling_patterns(_packet), do: false
  defp detect_fast_flux_patterns(_domain), do: false
  defp detect_mirai_patterns(_packet, _analyses), do: false
  defp detect_regular_beaconing(_packet), do: false
  defp detect_c2_patterns(_packet, _analyses), do: []
  defp detect_exfiltration_patterns(_packet, _analyses), do: []
  defp detect_lateral_movement_patterns(_packet, _analyses), do: []
  defp create_threats_from_anomalies(_packet, _anomalies), do: []
  defp calculate_threat_score(_threats, _anomalies), do: 0.0
  defp update_network_topology(_packet, _state), do: :ok
  defp update_flow_tracking(_packet, _state), do: :ok
  defp store_packet_analysis(_packet, _analysis, _state), do: :ok
  defp generate_realistic_size(_protocol), do: :rand.uniform(1500) + 64
  defp generate_realistic_ttl, do: Enum.random([64, 128, 255])
  defp generate_protocol_flags(_protocol), do: %{}
  defp add_udp_fields(packet), do: Map.merge(packet, %{src_port: :rand.uniform(65535), dst_port: :rand.uniform(65535)})
  defp add_icmp_fields(packet), do: Map.merge(packet, %{icmp_type: :rand.uniform(20), icmp_code: 0})
  defp add_suspicious_characteristics(packet), do: Map.put(packet, :suspicious, true)
  defp get_top_flows(_flows, _limit), do: []
  defp get_protocol_distribution(_state), do: %{tcp: 600, udp: 250, icmp: 50, other: 100}
  defp generate_traffic_history(current_value, count) do
    for _ <- 1..count, do: max(0, current_value + :rand.uniform(200) - 100)
  end
  defp get_network_topology_summary(_topology) do
    %{
      total_hosts: :rand.uniform(50) + 10,
      subnets: :rand.uniform(5) + 1,
      active_connections: :rand.uniform(100) + 20,
      routers: :rand.uniform(3) + 1,
      top_hosts: []
    }
  end
  defp render_network_map_ascii(_topology) do
    IO.puts("║                    [Router] ── [Switch] ── [Hosts...]                     ║")
    IO.puts("║                        │         │                                        ║")
    IO.puts("║                    [Internet]  [LAN]                                      ║")
  end
  defp get_recent_threats(_threat_intel, _limit), do: []
  defp calculate_threat_statistics(_threats) do
    %{total_threats: 0, critical: 0, botnets: 0, c2_comms: 0}
  end
  defp format_relative_time(_timestamp), do: "1m ago"
end
