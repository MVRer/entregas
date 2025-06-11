defmodule ScanDetector do
  @moduledoc """
  Sistema avanzado de detección de escaneos de red con respuesta activa.
  
  Capacidades:
  - Detección en tiempo real de escaneos
  - Análisis de patrones y técnicas
  - Fingerprinting del atacante
  - Escaneo reverso automático
  - Sistema de alertas y contramedidas
  
  LEGAL: Solo usar en sistemas propios para defensa legítima.
  """

  require Logger
  use GenServer

  # Patrones de detección de escaneos
  @scan_patterns %{
    port_scan: %{
      description: "Escaneo secuencial de puertos",
      indicators: [:sequential_ports, :rapid_connections, :connection_failures],
      threshold: %{connections_per_second: 10, unique_ports: 5, timeframe: 30}
    },
    stealth_scan: %{
      description: "Escaneo sigiloso (SYN scan)",
      indicators: [:incomplete_handshakes, :random_intervals, :fragmented_packets],
      threshold: %{syn_packets: 20, incomplete_ratio: 0.8, timeframe: 60}
    },
    aggressive_scan: %{
      description: "Escaneo agresivo de alta velocidad",
      indicators: [:high_connection_rate, :parallel_ports, :service_probing],
      threshold: %{connections_per_second: 50, parallel_connections: 100, timeframe: 10}
    },
    vulnerability_scan: %{
      description: "Escaneo de vulnerabilidades",
      indicators: [:service_fingerprinting, :banner_grabbing, :exploit_attempts],
      threshold: %{probe_requests: 10, different_services: 3, timeframe: 120}
    },
    network_discovery: %{
      description: "Descubrimiento de red",
      indicators: [:ping_sweep, :arp_requests, :dns_queries],
      threshold: %{host_probes: 20, timeframe: 30}
    }
  }

  # Fingerprints de herramientas conocidas
  @tool_fingerprints %{
    nmap: %{
      patterns: [
        "GET / HTTP/1.0\r\n\r\n",
        "OPTIONS / HTTP/1.0\r\n\r\n",
        "User-Agent: Mozilla/5.0 (compatible; Nmap"
      ],
      timing_signature: :variable_delays,
      port_order: :sequential_then_random
    },
    masscan: %{
      patterns: [],
      timing_signature: :extremely_fast,
      port_order: :random,
      connection_style: :syn_only
    },
    zmap: %{
      patterns: [],
      timing_signature: :constant_rate,
      port_order: :single_port_sweep,
      connection_style: :syn_only
    },
    custom_scanner: %{
      patterns: ["NetworkScanner", "Elixir"],
      timing_signature: :high_concurrency,
      port_order: :chunked_parallel
    }
  }

  defstruct [
    :monitor_pid,
    :active_monitors,
    :connection_log,
    :scan_events,
    :detected_scanners,
    :response_config,
    :honeypots,
    :start_time
  ]

  ## API Pública

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Inicia el monitoreo activo de red.
  """
  def start_monitoring(opts \\ []) do
    GenServer.call(__MODULE__, {:start_monitoring, opts})
  end

  @doc """
  Detiene el monitoreo.
  """
  def stop_monitoring do
    GenServer.call(__MODULE__, :stop_monitoring)
  end

  @doc """
  Obtiene estadísticas de detección en tiempo real.
  """
  def get_detection_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Lista todos los escáneres detectados actualmente.
  """
  def list_detected_scanners do
    GenServer.call(__MODULE__, :list_scanners)
  end

  @doc """
  Inicia un escaneo reverso contra un atacante detectado.
  """
  def reverse_scan(attacker_ip, opts \\ []) do
    GenServer.call(__MODULE__, {:reverse_scan, attacker_ip, opts}, :infinity)
  end

  @doc """
  Configura respuestas automáticas.
  """
  def configure_responses(config) do
    GenServer.call(__MODULE__, {:configure_responses, config})
  end

  @doc """
  Despliega honeypots para atraer atacantes.
  """
  def deploy_honeypots(ports) do
    GenServer.call(__MODULE__, {:deploy_honeypots, ports})
  end

  ## Callbacks del GenServer

  @impl true
  def init(opts) do
    state = %__MODULE__{
      active_monitors: %{},
      connection_log: :ets.new(:connections, [:bag, :public]),
      scan_events: :ets.new(:scan_events, [:bag, :public]),
      detected_scanners: %{},
      response_config: default_response_config(),
      honeypots: %{},
      start_time: System.monotonic_time()
    }

    Logger.info("ScanDetector iniciado - Modo defensivo activo")
    {:ok, state}
  end

  @impl true
  def handle_call({:start_monitoring, opts}, _from, state) do
    Logger.info("Iniciando monitoreo de red...")
    
    monitors = %{
      connection_monitor: start_connection_monitor(opts),
      pattern_analyzer: start_pattern_analyzer(),
      response_system: start_response_system(state.response_config),
      log_analyzer: start_log_analyzer()
    }

    new_state = %{state | active_monitors: monitors}
    {:reply, :ok, new_state}
  end

  @impl true
  def handle_call(:stop_monitoring, _from, state) do
    Logger.info("Deteniendo monitoreo...")
    
    Enum.each(state.active_monitors, fn {_name, pid} ->
      if Process.alive?(pid), do: Process.exit(pid, :normal)
    end)

    new_state = %{state | active_monitors: %{}}
    {:reply, :ok, new_state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = generate_detection_statistics(state)
    {:reply, stats, state}
  end

  @impl true
  def handle_call(:list_scanners, _from, state) do
    {:reply, state.detected_scanners, state}
  end

  @impl true
  def handle_call({:reverse_scan, attacker_ip, opts}, _from, state) do
    Logger.warn("Iniciando escaneo reverso contra: #{attacker_ip}")
    
    task = Task.async(fn -> 
      perform_reverse_scan(attacker_ip, opts)
    end)
    
    result = Task.await(task, 30_000)
    
    # Actualizar información del atacante
    updated_scanners = update_scanner_info(state.detected_scanners, attacker_ip, result)
    new_state = %{state | detected_scanners: updated_scanners}
    
    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:configure_responses, config}, _from, state) do
    new_state = %{state | response_config: config}
    {:reply, :ok, new_state}
  end

  @impl true
  def handle_call({:deploy_honeypots, ports}, _from, state) do
    honeypots = deploy_honeypot_services(ports)
    new_state = %{state | honeypots: Map.merge(state.honeypots, honeypots)}
    {:reply, :ok, new_state}
  end

  @impl true
  def handle_info({:scan_detected, scan_info}, state) do
    Logger.warn("🚨 ESCANEO DETECTADO: #{inspect(scan_info)}")
    
    # Registrar el evento
    :ets.insert(state.scan_events, {System.monotonic_time(), scan_info})
    
    # Actualizar información del escáner
    updated_scanners = register_scanner(state.detected_scanners, scan_info)
    
    # Activar respuesta automática si está configurada
    if state.response_config.auto_response do
      spawn(fn -> handle_auto_response(scan_info, state.response_config) end)
    end
    
    {:noreply, %{state | detected_scanners: updated_scanners}}
  end

  @impl true
  def handle_info({:connection_event, event}, state) do
    # Registrar conexión para análisis
    :ets.insert(state.connection_log, {System.monotonic_time(), event})
    {:noreply, state}
  end

  ## Módulos de Monitoreo

  defp start_connection_monitor(opts) do
    spawn_link(fn -> connection_monitor_loop(opts) end)
  end

  defp connection_monitor_loop(opts) do
    # Simular monitoreo de conexiones de red
    # En implementación real usaríamos pcap, netfilter, o eBPF
    
    ports_to_monitor = Keyword.get(opts, :ports, [22, 80, 443, 21, 23, 25, 53])
    
    Enum.each(ports_to_monitor, fn port ->
      spawn_link(fn -> monitor_port(port) end)
    end)
    
    # Loop principal del monitor
    monitor_network_traffic()
  end

  defp monitor_port(port) do
    # Escuchar en puerto específico para detectar conexiones
    case :gen_tcp.listen(port, [:binary, {:active, true}, {:reuseaddr, true}]) do
      {:ok, listen_socket} ->
        Logger.debug("Monitoreando puerto #{port}")
        accept_connections(listen_socket, port)
      
      {:error, reason} ->
        Logger.debug("No se pudo monitorear puerto #{port}: #{reason}")
    end
  end

  defp accept_connections(listen_socket, port) do
    case :gen_tcp.accept(listen_socket) do
      {:ok, socket} ->
        {:ok, {remote_ip, remote_port}} = :inet.peername(socket)
        
        # Registrar conexión
        connection_event = %{
          timestamp: System.monotonic_time(),
          source_ip: :inet.ntoa(remote_ip) |> to_string(),
          source_port: remote_port,
          dest_port: port,
          type: :tcp_connect
        }
        
        send(ScanDetector, {:connection_event, connection_event})
        
        # Analizar la conexión
        spawn(fn -> analyze_connection(socket, connection_event) end)
        
        # Continuar aceptando conexiones
        accept_connections(listen_socket, port)
      
      {:error, :closed} ->
        Logger.debug("Socket de escucha cerrado para puerto #{port}")
      
      {:error, reason} ->
        Logger.debug("Error aceptando conexión en puerto #{port}: #{reason}")
        Process.sleep(100)
        accept_connections(listen_socket, port)
    end
  end

  defp analyze_connection(socket, connection_event) do
    # Intentar recibir datos para fingerprinting
    case :gen_tcp.recv(socket, 0, 5000) do
      {:ok, data} ->
        # Analizar los datos recibidos
        analysis = analyze_received_data(data, connection_event)
        
        if analysis.suspicious do
          scan_info = %{
            type: analysis.scan_type,
            source_ip: connection_event.source_ip,
            confidence: analysis.confidence,
            evidence: analysis.evidence,
            timestamp: connection_event.timestamp
          }
          
          send(ScanDetector, {:scan_detected, scan_info})
        end
      
      {:error, _} ->
        # Conexión cerrada rápidamente - posible escaneo
        if connection_event.dest_port not in [80, 443] do  # Filtrar tráfico web normal
          scan_info = %{
            type: :port_scan,
            source_ip: connection_event.source_ip,
            confidence: 0.6,
            evidence: ["quick_disconnect", "non_web_port"],
            timestamp: connection_event.timestamp
          }
          
          send(ScanDetector, {:scan_detected, scan_info})
        end
    end
    
    :gen_tcp.close(socket)
  end

  defp analyze_received_data(data, connection_event) do
    data_str = to_string(data)
    
    # Detectar herramientas conocidas
    tool_detected = detect_scanning_tool(data_str)
    
    # Analizar patrones sospechosos
    suspicious_patterns = [
      {~r/GET \/ HTTP\/1\.0\r\n\r\n/, :http_fingerprinting},
      {~r/OPTIONS \* HTTP\/1\.0/, :http_method_scan},
      {~r/User-Agent: nmap/i, :nmap_detected},
      {~r/\x00/, :null_bytes},
      {~r/\\x[0-9a-f]{2}/, :hex_encoded}
    ]
    
    detected_patterns = Enum.filter(suspicious_patterns, fn {pattern, _name} ->
      Regex.match?(pattern, data_str)
    end)
    
    evidence = [
      "data_received: #{String.slice(data_str, 0, 50)}",
      "tool: #{tool_detected}",
      "patterns: #{inspect(Enum.map(detected_patterns, &elem(&1, 1)))}"
    ]
    
    %{
      suspicious: length(detected_patterns) > 0 or tool_detected != :unknown,
      scan_type: determine_scan_type(detected_patterns, tool_detected),
      confidence: calculate_confidence(detected_patterns, tool_detected),
      evidence: evidence,
      tool: tool_detected
    }
  end

  defp detect_scanning_tool(data) do
    @tool_fingerprints
    |> Enum.find_value(:unknown, fn {tool, fingerprint} ->
      if Enum.any?(fingerprint.patterns, &String.contains?(data, &1)) do
        tool
      end
    end)
  end

  defp determine_scan_type(patterns, tool) do
    cond do
      tool == :nmap -> :nmap_scan
      tool == :masscan -> :mass_scan
      Enum.any?(patterns, &(elem(&1, 1) == :http_fingerprinting)) -> :service_detection
      true -> :unknown_scan
    end
  end

  defp calculate_confidence(patterns, tool) do
    base_confidence = if tool != :unknown, do: 0.8, else: 0.3
    pattern_bonus = length(patterns) * 0.1
    min(1.0, base_confidence + pattern_bonus)
  end

  defp start_pattern_analyzer do
    spawn_link(fn -> pattern_analyzer_loop() end)
  end

  defp pattern_analyzer_loop do
    Process.sleep(10_000)  # Analizar cada 10 segundos
    
    # Analizar patrones de conexión
    recent_connections = get_recent_connections(30_000)  # Últimos 30 segundos
    
    # Detectar patrones de escaneo
    scan_patterns = analyze_connection_patterns(recent_connections)
    
    Enum.each(scan_patterns, fn pattern ->
      send(ScanDetector, {:scan_detected, pattern})
    end)
    
    pattern_analyzer_loop()
  end

  defp get_recent_connections(timeframe_ms) do
    current_time = System.monotonic_time()
    cutoff_time = current_time - System.convert_time_unit(timeframe_ms, :millisecond, :native)
    
    # En implementación real, consultaríamos ETS más eficientemente
    []  # Placeholder
  end

  defp analyze_connection_patterns(connections) do
    # Agrupar por IP origen
    grouped_by_ip = Enum.group_by(connections, & &1.source_ip)
    
    Enum.flat_map(grouped_by_ip, fn {ip, ip_connections} ->
      detect_ip_scan_patterns(ip, ip_connections)
    end)
  end

  defp detect_ip_scan_patterns(ip, connections) do
    patterns = []
    
    # Detectar escaneo de puertos secuencial
    if sequential_port_scan?(connections) do
      patterns = [create_scan_event(ip, :sequential_port_scan, 0.9) | patterns]
    end
    
    # Detectar escaneo de alta velocidad
    if high_speed_scan?(connections) do
      patterns = [create_scan_event(ip, :high_speed_scan, 0.8) | patterns]
    end
    
    # Detectar escaneo de servicios
    if service_enumeration?(connections) do
      patterns = [create_scan_event(ip, :service_enumeration, 0.7) | patterns]
    end
    
    patterns
  end

  defp sequential_port_scan?(connections) do
    ports = Enum.map(connections, & &1.dest_port) |> Enum.sort()
    consecutive_count = count_consecutive_ports(ports)
    consecutive_count >= 5
  end

  defp high_speed_scan?(connections) do
    length(connections) > 20  # Más de 20 conexiones en ventana de tiempo
  end

  defp service_enumeration?(connections) do
    unique_ports = connections |> Enum.map(& &1.dest_port) |> Enum.uniq()
    length(unique_ports) > 5  # Múltiples servicios diferentes
  end

  defp count_consecutive_ports(ports) do
    ports
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.count(fn [a, b] -> b - a == 1 end)
  end

  defp create_scan_event(ip, type, confidence) do
    %{
      type: type,
      source_ip: ip,
      confidence: confidence,
      evidence: ["pattern_analysis"],
      timestamp: System.monotonic_time()
    }
  end

  ## Sistema de Respuesta Activa

  defp start_response_system(config) do
    spawn_link(fn -> response_system_loop(config) end)
  end

  defp response_system_loop(config) do
    receive do
      {:respond_to_scan, scan_info} ->
        handle_scan_response(scan_info, config)
        response_system_loop(config)
      
      {:update_config, new_config} ->
        response_system_loop(new_config)
      
      _ ->
        response_system_loop(config)
    end
  end

  defp handle_auto_response(scan_info, config) do
    case config.response_level do
      :passive ->
        log_scan_event(scan_info)
      
      :active ->
        log_scan_event(scan_info)
        if config.reverse_scan, do: reverse_scan(scan_info.source_ip)
      
      :aggressive ->
        log_scan_event(scan_info)
        reverse_scan(scan_info.source_ip)
        deploy_targeted_honeypots(scan_info)
    end
  end

  defp log_scan_event(scan_info) do
    Logger.warn("""
    🚨 ESCANEO DETECTADO:
    Tipo: #{scan_info.type}
    Origen: #{scan_info.source_ip}
    Confianza: #{scan_info.confidence * 100}%
    Evidencia: #{inspect(scan_info.evidence)}
    """)
  end

  ## Escaneo Reverso del Atacante

  defp perform_reverse_scan(attacker_ip, opts) do
    Logger.info("🔍 Iniciando análisis profundo de: #{attacker_ip}")
    
    start_time = System.monotonic_time()
    
    # 1. Detección de OS avanzada
    os_info = advanced_os_detection(attacker_ip)
    
    # 2. Escaneo de puertos del atacante
    port_scan_results = reverse_port_scan(attacker_ip, opts)
    
    # 3. Fingerprinting de servicios
    service_info = reverse_service_detection(attacker_ip, port_scan_results)
    
    # 4. Análisis de comportamiento
    behavior_analysis = analyze_attacker_behavior(attacker_ip)
    
    # 5. Geolocalización y metadatos
    geo_info = geolocate_attacker(attacker_ip)
    
    # 6. Búsqueda en bases de datos de amenazas
    threat_intel = check_threat_databases(attacker_ip)
    
    end_time = System.monotonic_time()
    analysis_duration = System.convert_time_unit(end_time - start_time, :native, :millisecond)
    
    %{
      target_ip: attacker_ip,
      analysis_duration_ms: analysis_duration,
      os_detection: os_info,
      open_ports: port_scan_results,
      services: service_info,
      behavior: behavior_analysis,
      geolocation: geo_info,
      threat_intelligence: threat_intel,
      risk_score: calculate_attacker_risk_score(os_info, service_info, threat_intel),
      timestamp: System.monotonic_time()
    }
  end

  defp advanced_os_detection(target_ip) do
    Logger.debug("Detectando OS de #{target_ip}...")
    
    # Técnicas múltiples de OS fingerprinting
    techniques = [
      &tcp_window_analysis/1,
      &ttl_analysis/1,
      &tcp_options_analysis/1,
      &icmp_analysis/1,
      &service_banner_analysis/1
    ]
    
    results = Enum.map(techniques, fn technique ->
      try do
        technique.(target_ip)
      catch
        _, _ -> %{os: "unknown", confidence: 0.0, method: "failed"}
      end
    end)
    
    # Correlacionar resultados
    correlate_os_detection(results)
  end

  defp tcp_window_analysis(target_ip) do
    # Analizar tamaño de ventana TCP característico
    case attempt_tcp_connection(target_ip, 80) do
      {:ok, socket} ->
        # En implementación real analizaríamos headers TCP raw
        :gen_tcp.close(socket)
        %{os: "Linux", confidence: 0.3, method: "tcp_window", evidence: "window_size"}
      
      {:error, _} ->
        %{os: "unknown", confidence: 0.0, method: "tcp_window"}
    end
  end

  defp ttl_analysis(target_ip) do
    # Análisis de TTL mediante ping
    case System.cmd("ping", ["-c", "1", target_ip], stderr_to_stdout: true) do
      {output, 0} ->
        case Regex.run(~r/ttl=(\d+)/i, output) do
          [_, ttl_str] ->
            ttl = String.to_integer(ttl_str)
            determine_os_by_ttl(ttl)
          
          nil ->
            %{os: "unknown", confidence: 0.0, method: "ttl"}
        end
      
      {_, _} ->
        %{os: "unknown", confidence: 0.0, method: "ttl"}
    end
  end

  defp determine_os_by_ttl(ttl) do
    cond do
      ttl <= 64 -> %{os: "Linux/Unix", confidence: 0.7, method: "ttl", evidence: "ttl=#{ttl}"}
      ttl <= 128 -> %{os: "Windows", confidence: 0.7, method: "ttl", evidence: "ttl=#{ttl}"}
      ttl <= 255 -> %{os: "Network Device", confidence: 0.6, method: "ttl", evidence: "ttl=#{ttl}"}
      true -> %{os: "unknown", confidence: 0.0, method: "ttl"}
    end
  end

  defp tcp_options_analysis(target_ip) do
    # Placeholder para análisis de opciones TCP
    %{os: "unknown", confidence: 0.0, method: "tcp_options"}
  end

  defp icmp_analysis(target_ip) do
    # Placeholder para análisis ICMP
    %{os: "unknown", confidence: 0.0, method: "icmp"}
  end

  defp service_banner_analysis(target_ip) do
    # Analizar banners de servicios para clues de OS
    common_ports = [22, 25, 80, 110, 143]
    
    banners = Enum.map(common_ports, fn port ->
      case grab_service_banner(target_ip, port) do
        {:ok, banner} -> {port, banner}
        {:error, _} -> {port, ""}
      end
    end)
    
    os_clues = extract_os_from_banners(banners)
    
    if length(os_clues) > 0 do
      most_likely = Enum.max_by(os_clues, & &1.confidence)
      %{os: most_likely.os, confidence: most_likely.confidence, method: "service_banners", evidence: most_likely.evidence}
    else
      %{os: "unknown", confidence: 0.0, method: "service_banners"}
    end
  end

  defp extract_os_from_banners(banners) do
    Enum.flat_map(banners, fn {port, banner} ->
      cond do
        String.contains?(banner, "Ubuntu") -> 
          [%{os: "Ubuntu Linux", confidence: 0.9, evidence: "banner:#{port}:Ubuntu"}]
        
        String.contains?(banner, "CentOS") -> 
          [%{os: "CentOS Linux", confidence: 0.9, evidence: "banner:#{port}:CentOS"}]
        
        String.contains?(banner, "Microsoft") -> 
          [%{os: "Windows", confidence: 0.8, evidence: "banner:#{port}:Microsoft"}]
        
        String.contains?(banner, "OpenSSH") -> 
          [%{os: "Linux/Unix", confidence: 0.6, evidence: "banner:#{port}:OpenSSH"}]
        
        true -> []
      end
    end)
  end

  defp correlate_os_detection(results) do
    # Filtrar resultados válidos
    valid_results = Enum.filter(results, &(&1.confidence > 0.0))
    
    if length(valid_results) > 0 do
      # Agrupar por OS detectado
      grouped = Enum.group_by(valid_results, & &1.os)
      
      # Calcular confianza combinada
      os_scores = Enum.map(grouped, fn {os, detections} ->
        combined_confidence = Enum.sum(Enum.map(detections, & &1.confidence)) / length(detections)
        evidence = Enum.map(detections, & &1.evidence) |> Enum.join(", ")
        methods = Enum.map(detections, & &1.method) |> Enum.uniq() |> Enum.join(", ")
        
        %{
          os: os,
          confidence: min(1.0, combined_confidence),
          evidence: evidence,
          methods: methods,
          detection_count: length(detections)
        }
      end)
      
      # Retornar la detección con mayor confianza
      best_detection = Enum.max_by(os_scores, & &1.confidence)
      
      %{
        probable_os: best_detection.os,
        confidence: best_detection.confidence,
        all_detections: os_scores,
        evidence: best_detection.evidence,
        methods_used: best_detection.methods
      }
    else
      %{
        probable_os: "Unknown",
        confidence: 0.0,
        all_detections: [],
        evidence: "No OS signatures detected",
        methods_used: "none"
      }
    end
  end

  defp reverse_port_scan(target_ip, opts) do
    Logger.debug("Escaneando puertos de #{target_ip}...")
    
    # Usar el escaneador que ya tenemos pero configurado para ser sigiloso
    port_range = Keyword.get(opts, :ports, [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389, 5432, 3306])
    
    # Escaneo sigiloso para no alertar al atacante
    scan_results = Enum.map(port_range, fn port ->
      case attempt_tcp_connection(target_ip, port, 2000) do
        {:ok, socket} ->
          :gen_tcp.close(socket)
          {port, :open}
        
        {:error, :econnrefused} ->
          {port, :closed}
        
        {:error, _} ->
          {port, :filtered}
      end
    end)
    
    # Filtrar solo puertos abiertos
    open_ports = Enum.filter(scan_results, fn {_port, status} -> status == :open end)
                |> Enum.map(fn {port, _status} -> port end)
    
    open_ports
  end

  defp reverse_service_detection(target_ip, open_ports) do
    Logger.debug("Detectando servicios en #{target_ip}...")
    
    Enum.map(open_ports, fn port ->
      case grab_service_banner(target_ip, port) do
        {:ok, banner} ->
          service_info = analyze_service_banner(banner, port)
          %{port: port, service: service_info.service, version: service_info.version, banner: banner}
        
        {:error, reason} ->
          %{port: port, service: "unknown", version: "unknown", error: reason}
      end
    end)
  end

  defp grab_service_banner(target_ip, port, timeout \\ 3000) do
    case attempt_tcp_connection(target_ip, port, timeout) do
      {:ok, socket} ->
        # Enviar probe apropiado según el puerto
        probe = get_service_probe(port)
        :gen_tcp.send(socket, probe)
        
        case :gen_tcp.recv(socket, 0, 2000) do
          {:ok, data} ->
            :gen_tcp.close(socket)
            {:ok, clean_banner_data(data)}
          
          {:error, reason} ->
            :gen_tcp.close(socket)
            {:error, reason}
        end
      
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp get_service_probe(port) do
    case port do
      80 -> "GET / HTTP/1.0\r\n\r\n"
      443 -> "GET / HTTP/1.0\r\n\r\n"
      22 -> "\r\n"
      25 -> "EHLO test.com\r\n"
      21 -> "USER anonymous\r\n"
      _ -> "\r\n"
    end
  end

  defp clean_banner_data(data) do
    data
    |> to_string()
    |> String.replace(~r/[^\x20-\x7E\r\n]/, "")
    |> String.trim()
    |> String.slice(0, 200)
  end

  defp analyze_service_banner(banner, port) do
    # Analizar banner para extraer información del servicio
    cond do
      String.contains?(banner, "SSH-") ->
        version = extract_ssh_version(banner)
        %{service: "SSH", version: version}
      
      String.contains?(banner, "HTTP/") ->
        server = extract_http_server(banner)
        %{service: "HTTP", version: server}
      
      String.contains?(banner, "FTP") ->
        %{service: "FTP", version: "unknown"}
      
      String.contains?(banner, "SMTP") ->
        %{service: "SMTP", version: "unknown"}
      
      true ->
        # Lookup por puerto conocido
        service_name = get_default_service_name(port)
        %{service: service_name, version: "unknown"}
    end
  end

  defp extract_ssh_version(banner) do
    case Regex.run(~r/SSH-[\d.]+-(.+)/, banner) do
      [_, version] -> String.trim(version)
      nil -> "unknown"
    end
  end

  defp extract_http_server(banner) do
    case Regex.run(~r/Server:\s*(.+)/i, banner) do
      [_, server] -> String.trim(server)
      nil -> "unknown"
    end
  end

  defp get_default_service_name(port) do
    common_services = %{
      21 => "FTP",
      22 => "SSH", 
      23 => "Telnet",
      25 => "SMTP",
      53 => "DNS",
      80 => "HTTP",
      135 => "RPC",
      139 => "NetBIOS",
      443 => "HTTPS",
      445 => "SMB",
      3389 => "RDP"
    }
    
    Map.get(common_services, port, "unknown")
  end

  defp analyze_attacker_behavior(attacker_ip) do
    # Analizar patrones de comportamiento del atacante
    %{
      scan_patterns: ["sequential_ports", "service_probing"],
      timing_analysis: "moderate_speed",
      evasion_techniques: [],
      persistence: "single_session",
      sophistication_level: "intermediate"
    }
  end

  defp geolocate_attacker(attacker_ip) do
    # Placeholder para geolocalización
    # En implementación real usaríamos APIs como MaxMind, IPInfo, etc.
    %{
      country: "Unknown",
      region: "Unknown", 
      city: "Unknown",
      isp: "Unknown",
      is_tor: false,
      is_vpn: false,
      is_hosting: false
    }
  end

  defp check_threat_databases(attacker_ip) do
    # Placeholder para consulta de bases de datos de amenazas
    # En implementación real consultaríamos VirusTotal, AbuseIPDB, etc.
    %{
      malware_detected: false,
      reputation_score: 0,
      threat_feeds: [],
      last_seen_malicious: nil,
      categories: []
    }
  end

  defp calculate_attacker_risk_score(os_info, service_info, threat_intel) do
    base_score = 0.3  # Score base por escanear
    
    # Bonificación por OS detectado (más información = mayor sofisticación)
    os_bonus = os_info.confidence * 0.2
    
    # Bonificación por servicios abiertos (más servicios = mayor superficie de ataque)
    service_bonus = min(0.3, length(service_info) * 0.05)
    
    # Bonificación por inteligencia de amenazas
    threat_bonus = if threat_intel.malware_detected, do: 0.5, else: 0.0
    
    min(1.0, base_score + os_bonus + service_bonus + threat_bonus)
  end

  ## Honeypots

  defp deploy_honeypot_services(ports) do
    Logger.info("Desplegando honeypots en puertos: #{inspect(ports)}")
    
    Enum.reduce(ports, %{}, fn port, acc ->
      case start_honeypot(port) do
        {:ok, pid} -> Map.put(acc, port, pid)
        {:error, _reason} -> acc
      end
    end)
  end

  defp start_honeypot(port) do
    case :gen_tcp.listen(port, [:binary, {:active, true}, {:reuseaddr, true}]) do
      {:ok, listen_socket} ->
        pid = spawn_link(fn -> honeypot_loop(listen_socket, port) end)
        {:ok, pid}
      
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp honeypot_loop(listen_socket, port) do
    case :gen_tcp.accept(listen_socket) do
      {:ok, socket} ->
        {:ok, {remote_ip, remote_port}} = :inet.peername(socket)
        
        Logger.warn("🍯 HONEYPOT ACTIVADO - Puerto #{port} desde #{:inet.ntoa(remote_ip)}:#{remote_port}")
        
        # Simular servicio falso
        spawn(fn -> simulate_fake_service(socket, port) end)
        
        # Registrar actividad sospechosa
        honeypot_activity = %{
          type: :honeypot_access,
          source_ip: :inet.ntoa(remote_ip) |> to_string(),
          honeypot_port: port,
          confidence: 1.0,
          evidence: ["honeypot_interaction"],
          timestamp: System.monotonic_time()
        }
        
        send(ScanDetector, {:scan_detected, honeypot_activity})
        
        honeypot_loop(listen_socket, port)
      
      {:error, :closed} ->
        Logger.debug("Honeypot cerrado para puerto #{port}")
      
      {:error, reason} ->
        Logger.debug("Error en honeypot puerto #{port}: #{reason}")
        Process.sleep(1000)
        honeypot_loop(listen_socket, port)
    end
  end

  defp simulate_fake_service(socket, port) do
    # Simular respuestas de servicios falsos para engañar al atacante
    fake_response = case port do
      21 -> "220 FTP server ready\r\n"
      22 -> "SSH-2.0-OpenSSH_7.4\r\n"
      23 -> "Login: "
      25 -> "220 mail.example.com ESMTP ready\r\n"
      80 -> "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n<html><body>Welcome</body></html>"
      _ -> "Service ready\r\n"
    end
    
    :gen_tcp.send(socket, fake_response)
    
    # Mantener conexión abierta un poco para recopilar más información
    case :gen_tcp.recv(socket, 0, 10000) do
      {:ok, data} ->
        Logger.info("Datos recibidos en honeypot #{port}: #{inspect(data)}")
      {:error, _} ->
        :ok
    end
    
    :gen_tcp.close(socket)
  end

  defp deploy_targeted_honeypots(scan_info) do
    # Desplegar honeypots específicos basados en el tipo de escaneo detectado
    target_ports = case scan_info.type do
      :port_scan -> [21, 23, 1433, 3306]  # Servicios vulnerables falsos
      :service_detection -> [22, 80, 443]  # Servicios comunes
      _ -> [8080, 9999]  # Puertos genéricos
    end
    
    deploy_honeypots(target_ports)
  end

  ## Utilidades

  defp attempt_tcp_connection(host, port, timeout \\ 3000) do
    :gen_tcp.connect(to_charlist(host), port, [:binary, {:active, false}], timeout)
  end

  defp monitor_network_traffic do
    # Loop principal del monitor de red
    # En implementación real usaríamos herramientas como:
    # - eBPF para captura de paquetes
    # - netfilter para filtrado
    # - pcap para análisis profundo
    
    Process.sleep(1000)
    monitor_network_traffic()
  end

  defp start_log_analyzer do
    spawn_link(fn -> log_analyzer_loop() end)
  end

  defp log_analyzer_loop do
    # Analizar logs del sistema en busca de patrones sospechosos
    Process.sleep(30_000)  # Cada 30 segundos
    
    # En implementación real analizaríamos:
    # - /var/log/auth.log
    # - /var/log/syslog  
    # - Logs de firewall
    # - Logs de aplicaciones web
    
    log_analyzer_loop()
  end

  defp default_response_config do
    %{
      auto_response: true,
      response_level: :active,  # :passive, :active, :aggressive
      reverse_scan: true,
      deploy_honeypots: true,
      block_attacker: false,  # Requiere integración con firewall
      alert_admin: true,
      log_level: :info
    }
  end

  defp register_scanner(scanners, scan_info) do
    ip = scan_info.source_ip
    
    case Map.get(scanners, ip) do
      nil ->
        # Nuevo escáner
        scanner_profile = %{
          first_seen: scan_info.timestamp,
          last_seen: scan_info.timestamp,
          scan_types: [scan_info.type],
          total_scans: 1,
          highest_confidence: scan_info.confidence,
          evidence: scan_info.evidence,
          threat_level: :low,
          status: :active
        }
        
        Map.put(scanners, ip, scanner_profile)
      
      existing ->
        # Actualizar escáner existente
        updated_profile = %{existing |
          last_seen: scan_info.timestamp,
          scan_types: [scan_info.type | existing.scan_types] |> Enum.uniq(),
          total_scans: existing.total_scans + 1,
          highest_confidence: max(existing.highest_confidence, scan_info.confidence),
          evidence: existing.evidence ++ scan_info.evidence,
          threat_level: calculate_threat_level(existing.total_scans + 1, scan_info.confidence)
        }
        
        Map.put(scanners, ip, updated_profile)
    end
  end

  defp calculate_threat_level(scan_count, confidence) do
    cond do
      scan_count > 10 or confidence > 0.9 -> :critical
      scan_count > 5 or confidence > 0.7 -> :high  
      scan_count > 2 or confidence > 0.5 -> :medium
      true -> :low
    end
  end

  defp update_scanner_info(scanners, ip, reverse_scan_result) do
    case Map.get(scanners, ip) do
      nil -> scanners
      existing ->
        updated = Map.put(existing, :reverse_scan_data, reverse_scan_result)
        Map.put(scanners, ip, updated)
    end
  end

  defp generate_detection_statistics(state) do
    total_scanners = map_size(state.detected_scanners)
    
    threat_levels = state.detected_scanners
                  |> Map.values()
                  |> Enum.group_by(& &1.threat_level)
                  |> Enum.map(fn {level, scanners} -> {level, length(scanners)} end)
                  |> Enum.into(%{})
    
    scan_types = state.detected_scanners
               |> Map.values()
               |> Enum.flat_map(& &1.scan_types)
               |> Enum.frequencies()
    
    uptime = System.convert_time_unit(
      System.monotonic_time() - state.start_time,
      :native, :millisecond
    )
    
    %{
      uptime_ms: uptime,
      total_detected_scanners: total_scanners,
      threat_level_breakdown: threat_levels,
      scan_type_frequencies: scan_types,
      active_honeypots: map_size(state.honeypots),
      active_monitors: map_size(state.active_monitors),
      detection_rate: calculate_detection_rate(state)
    }
  end

  defp calculate_detection_rate(state) do
    # Calcular tasa de detección basada en eventos recientes
    recent_events = :ets.tab2list(state.scan_events)
                  |> length()
    
    uptime_hours = System.convert_time_unit(
      System.monotonic_time() - state.start_time,
      :native, :millisecond
    ) / (1000 * 60 * 60)
    
    if uptime_hours > 0 do
      recent_events / uptime_hours
    else
      0.0
    end
  end
end

# Interfaz de línea de comandos
defmodule ScanDetector.CLI do
  @moduledoc """
  Interfaz de línea de comandos para el detector de escaneos.
  """

  def main(args \\ []) do
    {opts, _, _} = OptionParser.parse(args, 
      switches: [
        monitor: :boolean,
        ports: :string,
        response: :string,
        honeypots: :string,
        help: :boolean
      ],
      aliases: [
        m: :monitor,
        p: :ports, 
        r: :response,
        h: :help
      ]
    )

    if opts[:help] do
      print_help()
    else
      run_detector(opts)
    end
  end

  defp run_detector(opts) do
    IO.puts("🛡️  Iniciando ScanDetector - Sistema de Defensa Activa")
    IO.puts("=" |> String.duplicate(50))

    {:ok, _pid} = ScanDetector.start_link()

    # Configurar respuestas
    if opts[:response] do
      response_level = String.to_atom(opts[:response])
      config = %{
        auto_response: true,
        response_level: response_level,
        reverse_scan: response_level in [:active, :aggressive],
        deploy_honeypots: response_level == :aggressive
      }
      ScanDetector.configure_responses(config)
      IO.puts("✅ Nivel de respuesta configurado: #{response_level}")
    end

    # Desplegar honeypots
    if opts[:honeypots] do
      ports = opts[:honeypots] 
            |> String.split(",") 
            |> Enum.map(&String.to_integer(String.trim(&1)))
      ScanDetector.deploy_honeypots(ports)
      IO.puts("🍯 Honeypots desplegados en puertos: #{inspect(ports)}")
    end

    # Iniciar monitoreo
    if opts[:monitor] do
      monitor_opts = []
      if opts[:ports] do
        ports = opts[:ports] 
              |> String.split(",") 
              |> Enum.map(&String.to_integer(String.trim(&1)))
        monitor_opts = [ports: ports]
      end

      ScanDetector.start_monitoring(monitor_opts)
      IO.puts("👁️  Monitoreo activo iniciado")
      
      # Mostrar estadísticas en tiempo real
      stats_loop()
    else
      IO.puts("Usar --monitor para iniciar detección activa")
    end
  end

  defp stats_loop do
    Process.sleep(10_000)  # Cada 10 segundos
    
    stats = ScanDetector.get_detection_stats()
    scanners = ScanDetector.list_detected_scanners()
    
    IO.puts("\n" <> "=" |> String.duplicate(50))
    IO.puts("📊 ESTADÍSTICAS EN TIEMPO REAL")
    IO.puts("Tiempo activo: #{div(stats.uptime_ms, 1000)} segundos")
    IO.puts("Escáneres detectados: #{stats.total_detected_scanners}")
    IO.puts("Honeypots activos: #{stats.active_honeypots}")
    IO.puts("Tasa de detección: #{Float.round(stats.detection_rate, 2)} eventos/hora")
    
    if map_size(scanners) > 0 do
      IO.puts("\n🚨 ESCÁNERES ACTIVOS:")
      Enum.each(scanners, fn {ip, info} ->
        IO.puts("  #{ip} - Nivel: #{info.threat_level} (#{info.total_scans} escaneos)")
      end)
    end
    
    stats_loop()
  end

  defp print_help do
    IO.puts("""
    ScanDetector - Sistema de Detección y Respuesta Activa
    
    Uso: scan_detector [opciones]
    
    Opciones:
      -m, --monitor              Iniciar monitoreo activo
      -p, --ports PORTS          Puertos a monitorear (separados por coma)
      -r, --response LEVEL       Nivel de respuesta (passive|active|aggressive)
      --honeypots PORTS          Desplegar honeypots en puertos específicos
      -h, --help                 Mostrar esta ayuda
    
    Ejemplos:
      scan_detector --monitor --ports 22,80,443 --response active
      scan_detector --monitor --honeypots 21,23,1433 --response aggressive
    """)
  end
end

# Demo completo
defmodule ScanDetector.Demo do
  @moduledoc """
  Demostración completa del sistema de detección.
  """

  def run_full_demo do
    IO.puts("🛡️  DEMO COMPLETO - SISTEMA DE DETECCIÓN DE ESCANEOS")
    IO.puts("=" |> String.duplicate(60))

    # Inicializar el sistema
    {:ok, _pid} = ScanDetector.start_link()
    
    # Configurar respuesta agresiva
    ScanDetector.configure_responses(%{
      auto_response: true,
      response_level: :aggressive,
      reverse_scan: true,
      deploy_honeypots: true
    })

    IO.puts("✅ Sistema inicializado con respuesta agresiva")

    # Desplegar honeypots
    honeypot_ports = [21, 23, 1433, 3306, 8080]
    ScanDetector.deploy_honeypots(honeypot_ports)
    IO.puts("🍯 Honeypots desplegados: #{inspect(honeypot_ports)}")

    # Iniciar monitoreo
    ScanDetector.start_monitoring(ports: [22, 80, 443, 21, 23, 25])
    IO.puts("👁️  Monitoreo activo en puertos críticos")

    IO.puts("\n⏳ Sistema listo. Esperando actividad sospechosa...")
    IO.puts("💡 Ejecuta el NetworkScanner contra localhost para ver la detección en acción")
    IO.puts("💡 Ejemplo: NetworkScanner.scan([\"localhost\"], [22, 80, 443])")

    # Simular algunos eventos para la demo
    Process.sleep(2000)
    simulate_detection_events()

    # Mostrar estadísticas
    Process.sleep(3000)
    show_demo_results()
  end

  defp simulate_detection_events do
    IO.puts("\n🎭 Simulando eventos de detección...")
    
    # Simular escaneo detectado
    scan_event = %{
      type: :nmap_scan,
      source_ip: "192.168.1.100",
      confidence: 0.95,
      evidence: ["nmap_user_agent", "sequential_port_scan", "service_probing"],
      timestamp: System.monotonic_time()
    }
    
    send(ScanDetector, {:scan_detected, scan_event})
    IO.puts("🚨 Simulado: Escaneo Nmap detectado desde 192.168.1.100")

    Process.sleep(1000)

    # Simular acceso a honeypot
    honeypot_event = %{
      type: :honeypot_access,
      source_ip: "10.0.0.50",
      confidence: 1.0,
      evidence: ["honeypot_interaction", "port_1433"],
      timestamp: System.monotonic_time()
    }
    
    send(ScanDetector, {:scan_detected, honeypot_event})
    IO.puts("🍯 Simulado: Acceso a honeypot desde 10.0.0.50")
  end

  defp show_demo_results do
    IO.puts("\n📊 RESULTADOS DE LA DEMO:")
    IO.puts("=" |> String.duplicate(40))

    stats = ScanDetector.get_detection_stats()
    scanners = ScanDetector.list_detected_scanners()

    IO.puts("Escáneres detectados: #{stats.total_detected_scanners}")
    IO.puts("Honeypots activos: #{stats.active_honeypots}")

    if map_size(scanners) > 0 do
      IO.puts("\n🎯 ANÁLISIS DE ATACANTES:")
      Enum.each(scanners, fn {ip, info} ->
        IO.puts("IP: #{ip}")
        IO.puts("  Nivel de amenaza: #{info.threat_level}")
        IO.puts("  Tipos de escaneo: #{inspect(info.scan_types)}")
        IO.puts("  Total de escaneos: #{info.total_scans}")
        IO.puts("  Confianza máxima: #{info.highest_confidence}")
        IO.puts("")
      end)
    end

    IO.puts("✅ Demo completada. El sistema sigue monitoreando...")
  end
end
