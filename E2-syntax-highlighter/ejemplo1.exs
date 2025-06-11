defmodule NetworkScanner do
  @moduledoc """
  Suite completa de escaneo de red con alta concurrencia en Elixir.
  
  IMPORTANTE: Esta herramienta debe usarse únicamente en sistemas propios
  o con autorización explícita. El uso no autorizado puede ser ilegal.
  """

  require Logger
  use GenServer

  # Configuraciones por tipo de escaneo
  @scan_profiles %{
    stealth: %{
      timeout: 10000,
      max_concurrent_hosts: 10,
      max_concurrent_ports: 50,
      delay_between_requests: 100,
      randomize_order: true,
      fragment_packets: true
    },
    fast: %{
      timeout: 500,
      max_concurrent_hosts: 100,
      max_concurrent_ports: 2000,
      delay_between_requests: 0,
      randomize_order: false,
      fragment_packets: false
    },
    balanced: %{
      timeout: 2000,
      max_concurrent_hosts: 50,
      max_concurrent_ports: 500,
      delay_between_requests: 10,
      randomize_order: true,
      fragment_packets: false
    },
    aggressive: %{
      timeout: 200,
      max_concurrent_hosts: 200,
      max_concurrent_ports: 5000,
      delay_between_requests: 0,
      randomize_order: false,
      fragment_packets: false
    }
  }

  # Base de datos extendida de servicios
  @service_signatures %{
    # Puertos estándar
    21 => %{name: "FTP", probes: ["USER anonymous\r\n"], patterns: ["220", "FTP"]},
    22 => %{name: "SSH", probes: ["\r\n"], patterns: ["SSH-", "OpenSSH"]},
    23 => %{name: "Telnet", probes: ["\r\n"], patterns: ["login:", "Password:"]},
    25 => %{name: "SMTP", probes: ["EHLO test\r\n"], patterns: ["220", "SMTP", "mail"]},
    53 => %{name: "DNS", probes: [], patterns: []},
    80 => %{name: "HTTP", probes: ["GET / HTTP/1.0\r\n\r\n"], patterns: ["HTTP/", "Server:"]},
    110 => %{name: "POP3", probes: ["\r\n"], patterns: ["+OK", "POP3"]},
    143 => %{name: "IMAP", probes: ["\r\n"], patterns: ["* OK", "IMAP"]},
    443 => %{name: "HTTPS", probes: [], patterns: []},
    993 => %{name: "IMAPS", probes: [], patterns: []},
    995 => %{name: "POP3S", probes: [], patterns: []},
    1433 => %{name: "MSSQL", probes: [], patterns: ["Microsoft SQL Server"]},
    3306 => %{name: "MySQL", probes: [], patterns: ["mysql_native_password", "MySQL"]},
    3389 => %{name: "RDP", probes: [], patterns: ["Terminal Services"]},
    5432 => %{name: "PostgreSQL", probes: [], patterns: ["PostgreSQL", "postgres"]},
    5900 => %{name: "VNC", probes: [], patterns: ["RFB"]},
    6379 => %{name: "Redis", probes: ["INFO\r\n"], patterns: ["redis_version", "# Server"]},
    8080 => %{name: "HTTP-Alt", probes: ["GET / HTTP/1.0\r\n\r\n"], patterns: ["HTTP/", "Server:"]},
    8443 => %{name: "HTTPS-Alt", probes: [], patterns: []},
    9200 => %{name: "Elasticsearch", probes: ["GET / HTTP/1.0\r\n\r\n"], patterns: ["elasticsearch", "cluster_name"]},
    27017 => %{name: "MongoDB", probes: [], patterns: ["MongoDB", "mongo"]}
  }

  # Fingerprints de aplicaciones web
  @web_fingerprints [
    %{pattern: "Server: nginx", name: "Nginx", category: "web_server"},
    %{pattern: "Server: Apache", name: "Apache", category: "web_server"},
    %{pattern: "Server: Microsoft-IIS", name: "IIS", category: "web_server"},
    %{pattern: "X-Powered-By: PHP", name: "PHP", category: "language"},
    %{pattern: "X-Powered-By: ASP.NET", name: "ASP.NET", category: "framework"},
    %{pattern: "Set-Cookie: JSESSIONID", name: "Java/Tomcat", category: "application"},
    %{pattern: "X-AspNet-Version", name: "ASP.NET", category: "framework"},
    %{pattern: "Server: Werkzeug", name: "Flask/Werkzeug", category: "framework"},
    %{pattern: "Server: gunicorn", name: "Gunicorn", category: "app_server"},
    %{pattern: "X-Framework: Laravel", name: "Laravel", category: "framework"},
    %{pattern: "X-Powered-By: Express", name: "Express.js", category: "framework"}
  ]

  defstruct [
    :scan_id,
    :targets,
    :port_ranges,
    :scan_profile,
    :custom_opts,
    :results,
    :scan_start_time,
    :progress_callback,
    :active_tasks
  ]

  ## API Pública

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Escanea múltiples hosts y rangos de puertos con perfiles configurables.
  
  ## Ejemplos
  
      # Escaneo básico
      NetworkScanner.scan(["192.168.1.1", "google.com"], [80, 443])
      
      # Escaneo de rango CIDR
      NetworkScanner.scan("192.168.1.0/24", 1..1000, profile: :stealth)
      
      # Escaneo personalizado
      NetworkScanner.scan(
        ["10.0.0.1", "10.0.0.2"], 
        [22, 80, 443, 8080],
        profile: :fast,
        service_detection: true,
        os_detection: true
      )
  """
  def scan(targets, port_ranges, opts \\ []) do
    scan_id = generate_scan_id()
    GenServer.call(__MODULE__, {:scan, scan_id, targets, port_ranges, opts}, :infinity)
  end

  @doc """
  Escaneo sigiloso con técnicas de evasión.
  """
  def stealth_scan(targets, port_ranges, opts \\ []) do
    stealth_opts = Keyword.merge([profile: :stealth, randomize: true, fragment: true], opts)
    scan(targets, port_ranges, stealth_opts)
  end

  @doc """
  Escaneo agresivo de alta velocidad.
  """
  def aggressive_scan(targets, port_ranges, opts \\ []) do
    aggressive_opts = Keyword.merge([profile: :aggressive, service_detection: true], opts)
    scan(targets, port_ranges, aggressive_opts)
  end

  @doc """
  Descubrimiento de hosts activos en una red.
  """
  def host_discovery(network_range, opts \\ []) do
    discovery_opts = Keyword.merge([
      ports: [22, 80, 443, 135, 139, 445], 
      ping_sweep: true,
      profile: :fast
    ], opts)
    scan(network_range, discovery_opts[:ports], discovery_opts)
  end

  @doc """
  Escaneo de vulnerabilidades conocidas.
  """
  def vulnerability_scan(targets, opts \\ []) do
    vuln_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080]
    vuln_opts = Keyword.merge([
      profile: :balanced,
      service_detection: true,
      version_detection: true,
      script_scan: true
    ], opts)
    scan(targets, vuln_ports, vuln_opts)
  end

  def get_scan_progress(scan_id) do
    GenServer.call(__MODULE__, {:get_progress, scan_id})
  end

  def cancel_scan(scan_id) do
    GenServer.call(__MODULE__, {:cancel_scan, scan_id})
  end

  def list_active_scans do
    GenServer.call(__MODULE__, :list_scans)
  end

  ## Callbacks del GenServer

  @impl true
  def init(_opts) do
    {:ok, %{scans: %{}}}
  end

  @impl true
  def handle_call({:scan, scan_id, targets, port_ranges, opts}, from, state) do
    profile = Keyword.get(opts, :profile, :balanced)
    scan_config = Map.merge(@scan_profiles[profile], Enum.into(opts, %{}))
    
    scan_state = %__MODULE__{
      scan_id: scan_id,
      targets: normalize_targets(targets),
      port_ranges: normalize_port_ranges(port_ranges),
      scan_profile: profile,
      custom_opts: scan_config,
      results: %{},
      scan_start_time: System.monotonic_time(),
      active_tasks: []
    }

    # Ejecutar escaneo de forma asíncrona
    task = Task.start(fn -> 
      result = perform_network_scan(scan_state)
      GenServer.reply(from, result)
    end)

    new_state = put_in(state.scans[scan_id], {scan_state, task})
    {:noreply, new_state}
  end

  @impl true
  def handle_call({:get_progress, scan_id}, _from, state) do
    case get_in(state.scans, [scan_id]) do
      {scan_state, _task} -> {:reply, calculate_scan_progress(scan_state), state}
      nil -> {:reply, {:error, :scan_not_found}, state}
    end
  end

  @impl true
  def handle_call(:list_scans, _from, state) do
    active_scans = Map.keys(state.scans)
    {:reply, active_scans, state}
  end

  ## Funciones Principales de Escaneo

  defp perform_network_scan(scan_state) do
    Logger.info("Iniciando escaneo #{scan_state.scan_id}: #{length(scan_state.targets)} hosts, #{length(scan_state.port_ranges)} puertos")
    
    start_time = System.monotonic_time()
    
    # Paralelización por hosts
    host_results = 
      scan_state.targets
      |> maybe_randomize_order(scan_state.custom_opts[:randomize_order])
      |> Task.async_stream(
        fn host -> {host, scan_host_comprehensive(host, scan_state)} end,
        max_concurrency: scan_state.custom_opts[:max_concurrent_hosts],
        timeout: :infinity
      )
      |> Enum.reduce(%{}, fn
        {:ok, {host, result}}, acc -> Map.put(acc, host, result)
        {:exit, _reason}, acc -> acc
      end)
    
    end_time = System.monotonic_time()
    scan_duration = System.convert_time_unit(end_time - start_time, :native, :millisecond)
    
    compile_final_results(scan_state, host_results, scan_duration)
  end

  defp scan_host_comprehensive(host, scan_state) do
    Logger.debug("Escaneando host: #{host}")
    
    # 1. Verificar si el host está vivo
    host_alive = ping_host(host, scan_state.custom_opts)
    
    if host_alive do
      # 2. Escanear puertos
      port_results = scan_host_ports(host, scan_state)
      
      # 3. Detección de OS (opcional)
      os_info = if scan_state.custom_opts[:os_detection] do
        detect_operating_system(host, port_results)
      else
        %{}
      end
      
      %{
        status: :alive,
        ports: port_results,
        os_detection: os_info,
        scan_time: System.monotonic_time()
      }
    else
      %{
        status: :unreachable,
        ports: %{},
        os_detection: %{},
        scan_time: System.monotonic_time()
      }
    end
  end

  defp scan_host_ports(host, scan_state) do
    ports = maybe_randomize_order(scan_state.port_ranges, scan_state.custom_opts[:randomize_order])
    
    # Dividir en chunks para controlar concurrencia
    port_chunks = Enum.chunk_every(ports, scan_state.custom_opts[:max_concurrent_ports])
    
    port_chunks
    |> Enum.reduce(%{}, fn chunk, acc ->
      # Delay entre chunks para escaneos sigilosos
      if scan_state.custom_opts[:delay_between_requests] > 0 do
        Process.sleep(scan_state.custom_opts[:delay_between_requests])
      end
      
      chunk_results = scan_port_chunk_advanced(host, chunk, scan_state)
      Map.merge(acc, chunk_results)
    end)
  end

  defp scan_port_chunk_advanced(host, ports, scan_state) do
    ports
    |> Task.async_stream(
      fn port -> {port, scan_single_port_advanced(host, port, scan_state)} end,
      max_concurrency: min(length(ports), scan_state.custom_opts[:max_concurrent_ports]),
      timeout: scan_state.custom_opts[:timeout] + 2000
    )
    |> Enum.reduce(%{}, fn
      {:ok, {port, result}}, acc -> Map.put(acc, port, result)
      {:exit, _reason}, acc -> acc
    end)
  end

  defp scan_single_port_advanced(host, port, scan_state) do
    start_time = System.monotonic_time()
    
    # Técnicas de escaneo según el perfil
    scan_result = case scan_state.scan_profile do
      :stealth -> stealth_port_scan(host, port, scan_state.custom_opts)
      :aggressive -> aggressive_port_scan(host, port, scan_state.custom_opts)
      _ -> standard_port_scan(host, port, scan_state.custom_opts)
    end
    
    case scan_result do
      {:open, socket} ->
        service_info = if scan_state.custom_opts[:service_detection] do
          advanced_service_detection(host, port, socket, scan_state.custom_opts)
        else
          basic_service_lookup(port)
        end
        
        :gen_tcp.close(socket)
        
        %{
          status: :open,
          service: service_info,
          response_time: calculate_response_time(start_time),
          scan_method: scan_state.scan_profile
        }
      
      {:filtered, reason} ->
        %{
          status: :filtered,
          service: %{name: "filtered", reason: reason},
          response_time: calculate_response_time(start_time),
          scan_method: scan_state.scan_profile
        }
      
      {:closed, reason} ->
        %{
          status: :closed,
          service: %{name: "closed", reason: reason},
          response_time: calculate_response_time(start_time),
          scan_method: scan_state.scan_profile
        }
    end
  end

  ## Técnicas de Escaneo Específicas

  defp stealth_port_scan(host, port, opts) do
    # SYN Stealth scan simulation usando connect con timeout muy corto
    case :gen_tcp.connect(to_charlist(host), port, 
                         [:binary, {:active, false}, {:send_timeout, 100}], 
                         div(opts[:timeout], 2)) do
      {:ok, socket} -> {:open, socket}
      {:error, :timeout} -> {:filtered, :timeout}
      {:error, :econnrefused} -> {:closed, :connection_refused}
      {:error, reason} -> {:filtered, reason}
    end
  end

  defp aggressive_port_scan(host, port, opts) do
    # Scan agresivo con múltiples intentos
    case :gen_tcp.connect(to_charlist(host), port, 
                         [:binary, {:active, false}], opts[:timeout]) do
      {:ok, socket} -> {:open, socket}
      {:error, :econnrefused} -> {:closed, :connection_refused}
      {:error, reason} -> {:filtered, reason}
    end
  end

  defp standard_port_scan(host, port, opts) do
    case :gen_tcp.connect(to_charlist(host), port, 
                         [:binary, {:active, false}], opts[:timeout]) do
      {:ok, socket} -> {:open, socket}
      {:error, :econnrefused} -> {:closed, :connection_refused}
      {:error, reason} -> {:filtered, reason}
    end
  end

  ## Detección Avanzada de Servicios

  defp advanced_service_detection(host, port, socket, opts) do
    base_service = basic_service_lookup(port)
    
    # Intentar obtener banner
    banner = grab_banner_advanced(socket, port)
    
    # Análisis de headers HTTP si es aplicable
    http_info = if port in [80, 443, 8080, 8443] do
      analyze_http_service(host, port, opts[:timeout])
    else
      %{}
    end
    
    # Fingerprinting específico del servicio
    specific_info = perform_service_fingerprinting(socket, port, banner)
    
    # Combinar toda la información
    %{
      name: base_service.name,
      version: extract_version_from_banner(banner),
      banner: String.slice(banner, 0, 200),
      http_info: http_info,
      fingerprint: specific_info,
      confidence: calculate_confidence(base_service, banner, specific_info)
    }
  end

  defp grab_banner_advanced(socket, port) do
    # Probes específicos según el puerto
    probe = case Map.get(@service_signatures, port) do
      %{probes: [probe | _]} -> probe
      _ -> "\r\n"
    end
    
    :gen_tcp.send(socket, probe)
    
    # Intentar recibir respuesta
    case :gen_tcp.recv(socket, 0, 2000) do
      {:ok, data} -> 
        # Intentar obtener más datos si es necesario
        additional_data = case :gen_tcp.recv(socket, 0, 500) do
          {:ok, more_data} -> more_data
          {:error, _} -> ""
        end
        
        clean_banner(data <> additional_data)
      
      {:error, _} -> ""
    end
  end

  defp analyze_http_service(host, port, timeout) do
    case http_request(host, port, timeout) do
      {:ok, response} -> parse_http_response(response)
      {:error, _} -> %{}
    end
  end

  defp http_request(host, port, timeout) do
    request = """
    GET / HTTP/1.1\r
    Host: #{host}\r
    User-Agent: Mozilla/5.0 (compatible; NetworkScanner/1.0)\r
    Accept: */*\r
    Connection: close\r
    \r
    """
    
    case :gen_tcp.connect(to_charlist(host), port, [:binary, {:active, false}], timeout) do
      {:ok, socket} ->
        :gen_tcp.send(socket, request)
        
        response = case :gen_tcp.recv(socket, 0, timeout) do
          {:ok, data} -> data
          {:error, _} -> ""
        end
        
        :gen_tcp.close(socket)
        {:ok, response}
      
      {:error, reason} -> {:error, reason}
    end
  end

  defp parse_http_response(response) do
    lines = String.split(response, "\r\n")
    [status_line | headers] = lines
    
    # Extraer información de headers
    header_map = parse_headers(headers)
    
    # Fingerprinting de tecnologías web
    technologies = detect_web_technologies(header_map, response)
    
    %{
      status: parse_status_line(status_line),
      server: Map.get(header_map, "server", "unknown"),
      technologies: technologies,
      headers: header_map,
      title: extract_html_title(response)
    }
  end

  defp detect_web_technologies(headers, body) do
    content = Map.values(headers) |> Enum.join(" ") |> Kernel.<>(body)
    
    @web_fingerprints
    |> Enum.filter(fn %{pattern: pattern} -> 
      String.contains?(String.downcase(content), String.downcase(pattern))
    end)
    |> Enum.map(fn %{name: name, category: category} -> 
      %{name: name, category: category}
    end)
  end

  defp perform_service_fingerprinting(socket, port, banner) do
    case Map.get(@service_signatures, port) do
      %{patterns: patterns} ->
        matches = Enum.filter(patterns, &String.contains?(banner, &1))
        %{matched_patterns: matches, confidence: length(matches) * 0.3}
      
      _ -> %{matched_patterns: [], confidence: 0.1}
    end
  end

  ## Detección de Sistema Operativo

  defp detect_operating_system(host, port_results) do
    open_ports = get_open_ports_list(port_results)
    
    # Técnicas básicas de OS fingerprinting
    os_hints = []
    
    # Análisis por puertos característicos
    os_hints = os_hints ++ analyze_characteristic_ports(open_ports)
    
    # TTL analysis (requeriría ping raw)
    # TCP window size analysis (requeriría sockets raw)
    
    %{
      probable_os: determine_probable_os(os_hints),
      confidence: calculate_os_confidence(os_hints),
      evidence: os_hints
    }
  end

  defp analyze_characteristic_ports(open_ports) do
    cond do
      135 in open_ports and 139 in open_ports and 445 in open_ports ->
        [%{evidence: "SMB ports (135,139,445)", os: "Windows", confidence: 0.8}]
      
      22 in open_ports and 80 in open_ports ->
        [%{evidence: "SSH + HTTP", os: "Linux/Unix", confidence: 0.6}]
      
      3389 in open_ports ->
        [%{evidence: "RDP port 3389", os: "Windows", confidence: 0.9}]
      
      true -> []
    end
  end

  ## Utilidades y Helpers

  defp normalize_targets(targets) when is_list(targets), do: Enum.flat_map(targets, &expand_target/1)
  defp normalize_targets(target), do: expand_target(target)

  defp expand_target(target) when is_binary(target) do
    cond do
      String.contains?(target, "/") -> expand_cidr_range(target)
      String.contains?(target, "-") -> expand_ip_range(target)
      true -> [target]
    end
  end

  defp expand_cidr_range(cidr) do
    # Implementación básica de expansión CIDR
    case String.split(cidr, "/") do
      [base_ip, prefix] ->
        prefix_int = String.to_integer(prefix)
        expand_ip_cidr(base_ip, prefix_int)
      
      _ -> [cidr]
    end
  end

  defp expand_ip_cidr(base_ip, prefix) when prefix >= 24 do
    # Solo implementamos /24 y superiores por simplicidad
    [a, b, c, _d] = String.split(base_ip, ".") |> Enum.map(&String.to_integer/1)
    
    case prefix do
      24 -> for d <- 1..254, do: "#{a}.#{b}.#{c}.#{d}"
      _ -> [base_ip]  # Fallback para otros prefijos
    end
  end

  defp expand_ip_cidr(base_ip, _prefix), do: [base_ip]

  defp expand_ip_range(range) do
    # Formato: 192.168.1.1-192.168.1.50
    case String.split(range, "-") do
      [start_ip, end_ip] ->
        generate_ip_sequence(start_ip, end_ip)
      _ -> [range]
    end
  end

  defp generate_ip_sequence(start_ip, end_ip) do
    # Implementación simplificada para el último octeto
    [a, b, c, start_d] = String.split(start_ip, ".") |> Enum.map(&String.to_integer/1)
    [_, _, _, end_d] = String.split(end_ip, ".") |> Enum.map(&String.to_integer/1)
    
    for d <- start_d..end_d, do: "#{a}.#{b}.#{c}.#{d}"
  end

  defp normalize_port_ranges(ranges) when is_list(ranges), do: Enum.flat_map(ranges, &normalize_single_range/1)
  defp normalize_port_ranges(range), do: normalize_single_range(range)

  defp normalize_single_range(first..last), do: Enum.to_list(first..last)
  defp normalize_single_range(port) when is_integer(port), do: [port]
  defp normalize_single_range(ports) when is_list(ports), do: ports

  defp ping_host(host, opts) do
    # Ping básico usando TCP connect a puertos comunes
    common_ports = [80, 443, 22, 25, 53]
    timeout = div(opts[:timeout] || 2000, 5)
    
    common_ports
    |> Enum.any?(fn port ->
      case :gen_tcp.connect(to_charlist(host), port, [], timeout) do
        {:ok, socket} -> 
          :gen_tcp.close(socket)
          true
        {:error, _} -> false
      end
    end)
  end

  defp maybe_randomize_order(list, true), do: Enum.shuffle(list)
  defp maybe_randomize_order(list, _), do: list

  defp basic_service_lookup(port) do
    case Map.get(@service_signatures, port) do
      %{name: name} -> %{name: name, source: "port_lookup"}
      nil -> %{name: "unknown", source: "port_lookup"}
    end
  end

  defp clean_banner(banner) do
    banner
    |> String.replace(~r/[^\x20-\x7E]/, "")  # Solo caracteres imprimibles
    |> String.trim()
  end

  defp parse_headers(header_lines) do
    header_lines
    |> Enum.reduce(%{}, fn line, acc ->
      case String.split(line, ":", parts: 2) do
        [key, value] -> 
          Map.put(acc, String.downcase(String.trim(key)), String.trim(value))
        _ -> acc
      end
    end)
  end

  defp parse_status_line(status_line) do
    case String.split(status_line, " ", parts: 3) do
      [version, code, message] -> %{version: version, code: code, message: message}
      _ -> %{version: "unknown", code: "unknown", message: "unknown"}
    end
  end

  defp extract_html_title(html) do
    case Regex.run(~r/<title[^>]*>(.*?)<\/title>/i, html) do
      [_, title] -> String.trim(title)
      _ -> "No title"
    end
  end

  defp extract_version_from_banner(banner) do
    # Patrones comunes de versión
    version_patterns = [
      ~r/version\s+(\d+\.\d+\.\d+)/i,
      ~r/(\d+\.\d+\.\d+)/,
      ~r/v(\d+\.\d+)/i
    ]
    
    version_patterns
    |> Enum.find_value(fn pattern ->
      case Regex.run(pattern, banner) do
        [_, version] -> version
        _ -> nil
      end
    end) || "unknown"
  end

  defp calculate_confidence(base_service, banner, fingerprint) do
    base_conf = if base_service.name != "unknown", do: 0.3, else: 0.0
    banner_conf = if String.length(banner) > 10, do: 0.4, else: 0.0
    finger_conf = Map.get(fingerprint, :confidence, 0.0)
    
    min(1.0, base_conf + banner_conf + finger_conf)
  end

  defp calculate_response_time(start_time) do
    end_time = System.monotonic_time()
    System.convert_time_unit(end_time - start_time, :native, :millisecond)
  end

  defp get_open_ports_list(port_results) do
    port_results
    |> Enum.filter(fn {_port, result} -> result.status == :open end)
    |> Enum.map(fn {port, _result} -> port end)
  end

  defp determine_probable_os(os_hints) do
    os_hints
    |> Enum.group_by(& &1.os)
    |> Enum.map(fn {os, hints} -> 
      {os, Enum.sum(Enum.map(hints, & &1.confidence))}
    end)
    |> Enum.max_by(fn {_os, confidence} -> confidence end, fn -> {"Unknown", 0.0} end)
    |> elem(0)
  end

  defp calculate_os_confidence(os_hints) do
    if length(os_hints) > 0 do
      Enum.sum(Enum.map(os_hints, & &1.confidence)) / length(os_hints)
    else
      0.0
    end
  end

  defp calculate_scan_progress(scan_state) do
    # Esta sería una implementación más compleja del progreso
    %{
      scan_id: scan_state.scan_id,
      status: "running",
      targets_completed: 0,
      total_targets: length(scan_state.targets),
      current_target: "scanning..."
    }
  end

  defp compile_final_results(scan_state, host_results, scan_duration) do
    total_hosts = length(scan_state.targets)
    alive_hosts = host_results |> Enum.count(fn {_host, result} -> result.status == :alive end)
    total_open_ports = count_total_open_ports(host_results)
    
    %{
      scan_id: scan_state.scan_id,
      summary: %{
        total_hosts: total_hosts,
        alive_hosts: alive_hosts,
        total_open_ports: total_open_ports,
        scan_duration_ms: scan_duration,
        scan_profile: scan_state.scan_profile
      },
      hosts: host_results,
      recommendations: generate_security_recommendations(host_results),
      detailed_report: generate_comprehensive_report(scan_state, host_results, scan_duration)
    }
  end

  defp count_total_open_ports(host_results) do
    host_results
    |> Enum.flat_map(fn {_host, result} -> 
      case result.status do
        :alive -> Map.values(result.ports) |> Enum.count(& &1.status == :open)
        _ -> [0]
      end
    end)
    |> Enum.sum()
  end

  defp generate_security_recommendations(host_results) do
    recommendations = []
    
    # Analizar puertos de riesgo alto
    high_risk_services = ["telnet", "FTP", "SMTP", "POP3"]
    
    recommendations = recommendations ++ analyze_high_risk_ports(host_results, high_risk_services)
    recommendations = recommendations ++ analyze_outdated_services(host_results)
    recommendations = recommendations ++ analyze_default_configurations(host_results)
    
    recommendations
  end

  defp analyze_high_risk_ports(host_results, high_risk_services) do
    host_results
    |> Enum.flat_map(fn {host, result} ->
      case result.status do
        :alive ->
          result.ports
          |> Enum.filter(fn {_port, port_result} ->
            port_result.status == :open and 
            port_result.service.name in high_risk_services
          end)
          |> Enum.map(fn {port, _} ->
            %{
              type: :security_risk,
              severity: :high,
              host: host,
              port: port,
              message: "Puerto de alto riesgo detectado",
              recommendation: "Considerar deshabilitar o asegurar este servicio"
            }
          end)
        _ -> []
      end
    end)
  end

  defp analyze_outdated_services(_host_results) do
    # Placeholder para análisis de versiones obsoletas
    []
  end

  defp analyze_default_configurations(_host_results) do
    # Placeholder para detectar configuraciones por defecto
    []
  end

  defp generate_comprehensive_report(scan_state, host_results, scan_duration) do
    alive_hosts = Enum.filter(host_results, fn {_host, result} -> result.status == :alive end)
    
    """
    ========================================
    REPORTE COMPLETO DE ESCANEO DE RED
    ========================================
    
    ID de Escaneo: #{scan_state.scan_id}
    Perfil: #{scan_state.scan_profile}
    Duración: #{scan_duration}ms
    
    RESUMEN EJECUTIVO:
    - Hosts objetivo: #{length(scan_state.targets)}
    - Hosts activos: #{length(alive_hosts)}
    - Puertos totales escaneados: #{length(scan_state.targets) * length(scan_state.port_ranges)}
    - Puertos abiertos encontrados: #{count_total_open_ports(host_results)}
    
    HOSTS ACTIVOS:
    #{format_alive_hosts_table(alive_hosts)}
    
    ANÁLISIS DE SEGURIDAD:
    #{format_security_analysis(host_results)}
    
    ========================================
    """
  end

  defp format_alive_hosts_table(alive_hosts) do
    alive_hosts
    |> Enum.map(fn {host, result} ->
      open_ports = get_open_ports_list(result.ports)
      os_info = result.os_detection.probable_os || "Unknown"
      "  #{String.pad_trailing(host, 15)} | OS: #{String.pad_trailing(os_info, 10)} | Puertos: #{inspect(Enum.take(open_ports, 5))}#{if length(open_ports) > 5, do: "...", else: ""}"
    end)
    |> Enum.join("\n")
  end

  defp format_security_analysis(host_results) do
    recommendations = generate_security_recommendations(host_results)
    
    if length(recommendations) > 0 do
      recommendations
      |> Enum.map(fn rec ->
        "  [#{String.upcase(to_string(rec.severity))}] #{rec.host}:#{rec.port} - #{rec.message}"
      end)
      |> Enum.join("\n")
    else
      "  No se encontraron problemas de seguridad evidentes."
    end
  end

  defp generate_scan_id do
    :crypto.strong_rand_bytes(8) |> Base.encode16() |> String.downcase()
  end
end

# Módulo de utilidades especializadas
defmodule NetworkScanner.Utils do
  @moduledoc """
  Utilidades especializadas para diferentes tipos de escaneo.
  """

  @doc """
  Escaneo específico para infraestructura web.
  """
  def web_infrastructure_scan(targets) do
    web_ports = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9090]
    NetworkScanner.scan(targets, web_ports, [
      profile: :balanced,
      service_detection: true,
      http_analysis: true
    ])
  end

  @doc """
  Escaneo de servicios de base de datos.
  """
  def database_services_scan(targets) do
    db_ports = [1433, 1521, 3306, 5432, 6379, 27017, 9200, 5984, 7000, 7001]
    NetworkScanner.scan(targets, db_ports, [
      profile: :stealth,
      service_detection: true,
      version_detection: true
    ])
  end

  @doc """
  Descubrimiento de servicios de red empresarial.
  """
  def enterprise_services_scan(targets) do
    enterprise_ports = [22, 23, 25, 53, 88, 135, 139, 389, 445, 636, 3389, 5985, 5986]
    NetworkScanner.scan(targets, enterprise_ports, [
      profile: :balanced,
      service_detection: true,
      os_detection: true
    ])
  end

  @doc """
  Escaneo de IoT y dispositivos embebidos.
  """
  def iot_devices_scan(network_range) do
    iot_ports = [21, 22, 23, 80, 443, 554, 1900, 5000, 8080, 8081, 9999]
    NetworkScanner.scan(network_range, iot_ports, [
      profile: :stealth,
      service_detection: true,
      banner_grabbing: true
    ])
  end

  @doc """
  Análisis de superficie de ataque.
  """
  def attack_surface_analysis(targets) do
    all_interesting_ports = [
      # Servicios básicos
      21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
      # Bases de datos
      1433, 1521, 3306, 5432, 6379, 27017, 9200,
      # Servicios Windows
      135, 139, 445, 3389, 5985, 5986,
      # Web alternativo
      8080, 8443, 8000, 8888, 9000,
      # Monitoreo y gestión
      161, 162, 623, 9100, 10000
    ]
    
    NetworkScanner.scan(targets, all_interesting_ports, [
      profile: :balanced,
      service_detection: true,
      version_detection: true,
      os_detection: true,
      vulnerability_checks: true
    ])
  end
end

# Ejemplo de aplicación con supervisor
defmodule NetworkScanner.Application do
  use Application

  def start(_type, _args) do
    children = [
      NetworkScanner,
      # Aquí podrías agregar otros servicios como un servidor web para UI
      # {Phoenix.Endpoint, []}
    ]

    opts = [strategy: :one_for_one, name: NetworkScanner.Supervisor]
    Supervisor.start_link(children, opts)
  end
end

# Script de demostración
defmodule NetworkScanner.Demo do
  @moduledoc """
  Ejemplos avanzados de uso del escaneador de red.
  """

  def run_comprehensive_demo do
    IO.puts("=== DEMO COMPLETO DE NETWORK SCANNER ===\n")

    {:ok, _pid} = NetworkScanner.start_link()

    # Demo 1: Escaneo básico
    IO.puts("1. Escaneo básico de localhost...")
    result1 = NetworkScanner.scan(["localhost"], [22, 80, 443, 8080])
    print_scan_summary(result1)

    # Demo 2: Escaneo sigiloso
    IO.puts("\n2. Escaneo sigiloso de rango local...")
    result2 = NetworkScanner.stealth_scan("127.0.0.1", [21, 22, 23, 80, 443])
    print_scan_summary(result2)

    # Demo 3: Descubrimiento de red
    IO.puts("\n3. Descubrimiento de hosts (simulado)...")
    result3 = NetworkScanner.host_discovery(["localhost", "127.0.0.1"])
    print_scan_summary(result3)

    # Demo 4: Escaneo web especializado
    IO.puts("\n4. Escaneo de infraestructura web...")
    result4 = NetworkScanner.Utils.web_infrastructure_scan(["localhost"])
    print_detailed_web_results(result4)

    IO.puts("\n=== DEMO COMPLETADO ===")
  end

  defp print_scan_summary(result) do
    IO.puts("  Hosts escaneados: #{result.summary.total_hosts}")
    IO.puts("  Hosts activos: #{result.summary.alive_hosts}")
    IO.puts("  Puertos abiertos: #{result.summary.total_open_ports}")
    IO.puts("  Tiempo: #{result.summary.scan_duration_ms}ms")
    
    if length(result.recommendations) > 0 do
      IO.puts("  ⚠️  Recomendaciones de seguridad: #{length(result.recommendations)}")
    end
  end

  defp print_detailed_web_results(result) do
    print_scan_summary(result)
    
    # Mostrar detalles de servicios web encontrados
    web_services = extract_web_services(result.hosts)
    if length(web_services) > 0 do
      IO.puts("  Servicios web detectados:")
      Enum.each(web_services, fn service ->
        IO.puts("    #{service.host}:#{service.port} - #{service.server} (#{service.title})")
      end)
    end
  end

  defp extract_web_services(hosts) do
    hosts
    |> Enum.flat_map(fn {host, host_result} ->
      if host_result.status == :alive do
        host_result.ports
        |> Enum.filter(fn {_port, port_result} ->
          port_result.status == :open and 
          Map.has_key?(port_result.service, :http_info)
        end)
        |> Enum.map(fn {port, port_result} ->
          %{
            host: host,
            port: port,
            server: port_result.service.http_info[:server] || "unknown",
            title: port_result.service.http_info[:title] || "no title"
          }
        end)
      else
        []
      end
    end)
  end
end
