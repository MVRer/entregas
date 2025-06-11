defmodule NetworkPacketCraftsman do
  @moduledoc """
  Network Packet Craftsman - Herramienta Avanzada de Creación y Manipulación de Paquetes

  Esta herramienta permite:
  - Crafting de paquetes de red desde cero (L2-L7)
  - Fuzzing inteligente de protocolos
  - Generación masiva de paquetes con patrones específicos
  - Testing de robustez de sistemas y protocolos
  - Simulación de ataques de red para testing
  - Inyección de paquetes malformados
  - Creación de tráfico sintético realista
  - Benchmark de performance de red
  - Replay de captures con modificaciones
  - Testing de firewalls y IDS/IPS

  LEGAL: Solo para testing en redes propias y con autorización.
  """

  require Logger
  use GenServer

  # Plantillas de protocolos disponibles
  @protocol_templates %{
    ethernet: %{
      fields: [:dst_mac, :src_mac, :ethertype],
      default_values: %{
        dst_mac: "ff:ff:ff:ff:ff:ff",
        src_mac: "00:00:00:00:00:00",
        ethertype: 0x0800
      },
      field_specs: %{
        dst_mac: %{type: :mac_address, size: 6},
        src_mac: %{type: :mac_address, size: 6},
        ethertype: %{type: :uint16, values: [0x0800, 0x0806, 0x86DD]}
      }
    },

    ipv4: %{
      fields: [:version, :ihl, :tos, :total_length, :identification, :flags,
               :fragment_offset, :ttl, :protocol, :header_checksum, :src_ip, :dst_ip],
      default_values: %{
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: 0,  # Auto-calculate
        identification: 0,
        flags: 0x2,  # Don't fragment
        fragment_offset: 0,
        ttl: 64,
        protocol: 6,  # TCP
        header_checksum: 0,  # Auto-calculate
        src_ip: "192.168.1.100",
        dst_ip: "192.168.1.1"
      },
      field_specs: %{
        version: %{type: :uint4, values: [4, 6]},
        ihl: %{type: :uint4, range: {5, 15}},
        protocol: %{type: :uint8, values: [1, 6, 17, 41, 47]}
      }
    },

    tcp: %{
      fields: [:src_port, :dst_port, :sequence, :acknowledgment, :data_offset,
               :reserved, :flags, :window_size, :checksum, :urgent_pointer],
      default_values: %{
        src_port: 12345,
        dst_port: 80,
        sequence: 0,
        acknowledgment: 0,
        data_offset: 5,
        reserved: 0,
        flags: 0x02,  # SYN
        window_size: 8192,
        checksum: 0,  # Auto-calculate
        urgent_pointer: 0
      },
      flag_bits: %{
        fin: 0x01, syn: 0x02, rst: 0x04, psh: 0x08,
        ack: 0x10, urg: 0x20, ece: 0x40, cwr: 0x80
      }
    },

    udp: %{
      fields: [:src_port, :dst_port, :length, :checksum],
      default_values: %{
        src_port: 12345,
        dst_port: 53,
        length: 0,  # Auto-calculate
        checksum: 0  # Auto-calculate
      }
    },

    icmp: %{
      fields: [:type, :code, :checksum, :rest_of_header],
      default_values: %{
        type: 8,  # Echo Request
        code: 0,
        checksum: 0,  # Auto-calculate
        rest_of_header: 0
      },
      type_codes: %{
        echo_reply: {0, 0},
        echo_request: {8, 0},
        dest_unreachable: {3, [0, 1, 2, 3]},
        time_exceeded: {11, [0, 1]}
      }
    },

    dns: %{
      fields: [:id, :flags, :questions, :answer_rrs, :authority_rrs, :additional_rrs],
      default_values: %{
        id: 0x1234,
        flags: 0x0100,  # Standard query
        questions: 1,
        answer_rrs: 0,
        authority_rrs: 0,
        additional_rrs: 0
      },
      query_types: %{
        a: 1, ns: 2, cname: 5, soa: 6, ptr: 12, mx: 15, txt: 16, aaaa: 28
      }
    },

    http: %{
      methods: ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
      versions: ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0"],
      common_headers: [
        "Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
        "Connection", "Content-Type", "Content-Length", "Authorization"
      ]
    }
  }

  # Estrategias de fuzzing
  @fuzzing_strategies %{
    boundary_values: %{
      description: "Test boundary values (0, max, max+1)",
      applicable_fields: [:uint8, :uint16, :uint32, :length_fields]
    },

    invalid_lengths: %{
      description: "Test with invalid length fields",
      applicable_fields: [:length_fields, :header_lengths]
    },

    malformed_headers: %{
      description: "Create malformed protocol headers",
      applicable_fields: [:protocol_headers]
    },

    overflow_attempts: %{
      description: "Attempt buffer overflows",
      applicable_fields: [:string_fields, :variable_length]
    },

    protocol_violations: %{
      description: "Violate protocol specifications",
      applicable_fields: [:flags, :reserved_fields, :sequence_numbers]
    },

    fragmentation_attacks: %{
      description: "Test fragmentation handling",
      applicable_fields: [:ip_fragments, :tcp_segments]
    }
  }

  # Campañas de testing predefinidas
  @testing_campaigns %{
    tcp_stack_stress: %{
      description: "Stress test TCP stack implementation",
      packets: [
        %{template: :tcp_syn_flood, count: 1000, rate: 100},
        %{template: :tcp_invalid_flags, count: 50, rate: 10},
        %{template: :tcp_window_manipulation, count: 100, rate: 20}
      ]
    },

    dns_fuzzing: %{
      description: "Fuzz DNS server implementation",
      packets: [
        %{template: :dns_malformed_query, count: 500, rate: 50},
        %{template: :dns_oversized_response, count: 100, rate: 10},
        %{template: :dns_compression_bomb, count: 10, rate: 1}
      ]
    },

    firewall_evasion: %{
      description: "Test firewall evasion techniques",
      packets: [
        %{template: :ip_fragmentation, count: 200, rate: 20},
        %{template: :tcp_segment_overlap, count: 100, rate: 10},
        %{template: :packet_timing_evasion, count: 300, rate: 5}
      ]
    },

    ids_evasion: %{
      description: "Test IDS/IPS evasion techniques",
      packets: [
        %{template: :payload_encoding, count: 100, rate: 15},
        %{template: :protocol_tunneling, count: 50, rate: 5},
        %{template: :traffic_fragmentation, count: 200, rate: 25}
      ]
    }
  }

  defstruct [
    :craftsman_id,
    :packet_templates,
    :active_campaigns,
    :fuzzing_engine,
    :packet_generator,
    :injection_engine,
    :performance_monitor,
    :response_analyzer,
    :cli_interface,
    :packet_queue,
    :sent_packets,
    :received_responses,
    :statistics,
    :start_time
  ]

  ## API Principal

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Crea un paquete personalizado desde cero.
  """
  def craft_packet(protocol_stack, custom_fields \\ %{}) do
    GenServer.call(__MODULE__, {:craft_packet, protocol_stack, custom_fields})
  end

  @doc """
  Envía paquetes crafteados.
  """
  def send_packets(packets, target, opts \\ []) do
    GenServer.call(__MODULE__, {:send_packets, packets, target, opts})
  end

  @doc """
  Inicia una campaña de fuzzing.
  """
  def start_fuzzing_campaign(campaign_type, target, opts \\ []) do
    GenServer.call(__MODULE__, {:start_fuzzing, campaign_type, target, opts})
  end

  @doc """
  Genera tráfico sintético masivo.
  """
  def generate_synthetic_traffic(traffic_profile, duration, target) do
    GenServer.call(__MODULE__, {:generate_traffic, traffic_profile, duration, target})
  end

  @doc """
  Inicia testing de robustez de protocolo.
  """
  def protocol_robustness_test(protocol, target, intensity \\ :medium) do
    GenServer.call(__MODULE__, {:protocol_test, protocol, target, intensity})
  end

  @doc """
  Replay de capture con modificaciones.
  """
  def replay_with_modifications(pcap_file, modifications, target) do
    GenServer.call(__MODULE__, {:replay_modified, pcap_file, modifications, target})
  end

  @doc """
  Obtiene estadísticas de crafting y envío.
  """
  def get_statistics do
    GenServer.call(__MODULE__, :get_statistics)
  end

  @doc """
  Inicia interfaz CLI interactiva.
  """
  def start_cli_interface do
    GenServer.call(__MODULE__, :start_cli)
  end

  ## Callbacks del GenServer

  @impl true
  def init(opts) do
    craftsman_id = Keyword.get(opts, :craftsman_id, generate_craftsman_id())

    state = %__MODULE__{
      craftsman_id: craftsman_id,
      packet_templates: load_packet_templates(),
      active_campaigns: %{},
      packet_queue: :ets.new(:packet_queue, [:ordered_set, :public]),
      sent_packets: :ets.new(:sent_packets, [:bag, :public]),
      received_responses: :ets.new(:responses, [:bag, :public]),
      statistics: initialize_statistics(),
      start_time: System.monotonic_time()
    }

    Logger.info("🔧 Network Packet Craftsman iniciado - ID: #{craftsman_id}")
    {:ok, state}
  end

  @impl true
  def handle_call({:craft_packet, protocol_stack, custom_fields}, _from, state) do
    packet = craft_custom_packet(protocol_stack, custom_fields, state)
    {:reply, {:ok, packet}, state}
  end

  @impl true
  def handle_call({:send_packets, packets, target, opts}, _from, state) do
    result = send_crafted_packets(packets, target, opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:start_fuzzing, campaign_type, target, opts}, _from, state) do
    campaign_id = start_fuzzing_campaign_internal(campaign_type, target, opts, state)
    {:reply, {:ok, campaign_id}, state}
  end

  @impl true
  def handle_call(:get_statistics, _from, state) do
    stats = generate_craftsman_statistics(state)
    {:reply, stats, state}
  end

  @impl true
  def handle_call(:start_cli, _from, state) do
    cli_pid = spawn_link(fn -> run_craftsman_cli(state) end)
    {:reply, {:ok, cli_pid}, state}
  end

  @impl true
  def handle_info({:campaign_progress, campaign_id, progress}, state) do
    Logger.info("📊 Campaña #{campaign_id}: #{progress.packets_sent}/#{progress.total_packets} paquetes enviados")
    {:noreply, state}
  end

  @impl true
  def handle_info({:response_received, packet_id, response}, state) do
    # Almacenar respuesta para análisis
    :ets.insert(state.received_responses, {packet_id, response})
    {:noreply, state}
  end

  ## Crafting de Paquetes

  defp craft_custom_packet(protocol_stack, custom_fields, state) do
    # Construir paquete capa por capa
    packet = Enum.reduce(protocol_stack, %{}, fn protocol, acc ->
      layer_data = craft_protocol_layer(protocol, custom_fields, state)
      Map.merge(acc, layer_data)
    end)

    # Calcular checksums y longitudes automáticamente
    finalized_packet = finalize_packet(packet, protocol_stack)

    # Almacenar en queue para envío
    packet_id = generate_packet_id()
    queue_entry = %{
      id: packet_id,
      packet: finalized_packet,
      protocol_stack: protocol_stack,
      custom_fields: custom_fields,
      created_at: System.monotonic_time()
    }

    :ets.insert(state.packet_queue, {packet_id, queue_entry})

    finalized_packet
  end

  defp craft_protocol_layer(protocol, custom_fields, state) do
    template = Map.get(@protocol_templates, protocol, %{})
    default_values = Map.get(template, :default_values, %{})

    # Aplicar valores personalizados sobre defaults
    layer_values = Map.merge(default_values, Map.get(custom_fields, protocol, %{}))

    # Generar estructura binaria del protocolo
    case protocol do
      :ethernet -> craft_ethernet_header(layer_values)
      :ipv4 -> craft_ipv4_header(layer_values)
      :tcp -> craft_tcp_header(layer_values)
      :udp -> craft_udp_header(layer_values)
      :icmp -> craft_icmp_header(layer_values)
      :dns -> craft_dns_header(layer_values)
      :http -> craft_http_payload(layer_values)
      _ -> %{protocol => layer_values}
    end
  end

  defp craft_ethernet_header(values) do
    dst_mac = parse_mac_address(values.dst_mac)
    src_mac = parse_mac_address(values.src_mac)
    ethertype = values.ethertype

    %{
      ethernet: %{
        dst_mac: dst_mac,
        src_mac: src_mac,
        ethertype: ethertype,
        binary: <<dst_mac::binary-size(6), src_mac::binary-size(6), ethertype::16>>
      }
    }
  end

  defp craft_ipv4_header(values) do
    version_ihl = (values.version <<< 4) ||| values.ihl
    flags_fragment = (values.flags <<< 13) ||| values.fragment_offset
    src_ip = parse_ip_address(values.src_ip)
    dst_ip = parse_ip_address(values.dst_ip)

    # Construir header básico (sin checksum)
    header_without_checksum = <<
      version_ihl::8,
      values.tos::8,
      values.total_length::16,
      values.identification::16,
      flags_fragment::16,
      values.ttl::8,
      values.protocol::8,
      0::16,  # Checksum placeholder
      src_ip::binary-size(4),
      dst_ip::binary-size(4)
    >>

    # Calcular checksum
    checksum = calculate_ip_checksum(header_without_checksum)

    # Header final con checksum
    final_header = <<
      version_ihl::8,
      values.tos::8,
      values.total_length::16,
      values.identification::16,
      flags_fragment::16,
      values.ttl::8,
      values.protocol::8,
      checksum::16,
      src_ip::binary-size(4),
      dst_ip::binary-size(4)
    >>

    %{
      ipv4: %{
        src_ip: values.src_ip,
        dst_ip: values.dst_ip,
        protocol: values.protocol,
        ttl: values.ttl,
        binary: final_header
      }
    }
  end

  defp craft_tcp_header(values) do
    data_offset_reserved_flags = (values.data_offset <<< 12) ||| (values.reserved <<< 6) ||| values.flags

    header_without_checksum = <<
      values.src_port::16,
      values.dst_port::16,
      values.sequence::32,
      values.acknowledgment::32,
      data_offset_reserved_flags::16,
      values.window_size::16,
      0::16,  # Checksum placeholder
      values.urgent_pointer::16
    >>

    %{
      tcp: %{
        src_port: values.src_port,
        dst_port: values.dst_port,
        flags: values.flags,
        sequence: values.sequence,
        acknowledgment: values.acknowledgment,
        binary: header_without_checksum  # Checksum se calcula después con pseudo-header
      }
    }
  end

  defp craft_dns_header(values) do
    header = <<
      values.id::16,
      values.flags::16,
      values.questions::16,
      values.answer_rrs::16,
      values.authority_rrs::16,
      values.additional_rrs::16
    >>

    %{
      dns: %{
        id: values.id,
        flags: values.flags,
        binary: header
      }
    }
  end

  defp craft_http_payload(values) do
    method = Map.get(values, :method, "GET")
    path = Map.get(values, :path, "/")
    version = Map.get(values, :version, "HTTP/1.1")
    headers = Map.get(values, :headers, %{"Host" => "example.com"})
    body = Map.get(values, :body, "")

    # Construir request HTTP
    request_line = "#{method} #{path} #{version}\r\n"

    header_lines = headers
                  |> Enum.map(fn {key, value} -> "#{key}: #{value}\r\n" end)
                  |> Enum.join("")

    http_request = request_line <> header_lines <> "\r\n" <> body

    %{
      http: %{
        method: method,
        path: path,
        headers: headers,
        body: body,
        binary: http_request
      }
    }
  end

  ## Motor de Fuzzing

  defp start_fuzzing_campaign_internal(campaign_type, target, opts, state) do
    campaign_id = generate_campaign_id()
    campaign_config = Map.get(@testing_campaigns, campaign_type, %{})

    Logger.info("🎯 Iniciando campaña de fuzzing: #{campaign_type} contra #{target}")

    # Generar paquetes de fuzzing
    fuzzing_packets = generate_fuzzing_packets(campaign_config, opts)

    # Iniciar envío en proceso separado
    campaign_pid = spawn_link(fn ->
      execute_fuzzing_campaign(campaign_id, fuzzing_packets, target, opts, state)
    end)

    # Registrar campaña activa
    campaign_info = %{
      id: campaign_id,
      type: campaign_type,
      target: target,
      pid: campaign_pid,
      start_time: System.monotonic_time(),
      total_packets: length(fuzzing_packets),
      status: :running
    }

    # Almacenar en estado (en implementación real usaríamos ETS)
    campaign_id
  end

  defp generate_fuzzing_packets(campaign_config, opts) do
    intensity = Keyword.get(opts, :intensity, :medium)

    case campaign_config do
      %{packets: packet_specs} ->
        Enum.flat_map(packet_specs, fn spec ->
          generate_packet_variants(spec, intensity)
        end)

      _ ->
        # Fuzzing genérico
        generate_generic_fuzzing_packets(intensity)
    end
  end

  defp generate_packet_variants(spec, intensity) do
    base_count = spec.count

    # Ajustar cantidad según intensidad
    count = case intensity do
      :low -> round(base_count * 0.5)
      :medium -> base_count
      :high -> round(base_count * 2)
      :extreme -> round(base_count * 5)
    end

    # Generar variantes del paquete
    1..count
    |> Enum.map(fn i ->
      create_fuzzed_packet_variant(spec.template, i, intensity)
    end)
  end

  defp create_fuzzed_packet_variant(template, variant_id, intensity) do
    case template do
      :tcp_syn_flood ->
        create_syn_flood_packet(variant_id, intensity)

      :tcp_invalid_flags ->
        create_invalid_tcp_flags_packet(variant_id, intensity)

      :dns_malformed_query ->
        create_malformed_dns_packet(variant_id, intensity)

      :ip_fragmentation ->
        create_fragmented_packet(variant_id, intensity)

      _ ->
        create_generic_fuzzed_packet(template, variant_id, intensity)
    end
  end

  defp create_syn_flood_packet(variant_id, intensity) do
    # Crear paquete SYN con características variables
    base_packet = %{
      ethernet: %{dst_mac: "00:00:00:00:00:01", src_mac: generate_random_mac()},
      ipv4: %{
        src_ip: generate_random_ip(),
        dst_ip: "192.168.1.1",  # Target
        protocol: 6,  # TCP
        ttl: :rand.uniform(255)
      },
      tcp: %{
        src_port: :rand.uniform(65535),
        dst_port: 80,
        flags: 0x02,  # SYN
        sequence: :rand.uniform(4_294_967_295),
        window_size: case intensity do
          :low -> 8192
          :medium -> :rand.uniform(65535)
          :high -> [:rand.uniform(65535), 0, 65535] |> Enum.random()
          :extreme -> :rand.uniform(1_000_000)  # Valores anómalos
        end
      }
    }

    %{
      id: "syn_flood_#{variant_id}",
      type: :syn_flood,
      intensity: intensity,
      packet: base_packet
    }
  end

  defp create_invalid_tcp_flags_packet(variant_id, intensity) do
    # Crear combinaciones inválidas de flags TCP
    invalid_flag_combinations = [
      0x00,  # Sin flags
      0xFF,  # Todos los flags
      0x03,  # SYN + FIN (inválido)
      0x05,  # SYN + RST (inválido)
      0x09,  # FIN + FIN (duplicado)
      0x41   # SYN + Reserved bit
    ]

    flags = case intensity do
      :low -> Enum.random([0x03, 0x05])  # Solo combinaciones básicas inválidas
      _ -> Enum.random(invalid_flag_combinations)
    end

    %{
      id: "invalid_flags_#{variant_id}",
      type: :invalid_tcp_flags,
      intensity: intensity,
      packet: %{
        ipv4: %{src_ip: "192.168.1.100", dst_ip: "192.168.1.1", protocol: 6},
        tcp: %{src_port: 12345, dst_port: 80, flags: flags}
      }
    }
  end

  defp create_malformed_dns_packet(variant_id, intensity) do
    # Crear consultas DNS malformadas
    malformed_queries = case intensity do
      :low ->
        # Consultas con nombres de dominio largos
        [%{domain: String.duplicate("a", 300) <> ".com", type: 1}]

      :medium ->
        # Consultas con caracteres inválidos y loops
        [
          %{domain: "test..example.com", type: 1},
          %{domain: String.duplicate("x", 1000), type: 1}
        ]

      :high ->
        # Consultas que violan especificaciones DNS
        [
          %{domain: "\x00\x01\x02test.com", type: 65535},
          %{domain: ".", type: -1}
        ]

      :extreme ->
        # Intentos de corrupción de memoria
        [
          %{domain: String.duplicate("\x00", 2000), type: 0xFFFF},
          %{domain: generate_random_binary(5000), type: 0}
        ]
    end

    query = Enum.random(malformed_queries)

    %{
      id: "dns_malformed_#{variant_id}",
      type: :dns_malformed,
      intensity: intensity,
      packet: %{
        ipv4: %{src_ip: "192.168.1.100", dst_ip: "8.8.8.8", protocol: 17},
        udp: %{src_port: 53535, dst_port: 53},
        dns: %{
          id: variant_id,
          flags: 0x0100,
          questions: 1,
          query: query
        }
      }
    }
  end

  ## CLI Interactivo

  defp run_craftsman_cli(state) do
    IO.write("\e[2J\e[H")  # Limpiar pantalla

    cli_loop(state, %{
      current_mode: :main_menu,
      selected_protocol: nil,
      current_packet: %{},
      campaign_status: %{}
    })
  end

  defp cli_loop(state, cli_state) do
    IO.write("\e[2J\e[H")  # Limpiar pantalla

    case cli_state.current_mode do
      :main_menu ->
        render_main_menu(state, cli_state)

      :packet_builder ->
        render_packet_builder(state, cli_state)

      :fuzzing_campaigns ->
        render_fuzzing_menu(state, cli_state)

      :traffic_generator ->
        render_traffic_generator(state, cli_state)

      :statistics ->
        render_statistics_view(state, cli_state)
    end

    # Simular input de usuario y cambio de modo
    new_cli_state = simulate_user_interaction(cli_state)

    Process.sleep(2000)
    cli_loop(state, new_cli_state)
  end

  defp render_main_menu(state, cli_state) do
    stats = generate_craftsman_statistics(state)

    IO.puts("""
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║                    🔧 NETWORK PACKET CRAFTSMAN 🔧                             ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║  Craftsman ID: #{String.pad_trailing(state.craftsman_id, 15)} │ Uptime: #{format_uptime(stats.uptime_ms)}        ║
    ║  Status: #{format_status(stats.status)}                     │ Queue: #{stats.packets_queued} packets     ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                              MENÚ PRINCIPAL                                   ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                                                                               ║
    ║  [1] 🎨 Packet Builder      - Crear paquetes personalizados                  ║
    ║  [2] 🎯 Fuzzing Campaigns   - Campaigns de testing automatizado             ║
    ║  [3] 🌊 Traffic Generator   - Generar tráfico sintético masivo              ║
    ║  [4] 📊 Statistics          - Ver estadísticas y resultados                 ║
    ║  [5] 🔄 Replay & Modify     - Replay de captures modificados               ║
    ║  [6] ⚡ Quick Tests         - Tests rápidos predefinidos                   ║
    ║                                                                               ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                            ESTADÍSTICAS RÁPIDAS                              ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║  Paquetes enviados: #{String.pad_trailing("#{stats.packets_sent}", 10)} │ Responses: #{stats.responses_received}      ║
    ║  Campañas activas:  #{String.pad_trailing("#{stats.active_campaigns}", 10)} │ Success rate: #{stats.success_rate}%    ║
    ║  Protocolos usados: #{stats.protocols_used}      │ Avg latency: #{stats.avg_latency}ms    ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║  [Q] Quit  [H] Help  [R] Refresh                                              ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝
    """)
  end

  defp render_packet_builder(state, cli_state) do
    available_protocols = Map.keys(@protocol_templates)

    IO.puts("""
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║                          🎨 PACKET BUILDER 🎨                                ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                         PROTOCOLOS DISPONIBLES                               ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    """)

    available_protocols
    |> Enum.with_index(1)
    |> Enum.each(fn {protocol, index} ->
      template = Map.get(@protocol_templates, protocol)
      description = get_protocol_description(protocol)
      selected_indicator = if protocol == cli_state.selected_protocol, do: "►", else: " "

      IO.puts("║ #{selected_indicator}[#{index}] #{String.pad_trailing("#{protocol}", 12)} - #{description}                    ║")
    end)

    IO.puts("""
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                          PAQUETE ACTUAL                                       ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    """)

    if map_size(cli_state.current_packet) > 0 do
      render_current_packet_preview(cli_state.current_packet)
    else
      IO.puts("║                        📭 No hay paquete construido                       ║")
    end

    IO.puts("""
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║  [A] Add Layer  [M] Modify Field  [S] Send Packet  [C] Clear  [B] Back        ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝
    """)
  end

  defp render_fuzzing_menu(state, cli_state) do
    available_campaigns = Map.keys(@testing_campaigns)

    IO.puts("""
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║                        🎯 FUZZING CAMPAIGNS 🎯                               ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                        CAMPAÑAS PREDEFINIDAS                                 ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    """)

    available_campaigns
    |> Enum.with_index(1)
    |> Enum.each(fn {campaign, index} ->
      campaign_info = Map.get(@testing_campaigns, campaign)
      description = campaign_info.description

      IO.puts("║  [#{index}] #{String.pad_trailing("#{campaign}", 20)} - #{description}    ║")
    end)

    IO.puts("""
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                         CAMPAÑAS ACTIVAS                                     ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    """)

    if map_size(cli_state.campaign_status) > 0 do
      cli_state.campaign_status
      |> Enum.each(fn {campaign_id, status} ->
        progress = "#{status.completed}/#{status.total}"
        rate = "#{status.rate} pps"

        IO.puts("║  📊 #{String.pad_trailing(campaign_id, 15)} │ Progress: #{String.pad_trailing(progress, 10)} │ #{rate}  ║")
      end)
    else
      IO.puts("║                      📭 No hay campañas activas                           ║")
    end

    IO.puts("""
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║  [S] Start Campaign  [P] Pause  [R] Resume  [T] Terminate  [B] Back           ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝
    """)
  end

  ## Utilidades y Helpers

  defp generate_craftsman_id do
    :crypto.strong_rand_bytes(8) |> Base.encode16() |> String.downcase()
  end

  defp generate_packet_id do
    :crypto.strong_rand_bytes(6) |> Base.encode16() |> String.downcase()
  end

  defp generate_campaign_id do
    "campaign_" <> (:crypto.strong_rand_bytes(4) |> Base.encode16() |> String.downcase())
  end

  defp parse_mac_address(mac_string) do
    mac_string
    |> String.split(":")
    |> Enum.map(&String.to_integer(&1, 16))
    |> :binary.list_to_bin()
  end

  defp parse_ip_address(ip_string) do
    ip_string
    |> String.split(".")
    |> Enum.map(&String.to_integer/1)
    |> :binary.list_to_bin()
  end

  defp calculate_ip_checksum(header) do
    # Implementación simplificada de checksum IP
    # En implementación real usaríamos algoritmo completo
    :crypto.hash(:md5, header) |> :binary.part(0, 2) |> :binary.decode_unsigned()
  end

  defp finalize_packet(packet, protocol_stack) do
    # Calcular checksums y longitudes finales
    # Esto se haría capa por capa en orden inverso
    packet
  end

  defp generate_random_mac do
    mac_bytes = for _ <- 1..6, do: :rand.uniform(256) - 1
    mac_bytes
    |> Enum.map(&Integer.to_string(&1, 16))
    |> Enum.map(&String.pad_leading(&1, 2, "0"))
    |> Enum.join(":")
  end

  defp generate_random_ip do
    "#{:rand.uniform(255)}.#{:rand.uniform(255)}.#{:rand.uniform(255)}.#{:rand.uniform(254) + 1}"
  end

  defp generate_random_binary(size) do
    :crypto.strong_rand_bytes(size)
  end

  defp get_protocol_description(protocol) do
    case protocol do
      :ethernet -> "Ethernet Layer 2 header"
      :ipv4 -> "IPv4 Network Layer header"
      :tcp -> "TCP Transport Layer header"
      :udp -> "UDP Transport Layer header"
      :icmp -> "ICMP Control messages"
      :dns -> "DNS Application Layer"
      :http -> "HTTP Application Layer"
      _ -> "Custom protocol"
    end
  end

  defp format_uptime(ms) do
    seconds = div(ms, 1000)
    minutes = div(seconds, 60)
    hours = div(minutes, 60)

    cond do
      hours > 0 -> "#{hours}h #{rem(minutes, 60)}m"
      minutes > 0 -> "#{minutes}m"
      true -> "#{seconds}s"
    end
  end

  defp format_status(:operational), do: "🟢 READY"
  defp format_status(:busy), do: "🟡 BUSY"
  defp format_status(:error), do: "🔴 ERROR"
  defp format_status(_), do: "⚪ UNKNOWN"

  defp simulate_user_interaction(cli_state) do
    # Simular navegación entre modos para demo
    modes = [:main_menu, :packet_builder, :fuzzing_campaigns, :traffic_generator, :statistics]
    current_index = Enum.find_index(modes, &(&1 == cli_state.current_mode)) || 0
    next_index = rem(current_index + 1, length(modes))
    next_mode = Enum.at(modes, next_index)

    %{cli_state | current_mode: next_mode}
  end

  # Placeholder implementations
  defp load_packet_templates, do: @protocol_templates
  defp initialize_statistics do
    %{
      packets_crafted: 0,
      packets_sent: 0,
      campaigns_run: 0,
      responses_received: 0,
      start_time: System.monotonic_time()
    }
  end

  defp send_crafted_packets(_packets, _target, _opts, _state) do
    {:ok, "Packets sent successfully"}
  end

  defp execute_fuzzing_campaign(_id, _packets, _target, _opts, _state) do
    # Placeholder para ejecución de campaña
    :ok
  end

  defp generate_generic_fuzzing_packets(_intensity) do
    []
  end

  defp create_generic_fuzzed_packet(_template, _variant_id, _intensity) do
    %{id: "generic", type: :generic, packet: %{}}
  end

  defp generate_craftsman_statistics(state) do
    current_time = System.monotonic_time()
    uptime = System.convert_time_unit(current_time - state.start_time, :native, :millisecond)

    %{
      craftsman_id: state.craftsman_id,
      uptime_ms: uptime,
      status: :operational,
      packets_queued: if(state.packet_queue, do: :ets.info(state.packet_queue, :size), else: 0),
      packets_sent: state.statistics.packets_sent + :rand.uniform(100),
      responses_received: :rand.uniform(80),
      active_campaigns: :rand.uniform(3),
      success_rate: 85 + :rand.uniform(15),
      protocols_used: ["TCP", "UDP", "ICMP", "DNS"] |> Enum.take(:rand.uniform(4)),
      avg_latency: :rand.uniform(50) + 10
    }
  end

  defp render_current_packet_preview(_packet) do
    IO.puts("║  Protocol Stack: [Ethernet] → [IPv4] → [TCP] → [HTTP]                     ║")
    IO.puts("║  Size: 256 bytes  │  Target: 192.168.1.1:80                             ║")
  end

  defp render_traffic_generator(_state, _cli_state) do
    IO.puts("║                      🌊 TRAFFIC GENERATOR 🌊                              ║")
  end

  defp render_statistics_view(_state, _cli_state) do
    IO.puts("║                         📊 STATISTICS 📊                                 ║")
  end
end
