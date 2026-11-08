"""Descoberta do ambiente de execução do NetProbe.

Antes de qualquer varredura é preciso saber *onde* e *com quais permissões* o
NetProbe está rodando. Este módulo levanta:

* sistema operacional, privilégios e driver de captura (Npcap, AF_PACKET, BPF);
* interfaces de rede (IPv4/prefixo, MAC, estado, física x virtual, Wi-Fi);
* gateways padrão (com MAC, via ARP), IP de saída e servidores DNS;
* capacidades efetivas: camada 2 (ARP/sniffing para colisão de IP), método ICMP
  (raw, camada 2, sem privilégio ou ``ping`` do sistema), TCP SYN e TCP connect;
* redes sugeridas para varredura, já filtradas (loopback, APIPA, virtuais,
  ponto-a-ponto, duplicadas) e limitadas em tamanho.

A fonte principal é o **Scapy** (``conf.ifaces``, ``conf.route``, sockets L2 e
``srp1``), que abstrai as diferenças entre Windows, Linux e macOS. Se o Scapy não
estiver instalado ou falhar, o módulo recorre ao ``psutil`` e a arquivos/comandos
do sistema (``route print``, ``/proc/net/route``, ``route -n get default``).

As funções de *parsing* e de decisão são puras (sem I/O) para serem testáveis
isoladamente; apenas :func:`discover_environment`, :func:`resolve_mac` e os
helpers ``_collect_*``/``_probe_*`` tocam o sistema.

Uso rápido::

    python -m core.environment            # relatório JSON do ambiente atual
"""

from __future__ import annotations

import ctypes
import errno
import glob
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field, fields, is_dataclass, replace
from functools import lru_cache
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Any, Iterable, List, Optional, Sequence, Set, Tuple

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

WINDOWS = "windows"
LINUX = "linux"
MACOS = "macos"
BSD = "bsd"
OTHER = "other"

ICMP_RAW = "raw"                    # socket raw do SO / Scapy L3
ICMP_LAYER2 = "layer2"              # Ether/IP/ICMP via driver de captura (Scapy srp)
ICMP_UNPRIVILEGED = "unprivileged"  # SOCK_DGRAM/ICMP (Linux/macOS) ou IcmpSendEcho (Windows)
ICMP_SYSTEM = "system"              # subprocesso do comando ``ping``

REASON_DEFAULT_ROUTE = "rota padrão"
REASON_PHYSICAL = "interface física"
REASON_VIRTUAL = "interface virtual"

#: Limite padrão de hosts por rede sugerida (equivale a uma /22).
DEFAULT_MAX_HOSTS = 1022

APIPA_NETWORK = IPv4Network("169.254.0.0/16")

#: Destino usado apenas para consultar a tabela de rotas (nenhum pacote é enviado).
OUTBOUND_PROBE_IP = "8.8.8.8"

_IPV4_RE = r"\d{1,3}(?:\.\d{1,3}){3}"

# Linux: bit de CAP_NET_RAW na máscara CapEff (include/uapi/linux/capability.h)
_CAP_NET_RAW_BIT = 13
# Linux: flags de /proc/net/route (include/uapi/linux/route.h)
_RTF_UP = 0x0001
_RTF_GATEWAY = 0x0002

# Nomes/descrições típicos de adaptadores virtuais, VPNs, contêineres e túneis.
_VIRTUAL_NAME_RE = re.compile(
    r"""
      virtual | vethernet | hyper-v | vmware | ^vmnet | vbox | parallels | qemu
    | docker | podman | containerd | ^veth | ^virbr | ^vnet\d | ^br- | ^cni
    | ^flannel | ^cali | ^kube | ^lxc | ^lxd | ^weave
    | ^tun | ^tap | ^utun | ^wg\d | wireguard | tailscale | zerotier | ^zt
    | vpn | (?:^|[^a-z])tap(?:[^a-z]|$) | miniport | pseudo | teredo | isatap
    | ^awdl | ^llw | ^anpi
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Prefixos de MAC (OUI) atribuídos a hipervisores e contêineres.
_VIRTUAL_MAC_PREFIXES = (
    "00:15:5d",  # Microsoft Hyper-V
    "00:03:ff",  # Microsoft Virtual PC
    "00:0c:29", "00:50:56", "00:05:69", "00:1c:14",  # VMware
    "08:00:27", "0a:00:27",  # VirtualBox
    "52:54:00",  # QEMU/KVM
    "00:16:3e",  # Xen
    "00:1c:42",  # Parallels
    "02:42:",    # Docker
)


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------

def _jsonable(value: Any) -> Any:
    """Converte dataclasses/endereços IP em estruturas serializáveis por ``json``."""
    if is_dataclass(value) and not isinstance(value, type):
        to_dict = getattr(value, "to_dict", None)
        if callable(to_dict):
            return to_dict()
        return {f.name: _jsonable(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, (IPv4Address, IPv4Network, IPv4Interface)):
        return str(value)
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    return value


def _fields_dict(obj: Any) -> dict:
    return {f.name: _jsonable(getattr(obj, f.name)) for f in fields(obj)}


@dataclass(frozen=True)
class InterfaceInfo:
    """Interface de rede local."""

    name: str
    mac: Optional[str]
    ipv4: Tuple[IPv4Interface, ...]
    is_up: bool
    is_loopback: bool = False
    is_virtual: bool = False
    is_wireless: bool = False
    description: Optional[str] = None
    #: Identificador aceito pelo Scapy (``\\Device\\NPF_{GUID}`` no Windows, ``eth0``...).
    device: Optional[str] = None
    index: Optional[int] = None

    @property
    def addresses(self) -> Tuple[IPv4Address, ...]:
        return tuple(i.ip for i in self.ipv4)

    @property
    def scapy_iface(self) -> str:
        """Valor a ser passado no parâmetro ``iface=`` das funções do Scapy."""
        return self.device or self.name

    @property
    def aliases(self) -> Set[str]:
        """Todos os nomes pelos quais a interface pode ser referenciada."""
        return {n for n in (self.name, self.device, self.description) if n}

    def has_address(self, ip: IPv4Address) -> bool:
        return any(i.ip == ip for i in self.ipv4)

    def to_dict(self) -> dict:
        return _fields_dict(self)


@dataclass(frozen=True)
class GatewayInfo:
    """Rota padrão (0.0.0.0/0)."""

    ip: IPv4Address
    interface: Optional[str] = None
    metric: Optional[int] = None
    #: IP local usado para alcançar o gateway (coluna "Interface" do ``route print``).
    source_ip: Optional[IPv4Address] = None
    mac: Optional[str] = None

    def to_dict(self) -> dict:
        return _fields_dict(self)


@dataclass(frozen=True)
class PacketCaptureInfo:
    """Driver de captura/injeção de pacotes em camada 2."""

    available: bool
    driver: Optional[str]
    requires_admin: bool = True
    version: Optional[str] = None
    #: Resultado de abrir um socket L2 de verdade (``None`` = não testado/inconclusivo).
    can_open: Optional[bool] = None

    def to_dict(self) -> dict:
        return _fields_dict(self)


@dataclass(frozen=True)
class Capabilities:
    """O que o NetProbe consegue fazer com os privilégios atuais."""

    is_admin: bool
    cap_net_raw: bool
    raw_socket: bool
    unprivileged_icmp: bool
    packet_capture: PacketCaptureInfo
    ping_command: Optional[str]
    #: Envio/captura em camada 2: varredura ARP e detecção passiva de colisão de IP.
    layer2: bool
    #: Um de ``ICMP_RAW``, ``ICMP_LAYER2``, ``ICMP_UNPRIVILEGED``, ``ICMP_SYSTEM`` ou ``None``.
    icmp_method: Optional[str]
    icmp_scan: bool
    tcp_syn: bool
    tcp_connect: bool = True

    @property
    def arp_scan(self) -> bool:
        return self.layer2

    def to_dict(self) -> dict:
        data = _fields_dict(self)
        data["arp_scan"] = self.arp_scan
        return data


@dataclass(frozen=True)
class ScanTarget:
    """Rede sugerida para varredura."""

    network: IPv4Network
    interface: str
    local_ip: IPv4Address
    reason: str
    #: Rede original quando ``network`` foi reduzida por exceder ``max_hosts``.
    truncated_from: Optional[IPv4Network] = None
    device: Optional[str] = None
    is_virtual: bool = False

    @property
    def num_hosts(self) -> int:
        return network_host_count(self.network)

    def to_dict(self) -> dict:
        data = _fields_dict(self)
        data["num_hosts"] = self.num_hosts
        return data


@dataclass(frozen=True)
class EnvironmentInfo:
    """Resultado completo de :func:`discover_environment`."""

    os_family: str
    os_version: str
    hostname: str
    python_version: str
    scapy_version: Optional[str]
    interfaces: Tuple[InterfaceInfo, ...]
    primary_interface: Optional[InterfaceInfo]
    gateways: Tuple[GatewayInfo, ...]
    outbound_ip: Optional[IPv4Address]
    dns_servers: Tuple[IPv4Address, ...]
    capabilities: Capabilities
    scan_targets: Tuple[ScanTarget, ...]
    warnings: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def default_gateway(self) -> Optional[GatewayInfo]:
        """Gateway da interface principal (ou o de menor métrica)."""
        if self.primary_interface is not None:
            for gw in self.gateways:
                if gateway_matches_interface(gw, self.primary_interface):
                    return gw
        return self.gateways[0] if self.gateways else None

    @property
    def local_addresses(self) -> Set[IPv4Address]:
        return {ip for iface in self.interfaces for ip in iface.addresses}

    def is_local(self, ip: Any) -> bool:
        """Indica se ``ip`` pertence a alguma interface desta máquina."""
        try:
            ip = IPv4Address(str(ip))
        except ValueError:
            return False
        return ip in self.local_addresses

    def to_dict(self) -> dict:
        data = _fields_dict(self)
        data["default_gateway"] = _jsonable(self.default_gateway)
        return data


# ---------------------------------------------------------------------------
# Utilitários puros
# ---------------------------------------------------------------------------

def current_os_family() -> str:
    plat = sys.platform
    if plat.startswith("win"):
        return WINDOWS
    if plat.startswith("linux"):
        return LINUX
    if plat == "darwin":
        return MACOS
    if "bsd" in plat or plat.startswith("dragonfly"):
        return BSD
    return OTHER


def normalize_mac(value: Optional[str]) -> Optional[str]:
    """Normaliza um MAC para ``aa:bb:cc:dd:ee:ff``.

    Retorna ``None`` para valores vazios, inválidos, todo-zero/broadcast ou com
    tamanho diferente de 6 octetos (ex.: os MACs de 8 bytes de adaptadores de
    túnel do Windows).
    """
    if not value:
        return None
    text = str(value).strip()
    if not re.fullmatch(r"[0-9A-Fa-f:.\-]+", text):
        return None
    parts = re.split(r"[:\-]", text)
    if len(parts) == 6 and all(1 <= len(p) <= 2 for p in parts):
        digits = "".join(p.zfill(2) for p in parts)  # aceita "0:1c:2:..." (macOS)
    else:
        digits = re.sub(r"[:.\-]", "", text)
    if len(digits) != 12 or digits.lower() in ("000000000000", "ffffffffffff"):
        return None
    digits = digits.lower()
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def is_virtual_interface(name: Optional[str], mac: Optional[str],
                         description: Optional[str] = None) -> bool:
    """Heurística por nome/descrição e OUI do MAC para adaptadores virtuais."""
    for text in (name, description):
        if text and _VIRTUAL_NAME_RE.search(text):
            return True
    norm = normalize_mac(mac)
    return bool(norm and norm.startswith(_VIRTUAL_MAC_PREFIXES))


def network_host_count(network: IPv4Network) -> int:
    """Quantidade de endereços de host utilizáveis (RFC 3021 para /31)."""
    if network.prefixlen >= 31:
        return network.num_addresses
    return network.num_addresses - 2


def parse_ip_list(text: Optional[str]) -> List[IPv4Address]:
    """Extrai IPv4s de uma string separada por espaço/vírgula (ignora 0.0.0.0)."""
    result: List[IPv4Address] = []
    for token in re.split(r"[\s,;]+", text or ""):
        try:
            ip = IPv4Address(token)
        except ValueError:
            continue
        if not ip.is_unspecified and ip not in result:
            result.append(ip)
    return result


def _dedupe(items: Iterable[Any]) -> list:
    seen: list = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def _gateway_sort_key(gw: GatewayInfo) -> Tuple[bool, int]:
    return (gw.metric is None, gw.metric if gw.metric is not None else 0)


def sort_gateways(gateways: Iterable[GatewayInfo]) -> List[GatewayInfo]:
    """Ordena por métrica (menor primeiro) e remove duplicatas."""
    return sorted(_dedupe(gateways), key=_gateway_sort_key)


# --- Parsing de tabelas de rota ---------------------------------------------

_WIN_DEFAULT_ROUTE_RE = re.compile(
    rf"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+({_IPV4_RE})\s+({_IPV4_RE})\s+(\d+)\s*$",
    re.MULTILINE,
)


def parse_windows_route_print(text: str) -> List[GatewayInfo]:
    """Gateways padrão a partir da saída de ``route print`` (qualquer idioma).

    Só as linhas de "Rotas ativas" possuem 5 colunas numéricas; as rotas
    persistentes (4 colunas) e as rotas "On-link"/"No vínculo" são ignoradas.
    """
    gateways = []
    for gw, src, metric in _WIN_DEFAULT_ROUTE_RE.findall(text or ""):
        try:
            gateways.append(GatewayInfo(IPv4Address(gw), metric=int(metric),
                                        source_ip=IPv4Address(src)))
        except ValueError:
            continue
    return sort_gateways(gateways)


def _hex_le_to_ip(value: str) -> IPv4Address:
    return IPv4Address(int.from_bytes(bytes.fromhex(value), "little"))


def parse_proc_net_route(text: str) -> List[GatewayInfo]:
    """Gateways padrão a partir de ``/proc/net/route`` (Linux)."""
    gateways = []
    for line in (text or "").splitlines():
        cols = line.split()
        if len(cols) < 8 or cols[0] == "Iface":
            continue
        try:
            dest, gw = _hex_le_to_ip(cols[1]), _hex_le_to_ip(cols[2])
            flags, metric = int(cols[3], 16), int(cols[6])
            mask = _hex_le_to_ip(cols[7])
        except ValueError:
            continue
        if int(dest) or int(mask) or not (flags & _RTF_UP and flags & _RTF_GATEWAY):
            continue
        gateways.append(GatewayInfo(gw, cols[0], metric))
    return sort_gateways(gateways)


def parse_bsd_route_get(text: str) -> List[GatewayInfo]:
    """Gateway a partir de ``route -n get default`` (macOS/BSD)."""
    gw_match = re.search(r"^\s*gateway:\s*(\S+)", text or "", re.MULTILINE)
    if not gw_match:
        return []
    try:
        ip = IPv4Address(gw_match.group(1))
    except ValueError:  # ex.: "link#5" em rotas diretas
        return []
    if_match = re.search(r"^\s*interface:\s*(\S+)", text, re.MULTILINE)
    return [GatewayInfo(ip, if_match.group(1) if if_match else None)]


def gateway_matches_interface(gw: GatewayInfo, iface: InterfaceInfo) -> bool:
    """Indica se o gateway é alcançado pela interface.

    A informação mais específica disponível decide: nome da interface, depois IP
    de origem e, por último, se o gateway está dentro de alguma sub-rede dela.
    """
    if gw.interface is not None:
        return gw.interface in iface.aliases or (
            gw.source_ip is not None and iface.has_address(gw.source_ip))
    if gw.source_ip is not None:
        return iface.has_address(gw.source_ip)
    return any(gw.ip in addr.network for addr in iface.ipv4)


# --- DNS ---------------------------------------------------------------------

def parse_resolv_conf(text: str) -> List[IPv4Address]:
    """Servidores DNS IPv4 de um ``resolv.conf`` (sem duplicatas, na ordem)."""
    servers: List[IPv4Address] = []
    for raw in (text or "").splitlines():
        parts = re.split(r"[#;]", raw, maxsplit=1)[0].split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            try:
                ip = IPv4Address(parts[1])
            except ValueError:
                continue
            if ip not in servers:
                servers.append(ip)
    return servers


def select_windows_dns(
    entries: Iterable[Tuple[Set[IPv4Address], Sequence[IPv4Address]]],
    active_ips: Iterable[IPv4Address],
    primary_ip: Optional[IPv4Address] = None,
) -> List[IPv4Address]:
    """Escolhe os DNS a partir das entradas por adaptador do registro do Windows.

    ``entries`` contém ``(IPs do adaptador, DNS do adaptador)``. O registro guarda
    valores de adaptadores desconectados (VPNs, por exemplo), então só entram os
    adaptadores com algum IP ativo; os do adaptador principal vêm primeiro.
    """
    active = set(active_ips)
    primary: List[IPv4Address] = []
    others: List[IPv4Address] = []
    for ips, servers in entries:
        ips = set(ips)
        if not ips & active:
            continue
        bucket = primary if primary_ip is not None and primary_ip in ips else others
        bucket.extend(servers)
    return _dedupe(primary + others)


# --- Capacidades ---------------------------------------------------------------

def parse_cap_net_raw(status_text: str) -> bool:
    """Lê ``CapEff`` de ``/proc/<pid>/status`` e testa ``CAP_NET_RAW``."""
    match = re.search(r"^CapEff:\s*([0-9a-fA-F]+)", status_text or "", re.MULTILINE)
    if not match:
        return False
    return bool((int(match.group(1), 16) >> _CAP_NET_RAW_BIT) & 1)


def derive_capabilities(
    *,
    is_admin: bool,
    cap_net_raw: bool,
    raw_socket: bool,
    unprivileged_icmp: bool,
    packet_capture: PacketCaptureInfo,
    ping_command: Optional[str],
    scapy_available: bool = True,
) -> Capabilities:
    """Combina privilégios e recursos detectados em capacidades efetivas."""
    layer2 = False
    if scapy_available and packet_capture.available:
        if packet_capture.can_open is not None:
            layer2 = packet_capture.can_open
        else:
            layer2 = not packet_capture.requires_admin or is_admin or cap_net_raw

    raw = raw_socket and scapy_available
    if raw:
        icmp_method: Optional[str] = ICMP_RAW
    elif layer2:
        icmp_method = ICMP_LAYER2
    elif unprivileged_icmp:
        icmp_method = ICMP_UNPRIVILEGED
    elif ping_command:
        icmp_method = ICMP_SYSTEM
    else:
        icmp_method = None

    return Capabilities(
        is_admin=is_admin,
        cap_net_raw=cap_net_raw,
        raw_socket=raw_socket,
        unprivileged_icmp=unprivileged_icmp,
        packet_capture=packet_capture,
        ping_command=ping_command,
        layer2=layer2,
        icmp_method=icmp_method,
        icmp_scan=icmp_method is not None,
        tcp_syn=raw or layer2,
        tcp_connect=True,
    )


def capability_warnings(caps: Capabilities, os_family: str,
                        scapy_available: bool = True) -> List[str]:
    """Avisos acionáveis sobre recursos indisponíveis.

    Com ``scapy_available=False`` a falta de camada 2 é consequência da ausência do
    Scapy (avisada à parte), não do driver ou de privilégios.
    """
    warnings: List[str] = []
    pc = caps.packet_capture
    if not scapy_available:
        pass
    elif not pc.available:
        if os_family == WINDOWS:
            warnings.append(
                "Npcap não encontrado: varredura ARP e detecção de colisão de IP "
                "indisponíveis. Instale-o em https://npcap.com (marque o modo "
                "compatível com a API WinPcap).")
        elif os_family in (MACOS, BSD):
            warnings.append(
                "Dispositivos /dev/bpf* não encontrados: varredura ARP e detecção "
                "de colisão de IP indisponíveis.")
        else:
            warnings.append(
                "Captura de pacotes em camada 2 indisponível neste sistema: "
                "varredura ARP e detecção de colisão de IP desativadas.")
    elif not caps.layer2:
        if os_family == WINDOWS:
            warnings.append(
                "O Npcap está restrito a administradores: execute o NetProbe em um "
                "terminal elevado para habilitar ARP e detecção de colisão de IP.")
        elif os_family == LINUX:
            warnings.append(
                "Sem root/CAP_NET_RAW: varredura ARP e detecção de colisão de IP "
                "indisponíveis. Execute com sudo ou conceda a capacidade ao "
                "interpretador: sudo setcap cap_net_raw,cap_net_admin+eip "
                "$(readlink -f $(which python3)).")
        else:
            warnings.append(
                "Sem acesso a /dev/bpf*: execute com sudo (ou instale o ChmodBPF) "
                "para habilitar ARP e detecção de colisão de IP.")

    if caps.icmp_method is None:
        warnings.append(
            "Nenhum método ICMP disponível (sem socket raw nem comando ping): "
            "apenas a sondagem TCP connect será usada.")
    elif caps.icmp_method == ICMP_SYSTEM:
        warnings.append(
            "ICMP será feito pelo comando ping do sistema, o que é mais lento; "
            "execute com privilégios elevados para usar o Scapy.")
    return warnings


# --- Interface principal e alvos de varredura -----------------------------------

def _is_candidate(iface: InterfaceInfo) -> bool:
    return (iface.is_up and not iface.is_loopback
            and any(not a.ip.is_loopback for a in iface.ipv4))


def _only_apipa(iface: InterfaceInfo) -> bool:
    return all(a.ip in APIPA_NETWORK for a in iface.ipv4)


def select_primary_interface(
    interfaces: Sequence[InterfaceInfo],
    gateways: Sequence[GatewayInfo],
    outbound_ip: Optional[IPv4Address] = None,
) -> Optional[InterfaceInfo]:
    """Escolhe a interface de saída padrão entre as interfaces ativas.

    Ordem: gateway de menor métrica que pertença a uma interface ativa → interface
    que possui o IP de saída → primeira interface física com IP utilizável.
    """
    candidates = [i for i in interfaces if _is_candidate(i)]
    if not candidates:
        return None

    for gw in sort_gateways(gateways):
        matches = [c for c in candidates if gateway_matches_interface(gw, c)]
        if not matches:
            continue
        if outbound_ip is not None:
            for c in matches:
                if c.has_address(outbound_ip):
                    return c
        return sorted(matches, key=lambda i: i.is_virtual)[0]

    if outbound_ip is not None:
        for c in candidates:
            if c.has_address(outbound_ip):
                return c

    return sorted(candidates, key=lambda i: (i.is_virtual, _only_apipa(i)))[0]


def _limit_network(addr: IPv4Interface, max_hosts: int
                   ) -> Tuple[IPv4Network, Optional[IPv4Network]]:
    """Reduz a rede para o maior bloco com até ``max_hosts`` que contém o IP local."""
    network = addr.network
    if network_host_count(network) <= max_hosts:
        return network, None
    for prefix in range(network.prefixlen + 1, 31):
        candidate = IPv4Interface((addr.ip, prefix)).network
        if network_host_count(candidate) <= max_hosts:
            return candidate, network
    return IPv4Interface((addr.ip, 30)).network, network


def suggest_scan_targets(
    interfaces: Sequence[InterfaceInfo],
    primary: Optional[InterfaceInfo],
    *,
    max_hosts: int = DEFAULT_MAX_HOSTS,
    include_virtual: bool = False,
) -> Tuple[List[ScanTarget], List[str]]:
    """Sugere as redes a varrer, com a interface principal primeiro.

    Ignora interfaces inativas/loopback, endereços APIPA, enlaces ponto-a-ponto
    (/31, /32), redes já cobertas por outra interface e — exceto se for a
    principal ou ``include_virtual=True`` — interfaces virtuais.
    """
    targets: List[ScanTarget] = []
    warnings: List[str] = []
    skipped_virtual: List[str] = []

    ordered = list(interfaces)
    if primary is not None:
        ordered = [primary] + [i for i in ordered if i.name != primary.name]

    for iface in ordered:
        is_primary = primary is not None and iface.name == primary.name
        if not iface.is_up or iface.is_loopback:
            continue
        if iface.is_virtual and not is_primary and not include_virtual:
            if iface.ipv4:
                skipped_virtual.append(iface.name)
            continue

        if is_primary:
            reason = REASON_DEFAULT_ROUTE
        elif iface.is_virtual:
            reason = REASON_VIRTUAL
        else:
            reason = REASON_PHYSICAL

        for addr in iface.ipv4:
            ip = addr.ip
            if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
                continue
            if ip in APIPA_NETWORK:
                warnings.append(
                    f"{iface.name}: endereço APIPA {ip} (o DHCP provavelmente não "
                    "respondeu); interface ignorada.")
                continue
            if addr.network.prefixlen >= 31:  # ponto-a-ponto (PPP, VPN, CGNAT)
                continue

            network, truncated = _limit_network(addr, max_hosts)
            overlap = next((t for t in targets if t.network.overlaps(network)), None)
            if overlap is not None:
                warnings.append(
                    f"{iface.name}: rede {network} já coberta pela interface "
                    f"{overlap.interface}; ignorada.")
                continue

            if truncated is not None:
                warnings.append(
                    f"{iface.name}: a rede {truncated} tem "
                    f"{network_host_count(truncated)} hosts; varredura limitada a "
                    f"{network} ({network_host_count(network)} hosts) ao redor de "
                    f"{ip}. Aumente max_hosts para ampliar.")
            if not network.is_private:
                warnings.append(
                    f"{iface.name}: a rede {network} não é privada; confirme que "
                    "você tem autorização antes de varrê-la.")

            targets.append(ScanTarget(
                network=network,
                interface=iface.name,
                local_ip=ip,
                reason=reason,
                truncated_from=truncated,
                device=iface.device,
                is_virtual=iface.is_virtual,
            ))

    if not targets:
        if skipped_virtual:
            warnings.append(
                "Nenhuma interface física com rede IPv4 utilizável; interfaces "
                f"virtuais ignoradas: {', '.join(skipped_virtual)}. Use "
                "include_virtual=True para incluí-las.")
        else:
            warnings.append("Nenhuma rede IPv4 local utilizável para varredura.")
    return targets, warnings


# ---------------------------------------------------------------------------
# Coleta no sistema (Scapy e fallbacks)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _load_scapy() -> Any:
    """Importa o Scapy sob demanda e devolve ``scapy.config.conf`` (ou ``None``).

    O import leva alguns segundos e emite avisos próprios (ex.: libpcap ausente),
    que são silenciados aqui porque o módulo gera os seus próprios avisos.
    """
    logger = logging.getLogger("scapy.runtime")
    previous = logger.level
    logger.setLevel(logging.ERROR)
    try:
        from scapy.all import conf  # noqa: WPS433 - import tardio intencional
    except Exception as exc:  # ImportError, OSError de libpcap quebrada etc.
        _log.debug("Scapy indisponível: %s", exc)
        return None
    finally:
        logger.setLevel(previous)
    return conf


def _scapy_version() -> Optional[str]:
    try:
        import scapy
        return str(scapy.VERSION)
    except Exception:
        return None


def _run(cmd: Sequence[str], timeout: float = 10.0) -> str:
    kwargs: dict = {}
    if current_os_family() == WINDOWS:
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        kwargs["encoding"] = "oem"
    try:
        completed = subprocess.run(
            list(cmd), capture_output=True, text=True, errors="replace",
            timeout=timeout, check=False, **kwargs)
    except (OSError, subprocess.SubprocessError, LookupError) as exc:
        _log.debug("Falha ao executar %s: %s", cmd, exc)
        return ""
    return completed.stdout or ""


def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _scapy_routes(conf: Any) -> list:
    try:
        return [r for r in conf.route.routes if len(r) >= 6]
    except Exception:
        return []


def _scapy_iface_name(conf: Any, dev: Any) -> Optional[str]:
    if dev is None:
        return None
    if not isinstance(dev, str):
        return getattr(dev, "name", None) or str(dev)
    try:
        return conf.ifaces.dev_from_networkname(dev).name
    except Exception:
        return dev


def _prefix_from_routes(ip: IPv4Address, device: Optional[str], routes: list
                        ) -> Optional[int]:
    """Prefixo da sub-rede conectada (rota sem gateway) que contém ``ip``."""
    best: Optional[int] = None
    ip_int = int(ip)
    for net, mask, gw, dev, out_ip, _metric in routes:
        prefix = bin(mask).count("1")
        if not 0 < prefix < 32 or gw not in ("0.0.0.0", "", None):
            continue
        if ip_int & mask != net:
            continue
        if out_ip != str(ip) and (device is None or dev != device):
            continue
        if best is None or prefix > best:
            best = prefix
    return best


def _psutil_netmasks() -> dict:
    """Mapa ``IPv4Address -> prefixo`` segundo o psutil (se instalado)."""
    try:
        import psutil
    except ImportError:
        return {}
    result = {}
    try:
        for entries in psutil.net_if_addrs().values():
            for a in entries:
                if a.family == socket.AF_INET and a.netmask:
                    try:
                        iface = IPv4Interface(f"{a.address}/{a.netmask}")
                    except ValueError:
                        continue
                    result[iface.ip] = iface.network.prefixlen
    except Exception as exc:
        _log.debug("psutil.net_if_addrs falhou: %s", exc)
    return result


def _is_wireless(name: str, description: Optional[str], flags: Set[str]) -> bool:
    if "WIRELESS" in flags:
        return True
    text = f"{name} {description or ''}".lower()
    return bool(re.search(r"^wl|wi-?fi|wireless|802\.11|wlan", text))


def _collect_interfaces_scapy(conf: Any) -> List[InterfaceInfo]:
    routes = _scapy_routes(conf)
    netmasks = _psutil_netmasks()
    result: List[InterfaceInfo] = []
    for dev in list(conf.ifaces.values()):
        name = getattr(dev, "name", None) or getattr(dev, "network_name", None)
        if not name:
            continue
        device = getattr(dev, "network_name", None) or name
        description = getattr(dev, "description", None)
        if description == name:
            description = None
        mac = normalize_mac(getattr(dev, "mac", None))

        raw_flags = getattr(dev, "flags", None)
        flag_names = {f for f in str(raw_flags).split("+") if f.isalpha()} if raw_flags else set()

        ips_by_version = getattr(dev, "ips", None) or {}
        ip_texts = list(ips_by_version.get(4, [])) if ips_by_version else []
        if not ip_texts and getattr(dev, "ip", None):
            ip_texts = [dev.ip]

        ipv4: List[IPv4Interface] = []
        for text in ip_texts:
            try:
                ip = IPv4Address(text)
            except ValueError:
                continue
            if ip.is_unspecified:
                continue
            prefix = netmasks.get(ip) or _prefix_from_routes(ip, device, routes) or 32
            ipv4.append(IPv4Interface((ip, prefix)))

        is_loopback = "LOOPBACK" in flag_names or (
            bool(ipv4) and all(a.ip.is_loopback for a in ipv4))
        if flag_names:
            is_up = ("UP" in flag_names and "RUNNING" in flag_names
                     and (is_loopback or "DISCONNECTED" not in flag_names))
        else:
            is_up = bool(ipv4)

        result.append(InterfaceInfo(
            name=name,
            mac=mac,
            ipv4=tuple(ipv4),
            is_up=is_up,
            is_loopback=is_loopback,
            is_virtual=not is_loopback and is_virtual_interface(name, mac, description),
            is_wireless=_is_wireless(name, description, flag_names),
            description=description,
            device=device,
            index=getattr(dev, "index", None),
        ))
    return result


def _collect_interfaces_psutil() -> List[InterfaceInfo]:
    try:
        import psutil
    except ImportError:
        return []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except Exception as exc:
        _log.debug("psutil falhou: %s", exc)
        return []
    result = []
    for name, entries in addrs.items():
        mac = next((normalize_mac(a.address) for a in entries
                    if a.family == getattr(psutil, "AF_LINK", None)
                    and normalize_mac(a.address)), None)
        ipv4 = []
        for a in entries:
            if a.family != socket.AF_INET:
                continue
            try:
                ipv4.append(IPv4Interface(f"{a.address}/{a.netmask or '255.255.255.255'}"))
            except ValueError:
                continue
        st = stats.get(name)
        is_loopback = (bool(ipv4) and all(i.ip.is_loopback for i in ipv4)) or \
            "loopback" in name.lower() or name == "lo"
        result.append(InterfaceInfo(
            name=name,
            mac=mac,
            ipv4=tuple(ipv4),
            is_up=st.isup if st is not None else bool(ipv4),
            is_loopback=is_loopback,
            is_virtual=not is_loopback and is_virtual_interface(name, mac),
            is_wireless=_is_wireless(name, None, set()),
            device=name,
        ))
    return result


def _collect_gateways_scapy(conf: Any) -> List[GatewayInfo]:
    gateways = []
    for net, mask, gw, dev, out_ip, metric in _scapy_routes(conf):
        if net != 0 or mask != 0:
            continue
        try:
            ip = IPv4Address(gw)
        except ValueError:
            continue
        if ip.is_unspecified:
            continue
        try:
            src: Optional[IPv4Address] = IPv4Address(out_ip)
            if src.is_unspecified:
                src = None
        except ValueError:
            src = None
        try:
            metric_value: Optional[int] = int(metric)
        except (TypeError, ValueError):
            metric_value = None
        gateways.append(GatewayInfo(ip, _scapy_iface_name(conf, dev), metric_value, src))
    return sort_gateways(gateways)


def _collect_gateways_system(os_family: str) -> List[GatewayInfo]:
    if os_family == WINDOWS:
        return parse_windows_route_print(_run(["route", "print", "-4"]))
    if os_family == LINUX:
        return parse_proc_net_route(_read_text("/proc/net/route"))
    if os_family in (MACOS, BSD):
        return parse_bsd_route_get(_run(["route", "-n", "get", "default"]))
    return []


def _outbound_ip(conf: Any) -> Optional[IPv4Address]:
    """IP local que o SO usaria para sair à internet (sem enviar pacotes)."""
    if conf is not None:
        try:
            _dev, out_ip, _gw = conf.route.route(OUTBOUND_PROBE_IP)
            ip = IPv4Address(out_ip)
            if not ip.is_unspecified:
                return ip
        except Exception:
            pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((OUTBOUND_PROBE_IP, 53))  # UDP: só consulta a rota
            ip = IPv4Address(sock.getsockname()[0])
            return None if ip.is_unspecified else ip
    except (OSError, ValueError):
        return None


def _collect_dns_windows(interfaces: Sequence[InterfaceInfo],
                         primary: Optional[InterfaceInfo]) -> List[IPv4Address]:
    try:
        import winreg
    except ImportError:
        return []

    def value(key: Any, name: str) -> str:
        try:
            data, _type = winreg.QueryValueEx(key, name)
        except OSError:
            return ""
        return " ".join(data) if isinstance(data, (list, tuple)) else str(data or "")

    entries = []
    base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base + r"\Interfaces") as root:
            index = 0
            while True:
                try:
                    sub = winreg.EnumKey(root, index)
                except OSError:
                    break
                index += 1
                try:
                    with winreg.OpenKey(root, sub) as key:
                        ips = set(parse_ip_list(value(key, "IPAddress"))) | \
                            set(parse_ip_list(value(key, "DhcpIPAddress")))
                        servers = parse_ip_list(value(key, "NameServer")) or \
                            parse_ip_list(value(key, "DhcpNameServer"))
                except OSError:
                    continue
                entries.append((ips, servers))
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as key:
            global_servers = parse_ip_list(value(key, "NameServer"))
    except OSError as exc:
        _log.debug("Falha ao ler DNS do registro: %s", exc)
        return []

    active = {ip for i in interfaces if i.is_up for ip in i.addresses}
    primary_ip = primary.addresses[0] if primary and primary.addresses else None
    return _dedupe(select_windows_dns(entries, active, primary_ip) + global_servers)


def _collect_dns_posix() -> List[IPv4Address]:
    servers = parse_resolv_conf(_read_text("/etc/resolv.conf"))
    if servers and all(s.is_loopback for s in servers):
        # systemd-resolved (127.0.0.53): os servidores reais ficam em outro arquivo
        upstream = parse_resolv_conf(_read_text("/run/systemd/resolve/resolv.conf"))
        if upstream:
            return upstream
    return servers


def _probe_is_admin(os_family: str) -> bool:
    if os_family == WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def _probe_cap_net_raw(os_family: str) -> bool:
    if os_family != LINUX:
        return False
    return parse_cap_net_raw(_read_text("/proc/self/status"))


def _probe_raw_socket() -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except (OSError, AttributeError):
        return False
    sock.close()
    return True


def _probe_unprivileged_icmp(os_family: str) -> bool:
    if os_family == WINDOWS:
        # IcmpSendEcho (iphlpapi) dispensa privilégios no Windows.
        try:
            api = ctypes.windll.iphlpapi  # type: ignore[attr-defined]
            api.IcmpCreateFile.restype = ctypes.c_void_p
            api.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
            handle = api.IcmpCreateFile()
        except Exception:
            return False
        if handle in (None, ctypes.c_void_p(-1).value):
            return False
        api.IcmpCloseHandle(handle)
        return True
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except (OSError, AttributeError):  # Linux: fora de net.ipv4.ping_group_range
        return False
    sock.close()
    return True


def _npcap_admin_only() -> Optional[bool]:
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\npcap\Parameters") as key:
            data, _type = winreg.QueryValueEx(key, "AdminOnly")
            return bool(data)
    except (ImportError, OSError):
        return None


def _pcap_version() -> Optional[str]:
    try:
        from scapy.libs.winpcapy import pcap_lib_version
        raw = pcap_lib_version()
        return raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)
    except Exception:
        return None


def _probe_packet_capture(os_family: str, conf: Any) -> PacketCaptureInfo:
    """Detecta o driver de captura (sem ainda abrir um socket)."""
    if os_family == WINDOWS:
        if conf is not None:
            available = bool(getattr(conf, "use_pcap", False))
            is_npcap = bool(getattr(conf, "use_npcap", False))
            version = _pcap_version() if available else None
        else:
            system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
            is_npcap = os.path.exists(os.path.join(system32, "Npcap", "wpcap.dll"))
            available = is_npcap or os.path.exists(os.path.join(system32, "wpcap.dll"))
            version = None
        if not available:
            return PacketCaptureInfo(False, None, requires_admin=True)
        if is_npcap:
            return PacketCaptureInfo(True, "Npcap", requires_admin=bool(_npcap_admin_only()),
                                     version=version)
        return PacketCaptureInfo(True, "WinPcap", requires_admin=True, version=version)

    if os_family == LINUX:
        driver = "libpcap" if conf is not None and getattr(conf, "use_pcap", False) \
            else "AF_PACKET"
        return PacketCaptureInfo(hasattr(socket, "AF_PACKET") or driver == "libpcap",
                                 driver, requires_admin=True)

    if os_family in (MACOS, BSD):
        devices = sorted(glob.glob("/dev/bpf*"))
        if not devices:
            return PacketCaptureInfo(False, None, requires_admin=True)
        accessible = os.access(devices[0], os.R_OK | os.W_OK)
        return PacketCaptureInfo(True, "BPF", requires_admin=not accessible)

    return PacketCaptureInfo(False, None, requires_admin=True)


def _is_permission_error(exc: BaseException) -> bool:
    if isinstance(exc, PermissionError):
        return True
    if isinstance(exc, OSError) and exc.errno in (errno.EPERM, errno.EACCES):
        return True
    text = str(exc).lower()
    return any(k in text for k in ("permission", "denied", "privilege", "not permitted",
                                   "access is denied", "acesso negado"))


def _probe_layer2_socket(conf: Any, iface: InterfaceInfo) -> Optional[bool]:
    """Tenta abrir (e fechar) um socket L2 do Scapy na interface.

    Retorna ``False`` só para falhas de permissão; outros erros são inconclusivos.
    """
    try:
        sock = conf.L2socket(iface=iface.scapy_iface)
    except Exception as exc:
        _log.debug("Socket L2 em %s falhou: %s", iface.name, exc)
        return False if _is_permission_error(exc) else None
    try:
        sock.close()
    except Exception:
        pass
    return True


def resolve_mac(ip: Any, iface: Optional[str] = None, timeout: float = 1.0
                ) -> Optional[str]:
    """Resolve o MAC de ``ip`` com um ARP who-has via Scapy (requer camada 2)."""
    if _load_scapy() is None:
        return None
    try:
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp1
        reply = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(ip)),
                     iface=iface, timeout=timeout, verbose=0)
    except Exception as exc:
        _log.debug("ARP para %s falhou: %s", ip, exc)
        return None
    if reply is None or ARP not in reply:
        return None
    return normalize_mac(reply[ARP].hwsrc)


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

def discover_environment(
    *,
    max_hosts: int = DEFAULT_MAX_HOSTS,
    include_virtual: bool = False,
    resolve_gateway_mac: bool = True,
    use_scapy: bool = True,
) -> EnvironmentInfo:
    """Levanta o ambiente de rede local. Nunca lança exceção por falha de coleta.

    :param max_hosts: tamanho máximo de cada rede sugerida (redes maiores são
        reduzidas ao redor do IP local).
    :param include_virtual: incluir interfaces virtuais nas redes sugeridas.
    :param resolve_gateway_mac: enviar um ARP ao gateway principal para obter o
        MAC (só quando há acesso à camada 2). Útil como referência para detecção
        de colisão/ARP spoofing.
    :param use_scapy: permite forçar o modo sem Scapy (psutil/comandos do SO).
    """
    if max_hosts < 1:
        raise ValueError("max_hosts deve ser >= 1")

    os_family = current_os_family()
    warnings: List[str] = []
    conf = _load_scapy() if use_scapy else None
    if conf is None:
        warnings.append(
            "Scapy indisponível (pip install -r requirements.txt): usando psutil e "
            "comandos do sistema; varreduras ARP/SYN/ICMP raw desativadas.")

    interfaces: List[InterfaceInfo] = []
    if conf is not None:
        try:
            interfaces = _collect_interfaces_scapy(conf)
        except Exception as exc:
            _log.debug("Coleta de interfaces via Scapy falhou: %s", exc)
    if not interfaces:
        interfaces = _collect_interfaces_psutil()

    gateways: List[GatewayInfo] = []
    if conf is not None:
        try:
            gateways = _collect_gateways_scapy(conf)
        except Exception as exc:
            _log.debug("Coleta de gateways via Scapy falhou: %s", exc)
    if not gateways:
        gateways = _collect_gateways_system(os_family)

    outbound_ip = _outbound_ip(conf)
    primary = select_primary_interface(interfaces, gateways, outbound_ip)

    is_admin = _probe_is_admin(os_family)
    packet_capture = _probe_packet_capture(os_family, conf)
    if conf is not None and packet_capture.available and primary is not None:
        packet_capture = replace(packet_capture,
                                 can_open=_probe_layer2_socket(conf, primary))
    capabilities = derive_capabilities(
        is_admin=is_admin,
        cap_net_raw=_probe_cap_net_raw(os_family),
        raw_socket=_probe_raw_socket(),
        unprivileged_icmp=_probe_unprivileged_icmp(os_family),
        packet_capture=packet_capture,
        ping_command=shutil.which("ping"),
        scapy_available=conf is not None,
    )

    if resolve_gateway_mac and capabilities.layer2 and primary is not None:
        for i, gw in enumerate(gateways):
            if gateway_matches_interface(gw, primary) and \
                    any(gw.ip in a.network for a in primary.ipv4):
                gateways[i] = replace(gw, mac=resolve_mac(gw.ip, primary.scapy_iface))
                break

    try:
        if os_family == WINDOWS:
            dns_servers = _collect_dns_windows(interfaces, primary)
        else:
            dns_servers = _collect_dns_posix()
    except Exception as exc:
        _log.debug("Coleta de DNS falhou: %s", exc)
        dns_servers = []

    targets, target_warnings = suggest_scan_targets(
        interfaces, primary, max_hosts=max_hosts, include_virtual=include_virtual)
    warnings += capability_warnings(capabilities, os_family, conf is not None)
    warnings += target_warnings

    return EnvironmentInfo(
        os_family=os_family,
        os_version=platform.platform(),
        hostname=socket.gethostname(),
        python_version=platform.python_version(),
        scapy_version=_scapy_version() if conf is not None else None,
        interfaces=tuple(interfaces),
        primary_interface=primary,
        gateways=tuple(gateways),
        outbound_ip=outbound_ip,
        dns_servers=tuple(dns_servers),
        capabilities=capabilities,
        scan_targets=tuple(targets),
        warnings=tuple(_dedupe(warnings)),
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Descoberta do ambiente de rede do NetProbe")
    parser.add_argument("--max-hosts", type=int, default=DEFAULT_MAX_HOSTS)
    parser.add_argument("--include-virtual", action="store_true")
    parser.add_argument("--no-arp", action="store_true",
                        help="não enviar ARP para descobrir o MAC do gateway")
    parser.add_argument("--no-scapy", action="store_true")
    args = parser.parse_args(argv)

    info = discover_environment(
        max_hosts=args.max_hosts,
        include_virtual=args.include_virtual,
        resolve_gateway_mac=not args.no_arp,
        use_scapy=not args.no_scapy,
    )
    print(json.dumps(info.to_dict(), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
