import ipaddress
import json
import platform
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# Cores ANSI
red = "\033[91m"
cyan = "\033[96m"
yellow = "\033[93m"
green = "\033[92m"
purple = "\033[95m"
white = "\033[97m"
reset = "\033[0m"
bold = "\033[1m"

# Banner LC_KING
logo = f"""
{white}██╗      ██████╗    ██╗  ██╗██╗███╗   ██╗ ██████╗
{green}██║     ██╔════╝    ██║ ██╔╝██║████╗  ██║██╔════╝
{green}██║     ██║         █████╔╝ ██║██╔██╗ ██║██║  ███╗
{green}██║     ██║         ██╔═██╗ ██║██║╚██╗██║██║   ██║
{white}███████╗╚██████╗    ██║  ██╗██║██║ ╚████║╚██████╔╝
{white}╚══════╝ ╚═════╝    ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝
{white}{bold}     [ https://github.com/LC-KING-debug]{reset}
"""

# Cores ANSI (já definidas)
# ...

# Portas comuns → serviço
PORT_SERVICES = {
    20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
    135: "MSRPC", 137: "NetBIOS", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 162: "SNMP Trap",
    389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "Submission",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 4443: "Docker Registry",
    5000: "UPnP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP Proxy",
    8443: "HTTPS Alt", 9090: "Web Admin",
    27017: "MongoDB", 54321: "PostgreSQL Alt",
}

# Top 1000 portas (subset para velocidade)
COMMON_PORTS = list(PORT_SERVICES.keys())
# Adicionar mais portas comuns
COMMON_PORTS += [111, 135, 139, 389, 445, 512, 513, 514, 543, 587, 631, 636, 993, 995, 1080, 1433, 2049, 2375, 3306, 3389, 5432, 5900, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9090, 9200, 9300, 27017, 27018]
COMMON_PORTS = sorted(set(COMMON_PORTS))

def scan_port(ip, port, timeout=0.3):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
        return (port, result == 0)
    except OSError:
        return (port, False)

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "N/A"

def get_reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None

def get_ip_info(ip):
    info = {}
    info['ip'] = ip
    info['hostname'] = get_hostname(ip)
    info['reverse_dns'] = get_reverse_dns(ip)
    # Verificar se é IP privado
    try:
        addr = ipaddress.ip_address(ip)
        info['is_private'] = addr.is_private
        info['is_global'] = addr.is_global
        info['version'] = addr.version
        info['is_loopback'] = addr.is_loopback
        info['is_link_local'] = addr.is_link_local
        info['is_multicast'] = addr.is_multicast
        info['operating_system'] = platform.system() if addr.is_loopback else None
    except ValueError:
        return info
    # CIDR de rede
    try:
        if ipaddress.ip_address(ip).version == 4:
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
            info['subnet'] = str(network)
            info['broadcast'] = str(network.broadcast_address)
    except ValueError:
        pass
    return info

def get_service_name(port):
    if port in PORT_SERVICES:
        return PORT_SERVICES[port]
    try:
        return f"{socket.getservbyport(port, 'tcp')} (cadastro TCP)"
    except (OSError, OverflowError, ValueError):
        return "Sem serviço TCP cadastrado"

def scan_ports(ip, ports, workers=100, timeout=0.3):
    if not ports:
        raise ValueError("A lista de portas não pode estar vazia.")
    if not 1 <= workers <= 100:
        raise ValueError("O número de workers deve estar entre 1 e 100.")
    if timeout <= 0:
        raise ValueError("O timeout deve ser maior que zero.")

    open_ports = []
    start = time.time()
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            try:
                port, is_open = future.result()
            except (OSError, RuntimeError):
                continue
            if is_open:
                open_ports.append(port)
    
    open_ports.sort()
    elapsed = time.time() - start
    
    # Identificar todas as portas abertas, recorrendo ao cadastro TCP do sistema.
    services = [(port, get_service_name(port)) for port in open_ports]
    
    return open_ports, services, elapsed

def build_report(ip, ip_info, open_ports, services, elapsed, total_scanned, timestamp):
    service_by_port = dict(services)
    database_ports = [p for p, name in services if any(
        term in name.lower() for term in ("mysql", "postgres", "mongo", "redis", "mssql", "oracle")
    )]
    web_ports = [p for p, name in services if any(
        term in name.lower() for term in ("http", "https", "ftp")
    )]
    admin_ports = [p for p, name in services if any(
        term in name.lower() for term in ("ssh", "rdp", "vnc", "telnet")
    )]

    recommendation_by_port = {
        21: "FTP detectado: prefira SFTP ou FTPS.",
        22: "SSH aberto: prefira autenticação por chave e desative senhas fracas.",
        23: "Telnet detectado: substitua por SSH.",
        80: "HTTP aberto: verifique os headers de segurança.",
        443: "HTTPS aberto: verifique os headers de segurança.",
        3306: "MySQL exposto: restrinja o acesso à rede necessária.",
        3389: "RDP exposto: restrinja o acesso e habilite NLA e MFA.",
        445: "SMB exposto: aplique atualizações e restrinja o acesso à rede necessária.",
        6379: "Redis exposto: restrinja o acesso à rede interna.",
        27017: "MongoDB exposto: confirme que a autenticação está habilitada.",
    }
    recommendations = [recommendation_by_port[p] for p in open_ports if p in recommendation_by_port]
    exposed_admin = [p for p in open_ports if p in (22, 23, 2375, 3389, 5900, 8080, 8443, 9090)]
    if exposed_admin:
        recommendations.append(f"Revise as portas administrativas expostas: {exposed_admin}.")

    return {
        "schema_version": 1,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "display_timestamp": timestamp,
        "target": {
            "ip": ip,
            "hostname": ip_info.get("hostname"),
            "operating_system": ip_info.get("operating_system"),
        },
        "ip_info": ip_info,
        "scan": {
            "protocol": "TCP",
            "duration_seconds": round(elapsed, 3),
            "ports_scanned": total_scanned,
            "open_ports": len(open_ports),
            "closed_or_filtered_ports": total_scanned - len(open_ports),
        },
        "ports": [
            {"port": port, "protocol": "TCP", "service": service_by_port[port], "state": "open"}
            for port in open_ports
        ],
        "summary": {
            "web_ports": web_ports,
            "database_ports": database_ports,
            "admin_ports": admin_ports,
            "recommendations": recommendations,
        },
    }

def save_report(report, output_dir=None):
    reports_dir = Path(output_dir) if output_dir else Path(__file__).resolve().parent / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    target_ip = report["target"]["ip"].replace(":", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    path = reports_dir / f"scan_{timestamp}_{target_ip}.json"
    with path.open("x", encoding="utf-8") as report_file:
        json.dump(report, report_file, ensure_ascii=False, indent=2)
        report_file.write("\n")
    return path

def read_custom_ports():
    while True:
        port_str = input(f"{cyan}  [?] Digite as portas separadas por vírgula (ex: 80,443,8080):{reset} ")
        try:
            ports = [int(value.strip()) for value in port_str.split(",") if value.strip()]
            if not ports:
                raise ValueError("Informe ao menos uma porta.")
            if any(port < 1 or port > 65535 for port in ports):
                raise ValueError("As portas devem estar entre 1 e 65535.")
            return sorted(set(ports))
        except ValueError as error:
            print(f"{red}  [ERRO] Lista de portas inválida: {error}{reset}")

def print_section(title, color=cyan):
    line = "═" * 60
    print(f"\n{color}{line}{reset}")
    print(f"{color}  {title}{reset}")
    print(f"{color}{line}{reset}")

def print_report(ip, ip_info, open_ports, services, elapsed, total_scanned, timestamp):
    # Header
    print_section(f"RELATÓRIO DE ESCANEAMENTO — {ip}", bold)
    
    print(f"""
{white}  {'═' * 56}
  📋 DOCUMENTAÇÃO TÉCNICA DE REDE
  {'═' * 56}

  🔹 Data/Hora do Escaneamento : {timestamp}
  🔹 Alvo (IP)                : {ip}
  🔹 Tempo de Execução        : {elapsed:.2f}s
  🔹 Portas Escaneadas        : {total_scanned}
  🔹 Portas Abertas           : {len(open_ports)}
  🔹 Portas Fechadas/Filtradas: {total_scanned - len(open_ports)}
{'═' * 56}""")
    
    # Informações do IP
    print_section("INFORMAÇÕES DO ENDEREÇO IP")
    print(f"""
  🔹 Versão do IP          : IPv{ip_info.get('version', '?')}
  🔹 Hostname (Reverse DNS): {ip_info.get('hostname', 'N/A')}
    🔹 Sistema Operacional   : {ip_info.get('operating_system') or 'Não identificado'}
  🔹 Tipo de Endereçamento : {'Privado (RFC 1918)' if ip_info.get('is_private') else 'Público/Global' if ip_info.get('is_global') else 'Loopback' if ip_info.get('is_loopback') else 'Link-Local' if ip_info.get('is_link_local') else 'Outro'}
  🔹 Subnet /24            : {ip_info.get('subnet', 'N/A')}
  🔹 Endereço Broadcast    : {ip_info.get('broadcast', 'N/A')}
""")
    
    # Portas Abertas
    if open_ports:
        print_section("PORTAS ABERTAS & SERVIÇOS IDENTIFICADOS", green)
        print(f"""
  {'PORTA':<10}{'PROTOCOLO':<14}{'SERVIÇO':<22}{'ESTADO'}
  {'─' * 56}""")
        for port, service in services:
            proto = "TCP"
            print(f"  {green}{str(port):<10}{reset}{proto:<14}{service:<22}{green}[ABERTA]{reset}")
    else:
        print_section("PORTAS ABERTAS & SERVIÇOS IDENTIFICADOS", yellow)
        print(f"\n  {yellow}Nenhuma porta aberta identificada no escaneamento.{reset}\n")
    
    # Resumo
    print_section("RESUMO EXECUTIVO", purple)
    if open_ports:
        db_ports = [p for p, s in services if any(k in s.lower() for k in ['mysql', 'postgres', 'mongo', 'redis', 'mssql', 'oracle'])]
        web_ports = [p for p, s in services if any(k in s.lower() for k in ['http', 'https', 'ftp'])]
        admin_ports = [p for p, s in services if any(k in s.lower() for k in ['ssh', 'rdp', 'vnc', 'telnet'])]
        
        print(f"""
  🔹 Serviços Web/HTTP   : {web_ports if web_ports else 'Nenhum'}
  🔹 Bancos de Dados     : {db_ports if db_ports else 'Nenhum'}
  🔹 Acesso Remoto/Admin : {admin_ports if admin_ports else 'Nenhum'}
  
  ⚠️  {bold}Recomendações:{reset}
""")
        if 22 in open_ports:
            print(f"     • SSH aberto — Verifique se autenticação por chave está habilitada e senha fraca descartada.")
        if 80 in open_ports or 443 in open_ports:
            print(f"     • HTTP(S) aberto — Verifique headers de segurança (HSTS, CSP, X-Frame-Options).")
        if 3306 in open_ports:
            print(f"     • MySQL exposto — Restrinja acesso ao VPC/subnet interna.")
        if 3389 in open_ports:
            print(f"     • RDP exposto — Alto risco de força bruta. Use NLA + MFA.")
        if 23 in open_ports:
            print(f"     • Telnet (clara) detectado — Substitua por SSH.")
        if 21 in open_ports:
            print(f"     • FTP (clara) detectado — Migre para SFTP/FTPS.")
        if 445 in open_ports:
            print(f"     • SMB exposto — Risco de EternalBlue. Aplique patches e restrinja rede.")
        if 6379 in open_ports:
            print(f"     • Redis exposto — Risco de escrita arbitrária. Restrinja a rede interna.")
        if 27017 in open_ports:
            print(f"     • MongoDB exposto — Risco de acesso não autorizado. Aplique autenticação.")
        
        # Verificar portas de administração expostas
        exposed_admin = [p for p in open_ports if p in [22, 3389, 5900, 23, 8080, 9090, 8443, 2375]]
        if exposed_admin:
            print(f"\n     • {bold}Portas administrativas expostas:{reset} {exposed_admin}")
    else:
        print(f"""
  🔹 Nenhuma porta aberta identificada.
  🔹 O host pode estar protegido por firewall restritivo.
  🔹 Considere escaneamento com mais portas e protocolos (UDP).
""")
    
    print(f"\n{'═' * 60}")
    print(f"{white}{bold}  FIM DO RELATÓRIO — Gerado por LC_KING Port Scanner{reset}")
    print(f"{'═' * 60}\n")

def scan_once():
    # Input do IP
    print(f"\n{cyan}  [?] Digite o IP ou hostname para escanear (Enter para 127.0.0.1):{reset} ", end="")
    try:
        target = input(f"{white}> {reset}").strip() or "127.0.0.1"
    except (EOFError, KeyboardInterrupt):
        print(f"\n{yellow}  [INFO] Operação cancelada.{reset}")
        return

    if len(target) > 253:
        print(f"\n{red}  [ERRO] O IP/hostname excede o tamanho permitido.{reset}\n")
        return
    
    # Resolver hostname se necessário
    try:
        ip = socket.gethostbyname(target)
    except (socket.gaierror, UnicodeError, OSError):
        print(f"\n{red}  [ERRO] Não foi possível resolver '{target}'.{reset}\n")
        return
    
    # Opção de scan
    print(f"\n{cyan}  [?] Tipo de escaneamento:{reset}")
    print(f"  {green}1{reset}) Portas comuns (~{len(COMMON_PORTS)} portas) — Rápido")
    print(f"  {yellow}2{reset}) Top 1000 portas — Médio")
    print(f"  {purple}3{reset}) Todas as 65535 portas — Completo")
    print(f"  {cyan}4{reset}) Lista customizada de portas", end="")
    try:
        choice = input(f"\n{white}  > {reset}").strip() or "1"
    except (EOFError, KeyboardInterrupt):
        print(f"\n{yellow}  [INFO] Operação cancelada.{reset}")
        return
    
    if choice == "1":
        ports = COMMON_PORTS
    elif choice == "2":
        ports = list(range(1, 1001))
    elif choice == "3":
        ports = list(range(1, 65536))
    elif choice == "4":
        try:
            ports = read_custom_ports()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{yellow}  [INFO] Operação cancelada.{reset}")
            return
    else:
        print(f"{yellow}  [AVISO] Opção inválida. Usando portas comuns.{reset}")
        ports = COMMON_PORTS
    
    # Obter informações do IP
    print(f"\n{cyan}  [→] Coletando informações do IP {ip}...{reset}")
    ip_info = get_ip_info(ip)
    
    # Scan
    total_ports = len(ports)
    print(f"{cyan}  [→] Escaneando {total_ports} portas em {ip}...{reset}")
    print(f"      (usando até 100 threads simultâneas, timeout 0.3s){reset}")

    try:
        open_ports, services, elapsed = scan_ports(ip, ports, workers=100, timeout=0.3)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"{red}  [ERRO] Não foi possível concluir o escaneamento: {error}{reset}")
        return
    
    # Relatório
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    print_report(ip, ip_info, open_ports, services, elapsed, total_ports, timestamp)

    report = build_report(ip, ip_info, open_ports, services, elapsed, total_ports, timestamp)
    try:
        report_path = save_report(report)
    except (OSError, TypeError, ValueError) as error:
        print(f"{red}  [ERRO] Relatório exibido, mas não foi possível salvar o JSON: {error}{reset}")
    else:
        print(f"{green}  [OK] Relatório JSON salvo em: {report_path}{reset}")

def main():
    print(logo)
    while True:
        scan_once()
        try:
            answer = input(f"\n{cyan}  [?] Deseja escanear outro IP? (s/N): {reset}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{yellow}  [INFO] Encerrando o programa.{reset}")
            break
        if answer not in ("s", "sim"):
            print(f"{cyan}  [INFO] Programa encerrado.{reset}")
            break

if __name__ == "__main__":
    main()
