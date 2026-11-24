# Arquivo: core/extractor.py
import csv
import io
import ipaddress
import os
import re

# Lista de extensões de ficheiros comuns que o Regex não deve tratar como domínios
FILE_EXTENSIONS_BLACKLIST = {
    'exe', 'bin', 'dll', 'sys', 'bat', 'cmd', 'ps1', 'sh',
    'txt', 'csv', 'log', 'pdf', 'docx', 'xlsx', 'zip', 'rar', 
    'tar', 'gz', 'py', 'java', 'c', 'cpp', 'json', 'xml'
}


def _is_public_ip(ip_str, expected_version=None):
    """Retorna True apenas para endereços IP públicos e globalmente roteáveis."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if expected_version is not None and ip_obj.version != expected_version:
        return False

    if (
        ip_obj.is_private
        or ip_obj.is_reserved
        or ip_obj.is_loopback
        or ip_obj.is_multicast
        or ip_obj.is_link_local
        or ip_obj.is_unspecified
    ):
        return False

    return ip_obj.is_global


def read_log_file(filepath):
    """
    Lê arquivos .txt e .csv com fallback de encoding (UTF-8-SIG -> Latin-1)
    e normaliza células CSV para preservar fronteiras de tokens na extração.
    """
    raw_text = None
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            with open(filepath, "r", encoding=encoding) as f:
                raw_text = f.read()
            break
        except UnicodeDecodeError:
            continue

    if raw_text is None:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            raw_text = f.read()

    if os.path.splitext(filepath)[1].lower() == ".csv":
        sample = raw_text[:4096]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel

        try:
            reader = csv.reader(io.StringIO(raw_text), dialect=dialect)
            linhas = [" ".join(cell.strip() for cell in row if cell and cell.strip()) for row in reader]
            return "\n".join(linha for linha in linhas if linha)
        except csv.Error:
            return raw_text

    return raw_text


def extract_iocs(text_log):
    """
    Recebe um texto de log e extrai IoCs de forma limpa,
    filtrando IPs privados/reservados/loopback/multicast e falsos positivos de arquivos.
    """
    
    # 1. Expressões Regulares
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ipv6_pattern = r'(?<![:\w])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![:\w])'
    url_pattern = r'https?://[^\s"\'<>`,;]+'
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    sha256_pattern = r'\b[A-Fa-f0-9]{64}\b'
    md5_pattern = r'\b[A-Fa-f0-9]{32}\b'

    raw_ipv4 = set(re.findall(ipv4_pattern, text_log))
    raw_ipv6 = set(re.findall(ipv6_pattern, text_log))
    raw_urls = {u.rstrip(".,;:!?)") for u in re.findall(url_pattern, text_log)}
    raw_urls.discard("")

    iocs = {
        "ipv4": sorted(ip for ip in raw_ipv4 if _is_public_ip(ip, expected_version=4)),
        "ipv6": sorted(ip for ip in raw_ipv6 if _is_public_ip(ip, expected_version=6)),
        "urls": sorted(raw_urls),
        "dominios": sorted(set(re.findall(domain_pattern, text_log))),
        "sha256": sorted(set(re.findall(sha256_pattern, text_log))),
        "md5": sorted(set(re.findall(md5_pattern, text_log)))
    }
    
    # 2. Tratamento e Limpeza de Domínios
    urls_unificadas = " ".join(iocs["urls"])
    dominios_filtrados = []

    for dom in iocs["dominios"]:
        # Ignora se for IPv4 (público ou privado)
        if dom in raw_ipv4:
            continue
        # Ignora se já estiver contido numa URL completa
        if dom in urls_unificadas:
            continue
        
        # Extrai a extensão final (ex: 'bin' de 'payload.bin')
        extensao = dom.split('.')[-1].lower()
        if extensao in FILE_EXTENSIONS_BLACKLIST:
            continue
            
        dominios_filtrados.append(dom)

    iocs["dominios"] = sorted(dominios_filtrados)
    
    return iocs