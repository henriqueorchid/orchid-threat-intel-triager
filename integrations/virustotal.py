# Arquivo: integrations/virustotal.py
import os
import requests
import base64
from dotenv import load_dotenv

# Carrega a chave do arquivo .env
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

HEADERS = {
    "accept": "application/json",
    "x-apikey": API_KEY if API_KEY else ""
}

def _verificar_erros_vt(response, msg_404):
    """Padroniza o tratamento de limites de cota (429/403) e erros HTTP do VirusTotal."""
    if response.status_code == 429:
        return {
            "source": "VirusTotal",
            "rate_limited": True,
            "aviso": "Cota diária ou limite de requisições por minuto da API VirusTotal gratuita esgotada."
        }
    elif response.status_code == 403:
        if "quota" in response.text.lower() or "limit" in response.text.lower():
            return {
                "source": "VirusTotal",
                "rate_limited": True,
                "aviso": "Cota diária da API VirusTotal gratuita esgotada."
            }
        return {
            "source": "VirusTotal",
            "rate_limited": True,
            "aviso": "Acesso negado ou cota diária da API VirusTotal gratuita esgotada (HTTP 403)."
        }
    elif response.status_code == 401:
        return {
            "source": "VirusTotal",
            "erro": "Chave da API VirusTotal inválida ou ausente no .env (HTTP 401)."
        }
    elif response.status_code == 404:
        return {
            "source": "VirusTotal",
            "aviso": msg_404
        }
    return {
        "source": "VirusTotal",
        "erro": f"Erro na API VirusTotal (Status Code {response.status_code})"
    }

# ==========================================
# 1. FUNÇÕES DE CHAMADA (ENDPOINTS)
# ==========================================

def analyze_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        return parse_vt_ip_response(response)
    except requests.RequestException as e:
        return {"source": "VirusTotal", "erro": f"Falha de conexão com a API VirusTotal: {e}"}

def analyze_hash(hash_string):
    url = f"https://www.virustotal.com/api/v3/files/{hash_string}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        return parse_vt_hash_response(response)
    except requests.RequestException as e:
        return {"source": "VirusTotal", "erro": f"Falha de conexão com a API VirusTotal: {e}"}

def analyze_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        return parse_vt_domain_response(response)
    except requests.RequestException as e:
        return {"source": "VirusTotal", "erro": f"Falha de conexão com a API VirusTotal: {e}"}

def analyze_url(target_url):
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        return parse_vt_url_response(response)
    except requests.RequestException as e:
        return {"source": "VirusTotal", "erro": f"Falha de conexão com a API VirusTotal: {e}"}

# ==========================================
# 2. FUNÇÕES DE PARSE (ENRIQUECIMENTO DOS DADOS)
# ==========================================

def parse_vt_ip_response(response):
    if response.status_code == 200:
        attr = response.json().get('data', {}).get('attributes', {})
        stats = attr.get('last_analysis_stats', {})
        return {
            "source": "VirusTotal",
            "malicious": stats.get('malicious', 0),
            "suspicious": stats.get('suspicious', 0),
            "harmless": stats.get('harmless', 0),
            "country": attr.get('country', 'Desconhecido'),
            "as_owner": attr.get('as_owner', 'Desconhecido'),
            "asn": attr.get('asn', 'Desconhecido'),
            "reputation": attr.get('reputation', 0),
            "network": attr.get('network', 'Não informado')
        }
    return _verificar_erros_vt(response, "Endereço IP não catalogado no VirusTotal.")

def parse_vt_hash_response(response):
    if response.status_code == 200:
        attr = response.json().get('data', {}).get('attributes', {})
        stats = attr.get('last_analysis_stats', {})
        popular_threat = attr.get('popular_threat_classification', {})
        threat_name = popular_threat.get('suggested_threat_label', 'Não identificada')
        
        return {
            "source": "VirusTotal",
            "malicious": stats.get('malicious', 0),
            "suspicious": stats.get('suspicious', 0),
            "harmless": stats.get('harmless', 0),
            "threat_label": threat_name,
            "type_description": attr.get('type_description', 'Desconhecido'),
            "meaningful_name": attr.get('meaningful_name', 'Sem nome de arquivo associado'),
            "size_bytes": attr.get('size', 0),
            "reputation": attr.get('reputation', 0),
            "times_submitted": attr.get('times_submitted', 0)
        }
    return _verificar_erros_vt(response, "Hash não encontrado na base do VirusTotal (arquivo inédito/desconhecido).")

def parse_vt_domain_response(response):
    if response.status_code == 200:
        attr = response.json().get('data', {}).get('attributes', {})
        stats = attr.get('last_analysis_stats', {})
        categories = attr.get('categories', {})
        return {
            "source": "VirusTotal",
            "malicious": stats.get('malicious', 0),
            "suspicious": stats.get('suspicious', 0),
            "harmless": stats.get('harmless', 0),
            "registrar": attr.get('registrar', 'Desconhecido'),
            "reputation": attr.get('reputation', 0),
            "categories": list(categories.values()) if categories else ['Não categorizado']
        }
    return _verificar_erros_vt(response, "Domínio não catalogado no VirusTotal.")

def parse_vt_url_response(response):
    if response.status_code == 200:
        attr = response.json().get('data', {}).get('attributes', {})
        stats = attr.get('last_analysis_stats', {})
        return {
            "source": "VirusTotal",
            "malicious": stats.get('malicious', 0),
            "suspicious": stats.get('suspicious', 0),
            "harmless": stats.get('harmless', 0),
            "title": attr.get('title', 'Sem título'),
            "reputation": attr.get('reputation', 0)
        }
    return _verificar_erros_vt(response, "URL não catalogada no VirusTotal.")