# Arquivo: integrations/alienvault.py
import os
import requests
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("ALIENVAULT_API_KEY")

HEADERS = {
    "Accept": "application/json",
    "X-OTX-API-KEY": API_KEY if API_KEY else "",
    "User-Agent": "Orchid-ThreatIntel-Triager/1.0"
}

OTX_TIMEOUT = (5, 25)

def _verificar_erros_otx(response, msg_404):
    """Padroniza o tratamento de limites de cota (429/403) e erros HTTP do AlienVault OTX."""
    if response.status_code == 429:
        return {
            "source": "AlienVault OTX",
            "rate_limited": True,
            "aviso": "Cota diária ou limite de requisições da API AlienVault OTX gratuita esgotada."
        }
    elif response.status_code == 403:
        if "quota" in response.text.lower() or "limit" in response.text.lower():
            return {
                "source": "AlienVault OTX",
                "rate_limited": True,
                "aviso": "Cota diária da API AlienVault OTX gratuita esgotada."
            }
        return {
            "source": "AlienVault OTX",
            "rate_limited": True,
            "aviso": "Acesso negado ou cota diária da API AlienVault OTX gratuita esgotada (HTTP 403)."
        }
    elif response.status_code == 401:
        return {
            "source": "AlienVault OTX",
            "erro": "Chave da API AlienVault OTX inválida ou ausente no .env (HTTP 401)."
        }
    elif response.status_code == 404:
        return {
            "source": "AlienVault OTX",
            "aviso": msg_404
        }
    elif response.status_code == 400:
        return {
            "source": "AlienVault OTX",
            "aviso": "Indicador inválido ou não roteável segundo a API AlienVault OTX (HTTP 400)."
        }
    return {
        "source": "AlienVault OTX",
        "erro": f"Erro na API AlienVault OTX (Status Code {response.status_code})"
    }

def _extrair_resumo_pulses(pulse_info):
    """Extrai nomes de campanhas, tags e possíveis grupos APT dos Pulses do OTX."""
    pulses = pulse_info.get("pulses", [])
    pulse_names = []
    adversaries = set()
    tags = set()

    for p in pulses[:5]:
        if p.get("name"):
            pulse_names.append(p.get("name"))
        if p.get("adversary"):
            adversaries.add(p.get("adversary"))
        for t in p.get("tags", [])[:5]:
            tags.add(t)

    return {
        "pulse_count": pulse_info.get("count", 0),
        "top_pulses": pulse_names if pulse_names else ["Nenhum pulse associado"],
        "threat_actors": list(adversaries) if adversaries else ["Não identificada"],
        "tags": list(tags)[:8] if tags else ["Sem tags"]
    }

# ==========================================
# 1. FUNÇÕES DE CHAMADA (ENDPOINTS)
# ==========================================

def analyze_ip(ip):
    ip_type = "IPv6" if ":" in ip else "IPv4"
    url = f"https://otx.alienvault.com/api/v1/indicators/{ip_type}/{ip}/general"
    try:
        response = requests.get(url, headers=HEADERS, timeout=OTX_TIMEOUT)
        return parse_otx_ip_response(response)
    except requests.RequestException as e:
        return {"source": "AlienVault OTX", "erro": f"Falha de conexão com a API AlienVault OTX: {e}"}

def analyze_hash(hash_string):
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash_string}/general"
    try:
        response = requests.get(url, headers=HEADERS, timeout=OTX_TIMEOUT)
        return parse_otx_generic_response(response, "Hash não encontrado na base do AlienVault OTX.")
    except requests.RequestException as e:
        return {"source": "AlienVault OTX", "erro": f"Falha de conexão com a API AlienVault OTX: {e}"}

def analyze_domain(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    try:
        response = requests.get(url, headers=HEADERS, timeout=OTX_TIMEOUT)
        return parse_otx_generic_response(response, "Domínio não catalogado no AlienVault OTX.")
    except requests.RequestException as e:
        return {"source": "AlienVault OTX", "erro": f"Falha de conexão com a API AlienVault OTX: {e}"}

def analyze_url(target_url):
    url = f"https://otx.alienvault.com/api/v1/indicators/url/{target_url}/general"
    try:
        response = requests.get(url, headers=HEADERS, timeout=OTX_TIMEOUT)
        return parse_otx_generic_response(response, "URL não catalogada no AlienVault OTX.")
    except requests.RequestException as e:
        return {"source": "AlienVault OTX", "erro": f"Falha de conexão com a API AlienVault OTX: {e}"}

# ==========================================
# 2. FUNÇÕES DE PARSE (ENRIQUECIMENTO DOS DADOS)
# ==========================================

def parse_otx_ip_response(response):
    if response.status_code == 200:
        data = response.json()
        resumo = _extrair_resumo_pulses(data.get("pulse_info", {}))
        validations = [v.get("name") for v in data.get("validation", []) if v.get("name")]
        
        return {
            "source": "AlienVault OTX",
            "pulse_count": resumo["pulse_count"],
            "threat_actors": resumo["threat_actors"],
            "top_pulses": resumo["top_pulses"],
            "tags": resumo["tags"],
            "country": data.get("country_name", "Desconhecido"),
            "asn": data.get("asn", "Desconhecido"),
            "reputation": data.get("reputation", 0),
            "whitelisted_info": validations if validations else ["Nenhuma"]
        }
    return _verificar_erros_otx(response, "Endereço IP não catalogado no AlienVault OTX.")

def parse_otx_generic_response(response, msg_404):
    if response.status_code == 200:
        data = response.json()
        resumo = _extrair_resumo_pulses(data.get("pulse_info", {}))
        validations = [v.get("name") for v in data.get("validation", []) if v.get("name")]

        return {
            "source": "AlienVault OTX",
            "pulse_count": resumo["pulse_count"],
            "threat_actors": resumo["threat_actors"],
            "top_pulses": resumo["top_pulses"],
            "tags": resumo["tags"],
            "whitelisted_info": validations if validations else ["Nenhuma"]
        }
    return _verificar_erros_otx(response, msg_404)