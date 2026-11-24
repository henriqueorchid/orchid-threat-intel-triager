# Arquivo: integrations/abuseipdb.py
import os
import requests
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_API_KEY")

HEADERS = {
    "Accept": "application/json",
    "Key": API_KEY if API_KEY else ""
}

def _verificar_erros_abuseipdb(response):
    """Padroniza o tratamento de limites de cota (429/403) e erros HTTP do AbuseIPDB."""
    if response.status_code == 429:
        return {
            "source": "AbuseIPDB",
            "rate_limited": True,
            "aviso": "Cota diária da API AbuseIPDB gratuita esgotada."
        }
    elif response.status_code == 403:
        if "quota" in response.text.lower() or "limit" in response.text.lower():
            return {
                "source": "AbuseIPDB",
                "rate_limited": True,
                "aviso": "Cota diária da API AbuseIPDB gratuita esgotada."
            }
        return {
            "source": "AbuseIPDB",
            "rate_limited": True,
            "aviso": "Acesso negado ou cota diária da API AbuseIPDB gratuita esgotada (HTTP 403)."
        }
    elif response.status_code == 401:
        return {
            "source": "AbuseIPDB",
            "erro": "Chave da API AbuseIPDB inválida ou ausente no .env (HTTP 401)."
        }
    elif response.status_code == 422:
        return {
            "source": "AbuseIPDB",
            "aviso": "Endereço IP inválido ou privado não suportado pelo AbuseIPDB."
        }
    return {
        "source": "AbuseIPDB",
        "erro": f"Erro na API AbuseIPDB (Status Code {response.status_code})"
    }

# ==========================================
# 1. FUNÇÕES DE CHAMADA (ENDPOINTS)
# ==========================================

def analyze_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }
    try:
        response = requests.get(url, headers=HEADERS, params=params, timeout=10)
        return parse_abuseipdb_ip_response(response)
    except requests.RequestException as e:
        return {"source": "AbuseIPDB", "erro": f"Falha de conexão com a API AbuseIPDB: {e}"}

# ==========================================
# 2. FUNÇÕES DE PARSE (ENRIQUECIMENTO DOS DADOS)
# ==========================================

def parse_abuseipdb_ip_response(response):
    if response.status_code == 200:
        data = response.json().get("data", {})
        return {
            "source": "AbuseIPDB",
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "distinct_users": data.get("numDistinctUsers", 0),
            "country": data.get("countryCode", "Desconhecido"),
            "isp": data.get("isp", "Desconhecido"),
            "domain": data.get("domain", "Não informado"),
            "usage_type": data.get("usageType", "Desconhecido"),
            "is_whitelisted": data.get("isWhitelisted", False),
            "is_tor": data.get("isTor", False),
            "last_reported_at": data.get("lastReportedAt", "Não informado")
        }
    return _verificar_erros_abuseipdb(response)