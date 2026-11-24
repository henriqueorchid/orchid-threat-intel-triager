# Arquivo: integrations/greynoise.py
import os
import requests
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("GREYNOISE_API_KEY")

HEADERS = {
    "Accept": "application/json",
    "key": API_KEY if API_KEY else ""
}

def _verificar_erros_greynoise(response):
    """Padroniza o tratamento de limites de cota (429/403) e erros HTTP do GreyNoise."""
    if response.status_code == 429:
        return {
            "source": "GreyNoise",
            "rate_limited": True,
            "aviso": "Cota diária da API GreyNoise gratuita esgotada."
        }
    elif response.status_code == 403:
        if "quota" in response.text.lower() or "limit" in response.text.lower() or "rate" in response.text.lower():
            return {
                "source": "GreyNoise",
                "rate_limited": True,
                "aviso": "Cota diária da API GreyNoise gratuita esgotada."
            }
        return {
            "source": "GreyNoise",
            "rate_limited": True,
            "aviso": "Cota diária da API GreyNoise gratuita esgotada ou acesso restrito (HTTP 403)."
        }
    elif response.status_code == 401:
        return {
            "source": "GreyNoise",
            "erro": "Chave da API GreyNoise inválida ou ausente no .env (HTTP 401)."
        }
    elif response.status_code == 404:
        # No GreyNoise, 404 significa que o IP não foi visto fazendo varreduras em massa nem está na base RIOT
        return {
            "source": "GreyNoise",
            "noise": False,
            "riot": False,
            "classification": "unknown",
            "actor_name": "Desconhecido",
            "last_seen": "Não informado",
            "message": "IP não observado em varreduras na internet nem listado como serviço benigno (RIOT)."
        }
    elif response.status_code == 400:
        return {
            "source": "GreyNoise",
            "aviso": "Endereço IP inválido ou não roteável segundo a API GreyNoise (HTTP 400)."
        }
    return {
        "source": "GreyNoise",
        "erro": f"Erro na API GreyNoise (Status Code {response.status_code})"
    }

# ==========================================
# 1. FUNÇÕES DE CHAMADA (ENDPOINTS)
# ==========================================

def analyze_ip(ip):
    url = f"https://api.greynoise.io/v3/community/{ip}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        return parse_greynoise_ip_response(response)
    except requests.RequestException as e:
        return {"source": "GreyNoise", "erro": f"Falha de conexão com a API GreyNoise: {e}"}

# ==========================================
# 2. FUNÇÕES DE PARSE (ENRIQUECIMENTO DOS DADOS)
# ==========================================

def parse_greynoise_ip_response(response):
    if response.status_code == 200:
        data = response.json()
        return {
            "source": "GreyNoise",
            "classification": data.get("classification", "unknown"),
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "actor_name": data.get("name", "Desconhecido"),
            "last_seen": data.get("last_seen", "Não informado"),
            "link": data.get("link", "Não informado"),
            "message": data.get("message", "Sem observações")
        }
    return _verificar_erros_greynoise(response)