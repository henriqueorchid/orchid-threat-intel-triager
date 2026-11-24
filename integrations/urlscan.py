# Arquivo: integrations/urlscan.py
import os
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("URLSCAN_API_KEY")

HEADERS = {
    "Accept": "application/json",
    "API-Key": API_KEY if API_KEY else ""
}

def _verificar_erros_urlscan(response, msg_404):
    """Padroniza o tratamento de limites de cota (429/403) e erros HTTP do URLScan.io."""
    if response.status_code == 429:
        return {
            "source": "URLScan.io",
            "rate_limited": True,
            "aviso": "Cota diária da API URLScan.io gratuita esgotada."
        }
    elif response.status_code == 403:
        if "quota" in response.text.lower() or "limit" in response.text.lower():
            return {
                "source": "URLScan.io",
                "rate_limited": True,
                "aviso": "Cota diária da API URLScan.io gratuita esgotada."
            }
        return {
            "source": "URLScan.io",
            "rate_limited": True,
            "aviso": "Acesso negado ou cota diária da API URLScan.io gratuita esgotada (HTTP 403)."
        }
    elif response.status_code == 401:
        return {
            "source": "URLScan.io",
            "erro": "Chave da API URLScan.io inválida ou ausente no .env (HTTP 401)."
        }
    elif response.status_code == 404:
        return {
            "source": "URLScan.io",
            "aviso": msg_404
        }
    return {
        "source": "URLScan.io",
        "erro": f"Erro na API URLScan.io (Status Code {response.status_code})"
    }

# ==========================================
# 1. FUNÇÕES DE CHAMADA (ENDPOINTS)
# ==========================================

def analyze_domain(domain):
    query = f"page.domain:{domain}"
    return _search_urlscan(query, "Domínio sem histórico de varreduras no URLScan.io.")

def analyze_ip(ip):
    query = f"page.ip:{ip}"
    return _search_urlscan(query, "Endereço IP sem histórico de varreduras web no URLScan.io.")

def analyze_url(target_url):
    parsed = urlparse(target_url)
    host = parsed.netloc if parsed.netloc else target_url
    query = f"page.domain:{host}"
    return _search_urlscan(query, "URL sem histórico de varreduras no URLScan.io.")

def _search_urlscan(query, msg_vazio):
    url = "https://urlscan.io/api/v1/search/"
    params = {"q": query, "size": 1}
    try:
        response = requests.get(url, headers=HEADERS, params=params, timeout=10)
        return parse_urlscan_response(response, msg_vazio)
    except requests.RequestException as e:
        return {"source": "URLScan.io", "erro": f"Falha de conexão com a API URLScan.io: {e}"}

# ==========================================
# 2. FUNÇÕES DE PARSE (ENRIQUECIMENTO DOS DADOS)
# ==========================================

def parse_urlscan_response(response, msg_vazio):
    if response.status_code == 200:
        data = response.json()
        results = data.get("results", [])
        if not results:
            return {"source": "URLScan.io", "aviso": msg_vazio}

        latest = results[0]
        page = latest.get("page", {})
        scan_id = latest.get("_id")

        # Valores padrão caso a consulta detalhada de veredito não esteja disponível
        malicious = False
        score = 0
        categories = ["Não categorizado"]
        tags = ["Sem tags"]

        # Busca o veredito de segurança completo usando o UUID da última varredura
        if scan_id:
            try:
                res_detail = requests.get(f"https://urlscan.io/api/v1/result/{scan_id}/", headers=HEADERS, timeout=10)
                if res_detail.status_code == 200:
                    verdicts = res_detail.json().get("verdicts", {}).get("overall", {})
                    malicious = verdicts.get("malicious", False)
                    score = verdicts.get("score", 0)
                    categories = verdicts.get("categories", []) or ["Não categorizado"]
                    tags = verdicts.get("tags", []) or ["Sem tags"]
            except requests.RequestException:
                pass

        return {
            "source": "URLScan.io",
            "malicious": malicious,
            "risk_score": score,
            "categories": categories,
            "tags": tags,
            "domain": page.get("domain", "Desconhecido"),
            "ip": page.get("ip", "Desconhecido"),
            "country": page.get("country", "Desconhecido"),
            "server": page.get("server", "Não informado"),
            "title": page.get("title", "Sem título"),
            "report_link": f"https://urlscan.io/result/{scan_id}/" if scan_id else "Não informado"
        }
    return _verificar_erros_urlscan(response, msg_vazio)