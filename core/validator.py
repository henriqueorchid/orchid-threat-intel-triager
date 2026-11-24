# Arquivo: core/validator.py
from concurrent.futures import ThreadPoolExecutor, as_completed
from integrations import virustotal, abuseipdb, alienvault, urlscan, greynoise

# Matriz de Pesos de Confiabilidade por Tipo de IoC (Soma = 1.0)
PESOS_CONFIABILIDADE = {
    "hash": {
        "VirusTotal": 0.75,
        "AlienVault OTX": 0.25
    },
    "ip": {
        "AbuseIPDB": 0.35,
        "GreyNoise": 0.25,
        "VirusTotal": 0.20,
        "AlienVault OTX": 0.12,
        "URLScan.io": 0.08
    },
    "domain": {
        "URLScan.io": 0.40,
        "VirusTotal": 0.40,
        "AlienVault OTX": 0.20
    },
    "url": {
        "URLScan.io": 0.40,
        "VirusTotal": 0.40,
        "AlienVault OTX": 0.20
    }
}

# Roteamento de funções por tipo de indicador
ROTEAMENTO_APIS = {
    "ip": {
        "VirusTotal": virustotal.analyze_ip,
        "AbuseIPDB": abuseipdb.analyze_ip,
        "AlienVault OTX": alienvault.analyze_ip,
        "URLScan.io": urlscan.analyze_ip,
        "GreyNoise": greynoise.analyze_ip
    },
    "hash": {
        "VirusTotal": virustotal.analyze_hash,
        "AlienVault OTX": alienvault.analyze_hash
    },
    "domain": {
        "VirusTotal": virustotal.analyze_domain,
        "AlienVault OTX": alienvault.analyze_domain,
        "URLScan.io": urlscan.analyze_domain
    },
    "url": {
        "VirusTotal": virustotal.analyze_url,
        "AlienVault OTX": alienvault.analyze_url,
        "URLScan.io": urlscan.analyze_url
    }
}

CDN_PROVIDERS = ["cloudflare", "akamai", "fastly", "amazon", "aws", "google", "microsoft", "azure", "incapsula"]


def analyze_ioc_parallel(alvo, tipo_ioc):
    """
    Dispara consultas em paralelo para todas as APIs compatíveis com o IoC
    e retorna o pacote consolidado com severidade, falso-positivo e correlações.
    """
    rotas = ROTEAMENTO_APIS.get(tipo_ioc, {})
    resultados_apis = {}

    # 1. Disparo Assíncrono/Paralelo com ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=len(rotas)) as executor:
        futuros = {executor.submit(func, alvo): nome_api for nome_api, func in rotas.items()}
        for futuro in as_completed(futuros):
            nome_api = futuros[futuro]
            try:
                resultados_apis[nome_api] = futuro.result()
            except Exception as e:
                resultados_apis[nome_api] = {
                    "source": nome_api,
                    "erro": f"Exceção interna durante consulta em {nome_api}: {e}"
                }

    # 2. Cálculo Matemático de Severidade, Falso-Positivo e Correlação
    validacao = _calcular_consenso_e_correlacao(resultados_apis, tipo_ioc)

    return {
        "alvo": alvo,
        "tipo": tipo_ioc,
        "validacao": validacao,
        "fontes": resultados_apis
    }


def _pontuar_api_individual(nome_api, dados, tipo_ioc):
    """
    Calcula o score de risco (0 a 100) de uma API específica,
    aplicando modificadores de comunidade (votos, denúncias e pulses).
    """
    # Se houve erro de conexão ou rate limit, a API não entra no cálculo
    if dados.get("rate_limited") or "erro" in dados:
        return None

    # Se retornou "aviso" (404 / não catalogado), o risco conhecido na base é 0
    if "aviso" in dados:
        return 0.0

    score = 0.0

    if nome_api == "VirusTotal":
        malicious = dados.get("malicious", 0)
        suspicious = dados.get("suspicious", 0)
        reputation = dados.get("reputation", 0)

        # Escala progressiva por motores de detecção
        if malicious == 0 and suspicious == 0:
            score = 0.0
        elif malicious == 0 and suspicious > 0:
            score = min(25.0, suspicious * 8.0)
        elif malicious == 1:
            score = 22.0
        elif malicious == 2:
            score = 38.0
        elif 3 <= malicious <= 5:
            score = 62.0
        elif 6 <= malicious <= 15:
            score = 82.0
        else:
            score = min(100.0, 88.0 + (malicious - 15) * 0.5)

        # Modificador de Comunidade do VirusTotal (Reputation Score)
        if reputation <= -20:
            score += 18.0
        elif reputation < 0:
            score += 8.0
        elif reputation >= 15:
            score -= 25.0
        elif reputation > 0:
            score -= 10.0

    elif nome_api == "AbuseIPDB":
        if dados.get("is_whitelisted"):
            return 0.0

        score = float(dados.get("abuse_confidence_score", 0))
        distinct_users = dados.get("distinct_users", 0)
        total_reports = dados.get("total_reports", 0)

        # Modificador de Comunidade (Volume de denúncias por redes distintas)
        if distinct_users >= 20 and total_reports >= 50:
            score += 15.0
        elif distinct_users >= 5 and total_reports >= 10:
            score += 8.0
        elif total_reports > 0 and score == 0:
            score = min(25.0, total_reports * 3.0)

        if dados.get("is_tor"):
            score += 10.0

    elif nome_api == "GreyNoise":
        riot = dados.get("riot", False)
        classification = dados.get("classification", "unknown")
        noise = dados.get("noise", False)

        if riot or classification == "benign":
            score = 0.0
        elif classification == "malicious":
            score = 95.0 if noise else 85.0
        elif noise and classification == "unknown":
            score = 45.0
        else:
            score = 0.0

    elif nome_api == "AlienVault OTX":
        whitelisted = dados.get("whitelisted_info", ["Nenhuma"])
        if whitelisted and whitelisted != ["Nenhuma"]:
            return 0.0

        pulses = dados.get("pulse_count", 0)
        actors = dados.get("threat_actors", ["Não identificada"])

        if pulses == 0:
            score = 0.0
        elif pulses == 1:
            score = 30.0
        elif 2 <= pulses <= 4:
            score = 55.0
        elif 5 <= pulses <= 15:
            score = 75.0
        else:
            score = 90.0

        # Bônus se houver atribuição a grupo APT / Threat Actor pela comunidade
        if actors and actors != ["Não identificada"]:
            score += 15.0

    elif nome_api == "URLScan.io":
        malicious = dados.get("malicious", False)
        risk_score = float(dados.get("risk_score", 0))

        if malicious:
            score = max(88.0, risk_score)
        else:
            score = max(0.0, risk_score)

    return max(0.0, min(100.0, score))


def _calcular_consenso_e_correlacao(resultados_apis, tipo_ioc):
    """
    Cruza os scores individuais aplicando os pesos de confiabilidade por tipo de IoC,
    gera insights de correlação e calcula a porcentagem de Falso-Positivo (0 a 100%).
    """
    pesos_tipo = PESOS_CONFIABILIDADE.get(tipo_ioc, {})
    scores_individuais = {}
    avisos_cota = []
    erros_api = []

    soma_pesos_ativos = 0.0
    soma_ponderada = 0.0
    fontes_maliciosas = []
    fontes_limpas = []

    for nome_api, dados in resultados_apis.items():
        if dados.get("rate_limited"):
            avisos_cota.append(dados.get("aviso", f"Cota da API {nome_api} esgotada."))
            continue
        if "erro" in dados:
            erros_api.append(dados.get("erro"))
            continue

        score_api = _pontuar_api_individual(nome_api, dados, tipo_ioc)
        if score_api is not None:
            scores_individuais[nome_api] = round(score_api, 1)
            peso = pesos_tipo.get(nome_api, 0.1)

            # Se o URLScan não tiver histórico prévio da URL/IP, reduz o peso dele na média
            # para não diluir artificialmente uma ameaça detectada pelo VT ou AbuseIPDB
            if nome_api == "URLScan.io" and "aviso" in dados:
                peso *= 0.25

            soma_pesos_ativos += peso
            soma_ponderada += score_api * peso

            if score_api >= 20.0:
                fontes_maliciosas.append(nome_api)
            else:
                fontes_limpas.append(nome_api)

    # Cálculo base da Severidade Ponderada (0 a 100)
    severidade = (soma_ponderada / soma_pesos_ativos) if soma_pesos_ativos > 0 else 0.0

    # ==========================================================
    # MOTOR DE CORRELAÇÃO CRUZADA E CÁLCULO DE FALSO-POSITIVO
    # ==========================================================
    correlacoes = []
    vt_data = resultados_apis.get("VirusTotal", {})
    abuse_data = resultados_apis.get("AbuseIPDB", {})
    gn_data = resultados_apis.get("GreyNoise", {})
    otx_data = resultados_apis.get("AlienVault OTX", {})
    url_data = resultados_apis.get("URLScan.io", {})

    # Sinergia Positiva (Aumenta severidade quando a fonte especialista confirma ameaça grave)
    if tipo_ioc == "hash" and scores_individuais.get("VirusTotal", 0) >= 75:
        severidade = max(severidade, scores_individuais["VirusTotal"] * 0.92)
        if vt_data.get("threat_label") and vt_data.get("threat_label") != "Não identificada":
            severidade = min(100.0, severidade + 8.0)
            correlacoes.append(f"Família de malware identificada pelo VirusTotal: {vt_data['threat_label']}")

    if tipo_ioc == "ip":
        if scores_individuais.get("AbuseIPDB", 0) >= 80 and scores_individuais.get("GreyNoise", 0) >= 80:
            severidade = min(100.0, severidade + 15.0)
            correlacoes.append("Alta convergência: AbuseIPDB e GreyNoise confirmam atividade hostil ativa.")
        elif scores_individuais.get("AbuseIPDB", 0) >= 85 and scores_individuais.get("VirusTotal", 0) >= 50:
            severidade = min(100.0, severidade + 12.0)

    if tipo_ioc in ("url", "domain"):
        if scores_individuais.get("URLScan.io", 0) >= 80 or scores_individuais.get("VirusTotal", 0) >= 75:
            maior_especialista = max(scores_individuais.get("URLScan.io", 0), scores_individuais.get("VirusTotal", 0))
            severidade = max(severidade, maior_especialista * 0.88)

    # Bônus de Consenso Multi-Fonte
    if len(fontes_maliciosas) >= 3:
        severidade = min(100.0, severidade + 12.0)
        correlacoes.append(f"Consenso forte: {len(fontes_maliciosas)} fontes independentes reportam indicadores maliciosos.")

    # Destaque para Threat Actors (APT) no OTX
    otx_actors = otx_data.get("threat_actors", ["Não identificada"])
    if otx_actors and otx_actors != ["Não identificada"] and "aviso" not in otx_data:
        severidade = min(100.0, severidade + 10.0)
        correlacoes.append(f"Associado a grupo(s) de ameaça no OTX: {', '.join(otx_actors)}")

    # ----------------------------------------------------------
    # Cálculo de Probabilidade de Falso-Positivo (0% a 100%)
    # ----------------------------------------------------------
    alguma_deteccao = (
        len(fontes_maliciosas) > 0
        or vt_data.get("malicious", 0) > 0
        or vt_data.get("suspicious", 0) > 0
        or abuse_data.get("total_reports", 0) > 0
        or otx_data.get("pulse_count", 0) > 0
    )

    if not alguma_deteccao:
        fp_prob = 0.0
        severidade = 0.0
        correlacoes.append("Nenhuma fonte de inteligência encontrou registros maliciosos para este indicador.")
    else:
        # Base inicial de incerteza quando há detecção (50%)
        fp_prob = 50.0

        # 1. Evidências que AUMENTAM a chance de Falso-Positivo (Conflito / Benigno Conhecido)
        if gn_data.get("riot") is True:
            fp_prob += 45.0
            severidade *= 0.25
            correlacoes.append(f"GreyNoise RIOT ativo: IP pertence a infraestrutura legítima ({gn_data.get('actor_name', 'Serviço Conhecido')}).")
        elif gn_data.get("classification") == "benign":
            fp_prob += 35.0
            severidade *= 0.45
            correlacoes.append(f"GreyNoise classifica o IP como scanner benigno ({gn_data.get('actor_name', 'Scanner Legítimo')}).")

        if abuse_data.get("is_whitelisted") is True:
            fp_prob += 35.0
            severidade *= 0.40
            correlacoes.append("Endereço consta na Whitelist oficial do AbuseIPDB.")

        otx_wl = otx_data.get("whitelisted_info", ["Nenhuma"])
        if otx_wl and otx_wl != ["Nenhuma"]:
            fp_prob += 30.0
            severidade *= 0.50
            correlacoes.append(f"Indicador validado na Whitelist do AlienVault OTX ({', '.join(otx_wl)}).")

        # Detecção marginal no VirusTotal (1 ou 2 motores isolados contra dezenas de harmless)
        vt_mal = vt_data.get("malicious", 0)
        vt_harm = vt_data.get("harmless", 0)
        if 1 <= vt_mal <= 2 and vt_harm >= 40:
            fp_prob += 30.0
            correlacoes.append(f"Detecção isolada no VirusTotal ({vt_mal} motor(es) contra {vt_harm} limpos) — padrão comum de Falso-Positivo.")

        # Reputação comunitária positiva no VirusTotal apesar de alerta
        vt_rep = vt_data.get("reputation", 0)
        if vt_rep > 5:
            fp_prob += 25.0
            severidade *= 0.60
            correlacoes.append(f"Comunidade do VirusTotal avalia este indicador positivamente (Reputation: +{vt_rep}).")

        # Infraestrutura compartilhada (CDNs / Cloud)
        isp_owner = f"{vt_data.get('as_owner', '')} {abuse_data.get('isp', '')}".lower()
        if any(cdn in isp_owner for cdn in CDN_PROVIDERS) and severidade < 75:
            fp_prob += 15.0
            correlacoes.append("Hospedado em CDN/Nuvem compartilhada (IP pode abrigar múltiplos domínios legítimos).")

        # Alerta isolado apenas em fonte de menor peso (ex: apenas OTX sem confirmação no VT/AbuseIPDB/URLScan)
        if fontes_maliciosas == ["AlienVault OTX"] and len(scores_individuais) >= 2:
            fp_prob += 28.0
            correlacoes.append("Alerta restrito a Pulses comunitários no OTX, sem confirmação nos motores primários.")

        # 2. Evidências que REDUZEM a chance de Falso-Positivo (Confirmação de Ameaça Real)
        if vt_mal >= 15:
            fp_prob -= 42.0
        elif vt_mal >= 6:
            fp_prob -= 25.0
        elif vt_mal >= 3:
            fp_prob -= 10.0

        if vt_rep <= -10:
            fp_prob -= 20.0
            correlacoes.append(f"Nota de comunidade fortemente negativa no VirusTotal (Reputation: {vt_rep}).")

        if abuse_data.get("abuse_confidence_score", 0) >= 80 and abuse_data.get("distinct_users", 0) >= 10:
            fp_prob -= 30.0
            correlacoes.append(
                f"Comunidade AbuseIPDB: {abuse_data.get('total_reports')} denúncias por {abuse_data.get('distinct_users')} redes distintas."
            )

        if gn_data.get("classification") == "malicious":
            fp_prob -= 30.0
            correlacoes.append("Sensores do GreyNoise confirmam atividade de exploração maliciosa em massa.")

        if url_data.get("malicious") is True:
            fp_prob -= 30.0
            correlacoes.append("Sandbox do URLScan.io confirmou comportamento malicioso/phishing na página.")

        if len(fontes_maliciosas) >= 3:
            fp_prob -= 25.0
        elif len(fontes_maliciosas) == 2:
            fp_prob -= 15.0

        fp_prob = max(1.0, min(99.0, fp_prob))

    severidade_final = round(max(0.0, min(100.0, severidade)), 1)
    fp_final = round(fp_prob, 1)

    # Classificação qualitativa de Severidade
    if severidade_final == 0:
        nivel_severidade = "LIMPO / INFORMATIVO"
    elif severidade_final < 25:
        nivel_severidade = "BAIXO"
    elif severidade_final < 55:
        nivel_severidade = "MÉDIO"
    elif severidade_final < 80:
        nivel_severidade = "ALTO"
    else:
        nivel_severidade = "CRÍTICO"

    # Classificação da chance de Falso-Positivo
    if not alguma_deteccao:
        status_fp = "N/A (Sem detecções maliciosas)"
    elif fp_final >= 65:
        status_fp = f"{fp_final}% (ALTA chance de ser Falso-Positivo)"
    elif fp_final >= 35:
        status_fp = f"{fp_final}% (MODERADA — requer revisão de contexto)"
    else:
        status_fp = f"{fp_final}% (BAIXA — Ameaça Verdadeira de Alta Confiança)"

    return {
        "severidade_score": severidade_final,
        "severidade_nivel": nivel_severidade,
        "falso_positivo_pct": fp_final,
        "falso_positivo_status": status_fp,
        "fontes_consultadas": len(scores_individuais),
        "fontes_maliciosas": fontes_maliciosas,
        "scores_por_fonte": scores_individuais,
        "correlacoes": correlacoes,
        "avisos_cota": avisos_cota,
        "erros_api": erros_api
    }