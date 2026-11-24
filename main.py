# Arquivo: main.py
import os
import time
from core.extractor import extract_iocs, read_log_file
from core.validator import analyze_ioc_parallel

# Paleta de Cores ANSI com identidade Orchid
ORCHID = '\033[95m'
BOLD = '\033[1m'
CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
GRAY = '\033[90m'
RESET = '\033[0m'


def _gerar_barra(porcentagem, tamanho=20):
    """Desenha uma barra visual proporcional de 0 a 100%."""
    preenchido = int(round((porcentagem / 100.0) * tamanho))
    preenchido = max(0, min(tamanho, preenchido))
    vazio = tamanho - preenchido
    return f"[{'█' * preenchido}{'░' * vazio}]"


def _cor_severidade(score):
    """Retorna a cor ANSI correspondente ao nível de severidade."""
    if score >= 80:
        return RED
    elif score >= 55:
        return YELLOW
    elif score >= 25:
        return CYAN
    return GREEN


def _cor_falso_positivo(fp_pct, alguma_deteccao):
    """Retorna a cor ANSI para a probabilidade de Falso-Positivo."""
    if not alguma_deteccao:
        return GREEN
    if fp_pct >= 65:
        return YELLOW
    elif fp_pct >= 35:
        return CYAN
    return RED


def exibir_relatorio_consolidado(pacote):
    """
    Imprime o novo layout de inteligência multi-fonte:
    1. Painel de Consenso, Severidade e Falso-Positivo
    2. Correlações Cruzadas e Alertas de Rate-Limit
    3. Detalhamento individual de cada fonte consultada
    """
    alvo = pacote["alvo"]
    tipo = pacote["tipo"].upper()
    val = pacote["validacao"]
    fontes = pacote["fontes"]

    sev_score = val["severidade_score"]
    sev_nivel = val["severidade_nivel"]
    fp_pct = val["falso_positivo_pct"]
    fp_status = val["falso_positivo_status"]
    alguma_deteccao = sev_score > 0 or len(val["fontes_maliciosas"]) > 0

    cor_sev = _cor_severidade(sev_score)
    cor_fp = _cor_falso_positivo(fp_pct, alguma_deteccao)

    print(f"\n{ORCHID}{'═' * 72}{RESET}")
    print(f"{ORCHID}{BOLD}   [+] VEREDITO CONSOLIDADO ORCHID  |  {tipo}: {alvo}{RESET}")
    print(f"{ORCHID}{'═' * 72}{RESET}")

    # 1. Métricas Principais de Severidade e Falso-Positivo
    barra_sev = _gerar_barra(sev_score)
    barra_fp = _gerar_barra(fp_pct)

    print(f"{ORCHID}Nível de Severidade :{RESET} {cor_sev}{BOLD}{barra_sev} {sev_score:>5.1f}/100 ({sev_nivel}){RESET}")
    print(f"{ORCHID}Chance Falso-Posit. :{RESET} {cor_fp}{BOLD}{barra_fp} {fp_status}{RESET}")

    # 2. Consenso entre os Bancos de Dados
    total_ativas = val["fontes_consultadas"]
    qtd_mal = len(val["fontes_maliciosas"])
    nomes_mal = ", ".join(val["fontes_maliciosas"]) if val["fontes_maliciosas"] else "Nenhuma"
    print(f"{ORCHID}Consenso das Fontes :{RESET} {qtd_mal} de {total_ativas} APIs ativas apontaram risco ({nomes_mal})")

    if val["scores_por_fonte"]:
        resumo_scores = " | ".join([f"{k}: {v}/100" for k, v in val["scores_por_fonte"].items()])
        print(f"{ORCHID}Score por Fonte     :{RESET} {GRAY}{resumo_scores}{RESET}")

    # 3. Insights de Correlação Cruzada
    if val["correlacoes"]:
        print(f"\n{ORCHID}{BOLD}[*] ANÁLISE DE CORRELAÇÃO E COMUNIDADE:{RESET}")
        for item in val["correlacoes"]:
            print(f"    {ORCHID}•{RESET} {item}")

    # 4. Alertas de Cota Esgotada (HTTP 429 / 403) ou Erros de Conexão
    if val["avisos_cota"]:
        print(f"\n{YELLOW}{BOLD}[!] ALERTAS DE LIMITE DE API (RATE LIMIT / QUOTA):{RESET}")
        for aviso in val["avisos_cota"]:
            print(f"    {YELLOW}• {aviso}{RESET}")

    if val["erros_api"]:
        print(f"\n{RED}{BOLD}[!] ERROS DE COMUNICAÇÃO:{RESET}")
        for erro in val["erros_api"]:
            print(f"    {RED}• {erro}{RESET}")

    # 5. Telemetria Detalhada por Fonte de Inteligência
    print(f"\n{ORCHID}{'─' * 72}{RESET}")
    print(f"{ORCHID}{BOLD}   DETALHAMENTO TÉCNICO POR FONTE DE INTELIGÊNCIA{RESET}")
    print(f"{ORCHID}{'─' * 72}{RESET}")

    for nome_api, dados in fontes.items():
        score_individual = val["scores_por_fonte"].get(nome_api)
        tag_score = f" (Risco: {score_individual}/100)" if score_individual is not None else ""
        print(f"\n{ORCHID}{BOLD}► {nome_api}{tag_score}{RESET}")

        if dados.get("rate_limited"):
            print(f"  {YELLOW}AVISO: {dados.get('aviso')}{RESET}")
            continue
        if "erro" in dados:
            print(f"  {RED}ERRO : {dados.get('erro')}{RESET}")
            continue
        if "aviso" in dados:
            print(f"  {GRAY}INFO : {dados.get('aviso')}{RESET}")
            continue

        for chave, valor in dados.items():
            if chave in ("source", "rate_limited"):
                continue

            if valor in ["Desconhecido", "Sem título", "Sem nome de arquivo associado", "Não informado", "Não identificada", "", [], {}] or valor is None:
                valor_formatado = "NULL"
            elif isinstance(valor, list):
                valor_formatado = ", ".join(str(x) for x in valor) if valor else "NULL"
            else:
                valor_formatado = valor

            chave_formatada = chave.replace('_', ' ').title()
            print(f"  {ORCHID}{chave_formatada:<22}:{RESET} {valor_formatado}")

    print(f"{ORCHID}{'═' * 72}{RESET}\n")


def exibir_resumo_lote(resultados_lote):
    """Imprime uma tabela consolidada no final da varredura de arquivos .txt / .csv."""
    if not resultados_lote:
        return

    print(f"\n{ORCHID}{'═' * 78}{RESET}")
    print(f"{ORCHID}{BOLD}   RESUMO EXECUTIVO DA VARREDURA DE LOG ({len(resultados_lote)} IoCs Analisados){RESET}")
    print(f"{ORCHID}{'═' * 78}{RESET}")
    print(f"{ORCHID}{BOLD}{'INDICADOR (IoC)':<34} | {'TIPO':<7} | {'SEVERIDADE':<16} | {'FALSO-POSITIVO'}{RESET}")
    print(f"{ORCHID}{'─' * 78}{RESET}")

    # Ordena do mais crítico para o mais baixo
    ordenados = sorted(resultados_lote, key=lambda x: x["validacao"]["severidade_score"], reverse=True)

    for item in ordenados:
        alvo_curto = item["alvo"] if len(item["alvo"]) <= 32 else item["alvo"][:29] + "..."
        tipo = item["tipo"].upper()
        val = item["validacao"]
        sev = val["severidade_score"]
        nivel = val["severidade_nivel"].split()[0]
        fp = val["falso_positivo_pct"]
        cor = _cor_severidade(sev)

        fp_str = f"{fp:>5.1f}%" if sev > 0 or val["fontes_maliciosas"] else "0.0% (Limpo)"
        print(f"{alvo_curto:<34} | {tipo:<7} | {cor}{sev:>5.1f} ({nivel}){RESET:<12} | {fp_str}")

    print(f"{ORCHID}{'═' * 78}{RESET}\n")


def menu():
    while True:
        print(f"{ORCHID}╔══════════════════════════════════════════════╗{RESET}")
        print(f"{ORCHID}║   {BOLD}ORCHID THREAT INTEL TRIAGER - MULTI-API{RESET}{ORCHID}    ║{RESET}")
        print(f"{ORCHID}╚══════════════════════════════════════════════╝{RESET}")
        print(f"{ORCHID}[1] Investigar Endereço IP (VT, AbuseIPDB, OTX, GreyNoise, URLScan){RESET}")
        print(f"{ORCHID}[2] Investigar Hash MD5 / SHA-256 (VT, AlienVault OTX){RESET}")
        print(f"{ORCHID}[3] Investigar URL / Domínio (URLScan, VT, AlienVault OTX){RESET}")
        print(f"{ORCHID}[4] Varrer arquivo de Log (.txt / .csv) com Consenso em Lote{RESET}")
        print(f"{ORCHID}[0] Sair{RESET}")

        escolha = input(f"{ORCHID}\nSelecione uma opção: {RESET}").strip()

        if escolha == '1':
            alvo = input(f"{ORCHID}[>] Digite o IP: {RESET}").strip()
            if alvo:
                print(f"{ORCHID}[*] Consultando 5 fontes de inteligência em paralelo...{RESET}")
                pacote = analyze_ioc_parallel(alvo, "ip")
                exibir_relatorio_consolidado(pacote)

        elif escolha == '2':
            alvo = input(f"{ORCHID}[>] Digite o Hash (MD5 ou SHA-256): {RESET}").strip()
            if alvo:
                print(f"{ORCHID}[*] Consultando VirusTotal e AlienVault OTX em paralelo...{RESET}")
                pacote = analyze_ioc_parallel(alvo, "hash")
                exibir_relatorio_consolidado(pacote)

        elif escolha == '3':
            alvo = input(f"{ORCHID}[>] Digite a URL ou Domínio: {RESET}").strip()
            if alvo:
                tipo_alvo = "url" if (alvo.startswith("http://") or alvo.startswith("https://")) else "domain"
                print(f"{ORCHID}[*] Consultando URLScan.io, VirusTotal e AlienVault OTX em paralelo...{RESET}")
                pacote = analyze_ioc_parallel(alvo, tipo_alvo)
                exibir_relatorio_consolidado(pacote)

        elif escolha == '4':
            caminho_arquivo = input(f"{ORCHID}[>] Digite o caminho do arquivo de log (ex: logs/evento.txt): {RESET}").strip().strip('"').strip("'")
            if os.path.exists(caminho_arquivo):
                print(f"\n{ORCHID}[*] Lendo e extraindo IoCs do arquivo...{RESET}")
                try:
                    texto_log = read_log_file(caminho_arquivo)

                    iocs = extract_iocs(texto_log)
                    fila_analise = []

                    for ip in iocs['ipv4'] + iocs['ipv6']:
                        fila_analise.append((ip, "ip"))
                    for dom in iocs['dominios']:
                        fila_analise.append((dom, "domain"))
                    for url in iocs['urls']:
                        fila_analise.append((url, "url"))
                    for h in iocs['sha256'] + iocs['md5']:
                        fila_analise.append((h, "hash"))

                    total_iocs = len(fila_analise)

                    print(f"{ORCHID}[+] Total de IoCs únicos identificados: {total_iocs}{RESET}")
                    print(
                        f"{ORCHID}IPs: {len(iocs['ipv4']) + len(iocs['ipv6'])} | "
                        f"Domínios/URLs: {len(iocs['dominios']) + len(iocs['urls'])} | "
                        f"Hashes: {len(iocs['sha256']) + len(iocs['md5'])}{RESET}"
                    )

                    if total_iocs == 0:
                        print(f"{ORCHID}[!] Nenhum indicador encontrado no arquivo.{RESET}\n")
                        continue

                    print(f"\n{ORCHID}Modos de Cadência para Varredura em Lote:{RESET}")
                    print(f"{ORCHID}[1] Modo Seguro (Pausa de 15s entre itens para respeitar limite grátis do VirusTotal){RESET}")
                    print(f"{ORCHID}[2] Modo Rápido (Sem pausa — caso uma API esgote a cota, o validador continua com as demais){RESET}")
                    modo_lote = input(f"{ORCHID}Escolha o modo (1 ou 2): {RESET}").strip()

                    intervalo = 15 if modo_lote == '1' else 0
                    if intervalo > 0 and total_iocs > 1:
                        tempo_estimado = (total_iocs - 1) * intervalo
                        print(f"{ORCHID}[!] Tempo estimado no Modo Seguro: ~{tempo_estimado} segundos.{RESET}")

                    confirmar = input(f"{ORCHID}Deseja iniciar a varredura agora? (s/n): {RESET}").strip().lower()
                    if confirmar != 's':
                        print(f"{ORCHID}[*] Operação cancelada.{RESET}\n")
                        continue

                    resultados_lote = []
                    print(f"\n{ORCHID}[*] Iniciando varredura multi-API paralelizada...{RESET}")

                    for idx, (indicador, tipo_ioc) in enumerate(fila_analise, start=1):
                        print(f"{ORCHID}[{idx}/{total_iocs}] Analisando {tipo_ioc.upper()}: {indicador}...{RESET}")
                        pacote = analyze_ioc_parallel(indicador, tipo_ioc)
                        resultados_lote.append(pacote)
                        exibir_relatorio_consolidado(pacote)

                        if intervalo > 0 and idx < total_iocs:
                            time.sleep(intervalo)

                    exibir_resumo_lote(resultados_lote)
                    print(f"{ORCHID}[+] Varredura do arquivo concluída com sucesso!{RESET}\n")

                except Exception as e:
                    print(f"{RED}[!] Erro ao processar o arquivo: {e}{RESET}\n")
            else:
                print(f"{RED}[!] Arquivo não encontrado.{RESET}\n")

        elif escolha == '0':
            print(f"{ORCHID}[*] Encerrando o Orchid Triager. Até logo!{RESET}")
            break

        else:
            print(f"{RED}[!] Opção inválida. Tente novamente.{RESET}\n")


if __name__ == "__main__":
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
        menu()
    except KeyboardInterrupt:
        print(f"\n{ORCHID}[*] Interrupção detectada. Encerrando o Orchid Triager...{RESET}")