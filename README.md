🇧🇷 Português | [🇺🇸 English](README.en.md)

# Orchid Threat Intel Triager

CLI de triagem e enriquecimento de Indicadores de Comprometimento (IoCs) em múltiplas fontes de Threat Intelligence. Desenvolvi esta ferramenta para agilizar a triagem no dia a dia de SOC direto pelo terminal — sem precisar abrir e alternar entre várias abas de portais para cada alerta. Ela aceita um indicador único (IP, hash, domínio ou URL) ou um arquivo de log bruto (`.txt`/`.csv`), descarta ruído interno antes de fazer qualquer requisição externa, consulta até 5 APIs em paralelo e entrega um veredito consolidado com score de severidade e estimativa de falso-positivo.

---

## O problema que resolve

Na rotina de N1/N2 de um SOC, validar alertas costuma virar troca constante de abas: abrir VirusTotal, checar AbuseIPDB, confirmar no GreyNoise se não é scanner conhecido, olhar pulses no AlienVault OTX e procurar histórico no URLScan. Esse processo manual consome tempo em cada incidente e aumenta a chance de escalar falso-positivo — por exemplo, um IP de CDN/serviço legítimo com 1 ou 2 detecções isoladas ou um alerta baseado em pulse antigo de comunidade.

O **Orchid Threat Intel Triager** automatiza essa correlação no terminal:

- **Sanitização antes da consulta**: extrai IoCs via Regex e usa `ipaddress` para descartar endereços privados, reservados, loopback, link-local, multicast e não especificados (`10.0.0.15`, `192.168.x.x`, `127.0.0.1`, etc.), além de extensões comuns de arquivo (`payload.exe`, `.dll`, `.log`), evitando vazamento de topologia interna ou erros HTTP 400 desnecessários.
- **Consulta paralela e resiliente**: dispara chamadas simultâneas com `ThreadPoolExecutor`. Se uma API bater cota (`429`/`403`) ou falhar na rede, o validador isola a fonte e recalcula o consenso apenas com as APIs que responderam.
- **Triagem de falso-positivo**: cruza detecções com sinais de legitimidade (GreyNoise RIOT/benigno, whitelists do AbuseIPDB e OTX, reputação comunitária do VirusTotal e infraestrutura de CDN/Cloud compartilhada).

---

## Arquitetura

O projeto separa explicitamente camada de apresentação, extração, motor de decisão e conectores externos:

```text
orchid-threat-intel-triager/
├── main.py                  # CLI ANSI (paleta Orchid), menus interativos, cadência de lote e exibição
├── core/
│   ├── extractor.py         # Leitura resiliente (.txt/.csv UTF-8/Latin-1), Regex e filtro ipaddress
│   └── validator.py         # Orquestração ThreadPoolExecutor, pesos dinâmicos, consenso e falso-positivo
├── integrations/
│   ├── virustotal.py        # Conector VirusTotal API v3 (IP, Hash, Domínio, URL)
│   ├── abuseipdb.py         # Conector AbuseIPDB API v2 (IP)
│   ├── alienvault.py        # Conector AlienVault OTX API v1 (IP, Hash, Domínio, URL)
│   ├── urlscan.py           # Conector URLScan.io Search + Result API (IP, Domínio, URL)
│   └── greynoise.py         # Conector GreyNoise Community API v3 (IP)
├── docs/images/             # Capturas de tela da CLI
├── .env.example             # Modelo de variáveis de ambiente para as chaves de API
├── requirements.txt         # Dependências Python
├── README.md                # Documentação em português
├── README.en.md             # Documentação em inglês
└── LICENSE                  # Licença MIT
```

### Contrato dos conectores (`integrations/`)

Todos os módulos de integração devolvem um dicionário padronizado com a identificação da fonte e seguem a mesma convenção de estado:
- **Sucesso (`200`)**: campos normalizados da fonte.
- **Rate limit / Cota (`429` ou `403`)**: sinaliza limite de cota e sai do denominador de pesos sem interromper a análise.
- **Sem registro ou indicador inválido (`404`, `422` ou `400`)**: retorna aviso informativo sem interromper o fluxo ou poluir o relatório com erro crítico.
- **Credencial inválida ou erro de rede (`401`, timeout, falha de conexão)**: retorna erro isolado daquela fonte, permitindo que as demais continuem.

---

## Lógica de consenso e falso-positivo (`core/validator.py`)

### 1. Matriz de pesos por tipo de IoC

Cada indicador é roteado apenas para as fontes compatíveis e pontuado de `0` a `100` com pesos que somam `1.0`:

| Tipo de IoC | VirusTotal | AbuseIPDB | GreyNoise | AlienVault OTX | URLScan.io |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **IP** | `0.20` | `0.35` | `0.25` | `0.12` | `0.08` |
| **Hash (MD5 / SHA-256)** | `0.75` | — | — | `0.25` | — |
| **Domínio / URL** | `0.40` | — | — | `0.20` | `0.40` |

- **Renormalização dinâmica**: quando alguma API está em *rate limit* ou falha de conexão, ela sai do cálculo ativo e os pesos das fontes restantes são reajustados proporcionalmente.
- **Ajuste para URLScan sem histórico**: se o URLScan.io não tiver varreduras prévias do indicador, seu peso é reduzido na média para não diluir ameaças confirmadas por VirusTotal ou AbuseIPDB.
- **Reforço por consenso entre fontes**: quando 3 ou mais fontes apontam risco, há atribuição de Threat Actor/APT no OTX ou forte concordância entre AbuseIPDB e GreyNoise, a severidade recebe reforço adicional.

### 2. Faixas de severidade

| Score | Nível |
| :--- | :--- |
| `0.0` | `LIMPO / INFORMATIVO` |
| `0.1 – 24.9` | `BAIXO` |
| `25.0 – 54.9` | `MÉDIO` |
| `55.0 – 79.9` | `ALTO` |
| `80.0 – 100.0` | `CRÍTICO` |

### 3. Estimativa de Falso-Positivo (0% a 100%)

Quando nenhuma fonte aponta risco, o falso-positivo fica marcado como `N/A (Sem detecções maliciosas)`. Havendo qualquer detecção, o motor parte de uma linha de base neutra e pondera evidências conflitantes contra confirmações independentes:

- **Sinais que elevam a chance de falso-positivo (e atenuam a severidade):**
  - IP classificado no GreyNoise RIOT (infraestrutura legítima conhecida, como DNS público ou provedores cloud) ou marcado como scanner benigno.
  - Presença nas whitelists oficiais do AbuseIPDB ou do AlienVault OTX.
  - Detecção marginal no VirusTotal (apenas 1 ou 2 motores sinalizando contra dezenas de motores limpos) ou reputação comunitária positiva.
  - Alerta restrito a pulses comunitários do OTX sem confirmação nos motores primários, ou hospedagem em CDN/nuvem compartilhada com severidade moderada.

- **Sinais que reduzem a chance de falso-positivo:**
  - Amplo consenso de motores no VirusTotal e reputação comunitária negativa.
  - Alto volume de denúncias distribuídas por múltiplas redes distintas no AbuseIPDB.
  - Atividade maliciosa confirmada pelos sensores do GreyNoise ou veredito malicioso na sandbox do URLScan.io.
  - Concordância simultânea entre duas ou mais fontes independentes.

---

## Instalação e configuração (`.env`)

Requisitos: **Python 3.10+** e chaves gratuitas das APIs utilizadas.

```bash
git clone https://github.com/henriqueorchid/orchid-threat-intel-triager.git
cd orchid-threat-intel-triager

python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows (PowerShell): .venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

Crie seu arquivo `.env` a partir do modelo (o `.env` já está no `.gitignore` para nunca vazar chaves):

```bash
cp .env.example .env
```

Preencha as variáveis com suas próprias credenciais:

| Variável | Provedor | Onde obter | Observação (Free Tier) |
| :--- | :--- | :--- | :--- |
| `VT_API_KEY` | VirusTotal | [virustotal.com](https://www.virustotal.com/) | Limite típico de 4 req/min e 500 req/dia |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com/api) | Usado na análise de IPs |
| `ALIENVAULT_API_KEY` | AlienVault OTX | [otx.alienvault.com](https://otx.alienvault.com/) | Pulses, tags, atores e whitelists |
| `URLSCAN_API_KEY` | URLScan.io | [urlscan.io](https://urlscan.io/user/apikey) | Consulta histórico de varreduras e veredito |
| `GREYNOISE_API_KEY` | GreyNoise | [viz.greynoise.io](https://viz.greynoise.io/account/api-key) | Community API (RIOT / scanner noise) |

---

## Uso e demonstração

Execute a interface interativa:

```bash
python main.py
```

O menu principal oferece 4 fluxos:
- `[1]` **Investigar Endereço IP** — consulta VT, AbuseIPDB, OTX, GreyNoise e URLScan.
- `[2]` **Investigar Hash (MD5 / SHA-256)** — consulta VT e AlienVault OTX.
- `[3]` **Investigar URL / Domínio** — consulta URLScan, VT e AlienVault OTX.
- `[4]` **Varrer arquivo de Log (`.txt` / `.csv`) com Consenso em Lote** — lê arquivos em UTF-8 ou Latin-1, extrai IoCs válidos descartando IPs internos e permite escolher entre:
  - **Modo Seguro** (pausa de `15s` entre IoCs para respeitar os 4 req/min do VirusTotal gratuito);
  - **Modo Rápido** (sem pausa; caso alguma API atinja `429`, as demais continuam operando normalmente).

### Capturas de tela

**1. Menu principal e fluxos disponíveis (`[1]` a `[4]`):**

![Menu principal do Orchid Threat Intel Triager](docs/images/print%201.jpg)

**2. Consulta individual de Hash via opção `[2]` (exemplo com hash SHA-256 do WannaCry):**

Ao submeter um hash na opção `[2]`, o triager consulta VirusTotal e AlienVault OTX em paralelo, cruza a família identificada (`trojan.wannacry/wanna`), atribuição de grupo (`Lazarus Group, WannaCry`) e reputação comunitária (`-1811`), fechando o veredito em `100.0/100 (CRÍTICO)` com `1.0%` de chance de falso-positivo.

![Veredito de hash WannaCry via opção 2](docs/images/print%202.jpg)

### Exemplo de varredura de log `.txt` (opção `[4]`)

Os prints **3** e **4** abaixo foram gerados a partir da varredura do seguinte arquivo de log em `.txt`, que mistura IPs internos (`10.0.0.15`, `10.0.0.42`), nome de executável (`payload.exe`) e indicadores externos reais:

```text
[2026-11-10 12:10:04] FW-DROP SRC=161.118.214.16 DST=10.0.0.15 PROTO=TCP DPT=443
[2026-11-10 12:11:19] DNS-QUERY client=10.0.0.42 query=word-template.net action=flagged
[2026-11-10 12:12:02] EDR-ALERT host=WKST-09 file=payload.exe sha256=1941cbf3b6e705550f373990b5702220b2c1db0dceaf252ded42cdaff295c54f
[2026-11-10 12:14:55] PROXY-ALLOW dst_ip=8.8.8.8 
url=eng-polymarket.com
```

O extrator descarta automaticamente `10.0.0.15`, `10.0.0.42` e `payload.exe`, enviando apenas os **5 IoCs roteáveis** (`161.118.214.16`, `8.8.8.8`, `word-template.net`, `eng-polymarket.com` e o SHA-256) para análise paralela e consolidação final.

**3. Consulta de IP durante a varredura do log `.txt` (`161.118.214.16`):**

![Consulta de IP durante varredura de log txt](docs/images/print%203.jpg)

**4. Resumo executivo ao final da varredura do arquivo `.txt`:**

![Resumo executivo da varredura do arquivo de log txt](docs/images/print%204.jpg)

---

## Licença e autor

Distribuído sob a licença **MIT**. Veja o arquivo [LICENSE](LICENSE) para detalhes.

**Autor:** Henrique 'Orchid' Silva (2026)
