# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║                                                                           ║
# ║   High Finder Forensics v1.0.0                                            ║
# ║                                                                           ║
# ╠═══════════════════════════════════════════════════════════════════════════╣
# ║   Autor:   Percio Castelo                                                 ║
# ║   Contato: percio@evolya.com.br | contato@perciocastelo.com.br            ║
# ║   Web:     https://perciocastelo.com.br                                   ║
# ║                                                                           ║
# ║   Função:  Forense Audit in cPanel                                        ║
# ║                                                                           ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

set -o pipefail
PATH="/usr/sbin:/usr/bin:/sbin:/bin"
HF_SCRIPT_VERSION="2026-03-06-userftp-sec1"
# Marker consumed by plugin wrapper to avoid using stale hf.sh builds.
HF_USER_MODE_FTP_READY=1

usage() {
    cat <<'EOF'
Uso:
  hf.sh --version
  hf.sh [--mode full|user] [--no-color] <caminho_do_arquivo>

Modos:
  full  - analise completa (inclui logs de sistema, recomendado para root)
  user  - analise segura para usuario cPanel (sem logs privilegiados)
EOF
}

MODE="${HF_MODE:-full}"
NO_COLOR_FLAG=0

while [ $# -gt 0 ]; do
    case "$1" in
        --mode)
            [ -z "${2:-}" ] && { echo "Erro: --mode requer valor."; exit 1; }
            MODE="$2"
            shift 2
            ;;
        --mode=*)
            MODE="${1#*=}"
            shift
            ;;
        --no-color)
            NO_COLOR_FLAG=1
            shift
            ;;
        -V|--version)
            echo "$HF_SCRIPT_VERSION"
            exit 0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "Erro: opção desconhecida: $1"
            usage
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

if [ "$MODE" != "full" ] && [ "$MODE" != "user" ]; then
    echo "Erro: modo inválido '$MODE'. Use full ou user."
    exit 1
fi

if [ -z "${1:-}" ] || [ ! -f "$1" ]; then
    echo "Erro: arquivo inválido."
    usage
    exit 1
fi

# ==========================================
# PALETA DE CORES E ESTILOS
# ==========================================
if [ "$NO_COLOR_FLAG" -eq 1 ] || [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
    BOLD=''; RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; RESET=''
else
    BOLD='\033[1m'; RED='\033[1;31m'; GREEN='\033[1;32m'
    YELLOW='\033[1;33m'; BLUE='\033[1;34m'; CYAN='\033[1;36m'; RESET='\033[0m'
fi

FILE_PATH=$(realpath "$1")
FILE_OWNER=$(stat -c %U "$FILE_PATH")
USER_NAME="$FILE_OWNER"
FILE_NAME=$(basename "$FILE_PATH")
M_EPOCH=$(stat -c %Y "$FILE_PATH")
RUN_PRIVILEGED_CHECKS=1
[ "$MODE" = "user" ] && RUN_PRIVILEGED_CHECKS=0
[ "${HF_UNPRIVILEGED:-0}" = "1" ] && RUN_PRIVILEGED_CHECKS=0

is_valid_user_name() {
    [[ "$1" =~ ^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,31}$ ]]
}

# Em modo user, a conta auditada deve seguir o caminho /home/<conta>/...
if [ "$RUN_PRIVILEGED_CHECKS" -eq 0 ] && [[ "$FILE_PATH" =~ ^/home/([^/]+)/ ]]; then
    PATH_USER="${BASH_REMATCH[1]}"
    if is_valid_user_name "$PATH_USER"; then
        USER_NAME="$PATH_USER"
    fi
fi

# Permite override explícito da conta, usado pelo wrapper do plugin.
if [ -n "${HF_AUDIT_USER:-}" ] && is_valid_user_name "$HF_AUDIT_USER"; then
    USER_NAME="$HF_AUDIT_USER"
fi

if ! is_valid_user_name "$USER_NAME"; then
    echo "Erro: usuario de auditoria invalido: '$USER_NAME'."
    exit 1
fi

escape_regex() {
    printf '%s' "$1" | sed 's/[][(){}.^$*+?|\\/]/\\&/g'
}

FILE_NAME_REGEX=$(escape_regex "$FILE_NAME")
USER_NAME_REGEX=$(escape_regex "$USER_NAME")

TOLERANCIA=300 # 5 minutos para envios Web/Painel/FTP
TOLERANCIA_SSH=1800 # 30 minutos de tolerância para o login do SFTP/SSH

# ==========================================
# DETECÇÃO DE AMBIENTE (CPANEL VS DIRECTADMIN)
# ==========================================
if [ -d "/usr/local/directadmin" ]; then
    PAINEL="DirectAdmin"
elif [ -d "/usr/local/cpanel" ]; then
    PAINEL="cPanel"
else
    PAINEL="Linux Puro / Desconhecido"
fi

# ==========================================
# CABEÇALHO PRINCIPAL
# ==========================================
echo -e "${CYAN}=================================================================${RESET}"
echo -e "${BOLD}🔎 AUDITORIA FORENSE DE ARQUIVO${RESET}"
echo -e "${CYAN}=================================================================${RESET}"
echo -e " 📁 ${BOLD}Arquivo:${RESET} $FILE_NAME"
echo -e " 👤 ${BOLD}Usuário:${RESET} $USER_NAME"
echo -e " 📍 ${BOLD}Caminho:${RESET} $FILE_PATH"
echo -e " 🖥️  ${BOLD}Painel Detectado:${RESET} $PAINEL"
echo -e " 🧩 ${BOLD}Versão HF:${RESET} $HF_SCRIPT_VERSION"
if [ "$RUN_PRIVILEGED_CHECKS" -eq 0 ]; then
    echo -e " ⚙️  ${BOLD}Modo:${RESET} user (seguro para conta cPanel)"
elif [ "$(id -u)" -ne 0 ]; then
    echo -e " ⚠️  ${YELLOW}${BOLD}Aviso:${RESET} modo full sem root pode não acessar todos os logs."
fi
echo -e "${CYAN}=================================================================\n${RESET}"

# ==========================================
# FASE 1: ANÁLISE ESTÁTICA
# ==========================================
analyze_security() {
    echo -e "${BLUE}${BOLD}▶ FASE 1: ANÁLISE ESTÁTICA E SEGURANÇA${RESET}"
    echo -e "-----------------------------------------------------------------"
    
    PERMISSOES=$(stat -c "%A (%a)" "$FILE_PATH")
    TAMANHO=$(du -h "$FILE_PATH" | cut -f1)
    ATRIBUTOS=$(lsattr "$FILE_PATH" 2>/dev/null | awk '{print $1}')
    
    echo -e " 📦 ${BOLD}Tamanho:${RESET} $TAMANHO | 🔒 ${BOLD}Permissões:${RESET} $PERMISSOES"
    
    if [[ "$ATRIBUTOS" == *"i"* ]]; then
        echo -e "\n 🚨 ${RED}${BOLD}ALERTA CRÍTICO:${RESET} Arquivo com atributo IMUTÁVEL (chattr +i)."
        echo -e "    ${YELLOW}Tática comum de Rootkits/Backdoors para impedir exclusão.${RESET}"
    fi

    TIPO_REAL=$(file -b --mime-type "$FILE_PATH")
    EXTENSAO="${FILE_NAME##*.}"
    echo -e " 🪪 ${BOLD}MIME Type Real:${RESET} $TIPO_REAL"
    
    if [[ "$TIPO_REAL" == *"text"* || "$TIPO_REAL" == *"php"* ]]; then
        if [[ "$EXTENSAO" =~ (jpg|jpeg|png|gif|webp|ico)$ ]]; then
            echo -e "\n 🎭 ${RED}${BOLD}SPOOFING DETECTADO:${RESET} O arquivo finge ser imagem, mas é código!"
        fi
        
        MALWARE_SIG=$(grep -Eio "base64_decode|eval\(|system\(|shell_exec|passthru|str_rot13|gzinflate" "$FILE_PATH" | head -n 4 | tr '\n' ' ')
        if [ -n "$MALWARE_SIG" ]; then
            echo -e " ☠️  ${YELLOW}${BOLD}SINTAXE SUSPEITA:${RESET} ${MALWARE_SIG}"
        fi
    fi

    HASH_SHA256=$(sha256sum "$FILE_PATH" | awk '{print $1}')
    echo -e " 🧬 ${BOLD}Hash SHA-256:${RESET} $HASH_SHA256"
    echo -e " 🔗 ${BOLD}VirusTotal:${RESET}   https://www.virustotal.com/gui/file/$HASH_SHA256\n"
}

# ==========================================
# FASE 2: RASTREAMENTO DE LOGS
# ==========================================
echo_match() {
    local SERVICO=$1; local IP=$2; local DATA=$3; local ALVO=$4; local ORIGEM=$5; local DETALHE=$6
    echo -e " ${GREEN}✅ MATCH ENCONTRADO (${SERVICO})${RESET}"
    echo -e "    ${BOLD}IP Origem:${RESET} $IP"
    echo -e "    ${BOLD}Data/Hora:${RESET} $DATA"
    [ -n "$ALVO" ] && echo -e "    ${BOLD}Ação/Alvo:${RESET} $ALVO"
    echo -e "    ${BOLD}Log Fonte:${RESET} $ORIGEM"
    echo -e "    ${BOLD}Detalhe:  ${RESET} ${DETALHE:0:110}...\n"
}

search_panel_api() {
    echo -e "⏳ ${YELLOW}Buscando requisições no Painel de Controle (API)...${RESET}"
    
    if [ "$PAINEL" == "cPanel" ]; then
        local ALVOS=("/usr/local/cpanel/logs/access_log" "/usr/local/cpanel/logs/access_log.*" "/usr/local/cpanel/logs/archive/access_log.*")
        for mask in "${ALVOS[@]}"; do
            for f in $mask; do
                [ ! -f "$f" ] && continue
                zgrep -ahE "POST .*/execute/(Fileman|Fileop)/(upload_files|savefile|fileop|fmmkdir)" "$f" 2>/dev/null | grep -F "$USER_NAME" | while read -r line; do
                    RAW_DATE=$(echo "$line" | grep -oE "[0-9]{2}/[0-9]{2}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}")
                    if [ -n "$RAW_DATE" ]; then
                        CLEAN_DATE="${RAW_DATE/:/ }"
                        LOG_EPOCH=$(date -u -d "$CLEAN_DATE" +%s 2>/dev/null)
                        if [ -n "$LOG_EPOCH" ]; then
                            DIFF=$((LOG_EPOCH - M_EPOCH)); [ $DIFF -lt 0 ] && DIFF_ABS=$(( -DIFF )) || DIFF_ABS=$DIFF
                            DIST_FUSO=$((DIFF_ABS - 10800)); [ $DIST_FUSO -lt 0 ] && DIST_FUSO=$(( -DIST_FUSO ))
                            if [ "$DIFF_ABS" -lt "$TOLERANCIA" ] || [ "$DIST_FUSO" -lt "$TOLERANCIA" ]; then
                                IP=$(echo "$line" | awk '{print $1}')
                                ACAO=$(echo "$line" | grep -oE "(upload_files|savefile|fileop|fmmkdir)" | head -n 1)
                                echo_match "API CPANEL" "$IP" "$RAW_DATE (UTC)" "$ACAO" "$f" "$line"
                            fi
                        fi
                    fi
                done
            done
        done
        
    elif [ "$PAINEL" == "DirectAdmin" ]; then
        local ALVOS=("/var/log/directadmin/20*.log" "/var/log/directadmin/system.log" "/var/log/directadmin/login.log")
        for mask in "${ALVOS[@]}"; do
            for f in $mask; do
                [ ! -f "$f" ] && continue
                zgrep -ahE "CMD_FILE_MANAGER" "$f" 2>/dev/null | grep -F "$USER_NAME" | while read -r line; do
                    # DA Date Format: 2026:03:05-16:08:18
                    RAW_DATE=$(echo "$line" | grep -oE "^[0-9]{4}:[0-9]{2}:[0-9]{2}-[0-9]{2}:[0-9]{2}:[0-9]{2}")
                    if [ -n "$RAW_DATE" ]; then
                        # Transforma 2026:03:05-16:08:18 em 2026-03-05 16:08:18
                        CLEAN_DATE=$(echo "$RAW_DATE" | sed 's/^\([0-9]\{4\}\):\([0-9]\{2\}\):\([0-9]\{2\}\)-\([0-9]\{2\}\):\([0-9]\{2\}\):\([0-9]\{2\}\)/\1-\2-\3 \4:\5:\6/')
                        LOG_EPOCH=$(date -d "$CLEAN_DATE" +%s 2>/dev/null)
                        if [ -n "$LOG_EPOCH" ]; then
                            DIFF=$((LOG_EPOCH - M_EPOCH)); [ $DIFF -lt 0 ] && DIFF_ABS=$(( -DIFF )) || DIFF_ABS=$DIFF
                            if [ "$DIFF_ABS" -lt "$TOLERANCIA" ]; then
                                IP=$(echo "$line" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | head -1)
                                echo_match "API DIRECTADMIN" "$IP" "$RAW_DATE" "Gerenciador de Arquivos" "$f" "$line"
                            fi
                        fi
                    fi
                done
            done
        done
    fi
}

search_apache() {
    echo -e "⏳ ${YELLOW}Buscando requisições no Servidor Web (Apache/Nginx)...${RESET}"
    local DOMAINS=""
    local ALVOS=()
    local REQUEST_REGEX='"POST '

    if [ "$RUN_PRIVILEGED_CHECKS" -eq 0 ]; then
        # Em modo user, aceita GET e POST porque logs acessíveis da conta são limitados.
        REQUEST_REGEX='"(GET|POST) '
    fi

    # Mapeia domínios de acordo com o painel
    if [ "$PAINEL" == "cPanel" ]; then
        local CP_USER_FILE="/var/cpanel/users/$USER_NAME"
        if [ "$RUN_PRIVILEGED_CHECKS" -eq 1 ] && [ -r "$CP_USER_FILE" ]; then
            DOMAINS=$(grep -E "^DNS=|^XDNS[0-9]*=" "$CP_USER_FILE" | cut -d= -f2)
        fi

        if [ -z "$DOMAINS" ] && [ "$RUN_PRIVILEGED_CHECKS" -eq 0 ]; then
            ALVOS+=("/home/$USER_NAME/logs/*" "/home/$USER_NAME/apachelogs/*")
        fi

        for DOMAIN in $DOMAINS; do
            if [ "$RUN_PRIVILEGED_CHECKS" -eq 1 ]; then
                ALVOS+=("/usr/local/apache/domlogs/$DOMAIN" "/usr/local/apache/domlogs/$DOMAIN-ssl_log" "/usr/local/apache/domlogs/$DOMAIN*.gz")
            fi
            ALVOS+=("/home/$USER_NAME/logs/$DOMAIN*" "/home/$USER_NAME/apachelogs/$DOMAIN*")
            if [ "$RUN_PRIVILEGED_CHECKS" -eq 1 ]; then
                for bkp in /home*/SERVER_BACKUP-*/home/apachelogs/$USER_NAME/$DOMAIN*; do [ -f "$bkp" ] && ALVOS+=("$bkp"); done
            fi
        done
    elif [ "$PAINEL" == "DirectAdmin" ]; then
        local DA_USER_FILE="/usr/local/directadmin/data/users/$USER_NAME/domains.list"
        if [ "$RUN_PRIVILEGED_CHECKS" -eq 1 ] && [ -r "$DA_USER_FILE" ]; then
            DOMAINS=$(cat "$DA_USER_FILE" 2>/dev/null)
        fi

        if [ -z "$DOMAINS" ] && [ "$RUN_PRIVILEGED_CHECKS" -eq 0 ]; then
            ALVOS+=("/home/$USER_NAME/domains/*/logs/*")
        fi

        for DOMAIN in $DOMAINS; do
            if [ "$RUN_PRIVILEGED_CHECKS" -eq 1 ]; then
                ALVOS+=("/var/log/httpd/domains/$DOMAIN.log" "/var/log/httpd/domains/$DOMAIN.error.log" "/var/log/httpd/domains/$DOMAIN*.gz")
                ALVOS+=("/var/log/nginx/domains/$DOMAIN.log" "/var/log/nginx/domains/$DOMAIN*.gz")
            fi
        done
    fi

    # Lógica unificada para logs de acesso web (Padrão Apache)
    for mask in "${ALVOS[@]}"; do
        for f in $mask; do
            [ ! -f "$f" ] && continue
            [[ "$f" =~ "bytes_log" ]] && continue
            zgrep -ahE "$REQUEST_REGEX" "$f" 2>/dev/null | while read -r line; do
                RAW_DATE=$(echo "$line" | awk -F'[' '{print $2}' | awk -F']' '{print $1}')
                IP=$(echo "$line" | awk '{print $1}')
                URL=$(echo "$line" | awk '{print $7}')
                METHOD=$(echo "$line" | awk -F'"' '{print $2}' | awk '{print $1}')
                [ -z "$METHOD" ] && METHOD="REQ"

                IS_TARGET_URL=0
                [[ "$URL" == *"/$FILE_NAME"* ]] && IS_TARGET_URL=1

                SHOULD_PRINT=0
                if [ -n "$RAW_DATE" ]; then
                    CLEAN_DATE=$(echo "$RAW_DATE" | sed 's/\//-/g' | sed 's/:/ /')
                    LOG_EPOCH=$(date -d "$CLEAN_DATE" +%s 2>/dev/null)
                    if [ -n "$LOG_EPOCH" ]; then
                        DIFF=$((LOG_EPOCH - M_EPOCH)); [ $DIFF -lt 0 ] && DIFF_ABS=$(( -DIFF )) || DIFF_ABS=$DIFF
                        if [ "$DIFF_ABS" -lt "$TOLERANCIA" ]; then
                            SHOULD_PRINT=1
                        fi
                    fi
                fi

                # No modo user, mantém evidência se o URL é do arquivo auditado.
                if [ "$RUN_PRIVILEGED_CHECKS" -eq 0 ] && [ "$IS_TARGET_URL" -eq 1 ]; then
                    SHOULD_PRINT=1
                fi

                [ "$SHOULD_PRINT" -ne 1 ] && continue

                SERVICO="HTTP/S ${METHOD}"
                ALVO="$URL"
                if [ "$RUN_PRIVILEGED_CHECKS" -eq 0 ]; then
                    SERVICO="HTTP/S USER LOG ${METHOD}"
                fi
                [ "$IS_TARGET_URL" -eq 1 ] && ALVO="${URL} (arquivo-alvo)"
                echo_match "$SERVICO" "$IP" "${RAW_DATE:-Sem data}" "$ALVO" "$f" "$line"
            done
        done
    done
}

search_ftp() {
    echo -e "⏳ ${YELLOW}Buscando conexões via FTP (Pure-FTPd / ProFTPd)...${RESET}"
    local ALVOS=("/var/log/messages*" "/var/log/xferlog*" "/var/log/proftpd/access.log*")
    
    for mask in "${ALVOS[@]}"; do
        for f in $mask; do
            [ ! -f "$f" ] && continue
            
            # 1. Checagem Pure-FTPd (Syslog)
            zgrep -ahE "pure-ftpd.*${FILE_NAME_REGEX}.*uploaded" "$f" 2>/dev/null | while read -r line; do
                RAW_DATE=$(echo "$line" | grep -oE "^[A-Z][a-z]{2} [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2}")
                if [ -n "$RAW_DATE" ]; then
                    LOG_EPOCH=$(date -d "$RAW_DATE" +%s 2>/dev/null)
                    if [ -n "$LOG_EPOCH" ]; then
                        DIFF=$((LOG_EPOCH - M_EPOCH)); [ $DIFF -lt 0 ] && DIFF_ABS=$(( -DIFF )) || DIFF_ABS=$DIFF
                        if [ "$DIFF_ABS" -lt "$TOLERANCIA" ]; then
                            IP=$(echo "$line" | grep -oE "\([^\)]+\)" | head -1 | tr -d '()')
                            echo_match "PURE-FTPD" "$IP" "$RAW_DATE" "Upload" "$f" "$line"
                        fi
                    fi
                fi
            done
            
            # 2. Checagem ProFTPd (Formato xferlog, comum no DirectAdmin)
            zgrep -ahE " i r ${USER_NAME_REGEX} .*${FILE_NAME_REGEX}" "$f" 2>/dev/null | while read -r line; do
                # Formato: Thu Mar  5 16:08:18 2026 1 191.189.27.205 4096 /home/user/file b _ i r user ftp 0 * c
                RAW_DATE=$(echo "$line" | awk '{print $1" "$2" "$3" "$4" "$5}')
                if [ -n "$RAW_DATE" ]; then
                    LOG_EPOCH=$(date -d "$RAW_DATE" +%s 2>/dev/null)
                    if [ -n "$LOG_EPOCH" ]; then
                        DIFF=$((LOG_EPOCH - M_EPOCH)); [ $DIFF -lt 0 ] && DIFF_ABS=$(( -DIFF )) || DIFF_ABS=$DIFF
                        if [ "$DIFF_ABS" -lt "$TOLERANCIA" ]; then
                            IP=$(echo "$line" | awk '{print $7}')
                            echo_match "PROFTPD" "$IP" "$RAW_DATE" "Upload (xferlog)" "$f" "$line"
                        fi
                    fi
                fi
            done
        done
    done
}

search_user_ftp_logs() {
    echo -e "⏳ ${YELLOW}Buscando logs FTP acessíveis da conta...${RESET}"
    local ALVOS=(
        "/home/$USER_NAME/logs/*ftp*_log*"
        "/home/$USER_NAME/logs/*xferlog*"
        "/home/$USER_NAME/logs/*ftp*"
    )
    local CANDIDATOS=0
    local LEGIVEIS=0
    local MATCHES=0
    local BLOQUEADOS=0
    declare -A ARQUIVOS_VISTOS=()

    for mask in "${ALVOS[@]}"; do
        for f in $mask; do
            [ ! -f "$f" ] && continue
            [ -n "${ARQUIVOS_VISTOS["$f"]+x}" ] && continue
            ARQUIVOS_VISTOS["$f"]=1
            CANDIDATOS=$((CANDIDATOS + 1))
            if [ ! -r "$f" ]; then
                BLOQUEADOS=$((BLOQUEADOS + 1))
                continue
            fi
            LEGIVEIS=$((LEGIVEIS + 1))

            while IFS= read -r line; do
                [ -z "$line" ] && continue
                RAW_DATE=$(echo "$line" | awk '{print $1" "$2" "$3" "$4" "$5}')
                IP=$(echo "$line" | awk '{print $7}')
                ALVO=$(echo "$line" | awk '{print $9}')
                LOG_USER=$(echo "$line" | awk '{print $14}')
                IS_TARGET_PATH=0

                if [ "$ALVO" = "$FILE_PATH" ] || [[ "$ALVO" == *"/$FILE_NAME" ]]; then
                    IS_TARGET_PATH=1
                fi

                # Mantem filtro de usuario para reduzir ruído, mas não descarta o arquivo-alvo.
                if [ "$LOG_USER" != "$USER_NAME" ] && [ "$IS_TARGET_PATH" -ne 1 ]; then
                    continue
                fi

                if [ -n "$RAW_DATE" ]; then
                    LOG_EPOCH=$(date -d "$RAW_DATE" +%s 2>/dev/null)
                    if [ -n "$LOG_EPOCH" ]; then
                        DIFF=$((LOG_EPOCH - M_EPOCH)); [ $DIFF -lt 0 ] && DIFF_ABS=$(( -DIFF )) || DIFF_ABS=$DIFF
                        if [ "$DIFF_ABS" -lt "$TOLERANCIA" ]; then
                            MATCHES=$((MATCHES + 1))
                            echo_match "FTP USER LOG" "${IP:-N/A}" "$RAW_DATE" "${ALVO:-Upload}" "$f" "$line"
                            continue
                        fi
                    fi
                fi

                # Mesmo fora da tolerância, mantém match quando o arquivo auditado aparece no log FTP da conta.
                MATCHES=$((MATCHES + 1))
                if [ "$IS_TARGET_PATH" -eq 1 ]; then
                    echo_match "FTP USER LOG" "${IP:-N/A}" "${RAW_DATE:-Sem data}" "${ALVO:-Upload} (arquivo-alvo)" "$f" "$line"
                else
                    echo_match "FTP USER LOG" "${IP:-N/A}" "${RAW_DATE:-Sem data}" "${ALVO:-Upload}" "$f" "$line"
                fi
            done < <(zgrep -ahF "/$FILE_NAME" "$f" 2>/dev/null || true)
        done
    done

    if [ "$CANDIDATOS" -eq 0 ]; then
        echo -e " ℹ️  ${YELLOW}Modo user:${RESET} nenhum arquivo de log FTP encontrado em /home/$USER_NAME/logs."
        return
    fi

    if [ "$LEGIVEIS" -eq 0 ]; then
        echo -e " ⚠️  ${YELLOW}Modo user:${RESET} logs FTP existem, mas sem permissão de leitura para esta conta ($BLOQUEADOS bloqueados)."
        return
    fi

    if [ "$MATCHES" -eq 0 ]; then
        echo -e " ℹ️  ${YELLOW}Modo user:${RESET} nenhum match FTP para ${FILE_NAME} nos logs acessíveis."
    fi
}

search_ssh_sftp() {
    echo -e "⏳ ${YELLOW}Buscando conexões via SSH/SFTP...${RESET}"
    local ALVOS=("/var/log/secure" "/var/log/secure-*" "/var/log/secure.*" "/var/log/auth.log*")
    for mask in "${ALVOS[@]}"; do
        for f in $mask; do
            [ ! -f "$f" ] && continue
            zgrep -ahE "sshd.*Accepted.*${USER_NAME_REGEX}" "$f" 2>/dev/null | while read -r line; do
                RAW_DATE=$(echo "$line" | grep -oE "^[A-Z][a-z]{2} [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2}")
                if [ -n "$RAW_DATE" ]; then
                    LOG_EPOCH=$(date -d "$RAW_DATE" +%s 2>/dev/null)
                    if [ -n "$LOG_EPOCH" ]; then
                        DIFF=$((LOG_EPOCH - M_EPOCH)); [ $DIFF -lt 0 ] && DIFF_ABS=$(( -DIFF )) || DIFF_ABS=$DIFF
                        if [ "$DIFF_ABS" -lt "$TOLERANCIA_SSH" ]; then
                            IP=$(echo "$line" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | head -1)
                            echo_match "SSH/SFTP LOGIN" "$IP" "$RAW_DATE" "Sessão Aberta" "$f" "$line"
                        fi
                    fi
                fi
            done
        done
    done
}

search_terminal() {
    echo -e "⏳ ${YELLOW}Buscando escalonamento de privilégio e comandos locais...${RESET}"
    
    # 1. Busca por alguém que virou o usuário dono do arquivo (su/sudo)
    local ALVOS=("/var/log/secure" "/var/log/secure-*" "/var/log/secure.*" "/var/log/auth.log*")
    for mask in "${ALVOS[@]}"; do
        for f in $mask; do
            [ ! -f "$f" ] && continue
            zgrep -ahE "(sudo|su).*session opened for user ${USER_NAME_REGEX}" "$f" 2>/dev/null | while read -r line; do
                RAW_DATE=$(echo "$line" | grep -oE "^[A-Z][a-z]{2} [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2}")
                if [ -n "$RAW_DATE" ]; then
                    LOG_EPOCH=$(date -d "$RAW_DATE" +%s 2>/dev/null)
                    if [ -n "$LOG_EPOCH" ]; then
                        DIFF=$((LOG_EPOCH - M_EPOCH)); [ $DIFF -lt 0 ] && DIFF_ABS=$(( -DIFF )) || DIFF_ABS=$DIFF
                        if [ "$DIFF_ABS" -lt "$TOLERANCIA_SSH" ]; then
                            echo_match "ESCALONAMENTO (SU/SUDO)" "Terminal Local" "$RAW_DATE" "Sessão Aberta" "$f" "$line"
                        fi
                    fi
                fi
            done
        done
    done

    # 2. Busca no histórico de comandos do usuário (Sem precisão de tempo)
    local BASH_HIST="/root/.bash_history"
    [ "$USER_NAME" != "root" ] && BASH_HIST="/home/$USER_NAME/.bash_history"
    
    if [ -f "$BASH_HIST" ]; then
        # Pega as últimas 500 linhas do histórico para ver se o nome do arquivo foi digitado
        MATCH_HIST=$(tail -n 500 "$BASH_HIST" | grep -Fi "$FILE_NAME" | head -n 3)
        if [ -n "$MATCH_HIST" ]; then
            echo -e " ${GREEN}✅ MATCH ENCONTRADO (BASH HISTORY)${RESET}"
            echo -e "    ${BOLD}Aviso:${RESET} O histórico não possui carimbo de tempo por padrão."
            echo -e "    ${BOLD}Log Fonte:${RESET} $BASH_HIST"
            echo -e "    ${BOLD}Comandos suspeitos:${RESET}"
            echo -e "    $MATCH_HIST\n"
        fi
    fi
}

# Ordem de Execução
analyze_security
echo -e "${BLUE}${BOLD}▶ FASE 2: RASTREAMENTO DE REDE E LOGS${RESET}"
echo -e "-----------------------------------------------------------------"
search_apache
if [ "$RUN_PRIVILEGED_CHECKS" -eq 1 ]; then
    search_panel_api
    search_ftp
    search_ssh_sftp
    search_terminal
else
    search_user_ftp_logs
    echo -e " ℹ️  ${YELLOW}Modo user:${RESET} verificações privilegiadas (API painel, SSH e terminal) foram ignoradas."
fi

echo -e "\n${GREEN}${BOLD}🏁 AUDITORIA FINALIZADA.${RESET}\n"