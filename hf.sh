#!/usr/bin/env bash
# +============================================================================+
# | hf.sh                                                                      |
# | High Forensic (cPanel / DirectAdmin) v1.1.0                                |
# | Read-only forensic auditor correlating static file metadata, MIME          |
# | spoofing, immutable flags, SHA-256 / VirusTotal links, and time-window     |
# | web, panel, FTP, SSH/SFTP, and shell history logs.                         |
# |                                                                            |
# | Author:  Percio Castelo                                                    |
# | Contact: percio@evolya.com.br | contato@perciocastelo.com.br               |
# | Web:     https://perciocastelo.com.br                                      |
# | Repo:    https://github.com/sr00t3d/cpanel-hf                              |
# |                                                                            |
# | Copyright 2024-2026 Percio Castelo                                         |
# | SPDX-License-Identifier: Apache-2.0                                        |
# +============================================================================+

set -o pipefail
PATH="/usr/sbin:/usr/bin:/sbin:/bin"
HF_SCRIPT_VERSION="2026-03-06-userftp-sec1"
# Marker consumed by plugin wrapper to avoid using stale hf.sh builds.
HF_USER_MODE_FTP_READY=1

normalize_lang_code() {
    local raw normalized
    raw=$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr '-' '_')
    raw=${raw%%.*}
    normalized=${raw#*=}

    case "$normalized" in
        en|en_*|english*) echo "en"; return 0 ;;
        pt|pt_*|portugu*) echo "pt"; return 0 ;;
    esac
    return 1
}

detect_lang_from_env() {
    local key value lang
    for key in HF_LANG HF_UI_LANG CPANEL_LOCALE CPANEL_LANG LC_ALL LC_MESSAGES LANG HTTP_ACCEPT_LANGUAGE; do
        value="${!key:-}"
        [ -z "$value" ] && continue
        if lang=$(normalize_lang_code "$value"); then
            echo "$lang"
            return 0
        fi
    done
    return 1
}

detect_lang_for_user() {
    local user="$1"
    local lang line key value user_file

    if lang=$(detect_lang_from_env); then
        echo "$lang"
        return 0
    fi

    if [[ "$user" =~ ^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,31}$ ]]; then
        user_file="/var/cpanel/users/$user"
        if [ -r "$user_file" ]; then
            while IFS= read -r line; do
                key="${line%%=*}"
                value="${line#*=}"
                case "$key" in
                    LOCALE|LANG)
                        if lang=$(normalize_lang_code "$value"); then
                            echo "$lang"
                            return 0
                        fi
                        ;;
                esac
            done < "$user_file"
        fi

        for path in "/home/$user/.cpanel/nvdata/lang" "/home/$user/.cpanel/lang"; do
            [ ! -r "$path" ] && continue
            value=$(cat "$path" 2>/dev/null || true)
            if lang=$(normalize_lang_code "$value"); then
                echo "$lang"
                return 0
            fi
        done
    fi

    echo "pt"
}

L() {
    if [ "${HF_LANG_CODE:-pt}" = "en" ]; then
        printf '%s' "$2"
    else
        printf '%s' "$1"
    fi
}

HF_LANG_CODE="$(detect_lang_from_env 2>/dev/null || true)"
[ -z "$HF_LANG_CODE" ] && HF_LANG_CODE="pt"

usage() {
    if [ "${HF_LANG_CODE:-pt}" = "en" ]; then
        cat <<'EOF'
Usage:
  hf.sh --version
  hf.sh [--mode full|user] [--no-color] <file_path>

Modes:
  full  - complete analysis (includes system logs, recommended for root)
  user  - safe analysis for cPanel account (no privileged logs)
EOF
    else
        cat <<'EOF'
Uso:
  hf.sh --version
  hf.sh [--mode full|user] [--no-color] <caminho_do_arquivo>

Modos:
  full  - analise completa (inclui logs de sistema, recomendado para root)
  user  - analise segura para usuario cPanel (sem logs privilegiados)
EOF
    fi
}

MODE="${HF_MODE:-full}"
NO_COLOR_FLAG=0

while [ $# -gt 0 ]; do
    case "$1" in
        --mode)
            [ -z "${2:-}" ] && { echo "$(L "Erro: --mode requer valor." "Error: --mode requires a value.")"; exit 1; }
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
            echo "$(L "Erro: opção desconhecida: $1" "Error: unknown option: $1")"
            usage
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

if [ "$MODE" != "full" ] && [ "$MODE" != "user" ]; then
    echo "$(L "Erro: modo inválido '$MODE'. Use full ou user." "Error: invalid mode '$MODE'. Use full or user.")"
    exit 1
fi

if [ -z "${1:-}" ] || [ ! -f "$1" ]; then
    echo "$(L "Erro: arquivo inválido." "Error: invalid file.")"
    usage
    exit 1
fi

# ==========================================
# COLOR AND STYLE PALETTE
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

# In user mode, the audited account should follow the path /home/<account>/...
if [ "$RUN_PRIVILEGED_CHECKS" -eq 0 ] && [[ "$FILE_PATH" =~ ^/home/([^/]+)/ ]]; then
    PATH_USER="${BASH_REMATCH[1]}"
    if is_valid_user_name "$PATH_USER"; then
        USER_NAME="$PATH_USER"
    fi
fi

# Allows explicit account override, used by the plugin wrapper.
if [ -n "${HF_AUDIT_USER:-}" ] && is_valid_user_name "$HF_AUDIT_USER"; then
    USER_NAME="$HF_AUDIT_USER"
fi

if ! is_valid_user_name "$USER_NAME"; then
    echo "$(L "Erro: usuario de auditoria invalido: '$USER_NAME'." "Error: invalid audit user: '$USER_NAME'.")"
    exit 1
fi

HF_LANG_CODE="$(detect_lang_for_user "$USER_NAME")"

escape_regex() {
    printf '%s' "$1" | sed 's/[][(){}.^$*+?|\\/]/\\&/g'
}

FILE_NAME_REGEX=$(escape_regex "$FILE_NAME")
USER_NAME_REGEX=$(escape_regex "$USER_NAME")

TOLERANCIA=300 # 5 minutes for Web/Dashboard/FTP submissions
TOLERANCIA_SSH=1800 # 30-minute grace period for SFTP/SSH login.

# ==========================================
# DETECÇÃO DE AMBIENTE (CPANEL VS DIRECTADMIN)
# ==========================================
if [ -d "/usr/local/directadmin" ]; then
    PAINEL="DirectAdmin"
elif [ -d "/usr/local/cpanel" ]; then
    PAINEL="cPanel"
else
    PAINEL="$(L "Linux Puro / Desconhecido" "Bare Linux / Unknown")"
fi

# ==========================================
# MAIN HEADER
# ==========================================
echo -e "${CYAN}=================================================================${RESET}"
echo -e "${BOLD}🔎 $(L "AUDITORIA FORENSE DE ARQUIVO" "FILE FORENSIC AUDIT")${RESET}"
echo -e "${CYAN}=================================================================${RESET}"
echo -e " 📁 ${BOLD}$(L "Arquivo" "File"):${RESET} $FILE_NAME"
echo -e " 👤 ${BOLD}$(L "Usuário" "User"):${RESET} $USER_NAME"
echo -e " 📍 ${BOLD}$(L "Caminho" "Path"):${RESET} $FILE_PATH"
echo -e " 🖥️  ${BOLD}$(L "Painel Detectado" "Detected Panel"):${RESET} $PAINEL"
echo -e " 🧩 ${BOLD}$(L "Versão HF" "HF Version"):${RESET} $HF_SCRIPT_VERSION"
if [ "$RUN_PRIVILEGED_CHECKS" -eq 0 ]; then
    echo -e " ⚙️  ${BOLD}$(L "Modo" "Mode"):${RESET} $(L "user (seguro para conta cPanel)" "user (safe for cPanel account)")"
elif [ "$(id -u)" -ne 0 ]; then
    echo -e " ⚠️  ${YELLOW}${BOLD}$(L "Aviso" "Warning"):${RESET} $(L "modo full sem root pode não acessar todos os logs." "full mode without root may not access all logs.")"
fi
echo -e "${CYAN}=================================================================\n${RESET}"

# ==========================================
# PHASE 1: STATIC ANALYSIS
# ==========================================
analyze_security() {
    echo -e "${BLUE}${BOLD}▶ $(L "FASE 1: ANÁLISE ESTÁTICA E SEGURANÇA" "PHASE 1: STATIC ANALYSIS AND SECURITY")${RESET}"
    echo -e "-----------------------------------------------------------------"
    
    PERMISSOES=$(stat -c "%A (%a)" "$FILE_PATH")
    TAMANHO=$(du -h "$FILE_PATH" | cut -f1)
    ATRIBUTOS=$(lsattr "$FILE_PATH" 2>/dev/null | awk '{print $1}')
    
    echo -e " 📦 ${BOLD}$(L "Tamanho" "Size"):${RESET} $TAMANHO | 🔒 ${BOLD}$(L "Permissões" "Permissions"):${RESET} $PERMISSOES"
    
    if [[ "$ATRIBUTOS" == *"i"* ]]; then
        echo -e "\n 🚨 ${RED}${BOLD}$(L "ALERTA CRÍTICO" "CRITICAL ALERT"):${RESET} $(L "Arquivo com atributo IMUTÁVEL (chattr +i)." "File has IMMUTABLE attribute (chattr +i).")"
        echo -e "    ${YELLOW}$(L "Tática comum de Rootkits/Backdoors para impedir exclusão." "Common Rootkit/Backdoor tactic to prevent deletion.")${RESET}"
    fi

    TIPO_REAL=$(file -b --mime-type "$FILE_PATH")
    EXTENSAO="${FILE_NAME##*.}"
    echo -e " 🪪 ${BOLD}$(L "MIME Type Real" "Real MIME Type"):${RESET} $TIPO_REAL"
    
    if [[ "$TIPO_REAL" == *"text"* || "$TIPO_REAL" == *"php"* ]]; then
        if [[ "$EXTENSAO" =~ (jpg|jpeg|png|gif|webp|ico)$ ]]; then
            echo -e "\n 🎭 ${RED}${BOLD}$(L "SPOOFING DETECTADO" "SPOOFING DETECTED"):${RESET} $(L "O arquivo finge ser imagem, mas é código!" "The file pretends to be an image, but it is code!")"
        fi
        
        MALWARE_SIG=$(grep -Eio "base64_decode|eval\(|system\(|shell_exec|passthru|str_rot13|gzinflate" "$FILE_PATH" | head -n 4 | tr '\n' ' ')
        if [ -n "$MALWARE_SIG" ]; then
            echo -e " ☠️  ${YELLOW}${BOLD}$(L "SINTAXE SUSPEITA" "SUSPICIOUS SYNTAX"):${RESET} ${MALWARE_SIG}"
        fi
    fi

    HASH_SHA256=$(sha256sum "$FILE_PATH" | awk '{print $1}')
    echo -e " 🧬 ${BOLD}$(L "Hash SHA-256" "SHA-256 Hash"):${RESET} $HASH_SHA256"
    echo -e " 🔗 ${BOLD}VirusTotal:${RESET}   https://www.virustotal.com/gui/file/$HASH_SHA256\n"
}

# ==========================================
# PHASE 2: LOG TRACKING
# ==========================================
echo_match() {
    local SERVICO=$1; local IP=$2; local DATA=$3; local ALVO=$4; local ORIGEM=$5; local DETALHE=$6
    if [ "$HF_LANG_CODE" = "en" ]; then
        echo -e " ${GREEN}✅ MATCH FOUND (${SERVICO})${RESET}"
        echo -e "    ${BOLD}Source IP:${RESET} $IP"
        echo -e "    ${BOLD}Date/Time:${RESET} $DATA"
        [ -n "$ALVO" ] && echo -e "    ${BOLD}Action/Target:${RESET} $ALVO"
        echo -e "    ${BOLD}Log Source:${RESET} $ORIGEM"
        echo -e "    ${BOLD}Detail:   ${RESET} ${DETALHE:0:110}...\n"
    else
        echo -e " ${GREEN}✅ MATCH ENCONTRADO (${SERVICO})${RESET}"
        echo -e "    ${BOLD}IP Origem:${RESET} $IP"
        echo -e "    ${BOLD}Data/Hora:${RESET} $DATA"
        [ -n "$ALVO" ] && echo -e "    ${BOLD}Ação/Alvo:${RESET} $ALVO"
        echo -e "    ${BOLD}Log Fonte:${RESET} $ORIGEM"
        echo -e "    ${BOLD}Detalhe:  ${RESET} ${DETALHE:0:110}...\n"
    fi
}

search_panel_api() {
    echo -e "⏳ ${YELLOW}$(L "Buscando requisições no Painel de Controle (API)..." "Searching Control Panel (API) requests...")${RESET}"
    
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
                                echo_match "API DIRECTADMIN" "$IP" "$RAW_DATE" "$(L "Gerenciador de Arquivos" "File Manager")" "$f" "$line"
                            fi
                        fi
                    fi
                done
            done
        done
    fi
}

search_apache() {
    echo -e "⏳ ${YELLOW}$(L "Buscando requisições no Servidor Web (Apache/Nginx)..." "Searching Web Server requests (Apache/Nginx)...")${RESET}"
    local DOMAINS=""
    local ALVOS=()
    local REQUEST_REGEX='"POST '

    if [ "$RUN_PRIVILEGED_CHECKS" -eq 0 ]; then
        # In user mode, it accepts GET and POST requests because accessible account logs are limited.
        REQUEST_REGEX='"(GET|POST) '
    fi

    # Maps domains according to the panel.
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

    # Unified logic for web access logs (Apache standard or Nginx), filtering by request method and file name, with time tolerance.
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

                # In user mode, retains evidence if the URL is from the audited file.
                if [ "$RUN_PRIVILEGED_CHECKS" -eq 0 ] && [ "$IS_TARGET_URL" -eq 1 ]; then
                    SHOULD_PRINT=1
                fi

                [ "$SHOULD_PRINT" -ne 1 ] && continue

                SERVICO="HTTP/S ${METHOD}"
                ALVO="$URL"
                if [ "$RUN_PRIVILEGED_CHECKS" -eq 0 ]; then
                    SERVICO="HTTP/S USER LOG ${METHOD}"
                fi
                [ "$IS_TARGET_URL" -eq 1 ] && ALVO="${URL} $(L "(arquivo-alvo)" "(target-file)")"
                echo_match "$SERVICO" "$IP" "${RAW_DATE:-$(L "Sem data" "No date")}" "$ALVO" "$f" "$line"
            done
        done
    done
}

search_ftp() {
    echo -e "⏳ ${YELLOW}$(L "Buscando conexões via FTP (Pure-FTPd / ProFTPd)..." "Searching FTP connections (Pure-FTPd / ProFTPd)...")${RESET}"
    local ALVOS=("/var/log/messages*" "/var/log/xferlog*" "/var/log/proftpd/access.log*")
    
    for mask in "${ALVOS[@]}"; do
        for f in $mask; do
            [ ! -f "$f" ] && continue
            
            # 1. Pure-FTPd (Syslog) check
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
            
            # 2. ProFTPd Check (xferlog format, common in DirectAdmin)
            zgrep -ahE " i r ${USER_NAME_REGEX} .*${FILE_NAME_REGEX}" "$f" 2>/dev/null | while read -r line; do
                # Format: Thu Mar  5 16:08:18 2026 1 191.189.27.205 4096 /home/user/file b _ i r user ftp 0 * c
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
    echo -e "⏳ ${YELLOW}$(L "Buscando logs FTP acessíveis da conta..." "Searching account-accessible FTP logs...")${RESET}"
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

                # Maintain user filter to reduce noise, but do not discard the target file.
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

                # Even outside the tolerance, retain match when the audited file appears in the account's FTP log.
                MATCHES=$((MATCHES + 1))
                if [ "$IS_TARGET_PATH" -eq 1 ]; then
                    echo_match "FTP USER LOG" "${IP:-N/A}" "${RAW_DATE:-$(L "Sem data" "No date")}" "${ALVO:-Upload} $(L "(arquivo-alvo)" "(target-file)")" "$f" "$line"
                else
                    echo_match "FTP USER LOG" "${IP:-N/A}" "${RAW_DATE:-$(L "Sem data" "No date")}" "${ALVO:-Upload}" "$f" "$line"
                fi
            done < <(zgrep -ahF "/$FILE_NAME" "$f" 2>/dev/null || true)
        done
    done

    if [ "$CANDIDATOS" -eq 0 ]; then
        echo -e " ℹ️  ${YELLOW}$(L "Modo user" "User mode"):${RESET} $(L "nenhum arquivo de log FTP encontrado em /home/$USER_NAME/logs." "no FTP log file found in /home/$USER_NAME/logs.")"
        return
    fi

    if [ "$LEGIVEIS" -eq 0 ]; then
        echo -e " ⚠️  ${YELLOW}$(L "Modo user" "User mode"):${RESET} $(L "logs FTP existem, mas sem permissão de leitura para esta conta ($BLOQUEADOS bloqueados)." "FTP logs exist, but this account has no read permission ($BLOQUEADOS blocked).")"
        return
    fi

    if [ "$MATCHES" -eq 0 ]; then
        echo -e " ℹ️  ${YELLOW}$(L "Modo user" "User mode"):${RESET} $(L "nenhum match FTP para ${FILE_NAME} nos logs acessíveis." "no FTP match for ${FILE_NAME} in accessible logs.")"
    fi
}

search_ssh_sftp() {
    echo -e "⏳ ${YELLOW}$(L "Buscando conexões via SSH/SFTP..." "Searching SSH/SFTP connections...")${RESET}"
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
                            echo_match "SSH/SFTP LOGIN" "$IP" "$RAW_DATE" "$(L "Sessão Aberta" "Session Opened")" "$f" "$line"
                        fi
                    fi
                fi
            done
        done
    done
}

search_terminal() {
    echo -e "⏳ ${YELLOW}$(L "Buscando escalonamento de privilégio e comandos locais..." "Searching privilege escalation and local commands...")${RESET}"
    
    # 1. Search for someone who has become the file's owner (su/sudo)
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
                            echo_match "ESCALONAMENTO (SU/SUDO)" "$(L "Terminal Local" "Local Terminal")" "$RAW_DATE" "$(L "Sessão Aberta" "Session Opened")" "$f" "$line"
                        fi
                    fi
                fi
            done
        done
    done

    # 2. Search the user's command history (No time precision)
    local BASH_HIST="/root/.bash_history"
    [ "$USER_NAME" != "root" ] && BASH_HIST="/home/$USER_NAME/.bash_history"
    
    if [ -f "$BASH_HIST" ]; then
        # Get the last 500 lines of the history to see if the file name was typed
        MATCH_HIST=$(tail -n 500 "$BASH_HIST" | grep -Fi "$FILE_NAME" | head -n 3)
        if [ -n "$MATCH_HIST" ]; then
            if [ "$HF_LANG_CODE" = "en" ]; then
                echo -e " ${GREEN}✅ MATCH FOUND (BASH HISTORY)${RESET}"
                echo -e "    ${BOLD}Warning:${RESET} Bash history does not include timestamps by default."
                echo -e "    ${BOLD}Log Source:${RESET} $BASH_HIST"
                echo -e "    ${BOLD}Suspicious commands:${RESET}"
            else
                echo -e " ${GREEN}✅ MATCH ENCONTRADO (BASH HISTORY)${RESET}"
                echo -e "    ${BOLD}Aviso:${RESET} O histórico não possui carimbo de tempo por padrão."
                echo -e "    ${BOLD}Log Fonte:${RESET} $BASH_HIST"
                echo -e "    ${BOLD}Comandos suspeitos:${RESET}"
            fi
            echo -e "    $MATCH_HIST\n"
        fi
    fi
}

# Execution Order
analyze_security
echo -e "${BLUE}${BOLD}▶ $(L "FASE 2: RASTREAMENTO DE REDE E LOGS" "PHASE 2: NETWORK AND LOG TRACKING")${RESET}"
echo -e "-----------------------------------------------------------------"
search_apache
if [ "$RUN_PRIVILEGED_CHECKS" -eq 1 ]; then
    search_panel_api
    search_ftp
    search_ssh_sftp
    search_terminal
else
    search_user_ftp_logs
    echo -e " ℹ️  ${YELLOW}$(L "Modo user" "User mode"):${RESET} $(L "verificações privilegiadas (API painel, SSH e terminal) foram ignoradas." "privileged checks (panel API, SSH and terminal) were skipped.")"
fi

echo -e "\n${GREEN}${BOLD}🏁 $(L "AUDITORIA FINALIZADA." "AUDIT COMPLETED.")${RESET}\n"