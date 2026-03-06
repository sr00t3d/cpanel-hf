# High Finder Forensics (standalone)

Readme: [EN](README.md)

![License](https://img.shields.io/github/license/sr00t3d/hf) ![Shell Script](https://img.shields.io/badge/language-Bash-green.svg)

<img width="700" src="hf-cover.webp" />

> Este script é uma reescrita do arquivo original hf.pl desenvolvido por Michael Karr (HostGator.com)

`hf.sh` é um utilitário de auditoria forense para rastrear a origem provável de
um arquivo em servidores Linux com cPanel ou DirectAdmin.

Ele cruza metadados do arquivo com evidências em logs (web, painel, FTP,
SSH/SFTP e terminal), gerando um relatório legível no terminal.

## O que ele faz

O script executa duas fases:

1. **Análise estática do arquivo**
   - tamanho e permissões;
   - atributo imutável (`chattr +i`);
   - comparação extensão x MIME real (spoofing);
   - assinaturas comuns de payload em código (`eval`, `base64_decode`, etc.);
   - hash SHA-256 e link para pesquisa no VirusTotal.
2. **Correlação de logs por janela de tempo**
   - web server (Apache/Nginx/domlogs);
   - API do painel (cPanel/DirectAdmin);
   - FTP (Pure-FTPd/ProFTPd/xferlog);
   - SSH/SFTP;
   - histórico de comandos (`.bash_history`, quando disponível).

## Requisitos

- Linux com `bash`.
- Ferramentas comuns do sistema: `realpath`, `stat`, `file`, `sha256sum`,
  `grep`, `awk`, `sed`, `date`, `zgrep`.
- Permissão de leitura nos logs desejados.

> **Nota:** Sem acesso root, parte das fontes de log pode ficar indisponível.

## Como Usar

### Modo hospedado

1. **Baixe o arquivo no servidor:**

```bash
curl -O https://raw.githubusercontent.com/sr00t3d/hf/refs/heads/main/hf.sh
```

2. **Dê permissão de execução:**

```bash
chmod +x hf.sh
```

3. **Execute o script:**

```bash
./hf.sh <options>
```

> Dica: Mova o arquivo para /usr/local/bin/hf e execute a partir do comando hf

### Modo direto

```bash
bash <(curl -fsSL 'https://raw.githubusercontent.com/sr00t3d/cpanel-tpm-manager/refs/heads/main/hf.sh') <options>
```

## Uso rápido

```bash
hf.sh --version
hf.sh [--mode full|user] [--no-color] <caminho_do_arquivo>
```

Exemplos:

```bash
# Auditoria completa (recomendado como root)
hf.sh --mode full /home/account/public_html/index.php

# Auditoria segura para conta cPanel
hf.sh --mode user /home/account/public_html/suspeito.php

# Saída sem ANSI/cores (CI, logs, parser)
hf.sh --mode user --no-color /home/account/public_html/file.php
```

## Modos de execução

### `full`

Modo completo. Tenta consultar logs privilegiados do sistema e do painel.

### `user`

Modo restrito para uso por conta cPanel:

- desativa buscas privilegiadas de painel/SSH/terminal;
- prioriza fontes acessíveis em `/home/<conta>/...`;
- mantém rastreio FTP em logs da conta quando disponíveis.

## Variáveis de ambiente úteis

- `HF_MODE=full|user`: define modo padrão sem passar `--mode`.
- `HF_UNPRIVILEGED=1`: força comportamento não privilegiado.
- `HF_AUDIT_USER=<conta>`: override explícito da conta auditada.
- `NO_COLOR=1`: desativa cores na saída.

Exemplo:

```bash
HF_MODE=user HF_UNPRIVILEGED=1 HF_AUDIT_USER=account hf.sh /home/account/public_html/a.php
```

## Como interpretar o resultado

- `MATCH ENCONTRADO (...)`: evidência encontrada para uma origem/canal.
- `SPOOFING DETECTADO`: extensão e tipo real não batem.
- `ALERTA CRÍTICO (imutável)`: arquivo com atributo `+i`.
- Link do VirusTotal: pesquisa do hash calculado no momento.

## Limitações importantes

- Não é antivírus nem EDR.
- A precisão depende da retenção e da qualidade dos logs.
- Fuso horário e rotação de logs podem impactar correlação temporal.
- `bash_history` não é prova temporal confiável por padrão.

## Segurança operacional

- O script é de leitura e análise (não move, não exclui e não corrige arquivos).
- Valida nome de usuário auditado para reduzir risco de entrada maliciosa.
- Em modo `user`, evita consultas privilegiadas por design.

## Exit codes

- `0`: execução concluída.
- `1`: erro de uso, parâmetro inválido, arquivo inválido ou falha de validação.

## Troubleshooting

### “modo full sem root pode não acessar todos os logs”

Execute com root ou troque para `--mode user`.

### “nenhum match encontrado”

Confirme:

- janela temporal do incidente;
- rotação/expurgo de logs;
- permissões de leitura do usuário atual;
- caminho do arquivo auditado.

---

Se você usa cPanel plugin, este README documenta apenas a versão standalone do
`hf.sh`.

## Aviso Legal

> [!WARNING]
> Este software é fornecido "tal como está". Certifique-se sempre de ter permissão explícita antes de executar. O autor não se responsabiliza por qualquer uso indevido, consequências legais ou impacto nos dados causados ​​por esta ferramenta.

## Tutorial Detalhado

Para um guia completo, passo a passo, confira meu artigo completo:

👉 [**Auditoria de uploads em servidor cPanel**](https://perciocastelo.com.br/blog/audit-uploads-on-cpanel-server.html)

## Licença 📄

Este projeto está licenciado sob a **GNU General Public License v3.0**. Veja o arquivo [LICENSE](LICENSE) para detalhes.