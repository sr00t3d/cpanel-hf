# High Finder Forensics (standalone)

Readme: [BR](README-ptbr.md)

![License](https://img.shields.io/github/license/sr00t3d/hf) ![Shell Script](https://img.shields.io/badge/language-Bash-green.svg)

<img width="700" src="hf-cover.webp" />

> This script is a rewrite of the original hf.pl file developed by Michael Karr (HostGator.com)

`hf.sh` is a forensic auditing utility for tracking the probable origin of  
a file on Linux servers with cPanel or DirectAdmin.

It cross-references file metadata with evidence in logs (web, panel, FTP,  
SSH/SFTP and terminal), generating a readable report in the terminal.

## What it does

The script executes two phases:

1. **Static file analysis**
   - size and permissions;
   - immutable attribute (`chattr +i`);
   - extension vs real MIME comparison (spoofing);
   - common payload signatures in code (`eval`, `base64_decode`, etc.);
   - SHA-256 hash and link for search on VirusTotal.

2. **Log correlation by time window**
   - web server (Apache/Nginx/domlogs);
   - panel API (cPanel/DirectAdmin);
   - FTP (Pure-FTPd/ProFTPd/xferlog);
   - SSH/SFTP;
   - command history (`.bash_history`, when available).

## Requirements

- Linux with `bash`.
- Common system tools: `realpath`, `stat`, `file`, `sha256sum`,
  `grep`, `awk`, `sed`, `date`, `zgrep`.
- Read permission for the desired logs.

> **Note:** Without root access, some log sources may be unavailable.

## How to Use

### Hosted mode

1. **Download the file on the server:**

```bash
curl -O https://raw.githubusercontent.com/sr00t3d/hf/refs/heads/main/hf.sh
```

2. **Grant execution permission:**

```bash
chmod +x hf.sh
```

3. **Run the script:**

```bash
./hf.sh <options>
```

> Tip: Move the file to /usr/local/bin/hf and run it with the `hf` command.

### Direct mode

```bash
bash <(curl -fsSL 'https://raw.githubusercontent.com/sr00t3d/hf/refs/heads/main/hf.sh') <options>
```

## Quick usage

```bash
hf.sh --version
hf.sh [--mode full|user] [--no-color] <file_path>
```

Examples:

```bash
# Full audit (recommended as root)
hf.sh --mode full /home/account/public_html/index.php

# Safe audit for cPanel account
hf.sh --mode user /home/account/public_html/suspeito.php

# Output without ANSI/colors (CI, logs, parser)
hf.sh --mode user --no-color /home/account/public_html/file.php
```

## Execution modes

### `full`

Full mode. Attempts to query privileged system and panel logs.

### `user`

Restricted mode for use by a cPanel account:

- disables privileged panel/SSH/terminal searches;
- prioritizes sources accessible in `/home/<account>/...`;
- keeps FTP tracking in account logs when available.

## Useful environment variables

- `HF_MODE=full|user`: defines default mode without passing `--mode`.
- `HF_UNPRIVILEGED=1`: forces non-privileged behavior.
- `HF_AUDIT_USER=<account>`: explicit override of the audited account.
- `NO_COLOR=1`: disables colors in output.

Example:

```bash
HF_MODE=user HF_UNPRIVILEGED=1 HF_AUDIT_USER=account hf.sh /home/account/public_html/a.php
```

## How to interpret the result

- `MATCH FOUND (...)`: evidence found for an origin/channel.
- `SPOOFING DETECTED`: extension and real type do not match.
- `CRITICAL ALERT (immutable)`: file with attribute `+i`.
- VirusTotal link: search for the hash calculated at the moment.

## Important limitations

- It is not an antivirus or EDR.
- Accuracy depends on log retention and quality.
- Time zone and log rotation may impact temporal correlation.
- `bash_history` is not reliable temporal evidence by default.

## Operational security

- The script is read-and-analysis only (does not move, delete, or fix files).
- Validates the audited username to reduce malicious input risk.
- In `user` mode, it avoids privileged queries by design.

## Exit codes

- `0`: execution completed.
- `1`: usage error, invalid parameter, invalid file, or validation failure.

## Troubleshooting

### “full mode without root may not access all logs”

Run with root or switch to `--mode user`.

### “no match found”

Check:

- incident time window;
- log rotation/purge;
- read permissions of the current user;
- path of the audited file.

---

If you use the cPanel plugin, this README documents only the standalone version of `hf.sh`.

## Legal Notice

> [!WARNING]
> This software is provided "as is". Always make sure you have explicit permission before running it. The author is not responsible for any misuse, legal consequences, or data impact caused by this tool.

## Detailed Tutorial

For a complete step-by-step guide, check my full article:

👉 **Audit of uploads on a cPanel server**  
https://perciocastelo.com.br/blog/audit-uploads-on-cpanel-server.html

## License 📄

This project is licensed under the **GNU General Public License v3.0**. See the [LICENSE](LICENSE) file for details.