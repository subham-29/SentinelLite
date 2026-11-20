import re
from urllib.parse import unquote_plus

IP = r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"

#auth logsss
valid_user_pattern = re.compile(r"Failed password for (?!invalid user\b)\S+ from ((?:\d{1,3}\.){3}\d{1,3})")
invalid_user_pattern = re.compile(r"Failed password for invalid user (\S+)")
AUTH_RULES = [
    ("invalid_user",       rf"Failed password for invalid user (?P<user>\S+) from {IP}"),
    ("failed_login",       rf"Failed password for (?!invalid user\b)(?P<user>\S+) from {IP}"),
    ("login_success",      rf"Accepted (?P<method>password|publickey) for (?P<user>\S+) from {IP}"),
    ("invalid_user_probe", rf"Invalid user (?P<user>\S+) from {IP}"),
    ("break_in_warning",   rf"POSSIBLE BREAK-IN ATTEMPT.*|reverse mapping checking getaddrinfo for \S+ \[{IP}\]"),
    ("ssh_scan",           rf"Did not receive identification string from {IP}"),
    ("ssh_scan",           rf"Bad protocol version identification .* from {IP}"),
    ("ssh_scan",           rf"Unable to negotiate with {IP}"),
    ("max_auth_exceeded",  rf"maximum authentication attempts exceeded for (?P<user>\S+) from {IP}"),
    ("max_auth_exceeded",  r"Too many authentication failures for (?P<user>\S+)"),
    ("auth_exhausted",     rf"error: Received disconnect from {IP}: \d+: No more user authentication methods"),
    ("auth_exhausted",     rf"Received disconnect from {IP}: 3: .*Auth fail"),
    ("pam_auth_fail",      rf"pam_unix\(sshd:auth\): authentication failure;.*rhost={IP}(?:\s+user=(?P<user>\S+))?"),
]

#linux logsss
LINUX_RULES = [
    ("ssh_pam_fail",      r"sshd\(pam_unix\)\[\d+\]: authentication failure;.*rhost=(?P<ip>\S*)(?:\s+user=(?P<user>\S+))?"),  #ip can be hostname ip/hostname
    ("unknown_user",      r"check pass; user unknown"),
    ("ftp_anon_refused",  rf"ANONYMOUS FTP LOGIN REFUSED FROM {IP}"),
    ("ftp_login_fail",    rf"FTP LOGIN FAILED FROM {IP} \([^)]*\), (?P<user>\S+)"),
    ("ftp_connection",    rf"ftpd\[\d+\]: connection from {IP}"),
    ("su_fail",           r"su\(pam_unix\)\[\d+\]: authentication failure;\s*logname=(?P<user>\S*)"),
    ("su_fail",           r"su: pam_authenticate: Authentication failure for (?P<user>\S+)"),
    ("sudo_violation",    r"sudo:\s+(?P<user>\S+) : (?:user NOT in sudoers|\d+ incorrect password attempts)"),
    ("user_added",        r"useradd\[\d+\]: new user: name=(?P<user>[^,]+)"),
    ("group_modified",    r"usermod\[\d+\]: add '(?P<user>[^']+)' to group '(?P<group>[^']+)'"),
    ("root_pw_changed",   r"passwd\[\d+\]:.*password changed for (?P<user>\S+)"),
    ("cron_modified",     r"crontab\[\d+\]: \((?P<user>\S+)\) REPLACE"),
    ("exec_denied",       r"kernel: audit: type=1400 avc: denied \{ (?P<action>\w+) \}.*comm=\"(?P<comm>[^\"]+)\""),
    ("syn_flood",         r"kernel: possible SYN flooding"),
    ("conntrack_full",    r"kernel: ip_conntrack: table full"),
    ("oom_kill",          r"kernel: Out of Memory: Killed process \d+ \((?P<comm>[^)]+)\)"),
    ("martian_packet",    rf"kernel: martian source {IP}"),
    ("promiscuous_mode",  r"kernel: promiscuous mode enabled"),
    ("xinetd_fail",       rf"xinetd\[\d+\]: FAIL: \S+ address from={IP}"),
]

#access logsss
ACCESS_RE = re.compile(
    rf'^{IP} \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>.*?)(?: HTTP/[\d.]+)?" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)
_I = re.I
# url encoded -> decoded , then only scan 
WEB_ATTACKS = [
    ("webshell",  re.compile(r"(?:shell|c99|r57|b374k|cmd)\.php|/uploads/[^?]*\.php", _I)),
    ("rce",       re.compile(r"jndi:|eval-stdin|invokefunction|call_user_func|/cgi-bin/bash|\$\(|;\s*cat\s|[?&]cmd=|\|\s*sh\b|\bwget\b|\bcurl\b|system\(", _I)),
    ("sqli",      re.compile(r"union\s+(?:all\s+)?select|\bor\b\s+'?\d'?\s*=\s*'?\d|sleep\(|information_schema|drop\s+table|load_file|@@version|'--|;--|benchmark\(", _I)),
    ("xss",       re.compile(r"<script|<svg|<img|onerror\s*=|onload\s*=|javascript:", _I)),
    ("traversal", re.compile(r"\.\./|\.\.\\|\.\.%2f|etc/passwd|etc/shadow|win\.ini", _I)),
]
BAD_UA = re.compile(r"sqlmap|nikto|nmap|masscan|hydra|wpscan|zgrab|dirbuster|acunetix|nessus|openvas|python-requests|go-http-client|^curl/", _I)
SHELLSHOCK_UA = re.compile(r"\(\)\s*\{")
RECON_PATH = re.compile(
    r"/\.env|/\.git|wp-login|wp-admin|phpmyadmin|xmlrpc\.php|/administrator|/admin\b|manager/html|"
    r"server-status|\.sql\b|\.bak\b|backup\.zip|id_rsa|\.aws|actuator|solr/admin|/shell|/c99", _I)
LOGIN_PATH = re.compile(r"login|xmlrpc\.php|/admin", _I)


def _parse_access(line):
    m = ACCESS_RE.match(line)
    if not m:
        return None
    ev = m.groupdict()
    ev["status"] = int(ev["status"])
    target = unquote_plus(unquote_plus(ev["path"]))          # decode twice (%252f tricks) for harder encondings

    etype = None
    for name, rx in WEB_ATTACKS:
        if rx.search(target):
            etype = name
            break
    if not etype and SHELLSHOCK_UA.search(ev["ua"]):
        etype = "rce"
    if not etype:
        if ev["method"] not in ("GET", "POST", "HEAD"):
            etype = "bad_method"
        elif ev["method"] == "POST" and LOGIN_PATH.search(target) and ev["status"] in (401, 403):
            etype = "web_login_fail"
        elif BAD_UA.search(ev["ua"]):
            etype = "scanner_ua"
        elif RECON_PATH.search(target) and ev["status"] in (401, 403, 404, 200):
            etype = "recon_scan"
        elif ev["status"] >= 500:
            etype = "http_5xx"
        else:
            etype = "http_request"                          # normal traffic
    ev["type"] = etype
    return ev

#apache logsss

ERR_RE = re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<level>\w+)\] (?:\[client (?P<ip>[\d.]+)\] )?(?P<msg>.*)$")
ERR_RULES = [
    ("waf_block",        re.compile(r"ModSecurity", _I)),
    ("traversal",        re.compile(r"Invalid URI in request|\.\./|etc/passwd", _I)),
    ("php_include",      re.compile(r"PHP Warning:.*include\(|PHP Fatal error", _I)),
    ("http_auth_fail",   re.compile(r"user \S+ not found|authentication failure for|Password Mismatch", _I)),
    ("dir_index_denied", re.compile(r"Directory index forbidden")),
    ("file_not_found",   re.compile(r"File does not exist|script not found")),
    ("malformed_request", re.compile(r"Invalid method in request|URI too long|without hostname", _I)),
    ("server_overload",  re.compile(r"MaxClients|Cannot allocate memory|couldn't create child|Unable to fork", _I)),
    ("jk_error",         re.compile(r"mod_jk child (?:workerEnv in error state|init)|Can't find child", _I)),
]


def _parse_error(line):
    m = ERR_RE.match(line)
    if not m:
        return None
    ev = m.groupdict()
    if ev["level"] in ("notice", "info", "debug"):
        return None                                         # normal startup things
    for name, rx in ERR_RULES:
        if rx.search(ev["msg"]):
            ev["type"] = name
            return ev
    ev["type"] = "web_error"
    return ev


def _compile(rules):
    return [(t, re.compile(p)) for t, p in rules]


_SYSLOG_RULES = {"auth": _compile(AUTH_RULES), "linux": _compile(LINUX_RULES)}


def parse_line(source, line):
    line = line.strip()
    if not line:
        return None

    if source in _SYSLOG_RULES:
        for etype, rx in _SYSLOG_RULES[source]:
            m = rx.search(line)
            if m:
                ev = {k: v for k, v in m.groupdict().items() if v}
                ev.update(type=etype, src=source, raw=line)
                return ev
        return None
    if source == "access":
        ev = _parse_access(line)
    elif source == "apache_error":
        ev = _parse_error(line)
    else:
        raise ValueError(f"unknown source: {source}")

    if ev:
        ev.update(src=source, raw=line)
    return ev