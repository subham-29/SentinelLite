# MITIRE FRAMEWORK
## SERVER SOFTWARE COMPONENT
### Server Software Component - Web Shell (T1505.003)
HOW TO DETECT -
1) HTTP request path matching a known web shell filename detected by `webshell` rule matching patterns such as `shell.php`, `c99.php`, `r57.php`, `b374k.php`, or `cmd.php` in the request URI.
2) HTTP request targeting a PHP file uploaded to a user-controlled directory such as `/uploads/` detected by the `webshell` pattern matching `/uploads/<filename>.php`.
3) Successful HTTP response (status 200) to a known web shell path indicating the shell is live and accessible.
4) POST request to a PHP file in an upload directory with subsequent command-like query parameters suggesting remote code execution through the shell.
5) Repeated access to the same PHP file in an upload directory from multiple source IPs indicating a publicly known or shared web shell.

## EXPLOITATION
### Exploit Public-Facing Application (T1190)
HOW TO DETECT -
1) SQL injection attempt in the HTTP request path or query string detected by `sqli` rule matching patterns such as `UNION SELECT`, `OR 1=1`, `sleep()`, `information_schema`, `DROP TABLE`, `load_file`, `@@version`, or `benchmark()`.
2) Double URL-encoded path traversal or injection string in the request URI decoded by the parser to reveal an underlying attack payload.
3) HTTP request triggering a WAF block rule detected on the Apache error side by `waf_block` rule matching `ModSecurity` in the error log.
4) Repeated SQL injection probes targeting authentication endpoints or search parameters from the same source IP.
5) Requests containing database metadata extraction payloads such as `information_schema` or `@@version` indicating active reconnaissance of the database.

### Exploit Public-Facing Application - Path Traversal (T1190 / T1083)
HOW TO DETECT -
1) Directory traversal sequence in the HTTP request path detected by `traversal` rule matching `../`, `..\`, `..%2f`, `etc/passwd`, `etc/shadow`, or `win.ini`.
2) Double URL-encoded traversal sequences such as `%252f` decoded by the parser (double unquote pass) revealing a hidden `../` traversal attempt.
3) Traversal path targeting sensitive system files such as `/etc/passwd` or `/etc/shadow` from an external client IP.
4) Apache error log entry indicating an invalid URI in the request detected by the `traversal` error rule matching `Invalid URI in request` or `../` in the error message.
5) Traversal attempts resulting in a 200 response indicating successful file read from the server.

## COMMAND AND SCRIPTING INTERPRETER
### Command and Scripting Interpreter (T1059)
HOW TO DETECT -
1) Remote code execution payload detected in the HTTP request URI by `rce` rule matching patterns such as `jndi:`, `eval-stdin`, `invokefunction`, `call_user_func`, `/cgi-bin/bash`, `$(`, `; cat `, `?cmd=`, `| sh`, `wget`, `curl`, or `system(`.
2) Shellshock exploit attempt detected via the User-Agent header by `SHELLSHOCK_UA` pattern matching `() {` indicating an attempt to execute shell commands through the HTTP User-Agent field.
3) JNDI injection string in the request path targeting Log4j or similar vulnerable libraries matching `jndi:` prefix.
4) OS command injection via query parameter such as `?cmd=` or `&cmd=` with shell metacharacters detected in the decoded URI.
5) Request to `/cgi-bin/bash` or similar CGI endpoint attempting direct shell access on the server.
6) PHP include or eval function call injection detected via `php_include` Apache error rule matching `PHP Warning: include(` or `PHP Fatal error`.

### Command and Scripting Interpreter - JavaScript (T1059.007)
HOW TO DETECT -
1) Cross-site scripting payload detected in the HTTP request URI by `xss` rule matching patterns such as `<script`, `<svg`, `<img`, `onerror=`, `onload=`, or `javascript:`.
2) Event handler injection via HTML attributes such as `onerror=` or `onload=` in query parameters or path segments.
3) JavaScript URI scheme injection via `javascript:` prefix in a URL parameter targeting client-side execution.
4) XSS payload embedded in a URL that is reflected in a 200 response suggesting a reflected cross-site scripting vulnerability.
5) Repeated XSS probes using different tag and event handler combinations from the same source IP indicating automated fuzzing.

## RECONNAISSANCE
### Active Scanning - Vulnerability Scanning (T1595.002)
HOW TO DETECT -
1) HTTP request originating from a known scanner User-Agent detected by `BAD_UA` pattern matching tools such as `sqlmap`, `nikto`, `nmap`, `masscan`, `hydra`, `wpscan`, `zgrab`, `dirbuster`, `acunetix`, `nessus`, `openvas`, `python-requests`, `go-http-client`, or `curl/`.
2) HTTP request targeting a known reconnaissance path detected by `recon_scan` rule matching paths such as `/.env`, `/.git`, `wp-login`, `wp-admin`, `phpmyadmin`, `xmlrpc.php`, `/administrator`, `/admin`, `manager/html`, `server-status`, `.sql`, `.bak`, `backup.zip`, `id_rsa`, `.aws`, `actuator`, `solr/admin`, `/shell`, or `/c99`.
3) Reconnaissance path request returning a 401, 403, 404, or 200 status code, all of which are captured as `recon_scan` events indicating the probe reached the server.
4) Sequence of requests to multiple sensitive administrative or backup paths from the same source IP within a short window indicating directory enumeration.
5) Scanner User-Agent combined with reconnaissance path access indicating an automated tool is actively mapping the application surface.

## CREDENTIAL ACCESS
### Brute Force - Password Guessing (T1110.001)
HOW TO DETECT -
1) POST request to a login or authentication endpoint returning HTTP 401 or 403 detected by `web_login_fail` rule matching `LOGIN_PATH` patterns such as `login`, `xmlrpc.php`, or `/admin` with the corresponding failure status code.
2) Repeated failed POST requests to the same login endpoint from the same source IP within a short time window indicating automated credential stuffing or brute-force.
3) WordPress XML-RPC endpoint (`xmlrpc.php`) receiving repeated POST requests with 401 or 403 responses indicating a multicall brute-force attack.
4) HTTP basic authentication failure on a protected admin path returning 401 indicating a credential guessing attempt against the web application.

## DEFENSE EVASION
### Obfuscated Files or Information (T1027)
HOW TO DETECT -
1) Double URL-encoded characters in the request path decoded by the parser (two passes of `unquote_plus`) revealing an otherwise hidden injection or traversal payload.
2) Request using non-standard HTTP methods detected by `bad_method` rule where the method is not `GET`, `POST`, or `HEAD` indicating an attempt to bypass method-based access controls or trigger unexpected server behavior.
3) Percent-encoded path traversal sequences such as `..%2f` or `%252f` in the URI decoded to reveal a directory traversal payload.
