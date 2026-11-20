# MITIRE FRAMEWORK
## EXPLOITATION
### Exploit Public-Facing Application (T1190)
HOW TO DETECT -
1) ModSecurity WAF rule violation recorded in Apache error log detected by `waf_block` rule matching `ModSecurity` in the error message indicating an inbound request was blocked by the web application firewall.
2) WAF block event from a client IP that has also generated other attack-type events such as SQLi or traversal probes in the access log within the same session.
3) Repeated WAF block events from the same source IP indicating an attacker iterating through payloads in an attempt to bypass the WAF ruleset.
4) WAF block followed by a successful request to the same path from the same IP suggesting a WAF bypass was eventually achieved.
5) Malformed or oversized HTTP request detected by `malformed_request` rule matching `Invalid method in request`, `URI too long`, or request `without hostname` indicating an attempt to confuse the server or its upstream proxy.

### Exploit Public-Facing Application - Path Traversal (T1190 / T1083)
HOW TO DETECT -
1) Invalid URI sequence in the HTTP request detected by `traversal` Apache error rule matching `Invalid URI in request` indicating the server rejected a malformed or traversal-containing path.
2) Directory traversal sequence `../` present in the URI recorded in the Apache error log matching the `traversal` error rule.
3) Request for `/etc/passwd` or similar sensitive system path appearing in the Apache error log indicating an attempt to read OS-level files through the web server.
4) Traversal attempt that caused an Apache error response, logged at warn or error level, suggesting the payload reached the application layer before being rejected.

## COMMAND AND SCRIPTING INTERPRETER
### Command and Scripting Interpreter - Unix Shell / PHP (T1059.004)
HOW TO DETECT -
1) PHP `include()` function failure or warning recorded in the Apache error log detected by `php_include` rule matching `PHP Warning: include(` indicating a possible remote or local file inclusion attempt.
2) PHP fatal error logged by Apache detected by `php_include` rule matching `PHP Fatal error` which may indicate a code injection or unexpected script execution path.
3) PHP include warning referencing a remote URL (`http://` or `ftp://`) indicating a Remote File Inclusion (RFI) attempt where an attacker is trying to load a remote PHP payload.
4) PHP include warning referencing an unusually long or encoded path that may indicate a Local File Inclusion (LFI) attempt targeting OS-level files.
5) PHP fatal error occurring immediately after a suspicious POST request to the same URI suggesting injected code caused an execution failure.

## SERVER SOFTWARE COMPONENT
### Server Software Component - Web Shell (T1505.003)
HOW TO DETECT -
1) PHP include failure targeting a file in a user-writable directory such as `/uploads/` or `/tmp/` recorded in the Apache error log suggesting an attempt to execute an uploaded PHP web shell via the include mechanism.
2) PHP fatal error or parse error logged for a file in an upload directory indicating a web shell script was uploaded and executed but failed due to a syntax or compatibility issue.

## CREDENTIAL ACCESS
### Brute Force - Password Guessing via HTTP Auth (T1110.001)
HOW TO DETECT -
1) HTTP authentication failure recorded in Apache error log detected by `http_auth_fail` rule matching `user <user> not found`, `authentication failure for`, or `Password Mismatch`.
2) Repeated HTTP Basic or Digest authentication failures for the same user or path from the same source IP indicating automated credential guessing against a protected directory or endpoint.
3) HTTP auth failure events across multiple usernames from the same source IP within a short time window indicating a credential spray against HTTP-protected resources.

## DISCOVERY
### File and Directory Discovery (T1083)
HOW TO DETECT -
1) Web request to a directory that has index listing disabled returning a `Directory index forbidden` error detected by `dir_index_denied` rule.
2) Web request to a non-existent file or script recorded in Apache error log detected by `file_not_found` rule matching `File does not exist` or `script not found`.
3) Repeated file-not-found errors for paths following a pattern such as common backup extensions (`.bak`, `.sql`, `.zip`) or admin filenames indicating automated directory enumeration or brute-forcing of file paths.
4) Requests for predictable filenames such as `backup.zip`, `db.sql`, `config.bak`, or `admin.php` generating 404 errors in the Apache error log indicating a file enumeration attack.

## IMPACT
### Endpoint Denial of Service - Resource Exhaustion (T1499)
HOW TO DETECT -
1) Apache server reaching its maximum client connection limit detected by `server_overload` rule matching `MaxClients` in the error log indicating the server can no longer accept new connections.
2) Memory allocation failure in the Apache process detected by `server_overload` rule matching `Cannot allocate memory` indicating the server is under resource pressure from a high connection or request load.
3) Apache failing to spawn a new child process detected by `server_overload` rule matching `couldn't create child` or `Unable to fork` indicating process table exhaustion on the host.
4) Sustained spike in Apache error log entries for resource exhaustion events correlating with elevated inbound connection rates from one or more source IPs.

## LATERAL MOVEMENT
### Exploitation of Remote Services - AJP/JK Connector (T1210)
HOW TO DETECT -
1) mod_jk connector reporting a worker in an error state detected by `jk_error` rule matching `mod_jk child workerEnv in error state` or `mod_jk child init` failure indicating a backend AJP worker is unreachable or misconfigured.
2) mod_jk unable to find a child worker detected by `jk_error` rule matching `Can't find child` indicating a potential exploitation or crash of the backend application server via the AJP connector.
3) Repeated jk_error events correlating with unusual inbound requests to AJP-proxied paths suggesting an attempt to exploit the AJP connector (e.g., Ghostcat / CVE-2020-1938).
