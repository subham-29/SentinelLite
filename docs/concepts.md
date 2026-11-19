# MITIRE FRAMEWORK
## BRUTFORCE 
### Password Guessing (T1110.001)
HOW TO DETECT -
1) Repeated failed SSH login attempts followed by a possible success from the same remote host.
2) Series of authentication failures (Event ID 4625) targeting the same or similar user accounts over time from one or more remote IPs.
3) Series of failed logins from loginwindow or sshd with repeated usernames or password prompts.
4) Multiple failed sign-in attempts from external sources across many users followed by success from the same IP.
5) Login attempt failures over SNMP, Telnet, or SSH interface, often reflected in logs or syslog events.
6) Password guessing attempts against web-based apps (e.g., Dropbox, Google Workspace) reflected in API or sign-in logs.

### Password Spraying (T1110.003)