# MITIRE FRAMEWORK
## BRUTFORCE
### Password Guessing (T1110.001)
HOW TO DETECT -
1) Repeated failed SSH login attempts for a valid username from the same remote IP address captured by `failed_login` rule matching `Failed password for <user> from <ip>`.
2) Multiple failed SSH login attempts targeting a non-existent or invalid username detected via `invalid_user` rule matching `Failed password for invalid user <user> from <ip>`.
3) PAM authentication failure events logged by sshd captured via `pam_auth_fail` rule matching `pam_unix(sshd:auth): authentication failure; rhost=<ip>`.
4) PAM-level SSH authentication failure from sshd matching `sshd(pam_unix): authentication failure; rhost=<ip>` detected via `ssh_pam_fail` rule.
5) Unknown user attempting to authenticate against PAM service detected by `unknown_user` rule matching `check pass; user unknown`.
6) Series of authentication failures targeting the same user account from one or more remote IPs over a short time window.
7) FTP login failure events from a remote IP detected by `ftp_login_fail` rule matching `FTP LOGIN FAILED FROM <ip> (<details>), <user>`.
8) FTP anonymous login attempts that are refused from a remote host captured by `ftp_anon_refused` rule matching `ANONYMOUS FTP LOGIN REFUSED FROM <ip>`.

### Password Spraying (T1110.003)
HOW TO DETECT -
1) SSH session hitting the maximum number of allowed authentication attempts detected via `max_auth_exceeded` rule matching `maximum authentication attempts exceeded for <user> from <ip>`.
2) Too many consecutive authentication failures for a single user triggering `Too many authentication failures for <user>` captured by the `max_auth_exceeded` rule.
3) Remote client exhausting all available authentication methods and disconnecting detected by `auth_exhausted` rule matching `Received disconnect from <ip>: No more user authentication methods`.
4) Client disconnecting after exhausting all auth methods with an explicit auth-fail reason matching `Received disconnect from <ip>: 3: Auth fail` captured by `auth_exhausted` rule.
5) Pattern of multiple users seeing max-attempts disconnects from the same source IP within a short window indicating spray behavior across accounts.

## ACTIVE SCANNING
### Active Scanning - Vulnerability Scanning (T1595.002)
HOW TO DETECT -
1) SSH daemon not receiving a valid identification string from a connecting client detected by `ssh_scan` rule matching `Did not receive identification string from <ip>`.
2) Client sending a malformed or unsupported SSH protocol version banner detected by `ssh_scan` rule matching `Bad protocol version identification from <ip>`.
3) SSH daemon unable to negotiate a compatible algorithm with a connecting client matching `Unable to negotiate with <ip>` captured by `ssh_scan` rule.
4) Reverse DNS mismatch or possible spoofed connection warning captured by `break_in_warning` rule matching `POSSIBLE BREAK-IN ATTEMPT` or `reverse mapping checking getaddrinfo for <host> [<ip>]`.
5) Martian packets (packets with an impossible source address) arriving at the host detected by `martian_packet` rule matching `kernel: martian source <ip>`.
6) FTP connection probe from a remote IP detected by `ftp_connection` rule matching `ftpd: connection from <ip>`.
7) High rate of TCP connections to various ports with no follow-up handshake or service negotiation indicative of port or service probing.

### Network Service Discovery (T1046)
HOW TO DETECT -
1) SSH client connecting but failing to send a protocol identification string, indicating automated scanner behavior, matched by `ssh_scan` rule.
2) SSH client advertising an incompatible protocol version, a common behavior of network service enumeration tools, matched by `ssh_scan` rule.
3) Connection negotiation failures across repeated short-lived sessions originating from the same remote IP pointing to service fingerprinting activity.

## VALID ACCOUNTS
### Valid Accounts (T1078)
HOW TO DETECT -
1) Successful SSH login recorded after a series of prior failed attempts from the same remote IP detected by `login_success` rule matching `Accepted password for <user> from <ip>`.
2) Successful public-key SSH authentication from a remote IP detected by `login_success` rule matching `Accepted publickey for <user> from <ip>`.
3) Successful authentication following a pattern of brute-force or spray attempts from the same source IP suggesting credential compromise.
4) Legitimate-looking logins occurring at unusual hours or from geographically anomalous IPs that do not match the account's normal access pattern.

## PRIVILEGE ESCALATION
### Abuse Elevation Control Mechanism - Sudo and Sudo Caching (T1548.003)
HOW TO DETECT -
1) Sudo invocation by a user who is not listed in the sudoers file detected by `sudo_violation` rule matching `sudo: <user> : user NOT in sudoers`.
2) Sudo invocation with repeated incorrect password entries detected by `sudo_violation` rule matching `sudo: <user> : <N> incorrect password attempts`.
3) `su` authentication failure through PAM captured by `su_fail` rule matching `su(pam_unix): authentication failure; logname=<user>`.
4) Direct `su` PAM authentication failure message detected by `su_fail` rule matching `su: pam_authenticate: Authentication failure for <user>`.
5) Repeated `su` or `sudo` failures from the same local user account suggesting attempt to escalate to root or another privileged user.

### Abuse Elevation Control Mechanism (T1548)
HOW TO DETECT -
1) SELinux or AppArmor kernel audit denial event captured by `exec_denied` rule matching `kernel: audit: type=1400 avc: denied { <action> } comm="<process>"`.
2) Process attempting an action that the mandatory access control policy explicitly forbids, logged as an AVC denial in the audit subsystem.
3) Repeated AVC denial events for the same process or action indicating persistent attempts to bypass enforced security policies.

## ACCOUNT MANIPULATION
### Account Manipulation (T1098)
HOW TO DETECT -
1) Root account password change event detected by `root_pw_changed` rule matching `passwd: password changed for <user>` where the target user is a privileged account.
2) Any unexpected or unscheduled password change for a sensitive account such as root or a service account logged by `passwd`.
3) Password change occurring outside of a known maintenance window or change management process.

### Create Local Account (T1136.001)
HOW TO DETECT -
1) New local user account creation detected by `user_added` rule matching `useradd: new user: name=<user>`.
2) Existing user added to a new group, potentially a privileged group such as `sudo` or `wheel`, detected by `group_modified` rule matching `usermod: add '<user>' to group '<group>'`.
3) Account creation or group membership change occurring outside of normal provisioning workflows or change management procedures.
4) New account created and immediately used to authenticate or escalate privileges within a short time window.

## SCHEDULED TASK / JOB
### Scheduled Task/Job - Cron (T1053.003)
HOW TO DETECT -
1) User crontab modification detected by `cron_modified` rule matching `crontab: (<user>) REPLACE` indicating an existing crontab was replaced with new content.
2) Unexpected crontab modification by a non-administrative user account suggesting installation of a persistence mechanism.
3) Crontab replacement occurring outside of known automation or deployment windows.
4) New cron job added that executes scripts from writable directories such as `/tmp` or `/var/tmp`.

## NETWORK EFFECTS
### Network Denial of Service - Direct Network Flood (T1498.001)
HOW TO DETECT -
1) Kernel-level SYN flood warning detected by `syn_flood` rule matching `kernel: possible SYN flooding`.
2) Connection tracking table exhaustion event detected by `conntrack_full` rule matching `kernel: ip_conntrack: table full` indicating the host is overwhelmed with connections.
3) Sudden spike in inbound SYN packets to a listening service with no corresponding ACK responses indicating a volumetric flood.

## COLLECTION
### Network Sniffing (T1040)
HOW TO DETECT -
1) Network interface set to promiscuous mode detected by `promiscuous_mode` rule matching `kernel: promiscuous mode enabled`.
2) Promiscuous mode activation on a production interface outside of a known monitoring or packet capture workflow.
3) Promiscuous mode enabled on a host that does not run any sanctioned network monitoring or analysis tools.
