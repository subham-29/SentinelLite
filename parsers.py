import re
from collector import follow_log

# Category 1: Existing user
valid_user_pattern = re.compile(r"Failed password for (?!invalid user\b)\S+ from ((?:\d{1,3}\.){3}\d{1,3})")
# Category 2: Non-existing user
invalid_user_pattern = re.compile(r"Failed password for invalid user (\S+)")
def parsersing(file_path,pattern1,pattern2=None):
    if pattern1 != None and pattern2 != None:
        for real_log in follow_log(file_path):
            valid_user_fails = pattern1.findall(real_log)
            invalid_user_fails = pattern2.findall(real_log)
            if valid_user_fails:
                for ip in valid_user_fails:
                    print(f"[VALID USER] {ip}")
            if invalid_user_fails:
                for username in invalid_user_fails:
                    print(f"[INVALID USER] {username}")
    else:
        for real_log in follow_log(file_path):
                    fails1 = pattern1.findall(real_log)
                    if fails1:
                        for ip in fails1:
                            print(ip)
                   