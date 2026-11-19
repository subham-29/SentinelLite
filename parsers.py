import re
import pandas
from main import authlog
# Category 1: existing user
valid_user_fails = re.findall(r".*Failed password for (?!invalid user)(\S+).*",authlog)
# Category 2: non existing user
invalid_user_fails = re.findall(r".*Failed password for invalid user (\S+).*",authlog)


inval_usr_ip = pandas.Series(valid_user_fails).value_counts()
val_usr_ip = pandas.Series(invalid_user_fails).value_counts()
print(inval_usr_ip)
print(val_usr_ip)
