import re
import pandas
from main import authlog
ips=re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",authlog)
print(ips)