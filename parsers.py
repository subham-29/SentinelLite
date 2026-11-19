import re
import pandas
from main import authlog
failed_logs = re.findall(r".*Failed password.*", authlog)

failed_text = "\n".join(failed_logs)

ips = re.findall(
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    failed_text
)

total_ips = pandas.Series(ips).value_counts()

print(total_ips.head(5))
# ips=re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",authlog)
# total_ips = pandas.Series(ips).value_counts()
# print(total_ips.head(3))