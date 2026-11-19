import time
def follow_log(file_path):
    with open(file_path,"r",encoding="utf-8") as f:
        while True:
            line=f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line.strip()