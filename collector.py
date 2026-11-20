import threading, queue, time
q = queue.Queue()

def _tail(path, source, replay=True):          # replay param for future uses
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        history = replay                        
        if not replay:
            f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                history = False                 # now we are reading live lines
                time.sleep(0.1); continue
            if not line.endswith("\n"):         #  half-written line -> wait for the rest , only for self genereted logs ill change it alter 
                time.sleep(0.05)
                line += f.readline()
            q.put((source, line.strip(), history))  


def follow_log(files, replay=True):   #replay pass
    for src, path in files.items():
        threading.Thread(target=_tail, args=(path, src, replay), daemon=True).start()
    return q