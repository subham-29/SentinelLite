def auth_data():
    with open("logs/auth.log", encoding="utf-8") as f:
        text = f.read()
        return text
authlog= auth_data()


def access_data():
    with open("logs/access.log", encoding="utf-8") as f:
        text = f.read()
        return text
accesslog= access_data()

def linux_data():
    with open("logs/linux.log", encoding="utf-8") as f:
        text = f.read()
        return text
linuxlog= linux_data()

def apache_data():
    with open("logs/apache_error.log", encoding="utf-8") as f1:
        text = f1.read()
        return text
apachelog= apache_data()
