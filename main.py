def auth_data():
    with open("logs/auth.log", encoding="utf-8") as f1:
        text = f1.read()
        return text
authlog= auth_data()
