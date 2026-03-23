from urllib.parse import urljoin

COMMON_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("test", "test"),
    ("user", "password")
]

def is_login_form(form):
    for inp in form["inputs"]:
        if inp["type"] == "password" :
            return True
    return False

def test_login_form(session, form):

    target_url = form["url"]
    action = form["action"]
    method = form["method"]

    url = urljoin(target_url, action)

    for username, password in COMMON_CREDENTIALS:

        data = {}

        for field in form["inputs"]:
            name = field["name"]

            if "user" in name.lower():
                data[name] = username
            elif "pass" in name.lower():
                data[name] = password
            else:
                data[name] = field["value"]

        if method == "POST":
            response = session.post(url, data=data)
        else:
            response = session.get(url, params=data)

        # Very simple detection logic
        if "logout" in response.text.lower() or "welcome" in response.text.lower():
            print("Weak credential found!")
            print(username, password)