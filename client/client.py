import sys
import requests


def main(argv):
    URL = 'http://127.0.0.1:8000/session/login'

    client = requests.session()

    # Retrieve the CSRF token first
    client.get(URL)  # sets cookie
    if 'csrftoken' in client.cookies:
        # Django 1.6 and up
        csrftoken = client.cookies['csrftoken']
    else:
        # older versions
        csrftoken = client.cookies['csrf']

    login_data = dict(session_id= argv[0], user_id= int(argv[1]), csrfmiddlewaretoken=csrftoken, next='/session/check')
    r = client.post(URL, data=login_data, headers=dict(Referer=URL))
    print(r.status_code, r.reason)


if __name__ == "__main__":
    main(sys.argv[1:])
