import requests
import pickle
import base64


def main():
    URL = 'http://127.0.0.1:8000/session/register'

    client = requests.session()

    # Retrieve the CSRF token first
    client.get(URL)  # sets cookie
    if 'csrftoken' in client.cookies:
        # Django 1.6 and up
        csrftoken = client.cookies['csrftoken']
    else:
        # older versions
        csrftoken = client.cookies['csrf']
    with open('keys/key', 'rb') as key_file:
        key = pickle.load(key_file)
        pk = base64.b64encode(pickle.dumps(key.publickey()))
        login_data = dict(pk=pk, csrfmiddlewaretoken=csrftoken, next='/session')
        r = client.post(URL, data=login_data, headers=dict(Referer=URL))
        print(r.status_code, r.reason)


if __name__ == "__main__":
    main()
