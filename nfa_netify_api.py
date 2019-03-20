import json
import urllib.request

def get(url):
    try:
        with urllib.request.urlopen(url) as ul:
            data = json.loads(ul.read().decode())
            #print(data)
        return data
    except urllib.error.URLError as e:
        print("API request failed: %s" %(e.reason))
        return None

def get_data(url):
    pages = []

    data = get(url)

    if data is None:
        return None

    if 'status_code' not in data:
        return None

    if data['status_code'] != 0:
        return None

    if 'data_info' not in data:
        return None

    data_info = data['data_info']

    if 'total_pages' not in data_info:
        return None

    total_pages = data_info['total_pages']

    if 'data' not in data:
        return None

    pages.append(data['data'])

    if total_pages > 1:
        for page in range(2, total_pages + 1):
            #print("Get page: %d / %d..." %(page, total_pages))
            data = get(url + '?page=' + str(page))

            if data is None:
                return None

            if 'status_code' not in data:
                return None

            if data['status_code'] != 0:
                return None

            if 'data' not in data:
                return None

            pages.append(data['data'])

    return pages
