import requests
import hashlib
import os

# Replace with your VirusTotal API key
API_KEY = 'e70e99350ed294ea898c091c9de6f92d5b221e7a8db5ed75bad6e1c4d8b81328'
VT_FILE_SCAN_URL = 'https://www.virustotal.com/api/v3/files'
VT_URL_SCAN_URL = 'https://www.virustotal.com/api/v3/urls'
VT_URL_ANALYSIS = 'https://www.virustotal.com/api/v3/analyses/'

headers = {
    "x-apikey": API_KEY
}


def scan_file_virustotal(file_storage):
    """
    file_storage: Flask's FileStorage object (request.files['file'])
    """
    files = {"file": (file_storage.filename, file_storage.stream, file_storage.content_type)}
    response = requests.post(VT_FILE_SCAN_URL, files=files, headers=headers)

    if response.status_code == 200:
        data = response.json()
        analysis_id = data['data']['id']
        return fetch_analysis_result(analysis_id)
    else:
        return f"Error: {response.status_code} - {response.text}"


def scan_url_virustotal(url):
    data = {"url": url}
    response = requests.post(VT_URL_SCAN_URL, headers=headers, data=data)

    if response.status_code == 200:
        data = response.json()
        analysis_id = data['data']['id']
        return fetch_analysis_result(analysis_id)
    else:
        return f"Error: {response.status_code} - {response.text}"


def fetch_analysis_result(analysis_id):
    import time
    time.sleep(5)  # Delay to give VirusTotal time to analyze

    response = requests.get(VT_URL_ANALYSIS + analysis_id, headers=headers)

    if response.status_code == 200:
        json_data = response.json()
        stats = json_data['data']['attributes']['stats']
        summary = f"Malicious: {stats['malicious']} | Suspicious: {stats['suspicious']} | Harmless: {stats['harmless']} | Undetected: {stats['undetected']}"
        return summary
    else:
        return f"Analysis Error: {response.status_code} - {response.text}"


# Optional: helper to hash a file (if you want to lookup hash instead of upload)
def get_file_hash(file_storage):
    hasher = hashlib.sha256()
    for chunk in file_storage.stream:
        hasher.update(chunk)
    return hasher.hexdigest()
