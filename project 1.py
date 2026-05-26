import hashlib
import urllib.request
import string

def check_leak_api(password):
    """HIBP Leak check using built-in urllib (No installation required)"""
    sha1_pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_pwd[:5], sha1_pwd[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            data = response.read().decode('utf-8')
            
        hashes = (line.split(':') for line in data.splitlines())
        for h_suffix, count in hashes:
            if h_suffix == suffix:
                return False, int(count)
        return True, 0
    except Exception:
        return True, 0

def password_strength_checker(password):
    if len(password) < 8:
        return "IMMEDIATE FAIL", ["Password must be at least 8 characters."]

    is_safe, count = check_leak_api(password)
    if not is_safe:
        return "CRITICAL RISK", [f"Found in {count:,} public data breaches!"]

    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    score = sum([has_upper, has_digit, has_symbol])
    
    if score == 3:
        return "Strong", []
    elif score == 2:
        return "Medium", ["Add more variety (symbols/numbers)."]
    else:
        return "Weak", ["Add uppercase, numbers, and symbols."]

if __name__ == "__main__":
    pwd = input("Enter password for security analysis: ")
    status, tips = password_strength_checker(pwd)
    print(f"\n[ANALYSIS RESULT]: {status}")
    for tip in tips:
        print(f" - {tip}")