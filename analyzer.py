import re
import math
import string
import os
def load_common_passwords(filepath="common_passwords.txt"):
    common = set()
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                pw = line.strip().lower()
                if pw:
                    common.add(pw)
    return common

def check_character_variety(password):
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_special = any(c in string.punctuation for c in password)

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_special:
        pool_size += len(string.punctuation)  # 32 symbols

    return {
        "lowercase": has_lower,
        "uppercase": has_upper,
        "digit": has_digit,
        "special": has_special,
        "pool_size": pool_size,
    }

def calculate_entropy(password, pool_size):
    if pool_size == 0 or len(password) == 0:
        return 0.0
    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)

def detect_patterns(password):
    issues = []
    lowered = password.lower()

    # Repeated characters e.g. "aaa", "111"
    if re.search(r"(.)\1{2,}", password):
        issues.append("Repeated characters mil rahe hain (e.g. 'aaa', '111')")

    # Sequential characters e.g. "abc", "123"
    sequence_str = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(len(lowered) - 2):
        chunk = lowered[i:i + 3]
        if chunk in sequence_str:
            issues.append(f"Sequential characters mil rahe hain ('{chunk}')")
            break
  # Common keyboard row patterns
    keyboard_patterns = ["qwerty", "asdfgh", "zxcvbn", "qazwsx", "1qaz2wsx"]
    for pattern in keyboard_patterns:
        if pattern in lowered:
            issues.append(f"Keyboard pattern mil raha hai ('{pattern}')")
            break

    return issues
def check_common_password(password, common_passwords):
    return password.lower() in common_passwords
def length_score(password):
    length = len(password)
    if length < 6:
        return 0
    elif length < 8:
        return 5
    elif length < 10:
        return 10
    elif length < 12:
        return 15
    elif length < 14:
        return 20
    elif length < 16:
        return 25
    else:
        return 30

def format_duration(seconds):
    """Seconds ko human-readable duration mein convert karta hai."""
    if seconds < 1:
        return "Instantly (< 1 second)"

    units = [
        ("century", 60 * 60 * 24 * 365 * 100),
        ("year", 60 * 60 * 24 * 365),
        ("day", 60 * 60 * 24),
        ("hour", 60 * 60),
        ("minute", 60),
        ("second", 1),
    ]

    plural = {"century": "centuries"}

    for name, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            label = plural.get(name, name + "s")
            if value > 1_000_000:
                return f"{value:.2e} {label}"
            return f"{value:.1f} {label}"

    return "Instantly (< 1 second)"


def estimate_crack_time(entropy_bits, is_common=False):
    """
    Teen attack scenarios ke liye crack time estimate karta hai:
      1. Online throttled  - login form jo rate-limit karta hai (100 guesses/sec)
      2. Offline slow hash - bcrypt/argon2 jaisi achi hashing (10,000 guesses/sec)
      3. Offline fast hash - GPU cracking rig, kamzor hashing (10 billion guesses/sec)
    """
    if is_common:
        return {
            "Online attack (throttled)": "Instantly (password list mein maujood hai)",
            "Offline attack (slow hash)": "Instantly (password list mein maujood hai)",
            "Offline attack (fast hash / GPU)": "Instantly (password list mein maujood hai)",
        }

    total_combinations = 2 ** entropy_bits
    average_guesses = total_combinations / 2

    scenarios = {
        "Online attack (throttled, ~100 guesses/sec)": 100,
        "Offline attack (slow hash e.g. bcrypt, ~10K guesses/sec)": 10_000,
        "Offline attack (fast hash / GPU, ~10B guesses/sec)": 10_000_000_000,
    }

    results = {}
    for label, speed in scenarios.items():
        seconds = average_guesses / speed
        results[label] = format_duration(seconds)

    return results

def generate_suggestions(password, variety, patterns, is_common):
    tips = []

    if is_common:
        tips.append("Ye ek bohat common password hai - foran change karo.")
        return tips  

    if len(password) < 12:
        tips.append("Password ki length kam se kam 12 characters rakho.")
    if not variety["uppercase"]:
        tips.append("Kam se kam ek UPPERCASE letter add karo (A-Z).")
    if not variety["lowercase"]:
        tips.append("Kam se kam ek lowercase letter add karo (a-z).")
    if not variety["digit"]:
        tips.append("Kam se kam ek number add karo (0-9).")
    if not variety["special"]:
        tips.append("Kam se kam ek special character add karo (!@#$ etc.).")
    for issue in patterns:
        tips.append(f"Fix karo: {issue}")

    if not tips:
        tips.append("Bohat achha! Ye password strong hai, koi major issue nahi.")

    return tips
def analyze_password(password, common_passwords=None):
    if common_passwords is None:
        common_passwords = set()

    variety = check_character_variety(password)
    entropy = calculate_entropy(password, variety["pool_size"])
    patterns = detect_patterns(password)
    is_common = check_common_password(password, common_passwords)
    score = 0
    score += length_score(password)                  # max 30
    score += 10 if variety["lowercase"] else 0        # max 10
    score += 10 if variety["uppercase"] else 0        # max 10
    score += 10 if variety["digit"] else 0            # max 10
    score += 10 if variety["special"] else 0          # max 10
    score += min(entropy / 4, 30)                     # max 30 (entropy bonus)
    score -= len(patterns) * 10

    if is_common:
        score = min(score, 5)

    # Clamp between 0 and 100
    score = max(0, min(100, round(score)))

    if score <= 20:
        rating = "Very Weak"
    elif score <= 40:
        rating = "Weak"
    elif score <= 60:
        rating = "Medium"
    elif score <= 80:
        rating = "Strong"
    else:
        rating = "Very Strong"

    suggestions = generate_suggestions(password, variety, patterns, is_common)
    crack_times = estimate_crack_time(entropy, is_common)

    return {
        "password_length": len(password),
        "variety": variety,
        "entropy_bits": entropy,
        "pattern_issues": patterns,
        "is_common_password": is_common,
        "score": score,
        "rating": rating,
        "suggestions": suggestions,
        "crack_time_estimates": crack_times,
    }