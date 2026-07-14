import getpass
from analyzer import analyze_password, load_common_passwords
def print_bar(score):
    """Terminal mein ek simple visual progress bar banata hai."""
    filled = int(score / 5)   # score 0-100 ko 0-20 blocks mein convert
    empty = 20 - filled
    bar = "#" * filled + "-" * empty
    return f"[{bar}] {score}/100"

def print_report(password, result):
    print("\n" + "=" * 55)
    print(" PASSWORD STRENGTH REPORT")
    print("=" * 55)
    print(f"Password Length : {result['password_length']}")
    print(f"Entropy         : {result['entropy_bits']} bits")
    print(f"Score           : {print_bar(result['score'])}")
    print(f"Rating          : {result['rating']}")

    v = result["variety"]
    print("\nCharacter Variety:")
    print(f"  Lowercase (a-z) : {'Yes' if v['lowercase'] else 'No'}")
    print(f"  Uppercase (A-Z) : {'Yes' if v['uppercase'] else 'No'}")
    print(f"  Digits    (0-9) : {'Yes' if v['digit'] else 'No'}")
    print(f"  Special   (!@#) : {'Yes' if v['special'] else 'No'}")

    if result["is_common_password"]:
        print("\n⚠ WARNING: Ye password 'common passwords' list mein maujood hai!")

    if result["pattern_issues"]:
        print("\nDetected Weak Patterns:")
        for issue in result["pattern_issues"]:
            print(f"  - {issue}")

    print("\nEstimated Crack Time:")
    for scenario, time_estimate in result["crack_time_estimates"].items():
        print(f"  {scenario}: {time_estimate}")

    print("\nSuggestions:")
    for tip in result["suggestions"]:
        print(f"  * {tip}")
    print("=" * 55 + "\n")

def main():
    print("=" * 55)
    print(" PASSWORD STRENGTH ANALYZER (built from scratch)")
    print("=" * 55)
    common_passwords = load_common_passwords("common_passwords.txt")
    while True:       
        password = getpass.getpass("\nApna password enter karo (hidden input): ")

        if not password:
            print("Khali password enter hua, dobara try karo.")
            continue

        result = analyze_password(password, common_passwords)
        print_report(password, result)

        again = input("Ek aur password check karna hai? (y/n): ").strip().lower()
        if again != "y":
            print("Shukriya! Analyzer band ho raha hai.")
            break

if __name__ == "__main__":
    main()
    