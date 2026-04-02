"""
Password Strength Checker
A CLI tool that evaluates password strength based on cybersecurity rules.
"""

import re


def check_length(password):
    """Check if password meets minimum length requirement."""
    return len(password) >= 8


def check_uppercase(password):
    """Check if password contains at least one uppercase letter."""
    return bool(re.search(r'[A-Z]', password))


def check_lowercase(password):
    """Check if password contains at least one lowercase letter."""
    return bool(re.search(r'[a-z]', password))


def check_digits(password):
    """Check if password contains at least one digit."""
    return bool(re.search(r'\d', password))


def check_special_chars(password):
    """Check if password contains at least one special character."""
    return bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))


def analyze_password(password):
    """
    Run all checks and return results dict plus a list of suggestions.
    Returns: (results dict, suggestions list, strength string)
    """
    results = {
        'length':   check_length(password),
        'uppercase': check_uppercase(password),
        'lowercase': check_lowercase(password),
        'digits':   check_digits(password),
        'special':  check_special_chars(password),
    }

    suggestions = []
    if not results['length']:
        suggestions.append("Use at least 8 characters")
    if not results['uppercase']:
        suggestions.append("Add uppercase letters (A-Z)")
    if not results['lowercase']:
        suggestions.append("Add lowercase letters (a-z)")
    if not results['digits']:
        suggestions.append("Include numbers (0-9)")
    if not results['special']:
        suggestions.append("Add special characters (!@#$%^&*)")

    passed = sum(results.values())

    if passed <= 2:
        strength = "Weak"
    elif passed <= 4:
        strength = "Medium"
    else:
        strength = "Strong"

    return results, suggestions, strength


def display_results(strength, suggestions):
    """Print the strength rating and any improvement suggestions."""
    colors = {"Weak": "\033[91m", "Medium": "\033[93m", "Strong": "\033[92m"}
    reset = "\033[0m"
    color = colors.get(strength, "")

    print(f"\nPassword Strength: {color}{strength}{reset}")

    if suggestions:
        print("\nSuggestions:")
        for tip in suggestions:
            print(f"  - {tip}")
    else:
        print("\nGreat job! Your password meets all security criteria.")


def main():
    print("=== Password Strength Checker ===\n")

    password = input("Enter your password: ").strip()

    # Handle empty input
    if not password:
        print("\nError: Password cannot be empty. Please try again.")
        return

    _, suggestions, strength = analyze_password(password)
    display_results(strength, suggestions)


if __name__ == "__main__":
    main()
