"""
Turns findings into specific, actionable advice.

Rule: suggestions never repeat or quote the user's password.
"""

BY_FINDING = {
    "common_password": "Your password matches a commonly used password pattern and should not be used.",
    "common_variant": "Your password is a common password with simple character swaps (like @ for a). Attackers try these swaps first.",
    "common_word_pattern": "Adding digits or symbols to a very common word is predictable. Choose something unrelated to common words.",
    "predictable_structure": "Avoid the 'word + number' formula (for example a word followed by 123 or a year).",
    "dictionary_word": "Your password is built mostly from common dictionary words. Combine several unrelated random words instead.",
    "sequence": "Your password contains a predictable numeric or alphabetic sequence. Remove it.",
    "keyboard_pattern": "Avoid common keyboard sequences such as qwerty or asdf.",
    "repeated_character": "Avoid repeating the same character several times in a row.",
    "repeated_substring": "Avoid repeating the same block of characters; repetition adds length but not unpredictability.",
    "year_pattern": "Avoid years and dates; they are among the easiest things to guess.",
    "personal_info": "Avoid including your name, birth year or organisation name.",
    "short_length": "Consider using a longer password or passphrase (12-16+ characters).",
    "low_variety": "Mix in more unrelated characters, or switch to a long passphrase of random words.",
}


def generate_suggestions(findings: list, metrics: dict, score: int) -> list:
    suggestions = []
    seen_types = {f["type"] for f in findings}
    for ftype, text in BY_FINDING.items():
        if ftype in seen_types:
            suggestions.append(text)

    if score < 61:
        suggestions.append("Increase unpredictability: use a generated password or a long passphrase of random words.")
    elif score < 81 and not suggestions:
        suggestions.append("Good start. A few more random characters or an extra random word would make it harder to guess.")
    else:
        if not suggestions:
            suggestions.append("No obvious weaknesses were found by this tool. That is not a guarantee; see the limitations.")

    suggestions += [
        "Avoid reusing passwords across different accounts.",
        "Use a password manager to generate and store unique passwords.",
        "Enable multi-factor authentication (MFA) where available.",
    ]
    return suggestions
