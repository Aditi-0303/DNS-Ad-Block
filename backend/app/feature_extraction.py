from dataclasses import dataclass
from typing import Dict, List


# ============================================================
# Configuration
# ============================================================

RISKY_TLDS = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "xyz",
    "top",
    "club",
    "work",
    "click",
}

VOWELS = {"a", "e", "i", "o", "u"}


FEATURE_NAMES = [
    "Length",
    "SubdomainCount",
    "Entropy",
    "DigitRatio",
    "HyphenCount",
    "VowelRatio",
    "ConsonantRatio",
    "LongestConsecutiveConsonants",
    "NgramSuspicionScore",
    "TldRiskScore",
]


# ============================================================
# Feature container
# ============================================================

@dataclass
class DomainFeatures:
    Domain: str

    Length: float
    SubdomainCount: float
    Entropy: float
    DigitRatio: float
    HyphenCount: float
    VowelRatio: float
    ConsonantRatio: float
    LongestConsecutiveConsonants: float
    NgramSuspicionScore: float
    TldRiskScore: float

    def to_dict(self) -> Dict[str, float]:
        return {
            "Length": self.Length,
            "SubdomainCount": self.SubdomainCount,
            "Entropy": self.Entropy,
            "DigitRatio": self.DigitRatio,
            "HyphenCount": self.HyphenCount,
            "VowelRatio": self.VowelRatio,
            "ConsonantRatio": self.ConsonantRatio,
            "LongestConsecutiveConsonants": (
                self.LongestConsecutiveConsonants
            ),
            "NgramSuspicionScore": self.NgramSuspicionScore,
            "TldRiskScore": self.TldRiskScore,
        }

    def to_vector(self) -> List[float]:
        return [
            self.Length,
            self.SubdomainCount,
            self.Entropy,
            self.DigitRatio,
            self.HyphenCount,
            self.VowelRatio,
            self.ConsonantRatio,
            self.LongestConsecutiveConsonants,
            self.NgramSuspicionScore,
            self.TldRiskScore,
        ]


# ============================================================
# Domain normalization
# ============================================================

def normalize_domain(domain: str) -> str:
    """
    Matches the C# behavior:

        domain.ToLowerInvariant().TrimEnd('.')
    """

    if not domain:
        return ""

    return domain.lower().rstrip(".")


# ============================================================
# Shannon entropy
# ============================================================

def calculate_shannon_entropy(value: str) -> float:
    """
    Exact equivalent of the C# implementation.

    C#:
        GroupBy(c => c)
        probability = count / length
        entropy -= probability * Math.Log2(probability)
    """

    if not value:
        return 0.0

    frequencies: Dict[str, int] = {}

    for character in value:
        frequencies[character] = (
            frequencies.get(character, 0) + 1
        )

    length = len(value)

    entropy = 0.0

    for count in frequencies.values():
        probability = count / length

        entropy -= probability * (
            probability.bit_length()
            if False
            else 0.0
        )

    # Use the actual log2 calculation separately.
    # This produces the same mathematical result as C# Math.Log2().
    entropy = 0.0

    import math

    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return float(entropy)


# ============================================================
# Digit ratio
# ============================================================

def calculate_digit_ratio(value: str) -> float:

    if not value:
        return 0.0

    digit_count = sum(
        character.isdigit()
        for character in value
    )

    return float(digit_count / len(value))


# ============================================================
# Vowel ratio
# ============================================================

def calculate_vowel_ratio(value: str) -> float:

    if not value:
        return 0.0

    vowel_count = sum(
        character in VOWELS
        for character in value
    )

    # IMPORTANT:
    # This matches the C# implementation.
    #
    # C#:
    #   return vowelCount / s.Length
    #
    # It is NOT divided by alphabetic characters only.

    return float(vowel_count / len(value))


# ============================================================
# Consonant ratio
# ============================================================

def calculate_consonant_ratio(value: str) -> float:

    if not value:
        return 0.0

    consonant_count = sum(
        character.isalpha()
        and character not in VOWELS
        for character in value
    )

    # IMPORTANT:
    # Matches C#:
    #
    # consonantCount / s.Length

    return float(consonant_count / len(value))


# ============================================================
# Longest consecutive consonants
# ============================================================

def calculate_longest_consecutive_consonants(
    value: str,
) -> float:

    max_run = 0
    current_run = 0

    for character in value:

        if (
            character.isalpha()
            and character not in VOWELS
        ):
            current_run += 1

            max_run = max(
                max_run,
                current_run,
            )

        else:
            current_run = 0

    return float(max_run)


# ============================================================
# N-gram suspicion
# ============================================================

def calculate_ngram_suspicion(
    value: str,
) -> float:

    # C#:
    #
    # if (s.Length < 3)
    #     return 0f;

    if len(value) < 3:
        return 0.0

    suspicious_trigrams = 0

    total_trigrams = len(value) - 2

    for index in range(total_trigrams):

        trigram = value[index:index + 3]

        consonants = sum(
            character.isalpha()
            and character not in VOWELS
            for character in trigram
        )

        # C#:
        #
        # if (consonants == 3)
        #     suspiciousTrigrams++;

        if consonants == 3:
            suspicious_trigrams += 1

    return float(
        suspicious_trigrams / total_trigrams
    )


# ============================================================
# TLD risk
# ============================================================

def calculate_tld_risk_score(tld: str) -> float:

    if tld in RISKY_TLDS:
        return 1.0

    return 0.0


# ============================================================
# Main feature extraction
# ============================================================

def extract_features(domain: str) -> DomainFeatures:
    """
    Python port of the C# FeatureExtractionService.

    IMPORTANT:
    - Length uses the FULL domain.
    - Lexical features use the registrable-looking SLD,
      which in the original C# implementation is labels[-2].
    - TLD is labels[-1].
    """

    domain = normalize_domain(domain)

    labels = domain.split(".")

    if len(labels) > 1:
        tld = labels[-1]
    else:
        tld = ""

    if len(labels) >= 2:
        main_label = labels[-2]
    elif len(labels) > 0:
        main_label = labels[0]
    else:
        main_label = domain

    subdomain_count = max(
        0,
        len(labels) - 2,
    )

    return DomainFeatures(
        Domain=domain,

        # IMPORTANT:
        # C# uses domain.Length, not mainLabel.Length.
        Length=float(len(domain)),

        SubdomainCount=float(
            subdomain_count
        ),

        Entropy=calculate_shannon_entropy(
            main_label
        ),

        DigitRatio=calculate_digit_ratio(
            main_label
        ),

        HyphenCount=float(
            main_label.count("-")
        ),

        VowelRatio=calculate_vowel_ratio(
            main_label
        ),

        ConsonantRatio=calculate_consonant_ratio(
            main_label
        ),

        LongestConsecutiveConsonants=(
            calculate_longest_consecutive_consonants(
                main_label
            )
        ),

        NgramSuspicionScore=(
            calculate_ngram_suspicion(
                main_label
            )
        ),

        TldRiskScore=calculate_tld_risk_score(
            tld
        ),
    )


# ============================================================
# Convenience function
# ============================================================

def extract_feature_dict(
    domain: str,
) -> Dict[str, float]:

    return extract_features(domain).to_dict()


# ============================================================
# Test
# ============================================================

if __name__ == "__main__":

    test_domains = [
        "google.com",
        "xkq7vbzwqmpz.tk",
        "s3.prd.na.vn.cloud.tesla.com",
        "1.pool.ntp.org",
        "5.cn.akanev.net",
    ]

    print("=" * 70)
    print("XAI-PiBlock Feature Extraction Test")
    print("=" * 70)

    for domain in test_domains:

        features = extract_features(domain)

        print("\n" + "-" * 70)
        print(f"Domain: {domain}")

        for name, value in features.to_dict().items():
            print(f"{name:35}: {value}")