from pathlib import Path
import io
import re
import zipfile
from urllib.parse import urlparse

import pandas as pd
import requests


# ============================================================
# Configuration
# ============================================================

OUTPUT_PATH = Path(__file__).resolve().parent / "domain_only_raw.csv"

MALICIOUS_LIMIT = 10_000
BENIGN_LIMIT = 10_000

PHISHING_URL = (
    "https://raw.githubusercontent.com/"
    "mitchellkrogza/Phishing.Database/master/"
    "phishing-links-ACTIVE.txt"
)

SPAM404_URL = (
    "https://raw.githubusercontent.com/"
    "Spam404/lists/master/main-blacklist.txt"
)

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"


# ============================================================
# Helpers
# ============================================================

IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)


def clean_domain(domain: str) -> str:
    if not domain:
        return ""

    domain = domain.strip()
    domain = domain.replace(r"\n", "")
    domain = domain.replace("\n", "")
    domain = domain.replace("\r", "")
    domain = domain.lower().rstrip(".")

    return domain


def is_valid_domain(domain: str) -> bool:
    if not domain:
        return False

    if IP_PATTERN.fullmatch(domain):
        return False

    if "." not in domain:
        return False

    if " " in domain:
        return False

    return True


def extract_hostname(value: str) -> str:
    value = value.strip()
    value = value.replace(r"\n", "")
    value = value.replace("\n", "")
    value = value.replace("\r", "")

    if not value:
        return ""

    if "://" not in value:
        value = "http://" + value

    try:
        hostname = urlparse(value).hostname
    except Exception:
        return ""

    return clean_domain(hostname)


# ============================================================
# Download malicious sources
# ============================================================

print("=" * 70)
print("XAI-PiBlock Domain-Only Dataset Builder")
print("=" * 70)

print("\nDownloading Phishing.Database...")

phishing_text = requests.get(
    PHISHING_URL,
    timeout=60,
).text

print("Downloading Spam404...")

spam404_text = requests.get(
    SPAM404_URL,
    timeout=60,
).text


# ============================================================
# Extract malicious domains
# ============================================================

malicious_domains = set()


for text in [phishing_text, spam404_text]:

    for line in text.splitlines():

        domain = extract_hostname(line)

        if is_valid_domain(domain):
            malicious_domains.add(domain)


print("\nMalicious domains collected:")
print(len(malicious_domains))


# ============================================================
# Download Tranco
# ============================================================

print("\nDownloading Tranco Top 1M...")

response = requests.get(
    TRANCO_URL,
    timeout=60,
)

response.raise_for_status()

with zipfile.ZipFile(
    io.BytesIO(response.content)
) as z:

    filename = z.namelist()[0]

    tranco = pd.read_csv(
        z.open(filename),
        header=None,
        names=["Rank", "Domain"],
    )


# ============================================================
# Extract benign domains
# ============================================================

benign_domains = set()

for domain in tranco["Domain"]:

    domain = clean_domain(str(domain))

    if is_valid_domain(domain):
        benign_domains.add(domain)


print("Benign domains collected:")
print(len(benign_domains))


# ============================================================
# Remove overlap
# ============================================================

overlap = malicious_domains & benign_domains

print("\nRemoving malicious/benign overlap:")
print(len(overlap))

benign_domains -= malicious_domains


# ============================================================
# Limit dataset
# ============================================================

# ============================================================
# Randomly sample a representative subset
# ============================================================

import random

random.seed(42)

malicious_domains = list(malicious_domains)
benign_domains = list(benign_domains)

if len(malicious_domains) < MALICIOUS_LIMIT:
    raise RuntimeError(
        f"Only {len(malicious_domains)} malicious domains available."
    )

if len(benign_domains) < BENIGN_LIMIT:
    raise RuntimeError(
        f"Only {len(benign_domains)} benign domains available."
    )

malicious_domains = random.sample(
    malicious_domains,
    MALICIOUS_LIMIT,
)

benign_domains = random.sample(
    benign_domains,
    BENIGN_LIMIT,
)

# ============================================================
# Create dataframe
# ============================================================

malicious_df = pd.DataFrame({
    "Domain": malicious_domains,
    "Label": 1,
})

benign_df = pd.DataFrame({
    "Domain": benign_domains,
    "Label": 0,
})


df = pd.concat(
    [
        malicious_df,
        benign_df,
    ],
    ignore_index=True,
)


# Shuffle

df = df.sample(
    frac=1,
    random_state=42,
).reset_index(drop=True)


# ============================================================
# Save
# ============================================================

df.to_csv(
    OUTPUT_PATH,
    index=False,
)


# ============================================================
# Results
# ============================================================

print("\n" + "=" * 70)
print("DATASET CREATED")
print("=" * 70)

print(f"\nOutput: {OUTPUT_PATH}")

print(f"Rows: {len(df)}")

print(
    f"Benign: {(df.Label == 0).sum()}"
)

print(
    f"Malicious: {(df.Label == 1).sum()}"
)

print(
    f"Unique domains: {df.Domain.nunique()}"
)

print("\nSample:")

print(
    df.head(20).to_string(index=False)
)

print("\nDataset creation complete.")