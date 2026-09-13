#!/usr/bin/env python3
"""Check document structure only; translation meaning requires human review."""

import argparse
from collections import Counter
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parent.parent
PATHS = {
    "en": ROOT / "docs/ops/privileged-credential-rotation.md",
    "zh-TW": ROOT / "docs/zh-TW/ops/privileged-credential-rotation.md",
    "ja": ROOT / "docs/ja/ops/privileged-credential-rotation.md",
}
ANCHORS = (
    "vault-transit", "vault-availability", "vault-configuration",
    "vault-authentication", "vault-secretid", "vault-actions",
    "vault-migration", "vault-recovery", "vault-protection",
)
KEYS = {
    "KEK_PROVIDER", "KEK_KMS_PROVIDER", "KEK_KMS_KEY_ID", "KEK_KMS_REGION",
    "KEK_VAULT_ADDR", "KEK_VAULT_ROLE_ID", "KEK_VAULT_SECRET_ID", "ENCRYPTION_KEY",
}
LINKS = {
    "https://developer.hashicorp.com/vault/api-docs/secret/transit",
    "https://developer.hashicorp.com/vault/api-docs/auth/approle",
    "https://developer.hashicorp.com/vault/api-docs/auth/token",
    "./backup-and-restore.md",
}
REQUESTS = {
    "POST /v1/transit/encrypt/<key>", "POST /v1/transit/decrypt/<key>",
    "POST /v1/transit/keys/<key>/rotate", "POST /v1/transit/rewrap/<key>",
    "DELETE /api/v1/keys/rewrap",
}


class Invalid(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def inspect(language):
    path = PATHS[language]
    text = path.read_text(encoding="utf-8")
    marker = '<a id="vault-transit"></a>'
    require(text.count(marker) == 1, "Vault section must occur exactly once")
    section = text.split(marker, 1)[1]
    anchors = ["vault-transit", *re.findall(r'<a id="([^"]+)"></a>', section)]
    require(tuple(anchors) == ANCHORS, "section anchors missing, duplicated or reordered")
    headings = re.findall(r"^### (14\.[1-8])\s+.+$", section, re.M)
    require(headings == [f"14.{i}" for i in range(1, 9)], "eight ordered headings required")
    subsections = re.split(r"^### 14\.[1-8]\s+.+$", section, flags=re.M)[1:]
    require(all(len(re.sub(r"<a [^>]+></a>", "", s).strip()) > 0 for s in subsections),
            "empty subsection")
    for index, size in ((3, 5), (5, 6)):
        steps = re.findall(r"^(\d+)\. ", subsections[index], re.M)
        require(steps == [str(i) for i in range(1, size + 1)], "ordered procedure steps differ")

    fences = re.findall(r"^```([^\n]*)\n(.*?)^```\s*$", section, re.M | re.S)
    require([kind for kind, _ in fences] == ["dotenv", "hcl"], "configuration and policy blocks required")
    settings = dict(re.findall(r"^([A-Z_]+)=(.*)$", fences[0][1], re.M))
    require(set(settings) == KEYS, "configuration key set differs")
    require(settings["KEK_PROVIDER"] == "kms" and settings["KEK_KMS_PROVIDER"] == "vault",
            "target configuration selectors differ")
    require(all(settings[key] == "" for key in
                ("KEK_VAULT_ROLE_ID", "KEK_VAULT_SECRET_ID", "KEK_KMS_REGION", "ENCRYPTION_KEY")),
            "credential and inapplicable material fields must be empty examples")

    links = Counter(re.findall(r"\[[^\]\n]+\]\(([^)\s]+)\)", section))
    require(set(links) == LINKS, "required link set differs")
    for target in links:
        if target.startswith("./"):
            require((path.parent / target).is_file(), "local link target missing")
    requests = Counter(re.findall(r"`((?:POST|DELETE) /[^`]+)`", section))
    require(set(requests) == REQUESTS, "operation endpoint set differs")
    keys = set(re.findall(r"\b(?:KEK_[A-Z_]+|ENCRYPTION_KEY|VAULT_[A-Z_]+)\b", section))
    return fences, links, requests, keys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", required=True, choices=("en", "all"))
    args = parser.parse_args()
    selected = ("en",) if args.language == "en" else tuple(PATHS)
    results = {}
    for language in selected:
        try:
            results[language] = inspect(language)
            if language != "en":
                require(results[language] == results["en"],
                        "code blocks, links, endpoints or configuration names differ from English")
        except (Invalid, OSError) as error:
            print(f"FAIL {language}: {error}", file=sys.stderr)
            return 1
        print(f"PASS {language}: structure=8-sections keys=8 code-blocks=2 links=4 endpoints=5")
    print("LIMIT: mechanical checks only; translation meaning and operational claims require human comparison.")
    print("LIMIT: external link targets were checked as text, not fetched; local targets exist.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
