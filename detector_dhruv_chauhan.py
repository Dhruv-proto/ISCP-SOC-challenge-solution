
"""
PII Detector & Redactor
Author: Dhruv Chauhan
Challenge: SOC CTF - Real-time PII Defense

Usage:
    python3 detector_full_dhruv_chauhan.py iscp_pii_dataset_-_Sheet1.csv
"""

import sys
import json
import re
import pandas as pd



PHONE_REGEX = re.compile(r"\b\d{10}\b")
AADHAAR_REGEX = re.compile(r"\b\d{12}\b")
PASSPORT_REGEX = re.compile(r"\b[A-PR-WYa-pr-wy][0-9]{7}\b")  
UPI_REGEX = re.compile(r"\b[\w.\-]+@\w+\b")


def mask_phone(number: str) -> str:
    """Mask a 10-digit phone number, keeping first 2 and last 2 digits."""
    return number[:2] + "XXXXXX" + number[-2:]


def mask_aadhaar(number: str) -> str:
    """Mask Aadhaar number, keeping last 4 digits."""
    return "XXXX XXXX " + number[-4:]


def mask_passport(pnum: str) -> str:
    """Mask passport number, keeping prefix letter and last 2 digits."""
    return pnum[0] + "XXXXX" + pnum[-2:]


def mask_upi(uid: str) -> str:
    """Mask UPI ID, keeping domain part intact."""
    try:
        user, domain = uid.split("@", 1)
        if len(user) <= 2:
            return "X@" + domain
        return user[:2] + "XXX@" + domain
    except ValueError:
        return "[REDACTED_PII]"


def mask_email(email: str) -> str:
    """Mask email address, preserve domain and part of username."""
    try:
        name, domain = email.split("@", 1)
        if len(name) <= 2:
            return "X@" + domain
        return name[:2] + "XXX@" + domain
    except ValueError:
        return "[REDACTED_PII]"


def mask_name(name: str) -> str:
    """Mask full name (first + last)."""
    parts = name.split()
    masked_parts = []
    for p in parts:
        if len(p) > 1:
            masked_parts.append(p[0] + "XXX")
        else:
            masked_parts.append("X")
    return " ".join(masked_parts)


def contains_pii(field: str, value: str) -> str:
    """
    Detects if a field/value contains PII and returns redacted version.
    If no PII detected, return value unchanged.
    """
    if not value or not isinstance(value, str):
        return value
    if PHONE_REGEX.fullmatch(value):
        return mask_phone(value)
    if AADHAAR_REGEX.fullmatch(value):
        return mask_aadhaar(value)
    if PASSPORT_REGEX.fullmatch(value):
        return mask_passport(value)
    if UPI_REGEX.fullmatch(value):
        return mask_upi(value)
    if field in ("name", "full_name") and len(value.split()) >= 2:
        return mask_name(value)
    if field == "email":
        return mask_email(value)
    if field == "upi_id":
        return mask_upi(value)
    if field == "passport":
        return mask_passport(value)
    if field == "phone":
        return mask_phone(value)
    if field == "aadhar":
        return mask_aadhaar(value)

    return value


def analyze_record(record: dict) -> (dict, bool):

    is_pii = False
    redacted = {}
    combo_hits = 0

    for key, val in record.items():
        original_val = val
        new_val = contains_pii(key, val)


        if new_val != original_val:
            is_pii = True

        if key in ("name", "email", "address", "ip_address", "device_id"):
            if val and isinstance(val, str):
                combo_hits += 1

        redacted[key] = new_val

    if combo_hits >= 2:
        is_pii = True
        if "name" in record and record["name"]:
            redacted["name"] = mask_name(record["name"])
        if "email" in record and record["email"]:
            redacted["email"] = mask_email(record["email"])
        if "address" in record and record["address"]:
            redacted["address"] = "[REDACTED_PII]"

    return redacted, is_pii


def main(input_file: str):
    df = pd.read_csv(input_file)

    out_records = []

    for _, row in df.iterrows():
        try:
            data = json.loads(row["data_json"])
        except json.JSONDecodeError:
            data = {}

        redacted_data, pii_flag = analyze_record(data)

        out_records.append({
            "record_id": row["record_id"],
            "redacted_data_json": json.dumps(redacted_data),
            "is_pii": pii_flag
        })

    out_df = pd.DataFrame(out_records)
    output_file = "redacted_output_dhruv_chauhan.csv"
    out_df.to_csv(output_file, index=False)

    print(f"[+] Processed {len(out_records)} records")
    print(f"[+] Output saved -> {output_file}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_dhruv_chauhan.py <input_csv>")
        sys.exit(1)

    main(sys.argv[1])
