# Project Guardian 2.0 – Real-time PII Defense

This repository contains my solution for the SOC CTF challenge **“Real-time PII Defense”**.  
The project focuses on detecting and redacting Personally Identifiable Information (PII) from incoming data streams to prevent data leaks and fraud.

---

## 📂 Repository Contents
- `detector_full_dhruv_chauhan.py` → Python script that detects and redacts PII.  
- `iscp_pii_dataset.csv` → Input dataset (provided during the challenge).  
- `redacted_output_dhruv_chauhan.csv` → Output file with PII masked and a new `is_pii` flag.  
- `deployment_strategy_dhruv_chauhan.md` → Write-up describing how to deploy the solution in a production environment.  
- `README.md` → This file.

---

## 🚀 How to Run
Make sure you have Python 3 installed. Then run:

```bash
python3 detector_full_dhruv_chauhan.py iscp_pii_dataset.csv
