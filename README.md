# Automated NGFW Using Isolation Forest Anomaly Detection

**CISC 699: Applied Project in Computer Science**  
**Harrisburg University of Science and Technology**  
**Author:** Unique Upreti | **Instructor:** Mani Akella | **April 2026**

## Overview
This repository contains the source code and research artifacts for a prototype
Next-Generation Firewall (NGFW) that integrates an Isolation Forest unsupervised
anomaly detection model with Suricata-based automated rule generation,
designed for resource-constrained SME environments.

## Results Summary
| Scenario | Baseline F1 | ML NGFW F1 | Baseline FPR | ML NGFW FPR |
|---|---|---|---|---|
| Port Scanning | 0.77 | 0.89 | 9.1% | 6.3% |
| DoS/DDoS | 0.89 | 0.94 | 5.4% | 3.9% |
| Brute-Force Auth | 0.71 | 0.85 | 11.3% | 7.6% |

Mean response latency: **2.3 seconds** | All components: open-source

## Requirements
- Ubuntu 22.04
- Python 3.10+
- Mininet 2.3.0
- Suricata 7.x
- See `requirements.txt`

## Installation
```bash
git clone https://github.com/YOUR_USERNAME/ngfw-isolation-forest.git
cd ngfw-isolation-forest
pip install -r requirements.txt
```

## Project Structure