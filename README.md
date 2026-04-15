# dpi-ips-project
Intrusion Prevention System using DPI

# DPI-Based Intrusion Prevention System (IPS)

## Overview
This project implements a Pattern-Based Stateful Deep Packet Inspection (DPI) Intrusion Prevention System using Machine Learning to detect and prevent malicious network traffic.

## Features
- Real-time packet capture using Scapy
- Protocol parsing (DNS, HTTP, TLS)
- Rule-based detection engine
- Machine Learning classification (Random Forest)
- Dataset: NSL-KDD
- Accuracy: 99%

## Folder Structure
- capture/ → packet capture modules
- parser/ → protocol parsing (DNS, HTTP, TLS)
- classifier/ → ML model & rule engine
- dataset/ → NSL-KDD dataset
- ips/ → intrusion prevention logic
- logs/ → attack logs

## How to Run
pip install scapy pandas scikit-learn  
python main.py
