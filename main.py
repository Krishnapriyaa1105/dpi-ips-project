import pandas as pd
from scapy.all import sniff
from datetime import datetime

from parser.http import parse_http
from parser.dns import parse_dns
from parser.tls import parse_tls
from classifier.rule_engine import classify

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# Network interface
INTERFACE = r"\Device\NPF_{9369B1A3-FB87-497F-BE6E-728A5496C5DA}"

# counters
total_packets = 0
blocked_packets = 0


# ------------------------------
# Logging function
# ------------------------------
def log_to_file(filename, message):
    with open(filename, "a") as f:
        f.write(message + "\n")


# ------------------------------
# Packet Processing
# ------------------------------
def process_packet(packet):

    global total_packets, blocked_packets
    total_packets += 1

    parsed = (
        parse_http(packet)
        or parse_dns(packet)
        or parse_tls(packet)
    )

    if parsed:

        result = classify(parsed)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        log_line = f"{timestamp} | {parsed} | {result}"

        log_to_file("logs/all_traffic.log", log_line)

        if result in ("BLOCKED", "MALICIOUS"):

            blocked_packets += 1

            alert = f"[ALERT] {log_line}"

            print(alert)

            log_to_file("logs/alerts.log", alert)
            log_to_file("logs/blocked.log", log_line)

        else:
            if "domain" in parsed:
                print(f"{timestamp} | Domain Accessed: {parsed['domain']} | {result}")
            else:
                print(log_line)

        log_to_file(
            "logs/stats.log",
            f"Total: {total_packets}, Blocked: {blocked_packets}"
        )


# ------------------------------
# Dataset Evaluation
# ------------------------------
def run_dataset_evaluation():

    print("\nRunning dataset evaluation...\n")

    from dataset.dataset_loader import load_dataset, preprocess_data

    data = load_dataset()

    X_train, X_test, y_train, y_test = preprocess_data(data)

    # Convert labels
    y_train = y_train.map({"normal": 0, "attack": 1})
    y_test = y_test.map({"normal": 0, "attack": 1})

    # One-hot encoding for categorical columns
    X_train = pd.get_dummies(X_train)
    X_test = pd.get_dummies(X_test)

    # Align columns
    X_train, X_test = X_train.align(X_test, join="left", axis=1, fill_value=0)

    # Train model
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train, y_train)

    # Predictions
    y_pred = model.predict(X_test)

    # Metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print("---- IPS Performance Evaluation ----\n")
    
    print(f"Accuracy : {accuracy*100:.2f}%")
    print(f"Precision: {precision*100:.2f}%")
    print(f"Recall   : {recall*100:.2f}%")
    print(f"F1 Score : {f1*100:.2f}%")

    print("\nConfusion Matrix:\n")
    print(confusion_matrix(y_test, y_pred))

    print("\nSample Predictions:")
    print(y_pred[:10])


# ------------------------------
# Main Program
# ------------------------------
if __name__ == "__main__":

    print("Starting IPS packet capture...\n")

    sniff(
        iface=INTERFACE,
        prn=process_packet,
        count=10
    )

    run_dataset_evaluation()