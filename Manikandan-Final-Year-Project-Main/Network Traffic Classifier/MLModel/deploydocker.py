import os
import time
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
import pandas as pd
from scapy.all import rdpcap, IP, TCP, IPerror, UDP

# ── Path config: works on both Windows and Linux/Docker ───────────────────────
if os.name == 'nt':  # Windows
    CAPTURE_DIR = r"C:\Users\mages\Downloads\Periscope-main\Periscope-main\Network Traffic Classifier\data1"
    CSV_OUTPUT  = r"C:\Users\mages\Downloads\Periscope-main\Periscope-main\Network Traffic Classifier\data2\output.csv"
else:                # Linux / Docker
    CAPTURE_DIR = "/app/data1"
    CSV_OUTPUT  = "/app/data2/output.csv"

os.makedirs(CAPTURE_DIR, exist_ok=True)
os.makedirs(os.path.dirname(CSV_OUTPUT), exist_ok=True)
# ──────────────────────────────────────────────────────────────────────────────

def extract_connection_stats(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        return {}   # ← was missing; caused crash if file unreadable

    connection_stats = {}

    for packet in packets:
        if IP in packet:
            src_ip    = packet[IP].src
            dst_ip    = packet[IP].dst
            src_port  = 0
            dst_port  = 0

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            connection_key = f"{src_ip}_{src_port}_{dst_ip}_{dst_port}"
            land = 1 if src_ip == dst_ip and src_port == dst_port else 0

            if connection_key in connection_stats:
                connection_stats[connection_key]["packet_count"]          += 1
                connection_stats[connection_key]["bytes_sent_src_to_dst"] += len(packet[IP])

                if packet[IP].src == connection_stats[connection_key]["dst_ip"]:
                    connection_stats[connection_key]["bytes_sent_dst_to_src"] += len(packet[IP])

                connection_stats[connection_key]["duration"] = (
                    packet.time - connection_stats[connection_key]["start_time"]
                )
                connection_stats[connection_key]["land"] = land

                if IPerror in packet:
                    connection_stats[connection_key]["wrong_fragments"] += 1

                if TCP in packet and packet[TCP].urgptr != 0:
                    connection_stats[connection_key]["urgent_packets"] += 1
            else:
                connection_stats[connection_key] = {
                    "src_ip": src_ip, "src_port": src_port,
                    "dst_ip": dst_ip, "dst_port": dst_port,
                    "packet_count": 1, "start_time": packet.time,
                    "duration": 0,
                    "bytes_sent_src_to_dst": len(packet[IP]),
                    "bytes_sent_dst_to_src": len(packet[IP]),
                    "land": land, "wrong_fragments": 0, "urgent_packets": 0,
                    "hot": 1, "num_failed_logins": 0, "logged_in": 0,
                    "num_compromised": 0, "root_shell": 0, "su_attempted": 0,
                    "num_root": 0, "num_file_creations": 0, "num_shells": 0,
                    "num_access_files": 0, "num_outbound_cmds": 0,
                    "is_host_login": 0, "is_guest_login": 0,
                    "count": 1, "srv_count": 1,
                    "serror_rate": 0, "srv_serror_rate": 0,
                    "rerror_rate": 0, "srv_rerror_rate": 0,
                    "same_srv_rate": 0, "diff_srv_rate": 0,
                    "srv_diff_host_rate": 0, "dst_host_count": 0,
                    "dst_host_srv_count": 0, "dst_host_same_srv_rate": 0,
                    "dst_host_diff_srv_rate": 0, "dst_host_same_src_port_rate": 0,
                    "dst_host_srv_diff_host_rate": 0, "dst_host_serror_rate": 0,
                    "dst_host_srv_serror_rate": 0, "dst_host_rerror_rate": 0,
                    "dst_host_srv_rerror_rate": 0
                }

    return connection_stats


def save_to_csv(connection_stats, csv_file):
    df = pd.DataFrame.from_dict(connection_stats, orient="index")
    X  = df.drop(["src_ip", "src_port", "dst_ip", "dst_port", "packet_count", "start_time"], axis=1)
    X['connection_key'] = X.index
    X.to_csv(csv_file, index=False, header=True)
    print(f"CSV saved to {csv_file}")


def watch_capture_directory(directory_path):
    print(f"Watching: {directory_path}")
    while True:
        for filename in os.listdir(directory_path):
            if filename.endswith(".pcap"):
                file_path = os.path.join(directory_path, filename)
                print(f"Processing: {filename}")
                time.sleep(1)
                connection_stats = extract_connection_stats(file_path)
                if connection_stats:                    # ← guard: skip empty result
                    save_to_csv(connection_stats, CSV_OUTPUT)
                os.remove(file_path)
                print(f"Deleted: {filename}")
        time.sleep(2)                                   # ← prevents CPU spin


def main():
    watch_capture_directory(CAPTURE_DIR)

if __name__ == "__main__":
    main()