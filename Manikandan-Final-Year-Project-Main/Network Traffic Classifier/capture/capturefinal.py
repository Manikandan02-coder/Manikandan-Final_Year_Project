import os
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from scapy.all import conf, sniff, wrpcap

PACKETS_TO_CAPTURE = 1000

# ── Path config: works on both Windows and Linux/Docker ───────────────────────
if os.name == 'nt':  # Windows
    OUTPUT_DIR = r"C:\Users\mages\Downloads\Periscope-main\Periscope-main\Network Traffic Classifier\data1"
else:                # Linux / Docker
    OUTPUT_DIR = "/app/data1"

os.makedirs(OUTPUT_DIR, exist_ok=True)
# ──────────────────────────────────────────────────────────────────────────────

captured_packets = []
file_counter = 1  # unique filename per batch

def packet_callback(packet):
    global captured_packets
    captured_packets.append(packet)
    if len(captured_packets) == PACKETS_TO_CAPTURE:
        save_packets()

def save_packets():
    global captured_packets, file_counter
    filename = os.path.join(OUTPUT_DIR, f"captured_packets_{file_counter}.pcap")
    wrpcap(filename, captured_packets)
    print(f"{len(captured_packets)} packets saved to {filename}")
    captured_packets = []
    file_counter += 1

def main():
    print(f"Starting capture on interface: {conf.iface}")
    print(f"Saving to: {OUTPUT_DIR}")
    while True:  # keep capturing in batches continuously
        sniff(iface=conf.iface, prn=packet_callback, store=0, count=PACKETS_TO_CAPTURE)

if __name__ == "__main__":
    main()