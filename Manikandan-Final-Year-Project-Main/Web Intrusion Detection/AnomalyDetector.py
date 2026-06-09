## The main deployment file
import pandas as pd
import re
import os
import pickle
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from alert import mainalert

# ── Path config: works on both Windows and Linux/Docker ───────────────────────
if os.name == 'nt':  # Windows
    BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
    DATA_FOLDER = os.path.join(BASE_DIR, "data2")
    RESULTS_OUT = os.path.join(BASE_DIR, "data2", "results.csv")
    MODEL_PATH  = os.path.join(BASE_DIR, "isolationforestv2.pkl")
    SCALER_PATH = os.path.join(BASE_DIR, "scalerv2.pkl")
else:               # Linux / Docker
    DATA_FOLDER = "/app/data2"
    RESULTS_OUT = "/app/data2/results.csv"
    MODEL_PATH  = "/app/isolationforestv2.pkl"
    SCALER_PATH = "/app/scalerv2.pkl"

os.makedirs(DATA_FOLDER, exist_ok=True)
# ──────────────────────────────────────────────────────────────────────────────


def feature(df):
    # Extract unique connections based on IP address and request
    uc        = df[['ip', 'request']].drop_duplicates()
    uc_count  = uc['ip'].value_counts()
    ip_volume = df.groupby('ip')['size'].sum()

    df['ip_frequency']            = df['ip'].map(uc_count)
    df['unique_connections_count']= df['ip'].map(uc_count)
    df['ip_volume']               = df['ip'].map(ip_volume)

    def detect_aberrations(url):
        return 1 if re.search(r'/\./|/\.\./', url) else 0

    df['url_aberrations'] = df['request'].apply(detect_aberrations)

    unusual_referrer_pattern = re.compile(r'^-|^(https?://[^/]+)?example\.com')

    def detect_unusual_referrer(referrer):
        return 0 if unusual_referrer_pattern.match(referrer) else 1

    df['unusual_referrer'] = df['referer'].fillna('').apply(detect_unusual_referrer)

    # ── Fix: known_user_agents must be defined BEFORE user_agent_analysis ─────
    known_user_agents = df['user_agent'].value_counts().index.tolist()

    def user_agent_analysis(user_agent):
        if 'Mosaic/0.9' in user_agent:
            return 'old_client'
        elif user_agent not in known_user_agents:
            return 'unusual_user_agent'
        else:
            return 'normal'

    df['user_agent_analysis'] = df['user_agent'].apply(user_agent_analysis)
    # ─────────────────────────────────────────────────────────────────────────

    endpoint_sequence = {}

    def detect_out_of_order_access(ip_address, request):
        if ip_address in endpoint_sequence and request != endpoint_sequence[ip_address]:
            return 1
        else:
            endpoint_sequence[ip_address] = request
            return 0

    df['out_of_order_access'] = df.apply(
        lambda row: detect_out_of_order_access(row['ip'], row['request']), axis=1
    )

    X = df.drop(columns=['ip', 'request', 'time', 'size', 'referer', 'user_agent'], axis=1)
    X['user_agent_analysis'] = X['user_agent_analysis'].astype('category').cat.codes

    return X


def preprocess(log_file):
    df = pd.read_csv(
        log_file,
        sep=r'\s(?=(?:[^"]*"[^"]*")*[^"]*$)(?![^\[]*\])',
        engine='python',
        usecols=[0, 3, 4, 5, 6, 7, 8],
        names=['ip', 'time', 'request', 'status', 'size', 'referer', 'user_agent'],
        na_values='-',
        header=None
    )
    df.dropna(inplace=True)
    return feature(df)


def main():
    # Load model and scaler once — not inside the loop ← was reloading every iteration
    print(f"Loading model from: {MODEL_PATH}")
    with open(MODEL_PATH, 'rb') as model_file:
        model = pickle.load(model_file)

    with open(SCALER_PATH, 'rb') as scaler_file:
        scaler = pickle.load(scaler_file)

    print(f"Monitoring folder: {DATA_FOLDER}")

    while True:
        for new_file in os.listdir(DATA_FOLDER):
            if new_file == 'access.log':
                file_path = os.path.join(DATA_FOLDER, new_file)
                print(f"Detected log file: {file_path}")

                try:
                    X  = preprocess(file_path)
                    uc = X['unique_connections_count'].nunique()

                    new  = scaler.transform(X)
                    pred = model.predict(new)
                    X['Anomaly'] = pred

                    anomalies_count = X[X['Anomaly'] == -1].shape[0]
                    alert_threshold = 0.2 * uc  # 20% threshold (was labelled 25% but set to 0.2)

                    mainalert(anomalies_count, alert_threshold, uc)

                    # ── Fix: results path was hardcoded to Linux ──────────────
                    X.to_csv(RESULTS_OUT, index=False)
                    print(f"Results saved to: {RESULTS_OUT}")
                    # ─────────────────────────────────────────────────────────

                    os.remove(file_path)
                    print(f"Deleted: {new_file}")

                except Exception as e:
                    print(f"Error processing {new_file}: {e}")

        import time
        time.sleep(2)  # ← prevents CPU spin on empty folder


main()