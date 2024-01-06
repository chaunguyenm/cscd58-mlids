import pandas as pd
from joblib import load

MODEL_PATH = "/usr/src/app/model/intrusion-classifier.joblib"
RAW_FILEPATH = "/usr/src/app/tmp/raw/"
ANALYZED_FILEPATH = "/usr/src/app/tmp/analyzed/"

COL_LABELS=["Dst Port","Protocol","Flow Duration","Tot Fwd Pkts","Tot Bwd Pkts","TotLen Fwd Pkts","TotLen Bwd Pkts","Fwd Pkt Len Max","Fwd Pkt Len Min","Fwd Pkt Len Mean","Fwd Pkt Len Std","Bwd Pkt Len Max","Bwd Pkt Len Min","Bwd Pkt Len Mean","Bwd Pkt Len Std","Flow Byts/s","Flow Pkts/s","Flow IAT Mean","Flow IAT Std","Flow IAT Max","Flow IAT Min","Fwd IAT Tot","Fwd IAT Mean","Fwd IAT Std","Fwd IAT Max","Fwd IAT Min","Bwd IAT Tot","Bwd IAT Mean","Bwd IAT Std","Bwd IAT Max","Bwd IAT Min","Fwd PSH Flags","Bwd PSH Flags","Fwd URG Flags","Bwd URG Flags","Fwd Header Len","Bwd Header Len","Fwd Pkts/s","Bwd Pkts/s","Pkt Len Min","Pkt Len Max","Pkt Len Mean","Pkt Len Std","Pkt Len Var","FIN Flag Cnt","SYN Flag Cnt","RST Flag Cnt","PSH Flag Cnt","ACK Flag Cnt","URG Flag Cnt","CWE Flag Count","ECE Flag Cnt","Down/Up Ratio","Pkt Size Avg","Fwd Seg Size Avg","Bwd Seg Size Avg","Fwd Byts/b Avg","Fwd Pkts/b Avg","Fwd Blk Rate Avg","Bwd Byts/b Avg","Bwd Pkts/b Avg","Bwd Blk Rate Avg","Subflow Fwd Pkts","Subflow Fwd Byts","Subflow Bwd Pkts","Subflow Bwd Byts","Init Fwd Win Byts","Init Bwd Win Byts","Fwd Act Data Pkts","Fwd Seg Size Min","Active Mean","Active Std","Active Max","Active Min","Idle Mean","Idle Std","Idle Max","Idle Min"]
LABELS=['Benign','Infilteration','DoS attacks-Hulk','DoS attacks-SlowHTTPTest','DoS attacks-GoldenEye','DoS attacks-Slowloris','DDOS attack-HOIC','DDOS attack-LOIC-UDP','Bot','Brute Force -Web','Brute Force -XSS','SQL Injection','FTP-BruteForce','SSH-Bruteforce']

print("App started")
loaded = load(MODEL_PATH)
print(type(loaded))

df = pd.read_csv(ANALYZED_FILEPATH + "capture.pcap_Flow.csv")
df.drop(["Timestamp", "Flow ID", "Label", "Src IP", "Src Port", "Dst IP"], axis="columns", inplace=True)
df = pd.DataFrame(df.values, columns=COL_LABELS)
y = loaded.predict(df)
labels = [LABELS[i] for i in y]
print(labels)