import os
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

DATASET_PATH = "data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

df = pd.read_csv(DATASET_PATH)
df.columns = df.columns.str.strip()

features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s"
]

missing_columns = [col for col in features if col not in df.columns]

if missing_columns:
    raise ValueError(f"Missing columns in dataset: {missing_columns}")

df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna(subset=features)

X = df[features]

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

model = IsolationForest(
    n_estimators=150,
    contamination=0.15,
    random_state=42
)

model.fit(X_scaled)

os.makedirs("model", exist_ok=True)

joblib.dump(model, "model/anomaly_model.pkl")
joblib.dump(scaler, "model/scaler.pkl")
joblib.dump(features, "model/features.pkl")

print("Model trained and saved using CICIDS2017.")