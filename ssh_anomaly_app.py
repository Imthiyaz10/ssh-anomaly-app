import streamlit as st
import pandas as pd
import re
from sklearn.ensemble import IsolationForest

st.title("🚨 SSH Log Anomaly Detector")

uploaded_file = st.file_uploader("Upload SSH log file (.txt)", type=["txt"])

if uploaded_file is not None:
    # Read log lines
    logs = uploaded_file.read().decode("utf-8").splitlines()

    data = []
    pattern = r'(\w+ \d+ \d+:\d+:\d+) server sshd\[\d+\]: (\w+) password for (\w+) from ([\d\.]+) port (\d+) ssh2'

    for line in logs:
        match = re.match(pattern, line)
        if match:
            timestamp, result, user, ip, port = match.groups()
            hour = int(timestamp.split()[2].split(":")[0])
            data.append({
                'timestamp': timestamp,
                'user': user,
                'ip': ip,
                'port': int(port),
                'hour': hour,
                'result': 1 if result == 'Accepted' else 0
            })

    if not data:
        st.error("❌ Could not parse any valid SSH log lines.")
    else:
        df = pd.DataFrame(data)

        # Encode categories
        df_encoded = df.copy()
        df_encoded['user'] = df['user'].astype('category').cat.codes
        df_encoded['ip'] = df['ip'].astype('category').cat.codes

        # Train Isolation Forest model
        model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        df['anomaly'] = model.fit_predict(df_encoded[['user', 'ip', 'port', 'hour', 'result']])

        # Display results
        st.subheader("📄 Full SSH Log Data")
        st.dataframe(df)

        # Show anomalies
        anomalies = df[df['anomaly'] == -1]
        st.subheader("⚠️ Detected Anomalies")
        st.dataframe(anomalies)

        # Download anomalies
        csv = anomalies.to_csv(index=False).encode("utf-8")
        st.download_button("Download Anomalies CSV", data=csv, file_name="anomalies.csv", mime="text/csv")
