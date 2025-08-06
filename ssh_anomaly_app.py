import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
from io import StringIO
import re

# Page config
st.set_page_config(page_title="SSH Log Anomaly Detector", layout="centered")

# Title and instructions
st.title("🛡️ SSH Log Anomaly Detection Tool")
st.write("Upload your SSH log file (.log or .txt) to detect suspicious login activity.")

# File uploader
uploaded_file = st.file_uploader("📤 Upload SSH log file", type=["log", "txt"])

if uploaded_file:
    try:
        content = StringIO(uploaded_file.getvalue().decode("utf-8"))
        log_lines = content.readlines()

        # Debug: show first few lines of uploaded log
        st.subheader("📄 Raw Log Lines (First 10)")
        st.text("".join(log_lines[:10]))

        # Parse log lines
        data = []
        for line in log_lines:
            if "Failed password" in line:
                st.success(f"✅ Found 'Failed password' line:\n{line.strip()}")
                match = re.search(r'from ([\d\.]+).*?(\d{2}):\d{2}:\d{2}', line)
                if match:
                    ip = match.group(1)
                    hour = int(match.group(2))
                    data.append({"IP": ip, "Hour": hour})
                else:
                    st.warning(f"⚠️ Regex failed on line:\n{line.strip()}")

        if len(data) == 0:
            st.error("❌ Could not parse any valid SSH log lines.")
        else:
            df = pd.DataFrame(data)
            st.subheader("📝 Parsed Failed Login Attempts")
            st.dataframe(df)

            # Anomaly detection
            model = IsolationForest(contamination=0.1, random_state=42)
            df["anomaly"] = model.fit_predict(df[["Hour"]])
            df["Status"] = df["anomaly"].map({1: "Normal", -1: "Anomaly"})

            st.subheader("🚨 Detection Results")
            st.dataframe(df)

            anomalies = df[df["Status"] == "Anomaly"]
            st.markdown(f"**🔎 Total Anomalies Found:** {len(anomalies)}")

            # Download button
            csv = df.to_csv(index=False).encode("utf-8")
            st.download_button("⬇️ Download Anomaly Report", csv, "anomaly_report.csv", "text/csv")

    except Exception as e:
        st.error(f"❌ Something went wrong: {e}")
