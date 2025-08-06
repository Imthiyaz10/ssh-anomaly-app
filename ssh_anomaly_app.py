import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
from io import StringIO
import re

# Streamlit UI setup
st.set_page_config(page_title="SSH Log Anomaly Detector", layout="centered")
st.title("🛡️ SSH Log Anomaly Detection Tool")
st.write("Upload your SSH log file (.log or .txt) to detect suspicious login activity.")

# Upload
uploaded_file = st.file_uploader("📤 Upload SSH log file", type=["log", "txt"])

if uploaded_file:
    try:
        content = StringIO(uploaded_file.getvalue().decode("utf-8"))
        log_lines = content.readlines()

        st.subheader("📄 Raw Log Lines (First 10)")
        st.text("".join(log_lines[:10]))

        data = []

        for line in log_lines:
            if "Failed password" in line:
                st.success(f"✅ Found 'Failed password' line:\n{line.strip()}")

                # Extract hour from start of line, and IP from later
                match = re.search(r'\s(\d{2}):\d{2}:\d{2}.*?Failed password.*?from ([\d\.]+)', line)
                if match:
                    hour = int(match.group(1))
                    ip = match.group(2)
                    data.append({"IP": ip, "Hour": hour})
                else:
                    st.warning(f"⚠️ Regex failed on line:\n{line.strip()}")

        if len(data) == 0:
            st.error("❌ Could not parse any valid SSH log lines.")
        else:
            df = pd.DataFrame(data)
            st.subheader("📝 Parsed Failed Login Attempts")
            st.dataframe(df)

            # Anomaly Detection
            model = IsolationForest(contamination=0.1, random_state=42)
            df["anomaly"] = model.fit_predict(df[["Hour"]])
            df["Status"] = df["anomaly"].map({1: "Normal", -1: "Anomaly"})

            st.subheader("🚨 Detection Results")
            st.dataframe(df)

            anomalies = df[df["Status"] == "Anomaly"]
            st.markdown(f"**🔎 Total Anomalies Found:** {len(anomalies)}")

            csv = df.to_csv(index=False).encode("utf-8")
            st.download_button("⬇️ Download Anomaly Report", csv, "anomaly_report.csv", "text/csv")

    except Exception as e:
        st.error(f"❌ Something went wrong: {e}")
