import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
from io import StringIO
import re

# Set up Streamlit page
st.set_page_config(page_title="SSH Anomaly Detector", layout="centered")
st.title("🛡️ SSH Log Anomaly Detection Tool")
st.write("Upload your SSH log file (.log or .txt) to detect suspicious login activity.")

# File upload
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

                ip_pattern = re.search(r'from ([\d\.]+)', line)
                time_pattern = re.search(r'\s(\d{2}):\d{2}:\d{2}', line)
                user_match = re.search(r'Failed password for (invalid user )?(\w+)', line)

                if ip_pattern and time_pattern and user_match:
                    hour = int(time_pattern.group(1))
                    ip = ip_pattern.group(1)
                    user_type = user_match.group(1)
                    username = user_match.group(2)

                    if user_type:
                        username_type = "invalid_user"
                    elif username == "root":
                        username_type = "root"
                    else:
                        username_type = "normal_user"

                    # Check if IP is private
                    is_private = ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172.")

                    data.append({
                        "IP": ip,
                        "Hour": hour,
                        "UsernameType": username_type,
                        "IsPrivateIP": int(is_private)
                    })
                else:
                    st.warning(f"⚠️ Regex failed on line:\n{line.strip()}")

        if not data:
            st.error("❌ Could not parse any valid SSH log lines.")
        else:
            df = pd.DataFrame(data)

            # IP Frequency
            df["IPFreq"] = df.groupby("IP")["IP"].transform("count")

            # One-hot encode username type
            df = pd.get_dummies(df, columns=["UsernameType"])

            st.subheader("📝 Parsed Failed Login Attempts")
            st.dataframe(df)

            # Select features
            feature_cols = [
                "Hour", "IsPrivateIP", "IPFreq",
                "UsernameType_invalid_user",
                "UsernameType_normal_user",
                "UsernameType_root"
            ]

            # Handle missing columns (for one-hot encoded categories)
            for col in feature_cols:
                if col not in df.columns:
                    df[col] = 0

            # Anomaly detection
            model = IsolationForest(contamination=0.1, random_state=42)
            df["anomaly"] = model.fit_predict(df[feature_cols])
            df["Status"] = df["anomaly"].map({1: "Normal", -1: "Anomaly"})

            st.subheader("🚨 Detection Results")
            st.dataframe(df)

            anomalies = df[df["Status"] == "Anomaly"]
            st.markdown(f"**🔎 Total Anomalies Found:** {len(anomalies)}")

            csv = df.to_csv(index=False).encode("utf-8")
            st.download_button("⬇️ Download Anomaly Report", csv, "anomaly_report.csv", "text/csv")

    except Exception as e:
        st.error(f"❌ Something went wrong: {e}")
