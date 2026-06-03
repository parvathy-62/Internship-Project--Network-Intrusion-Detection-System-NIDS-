import streamlit as st
import pandas as pd
import joblib

# =====================================================
# LOAD MODELS
# =====================================================

feature_names = [
    'protocol_type',
    'dst_host_srv_count',
    'count',
    'serror_rate',
    'src_bytes',
    'dst_bytes',
    'srv_count',
    'diff_srv_rate',
    'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate',
    'same_srv_rate',
    'dst_host_count',
    'dst_host_same_srv_rate',
    'service_category',
    'flag_category',
    'land',
    'logged_in',
    'root_shell',
    'is_host_login',
    'is_guest_login',
    'duration',
    'wrong_fragment',
    'urgent',
    'hot',
    'num_failed_logins',
    'num_compromised',
    'su_attempted',
    'num_file_creations',
    'num_shells',
    'num_access_files',
    'rerror_rate',
    'srv_diff_host_rate',
    'dst_host_rerror_rate'
]

binary_model = joblib.load("binary_model.pkl")
multiclass_model = joblib.load("multiclass_model.pkl")
scaler = joblib.load("scaler.pkl")

# =====================================================
# PAGE
# =====================================================

st.set_page_config(page_title="Network Intrusion Detection System")

st.title("Network Intrusion Detection System (NIDS)")
st.write("Predict whether network traffic is normal or malicious.")

# =====================================================
# INPUTS
# =====================================================

st.subheader("Enter Network Features")

user_input = {}

for feature in feature_names:
    user_input[feature] = st.number_input(
        feature,
        value=0.0,
        format="%.4f"
    )
# =====================================================
# PREDICT
# =====================================================

data = pd.DataFrame([user_input])

st.write("Input Data")
st.dataframe(data)

# =====================================================
# PREDICTION
# =====================================================

if st.button("Predict"):

    # Scale input
    data_scaled = scaler.transform(data)

    # Binary prediction
    binary_pred = binary_model.predict(data_scaled)[0]

    if binary_pred == 0:
        st.success("Normal Traffic")
    else:
        st.error("Attack Detected")

        # Multiclass prediction
        attack_pred = multiclass_model.predict(data_scaled)[0]

        attack_classes = {
            0: "DoS",
            1: "Normal",
            2: "Probe",
            3: "R2L",
            4: "U2R"
        }

        st.warning(
            f"Attack Type: {attack_classes.get(attack_pred, 'Unknown')}"
        )
