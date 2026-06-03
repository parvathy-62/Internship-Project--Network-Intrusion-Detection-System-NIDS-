import streamlit as st
import pandas as pd
import joblib

# =====================================================
# LOAD MODELS
# =====================================================

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

protocol_type = st.number_input("protocol_type", value=0)
dst_host_srv_count = st.number_input("dst_host_srv_count", value=0)
count = st.number_input("count", value=0)
serror_rate = st.number_input("serror_rate", value=0.0)
src_bytes = st.number_input("src_bytes", value=0.0)
dst_bytes = st.number_input("dst_bytes", value=0.0)

# =====================================================
# PREDICT
# =====================================================

if st.button("Predict"):

    data = pd.DataFrame([[
        protocol_type,
        dst_host_srv_count,
        count,
        serror_rate,
        src_bytes,
        dst_bytes
    ]])

    st.write("Prediction generated.")
