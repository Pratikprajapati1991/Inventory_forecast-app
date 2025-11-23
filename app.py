import streamlit as st
import pandas as pd
import numpy as np
import altair as alt
import zipfile
import sqlite3
from datetime import datetime
from io import BytesIO
import requests

# ======================================================
# CONFIG
# ======================================================
st.set_page_config(page_title="Item Master Forecast App", layout="wide")

# --- Simple Auth Settings (can be overridden via Secrets) ---
VALID_USER = st.secrets.get("APP_USERNAME", "admin")
VALID_PASS = st.secrets.get("APP_PASSWORD", "Pratik@123")

# Optional hosted default file (e.g. from GitHub raw URL)
DEFAULT_FILE_URL = st.secrets.get("DEFAULT_FILE_URL", "")

DB_PATH = "app_data.db"


# ======================================================
# DB HELPERS
# ======================================================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            filename TEXT,
            rows INTEGER
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS searches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            query TEXT,
            results INTEGER
        )
        """
    )
    conn.commit()
    conn.close()


def log_upload(filename: str, rows: int):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO uploads (ts, filename, rows) VALUES (?, ?, ?)",
            (datetime.utcnow().isoformat(), filename, rows),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # don't break app on logging error


def log_search(query: str, results: int):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO searches (ts, query, results) VALUES (?, ?, ?)",
            (datetime.utcnow().isoformat(), query, results),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# ======================================================
# LOGIN
# ======================================================
def require_login():
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if st.session_state.authenticated:
        return

    st.markdown("### 🔐 Login to Item Master Forecast App")

    with st.form("login_form"):
        username = st.text_input("Username", value="")
        password = st.text_input("Password", type="password", value="")
        submitted = st.form_submit_button("Login")

    if submitted:
        if username == VALID_USER and password == VALID_PASS:
            st.session_state.authenticated = True
            st.experimental_rerun()
        else:
            st.error("Invalid username or password.")
            st.stop()
    else:
        st.stop()


# ======================================================
# SMALL HELPERS
# ======================================================
def fmt(x):
    try:
        if pd.isna(x):
            return "-"
        return f"{float(x):.0f}"
    except Exception:
        return "-"


def load_default_file_from_url():
    if not DEFAULT_FILE_URL:
        st.warning("No DEFAULT_FILE_URL configured in Streamlit secrets.")
        return None

    try:
        resp = requests.get(DEFAULT_FILE_URL)
        resp.raise_for_status()
        bio = BytesIO(resp.content)
        bio.name = "default.xlsx"
        return bio
    except Exception as e:
        st.error(f"Error downloading default file: {e}")
        return None


# ======================================================
# APP START
# ======================================================
require_login()
init_db()

st.markdown(
    "<h1 style='text-align:center;'>📦 Item Master Forecast App</h1>",
    unsafe_allow_html=True,
)
st.write(
    "Upload your processed Excel file and explore it with search, forecast, "
    "inventory KPIs, and vendor intelligence."
)

with st.sidebar:
    st.markdown("### ℹ️ Help & Info")
    st.write(
        """
        **Steps to use:**
        1. Upload your final Excel (`.xlsx`) or a ZIP containing the file.
        2. Use **Search** to find any item.
        3. Use **Forecast & Planning** for inventory decisions.
        4. Use **Vendor Recommendation** to see suggested vendor.
        """
    )
    st.write("---")
    st.write("Logged in as:", f"**{VALID_USER}**")


# ======================================================
# FILE UPLOAD SECTION
# ======================================================
st.subheader("Step 1: Upload Final Excel File")

uploaded_file = st.file_uploader(
    "Upload Final Excel File (XLSX or ZIP containing XLSX)",
    type=["xlsx", "zip"],
)

col_left, col_right = st.columns([1, 1])

with col_left:
    if DEFAULT_FILE_URL:
        if st.button("📥 Or load default file from server"):
            default_file = load_default_file_from_url()
            if default_file is not None:
                uploaded_file = default_file

with col_right:
    st.caption("Max file size ~200 MB. Your data is not saved permanently on Streamlit.")

if not uploaded_file:
    st.info(
        "Please upload your Excel file (Final_Planning_With_Forecast_And_Vendor.xlsx). "
        "You can also configure a DEFAULT_FILE_URL in Streamlit secrets."
    )
    st.stop()

# === Load data (XLSX or ZIP) ===
file_name = uploaded_file.name.lower()

if file_name.endswith(".xlsx"):
    df_raw = pd.read_excel(uploaded_file)

elif file_name.endswith(".zip"):
    try:
        with zipfile.ZipFile(uploaded_file) as z:
            xlsx_names = [n for n in z.namelist() if n.lower().endswith(".xlsx")]
            if not xlsx_names:
                st.error("No .xlsx file found inside the ZIP.")
                st.stop()
            with z.open(xlsx_names[0]) as f:
                df_raw = pd.read_excel(f)
    except Exception as e:
        st.error(f"Error reading ZIP: {e}")
        st.stop()
else:
    st.error("Unsupported file type. Please upload .xlsx or .zip.")
    st.stop()

df = df_raw.copy()
log_upload(uploaded_file.name, len(df))

st.success(f"✅ File loaded successfully! Rows: {len(df):,}")

# ----------------- BASIC CLEANING -----------------
if "Rec_Vendor_Name" in df.columns:
    df["Rec_Vendor_Name"] = df["Rec_Vendor_Name"].fillna("No vendor data")

for col in [
    "Rec_Vendor_Price_USD",
    "Rec_Vendor_LeadTime_Days",
    "Rec_Vendor_OnTime_Percent",
    "Rec_Vendor_Reliability_Score",
    "Rec_Vendor_Composite_Score",
]:
    if col in df.columns:
        df[col] = df[col].fillna(0)

for col in ["safety_stock", "ROP", "On_Hand_Qty", "Coverage_Days",
            "forecast_3M", "forecast_6M", "forecast_12M"]:
    if col in df.columns:
        df[col] = df[col].fillna(0)

# ======================================================
# TABS
# ======================================================
tab_dash, tab_search, tab_forecast, tab_vendor, tab_logs = st.tabs(
    [
        "📊 Dashboard",
        "🔎 Item Search",
        "📈 Forecast & Planning",
        "🤝 Vendor Recommendation",
        "🗄 Logs (Admin)",
    ]
)

# ======================================================
# TAB 1 – DASHBOARD
# ======================================================
with tab_dash:
    st.subheader("📊 Overall Inventory & Forecast Dashboard")

    total_rows = len(df)
    total_items = df["Item Name"].nunique() if "Item Name" in df.columns else total_rows
    zero_stock = (
        df[df.get("On_Hand_Qty", 0) <= 0].shape[0]
        if "On_Hand_Qty" in df.columns
        else 0
    )
    below_safety = (
        df[df.get("On_Hand_Qty", 0) < df.get("safety_stock", 0)].shape[0]
        if ("On_Hand_Qty" in df.columns and "safety_stock" in df.columns)
        else 0
    )

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Rows", f"{total_rows:,}")
    col2.metric("Unique Items", f"{total_items:,}")
    col3.metric("Zero / Negative Stock", f"{zero_stock:,}")
    col4.metric("Below Safety Stock", f"{below_safety:,}")

    st.divider()

    # Coverage distribution
    if "Coverage_Days" in df.columns:
        st.write("### Coverage Days Distribution (All Items)")
        cov_chart = (
            alt.Chart(df)
            .mark_bar()
            .encode(
                x=alt.X("Coverage_Days:Q", bin=alt.Bin(maxbins=30), title="Coverage (Days)"),
                y=alt.Y("count():Q", title="Number of Items"),
                tooltip=["count()"],
            )
        )
        st.altair_chart(cov_chart, use_container_width=True)
    else:
        st.info("Coverage_Days column not found for coverage chart.")

# ======================================================
# TAB 2 – ITEM SEARCH
# ======================================================
with tab_search:
    st.subheader("🔎 Search Items in Final Master")

    search_text = st.text_input("Search by Item Number / Name / Description:")

    filtered_df = df.copy()
    if search_text:
        filtered_df = df[
            df.apply(
                lambda row: row.astype(str).str.contains(search_text, case=False).any(),
                axis=1,
            )
        ]
        log_search(search_text, len(filtered_df))

    st.write(f"Showing **{len(filtered_df):,}** records")
    st.dataframe(filtered_df, use_container_width=True)

    csv_data = filtered_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="⬇️ Download filtered records (CSV)",
        data=csv_data,
        file_name="filtered_items.csv",
        mime="text/csv",
    )

# ======================================================
# TAB 3 – FORECAST & INVENTORY
# ======================================================
with tab_forecast:
    st.subheader("📈 Forecast & Inventory Planning")

    required_columns = [
        "Item Name",
        "Item Description",
        "On_Hand_Qty",
        "safety_stock",
        "ROP",
        "forecast_3M",
        "forecast_6M",
        "forecast_12M",
        "Coverage_Days",
    ]

    missing_cols = [col for col in required_columns if col not in df.columns]
    if missing_cols:
        st.error(f"Missing columns in Excel: {missing_cols}")
    else:
        item_list = df["Item Name"].dropna().unique().tolist()
        item_selected = st.selectbox("Select Item (Item Name / Code)", item_list)

        item_data = df[df["Item Name"] == item_selected].iloc[0]

        st.write(f"### 🏷️ {item_data['Item Name']}")
        st.write(item_data["Item Description"])

        colA, colB, colC = st.columns(3)
        colD, colE, colF = st.columns(3)

        colA.metric("Forecast 3M", fmt(item_data["forecast_3M"]))
        colB.metric("Forecast 6M", fmt(item_data["forecast_6M"]))
        colC.metric("Forecast 12M", fmt(item_data["forecast_12M"]))

        colD.metric("Safety Stock", fmt(item_data["safety_stock"]))
        colE.metric("Reorder Point (ROP)", fmt(item_data["ROP"]))
        colF.metric("On-Hand Qty", fmt(item_data["On_Hand_Qty"]))

        st.metric("Coverage Days", fmt(item_data["Coverage_Days"]))

        st.success("Forecast and inventory values loaded successfully!")

        st.divider()

        # Forecast trend chart
        st.write("### 📊 Forecast Trend (3M / 6M / 12M)")
        chart_df = pd.DataFrame(
            {
                "Period": ["3M", "6M", "12M"],
                "ForecastQty": [
                    float(item_data["forecast_3M"]),
                    float(item_data["forecast_6M"]),
                    float(item_data["forecast_12M"]),
                ],
            }
        )
        chart = (
            alt.Chart(chart_df)
            .mark_line(point=True)
            .encode(
                x=alt.X("Period:N", title="Period"),
                y=alt.Y("ForecastQty:Q", title="Forecast Quantity"),
                tooltip=["Period", "ForecastQty"],
            )
        )
        st.altair_chart(chart, use_container_width=True)

        # Inventory levels comparison
        st.write("### 📦 Inventory vs Safety & ROP")
        inv_df = pd.DataFrame(
            {
                "Metric": ["On-Hand Qty", "Safety Stock", "ROP"],
                "Value": [
                    float(item_data["On_Hand_Qty"]),
                    float(item_data["safety_stock"]),
                    float(item_data["ROP"]),
                ],
            }
        )
        inv_chart = (
            alt.Chart(inv_df)
            .mark_bar()
            .encode(
                x=alt.X("Metric:N", sort=None),
                y=alt.Y("Value:Q"),
                tooltip=["Metric", "Value"],
            )
        )
        st.altair_chart(inv_chart, use_container_width=True)

# ======================================================
# TAB 4 – VENDOR RECOMMENDATION
# ======================================================
with tab_vendor:
    st.subheader("🤝 Vendor Recommendation Engine")

    vendor_cols = [
        "Item Name",
        "Item Description",
        "Rec_Vendor_Name",
        "Rec_Vendor_Price_USD",
        "Rec_Vendor_LeadTime_Days",
        "Rec_Vendor_OnTime_Percent",
        "Rec_Vendor_Reliability_Score",
        "Rec_Vendor_Composite_Score",
    ]

    missing = [c for c in vendor_cols if c not in df.columns]
    if missing:
        st.error(f"Missing vendor columns in Excel: {missing}")
    else:
        item_list_v = df["Item Name"].dropna().unique().tolist()
        item_selected_v = st.selectbox("Select Item for Vendor Comparison", item_list_v)

        item_rows = df[df["Item Name"] == item_selected_v]
        if item_rows.empty:
            st.warning("No vendor data for this item.")
        else:
            item_data_v = item_rows.iloc[0]

            st.write(f"### 🏷️ {item_data_v['Item Name']}")
            st.write(item_data_v["Item Description"])

            st.subheader("⭐ Recommended Vendor")

            col1, col2, col3 = st.columns(3)
            col4, col5 = st.columns(2)

            col1.metric("Vendor", str(item_data_v["Rec_Vendor_Name"]))
            col2.metric("Price (USD)", fmt(item_data_v["Rec_Vendor_Price_USD"]))
            col3.metric("Lead Time (Days)", fmt(item_data_v["Rec_Vendor_LeadTime_Days"]))

            col4.metric("On-Time %", fmt(item_data_v["Rec_Vendor_OnTime_Percent"]))
            col5.metric("Reliability Score", fmt(item_data_v["Rec_Vendor_Reliability_Score"]))

            st.metric("Composite Score", fmt(item_data_v["Rec_Vendor_Composite_Score"]))

            st.success("Recommended vendor loaded successfully!")

            st.write("### 📊 Vendor Performance Profile")
            vc_df = pd.DataFrame(
                {
                    "Metric": [
                        "Price (USD)",
                        "Lead Time (Days)",
                        "On-Time %",
                        "Reliability",
                        "Composite Score",
                    ],
                    "Value": [
                        float(item_data_v["Rec_Vendor_Price_USD"]),
                        float(item_data_v["Rec_Vendor_LeadTime_Days"]),
                        float(item_data_v["Rec_Vendor_OnTime_Percent"]),
                        float(item_data_v["Rec_Vendor_Reliability_Score"]),
                        float(item_data_v["Rec_Vendor_Composite_Score"]),
                    ],
                }
            )
            v_chart = (
                alt.Chart(vc_df)
                .mark_bar()
                .encode(
                    x=alt.X("Metric:N", sort=None),
                    y=alt.Y("Value:Q"),
                    tooltip=["Metric", "Value"],
                )
            )
            st.altair_chart(v_chart, use_container_width=True)

            st.divider()

            st.write("### 📋 Complete Vendor Details for this Item")
            st.dataframe(item_rows, use_container_width=True)

# ======================================================
# TAB 5 – LOGS
# ======================================================
with tab_logs:
    st.subheader("🗄 Basic Usage Logs (from SQLite DB)")

    try:
        conn = sqlite3.connect(DB_PATH)
        uploads_df = pd.read_sql_query("SELECT * FROM uploads ORDER BY id DESC", conn)
        searches_df = pd.read_sql_query("SELECT * FROM searches ORDER BY id DESC", conn)
        conn.close()

        st.write("#### Upload History")
        if uploads_df.empty:
            st.info("No uploads logged yet.")
        else:
            st.dataframe(uploads_df, use_container_width=True)

        st.write("#### Search History")
        if searches_df.empty:
            st.info("No searches logged yet.")
        else:
            st.dataframe(searches_df, use_container_width=True)

    except Exception as e:
        st.error(f"Error reading logs: {e}")

