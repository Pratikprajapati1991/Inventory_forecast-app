import streamlit as st
import pandas as pd
import altair as alt
import io

# ----------------- PAGE CONFIG -----------------
st.set_page_config(page_title="Item Master Forecast App", layout="wide")

st.title("📦 Item Master Forecast App")
st.write("Upload your processed Excel file and explore it with search, forecast, and vendor intelligence.")

# ----------------- FILE UPLOAD -----------------
uploaded_file = st.file_uploader("Upload Final Excel File", type=["xlsx"])

if not uploaded_file:
    st.info("Please upload your Excel file (Final_Planning_With_Forecast_And_Vendor.xlsx).")
    st.stop()

# Load data
df_raw = pd.read_excel(uploaded_file)
df = df_raw.copy()

# ----------------- BASIC DATA CLEANING (F) -----------------
# Fill vendor text fields
if "Rec_Vendor_Name" in df.columns:
    df["Rec_Vendor_Name"] = df["Rec_Vendor_Name"].fillna("No vendor data")

# Fill vendor numeric fields
for col in [
    "Rec_Vendor_Price_USD",
    "Rec_Vendor_LeadTime_Days",
    "Rec_Vendor_OnTime_Percent",
    "Rec_Vendor_Reliability_Score",
    "Rec_Vendor_Composite_Score",
]:
    if col in df.columns:
        df[col] = df[col].fillna(0)

# Fill inventory numeric fields
for col in ["safety_stock", "ROP", "On_Hand_Qty", "Coverage_Days",
            "forecast_3M", "forecast_6M", "forecast_12M"]:
    if col in df.columns:
        df[col] = df[col].fillna(0)

st.success(f"File uploaded successfully! Rows: {len(df):,}")

# Helper function for safe number formatting
def fmt(x):
    try:
        if pd.isna(x):
            return "-"
        return f"{float(x):.0f}"
    except Exception:
        return "-"

# ----------------- TABS -----------------
tab_dash, tab_search, tab_forecast, tab_vendor = st.tabs(
    ["📊 Dashboard", "🔎 Item Search", "📈 Forecast & Planning", "🤝 Vendor Recommendation"]
)

# ===========================================================
# TAB 1 – DASHBOARD (E)
# ===========================================================
with tab_dash:
    st.subheader("📊 Overall Dashboard")

    total_rows = len(df)
    total_items = df["Item Name"].nunique() if "Item Name" in df.columns else total_rows
    zero_stock = df[df.get("On_Hand_Qty", 0) <= 0].shape[0] if "On_Hand_Qty" in df.columns else 0
    below_safety = df[df.get("On_Hand_Qty", 0) < df.get("safety_stock", 0)].shape[0] \
        if ("On_Hand_Qty" in df.columns and "safety_stock" in df.columns) else 0

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Rows", f"{total_rows:,}")
    col2.metric("Unique Items", f"{total_items:,}")
    col3.metric("Items with Zero / Negative Stock", f"{zero_stock:,}")
    col4.metric("Items Below Safety Stock", f"{below_safety:,}")

    st.divider()

    st.write("### Top 10 Items by Coverage (Days)")
    if "Coverage_Days" in df.columns and "Item Name" in df.columns:
        top_cov = df.sort_values("Coverage_Days", ascending=False)[
            ["Item Name", "Coverage_Days"]
        ].head(10)
        chart = alt.Chart(top_cov).mark_bar().encode(
            x=alt.X("Coverage_Days:Q", title="Coverage Days"),
            y=alt.Y("Item Name:N", sort='-x', title="Item"),
            tooltip=["Item Name", "Coverage_Days"]
        )
        st.altair_chart(chart, use_container_width=True)
    else:
        st.info("Coverage_Days or Item Name column not found for dashboard chart.")

# ===========================================================
# TAB 2 – ITEM SEARCH (C)
# ===========================================================
with tab_search:
    st.subheader("🔎 Search Items in Final Master")

    search_text = st.text_input("Search by Item Number / Name / Description:")

    filtered_df = df.copy()
    if search_text:
        filtered_df = df[
            df.apply(lambda row: row.astype(str).str.contains(search_text, case=False).any(), axis=1)
        ]

    st.write(f"Showing **{len(filtered_df):,}** records")
    st.dataframe(filtered_df, use_container_width=True)

    # Download filtered data
    csv_data = filtered_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="⬇️ Download filtered records (CSV)",
        data=csv_data,
        file_name="filtered_items.csv",
        mime="text/csv",
    )

# ===========================================================
# TAB 3 – FORECAST & INVENTORY (A)
# ===========================================================
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
        st.stop()

    # Item selection
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

    # --- Forecast Chart (simple trend for 3/6/12M) ---
    st.write("### 📊 Forecast Trend (3M / 6M / 12M)")
    chart_df = pd.DataFrame({
        "Period": ["3M", "6M", "12M"],
        "ForecastQty": [
            float(item_data["forecast_3M"]),
            float(item_data["forecast_6M"]),
            float(item_data["forecast_12M"]),
        ],
    })
    chart = alt.Chart(chart_df).mark_line(point=True).encode(
        x=alt.X("Period:N", title="Period"),
        y=alt.Y("ForecastQty:Q", title="Forecast Quantity"),
        tooltip=["Period", "ForecastQty"]
    )
    st.altair_chart(chart, use_container_width=True)

# ===========================================================
# TAB 4 – VENDOR RECOMMENDATION (B, C, D)
# ===========================================================
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
        st.stop()

    # Item selection
    item_list_v = df["Item Name"].dropna().unique().tolist()
    item_selected_v = st.selectbox("Select Item for Vendor Comparison", item_list_v)

    item_rows = df[df["Item Name"] == item_selected_v]
    if item_rows.empty:
        st.warning("No vendor data for this item.")
        st.stop()

    item_data_v = item_rows.iloc[0]

    # Show selected item
    st.write(f"### 🏷️ {item_data_v['Item Name']}")
    st.write(item_data_v["Item Description"])

    # Recommended vendor summary
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

    # --- Vendor metrics chart (B) ---
    st.write("### 📊 Vendor Performance Profile (Recommended Vendor)")
    vc_df = pd.DataFrame({
        "Metric": ["Price (USD)", "Lead Time (Days)", "On-Time %", "Reliability", "Composite Score"],
        "Value": [
            float(item_data_v["Rec_Vendor_Price_USD"]),
            float(item_data_v["Rec_Vendor_LeadTime_Days"]),
            float(item_data_v["Rec_Vendor_OnTime_Percent"]),
            float(item_data_v["Rec_Vendor_Reliability_Score"]),
            float(item_data_v["Rec_Vendor_Composite_Score"]),
        ],
    })
    v_chart = alt.Chart(vc_df).mark_bar().encode(
        x=alt.X("Metric:N", sort=None),
        y=alt.Y("Value:Q"),
        tooltip=["Metric", "Value"]
    )
    st.altair_chart(v_chart, use_container_width=True)

    st.divider()

    # --- Full vendor table (even if only one row) ---
    st.write("### 📋 Complete Vendor Details for this Item")
    st.dataframe(item_rows, use_container_width=True)

    # --- Download vendor data for this item (C) ---
    vendor_csv = item_rows.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="⬇️ Download vendor data for this item (CSV)",
        data=vendor_csv,
        file_name=f"vendor_data_{item_selected_v}.csv",
        mime="text/csv",
    )

    # --- Text report for this item (D) ---
    report_lines = [
        f"Item: {item_data_v['Item Name']}",
        f"Description: {item_data_v['Item Description']}",
        "",
        "=== Recommended Vendor ===",
        f"Name: {item_data_v['Rec_Vendor_Name']}",
        f"Price (USD): {fmt(item_data_v['Rec_Vendor_Price_USD'])}",
        f"Lead Time (Days): {fmt(item_data_v['Rec_Vendor_LeadTime_Days'])}",
        f"On-Time %: {fmt(item_data_v['Rec_Vendor_OnTime_Percent'])}",
        f"Reliability Score: {fmt(item_data_v['Rec_Vendor_Reliability_Score'])}",
        f"Composite Score: {fmt(item_data_v['Rec_Vendor_Composite_Score'])}",
    ]
    report_text = "\n".join(report_lines)

    st.download_button(
        label="⬇️ Download simple text report (open & Print to PDF)",
        data=report_text,
        file_name=f"ItemReport_{item_selected_v}.txt",
        mime="text/plain",
    )
