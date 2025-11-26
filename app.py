import streamlit as st
import pandas as pd
import sqlite3
import bcrypt
from datetime import datetime
import io
from typing import Optional, Tuple, List

# ======================================================
#  BASIC CONFIG
# ======================================================
DB_PATH = "users.db"

st.set_page_config(
    page_title="Inventory Forecast & Planning",
    layout="wide",
)


# ======================================================
#  DATABASE HELPERS
# ======================================================
def get_connection():
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def init_user_db():
    """Create users table and default admin user."""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password_hash BLOB NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()

    # Ensure default admin
    cur.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    admin = cur.fetchone()
    if not admin:
        default_password = "Pratik@123"
        password_hash = bcrypt.hashpw(default_password.encode("utf-8"), bcrypt.gensalt())
        cur.execute(
            """
            INSERT INTO users (username, email, password_hash, role, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "admin",
                "admin@example.com",
                password_hash,
                "admin",
                1,
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()

    conn.close()


def init_planning_table():
    """Create table to store uploaded planning files."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS planning_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            file_data BLOB NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def save_planning_file(filename: str, file_bytes: bytes):
    """Save uploaded planning file into SQLite (separate connection)."""
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO planning_files (filename, uploaded_at, file_data)
            VALUES (?, ?, ?)
            """,
            (filename, datetime.utcnow().isoformat(), file_bytes),
        )
        conn.commit()


def get_latest_planning_file() -> Optional[Tuple[str, bytes, str]]:
    """Return (filename, file_data, uploaded_at) of the latest saved file."""
    try:
        with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT filename, file_data, uploaded_at
                FROM planning_files
                ORDER BY datetime(uploaded_at) DESC
                LIMIT 1
                """
            )
            row = cur.fetchone()
        if row:
            return row[0], row[1], row[2]
        return None
    except Exception:
        return None


# ======================================================
#  USER MANAGEMENT HELPERS
# ======================================================
def get_user_by_username(username: str):
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row


def get_all_users() -> List[sqlite3.Row]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM users ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return rows


def create_user(username: str, email: str, password: str, role: str = "viewer") -> Tuple[bool, str]:
    if not username or not password:
        return False, "Username and password are required."

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        conn.close()
        return False, "Username already exists."

    if email:
        cur.execute("SELECT 1 FROM users WHERE email = ?", (email,))
        if cur.fetchone():
            conn.close()
            return False, "Email already exists."

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    cur.execute(
        """
        INSERT INTO users (username, email, password_hash, role, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (username, email, password_hash, role, 1, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()
    return True, "User created successfully."


def set_user_active(user_id: int, active: bool):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET is_active = ? WHERE id = ?",
        (1 if active else 0, user_id),
    )
    conn.commit()
    conn.close()


# ======================================================
#  SESSION STATE
# ======================================================
def init_session_state():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if "username" not in st.session_state:
        st.session_state.username = None
    if "role" not in st.session_state:
        st.session_state.role = "viewer"
    # Chat history for AI Assistant
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []  # list of dicts: {"role": "user"/"assistant", "text": "..."}


def is_admin() -> bool:
    return st.session_state.get("role") == "admin"


def require_login():
    if not st.session_state.get("logged_in", False):
        st.warning("You must be logged in to view this page.")
        st.stop()


def logout():
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = "viewer"
    st.success("You have been logged out.")
    st.rerun()


# ======================================================
#  CACHED DATA FUNCTIONS – SPEED IMPROVEMENT
# ======================================================
@st.cache_data(show_spinner=False)
def load_and_preprocess_excel(file_bytes: bytes) -> pd.DataFrame:
    """
    Read Excel from bytes and preprocess numeric columns.
    Cached by bytes → avoids re-reading the same file every time.
    """
    buffer = io.BytesIO(file_bytes)
    df = pd.read_excel(buffer)

    dfc = df.copy()
    numeric_cols = [
        "On_Hand_Qty",
        "Min_Stock",
        "Max_Stock",
        "Coverage_Days",
        "forecast_3M",
        "forecast_6M",
        "forecast_12M",
    ]
    for col in numeric_cols:
        if col in dfc.columns:
            dfc[col] = pd.to_numeric(dfc[col], errors="coerce")
    return dfc


# ======================================================
#  LOGIN SCREEN
# ======================================================
def login_screen():
    st.title("🔐 Inventory Forecast App")

    tab_login = st.tabs(["Login"])[0]

    with tab_login:
        col1, col2 = st.columns([2, 1])

        with col1:
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            login_btn = st.button("Login")

        with col2:
            st.markdown("#### Default Admin (first time)")
            st.code("Username: admin\nPassword: Pratik@123")

        if login_btn:
            user = get_user_by_username(username)
            if not user:
                st.error("Invalid username or password")
                return

            if not user["is_active"]:
                st.error("Your account is deactivated. Please contact the admin.")
                return

            stored_hash = user["password_hash"]
            if isinstance(stored_hash, str):
                stored_hash = stored_hash.encode("utf-8")

            if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
                st.session_state.logged_in = True
                st.session_state.username = user["username"]
                st.session_state.role = user["role"]
                st.success(f"Welcome, {user['username']} ({user['role'].title()})!")
                st.rerun()
            else:
                st.error("Invalid username or password")


# ======================================================
#  ADMIN PANEL
# ======================================================
def admin_panel():
    require_login()
    if not is_admin():
        st.error("Only admin users can access this page.")
        return

    st.header("🧑‍💼 Admin Panel – User Management")

    st.subheader("Existing Users")
    users = get_all_users()
    if users:
        user_rows = []
        for u in users:
            user_rows.append(
                {
                    "ID": u["id"],
                    "Username": u["username"],
                    "Email": u["email"],
                    "Role": u["role"],
                    "Active": bool(u["is_active"]),
                    "Created At (UTC)": u["created_at"],
                }
            )
        st.dataframe(pd.DataFrame(user_rows), use_container_width=True)
    else:
        st.info("No users found.")

    st.markdown("---")
    st.subheader("Create New User")

    col1, col2, col3 = st.columns(3)
    with col1:
        new_username = st.text_input("New Username")
        new_email = st.text_input("Email (optional)")
    with col2:
        new_password = st.text_input("Password", type="password")
        new_role = st.selectbox("Role", ["viewer", "admin"])
    with col3:
        if st.button("Create User"):
            ok, msg = create_user(new_username, new_email, new_password, new_role)
            if ok:
                st.success(msg)
                st.rerun()
            else:
                st.error(msg)

    st.markdown("---")
    st.subheader("Activate / Deactivate User")

    if users:
        user_dict = {f"{u['username']} (ID {u['id']})": u for u in users}
        selected_label = st.selectbox("Select User", list(user_dict.keys()))
        selected_user = user_dict[selected_label]
        active_flag = bool(selected_user["is_active"])
        desired_state = st.checkbox("Active", value=active_flag)
        if st.button("Update Status"):
            set_user_active(selected_user["id"], desired_state)
            st.success("User status updated.")
            st.rerun()


# ======================================================
#  MAIN DASHBOARD
# ======================================================
def run_inventory_forecast_app():
    require_login()

    st.header("📊 Inventory Forecast & Planning Dashboard")

    st.info(
        "Step 1: Upload your latest planning Excel file "
        "(Final_Planning_With_Forecast_And_Vendor.xlsx or similar). "
        "If you do not upload, the app will use the last saved file."
    )

    uploaded_file = st.file_uploader(
        "Upload planning file (Excel)",
        type=["xlsx"],
        help="Upload your final planning master file.",
    )

    source = None  # "upload" or "db"
    filename = None
    file_bytes = None

    if uploaded_file is not None:
        source = "upload"
        filename = uploaded_file.name
        file_bytes = uploaded_file.getvalue()
    else:
        latest = get_latest_planning_file()
        if latest is not None:
            filename, file_bytes, uploaded_at = latest
            st.info(
                f"📂 Using last saved planning file: **{filename}** "
                f"(uploaded at {uploaded_at} UTC). Upload a new file to override."
            )
            source = "db"
        else:
            st.warning("No file uploaded and no saved file found. Please upload a planning Excel file.")
            st.stop()

    # -------- Read Excel (cached by file_bytes) --------
    try:
        df = load_and_preprocess_excel(file_bytes)
    except Exception as e:
        st.error(f"Error reading Excel file: {e}")
        st.stop()

    # -------- Save file only when new upload --------
    if source == "upload":
        try:
            save_planning_file(filename, file_bytes)
            st.info("📦 This planning file has been saved in the database.")
        except Exception as e:
            st.warning(f"Could not save file in database: {e}")

    st.success(f"File loaded: {filename}")
    st.write(f"Rows: **{df.shape[0]:,}**, Columns: **{df.shape[1]:,}**")

    with st.expander("🔍 Preview data (first 10 rows)", expanded=False):
        st.dataframe(df.head(10), use_container_width=True)

    # --------------------------------------------------
    #  INVENTORY RISK OVERVIEW
    # --------------------------------------------------
    st.markdown("---")
    st.subheader("📦 Inventory Risk Overview")

    if "Item Name" in df.columns:
        total_skus = df["Item Name"].nunique()
    else:
        total_skus = df.shape[0]

    shortage = excess = healthy = no_model = 0
    status_chart_df = None

    if "Stock_Status" in df.columns:
        status_counts = df["Stock_Status"].value_counts()
        shortage = int(status_counts.get("Shortage_Risk", 0))
        excess = int(status_counts.get("Excess_Risk", 0))
        healthy = int(status_counts.get("OK", 0))
        no_model = int(status_counts.get("No-ROP-Model", 0))

        status_chart_df = (
            status_counts.rename_axis("Status")
            .reset_index(name="Count")
            .set_index("Status")
        )

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total SKUs", f"{total_skus:,}")
    c2.metric("Shortage Risk", f"{shortage:,}")
    c3.metric("Excess Risk", f"{excess:,}")
    c4.metric("Healthy (OK)", f"{healthy:,}")
    c5.metric("No ROP Model", f"{no_model:,}")

    if status_chart_df is not None:
        st.bar_chart(status_chart_df)

    # --------------------------------------------------
    #  COVERAGE & STOCK LEVEL INSIGHTS
    # --------------------------------------------------
    st.markdown("---")
    st.subheader("⏱ Coverage & Stock Level Insights")

    if "Coverage_Days" in df.columns:
        cov = pd.to_numeric(df["Coverage_Days"], errors="coerce").dropna()
        if not cov.empty:
            colA, colB, colC, colD = st.columns(4)
            colA.metric("Avg Coverage (days)", f"{cov.mean():.1f}")
            colB.metric("Median Coverage (days)", f"{cov.median():.1f}")
            colC.metric("P10 (Low)", f"{cov.quantile(0.10):.0f}")
            colD.metric("P90 (High)", f"{cov.quantile(0.90):.0f}")

            st.write("Coverage days distribution (bucketed):")
            cov_bins = pd.cut(
                cov,
                bins=[0, 30, 60, 90, 180, 365, cov.max()],
                labels=["0–30", "31–60", "61–90", "91–180", "181–365", "365+"],
            )
            cov_counts = (
                cov_bins.value_counts()
                .sort_index()
                .rename_axis("Coverage_Bucket")
                .reset_index(name="Count")
                .set_index("Coverage_Bucket")
            )
            st.bar_chart(cov_counts)
        else:
            st.info("Coverage_Days column is present but has no numeric values.")
    else:
        st.info("No 'Coverage_Days' column found – skipping coverage analysis.")

    # --------------------------------------------------
    #  DETAILED TABLES BY STATUS
    # --------------------------------------------------
    st.markdown("---")
    st.subheader("📃 Item-Level Details by Risk Category")

    if "Stock_Status" in df.columns:
        tab_all, tab_short, tab_excess, tab_ok, tab_nomodel = st.tabs(
            ["All Items", "Shortage Risk", "Excess Risk", "OK", "No-ROP-Model"]
        )

        with tab_all:
            st.dataframe(df, use_container_width=True)

        with tab_short:
            st.write(f"Total Shortage_Risk items: **{shortage:,}**")
            st.dataframe(df[df["Stock_Status"] == "Shortage_Risk"], use_container_width=True)

        with tab_excess:
            st.write(f"Total Excess_Risk items: **{excess:,}**")
            st.dataframe(df[df["Stock_Status"] == "Excess_Risk"], use_container_width=True)

        with tab_ok:
            st.write(f"Total OK items: **{healthy:,}**")
            st.dataframe(df[df["Stock_Status"] == "OK"], use_container_width=True)

        with tab_nomodel:
            st.write(f"Total No-ROP-Model items: **{no_model:,}**")
            st.dataframe(df[df["Stock_Status"] == "No-ROP-Model"], use_container_width=True)
    else:
        st.dataframe(df, use_container_width=True)

    # --------------------------------------------------
    #  FORECAST OVERVIEW
    # --------------------------------------------------
    st.markdown("---")
    st.subheader("📈 Forecast Overview")

    forecast_cols = ["forecast_3M", "forecast_6M", "forecast_12M"]
    missing_forecast = [c for c in forecast_cols if c not in df.columns]

    if missing_forecast:
        st.info(
            f"Forecast columns missing: {', '.join(missing_forecast)}. "
            "Skipping forecast charts."
        )
    else:
        fdf = df.copy()
        for c in forecast_cols:
            fdf[c] = pd.to_numeric(fdf[c], errors="coerce")

        totals = fdf[forecast_cols].sum()

        colF1, colF2, colF3, colF4 = st.columns(4)
        colF1.metric("Total Forecast 3M", f"{totals['forecast_3M']:.0f}")
        colF2.metric("Total Forecast 6M", f"{totals['forecast_6M']:.0f}")
        colF3.metric("Total Forecast 12M", f"{totals['forecast_12M']:.0f}")
        colF4.metric("Avg Monthly Forecast (12M)", f"{(totals['forecast_12M'] / 12):.0f}")

        agg_forecast_df = (
            totals.rename_axis("Horizon")
            .reset_index(name="Quantity")
            .set_index("Horizon")
        )
        st.bar_chart(agg_forecast_df)

        # Item-wise Forecast Explorer
        st.markdown("### 🔍 Item-wise Forecast Explorer")

        if "Item Name" in fdf.columns:
            fdf_nonzero = fdf[
                (fdf["forecast_3M"] > 0)
                | (fdf["forecast_6M"] > 0)
                | (fdf["forecast_12M"] > 0)
            ]
            if fdf_nonzero.empty:
                st.info("No items with non-zero forecast values.")
            else:
                fdf_nonzero = fdf_nonzero.sort_values("forecast_12M", ascending=False)
                item_list = fdf_nonzero["Item Name"].unique().tolist()
                selected_item = st.selectbox(
                    "Select an item (sorted by highest 12M forecast)",
                    item_list,
                    key="forecast_item_select",
                )

                row = fdf_nonzero[fdf_nonzero["Item Name"] == selected_item].iloc[0]

                values = {}
                if "On_Hand_Qty" in row.index:
                    values["On Hand"] = row["On_Hand_Qty"]
                values["Forecast 3M"] = row["forecast_3M"]
                values["Forecast 6M"] = row["forecast_6M"]
                values["Forecast 12M"] = row["forecast_12M"]

                item_chart_df = (
                    pd.Series(values)
                    .rename_axis("Horizon")
                    .reset_index(name="Quantity")
                    .set_index("Horizon")
                )

                st.write(f"**Item:** {selected_item}")
                st.bar_chart(item_chart_df)

                info_cols = [
                    "Item Name",
                    "Item Description",
                    "On_Hand_Qty",
                    "Min_Stock",
                    "Max_Stock",
                    "Coverage_Days",
                    "Stock_Status",
                    "forecast_3M",
                    "forecast_6M",
                    "forecast_12M",
                    "Rec_Vendor_Name",
                    "Rec_Vendor_Price_USD",
                    "Rec_Vendor_LeadTime_Days",
                    "Rec_Vendor_OnTime_Percent",
                    "Rec_Vendor_Reliability_Score",
                    "Rec_Vendor_Composite_Score",
                ]
                info_cols = [c for c in info_cols if c in row.index]

                st.write("**Item details:**")
                st.dataframe(
                    pd.DataFrame(row[info_cols]).T,
                    use_container_width=True,
                )
        else:
            st.info("Column 'Item Name' not found, cannot build item-wise explorer.")

    # --------------------------------------------------
    #  ITEM INSIGHTS + REORDER CALCULATOR
    # --------------------------------------------------
    st.markdown("---")
    st.subheader("🤖 Item Insights (Local – Instant) + Reorder Suggestion")

    if "Item Name" not in df.columns:
        st.info("Item insights require an 'Item Name' column.")
        return

    item_list_ai = df["Item Name"].unique().tolist()
    selected_item_ai = st.selectbox(
        "Select an item for analysis",
        item_list_ai,
        key="ai_item_select",
    )

    item_row = df[df["Item Name"] == selected_item_ai].iloc[0]
    item_data = item_row.to_dict()

    name = item_data.get("Item Name", "N/A")
    desc = item_data.get("Item Description", "N/A")
    status = str(item_data.get("Stock_Status", "N/A"))
    on_hand = item_data.get("On_Hand_Qty", None)
    min_stock = item_data.get("Min_Stock", None)
    max_stock = item_data.get("Max_Stock", None)
    cov_days = item_data.get("Coverage_Days", None)

    f3 = item_data.get("forecast_3M", None)
    f6 = item_data.get("forecast_6M", None)
    f12 = item_data.get("forecast_12M", None)

    vendor = item_data.get("Rec_Vendor_Name", "N/A")
    v_price = item_data.get("Rec_Vendor_Price_USD", None)
    v_lead = item_data.get("Rec_Vendor_LeadTime_Days", None)
    v_ontime = item_data.get("Rec_Vendor_OnTime_Percent", None)
    v_rel = item_data.get("Rec_Vendor_Reliability_Score", None)
    v_comp = item_data.get("Rec_Vendor_Composite_Score", None)

    # Stock health
    stock_summary = []
    if on_hand is not None and min_stock is not None and max_stock is not None:
        try:
            if on_hand < min_stock:
                stock_summary.append("🔴 Current stock is **below Min_Stock** → shortage risk.")
            elif on_hand > max_stock:
                stock_summary.append("🟠 Current stock is **above Max_Stock** → excess/overstock risk.")
            else:
                stock_summary.append("🟢 Current stock is **between Min and Max** → healthy range.")
        except Exception:
            pass

    if status.lower().startswith("shortage"):
        stock_summary.append("⚠ Stock_Status is **Shortage_Risk** – item needs attention.")
    elif status.lower().startswith("excess"):
        stock_summary.append("⚠ Stock_Status is **Excess_Risk** – consider slowing or stopping orders.")
    elif status.lower() == "ok":
        stock_summary.append("✅ Stock_Status is **OK** – item is under control.")
    elif "no-rop" in status.lower():
        stock_summary.append("ℹ Stock_Status is **No-ROP-Model** – reorder policy not defined, review settings.")

    # Coverage
    coverage_text = []
    try:
        if cov_days is not None:
            if cov_days < 15:
                coverage_text.append(f"🔴 Coverage is only **{cov_days:.1f} days** – very low, high risk of stockout.")
            elif cov_days < 45:
                coverage_text.append(f"🟠 Coverage is **{cov_days:.1f} days** – moderate, monitor closely.")
            elif cov_days < 120:
                coverage_text.append(f"🟢 Coverage is **{cov_days:.1f} days** – comfortable.")
            else:
                coverage_text.append(f"🟣 Coverage is **{cov_days:.1f} days** – very high, potential overstock.")
    except Exception:
        pass

    # Forecast trend
    forecast_text = []
    try:
        if f3 is not None and f6 is not None and f12 is not None:
            if f12 > f6 > f3:
                forecast_text.append("📈 Demand forecast is **accelerating** (3M < 6M < 12M).")
            elif f12 < f6 < f3:
                forecast_text.append("📉 Demand forecast is **declining** (3M > 6M > 12M).")
            else:
                forecast_text.append("➖ Demand forecast is **mixed/flat** – no clear trend.")
    except Exception:
        pass

    # Vendor assessment
    vendor_text = [f"Primary recommended vendor: **{vendor}**."]
    try:
        if v_ontime is not None:
            if v_ontime >= 95:
                vendor_text.append(f"✅ On-time performance is **{v_ontime:.1f}%** – very reliable.")
            elif v_ontime >= 85:
                vendor_text.append(f"🟢 On-time performance is **{v_ontime:.1f}%** – generally reliable.")
            elif v_ontime >= 70:
                vendor_text.append(f"🟠 On-time performance is **{v_ontime:.1f}%** – moderate, monitor closely.")
            else:
                vendor_text.append(f"🔴 On-time performance is **{v_ontime:.1f}%** – weak, high delay risk.")

        if v_rel is not None:
            vendor_text.append(f"Vendor reliability score: **{v_rel}**.")
        if v_comp is not None:
            vendor_text.append(f"Vendor composite score: **{v_comp}**.")
        if v_price is not None:
            vendor_text.append(f"Unit price (USD): **{v_price}**.")
        if v_lead is not None:
            vendor_text.append(f"Lead time: **{v_lead} days**.")
    except Exception:
        pass

    # Qualitative action
    recommendation_lines = []
    try:
        if status.lower().startswith("shortage") or (
            on_hand is not None and min_stock is not None and on_hand < min_stock
        ):
            recommendation_lines.append("✅ **Action:** Consider placing/releasing a PO immediately for this item.")
        elif status.lower().startswith("excess") or (
            on_hand is not None and max_stock is not None and on_hand > max_stock
        ):
            recommendation_lines.append(
                "✅ **Action:** Slow down or pause new orders, and review consumption plan."
            )
        elif status.lower() == "ok":
            recommendation_lines.append(
                "✅ **Action:** No urgent action; continue monitoring based on coverage and forecast."
            )
        else:
            recommendation_lines.append(
                "ℹ **Action:** Review item parameters (Min/Max, forecast, vendor) before deciding."
            )
    except Exception:
        pass

    # Reorder calculator
    monthly_demand = None
    try:
        if f12 is not None and f12 > 0:
            monthly_demand = f12 / 12
        elif f6 is not None and f6 > 0:
            monthly_demand = f6 / 6
        elif f3 is not None and f3 > 0:
            monthly_demand = f3 / 3
    except Exception:
        monthly_demand = None

    lead_time_days = v_lead if v_lead is not None else 30
    lead_time_months = None
    try:
        if lead_time_days is not None and lead_time_days > 0:
            lead_time_months = lead_time_days / 30.0
    except Exception:
        lead_time_months = None

    reorder_point = target_level = recommended_order = None
    if monthly_demand is not None and lead_time_months is not None and on_hand is not None:
        safety_stock = min_stock if min_stock is not None else 0
        try:
            reorder_point = monthly_demand * lead_time_months + safety_stock
            if max_stock is not None and max_stock > 0:
                target_level = max_stock
            else:
                target_level = reorder_point * 1.5

            recommended_order = max(0, target_level - on_hand)
        except Exception:
            reorder_point = target_level = recommended_order = None

    # Display
    st.markdown(f"### 🧾 Summary for: **{name}**")
    st.markdown(f"**Description:** {desc}")

    st.markdown("#### 1. Stock Health")
    st.write("\n".join(stock_summary) if stock_summary else "No stock health information available.")

    st.markdown("#### 2. Coverage Analysis")
    st.write("\n".join(coverage_text) if coverage_text else "Coverage information not available.")

    st.markdown("#### 3. Forecast Behaviour")
    st.write("\n".join(forecast_text) if forecast_text else "Forecast information not sufficient.")

    st.markdown("#### 4. Vendor Assessment")
    for line in vendor_text:
        st.write(line)

    st.markdown("#### 5. Recommended Next Action (Qualitative)")
    for line in recommendation_lines:
        st.write(line)

    st.markdown("#### 6. Reorder Quantity Suggestion")
    if recommended_order is not None and reorder_point is not None and target_level is not None:
        colR1, colR2, colR3, colR4 = st.columns(4)
        colR1.metric("On Hand Qty", f"{on_hand:.0f}" if on_hand is not None else "N/A")
        colR2.metric("Reorder Point (approx.)", f"{reorder_point:.0f}")
        colR3.metric("Target Stock Level", f"{target_level:.0f}")
        colR4.metric("Suggested Order Qty", f"{recommended_order:.0f}")

        if recommended_order > 0:
            st.write("✅ Suggested action: **Place a PO** approximately for the suggested order quantity.")
        else:
            st.write("🟢 Suggested action: **No immediate PO** required based on current stock vs target.")
    else:
        st.write(
            "ℹ Not enough data to compute a reliable reorder quantity "
            "(missing forecast, lead time, or stock values)."
        )


# ======================================================
#  LOCAL AI CHAT ASSISTANT – NOW FIRST & WITH HISTORY
# ======================================================
def ai_chat_page():
    """Local, fast AI-style assistant (no external API)."""
    require_login()

    st.header("🤖 AI Assistant (Local, Rule-Based)")

    st.write(
        "Ask any question related to inventory, Min–Max, stockouts, coverage, "
        "vendor performance, or planning logic.\n\n"
        "This assistant uses rule-based logic from your supply-chain domain, "
        "so it is fast and does not require internet or API keys."
    )

    # Show chat history
    if st.session_state.chat_history:
        st.markdown("### 💬 Conversation")
        for msg in st.session_state.chat_history:
            if msg["role"] == "user":
                st.markdown(f"**You:** {msg['text']}")
            else:
                st.markdown(f"**Assistant:** {msg['text']}")

        st.markdown("---")

    question = st.text_area("Your question", height=120, key="ai_chat_question")

    if st.button("Ask", key="ai_chat_button"):
        q = (question or "").strip()
        if not q:
            st.error("Please type a question first.")
            return

        q_low = q.lower()
        answers = []

        # Stockout / shortage
        if "stockout" in q_low or "stock out" in q_low or "shortage" in q_low:
            answers.append(
                "### 🔴 Handling Stockouts / Shortage Risk\n"
                "- Identify SKUs with `Stock_Status = Shortage_Risk` and very low `Coverage_Days` (e.g. < 15 days).\n"
                "- Check `On_Hand_Qty` vs `Min_Stock`. If On Hand < Min Stock, plan an urgent PO.\n"
                "- Use recommended vendor fields and lead time to pick fastest reliable vendor.\n"
                "- For long lead-time items, consider safety stock increase and alternate vendors.\n"
                "- Communicate risk items to production so they can adjust schedules."
            )

        # Excess / overstock
        if "overstock" in q_low or "excess" in q_low or "slow moving" in q_low:
            answers.append(
                "### 🟠 Handling Excess / Overstock\n"
                "- Filter items with `Stock_Status = Excess_Risk` and very high `Coverage_Days` (e.g. > 180 days).\n"
                "- Compare `On_Hand_Qty` vs `Max_Stock`. If On Hand >> Max Stock, put the item on PO hold.\n"
                "- Reduce or postpone new orders for these items.\n"
                "- Discuss alternate uses or substitution possibilities with users.\n"
                "- Plan liquidation or scrap review for extreme cases."
            )

        # Min/Max
        if "min" in q_low and "max" in q_low:
            answers.append(
                "### 📏 Setting Min / Max Levels\n"
                "- Estimate monthly demand from `forecast_12M` (or 6M/3M).\n"
                "- Reorder point (ROP) ≈ Demand during lead time + safety stock.\n"
                "- Demand during lead time ≈ Monthly demand × (LeadTimeDays / 30).\n"
                "- Safety stock can be based on variability or existing Min_Stock.\n"
                "- Set Max_Stock around 1.5–2 × ROP for critical items, lower for others.\n"
                "- Review parameters regularly for items with unstable demand."
            )

        # Vendor
        if "vendor" in q_low or "supplier" in q_low:
            answers.append(
                "### 🧑‍💼 Vendor Performance & Selection\n"
                "- Compare vendors on on-time %, reliability score, and composite score.\n"
                "- For critical items, prefer vendors with high on-time and reliability even if slightly costlier.\n"
                "- Use poor performers only for non-critical items or as backup.\n"
                "- Track lead time adherence and update master data when vendor performance changes."
            )

        # Coverage
        if "coverage" in q_low:
            answers.append(
                "### ⏱ Coverage Days Interpretation\n"
                "- < 15 days: Very high stockout risk → expedite PO.\n"
                "- 15–45 days: Acceptable but monitor.\n"
                "- 45–120 days: Healthy coverage.\n"
                "- > 120 days: Potential overstock → slow or stop new orders and review forecast."
            )

        # Reorder / PO
        if (
            "reorder" in q_low
            or "order quantity" in q_low
            or "purchase order" in q_low
            or "po " in q_low
        ):
            answers.append(
                "### 📦 Reorder Quantity & PO Recommendation\n"
                "- Monthly demand from forecast; ROP = demand during lead time + safety stock.\n"
                "- Target stock = Max_Stock or ~1.5 × ROP.\n"
                "- Suggested order = max(0, TargetStock − OnHand).\n"
                "- For high-value items, reduce target and order more frequently in smaller lots."
            )

        # Fallback
        if not answers:
            answers.append(
                "### 🧠 General Guidance\n"
                "- Focus first on Shortage_Risk items with low coverage; then on Excess_Risk with very high coverage.\n"
                "- Use the dashboard Item Insights section to analyse a specific SKU.\n"
                "- If you share concrete numbers (On_Hand, Min, Max, forecast, lead time), "
                "you can translate them into ROP and recommended order using the same logic used in the app."
            )

        full_answer = "\n\n".join(answers)

        # Save to chat history
        st.session_state.chat_history.append({"role": "user", "text": q})
        st.session_state.chat_history.append({"role": "assistant", "text": full_answer})

        st.markdown("### 💬 Answer")
        st.markdown(full_answer)


# ======================================================
#  MAIN ROUTER
# ======================================================
def main():
    init_user_db()
    init_planning_table()
    init_session_state()

    if not st.session_state.logged_in:
        login_screen()
        return

    st.sidebar.title("Navigation")
    st.sidebar.write(f"👤 Logged in as: **{st.session_state.username}**")
    st.sidebar.write(f"🔑 Role: **{st.session_state.role}**")

    # 👉 AI Assistant FIRST
    menu = ["AI Assistant", "Dashboard"]
    if is_admin():
        menu.append("Admin Panel")
    menu.append("Logout")

    choice = st.sidebar.radio("Go to", menu, index=0)

    if choice == "Dashboard":
        run_inventory_forecast_app()
    elif choice == "AI Assistant":
        ai_chat_page()
    elif choice == "Admin Panel":
        admin_panel()
    elif choice == "Logout":
        logout()


if __name__ == "__main__":
    main()
