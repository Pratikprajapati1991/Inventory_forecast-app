import secrets
import string
import smtplib
from email.mime.text import MIMEText
import streamlit as st
import pandas as pd
import sqlite3
import bcrypt
from datetime import datetime
from openai import OpenAI

@st.cache_data(show_spinner=False)
def load_excel(file):
    import pandas as pd
    return pd.read_excel(file)

@st.cache_data(show_spinner=False)
def preprocess_df(df):
    """Pre-calculate stock status, coverage buckets, forecast totals etc. to avoid reprocessing."""
    dfc = df.copy()

    # numeric conversions
    numeric_cols = [
        "On_Hand_Qty", "Min_Stock", "Max_Stock", "Coverage_Days",
        "forecast_3M", "forecast_6M", "forecast_12M"
    ]
    for col in numeric_cols:
        if col in dfc.columns:
            dfc[col] = pd.to_numeric(dfc[col], errors="coerce")

    return dfc

# ======================================================
# BASIC CONFIG
# ======================================================
st.set_page_config(
    page_title="Inventory Forecast App",
    layout="wide",
    initial_sidebar_state="expanded"
)

DB_PATH = "users.db"   # SQLite file for users


# ======================================================
# DATABASE HELPERS
# ======================================================
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_user_db():
    """Create users table if it doesn't exist and ensure an admin user."""
    conn = get_connection()
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
# =========================================
#  PLANNING FILE STORAGE (in users.db)
# =========================================

def init_planning_table():
    """Create table to store uploaded planning files (once)."""
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
    """Save uploaded planning file into SQLite (robust, own connection)."""
    from datetime import datetime
    import sqlite3

    try:
        # Open a fresh connection just for this insert
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
    except Exception as e:
        # Let caller decide how to show the message
        raise e

    # Ensure default admin exists
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
                datetime.utcnow().isoformat()
            ),
        )
        conn.commit()
    conn.close()


def create_user(username, email, password, role="viewer"):
    conn = get_connection()
    cur = conn.cursor()
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    try:
        cur.execute(
            """
            INSERT INTO users (username, email, password_hash, role, is_active, created_at)
            VALUES (?, ?, ?, ?, 1, ?)
            """,
            (username, email, password_hash, role, datetime.utcnow().isoformat()),
        )
        conn.commit()
        return True, "User created successfully."
    except sqlite3.IntegrityError as e:
        if "UNIQUE constraint failed: users.username" in str(e):
            return False, "Username already exists."
        if "UNIQUE constraint failed: users.email" in str(e):
            return False, "Email already exists."
        return False, f"Database error: {e}"
    finally:
        conn.close()


def get_user_by_username(username):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row


def list_users():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return rows


def set_user_active(username, is_active: bool):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET is_active = ? WHERE username = ?",
        (1 if is_active else 0, username),
    )
    conn.commit()
    conn.close()


def delete_user(username):
    if username == "admin":
        return False, "Cannot delete default admin user."
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    deleted = cur.rowcount
    conn.close()
    if deleted:
        return True, "User deleted."
    return False, "User not found."


# ======================================================
# SESSION HELPERS
# ======================================================
def init_session_state():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if "username" not in st.session_state:
        st.session_state.username = None
    if "role" not in st.session_state:
        st.session_state.role = None

def get_openai_client():
    """Return an OpenAI client if API key is configured, otherwise None."""
    api_key = st.secrets.get("OPENAI_API_KEY")
    if not api_key:
        return None
    return OpenAI(api_key=api_key)

def require_login():
    if not st.session_state.get("logged_in", False):
        st.warning("Please log in to continue.")
        st.stop()


def is_admin():
    return st.session_state.get("role") == "admin"

# =========================================
#  EMAIL + OTP HELPERS
# =========================================

def send_email(to_email, subject, body):
    """Send an email using SMTP details from secrets.toml."""
    if "email" not in st.secrets:
        st.error("❌ Email settings missing in secrets.toml.")
        return False

    cfg = st.secrets["email"]
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = cfg["from_address"]
    msg["To"] = to_email

    try:
        with smtplib.SMTP(cfg["host"], cfg["port"]) as server:
            server.starttls()
            server.login(cfg["username"], cfg["password"])
            server.send_message(msg)
        return True
    except Exception as e:
        st.error(f"❌ Failed to send email: {e}")
        return False


def generate_otp(length=6):
    """Generate a numeric OTP."""
    return "".join(secrets.choice(string.digits) for _ in range(length))

# ======================================================
# LOGIN / LOGOUT UI
# ======================================================
def login_screen():
    st.title("🔐 Inventory Forecast App")

    tab_login, tab_forgot = st.tabs(["Login", "Forgot Password"])

    # ---------------- LOGIN TAB ----------------
    with tab_login:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        login_btn = st.button("Login")

        if login_btn:
            user = get_user_by_username(username)
            if not user:
                st.error("Invalid username or password")
                return

            stored_hash = user["password_hash"]
            if isinstance(stored_hash, str):
                stored_hash = stored_hash.encode("utf-8")

            if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
                st.session_state.logged_in = True
                st.session_state.username = user["username"]
                st.session_state.role = user["role"]
                st.success(f"Welcome, {user['username']}!")
                st.rerun()
            else:
                st.error("Invalid username or password")

    # ---------------- FORGOT PASSWORD TAB ----------------
    with tab_forgot:
        st.write("Enter your registered email to receive an OTP.")

        email_input = st.text_input("Registered Email")
        send_otp_btn = st.button("Send OTP")

        if send_otp_btn:
            # find user
            conn = get_connection()
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE email = ?", (email_input,))
            row = cur.fetchone()
            conn.close()

            if not row:
                st.error("No user found with this email.")
                return

            otp = generate_otp()

            body = f"""
Your password reset OTP is: {otp}

Valid for 10 minutes.
If you did not request this, ignore this email.
"""

            sent = send_email(email_input, "Your Password Reset OTP", body)

            if sent:
                st.success("OTP sent to your email.")
                # Store OTP in session for next step
                st.session_state.reset_email = email_input
                st.session_state.reset_otp = otp
        # ---------- Step 2: Verify OTP & Set New Password ----------
        if st.session_state.get("reset_email") and st.session_state.get("reset_otp"):
            st.markdown("---")
            st.markdown("### Set New Password")

            otp_input = st.text_input("Enter OTP received in email", key="reset_otp_input")
            new_pass = st.text_input("New Password", type="password", key="reset_new_pass")
            confirm_pass = st.text_input("Confirm New Password", type="password", key="reset_confirm_pass")
            reset_btn = st.button("Reset Password")

            if reset_btn:
                if not otp_input or not new_pass or not confirm_pass:
                    st.error("Please fill all fields.")
                elif new_pass != confirm_pass:
                    st.error("New password and confirm password do not match.")
                elif otp_input != st.session_state.get("reset_otp"):
                    st.error("Invalid OTP.")
                else:
                    # Update password in database for this email
                    email = st.session_state.get("reset_email")
                    conn = get_connection()
                    cur = conn.cursor()
                    new_hash = bcrypt.hashpw(new_pass.encode("utf-8"), bcrypt.gensalt())
                    cur.execute(
                        "UPDATE users SET password_hash = ? WHERE email = ?",
                        (new_hash, email),
                    )
                    conn.commit()
                    conn.close()

                    # Clear reset data from session
                    st.session_state.reset_email = None
                    st.session_state.reset_otp = None

                    st.success("Password reset successfully. You can now log in with your new password.")

def logout():
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None
    st.success("You have been logged out.")
    st.rerun()


# ======================================================
# DASHBOARD – INVENTORY & FORECAST (FILE UPLOAD)
# ======================================================
def run_inventory_forecast_app():
    require_login()

    st.header("📊 Inventory Forecast & Planning Dashboard")

    st.info(
        "Step 1: Upload your latest planning Excel file "
        "(Final_Planning_With_Forecast_And_Vendor.xlsx or similar)."
    )

    uploaded_file = st.file_uploader(
        "Upload planning file (Excel)",
        type=["xlsx"],
        help="Upload your final planning master file."
    )

    if uploaded_file is None:
        st.stop()

    # -------- Read Excel (cached) --------
    try:
        df_raw = load_excel(uploaded_file)
        df = preprocess_df(df_raw)
    except Exception as e:
        st.error(f"Error reading Excel file: {e}")
        st.stop()
    
    # Save raw uploaded file into database (permanent storage)
    try:
        save_planning_file(uploaded_file.name, uploaded_file.getvalue())
        st.info("📦 This planning file has been saved in the database.")
    except Exception as e:
        st.warning(f"Could not save file in database: {e}")

    st.success(f"File loaded: {uploaded_file.name}")
    st.write(f"Rows: **{df.shape[0]}**, Columns: **{df.shape[1]}**")

    # Quick preview
    with st.expander("🔍 Preview data (first 10 rows)", expanded=False):
        st.dataframe(df.head(10), use_container_width=True)

    # =====================================================
    #  STOCK STATUS & RISK METRICS
    # =====================================================
    st.markdown("---")
    st.subheader("📦 Inventory Risk Overview")

    # Total SKUs
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
    else:
        st.warning("Column 'Stock_Status' not found. Risk breakdown will be limited.")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total SKUs", f"{total_skus:,}")
    c2.metric("Shortage Risk", f"{shortage:,}")
    c3.metric("Excess Risk", f"{excess:,}")
    c4.metric("Healthy (OK)", f"{healthy:,}")
    c5.metric("No ROP Model", f"{no_model:,}")

    if status_chart_df is not None:
        st.bar_chart(status_chart_df)

    # =====================================================
    #  COVERAGE & STOCK LEVEL INSIGHTS
    # =====================================================
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
                labels=["0–30", "31–60", "61–90", "91–180", "181–365", "365+"]
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

    # =====================================================
    #  DETAILED TABLES BY STATUS
    # =====================================================
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

    # =====================================================
    #  FORECAST OVERVIEW (3M / 6M / 12M)
    # =====================================================
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

        # -------------------------------------------------
        #  ITEM-WISE FORECAST EXPLORER
        # -------------------------------------------------
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

    # =====================================================
    #  🤖 Item Insights (Local – Instant) + Reorder Calculator
    # =====================================================
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

    # Extract fields safely
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

    # ---- 1. Stock health text ----
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

    # ---- 2. Coverage interpretation ----
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

    # ---- 3. Forecast trend ----
    forecast_text = []
    try:
        if f3 is not None and f6 is not None and f12 is not None:
            if f12 > f6 > f3:
                forecast_text.append("📈 Demand forecast is **accelerating** (3M < 6M < 12M). Future demand increasing.")
            elif f12 < f6 < f3:
                forecast_text.append("📉 Demand forecast is **declining** (3M > 6M > 12M). Demand is slowing down.")
            else:
                forecast_text.append("➖ Demand forecast is **mixed/flat** – no clear up or down trend.")
    except Exception:
        pass

    # ---- 4. Vendor assessment ----
    vendor_text = []
    vendor_text.append(f"Primary recommended vendor: **{vendor}**.")
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
    except Exception:
        pass

    try:
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

    # ---- 5. Action recommendation (qualitative) ----
    recommendation_lines = []
    try:
        if status.lower().startswith("shortage") or (on_hand is not None and min_stock is not None and on_hand < min_stock):
            recommendation_lines.append("✅ **Action:** Consider placing/releasing a PO immediately for this item.")
        elif status.lower().startswith("excess") or (on_hand is not None and max_stock is not None and on_hand > max_stock):
            recommendation_lines.append("✅ **Action:** Slow down or pause new orders, and review consumption plan.")
        elif status.lower() == "ok":
            recommendation_lines.append("✅ **Action:** No urgent action; continue monitoring based on coverage and forecast.")
        else:
            recommendation_lines.append("ℹ **Action:** Review item parameters (Min/Max, forecast, vendor) before deciding.")
    except Exception:
        pass

    # ---- 6. Reorder quantity calculator (simple ROP model) ----
    # Logic:
    #  - Monthly demand ≈ forecast_12M / 12 (fallback to 6M / 3M if needed)
    #  - Lead time in months = Rec_Vendor_LeadTime_Days / 30 (fallback 30 days)
    #  - Reorder point = monthly_demand * lead_time_months + safety_stock (Min_Stock)
    #  - Target level = Max_Stock (if available) else 1.5 * reorder_point
    #  - Recommended order = max(0, target_level - On_Hand_Qty)
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

    reorder_point = None
    target_level = None
    recommended_order = None

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
            reorder_point = None
            target_level = None
            recommended_order = None

    # ---- Display nicely ----
    st.markdown(f"### 🧾 Summary for: **{name}**")
    st.markdown(f"**Description:** {desc}")

    st.markdown("#### 1. Stock Health")
    if stock_summary:
        for line in stock_summary:
            st.write(line)
    else:
        st.write("No stock health information available.")

    st.markdown("#### 2. Coverage Analysis")
    if coverage_text:
        for line in coverage_text:
            st.write(line)
    else:
        st.write("Coverage information not available.")

    st.markdown("#### 3. Forecast Behaviour")
    if forecast_text:
        for line in forecast_text:
            st.write(line)
    else:
        st.write("Forecast information not sufficient to derive a trend.")

    st.markdown("#### 4. Vendor Assessment")
    for line in vendor_text:
        st.write(line)

    st.markdown("#### 5. Recommended Next Action (Qualitative)")
    for line in recommendation_lines:
        st.write(line)

    # ---- 7. Reorder quantity output ----
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
        st.write("ℹ Not enough data to compute a reliable reorder quantity (missing forecast, lead time, or stock values).")


    # Convert row to dictionary for easier use
    item_data = item_row.to_dict()

    # AI prompt construction
    ai_prompt = f"""
    You are an expert Supply Chain planner. Analyze the following item data and produce a clear, practical insight summary.
    
    Item Name: {item_data.get('Item Name')}
    Description: {item_data.get('Item Description')}
    Stock Status: {item_data.get('Stock_Status')}
    On Hand Qty: {item_data.get('On_Hand_Qty')}
    Min Stock: {item_data.get('Min_Stock')}
    Max Stock: {item_data.get('Max_Stock')}
    Coverage Days: {item_data.get('Coverage_Days')}

    forecast_3M: {item_data.get('forecast_3M')}
    forecast_6M: {item_data.get('forecast_6M')}
    forecast_12M: {item_data.get('forecast_12M')}

    Recommended Vendor: {item_data.get('Rec_Vendor_Name')}
    Vendor Price (USD): {item_data.get('Rec_Vendor_Price_USD')}
    Vendor Lead Time (Days): {item_data.get('Rec_Vendor_LeadTime_Days')}
    Vendor On-Time %: {item_data.get('Rec_Vendor_OnTime_Percent')}
    Vendor Reliability Score: {item_data.get('Rec_Vendor_Reliability_Score')}
    Vendor Composite Score: {item_data.get('Rec_Vendor_Composite_Score')}

    Provide a structured analysis with:
    1. Summary of current stock health
    2. Whether stockout or excess is likely
    3. Forecast trend interpretation (3M vs 6M vs 12M)
    4. Vendor recommendation & reliability assessment
    5. Risk factors to monitor
    6. Final actionable recommendation (Buy / Hold / Expedite / Monitor)
    """

    if st.button("Generate AI Insight"):
        with st.spinner("Thinking…"):
            from openai import OpenAI
            client = OpenAI()

            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a supply chain expert."},
                    {"role": "user", "content": ai_prompt},
                ],
                max_tokens=400,
            )

            ai_result = response.choices[0].message["content"]
            st.markdown("### 🧠 AI Insight Result")
            st.write(ai_result)

    # =====================================================
    #  EXACT STOCKOUT / OVERSTOCK LOGIC USING YOUR COLUMNS
    # =====================================================
    # Total SKUs
    total_skus = df["Item Name"].nunique() if "Item Name" in df.columns else df.shape[0]

    # Use your existing Stock_Status values:
    #   Shortage_Risk, Excess_Risk, OK, No-ROP-Model
    if "Stock_Status" not in df.columns:
        st.error("Column 'Stock_Status' not found in file.")
        st.stop()

    status_counts = df["Stock_Status"].value_counts()

    shortage = int(status_counts.get("Shortage_Risk", 0))
    excess = int(status_counts.get("Excess_Risk", 0))
    healthy = int(status_counts.get("OK", 0))
    no_model = int(status_counts.get("No-ROP-Model", 0))

    # Top metrics
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total SKUs", f"{total_skus:,}")
    c2.metric("Shortage Risk", f"{shortage:,}")
    c3.metric("Excess Risk", f"{excess:,}")
    c4.metric("Healthy (OK)", f"{healthy:,}")
    c5.metric("No ROP Model", f"{no_model:,}")

    st.markdown("---")
    st.subheader("📦 Inventory Risk Overview")

    # Status bar chart
    status_chart_df = (
        status_counts.rename_axis("Status")
        .reset_index(name="Count")
        .set_index("Status")
    )
    st.bar_chart(status_chart_df)

    # =====================================================
    #  COVERAGE & STOCK LEVEL INSIGHTS (USING YOUR COLUMNS)
    # =====================================================
    st.markdown("---")
    st.subheader("⏱ Coverage & Stock Level Insights")

    if "Coverage_Days" in df.columns:
        cov = df["Coverage_Days"].dropna()
        if not cov.empty:
            colA, colB, colC, colD = st.columns(4)
            colA.metric("Avg Coverage (days)", f"{cov.mean():.1f}")
            colB.metric("Median Coverage (days)", f"{cov.median():.1f}")
            colC.metric("P10 (Low)", f"{cov.quantile(0.10):.0f}")
            colD.metric("P90 (High)", f"{cov.quantile(0.90):.0f}")

            # Simple coverage distribution chart
            st.write("Coverage days distribution (bucketed):")
            cov_bins = pd.cut(
                cov,
                bins=[0, 30, 60, 90, 180, 365, cov.max()],
                labels=["0–30", "31–60", "61–90", "91–180", "181–365", "365+"]
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
            st.info("Coverage_Days column is present but contains no numeric data.")
    else:
        st.info("No 'Coverage_Days' column found – skipping coverage analysis.")

    # =====================================================
    #  DETAILED TABLES BY STATUS
    # =====================================================
    st.markdown("---")
    st.subheader("📃 Item-Level Details by Risk Category")

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

    # =====================================================
    #  📈 FORECAST OVERVIEW USING forecast_3M / 6M / 12M
    # =====================================================
    st.markdown("---")
    st.subheader("📈 Forecast Overview")

    forecast_cols = ["forecast_3M", "forecast_6M", "forecast_12M"]
    missing_forecast = [c for c in forecast_cols if c not in df.columns]

    if missing_forecast:
        st.info(
            f"Forecast columns missing: {', '.join(missing_forecast)}. "
            "Skipping forecast charts."
        )
        return

    # Ensure numeric
    fdf = df.copy()
    for c in forecast_cols:
        fdf[c] = pd.to_numeric(fdf[c], errors="coerce")

    totals = fdf[forecast_cols].sum()

    colF1, colF2, colF3, colF4 = st.columns(4)
    colF1.metric("Total Forecast 3M", f"{totals['forecast_3M']:.0f}")
    colF2.metric("Total Forecast 6M", f"{totals['forecast_6M']:.0f}")
    colF3.metric("Total Forecast 12M", f"{totals['forecast_12M']:.0f}")
    colF4.metric("Avg Monthly Forecast (12M)", f"{(totals['forecast_12M'] / 12):.0f}")

    # Simple aggregate chart: horizon vs total forecast
    agg_forecast_df = (
        totals.rename_axis("Horizon")
        .reset_index(name="Quantity")
        .set_index("Horizon")
    )
    st.bar_chart(agg_forecast_df)

    # =====================================================
    #  🔍 ITEM-WISE FORECAST EXPLORER
    # =====================================================
    st.markdown("### 🔍 Item-wise Forecast Explorer")

    if "Item Name" in fdf.columns:
        # Limit to items with some forecast
        fdf_nonzero = fdf[
            (fdf["forecast_3M"] > 0)
            | (fdf["forecast_6M"] > 0)
            | (fdf["forecast_12M"] > 0)
        ]
        if fdf_nonzero.empty:
            st.info("No items with non-zero forecast values.")
            return

        # Sort by highest 12M forecast
        fdf_nonzero = fdf_nonzero.sort_values("forecast_12M", ascending=False)

        item_list = fdf_nonzero["Item Name"].unique().tolist()
        selected_item = st.selectbox(
            "Select an item (sorted by highest 12M forecast)",
            item_list,
        )

        row = fdf_nonzero[fdf_nonzero["Item Name"] == selected_item].iloc[0]

        # Prepare chart data: On-hand vs forecast horizons
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

        # Show key fields for this item
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

    # =====================================================
    #  DETAILED TABLES BY STATUS
    # =====================================================
    st.markdown("---")
    st.subheader("📃 Item-Level Details by Risk Category")

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


    # =====================================================
    #  CONFIGURE STOCKOUT / OVERSTOCK LOGIC FROM COLUMNS
    # =====================================================
    numeric_cols = df.select_dtypes(include="number").columns.tolist()

    if len(numeric_cols) < 1:
        st.error("No numeric columns found. Cannot compute stockout/overstock.")
        st.stop()

    def guess_index(keywords):
        for i, c in enumerate(numeric_cols):
            cl = c.lower()
            if any(k in cl for k in keywords):
                return i
        return 0

    st.markdown("### ⚙ Stock Logic Configuration")

    col_a, col_b, col_c = st.columns(3)
    with col_a:
        idx_current = guess_index(["current", "stock", "qty", "quantity"])
        current_col = st.selectbox(
            "Select **Current Stock** column",
            numeric_cols,
            index=idx_current,
        )
    with col_b:
        idx_min = guess_index(["min", "safety", "reorder"])
        min_col = st.selectbox(
            "Select **Min Level / Safety Stock** column",
            numeric_cols,
            index=idx_min,
        )
    with col_c:
        idx_max = guess_index(["max", "target", "upper"])
        max_col = st.selectbox(
            "Select **Max Level** column",
            numeric_cols,
            index=idx_max,
        )

    # -------- Compute stock status --------
    df = df.copy()
    df["Stock_Status"] = "OK"
    df.loc[df[current_col] < df[min_col], "Stock_Status"] = "Stockout"
    df.loc[df[current_col] > df[max_col], "Stock_Status"] = "Overstock"

    stockout_items = (df["Stock_Status"] == "Stockout").sum()
    overstock_items = (df["Stock_Status"] == "Overstock").sum()
    healthy_items = (df["Stock_Status"] == "OK").sum()

    # -------- Total SKUs (by item identifier if present) --------
    total_skus = df.shape[0]
    if "Item Name" in df.columns:
        total_skus = df["Item Name"].nunique()
    elif "ITEM_NUMBER" in df.columns:
        total_skus = df["ITEM_NUMBER"].nunique()
    elif "Item Code" in df.columns:
        total_skus = df["Item Code"].nunique()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total SKUs", f"{total_skus:,}")
    col2.metric("Stockout Items", f"{stockout_items:,}")
    col3.metric("Overstock Items", f"{overstock_items:,}")
    col4.metric("Healthy Items", f"{healthy_items:,}")

    # -------- Status chart --------
    st.markdown("---")
    st.subheader("Inventory Status Summary")

    status_df = (
        df["Stock_Status"]
        .value_counts()
        .reindex(["Stockout", "OK", "Overstock"])
        .fillna(0)
        .astype(int)
        .rename_axis("Status")
        .reset_index(name="Count")
    )
    status_df = status_df.set_index("Status")
    st.bar_chart(status_df)

    # -------- Detailed tables in tabs --------
    st.markdown("---")
    st.subheader("Item-Level Details")
    tab_all, tab_stockout, tab_over = st.tabs(
        ["All Items", "Stockout Items", "Overstock Items"]
    )

    with tab_all:
        st.dataframe(df, use_container_width=True)

    with tab_stockout:
        st.write(f"Total stockout items: **{stockout_items}**")
        st.dataframe(df[df["Stock_Status"] == "Stockout"], use_container_width=True)

    with tab_over:
        st.write(f"Total overstock items: **{overstock_items}**")
        st.dataframe(df[df["Stock_Status"] == "Overstock"], use_container_width=True)


# ======================================================
# ADMIN PANEL – MANAGE USERS
# ======================================================
def admin_panel():
    require_login()
    if not is_admin():
        st.error("You are not authorized to view this page.")
        st.stop()

    st.subheader("🛠 Admin Panel – User Management")

    st.write(
        f"Logged in as: **{st.session_state.username}** "
        f"(Role: **{st.session_state.role}**)"
    )

    # ----- Add New User -----
    st.markdown("### ➕ Add New User")
    with st.form("add_user_form"):
        new_username = st.text_input("Username")
        new_email = st.text_input("Email")
        new_password = st.text_input("Password", type="password")
        new_role = st.selectbox("Role", ["viewer", "admin"])
        submitted = st.form_submit_button("Create User")

    if submitted:
        if not new_username or not new_password:
            st.error("Username and Password are required.")
        else:
            ok, msg = create_user(new_username, new_email, new_password, new_role)
            if ok:
                st.success(msg)
                st.rerun()
            else:
                st.error(msg)

    st.markdown("---")

    # ----- Existing Users -----
    st.markdown("### 👥 Existing Users")
    users = list_users()
    if not users:
        st.info("No users found.")
    else:
        for u in users:
            cols = st.columns([2, 2, 2, 1, 2])
            with cols[0]:
                st.write(f"**{u['username']}**")
            with cols[1]:
                st.write(u["email"] or "—")
            with cols[2]:
                st.write(f"Role: `{u['role']}`")
            with cols[3]:
                active_label = "Active" if u["is_active"] else "Inactive"
                st.write(active_label)
            with cols[4]:
                st.write(f"Created: {u['created_at'][:19]}")

    st.markdown("---")

    # ----- Activate / Deactivate User -----
    st.markdown("### ✅ Activate / Deactivate User")
    col_a, col_b = st.columns(2)
    with col_a:
        tgt_user = st.text_input("Username to activate/deactivate")
    with col_b:
        active_choice = st.selectbox("Set status to", ["Active", "Inactive"])
    if st.button("Update Status"):
        if not tgt_user:
            st.error("Please enter a username.")
        else:
            set_user_active(tgt_user, active_choice == "Active")
            st.success(f"Status for '{tgt_user}' set to {active_choice}.")
            st.rerun()

    # ----- Delete User -----
    st.markdown("### 🗑 Delete User")
    del_user = st.text_input("Username to delete (cannot delete 'admin')")
    if st.button("Delete User"):
        if not del_user:
            st.error("Please enter a username.")
        else:
            ok, msg = delete_user(del_user)
            if ok:
                st.success(msg)
                st.rerun()
            else:
                st.error(msg)

    st.info(
        "Next steps (future upgrades):\n"
        "- Password reset via email / OTP\n"
        "- Detailed audit logs and login history\n"
        "- Per-page permissions"
    )

def ai_chat_page():
    """Simple AI chat page for supply chain & inventory questions."""
    require_login()

    st.header("🤖 AI Chat Assistant")

    st.write(
        "Ask any question related to inventory, forecasting, vendor selection, "
        "min–max levels, or supply chain planning."
    )

    client = get_openai_client()
    if client is None:
        st.warning(
            "OPENAI_API_KEY is not configured in secrets.toml. "
            "Please add it there to use the AI chat."
        )
        return

    user_question = st.text_area("Your question", height=120)

    if st.button("Ask"):
        if not user_question.strip():
            st.error("Please enter a question.")
            return

        with st.spinner("Thinking..."):
            try:
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "You are a senior supply chain and inventory planning expert. "
                                "Answer clearly, practically, and step-by-step. "
                                "If user mentions stockout, min/max, coverage, or vendors, "
                                "give concrete actions they can take."
                            ),
                        },
                        {"role": "user", "content": user_question},
                    ],
                    max_tokens=500,
                )
                answer = response.choices[0].message["content"]
                st.markdown("### 💬 Answer")
                st.write(answer)
            except Exception as e:
                st.error(f"Error while contacting AI service: {e}")

# ======================================================
# MAIN ROUTER
# ======================================================
def main():
    init_user_db()
    init_planning_table()
    init_session_state()

    if not st.session_state.logged_in:
        login_screen()
        return

    # Logged in: show sidebar + pages
    st.sidebar.title("Navigation")
    st.sidebar.write(f"👤 Logged in as: **{st.session_state.username}**")
    st.sidebar.write(f"🔑 Role: **{st.session_state.role}**")

        menu = ["Dashboard", "AI Assistant"]
    if is_admin():
        menu.append("Admin Panel")
    menu.append("Logout")

    choice = st.sidebar.radio("Go to", menu)

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















