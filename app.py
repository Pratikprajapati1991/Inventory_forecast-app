import streamlit as st
import pandas as pd
import sqlite3
import bcrypt
from datetime import datetime

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


def require_login():
    if not st.session_state.get("logged_in", False):
        st.warning("Please log in to continue.")
        st.stop()


def is_admin():
    return st.session_state.get("role") == "admin"


# ======================================================
# LOGIN / LOGOUT UI
# ======================================================
def login_screen():
    st.title("🔐 Inventory Forecast App - Login")

    col1, col2 = st.columns([2, 1])

    with col1:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        login_btn = st.button("Login")

    with col2:
        st.markdown("#### Default Admin")
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

    # -------- Read Excel --------
    try:
        df = pd.read_excel(uploaded_file)
    except Exception as e:
        st.error(f"Error reading Excel file: {e}")
        st.stop()

    st.success(f"File loaded: {uploaded_file.name}")
    st.write(f"Rows: **{df.shape[0]}**, Columns: **{df.shape[1]}**")

    # Quick preview
    with st.expander("🔍 Preview data (first 10 rows)", expanded=False):
        st.dataframe(df.head(10), use_container_width=True)

    # =====================================================
    #  EXACT STOCKOUT / OVERSTOCK LOGIC USING YOUR COLUMNS
    # =====================================================
    # Total SKUs
    total_skus = df["Item Name"].nunique() if "Item Name" in df.columns else df.shape[0]

    # Use your existing Stock_Status values:
    #   Shortage_Risk, Excess_Risk, OK, No-ROP-Model
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
            cov_bins = pd.cut(cov, bins=[0, 30, 60, 90, 180, 365, cov.max()],
                              labels=["0–30", "31–60", "61–90", "91–180", "181–365", "365+"])
            cov_counts = cov_bins.value_counts().sort_index().rename_axis("Coverage_Bucket").reset_index(name="Count")
            cov_counts = cov_counts.set_index("Coverage_Bucket")
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


# ======================================================
# MAIN ROUTER
# ======================================================
def main():
    init_user_db()
    init_session_state()

    if not st.session_state.logged_in:
        login_screen()
        return

    # Logged in: show sidebar + pages
    st.sidebar.title("Navigation")
    st.sidebar.write(f"👤 Logged in as: **{st.session_state.username}**")
    st.sidebar.write(f"🔑 Role: **{st.session_state.role}**")

    menu = ["Dashboard"]
    if is_admin():
        menu.append("Admin Panel")
    menu.append("Logout")

    choice = st.sidebar.radio("Go to", menu)

    if choice == "Dashboard":
        run_inventory_forecast_app()
    elif choice == "Admin Panel":
        admin_panel()
    elif choice == "Logout":
        logout()


if __name__ == "__main__":
    main()


