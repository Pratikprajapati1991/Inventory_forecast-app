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
        "(for example: Final_Planning_With_Forecast_And_Vendor.xlsx)."
    )

    uploaded_file = st.file_uploader(
        "Upload planning file (Excel)",
        type=["xlsx"],
        help="Upload the same master file you use for planning."
    )

    if uploaded_file is None:
        st.stop()

    # Read Excel into DataFrame
    try:
        df = pd.read_excel(uploaded_file)
    except Exception as e:
        st.error(f"Error reading Excel file: {e}")
        st.stop()

    st.success(f"File loaded: {uploaded_file.name}")
    st.write(f"Rows: **{df.shape[0]}**, Columns: **{df.shape[1]}**")

    st.subheader("Columns in your file")
    st.write(list(df.columns))

    st.markdown("---")
    st.subheader("Dataset Preview")
    st.dataframe(df.head(), use_container_width=True)

    # --------- Metrics ---------
    # Total SKUs
    total_skus = df.shape[0]
    if "Item Name" in df.columns:
        total_skus = df["Item Name"].nunique()
    elif "ITEM_NUMBER" in df.columns:
        total_skus = df["ITEM_NUMBER"].nunique()
    elif "Item Code" in df.columns:
        total_skus = df["Item Code"].nunique()

    # For now we keep simple placeholder logic
    stockout_items_display = "N/A"
    overstock_items_display = "N/A"

    cols_lower = [c.lower() for c in df.columns]

    try:
        # Look for typical column names
        if "current_stock" in cols_lower and "min_level" in cols_lower:
            current_col = df.columns[cols_lower.index("current_stock")]
            min_col = df.columns[cols_lower.index("min_level")]
            stockout_items = (df[current_col] < df[min_col]).sum()
            stockout_items_display = f"{stockout_items:,}"

        if "current_stock" in cols_lower and "max_level" in cols_lower:
            current_col = df.columns[cols_lower.index("current_stock")]
            max_col = df.columns[cols_lower.index("max_level")]
            overstock_items = (df[current_col] > df[max_col]).sum()
            overstock_items_display = f"{overstock_items:,}"
    except Exception:
        pass  # leave as N/A if anything fails

    col1, col2, col3 = st.columns(3)
    col1.metric("Total SKUs", f"{total_skus:,}")
    col2.metric("Stockout Risk Items", stockout_items_display)
    col3.metric("Overstock Items", overstock_items_display)

    st.markdown("---")
    st.subheader("Full Data")
    st.dataframe(df, use_container_width=True)


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
