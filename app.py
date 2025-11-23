import streamlit as st
import pandas as pd

# -------------------------------------------------------
# BASIC CONFIG
# -------------------------------------------------------
st.set_page_config(
    page_title="Inventory Forecast App",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -------------------------------------------------------
# SIMPLE USER DATABASE (IN-MEMORY)
# -------------------------------------------------------
USERS = {
    "admin": {
        "password": "Pratik@123",
        "role": "admin",
        "full_name": "Admin User",
    },
    "user1": {
        "password": "User@123",
        "role": "viewer",
        "full_name": "Viewer User",
    },
    # You can add more users like this:
    # "another": {"password": "Pass@123", "role": "viewer", "full_name": "Some User"},
}


# -------------------------------------------------------
# SESSION HELPERS
# -------------------------------------------------------
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


# -------------------------------------------------------
# LOGIN / LOGOUT
# -------------------------------------------------------
def login_screen():
    st.title("🔐 Inventory Forecast App - Login")

    col1, col2 = st.columns([2, 1])

    with col1:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        login_btn = st.button("Login")

    with col2:
        st.markdown("#### Demo Credentials")
        st.code(
            "Admin : admin / Pratik@123\n"
            "Viewer: user1 / User@123"
        )

    if login_btn:
        user = USERS.get(username)
        if user and password == user["password"]:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.role = user["role"]
            st.success(
                f"Welcome, {user['full_name']} "
                f"({user['role'].title()})!"
            )
            st.rerun()  # ✅ correct rerun
        else:
            st.error("Invalid username or password")


def logout():
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None
    st.success("You have been logged out.")
    st.rerun()


# -------------------------------------------------------
# MAIN DASHBOARD (UPLOAD-BASED)
# -------------------------------------------------------
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
        # If any error in logic, just leave as N/A
        pass

    col1, col2, col3 = st.columns(3)
    col1.metric("Total SKUs", f"{total_skus:,}")
    col2.metric("Stockout Risk Items", stockout_items_display)
    col3.metric("Overstock Items", overstock_items_display)

    st.markdown("---")
    st.subheader("Full Data")
    st.dataframe(df, use_container_width=True)


# -------------------------------------------------------
# ADMIN PANEL
# -------------------------------------------------------
def admin_panel():
    require_login()
    if not is_admin():
        st.error("You are not authorized to view this page.")
        st.stop()

    st.subheader("🛠 Admin Panel")
    st.write(
        f"Logged in as: **{st.session_state.username}** "
        f"(Role: **{st.session_state.role}**)"
    )

    st.markdown("### Users (In-Memory Demo)")
    for uname, info in USERS.items():
        st.write(
            f"- **{uname}** – Role: `{info['role']}`, "
            f"Name: {info['full_name']}"
        )

    st.info(
        "Future upgrades (later steps):\n"
        "- Move users to a real database (SQLite)\n"
        "- Add password reset\n"
        "- Add OTP login via email\n"
        "- Add detailed role-based permissions"
    )


# -------------------------------------------------------
# MAIN ROUTER
# -------------------------------------------------------
def main():
    init_session_state()

    if not st.session_state.logged_in:
        # Only show login when not logged in
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
