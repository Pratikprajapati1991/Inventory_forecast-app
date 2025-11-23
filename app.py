import streamlit as st

# -------------------------------------------------------
# BASIC CONFIG
# -------------------------------------------------------
st.set_page_config(page_title="Inventory Forecast App",
                   layout="wide",
                   initial_sidebar_state="expanded")

# -------------------------------------------------------
# SIMPLE IN-MEMORY USER DATABASE
# (Later we can move this to SQLite + email OTP etc.)
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
        "full_name": "Viewer User 1",
    },
    # You can add more users here
    # "another_user": {"password": "Password123", "role": "viewer", "full_name": "XYZ"},
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
    """Stop the app if user is not logged in."""
    if not st.session_state.get("logged_in", False):
        st.warning("Please log in to continue.")
        st.stop()


def is_admin():
    return st.session_state.get("role") == "admin"


# -------------------------------------------------------
# LOGIN / LOGOUT UI
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
        st.code("Admin:   admin / Pratik@123\nViewer:  user1 / User@123")

    if login_btn:
        user = USERS.get(username)
        if user and password == user["password"]:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.role = user["role"]
            st.success(f"Welcome, {user['full_name']} ({user['role'].title()})!")
            # ✅ Correct function instead of st.experimental_rerun()
            st.rerun()
        else:
            st.error("Invalid username or password")


def logout():
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None
    st.success("You have been logged out.")
    st.rerun()


# -------------------------------------------------------
# MAIN APP CONTENT (AFTER LOGIN)
# -------------------------------------------------------
def run_inventory_forecast_app():
    """
    👉 IMPORTANT:
    This is where your existing inventory forecasting Streamlit code goes.

    For now I'm putting a simple placeholder.
    In the next step, we will paste your old logic here.
    """
    st.header("📊 Inventory Forecast & Planning Dashboard")

    st.info(
        "Placeholder: this is where your existing forecasting UI will appear.\n\n"
        "In the next step, you will paste your old app code inside "
        "`run_inventory_forecast_app()`."
    )

    # Example dummy content so page is not empty
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total SKUs", "1,250")
    with col2:
        st.metric("Stockout Risk Items", "37")
    with col3:
        st.metric("Overstock Items", "112")


def admin_panel():
    st.subheader("🛠 Admin Panel")

    st.write(f"Logged in as: **{st.session_state.username}** (Role: **{st.session_state.role}**)")

    st.markdown("### User List (In-Memory Demo)")
    for uname, info in USERS.items():
        st.write(
            f"- **{uname}** – Role: `{info['role']}`, Name: {info['full_name']}"
        )

    st.info(
        "Later we can:\n"
        "- Move users to a database (SQLite)\n"
        "- Add user creation, deactivation\n"
        "- Implement password reset and OTP login via email\n"
        "- Add detailed role-based permissions"
    )


# -------------------------------------------------------
# ROUTER
# -------------------------------------------------------
def main():
    init_session_state()

    if not st.session_state.logged_in:
        # Not logged in -> show login page only
        login_screen()
        return

    # Logged in -> show app
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
        if is_admin():
            admin_panel()
        else:
            st.error("You are not authorized to view this page.")
    elif choice == "Logout":
        logout()


if __name__ == "__main__":
    main()
