import sys
import os
from streamlit import config
from streamlit.web import bootstrap

if __name__ == "__main__":
    # Capture app directory BEFORE Streamlit bootstrap (onefile-safe)
    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        if '_MEI' in exe_dir:
            # --onefile: sys.argv[0] points to temp dir; use CWD instead
            exe_dir = os.getcwd()
    else:
        exe_dir = os.getcwd()
    os.environ["GS_APP_BASE"] = exe_dir

    base_dir = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    app_path = os.path.join(base_dir, "app.py")

    config.set_option("server.port", 8501)
    config.set_option("server.address", "127.0.0.1")
    config.set_option("server.headless", True)
    config.set_option("browser.serverPort", 8501)
    config.set_option("browser.serverAddress", "127.0.0.1")
    config.set_option("global.developmentMode", False)
    config.set_option("client.toolbarMode", "viewer")

    flag_options = {}
    args = []
    for arg in sys.argv[1:]:
        if arg.startswith("--"):
            if "=" in arg:
                k, v = arg[2:].split("=", 1)
                flag_options[k] = v
        else:
            args.append(arg)

    bootstrap.run(app_path, False, args, flag_options)
