# config.py
import os
import colorama


# ------------------------------
# Couleurs CLI
# ------------------------------
def init_config():
    colorama.init(autoreset=True)
    r = colorama.Fore.RED
    g = colorama.Fore.GREEN
    b = colorama.Fore.BLUE
    y = colorama.Fore.YELLOW
    w = colorama.Fore.WHITE
    c = colorama.Fore.CYAN
    m = colorama.Fore.MAGENTA
    return r, g, b, y, w, c, m


# ------------------------------
# Chargement secrets depuis serveur
# ------------------------------
def load():
    from secure_loader import authenticate_and_load

    secrets = authenticate_and_load()

    # On récupère proprement les valeurs
    secrets_dict = secrets["decrypted"]  # dict direct     # maintenant c'est un dict Python

    SSH_HOST = secrets_dict["SSH_HOST"]
    SSH_PASSWORD = secrets_dict["SSH_PASSWORD"]
    PG_PASSWORD = secrets_dict["PG_PASSWORD"]

    return SSH_HOST, SSH_PASSWORD, PG_PASSWORD


# ------------------------------
# Variables globales
# ------------------------------
path_dirname = os.path.dirname(os.path.abspath(__file__))

debug = True

SSH_HOST = None
SSH_PASSWORD = None
PG_PASSWORD = None

SSH_PORT = 22
SSH_USER = "ilan"

PG_HOST = "127.0.0.1"      # Toujours localhost via le tunnel
PG_PORT = 5432             # Port interne PostgreSQL sur le serveur
PG_DATABASE = "accounts_db"
PG_USER = "ilan"

LOCAL_PORT = 5433          # Port local pour le tunnel SSH
