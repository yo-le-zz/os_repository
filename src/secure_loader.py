# secure_loader.py
import uuid
import datetime
import hmac
import hashlib
import requests
import json
import os

# -----------------------
# CONFIG CLIENT → SERVEUR
# -----------------------

SERVER_URL = "https://stannic-uncomprehended-cornelius.ngrok-free.dev/activate"
LICENSE_PATH = "license.txt"
MACHINE_ID_PATH = "machine_id.txt"
SECURE_PATH = "secure.bin"

# Identique au serveur FastAPI
HMAC_SECRET = b"\xd8\xa1\x88\xe2\xf4\x9b\x17m\x9f#\xe5\xfa\xbd\xfc\xee\xeb\x96\xca@\x03\xc5\x0cn\x85\xeak4\x9frm)I"

# -----------------------
# FONCTIONS LICENCE
# -----------------------

def load_secure():
    """Charge le fichier secure.bin chiffré."""
    if not os.path.exists(SECURE_PATH):
        raise Exception("Fichier secure.bin introuvable.")
    with open(SECURE_PATH, "rb") as f:
        ciphertext = f.read()
    return ciphertext

def load_license():
    """Charge la licence, ou la demande si inexistante."""
    if not os.path.exists(LICENSE_PATH):
        print("Aucune licence trouvée. Entrez votre licence :")
        key = input("Licence : ").strip()
        with open(LICENSE_PATH, "w") as f:
            f.write(key)
        print("Licence enregistrée.\n")
        return key
    return open(LICENSE_PATH).read().strip()

# -----------------------
# MACHINE HASH (UUID + MAC)
# -----------------------

def get_local_path(name: str):
    """Toujours propre, compatible exe / script."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), name)

def get_machine_id():
    """Renvoie un identifiant unique pour la machine (UUID local stocké)."""
    machine_file = get_local_path(MACHINE_ID_PATH)
    if os.path.exists(machine_file):
        with open(machine_file, "r") as f:
            machine_id = f.read().strip()
    else:
        machine_id = str(uuid.uuid4())
        with open(machine_file, "w") as f:
            f.write(machine_id)
    return machine_id

# -----------------------
# SIGNATURE HMAC
# -----------------------

def generate_signature(machine_id, timestamp):
    msg = f"{machine_id}:{timestamp}".encode()
    return hmac.new(HMAC_SECRET, msg, hashlib.sha256).hexdigest()

# -----------------------
# AUTHENTIFICATION SERVEUR
# -----------------------

def authenticate(action="decrypt"):
    """
    action : "decrypt" (par défaut) ou "encrypt"
    """
    license_key = load_license()
    machine_id = get_machine_id()
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    signature = generate_signature(machine_id, timestamp)

    payload = {
        "license_key": license_key,
        "machine_id": machine_id,
        "timestamp": timestamp,
        "signature": signature,
        "action": action
    }

    # Pour decrypt, on envoie le fichier secure.bin
    if action == "decrypt":
        ciphertext = load_secure()
        payload["ciphertext"] = ciphertext.decode()

    r = requests.post(SERVER_URL, json=payload)

    if r.status_code != 200:
        raise Exception("Échec auth : " + r.text)

    print("Authentification OK")
    print(f"json : {r.json()}")
    return r.json()  # le serveur renvoie le dict déchiffré ou le ciphertext encrypté

# -----------------------
# FONCTION PRINCIPALE
# -----------------------

def authenticate_and_load(action="decrypt"):
    """
    1. Vérifie la licence + machine_hash auprès du serveur HTTPS.
    2. action : "decrypt" ou "encrypt"
    3. Retourne le contenu déchiffré ou le ciphertext généré.
    """
    return authenticate(action)
