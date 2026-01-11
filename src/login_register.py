# login_register.py
from serveur_func import *
from config import *
from logger import *
from connected import choice_menu
from secure_loader import *
import base64
import os
import requests
import sys
import subprocess
import platform
import uuid
import hashlib
import json
import bcrypt
import psycopg2

def init_login_register():
    """
    Initialise la palette de couleurs globale pour le login et l'inscription.
    """
    color_palette = init_config()
    global r, g, b, y, w, c, m
    r, g, b, y, w, c, m = color_palette

# -----------------------------
# Charger les secrets chiffrés
# -----------------------------
secrets = authenticate_and_load()
secrets_dict = secrets["decrypted"]

# Variables pour couleur
color_palette = init_config()
r, g, b, y, w, c, m = color_palette

# -----------------------------
# Fonctions utilitaires
# -----------------------------

def is_banned(curs):
    if curs is None or not hasattr(curs, "execute"):
        print("Erreur : curseur invalide pour vérifier le ban")
        return False

    machine_hash = get_machine_hash()

    try:
        curs.execute("SELECT 1 FROM blacklist WHERE machine_hash = %s LIMIT 1", (machine_hash,))
        result = curs.fetchone()
        if result is not None:
            log("La machine est bannie !", level=10)
            return True
        else:
            log("La machine n'est pas bannie.", level=10)
            return False
    except Exception as e:
        print(f"Erreur SQL lors de la vérification du ban : {e}")
        return False

def ping(host):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", host]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

def get_local_path(filename):
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, filename)

def get_machine_hash():
    machine_file = get_local_path("machine_id.txt")
    if os.path.exists(machine_file):
        with open(machine_file, "r") as f:
            uuid_stored = f.read().strip()
    else:
        uuid_stored = str(uuid.uuid4())
        with open(machine_file, "w") as f:
            f.write(uuid_stored)
    mac_addr = uuid.getnode()
    raw_data = f"{uuid_stored}-{mac_addr}"
    return hashlib.sha256(raw_data.encode()).hexdigest()


def server_encrypt(plaintext: str, license_key: str, machine_id: str) -> str:
    # Générer un timestamp et une signature
    from datetime import datetime
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    signature = generate_signature(machine_id, timestamp)  # fonction locale HMAC identique au serveur

    payload = {
        "license_key": license_key,
        "machine_id": machine_id,
        "timestamp": timestamp,
        "signature": signature,
        "action": "encrypt",  # ou "decrypt"
        "plaintext": plaintext  # Utilise "plaintext" pour encrypt, ou "ciphertext" pour decrypt
    }

    log(f"DEBUG payload: {payload}", level=10)  # Debug pour vérifier les valeurs envoyées

    try:
        r = requests.post(SERVER_URL, json=payload, timeout=10)
        log(f"Voici la réponse du serveur : {r.text}", level=20)  # Log de la réponse serveur
        r.raise_for_status()  # Vérifier si la requête a bien fonctionné
        data = r.json()  # Convertir la réponse JSON en objet Python
        log("Données chiffrées via le serveur en cours de traitement...", level=20)
        return data["ciphertext"]  # Retourner le ciphertext ou le résultat
    except requests.exceptions.RequestException as e:
        log(f"Erreur lors de l'envoi de la requête : {e}", level=30)
        return None


def server_decrypt(ciphertext: str, license_key: str, machine_id: str) -> str:
    """Déchiffre les données via le serveur"""
    from datetime import datetime
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    signature = generate_signature(machine_id, timestamp)

    payload = {
        "license_key": license_key,
        "machine_id": machine_id,
        "timestamp": timestamp,
        "signature": signature,
        "action": "decrypt",
        "ciphertext": ciphertext
    }

    log(f"DEBUG payload decrypt: {{'action':'decrypt','ciphertext_len':{len(str(ciphertext))}}}", level=10)
    try:
        r = requests.post(SERVER_URL, json=payload, timeout=10)
    except requests.exceptions.RequestException as e:
        log(f"Erreur réseau lors du déchiffrement serveur : {e}", level=30)
        return None

    # Log server body for diagnosis and avoid raising so we can inspect 400 details
    try:
        log(f"Réponse serveur decrypt: {r.text}", level=20)
        if r.status_code != 200:
            log(f"Serveur retourné status {r.status_code} lors du déchiffrement: {r.text}", level=30)
            return None
        data = r.json()
        log("Données déchiffrées via le serveur", level=20)
        # support both possible keys from server responses
        return data.get("plaintext") or data.get("decrypted")
    except ValueError:
        log(f"Réponse JSON invalide du serveur: {r.text}", level=30)
        return None


def write_local_data(username, password):
    machine_id = get_machine_id()
    license_key = load_license()

    # Pack both credentials into a single JSON so server decrypt expects valid JSON
    credentials = {"username": username, "password": password}
    plaintext = json.dumps(credentials)
    credentials_cipher = server_encrypt(plaintext, license_key, machine_id)

    if not credentials_cipher:
        raise Exception("Échec chiffrement serveur")

    local_data = {
        "credentials": credentials_cipher
    }

    local_file = get_local_path("local_user.json")
    with open(local_file, "w") as f:
        json.dump(local_data, f)


# -----------------------------
# Connexion automatique
# -----------------------------
def login_auto():
    local_file = get_local_path("local_user.json")
    tunnel = conn = curs = None
    try:
        tunnel, conn, curs = open_all()
        network_available = True
    except Exception:
        tunnel = conn = curs = None
        network_available = False
        log("Pas de connexion réseau, utilisation du fichier local si disponible", level=20)

    if os.path.exists(local_file):
        try:
            with open(local_file, "r") as f:
                local_data = json.load(f)
            
            # Déchiffrer via le serveur
            license_key = load_license()
            machine_id = get_machine_id()
            
            # Initialize
            username = None
            password = None
            # New format: single 'credentials' ciphertext that decrypts to a JSON {username, password}
            creds = None
            if "credentials" in local_data:
                creds = server_decrypt(local_data.get("credentials"), license_key, machine_id)
                if isinstance(creds, dict):
                    username = creds.get("username")
                    password = creds.get("password")

            # Dump local payload to logs for diagnosis
            log(f"DEBUG local_user.json keys: {list(local_data.keys())}", level=10)
            try:
                preview = {k: (v[:80] + '...') if isinstance(v, str) and len(v) > 80 else v for k, v in local_data.items()}
                log(f"DEBUG local_user.json preview: {preview}", level=10)
            except Exception:
                log("Impossible de faire un preview du local_user.json", level=10)

            if not username or not password:
                log("Déchiffrement serveur et local échoués — fichier local conservé pour inspection. Demande de login manuel.", level=30)
                return False
            log(f"Déchiffrement final : username={username}, password={'*' * len(password) if password else None}", level=10)
            # Ne pas appeler la DB si on n'a pas de credentials valides
            if username and password and network_available and curs is not None:
                statut, pseudo_conn, password_conn, rank = login_database(username, password, tunnel, conn, curs)
                if statut:
                    choice_menu(pseudo_conn, password_conn, rank, tunnel, conn, curs)
                    return True
                else:
                    log("Connexion BDD échouée, fallback sur local", level=20)

            rank = "user"
            choice_menu(username, password, rank, tunnel, conn, curs)
            return True
        except Exception as e:
            log(f"Erreur lors de la connexion automatique: {e}", level=30)

    return False

def login_database(username, password, tunnel, conn, curs, key=None):
    """
    Vérifie le nom d'utilisateur et le mot de passe dans la base.
    Si correct, renvoie True + infos utilisateur.
    
    Args:
        username (str): Nom d'utilisateur
        password (str): Mot de passe en clair
        tunnel, conn, curs: connexions SSH/BDD
        key (bytes): clé pour stocker localement les infos (optionnel)
    
    Returns:
        tuple: (statut_bool, username, password, rank)
    """
    if not all([tunnel, conn, curs]):
        log("Connexion SSH/BDD invalide pour login_database.", level=40)
        return False, None, None, None

    try:
        curs.execute("SELECT password, rank FROM users WHERE username = %s", (username,))
        result = curs.fetchone()
        if not result:
            print(f"{r}Nom d'utilisateur ou mot de passe incorrect.")
            log(f"Échec de la connexion pour l'utilisateur: {username}", level=30)
            try: conn.rollback()
            except Exception: pass
            close_ssh_tunnel(tunnel, conn, curs)
            return False, None, None, None

        stored_pw = result[0]

        # Normalise le type du mot de passe pour bcrypt
        if isinstance(stored_pw, memoryview):
            stored_pw_bytes = stored_pw.tobytes()
        elif isinstance(stored_pw, bytes):
            stored_pw_bytes = stored_pw
        elif isinstance(stored_pw, str):
            stored_pw_bytes = stored_pw.encode()
        else:
            stored_pw_bytes = bytes(stored_pw)

        # Vérification avec bcrypt
        if bcrypt.checkpw(password.encode(), stored_pw_bytes):
            db_rank = result[1]
            log(f"Utilisateur connecté: {username}", level=20)

            # Écriture locale sécurisée
            if key:
                try:
                    write_local_data(username, password)
                except Exception as e:
                    log(f"Erreur écriture locale après login: {e}", level=30)

            return True, username, password, db_rank
        else:
            print(f"{r}Nom d'utilisateur ou mot de passe incorrect.")
            log(f"Échec de la connexion pour l'utilisateur: {username}", level=30)
            try: conn.rollback()
            except Exception: pass
            close_ssh_tunnel(tunnel, conn, curs)
            return False, None, None, None

    except Exception as e:
        log(f"❌ Échec de la connexion: {e}", level=40)
        close_ssh_tunnel(tunnel, conn, curs)
        return False, None, None, None

# -----------------------------
# Connexion manuelle
# -----------------------------
def login():
    try:
        tunnel, conn, curs = open_all()
        network_available = True
    except Exception:
        tunnel = conn = curs = None
        network_available = False
        log(f"{r}Pas de connexion réseau, utilisation du fichier local si disponible", level=20)

    if curs is None:
        print("Erreur : curseur invalide")
        return False

    if is_banned(curs):
        print(f"{r}❌ Accès refusé : cette machine est bannie.")
        return False

    local_file = get_local_path("local_user.json")
    if os.path.exists(local_file):
        return login_auto()
    
    print(f"{c}===Connexion===")
    username = input(f"{c}Nom d'utilisateur : ")
    password = input(f"{c}Mot de passe : ")

    if network_available:
        statut, pseudo_conn, password_conn, rank = login_database(username, password, tunnel, conn, curs)
        if statut:
            try:
                if pseudo_conn and password_conn:
                    try:
                        write_local_data(pseudo_conn, password_conn)
                        log(f"Écriture locale réussie pour l'utilisateur {pseudo_conn}", level=20)
                        choice_menu(pseudo_conn, password_conn, rank, tunnel, conn, curs)
                    except Exception as e:
                        log(f"Erreur après pendant l'écriture : {e}", level=30)
                else:
                    choice_menu(username, password, rank, tunnel, conn, curs)
            except Exception as e:
                log(f"Erreur après authentification distante : {e}", level=30)
            finally:
                close_ssh_tunnel(tunnel, conn, curs)
            return True
        else:
            log("Connexion distante échouée → vérifier le fichier local si disponible", level=20)

    if os.path.exists(local_file):
        try:
            with open(local_file, "r") as f:
                local_data = json.load(f)
            
            # Déchiffrer via le serveur
            license_key = load_license()
            machine_id = get_machine_id()
            
            # Try new 'credentials' format first
            username = None
            password = None
            if "credentials" in local_data:
                creds = server_decrypt(local_data.get("credentials"), license_key, machine_id)
                if isinstance(creds, dict):
                    username = creds.get("username")
                    password = creds.get("password")

            if not username or not password:
                log("Échec du déchiffrement des données locales.", level=30)
                return False

            rank = "user"
            choice_menu(username, password, rank, tunnel, conn, curs)
            return True
        except Exception as e:
            log(f"Erreur lecture/déchiffrement du fichier local : {e}", level=30)
            log("Fichier local défectueux, mais conservé pour inspection.", level=20)
    else:
        log("Aucun fichier local disponible", level=30)

    return False

# -----------------------------
# Inscription
# -----------------------------
def register():
    try:
        tunnel = open_ssh_tunnel()
        conn, curs = connect_to_db()
        if curs is None:
            print("Erreur : curseur invalide")
            return False

        if is_banned(curs):
            print(f"{r}❌ Accès refusé : cette machine est bannie.")
            return False
    except Exception as e:
        log("Erreur de connexion impossible de créer le compte, arrêt du script", level=50)
        sys.exit(1)

    if conn is None or curs is None:
        log("❌ Impossible de s'inscrire, la connexion à la base de données a échoué.", level=40)
        return False

    try:
        print(f"{c}===Inscription===")
        username = input(f"{c}Nom d'utilisateur : ")
        password = input(f"{c}Mot de passe : ")

        if len(username) < 3:
            print(f"{r}Le pseudo doit faire minimum 3 caractères")
            return False
        if len(password) < 6:
            print(f"{r}Le mot de passe doit faire minimum 6 caractères")
            return False

        curs.execute("SELECT 1 FROM users WHERE username = %s LIMIT 1", (username,))
        if curs.fetchone():
            print(f"{r}Le pseudo {username} est déjà utilisé !")
            return False

        # Hash en bytes, stocker en BYTEA via psycopg2.Binary
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        machine_hash = get_machine_hash()
        curs.execute(
            "INSERT INTO users (username, password, rank, machine_hash) VALUES (%s, %s, %s, %s)",
            (username, psycopg2.Binary(hashed_password), "user", machine_hash)
        )
        conn.commit()
        print(f"{g}Inscription réussie pour l'utilisateur {username}!")
        log(f"Nouvel utilisateur inscrit: {username}", level=20)
        return True
    except Exception as e:
        log(f"❌ Échec de l'inscription: {e}", level=40)
        try:
            conn.rollback()
        except Exception:
            pass
        return False
    finally:
        close_ssh_tunnel(tunnel, conn, curs)
