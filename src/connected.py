# connected.py
import sys
import os

import hashlib
import uuid
import requests
import json

import bcrypt

from logger import init_logger, log
from config import init_config
from secure_loader import SERVER_URL, generate_signature
from system import *
from serveur_func import open_all, close_ssh_tunnel, create_admin_if_needed
from secure_loader import load_license, get_machine_id
from datetime import datetime

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

def write_local_data(username, password):
    machine_id = get_machine_id()
    license_key = load_license()

    # Pack credentials into a single JSON payload so server decrypt returns a JSON object
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

def get_local_path(filename):
    # Si on est compilé (PyInstaller), sys._MEIPASS existe
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, filename)

def get_machine_hash():
    """
    Génère un identifiant unique pour la machine.
    Si possible, combine l'utilisateur et l'adresse MAC pour plus de fiabilité.
    
    Returns:
        str: hash SHA256 unique de la machine
    """
    try:
        # Nom de l'utilisateur + MAC address
        unique_str = f"{os.getlogin()}-{uuid.getnode()}"
        machine_hash = hashlib.sha256(unique_str.encode()).hexdigest()
        return machine_hash
    except Exception as e:
        print(f"Erreur lors de la génération du machine_hash : {e}")
        # fallback simple
        return str(uuid.uuid4())

def make_color():
    global r, g, b, y, w, c, m, color
    color = init_config()
    r, g, b, y, w, c, m = color

def remove_local_data():
    """
    Supprime le fichier local_user.json si il existe.
    """
    local_file = get_local_path("local_user.json")
    if os.path.exists(local_file):
        try:
            os.remove(local_file)
            log("Fichier local supprimé avec succès.", level=20)
        except Exception as e:
            log(f"Impossible de supprimer le fichier local : {e}", level=30)

# DANGEROUS FUNCTION
def reset_database(tables, tunnel, conn, curs):
    """
    Vide complètement les tables et réinitialise les SERIAL (id) après confirmation.
    
    Args:
        tables (list of str): noms des tables à réinitialiser
        curs: curseur BDD
        conn: connexion BDD
    """
    close_ssh_tunnel(tunnel, conn, curs)
    tunnel, conn, curs = open_all()
    confirm = input("⚠️ Attention ! Voulez-vous vraiment réinitialiser toutes les tables ? (O/N) : ").strip().lower()
    if confirm != "o":
        print("Réinitialisation annulée.")
        return

    try:
        for table in tables:
            # Supprime tout le contenu
            curs.execute(f"TRUNCATE TABLE {table} RESTART IDENTITY CASCADE;")
            # RESTART IDENTITY → réinitialise les SERIAL à 1
            # CASCADE → supprime aussi les dépendances si FK
        conn.commit()
        close_ssh_tunnel(tunnel, conn, curs)
        create_admin_if_needed()
        print("✅ Base de données réinitialisée avec succès.")
    except Exception as e:
        print(f"Erreur lors de la réinitialisation : {e}")
        try: conn.rollback()
        except: pass
    

# fonction du menu:
def del_user(tunnel, conn, curs, v, re):
    """
    Supprime un utilisateur de la base après confirmation.

    Args:
        curs: Curseur PostgreSQL
        conn: Connexion PostgreSQL
        v: Couleur violette (texte)
        re: Reset couleur
    """
    close_ssh_tunnel(tunnel, conn, curs)

    # Rouvrir les connexions/tunnels
    tunnel, conn, curs = open_all()
    username = input(f"{v}Nom de l'utilisateur à supprimer : {re}").strip()

    if not username:
        log("Aucun nom d'utilisateur saisi.", level=30)
        return

    curs.execute("SELECT rank FROM users WHERE username = %s", (username,))
    result = curs.fetchone()
    
    rank_of_user = result[0]
    
    if rank_of_user == "fondateur":
        print(f"{r}Vous n'avez pas les permissions nessecaire pour supprimer le fondateur !{re}")
        return
    
    confirm = input(f"{v}Tapez 'OUI' pour confirmer la suppression de {username} : {re}").strip()

    if confirm.lower() != "oui":
        log(f"Suppression annulée pour {username}.", level=20)
        return

    try:
        curs.execute("DELETE FROM users WHERE username = %s", (username,))
        if curs.rowcount == 0:
            log(f"Utilisateur '{username}' introuvable.", level=40)
            return
        conn.commit()
        log(f"Utilisateur '{username}' supprimé avec succès.", level=20)
    except Exception as e:
        log(f"Erreur SQL lors de la suppression de '{username}' : {e}", level=50)

def list_users(curs):
    """
    Liste tous les utilisateurs de la BDD avec leur id, username et rank.
    
    Args:
        curs: Curseur de la base de données.
    
    Returns:
        list de dict: Chaque dict contient 'id', 'username', 'rank'.
    """
    try:
        curs.execute("SELECT id, username, rank FROM users ORDER BY id")
        results = curs.fetchall()
        users = []
        for row in results:
            users.append({
                "id": row[0],
                "username": row[1],
                "rank": row[2]
            })
        return users
    except Exception as e:
        print(f"Erreur SQL lors de la récupération des utilisateurs : {e}")
        return []

def ban_user(tunnel, curs, conn):
    """
    Bannit la machine associée à un utilisateur choisi par l'admin.
    """
    try:
        close_ssh_tunnel(tunnel, conn, curs)
        tunnel, conn, curs = open_all()
        username = input("Nom de l'utilisateur à bannir : ").strip()

        # Récupérer le machine_hash depuis la table users
        curs.execute("SELECT machine_hash FROM users WHERE username = %s", (username,))
        result = curs.fetchone()
        if not result or not result[0]:
            print(f"Erreur : aucun machine_hash trouvé pour {username}.")
            return

        machine_hash = result[0]

        # Vérifier si la machine est déjà bannie
        curs.execute("SELECT 1 FROM blacklist WHERE machine_hash = %s LIMIT 1", (machine_hash,))
        if curs.fetchone():
            print(f"❌ La machine de {username} est déjà bannie.")
            return

        reason = input("Raison du ban : ").strip()

        curs.execute(
            "INSERT INTO blacklist (machine_hash, reason) VALUES (%s, %s)",
            (machine_hash, reason)
        )
        conn.commit()
        print(f"Utilisateur {username} (machine {machine_hash}) banni pour : {reason}")
    except Exception as e:
        print(f"Erreur SQL lors du ban : {e}")
        try:
            conn.rollback()
        except:
            pass

        
def unban_user(tunnel, curs, conn):
    """
    Débannit la machine associée à un utilisateur choisi par l'admin.
    """
    try:
        close_ssh_tunnel(tunnel, conn, curs)
        tunnel, conn, curs = open_all()
        username = input("Nom de l'utilisateur à débannir : ")

        # Récupérer le machine_hash depuis la table users
        curs.execute("SELECT machine_hash FROM users WHERE username = %s", (username,))
        result = curs.fetchone()
        if not result or not result[0]:
            print(f"Erreur : aucun machine_hash trouvé pour {username}.")
            return

        machine_hash = result[0]

        curs.execute("DELETE FROM blacklist WHERE machine_hash = %s", (machine_hash,))
        conn.commit()
        print(f"Utilisateur {username} (machine {machine_hash}) débanni.")
    except Exception as e:
        print(f"Erreur SQL lors du deban : {e}")
        try: conn.rollback()
        except: pass

def set_rank(tunnel, conn, curs, rank, v, re):
    close_ssh_tunnel(tunnel, conn, curs)

    # Rouvrir les connexions/tunnels
    tunnel, conn, curs = open_all()
    
    if rank == "fondateur":
        ranks = ["vip", "tester", "admin", "superadmin", "fondateur"]
    else:
        ranks = ["vip", "tester", "admin", "superadmin"]

    username = input(f"{v}Nom d'utilisateur à modifier : {re}")

    # Récupérer le rank actuel
    curs.execute("SELECT rank FROM users WHERE username = %s", (username,))
    result = curs.fetchone()
    
    if not result:
        log(f"Erreur : utilisateur '{username}' introuvable.", level=40)
        return

    current_rank = result[0]
    if current_rank == "fondateur":
        print(f"{r}Il est impossible de changer le rank du fondateur !{re}")
        return

    # Afficher les rangs possibles
    print(f"{v}Rang actuel : {current_rank}{re}")
    print(f"{v}Rangs possibles : {', '.join(ranks)}{re}")

    new_rank = input(f"{v}Entrez le nouveau rang : {re}").strip().lower()

    # Vérification
    if new_rank not in ranks:
        log(f"Rang invalide : {new_rank}", level=30)
        return

    if new_rank == current_rank:
        print(f"L'utilisateur '{username}' est déjà au rang '{current_rank}'")
        return

    # Mise à jour SQL
    try:
        curs.execute("UPDATE users SET rank = %s WHERE username = %s", (new_rank, username))
        conn.commit()
        print(f"Changement de rang : {username} → {new_rank}")
    except Exception as e:
        log(f"Erreur SQL lors du changement de rang : {e}", level=50)

def show_info(curs, conn, server_context, username, password, db_rank):
    print(f"{c}=== Informations du compte ===")

    try:
        curs.execute("SELECT username, rank FROM users WHERE username = %s", (username,))
        data = curs.fetchone()
        if data:
            print(f"{c}Pseudo : {data[0]}")
            print(f"{c}Rang : {data[1]}")
            print(f"{c}===Modifier votre compte===")
            print(f"{c}Pseudo actuel : {username}")
            # Chiffrer le mot de passe via le serveur
            password_enc = server_context["server_encrypt"](password, server_context["license_key"], server_context["machine_id"])
            print(f"{c}Mot de passe actuelle (chiffré) : {password_enc}")
            print(f"{c}Rank actuel : {db_rank}")
            new_username = input(f"{c}Nouveau pseudo (laisser vide pour ne pas changer) : ")
            new_password = input(f"{c}Nouveau mot de passe (laisser vide pour ne pas changer) : ")
            if new_username:
                username = new_username
            if new_password:
                hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
                # mettre à jour la BDD
                curs.execute("UPDATE users SET username = %s, password = %s WHERE username = %s",
                            (new_username if new_username else username, hashed_password, username))
                conn.commit()
                # mettre à jour le fichier local avec chiffrement serveur
                write_local_data(username, password)
            print(f"{g}Compte mis à jour !")
        else:
            print(f"{r}Impossible de récupérer les infos utilisateur.")
    except Exception as e:
        print(f"{r}Erreur SQL : {e}")

def del_account(username, curs, conn):
    print(f"{r}⚠ Voulez‑vous vraiment supprimer le compte {username} ?")
    confirm = input("Tape OUI pour confirmer : ")

    if confirm.lower() == "oui":
        try:
            curs.execute("DELETE FROM users WHERE username = %s", (username,))
            conn.commit()
            remove_local_data()
            print(f"{m}Compte supprimé avec succès.")
            return
        except Exception as e:
            print(f"{r}Erreur SQL lors de la suppression : {e}")
    else:
        print(f"{c}Annulé.")

def deconnexion():
    remove_local_data()
    print(f"{r}Déconnexion...")
    return

def quit(tunnel, conn, curs):
    print(f"{m}Aurevoir !")
    close_ssh_tunnel(tunnel, conn, curs)
    sys.exit(1)

# ================ DECORATEUR ====================
def with_user_rank_and_key(func):
    """
    Décorateur qui récupère le rank de l'utilisateur et initialise le contexte serveur.
    Passe (db_rank, server_context) avant les arguments tunnels/conn/curs.
    """
    def wrapper(username, password, rank, tunnel, conn, curs, *args, **kwargs):
        # Import local pour éviter l'importation circulaire
        from login_register import server_encrypt, generate_signature
        
        if not curs:
            print("Erreur : curseur invalide pour récupérer le rank.")
            return
        try:
            curs.execute("SELECT rank FROM users WHERE username = %s", (username,))
            result = curs.fetchone()
            if not result:
                print("Erreur : utilisateur introuvable en base.")
                return
            db_rank = result[0]
        except Exception as e:
            print(f"Erreur SQL lors de la récupération du rank : {e}")
            return
        
        # Créer le contexte pour le chiffrement via serveur
        try:
            license_key = load_license()
            machine_id = get_machine_id()
            server_context = {
                "license_key": license_key,
                "machine_id": machine_id,
                "server_encrypt": server_encrypt
            }
        except Exception as e:
            print(f"Erreur lors de la récupération du contexte serveur : {e}")
            return
        
        return func(username, password, rank, db_rank, server_context, tunnel, conn, curs, *args, **kwargs)
    return wrapper

# ================ MAIN FUNC =====================
def choice_menu(username, password, rank, tunnel, conn, curs):
    make_color()
    log = init_logger('logger', color=color)
    # verifier si le rank est valide et si non on le retrouve
    if rank:
        pass
    else:
        try:
            curs.execute("SELECT rank FROM users WHERE username = %s", (username,))
            result = curs.fetchone()
        except Exception as e:
                log(f"Erreur de recuperation du rank : {e}", level=50)
        if result is None:
            # utilisateur est invalide ou n'existe pas
            log("utilisateur est invalide ou n'existe pas", level=50)
            return
        else:
            rank = result[0]
            if rank is None:
                # le rank est vide dans la base
                log("le rank est vide dans la base", level=50)
                return
    
    if rank == "fondateur":
        connect_fondateur(username, password, rank, tunnel, conn, curs)
    elif rank == "superadmin":
        connect_superadmin(username, password, rank, tunnel, conn, curs)
    elif rank == "admin":
        connect_admin(username, password, rank, tunnel, conn, curs)
    elif rank == "tester":
        connect_tester(username, password, rank, tunnel, conn, curs)
    elif rank == "vip":
        connect_vip(username, password, rank, tunnel, conn, curs)
    else:
        connect_user(username, password, rank, tunnel, conn, curs)

# fonctionner de connecter avec chaque rang

@with_user_rank_and_key            
def connect_user(username, password, rank, db_rank, server_context, tunnel, conn, curs):
    # Boucle du menu utilisateur
    while True:
        print(f"{c}=== Bonjour {db_rank} {username} ===")
        print(f"{c}1. Voir les informations du compte et les modifier")
        print(f"{c}2. Lister les dossiers et fichiers ISO")
        print(f"{c}3. Naviguer dans les dossiers")
        print(f"{c}4. Télécharger ou uploder un fichier ISO")
        print(f"{c}5. Rechercher un ISO")
        print(f"{c}6. Supprimer le compte")
        print(f"{c}7. Se déconnecter")
        print(f"{c}8. Quitter")

        choix = input(f"{c}Entrer un numéro : ")

        # ----- 1. Voir/Modifier le compte -----
        if choix == "1":
            show_info(curs, conn, server_context, username, password, db_rank)
        # fonction en relation avec les system d'exploitation
        elif choix == "2":
            lister_fichiers_serveur()
        elif choix == "3":
            explorer_serveur()
        elif choix == "4":
            choice_2 = input("Vous voulez uplode ou download ? : ")
            if choice_2 == "uplode":
                upload_fichier(username)
            elif choice_2 == "download":
                telecharger_fichier()
        elif choix == "5":
            mot_cle = input("Entrer un mot cle (ex : le nom) : ")
            rechercher_iso(mot_cle)
        # ----- 2. Supprimer le compte -----
        elif choix == "6":
            del_account(username, curs, conn)

        # ----- 3. Déconnexion -----
        elif choix == "7":
            deconnexion()
            return

        # ----- 4. Quitter complètement -----
        elif choix == "8":
            quit(tunnel, conn, curs)

        # Mauvaise entrée
        else:
            print(f"{r}Choix invalide !")

@with_user_rank_and_key
def connect_vip(username, password, rank, db_rank, server_context, tunnel, conn, curs):
    while True:
        print(f"{b}=== Bonjour {db_rank} {username} ===")
        print(f"{b}1. Voir les informations du compte et les modifier")
        print(f"{b}2. Lister les dossiers et fichiers ISO")
        print(f"{b}3. Naviguer dans les dossiers")
        print(f"{b}4. Télécharger ou uploder un fichier ISO")
        print(f"{b}5. Rechercher un ISO")
        print(f"{b}6. Supprimer le compte")
        print(f"{b}7. Se déconnecter")
        print(f"{b}8. Quitter")
        
        choice = input(f"{b}Entrer un numero : ")

        if choice == "1":
            show_info(curs, conn, server_context, username, password, db_rank)

        # fonction en relation avec les system d'exploitation
        elif choice == "2":
            lister_fichiers_serveur()
        elif choice == "3":
            explorer_serveur()
        elif choice == "4":
            choice_2 = input("Vous voulez uplode ou download ? : ")
            if choice_2 == "uplode":
                upload_fichier(username)
            elif choice_2 == "download":
                telecharger_fichier()
        elif choice == "5":
            mot_cle = input("Entrer un mot cle (ex : le nom) : ")
            rechercher_iso(mot_cle)
            
        elif choice == "6":
            del_account(username, curs, conn)
            
        elif choice == "7":
            deconnexion()
            return

        elif choice == "8":
            quit(tunnel, conn, curs)
            return

        else:
            print(f"{r}Erreur : choix invalide.{r}")

@with_user_rank_and_key
def connect_tester(username, password, rank, db_rank, server_context, tunnel, conn, curs):
    # couleur
    orange_color = "\033[38;2;255;165;0m"  # Orange
    reset = "\033[0m"

    o = orange_color
    re = reset
    while True:
        print(f"{o}=== Bonjour {db_rank} {username} ==={re}")
        print(f"{o}1. Voir les informations du compte et les modifier")
        print(f"{o}2. Lister les dossiers et fichiers ISO")
        print(f"{o}3. Naviguer dans les dossiers")
        print(f"{o}4. Télécharger ou uploder un fichier ISO")
        print(f"{o}5. Rechercher un ISO")
        print(f"{o}6. Supprimer le compte")
        print(f"{o}7. Se déconnecter")
        print(f"{o}8. Quitter")

        choice = input(f"{o}Entrer un numero : {re}")

        if choice == "1":
            show_info(curs, conn, server_context, username, password, db_rank)

        # fonction en relation avec les system d'exploitation
        elif choice == "2":
            lister_fichiers_serveur()
        elif choice == "3":
            explorer_serveur()
        elif choice == "4":
            choice_2 = input("Vous voulez uplode ou download ? : ")
            if choice_2 == "uplode":
                upload_fichier(username)
            elif choice_2 == "download":
                telecharger_fichier()
        elif choice == "5":
            mot_cle = input("Entrer un mot cle (ex : le nom) : ")
            rechercher_iso(mot_cle)
            
        elif choice == "6":
            del_account(username, curs, conn)
            
        elif choice == "7":
            deconnexion()
            return

        elif choice == "8":
            quit(tunnel, conn, curs)
            return

        else:
            print(f"{r}Erreur : choix invalide.{r}")

@with_user_rank_and_key
def connect_admin(username, password, rank, db_rank, server_context, tunnel, conn, curs):
    reset = "\033[0m"
    re = reset
    while True:
        print(f"{r}=== Bonjour {db_rank} {username} ==={re}")
        print(f"{r}1. Voir les informations du compte et les modifier{re}")
        print(f"{r}2. Lister les dossiers et fichiers ISO")
        print(f"{r}3. Naviguer dans les dossiers")
        print(f"{r}4. Télécharger ou uploder un fichier ISO")
        print(f"{r}5. Rechercher un ISO")
        print(f"{r}6. Voir les détails d’un fichier")
        print(f"{r}7. Lister les utilisateurs{re}")
        print(f"{r}8. Supprimer un utilisateur{re}")
        print(f"{r}9. Se déconnecter{re}")
        print(f"{r}10. Quitter{re}")

        choice = input(f"{r}Entrer un numero : {re}")

        if choice == "1":
            show_info(curs, conn, server_context, username, password, db_rank)

        # fonction en relation avec les system d'exploitation
        elif choice == "2":
            lister_fichiers_serveur()
        elif choice == "3":
            explorer_serveur()
        elif choice == "4":
            choice_2 = input("Vous voulez uplode ou download ? : ")
            if choice_2 == "uplode":
                upload_fichier(username)
            elif choice_2 == "download":
                telecharger_fichier()
        elif choice == "5":
            mot_cle = input("Entrer un mot cle (ex : le nom) : ")
            rechercher_iso(mot_cle)
        elif choice == "6":
            details_fichier()

        elif choice == "7":
            list_users(curs, r, re)
            users = list_users(curs)
            if users:
                for u in users:
                    print(f"{r}ID: {u['id']}, Username: {u['username']}, Rank: {u['rank']}{re}")
            else:
                print("Aucun utilisateur trouvé.")
            
        elif choice == "8":
            del_user(tunnel, conn, curs, r, re)
            
        elif choice == "9":
            deconnexion()
            return  # sinon le menu se relance

        elif choice == "10":
            quit(tunnel, conn, curs)
            return

        else:
            print(f"{r}Erreur : choix invalide.{re}")
        

@with_user_rank_and_key
def connect_superadmin(username, password, rank, db_rank, server_context, tunnel, conn, curs):
    reset = "\033[0m"
    re = reset
    while True:
        print(f"{m}=== Bonjour {db_rank} {username} ==={re}")
        print(f"{m}1. Voir les informations du compte et les modifier{re}")
        print(f"{m}2. Lister les dossiers et fichiers ISO")
        print(f"{m}3. Naviguer dans les dossiers")
        print(f"{m}4. Télécharger ou uploder un fichier ISO")
        print(f"{m}5. Rechercher un ISO")
        print(f"{m}6. Voir les détails d’un fichier")
        print(f"{m}7. Supprimer un ISO")
        print(f"{m}8. Lister les utilisateurs{re}")
        print(f"{m}9. Ban / deban un utilisateur")
        print(f"{m}10. Changer le rang un utilisateur{re}")
        print(f"{m}11. Supprimer un utilisateur{re}")
        print(f"{m}12. Se déconnecter{re}")
        print(f"{m}13. Quitter{re}")

        choice = input(f"{m}Entrer un numero : {re}")

        if choice == "1":
            show_info(curs, conn, server_context, username, password, db_rank)

        # fonction en relation avec les system d'exploitation
        elif choice == "2":
            lister_fichiers_serveur()
        elif choice == "3":
            explorer_serveur()
        elif choice == "4":
            choice_2 = input("Vous voulez uplode ou download ? : ")
            if choice_2 == "uplode":
                upload_fichier(username)
            elif choice_2 == "download":
                telecharger_fichier()
        elif choice == "5":
            mot_cle = input("Entrer un mot cle (ex : le nom) : ")
            rechercher_iso(mot_cle)
        elif choice == "6":
            details_fichier()
        elif choice == "7":
            file_path = input("Entrer le chemin du fichier a supprimer : ")
            verification = input("Tapper 'OUI' pour supprimer : ")
            if verification.lower() == "oui":
                supprimer_fichier(file_path)
            else:
                print(f"{g}Supression annuler")
            
        elif choice == "8":
            list_users(curs, r, re)
            users = list_users(curs)
            if users:
                print(f"{m}======User====={re}")
                for u in users:
                    print(f"{m}ID: {u['id']}, Username: {u['username']}, Rank: {u['rank']}{re}")
                print(f"{m}==============={re}")
            else:
                print("Aucun utilisateur trouvé.")
        
        elif choice == "9":
            ban_deban = input(f"{m}Vous voulez ban ou deban ? : ")
            if ban_deban == "ban":
                ban_user(tunnel, curs, conn)
            elif ban_deban == "deban":
                unban_user(tunnel, curs, conn)
         
        elif choice == "10":
            set_rank(tunnel, conn, curs, rank, m, re)
            
        elif choice == "11":
            del_user(tunnel, conn, curs, m, re)
            
        elif choice == "12":
            deconnexion()
            return  # sinon le menu se relance

        elif choice == "13":
            quit(tunnel, conn, curs)
            return

        else:
            print(f"{r}Erreur : choix invalide.{re}")

@with_user_rank_and_key
def connect_fondateur(username, password, rank, db_rank, server_context, tunnel, conn, curs):
    # Couleurs
    violet_fondateur = "\033[38;2;66;5;112m"
    reset = "\033[0m"
    v = violet_fondateur
    re = reset

    # Menu fondateur
    while True:
        print(f"{v}=== Bonjour {db_rank} {username} ==={re}")
        print(f"{v}1. Voir les informations du compte et les modifier{re}")
        print(f"{v}2. Lister les dossiers et fichiers ISO")
        print(f"{v}3. Naviguer dans les dossiers")
        print(f"{v}4. Télécharger ou uploder un fichier ISO")
        print(f"{v}5. Rechercher un ISO")
        print(f"{v}6. Voir les détails d’un fichier")
        print(f"{v}7. Supprimer un ISO")
        print(f"{v}8. Lister les utilisateurs{re}")
        print(f"{v}9. Ban / deban un utilisateur")
        print(f"{v}10. Changer le rang un utilisateur{re}")
        print(f"{v}11. Supprimer un utilisateur{re}")
        print(f"{v}12. Se déconnecter{re}")
        print(f"{v}13. Quitter{re}")
        print(f"{r}14. Supprimer toutes les tables{re}")

        choice = input(f"{v}Entrer un numero : {re}")

        if choice == "1":
            show_info(curs, conn, server_context, username, password, db_rank)
        
        # fonction en relation avec les system d'exploitation
        elif choice == "2":
            lister_fichiers_serveur()
        elif choice == "3":
            explorer_serveur()
        elif choice == "4":
            choice_2 = input("Vous voulez uplode ou download ? : ")
            if choice_2 == "uplode":
                upload_fichier(username)
            elif choice_2 == "download":
                telecharger_fichier()
        elif choice == "5":
            mot_cle = input("Entrer un mot cle (ex : le nom) : ")
            rechercher_iso(mot_cle)
        elif choice == "6":
            details_fichier()
        elif choice == "7":
            file_path = input("Entrer le chemin du fichier a supprimer : ")
            verification = input("Tapper 'OUI' pour supprimer : ")
            if verification.lower() == "oui":
                supprimer_fichier(file_path)
            else:
                print(f"{g}Supression annuler")
                
                
        elif choice == "8":
            list_users(curs)
            users = list_users(curs)
            if users:
                print(f"{v}======User====={re}")
                for u in users:
                    print(f"{m}ID: {u['id']}, Username: {u['username']}, Rank: {u['rank']}{re}")
                print(f"{v}==============={re}")
            else:
                print("Aucun utilisateur trouvé.")
        
        elif choice == "9":
            ban_deban = input(f"{m}Vous voulez ban ou deban ? : ")
            if ban_deban == "ban":
                ban_user(tunnel, curs, conn)
            elif ban_deban == "deban":
                unban_user(tunnel, curs, conn)
            
        elif choice == "10":
            set_rank(tunnel, conn, curs, rank, v, re)
            
        elif choice == "11":
            del_user(tunnel, conn, curs, v, re)
            
        elif choice == "12":
            deconnexion()
            return  # sinon le menu se relance

        elif choice == "13":
            quit(tunnel, conn, curs)
            return

        elif choice == "14":
            tables_to_reset = ["users", "blacklist"]
            reset_database(tables_to_reset, tunnel, conn, curs)
        
        else:
            print(f"{r}Erreur : choix invalide.{re}")
