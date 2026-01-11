# system.py
from config import *
import paramiko
import psycopg2
import os
import unicodedata
import sys
from serveur_func import *

import time
from datetime import datetime

def make_color():
    global r, g, b, y, w, c, m, color
    color = init_config()
    r, g, b, y, w, c, m = color

def supprimer_fichier(remote_file_path):
    SSH_HOST, SSH_PASSWORD, PG_PASSWORD = load()
    """
    Supprime un fichier sur le serveur et le retire de la colonne 'uploaded' de l'utilisateur.
    """
    make_color()
    client = None
    sftp = None
    conn = None
    curs = None

    try:
        # Connexion SSH
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(SSH_HOST, port=SSH_PORT, username=SSH_USER, password=SSH_PASSWORD)
        sftp = client.open_sftp()
        print(f"{g}Connexion SSH réussie sur le serveur")

        # Vérifie si le fichier existe
        try:
            sftp.stat(remote_file_path)
        except IOError:
            print(f"{r}Fichier introuvable sur le serveur !")
            return

        # Supprimer le fichier
        sftp.remove(remote_file_path)
        print(f"{g}Fichier {remote_file_path} supprimé avec succès sur le serveur")

        # Connexion DB pour retirer le fichier de la colonne uploaded
        conn = psycopg2.connect(
            host=PG_HOST,
            port=PG_PORT,
            database=PG_DATABASE,
            user=PG_USER,
            password=PG_PASSWORD
        )
        curs = conn.cursor()
        # Retire le fichier de tous les utilisateurs qui l'ont uploadé
        curs.execute("UPDATE users SET uploaded = array_remove(uploaded, %s) WHERE %s = ANY(uploaded)", (remote_file_path, remote_file_path))
        conn.commit()
        print(f"{g}Base de données mise à jour, fichier retiré de tous les utilisateurs")

    except Exception as e:
        print(f"{r}Erreur : {e}")

    finally:
        if sftp:
            try: sftp.close()
            except: pass
        if client:
            try: client.close()
            except: pass
        if curs:
            try: curs.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass
        print(f"{g}Connexion SSH et DB fermées")

def lister_fichiers_serveur(remote_path="/home/ilan/Bureau/hub_exploitation/system"):
    SSH_HOST, SSH_PASSWORD, PG_PASSWORD = load()
    make_color()
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(SSH_HOST, port=SSH_PORT, username=SSH_USER, password=SSH_PASSWORD)
        print(f"{g}Connexion SSH réussie sur le serveur !")

        # Utilisation de 'find' pour lister récursivement tous les fichiers et dossiers
        # -maxdepth 3 permet de ne pas s'y perdre, vous pouvez l'augmenter ou l'enlever
        stdin, stdout, stderr = client.exec_command(f'find {remote_path} -not -path "*/.*"')
        lignes = stdout.read().decode().splitlines()

        if not lignes:
            print(f"{y}Aucun contenu trouvé dans {remote_path}")
            return
        
        print(f"\n{c}Arborescence complète de : {remote_path}")
        for ligne in lignes:
            # On calcule l'indentation pour l'aspect visuel
            profondeur = ligne.replace(remote_path, "").count("/")
            nom = os.path.basename(ligne.rstrip("/"))
            indent = "  " * profondeur
            
            if ligne.endswith("/"): # C'est un dossier
                print(f"{indent}{y}📁 {nom}/")
            else: # C'est un fichier
                color_file = g if nom.lower().endswith(".iso") else w
                print(f"{indent}{color_file}📄 {nom}")

    except Exception as e:
        print(f"{r}Erreur SSH : {e}")
    finally:
        client.close()
        print(f"{g}Connexion SSH fermée")
        
def explorer_serveur(remote_path="/home/ilan/Bureau/hub_exploitation/system"):
    SSH_HOST, SSH_PASSWORD, PG_PASSWORD = load()
    """
    Menu interactif pour naviguer dans les dossiers du serveur distant.
    """
    make_color()
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(SSH_HOST, port=SSH_PORT, username=SSH_USER, password=SSH_PASSWORD)
        print(f"{g}Connexion SSH réussie sur {SSH_HOST}")

        current_path = remote_path

        while True:
            print(f"\n{c}Dossier actuel : {current_path}")
            
            # Liste les dossiers et fichiers
            stdin, stdout, stderr = client.exec_command(f'ls -p {current_path}')
            items = stdout.read().decode().splitlines()

            dossiers = [i for i in items if i.endswith("/")]
            fichiers = [i for i in items if not i.endswith("/")]

            # Affichage
            print(f"{y}Sous-dossiers :")
            for d in dossiers:
                print(f"  - {d}")
            print(f"{m}Fichiers :")
            for f in fichiers:
                print(f"  - {f}")

            # Menu de navigation
            print(f"\n{w}Options :")
            print("1. Entrer dans un sous-dossier")
            print("2. Remonter d'un niveau")
            print("3. Quitter")

            choix = input(f"{b}Choix : {w}")
            if choix == "1":
                nom_dossier = input("Nom du sous-dossier : ")
                if nom_dossier in dossiers:
                    # enlever le "/" final pour concaténation
                    current_path = current_path = current_path.rstrip("/") + "/" + nom_dossier.rstrip("/")
                else:
                    print(f"{r}Dossier introuvable !")
                    print(dossiers)
            elif choix == "2":
                if os.path.dirname(current_path) == "/home/ilan/Bureau/hub_exploitation":
                    print(f"{r}Vous ne pouvez pas remonter si haut")
                else:
                    current_path = os.path.dirname(current_path)
            elif choix == "3":
                break
            else:
                print(f"{r}Option invalide.")

    except Exception as e:
        print(f"{r}Erreur SSH : {e}")
    finally:
        client.close()
        print(f"{g}Connexion SSH fermée")
        
def telecharger_fichier(remote_file_path=None):
    SSH_HOST, SSH_PASSWORD, PG_PASSWORD = load()
    """
    Télécharge un fichier depuis le serveur, limité à 'system/'.
    Affiche un spinner et le pourcentage.
    """
    make_color()
    client = None
    sftp = None

    base_dir = "/home/ilan/Bureau/hub_exploitation/system"

    try:
        # Connexion SSH
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(SSH_HOST, port=SSH_PORT, username=SSH_USER, password=SSH_PASSWORD)
        sftp = client.open_sftp()
        print(f"{g}Connexion SSH réussie sur le serveur")

        if not remote_file_path:
            user_input = input(f"{b}Chemin relatif depuis 'system/' (ex: Linux/iso.iso) : {w}").strip().rstrip("/")
            user_input = user_input.replace("\\", "/")
            if not user_input:
                print(f"{r}Aucun chemin fourni !")
                return

            # Construire le chemin complet côté serveur
            remote_file_path = f"{base_dir}/{user_input}"
            remote_file_path = remote_file_path.replace("//", "/")  # éviter double slash

        # Vérification : le fichier doit rester dans system/
        if not remote_file_path.startswith(base_dir + "/") and remote_file_path != base_dir:
            print(f"{r}Accès refusé : chemin en dehors de 'system/' interdit.")
            print(f"Exemple valide : Windows/machine_id.txt ou Linux/iso.iso")
            return

        # Vérifie si le fichier existe
        try:
            attr = sftp.stat(remote_file_path)
        except IOError:
            print(f"{r}Fichier introuvable sur le serveur !")
            print(f"DEBUG chemin tenté : {remote_file_path}")
            return

        # Choix du dossier local
        local_dir = input(f"{b}Dossier local pour sauvegarder le fichier : {w}").strip()
        if not os.path.exists(local_dir):
            os.makedirs(local_dir)
            print(f"{y}Dossier créé : {local_dir}")

        filename = os.path.basename(remote_file_path)
        local_file_path = os.path.join(local_dir, filename)

        # Téléchargement avec spinner et pourcentage
        file_size = attr.st_size
        downloaded = 0
        spinner = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
        spin_index = 0

        print(f"{c}Téléchargement en cours... ", end="")
        sys.stdout.flush()

        with sftp.file(remote_file_path, "rb") as f:
            with open(local_file_path, "wb") as local_f:
                while True:
                    chunk = f.read(1048576)
                    if not chunk:
                        break
                    local_f.write(chunk)
                    downloaded += len(chunk)
                    percent = (downloaded / file_size) * 100
                    print(f"\r{c}Téléchargement en cours... {spinner[spin_index % len(spinner)]} {percent:.1f}% ", end="")
                    sys.stdout.flush()
                    spin_index += 1
                    time.sleep(0.05)

        print(f"\r{g}Téléchargement terminé ✔️ {' ' * 20}")
        print(f"{g}Fichier téléchargé avec succès : {local_file_path}")

    except Exception as e:
        print(f"{r}Erreur : {e}")

    finally:
        if sftp:
            try: sftp.close()
            except: pass
        if client:
            try: client.close()
            except: pass
        print(f"{g}Connexion SSH fermée")

def rechercher_iso(mot_cle, remote_path="/home/ilan/Bureau/hub_exploitation/system"):
    SSH_HOST, SSH_PASSWORD, PG_PASSWORD = load()
    make_color()
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(SSH_HOST, port=SSH_PORT, username=SSH_USER, password=SSH_PASSWORD)
        
        # Recherche récursive de fichiers contenant le mot-clé et finissant par .iso
        commande = f'find {remote_path} -type f -iname "*{mot_cle}*.iso"'
        stdin, stdout, stderr = client.exec_command(commande)
        resultats = stdout.read().decode().splitlines()

        if resultats:
            print(f"{g}Résultats pour '{mot_cle}':")
            for r in resultats:
                # Affiche le chemin relatif pour plus de clarté
                print(f" - {r.replace(remote_path, '')}")
        else:
            print(f"{y}Aucun fichier .iso trouvé pour : {mot_cle}")
    except Exception as e:
        print(f"{r}Erreur : {e}")
    finally:
        if client: client.close()

def details_fichier():
    SSH_HOST, SSH_PASSWORD, PG_PASSWORD = load()
    """
    Affiche les détails d'un fichier situé dans system/
    + donne l'utilisateur qui l'a uploadé.
    """
    make_color()

    base_dir = "/home/ilan/Bureau/hub_exploitation/system"

    client = None
    sftp = None

    remote_relative_path = input(f"{b}fichier distant relatif à system/ (ex: Linux/iso.iso) : {w}").strip().rstrip("/")
    
    # ---------------------------------------------------
    # 🔐 Vérification du chemin (doit rester dans system/)
    # ---------------------------------------------------
    remote_relative_path = remote_relative_path.replace("\\", "/").lstrip("/")
    remote_file_path = f"{base_dir}/{remote_relative_path}"

    if not os.path.realpath(remote_file_path).startswith(os.path.realpath(base_dir)):
        print(f"{r}Accès refusé : chemin en dehors de 'system/' interdit.")
        print(f"{y}Exemple valide : Windows/machine_id.txt ou Linux/iso.iso")
        return

    try:
        # -----------------------------
        # 🔌 Connexion SFTP (SSH direct)
        # -----------------------------
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(SSH_HOST, port=SSH_PORT, username=SSH_USER, password=SSH_PASSWORD)
        sftp = client.open_sftp()

        print(f"{g}Connexion SSH réussie sur le serveur")

        # -----------------------------
        # 📁 Vérifier si le fichier existe
        # -----------------------------
        try:
            attr = sftp.stat(remote_file_path)
        except FileNotFoundError:
            print(f"{r}Fichier introuvable sur le serveur !")
            return

        filename = os.path.basename(remote_file_path)

        # Taille KO + MO
        size_bytes = attr.st_size
        size_kb = size_bytes / 1024
        size_mb = size_bytes / (1024*1024)

        print(f"{c}Nom du fichier : {w}{filename}")
        print(f"{c}Chemin complet : {w}{remote_file_path}")

        # -----------------------------
        # 🔗 Connexion DB via open_all()
        # -----------------------------
        tunnel, conn, curs = open_all()   # <<< ICI → RESPECT TA STRUCTURE
                                         # PAS DE "too many values to unpack"

        curs.execute(
            "SELECT username FROM users WHERE %s = ANY(uploaded)",
            (remote_file_path,)
        )
        result = curs.fetchone()

        if result:
            print(f"{c}Expéditeur : {w}{result[0]}")
        else:
            print(f"{c}Expéditeur : {w}inconnu")

        # Fermeture BDD
        close_ssh_tunnel(tunnel, conn, curs)

    except Exception as e:
        print(f"{r}Erreur : {e}")

    finally:
        if sftp:
            try: sftp.close()
            except: pass
        if client:
            try: client.close()
            except: pass

        print(f"{g}Connexion SSH et DB fermées")

def upload_fichier(username):
    SSH_HOST, SSH_PASSWORD, PG_PASSWORD = load()
    """
    Upload un fichier depuis la machine locale vers le serveur
    avec animation, pourcentage et ajout à la colonne uploaded de l'utilisateur.
    Bloque tout accès en dehors de system/.
    """
    make_color()
    client = None
    sftp = None
    remote_file_path = None

    base_dir = "/home/ilan/Bureau/hub_exploitation/system"

    try:
        # Connexion SSH
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(SSH_HOST, port=SSH_PORT, username=SSH_USER, password=SSH_PASSWORD)
        sftp = client.open_sftp()
        print(f"{g}Connexion SSH réussie sur le serveur")

        # Chemin local
        local_file = input(f"{b}Chemin complet du fichier local à uploader : {w}").strip()
        if not os.path.exists(local_file):
            print(f"{r}Fichier local introuvable !")
            return

        # Dossier distant relatif à system/
        user_input = input(f"{b}Dossier distant relatif à system/ (ex: Linux) : {w}").strip().rstrip("/")
        remote_dir = base_dir + "/" + user_input.replace("\\", "/")

        # Vérification sécurité
        if not os.path.realpath(remote_dir).startswith(os.path.realpath(base_dir)):
            print(f"{r}Accès refusé : dossier en dehors de system/ interdit.")
            return

        # Créer dossier distant si nécessaire
        try:
            sftp.chdir(remote_dir)
        except IOError:
            sftp.mkdir(remote_dir)
            print(f"{y}Dossier distant créé : {remote_dir}")

        # Nom du fichier
        filename = os.path.basename(local_file)
        remote_file_path = remote_dir + "/" + filename
        print(f"DEBUG remote_file_path = {remote_file_path}")

        # Animation + upload
        spinner = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
        file_size = os.path.getsize(local_file)
        uploaded = 0
        spin_index = 0

        print(f"{c}Upload en cours... ", end="")
        sys.stdout.flush()

        with open(local_file, "rb") as f:
            sftp_file = sftp.file(remote_file_path, 'wb')
            while True:
                chunk = f.read(1048576)  # 1 Mo
                if not chunk:
                    break
                sftp_file.write(chunk)
                sftp_file.flush()
                uploaded += len(chunk)
                percent = (uploaded / file_size) * 100
                print(f"\r{c}Upload en cours... {spinner[spin_index % len(spinner)]} {percent:.1f}% ", end="")
                sys.stdout.flush()
                spin_index += 1
                time.sleep(0.05)
            sftp_file.close()

        print(f"\r{g}Upload terminé ✔️ {' ' * 20}")

        # Mise à jour DB via tunnel
        tunnel, conn, curs = open_all()
        try:
            curs.execute(
                "UPDATE users SET uploaded = COALESCE(uploaded, '{}') || %s WHERE username = %s",
                ([remote_file_path], username)
            )
            conn.commit()
            print(f"{g}Base de données mise à jour, fichier ajouté à {username}")
        finally:
            close_ssh_tunnel(tunnel, conn, curs)

    except Exception as e:
        print(f"\n{r}Erreur pendant l'upload : {e}")
        print(f"{r}Si l'erreur est : 'utf-8' codec can't decode byte 0xe9 in position 97, ne faites pas attention")

    finally:
        if sftp:
            try: sftp.close()
            except: pass
        if client:
            try: client.close()
            except: pass
        print(f"{g}Connexion SSH et DB fermées")
