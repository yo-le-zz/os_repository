from logger import log
from config import *

import bcrypt

from sshtunnel import SSHTunnelForwarder
import psycopg2

def init_server():
    global SSH_HOST, SSH_PASSWORD, PG_PASSWORD
    SSH_HOST, SSH_PASSWORD, PG_PASSWORD = load()
    tunnel, conn, curs = open_all()
    if not tunnel:
        return
    
    create_tables(conn, curs)
    create_admin_if_needed(conn, curs)

    close_ssh_tunnel(tunnel, conn, curs)

def open_all():
    tunnel = open_ssh_tunnel()
    conn, curs = connect_to_db()
    if conn is None or curs is None:
        log("❌ Impossible de se connecter à la base de données.", level=40)
        return None, None, None
    return tunnel, conn, curs

def create_admin_if_needed(conn, curs):
    try:
        curs.execute("SELECT COUNT(*) FROM users;")
        count = curs.fetchone()[0]

        if count == 0:
            log("👑 Aucun utilisateur → création du fondateur...", level=20)

            username = "yolezz"
            hashed_password = b"$2b$12$.Sj.nlMtegYiCeM9lb87UOmBl5XczsQPAGw7AY61xnK.sER7xR3Sa"

            hashed = password

            curs.execute("""
                INSERT INTO users (username, password, rank)
                VALUES (%s, %s, %s)
            """, (username, hashed_password, "fondateur"))

            conn.commit()
            log("👑 Admin créé avec succès.", level=20)

        else:
            log("Admin déjà existant, skip.", level=20)

    except Exception as e:
        log(f"❌ Erreur création admin : {e}", level=40)
        conn.rollback()

def create_tables(conn, curs):
    try:
        curs.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                password BYTEA NOT NULL,
                rank TEXT DEFAULT 'user',
                machine_hash TEXT,
                uploaded TEXT[] DEFAULT ARRAY[]::TEXT[]
            );
        """)
        conn.commit()
        log("✅ Table 'users' OK", level=20)

    except Exception as e:
        log(f"❌ Erreur création table users : {e}", level=40)
        conn.rollback()

    try:
        curs.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                id SERIAL PRIMARY KEY,
                machine_hash TEXT NOT NULL,
                reason TEXT,
                banned_at TIMESTAMP DEFAULT NOW()
            );
        """)
        conn.commit()
        log("✅ Table 'blacklist' OK", level=20)

    except Exception as e:
        log(f"❌ Erreur création table blacklist : {e}", level=40)
        conn.rollback()

def open_ssh_tunnel():
    log("🔌 Ouverture du tunnel SSH...", level=20)
    tunnel = SSHTunnelForwarder(
        (SSH_HOST, SSH_PORT),
        ssh_username=SSH_USER,
        ssh_password=SSH_PASSWORD,
        remote_bind_address=(PG_HOST, PG_PORT),
        local_bind_address=('localhost', LOCAL_PORT)
    )
    tunnel.start()
    return tunnel

def connect_to_db():
    try:
        conn = psycopg2.connect(
            host="127.0.0.1",
            port=LOCAL_PORT,
            database=PG_DATABASE,
            user=PG_USER,
            password=PG_PASSWORD
        )
        curs = conn.cursor()
        log("✅ Connexion PostgreSQL OK", level=20)
        return conn, curs
    except Exception as e:
        log(f"❌ Connexion DB échouée : {e}", level=40)
        return None, None

def close_ssh_tunnel(tunnel, conn, curs):
    try:
        if curs:
            curs.close()
        if conn:
            conn.close()
        if tunnel:
            tunnel.stop()
        log("🔌 Fermeture propre terminée.", level=20)
    except Exception:

        pass
