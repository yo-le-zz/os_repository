# main.py
# activer la venv : .\env\Scripts\Activate.ps1

import warnings
warnings.filterwarnings('ignore')

import os
import sys

import bcrypt

from config import *
from logger import *
from serveur_func import open_all, close_ssh_tunnel, create_admin_if_needed, init_server, create_tables
from login_register import init_login_register, register, login

def init_all():
    color = init_config()
    try:
        init_server()
        tunnel, conn, curs = open_all()
        create_tables(conn, curs)
        create_admin_if_needed(conn, curs)
        close_ssh_tunnel(tunnel, conn, curs)
    except Exception as e:
        print(f"Le reseau est inacessible ou la connexion au serveur a echouer utilisation du json local pour la connexion, inscription impossible")
        print(f"l'erreur est : ")
        import traceback
        traceback.print_exc()
    init_logger('logger', color=color)
    init_login_register()

def make_color():
    color_palette = init_config()
    global r, g, b, y, w, c, m
    r, g, b, y, w, c, m = color_palette

def menu():
    make_color()
    while True:
        print(f"{c}===Menu===")
        print(f"{c}1. S'enregistrer")
        print(f"{c}2. Se connecter")
        print(f"{c}3. Quitter")
        choice = input(f"{c}Entrer un numero : ")
        if choice == '1':
            register()
        elif choice == '2':
            login()
        elif choice == '3':
            print(f"{m}Au revoir!")
            sys.exit()
        else:
            print(f"{r}Option invalide !")
        

if __name__ == "__main__":
    init_all()
    menu()