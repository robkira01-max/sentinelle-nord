#!/usr/bin/env python3
"""Crée le premier utilisateur admin — à lancer une seule fois.

Usage :
    source .venv/bin/activate
    python3 scripts/create_admin.py
    python3 scripts/create_admin.py --username admin --password MonMotDePasse123!
    python3 scripts/create_admin.py --list          # affiche les users existants
"""
import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
# Désactiver le scheduler pour ce script CLI
os.environ.setdefault("SCHEDULER_ENABLED", "false")


def main() -> None:
    parser = argparse.ArgumentParser(description="Gestion des utilisateurs Sentinelle")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default=None,
                        help="Mot de passe (min 12 car.) — demandé interactivement si absent")
    parser.add_argument("--role", default="admin",
                        choices=("admin", "analyst", "readonly"))
    parser.add_argument("--list", action="store_true",
                        help="Affiche les utilisateurs existants")
    args = parser.parse_args()

    from app import create_app
    flask_app = create_app()

    with flask_app.app_context():
        from models import User, db

        if args.list:
            users = User.query.order_by(User.id).all()
            if not users:
                print("Aucun utilisateur.")
            else:
                print(f"{'ID':<4} {'Username':<20} {'Role':<10} {'Active':<8} {'Last login'}")
                print("-" * 60)
                for u in users:
                    last = u.last_login.strftime("%Y-%m-%d %H:%M") if u.last_login else "—"
                    print(f"{u.id:<4} {u.username:<20} {u.role:<10} {str(u.active):<8} {last}")
            return

        # Demander le mot de passe si non fourni
        password = args.password
        if not password:
            import getpass
            print(f"Création de l'utilisateur '{args.username}' (rôle: {args.role})")
            password = getpass.getpass("Mot de passe (min 12 caractères) : ")
            confirm  = getpass.getpass("Confirmer le mot de passe : ")
            if password != confirm:
                print("ERREUR : les mots de passe ne correspondent pas.", file=sys.stderr)
                sys.exit(1)

        if len(password) < 12:
            print("ERREUR : le mot de passe doit faire au moins 12 caractères.", file=sys.stderr)
            sys.exit(1)

        existing = User.query.filter_by(username=args.username).first()
        if existing:
            print(f"L'utilisateur '{args.username}' existe déjà (rôle: {existing.role}).")
            overwrite = input("Réinitialiser le mot de passe ? [o/N] ").strip().lower()
            if overwrite == "o":
                existing.set_password(password)
                db.session.commit()
                print(f"Mot de passe de '{args.username}' réinitialisé.")
            return

        user = User(username=args.username, role=args.role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        print(f"✅ Utilisateur '{args.username}' ({args.role}) créé avec succès.")
        print(f"   Connectez-vous sur http://127.0.0.1:5000/auth/login")


if __name__ == "__main__":
    main()
