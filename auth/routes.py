"""Auth blueprint — login, logout, gestion des utilisateurs."""
from datetime import datetime, timezone
from functools import wraps

from flask import (Blueprint, abort, flash, jsonify, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required, login_user, logout_user

from extensions import limiter
from models import ROLES, User, db

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# ── Décorateur rôle ───────────────────────────────────────────────────────────

def require_role(*roles: str):
    """Décorateur — refuse l'accès si le rôle courant n'est pas dans `roles`."""
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                if request.is_json or request.path.startswith("/api/"):
                    return jsonify({"error": "forbidden", "required_role": roles}), 403
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator


# ── Login / Logout ────────────────────────────────────────────────────────────

@auth_bp.get("/login")
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for("api.dashboard"))
    return render_template("login.html")


@auth_bp.post("/login")
@limiter.limit("5 per minute; 20 per hour")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    remember = bool(request.form.get("remember"))

    if not username or not password:
        flash("Identifiants requis.", "danger")
        return render_template("login.html"), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        flash("Nom d'utilisateur ou mot de passe incorrect.", "danger")
        return render_template("login.html"), 401

    if not user.active:
        flash("Compte désactivé.", "danger")
        return render_template("login.html"), 403

    login_user(user, remember=remember)
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()

    next_page = request.args.get("next")
    # 303 See Other force le navigateur/curl à faire un GET sur la cible
    # Validation SSRF : n'accepter que les chemins internes
    if next_page and next_page.startswith("/") and not next_page.startswith("//"):
        return redirect(next_page, 303)
    return redirect(url_for("api.dashboard"), 303)


@auth_bp.get("/logout")
@login_required
def logout():
    logout_user()
    flash("Déconnexion réussie.", "success")
    return redirect(url_for("auth.login_page"))


# ── Gestion des utilisateurs (admin) ─────────────────────────────────────────

@auth_bp.get("/users")
@require_role("admin")
def list_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("users.html", users=users, roles=ROLES)


@auth_bp.post("/users/create")
@require_role("admin")
def create_user():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    role     = request.form.get("role", "analyst")

    if not username or len(username) < 3:
        flash("Nom d'utilisateur trop court (min 3 caractères).", "danger")
        return redirect(url_for("auth.list_users"))
    if len(password) < 12:
        flash("Mot de passe trop court (min 12 caractères).", "danger")
        return redirect(url_for("auth.list_users"))
    if role not in ROLES:
        flash("Rôle invalide.", "danger")
        return redirect(url_for("auth.list_users"))
    if User.query.filter_by(username=username).first():
        flash(f"Utilisateur '{username}' existe déjà.", "danger")
        return redirect(url_for("auth.list_users"))

    u = User(username=username, role=role)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    flash(f"Utilisateur '{username}' ({role}) créé.", "success")
    return redirect(url_for("auth.list_users"))


@auth_bp.post("/users/<int:user_id>/toggle")
@require_role("admin")
def toggle_user(user_id: int):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if user.id == current_user.id:
        flash("Impossible de désactiver son propre compte.", "danger")
        return redirect(url_for("auth.list_users"))
    user.active = not user.active
    db.session.commit()
    state = "activé" if user.active else "désactivé"
    flash(f"Compte '{user.username}' {state}.", "success")
    return redirect(url_for("auth.list_users"))


@auth_bp.post("/users/<int:user_id>/reset-password")
@require_role("admin")
def reset_password(user_id: int):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    new_pw = request.form.get("new_password") or ""
    if len(new_pw) < 12:
        flash("Mot de passe trop court (min 12 caractères).", "danger")
        return redirect(url_for("auth.list_users"))
    user.set_password(new_pw)
    db.session.commit()
    flash(f"Mot de passe de '{user.username}' réinitialisé.", "success")
    return redirect(url_for("auth.list_users"))


@auth_bp.post("/users/<int:user_id>/role")
@require_role("admin")
def change_role(user_id: int):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if user.id == current_user.id:
        flash("Impossible de modifier son propre rôle.", "danger")
        return redirect(url_for("auth.list_users"))
    new_role = request.form.get("role", "analyst")
    if new_role not in ROLES:
        flash("Rôle invalide.", "danger")
        return redirect(url_for("auth.list_users"))
    user.role = new_role
    db.session.commit()
    flash(f"Rôle de '{user.username}' → {new_role}.", "success")
    return redirect(url_for("auth.list_users"))
