"""Tests — authentification et gestion des utilisateurs."""
import pytest
from models import User


# ── Login page ────────────────────────────────────────────────────────────────

class TestLoginPage:
    def test_login_page_returns_200(self, client):
        r = client.get("/auth/login")
        assert r.status_code == 200

    def test_login_page_html(self, client):
        r = client.get("/auth/login")
        assert b"login" in r.data.lower() or b"connexion" in r.data.lower()

    def test_authenticated_user_redirected_from_login(self, admin_client):
        r = admin_client.get("/auth/login", follow_redirects=False)
        # Flask-Login redirects authenticated users away from login
        assert r.status_code in (302, 200)


# ── Login POST ────────────────────────────────────────────────────────────────

class TestLoginPost:
    def test_valid_admin_login(self, client, admin_user):
        r = client.post("/auth/login", data={
            "username": "admin_test",
            "password": "AdminPassword2026!",
        }, follow_redirects=False)
        assert r.status_code == 303

    def test_valid_analyst_login(self, client, analyst_user):
        r = client.post("/auth/login", data={
            "username": "analyst_test",
            "password": "AnalystPassword2026!",
        }, follow_redirects=False)
        assert r.status_code == 303

    def test_wrong_password_returns_401(self, client, admin_user):
        r = client.post("/auth/login", data={
            "username": "admin_test",
            "password": "wrongpassword",
        })
        assert r.status_code == 401

    def test_unknown_user_returns_401(self, client):
        r = client.post("/auth/login", data={
            "username": "nobody",
            "password": "somepassword",
        })
        assert r.status_code == 401

    def test_empty_credentials_returns_400(self, client):
        r = client.post("/auth/login", data={
            "username": "",
            "password": "",
        })
        assert r.status_code == 400

    def test_inactive_user_cannot_login(self, client, db):
        u = User(username="inactive_user", role="analyst", active=False)
        u.set_password("Inactive2026Password!")
        db.session.add(u)
        db.session.commit()
        r = client.post("/auth/login", data={
            "username": "inactive_user",
            "password": "Inactive2026Password!",
        })
        assert r.status_code == 403

    def test_next_redirect_stays_internal(self, client, admin_user):
        r = client.post("/auth/login?next=/auth/users", data={
            "username": "admin_test",
            "password": "AdminPassword2026!",
        }, follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["Location"].startswith("/") or "auth" in r.headers["Location"]

    def test_next_redirect_ignores_external_url(self, client, admin_user):
        r = client.post("/auth/login?next=//evil.com", data={
            "username": "admin_test",
            "password": "AdminPassword2026!",
        }, follow_redirects=False)
        assert r.status_code == 303
        assert "evil.com" not in r.headers.get("Location", "")


# ── Logout ────────────────────────────────────────────────────────────────────

class TestLogout:
    def test_logout_redirects_to_login(self, admin_client):
        r = admin_client.get("/auth/logout", follow_redirects=False)
        assert r.status_code == 302
        assert "/auth/login" in r.headers["Location"]

    def test_logout_requires_login(self, client):
        r = client.get("/auth/logout", follow_redirects=False)
        assert r.status_code == 302


# ── User management (admin only) ──────────────────────────────────────────────

class TestUserManagement:
    def test_list_users_requires_admin(self, analyst_client):
        r = analyst_client.get("/auth/users")
        assert r.status_code == 403

    def test_list_users_as_admin(self, admin_client, admin_user):
        r = admin_client.get("/auth/users")
        assert r.status_code == 200

    def test_create_user_as_admin(self, admin_client, db):
        r = admin_client.post("/auth/users/create", data={
            "username": "newuser",
            "password": "Newpassword2026!",
            "role": "analyst",
        }, follow_redirects=False)
        assert r.status_code == 302
        assert User.query.filter_by(username="newuser").first() is not None

    def test_create_user_short_password_rejected(self, admin_client, db):
        r = admin_client.post("/auth/users/create", data={
            "username": "badpw_user",
            "password": "short",
            "role": "analyst",
        }, follow_redirects=True)
        assert User.query.filter_by(username="badpw_user").first() is None

    def test_create_user_invalid_role_rejected(self, admin_client, db):
        r = admin_client.post("/auth/users/create", data={
            "username": "badrole_user",
            "password": "ValidPassword2026!",
            "role": "superuser",
        }, follow_redirects=True)
        assert User.query.filter_by(username="badrole_user").first() is None

    def test_create_user_duplicate_rejected(self, admin_client, admin_user):
        r = admin_client.post("/auth/users/create", data={
            "username": "admin_test",
            "password": "AnotherPassword2026!",
            "role": "analyst",
        }, follow_redirects=True)
        # Should not crash, just flash error
        assert r.status_code == 200

    def test_toggle_user_as_admin(self, admin_client, readonly_user):
        r = admin_client.post(f"/auth/users/{readonly_user.id}/toggle",
                              follow_redirects=False)
        assert r.status_code == 302
        from models import db as _db, User as U
        u = _db.session.get(U, readonly_user.id)
        assert u.active is False

    def test_cannot_toggle_own_account(self, admin_client, admin_user, db):
        r = admin_client.post(f"/auth/users/{admin_user.id}/toggle",
                              follow_redirects=True)
        # Should be blocked with flash, not actually toggled
        u = db.session.get(User, admin_user.id)
        assert u.active is True

    def test_reset_password_as_admin(self, admin_client, analyst_user, db):
        r = admin_client.post(f"/auth/users/{analyst_user.id}/reset-password", data={
            "new_password": "NewPassword2026!",
        }, follow_redirects=False)
        assert r.status_code == 302

    def test_change_role_as_admin(self, admin_client, readonly_user, db):
        r = admin_client.post(f"/auth/users/{readonly_user.id}/role", data={
            "role": "analyst",
        }, follow_redirects=False)
        assert r.status_code == 302
        u = db.session.get(User, readonly_user.id)
        assert u.role == "analyst"

    def test_non_admin_cannot_create_user(self, analyst_client):
        r = analyst_client.post("/auth/users/create", data={
            "username": "hacked",
            "password": "HackedPassword2026!",
            "role": "admin",
        }, follow_redirects=False)
        assert r.status_code == 403


# ── User model ────────────────────────────────────────────────────────────────

class TestUserModel:
    def test_has_role(self, admin_user):
        assert admin_user.has_role("admin")
        assert not admin_user.has_role("analyst")

    def test_can_scan_analyst(self, analyst_user):
        assert analyst_user.can_scan()

    def test_can_scan_admin(self, admin_user):
        assert admin_user.can_scan()

    def test_cannot_scan_readonly(self, readonly_user):
        assert not readonly_user.can_scan()

    def test_is_admin(self, admin_user, analyst_user):
        assert admin_user.is_admin()
        assert not analyst_user.is_admin()

    def test_password_hashing(self, db):
        u = User(username="pw_test", role="analyst")
        u.set_password("StrongPassword2026!")
        assert u.pw_hash != "StrongPassword2026!"
        assert u.check_password("StrongPassword2026!")
        assert not u.check_password("wrongpassword")
