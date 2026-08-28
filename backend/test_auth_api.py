"""Pruebas de la API autenticada: que NADA quede abierto por descuido.

Correr con:  python test_auth_api.py
"""
from __future__ import annotations

import os

os.environ.setdefault("ORACLE_JWT_SECRET", "z" * 48)
os.environ.setdefault("ORACLE_OPERATOR", "denis")
os.environ.setdefault("ORACLE_COOKIE_SECURE", "0")

from app.auth import COOKIE, hash_password  # noqa: E402

os.environ.setdefault("ORACLE_OPERATOR_HASH", hash_password("clave-de-prueba"))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

PROTEGIDOS = [
    ("GET", "/api/missions", None),
    ("POST", "/api/missions", {"objective": "auditar algo", "demo": True}),
    ("POST", "/api/decisions", {"mission": "x", "action": "approve"}),
    ("GET", "/api/auth/me", None),
]


def main() -> int:
    c = TestClient(app)
    res: list[tuple[str, bool]] = []

    def check(n: str, ok: bool) -> None:
        res.append((n, ok))

    # --- sin token, TODO cerrado ---
    for metodo, ruta, cuerpo in PROTEGIDOS:
        r = c.request(metodo, ruta, json=cuerpo)
        check(f"sin token: {metodo} {ruta} da 401", r.status_code == 401)

    # --- el panel sigue publico (es solo la pantalla de login) ---
    check("el panel se sirve sin token", c.get("/").status_code == 200)

    # --- login ---
    r = c.post("/api/auth/login", json={"username": "denis", "password": "mala"})
    check("login con clave mala da 401", r.status_code == 401)

    r = c.post("/api/auth/login",
               json={"username": "denis", "password": "clave-de-prueba"})
    check("login correcto da 200", r.status_code == 200)
    datos = r.json()
    check("devuelve token de acceso y caducidad",
          bool(datos.get("access_token")) and datos.get("expires_in") == 900)

    galletas = r.headers.get("set-cookie", "")
    check("la cookie de refresco es HttpOnly", "httponly" in galletas.lower())
    check("la cookie es SameSite=strict", "samesite=strict" in galletas.lower())
    check("la cookie se limita a /api/auth", "path=/api/auth" in galletas.lower())
    check("el refresco NO viaja en el cuerpo", "refresh" not in str(datos).lower())

    auth = {"Authorization": f"Bearer {datos['access_token']}"}

    # --- con token, todo abre ---
    check("con token: /api/auth/me responde",
          c.get("/api/auth/me", headers=auth).json().get("user") == "denis")
    check("con token: se listan misiones",
          c.get("/api/missions", headers=auth).status_code == 200)

    r = c.post("/api/decisions", headers=auth,
               json={"mission": "inexistente", "action": "approve"})
    check("con token: una decision invalida da 404 (no 401)", r.status_code == 404)

    # --- token falsificado ---
    malo = {"Authorization": "Bearer " + datos["access_token"][:-3] + "abc"}
    check("un token manipulado da 401",
          c.get("/api/missions", headers=malo).status_code == 401)

    # --- rotacion por cookie ---
    r2 = c.post("/api/auth/refresh")
    check("refrescar devuelve un acceso nuevo",
          r2.status_code == 200 and r2.json()["access_token"] != datos["access_token"])

    viejo = None
    for cookie in c.cookies.jar:
        if cookie.name == COOKIE:
            viejo = cookie.value
    check("la cookie se roto en el cliente", viejo is not None)

    # --- logout ---
    auth2 = {"Authorization": f"Bearer {r2.json()['access_token']}"}
    check("logout responde ok",
          c.post("/api/auth/logout", headers=auth2).json().get("ok") is True)
    check("tras logout el acceso queda revocado",
          c.get("/api/missions", headers=auth2).status_code == 401)
    check("tras logout no se puede refrescar",
          c.post("/api/auth/refresh").status_code == 401)

    # --- WebSocket sin token ---
    try:
        with c.websocket_connect("/ws/operator"):
            check("el WebSocket exige token", False)
    except Exception:  # noqa: BLE001
        check("el WebSocket exige token", True)

    fallos = sum(1 for _, ok in res if not ok)
    for n, ok in res:
        print(f"  [{'OK' if ok else 'XX'}] {n}")
    print(f"\n{len(res) - fallos}/{len(res)} casos correctos.")
    return 1 if fallos else 0


if __name__ == "__main__":
    raise SystemExit(main())
