"""Pruebas de autenticacion: JWT, rotacion de refresco y deteccion de reuso.

Sin red externa, sin API de Anthropic.

Correr con:  python test_auth.py
"""
from __future__ import annotations

import os
import time

os.environ.setdefault("ORACLE_JWT_SECRET", "x" * 48)
os.environ.setdefault("ORACLE_OPERATOR", "denis")
os.environ.setdefault("ORACLE_COOKIE_SECURE", "0")

from app.auth import (  # noqa: E402
    AuthError,
    AuthMisconfigured,
    TokenStore,
    autenticar,
    hash_password,
)

os.environ.setdefault("ORACLE_OPERATOR_HASH", hash_password("clave-de-prueba"))


def main() -> int:
    res: list[tuple[str, bool]] = []

    def check(n: str, ok: bool) -> None:
        res.append((n, ok))

    # ------------------------------------------------------- credenciales
    check("credenciales correctas autentican",
          autenticar("denis", "clave-de-prueba") == "denis")

    for nombre, u, c in [("clave incorrecta", "denis", "mala"),
                         ("usuario incorrecto", "otro", "clave-de-prueba")]:
        try:
            autenticar(u, c)
            check(f"{nombre} se rechaza", False)
        except AuthError:
            check(f"{nombre} se rechaza", True)

    # ------------------------------------------------------------ acceso
    st = TokenStore()
    tok, jti = st.emitir_acceso("denis")
    check("el JWT emitido se lee", st.leer_acceso(tok)["sub"] == "denis")
    check("el JWT lleva jti", st.leer_acceso(tok)["jti"] == jti)

    try:
        st.leer_acceso(tok + "x")
        check("un JWT manipulado se rechaza", False)
    except AuthError:
        check("un JWT manipulado se rechaza", True)

    st.bloquear_jti(jti)
    try:
        st.leer_acceso(tok)
        check("un jti bloqueado se rechaza al instante", False)
    except AuthError as e:
        check("un jti bloqueado se rechaza al instante", "revocado" in str(e))

    # ---------------------------------------------------------- refresco
    st2 = TokenStore()
    r1 = st2.emitir_refresco("denis")
    r2, u = st2.rotar(r1)
    check("rotar devuelve un token nuevo", r2 != r1 and u == "denis")

    r3, _ = st2.rotar(r2)
    check("la cadena de rotacion sigue funcionando", r3 not in (r1, r2))

    # --- EL CASO QUE JUSTIFICA RTR: reuso de un token ya rotado ---
    try:
        st2.rotar(r1)
        check("reusar un token rotado se detecta", False)
    except AuthError as e:
        check("reusar un token rotado se detecta", "reuso" in str(e))

    try:
        st2.rotar(r3)
        check("el reuso mata la familia entera", False)
    except AuthError:
        check("el reuso mata la familia entera", True)

    # ------------------------------------------------- expiracion y purga
    st3 = TokenStore()
    r = st3.emitir_refresco("denis")
    st3._refresh[r].expira = time.time() - 1  # noqa: SLF001
    try:
        st3.rotar(r)
        check("un refresco caducado se rechaza", False)
    except AuthError as e:
        check("un refresco caducado se rechaza", "expiro" in str(e))

    st3.purgar()
    check("la purga limpia lo caducado", r not in st3._refresh)  # noqa: SLF001

    try:
        st3.rotar("inventado")
        check("un refresco desconocido se rechaza", False)
    except AuthError:
        check("un refresco desconocido se rechaza", True)

    # --------------------------------------------- falla cerrado sin secreto
    guardado = os.environ.pop("ORACLE_JWT_SECRET")
    try:
        TokenStore().emitir_acceso("denis")
        check("sin secreto configurado NO arranca", False)
    except AuthMisconfigured as e:
        check("sin secreto configurado NO arranca", "por defecto" in str(e))
    os.environ["ORACLE_JWT_SECRET"] = guardado

    os.environ["ORACLE_JWT_SECRET"] = "corto"
    try:
        TokenStore().emitir_acceso("denis")
        check("un secreto corto se rechaza", False)
    except AuthMisconfigured:
        check("un secreto corto se rechaza", True)
    os.environ["ORACLE_JWT_SECRET"] = guardado

    # ------------------------------------------- otra clave no lee el token
    st4 = TokenStore()
    t4, _ = st4.emitir_acceso("denis")
    os.environ["ORACLE_JWT_SECRET"] = "y" * 48
    try:
        st4.leer_acceso(t4)
        check("un JWT firmado con otro secreto no valida", False)
    except AuthError:
        check("un JWT firmado con otro secreto no valida", True)
    os.environ["ORACLE_JWT_SECRET"] = guardado

    fallos = sum(1 for _, ok in res if not ok)
    for n, ok in res:
        print(f"  [{'OK' if ok else 'XX'}] {n}")
    print(f"\n{len(res) - fallos}/{len(res)} casos correctos.")
    return 1 if fallos else 0


if __name__ == "__main__":
    raise SystemExit(main())
