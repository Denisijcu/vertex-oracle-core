"""Autenticacion: JWT de acceso corto + rotacion de refresh tokens (RTR).

EL MODELO
---------
- ACCESO: JWT firmado, 15 minutos, viaja en la cabecera Authorization y vive
  SOLO en memoria del navegador. Nunca en localStorage: cualquier XSS lo leeria.
- REFRESCO: token opaco de 256 bits en cookie HttpOnly. El navegador no lo puede
  leer, solo reenviarlo. Se ROTA en cada uso: el viejo muere al nacer el nuevo.

DETECCION DE REUSO (lo que hace util a RTR)
-------------------------------------------
Los refresh tokens se agrupan en FAMILIAS. Si alguien presenta un token ya
rotado, solo hay dos explicaciones: o se lo robaron a el, o se lo robaron a
otro. En ambos casos hay un token circulando fuera de control, asi que se
revoca la FAMILIA ENTERA y ambas partes tienen que volver a autenticarse.

Sin esta deteccion, rotar es solo higiene. Con ella, un robo de cookie tiene
un plazo de vida que termina en cuanto el legitimo vuelve a refrescar.

FALLA CERRADO, COMO TODO LO DEMAS
----------------------------------
Sin ORACLE_JWT_SECRET en el entorno, el modulo se niega a arrancar. Un secreto
por defecto en el codigo es peor que no tener autenticacion: da la sensacion
de estar protegido.

ALCANCE HONESTO
---------------
Un solo operador, definido por variables de entorno. No hay base de datos de
usuarios ni roles. Los tokens viven en memoria: reiniciar el servidor cierra
todas las sesiones, lo cual es seguro aunque incomodo. Para varios operadores
o varias instancias, el punto de cambio son las clases de este archivo.
"""
from __future__ import annotations

import os
import secrets
import time
import uuid
from dataclasses import dataclass, field

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

ACCESO_S = 15 * 60             # 15 minutos
REFRESCO_S = 7 * 24 * 3600     # 7 dias
ALGO = "HS256"
COOKIE = "oracle_refresh"

_ph = PasswordHasher()


class AuthError(Exception):
    """Credenciales o token invalidos. El mensaje va al cliente tal cual."""


class AuthMisconfigured(RuntimeError):
    """Falta configuracion imprescindible. El servidor no debe arrancar."""


def _secreto() -> str:
    s = os.getenv("ORACLE_JWT_SECRET", "")
    if len(s) < 32:
        raise AuthMisconfigured(
            "Falta ORACLE_JWT_SECRET (minimo 32 caracteres) en el entorno o .env. "
            "Generalo con: python -c \"import secrets;print(secrets.token_urlsafe(48))\". "
            "No hay valor por defecto a proposito: un secreto conocido es peor "
            "que no tener autenticacion."
        )
    return s


def hash_password(clave: str) -> str:
    return _ph.hash(clave)


def _operador() -> tuple[str, str]:
    """(usuario, hash) del unico operador. El hash sale del entorno."""
    usuario = os.getenv("ORACLE_OPERATOR", "")
    hash_ = os.getenv("ORACLE_OPERATOR_HASH", "")
    if not usuario or not hash_:
        raise AuthMisconfigured(
            "Faltan ORACLE_OPERATOR y ORACLE_OPERATOR_HASH. Genera el hash con: "
            "python -m app.auth hash <tu-clave>"
        )
    return usuario, hash_


@dataclass
class _Refresh:
    familia: str
    usuario: str
    expira: float
    usado: bool = False


@dataclass
class TokenStore:
    """Refresh tokens y lista de bloqueo de jti. En memoria a proposito.

    Es la costura para Redis: cambiar estos tres diccionarios por claves con
    TTL es todo lo que hace falta para varias instancias.
    """

    _refresh: dict[str, _Refresh] = field(default_factory=dict)
    _familias_muertas: set[str] = field(default_factory=set)
    _jti_bloqueados: dict[str, float] = field(default_factory=dict)

    # -------------------------------------------------------------- acceso

    def emitir_acceso(self, usuario: str) -> tuple[str, str]:
        jti = uuid.uuid4().hex
        ahora = int(time.time())
        token = jwt.encode(
            {"sub": usuario, "jti": jti, "iat": ahora, "exp": ahora + ACCESO_S},
            _secreto(),
            algorithm=ALGO,
        )
        return token, jti

    def leer_acceso(self, token: str) -> dict:
        try:
            datos = jwt.decode(token, _secreto(), algorithms=[ALGO])
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("el token de acceso expiro") from exc
        except jwt.InvalidTokenError as exc:
            raise AuthError("token de acceso invalido") from exc
        if datos.get("jti") in self._jti_bloqueados:
            raise AuthError("ese token fue revocado")
        return datos

    def bloquear_jti(self, jti: str) -> None:
        self._jti_bloqueados[jti] = time.time() + ACCESO_S

    # ------------------------------------------------------------ refresco

    def emitir_refresco(self, usuario: str, familia: str | None = None) -> str:
        token = secrets.token_urlsafe(32)
        self._refresh[token] = _Refresh(
            familia=familia or uuid.uuid4().hex,
            usuario=usuario,
            expira=time.time() + REFRESCO_S,
        )
        return token

    def rotar(self, token: str) -> tuple[str, str]:
        """Canjea un refresh por uno nuevo. Devuelve (refresco, usuario).

        Si el token ya se habia usado, se revoca la familia completa.
        """
        r = self._refresh.get(token)
        if r is None:
            raise AuthError("token de refresco desconocido")
        if r.familia in self._familias_muertas:
            raise AuthError("esta sesion fue revocada")
        if r.expira < time.time():
            raise AuthError("el token de refresco expiro")

        if r.usado:
            # Reuso: hay una copia circulando. Se cae toda la familia.
            self.revocar_familia(r.familia)
            raise AuthError(
                "se detecto reuso de un token de refresco; la sesion completa "
                "fue revocada por seguridad"
            )

        r.usado = True
        return self.emitir_refresco(r.usuario, familia=r.familia), r.usuario

    def revocar_familia(self, familia: str) -> None:
        self._familias_muertas.add(familia)
        for tok in [t for t, r in self._refresh.items() if r.familia == familia]:
            self._refresh.pop(tok, None)

    def revocar_token(self, token: str) -> None:
        r = self._refresh.get(token)
        if r is not None:
            self.revocar_familia(r.familia)

    def purgar(self) -> None:
        """Limpia lo caducado. Barato y sin efectos sobre lo vigente."""
        ahora = time.time()
        for t in [t for t, r in self._refresh.items() if r.expira < ahora]:
            self._refresh.pop(t, None)
        for j in [j for j, e in self._jti_bloqueados.items() if e < ahora]:
            self._jti_bloqueados.pop(j, None)


def autenticar(usuario: str, clave: str) -> str:
    """Comprueba credenciales. Devuelve el usuario o lanza AuthError."""
    esperado, hash_ = _operador()
    # Se verifica el hash SIEMPRE, aunque el usuario no coincida: si no, el
    # tiempo de respuesta delata que ese usuario no existe.
    try:
        _ph.verify(hash_, clave)
        clave_ok = True
    except (VerificationError, Exception):  # noqa: BLE001
        clave_ok = False
    if not (secrets.compare_digest(usuario, esperado) and clave_ok):
        raise AuthError("usuario o clave incorrectos")
    return usuario


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3 and sys.argv[1] == "hash":
        print(hash_password(sys.argv[2]))
    else:
        print("Uso: python -m app.auth hash <clave>")
        print(f"\nSecreto sugerido para ORACLE_JWT_SECRET:\n{secrets.token_urlsafe(48)}")
