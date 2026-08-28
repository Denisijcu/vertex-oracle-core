"""Anclaje criptografico del ledger con ML-DSA-65 (FIPS 204, post-cuantico).

QUE PROBLEMA RESUELVE
---------------------
La cadena SHA-256 de ledger.py detecta que alguien EDITO una fila. No detecta
que alguien la reescribio ENTERA: un atacante con acceso al .db puede borrar
filas, cambiar payloads y recalcular todos los hashes desde ahi. El resultado
es una cadena internamente consistente y completamente falsa.

El hash chain prueba CONSISTENCIA. No prueba AUTORIA ni MOMENTO.

COMO
----
Cada N entradas (o al cerrar una mision) se firma la cabeza de la cadena con
una clave privada que NO vive junto al ledger. Un atacante que reescriba la
cadena no puede producir firmas validas para las cabezas nuevas: le faltaria
la clave.

Con eso, la verificacion pasa a responder tres preguntas:
  1. ¿La cadena es internamente consistente?        (ledger.verify)
  2. ¿Las cabezas ancladas siguen apareciendo?      (anclas presentes)
  3. ¿Las firmas de esas cabezas son validas?       (ML-DSA-65)

DONDE VIVE LA CLAVE
-------------------
La privada NUNCA en el repo ni junto al .db. En desarrollo, un archivo fuera
del arbol del proyecto; en produccion, un HSM o un KMS. La publica se
distribuye libremente: es lo que le das a un tercero para que verifique sin
confiar en ti.

POR QUE POST-CUANTICO
---------------------
Un ledger forense tiene que seguir siendo verificable dentro de diez o quince
anos. Una firma Ed25519 emitida hoy es repudiable el dia que exista una
computadora cuantica relevante. ML-DSA-65 es el estandar NIST (FIPS 204) para
ese horizonte.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from dilithium_py.ml_dsa import ML_DSA_65

ALGO = "ML-DSA-65"


class AnchorError(RuntimeError):
    """Problema con las claves o con un ancla."""


@dataclass(frozen=True)
class Anchor:
    seq: int              # ultima entrada del ledger cubierta por esta firma
    head: str             # hash de esa entrada
    ts: float
    signature: bytes
    algo: str = ALGO

    def message(self) -> bytes:
        """Lo que se firma. Incluye seq y ts para atar la firma a un momento."""
        return json.dumps(
            {"algo": self.algo, "seq": self.seq, "head": self.head, "ts": round(self.ts, 6)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


@dataclass
class VerificationReport:
    chain_ok: bool = False
    chain_broken_at: int | None = None
    anchors_total: int = 0
    anchors_valid: int = 0
    anchors_invalid: list[int] = None          # seq de las anclas que no validan
    missing_heads: list[int] = None            # anclas cuya entrada ya no existe
    unanchored_tail: int = 0                   # entradas despues del ultimo ancla

    def __post_init__(self) -> None:
        self.anchors_invalid = self.anchors_invalid or []
        self.missing_heads = self.missing_heads or []

    @property
    def trustworthy(self) -> bool:
        """Solo True si TODO cuadra. Un ledger sin anclas no es de fiar."""
        return (
            self.chain_ok
            and self.anchors_total > 0
            and not self.anchors_invalid
            and not self.missing_heads
        )

    def summary(self) -> str:
        if self.trustworthy:
            extra = f", {self.unanchored_tail} entradas sin anclar aun" if self.unanchored_tail else ""
            return f"VERIFICADO: cadena integra y {self.anchors_valid} anclas validas{extra}"
        motivos = []
        if not self.chain_ok:
            motivos.append(f"cadena rota en la entrada #{self.chain_broken_at}")
        if self.anchors_total == 0:
            motivos.append("no hay ninguna ancla firmada")
        if self.anchors_invalid:
            motivos.append(f"firmas invalidas en seq {self.anchors_invalid}")
        if self.missing_heads:
            motivos.append(f"anclas cuya entrada desaparecio: seq {self.missing_heads}")
        return "NO VERIFICADO: " + "; ".join(motivos)


def generate_keypair() -> tuple[bytes, bytes]:
    """Devuelve (publica, privada). La privada se guarda FUERA del proyecto."""
    return ML_DSA_65.keygen()


def save_key(path: str | Path, key: bytes) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(key)
    try:
        p.chmod(0o600)     # no-op en Windows, correcto en Linux
    except OSError:
        pass


def load_key(path: str | Path) -> bytes:
    p = Path(path)
    if not p.exists():
        raise AnchorError(f"no existe la clave en {p}")
    return p.read_bytes()


class AnchorStore:
    """Guarda las firmas en una tabla APARTE de la cadena.

    Va aparte a proposito: si las anclas vivieran dentro de la cadena, cada
    ancla cambiaria la cabeza que acaba de firmar.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._con = sqlite3.connect(str(db_path))
        self._con.execute(
            """CREATE TABLE IF NOT EXISTS anchors (
                   seq       INTEGER PRIMARY KEY,
                   head      TEXT NOT NULL,
                   ts        REAL NOT NULL,
                   algo      TEXT NOT NULL,
                   signature BLOB NOT NULL
               )"""
        )
        self._con.commit()

    def add(self, anchor: Anchor) -> None:
        self._con.execute(
            "INSERT OR REPLACE INTO anchors (seq, head, ts, algo, signature) VALUES (?,?,?,?,?)",
            (anchor.seq, anchor.head, anchor.ts, anchor.algo, anchor.signature),
        )
        self._con.commit()

    def all(self) -> list[Anchor]:
        return [
            Anchor(seq, head, ts, sig, algo)
            for seq, head, ts, algo, sig in self._con.execute(
                "SELECT seq, head, ts, algo, signature FROM anchors ORDER BY seq"
            )
        ]

    def last_seq(self) -> int:
        row = self._con.execute("SELECT MAX(seq) FROM anchors").fetchone()
        return row[0] or 0

    def close(self) -> None:
        self._con.close()


class Anchorer:
    """Firma cabezas de cadena y verifica ledgers completos."""

    def __init__(self, ledger, store: AnchorStore) -> None:
        self._ledger = ledger
        self._store = store

    def anchor_now(self, private_key: bytes) -> Anchor | None:
        """Firma la cabeza actual. Devuelve None si no hay nada nuevo."""
        import time

        entradas = list(self._ledger.entries())
        if not entradas:
            return None
        ultima = entradas[-1]
        if ultima.seq <= self._store.last_seq():
            return None

        a = Anchor(seq=ultima.seq, head=ultima.entry_hash, ts=time.time(), signature=b"")
        firma = ML_DSA_65.sign(private_key, a.message())
        anclada = Anchor(a.seq, a.head, a.ts, firma)
        self._store.add(anclada)
        return anclada

    def verify(self, public_key: bytes) -> VerificationReport:
        """Verificacion completa: cadena + presencia de cabezas + firmas."""
        rep = VerificationReport()
        rep.chain_ok, rep.chain_broken_at = self._ledger.verify()

        por_seq = {e.seq: e.entry_hash for e in self._ledger.entries()}
        anclas = self._store.all()
        rep.anchors_total = len(anclas)

        for a in anclas:
            real = por_seq.get(a.seq)
            if real is None or real != a.head:
                # La entrada que se firmo ya no esta, o su hash cambio.
                rep.missing_heads.append(a.seq)
                continue
            if ML_DSA_65.verify(public_key, a.message(), a.signature):
                rep.anchors_valid += 1
            else:
                rep.anchors_invalid.append(a.seq)

        ultimo = max((a.seq for a in anclas), default=0)
        rep.unanchored_tail = sum(1 for s in por_seq if s > ultimo)
        return rep
