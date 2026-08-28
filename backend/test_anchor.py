"""Pruebas del anclaje criptografico. Sin red, sin API.

La prueba central es el ESCENARIO DE REESCRITURA: un atacante con acceso al
.db borra una entrada y recalcula toda la cadena. El hash chain la da por
buena. La firma no.

Correr con:  python test_anchor.py
"""
from __future__ import annotations

import sqlite3
import tempfile
import time
from pathlib import Path

from oracle.anchor import (
    Anchor,
    AnchorStore,
    Anchorer,
    generate_keypair,
    load_key,
    save_key,
)
from oracle.ledger import Ledger, compute_hash


def _ledger_con_datos(p: Path, n: int = 6) -> Ledger:
    led = Ledger(p)
    for i in range(n):
        led.append("m1", "step.checkpoint", {"step": i, "result": f"dato-{i}"})
    return led


def _reescribir_cadena(db: Path, borrar_seq: int) -> None:
    """Simula al atacante: borra una entrada y RECALCULA toda la cadena.

    Esto es lo que hace un adversario competente. Una edicion tonta rompe la
    cadena; esta no.
    """
    con = sqlite3.connect(str(db))
    con.execute("DELETE FROM ledger WHERE seq = ?", (borrar_seq,))
    filas = con.execute(
        "SELECT seq, ts, mission_id, kind, payload FROM ledger ORDER BY seq"
    ).fetchall()
    import json as _j

    prev = "0" * 64
    for seq, ts, mid, kind, payload in filas:
        h = compute_hash(prev, ts, mid, kind, _j.loads(payload))
        con.execute("UPDATE ledger SET prev_hash=?, entry_hash=? WHERE seq=?", (prev, h, seq))
        prev = h
    con.commit()
    con.close()


def main() -> int:
    fallos = 0
    resultados: list[tuple[str, bool]] = []

    def check(nombre: str, ok: bool) -> None:
        nonlocal fallos
        resultados.append((nombre, ok))
        fallos += not ok

    # ---------------------------------------------------------------- claves
    pk, sk = generate_keypair()
    check("keygen produce par ML-DSA-65", len(pk) == 1952 and len(sk) == 4032)

    tmp = Path(tempfile.mkdtemp())
    save_key(tmp / "priv.key", sk)
    save_key(tmp / "pub.key", pk)
    check("las claves se guardan y releen", load_key(tmp / "priv.key") == sk)

    # --------------------------------------------------------- ledger limpio
    db = tmp / "l.db"
    led = _ledger_con_datos(db)
    store = AnchorStore(tmp / "anchors.db")
    anc = Anchorer(led, store)

    a = anc.anchor_now(sk)
    check("se ancla la cabeza actual", a is not None and a.seq == 6)
    check("no se re-ancla si no hay nada nuevo", anc.anchor_now(sk) is None)

    rep = anc.verify(pk)
    check("ledger limpio y anclado -> confiable", rep.trustworthy and rep.anchors_valid == 1)

    led.append("m1", "step.checkpoint", {"step": 99})
    rep = anc.verify(pk)
    check("entradas nuevas quedan como cola sin anclar",
          rep.trustworthy and rep.unanchored_tail == 1)

    # ------------------------------------------- EL ATAQUE: reescritura total
    db2 = tmp / "l2.db"
    led2 = _ledger_con_datos(db2)
    store2 = AnchorStore(tmp / "anchors2.db")
    anc2 = Anchorer(led2, store2)
    anc2.anchor_now(sk)
    led2.close()

    _reescribir_cadena(db2, borrar_seq=3)

    led3 = Ledger(db2)
    solo_hash, _ = led3.verify()
    check("SIN firma: la cadena reescrita pasa por buena", solo_hash is True)

    rep = Anchorer(led3, store2).verify(pk)
    check("CON firma: la reescritura se detecta", not rep.trustworthy)
    check("se identifica el ancla huerfana", rep.missing_heads == [6])

    # -------------------------------------------------- clave publica ajena
    pk_otro, _ = generate_keypair()
    rep = anc.verify(pk_otro)
    check("otra clave publica no valida las firmas",
          not rep.trustworthy and rep.anchors_invalid)

    # --------------------------------------------------- firma manipulada
    db4 = tmp / "l4.db"
    led4 = _ledger_con_datos(db4)
    store4 = AnchorStore(tmp / "anchors4.db")
    a4 = Anchorer(led4, store4).anchor_now(sk)
    rota = bytearray(a4.signature)
    rota[100] ^= 0xFF
    store4.add(Anchor(a4.seq, a4.head, a4.ts, bytes(rota)))
    rep = Anchorer(led4, store4).verify(pk)
    check("una firma alterada no valida", not rep.trustworthy and rep.anchors_invalid == [6])

    # ------------------------------------------ ts falsificado en el ancla
    db5 = tmp / "l5.db"
    led5 = _ledger_con_datos(db5)
    store5 = AnchorStore(tmp / "anchors5.db")
    a5 = Anchorer(led5, store5).anchor_now(sk)
    store5.add(Anchor(a5.seq, a5.head, a5.ts - 86400, a5.signature))
    rep = Anchorer(led5, store5).verify(pk)
    check("cambiar la fecha del ancla invalida la firma",
          not rep.trustworthy and rep.anchors_invalid == [6])

    # ------------------------------------------------------ sin anclas = no
    db6 = tmp / "l6.db"
    led6 = _ledger_con_datos(db6)
    rep = Anchorer(led6, AnchorStore(tmp / "anchors6.db")).verify(pk)
    check("un ledger sin anclar NO es confiable", not rep.trustworthy and rep.chain_ok)

    for nombre, ok in resultados:
        print(f"  [{'OK' if ok else 'XX'}] {nombre}")
    print(f"\n{len(resultados) - fallos}/{len(resultados)} casos correctos.")
    return 1 if fallos else 0


if __name__ == "__main__":
    raise SystemExit(main())
