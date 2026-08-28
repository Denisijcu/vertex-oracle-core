"""Herramienta de operador para el anclaje del ledger.

  python anchor_tool.py keygen  <dir>      Genera el par de claves
  python anchor_tool.py sign    <dir>      Firma la cabeza actual del ledger
  python anchor_tool.py verify  <dir>      Verifica cadena + firmas

<dir> es donde viven las claves. Ponlo FUERA del arbol del proyecto:
la privada nunca debe quedar cerca del .db ni del repositorio.

  python anchor_tool.py keygen C:\\claves\\oracle
"""
from __future__ import annotations

import sys
from pathlib import Path

from oracle.anchor import AnchorStore, Anchorer, generate_keypair, load_key, save_key
from oracle.ledger import Ledger

AQUI = Path(__file__).parent
LEDGER_DB = AQUI / "oracle_ledger.db"
ANCHOR_DB = AQUI / "oracle_anchors.db"


def _abrir(keydir: Path):
    if not LEDGER_DB.exists():
        print(f"No hay ledger en {LEDGER_DB}. Corre una mision primero.")
        raise SystemExit(2)
    return Ledger(LEDGER_DB), AnchorStore(ANCHOR_DB)


def cmd_keygen(keydir: Path) -> int:
    priv, pub = keydir / "oracle_anchor.key", keydir / "oracle_anchor.pub"
    if priv.exists():
        print(f"Ya existe {priv}. No la sobrescribo: perderias la capacidad de")
        print("verificar todas las firmas anteriores. Borrala a mano si es lo que quieres.")
        return 2
    pk, sk = generate_keypair()
    save_key(priv, sk)
    save_key(pub, pk)
    print(f"Clave privada : {priv}   ({len(sk)} bytes)  <- NUNCA la compartas ni la subas")
    print(f"Clave publica : {pub}   ({len(pk)} bytes)  <- esta si se distribuye")
    print("\nLa publica es lo que le entregas a un tercero para que verifique")
    print("el ledger sin tener que confiar en ti.")
    return 0


def cmd_sign(keydir: Path) -> int:
    led, store = _abrir(keydir)
    sk = load_key(keydir / "oracle_anchor.key")
    a = Anchorer(led, store).anchor_now(sk)
    if a is None:
        print("No hay entradas nuevas desde el ultimo anclaje. Nada que firmar.")
        return 0
    print(f"Anclada la entrada #{a.seq}")
    print(f"  cabeza : {a.head}")
    print(f"  algo   : {a.algo}   firma de {len(a.signature)} bytes")
    return 0


def cmd_verify(keydir: Path) -> int:
    led, store = _abrir(keydir)
    pk = load_key(keydir / "oracle_anchor.pub")
    rep = Anchorer(led, store).verify(pk)

    print(f"  cadena interna    : {'integra' if rep.chain_ok else f'ROTA en #{rep.chain_broken_at}'}")
    print(f"  anclas totales    : {rep.anchors_total}")
    print(f"  firmas validas    : {rep.anchors_valid}")
    if rep.anchors_invalid:
        print(f"  firmas INVALIDAS  : {rep.anchors_invalid}")
    if rep.missing_heads:
        print(f"  anclas huerfanas  : {rep.missing_heads}  <- la entrada firmada desaparecio")
    if rep.unanchored_tail:
        print(f"  cola sin anclar   : {rep.unanchored_tail} entradas")
    print(f"\n{rep.summary()}")
    return 0 if rep.trustworthy else 1


def main(argv: list[str]) -> int:
    if len(argv) < 3 or argv[1] not in ("keygen", "sign", "verify"):
        print(__doc__)
        return 2
    keydir = Path(argv[2]).expanduser()
    return {"keygen": cmd_keygen, "sign": cmd_sign, "verify": cmd_verify}[argv[1]](keydir)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
