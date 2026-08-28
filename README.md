# Vertex Oracle Core

Orquestador de agentes de IA de **autonomía prolongada** (*long-horizon agents*)
bajo arquitectura Zero-Trust, enfocado en seguridad ofensiva y defensiva.

Ejecuta misiones complejas de múltiples pasos de forma desatendida, atacando
tres problemas concretos:

1. **Goal drift** — el agente se olvida del objetivo a mitad de camino.
2. **Ejecución insegura** — herramientas corriendo sin aislamiento en el host.
3. **Falta de trazabilidad** — no hay forma de probar qué pasó ni de detectar
   si el registro fue alterado.

## Estado

| Fase | Alcance | Estado |
|---|---|---|
| 0 | Esqueleto: MCP stdio, descubrimiento de tools, reintentos, ledger SHA-256 | ✅ verificada |
| 1 | Planner LLM, plan como contrato validado, plan bloqueado | ✅ verificada |
| 2a | Tool poisoning: pinning SHA-256 + escaneo de descripciones | ✅ verificada |
| 2b | Sandbox gVisor: módulo + infraestructura WSL2 | ✅ verificada |
| 3 | Sentinel Auditor: auditoría de salidas, dos capas | ✅ verificada |
| 4 | HITL: política de fallo cerrado, re-fijado con aprobación humana | ✅ verificada |
| 5a | Anclaje ML-DSA-65 del ledger (FIPS 204, post-cuántico) | ✅ verificada |
| 5b | JWT/RTR + PostgreSQL 17 | ⬜ depende del transporte |
| — | Transporte HITL: Redis Pub/Sub + WebSocket + Angular 22 | ⬜ |
| — | Cableado del sandbox al camino de ejecución | ⬜ **pendiente clave** |

### Suites verdes

| Suite | Casos | Costo |
|---|---|---|
| `test_planner.py` | 7/7 | gratis |
| `test_manifest.py` | 13/13 | gratis |
| `test_poisoning_live.py` | 4/4 | gratis |
| `test_sandbox.py` | 20/20 | gratis (4 requieren gVisor) |
| `test_sentinel.py` | 23/23 | gratis |
| `test_sentinel_live.py` | 3/3 | gratis |
| `test_hitl.py` | 12/12 | gratis |
| `test_anchor.py` | 13/13 | gratis |
| `spike.py` | smoke OK | gratis |
| `mission.py` | misión real OK | ~centavos de API |

## Arranque

```bash
cd backend
python -m venv .venv          # Python 3.12
.venv/bin/pip install -r requirements.txt      # Windows: .venv\Scripts\pip

# Copiar .env.example a backend/.env y poner la llave real
python test_planner.py          # validacion offline, gratis
python test_manifest.py         # defensa anti-poisoning, gratis
python test_poisoning_live.py   # escenarios vivos, gratis
python spike.py                 # smoke test offline, gratis
python mission.py "auditar el host 10.0.0.5"   # usa la API
```

## Estructura

```
backend/
  mission.py           <- CLI: objetivo en lenguaje natural -> misión ejecutada
  spike.py             <- smoke test offline (plan fijo, sin API)
  test_planner.py      <- 7 casos de validación de la barrera del plan
  oracle/
    plan.py            <- el plan como contrato (Pydantic + JSON Schema)
    planner.py         <- ClaudePlanner (API) y StubPlanner (tests)
    runner.py          <- plan bloqueado -> Worker -> checkpoints
    ledger.py          <- cadena SHA-256 sobre SQLite
  tools_server/
    echo_server.py     <- servidor MCP de prueba (3 tools)
    poisoned_server.py <- FIXTURE DE PRUEBA: servidor malicioso (ver aviso abajo)
  app/                 <- FastAPI (vacío todavía, Fase 4)
frontend/              <- Angular 22 (vacío todavía, Fase 4)
```

## ⚠️ Aviso sobre `tools_server/poisoned_server.py`

Este repositorio contiene un servidor MCP **deliberadamente malicioso** como
fixture de prueba. Existe con un único fin: demostrar que las defensas de
`oracle/manifest.py` lo detectan y abortan la misión antes de que el Planner
lea sus descripciones.

No es código de ataque destinado a usarse contra terceros, y sus payloads son
ejemplos públicos y ampliamente documentados de tool poisoning en MCP. No
contiene técnicas novedosas.

**No usarlo como base de ningún servidor real. No desplegarlo.**

## Decisiones de arquitectura

**El estado de la misión vive en Oracle Core, no en la capa MCP.**
La extensión Tasks del protocolo (`tasks/get`, `tasks/update`, `tasks/cancel`)
está en la spec 2026-07-28 pero todavía no implementada en el SDK de Python.
Cuando salga, `oracle/runner.py` es el único módulo que cambia.

**El plan es un contrato, no texto.** La salida del Planner se valida con
Pydantic v2 y contra el JSON Schema real de cada tool. Un plan que use una tool
inexistente o argumentos mal tipados se rechaza y se le devuelve el error
concreto al modelo para que reintente.

**Plan-before-act.** Una vez bloqueado, el Worker no renegocia el plan: no
puede agregar pasos ni cambiar la tool de un paso. Ahí se corta el drift.

**El Sentinel debe usar un modelo distinto al del Worker.** La autoevaluación
de un solo modelo no es confiable como detector de drift.

**El escaneo de descripciones es un cable trampa, no una garantía.** Son
heurísticas evadibles por quien conozca los patrones. La defensa fuerte es el
pinning criptográfico más aprobación humana de tools nuevas (Fase 4).

**Un servidor que llega envenenado nunca se fija.** Fijarlo legitimaría el
ataque en el primer contacto.

**El HITL falla cerrado.** Sin operador, o sin respuesta a tiempo, la misión
se aborta. Nunca se auto-aprueba. Y lo indefendible —inyección declarada, o un
veredicto `reject` del Sentinel— no llega al operador: si todo fuera aprobable,
el humano se convierte en el eslabón que el atacante ataca.

**El hash chain prueba consistencia, no autoría.** Un atacante con acceso al
`.db` puede borrar filas y recalcular toda la cadena; el resultado es
internamente consistente y falso. Por eso las cabezas se firman con ML-DSA-65:
sin la clave privada no se puede anclar una cadena reescrita. La clave pública
se distribuye, y con ella un tercero verifica el ledger sin confiar en
nosotros.
