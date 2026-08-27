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
| 2b | Sandbox de ejecución (gVisor/microVM) | ⬜ **siguiente** |
| 3 | Sentinel Auditor (modelo distinto) + AgentDojo | ⬜ |
| 4 | HITL: Redis Pub/Sub + WebSockets + Angular 22 | ⬜ |
| 5 | JWT/RTR, PostgreSQL 17, anclaje ML-DSA-65 del ledger | ⬜ |

### Suites verdes

| Suite | Casos | Costo |
|---|---|---|
| `test_planner.py` | 7/7 | gratis |
| `test_manifest.py` | 13/13 | gratis |
| `test_poisoning_live.py` | 4/4 | gratis |
| `spike.py` | smoke OK | gratis |
| `mission.py` | misión real OK | ~centavos de API |

## Arranque

```powershell
cd F:\vertex-oracle-core\backend
D:\python312\python.exe -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt

# Copiar .env.example a backend\.env y poner la llave real
.\.venv\Scripts\python test_planner.py    # validación offline, gratis
.\.venv\Scripts\python spike.py           # smoke test offline, gratis
.\.venv\Scripts\python mission.py "auditar el host 10.0.0.5"   # usa la API
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
  app/                 <- FastAPI (vacío todavía, Fase 4)
frontend/              <- Angular 22 (vacío todavía, Fase 4)
```

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
