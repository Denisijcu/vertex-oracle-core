// Consola de operador de Vertex Oracle Core.
// El token de acceso vive SOLO en esta variable: nunca en localStorage, que
// cualquier XSS podria leer. El de refresco viaja en cookie HttpOnly y el
// JavaScript no lo ve nunca.

let acceso = null;
let usuario = null;
let renovar = null;

async function api(ruta, opciones = {}, reintentar = true){
  const cab = { ...(opciones.headers || {}) };
  if (acceso) cab.Authorization = `Bearer ${acceso}`;
  if (opciones.body) cab["Content-Type"] = "application/json";
  const r = await fetch(ruta, { ...opciones, headers: cab });
  if (r.status === 401 && reintentar && await refrescar()){
    return api(ruta, opciones, false);
  }
  return r;
}

async function refrescar(){
  const r = await fetch("/api/auth/refresh", { method: "POST" });
  if (!r.ok){ cerrarSesion(); return false; }
  const d = await r.json();
  acceso = d.access_token; usuario = d.user;
  programarRenovacion(d.expires_in);
  return true;
}

function programarRenovacion(segundos){
  clearTimeout(renovar);
  // Se renueva un minuto antes de caducar, para no cortar nada a media accion.
  renovar = setTimeout(refrescar, Math.max(10, segundos - 60) * 1000);
}

function cerrarSesion(){
  acceso = null; usuario = null;
  clearTimeout(renovar);
  M.clear(); selected = null;
  $("app").hidden = true;
  $("entrar").hidden = false;
  $("clave").value = "";
}

const M = new Map();
let selected = null, pending = null;
const $ = id => document.getElementById(id);

const ETIQUETA = {
  "mission.start":"Misión iniciada", "tools.discovered":"Herramientas declaradas",
  "tools.findings":"Hallazgos en herramientas", "tools.repinned":"Herramientas re-aprobadas",
  "plan.locked":"Plan bloqueado", "plan.rejected":"Plan rechazado",
  "step.start":"Paso iniciado", "step.checkpoint":"Punto de control sellado",
  "step.error":"Error en el paso", "sentinel.verdict":"Veredicto del Sentinel",
  "hitl.requested":"Intervención solicitada", "hitl.decision":"Decisión del operador",
  "mission.halted":"Misión detenida", "mission.aborted":"Misión abortada",
  "mission.end":"Misión finalizada", "drift.detected":"Deriva de objetivo",
};

function esRuptura(e){
  if (["mission.halted","mission.aborted","plan.rejected","drift.detected"].includes(e.kind)) return true;
  return e.kind === "sentinel.verdict" && e.payload?.verdict === "reject";
}
function esEspera(e){
  return e.kind === "hitl.requested" ||
    (e.kind === "sentinel.verdict" && e.payload?.verdict === "escalate");
}

function pintarLista(){
  const box = $("list");
  if (!M.size){
    box.innerHTML = `<div class="empty"><b>Todavía no has lanzado nada</b>
      Escribe un objetivo arriba y pulsa Demo para ver el flujo completo.</div>`;
    return;
  }
  box.innerHTML = "";
  for (const m of [...M.values()].reverse()){
    const esperando = !!m.pending;
    const el = document.createElement("div");
    el.className = "mission";
    el.setAttribute("aria-current", String(m.id === selected));
    el.innerHTML = `<div class="row">
        <span class="eyebrow mono"></span>
        <span class="state ${esperando ? "espera" : m.status}">${esperando ? "tu turno" : m.status}</span>
      </div><h3></h3>`;
    el.querySelector(".eyebrow").textContent = m.id;
    el.querySelector("h3").textContent = m.objective;
    el.onclick = () => { selected = m.id; pintarLista(); pintarDetalle(); };
    box.appendChild(el);
  }
}

function pintarDetalle(){
  const box = $("detail");
  const m = M.get(selected);
  if (!m){
    box.innerHTML = `<div class="empty"><b>Nada seleccionado</b>
      Cada misión deja una cadena de entradas selladas. Elige una para leerla.</div>`;
    return;
  }
  if (!m.entries.length){
    box.innerHTML = `<div class="empty"><b>Sin entradas todavía</b>
      Las entradas aparecen aquí según se van sellando.</div>`;
    return;
  }
  const ul = document.createElement("ul");
  ul.className = "chain";
  for (const e of m.entries){
    const li = document.createElement("li");
    li.className = "link-row" + (esRuptura(e) ? " break" : esEspera(e) ? " hold" : "");
    const detalle = e.payload?.verdict || e.payload?.motivo || e.payload?.tool || "";
    li.innerHTML = `<div class="knot"><i></i><s></s></div>
      <div class="entry"><b></b><div class="digest"></div></div>`;
    li.querySelector("b").textContent =
      (ETIQUETA[e.kind] || e.kind) + (detalle ? ` — ${detalle}` : "");
    const d = li.querySelector(".digest");
    d.textContent = `#${e.seq} · `;
    const em = document.createElement("em");
    em.textContent = e.hash.slice(0, 32) + "…";
    d.appendChild(em);
    ul.appendChild(li);
  }
  box.innerHTML = "";
  box.appendChild(ul);
}

const TITULO = {
  sentinel_escalation: "El Sentinel no puede aprobar este resultado",
  tool_drift: "Una herramienta cambió después de ser aprobada",
};
const BOTON = { approve:"Aprobar", override:"Sustituir resultado",
                retry:"Reintentar el paso", abort:"Abortar misión" };

function preguntar(p){
  pending = p;
  $("askKind").textContent = p.kind.replace("_", " ");
  $("askH").textContent = TITULO[p.kind] || p.summary;
  const dl = $("askCtx"); dl.innerHTML = "";
  for (const [k, v] of Object.entries(p.context || {})){
    const dt = document.createElement("dt"); dt.textContent = k;
    const dd = document.createElement("dd"); dd.textContent = String(v);
    dl.append(dt, dd);
  }
  const acts = $("acts"); acts.innerHTML = "";
  for (const op of p.options){
    const b = document.createElement("button");
    b.dataset.a = op; b.textContent = BOTON[op] || op;
    b.onclick = () => responder(op);
    acts.appendChild(b);
  }
  $("why").value = "";
  $("veil").hidden = false;
  $("why").focus();
}

async function responder(action){
  const body = { mission: pending.mission, action, operator: "operador",
                 reason: $("why").value.trim() };
  $("veil").hidden = true;
  pending = null;
  await api("/api/decisions", {method:"POST", body: JSON.stringify(body)});
}

function conectar(){
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(
    `${proto}://${location.host}/ws/operator?token=${encodeURIComponent(acceso)}`);
  ws.onopen = () => { $("dot").classList.add("on"); $("linkTxt").textContent = "en línea"; };
  ws.onclose = ev => {
    $("dot").classList.remove("on");
    if (ev.code === 4401){ cerrarSesion(); return; }
    $("linkTxt").textContent = "sin conexión · reintentando";
    if (acceso) setTimeout(conectar, 1800);
  };
  ws.onmessage = ev => {
    const { kind, data } = JSON.parse(ev.data);
    if (kind === "snapshot"){
      M.clear();
      data.missions.forEach(m => M.set(m.id, m));
      if (!selected && data.missions.length) selected = data.missions.at(-1).id;
    }
    if (kind === "mission.started"){
      M.set(data.mission, {id:data.mission, objective:data.objective,
                           status:"corriendo", entries:[], steps:[], pending:null});
      selected = data.mission;
    }
    if (kind === "ledger.entry") M.get(data.mission)?.entries.push(data.entry);
    if (kind === "mission.ended"){
      const m = M.get(data.mission);
      if (m){ m.status = data.status; m.pending = null; }
    }
    if (kind === "hitl.requested"){
      const m = M.get(data.mission);
      if (m) m.pending = data;
      preguntar(data);
    }
    if (kind === "hitl.resolved"){
      const m = M.get(data.mission);
      if (m) m.pending = null;
      $("veil").hidden = true;
    }
    pintarLista(); pintarDetalle();
  };
}

async function lanzar(demo){
  const objective = $("obj").value.trim() || "Audita el host 10.0.0.5";
  const r = await api("/api/missions", {method:"POST",
    body: JSON.stringify({objective, demo})});
  if (!r.ok) alert((await r.json()).detail || "No se pudo lanzar la misión");
}
$("demo").onclick = () => lanzar(true);
$("real").onclick = () => lanzar(false);
$("obj").onkeydown = e => { if (e.key === "Enter") lanzar(true); };

// ------------------------------------------------------------ sesión

async function entrar(){
  $("errLogin").textContent = "";
  const r = await fetch("/api/auth/login", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ username: $("usuario").value.trim(),
                           password: $("clave").value })});
  if (!r.ok){
    $("errLogin").textContent = (await r.json()).detail || "No se pudo entrar";
    $("clave").value = "";
    return;
  }
  const d = await r.json();
  acceso = d.access_token; usuario = d.user;
  programarRenovacion(d.expires_in);
  abrirConsola();
}

function abrirConsola(){
  $("entrar").hidden = true;
  $("app").hidden = false;
  $("quien").textContent = usuario;
  pintarLista(); pintarDetalle(); conectar();
}

$("btnEntrar").onclick = entrar;
$("clave").onkeydown = e => { if (e.key === "Enter") entrar(); };
$("usuario").onkeydown = e => { if (e.key === "Enter") $("clave").focus(); };
$("salir").onclick = async () => {
  await api("/api/auth/logout", {method:"POST"}, false);
  cerrarSesion();
};

// Si queda una cookie de refresco viva, se entra sin pedir credenciales.
refrescar().then(ok => { if (ok) abrirConsola(); else $("usuario").focus(); });
