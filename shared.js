/* ════════════════════════════════════════════════════════════
   C.I.U. — SHARED CORE
   Firebase, session, permissions, topbar/settings injection.
   Chaque page inclut ce fichier puis appelle CIU.init({page:'...'})
════════════════════════════════════════════════════════════ */
const CIU = (function(){

const firebaseConfig = {
  apiKey: "AIzaSyDjFtSaDCRnBh2rqQezLOAFyvBA6aV2Mds",
  authDomain: "ciu-portal.firebaseapp.com",
  projectId: "ciu-portal",
  storageBucket: "ciu-portal.firebasestorage.app",
  messagingSenderId: "1072590977967",
  appId: "1:1072590977967:web:4d1b0b8b3a6bdcfb208d5a"
};

const SSK='ciu_sess_v2', SESS_MS=15*60*1000;
const ROOT='jamesjones.lspd@gmail.com';
const DEV_EMAIL='john.anderson.ctg@gmail.com';
const PROTECTED_EMAILS=[ROOT, DEV_EMAIL];
const DEF_PW='lspd-dd-2026';

let fdb, COL, fauth;
let DB = { users:{}, effectif:[], online:{}, manuels:[], penalCode:[], warrants:[], bracelets:[], events:[], service:[], grades:[], roleNames:{}, charte:[], modules:null, missions:null, calCategories:null, fpConfig:null, effectifInfobox:'' };
let currentEmail=null, currentUser=null, userRole='agent';
let ready=false;

// ── Session ──────────────────────────────────────────────
const loadSess=()=>{try{const r=localStorage.getItem(SSK);if(!r)return null;const s=JSON.parse(r);return Date.now()-s.ts<SESS_MS?s:null;}catch{return null;}};
const saveSess=e=>localStorage.setItem(SSK,JSON.stringify({email:e,ts:Date.now()}));
const clearSess=()=>localStorage.removeItem(SSK);
function touchSess(){ if(currentEmail) saveSess(currentEmail); }

// ── Hash / verify ────────────────────────────────────────
async function sha256(str){
  const buf=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}
async function verifyPw(input,stored){
  if(!stored||!input)return false;
  if(stored.length===64&&/^[0-9a-f]+$/.test(stored)) return (await sha256(input))===stored;
  return input===stored;
}
async function hashPw(pw){return sha256(pw);}

// ── Permissions ──────────────────────────────────────────
const isDirection=()=>userRole==='direction';
const isResp=()=>userRole==='direction'||userRole==='responsable';
const isDev=()=>currentEmail===DEV_EMAIL||currentEmail===ROOT;
const isProtected=(e)=>PROTECTED_EMAILS.includes(e);
const isProcureur=()=>userRole==='procureur';
const canEditEffectif=()=>isDirection()||isDev();

function roleName(r){
  if(!DB.roleNames) return _defaultRoleName(r);
  return DB.roleNames[r]||_defaultRoleName(r);
}
function _defaultRoleName(r){
  return r==='direction'?'Direction':r==='responsable'?'Responsable':r==='procureur'?'Bureau du Procureur':'Agent';
}

// ── Firestore helpers ────────────────────────────────────
async function fsSet(col,id,data){ await COL[col].doc(id).set(data); }
async function fsUpdate(col,id,data){ await COL[col].doc(id).update(data); }
async function fsAdd(col,data){ return await COL[col].add(data); }
async function fsDelete(col,id){ await COL[col].doc(id).delete(); }
async function fsGet(col,id){ const d=await COL[col].doc(id).get(); return d.exists?{id:d.id,...d.data()}:null; }

async function saveConfig(){
  await fsSet('config','main',{
    users: DB.users, effectif: DB.effectif, online: DB.online||{},
    manuels: DB.manuels||[], penalCode: DB.penalCode||[], modules: DB.modules||[],
    missions: DB.missions||[], calCategories: DB.calCategories||[],
    fpConfig: DB.fpConfig||null, effectifInfobox: DB.effectifInfobox||'',
    grades: DB.grades||[], roleNames: DB.roleNames||{}, charte: DB.charte||[]
  });
}

function initFirebase(){
  if(typeof firebase==='undefined') return false;
  try{
    if(!firebase.apps.length) firebase.initializeApp(firebaseConfig);
    fdb=firebase.firestore();
    fauth=firebase.auth();
    fauth.setPersistence(firebase.auth.Auth.Persistence.LOCAL).catch(()=>{});
    COL={
      config:fdb.collection('config'),warrants:fdb.collection('warrants'),
      bracelets:fdb.collection('bracelets'),events:fdb.collection('events'),
      service:fdb.collection('service'),notes:fdb.collection('notes')
    };
    return true;
  }catch(e){ console.error('Firebase init error:',e); return false; }
}

// ── Charge la config + collections depuis Firestore ──────
async function loadAll(){
  const snap = await COL.config.doc('main').get();
  if(snap.exists){
    const d=snap.data();
    DB.users=d.users||{}; DB.effectif=d.effectif||[]; DB.manuels=d.manuels||[];
    DB.penalCode=d.penalCode||[]; DB.online=d.online||{};
    DB.modules=d.modules||null; DB.missions=d.missions||null;
    DB.calCategories=d.calCategories||null; DB.fpConfig=d.fpConfig||null;
    DB.effectifInfobox=d.effectifInfobox||''; DB.grades=d.grades||[];
    DB.roleNames=d.roleNames||{}; DB.charte=d.charte||[];
  }
  try{
    const [wSnap,bSnap,eSnap,sSnap] = await Promise.all([
      COL.warrants.get(), COL.bracelets.get(), COL.events.get(), COL.service.get()
    ]);
    DB.warrants  = wSnap.docs.map(d=>({_id:d.id,...d.data()}));
    DB.bracelets = bSnap.docs.map(d=>({_id:d.id,...d.data()}));
    DB.events    = eSnap.docs.map(d=>({_id:d.id,...d.data()}));
    DB.events.sort((a,b)=>(a.date||'').localeCompare(b.date||''));
    DB.service   = sSnap.docs.map(d=>({_id:d.id,...d.data()}));
    DB.service.sort((a,b)=>(b.ts||0)-(a.ts||0));
  }catch(e){ console.warn('Collections protégées non chargées (règles Firestore)'); }
  ready=true;
}

async function resolveUserFromEmail(email){
  const u = DB.users[email] || {name: email.split('@')[0], role:'agent'};
  currentEmail=email; currentUser=u.name; userRole=u.role||'agent';
  if(PROTECTED_EMAILS.includes(email)) userRole='direction';
  if(DB.online) DB.online[email]={name:currentUser,since:new Date().toISOString()};
  saveConfig().catch(()=>{});
}

// ════════════════════════════════════════════════════════
// TOPBAR + SETTINGS MENU INJECTION
// ════════════════════════════════════════════════════════
const NAV_LINKS = [
  {href:'accueil.html', label:'Accueil'},
  {href:'registre.html', label:'Registre'},
  {href:'calendrier.html', label:'Calendrier'},
  {href:'penal.html', label:'Code Pénal'},
  {href:'mandats.html', label:'Mandats'},
  {href:'bracelets.html', label:'Bracelets'},
  {href:'charte.html', label:'Charte'},
  {href:'manuels.html', label:'Manuels'},
];

function injectTopbar(opts){
  const page = (opts&&opts.page)||'';
  const navHtml = NAV_LINKS.map(l=>`<a class="tb-link${l.href===page?' active':''}" href="${l.href}">${l.label}</a>`).join('');
  const bar = document.createElement('div');
  bar.id='ciu-topbar';
  bar.innerHTML = `
    <a class="tb-brand" href="accueil.html">
      <img src="ciu_logo.png" alt="CIU" onerror="this.style.display='none'">
      <span class="tb-brand-text"><span class="tb-org">L.S.P.D.</span><span class="tb-unit">Criminal Investigation Union</span></span>
    </a>
    <nav>${navHtml}</nav>
    <button class="tb-burger" id="tb-burger-btn">☰</button>
    <div class="tb-actions">
      <a class="tb-btn tb-btn-home" href="accueil.html">⌂ Accueil</a>
      <button class="tb-btn" id="tb-settings-btn">⚙ Paramètres</button>
    </div>`;
  document.body.prepend(bar);

  const mobileNav = document.createElement('div');
  mobileNav.id='mobile-nav';
  mobileNav.innerHTML = NAV_LINKS.map(l=>`<a class="tb-link${l.href===page?' active':''}" href="${l.href}">${l.label}</a>`).join('');
  document.body.appendChild(mobileNav);
  document.getElementById('tb-burger-btn').onclick=()=>mobileNav.classList.toggle('open');

  injectSettingsMenu();
}

function injectSettingsMenu(){
  const overlay = document.createElement('div');
  overlay.id='settings-overlay';
  overlay.innerHTML = `
    <div id="settings-panel">
      <div class="settings-head"><span>⚙ Paramètres</span><button class="ciu-modal-close" id="settings-close" style="background:none;border:none;color:var(--tan);cursor:pointer;">✕</button></div>
      <div class="settings-user">
        <div class="name" id="settings-username">—</div>
        <div class="role" id="settings-userrole">—</div>
      </div>
      <div class="settings-list" id="settings-list"></div>
    </div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click',e=>{ if(e.target===overlay) overlay.classList.remove('open'); });
  document.getElementById('settings-close').onclick=()=>overlay.classList.remove('open');
  document.getElementById('tb-settings-btn').onclick=()=>{
    populateSettingsMenu();
    overlay.classList.add('open');
  };
}

function populateSettingsMenu(){
  document.getElementById('settings-username').textContent = currentUser||'—';
  document.getElementById('settings-userrole').textContent = roleName(userRole);
  const items = [];
  items.push({ic:'🔑',label:'Changer mon mot de passe',href:'parametres.html#mdp'});
  if(isResp() && !isProcureur()) items.push({ic:'🕐',label:'Temps de service',href:'service.html'});
  if(isDirection()||isDev()) items.push({ic:'🛡',label:'Panneau Direction',href:'admin.html'});
  items.push({sep:true});
  items.push({ic:'⏻',label:'Déconnexion',action:'logout',danger:true});
  const list = document.getElementById('settings-list');
  list.innerHTML = items.map(it=>{
    if(it.sep) return '<div class="settings-sep"></div>';
    const cls = it.danger?'settings-item danger':'settings-item';
    if(it.href) return `<a class="${cls}" href="${it.href}"><span class="ic">${it.ic}</span>${it.label}</a>`;
    return `<button class="${cls}" data-action="${it.action}"><span class="ic">${it.ic}</span>${it.label}</button>`;
  }).join('');
  const logoutBtn = list.querySelector('[data-action="logout"]');
  if(logoutBtn) logoutBtn.onclick=logout;
}

async function logout(){
  if(currentEmail && DB.online && DB.online[currentEmail]){
    delete DB.online[currentEmail];
    await saveConfig().catch(()=>{});
  }
  clearSess();
  if(fauth) fauth.signOut().catch(()=>{});
  window.location.href='index.html';
}

// ════════════════════════════════════════════════════════
// INIT — appelé par chaque page protégée
// ════════════════════════════════════════════════════════
async function init(opts){
  opts = opts||{};
  if(!initFirebase()){
    alert('⚠️ Firebase non chargé. Vérifiez la connexion internet.');
    return false;
  }
  await loadAll();

  // Vérifier la session
  const sess = loadSess();
  let emailToUse = null;

  if(sess){ emailToUse = sess.email; }
  else if(fauth && fauth.currentUser){ emailToUse = fauth.currentUser.email; }

  if(!emailToUse){
    if(opts.requireAuth!==false){ window.location.href='index.html'; }
    return false;
  }

  await resolveUserFromEmail(emailToUse);
  touchSess();

  injectTopbar(opts);

  // Timer d'inactivité
  ['click','keydown','scroll'].forEach(ev=>document.addEventListener(ev,touchSess,{passive:true}));
  setInterval(()=>{
    const s=loadSess();
    if(!s){ logout(); }
  },30000);

  return true;
}

return {
  init, DB:()=>DB, get currentEmail(){return currentEmail;}, get currentUser(){return currentUser;}, get userRole(){return userRole;},
  isDirection, isResp, isDev, isProtected, isProcureur, canEditEffectif, roleName,
  fsSet, fsUpdate, fsAdd, fsDelete, fsGet, saveConfig,
  hashPw, verifyPw, sha256,
  get COL(){return COL;}, get fdb(){return fdb;}, get fauth(){return fauth;},
  ROOT, DEV_EMAIL, PROTECTED_EMAILS, DEF_PW,
  logout, loadAll, resolveUserFromEmail,
  loadSess, saveSess, clearSess
};
})();
