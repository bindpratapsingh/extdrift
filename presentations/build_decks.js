// Builds two .pptx decks for extdrift: mid-semester (progress) and end-semester (final).
// Sober navy/formal academic style. Run: node presentations/build_decks.js
const pptxgen = require("pptxgenjs");

const C = {
  navy:  "16294D", navy2: "24365C", ink: "1E2733", muted: "5C6B7A",
  line:  "D8DEE6", paper: "FFFFFF", cloud: "F4F6F9",
  red:   "B3202C", redSoft: "F4DEDF", teal: "1F7A73", tealSoft: "DCEAE8",
  onNavy:"E9EEF6", onNavyMut:"AEBBD0",
};
const BODY = "Calibri", SERIF = "Cambria";
const W = 13.33, H = 7.5, MX = 0.62;

// ---- helpers ---------------------------------------------------------------
function dark(p){ const s=p.addSlide(); s.background={color:C.navy}; return s; }
function light(p){ const s=p.addSlide(); s.background={color:C.paper}; return s; }

function kicker(s, t){ s.addText(String(t).toUpperCase(), {x:MX,y:0.42,w:12,h:0.3,
  fontFace:BODY,fontSize:12,bold:true,color:C.red,charSpacing:2,isTextBox:true,margin:0}); }
function head(s, t){ s.addText(t, {x:MX,y:0.72,w:12.1,h:0.85,fontFace:BODY,fontSize:31,
  bold:true,color:C.navy,align:"left",valign:"top",isTextBox:true,margin:0}); }
function pageno(s,n){ s.addText(String(n),{x:12.7,y:7.02,w:0.5,h:0.3,fontFace:BODY,
  fontSize:10,color:C.muted,align:"right",isTextBox:true,margin:0}); }
function foot(s,t){ s.addText(t,{x:MX,y:7.02,w:11,h:0.3,fontFace:BODY,fontSize:10,
  color:C.muted,align:"left",isTextBox:true,margin:0}); }

function bullets(s, items, x, y, w, h, fs){
  s.addText(items.map((it,i)=>{
    const o = typeof it==="object" ? it : {text:it};
    return {text:o.text, options:{bullet:{indent:16}, breakLine:true, paraSpaceAfter:9,
      fontSize:o.fs||fs||15.5, bold:!!o.b, color:o.c||C.ink, indentLevel:o.lvl||0}};
  }), {x,y,w,h,fontFace:BODY,isTextBox:true,valign:"top",margin:0,lineSpacingMultiple:1.02});
}
function panel(s,x,y,w,h,fill){ s.addShape("roundRect",{x,y,w,h,fill:{color:fill||C.cloud},
  line:{color:C.line,width:1},rectRadius:0.07}); }
function stat(s,x,y,w,num,label,accent,h){
  h=h||1.9; panel(s,x,y,w,h,C.cloud);
  s.addText(num,{x:x+0.12,y:y+0.16,w:w-0.24,h:h*0.5,fontFace:BODY,fontSize:38,bold:true,
    color:accent||C.navy,align:"center",valign:"middle",isTextBox:true,margin:0});
  s.addText(label,{x:x+0.16,y:y+h*0.62,w:w-0.32,h:h*0.34,fontFace:BODY,fontSize:12.5,
    color:C.muted,align:"center",valign:"top",isTextBox:true,margin:0});
}
function pipeBox(s,x,y,w,h,t,fill,tc){ s.addShape("roundRect",{x,y,w,h,fill:{color:fill},
  line:{type:"none"},rectRadius:0.06});
  s.addText(t,{x:x+0.04,y,w:w-0.08,h,fontFace:BODY,fontSize:11.5,bold:true,color:tc,
    align:"center",valign:"middle",isTextBox:true,margin:0}); }
function arrow(s,x,y,w){ s.addShape("line",{x,y,w,h:0,line:{color:C.muted,width:1.5,
  endArrowType:"triangle"}}); }
function chip(s,x,y,w,h,t,fill,tc){ s.addShape("roundRect",{x,y,w,h,fill:{color:fill},
  line:{type:"none"},rectRadius:0.5});
  s.addText(t,{x,y,w,h,fontFace:BODY,fontSize:11,bold:true,color:tc,align:"center",
    valign:"middle",isTextBox:true,margin:0}); }

function table(s, rows, x, y, w, colW){
  s.addTable(rows, {x,y,w,colW,border:{type:"solid",color:C.line,pt:0.75},
    fontFace:BODY,fontSize:12.5,color:C.ink,valign:"middle",autoPage:false,rowH:0.42});
}
function th(t){ return {text:t,options:{bold:true,color:C.paper,fill:{color:C.navy},
  fontSize:12.5,align:"left",margin:[2,6,2,6]}}; }
function td(t,opt){ return {text:t,options:Object.assign({align:"left",margin:[2,6,2,6],
  color:C.ink},opt||{})}; }

// title / section / closing -------------------------------------------------
function titleSlide(p, sub){
  const s=dark(p);
  s.addText("extdrift",{x:MX,y:2.05,w:12,h:1.1,fontFace:SERIF,fontSize:60,bold:true,
    color:C.paper,isTextBox:true,margin:0});
  s.addText("Detecting Malicious Browser-Extension Updates by Behavioural Differencing",
    {x:MX,y:3.15,w:11.5,h:0.7,fontFace:BODY,fontSize:20,color:C.onNavy,isTextBox:true,margin:0});
  s.addText(sub.toUpperCase(),{x:MX,y:4.05,w:11,h:0.4,fontFace:BODY,fontSize:15,bold:true,
    color:C.red,charSpacing:2,isTextBox:true,margin:0});
  s.addText([
    {text:"Bind Pratap Singh  ·  Suhani Deepak Agrawat",options:{breakLine:true,fontSize:14,color:C.onNavy}},
    {text:"Advisor: Dr. Sweta Mishra",options:{breakLine:true,fontSize:13,color:C.onNavyMut}},
    {text:"CSD493 Project  ·  B.Tech CSE  ·  Shiv Nadar Institution of Eminence",options:{fontSize:12,color:C.onNavyMut}},
  ],{x:MX,y:5.55,w:11,h:1.2,fontFace:BODY,isTextBox:true,margin:0,paraSpaceAfter:4});
  return s;
}
function closing(p, line){
  const s=dark(p);
  s.addText("Thank you",{x:MX,y:2.4,w:12,h:1,fontFace:SERIF,fontSize:46,bold:true,
    color:C.paper,isTextBox:true,margin:0});
  s.addText(line,{x:MX,y:3.6,w:11.4,h:1.2,fontFace:BODY,fontSize:18,color:C.onNavy,
    isTextBox:true,margin:0,lineSpacingMultiple:1.15});
  s.addText("Questions & discussion",{x:MX,y:5.1,w:11,h:0.4,fontFace:BODY,fontSize:14,
    bold:true,color:C.red,isTextBox:true,margin:0});
  return s;
}

// pipeline diagram (reused) --------------------------------------------------
function pipeline(s, y){
  const boxes=[
    ["Unpack\n.crx / .xpi", C.navy2, C.onNavy],
    ["Sealed sandbox\ncapture", C.navy, C.paper],
    ["Features\nf( · )", C.navy2, C.onNavy],
    ["Δ = f(v2) − f(v1)", C.red, C.paper],
    ["Rules + ML\n+ Anomaly", C.navy2, C.onNavy],
    ["Verdict\n+ evidence", C.teal, C.paper],
  ];
  const bw=1.78, bh=1.0, gap=0.34; let x=MX;
  boxes.forEach((b,i)=>{ pipeBox(s,x,y,bw,bh,b[0],b[1],b[2]);
    if(i<boxes.length-1) arrow(s,x+bw+0.04,y+bh/2,gap-0.08); x+=bw+gap; });
}

//============================================================================
// DECK 1 — MID-SEMESTER
//============================================================================
function buildMidSem(){
  const p=new pptxgen(); p.layout="LAYOUT_WIDE"; p.author="extdrift";
  p.title="extdrift — Mid-Semester Progress";
  let n=0; const P=()=>++n;

  titleSlide(p,"Mid-Semester Progress Review");

  // 2 problem
  let s=light(p); kicker(s,"Motivation"); head(s,"A trusted extension can turn malicious in one update");
  bullets(s,[
    {text:"Extensions update automatically and silently — new code arrives without review or consent.",b:false},
    "They can read every page, your cookies (live sessions), and form fields.",
    {text:"Cyberhaven, Dec 2024: a phished developer account pushed a malicious update that stole session tokens from everyone who auto-updated.",c:C.ink},
    "Store review is point-in-time; it is not built to judge the change between two versions.",
  ],MX,1.75,7.4,4.2,16);
  panel(s,8.5,1.9,4.2,4.0,C.redSoft);
  s.addText("The gap",{x:8.75,y:2.15,w:3.7,h:0.4,fontFace:BODY,fontSize:14,bold:true,color:C.red,isTextBox:true,margin:0});
  s.addText("Malicious extensions are studied.\nMalicious UPDATES to trusted extensions are not — that is the attack surface.",
    {x:8.75,y:2.7,w:3.7,h:2.9,fontFace:BODY,fontSize:15,color:C.ink,isTextBox:true,margin:0,lineSpacingMultiple:1.1});
  pageno(s,P());

  // 3 idea
  s=light(p); kicker(s,"Core idea"); head(s,"Score the change, not the extension");
  panel(s,MX,1.85,12.1,1.5,C.cloud);
  s.addText([{text:"Δ  =  f(v₂)  −  f(v₁)",options:{fontSize:34,bold:true,color:C.navy}}],
    {x:MX,y:1.85,w:12.1,h:1.5,fontFace:SERIF,align:"center",valign:"middle",isTextBox:true,margin:0});
  bullets(s,[
    "A password manager reads passwords in every version — that alone is never suspicious.",
    "What is suspicious is an update that newly starts sending that data to a server never contacted before.",
    {text:"We run both versions in a sealed sandbox, record what each DOES, and difference the behaviour.",b:true,c:C.navy},
    "Because we watch the effect, obfuscation hides the code but not the malicious behaviour.",
  ],MX,3.7,12.1,3.0,16);
  pageno(s,P());

  // 4 why hard (2x2)
  s=light(p); kicker(s,"Challenges"); head(s,"Why this is genuinely hard");
  const grid=[
    ["Web noise","Two live sessions differ by ads and nonces. We use a deterministic sandbox: byte-identical pages, sealed egress."],
    ["Version acquisition","Chrome serves only the current version. Firefox AMO exposes full history; we crawl it."],
    ["Dormant payloads","Attacks fire on triggers. A HoneyPage + event fuzzing (Hulk) elicits them."],
    ["Multi-component / MV3","We instrument content scripts, MV2 pages and the MV3 service worker — the exfiltration blind spot."],
  ];
  let gx=MX, gy=1.85, gw=5.9, gh=2.35;
  grid.forEach((g,i)=>{ const x=gx+(i%2)*(gw+0.3), y=gy+Math.floor(i/2)*(gh+0.3);
    panel(s,x,y,gw,gh,C.cloud);
    s.addText(g[0],{x:x+0.22,y:y+0.18,w:gw-0.4,h:0.4,fontFace:BODY,fontSize:16,bold:true,color:C.navy,isTextBox:true,margin:0});
    s.addText(g[1],{x:x+0.22,y:y+0.66,w:gw-0.44,h:gh-0.8,fontFace:BODY,fontSize:13.5,color:C.ink,isTextBox:true,margin:0,lineSpacingMultiple:1.06}); });
  pageno(s,P());

  // 5 architecture
  s=light(p); kicker(s,"What we built"); head(s,"System architecture");
  pipeline(s,2.15);
  bullets(s,[
    {text:"Two capture engines (Chromium via Playwright, Firefox via Selenium) behind one trace schema.",b:false},
    "Four observation channels: network, DOM, storage/cookies, chrome.* / browser.* API.",
    "Three-layer scoring: transparent rules, a machine-learning classifier, and an anomaly detector.",
    {text:"~4,600 lines of Python · 111 automated tests · continuous integration.",c:C.muted},
  ],MX,3.7,12.1,3.0,15);
  pageno(s,P());

  // 6 data
  s=light(p); kicker(s,"Data"); head(s,"A hardened dataset — synthetic at scale, validated on real");
  stat(s,MX,1.9,3.75,"1,047","update pairs in the dataset",C.navy);
  stat(s,MX+4.0,1.9,3.75,"15","real extensions captured",C.teal);
  stat(s,MX+8.0,1.9,3.75,"9","malicious payload families",C.red);
  bullets(s,[
    {text:"Synthetic: 12 benign personas × 9 payload families with deliberate hard-benign / stealth overlap; real JavaScript payloads injected by a weaponiser.",b:false},
    "Real: benign update pairs from Firefox AMO version history; the same real extensions weaponised for the malicious class.",
    {text:"Why synthetic? Real malicious UPDATE pairs cannot be sourced — 60% of known-malicious IDs are delisted and predecessors are not archived.",c:C.ink},
  ],MX,4.25,12.1,2.6,14.5);
  pageno(s,P());

  // 7 detection
  s=light(p); kicker(s,"Models"); head(s,"Evidence-based model selection");
  bullets(s,[
    {text:"We do not assume XGBoost — we bake off six approaches on identical features and let the numbers decide.",b:true,c:C.navy},
    "Leakage-free: extension-level cross-validation and a strict temporal split (train earlier updates, test later).",
    "Metrics: PR-AUC and false-positive rate at 90% recall (the usability metric).",
    "The gradient-boosted-tree family wins; an anomaly layer trained on benign updates covers unseen threats.",
  ],MX,1.8,7.2,4.3,15.5);
  panel(s,8.35,1.95,4.35,3.9,C.cloud);
  s.addText("Rules vs. learned model",{x:8.6,y:2.15,w:3.9,h:0.4,fontFace:BODY,fontSize:14,bold:true,color:C.navy,isTextBox:true,margin:0});
  s.addText("False positives to catch 90% of attacks",{x:8.6,y:2.55,w:3.9,h:0.35,fontFace:BODY,fontSize:11.5,color:C.muted,isTextBox:true,margin:0});
  // two bars
  const b0y=5.55, bmax=2.1;
  s.addShape("rect",{x:9.05,y:b0y-bmax*0.90,w:1.15,h:bmax*0.90,fill:{color:C.red}});
  s.addShape("rect",{x:10.95,y:b0y-bmax*0.04,w:1.15,h:bmax*0.04,fill:{color:C.teal}});
  s.addText("45%",{x:8.9,y:b0y-bmax*0.90-0.42,w:1.45,h:0.4,fontFace:BODY,fontSize:18,bold:true,color:C.red,align:"center",isTextBox:true,margin:0});
  s.addText("~1%",{x:10.8,y:b0y-0.5,w:1.45,h:0.4,fontFace:BODY,fontSize:18,bold:true,color:C.teal,align:"center",isTextBox:true,margin:0});
  s.addText("Rules",{x:8.9,y:b0y+0.05,w:1.45,h:0.3,fontFace:BODY,fontSize:12,color:C.ink,align:"center",isTextBox:true,margin:0});
  s.addText("Model",{x:10.8,y:b0y+0.05,w:1.45,h:0.3,fontFace:BODY,fontSize:12,color:C.ink,align:"center",isTextBox:true,margin:0});
  pageno(s,P());

  // 8 results
  s=light(p); kicker(s,"Preliminary results"); head(s,"Early results are strong");
  stat(s,MX,2.0,3.85,"0.998","synthetic→real PR-AUC",C.navy,2.15);
  stat(s,MX+4.1,2.0,3.85,"30 / 30","rules recall on real weaponised",C.teal,2.15);
  stat(s,MX+8.2,2.0,3.85,"21 vs 0","static: clean vs obfuscated",C.red,2.15);
  s.addText("A model trained on synthetic data only separates real extensions it never saw (precision 1.0). Static update-differencing is blinded by obfuscation on real code; our dynamic diff is not.",
    {x:MX,y:4.55,w:12.1,h:1.4,fontFace:BODY,fontSize:15.5,color:C.ink,isTextBox:true,margin:0,align:"left",lineSpacingMultiple:1.12});
  pageno(s,P());

  // 9 validated
  s=light(p); kicker(s,"Status"); head(s,"What is validated so far");
  const done=[
    ["Cross-browser + MV3","Firefox and Chromium engines validated on real extensions, incl. the MV3 service worker."],
    ["Statistical rigor","95% confidence intervals; the ML gain over rules is statistically significant."],
    ["Held-out test","A locked by-extension test set with a calibrated operating point (PR-AUC 0.976)."],
    ["Anomaly on real","Benign-trained detector flags 93% of unseen real weaponised extensions."],
    ["Reproducible","One-command reproduction, continuous integration, 111 passing tests."],
    ["Prior-work baseline","You've Changed static method reproduced and beaten under obfuscation."],
  ];
  let dx=MX, dy=1.85, dw=3.9, dh=2.0;
  done.forEach((g,i)=>{ const x=dx+(i%3)*(dw+0.2), y=dy+Math.floor(i/3)*(dh+0.25);
    panel(s,x,y,dw,dh,C.cloud);
    s.addText("✓",{x:x+0.18,y:y+0.16,w:0.5,h:0.5,fontFace:BODY,fontSize:22,bold:true,color:C.teal,isTextBox:true,margin:0});
    s.addText(g[0],{x:x+0.72,y:y+0.18,w:dw-0.9,h:0.5,fontFace:BODY,fontSize:14.5,bold:true,color:C.navy,isTextBox:true,margin:0});
    s.addText(g[1],{x:x+0.2,y:y+0.72,w:dw-0.4,h:dh-0.85,fontFace:BODY,fontSize:12.5,color:C.ink,isTextBox:true,margin:0,lineSpacingMultiple:1.05}); });
  pageno(s,P());

  // 10 roadmap
  s=light(p); kicker(s,"Plan"); head(s,"Path to completion");
  const steps=[
    ["Now","Scale the real corpus to 100+ extensions (parallel capture on the MacBook)."],
    ["Next","Tier-2 dependency-graph model over cross-component message passing (beyond RF)."],
    ["Then","Final evaluation, thesis write-up, and demonstration."],
  ];
  let ry=2.1;
  steps.forEach((st,i)=>{ const y=ry+i*1.55;
    s.addShape("ellipse",{x:MX,y:y,w:0.9,h:0.9,fill:{color:i===0?C.red:C.navy},line:{type:"none"}});
    s.addText(String(i+1),{x:MX,y:y,w:0.9,h:0.9,fontFace:BODY,fontSize:24,bold:true,color:C.paper,align:"center",valign:"middle",isTextBox:true,margin:0});
    s.addText(st[0],{x:MX+1.25,y:y+0.02,w:2.2,h:0.4,fontFace:BODY,fontSize:16,bold:true,color:C.red,isTextBox:true,margin:0});
    s.addText(st[1],{x:MX+1.25,y:y+0.42,w:9.8,h:0.9,fontFace:BODY,fontSize:15.5,color:C.ink,isTextBox:true,margin:0,lineSpacingMultiple:1.05});
    if(i<steps.length-1) s.addShape("line",{x:MX+0.45,y:y+0.95,w:0,h:0.55,line:{color:C.line,width:2}}); });
  pageno(s,P());

  closing(p,"We detect the malicious update — not the extension — and it is validated end-to-end across two browsers.");
  return p.writeFile({fileName:"presentations/extdrift_MidSem.pptx"});
}

//============================================================================
// DECK 2 — END-SEMESTER
//============================================================================
function buildEndSem(){
  const p=new pptxgen(); p.layout="LAYOUT_WIDE"; p.author="extdrift";
  p.title="extdrift — Final Presentation";
  let n=0; const P=()=>++n;

  titleSlide(p,"Final Project Presentation");

  // 2 motivation
  let s=light(p); kicker(s,"Motivation"); head(s,"The silent malicious-update threat");
  bullets(s,[
    "Extensions run with deep privilege and update silently and automatically after install.",
    {text:"Cyberhaven (Dec 2024): a phished developer account pushed a malicious update that exfiltrated session tokens at scale.",b:false},
    "DataSpii (2019) and large ad-injection / affiliate campaigns (~87M users) follow the same bait-and-switch-on-update pattern.",
    {text:"Adware — ad injection and data collection without consent — is in scope as malicious.",b:true,c:C.navy},
  ],MX,1.8,7.3,4.2,15.5);
  panel(s,8.4,1.95,4.3,3.9,C.redSoft);
  s.addText("Why the stores miss it",{x:8.66,y:2.18,w:3.85,h:0.4,fontFace:BODY,fontSize:14,bold:true,color:C.red,isTextBox:true,margin:0});
  s.addText("Store review evaluates an extension in isolation, at one point in time. It is not designed to reason about what changed between two versions — exactly where the attack lives.",
    {x:8.66,y:2.68,w:3.85,h:3.0,fontFace:BODY,fontSize:15,color:C.ink,isTextBox:true,margin:0,lineSpacingMultiple:1.12});
  pageno(s,P());

  // 3 threat model
  s=light(p); kicker(s,"Threat model"); head(s,"Adversary and assumptions");
  bullets(s,[
    {text:"Adversary:",b:true,c:C.navy},
    {text:"controls the publishing account of a widely-installed, trusted extension (sold, phished, or compromised).",lvl:1},
    {text:"pushes a malicious update through the legitimate auto-update channel.",lvl:1},
    {text:"Goal:",b:true,c:C.navy},
    {text:"steal cookies / credentials / history, or covertly inject ads and affiliate links.",lvl:1},
    {text:"Assumptions:",b:true,c:C.navy},
    {text:"full control of the extension's own code; cannot bypass the browser permission model.",lvl:1},
    {text:"malicious behaviour manifests at runtime, possibly only under specific triggers.",lvl:1},
  ],MX,1.8,12.1,4.8,15);
  pageno(s,P());

  // 4 related work / novelty
  s=light(p); kicker(s,"Related work"); head(s,"Where we sit — and our novelty");
  table(s,[
    [th("Prior work"), th("What it does"), th("Limitation we address")],
    [td("You've Changed (CCS'20)"), td("Static diff of consecutive versions"), td("Blinded by obfuscation")],
    [td("Hulk (USENIX'14)"), td("Elicits behaviour on single versions"), td("No cross-version diff")],
    [td("EmPoWeb (S&P'19)"), td("Extension message-passing attacks"), td("Motivates our IPC features")],
    [td("Karami (NDSS'21)"), td("MV3 service-worker analysis"), td("We instrument the SW")],
  ],MX,1.85,12.1,[3.3,4.6,4.2]);
  panel(s,MX,4.75,12.1,1.4,C.tealSoft);
  s.addText([{text:"Our wedge:  ",options:{bold:true,color:C.teal,fontSize:16}},
    {text:"dynamic BEHAVIOURAL differencing of consecutive versions — obfuscation hides the code, not the runtime effect.",options:{color:C.ink,fontSize:16}}],
    {x:MX+0.25,y:4.75,w:11.6,h:1.4,fontFace:BODY,valign:"middle",isTextBox:true,margin:0,lineSpacingMultiple:1.1});
  pageno(s,P());

  // 5 approach
  s=light(p); kicker(s,"Approach"); head(s,"Behavioural differencing");
  panel(s,MX,1.9,12.1,1.5,C.cloud);
  s.addText("Δ  =  f(v₂)  −  f(v₁)",{x:MX,y:1.9,w:12.1,h:1.5,fontFace:SERIF,fontSize:34,bold:true,color:C.navy,align:"center",valign:"middle",isTextBox:true,margin:0});
  bullets(s,[
    {text:"f(·) is a feature vector of what a version DOES when executed under an identical, scripted scenario.",b:false},
    "Both versions see a byte-identical world, so the extension version is the only variable and the delta is meaningful.",
    {text:"The label lives in the change: score Δ, then explain the verdict with the exact new behaviours that fired.",b:true,c:C.navy},
  ],MX,3.7,12.1,2.8,16);
  pageno(s,P());

  // 6 architecture
  s=light(p); kicker(s,"System"); head(s,"Pipeline: two packages in, one explainable verdict");
  pipeline(s,2.35);
  bullets(s,[
    "Unpack → instrument → capture each version → validated trace → f(·) → Δ → three-layer score → verdict + evidence.",
    "Two engines share one trace schema, so synthetic, Chromium and Firefox rows are directly comparable.",
    {text:"Analysis is pure Python (runs on a laptop); only capture needs a browser.",c:C.muted},
  ],MX,3.85,12.1,2.6,15.5);
  pageno(s,P());

  // 7 sandbox
  s=light(p); kicker(s,"Capture"); head(s,"A sealed, deterministic sandbox");
  const sb=[
    ["Determinism","An in-process server returns byte-identical pages for reserved .test hosts; both versions see one fixed web."],
    ["Sealed egress","All outbound traffic is blackholed; a fake collector logs any exfiltration as ground truth. Nothing leaves the machine."],
    ["Instrumentation","A prelude hooks cookies, fetch/XHR, and chrome.*/browser.* in content scripts, MV2 pages and MV3 workers."],
    ["Elicitation","A Hulk-style HoneyPage plus event-handler fuzzing fires dormant payloads without a navigation that races the trace."],
  ];
  let sx=MX, sy=1.85, sw=5.9, sh=2.3;
  sb.forEach((g,i)=>{ const x=sx+(i%2)*(sw+0.3), y=sy+Math.floor(i/2)*(sh+0.28);
    panel(s,x,y,sw,sh,C.cloud);
    s.addText(g[0],{x:x+0.22,y:y+0.16,w:sw-0.4,h:0.4,fontFace:BODY,fontSize:15.5,bold:true,color:C.navy,isTextBox:true,margin:0});
    s.addText(g[1],{x:x+0.22,y:y+0.62,w:sw-0.44,h:sh-0.75,fontFace:BODY,fontSize:13,color:C.ink,isTextBox:true,margin:0,lineSpacingMultiple:1.05}); });
  s.addText("Engineering note: binding instrumentation to the content script's own realm (globalThis) raised real-extension recall from 70% to 100%.",
    {x:MX,y:6.55,w:12.1,h:0.5,fontFace:BODY,fontSize:12.5,italic:true,color:C.muted,isTextBox:true,margin:0});
  pageno(s,P());

  // 8 features
  s=light(p); kicker(s,"Features"); head(s,"What we measure, and why");
  table(s,[
    [th("Channel"), th("Representative features"), th("Signal")],
    [td("Network"), td("hosts, third-party, POSTs, upload bytes, low-reputation dest."), td("Exfiltration")],
    [td("DOM"), td("reads, sensitive reads, injections"), td("Credential theft, ads")],
    [td("Storage"), td("cookie reads, whole-jar reads"), td("Session theft")],
    [td("API"), td("high-risk calls, message passing"), td("Capability use, IPC")],
    [td("Derived"), td("read-then-upload flows"), td("Taint proxy")],
  ],MX,1.85,12.1,[2.3,6.6,3.2]);
  s.addText("26 behavioural features (+3 manifest-diff)  ·  plus 27 static-code features adopting the You've Changed discriminative-API set.",
    {x:MX,y:5.7,w:12.1,h:0.5,fontFace:BODY,fontSize:13.5,bold:true,color:C.navy,isTextBox:true,margin:0});
  pageno(s,P());

  // 9 data: real + why no pairs
  s=light(p); kicker(s,"Data · real"); head(s,"Why real malicious UPDATE pairs cannot be sourced");
  bullets(s,[
    "Firefox AMO exposes full version history + downloads → real benign update pairs (we crawl by popularity).",
    "Chrome serves only the current version — there is no public history.",
    {text:"We measured the malicious class empirically:",b:true,c:C.navy},
  ],MX,1.78,7.2,2.2,15);
  stat(s,MX,4.15,3.5,"~60%","known-malicious IDs delisted",C.red,1.8);
  stat(s,MX+3.75,4.15,3.5,"0 / 15","live IDs with archived history",C.red,1.8);
  panel(s,8.35,1.95,4.35,4.6,C.tealSoft);
  s.addText("Our resolution",{x:8.6,y:2.18,w:3.9,h:0.4,fontFace:BODY,fontSize:14,bold:true,color:C.teal,isTextBox:true,margin:0});
  s.addText("Real malicious pairs cannot be assembled from public sources. We therefore weaponise real benign extensions with real payloads — a real extension turned malicious — and validate that a synthetic-trained model transfers to them.",
    {x:8.6,y:2.68,w:3.9,h:3.7,fontFace:BODY,fontSize:14.5,color:C.ink,isTextBox:true,margin:0,lineSpacingMultiple:1.12});
  pageno(s,P());

  // 10 data: synthetic + dataset
  s=light(p); kicker(s,"Data · dataset"); head(s,"Synthetic at scale, one schema");
  bullets(s,[
    "12 benign personas × 9 payload families, with deliberate hard-benign and stealth-malicious overlap so no single threshold separates the classes.",
    "A weaponiser injects real JavaScript payloads in clean and obfuscated variants with identical runtime behaviour.",
  ],MX,1.8,7.1,2.4,15);
  table(s,[
    [th("Source"), th("Pairs"), th("Class")],
    [td("Synthetic (250×4)"), td("1,000"), td("mixed")],
    [td("Real, weaponised"), td("30"), td("malicious")],
    [td("Real benign (AMO)"), td("15"), td("benign")],
    [td("Total"), td("1,047",{bold:true}), td("449 / 598",{bold:true})],
  ],MX,4.05,6.9,[3.5,1.8,1.6]);
  panel(s,8.1,4.05,4.6,2.3,C.cloud);
  s.addText("266",{x:8.1,y:4.2,w:4.6,h:0.9,fontFace:BODY,fontSize:40,bold:true,color:C.navy,align:"center",isTextBox:true,margin:0});
  s.addText("distinct extensions — the unit we group on to prevent evaluation leakage",{x:8.35,y:5.15,w:4.1,h:1.0,fontFace:BODY,fontSize:13,color:C.muted,align:"center",isTextBox:true,margin:0,lineSpacingMultiple:1.08});
  pageno(s,P());

  // 11 models
  s=light(p); kicker(s,"Models"); head(s,"Three complementary layers");
  bullets(s,[
    {text:"Tier 1 — Rules:",b:true,c:C.navy},
    {text:"12 transparent weighted rules; the interpretable control the model must beat.",lvl:1},
    {text:"Tier 2 — Bake-off:",b:true,c:C.navy},
    {text:"six models on identical features; selected by leakage-free PR-AUC and FPR at 90% recall.",lvl:1},
    {text:"Tier 3 — Anomaly:",b:true,c:C.navy},
    {text:"IsolationForest / One-Class-SVM trained on benign deltas only — flags unseen threats.",lvl:1},
  ],MX,1.8,6.8,4.4,15);
  table(s,[
    [th("Model"), th("PR-AUC"), th("FPR@90%")],
    [td("HistGB"), td("0.983",{bold:true}), td("0.008",{bold:true})],
    [td("XGBoost"), td("0.982"), td("0.015")],
    [td("Random Forest"), td("0.982"), td("0.027")],
    [td("SVM / LogReg"), td("0.972"), td("0.03 – 0.06")],
    [td("Rules (control)"), td("0.868",{color:C.red}), td("0.450",{color:C.red,bold:true})],
  ],7.85,1.95,4.85,[2.35,1.25,1.25]);
  pageno(s,P());

  // 12 evaluation setup
  s=light(p); kicker(s,"Evaluation"); head(s,"A leakage-free, paper-grade protocol");
  const ev=[
    ["Extension-level CV","StratifiedGroupKFold by extension id — all versions of one extension stay in one fold."],
    ["Temporal split","Train on earlier updates, test on later ones — no training on the future."],
    ["Right metrics","PR-AUC and false-positive rate at 90% recall, not accuracy."],
    ["Held-out + CIs","A locked by-extension test set and bootstrap confidence intervals."],
  ];
  let ex=MX, ey=1.9, ew=5.9, eh=2.25;
  ev.forEach((g,i)=>{ const x=ex+(i%2)*(ew+0.3), y=ey+Math.floor(i/2)*(eh+0.28);
    panel(s,x,y,ew,eh,C.cloud);
    s.addText(g[0],{x:x+0.22,y:y+0.16,w:ew-0.4,h:0.4,fontFace:BODY,fontSize:15.5,bold:true,color:C.navy,isTextBox:true,margin:0});
    s.addText(g[1],{x:x+0.22,y:y+0.62,w:ew-0.44,h:eh-0.75,fontFace:BODY,fontSize:13.5,color:C.ink,isTextBox:true,margin:0,lineSpacingMultiple:1.06}); });
  pageno(s,P());

  // 13 results: model + rigor (native chart)
  s=light(p); kicker(s,"Results 1/3"); head(s,"The learned tier earns its place");
  s.addChart(p.ChartType.bar, [{name:"FPR@90% recall",
    labels:["Rules","LogReg","SVM","RF","XGB","HistGB"], values:[0.45,0.062,0.028,0.027,0.015,0.008]}],
    {x:MX,y:1.95,w:6.9,h:4.4, barDir:"col", chartColors:[C.red,C.navy2,C.navy2,C.navy2,C.navy2,C.navy2],
     showTitle:false, showLegend:false, showValue:true, dataLabelPosition:"outEnd",
     dataLabelFormatCode:"0%", dataLabelFontSize:10, dataLabelColor:C.ink,
     valAxisMinVal:0, valAxisMaxVal:0.5, valAxisLabelFormatCode:"0%",
     catAxisLabelColor:C.muted, valAxisLabelColor:C.muted, catAxisLabelFontSize:11, valAxisLabelFontSize:10,
     valGridLine:{color:"E8ECF1",size:1}, catGridLine:{style:"none"}, chartColorsOpacity:100});
  s.addText("False positives to reach 90% recall (lower is better)",{x:MX,y:6.35,w:6.9,h:0.35,fontFace:BODY,fontSize:12,italic:true,color:C.muted,align:"center",isTextBox:true,margin:0});
  bullets(s,[
    {text:"Rules would false-positive on 45% of benign updates to catch 90% of attacks; the model on under 2%.",b:false},
    {text:"HistGB PR-AUC 0.983 [0.976, 0.989] vs rules 0.868 [0.844, 0.891].",b:true,c:C.navy},
    "The +0.115 PR-AUC gain has 95% CI [0.093, 0.137] — statistically significant, not noise.",
    "Under the temporal split the winner holds (≈ 0.97), so it generalises to future updates.",
  ],7.95,2.05,4.75,4.2,14);
  pageno(s,P());

  // 14 results: real-world transfer
  s=light(p); kicker(s,"Results 2/3"); head(s,"It generalises to real extensions");
  stat(s,MX,2.0,3.85,"0.998","synthetic→real transfer PR-AUC",C.navy,2.0);
  stat(s,MX+4.1,2.0,3.85,"1.00","precision on real (held out)",C.teal,2.0);
  stat(s,MX+8.2,2.0,3.85,"30 / 30","rules recall on real weaponised",C.red,2.0);
  bullets(s,[
    {text:"We train on synthetic data ONLY, then test on 45 captures from 15 real extensions the model never saw — PR-AUC 0.998 at recall 0.93, precision 1.0, zero false positives.",b:false},
    {text:"The case for ML over rules, on real data: three benign updates (LanguageTool, Privacy Badger, RYD) tripped a rule, but the model correctly called all three benign (≤ 0.03).",b:true,c:C.navy},
  ],MX,4.35,12.1,2.4,14.5);
  pageno(s,P());

  // 15 results: robustness
  s=light(p); kicker(s,"Results 3/3"); head(s,"Robustness, novelty, and speed");
  const rb=[
    ["Obfuscation","Static (You've Changed) catches clean 21/21 but obfuscated 0/21; our dynamic diff catches both."],
    ["Unseen threats","Anomaly layer, benign-trained, flags 93% of real weaponised extensions (ROC-AUC 0.989)."],
    ["Cross-browser","Firefox on 15 real extensions; Chromium validated on a real MV3 extension (service worker reached)."],
    ["Performance","Analysis 0.22 ms/pair — scales to store size; browser capture is the only bottleneck and parallelises."],
  ];
  let rx=MX, ry2=1.9, rw=5.9, rh=2.25;
  rb.forEach((g,i)=>{ const x=rx+(i%2)*(rw+0.3), y=ry2+Math.floor(i/2)*(rh+0.28);
    panel(s,x,y,rw,rh,C.cloud);
    s.addText(g[0],{x:x+0.22,y:y+0.16,w:rw-0.4,h:0.4,fontFace:BODY,fontSize:15.5,bold:true,color:C.navy,isTextBox:true,margin:0});
    s.addText(g[1],{x:x+0.22,y:y+0.62,w:rw-0.44,h:rh-0.75,fontFace:BODY,fontSize:13,color:C.ink,isTextBox:true,margin:0,lineSpacingMultiple:1.05}); });
  pageno(s,P());

  // 16 live demo
  s=light(p); kicker(s,"Demonstration"); head(s,"Live: a malicious update, caught end-to-end");
  panel(s,MX,1.9,12.1,2.9,"11202E");
  s.addText([
    {text:"$ python scripts/demo.py",options:{color:"9FE0C8",breakLine:true,fontSize:14}},
    {text:"",options:{breakLine:true,fontSize:8}},
    {text:"Benign feature update      BENIGN      score=0.25  leak=False   PASS",options:{color:"CFE8DC",breakLine:true,fontSize:14}},
    {text:"Weaponised update          MALICIOUS   score=0.99  leak=True    PASS",options:{color:"F6B8B8",breakLine:true,fontSize:14}},
  ],{x:MX+0.3,y:2.15,w:11.5,h:2.4,fontFace:"Consolas",valign:"top",isTextBox:true,margin:0,lineSpacingMultiple:1.25});
  bullets(s,[
    "A real browser loads each version; a synthetic payload attempts cookie theft.",
    {text:"The sandbox both catches the behaviour change AND proves the leak (the collector received the data) — while blackholing it locally.",b:true,c:C.navy},
  ],MX,5.1,12.1,1.7,15);
  pageno(s,P());

  // 17 limitations
  s=light(p); kicker(s,"Honesty"); head(s,"Limitations we state, not hide");
  bullets(s,[
    "No genuinely in-the-wild malicious pair is captured — the malicious class is real-extension-weaponised because such pairs cannot be sourced; the transfer result mitigates but does not replace this.",
    "The real corpus (15 extensions) is modest; a production false-positive claim warrants hundreds — a matter of compute time, and in progress.",
    "The HoneyPage elicits most payloads, but time-bomb and anti-analysis evasion remain open.",
  ],MX,1.85,12.1,4.4,16.5);
  pageno(s,P());

  // 18 contributions + future -> closing
  s=light(p); kicker(s,"Contributions & future work"); head(s,"What we contribute, and what's next");
  bullets(s,[
    {text:"Contributions:",b:true,c:C.navy},
    {text:"a dynamic behavioural-differencing formulation for malicious-update detection;",lvl:1},
    {text:"a sealed sandbox with cross-engine, cross-manifest (MV3) instrumentation;",lvl:1},
    {text:"a rigorously evaluated three-layer detector whose synthetic training transfers to real extensions;",lvl:1},
    {text:"an empirical account of why real malicious pairs cannot be sourced.",lvl:1},
    {text:"Future work:",b:true,c:C.navy},
    {text:"scale the real corpus; a Tier-2 dependency-graph model; longitudinal in-the-wild collection.",lvl:1},
  ],MX,1.8,12.1,4.9,15);
  pageno(s,P());

  closing(p,"extdrift detects the malicious update — not the extension — robustly to obfuscation, across two browsers, with results that transfer to the real world.");
  return p.writeFile({fileName:"presentations/extdrift_EndSem.pptx"});
}

Promise.resolve()
  .then(buildMidSem).then(f=>console.log("wrote", f))
  .then(buildEndSem).then(f=>console.log("wrote", f))
  .catch(e=>{ console.error("ERROR", e); process.exit(1); });
