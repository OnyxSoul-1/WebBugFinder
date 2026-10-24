(async function(){
"use strict";
if (window.__WBF_EXT__) { window.__WBF_EXT__.toggle(); return; }

var FLAGS = [];
function flag(sev, msg){ FLAGS.push({sev:sev, msg:msg}); }

var d = {
  html: document.documentElement.outerHTML,
  scripts: [], forms: [], links: [], iframes: [],
  cookies: document.cookie, ls: {}, ss: {}
};
document.querySelectorAll('script').forEach(function(s){
  d.scripts.push({src: s.src || '(inline)', inline: !s.src, len: (s.textContent||'').length});
});
document.querySelectorAll('form').forEach(function(f){
  var fields = [];
  f.querySelectorAll('input,select,textarea').forEach(function(i){
    fields.push({name:i.name, type:i.type});
  });
  d.forms.push({action: f.action || location.href, method: (f.method||'get').toUpperCase(), fields: fields});
});
document.querySelectorAll('a[href]').forEach(function(a,i){ if(i<300) d.links.push(a.href); });
document.querySelectorAll('iframe').forEach(function(f){ d.iframes.push(f.src); });
try { for (var i=0;i<localStorage.length;i++){var k=localStorage.key(i); d.ls[k]=localStorage.getItem(k);} } catch(e){}
try { for (var j=0;j<sessionStorage.length;j++){var q=sessionStorage.key(j); d.ss[q]=sessionStorage.getItem(q);} } catch(e){}

if (location.protocol !== 'https:') flag('HIGH','Page is not HTTPS');
if (!document.querySelector('meta[http-equiv="Content-Security-Policy"]')) flag('MED','No CSP meta tag');
var inline = d.scripts.filter(function(s){return s.inline && s.len>0;});
if (inline.length) flag('MED', inline.length+' inline scripts — XSS surface');
if (/document\.write\s*\(/.test(d.html)) flag('MED','document.write() found');
if (/\beval\s*\(/.test(d.html)) flag('MED','eval() found');
if (/\.innerHTML\s*=/.test(d.html)) flag('LOW','innerHTML assignment');
if (/dangerouslySetInnerHTML/.test(d.html)) flag('LOW','dangerouslySetInnerHTML found');

d.forms.forEach(function(f){
  if (f.action.indexOf('http:') === 0) flag('HIGH','Form over HTTP: '+f.action);
  var hasPw = f.fields.some(function(x){return x.type==='password';});
  if (hasPw && location.protocol !== 'https:') flag('HIGH','Password on non-HTTPS');
});

var tb = [];
document.querySelectorAll('a[target="_blank"]').forEach(function(a){
  if ((a.rel||'').indexOf('noopener') === -1) tb.push(a);
});
if (tb.length) flag('LOW', tb.length+' target=_blank without rel=noopener');

document.querySelectorAll('script[src]').forEach(function(s){
  try {
    var u = new URL(s.src, location.href);
    if (u.origin !== location.origin && !s.integrity)
      flag('LOW','3rd-party script no SRI: '+u.href);
  } catch(e){}
});

var ps = new URLSearchParams(location.search);
['url','next','redirect','return','continue','dest','target'].forEach(function(p){
  if (ps.has(p)) flag('MED',"Redirect-ish param '"+p+"'");
});

d.links.forEach(function(h){
  if (/\.(env|git|bak|old|sql|zip)$/i.test(h) || /\/\.git\//.test(h))
    flag('HIGH','Sensitive path link: '+h);
});

var cm = d.html.match(/<!--[\s\S]{0,200}?-->/g) || [];
var leak = cm.some(function(c){ return /(TODO|FIXME|password|secret|api[_-]?key|token)/i.test(c); });
if (leak) flag('MED','Comments may leak sensitive notes');

// source map HEAD checks (same-origin, first 20 scripts)
var exts = [];
document.querySelectorAll('script[src]').forEach(function(s){ if(s.src) exts.push(s.src); });
for (var n=0; n<Math.min(exts.length,20); n++) {
  try {
    var u2 = new URL(exts[n], location.href);
    if (u2.origin !== location.origin) continue;
    var mapUrl = exts[n] + '.map';
    var r = await fetch(mapUrl, {method:'HEAD'});
    if (r.ok) flag('MED','Source map exposed: '+mapUrl);
  } catch(e){}
}

var sevColor = {HIGH:'#f85149', MED:'#f0c850', LOW:'#58a6ff'};
function esc(s){ return String(s).replace(/[&<>]/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c]; }); }
function sec(t,b){ return '<details><summary>'+t+'</summary><div class="wbf-pre">'+b+'</div></details>'; }

function render(){
  var old = document.getElementById('__wbf'); if (old) old.remove();
  var box = document.createElement('div');
  box.id = '__wbf'; box.className = 'wbf-panel';
  var flagsHtml = FLAGS.map(function(f){
    return '<div class="wbf-flag" style="border-left-color:'+sevColor[f.sev]+'"><b style="color:'+sevColor[f.sev]+'">'+f.sev+'</b> '+esc(f.msg)+'</div>';
  }).join('') || '<i>none</i>';
  box.innerHTML =
    '<div class="wbf-head"><b>WBF — WebBugFinder</b><button id="__wbf_close">close</button></div>'+
    '<div class="wbf-url">'+esc(location.href)+'</div>'+
    '<h4 class="wbf-flags-title">FLAGS ('+FLAGS.length+')</h4>'+
    '<div>'+flagsHtml+'</div>'+
    sec('HTML source ('+d.html.length+' chars)', esc(d.html.slice(0,20000)))+
    sec('Scripts ('+d.scripts.length+')', d.scripts.map(function(s){ return s.inline ? '[inline '+s.len+'b]' : esc(s.src); }).join('\n'))+
    sec('Forms ('+d.forms.length+')', d.forms.map(function(f){
      return f.method+' '+esc(f.action)+'\n  '+f.fields.map(function(x){return x.type+' '+x.name;}).join(', ');
    }).join('\n\n'))+
    sec('Iframes', d.iframes.map(esc).join('\n'))+
    sec('Cookies', esc(d.cookies || '(none)'))+
    sec('localStorage', esc(JSON.stringify(d.ls,null,2)))+
    sec('sessionStorage', esc(JSON.stringify(d.ss,null,2)))+
    sec('Links ('+d.links.length+')', d.links.map(esc).join('\n'))+
    '<div class="wbf-foot">static analysis · devtools for full fidelity</div>';
  document.body.appendChild(box);
  box.querySelector('#__wbf_close').onclick = function(){ box.remove(); window.__WBF_EXT__.open=false; };
}

window.__WBF_EXT__ = { open:true, toggle:function(){
  var b = document.getElementById('__wbf');
  if (b) { b.remove(); this.open=false; } else { render(); this.open=true; }
}};
render();
})();
