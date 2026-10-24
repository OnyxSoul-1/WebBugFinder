(function(){
"use strict";
if (window.__WBF__) { window.__WBF__.toggle(); return; }

var FLAGS = [];
function flag(sev, msg){ FLAGS.push({sev:sev, msg:msg}); }

function collect(){
  var html = document.documentElement.outerHTML;
  var scripts = [];
  document.querySelectorAll('script').forEach(function(s){
    scripts.push({src: s.src || '(inline)', inline: !s.src, len: (s.textContent||'').length});
  });
  var forms = [];
  document.querySelectorAll('form').forEach(function(f){
    var fields = [];
    f.querySelectorAll('input,select,textarea').forEach(function(i){
      fields.push({name:i.name, type:i.type, autocomplete:i.autocomplete});
    });
    forms.push({action: f.action || location.href, method: (f.method||'get').toUpperCase(), fields: fields});
  });
  var links = [];
  document.querySelectorAll('a[href]').forEach(function(a,i){ if(i<300) links.push(a.href); });
  var iframes = [];
  document.querySelectorAll('iframe').forEach(function(f){ iframes.push(f.src); });
  var cookies = document.cookie;
  var ls = {}, ss = {};
  try { for (var i=0;i<localStorage.length;i++){var k=localStorage.key(i); ls[k]=localStorage.getItem(k);} } catch(e){}
  try { for (var j=0;j<sessionStorage.length;j++){var q=sessionStorage.key(j); ss[q]=sessionStorage.getItem(q);} } catch(e){}
  return {html:html, scripts:scripts, forms:forms, links:links, iframes:iframes, cookies:cookies, ls:ls, ss:ss};
}

function analyze(d){
  if (location.protocol !== 'https:') flag('HIGH','Page is not HTTPS');
  if (!document.querySelector('meta[http-equiv="Content-Security-Policy"]'))
    flag('MED','No CSP meta tag visible (header CSP not checkable from JS)');
  var inline = d.scripts.filter(function(s){return s.inline && s.len>0;});
  if (inline.length) flag('MED', inline.length+' inline <script> block(s) — XSS surface if inputs reflected');
  if (/document\.write\s*\(/.test(d.html)) flag('MED','document.write() found');
  if (/\beval\s*\(/.test(d.html)) flag('MED','eval() found');
  if (/\.innerHTML\s*=/.test(d.html)) flag('LOW','innerHTML assignment found (check for unsanitized input)');
  if (/dangerouslySetInnerHTML/.test(d.html)) flag('LOW','dangerouslySetInnerHTML found');

  d.forms.forEach(function(f){
    if (f.action.indexOf('http:') === 0) flag('HIGH','Form posts over HTTP: '+f.action);
    var hasPw = f.fields.some(function(x){return x.type==='password';});
    if (hasPw && location.protocol !== 'https:') flag('HIGH','Password field on non-HTTPS page');
  });

  var tb = [];
  document.querySelectorAll('a[target="_blank"]').forEach(function(a){
    if ((a.rel||'').indexOf('noopener') === -1) tb.push(a);
  });
  if (tb.length) flag('LOW', tb.length+' link(s) target=_blank without rel=noopener');

  document.querySelectorAll('script[src]').forEach(function(s){
    try {
      var u = new URL(s.src, location.href);
      if (u.origin !== location.origin && !s.integrity)
        flag('LOW','Third-party script without SRI: '+u.href);
    } catch(e){}
  });

  var params = new URLSearchParams(location.search);
  ['url','next','redirect','return','continue','dest','target'].forEach(function(p){
    if (params.has(p)) flag('MED',"Redirect-ish parameter '"+p+"' in URL — check open-redirect handling");
  });

  d.links.forEach(function(h){
    if (/\.(env|git|svn|bak|old|sql|zip|tar\.gz)$/i.test(h) || /\/\.git\//.test(h) || /\/\.env/.test(h))
      flag('HIGH','Link references sensitive path: '+h);
  });

  var cm = d.html.match(/<!--[\s\S]{0,200}?-->/g) || [];
  var leak = cm.some(function(c){ return /(TODO|FIXME|password|secret|api[_-]?key|token)/i.test(c); });
  if (leak) flag('MED','HTML comments may leak sensitive notes');
}

function panel(d){
  var old = document.getElementById('__wbf'); if (old) old.remove();
  var box = document.createElement('div');
  box.id = '__wbf';
  box.style.cssText = 'position:fixed;top:0;right:0;width:46vw;height:100vh;z-index:2147483647;background:#0a0c10;color:#c9d1d9;font:12px/1.45 monospace;border-left:1px solid #1f2733;overflow:auto;padding:12px;box-sizing:border-box';
  var sevColor = {HIGH:'#f85149', MED:'#f0c850', LOW:'#58a6ff'};
  function esc(s){ return String(s).replace(/[&<>]/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c]; }); }
  function sec(title, body){
    return '<details><summary style="color:#f0c850;cursor:pointer;margin:6px 0">'+title+
           '</summary><div style="background:#06080b;border:1px solid #1f2733;padding:8px;white-space:pre-wrap;word-break:break-all;max-height:40vh;overflow:auto">'+body+'</div></details>';
  }
  var flagsHtml = FLAGS.map(function(f){
    return '<div style="border-left:3px solid '+sevColor[f.sev]+';padding:4px 8px;margin:3px 0;background:#06080b"><b style="color:'+sevColor[f.sev]+'">'+f.sev+'</b> '+esc(f.msg)+'</div>';
  }).join('') || '<i>none</i>';

  box.innerHTML =
    '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">'+
      '<b style="color:#f0c850">WBF — WebBugFinder</b>'+
      '<button id="__wbf_close" style="background:#1f2733;color:#c9d1d9;border:1px solid #303a48;padding:2px 8px;cursor:pointer">close</button>'+
    '</div>'+
    '<div style="color:#8b949e;word-break:break-all">'+esc(location.href)+'</div>'+
    '<h4 style="color:#f85149;margin:10px 0 4px">FLAGS ('+FLAGS.length+')</h4>'+
    '<div>'+flagsHtml+'</div>'+
    sec('HTML source ('+d.html.length+' chars)', esc(d.html.slice(0,20000)))+
    sec('Scripts ('+d.scripts.length+')', d.scripts.map(function(s){ return s.inline ? '[inline '+s.len+'b]' : esc(s.src); }).join('\n'))+
    sec('Forms ('+d.forms.length+')', d.forms.map(function(f){
      return f.method+' '+esc(f.action)+'\n  '+f.fields.map(function(x){return x.type+' '+x.name;}).join(', ');
    }).join('\n\n'))+
    sec('Iframes ('+d.iframes.length+')', d.iframes.map(esc).join('\n'))+
    sec('Cookies (readable)', esc(d.cookies || '(none readable)'))+
    sec('localStorage', esc(JSON.stringify(d.ls,null,2)))+
    sec('sessionStorage', esc(JSON.stringify(d.ss,null,2)))+
    sec('Links ('+d.links.length+')', d.links.map(esc).join('\n'))+
    '<div style="color:#8b949e;margin-top:8px">static analysis — does not execute new JS; not a substitute for devtools or a real scanner</div>';

  document.body.appendChild(box);
  box.querySelector('#__wbf_close').onclick = function(){ box.remove(); window.__WBF__.open=false; };
}

function run(){
  FLAGS.length = 0;
  var d = collect();
  analyze(d);
  panel(d);
  window.__WBF__ = { open:true, toggle:function(){
    var b = document.getElementById('__wbf');
    if (b) { b.remove(); this.open=false; } else { run(); }
  }};
}

run();
})();
