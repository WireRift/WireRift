package clientui

// pageHTML is the whole interface. It is one file with inline script and
// style (both carry the per-request nonce), so it needs nothing from the
// network. The script must not contain a backtick: this is a raw string.
const pageHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WireRift client</title>
<style nonce="{{NONCE}}">
:root{--bg:#f8fafc;--bg1:#fff;--bg2:#f1f5f9;--bd:#e2e8f0;--tx:#0f172a;--tx1:#475569;--tx2:#94a3b8;--ac:#2563eb;--ok:#16a34a;--wn:#d97706;--er:#dc2626}
@media (prefers-color-scheme:dark){:root{--bg:#06080f;--bg1:#0c1019;--bg2:#151b2b;--bd:#1e293b;--tx:#e2e8f0;--tx1:#94a3b8;--tx2:#64748b;--ac:#3b82f6;--ok:#22c55e;--wn:#f59e0b;--er:#ef4444}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1200px;margin:0 auto;padding:1rem 1rem 3rem}
header{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.5rem 0 1rem;border-bottom:1px solid var(--bd);margin-bottom:1rem}
h1{font-size:1.15rem;margin:0}h1 b{color:var(--ac)}h1 small{color:var(--tx2);font-weight:400;margin-left:.5rem}
.pill{display:inline-block;padding:.15rem .6rem;border-radius:999px;font-size:.75rem;font-weight:600;background:var(--bg2);color:var(--tx1);border:1px solid var(--bd)}
.pill.ok{color:var(--ok);border-color:var(--ok)}.pill.warn{color:var(--wn);border-color:var(--wn)}.pill.bad{color:var(--er);border-color:var(--er)}
.card{background:var(--bg1);border:1px solid var(--bd);border-radius:.6rem;padding:1rem;margin-bottom:1rem}
.ttl{font-size:1rem;font-weight:600;margin:0 0 .5rem;word-break:break-all}
.card h2{font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;color:var(--tx1);margin:0 0 .75rem}
.row{display:flex;gap:.75rem;flex-wrap:wrap;align-items:flex-end}
.f{display:flex;flex-direction:column;gap:.2rem;min-width:9rem;flex:1}.f.w{flex:2;min-width:14rem}
label{font-size:.72rem;color:var(--tx1)}label .h{color:var(--tx2)}
input[type=text],input[type=password],input[type=number],select{width:100%;padding:.45rem .6rem;background:var(--bg);border:1px solid var(--bd);border-radius:.4rem;color:var(--tx);font:inherit}
input:focus,select:focus{outline:2px solid var(--ac);outline-offset:-1px}
.chk{display:flex;align-items:center;gap:.4rem;font-size:.8rem;color:var(--tx1)}
button{font:inherit;cursor:pointer;border-radius:.4rem;padding:.45rem .9rem;border:1px solid var(--bd);background:var(--bg2);color:var(--tx)}
button.p{background:var(--ac);border-color:var(--ac);color:#fff}button.d{color:var(--er);border-color:var(--er);background:transparent}
button:disabled{opacity:.5;cursor:not-allowed}button.s{padding:.2rem .55rem;font-size:.78rem}
.err{color:var(--er);font-size:.82rem;margin-top:.5rem}.note{color:var(--tx2);font-size:.78rem;margin-top:.5rem}
.tabs{display:flex;gap:.25rem;border-bottom:1px solid var(--bd);margin-bottom:1rem}
.tab{padding:.5rem 1rem;cursor:pointer;color:var(--tx1);border-bottom:2px solid transparent}.tab.on{color:var(--ac);border-color:var(--ac)}
.tab i{font-style:normal;background:var(--bg2);border-radius:999px;padding:0 .45rem;font-size:.72rem;margin-left:.3rem}
table{width:100%;border-collapse:collapse;font-size:.82rem}
th{text-align:left;color:var(--tx1);font-weight:600;padding:.4rem .5rem;border-bottom:1px solid var(--bd);white-space:nowrap}
td{padding:.35rem .5rem;border-bottom:1px solid var(--bd);vertical-align:top}
tbody tr.x{cursor:pointer}tbody tr.x:hover{background:var(--bg2)}tbody tr.sel{background:var(--bg2);outline:1px solid var(--ac)}
.mono,td.m{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.78rem}
td.p{max-width:28rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.s2{color:var(--ok)}.s3{color:var(--ac)}.s4{color:var(--wn)}.s5{color:var(--er)}
.meth{font-weight:700}
.seg{display:inline-flex;border:1px solid var(--bd);border-radius:.4rem;overflow:hidden}.seg button{border:0;border-radius:0;background:var(--bg1);color:var(--tx1)}.seg button.on{background:var(--ac);color:#fff}
.chips{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:.75rem}.chip{color:var(--tx1);font-size:.8rem}.chip b{color:var(--tx);font-size:1rem;margin-right:.25rem}
pre{margin:.25rem 0 0;padding:.6rem .75rem;background:var(--bg);border:1px solid var(--bd);border-radius:.4rem;overflow:auto;max-height:22rem;white-space:pre-wrap;word-break:break-all;font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:1rem}@media (max-width:900px){.cols{grid-template-columns:1fr}}
.kv{font-size:.78rem}.kv div{display:flex;gap:.5rem;border-bottom:1px solid var(--bd);padding:.15rem 0}.kv span:first-child{min-width:9rem;color:var(--tx1);font-weight:600}.kv span:last-child{word-break:break-all}
.empty{color:var(--tx2);padding:1.5rem;text-align:center}
.hide{display:none}
details summary{cursor:pointer;color:var(--tx1);font-size:.82rem;margin:.75rem 0 .25rem}
a{color:var(--ac);text-decoration:none}a:hover{text-decoration:underline}
</style></head><body><div class="wrap">
<header><h1>Wire<b>Rift</b> client<small>{{VERSION}}</small></h1><span class="pill" id="pill">loading...</span></header>

<div class="card"><h2>Connection</h2>
<div class="row">
<div class="f w"><label for="server">Server <span class="h">host:4443, or tls://host:4443 when the server uses TLS</span></label><input id="server" type="text" placeholder="tls://tunnel.example.com:4443" autocomplete="off" spellcheck="false"></div>
<div class="f w"><label for="token">Token</label><input id="token" type="password" placeholder="wr_..." autocomplete="off" spellcheck="false"></div>
<div class="f" style="flex:0 0 auto"><button class="p" id="connectBtn">Connect</button></div>
</div>
<div class="row" style="margin-top:.5rem"><label class="chk"><input type="checkbox" id="remember"> Remember the token on this computer</label><span class="note" id="rememberNote"></span><button class="s hide" id="forgetBtn">Forget saved login</button></div>
<div class="err" id="connErr"></div>
</div>

<div class="tabs"><div class="tab on" data-t="tunnels">Tunnels<i id="nTunnels">0</i></div><div class="tab" data-t="traffic">Traffic<i id="nTraffic">0</i></div></div>

<div id="tunnels">
<div class="card"><h2>New tunnel</h2>
<div class="row">
<div class="f" style="flex:0 0 auto"><label>Type</label><div class="seg" id="type"><button class="on" data-v="http">Web</button><button data-v="tcp">TCP</button></div></div>
<div class="f"><label for="local">Local port <span class="h">3000 or host:3000</span></label><input id="local" type="text" placeholder="3000" autocomplete="off"></div>
<div class="f" id="subWrap"><label for="sub">Subdomain <span class="h">empty = random</span></label><input id="sub" type="text" placeholder="myapp" autocomplete="off" spellcheck="false"></div>
<div class="f" style="flex:0 0 auto"><button class="p" id="openBtn" disabled>Open tunnel</button></div>
</div>
<details><summary>More options</summary>
<div class="row">
<div class="f" data-http><label for="auth">Basic auth <span class="h">user:password</span></label><input id="auth" type="text" autocomplete="off"></div>
<div class="f" data-http><label for="pin">PIN</label><input id="pin" type="text" autocomplete="off"></div>
<div class="f" data-http><label for="allow">IP allow-list <span class="h">1.2.3.4,10.0.0.0/8</span></label><input id="allow" type="text" autocomplete="off"></div>
<div class="f" data-http><label for="domain">Own domain <span class="h">needs a DNS TXT record</span></label><input id="domain" type="text" autocomplete="off"></div>
<div class="f"><label for="ttl">Close automatically after</label><select id="ttl"><option value="">never</option><option>30m</option><option>2h</option><option>8h</option><option>24h</option></select></div>
<div class="f" data-http style="flex:0 0 auto"><label class="chk"><input type="checkbox" id="inspect"> Also inspect on the server</label></div>
</div></details>
<div class="err" id="openErr"></div>
</div>
<div class="card"><h2>Open tunnels</h2>
<table><thead><tr><th>Type</th><th>Public address</th><th>Forwards to</th><th>Closes</th><th></th></tr></thead><tbody id="tbTunnels"></tbody></table>
<div class="empty" id="noTunnels">No tunnels yet. Connect, then open one above.</div></div>
</div>

<div id="traffic" class="hide">
<div class="card">
<div class="chips"><span class="chip"><b id="stReq">0</b>requests</span><span class="chip"><b id="stErr">0</b>errors</span><span class="chip"><b id="stIn">0 B</b>in</span><span class="chip"><b id="stOut">0 B</b>out</span></div>
<div class="row" style="margin-bottom:.75rem">
<div class="f w"><input id="filter" type="text" placeholder="Filter by path, method, address..." autocomplete="off"></div>
<div class="f" style="flex:0 0 9rem"><select id="statusF"><option value="">all statuses</option><option value="2">2xx</option><option value="3">3xx</option><option value="4">4xx</option><option value="5">5xx</option><option value="e">errors</option></select></div>
<label class="chk"><input type="checkbox" id="pause"> Pause</label><button class="s" id="clearBtn">Clear</button>
</div>
<table><thead><tr><th>Time</th><th>Method</th><th>Path</th><th>Status</th><th>ms</th><th>In</th><th>Out</th><th>From</th></tr></thead><tbody id="tbTraffic"></tbody></table>
<div class="empty" id="noTraffic">Nothing yet. Requests that visitors send through a tunnel appear here as they happen.</div>
</div>
<div class="card hide" id="detail"></div>
</div>
</div>
<script nonce="{{NONCE}}">
(function(){
var $=function(i){return document.getElementById(i)};
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function api(method,path,body){
  return fetch(path,{method:method,headers:{'Content-Type':'application/json','X-WireRift-UI':'1'},body:body?JSON.stringify(body):undefined}).then(function(r){
    return r.json().catch(function(){return{}}).then(function(j){if(!r.ok)throw new Error(j.error||('error '+r.status));return j});
  });
}
function fb(n){if(n<1024)return n+' B';if(n<1048576)return(n/1024).toFixed(1)+' KB';if(n<1073741824)return(n/1048576).toFixed(1)+' MB';return(n/1073741824).toFixed(2)+' GB'}
function ft(t){var d=new Date(t);return d.toTimeString().slice(0,8)+'.'+String(d.getMilliseconds()).padStart(3,'0')}
var state=null,rows=[],lastId=0,selected=0,type='http',tab='tunnels',filled=false,tunJSON='';

/* ---- connection ---- */
function renderState(s){
  state=s;
  var p=$('pill');p.textContent=s.state==='connected'?'connected':s.state;
  p.className='pill '+(s.state==='connected'?'ok':(s.state==='reconnecting'?'warn':(s.state==='failed'?'bad':'')));
  var on=s.state!=='disconnected';
  if(!filled){$('server').value=s.server||'';filled=true}
  $('server').disabled=on;$('token').disabled=on;$('remember').disabled=on;
  $('token').placeholder=s.token_saved?'saved - leave empty to use it':'wr_...';
  if(!$('remember').dataset.set){$('remember').checked=!!s.remembered;$('remember').dataset.set='1'}
  $('connectBtn').textContent=on?'Disconnect':'Connect';$('connectBtn').className=on?'d':'p';
  $('forgetBtn').classList.toggle('hide',!s.token_saved&&!s.remembered);
  $('rememberNote').textContent=s.remembered?'A token is stored in your user config folder.':'';
  $('connErr').textContent=s.state==='disconnected'||s.state==='connected'?(s.error||''):(s.error||(s.state==='reconnecting'?'Connection lost, trying again...':''));
  $('openBtn').disabled=s.state!=='connected';
  $('nTunnels').textContent=s.tunnels.length;
  $('stReq').textContent=s.stats.requests;$('stErr').textContent=s.stats.errors;$('stIn').textContent=fb(s.stats.bytes_in);$('stOut').textContent=fb(s.stats.bytes_out);
  var j=JSON.stringify(s.tunnels);if(j!==tunJSON){tunJSON=j;renderTunnels(s.tunnels)}
}
function renderTunnels(list){
  var h='';
  list.forEach(function(t){
    var addr=t.type==='tcp'?(t.url||('port '+t.port)):t.url;
    var link=t.type==='http'?'<a href="'+esc(t.url)+'" target="_blank" rel="noopener noreferrer">'+esc(t.url)+'</a>':esc(addr);
    h+='<tr><td>'+esc(t.type.toUpperCase())+'</td><td class="m">'+link+' <button class="s" data-copy="'+esc(addr)+'">Copy</button></td><td class="m">'+esc(t.local)+'</td><td>'+(t.expires_at?esc(new Date(t.expires_at).toLocaleTimeString()):'never')+'</td><td><button class="s d" data-close="'+esc(t.id)+'">Close</button></td></tr>';
  });
  $('tbTunnels').innerHTML=h;$('noTunnels').classList.toggle('hide',list.length>0);
}
function poll(){api('GET','/api/state').then(renderState).catch(function(e){$('pill').textContent='UI stopped';$('pill').className='pill bad'});
  if(!$('pause').checked)api('GET','/api/traffic?since='+lastId).then(function(r){
    if(r.last<lastId){rows=[];selected=0}
    if(r.rows&&r.rows.length){rows=rows.concat(r.rows).slice(-500)}
    lastId=r.last;if(r.rows&&r.rows.length)renderTraffic();$('nTraffic').textContent=rows.length;
  }).catch(function(){});
}
$('connectBtn').onclick=function(){
  $('connErr').textContent='';var b=$('connectBtn');b.disabled=true;
  var p=state&&state.state!=='disconnected'?api('POST','/api/disconnect'):api('POST','/api/connect',{server:$('server').value,token:$('token').value,remember:$('remember').checked});
  p.then(function(s){$('token').value='';renderState(s)}).catch(function(e){$('connErr').textContent=e.message}).then(function(){b.disabled=false});
};
$('forgetBtn').onclick=function(){if(confirm('Delete the saved server and token from this computer?'))api('POST','/api/forget').then(function(s){$('remember').checked=false;renderState(s)}).catch(function(e){$('connErr').textContent=e.message})};

/* ---- tunnels ---- */
function setType(t){type=t;[].forEach.call($('type').children,function(b){b.classList.toggle('on',b.dataset.v===t)});
  $('subWrap').classList.toggle('hide',t!=='http');[].forEach.call(document.querySelectorAll('[data-http]'),function(e){e.classList.toggle('hide',t!=='http')})}
[].forEach.call($('type').children,function(b){b.onclick=function(){setType(b.dataset.v)}});
$('openBtn').onclick=function(){
  $('openErr').textContent='';var b=$('openBtn');b.disabled=true;
  api('POST','/api/tunnels',{type:type,local:$('local').value,subdomain:$('sub').value,auth:$('auth').value,pin:$('pin').value,allow:$('allow').value,domain:$('domain').value,ttl:$('ttl').value,inspect:$('inspect').checked})
  .then(function(){poll()}).catch(function(e){$('openErr').textContent=e.message}).then(function(){b.disabled=!state||state.state!=='connected'});
};
$('tbTunnels').onclick=function(e){
  var c=e.target.getAttribute('data-copy'),x=e.target.getAttribute('data-close');
  if(c){copy(c);e.target.textContent='Copied';setTimeout(function(){e.target.textContent='Copy'},1000)}
  if(x)api('DELETE','/api/tunnels/'+encodeURIComponent(x)).then(poll).catch(function(er){$('openErr').textContent=er.message});
};
function legacyCopy(t){var a=document.createElement('textarea');a.value=t;a.style.position='fixed';a.style.left='-9999px';document.body.appendChild(a);a.select();try{document.execCommand('copy')}catch(e){}document.body.removeChild(a)}
function copy(t){if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).catch(function(){legacyCopy(t)})}else{legacyCopy(t)}}

/* ---- traffic ---- */
function sc(r){if(r.error)return's5';return r.status?'s'+String(r.status)[0]:''}
function renderTraffic(){
  var q=$('filter').value.toLowerCase(),sf=$('statusF').value,h='',n=0;
  for(var i=rows.length-1;i>=0&&n<300;i--){
    var r=rows[i];
    if(sf==='e'){if(!(r.error||r.status>=500))continue}else if(sf&&String(r.status||'')[0]!==sf)continue;
    var label=r.kind==='tcp'?'TCP':(r.kind==='websocket'?'WS':r.method);
    var text=(label+' '+(r.path||'')+' '+(r.remote||'')+' '+(r.tunnel||'')).toLowerCase();
    if(q&&text.indexOf(q)<0)continue;
    n++;
    h+='<tr class="x'+(r.id===selected?' sel':'')+'" data-id="'+r.id+'"><td class="m">'+ft(r.time)+'</td><td class="meth">'+esc(label)+'</td><td class="m p" title="'+esc(r.path||'')+'">'+esc(r.path||(r.kind==='tcp'?'connection':''))+'</td><td class="'+sc(r)+'">'+(r.error?'unreachable':(r.status||'-'))+'</td><td>'+r.ms+'</td><td>'+fb(r.bytes_in)+'</td><td>'+fb(r.bytes_out)+'</td><td class="m">'+esc(r.remote||'')+'</td></tr>';
  }
  $('tbTraffic').innerHTML=h;$('noTraffic').classList.toggle('hide',rows.length>0);
}
$('filter').oninput=renderTraffic;$('statusF').onchange=renderTraffic;
$('clearBtn').onclick=function(){api('DELETE','/api/traffic').then(function(){rows=[];lastId=0;selected=0;$('detail').classList.add('hide');renderTraffic();$('nTraffic').textContent=0;poll()})};
$('tbTraffic').onclick=function(e){var tr=e.target.closest('tr');if(!tr)return;selected=parseInt(tr.dataset.id,10);renderTraffic();showDetail(selected)};
function kv(h){var o='';Object.keys(h||{}).sort().forEach(function(k){o+='<div><span>'+esc(k)+'</span><span>'+esc(h[k].join(', '))+'</span></div>'});return o||'<div><span>(none)</span></div>'}
function body(m){
  if(m.binary)return'<pre>binary data, '+m.body_bytes+' bytes kept</pre>';
  if(!m.body)return'<pre>(empty)</pre>';
  var t=m.body,ct=((m.headers['Content-Type']||[])[0]||'').toLowerCase();
  if(ct.indexOf('json')>=0){try{t=JSON.stringify(JSON.parse(t),null,2)}catch(e){}}
  return'<pre>'+esc(t)+'</pre>'+(m.truncated?'<div class="note">Only the first part of the body is kept.</div>':'');
}
var cur=null;
function showDetail(id){
  api('GET','/api/traffic/'+id).then(function(d){
    cur=d;var el=$('detail');el.classList.remove('hide');
    var head=d.kind==='http'?esc(d.method)+' '+esc(d.path):(d.kind==='tcp'?'TCP connection':'WebSocket '+esc(d.path));
    var st=d.error?'<span class="s5">local service unreachable: '+esc(d.error)+'</span>':(d.status?'<span class="'+sc(d)+'">'+d.status+'</span>':'');
    el.innerHTML='<div class="ttl">'+head+' '+st+'</div><div class="note" style="margin:0 0 .75rem">'+esc(new Date(d.time).toLocaleString())+' &middot; '+d.ms+' ms &middot; '+fb(d.bytes_in)+' in, '+fb(d.bytes_out)+' out &middot; via '+esc(d.tunnel)+' &rarr; '+esc(d.local)+(d.remote?' &middot; from '+esc(d.remote):'')+'</div>'
     +(d.kind==='http'?'<div class="row" style="margin-bottom:.75rem"><button class="s" id="replayBtn">Replay to local service</button><button class="s" id="curlBtn">Copy as curl</button></div><div id="replayOut"></div>':'')
     +(d.kind==='tcp'?'':'<div class="cols"><div><h2>Request</h2><div class="kv">'+kv(d.request.headers)+'</div>'+body(d.request)+'</div><div><h2>Response</h2><div class="kv">'+kv(d.response.headers)+'</div>'+body(d.response)+'</div></div>');
    if(d.kind==='http'){$('replayBtn').onclick=replay;$('curlBtn').onclick=function(){copy(curl(cur));$('curlBtn').textContent='Copied';setTimeout(function(){$('curlBtn').textContent='Copy as curl'},1000)}}
    el.scrollIntoView({block:'nearest'});
  }).catch(function(e){var el=$('detail');el.classList.remove('hide');el.innerHTML='<div class="err">'+esc(e.message)+'</div>'});
}
function q1(s){return"'"+String(s).replace(/'/g,"'\\''")+"'"}
function curl(d){
  var s='curl -i -X '+d.method+' '+q1('http://'+d.local+d.path);
  var skip={'content-length':1,'connection':1,'accept-encoding':1,'x-forwarded-for':1,'x-forwarded-proto':1,'x-forwarded-host':1};
  Object.keys(d.request.headers||{}).forEach(function(k){if(!skip[k.toLowerCase()])d.request.headers[k].forEach(function(v){s+=' -H '+q1(k+': '+v)})});
  if(d.request.body)s+=' --data-binary '+q1(d.request.body);
  return s;
}
function replay(){
  var out=$('replayOut');out.innerHTML='<div class="note">Sending...</div>';
  api('POST','/api/traffic/'+cur.id+'/replay').then(function(r){
    if(r.error){out.innerHTML='<div class="err">Replay failed: '+esc(r.error)+'</div>';return}
    out.innerHTML='<div class="ttl">Replay result: <span class="'+sc(r)+'">'+r.status+'</span> in '+r.ms+' ms <span class="note">(sent to '+esc(r.local)+', not through the tunnel)</span></div><div class="cols"><div class="kv">'+kv(r.response.headers)+'</div><div>'+body(r.response)+'</div></div>';
  }).catch(function(e){out.innerHTML='<div class="err">'+esc(e.message)+'</div>'});
}

/* ---- tabs ---- */
[].forEach.call(document.querySelectorAll('.tab'),function(t){t.onclick=function(){
  tab=t.dataset.t;[].forEach.call(document.querySelectorAll('.tab'),function(x){x.classList.toggle('on',x===t)});
  $('tunnels').classList.toggle('hide',tab!=='tunnels');$('traffic').classList.toggle('hide',tab!=='traffic');if(tab==='traffic')renderTraffic();
}});
setType('http');poll();setInterval(poll,1000);
})();
</script></body></html>`
