const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}});
const bad=(message,status=400)=>json({error:message},status);
const hash=async s=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))).map(x=>x.toString(16).padStart(2,'0')).join('');
const validId=s=>/^[a-f0-9-]{36}$/i.test(s||'');
export default {async fetch(req,env){
 const origin=req.headers.get('Origin');const allowed=(env.ALLOWED_ORIGINS||'').split(',').map(x=>x.trim()).filter(Boolean);const cors={'Access-Control-Allow-Origin':allowed.includes(origin)?origin:'null','Access-Control-Allow-Methods':'GET,POST,OPTIONS','Access-Control-Allow-Headers':'Authorization,Content-Type','Vary':'Origin'};
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers:cors});
 const reply=r=>{let h=new Headers(r.headers);Object.entries(cors).forEach(([k,v])=>h.set(k,v));return new Response(r.body,{status:r.status,headers:h})};
 if(origin&&!allowed.includes(origin))return reply(bad('Origin not allowed',403));
 try{let u=new URL(req.url),parts=u.pathname.split('/').filter(Boolean);
 if(req.method==='POST'&&u.pathname==='/lists'){
 let body=await req.json(),name=String(body.name||'').trim();if(!name||name.length>80)return reply(bad('Invalid name'));
 let id=crypto.randomUUID(),token=crypto.randomUUID()+crypto.randomUUID();await env.DB.prepare('INSERT INTO lists(id,name,token_hash) VALUES(?,?,?)').bind(id,name,await hash(token)).run();return reply(json({id,name,token},201));}
 if(parts[0]!=='lists'||!validId(parts[1]))return reply(bad('Not found',404));
 let id=parts[1],token=(req.headers.get('Authorization')||'').replace(/^Bearer /i,'');if(!token)return reply(bad('Unauthorized',401));
 let list=await env.DB.prepare('SELECT id,name,token_hash FROM lists WHERE id=?').bind(id).first();if(!list||await hash(token)!==list.token_hash)return reply(bad('Unauthorized',401));
 if(req.method==='GET'&&parts.length===2){let rows=await env.DB.prepare('SELECT id,name,quantity,done FROM items WHERE list_id=? ORDER BY created_at,id').bind(id).all();return reply(json({id,name:list.name,items:rows.results.map(i=>({...i,done:!!i.done}))}));}
 if(req.method==='POST'&&parts[2]==='operations'&&parts.length===3){
 let op=await req.json();if(!validId(op.opId))return reply(bad('Invalid operation ID'));
 if(!['add','update','delete','clear'].includes(op.type))return reply(bad('Invalid operation'));
 if(op.type!=='clear'&&!validId(op.id))return reply(bad('Invalid item ID'));
 if(op.type==='add'&&(!String(op.name||'').trim()||String(op.name).length>120||String(op.quantity||'').length>40))return reply(bad('Invalid product'));
 let prior=await env.DB.prepare('SELECT id FROM operations WHERE id=? AND list_id=?').bind(op.opId,id).first();if(prior)return reply(json({ok:true}));
 let statements=[];
 if(op.type==='add')statements.push(env.DB.prepare('INSERT OR IGNORE INTO items(id,list_id,name,quantity) VALUES(?,?,?,?)').bind(op.id,id,op.name.trim(),String(op.quantity||'')));
 if(op.type==='update')statements.push(env.DB.prepare('UPDATE items SET done=? WHERE id=? AND list_id=?').bind(op.done?1:0,op.id,id));
 if(op.type==='delete')statements.push(env.DB.prepare('DELETE FROM items WHERE id=? AND list_id=?').bind(op.id,id));
 if(op.type==='clear')statements.push(env.DB.prepare('DELETE FROM items WHERE list_id=? AND done=1').bind(id));
 statements.push(env.DB.prepare('INSERT OR IGNORE INTO operations(id,list_id) VALUES(?,?)').bind(op.opId,id));await env.DB.batch(statements);return reply(json({ok:true}));}
 return reply(bad('Not found',404));
 }catch(e){return reply(bad('Request failed',500))}
 }};