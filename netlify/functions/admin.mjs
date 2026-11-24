import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';
const store=()=>getStore({name:'jana-bookings',consistency:'strong'});
const password=()=>process.env.ADMIN_PASSWORD||'kafkova';
const secret=()=>process.env.ADMIN_SESSION_SECRET||password();
const sign=value=>crypto.createHmac('sha256',secret()).update(value).digest('hex');
const cookieValue=()=>{const value=String(Date.now()+1000*60*60*24*7);return value+'.'+sign(value);};
const authorized=request=>{const cookie=request.headers.get('cookie')||'';const match=cookie.match(/jana_admin=([^;]+)/);if(!match)return false;const parts=match[1].split('.');return Number(parts[0])>Date.now()&&parts[1]===sign(parts[0]);};
const json=(body,init={})=>new Response(JSON.stringify(body),{...init,headers:{'content-type':'application/json; charset=utf-8',...(init.headers||{})}});
export default async request=>{
if(request.method==='POST'&&new URL(request.url).pathname.endsWith('/login')){const data=await request.json();if(!data.password||data.password!==password())return json({error:'Neplatne heslo.'},{status:401});return json({ok:true},{headers:{'set-cookie':'jana_admin='+cookieValue()+'; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800'}});}
const blob=store();if(request.method==='GET'&&new URL(request.url).searchParams.get('public')==='1')return json({blocked:(await blob.get('blocked',{type:'json'}))||[]});
if(!authorized(request))return json({error:'Neprihlaseny administrator.'},{status:401});
if(request.method==='GET')return json({blocked:(await blob.get('blocked',{type:'json'}))||[],bookings:(await blob.get('bookings',{type:'json'}))||[]});
if(request.method!=='POST')return json({error:'Metoda neni podporovana.'},{status:405});
const data=await request.json();if(data.action==='block'||data.action==='unblock'){const blocked=(await blob.get('blocked',{type:'json'}))||[];const next=data.action==='block'?[...new Set([...blocked,data.date])]:blocked.filter(date=>date!==data.date);await blob.setJSON('blocked',next);return json({blocked:next});}return json({error:'Neznama akce.'},{status:400});
};
