// Supabase Edge Function: lp-tiktok-connect
// TikTok Login Kit OAuth v2. This does NOT grant access to LIVE comments.
import {createClient} from 'https://esm.sh/@supabase/supabase-js@2';
const get=(n:string)=>Deno.env.get(n)||'';
const site=get('LIVEPRINT_SITE_URL');
const siteOrigin=site?new URL(site).origin:'';
const supa=createClient(get('SUPABASE_URL'),get('SUPABASE_SERVICE_ROLE_KEY'),{auth:{persistSession:false}});
const cors={'Access-Control-Allow-Origin':siteOrigin,'Access-Control-Allow-Headers':'authorization,apikey,content-type','Access-Control-Allow-Methods':'GET,POST,OPTIONS'};
const respond=(v:unknown,code=200)=>new Response(JSON.stringify(v),{status:code,headers:{...cors,'Content-Type':'application/json'}});
const go=(k:string,v:string)=>{const u=new URL(site);u.searchParams.set(k,v);return Response.redirect(u,302)};
const key=get('TIKTOK_CLIENT_KEY'),secret=get('TIKTOK_CLIENT_SECRET'),redirect=get('TIKTOK_REDIRECT_URI');
Deno.serve(async req=>{
 if(req.method==='OPTIONS')return new Response(null,{headers:cors});
 if(!key||!secret||!redirect||!site)return respond({error:'Thiếu cấu hình TikTok'},503);
 const url=new URL(req.url);
 if(req.method==='GET'){
  const code=url.searchParams.get('code'),state=url.searchParams.get('state');
  if(!code||!state)return go('tt_error','missing_code');
  const {data:record}=await supa.from('lp_tiktok_oauth_states').select('*').eq('state',state).maybeSingle();
  if(!record||new Date(record.expires_at).getTime()<Date.now())return go('tt_error','invalid_state');
  await supa.from('lp_tiktok_oauth_states').delete().eq('state',state);
  try{
   const params=new URLSearchParams({client_key:key,client_secret:secret,code,grant_type:'authorization_code',redirect_uri:redirect,code_verifier:record.code_verifier});
   const res=await fetch('https://open.tiktokapis.com/v2/oauth/token/',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:params});
   const token=await res.json();if(!res.ok||!token.access_token)throw Error('TikTok token exchange failed');
   const infoRes=await fetch('https://open.tiktokapis.com/v2/user/info/?fields=open_id,display_name',{headers:{Authorization:'Bearer '+token.access_token}});
   const info=await infoRes.json();if(!infoRes.ok)throw Error('TikTok profile read failed');
   const user=info.data?.user||{};
   const {error}=await supa.from('lp_tiktok_connections').upsert({shop_id:record.shop_id,connected_by:record.user_id,open_id:user.open_id||token.open_id,display_name:user.display_name||null,username:user.username||null,access_token:token.access_token,refresh_token:token.refresh_token||null,expires_at:new Date(Date.now()+Number(token.expires_in||0)*1000).toISOString()},{onConflict:'shop_id'});
   if(error)throw error;
   return go('tt_connected','1');
  }catch(_){return go('tt_error','oauth_failed')}
 }
 if(req.method!=='POST')return respond({error:'Method not allowed'},405);
 try{
  const jwt=(req.headers.get('authorization')||'').replace(/^Bearer\s+/i,'');
  const auth=createClient(get('SUPABASE_URL'),get('SUPABASE_ANON_KEY'),{auth:{persistSession:false}});
  const {data:{user}}=await auth.auth.getUser(jwt);if(!user)return respond({error:'Chưa đăng nhập'},401);
  const body=await req.json();const shopId=String(body.shop_id||'');
  const {data:membership}=await supa.from('lp_members').select('shop_id').eq('shop_id',shopId).eq('user_id',user.id).maybeSingle();
  if(!membership)return respond({error:'Không có quyền truy cập shop'},403);
  if(body.action==='status'){
   const {data}=await supa.from('lp_tiktok_connections').select('display_name,username').eq('shop_id',shopId).maybeSingle();
   return respond({connected:!!data,display_name:data?.username||data?.display_name||null});
  }
  if(body.action!=='authorize')return respond({error:'Invalid action'},400);
  const verifier=Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');
  const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier)));
  const challenge=btoa(String.fromCharCode(...digest)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  const state=crypto.randomUUID();
  const {error}=await supa.from('lp_tiktok_oauth_states').insert({state,shop_id:shopId,user_id:user.id,code_verifier:verifier});
  if(error)throw error;
  const u=new URL('https://www.tiktok.com/v2/auth/authorize/');
  for(const [k,v] of Object.entries({client_key:key,scope:'user.info.basic',response_type:'code',redirect_uri:redirect,state,code_challenge:challenge,code_challenge_method:'S256'}))u.searchParams.set(k,v);
  return respond({authorization_url:u.toString()});
 }catch(e){return respond({error:String(e)},500)}
});
