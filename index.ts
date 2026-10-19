import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
const env=(k:string)=>Deno.env.get(k)||"";
const url=env("SUPABASE_URL"), service=env("SUPABASE_SERVICE_ROLE_KEY");
const appId=env("FB_APP_ID"), secret=env("FB_APP_SECRET");
const callback=env("FB_REDIRECT_URI");
const site=env("LIVEPRINT_SITE_URL");
const graph=env("FB_GRAPH_VERSION")||"v23.0";
const admin=createClient(url,service,{auth:{persistSession:false}});
const cors={"Access-Control-Allow-Origin":site,"Access-Control-Allow-Headers":"authorization, apikey, content-type","Access-Control-Allow-Methods":"POST, GET, OPTIONS"};
const json=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{...cors,"Content-Type":"application/json"}});
const redirect=(params:Record<string,string>)=>{
 const u=new URL(site); for(const [k,v] of Object.entries(params))u.searchParams.set(k,v);
 return Response.redirect(u.toString(),302);
};
async function graphGet(path:string,token:string){
 const r=await fetch(`https://graph.facebook.com/${graph}/${path}`,{headers:{Authorization:`Bearer ${token}`}});
 const d=await r.json(); if(!r.ok)throw Error(d.error?.message||"Meta API error");return d;
}
Deno.serve(async req=>{
 if(req.method==="OPTIONS")return new Response(null,{headers:cors});
 if(!url||!service||!appId||!secret||!callback||!site)return json({error:"Thiếu cấu hình Meta / Supabase trên máy chủ"},503);
 const parsed=new URL(req.url);
 if(req.method==="GET"&&parsed.searchParams.has("code")){
  const state=parsed.searchParams.get("state")||"";
  const code=parsed.searchParams.get("code")||"";
  const {data:record}=await admin.from("lp_facebook_oauth_states").select("*").eq("state",state).maybeSingle();
  if(!record||new Date(record.expires_at).getTime()<Date.now())return redirect({fb_error:"invalid_state"});
  await admin.from("lp_facebook_oauth_states").delete().eq("state",state);
  try{
   const t=new URL(`https://graph.facebook.com/${graph}/oauth/access_token`);
   t.searchParams.set("client_id",appId);t.searchParams.set("client_secret",secret);
   t.searchParams.set("redirect_uri",callback);t.searchParams.set("code",code);
   const tr=await fetch(t);const td=await tr.json();
   if(!tr.ok||!td.access_token)throw Error(td.error?.message||"Không lấy được access token");
   const pages=await graphGet("me/accounts?fields=id,name,access_token&limit=100",td.access_token);
   const candidates=(pages.data||[]).filter((x:any)=>x.access_token);
   const selected=record.page_id?candidates.find((x:any)=>x.id===record.page_id):(candidates.length===1?candidates[0]:null);
   if(!selected)return redirect({fb_error:"choose_page_id",fb_pages:String(candidates.length)});
   const {error}=await admin.from("lp_facebook_connections").upsert({
    shop_id:record.shop_id,page_id:selected.id,page_name:selected.name,
    page_access_token:selected.access_token,connected_by:record.user_id,connected_at:new Date().toISOString()
   },{onConflict:"shop_id"});
   if(error)throw error;
   return redirect({fb_connected:"1"});
  }catch(e){return redirect({fb_error:"oauth_failed"});}
 }
 if(req.method!=="POST")return json({error:"Method not allowed"},405);
 try{
  const bearer=(req.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"");
  const auth=createClient(url,env("SUPABASE_ANON_KEY"),{auth:{persistSession:false}});
  const {data:{user},error:userError}=await auth.auth.getUser(bearer);
  if(userError||!user)return json({error:"Bạn chưa đăng nhập"},401);
  const body=await req.json();
  if(body.provider!=="facebook")return json({error:"Kênh chưa được hỗ trợ"},400);
  const shopId=String(body.shop_id||"");
  const {data:membership,error:memberError}=await admin.from("lp_members")
   .select("shop_id").eq("shop_id",shopId).eq("user_id",user.id).maybeSingle();
  if(memberError||!membership)return json({error:"Bạn không có quyền quản lý shop"},403);
  if(body.action==="status"){
   const {data}=await admin.from("lp_facebook_connections").select("page_id,page_name").eq("shop_id",shopId).maybeSingle();
   return json({connected:!!data,display_name:data?.page_name||null,page_id:data?.page_id||null});
  }
  if(body.action==="authorize"){
   const pageId=String(body.page_id||"").trim();
   if(pageId&&!/^\d{5,30}$/.test(pageId))return json({error:"ID Page chỉ gồm chữ số"},400);
   const state=crypto.randomUUID()+"-"+crypto.randomUUID();
   const {error}=await admin.from("lp_facebook_oauth_states").insert({state,shop_id:shopId,user_id:user.id,page_id:pageId||null});
   if(error)throw error;
   const u=new URL(`https://www.facebook.com/${graph}/dialog/oauth`);
   u.searchParams.set("client_id",appId);u.searchParams.set("redirect_uri",callback);
   u.searchParams.set("state",state);
   u.searchParams.set("scope","pages_show_list,pages_read_engagement,pages_read_user_content,pages_manage_metadata");
   u.searchParams.set("response_type","code");
   return json({authorization_url:u.toString()});
  }
  return json({error:"Thao tác không hợp lệ"},400);
 }catch(e){return json({error:String(e instanceof Error?e.message:e)},500);}
});
