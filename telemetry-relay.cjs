'use strict';
const http=require('node:http'),crypto=require('node:crypto');
function equal(a,b){const x=crypto.createHash('sha256').update(String(a)).digest(),y=crypto.createHash('sha256').update(String(b)).digest();return crypto.timingSafeEqual(x,y)}
function createTelemetryRelay({publisherToken,viewerToken,ttlMs=30000,now=Date.now}={}){
 if(typeof publisherToken!=='string'||publisherToken.length<32||typeof viewerToken!=='string'||viewerToken.length<32||equal(publisherToken,viewerToken))throw Error('DISTINCT_RELAY_CREDENTIALS_REQUIRED');
 let latest=null,receivedAt=0,deliveryId=null;
 function reply(res,status,data){res.writeHead(status,{'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff'});res.end(JSON.stringify(data))}
 return http.createServer(async(req,res)=>{
  const address=req.socket.remoteAddress;
  if(address!=='127.0.0.1'&&address!=='::1'&&address!=='::ffff:127.0.0.1'){reply(res,403,{error:'loopback only'});return}
  const bearer=String(req.headers.authorization||'');
  if(req.method==='POST'&&req.url==='/v1/ingest'){
   if(!bearer.startsWith('Bearer ')||!equal(bearer.slice(7),publisherToken)){reply(res,401,{error:'unauthorized'});return}
   const id=String(req.headers['x-atlas-delivery-id']||'');
   if(!/^[a-f0-9-]{36}$/.test(id)){reply(res,400,{error:'invalid delivery ID'});return}
   let chunks=[],size=0;for await(const chunk of req){size+=chunk.length;if(size>262144){reply(res,413,{error:'payload too large'});return}chunks.push(chunk)}
   let payload;try{payload=JSON.parse(Buffer.concat(chunks).toString('utf8'))}catch{reply(res,400,{error:'invalid JSON'});return}
   if(payload?.schema!=='buildwise.atlas.snapshot.v1'||!Number.isFinite(Date.parse(payload.sentAt))||Math.abs(now()-Date.parse(payload.sentAt))>60000){reply(res,400,{error:'invalid or stale snapshot'});return}
   const allowed=new Set(['schema','sentAt','source','sampledAt','totalJobs','activeJobs','errors','jobs','agents','events','resources']);
   if(Object.keys(payload).some(k=>!allowed.has(k))){reply(res,400,{error:'unexpected fields'});return}
   if(deliveryId===id){reply(res,409,{error:'duplicate delivery'});return}
   latest=payload;receivedAt=now();deliveryId=id;reply(res,202,{accepted:true});return
  }
  if(req.method==='GET'&&req.url==='/v1/snapshot'){
   if(!bearer.startsWith('Bearer ')||!equal(bearer.slice(7),viewerToken)){reply(res,401,{error:'unauthorized'});return}
   if(!latest||now()-receivedAt>ttlMs){reply(res,404,{error:'no fresh snapshot'});return}
   reply(res,200,{...latest,receivedAt:new Date(receivedAt).toISOString()});return
  }
  reply(res,404,{error:'not found'});
 });
}
module.exports={createTelemetryRelay};
if(require.main===module){console.error('Relay disabled: deploy only behind reviewed TLS and authenticated edge configuration.');process.exitCode=1}
