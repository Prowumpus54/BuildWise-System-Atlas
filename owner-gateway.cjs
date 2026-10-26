'use strict';
const http=require('node:http'),crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
const ORIGIN='https://prowumpus54.github.io';
const COMMANDS=Object.freeze({'health.check':{method:'GET',path:'/api/health'}});
function safeEqual(a,b){const x=crypto.createHash('sha256').update(String(a)).digest(),y=crypto.createHash('sha256').update(String(b)).digest();return crypto.timingSafeEqual(x,y)}
function createGateway({token,port=7336,upstream='http://127.0.0.1:7331',auditPath=path.join(__dirname,'runtime','atlas-command-audit.jsonl'),fetcher=fetch,verifyBuildWiseSession=null}={}){
 if(typeof token!=='string'||token.length<32)throw Error('ATLAS_OWNER_TOKEN must be a high-entropy secret of at least 32 characters');
 let sequence=0;
 function audit(record){fs.mkdirSync(path.dirname(auditPath),{recursive:true});fs.appendFileSync(auditPath,JSON.stringify({at:new Date().toISOString(),id:crypto.randomUUID(),...record})+'\n',{encoding:'utf8',flag:'a',mode:0o600})}
 function reply(res,status,body){res.writeHead(status,{'content-type':'application/json','cache-control':'no-store','access-control-allow-origin':ORIGIN,'access-control-allow-headers':'authorization, content-type, x-atlas-request-id','access-control-allow-methods':'POST, OPTIONS','vary':'Origin'});res.end(JSON.stringify(body))}
 const server=http.createServer(async(req,res)=>{
  const origin=req.headers.origin||'';
  if(origin!==ORIGIN){audit({action:'unknown',result:'denied-origin'});reply(res,403,{error:'origin denied'});return}
  if(req.method==='OPTIONS'){res.writeHead(204,{'access-control-allow-origin':ORIGIN,'access-control-allow-methods':'POST, OPTIONS','access-control-allow-headers':'authorization, content-type, x-atlas-request-id','vary':'Origin'});res.end();return}
  if(req.method!=='POST'||req.url!=='/atlas/command'){reply(res,404,{error:'not found'});return}
  const bearer=String(req.headers.authorization||'');
  if(!bearer.startsWith('Bearer ')||!safeEqual(bearer.slice(7),token)){audit({action:'unknown',result:'denied-auth'});reply(res,401,{error:'unauthorized'});return}
  const chunks=[];let size=0;for await(const c of req){size+=c.length;if(size>2048){audit({action:'unknown',result:'denied-size'});reply(res,413,{error:'request too large'});return}chunks.push(c)}
  let payload;try{payload=JSON.parse(Buffer.concat(chunks).toString('utf8'))}catch{reply(res,400,{error:'invalid json'});return}
  const action=typeof payload?.action==='string'?payload.action:'invalid',requestId=String(req.headers['x-atlas-request-id']||'').slice(0,72);
  if(!/^[a-zA-Z0-9-]{8,72}$/.test(requestId)){audit({action,result:'denied-request-id'});reply(res,400,{error:'valid request id required'});return}
  if(action!=='health.check'){audit({action:action.slice(0,80),requestId,result:'denied-action'});reply(res,403,{error:'action not authorized'});return}
  if(verifyBuildWiseSession){let authenticated=false;try{authenticated=await verifyBuildWiseSession(bearer.slice(7))}catch{}if(authenticated!==true){audit({action,requestId,result:'denied-buildwise-session'});reply(res,403,{error:'BuildWise session not authorized'});return}}
  try{const r=await fetcher(upstream+'/api/health',{method:'GET',signal:AbortSignal.timeout(3000)});if(!r.ok)throw Error('upstream unavailable');const body=await r.json();audit({action,requestId,result:'success',sequence:++sequence});reply(res,200,{requestId,status:body.ok===true?'healthy':'unhealthy',service:'buildwise',checkedAt:new Date().toISOString()})}
  catch{audit({action,requestId,result:'upstream-failure'});reply(res,503,{error:'health check unavailable',requestId})}
 });
 return server;
}
if(require.main===module){const token=process.env.ATLAS_OWNER_TOKEN;if(!token){console.error('Gateway not started: ATLAS_OWNER_TOKEN is unset. Fail closed.');process.exitCode=1}else createGateway({token}).listen(7336,'127.0.0.1',()=>console.log('Atlas authorized health gateway listening on loopback port 7336'))}
module.exports={createGateway};
