'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),http=require('node:http'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {createBuildWiseVaultStatus}=require('../buildwise-vault-status.cjs'),{createBuildWiseSessionVerifier}=require('../buildwise-owner-session.cjs'),{createGateway}=require('../owner-gateway.cjs');
const sample={available:true,authenticatedBroker:true,ownerEnrolled:false,privilegedCommandsEnabled:false,ownerApprovalRequired:true};
const listen=server=>new Promise(resolve=>server.listen(0,'127.0.0.1',()=>resolve('http://127.0.0.1:'+server.address().port)));
const close=server=>new Promise(resolve=>{server.close(resolve);server.closeAllConnections();});
test('bridge accepts only loopback, verified status and disabled privileged controls',async()=>{
 for(const base of ['https://example.com','http://localhost:7331','http://127.0.0.1/path','http://user:pass@127.0.0.1'])assert.throws(()=>createBuildWiseVaultStatus({base}),/LOOPBACK/);
 for(const r of [{...sample,privilegedCommandsEnabled:true},{...sample,ownerApprovalRequired:false},{...sample,available:false},{...sample,authorized:true}]){
  const status=createBuildWiseVaultStatus({fetcher:async()=>({ok:true,json:async()=>r})});await assert.rejects(status('t'.repeat(32)),/STATUS_DENIED/);
 }
});
test('Atlas reads authenticated BuildWise status without converting enrollment into an approval',async()=>{
 const token=crypto.randomBytes(32).toString('hex'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'atlas-vault-'));let healthCalls=0,ownerCalls=0;
 const upstream=http.createServer((req,res)=>{
  assert.equal(req.headers['x-factory-token'],token);res.setHeader('content-type','application/json');
  if(req.url==='/api/control-center/status')res.end(JSON.stringify({session:{authenticated:true}}));
  else if(req.url==='/api/vault/status')res.end(JSON.stringify(sample));else{res.statusCode=404;res.end('{}');}
 });
 let gateway;
 try{
  const base=await listen(upstream);gateway=createGateway({token,auditPath:path.join(dir,'audit.jsonl'),verifyBuildWiseSession:createBuildWiseSessionVerifier({base}),getVaultStatus:createBuildWiseVaultStatus({base}),authorizeOwner:async()=>{ownerCalls++;return false;},fetcher:async()=>{healthCalls++;return {ok:true,json:async()=>({ok:true})};}});
  const url=await listen(gateway);
  const send=(action,extra={})=>fetch(url+'/atlas/command',{method:'POST',headers:{Origin:'https://prowumpus54.github.io',Authorization:'Bearer '+token,'Content-Type':'application/json','X-Atlas-Request-Id':crypto.randomUUID()},body:JSON.stringify({action,...extra})});
  let response=await send('vault.status');assert.equal(response.status,200);assert.deepEqual((await response.json()).vault,sample);assert.equal(ownerCalls,0);
  response=await send('health.check');assert.equal(response.status,403);assert.equal(ownerCalls,1);assert.equal(healthCalls,0);
  response=await send('vault.status',{authorized:true});assert.equal(response.status,503);
  response=await send('vault.unlock');assert.equal(response.status,403);
  assert.equal(fs.readFileSync(path.join(dir,'audit.jsonl'),'utf8').includes(token),false);
 }finally{if(gateway)await close(gateway);await close(upstream);fs.rmSync(dir,{recursive:true,force:true});}
});
test('vault status cannot run with a missing BuildWise session verifier',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'atlas-vault-')),token='x'.repeat(32);let calls=0;
 const gateway=createGateway({token,auditPath:path.join(dir,'audit.jsonl'),getVaultStatus:async()=>{calls++;return sample;}});
 try{const base=await listen(gateway),r=await fetch(base+'/atlas/command',{method:'POST',headers:{Origin:'https://prowumpus54.github.io',Authorization:'Bearer '+token,'Content-Type':'application/json','X-Atlas-Request-Id':crypto.randomUUID()},body:'{"action":"vault.status"}'});assert.equal(r.status,503);assert.equal(calls,0);}
 finally{await close(gateway);fs.rmSync(dir,{recursive:true,force:true});}
});
