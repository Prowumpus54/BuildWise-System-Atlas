'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {createTelemetryRelay}=require('../telemetry-relay.cjs');
const pub='synthetic-publisher-secret-01234567890123',view='synthetic-viewer-secret-012345678901234';
test('requires distinct credentials',()=>assert.throws(()=>createTelemetryRelay({publisherToken:pub,viewerToken:pub}),/DISTINCT/));
test('separate roles, stale snapshots, and unexpected fields are denied',async()=>{
 let time=Date.now();const srv=createTelemetryRelay({publisherToken:pub,viewerToken:view,now:()=>time,ttlMs:3000});await new Promise(r=>srv.listen(0,'127.0.0.1',r));
 const url='http://127.0.0.1:'+srv.address().port;const snapshot={schema:'buildwise.atlas.snapshot.v1',sentAt:new Date(time).toISOString(),sampledAt:new Date(time).toISOString(),source:'BuildWise dispatcher',totalJobs:1,activeJobs:1,errors:[],jobs:[],agents:[],events:[],resources:{cpuPercent:null,ramFreeGB:1,ramTotalGB:2}};
 const send=async(tok,payload=snapshot,id=crypto.randomUUID())=>fetch(url+'/v1/ingest',{method:'POST',headers:{authorization:'Bearer '+tok,'x-atlas-delivery-id':id},body:JSON.stringify(payload)});
 const read=async tok=>fetch(url+'/v1/snapshot',{headers:{authorization:'Bearer '+tok}});
 try{
  assert.equal((await read(view)).status,404);
  assert.equal((await send(view)).status,401);
  assert.equal((await send(pub,{...snapshot,owner:{credential:'private'}})).status,400);
  const id=crypto.randomUUID();assert.equal((await send(pub,snapshot,id)).status,202);
  assert.equal((await send(pub,snapshot,id)).status,409);
  assert.equal((await read(pub)).status,401);
  const r=await read(view);assert.equal(r.status,200);assert.equal((await r.json()).activeJobs,1);
  time+=4000;assert.equal((await read(view)).status,404);
  time+=61000;assert.equal((await send(pub)).status,400);
 }finally{await new Promise(r=>srv.close(r))}
});
