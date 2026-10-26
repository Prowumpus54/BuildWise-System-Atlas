'use strict';
const crypto=require('node:crypto');
const {snapshot}=require('./atlas-bridge.cjs');
function createTelemetryPublisher({endpoint,token,fetcher=fetch,readSnapshot=snapshot,now=Date.now}={}){
 const url=new URL(endpoint||'https://invalid.example/');
 if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash||url.hostname==='invalid.example'||!token||token.length<32)throw Error('SECURE_RELAY_CONFIGURATION_REQUIRED');
 return async function publish(){
  const data=await readSnapshot();
  // No keys/credentials, raw job objects, or arbitrary metadata forwarded.
  const allowed=['source','sampledAt','totalJobs','activeJobs','errors','jobs','agents','events','resources'];
  const payload={schema:'buildwise.atlas.snapshot.v1',sentAt:new Date(now()).toISOString()};
  for(const key of allowed)if(Object.hasOwn(data,key))payload[key]=data[key];
  const body=JSON.stringify(payload);
  if(Buffer.byteLength(body)>256*1024)throw Error('TELEMETRY_PAYLOAD_TOO_LARGE');
  const id=crypto.randomUUID();
  const response=await fetcher(url.href,{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json','x-atlas-delivery-id':id},body,redirect:'error',signal:AbortSignal.timeout(5000)});
  if(!response.ok)throw Error('TELEMETRY_DELIVERY_FAILED');
  return {delivered:true,id,bytes:Buffer.byteLength(body)};
 };
}
module.exports={createTelemetryPublisher};
