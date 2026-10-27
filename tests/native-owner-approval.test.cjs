'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {createBuildWiseOwnerApproval}=require('../buildwise-owner-approval.cjs');
const {createOwnerApprovalGate}=require('../owner-approval-gate.cjs');
const key=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'}),jwk=key.publicKey.export({format:'jwk'}),publicBlob=Buffer.alloc(72),installationId='a'.repeat(32);
publicBlob.writeUInt32LE(0x31534345,0);publicBlob.writeUInt32LE(32,4);Buffer.from(jwk.x,'base64url').copy(publicBlob,8);Buffer.from(jwk.y,'base64url').copy(publicBlob,40);
const token=crypto.randomBytes(32).toString('hex');
const input=()=>({action:'health.check',requestId:crypto.randomUUID(),expiresAt:61000});
function receipt(r,decision='approved',change=x=>x){
 const fields=change(['BUILDWISE-OWNER-ACTION-RECEIPT-V1',installationId,'atlas',r.action,'buildwise-local-health',r.requestId,r.nonce,'1001',String(r.expiresAt),decision,'privileged-disabled']),body=JSON.stringify(fields);
 return {body,signature:crypto.sign('sha256',Buffer.from(body),{key:key.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64')};
}
test('Atlas requires a pinned broker and loopback authenticated BuildWise',()=>{
 for(const options of [{},{token,installationId,publicBlob,base:'https://example.com'},{token,installationId,publicBlob:Buffer.alloc(2)}])assert.throws(()=>createBuildWiseOwnerApproval(options));
});
test('trusted approval gate accepts only a signed fresh exact-request receipt',async()=>{
 let time=1000,calls=0;
 const issuer=createBuildWiseOwnerApproval({token,installationId,publicBlob,now:()=>time,fetcher:async(url,options)=>{
  calls++;assert.equal(url,'http://127.0.0.1:7331/api/vault/owner-approval');assert.equal(options.headers['X-Factory-Token'],token);assert.equal(options.redirect,'error');
  const r=JSON.parse(options.body);assert.match(r.nonce,/^[A-Za-z0-9_-]{43}$/);time=1002;
  return {ok:true,json:async()=>({authorized:true,receipt:receipt(r)})};
 }});
 const gate=createOwnerApprovalGate({requestApproval:issuer,now:()=>time});assert.equal(await gate({action:'health.check',requestId:crypto.randomUUID()}),true);assert.equal(calls,1);
});
test('HTTP booleans, receipt substitutions, expiry, and request/target tampering deny',async()=>{
 const cases=[
  r=>({authorized:true}),
  r=>({authorized:true,receipt:receipt(r,'approved',a=>{a[6]='x'.repeat(43);return a;})}),
  r=>({authorized:true,receipt:receipt(r,'approved',a=>{a[4]='credential';return a;})}),
  r=>({authorized:true,receipt:receipt(r,'approved',a=>{a[5]=crypto.randomUUID();return a;})}),
  r=>({authorized:false,receipt:receipt(r)}),
  r=>({authorized:true,receipt:{...receipt(r),signature:Buffer.alloc(64).toString('base64')}})
 ];
 for(const response of cases){
  let time=1000;const issuer=createBuildWiseOwnerApproval({token,installationId,publicBlob,now:()=>time,fetcher:async(u,o)=>{const r=JSON.parse(o.body);time=1002;return {ok:true,json:async()=>response(r)};}});
  await assert.rejects(issuer(input()));
 }
});
test('valid signed denial remains denied and unavailable/cancelled owner requests cannot authorize',async()=>{
 let time=1000;const issuer=createBuildWiseOwnerApproval({token,installationId,publicBlob,now:()=>time,fetcher:async(u,o)=>{const r=JSON.parse(o.body);time=1002;return {ok:true,json:async()=>({authorized:false,receipt:receipt(r,'denied')})};}});
 assert.equal((await issuer(input())).authorized,false);
 const controller=new AbortController();controller.abort();await assert.rejects(issuer(input(),controller.signal));
 const unavailable=createBuildWiseOwnerApproval({token,installationId,publicBlob,fetcher:async()=>({ok:false})});await assert.rejects(unavailable(input()));
});

