'use strict';
const crypto=require('node:crypto');
const {verifyReceipt}=require('./owner-approval-receipt.cjs');
function createBuildWiseOwnerApproval({token,installationId,publicBlob,base='http://127.0.0.1:7331',fetcher=fetch,now=Date.now}={}){
 const url=new URL(base);
 if(url.protocol!=='http:'||url.hostname!=='127.0.0.1'||url.username||url.password||url.pathname!=='/'||url.search||url.hash||typeof token!=='string'||token.length<32||! /^[a-f0-9]{32}$/.test(installationId)||!Buffer.isBuffer(publicBlob)||publicBlob.length!==72)throw Error('PINNED_BUILDWISE_APPROVAL_REQUIRED');
 const pinned=Buffer.from(publicBlob);
 return async function requestApproval(input,signal){
  const startedAt=now(),request={...input,nonce:crypto.randomBytes(32).toString('base64url')};
  if(input?.action!=='health.check'||signal?.aborted)throw Error('OWNER_APPROVAL_DENIED');
  const response=await fetcher(url.origin+'/api/vault/owner-approval',{method:'POST',headers:{'X-Factory-Token':token,'Content-Type':'application/json'},body:JSON.stringify(request),signal:signal?AbortSignal.any([signal,AbortSignal.timeout(65000)]):AbortSignal.timeout(65000),redirect:'error'});
  if(!response.ok||signal?.aborted)throw Error('OWNER_APPROVAL_DENIED');
  const received=await response.json(),verified=verifyReceipt({receipt:received.receipt,publicBlob:pinned,installationId,request,startedAt,now:now()});
  if(!verified||received.authorized!==verified.authorized)throw Error('SIGNED_OWNER_APPROVAL_REQUIRED');
  return verified;
 };
}
module.exports={createBuildWiseOwnerApproval};
