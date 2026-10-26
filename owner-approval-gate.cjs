'use strict';
// Atlas approval adapter contract. The injected issuer must be a trusted BuildWise
// owner-approval authority, never a browser-provided boolean or session token.
function createOwnerApprovalGate({requestApproval,now=Date.now,timeoutMs=60000}={}){
 if(typeof requestApproval!=='function')throw Error('TRUSTED_OWNER_APPROVAL_ISSUER_REQUIRED');
 return async function authorize({action,requestId,signal}={}){
  if(action!=='health.check'||typeof requestId!=='string'||!requestId) return false;
  if(signal?.aborted)return false;
  const expiry=now()+timeoutMs,controller=new AbortController();
  const onAbort=()=>controller.abort();signal?.addEventListener('abort',onAbort,{once:true});
  try {
   const approval=await requestApproval(Object.freeze({action,requestId,expiresAt:expiry}),controller.signal);
   return !controller.signal.aborted && now()<expiry && approval?.authorized===true &&
     approval?.action===action && approval?.requestId===requestId &&
     Number.isFinite(approval?.expiresAt) && approval.expiresAt===expiry;
  }catch{return false}finally{signal?.removeEventListener('abort',onAbort)}
 };
}
module.exports={createOwnerApprovalGate};
