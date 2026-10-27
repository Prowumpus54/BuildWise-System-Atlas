'use strict';
// Authenticated read-only bridge. A status response is never an owner approval.
function createBuildWiseVaultStatus({fetcher=fetch,base='http://127.0.0.1:7331'}={}){
 const url=new URL(base);if(url.protocol!=='http:'||url.hostname!=='127.0.0.1'||url.username||url.password||url.pathname!=='/'||url.search||url.hash)throw Error('LOOPBACK_BUILDWISE_REQUIRED');
 return async function status(token){
  if(typeof token!=='string'||token.length<16)throw Error('BUILDWISE_SESSION_REQUIRED');
  const response=await fetcher(url.origin+'/api/vault/status',{method:'GET',headers:{'X-Factory-Token':token},signal:AbortSignal.timeout(6000),redirect:'error'});
  if(!response.ok)throw Error('VAULT_STATUS_UNAVAILABLE');const r=await response.json();
  if(!r||Object.keys(r).sort().join(',')!=='authenticatedBroker,available,ownerApprovalRequired,ownerEnrolled,privilegedCommandsEnabled'||typeof r.available!=='boolean'||typeof r.authenticatedBroker!=='boolean'||typeof r.ownerEnrolled!=='boolean'||r.privilegedCommandsEnabled!==false||r.ownerApprovalRequired!==true||(!r.available&&(r.authenticatedBroker||r.ownerEnrolled))||r.available!==r.authenticatedBroker)throw Error('VAULT_STATUS_DENIED');
  return Object.freeze({available:r.available,authenticatedBroker:r.authenticatedBroker,ownerEnrolled:r.ownerEnrolled,privilegedCommandsEnabled:false,ownerApprovalRequired:true});
 };
}
module.exports={createBuildWiseVaultStatus};
