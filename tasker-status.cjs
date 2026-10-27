'use strict';
const ENDPOINT='https://us-central1-flowwise-fe645.cloudfunctions.net/taskerApi/v1/inbox?limit=1';
function createTaskerStatus({fetcher=fetch,tokenProvider}={}){
 if(typeof tokenProvider!=='function')throw Error('SCOPED_TASKER_TOKEN_PROVIDER_REQUIRED');
 return async function check(){
  const token=await tokenProvider();
  if(typeof token!=='string'||token.length<32)throw Error('TASKER_CREDENTIAL_UNAVAILABLE');
  let response;
  try{response=await fetcher(ENDPOINT,{method:'GET',headers:{authorization:'Bearer '+token,accept:'application/json'},redirect:'error',signal:AbortSignal.timeout(5000)})}
  catch{throw Error('TASKER_UNREACHABLE')}
  if(response.status===401||response.status===403)return Object.freeze({reachable:true,authorized:false});
  if(response.status!==200)throw Error('TASKER_STATUS_UNAVAILABLE');
  // Do not consume the response: inbox data is private and not Atlas telemetry.
  response.body?.cancel?.().catch?.(()=>{});
  return Object.freeze({reachable:true,authorized:true});
 };
}
module.exports={createTaskerStatus};
