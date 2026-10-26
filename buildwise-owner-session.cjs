'use strict';
const {createGateway}=require('./owner-gateway.cjs');
// Verify an existing BuildWise session with its authoritative session status.
// This is not enrollment and never exposes the server's factory token.
function createBuildWiseSessionVerifier({fetcher=fetch,base='http://127.0.0.1:7331'}={}){
 return async function verify(candidate){
  if(typeof candidate!=='string'||candidate.length<16)return false;
  try{
   const response=await fetcher(base+'/api/control-center/status',{headers:{'X-Factory-Token':candidate},signal:AbortSignal.timeout(3000)});
   if(!response.ok)return false;
   const result=await response.json();
   return result?.session?.authenticated===true;
  }catch{return false}
 };
}
module.exports={createBuildWiseSessionVerifier};
