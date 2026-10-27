'use strict';
const {createGateway}=require('./owner-gateway.cjs');
const {createBuildWiseSessionVerifier}=require('./buildwise-owner-session.cjs');
const {createBuildWiseVaultStatus}=require('./buildwise-vault-status.cjs');
// This launcher connects status only. Health commands require a future live owner issuer.
function start({token=process.env.ATLAS_OWNER_TOKEN,port=7336}={}){
 const server=createGateway({token,verifyBuildWiseSession:createBuildWiseSessionVerifier(),getVaultStatus:createBuildWiseVaultStatus(),authorizeOwner:async()=>false});
 server.listen(port,'127.0.0.1');return server;
}
if(require.main===module){try{start();}catch{console.error('Atlas status gateway unavailable: configure an existing BuildWise session first.');process.exitCode=1;}}
module.exports={start};
