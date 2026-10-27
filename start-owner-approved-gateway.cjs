'use strict';
const fs=require('node:fs'),path=require('node:path');
const {createGateway}=require('./owner-gateway.cjs');
const {createBuildWiseSessionVerifier}=require('./buildwise-owner-session.cjs');
const {createBuildWiseVaultStatus}=require('./buildwise-vault-status.cjs');
const {createBuildWiseOwnerApproval}=require('./buildwise-owner-approval.cjs');
const {createOwnerApprovalGate}=require('./owner-approval-gate.cjs');
function start({token=process.env.ATLAS_OWNER_TOKEN,port=7336}={}){
 if(process.platform!=='win32')throw Error('PROTECTED_WINDOWS_INSTALLATION_REQUIRED');
 const file=path.join(process.env.ProgramFiles||'C:\\Program Files','BuildWiseVault','broker-config.json'),bytes=fs.readFileSync(file);if(bytes.length>4096)throw Error();
 const config=JSON.parse(bytes.toString());
 if(!Array.isArray(config)||config.length!==10||config[0]!=='BUILDWISE-PROTECTED-VAULT-SETUP-V1'||config[7]!=='sealed')throw Error();
 const requestApproval=createBuildWiseOwnerApproval({token,installationId:config[1],publicBlob:Buffer.from(config[8],'base64')});
 const server=createGateway({token,verifyBuildWiseSession:createBuildWiseSessionVerifier(),getVaultStatus:createBuildWiseVaultStatus(),authorizeOwner:createOwnerApprovalGate({requestApproval})});
 server.listen(port,'127.0.0.1');return server;
}
if(require.main===module){try{start();}catch{console.error('Atlas owner gateway unavailable: protected vault and existing BuildWise session are required.');process.exitCode=1;}}
module.exports={start};
