'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {APP,loadSdk,validateConnection,createAtlasVault}=require('./atlas-vault-hmac.cjs');
async function main(){
 const sdk=loadSdk();
 if(process.platform!=='win32'||!sdk.protectCurrentOwnerProcess({programFiles:'C:\\Program Files'}).protected)throw Error('Open this tool from your Windows owner desktop');
 const dir=path.join(process.env.APPDATA,'BuildWiseVaultClients','Atlas'),file=path.join(dir,'hmac-connection-v1.json');
 function save(c){fs.mkdirSync(dir,{recursive:true});const temp=file+'.tmp';fs.writeFileSync(temp,JSON.stringify(c,null,2)+'\n',{flag:'wx'});fs.renameSync(temp,file);}
 const tokenFile=path.join(process.env.APPDATA,'factorydashboard','data','terminal-token.txt');
 const client=createAtlasVault({tokenProvider:async()=>fs.readFileSync(tokenFile,'utf8').trim()});
 let connection=fs.existsSync(file)?JSON.parse(fs.readFileSync(file,'utf8')):null;
 if(!connection){
  connection={schemaVersion:1,app:APP,credential:crypto.randomUUID(),version:1,installationId:client.installationId,phase:'registering',createdAt:new Date().toISOString()};
  save(connection);
  console.log('Connect BuildWise Atlas: three local Windows Hello approvals. No provider key is used.');
  console.log('1/3 Register BuildWise Atlas as its own vault app.');
  connection.appKeyFingerprint=await client.register(connection);connection.phase='app-registered';save(connection);
 }
 validateConnection(connection,['',client.installationId],{ready:false});
 if(connection.phase==='app-registered'){
  connection.phase='importing';save(connection);
  console.log('2/3 In the native secret window choose Generate secret, Continue, then approve.');
  console.log('This generated HMAC key stays in the vault and will sign compact Atlas health snapshots.');
  await client.importKey(connection);connection.phase='ready';save(connection);
 }
 if(connection.phase!=='ready')throw Error('A previous setup outcome is uncertain. Inspect the native vault before retrying; do not delete the connection file or replace the app key.');
 console.log('Approve the Atlas snapshot signing request with Windows Hello.');
 const signed=await client.signSnapshot(connection);
 const record={...signed,persistentConnection:true,providerSecretsUsed:false,at:new Date().toISOString()};
 const evidence=path.join(__dirname,'runtime','atlas-vault-hmac');fs.mkdirSync(evidence,{recursive:true});fs.writeFileSync(path.join(evidence,'snapshot-'+signed.requestId+'.json'),JSON.stringify(record,null,2)+'\n');
 console.log(JSON.stringify(record));
 console.log('Atlas is connected locally. Its app and credential remain active. Run this shortcut again to approve one new snapshot.');
}
main().catch(error=>{console.error('Atlas vault connection did not complete: '+error.message);console.error('Completed approvals remain committed. No raw secret is returned.');process.exitCode=1;});
