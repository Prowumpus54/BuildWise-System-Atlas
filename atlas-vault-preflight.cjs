'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),cp=require('node:child_process');
async function main(){
 require('./atlas-vault-hmac.cjs').loadSdk();
 if(process.platform!=='win32')throw Error('Windows required');
 const root='C:\\Program Files\\BuildWiseVault',config=path.join(root,'broker-config.json'),bytes=fs.readFileSync(config),pin=crypto.createHash('sha256').update(bytes).digest('hex');
 const env={...process.env};for(const k of Object.keys(env))if(/^(COR_|CORECLR_|COMPLUS_|DOTNET_STARTUP_HOOKS$)/i.test(k))delete env[k];
 const verified=JSON.parse(cp.execFileSync(path.join(root,'BuildWiseVaultBroker.exe'),['--verify-installation',config,pin],{shell:false,windowsHide:true,timeout:5000,maxBuffer:4096,encoding:'utf8',env}));
 if(verified.configurationVerified!==true||verified.privilegedCommandsEnabled!==false)throw Error('Installed host verification failed');
 const health=await fetch('http://127.0.0.1:7331/api/health',{redirect:'error',signal:AbortSignal.timeout(5000)});
 const denied=await fetch('http://127.0.0.1:7331/api/vault/credentials/operate',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}',redirect:'error',signal:AbortSignal.timeout(5000)});
 await health.body?.cancel();await denied.body?.cancel();
 if(health.status!==200||denied.status!==401)throw Error('Installed desktop API boundary failed');
 const evidence={schemaVersion:1,kind:'atlas-vault-preflight',readOnly:true,sdkSnapshotVerified:true,installedConfigurationVerified:true,desktopHealth:health.status,unauthenticatedCredentialEndpoint:denied.status,ownerApprovalRequested:false,credentialAccess:false,physicalAtlasEnrollmentPassed:false,at:new Date().toISOString()};
 fs.mkdirSync(path.join(__dirname,'runtime'),{recursive:true});fs.writeFileSync(path.join(__dirname,'runtime','atlas-vault-preflight.json'),JSON.stringify(evidence,null,2)+'\n');console.log(JSON.stringify(evidence));
}
main().catch(()=>{console.error('Atlas vault preflight failed; no credential operation was requested.');process.exitCode=1;});
