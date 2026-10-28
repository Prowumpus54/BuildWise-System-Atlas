'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),cp=require('node:child_process');
function protectCurrentOwnerProcess({platform=process.platform,readFile=fs.readFileSync,execute=cp.execFileSync,programFiles=process.env.ProgramFiles||'C:\\Program Files',pid=process.pid}={}){
 if(platform!=='win32')return {protected:false,reason:'Windows required'};
 try{
  const root=path.win32.join(programFiles,'BuildWiseVault'),config=path.win32.join(root,'broker-config.json'),bytes=readFile(config);
  if(!Buffer.isBuffer(bytes)||bytes.length>4096)throw Error();
  const env={...process.env};for(const k of Object.keys(env))if(/^(COR_|CORECLR_|COMPLUS_|DOTNET_STARTUP_HOOKS$)/i.test(k))delete env[k];
  const output=execute(path.win32.join(root,'BuildWiseVaultBroker.exe'),['--protect-owner-process',config,crypto.createHash('sha256').update(bytes).digest('hex'),String(pid)],{encoding:'utf8',windowsHide:true,timeout:5000,maxBuffer:4096,shell:false,env});
  const result=JSON.parse(output);if(result.ownerProcessProtected!==true)throw Error();return {protected:true};
 }catch{return {protected:false,reason:'Protected owner-session host is unavailable'};}
}
module.exports={protectCurrentOwnerProcess};
