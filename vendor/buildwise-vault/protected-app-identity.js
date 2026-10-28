'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{execFile}=require('node:child_process');
const {validFields,publicKey}=require('./protected-credential-client');
function createProtectedAppIdentity({platform=process.platform,programFiles=process.env.ProgramFiles||'C:\\Program Files',readFile=fs.readFileSync,execute=execFile,now=Date.now}={}){
 const root=path.win32.join(programFiles,'BuildWiseVault'),config=path.win32.join(root,'broker-config.json');
 async function invoke(action,input){
  if(platform!=='win32')throw Error('Windows owner identity required');
  const bytes=readFile(config),c=JSON.parse(bytes);if(!Buffer.isBuffer(bytes)||bytes.length>4096||!Array.isArray(c)||c.length!==10||c[7]!=='sealed')throw Error('Pinned installation required');
  const env={...process.env};for(const name of Object.keys(env))if(/^(COR_|CORECLR_|COMPLUS_|DOTNET_STARTUP_HOOKS$)/i.test(name))delete env[name];
  const output=await new Promise((resolve,reject)=>{let child;try{child=execute(path.win32.join(root,'BuildWiseVaultBroker.exe'),[action,config,crypto.createHash('sha256').update(bytes).digest('hex')],{shell:false,windowsHide:true,encoding:'utf8',timeout:10000,maxBuffer:8192,env},(e,out,err)=>e||String(err||'').trim()?reject(Error('App identity unavailable')):resolve(out));child.stdin.end(JSON.stringify(input));}catch{child?.kill();reject(Error('App identity unavailable'));}});
  if(!readFile(config).equals(bytes))throw Error('Installation changed');return JSON.parse(output);
 }
 function identity(app){if(!/^[a-z][a-z0-9-]{0,39}$/.test(app))throw Error('Invalid app identity');return ['BUILDWISE-APP-IDENTITY-V1',app];}
 async function create(app){const r=await invoke('--app-key-create',identity(app)),blob=Buffer.from(r.publicBlob||'','base64');publicKey(blob);if(r.app!==app||r.privateKeyExportable!==false||r.fingerprint!==crypto.createHash('sha256').update(blob).digest('hex'))throw Error('Invalid app identity');return Object.freeze(r);}
 async function sign(draft){
  if(!Array.isArray(draft)||!['credential.sign','credential.tasker.status'].includes(draft[1])||draft[11]!=='')throw Error('Unsigned signing request required');
  validFields([...draft.slice(0,11),Buffer.alloc(64).toString('base64')],now());
  const signed=await invoke('--app-key-sign',draft);validFields(signed,now());
  if(JSON.stringify(signed.slice(0,11))!==JSON.stringify(draft.slice(0,11)))throw Error('Signing request changed');return signed;
 }
 async function remove(app){const r=await invoke('--app-key-delete',identity(app));if(r.deleted!==true)throw Error('App identity deletion failed');return r;}
 return Object.freeze({create,sign,remove});
}
module.exports={createProtectedAppIdentity};
