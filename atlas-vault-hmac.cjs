'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const APP='buildwise-atlas',PURPOSE='atlas.telemetry.check',BASE='http://127.0.0.1:7331';
function loadSdk(){
 const dir=path.join(__dirname,'vendor','buildwise-vault'),m=JSON.parse(fs.readFileSync(path.join(dir,'manifest.json')));
 const files=['protected-credential-client.js','protected-app-identity.js','protected-owner-process.js'];
 if(m.sourceCommit!=='fbd2e4a17158a0578f851eda1e539dfdb3e82d8a'||m.files.length!==files.length)throw Error('Reviewed BuildWise SDK required');
 for(const name of files){const entry=m.files.find(f=>f.name===name),text=fs.readFileSync(path.join(dir,name),'utf8').replace(/\r\n/g,'\n');if(!entry||crypto.createHash('sha256').update(text).digest('hex')!==entry.sha256)throw Error('BuildWise SDK changed');}
 return {...require('./vendor/buildwise-vault/protected-credential-client.js'),...require('./vendor/buildwise-vault/protected-app-identity.js'),...require('./vendor/buildwise-vault/protected-owner-process.js')};
}
const SDK=loadSdk();
function validateConnection(c,pin,{ready=true}={}){
 if(!c||c.schemaVersion!==1||c.app!==APP||c.installationId!==pin[1]||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(c.credential)||!Number.isSafeInteger(c.version)||c.version<1||c.version>999999999||ready&&c.phase!=='ready')throw Error('Atlas vault connection is not ready');
 return c;
}
async function readJson(response){
 if(!response.body)throw Error('BuildWise response unavailable');let bytes=0;const chunks=[];
 for await(const chunk of response.body){bytes+=chunk.length;if(bytes>16384)throw Error('BuildWise response too large');chunks.push(Buffer.from(chunk));}
 return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
function createAtlasVault({tokenProvider,fetcher=fetch,readFile=fs.readFileSync,programFiles='C:\\Program Files',identity=SDK.createProtectedAppIdentity({programFiles}),now=Date.now}={}){
 if(typeof tokenProvider!=='function')throw Error('Server-side BuildWise authentication required');
 const file=path.win32.join(programFiles,'BuildWiseVault','broker-config.json'),bytes=readFile(file),pin=JSON.parse(bytes);
 if(!Buffer.isBuffer(bytes)||bytes.length>4096||!Array.isArray(pin)||pin.length!==10||pin[0]!=='BUILDWISE-PROTECTED-VAULT-SETUP-V1'||pin[7]!=='sealed'||!/^[a-f0-9]{32}$/.test(pin[1]))throw Error('Pinned installed vault required');
 SDK.publicKey(Buffer.from(pin[8],'base64'));let busy=false;
 function unchanged(){if(!readFile(file).equals(bytes))throw Error('Vault installation changed');}
 async function http(route,options={}){
  unchanged();const token=await tokenProvider();if(typeof token!=='string'||token.length<16||token.length>512||/[\r\n]/.test(token))throw Error('BuildWise authentication unavailable');
  const response=await fetcher(BASE+route,{...options,headers:{'X-Factory-Token':token,'Content-Type':'application/json'},redirect:'error',signal:AbortSignal.timeout(options.method==='POST'?70000:10000)});
  const body=await readJson(response);unchanged();return {response,body};
 }
 async function operate(fields){
  SDK.validFields(fields,now());const startedAt=now();
  const {response,body}=await http('/api/vault/credentials/operate',{method:'POST',body:JSON.stringify({fields})});
  const proof=SDK.verifyCredentialReceipt({receipt:body.receipt,fields,installationId:pin[1],publicBlob:Buffer.from(pin[8],'base64'),startedAt,now:now()});
  if(response.status!==200||!proof?.authorized||body.authorized!==true)throw Error('Atlas vault operation was not approved');
  return {...proof,receipt:body.receipt};
 }
 function request(action,c,extra={}){return SDK.makeCredentialRequest({action,app:APP,...(action.startsWith('credential.')?{credential:c.credential,version:c.version}:{}),...extra,expiresAt:now()+60000});}
 async function existingIdentity(c){
  const fields=['BUILDWISE-CREDENTIAL-REQUEST-V1','credential.sign',APP,c.credential,String(c.version),'','',Buffer.from('Atlas existing identity continuity check').toString('base64'),crypto.randomUUID(),crypto.randomBytes(32).toString('base64url'),String(now()+60000),''];
  // Signing opens an existing key only. Missing identity stops before create can be called.
  const signed=await identity.sign(fields);
  if(JSON.stringify(signed.slice(0,11))!==JSON.stringify(fields.slice(0,11)))throw Error('Atlas identity proof changed');
  const found=await identity.create(APP);
  if(!crypto.verify('sha256',Buffer.from(JSON.stringify(fields)),{key:SDK.publicKey(Buffer.from(found.publicBlob,'base64')),dsaEncoding:'ieee-p1363'},Buffer.from(signed[11],'base64')))throw Error('Atlas identity continuity failed');
  return found;
 }
 async function register(c,{requireExistingIdentity=false,onIdentity=()=>{}}={}){
  validateConnection(c,pin,{ready:false});const publicIdentity=requireExistingIdentity?await existingIdentity(c):await identity.create(APP);
  await onIdentity(publicIdentity);
  await operate(request('app.register',c,{publicKey:publicIdentity.publicBlob,label:'BuildWise Atlas snapshot signer'}));
  return publicIdentity.fingerprint;
 }
 async function reconcile(c,{onPage=()=>{}}={}){
  validateConnection(c,pin,{ready:false});let app=null,credential=null,finished=false;
  for(let page=0;page<32;page++){
   await onPage(page);
   const response=await operate(SDK.makeCredentialRequest({action:'vault.list',app:'owner',version:page,expiresAt:now()+60000}));
   app=app||response.result.apps.find(a=>a.id===APP);
   credential=credential||response.result.credentials.find(v=>v.id===c.credential);
   if(!response.result.more){finished=true;break;}
  }
  if(!finished)throw Error('Atlas registry inspection exceeded its bound');
  if(!app){if(credential)throw Error('Atlas registry binding inconsistent');return {phase:'registering'};}
  if(app.state!=='active')throw Error('Atlas app was revoked; owner recovery is required');
  const found=await existingIdentity(c);
  if(found.fingerprint!==app.publicKeyFingerprint)throw Error('Atlas app identity does not match the registered key');
  if(credential&&(credential.app!==APP||credential.state!=='active'||credential.version!==c.version||credential.operation!=='hmac.sha256'))throw Error('Atlas credential binding changed; owner recovery is required');
  return {phase:credential?'ready':'app-registered',appKeyFingerprint:found.fingerprint,publicBlob:found.publicBlob};
 }
 async function checkHealth(){
  const health=await http('/api/health'),vault=await http('/api/vault/status'),v=vault.body;
  if(health.response.status!==200||health.body.ok!==true||vault.response.status!==200||v.available!==true||v.authenticatedBroker!==true||v.ownerEnrolled!==true||v.privilegedCommandsEnabled!==false||v.ownerApprovalRequired!==true)throw Error('Verified BuildWise and vault health required');
 }
 async function importKey(c){validateConnection(c,pin,{ready:false});if(c.version!==1)throw Error('Initial Atlas credential version must be one');await operate(request('credential.import',c,{label:'Atlas snapshot signing key'}));}
 async function signSnapshot(c,input={}){
  validateConnection(c,pin);if(busy)throw Error('Atlas signing request already active');
  if(Object.keys(input).some(k=>k!=='requestId')||input.requestId!==undefined&&!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(input.requestId))throw Error('Bounded Atlas snapshot request required');
  busy=true;
  try{
   await checkHealth();
   const requestId=input.requestId||crypto.randomUUID();
   const snapshot=JSON.stringify({schemaVersion:1,purpose:PURPOSE,requestId,at:new Date(now()).toISOString(),buildwise:'healthy',vault:'owner-enrolled'});
   const data=Buffer.from(snapshot,'utf8');if(data.length>768)throw Error('Atlas snapshot too large');
   const fields=['BUILDWISE-CREDENTIAL-REQUEST-V1','credential.sign',APP,c.credential,String(c.version),'','',data.toString('base64'),crypto.randomUUID(),crypto.randomBytes(32).toString('base64url'),String(now()+60000),''];
   const signed=await identity.sign(fields);
   if(JSON.stringify(signed.slice(0,11))!==JSON.stringify(fields.slice(0,11)))throw Error('Atlas signing request changed');
   const result=await operate(signed);
   return Object.freeze({schemaVersion:1,kind:'atlas-vault-hmac-snapshot',requestId,app:APP,credential:c.credential,version:c.version,messageBase64:data.toString('base64'),messageSha256:crypto.createHash('sha256').update(data).digest('hex'),hmacBase64:result.result.result,ownerApproved:true,brokerReceiptVerified:true,receipt:result.receipt,rawSecretReturned:false});
  }finally{busy=false;}
 }
 return Object.freeze({installationId:pin[1],checkHealth,register,reconcile,importKey,signSnapshot});
}
module.exports={APP,PURPOSE,loadSdk,validateConnection,createAtlasVault};
