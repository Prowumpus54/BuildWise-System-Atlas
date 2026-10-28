'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{execFile}=require('node:child_process');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/,APP=/^[a-z][a-z0-9-]{0,39}$/,LABEL=/^[A-Za-z0-9 ._-]{1,60}$/;
const TASKER_ENDPOINT='https://us-central1-flowwise-fe645.cloudfunctions.net/taskerApi/v1/inbox?limit=1';
const TASKER_SCOPE=crypto.createHash('sha256').update(JSON.stringify(['TASKER-READ-STATUS-V1','GET',TASKER_ENDPOINT,'reachable,authorized'])).digest('hex');
const actions=new Set(['app.register','app.revoke','credential.import','credential.rotate','credential.revoke','credential.sign','vault.list','vault.audit','credential.tasker.import','credential.tasker.rotate','credential.tasker.revoke','credential.tasker.status']);
function publicKey(blob){
 if(!Buffer.isBuffer(blob)||blob.length!==72||blob.readUInt32LE(0)!==0x31534345||blob.readUInt32LE(4)!==32)throw Error('KEY_PIN_INVALID');
 return crypto.createPublicKey({format:'jwk',key:{kty:'EC',crv:'P-256',x:blob.subarray(8,40).toString('base64url'),y:blob.subarray(40).toString('base64url')}});
}
function validFields(f,now){
 if(!Array.isArray(f)||f.length!==12||f.some(v=>typeof v!=='string'||/[\r\n]/.test(v))||JSON.stringify(f).length>3000||f[0]!=='BUILDWISE-CREDENTIAL-REQUEST-V1'||!actions.has(f[1])||!APP.test(f[2])||!UUID.test(f[8])||! /^[A-Za-z0-9_-]{43}$/.test(f[9])||Buffer.from(f[9],'base64url').toString('base64url')!==f[9])throw Error('CREDENTIAL_REQUEST_DENIED');
 const expiry=Number(f[10]);if(!Number.isSafeInteger(expiry)||String(expiry)!==f[10]||expiry<=now||expiry>now+60000)throw Error('CREDENTIAL_EXPIRED');
 if(f[1].startsWith('credential.')){if(!UUID.test(f[3])||! /^[1-9][0-9]{0,8}$/.test(f[4])||f[5]!=='')throw Error('CREDENTIAL_REQUEST_DENIED');}
 else if(f[3]!==''||(!['vault.list','vault.audit'].includes(f[1])&&f[4]!==''))throw Error('CREDENTIAL_REQUEST_DENIED');
 if(f[1]==='app.register'){publicKey(Buffer.from(f[5],'base64'));if(!LABEL.test(f[6])||f[7]!==''||f[11]!=='')throw Error('CREDENTIAL_REQUEST_DENIED');}
 else if(f[1]==='app.revoke'||['vault.list','vault.audit'].includes(f[1])){if(f[5]!==''||f[6]!==''||f[7]!==''||f[11]!==''||['vault.list','vault.audit'].includes(f[1])&&(f[2]!=='owner'||! /^(?:0|[1-9][0-9]{0,5})$/.test(f[4])))throw Error('CREDENTIAL_REQUEST_DENIED');}
 else if(f[1]==='credential.import'||f[1]==='credential.tasker.import'){if(f[4]!=='1'||!LABEL.test(f[6])||f[7]!==''||f[11]!=='')throw Error('CREDENTIAL_REQUEST_DENIED');}
 else if(f[6]!==''||!['credential.sign','credential.tasker.status'].includes(f[1])&&(f[7]!==''||f[11]!==''))throw Error('CREDENTIAL_REQUEST_DENIED');
 if(f[1]==='credential.tasker.status'){const signature=Buffer.from(f[11],'base64');if(f[7]!==TASKER_SCOPE||signature.length!==64||signature.toString('base64')!==f[11])throw Error('TASKER_SCOPE_DENIED');}
 if(f[1]==='credential.sign'){
  const data=Buffer.from(f[7],'base64'),signature=Buffer.from(f[11],'base64');new TextDecoder('utf-8',{fatal:true}).decode(data);
  if(data.length<1||data.length>768||data.toString('base64')!==f[7]||signature.length!==64||signature.toString('base64')!==f[11])throw Error('CREDENTIAL_REQUEST_DENIED');
 }
 return f;
}
function verifyCredentialReceipt({receipt,fields,installationId,publicBlob,startedAt,now=Date.now()}){
 try{
  if(!receipt||Object.keys(receipt).sort().join(',')!=='body,signature'||typeof receipt.body!=='string'||receipt.body.length>4096||typeof receipt.signature!=='string'||now<startedAt||now>=Number(fields[10]))return null;
  const b=JSON.parse(receipt.body),sig=Buffer.from(receipt.signature,'base64');
  if(!Array.isArray(b)||b.length!==7||b.some(v=>typeof v!=='string')||JSON.stringify(b)!==receipt.body||b[0]!=='BUILDWISE-CREDENTIAL-RESULT-V1'||b[1]!==installationId||b[2]!==JSON.stringify(fields)||!['approved','denied','cancelled'].includes(b[4])||!Number.isSafeInteger(Number(b[5]))||String(Number(b[5]))!==b[5]||Number(b[5])<startedAt||Number(b[5])>now||Buffer.from(b[3],'base64').length!==32||sig.length!==64||sig.toString('base64')!==receipt.signature||!crypto.verify('sha256',Buffer.from(receipt.body),{key:publicKey(publicBlob),dsaEncoding:'ieee-p1363'},sig))return null;
  if(b[4]!=='approved'){if(b[6]!=='')return null;return {authorized:false,decision:b[4],requestId:fields[8],result:null};}
  const result=JSON.parse(b[6]);
  if(!result||Object.keys(result).sort().join(',')!==(fields[1]==='vault.audit'?'app,apps,audit,auditEntries,credential,credentials,more,page,result,revision':'app,apps,auditEntries,credential,credentials,more,page,result,revision')||result.app!==fields[2]||result.credential!==fields[3]||!Number.isSafeInteger(result.revision)||result.revision<1||result.auditEntries!==result.revision||typeof result.more!=='boolean'||!Number.isSafeInteger(result.page)||!Array.isArray(result.apps)||result.apps.length>4||!Array.isArray(result.credentials)||result.credentials.length>4)return null;
  if(fields[1]==='credential.sign'){if(Buffer.from(result.result,'base64').length!==32||Buffer.from(result.result,'base64').toString('base64')!==result.result)return null;}else if(fields[1]==='credential.tasker.status'){const status=JSON.parse(result.result);if(Object.keys(status).sort().join(',')!=='authorized,reachable'||status.reachable!==true||typeof status.authorized!=='boolean'||JSON.stringify({reachable:status.reachable,authorized:status.authorized})!==result.result)return null;}else if(result.result!=='')return null;
  for(const a of result.apps)if(Object.keys(a).sort().join(',')!=='id,label,publicKeyFingerprint,state'||!APP.test(a.id)||!LABEL.test(a.label)||! /^[a-f0-9]{64}$/.test(a.publicKeyFingerprint)||!['active','revoked'].includes(a.state))return null;
  for(const c of result.credentials)if(Object.keys(c).sort().join(',')!=='app,id,label,operation,state,version'||!APP.test(c.app)||!UUID.test(c.id)||!LABEL.test(c.label)||!Number.isSafeInteger(c.version)||c.version<1||!['hmac.sha256','tasker.status.v1'].includes(c.operation)||!['active','revoked'].includes(c.state))return null;
  if(['vault.list','vault.audit'].includes(fields[1])&&result.page!==Number(fields[4]))return null;
  if(fields[1]==='vault.audit'){
   if(!Array.isArray(result.audit)||result.audit.length>2)return null;
   for(const row of result.audit){if(!row||Object.keys(row).sort().join(',')!=='app,appKeyFingerprint,at,credential,credentialVersion,decision,hash,legacy,messageDigest,nonce,operation,ownerProofDigest,previousHash,requestDigest,requestId'||typeof row.legacy!=='boolean'||!['requested','completed','denied','cancelled','failed','rejected'].includes(row.decision))return null;
    for(const key of ['app','at','credential','credentialVersion','nonce','operation','requestId'])if(typeof row[key]!=='string')return null;
    for(const key of ['previousHash','hash','appKeyFingerprint','messageDigest','ownerProofDigest','requestDigest'])if(typeof row[key]!=='string'||row[key]!==''&&!/^[a-f0-9]{64}$/.test(row[key]))return null;
   }
  }
  return Object.freeze({authorized:true,decision:'approved',requestId:fields[8],result});
 }catch{return null;}
}
function createProtectedCredentialClient({platform=process.platform,programFiles=process.env.ProgramFiles||'C:\\Program Files',readFile=fs.readFileSync,execute=execFile,now=Date.now}={}){
 const root=path.win32.join(programFiles,'BuildWiseVault'),image=path.win32.join(root,'BuildWiseVaultBroker.exe'),config=path.win32.join(root,'broker-config.json');let busy=false;
 async function operate(fields,signal){
  if(platform!=='win32'||busy||signal?.aborted)throw Error('CREDENTIAL_UNAVAILABLE');
  fields=Object.freeze([...validFields(fields,now())]);const startedAt=now();busy=true;
  try{
   const bytes=readFile(config);if(!Buffer.isBuffer(bytes)||bytes.length>4096)throw Error();
   const c=JSON.parse(bytes);if(!Array.isArray(c)||c.length!==10||c[0]!=='BUILDWISE-PROTECTED-VAULT-SETUP-V1'||c[7]!=='sealed'||! /^[a-f0-9]{32}$/.test(c[1]))throw Error();
   const env={...process.env};for(const name of Object.keys(env))if(/^(COR_|CORECLR_|COMPLUS_|DOTNET_STARTUP_HOOKS$)/i.test(name))delete env[name];
   const output=await new Promise((resolve,reject)=>{let child;try{child=execute(image,['--credentials',config,crypto.createHash('sha256').update(bytes).digest('hex')],{shell:false,windowsHide:false,encoding:'utf8',timeout:65000,maxBuffer:8192,env,signal},(error,stdout,stderr)=>error||String(stderr||'').trim()?reject(Error('CREDENTIAL_NOT_COMPLETED')):resolve(stdout));child.stdin.end(JSON.stringify(fields));}catch{child?.kill();reject(Error('CREDENTIAL_UNAVAILABLE'));}});
   if(signal?.aborted||!readFile(config).equals(bytes))throw Error();
   const receipt=JSON.parse(output),verified=verifyCredentialReceipt({receipt,fields,installationId:c[1],publicBlob:Buffer.from(c[8],'base64'),startedAt,now:now()});if(!verified)throw Error();return {...verified,receipt};
  }catch{throw Error('CREDENTIAL_NOT_COMPLETED');}finally{busy=false;}
 }
 return Object.freeze({operate});
}
function installProtectedCredentials(app,{auth,client=createProtectedCredentialClient()}={}){
 if(typeof auth!=='function')throw TypeError('Authenticated credential endpoint required');
 app.post('/api/vault/credentials/operate',auth,async(req,res)=>{
  res.set('Cache-Control','no-store');const control=new AbortController(),abort=()=>control.abort();req.once('aborted',abort);res.once('close',abort);
  try{if(!req.body||Object.keys(req.body).join(',')!=='fields')throw Error();const result=await client.operate(req.body.fields,control.signal);res.status(result.authorized?200:403).json(result);}
  catch{if(!res.destroyed)res.status(403).json({authorized:false,error:'Credential operation was not completed'});}
  finally{req.removeListener('aborted',abort);res.removeListener('close',abort);}
 });
}
function makeCredentialRequest({action,app,credential='',version='',publicKey='',label='',data='',privateKey,expiresAt=Date.now()+60000}){
 const fields=['BUILDWISE-CREDENTIAL-REQUEST-V1',action,app,credential,String(version),publicKey,label,data,crypto.randomUUID(),crypto.randomBytes(32).toString('base64url'),String(expiresAt),''];
 if(action==='credential.sign'||action==='credential.tasker.status'){if(!privateKey)throw Error('App signing key required');fields[11]=crypto.sign('sha256',Buffer.from(JSON.stringify(fields)),{key:privateKey,dsaEncoding:'ieee-p1363'}).toString('base64');}
 return fields;
}
module.exports={createProtectedCredentialClient,installProtectedCredentials,verifyCredentialReceipt,makeCredentialRequest,validFields,publicKey,TASKER_SCOPE,TASKER_ENDPOINT};
