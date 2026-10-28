'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {APP,createAtlasVault,loadSdk}=require('../atlas-vault-hmac.cjs');
function key(){const pair=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'}),j=pair.publicKey.export({format:'jwk'}),blob=Buffer.alloc(72);blob.writeUInt32LE(0x31534345);blob.writeUInt32LE(32,4);Buffer.from(j.x,'base64url').copy(blob,8);Buffer.from(j.y,'base64url').copy(blob,40);return {...pair,blob};}
function fixture({token='t'.repeat(24)}={}){
 const broker=key(),app=key(),time=1000000;
 let config=Buffer.from(JSON.stringify(['BUILDWISE-PROTECTED-VAULT-SETUP-V1','a'.repeat(32),'owner','1','broker','pipe','b'.repeat(64),'sealed',broker.blob.toString('base64'),'key']));
 const c={schemaVersion:1,app:APP,credential:crypto.randomUUID(),version:1,installationId:'a'.repeat(32),phase:'ready'},requests=[];
 const control={mode:'normal',created:0,signed:0,hold:null,apps:[],credentials:[],morePages:0,appFingerprint:crypto.createHash('sha256').update(app.blob).digest('hex')};
 const identity={create:async()=>{control.created++;return {publicBlob:app.blob.toString('base64'),fingerprint:crypto.createHash('sha256').update(app.blob).digest('hex'),privateKeyExportable:false};},sign:async fields=>{control.signed++;if(control.mode==='missing-key')throw Error('APP_IDENTITY_KEY_MISSING');const f=[...fields];if(control.mode==='changed-draft')f[4]='2';f[11]=crypto.sign('sha256',Buffer.from(JSON.stringify(f)),{key:app.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64');return f;}};
 const response=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json'}});
 const fetcher=async(url,options)=>{
  assert.ok(url.startsWith('http://127.0.0.1:7331/'));assert.equal(options.redirect,'error');assert.equal(options.headers['X-Factory-Token'],token);
  if(url.endsWith('/api/health')){if(control.hold)await control.hold;if(control.mode==='oversized')return new Response('x'.repeat(17000));return response({ok:control.mode!=='unhealthy',privateField:'DO_NOT_EXPOSE'});}
  if(url.endsWith('/api/vault/status'))return response({available:true,authenticatedBroker:true,ownerEnrolled:true,ownerApprovalRequired:true,privilegedCommandsEnabled:false,privateField:'DO_NOT_EXPOSE'});
  assert.equal(url,'http://127.0.0.1:7331/api/vault/credentials/operate');const f=JSON.parse(options.body).fields;requests.push(f);
  if(control.mode==='denied')return response({authorized:false},403);
  if(control.mode==='pin-change')config=Buffer.from(config.toString().replace('owner','changed'));
  const result={revision:2,result:f[1]==='credential.sign'?crypto.createHash('sha256').update('public test HMAC').digest('base64'):'',app:f[2],credential:f[3],apps:f[1]==='vault.list'?control.apps:[],credentials:f[1]==='vault.list'?control.credentials:[],page:f[1]==='vault.list'?Number(f[4]):0,more:f[1]==='vault.list'&&Number(f[4])<control.morePages,auditEntries:2};
  const body=JSON.stringify(['BUILDWISE-CREDENTIAL-RESULT-V1',c.installationId,JSON.stringify(f),crypto.randomBytes(32).toString('base64'),'approved',String(time),JSON.stringify(result)]);
  const signature=crypto.sign('sha256',Buffer.from(body),{key:control.mode==='forged'?app.privateKey:broker.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64');
  return response({authorized:true,receipt:{body,signature}});
 };
 const client=createAtlasVault({tokenProvider:async()=>token,readFile:()=>config,fetcher,identity,now:()=>time});
 return {client,c,control,requests,token};
}
test('Atlas uses pinned reviewed SDK bytes',()=>{assert.equal(typeof loadSdk().verifyCredentialReceipt,'function');});
test('Atlas registration, local import and bounded snapshot use independent app identity and signed receipts',async()=>{
 const {client,c,requests,control,token}=fixture();await client.register(c);await client.importKey(c);const result=await client.signSnapshot(c);
 assert.equal(control.created,1);assert.equal(control.signed,1);assert.deepEqual(requests.map(f=>f[1]),['app.register','credential.import','credential.sign']);
 assert.equal(requests[0][2],APP);assert.equal(requests[1][7],'');assert.equal(result.brokerReceiptVerified,true);assert.equal(result.rawSecretReturned,false);
 const snapshot=JSON.parse(Buffer.from(result.messageBase64,'base64'));assert.deepEqual(Object.keys(snapshot),['schemaVersion','purpose','requestId','at','buildwise','vault']);assert.equal(snapshot.purpose,'atlas.telemetry.check');
 assert.equal(result.messageSha256,crypto.createHash('sha256').update(Buffer.from(result.messageBase64,'base64')).digest('hex'));
 assert.equal(Buffer.from(result.hmacBase64,'base64').length,32);assert.ok(!JSON.stringify(result).includes(token));assert.ok(!JSON.stringify(result).includes('DO_NOT_EXPOSE'));
});
test('Atlas denies forged, denied, changed and unhealthy requests and never recreates a missing identity',async()=>{
 for(const mode of ['forged','denied','pin-change','changed-draft','unhealthy','missing-key','oversized']){
  const {client,c,control}=fixture();control.mode=mode;await assert.rejects(client.signSnapshot(c),undefined,mode);assert.equal(control.created,0,mode);
 }
 const {client,c,requests}=fixture();
 for(const input of [{message:'arbitrary'},{credential:crypto.randomUUID()},{requestId:'bad'}])await assert.rejects(client.signSnapshot(c,input));
 await assert.rejects(client.signSnapshot({...c,app:'different'}));await assert.rejects(client.signSnapshot({...c,phase:'importing'}));assert.equal(requests.length,0);
});
test('Atlas only allows one signing request at a time',async()=>{
 const {client,c,control}=fixture();let release;control.hold=new Promise(r=>release=r);
 const first=client.signSnapshot(c);await assert.rejects(client.signSnapshot(c),/already active/);control.hold=null;release();assert.equal((await first).ownerApproved,true);
});

test('existing 24-character desktop token is accepted and pending public identity is saved before registration',async()=>{
 const {client,c,requests,token}=fixture();assert.equal(token.length,24);await client.checkHealth();
 let remembered=false;await client.register(c,{onIdentity:publicIdentity=>{assert.equal(requests.length,0);assert.equal(publicIdentity.fingerprint.length,64);remembered=true;}});
 assert.equal(remembered,true);
 for(const token of ['short','t'.repeat(513),'t'.repeat(24)+'\n'])await assert.rejects(fixture({token}).client.checkHealth(),/authentication unavailable/);
});
test('signed registry inspection reconciles absent and committed registration without replacing identity',async()=>{
 const first=fixture();assert.deepEqual(await first.client.reconcile(first.c),{phase:'registering'});assert.equal(first.control.created,0);
 await first.client.register(first.c,{requireExistingIdentity:true});assert.equal(first.control.signed,1);assert.equal(first.control.created,1);
 const found=fixture();found.control.apps=[{id:APP,label:'Atlas',state:'active',publicKeyFingerprint:found.control.appFingerprint}];found.control.morePages=1;
 const reconciled=await found.client.reconcile(found.c);assert.equal(reconciled.phase,'app-registered');assert.equal(reconciled.appKeyFingerprint,found.control.appFingerprint);
 assert.deepEqual(found.requests.map(f=>f[1]),['vault.list','vault.list']);
});
test('committed import resumes ready; revoked, wrong-key and changed-version state cannot be adopted',async()=>{
 const good=fixture();good.control.apps=[{id:APP,label:'Atlas',state:'active',publicKeyFingerprint:good.control.appFingerprint}];
 good.control.credentials=[{id:good.c.credential,app:APP,label:'Atlas key',state:'active',version:1,operation:'hmac.sha256'}];
 assert.equal((await good.client.reconcile(good.c)).phase,'ready');
 for(const variant of ['revoked-app','wrong-key','revoked-credential','changed-version','foreign-app','changed-kind']){
  const f=fixture();f.control.apps=[{id:APP,label:'Atlas',state:variant==='revoked-app'?'revoked':'active',publicKeyFingerprint:variant==='wrong-key'?'0'.repeat(64):f.control.appFingerprint}];
  f.control.credentials=[{id:f.c.credential,app:variant==='foreign-app'?'other':APP,label:'Atlas key',state:variant==='revoked-credential'?'revoked':'active',version:variant==='changed-version'?2:1,operation:variant==='changed-kind'?'tasker.status.v1':'hmac.sha256'}];
  await assert.rejects(f.client.reconcile(f.c),undefined,variant);assert.ok(f.requests.every(r=>r[1]==='vault.list'));
 }
});
test('recovery never creates a missing key, trusts an unsigned listing or exceeds registry page bound',async()=>{
 const f=fixture();f.control.mode='missing-key';await assert.rejects(f.client.register(f.c,{requireExistingIdentity:true}),/MISSING/);assert.equal(f.control.created,0);
 const forged=fixture();forged.control.mode='forged';await assert.rejects(forged.client.reconcile(forged.c));assert.equal(forged.control.created,0);
 const full=fixture();full.control.morePages=100;await assert.rejects(full.client.reconcile(full.c),/bound/);assert.equal(full.requests.length,32);
});
