'use strict';
const crypto=require('node:crypto');
function publicKey(blob){
 if(!Buffer.isBuffer(blob)||blob.length!==72||blob.readUInt32LE(0)!==0x31534345||blob.readUInt32LE(4)!==32)throw Error('BROKER_PIN_INVALID');
 crypto.ECDH.convertKey(Buffer.concat([Buffer.from([4]),blob.subarray(8)]),'prime256v1');
 return crypto.createPublicKey({format:'jwk',key:{kty:'EC',crv:'P-256',x:blob.subarray(8,40).toString('base64url'),y:blob.subarray(40).toString('base64url')}});
}
function verifyReceipt({receipt,publicBlob,installationId,request,startedAt,now=Date.now()}={}){
 try{
  if(!receipt||Object.keys(receipt).sort().join(',')!=='body,signature'||typeof receipt.body!=='string'||receipt.body.length>4096||typeof receipt.signature!=='string')return null;
  if(!request||request.action!=='health.check'||!Number.isSafeInteger(request.expiresAt)||!Number.isSafeInteger(startedAt)||!Number.isSafeInteger(now)||now<startedAt||now>=request.expiresAt)return null;
  const body=JSON.parse(receipt.body);
  if(!Array.isArray(body)||body.length!==11||body.some(x=>typeof x!=='string')||JSON.stringify(body)!==receipt.body)return null;
  const [domain,id,app,action,target,requestId,nonce,issued,expires,decision,state]=body;
  if(domain!=='BUILDWISE-OWNER-ACTION-RECEIPT-V1'||id!==installationId||app!=='atlas'||action!==request.action||target!=='buildwise-local-health'||requestId!==request.requestId||nonce!==request.nonce||expires!==String(request.expiresAt)||state!=='privileged-disabled'||!['approved','denied','cancelled'].includes(decision))return null;
  const time=Number(issued);if(!Number.isSafeInteger(time)||String(time)!==issued||time<startedAt||time>now)return null;
  const signature=Buffer.from(receipt.signature,'base64');
  if(signature.length!==64||signature.toString('base64')!==receipt.signature||!crypto.verify('sha256',Buffer.from(receipt.body),{key:publicKey(publicBlob),dsaEncoding:'ieee-p1363'},signature))return null;
  return Object.freeze({authorized:decision==='approved',decision,action,requestId,expiresAt:request.expiresAt});
 }catch{return null;}
}
module.exports={verifyReceipt};
