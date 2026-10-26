'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createBuildWiseSessionVerifier}=require('../buildwise-owner-session.cjs');
const key='synthetic-test-credential-123456';
test('fails closed for absent credential',async()=>{const verify=createBuildWiseSessionVerifier({fetcher:()=>{throw Error('unexpected')}});assert.equal(await verify(''),false)});
test('rejects denied session',async()=>{const verify=createBuildWiseSessionVerifier({fetcher:async()=>({ok:true,json:async()=>({session:{authenticated:false}})})});assert.equal(await verify(key),false)});
test('accepts explicit verified session',async()=>{const verify=createBuildWiseSessionVerifier({fetcher:async()=>({ok:true,json:async()=>({session:{authenticated:true}})})});assert.equal(await verify(key),true)});
test('fails closed on connection error',async()=>{const verify=createBuildWiseSessionVerifier({fetcher:async()=>{throw Error('offline')}});assert.equal(await verify(key),false)});
test('checks only existing local control-center session endpoint',async()=>{let endpoint='';const verify=createBuildWiseSessionVerifier({fetcher:async url=>{endpoint=url;return {ok:true,json:async()=>({session:{authenticated:true}})}}});assert.equal(await verify(key),true);assert.equal(endpoint,'http://127.0.0.1:7331/api/control-center/status')});
