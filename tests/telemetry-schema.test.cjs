'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {validateTelemetry}=require('../telemetry-schema.cjs');
const good=()=>({schema:'buildwise.atlas.snapshot.v1',sentAt:new Date().toISOString(),sampledAt:new Date().toISOString(),source:'BuildWise dispatcher',totalJobs:1,activeJobs:0,errors:[],jobs:[{id:'job-1',state:'FAILED',worker:'codex'}],agents:[],events:[],resources:{cpuPercent:null,ramFreeGB:1,ramTotalGB:2}});
test('accepts minimal sanitized snapshot',()=>assert.equal(validateTelemetry(good()),true));
test('rejects nested credentials and extra worker keys',()=>{const p=good();p.jobs[0].apiKey='secret';assert.equal(validateTelemetry(p),false)});
test('rejects incorrect resource types',()=>{const p=good();p.resources.ramFreeGB='2GB';assert.equal(validateTelemetry(p),false)});
test('rejects unbounded arrays',()=>{const p=good();p.jobs=Array(1001).fill({id:'x',state:'A',worker:'W'});assert.equal(validateTelemetry(p),false)});
test('rejects malformed timestamps and inconsistent active count',()=>{const p=good();p.sampledAt='yesterday';assert.equal(validateTelemetry(p),false);p.sampledAt=new Date().toISOString();p.activeJobs=2;assert.equal(validateTelemetry(p),false)});
