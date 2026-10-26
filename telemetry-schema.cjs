'use strict';
const own=(v)=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const keys=(o,allowed)=>Object.keys(o).every(k=>allowed.includes(k));
const str=(v,max=160)=>typeof v==='string'&&v.length<=max&&!/[\u0000-\u001f]/.test(v);
const count=(v)=>Number.isSafeInteger(v)&&v>=0&&v<=100000;
const iso=(v)=>str(v,40)&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString()===v;
function validateTelemetry(p){
 if(!own(p)||!keys(p,['schema','sentAt','source','sampledAt','totalJobs','activeJobs','errors','jobs','agents','events','resources']))return false;
 if(p.schema!=='buildwise.atlas.snapshot.v1'||!iso(p.sentAt)||!iso(p.sampledAt)||!str(p.source,80)||!count(p.totalJobs)||!count(p.activeJobs)||p.activeJobs>p.totalJobs)return false;
 for(const [key,max,fields] of [
 ['jobs',1000,['id','state','worker']],['agents',1000,['id','worker','state','phase','progressPercent']],['errors',1000,['jobId','area','status','at','message']],['events',40,['jobId','kind','at','message']]]){
  if(!Array.isArray(p[key])||p[key].length>max)return false;
  for(const e of p[key]){
   if(!own(e)||!keys(e,fields))return false;
   for(const [k,v] of Object.entries(e)){if(k==='progressPercent'){if(v!==null&&(!Number.isFinite(v)||v<0||v>100))return false}else if(v!==null&&!str(v,k==='message'?160:80))return false}
  }
 }
 if(!own(p.resources)||!keys(p.resources,['cpuPercent','ramFreeGB','ramTotalGB']))return false;
 for(const v of Object.values(p.resources))if(v!==null&&(!Number.isFinite(v)||v<0||v>1000000))return false;
 return true;
}
module.exports={validateTelemetry};
