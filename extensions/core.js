export const GB=1_000_000_000;
export function safeText(value,limit=100) {
  return String(value??"").replace(/\x1b\][\s\S]*?(?:\x07|\x1b\\)/g,"").replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,"")
    .replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/g,"").slice(0,limit);
}
const number=v=>typeof v==="number"&&Number.isFinite(v)&&v>=0?v:null;
export function parseProcesses(input) {
  const raw=typeof input==="string"?JSON.parse(input.replace(/^\ufeff/,"")):input;
  if(!raw||!Array.isArray(raw.processes))throw new Error("Invalid process snapshot");
  const seen=new Set(),processes=[];let complete=raw.complete===true;
  for(const p of raw.processes) {
    if(!p||!Number.isSafeInteger(p.pid)||p.pid<0||!Number.isSafeInteger(p.ppid)||p.ppid<0||seen.has(p.pid)){complete=false;continue;}
    seen.add(p.pid);
    processes.push({pid:p.pid,ppid:p.ppid,name:typeof p.name==="string"?p.name:"Unknown",
      startedMs:Number.isSafeInteger(p.startedMs)&&p.startedMs>0?p.startedMs:null,
      executablePath:typeof p.executablePath==="string"?p.executablePath:null,
      sessionId:Number.isInteger(p.sessionId)&&p.sessionId>=0?p.sessionId:null,
      accountSid:typeof p.accountSid==="string"?p.accountSid:null,
      critical:typeof p.critical==="boolean"?p.critical:null,canQuery:p.canQuery===true,
      windowHandles:Array.isArray(p.windowHandles)?p.windowHandles.filter(h=>typeof h==="string"&&/^\d+$/.test(h)):[],
      description:typeof p.description==="string"?safeText(p.description):"",
      serviceCount:Number.isInteger(p.serviceCount)&&p.serviceCount>=0?p.serviceCount:null,
      workingSetBytes:number(p.workingSetBytes),privateBytes:number(p.privateBytes),cpuSeconds:number(p.cpuSeconds)});
  }
  return {processes,complete,shellPid:Number.isInteger(raw.shellPid)?raw.shellPid:null,boundariesComplete:raw.boundariesComplete===true,
    probeCount:Number.isInteger(raw.probeCount)?raw.probeCount:null};
}
export const privateSum=ps=>ps.every(p=>typeof p.privateBytes==="number"&&Number.isFinite(p.privateBytes)&&p.privateBytes>=0)
  ?ps.reduce((n,p)=>n+p.privateBytes,0):null;
