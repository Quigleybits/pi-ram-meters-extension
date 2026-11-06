import {processIdentity,sameProcess,validEdge,validIdentity} from "./ownership.js";
const short=p=>({pid:p.pid,startedMs:p.startedMs});
export async function observeApplication(option,baseline,{readProcesses,clock=()=>performance.now(),sleep=ms=>new Promise(r=>setTimeout(r,ms))}={}) {
  const started=clock(),times=[],newInScope=new Map(),possible=new Map();
  const original=new Map(option.treeTargets.map(p=>[processIdentity(p),p])),lineage=new Map(original);
  const roots=new Set(option.roots.map(processIdentity)),baselineIds=new Set((baseline?.processes??[]).filter(validIdentity).map(processIdentity));
  let rootsAlive=[],childrenAlive=[],first,last;
  const result=(state,message)=>({state,message,rootsAlive,childrenAlive,newInScope:[...newInScope.values()].map(short),
    possible:[...possible.values()].map(short),sampleTimes:times,coverageMs:first===undefined?0:Math.max(0,Math.round(last-first)),elapsedMs:Math.max(0,Math.round(clock()-started))});
  try {
    if(baseline?.processesComplete!==true||typeof readProcesses!=="function")throw new Error("Missing baseline");
    for(const offset of [0,500,2000]) {
      const delay=(first??0)+offset-(clock()-started);if(delay>0)await sleep(Math.ceil(delay));
      const budget=Math.floor(5000-(clock()-started));if(budget<=0)throw new Error("Observation deadline");
      const sample=await readProcesses({timeoutMs:budget,lineage:[...lineage.values()]});
      const completed=clock()-started;
      if(completed>5000||!Number.isFinite(completed)||completed<0||!(sample?.processesComplete===true||sample?.complete===true)||!Array.isArray(sample.processes))throw new Error("Incomplete sample");
      const byPid=new Map(sample.processes.map(p=>[p.pid,p]));
      if(byPid.size!==sample.processes.length)throw new Error("Duplicate inventory");
      if(last!==undefined&&completed-last<500)throw new Error("Unseparated samples");
      if(first===undefined)first=completed;last=completed;times.push(Math.round(completed));
      for(const known of lineage.values()) {
        const current=byPid.get(known.pid);
        if(current&&(!Number.isSafeInteger(current.startedMs)||current.startedMs<=0))throw new Error("Unresolved lineage birth");
      }
      const live=new Set();
      for(const p of sample.processes) {
        const known=lineage.get(processIdentity(p));
        if(known){if(!sameProcess(known,p)||p.ppid!==known.ppid)throw new Error("Changed identity/edge");live.add(processIdentity(p));}
      }
      let changed;
      do {
        changed=false;
        for(const p of sample.processes) {
          const id=processIdentity(p),parent=byPid.get(p.ppid);
          if(live.has(id)||baselineIds.has(id)||!parent||!live.has(processIdentity(parent)))continue;
          if(!validEdge(parent,p))throw new Error("Unknown selected child");
          live.add(id);lineage.set(id,p);newInScope.set(id,p);changed=true;
        }
      }while(changed);
      rootsAlive=[];childrenAlive=[];
      for(const p of sample.processes) {
        const id=processIdentity(p);
        if(original.has(id)){(roots.has(id)?rootsAlive:childrenAlive).push(short(p));continue;}
        if(live.has(id)||baselineIds.has(id))continue;
        // A stale parent PID alone is uncertainty, never verified respawn.
        const candidates=[...lineage.values()].filter(known=>known.pid===p.ppid);
        for(const parent of candidates) {
          if(!Number.isSafeInteger(p.startedMs)||p.startedMs<=0)throw new Error("Unknown potential descendant");
          if(p.startedMs<parent.startedMs)continue;
          const currentParent=byPid.get(p.ppid);
          if(currentParent&&validIdentity(currentParent)&&!sameProcess(currentParent,parent)&&p.startedMs>=currentParent.startedMs)continue;
          possible.set(id,p);
        }
      }
    }
    if(last-first<2000)throw new Error("Insufficient coverage");
    const timing=`Observed ${times.length} separated snapshots across ${Math.round(last-first)} ms. Outside-supervisor restarts and processes entirely between samples cannot be attributed; later restarts are outside this interval.`;
    if(newInScope.size)return result("respawn",`New verified selected-lineage processes were observed. No automatic retry. ${timing}`);
    if(possible.size)return result("uncertain-lineage",`New processes reference a departed lineage PID; attribution is uncertain. No automatic retry. ${timing}`);
    if(rootsAlive.length||childrenAlive.length)return result("survivors",`Selected scope still has ${rootsAlive.length} original roots and ${childrenAlive.length} original children. No automatic retry. ${timing}`);
    return result("completed",`Selected verified scope was observed gone during this interval. ${timing}`);
  }catch{return result("unconfirmed","Post-close observation was incomplete, insufficiently separated or exceeded its deadline. Remaining selections were kept. No automatic retry.");}
}
