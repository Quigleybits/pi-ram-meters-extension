import {safeText,privateSum} from "./core.js";
import {processAction,processIdentity,validEdge,sameProcess,deduplicateRoots} from "./ownership.js";
export function buildTableRows(s) {
  const byPid=new Map(s.processes.map(p=>[p.pid,p])),children=new Map(),roots=[];
  for(const p of s.processes) {
    const parent=byPid.get(p.ppid);
    if(validEdge(parent,p)&&parent.pid!==p.pid){const list=children.get(parent.pid)??[];list.push(p);children.set(parent.pid,list);}
    else roots.push(p);
  }
  const sort=ps=>ps.sort((a,b)=>(b.workingSetBytes??0)-(a.workingSetBytes??0)||a.pid-b.pid),ordered=[],seen=new Set();
  const walk=(seed,depth)=>{const stack=[{p:seed,depth}];while(stack.length){const {p,depth}=stack.pop();if(seen.has(p.pid))continue;
    seen.add(p.pid);ordered.push({p,depth});for(const child of sort([...(children.get(p.pid)??[])]).reverse())stack.push({p:child,depth:depth+1});}};
  for(const p of sort(roots))walk(p,0);for(const p of sort([...s.processes]))if(!seen.has(p.pid))walk(p,0);
  return ordered.map(({p,depth})=>{
    const {action,reason}=processAction(s,p.pid),tree=action?.treeTargets??[p];
    return {id:`process:${processIdentity(p)}`,kind:"process",pid:p.pid,name:safeText(p.name,50),depth,
      actions:action?[action]:[],count:tree.length,closableCount:action?1:0,workingSetBytes:p.workingSetBytes,
      estimatedBytes:action?privateSum(tree):null,reason,
      label:`PID ${p.pid} · parent ${p.ppid} · selected PID is default root · ${p.windowHandles?.length??0} windows${p.serviceCount?` · ${p.serviceCount} hosted services (shared scope)`:''}`,
      description:safeText(p.description)||"Purpose unknown"};
  });
}
export function selectedActions(rows,ids) {
  if(!Array.isArray(ids)||!ids.length||new Set(ids).size!==ids.length)throw new Error("Invalid selection");
  return deduplicateRoots(ids.map(id=>{const row=rows.find(r=>r.id===id);if(row?.actions.length!==1)throw new Error("Unavailable process");return row.actions[0];}));
}
export function refreshActions(actions,snapshot) {
  try {
    const result=[];
    for(const original of actions) {
      if(!["task","tree"].includes(original.mode))return undefined;
      for(const root of original.roots) {
        const live=snapshot.processes.find(p=>p.pid===root.pid);if(!sameProcess(root,live))return undefined;
        const {action}=processAction(snapshot,root.pid);if(!action||original.mode==="tree"&&action.issues.length)return undefined;
        result.push({...action,mode:original.mode});
      }
    }
    return deduplicateRoots(result);
  }catch{return undefined;}
}
