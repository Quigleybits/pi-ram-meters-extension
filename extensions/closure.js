import {refreshActions} from "./app-rows.js";
import {sameProcess,processIdentity,combineActions} from "./ownership.js";
import {readPhaseReceipt} from "./app-script.js";
import {observeApplication} from "./observation.js";
async function executeMarked(option,baseline,deps) {
  const stopped=new Set(),failed=new Set(),forced=new Set(),receipts=[],scope=new Map();
  let action=option,state,attempted=false,effectSeen=false;
  const message="Process identity, group validation or execution receipt is unavailable. Remaining selections were kept. No automatic retry.";
  try {
    const fresh=refreshActions([option],baseline);if(!fresh)return {state:"unconfirmed",message,stopped:[],failed:[],forced:[],receipts};
    action=combineActions(fresh);for(const p of action.treeTargets)scope.set(processIdentity(p),p);
    const phase=async(current,name)=>{
      attempted=true;const r=readPhaseReceipt(await deps.runPhase(current,name),current,name);receipts.push(r);
      for(const pid of r.stopped)stopped.add(pid);for(const pid of r.failed)failed.add(pid);for(const pid of r.forced)forced.add(pid);
      effectSeen=effectSeen||r.forceAttempted.length>0||r.closeRequested.length>0;
      for(const p of r.validationIdentities)scope.set(processIdentity(p),{...scope.get(processIdentity(p)),...p});
      if(!r.preflightComplete||!r.operationComplete||!r.validationComplete||r.failed.length)state=effectSeen?"partial":"unconfirmed";
      return r;
    };
    if(action.mode==="task") {
      await phase(action,"grace");
      if(!state) {
        const snapshot=await deps.collectGuarded(),effectRootIds=[];
        for(const root of action.roots) {
          const live=snapshot.processes?.find(p=>p.pid===root.pid);
          if(live&&!sameProcess(root,live))throw new Error("Frozen root changed");
          if(live)effectRootIds.push(processIdentity(root));
        }
        const validationLineage=[...scope.values()],exitedIdentities=validationLineage.filter(p=>p.outcome==="exited"&&Number.isSafeInteger(p.exitMs)&&p.exitMs>=p.startedMs);
        const checked=refreshActions([{...action,treeTargets:validationLineage,effectRootIds}],snapshot,{validationLineage,exitedIdentities});
        if(!checked)throw new Error("Full marked continuation changed");
        action={...combineActions(checked),validationExits:validationLineage.filter(p=>p.outcome==="exited")};
        await phase(action,"force");
      }
    } else await phase(action,"force");
  }catch{state=effectSeen?"partial":"unconfirmed";}
  if(!attempted)return {state:"unconfirmed",message,stopped:[...stopped],failed:[...failed],forced:[...forced],receipts};
  action={...action,treeTargets:[...scope.values()]};
  const observation=await observeApplication(action,baseline,deps);
  return {...observation,observation,stopped:[...stopped],failed:[...failed],forced:[...forced],receipts,
    ...(state?{state,message:`Group phase ${state}; remaining selections were kept. No automatic retry. ${observation.message}`}:{})};
}
export async function executeApplication(option,baseline,deps) {
  if(option?.groupPolicy!==undefined)return executeMarked(option,baseline,deps);
  const stopped=new Set(),failed=new Set(),forced=new Set(),receipts=[];
  let action=option,state,attempted=false;
  const uncertain=()=>({state:"unconfirmed",message:"Process identity, safety or execution receipt is unavailable. Remaining selections were kept. No automatic retry.",
    stopped:[...stopped],failed:[...failed],forced:[...forced],receipts});
  try {
    const fresh=refreshActions([option],baseline);if(!fresh)return uncertain();action=combineActions(fresh);
    const scope=new Map(action.treeTargets.map(p=>[processIdentity(p),p]));
    const phase=async(current,name)=>{
      attempted=true;const r=readPhaseReceipt(await deps.runPhase(current,name),current,name);receipts.push(r);
      for(const pid of r.stopped)stopped.add(pid);for(const pid of r.failed)failed.add(pid);for(const pid of r.forced)forced.add(pid);
      for(const p of r.identities)if(!scope.has(processIdentity(p)))scope.set(processIdentity(p),p);
      if(!r.preflightComplete||!r.operationComplete||r.failed.length)state=r.forceAttempted.length||r.closeRequested.length||stopped.size?"partial":"unconfirmed";
      return r;
    };
    if(action.mode==="task") {
      const grace=await phase(action,"grace");
      if(!state&&grace.alive.length) {
        const snapshot=await deps.collectGuarded(),remaining=[];
        for(const root of action.roots) {
          const live=snapshot.processes?.find(p=>p.pid===root.pid);
          if(!live){stopped.add(root.pid);continue;}if(!sameProcess(root,live))throw new Error("Root identity changed");remaining.push(root);
        }
        if(remaining.length) {
          const checked=refreshActions([{...action,roots:remaining}],snapshot);if(!checked)throw new Error("Guard changed");
          await phase(combineActions(checked),"force");
        }
      }
    } else await phase(action,"force");
    action={...action,treeTargets:[...scope.values()]};
  }catch{state="unconfirmed";}
  if(!attempted)return uncertain();
  const observation=await observeApplication(action,baseline,deps);
  return {...observation,observation,stopped:[...stopped],failed:[...failed],forced:[...forced],receipts,
    ...(state?{state,message:`Process phase ${state}; remaining selections were kept. No automatic retry. ${observation.message}`}:{})};
}
