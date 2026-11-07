import {safeText,privateSum} from "./core.js";
import {groupAttribution} from "./attribution.js";
import {groupDanger} from "./danger.js";
import {processAction,processIdentity,validIdentity,validEdge,sameProcess,deduplicateRoots,controllerProtection,safetyReason} from "./ownership.js";
function groupContext(s) {
  if(!Number.isSafeInteger(s.now)||s.now<=0||s.boundariesComplete!==true)throw new Error("OS boundary facts incomplete");
  const protection=controllerProtection(s),byPid=new Map(s.processes.map(p=>[p.pid,p])),children=new Map();
  for(const identity of [s.controllerIdentity,s.shellIdentity]) {
    if(!sameProcess(identity,byPid.get(identity?.pid))||identity.startedMs>s.now||identity.canQuery!==true
      ||typeof identity.critical!=="boolean"||!Number.isInteger(identity.serviceCount)||identity.serviceCount<0)
      throw new Error("Controller or shell facts incomplete");
  }
  for(const p of s.processes) {
    if(!Number.isSafeInteger(p.pid)||p.pid<0||!Number.isSafeInteger(p.ppid)||p.ppid<0)throw new Error("Invalid inventory");
    const list=children.get(p.ppid)??[];list.push(p);children.set(p.ppid,list);
  }
  return {byPid,children,protection,sid:s.controllerIdentity.accountSid};
}
function boundary(s,p,context) {
  if(!validIdentity(p)||p.startedMs>s.now)return false;
  if(context.protection.has(processIdentity(p))||sameProcess(p,s.shellIdentity))return true;
  return p.canQuery===true&&typeof p.critical==="boolean"&&Number.isInteger(p.serviceCount)&&p.serviceCount>=0
    &&(p.critical||p.serviceCount>0||p.accountSid!==context.sid);
}
function memberReason(s,p,context) {
  const reason=safetyReason(s,p,context.protection);if(reason)return reason;
  if(p.accountSid!==context.sid)return "Other-user process";
  if(sameProcess(p,s.shellIdentity))return "OS shell";
  if(!Number.isInteger(p.serviceCount)||p.serviceCount<0)return "OS role unavailable";
  return p.serviceCount?"Hosted service":"";
}
function groupReason(s,action,context) {
  if(!action?.groupPolicy||action.groupPolicy.accountSid!==context.sid||!sameProcess(action.controllerIdentity,s.controllerIdentity)
    ||!Array.isArray(action.issues)||action.issues.length)return "Group safety unavailable";
  try{deduplicateRoots([action]);}catch{return "Group scope, policy or member limit unavailable";}
  const scope=new Map(action.treeTargets.map(p=>[processIdentity(p),p]));
  for(const p of action.treeTargets) {
    const live=context.byPid.get(p.pid),reason=memberReason(s,p,context);
    if(reason)return reason;
    if(!sameProcess(p,live)||p.ppid!==live.ppid)return "Group identity changed";
    for(const child of context.children.get(p.pid)??[]) {
      if(Number.isSafeInteger(child.startedMs)&&child.startedMs<p.startedMs)continue;
      if(!validEdge(p,child)||!sameProcess(child,scope.get(processIdentity(child))))return "Full group scope unavailable";
    }
  }
  return "";
}
export function appGroupReason(s,action) {
  try{return groupReason(s,action,groupContext(s));}catch{return "Group identity, policy or boundary facts unavailable";}
}
const memorySum=(ps,key)=>{
  if(ps.some(p=>typeof p[key]!=="number"||!Number.isFinite(p[key])||p[key]<0))return null;
  const total=ps.reduce((sum,p)=>sum+p[key],0);return Number.isFinite(total)?total:null;
};
export function buildTableRows(s) {
  try {
    const context=groupContext(s),result=[],claimed=new Set();
    for(const p of s.processes) {
      if(memberReason(s,p,context))continue;
      const parent=context.byPid.get(p.ppid),orphan=p.ppid===0||!parent
        ||Number.isSafeInteger(parent.startedMs)&&parent.startedMs>p.startedMs;
      if(!orphan&&!(validEdge(parent,p)&&boundary(s,parent,context)))continue;
      const candidate=processAction(s,p.pid).action;if(!candidate)continue;
      const action={...candidate,groupPolicy:{kind:"same-user-app-tree-v1",accountSid:context.sid}};
      if(groupReason(s,action,context))continue;
      const tree=action.treeTargets;
      if(tree.some(member=>claimed.has(processIdentity(member))))return [];
      for(const member of tree)claimed.add(processIdentity(member));
      const presentation=groupAttribution(p,tree,s.herdrAttribution);
      result.push({id:`app:${processIdentity(p)}`,kind:"app",pid:p.pid,name:presentation.name,depth:0,
        danger:groupDanger(tree,{protection:context.protection,shellIdentity:s.shellIdentity,herdrAttribution:s.herdrAttribution}),
        actions:[action],count:tree.length,closableCount:1,workingSetBytes:memorySum(tree,"workingSetBytes"),
        estimatedBytes:memorySum(tree,"privateBytes"),reason:"",
        label:presentation.label,description:presentation.description});
    }
    return result.sort((a,b)=>a.workingSetBytes===null&&b.workingSetBytes!==null?1:b.workingSetBytes===null&&a.workingSetBytes!==null?-1
      :(b.workingSetBytes??0)-(a.workingSetBytes??0)||a.pid-b.pid||a.actions[0].roots[0].startedMs-b.actions[0].roots[0].startedMs);
  }catch{return [];}
}
export function selectedActions(rows,ids) {
  if(!Array.isArray(ids)||!ids.length||new Set(ids).size!==ids.length)throw new Error("Invalid selection");
  return deduplicateRoots(ids.map(id=>{const row=rows.find(r=>r.id===id);if(row?.actions.length!==1)throw new Error("Unavailable process");return row.actions[0];}));
}
function markedRefresh(original,s,context,{validationLineage,exitedIdentities}) {
  if(!sameProcess(original.controllerIdentity,s.controllerIdentity)||original.groupPolicy.accountSid!==context.sid)throw new Error("Controller changed");
  const rootIds=new Set(original.roots.map(processIdentity)),scope=new Map(),queue=[];
  const add=p=>{
    const id=processIdentity(p),old=scope.get(id);
    if(old) {
      if(!sameProcess(old,p)||old.ppid!==p.ppid||old.parentIdentity!==p.parentIdentity||old.rootIdentity!==p.rootIdentity
        ||old.rootPid!==p.rootPid||old.depth!==p.depth)throw new Error("Changed validation lineage");
      return;
    }
    if(scope.size>=1000)throw new Error("Full member limit exceeded");
    scope.set(id,p);queue.push(p);
  };
  for(const p of [...original.treeTargets,...validationLineage.filter(p=>rootIds.has(p.rootIdentity))])add(p);
  const exits=new Map();
  for(const p of exitedIdentities.filter(p=>rootIds.has(p.rootIdentity))) {
    const old=scope.get(processIdentity(p));
    if(!sameProcess(old,p)||p.outcome!=="exited"||!Number.isSafeInteger(p.exitMs)||p.exitMs<p.startedMs||p.exitMs>s.now)
      throw new Error("Exit evidence unavailable");
    exits.set(processIdentity(p),p);
  }
  for(const root of original.roots) {
    const live=context.byPid.get(root.pid);
    if(live) {
      if(!sameProcess(root,live)||root.ppid!==live.ppid)throw new Error("Root identity changed");
      const action={...processAction(s,root.pid).action,groupPolicy:original.groupPolicy};
      if(groupReason(s,action,context))throw new Error("Full group safety changed");
      for(const p of action.treeTargets)add(p);
    } else if(!exits.has(processIdentity(root)))throw new Error("Root exit unconfirmed");
  }
  for(let i=0;i<queue.length;i++) {
    const parent=queue[i],live=context.byPid.get(parent.pid);
    if(live&&processIdentity(live)===processIdentity(parent)) {
      if(!sameProcess(parent,live)||parent.ppid!==live.ppid||memberReason(s,live,context))throw new Error("Member identity or safety changed");
    }
    for(const child of context.children.get(parent.pid)??[]) {
      if(scope.has(processIdentity(child)))continue;
      if(Number.isSafeInteger(child.startedMs)&&child.startedMs<parent.startedMs)continue;
      let evidence,parentExitMs=0;
      if(sameProcess(parent,live))evidence="coobserved";
      else if(validIdentity(live)&&!sameProcess(parent,live)&&child.startedMs>=live.startedMs)continue;
      else if(exits.get(processIdentity(parent))?.exitMs>child.startedMs) {
        evidence="lifetime";parentExitMs=exits.get(processIdentity(parent)).exitMs;
      }
      if(!evidence||!validEdge(parent,child)||memberReason(s,child,context))throw new Error("Unverified or unsafe descendant");
      add({...child,depth:parent.depth+1,parentIdentity:processIdentity(parent),rootIdentity:parent.rootIdentity,
        rootPid:parent.rootPid,evidence,parentExitMs});
    }
  }
  const rootOrder=new Map(original.roots.map((p,i)=>[processIdentity(p),i]));
  const treeTargets=[...scope.values()].sort((a,b)=>rootOrder.get(a.rootIdentity)-rootOrder.get(b.rootIdentity)
    ||a.depth-b.depth||a.pid-b.pid||a.startedMs-b.startedMs);
  return {...original,treeTargets,estimatedBytes:memorySum(treeTargets,"privateBytes")};
}
export function refreshActions(actions,snapshot,{validationLineage=[],exitedIdentities=[]}={}) {
  try {
    deduplicateRoots(actions);
    if(actions.some(a=>a.groupPolicy!==undefined)) {
      if(!Array.isArray(validationLineage)||!Array.isArray(exitedIdentities))return undefined;
      const roots=new Set(actions.flatMap(a=>a.roots.map(processIdentity)));
      if([...validationLineage,...exitedIdentities].some(p=>!roots.has(p.rootIdentity)))return undefined;
      const context=groupContext(snapshot);
      return deduplicateRoots(actions.map(a=>{
        if(!["task","tree"].includes(a.mode))throw new Error("Invalid action mode");
        return markedRefresh(a,snapshot,context,{validationLineage,exitedIdentities});
      }));
    }
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
