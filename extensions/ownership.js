import {safeText,privateSum} from "./core.js";
export const normalizedPath=value=>String(value??"").replaceAll("/","\\").toLowerCase();
export const processIdentity=p=>`${p.pid}:${p.startedMs}`;
export const validIdentity=p=>!!p&&Number.isSafeInteger(p.pid)&&p.pid>0&&Number.isSafeInteger(p.startedMs)&&p.startedMs>0
  &&Number.isInteger(p.sessionId)&&p.sessionId>=0&&typeof p.executablePath==="string"&&/^(?:[a-z]:[\\/]|\\\\)/i.test(p.executablePath)
  &&!/[\x00-\x1f"]/.test(p.executablePath)&&typeof p.accountSid==="string"&&/^S-\d+(?:-\d+)+$/.test(p.accountSid);
export const sameProcess=(a,b)=>validIdentity(a)&&validIdentity(b)&&a.pid===b.pid&&a.startedMs===b.startedMs
  &&a.sessionId===b.sessionId&&a.accountSid===b.accountSid&&normalizedPath(a.executablePath)===normalizedPath(b.executablePath);
export const validEdge=(parent,child)=>validIdentity(parent)&&validIdentity(child)&&child.ppid===parent.pid
  &&parent.startedMs<=child.startedMs;
export function controllerProtection(s) {
  if(s.processesComplete!==true||s.ownershipComplete!==true||!Array.isArray(s.processes))throw new Error("Process/controller facts incomplete");
  const byPid=new Map(s.processes.map(p=>[p.pid,p]));
  if(byPid.size!==s.processes.length||!sameProcess(s.controllerIdentity,byPid.get(s.controllerIdentity?.pid)))throw new Error("Controller identity unavailable");
  const protectedIds=new Set();let p=byPid.get(s.controllerIdentity.pid);
  while(p) {
    const id=processIdentity(p);if(protectedIds.has(id))throw new Error("Controller ancestry cycle");
    protectedIds.add(id);const parent=byPid.get(p.ppid);
    if(!parent||parent.startedMs>p.startedMs)break;
    if(!validIdentity(parent))throw new Error("Controller ancestor identity unavailable");
    if(!validEdge(parent,p))break;p=parent;
  }
  return protectedIds;
}
export function safetyReason(s,p,protectedIds) {
  if(!validIdentity(p)||p.startedMs>s.now)return "Process identity unavailable";
  if(p.canQuery!==true||typeof p.critical!=="boolean")return "Access or critical-process state unavailable";
  if(p.critical)return "OS critical process";
  if(protectedIds.has(processIdentity(p)))return "Active controller or controlling ancestor";
  return "";
}
export function processAction(s,rootPid) {
  const byPid=new Map(s.processes.map(p=>[p.pid,p])),root=byPid.get(rootPid);
  let protection;try{protection=controllerProtection(s);}catch{return {reason:"Process/controller facts incomplete"};}
  if(!root)return {reason:"Selected process is unavailable"};
  const reason=safetyReason(s,root,protection);if(reason)return {reason};
  const children=new Map();
  for(const p of s.processes){const list=children.get(p.ppid)??[];list.push(p);children.set(p.ppid,list);}
  const tree=[],issues=[],seen=new Set(),rootId=processIdentity(root);
  const queue=[{...root,depth:0,parentIdentity:null,rootIdentity:rootId,rootPid:root.pid}];
  for(let i=0;i<queue.length;i++) {
    const p=queue[i],id=processIdentity(p);
    if(seen.has(id)){issues.push("Process ancestry cycle");continue;}seen.add(id);tree.push(p);
    const blocked=safetyReason(s,p,protection);if(blocked)issues.push(blocked);
    for(const child of (children.get(p.pid)??[]).sort((a,b)=>a.pid-b.pid)) {
      if(Number.isSafeInteger(child.startedMs)&&child.startedMs<p.startedMs)continue;
      if(!validEdge(p,child)){issues.push("Descendant identity, session or account edge unavailable");continue;}
      queue.push({...child,depth:p.depth+1,parentIdentity:id,rootIdentity:rootId,rootPid:root.pid});
    }
  }
  if(tree.some(p=>protection.has(processIdentity(p))))return {reason:"Selected scope contains active controller"};
  return {reason:"",action:{id:`process:${rootId}`,kind:"process",actionable:true,label:safeText(root.name),
    roots:[tree[0]],targets:[tree[0]],treeTargets:tree,controllerIdentity:s.controllerIdentity,issues:[...new Set(issues)],estimatedBytes:privateSum(tree)}};
}
export function rootPreview(s,selectedPid) {
  const byPid=new Map(s.processes.map(p=>[p.pid,p])),selected=byPid.get(selectedPid),choices=[],seen=new Set();let p=selected;
  while(p&&!seen.has(processIdentity(p))) {
    seen.add(processIdentity(p));const {action,reason}=processAction(s,p.pid);
    choices.push({root:p,action,reason,windows:p.windowHandles?.length??0,
      siblings:s.processes.filter(c=>c.ppid===p.pid&&validEdge(p,c)).map(c=>c.pid)});
    if(s.boundariesComplete===false||p.serviceCount>0||p.pid===s.shellIdentity?.pid)break;
    const parent=byPid.get(p.ppid);
    if(!validEdge(parent,p)||parent.pid===s.shellIdentity?.pid||parent.serviceCount>0
      ||parent.sessionId!==p.sessionId||parent.accountSid!==p.accountSid)break;p=parent;
  }
  return {selected,choices};
}
function markedActions(actions) {
  if(!actions.some(a=>a.groupPolicy!==undefined))return false;
  const first=actions[0],sid=first.groupPolicy?.accountSid,identities=new Set(),rootIds=new Set();
  if(typeof sid!=="string"||!/^S-\d+(?:-\d+)+$/.test(sid))throw new Error("Invalid group policy");
  for(const action of actions) {
    const policy=action.groupPolicy;
    if(!policy||policy.kind!=="same-user-app-tree-v1"||policy.accountSid!==sid
      ||Object.keys(policy).some(key=>!["kind","accountSid"].includes(key))
      ||!sameProcess(first.controllerIdentity,action.controllerIdentity)||action.controllerIdentity.accountSid!==sid)
      throw new Error("Conflicting group policy");
    if(!Array.isArray(action.roots)||!action.roots.length||!Array.isArray(action.treeTargets)||!action.treeTargets.length)
      throw new Error("Invalid group scope");
    const roots=new Map(action.roots.map(p=>[processIdentity(p),p])),scope=new Map();
    if(roots.size!==action.roots.length)throw new Error("Overlapping group roots");
    for(const root of action.roots) {
      const id=processIdentity(root);if(rootIds.has(id))throw new Error("Overlapping group roots");rootIds.add(id);
    }
    for(const p of action.treeTargets) {
      const id=processIdentity(p);
      if(!validIdentity(p)||p.accountSid!==sid||identities.has(id)||!roots.has(p.rootIdentity)
        ||!Number.isInteger(p.depth)||p.depth<0)throw new Error("Invalid or overlapping group identity");
      identities.add(id);scope.set(id,p);
    }
    for(const p of scope.values()) {
      const id=processIdentity(p);
      if(roots.has(id)) {
        if(!sameProcess(p,roots.get(id))||p.depth!==0||p.parentIdentity!==null||p.rootIdentity!==id||p.rootPid!==p.pid)
          throw new Error("Invalid group root");
      } else {
        const parent=scope.get(p.parentIdentity);
        if(!validEdge(parent,p)||parent.depth+1!==p.depth||parent.rootIdentity!==p.rootIdentity||parent.rootPid!==p.rootPid)
          throw new Error("Invalid group lineage");
      }
    }
    for(const [id,root] of roots)if(!sameProcess(root,scope.get(id)))throw new Error("Missing group root");
    if(action.effectRootIds!==undefined&&(!Array.isArray(action.effectRootIds)||action.mode!=="task"
      ||new Set(action.effectRootIds).size!==action.effectRootIds.length||action.effectRootIds.some(id=>!roots.has(id))))
      throw new Error("Invalid group effect roots");
  }
  if(rootIds.size>32||identities.size>1000)throw new Error("Group batch limit exceeded");
  return true;
}
export function deduplicateRoots(actions) {
  if(markedActions(actions))return actions.map(action=>({...action}));
  const roots=new Map();
  for(const action of actions)for(const root of action.roots??[]) {
    const id=processIdentity(root),old=roots.get(id);if(old&&!sameProcess(old.root,root))throw new Error("Conflicting root identity");
    roots.set(id,{root,action});
  }
  return [...roots.values()].filter(({root})=>![...roots.values()].some(({root:other,action})=>
    action.mode==='tree'&&roots.get(processIdentity(root)).action.mode==='tree'
    &&processIdentity(root)!==processIdentity(other)&&action.treeTargets.some(p=>sameProcess(p,root)))).map(({action,root})=>({...action,roots:[root]}));
}
export function combineActions(actions) {
  const dedup=deduplicateRoots(actions),scope=new Map(),roots=dedup.flatMap(a=>a.roots);
  if(!roots.length||new Set(dedup.map(a=>a.mode)).size!==1)throw new Error('Invalid action batch');
  for(const action of dedup)for(const p of action.treeTargets) {
    const id=processIdentity(p),old=scope.get(id);
    if(old&&!sameProcess(old,p))throw new Error('Conflicting scope identity');
    if(!old||p.depth<old.depth)scope.set(id,p);
  }
  const effectRoots=dedup.some(a=>a.effectRootIds!==undefined)
    ?{effectRootIds:dedup.flatMap(a=>a.effectRootIds??a.roots.map(processIdentity))}:{};
  return {...dedup[0],...effectRoots,id:'confirmed-batch',roots,targets:roots,treeTargets:[...scope.values()],
    label:roots.map(p=>safeText(p.name)).join(', '),issues:dedup.flatMap(a=>a.issues),estimatedBytes:privateSum([...scope.values()])};
}
