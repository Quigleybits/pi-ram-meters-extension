import {GB,safeText,privateSum} from "./core.js";
import {createWindowsAdapter} from "./windows.js";
import {buildTableRows,selectedActions,refreshActions} from "./app-rows.js";
import {combineActions,processIdentity,sameProcess} from "./ownership.js";
import {renderTableReport,showTablePicker} from "./table.js";
import {groupAttribution} from "./attribution.js";
const formatBytes=bytes=>Number.isFinite(bytes)&&bytes>=0?(bytes/GB).toFixed(2):"?";
function captureAction(action) {
  const capture=p=>Object.freeze({...p,windowHandles:Object.freeze([...(p.windowHandles??[])])});
  const roots=Object.freeze(action.roots.map(capture));
  return Object.freeze({...action,roots,targets:roots,treeTargets:Object.freeze(action.treeTargets.map(capture)),
    controllerIdentity:capture(action.controllerIdentity),groupPolicy:Object.freeze({...action.groupPolicy}),
    issues:Object.freeze([...action.issues])});
}
function scopeSummary(actions,metadata) {
  return actions.flatMap(action=>action.roots.map(root=>{
    const tree=action.treeTargets.filter(p=>p.rootIdentity===processIdentity(root));
    const ws=tree.every(p=>Number.isFinite(p.workingSetBytes)&&p.workingSetBytes>=0)?tree.reduce((sum,p)=>sum+p.workingSetBytes,0):null;
    const display=groupAttribution(root,tree,metadata);
    return `${safeText(display.name,50)} · root PID ${root.pid} (${safeText(root.name,50)}) · ${tree.length} captured processes · WS sum ${formatBytes(ws)} GB (incl. shared) · Private tree ~${formatBytes(privateSum(tree))} GB\n${safeText(display.description,240)}`;
  })).join("\n");
}
export function createRamHandler(deps) {
  let busy=false;
  return async(args,ctx)=>{
    const notify=(message,type="info")=>ctx.ui?.notify?.(message,type);
    const flags=String(args??"").trim().split(/\s+/).filter(Boolean);
    if(flags.length>1||flags.some(f=>f!=="--read-only")){notify("Usage: /ram [--read-only]","warning");return;}
    if(busy){notify("/ram is already running.","warning");return;}busy=true;
    let attempting=false;
    try {
      const snapshot=await deps.collect(),rows=buildTableRows(snapshot);
      if(flags.includes("--read-only")||ctx.hasUI!==true||ctx.mode!=="tui"){notify(renderTableReport(snapshot,rows));return;}
      const picked=await (deps.pickRows??showTablePicker)(snapshot,rows,ctx);
      if(picked?.intent!=="kill")return;
      if(typeof ctx.ui?.select!=="function"){notify("Confirmation UI unavailable; nothing was stopped.","warning");return;}
      const selected=selectedActions(rows,picked.rowIds).map(captureAction),scope=scopeSummary(selected,snapshot.herdrAttribution);
      const modeLabel=await ctx.ui.select(`Choose process action\nReview selected app/root trees\n${scope}`,["Cancel","End task","End process tree"]);
      if(!["End task","End process tree"].includes(modeLabel))return;
      const mode=modeLabel==="End task"?"task":"tree",plan=captureAction(combineActions(selected.map(a=>({...a,mode}))));
      if(plan.issues.length){notify(`Group safety unavailable: ${safeText(plan.issues.join("; "),250)}. Nothing was stopped.`,"warning");return;}
      const warning=mode==="task"?"Request closure of all root windows within one shared grace interval, then force only still-live original roots. A windowless root uses root-force fallback; children may remain."
        :"Force the frozen roots and ALL currently verified same-user descendants, including GUI, cross-session and newly verified children. Parents stop before children. No save opportunity.";
      const affirmative=`Confirm ${modeLabel}`;
      const footprint=privateSum(mode==="task"?plan.roots:plan.treeTargets);
      if(await ctx.ui.select(`Confirm closure and unsaved-data risk\n${scope}\n${plan.treeTargets.length} captured tree identities.\nPrivate-byte ${mode==="task"?"root":"tree"} footprint ~${formatBytes(footprint)} GB; not guaranteed freed RAM.\n${warning}\nUnsaved data may be lost. Save your work before confirming.`,["Cancel",affirmative])!==affirmative)return;
      const fresh=await deps.collect(),validated=refreshActions([plan],fresh);
      if(!validated){notify("Selected identity or safety changed; nothing was stopped. Review fresh options.","warning");return;}
      const batch=combineActions(validated);
      if(batch.roots.length!==plan.roots.length||batch.roots.some(p=>!plan.roots.some(root=>sameProcess(root,p))))throw new Error("Root expansion");
      attempting=true;const result=await deps.execute(batch,{baseline:fresh});attempting=false;
      const completed=result?.state==="completed"&&Array.isArray(result.failed)&&result.failed.length===0;
      notify(safeText(result?.message??"Execution receipt unavailable. Remaining selections were kept. No automatic retry.",1000),completed?"info":"warning");
      for(const [key,label] of [["rootsAlive","Original roots still alive"],["childrenAlive","Original children still alive"],
        ["newInScope","New verified lineage"],["possible","Uncertain-lineage candidates"]]) {
        const members=result?.[key];if(Array.isArray(members)&&members.length)notify(`${label}: ${members.length}.`,"warning");
      }
      if(!completed)notify("Batch stopped; remaining selections were kept. No automatic retry.","warning");
    }catch{
      notify(attempting?"Close outcome unconfirmed; remaining selections were kept. No automatic retry.":"/ram could not finish; no further close action was run.","warning");
    }finally{busy=false;}
  };
}
export default function(pi,toolkit) {
  pi.registerCommand("ram",{description:"Show compact app/root trees and confirm exact group closure",
    handler:createRamHandler({...createWindowsAdapter(),pickRows:(snapshot,rows,ctx)=>showTablePicker(snapshot,rows,ctx,toolkit)})});
}
