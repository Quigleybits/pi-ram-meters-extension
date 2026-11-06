import {safeText} from "./core.js";
import {createWindowsAdapter} from "./windows.js";
import {buildTableRows,selectedActions,refreshActions} from "./app-rows.js";
import {rootPreview,combineActions,processIdentity} from "./ownership.js";
import {renderTableReport,showTablePicker} from "./table.js";
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
      if(typeof ctx.ui?.select!=="function"){notify("Root and confirmation UI unavailable; nothing was stopped.","warning");return;}
      const selected=selectedActions(rows,picked.rowIds),reviewed=[];
      for(const action of selected) {
        const pid=action.roots[0].pid,preview=rootPreview(snapshot,pid);
        const labels=preview.choices.map((c,i)=>`${i===0?"Use selected":"Choose ancestor"} PID ${c.root.pid} · ${safeText(c.root.name,36)} · ${c.windows} root windows · ${c.action?.treeTargets.length??"?"} tree processes${c.reason?` · unavailable: ${c.reason}`:""}`);
        const detail=preview.choices.map(c=>`PID ${c.root.pid}, parent ${c.root.ppid}; children/branches: ${c.siblings.join(", ")||"none"}; scope: ${c.action?.treeTargets.map(p=>p.pid).slice(0,40).join(", ")||"unavailable"}${c.action?.treeTargets.length>40?" …":""}`).join("\n");
        const choice=await ctx.ui.select(`Review root for selected PID ${pid}\nSelected PID is the default. Parentage cannot distinguish a launcher from an owning supervisor. Choosing an ancestor includes its other branches.\n${detail}`,[...labels,"Cancel"]);
        const index=labels.indexOf(choice);if(index<0)return;
        const next=preview.choices[index].action;if(!next){notify("Root unavailable; nothing was stopped.","warning");return;}reviewed.push(next);
      }
      const modeLabel=await ctx.ui.select("Choose process action",["End task","End process tree"]);
      if(!["End task","End process tree"].includes(modeLabel))return;
      const mode=modeLabel==="End task"?"task":"tree",plan=combineActions(reviewed.map(a=>({...a,mode})));
      if(mode==="tree"&&plan.issues.length){notify(`Tree safety unavailable: ${safeText(plan.issues.join("; "),250)}. Nothing was stopped.`,"warning");return;}
      const scope=plan.roots.map(p=>`PID ${p.pid} (${safeText(p.name,40)}), ${p.windowHandles?.length??0} root windows`).join("\n");
      const warning=mode==="task"?"Request closure of all root windows within one shared grace interval, then force only still-live original roots. A windowless root uses root-force fallback; children may remain."
        :"Force the frozen roots and ALL currently verified descendants, including GUI, cross-session and newly verified children. Parents stop before children. No save opportunity.";
      const affirmative=`Confirm ${modeLabel}`;
      if(await ctx.ui.select(`Confirm closure and unsaved-data risk\n${scope}\n${plan.treeTargets.length} captured tree identities.\n${warning}\nUnsaved data may be lost. Save your work before confirming.`,["Cancel",affirmative])!==affirmative)return;
      const frozenRoots=Object.freeze(plan.roots.map(p=>Object.freeze({...p}))),frozen={...plan,roots:frozenRoots};
      const fresh=await deps.collect(),validated=refreshActions([frozen],fresh);
      if(!validated){notify("Selected identity or safety changed; nothing was stopped. Review fresh options.","warning");return;}
      const batch=combineActions(validated);
      if(batch.roots.some(p=>!frozenRoots.some(root=>processIdentity(root)===processIdentity(p))))throw new Error("Root expansion");
      attempting=true;const result=await deps.execute(batch,{baseline:fresh});attempting=false;
      const completed=result?.state==="completed"&&Array.isArray(result.failed)&&result.failed.length===0;
      notify(safeText(result?.message??"Execution receipt unavailable. Remaining selections were kept. No automatic retry.",1000),completed?"info":"warning");
      for(const key of ["rootsAlive","childrenAlive","newInScope","possible"]) {
        const ids=result?.[key];if(Array.isArray(ids)&&ids.length)notify(`${key}: ${ids.slice(0,50).map(p=>`${p.pid}:${p.startedMs}`).join(", ")}`,"warning");
      }
      if(!completed)notify("Batch stopped; remaining selections were kept. No automatic retry.","warning");
    }catch{
      notify(attempting?"Close outcome unconfirmed; remaining selections were kept. No automatic retry.":"/ram could not finish; no further close action was run.","warning");
    }finally{busy=false;}
  };
}
export default function(pi,toolkit) {
  pi.registerCommand("ram",{description:"Show every process, review roots and confirm closure",
    handler:createRamHandler({...createWindowsAdapter(),pickRows:(snapshot,rows,ctx)=>showTablePicker(snapshot,rows,ctx,toolkit)})});
}
