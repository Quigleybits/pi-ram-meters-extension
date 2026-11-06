import {GB,safeText} from "./core.js";
import {bar} from "./display.js";
function header(s){return `RAM ${(s.freeBytes/GB).toFixed(1)} / ${(s.totalBytes/GB).toFixed(1)} GB free (${Math.round(100*s.freeBytes/s.totalBytes)}%) ${bar(s.freeBytes/s.totalBytes)}`;}
function rowText(r,largest) {
  const ws=Number.isFinite(r.workingSetBytes)?(r.workingSetBytes/GB).toFixed(2):"?";
  const estimate=r.estimatedBytes===null?"?":(r.estimatedBytes/GB).toFixed(2);
  return `${String(r.pid).padStart(6)} ${("  ".repeat(Math.min(r.depth,5))+r.name).slice(0,26).padEnd(26)} ${ws.padStart(6)} ${estimate.padStart(7)} ${bar(r.workingSetBytes/largest)} ${r.count} scope · ${safeText(r.reason||r.description,120)}`;
}
export function renderTableReport(s,rows) {
  const largest=Math.max(1,...rows.map(r=>r.workingSetBytes??0));
  return [header(s),"Processes (working set, incl. shared) · ~Free GB: private-byte tree estimates","   PID Process                     WS GB Tree~GB Relative Scope · Purpose / availability",
    ...rows.map(r=>rowText(r,largest)),...(!rows.length?["Process list unavailable."]:[]),...(s.diagnostics??[]).map(d=>`Note: ${safeText(d,140)}`)].join("\n");
}
export function createTablePicker({snapshot,rows,done,requestRender,keyMatches,theme,getHeight=()=>Infinity,truncate=(t,n)=>t.slice(0,n)}) {
  const selected=new Set();let focus=0,offset=0,closed=false,status="",query="",searching=false;
  const filtered=()=>rows.filter(r=>!query||`${r.pid} ${r.name}`.toLowerCase().includes(query.toLowerCase()));
  const finish=value=>{if(!closed){closed=true;done(value);}};
  return {
    render(width) {
      const visible=filtered(),size=Number.isInteger(width)&&width>0?width:1,requested=getHeight();
      const capacity=Number.isFinite(requested)?Math.max(1,Math.floor(requested)-6):Math.max(1,visible.length);
      focus=Math.min(focus,visible.length);if(focus<offset)offset=focus;if(focus>=offset+capacity)offset=focus-capacity+1;
      offset=Math.max(0,Math.min(offset,Math.max(0,visible.length-capacity)));
      const largest=Math.max(1,...rows.map(r=>r.workingSetBytes??0)),end=Math.min(visible.length,offset+capacity);
      const lines=[header(snapshot),`Processes · / search PID/name${query?`: ${safeText(query)}`:""} · ${rows.length} total · private-byte tree estimates`,
        "   PID Process                     WS GB Tree~GB Relative Scope · Purpose / availability"];
      for(let i=offset;i<end;i++){const r=visible[i],tick=selected.has(r.id)?theme.fg("success","✓"):r.actions.length?" ":"-";lines.push(`${focus===i?">":" "}[${tick}] ${rowText(r,largest)}`);}
      if(!visible.length)lines.push("No matching processes.");
      lines.push(searching?"Type search · Backspace edit · Enter finish · Esc clear":status||visible[focus]?.label||"↑↓ move · Space select · End then Enter review · Esc cancel");
      lines.push(theme.fg(selected.size?"error":"muted",`${focus===visible.length?"> ":"  "}Kill (${selected.size} selected roots) · review scope next`));
      return lines.map(l=>truncate(l,size));
    },
    handleInput(data) {
      if(closed)return;
      if(searching) {
        if(keyMatches(data,"cancel")){query="";searching=false;}
        else if(keyMatches(data,"enter"))searching=false;
        else if(data==="\x7f"||data==="\b")query=query.slice(0,-1);
        else if(typeof data==="string"&&/^[^\x00-\x1f\x7f]+$/.test(data))query=(query+data).slice(0,100);
        focus=0;offset=0;requestRender();return;
      }
      const visible=filtered();
      if(keyMatches(data,"cancel")){finish(undefined);return;}
      if(data==="/"){searching=true;query="";focus=0;}
      else if(keyMatches(data,"up"))focus=Math.max(0,focus-1);
      else if(keyMatches(data,"down"))focus=Math.min(visible.length,focus+1);
      else if(keyMatches(data,"home"))focus=0;
      else if(keyMatches(data,"end"))focus=visible.length;
      else if(keyMatches(data,"space")&&focus<visible.length) {
        const row=visible[focus];if(!row.actions.length)status=row.reason||"Identity/access unavailable";
        else{selected.has(row.id)?selected.delete(row.id):selected.add(row.id);status="";}
      }else if(keyMatches(data,"enter")&&focus===visible.length) {
        if(selected.size){finish({intent:"kill",rowIds:[...selected]});return;}status="Select a process with Space.";
      }
      requestRender();
    },invalidate(){}
  };
}
export async function showTablePicker(snapshot,rows,ctx,toolkit) {
  const {matchesKey,truncateToWidth,isKeyRelease,isKeyRepeat}=toolkit;
  return ctx.ui.custom((tui,theme,keybindings,done)=>createTablePicker({snapshot,rows,done,theme,
    getHeight:()=>Math.max(6,tui.terminal.rows-8),requestRender:()=>tui.requestRender(),truncate:truncateToWidth,
    keyMatches:(data,action)=>{
      if(isKeyRelease(data)||(["space","enter"].includes(action)&&isKeyRepeat(data)))return false;
      return action==="cancel"?keybindings.matches(data,"tui.select.cancel")||matchesKey(data,"ctrl+c")
        :action==="up"||action==="down"?keybindings.matches(data,`tui.select.${action}`):matchesKey(data,action);
    }}));
}
