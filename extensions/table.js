import {GB,safeText} from "./core.js";
import {bar} from "./display.js";
function header(s){return `RAM ${(s.freeBytes/GB).toFixed(1)} / ${(s.totalBytes/GB).toFixed(1)} GB free (${Math.round(100*s.freeBytes/s.totalBytes)}%) ${bar(s.freeBytes/s.totalBytes)}`;}
const known=value=>Number.isFinite(value)&&value>=0;
const largestSet=rows=>rows.reduce((largest,r)=>known(r.workingSetBytes)?Math.max(largest,r.workingSetBytes):largest,1);
const columns=`${"App name".padEnd(24)} ${"WS GB".padStart(6)} ${"Priv~GB".padStart(7)} Relative · Risk hint / Purpose`;
function rowText(r,largest) {
  const ws=known(r.workingSetBytes)?(r.workingSetBytes/GB).toFixed(2):"?";
  const estimate=known(r.estimatedBytes)?(r.estimatedBytes/GB).toFixed(2):"?";
  return `${safeText(r.name,24).padEnd(24)} ${ws.padStart(6)} ${estimate.padStart(7)} ${known(r.workingSetBytes)?bar(r.workingSetBytes/largest):"????????"} · ${r.danger?.label??"Caution"} · ${safeText(r.description,120)}`;
}
export function renderTableReport(s,rows) {
  const largest=largestSet(rows),unknown=rows.filter(r=>!known(r.workingSetBytes)).length;
  return [header(s),`App/root trees · WS sum GB (incl. shared) · Priv~GB: private bytes${unknown?` · ${unknown} WS totals unranked`:""}`,columns,
    ...rows.map(r=>rowText(r,largest)),
    ...(!rows.length?["No eligible app trees."]:[]),...(s.diagnostics??[]).map(d=>`Note: ${safeText(d,140)}`)].join("\n");
}
export function createTablePicker({snapshot,rows,done,requestRender,keyMatches,theme,getHeight=()=>Infinity,truncate=(t,n)=>t.slice(0,n)}) {
  const selected=new Set();let focus=0,offset=0,closed=false,status="",query="",searching=false;
  const items=()=>rows.filter(r=>!query||`${r.pid} ${r.name}`.toLowerCase().includes(query.toLowerCase())).map(row=>({row}));
  const paint=(r,text)=>r.danger?.foreground&&typeof theme.style==="function"
    ?theme.style(text,{fg:r.danger.foreground}):theme.fg(r.danger?.color??"warning",text);
  const finish=value=>{if(!closed){closed=true;done(value);}};
  return {
    render(width) {
      const visible=items(),size=Number.isInteger(width)&&width>0?width:1,requested=getHeight();
      const height=Number.isFinite(requested)?Math.max(1,Math.floor(requested)):16,capacity=height>=6?height-5:height-1;
      focus=Math.min(focus,visible.length);if(focus<offset)offset=focus;if(capacity&&focus>=offset+capacity)offset=focus-capacity+1;
      offset=Math.max(0,Math.min(offset,Math.max(0,visible.length-capacity)));
      const largest=largestSet(rows),unknown=rows.filter(r=>!known(r.workingSetBytes)).length,end=Math.min(visible.length,offset+capacity);
      const lines=height>=6?[header(snapshot),`App/root trees · WS sum GB (incl. shared) · / search${query?`: ${safeText(query)}`:""}${unknown?` · ${unknown} unranked`:""}`,`     ${columns}`]:[];
      for(let i=offset;i<end;i++) {
        const r=visible[i].row,prefix=`${focus===i?">":" "}[`,body=`] ${rowText(r,largest)}`;
        lines.push(selected.has(r.id)?paint(r,prefix)+theme.fg("success","✓")+paint(r,body):paint(r,`${prefix} ${body}`));
      }
      if(!visible.length&&capacity)lines.push(query?"No matching app trees.":"No eligible app trees.");
      if(height>=6)lines.push(searching?"Type search · Backspace edit · Tab review · Esc clear":status||visible[focus]?.row?.label||"↑↓ move · Space select · Tab then Enter review · Esc cancel");
      lines.push(theme.fg(selected.size?"error":"muted",`${focus===visible.length?"> ":"  "}Kill (${selected.size} selected app trees) · review scope next`));
      return lines.map(l=>truncate(l,size));
    },
    handleInput(data) {
      if(closed)return;
      if(keyMatches(data,"tab")){searching=false;focus=items().length;status="";requestRender();return;}
      if(searching) {
        if(keyMatches(data,"cancel")){query="";searching=false;}
        else if(keyMatches(data,"enter"))searching=false;
        else if(data==="\x7f"||data==="\b")query=query.slice(0,-1);
        else if(typeof data==="string"&&/^[^\x00-\x1f\x7f]+$/.test(data))query=(query+data).slice(0,100);
        focus=0;offset=0;requestRender();return;
      }
      const visible=items();
      if(keyMatches(data,"cancel")){finish(undefined);return;}
      if(data==="/"){searching=true;query="";focus=0;}
      else if(keyMatches(data,"up"))focus=Math.max(0,focus-1);
      else if(keyMatches(data,"down"))focus=Math.min(visible.length,focus+1);
      else if(keyMatches(data,"home"))focus=0;
      else if(keyMatches(data,"end"))focus=visible.length;
      else if(keyMatches(data,"space")&&focus<visible.length) {
        const row=visible[focus].row;selected.has(row.id)?selected.delete(row.id):selected.add(row.id);status="";
      }else if(keyMatches(data,"enter")&&focus===visible.length) {
        if(selected.size){finish({intent:"kill",rowIds:[...selected]});return;}status="Select an app tree with Space.";
      }
      requestRender();
    },invalidate(){}
  };
}
export async function showTablePicker(snapshot,rows,ctx,toolkit) {
  const {matchesKey,truncateToWidth,isKeyRelease,isKeyRepeat}=toolkit;
  return ctx.ui.custom((tui,theme,keybindings,done)=>createTablePicker({snapshot,rows,done,theme,
    getHeight:()=>Math.max(1,tui.terminal.rows-8),requestRender:()=>tui.requestRender(),truncate:truncateToWidth,
    keyMatches:(data,action)=>{
      if(isKeyRelease(data)||(["space","enter"].includes(action)&&isKeyRepeat(data)))return false;
      return action==="cancel"?keybindings.matches(data,"tui.select.cancel")||matchesKey(data,"ctrl+c")
        :action==="up"||action==="down"?keybindings.matches(data,`tui.select.${action}`):matchesKey(data,action);
    }}));
}
