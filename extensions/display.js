import {safeText} from "./core.js";
export function describeProcess(p) {
  return {purpose:typeof p==="object"&&p?.description?safeText(p.description):"Purpose unknown",
    effect:"Unsaved data may be lost",level:"Risk",dot:"●"};
}
export function describeOption(option) {return {...describeProcess(option),name:`${safeText(option.label||'Process')} PID ${option.roots?.map(p=>p.pid).join(', ')}`};}
export function bar(fraction,width=8) {
  const size=Number.isInteger(width)?Math.max(1,Math.min(20,width)):8;
  const fill=Math.round((Number.isFinite(fraction)?Math.max(0,Math.min(1,fraction)):0)*size);
  return "█".repeat(fill)+"░".repeat(size-fill);
}
