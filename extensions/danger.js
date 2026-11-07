// Relative display hints only. Eligibility, selection and execution never use these rules.
import {safeText} from './core.js';
const styles=Object.freeze({
  lower:Object.freeze({level:'lower',color:'success',label:'Lower risk'}),
  caution:Object.freeze({level:'caution',color:'warning',foreground:Object.freeze({kind:'rgb',r:255,g:140,b:0}),label:'Caution'}),
  danger:Object.freeze({level:'danger',color:'error',label:'Danger'})
});
const name=p=>String(p.name??'').replace(/\\/g,'/').split('/').at(-1);
const description=p=>safeText(`${name(p)} ${p.description??''} ${p.programLabel??''}`,300);
const agentOrSystem=p=>/\b(?:herdr|agent|codex|claude|pi-coding-agent|system process|system service)\b/i.test(description(p));
const caution=p=>/\b(?:editor|IDE|terminal|shell|console|document|spreadsheet)\b/i.test(description(p))
  ||/^(?:sh|bash|zsh|dash|pwsh|powershell|cmd|conhost)(?:\.exe)?$/i.test(name(p));
const lower=p=>/\b(?:browser|helper|renderer|crash handler|crash reporter)\b/i.test(description(p))
  ||/^(?:chrome|msedge|firefox|brave|opera|vivaldi)(?:\.exe)?$/i.test(name(p));
export const DANGER_RULES=Object.freeze([
  {level:'danger',matches:({members,context,pids})=>members.some(p=>p.critical===true||p.serviceCount>0||p.pid===0||p.pid===4
    ||context.protection?.has(`${p.pid}:${p.startedMs}`)||p.pid===context.shellIdentity?.pid||agentOrSystem(p))
    ||(context.herdrAttribution??[]).some(m=>pids.has(m.pid))},
  {level:'caution',matches:({members})=>!members.length||members.some(p=>caution(p)||!lower(p))},
  {level:'lower',matches:()=>true}
]);
export function groupDanger(members,context={}) {
  const facts={members,context,pids:new Set(members.map(p=>p.pid))};
  return styles[DANGER_RULES.find(rule=>rule.matches(facts)).level];
}
