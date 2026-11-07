// Display-only metadata. Nothing here selects a process or authorizes an action.
const text=(v,n=100)=>String(v??'').replace(/\x1b\][\s\S]*?(?:\x07|\x1b\\)/g,'').replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'')
  .replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/g,'').trim().slice(0,n);
const basename=v=>String(v??'').replace(/\\/g,'/').replace(/\/+$/,'').split('/').at(-1)??'';
const token=v=>{const s=text(v,80);return /^[\w@][\w .@+/-]*$/.test(s)?s:'';};
const stem=v=>basename(v).replace(/\.exe$/i,'').toLowerCase();
const wrappers=new Set(['sh','bash','zsh','dash','pwsh','powershell','cmd','conhost']);
const interpreters=new Set(['node','nodejs','python','python3','pythonw','ruby','perl','bun','deno']);
const entryLabel=value=>{
  const path=String(value??'').replace(/\\/g,'/'),matches=[...path.matchAll(/(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)/g)];
  return token(matches.at(-1)?.[1]??basename(path));
};
export function processAttribution(p) {
  const name=stem(p.name),tokens=String(p.commandLine??'').slice(0,8192).match(/"[^"]*"|'[^']*'|[^\s]+/g)?.slice(0,128)
    .map(t=>t.replace(/^["']|["']$/g,''))??[];
  let programLabel='';
  if(interpreters.has(name)||wrappers.has(name)) {
    for(let i=1;i<tokens.length;i++) {
      const t=tokens[i];
      if(['-e','--eval','-p','--print','-EncodedCommand','-enc','-Command','-c','/c','/k'].some(f=>f.toLowerCase()===t.toLowerCase()))break;
      if(t==='-m'&&name.startsWith('python')){programLabel=token(tokens[i+1]);break;}
      if(['--import','--loader','--require','-r'].includes(t)){i++;continue;}
      if(t==='--')continue;
      if(t.startsWith('-')) {
        if(/^(?:--(?:no-warnings|trace-warnings|inspect(?:-brk)?(?:=.*)?|import=.+|loader=.+)|-[uBO])$/.test(t))continue;
        break;
      }
      programLabel=entryLabel(t);break;
    }
  }
  return {programLabel,cwd:text(p.cwd,240)};
}
export function groupAttribution(root,members,metadata=[]) {
  const meaningful=members.filter(p=>!wrappers.has(stem(p.name))),ordered=[...meaningful,...members.filter(p=>wrappers.has(stem(p.name)))];
  const representative=meaningful[0]??root,name=text(representative.programLabel||representative.name,50);
  const pids=new Set(members.map(p=>p.pid));
  const jobs=[...new Map(metadata.filter(m=>pids.has(m.pid)).map(m=>[m.paneId,m])).values()];
  const context=jobs.map(m=>`${text(m.name||m.label||'Job',45)}${m.status?` (${m.status})`:''}`).join(', ');
  const description=ordered.map(p=>text(p.description)).find(d=>d&&!/^(?:purpose )?unknown$/i.test(d));
  const cwd=basename(jobs.find(m=>m.cwd)?.cwd||ordered.find(p=>p.cwd)?.cwd);
  const active=jobs.some(m=>m.status==='working'),guidance=active?'Active: save':jobs.some(m=>m.status==='idle'||m.status==='done')?'Idle: review':'Review/save';
  const purpose=[context&&(jobs.length>1?`${jobs.length} jobs: ${context}`:context),cwd&&`Folder: ${text(cwd,60)}`,description,
    !description&&representative.programLabel&&`Program: ${representative.programLabel}`].filter(Boolean).join(' · ')||'Purpose unknown';
  return {name,description:`${guidance} · ${purpose}`,label:`${active?'Active agent/job':'Review'} · ${jobs.length>1?`${jobs.length} jobs · `:''}${name} · root PID ${root.pid} (${text(root.name,24)}) · Save work · ${purpose}`};
}
export async function readHerdrAttribution({run,env=process.env}={}) {
  if(env.HERDR_ENV!=='1'||typeof run!=='function')return [];
  const metadata=[],deadline=performance.now()+1500;
  const read=async args=>{
    const remaining=Math.floor(deadline-performance.now());if(remaining<=0)throw new Error('Metadata budget');
    const raw=await run(args,{timeoutMs:Math.min(350,remaining)});
    if(typeof raw!=='string'||raw.length>1024*1024)throw new Error('Metadata unavailable');return JSON.parse(raw);
  };
  try {
    const s=(await read(['api','snapshot'])).result?.snapshot;
    if(!Array.isArray(s?.panes)||!Array.isArray(s?.agents))return [];
    const agents=new Map(s.agents.slice(0,256).map(a=>[a.pane_id,a]));
    const panes=[...s.panes].sort((a,b)=>Number(agents.has(b.pane_id))-Number(agents.has(a.pane_id)));
    for(const pane of panes.slice(0,32)) {
      if(typeof pane.pane_id!=='string'||!/^[-\w:]+$/.test(pane.pane_id))continue;
      const agent=agents.get(pane.pane_id),base={paneId:pane.pane_id,name:text(agent?.name,45),label:text(pane.label,45),cwd:text(pane.cwd,240),
        status:['working','idle','done','blocked','unknown'].includes(agent?.agent_status??pane.agent_status)?agent?.agent_status??pane.agent_status:''};
      metadata.push({...base,pid:null});
      try {
        const info=(await read(['pane','process-info','--pane',pane.pane_id])).result?.process_info;
        for(const process of [{pid:info?.shell_pid},...(Array.isArray(info?.foreground_processes)?info.foreground_processes.slice(0,64):[])])
          if(Number.isSafeInteger(process.pid)&&process.pid>0)metadata.push({...base,pid:process.pid,cwd:text(process.cwd||base.cwd,240)});
      }catch{if(performance.now()>=deadline)break;}
    }
  }catch{}
  return metadata;
}
