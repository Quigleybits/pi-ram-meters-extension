import {execFile} from "node:child_process";
import {promisify} from "node:util";
import {freemem,totalmem} from "node:os";
import {validIdentity} from "./ownership.js";
import {parseProcesses} from "./core.js";
import {readHerdrAttribution} from "./attribution.js";
import {NATIVE_PRELUDE} from "./native.js";
import {buildAppPhaseScript} from "./app-script.js";
import {executeApplication} from "./closure.js";
export {buildAppPhaseScript} from "./app-script.js";
export {observeApplication} from "./observation.js";
export {executeApplication} from "./closure.js";
const encode=source=>["-NoLogo","-NoProfile","-NonInteractive","-EncodedCommand",Buffer.from(source,"utf16le").toString("base64")];
const execAsync=promisify(execFile);
const defaultRun=async(file,args,{timeoutMs=15000}={})=>{
  let input;
  if(args.at(-1).length>16000){input=Buffer.from(args.at(-1),"base64").toString("utf16le");args=encode("& ([ScriptBlock]::Create([Console]::In.ReadToEnd()))");}
  const pending=execAsync(file,args,{encoding:"utf8",windowsHide:true,timeout:timeoutMs,maxBuffer:16*1024*1024});
  if(input!==undefined){pending.child.stdin.on("error",()=>{});pending.child.stdin.end(input);}return (await pending).stdout;
};
const processRows=String.raw`
$rows=@();$descriptionCache=@{}
foreach($p in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
  $h=$null;$birth=$null;$image=$p.ExecutablePath;$account=$null;$critical=$null;$canQuery=$false
  try{if($null -ne $p.CreationDate){$birth=([DateTimeOffset]$p.CreationDate.ToUniversalTime()).ToUnixTimeMilliseconds()}}catch{}
  try{
    $h=[RamNative]::Open([int]$p.ProcessId,$false)
    if($null -eq $birth -or $h.StartedMs -ne $birth -or $h.SessionId -ne [int]$p.SessionId -or $h.IsExited()){throw 'Changed process'}
    $image=$h.Image;$account=$h.AccountSid;$critical=$h.IsCritical();$canQuery=$true
  }catch{}finally{if($null -ne $h){$h.Dispose()}}
  $description=''
  if($image){
    if(!$descriptionCache.ContainsKey([string]$image)){
      $value='';try{$value=[string][Diagnostics.FileVersionInfo]::GetVersionInfo([string]$image).FileDescription}catch{}
      $descriptionCache[[string]$image]=$value.Trim()
    }
    $description=$descriptionCache[[string]$image]
  }
  $cpu=$null;if($null -ne $p.KernelModeTime -and $null -ne $p.UserModeTime){$cpu=([double]$p.KernelModeTime+[double]$p.UserModeTime)/10000000}
  $rows += [pscustomobject]@{pid=[int]$p.ProcessId;ppid=[int]$p.ParentProcessId;name=$p.Name;startedMs=$birth;executablePath=$image;
    sessionId=[int]$p.SessionId;accountSid=$account;critical=$critical;canQuery=$canQuery;cpuSeconds=$cpu;description=$description;commandLine=$p.CommandLine;
    workingSetBytes=if($null -ne $p.WorkingSetSize){[double]$p.WorkingSetSize}else{$null};
    privateBytes=if($null -ne $p.PrivatePageCount){[double]$p.PrivatePageCount}else{$null};windowHandles=@();serviceCount=0}
}
`;
export const SNAPSHOT_SCRIPT=NATIVE_PRELUDE+processRows+String.raw`
$boundaries=$true;$shell=0;$windows=@();$services=@{}
try{$shell=[RamNative]::ShellPid();$windows=@([RamNative]::Windows())
 foreach($service in @(Get-CimInstance Win32_Service -ErrorAction Stop)){
   if($service.ProcessId -gt 0){$key=[string]$service.ProcessId;$services[$key]=1+[int]$services[$key]}
 }
}catch{$boundaries=$false}
foreach($p in $rows){$p.windowHandles=@($windows|Where-Object {$_.Pid -eq $p.pid}|ForEach-Object {[string]$_.Handle});$p.serviceCount=if($boundaries){[int]$services[[string]$p.pid]}else{$null}}
[pscustomobject]@{complete=$true;boundariesComplete=$boundaries;shellPid=$shell;processes=@($rows)}|ConvertTo-Json -Depth 6 -Compress
`;
export function buildObservationScript(lineage=[]) {
  if(!Array.isArray(lineage)||lineage.length>1000||lineage.some(p=>!validIdentity(p)))throw new Error("Invalid observation lineage");
  const payload=Buffer.from(JSON.stringify(lineage.map(p=>({pid:p.pid,startedMs:p.startedMs})))).toString("base64");
  return NATIVE_PRELUDE+`
# RAM observation: complete generic metadata; native probes only for candidate lineage.
$observationLineage=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}'))|ConvertFrom-Json
$known=@{};foreach($p in $observationLineage){$known[[string]$p.pid]=[long]$p.startedMs}
$rows=@();$byPid=@{};$candidate=@{}
foreach($p in @(Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,Name,CreationDate,SessionId,ExecutablePath -ErrorAction Stop)) {
  $birth=$null;try{if($null -ne $p.CreationDate){$birth=([DateTimeOffset]$p.CreationDate.ToUniversalTime()).ToUnixTimeMilliseconds()}}catch{}
  $row=[pscustomobject]@{pid=[int]$p.ProcessId;ppid=[int]$p.ParentProcessId;name=$p.Name;startedMs=$birth;
    executablePath=$p.ExecutablePath;sessionId=[int]$p.SessionId;accountSid=$null;critical=$null;canQuery=$false}
  $rows+=$row;$byPid[[string]$row.pid]=$row
  if($null -ne $birth -and $known.ContainsKey([string]$row.pid) -and $known[[string]$row.pid] -eq $birth){$candidate[[string]$row.pid]=$true}
}
do {
  $changed=$false
  foreach($p in $rows) {
    if($candidate.ContainsKey([string]$p.pid) -or -not $candidate.ContainsKey([string]$p.ppid)){continue}
    $parent=$byPid[[string]$p.ppid]
    if($null -ne $p.startedMs -and $p.startedMs -ge $parent.startedMs){$candidate[[string]$p.pid]=$true;$changed=$true}
  }
}while($changed)
foreach($p in $rows) {
  if(-not $candidate.ContainsKey([string]$p.pid)){continue};$h=$null
  try{$h=[RamNative]::Open([int]$p.pid,$false)
    if($h.IsExited() -or $h.StartedMs -ne [long]$p.startedMs -or $h.SessionId -ne [int]$p.sessionId){throw 'Changed observation identity'}
    $p.executablePath=$h.Image;$p.accountSid=$h.AccountSid;$p.canQuery=$true
  }catch{}finally{if($null -ne $h){$h.Dispose()}}
}
[pscustomobject]@{complete=$true;processes=@($rows);probeCount=$candidate.Count}|ConvertTo-Json -Depth 6 -Compress
`;
}
export const OBSERVATION_SCRIPT=buildObservationScript();
export function createWindowsAdapter({run=defaultRun,platform=process.platform,selfPid=process.pid,
  memoryInfo=()=>({freeBytes:freemem(),totalBytes:totalmem()}),now=Date.now,clock=()=>performance.now(),sleep=ms=>new Promise(r=>setTimeout(r,ms)),
  env=process.env,herdrRun=run===defaultRun?(args,options)=>defaultRun(env.HERDR_BIN_PATH||"herdr",args,options):null}={}) {
  const powershell=(source,options)=>run("powershell.exe",encode(source),options);
  const requireWindows=()=>{if(platform!=="win32")throw new Error("Windows is required");};
  const adapter={
    async collect() {
      requireWindows();
      let parsed;try{parsed=parseProcesses(await powershell(SNAPSHOT_SCRIPT));}catch{parsed={processes:[],complete:false,boundariesComplete:false};}
      const controllerIdentity=parsed.processes.find(p=>p.pid===selfPid),shellIdentity=parsed.processes.find(p=>p.pid===parsed.shellPid);
      const herdrAttribution=await readHerdrAttribution({run:herdrRun,env});
      return {...memoryInfo(),now:now(),processes:parsed.processes,processesComplete:parsed.complete,ownershipComplete:!!controllerIdentity?.canQuery,
        boundariesComplete:parsed.boundariesComplete,controllerIdentity,shellIdentity,herdrAttribution,
        diagnostics:[...(!parsed.complete?["Process enumeration incomplete; actions disabled."]:[]),
          ...(!controllerIdentity?.canQuery?["Controller identity unavailable; actions disabled."]:[]),
          ...(!parsed.boundariesComplete?["OS boundary facts incomplete; app-group safety/actions disabled."]:[])]};
    },
    async readProcesses({timeoutMs=5000,lineage=[]}={}) {
      requireWindows();const parsed=parseProcesses(await powershell(buildObservationScript(lineage),{timeoutMs}));
      return {...parsed,processesComplete:parsed.complete};
    },
    async execute(option,{baseline}={}) {
      requireWindows();if(option?.kind!=="process"||option.actionable!==true)throw new Error("Invalid process action");
      return executeApplication(option,baseline,{clock,sleep,collectGuarded:()=>adapter.collect(),
        runPhase:(action,phase)=>powershell(buildAppPhaseScript(action,phase)),
        readProcesses:options=>adapter.readProcesses(options)});
    }
  };return adapter;
}
