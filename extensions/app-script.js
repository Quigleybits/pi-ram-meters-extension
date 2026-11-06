import {processIdentity,sameProcess,validIdentity,validEdge} from "./ownership.js";
import {NATIVE_PRELUDE} from "./native.js";
export function phaseTargets(option,phase) {
  if(!["task","tree"].includes(option?.mode)||!["grace","force"].includes(phase)||!Array.isArray(option.roots)
    ||!option.roots.length||option.roots.length>32||!Array.isArray(option.treeTargets)||option.treeTargets.length>1000)throw new Error("Invalid process plan");
  const roots=new Map(option.roots.map(p=>[processIdentity(p),p])),scope=new Map(option.treeTargets.map(p=>[processIdentity(p),p]));
  if(roots.size!==option.roots.length||scope.size!==option.treeTargets.length||new Set(option.treeTargets.map(p=>p.pid)).size!==scope.size)throw new Error("Duplicate identities");
  for(const p of option.treeTargets) {
    if(!validIdentity(p)||!roots.has(p.rootIdentity)||!Number.isInteger(p.depth)||p.depth<0)throw new Error("Invalid tree identity");
    if(roots.has(processIdentity(p))) {
      if(!sameProcess(p,roots.get(processIdentity(p)))||p.depth!==0||p.parentIdentity!==null||p.rootIdentity!==processIdentity(p))throw new Error("Invalid root");
    } else {
      const parent=scope.get(p.parentIdentity);
      if(!validEdge(parent,p)||parent.depth+1!==p.depth||parent.rootIdentity!==p.rootIdentity)throw new Error("Invalid tree edge");
    }
  }
  for(const p of option.roots)if(!sameProcess(p,scope.get(processIdentity(p))))throw new Error("Root absent from scope");
  return phase==="force"&&option.mode==="tree"?[...option.roots,...option.treeTargets.filter(p=>!roots.has(processIdentity(p))).sort((a,b)=>a.depth-b.depth||a.pid-b.pid)]:[...option.roots];
}
const fields=p=>({pid:p.pid,ppid:p.ppid,startedMs:p.startedMs,executablePath:p.executablePath,sessionId:p.sessionId,
  accountSid:p.accountSid,depth:p.depth,parentIdentity:p.parentIdentity,rootIdentity:p.rootIdentity,rootPid:p.rootPid});
export function buildAppPhaseScript(option,phase,{waitMs=5000,budgetMs=10000,maxMembers=1000,maxScans=64}={}) {
  const targets=phaseTargets(option,phase);
  if(!validIdentity(option.controllerIdentity)||!Number.isSafeInteger(waitMs)||waitMs<1||waitMs>5000||!Number.isSafeInteger(budgetMs)||budgetMs<1||budgetMs>10000
    ||!Number.isInteger(maxMembers)||maxMembers<targets.length||maxMembers>1000||!Number.isInteger(maxScans)||maxScans<1||maxScans>128)throw new Error("Invalid execution bounds/controller");
  const payload=Buffer.from(JSON.stringify({targets:targets.map(fields),roots:option.roots.map(fields),controller:fields(option.controllerIdentity)})).toString("base64");
  return NATIVE_PRELUDE+`
$plan=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}'))|ConvertFrom-Json
$isTree=$${option.mode==="tree"&&phase==="force"?"true":"false"};$isGrace=$${phase==="grace"?"true":"false"}
$members=[Collections.Specialized.OrderedDictionary]::new();$handles=@{};$status=@{};$evidence=@{};$parentExit=@{}
$forced=[Collections.Generic.List[int]]::new();$attempted=[Collections.Generic.List[int]]::new()
$requested=[Collections.Generic.HashSet[int]]::new();$windows=[Collections.Generic.HashSet[long]]::new();$windowCounts=@{}
$already=[Collections.Generic.HashSet[int]]::new();$protected=@{}
$clock=[Diagnostics.Stopwatch]::StartNew();$preflight=$false;$operationComplete=$false;$discovery=@{count=0};$effect=$false
function Identity($p){return ([string]$p.pid)+':'+([string]$p.startedMs)}
function Budget {if($clock.ElapsedMilliseconds -ge ${budgetMs}){throw 'Operation deadline'}}
function Birth($row){if($null -eq $row.CreationDate){throw 'Unknown birth'};return ([DateTimeOffset]$row.CreationDate.ToUniversalTime()).ToUnixTimeMilliseconds()}
function Validate($p,$h,$allowCritical=$false) {
  if($h.Pid -ne [int]$p.pid -or $h.StartedMs -ne [long]$p.startedMs -or $h.SessionId -ne [int]$p.sessionId -or $h.AccountSid -ne [string]$p.accountSid -or -not [String]::Equals($h.Image,[string]$p.executablePath,[StringComparison]::OrdinalIgnoreCase)){throw 'Identity changed'}
  if(-not $allowCritical -and $h.IsCritical()){throw 'Critical process'}
}
function Acquire($p,$source,$exitMs=0) {
  Budget;$key=Identity $p;if($members.Contains($key)){return};if($members.Count -ge ${maxMembers}){throw 'Member budget'}
  $members.Add($key,$p);$status[$key]='pending';$evidence[$key]=$source;$parentExit[$key]=$exitMs
  $h=$null
  try{$h=[RamNative]::Open([int]$p.pid,$true)}
  catch{if($_.Exception -is [ArgumentException] -or $_.Exception.InnerException -is [ArgumentException]){$status[$key]='stopped';$null=$already.Add([int]$p.pid);return};throw}
  $handles[$key]=$h;Validate $p $h
  if($h.IsExited()){$status[$key]='stopped';$null=$already.Add([int]$p.pid)}else{$status[$key]='alive'}
}
function Controller($rows) {
  $protected.Clear();$c=$plan.controller;$seen=@{}
  while($null -ne $c) {
    Budget;$id=Identity $c;if($seen.ContainsKey($id)){throw 'Controller cycle'};$seen[$id]=$true;$h=$null
    try{$h=[RamNative]::Open([int]$c.pid,$false);Validate $c $h $true;if($h.IsExited()){throw 'Controller ancestor exited'}}finally{if($null -ne $h){$h.Dispose()}}
    $protected[$id]=$true;$row=$rows[[string]$c.pid]
    if($null -eq $row -or (Birth $row) -ne [long]$c.startedMs){throw 'Controller enumeration changed'}
    $parent=$rows[[string]$row.ParentProcessId];if($null -eq $parent){break};$birth=Birth $parent
    if($birth -gt [long]$c.startedMs){break};$ph=$null
    try{$ph=[RamNative]::Open([int]$parent.ProcessId,$false)
      if($ph.StartedMs -ne $birth -or $ph.SessionId -ne [int]$parent.SessionId){throw 'Controller parent changed'}
      $c=[pscustomobject]@{pid=[int]$parent.ProcessId;startedMs=$birth;sessionId=$ph.SessionId;accountSid=$ph.AccountSid;executablePath=$ph.Image}
    }finally{if($null -ne $ph){$ph.Dispose()}}
  }
}
function Sync-Scope {
  Budget;$discovery.count++;if($discovery.count -gt ${maxScans}){throw 'Discovery budget'}
  $rows=@{};foreach($row in @(Get-CimInstance Win32_Process -ErrorAction Stop)){
    $key=[string]$row.ProcessId;if($rows.ContainsKey($key)){throw 'Duplicate inventory'};$rows[$key]=$row
  }
  Controller $rows
  foreach($key in @($members.Keys)) {
    $p=$members[$key];if($protected.ContainsKey($key)){throw 'Selected controller lineage'}
    $h=$handles[$key]
    if($null -ne $h) {
      Validate $p $h
      if($h.IsExited()){if($status[$key] -ne 'stopped'){$null=$already.Add([int]$p.pid)};$status[$key]='stopped';continue}
      $row=$rows[[string]$p.pid]
      if($null -eq $row -or (Birth $row) -ne [long]$p.startedMs -or $row.SessionId -ne [int]$p.sessionId -or ($p.depth -gt 0 -and $row.ParentProcessId -ne [int]$p.ppid)){throw 'Current identity/edge changed'}
    }
  }
  if($isTree) {
    do {
      $changed=$false
      foreach($row in @($rows.Values)) {
        foreach($parentKey in @($members.Keys)) {
          $parent=$members[$parentKey];if([int]$row.ParentProcessId -ne [int]$parent.pid){continue}
          $birth=Birth $row;if($birth -lt [long]$parent.startedMs){continue}
          $key=([string]$row.ProcessId)+':'+([string]$birth);if($members.Contains($key)){continue}
          $ph=$handles[$parentKey];$source=$null;$exitMs=0
          if($null -ne $ph) {
            if(-not $ph.IsExited()) {
              $liveParent=$rows[[string]$parent.pid]
              if($null -ne $liveParent -and (Birth $liveParent) -eq [long]$parent.startedMs){$source='coobserved'}
            } else {
              $exitMs=$ph.ExitMs;if($exitMs -gt $birth -and $birth -ge [long]$parent.startedMs){$source='lifetime'}
            }
          }
          if($null -eq $source){throw 'Unconfirmed late descendant'}
          $h=$null
          try{$h=[RamNative]::Open([int]$row.ProcessId,$false)
            if($h.StartedMs -ne $birth -or $h.SessionId -ne [int]$row.SessionId){throw 'New child identity changed'}
            $p=[pscustomobject]@{pid=[int]$row.ProcessId;ppid=[int]$row.ParentProcessId;startedMs=$birth;sessionId=$h.SessionId;accountSid=$h.AccountSid;
              executablePath=$h.Image;depth=([int]$parent.depth+1);parentIdentity=$parentKey;rootIdentity=$parent.rootIdentity;rootPid=$parent.rootPid}
          }finally{if($null -ne $h){$h.Dispose()}}
          if($protected.ContainsKey($key)){throw 'Dynamic controller descendant'}
          Acquire $p $source $exitMs;$changed=$true
        }
      }
    }while($changed)
  }
  Budget
}
try {
  foreach($p in @($plan.targets)){Acquire $p 'confirmed'}
  Sync-Scope;$preflight=$true
  if($isGrace) {
    $deadline=[Math]::Min(${budgetMs},[int]$clock.ElapsedMilliseconds+${waitMs})
    do {
      Sync-Scope
      foreach($window in @([RamNative]::Windows())) {
        $root=@($plan.roots|Where-Object {$_.pid -eq $window.Pid})|Select-Object -First 1
        if($null -eq $root){continue};$key=Identity $root
        if($status[$key] -ne 'alive' -or $handles[$key].IsExited() -or $windows.Contains([long]$window.Handle)){continue}
        if($windows.Count -ge 1024){throw 'Window budget'}
        Validate $root $handles[$key]
        if(-not [RamNative]::WindowExists([long]$window.Handle)){continue}
        $owner=[RamNative]::WindowOwner([long]$window.Handle)
        if($owner -ne [int]$root.pid){
          if($owner -eq 0 -and -not [RamNative]::WindowExists([long]$window.Handle)){continue}
          throw 'Window owner changed'
        }
        if($handles[$key].IsExited()){continue}
        if(-not [RamNative]::CloseWindow([long]$window.Handle,[int]$root.pid)){continue}
        $null=$windows.Add([long]$window.Handle);$effect=$true
        $null=$requested.Add([int]$root.pid);$windowCounts[[string]$root.pid]=1+[int]$windowCounts[[string]$root.pid]
      }
      foreach($key in @($members.Keys)){if($null -ne $handles[$key] -and $handles[$key].IsExited()){$status[$key]='stopped'}}
      $alive=@($status.Values|Where-Object {$_ -eq 'alive'});$remaining=$deadline-[int]$clock.ElapsedMilliseconds
      if($alive.Count -and $remaining -gt 0){Start-Sleep -Milliseconds ([Math]::Min(100,$remaining))}
    }while($alive.Count -and $clock.ElapsedMilliseconds -lt $deadline)
  } else {
    while($true) {
      Sync-Scope
      $next=@($members.Values|Where-Object {$status[(Identity $_)] -eq 'alive'}|Sort-Object depth,pid)|Select-Object -First 1
      if($null -eq $next){break};$key=Identity $next
      if($next.depth -gt 0 -and $status[[string]$next.parentIdentity] -ne 'stopped'){throw 'Parent exit not confirmed'}
      $h=$handles[$key];Validate $next $h
      if($h.IsExited()){$status[$key]='stopped';$null=$already.Add([int]$next.pid);continue}
      Budget;$effect=$true;$attempted.Add([int]$next.pid);$h.Kill()
      $remaining=${budgetMs}-[int]$clock.ElapsedMilliseconds
      if($remaining -le 0 -or -not $h.WaitForExit($remaining)){throw 'Exit not confirmed'}
      $forced.Add([int]$next.pid);$status[$key]='stopped'
    }
  }
  $operationComplete=$true
} catch {
  foreach($key in @($members.Keys)){if($status[$key] -ne 'stopped'){$status[$key]='failed'}}
} finally {foreach($h in $handles.Values){$h.Dispose()}}
$identities=@();$stopped=@();$failed=@();$alivePids=@()
foreach($key in @($members.Keys)) {
  $p=$members[$key];$outcome=$status[$key]
  if($outcome -eq 'stopped'){$stopped+=([int]$p.pid)}elseif($outcome -eq 'alive'){$alivePids+=([int]$p.pid)}else{$outcome='failed';$failed+=([int]$p.pid)}
  $identities += [pscustomobject]@{pid=[int]$p.pid;ppid=[int]$p.ppid;startedMs=[long]$p.startedMs;executablePath=[string]$p.executablePath;
    sessionId=[int]$p.sessionId;accountSid=[string]$p.accountSid;depth=[int]$p.depth;parentIdentity=$p.parentIdentity;rootIdentity=$p.rootIdentity;rootPid=[int]$p.rootPid;
    evidence=$evidence[$key];parentExitMs=[long]$parentExit[$key];outcome=$outcome}
}
foreach($p in @($plan.targets)) {
  $key=Identity $p;if($members.Contains($key)){continue};$failed+=([int]$p.pid)
  $identities += [pscustomobject]@{pid=[int]$p.pid;ppid=[int]$p.ppid;startedMs=[long]$p.startedMs;executablePath=[string]$p.executablePath;
    sessionId=[int]$p.sessionId;accountSid=[string]$p.accountSid;depth=[int]$p.depth;parentIdentity=$p.parentIdentity;rootIdentity=$p.rootIdentity;rootPid=[int]$p.rootPid;
    evidence='confirmed';parentExitMs=0;outcome='failed'}
}
$counts=@();foreach($root in @($plan.roots)){$counts += [pscustomobject]@{pid=[int]$root.pid;requested=[int]$windowCounts[[string]$root.pid]}}
[pscustomobject]@{phase='${phase}';preflightComplete=$preflight;operationComplete=$operationComplete;stopped=@($stopped);failed=@($failed);alive=@($alivePids);
  forced=@($forced.ToArray());forceAttempted=@($attempted.ToArray());alreadyExited=@($already);closeRequested=@($requested);windowCounts=@($counts);
  identities=@($identities);elapsedMs=$clock.ElapsedMilliseconds;discoveryCount=$discovery.count;effectStarted=$effect;
  message='Process phase finished; inspect identity outcomes.'}|ConvertTo-Json -Depth 8 -Compress
`;
}
export function readPhaseReceipt(raw,option,phase) {
  const expected=phaseTargets(option,phase),r=typeof raw==="string"?JSON.parse(raw.replace(/^\ufeff/,"")):raw;
  if(!r||r.phase!==phase||typeof r.preflightComplete!=="boolean"||typeof r.operationComplete!=="boolean"||typeof r.message!=="string"||!Array.isArray(r.identities)
    ||r.identities.length>1000||r.identities.length<expected.length)throw new Error("Invalid receipt");
  const original=new Map(expected.map(p=>[processIdentity(p),p])),roots=new Map(option.roots.map(p=>[processIdentity(p),p])),scope=new Map(),pids=new Set();
  for(const p of r.identities) {
    if(!validIdentity(p)||pids.has(p.pid)||!roots.has(p.rootIdentity)||!Number.isInteger(p.depth)||p.depth<0)throw new Error("Invalid identity receipt");
    pids.add(p.pid);scope.set(processIdentity(p),p);
  }
  for(const [id,p] of original)if(!sameProcess(p,scope.get(id)))throw new Error("Original identity missing");
  for(const [id,p] of scope) {
    const old=original.get(id);
    if(old) {
      if(p.depth!==old.depth||p.parentIdentity!==old.parentIdentity||p.rootIdentity!==old.rootIdentity||p.ppid!==old.ppid||p.evidence!=="confirmed")throw new Error("Original edge changed");
    } else if(option.mode!=="tree"||phase!=="force"||!["coobserved","lifetime"].includes(p.evidence))throw new Error("Outside adoption");
    if(!roots.has(id)) {
      const parent=scope.get(p.parentIdentity);
      if(!validEdge(parent,p)||parent.rootIdentity!==p.rootIdentity||parent.depth+1!==p.depth)throw new Error("Invalid adopted edge");
      if(p.evidence==="lifetime"&&(!Number.isSafeInteger(p.parentExitMs)||p.parentExitMs<=p.startedMs))throw new Error("Invalid lifetime");
    } else if(p.depth!==0||p.parentIdentity!==null||p.rootIdentity!==id)throw new Error("Invalid root receipt");
  }
  const partition=new Set();
  for(const state of ["stopped","failed","alive"]) {
    if(!Array.isArray(r[state]))throw new Error("Missing partition");
    for(const pid of r[state]) {
      const p=r.identities.find(p=>p.pid===pid);if(!p||partition.has(pid)||p.outcome!==state)throw new Error("Contradictory partition");partition.add(pid);
    }
  }
  if(partition.size!==scope.size||phase==="force"&&r.alive.length)throw new Error("Incomplete partition");
  for(const key of ["forced","forceAttempted","alreadyExited","closeRequested"]) {
    if(!Array.isArray(r[key])||new Set(r[key]).size!==r[key].length||r[key].some(pid=>!pids.has(pid)))throw new Error("Invalid effects");
  }
  if(r.forced.some(pid=>!r.stopped.includes(pid)||!r.forceAttempted.includes(pid)||r.alreadyExited.includes(pid))
    ||r.alreadyExited.some(pid=>!r.stopped.includes(pid)||r.forceAttempted.includes(pid))
    ||r.closeRequested.some(pid=>!option.roots.some(p=>p.pid===pid))
    ||!r.preflightComplete&&(r.forceAttempted.length||r.closeRequested.length||r.operationComplete)
    ||r.operationComplete&&r.failed.length
    ||phase==="grace"&&(r.forceAttempted.length||r.forced.length)||phase==="force"&&r.closeRequested.length)throw new Error("Contradictory effects");
  if(phase==='force'&&r.stopped.some(pid=>!r.forced.includes(pid)&&!r.alreadyExited.includes(pid)))throw new Error('Unsupported stop');
  const attempted=new Set();
  for(const pid of r.forceAttempted) {
    const p=r.identities.find(p=>p.pid===pid);
    if(p.depth>0){const parent=scope.get(p.parentIdentity);if(!r.stopped.includes(parent.pid)||!r.alreadyExited.includes(parent.pid)&&!(attempted.has(parent.pid)&&r.forced.includes(parent.pid)))throw new Error("Child forced before confirmed parent exit");}
    attempted.add(pid);
  }
  return r;
}
