import {processIdentity,sameProcess,validIdentity,validEdge,deduplicateRoots} from "./ownership.js";
import {NATIVE_PRELUDE} from "./native.js";
function markedScopes(option,phase) {
  if(!["task","tree"].includes(option?.mode)||!["grace","force"].includes(phase))throw new Error("Invalid group phase");
  deduplicateRoots([option]);
  const validationTargets=[...option.treeTargets],rootPids=new Set(option.roots.map(p=>p.pid)),latest=new Map();
  for(const p of validationTargets) {
    const old=latest.get(p.pid);
    if(old&&rootPids.has(p.pid))throw new Error("Conflicting frozen root epoch");
    if(!old||p.startedMs>old.startedMs)latest.set(p.pid,p);
  }
  const effectTargets=phase==="force"&&option.mode==="tree"
    ?[...latest.values()].sort((a,b)=>a.depth-b.depth||a.pid-b.pid)
    :option.roots.filter(p=>option.effectRootIds===undefined||option.effectRootIds.includes(processIdentity(p)));
  const scope=new Map(validationTargets.map(p=>[processIdentity(p),p]));
  if(option.validationExits!==undefined) {
    if(!Array.isArray(option.validationExits)||option.validationExits.length>1000)throw new Error("Invalid validation exits");
    for(const p of option.validationExits)if(!sameProcess(p,scope.get(processIdentity(p)))||p.outcome!=="exited")throw new Error("Unrelated validation exit");
  }
  return {validationTargets,effectTargets};
}
export function phaseScopes(option,phase) {
  if(option?.groupPolicy!==undefined)return markedScopes(option,phase);
  const effectTargets=phaseTargets(option,phase);return {validationTargets:effectTargets,effectTargets};
}
export function phaseTargets(option,phase) {
  if(option?.groupPolicy!==undefined)return markedScopes(option,phase).effectTargets;
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
  const {validationTargets,effectTargets:targets}=phaseScopes(option,phase),marked=option.groupPolicy!==undefined;
  if(!validIdentity(option.controllerIdentity)||!Number.isSafeInteger(waitMs)||waitMs<1||waitMs>5000||!Number.isSafeInteger(budgetMs)||budgetMs<1||budgetMs>10000
    ||!Number.isInteger(maxMembers)||maxMembers<validationTargets.length||maxMembers>1000||!Number.isInteger(maxScans)||maxScans<1||maxScans>128)throw new Error("Invalid execution bounds/controller");
  const payload=Buffer.from(JSON.stringify({targets:targets.map(fields),roots:option.roots.map(fields),controller:fields(option.controllerIdentity),
    ...(marked?{groupPolicy:option.groupPolicy,validationTargets:validationTargets.map(fields),validationExits:(option.validationExits??[]).map(p=>({...fields(p),exitMs:p.exitMs}))}:{})})).toString("base64");
  return NATIVE_PRELUDE+`
$plan=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}'))|ConvertFrom-Json
$isTree=$${option.mode==="tree"&&phase==="force"?"true":"false"};$isGrace=$${phase==="grace"?"true":"false"}
$isMarked=$${marked?"true":"false"};$effectMembers=@{};$rootIds=@{};$knownExits=@{}
foreach($p in @($plan.targets)){$effectMembers[([string]$p.pid)+':'+([string]$p.startedMs)]=$true}
foreach($p in @($plan.roots)){$rootIds[([string]$p.pid)+':'+([string]$p.startedMs)]=$true}
foreach($p in @($plan.validationExits)){$knownExits[([string]$p.pid)+':'+([string]$p.startedMs)]=$p}
$facts=@{};$exitKind=@{};$exitTimes=@{};$reusedBy=@{};$absent=@{};$script:inventoryComplete=$false;$script:roleServices=$null;$script:roleShell=0
$members=[Collections.Specialized.OrderedDictionary]::new();$handles=@{};$status=@{};$evidence=@{};$parentExit=@{}
$forced=[Collections.Generic.List[int]]::new();$attempted=[Collections.Generic.List[int]]::new()
$effectSubstitutions=[Collections.Generic.List[object]]::new()
$requested=[Collections.Generic.HashSet[int]]::new();$windows=[Collections.Generic.HashSet[long]]::new();$windowCounts=@{}
$already=[Collections.Generic.HashSet[int]]::new();$protected=@{}
$clock=[Diagnostics.Stopwatch]::StartNew();$preflight=$false;$operationComplete=$false;$discovery=@{count=0};$effect=$false
function Identity($p){return ([string]$p.pid)+':'+([string]$p.startedMs)}
function Is-Effect($key){return (-not $isMarked -or $effectMembers.ContainsKey([string]$key))}
function Add-TreeEffect($p) {
  $key=Identity $p
  $previous=@($effectMembers.Keys|Where-Object {$members.Contains($_) -and [int]$members[$_].pid -eq [int]$p.pid -and $_ -ne $key})
  if($previous.Count) {
    if($previous.Count -ne 1 -or $effect -or $attempted.Count -or $requested.Count){throw 'Ambiguous effect PID reuse'}
    $oldKey=[string]$previous[0];$old=$members[$oldKey];$proof=$reusedBy[$oldKey]
    if($rootIds.ContainsKey($oldKey) -or $evidence[$oldKey] -ne 'confirmed' -or $status[$oldKey] -ne 'stopped' -or $exitKind[$oldKey] -ne 'reused' -or
      $null -eq $proof -or [long]$p.startedMs -le [long]$old.startedMs -or (Identity $proof) -ne $key -or
      $proof.SessionId -ne [int]$p.sessionId -or $proof.AccountSid -ne [string]$p.accountSid -or
      -not [String]::Equals($proof.executablePath,[string]$p.executablePath,[StringComparison]::OrdinalIgnoreCase)){throw 'Unproved effect PID reuse'}
    $effectMembers.Remove($oldKey);$null=$already.Remove([int]$p.pid)
    $effectSubstitutions.Add([pscustomobject]@{oldIdentity=$oldKey;newIdentity=$key;beforeEffects=$true})
  }
  $effectMembers[$key]=$true
}
function Budget {if($clock.ElapsedMilliseconds -ge ${budgetMs}){throw 'Operation deadline'}}
function Birth($row){if($null -eq $row.CreationDate){throw 'Unknown birth'};return ([DateTimeOffset]$row.CreationDate.ToUniversalTime()).ToUnixTimeMilliseconds()}
function Validate($p,$h,$allowCritical=$false) {
  if($h.Pid -ne [int]$p.pid -or $h.StartedMs -ne [long]$p.startedMs -or $h.SessionId -ne [int]$p.sessionId -or $h.AccountSid -ne [string]$p.accountSid -or -not [String]::Equals($h.Image,[string]$p.executablePath,[StringComparison]::OrdinalIgnoreCase)){throw 'Identity changed'}
  if(-not $allowCritical) {
    $critical=$h.IsCritical()
    if($isMarked){$key=Identity $p;$facts[$key].canQuery=$true;$facts[$key].critical=$critical;if($h.AccountSid -ne [string]$plan.groupPolicy.accountSid){throw 'Other-user group member'}}
    if($critical){throw 'Critical process'}
  }
}
function Mark-Exited($key,$h) {
  $p=$members[$key];$status[$key]='stopped'
  if($isMarked){$exitKind[$key]='retained';$exitTimes[$key]=$h.ExitMs}
  if(Is-Effect $key){$null=$already.Add([int]$p.pid)}
}
function Check-Role($p) {
  if(-not $isMarked){return};$key=Identity $p
  if($null -eq $script:roleServices -or $script:roleShell -le 0){throw 'OS role facts unavailable'}
  $facts[$key].serviceCount=[int]$script:roleServices[[string]$p.pid];$facts[$key].isShell=([int]$p.pid -eq $script:roleShell)
  if($facts[$key].serviceCount -gt 0 -or $facts[$key].isShell){throw 'OS role excluded from app group'}
}
function Acquire($p,$source,$exitMs=0) {
  Budget;$key=Identity $p;if($members.Contains($key)){return};if($members.Count -ge ${maxMembers}){throw 'Member budget'}
  $members.Add($key,$p);$status[$key]='pending';$evidence[$key]=$source;$parentExit[$key]=$exitMs
  if($isMarked){$facts[$key]=@{canQuery=$false;critical=$null;serviceCount=$null;isShell=$null}}
  $h=$null
  try{$h=[RamNative]::Open([int]$p.pid,(-not $isMarked))}
  catch{if($_.Exception -is [ArgumentException] -or $_.Exception.InnerException -is [ArgumentException]){
    $status[$key]='stopped';if(Is-Effect $key){$null=$already.Add([int]$p.pid)}
    if($isMarked){$exitKind[$key]='absent';$exitTimes[$key]=[long]$knownExits[$key].exitMs};return
  };throw}
  if($isMarked -and $h.StartedMs -gt [long]$p.startedMs -and -not $rootIds.ContainsKey($key)) {
    $reusedBy[$key]=[pscustomobject]@{pid=$h.Pid;startedMs=$h.StartedMs;sessionId=$h.SessionId;accountSid=$h.AccountSid;executablePath=$h.Image}
    $h.Dispose();$status[$key]='stopped';$exitKind[$key]='reused';$exitTimes[$key]=0
    if(Is-Effect $key){$null=$already.Add([int]$p.pid)};return
  }
  $handles[$key]=$h;Validate $p $h
  if($isMarked -and (Is-Effect $key)) {
    $actionHandle=[RamNative]::Open([int]$p.pid,$true);$handles[$key]=$actionHandle;$h.Dispose();$h=$actionHandle;Validate $p $h
  }
  if($h.IsExited()){Mark-Exited $key $h}else{$status[$key]='alive'}
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
  if($isMarked) {
    $script:inventoryComplete=$false;$script:roleServices=$null;$script:roleShell=[RamNative]::ShellPid()
    if($script:roleShell -le 0 -or -not $rows.ContainsKey([string]$script:roleShell)){throw 'OS shell facts unavailable'}
    $shellRow=$rows[[string]$script:roleShell];$shellHandle=$null
    try{$shellHandle=[RamNative]::Open($script:roleShell,$false)
      if($shellHandle.StartedMs -ne (Birth $shellRow) -or $shellHandle.SessionId -ne [int]$shellRow.SessionId -or $shellHandle.IsExited()){throw 'OS shell identity changed'}
    }finally{if($null -ne $shellHandle){$shellHandle.Dispose()}}
    $servicePids=@{};foreach($service in @(Get-CimInstance Win32_Service -ErrorAction Stop)){
      if($null -eq $service.ProcessId){throw 'Service identity unavailable'}
      if([int]$service.ProcessId -gt 0){$serviceKey=[string]$service.ProcessId;$servicePids[$serviceKey]=1+[int]$servicePids[$serviceKey]}
    }
    $script:roleServices=$servicePids;$script:inventoryComplete=$true
  }
  foreach($key in @($members.Keys)) {
    $p=$members[$key];if($protected.ContainsKey($key)){throw 'Selected controller lineage'}
    $h=$handles[$key]
    if($isMarked -and $rootIds.ContainsKey($key) -and $null -ne $rows[[string]$p.pid] -and (Birth $rows[[string]$p.pid]) -ne [long]$p.startedMs){throw 'Frozen root reused'}
    if($null -ne $h) {
      Validate $p $h
      if($h.IsExited()){if($status[$key] -ne 'stopped'){Mark-Exited $key $h};continue}
      $row=$rows[[string]$p.pid]
      if($null -eq $row -or (Birth $row) -ne [long]$p.startedMs -or $row.SessionId -ne [int]$p.sessionId -or ($p.depth -gt 0 -and $row.ParentProcessId -ne [int]$p.ppid)){throw 'Current identity/edge changed'}
      Check-Role $p
    } elseif($isMarked) {
      $row=$rows[[string]$p.pid]
      if($exitKind[$key] -eq 'absent') {
        if($null -ne $row){throw 'Absent identity is present or reused'};$absent[$key]=$true
      } elseif($exitKind[$key] -eq 'reused') {
        if($null -ne $row -and (Birth $row) -ne [long]$reusedBy[$key].startedMs){throw 'Reuse evidence changed'}
      } else {throw 'Validation identity unresolved'}
    }
  }
  if($isTree -or $isMarked) {
    do {
      $changed=$false
      foreach($row in @($rows.Values)) {
        foreach($parentKey in @($members.Keys)) {
          $parent=$members[$parentKey];if([int]$row.ParentProcessId -ne [int]$parent.pid){continue}
          $birth=Birth $row;if($birth -lt [long]$parent.startedMs){continue}
          $key=([string]$row.ProcessId)+':'+([string]$birth);if($members.Contains($key)){continue}
          if($isMarked) {
            $currentParent=$rows[[string]$parent.pid]
            if($null -ne $currentParent -and (Birth $currentParent) -ne [long]$parent.startedMs -and $birth -ge (Birth $currentParent)){continue}
          }
          $ph=$handles[$parentKey];$source=$null;$exitMs=0
          if($null -ne $ph) {
            if(-not $ph.IsExited()) {
              $liveParent=$rows[[string]$parent.pid]
              if($null -ne $liveParent -and (Birth $liveParent) -eq [long]$parent.startedMs){$source='coobserved'}
            } else {
              $exitMs=$ph.ExitMs;if($exitMs -gt $birth -and $birth -ge [long]$parent.startedMs){$source='lifetime'}
            }
          }
          if($isMarked -and $null -eq $source -and [long]$knownExits[$parentKey].exitMs -gt $birth){$source='lifetime';$exitMs=[long]$knownExits[$parentKey].exitMs}
          if($null -eq $source){throw 'Unconfirmed late descendant'}
          $h=$null
          try{$h=[RamNative]::Open([int]$row.ProcessId,$false)
            if($h.StartedMs -ne $birth -or $h.SessionId -ne [int]$row.SessionId){throw 'New child identity changed'}
            $p=[pscustomobject]@{pid=[int]$row.ProcessId;ppid=[int]$row.ParentProcessId;startedMs=$birth;sessionId=$h.SessionId;accountSid=$h.AccountSid;
              executablePath=$h.Image;depth=([int]$parent.depth+1);parentIdentity=$parentKey;rootIdentity=$parent.rootIdentity;rootPid=$parent.rootPid}
          }finally{if($null -ne $h){$h.Dispose()}}
          if($protected.ContainsKey($key)){throw 'Dynamic controller descendant'}
          if($isMarked -and $isTree){Add-TreeEffect $p}
          Acquire $p $source $exitMs;Check-Role $p;$changed=$true
        }
      }
    }while($changed)
  }
  Budget
}
try {
  $initial=if($isMarked){@($plan.validationTargets)}else{@($plan.targets)}
  foreach($p in $initial){Acquire $p 'confirmed'}
  Sync-Scope;$preflight=$true
  if($isGrace) {
    $deadline=[Math]::Min(${budgetMs},[int]$clock.ElapsedMilliseconds+${waitMs})
    do {
      Sync-Scope
      foreach($window in @([RamNative]::Windows())) {
        $root=@($plan.roots|Where-Object {$_.pid -eq $window.Pid})|Select-Object -First 1
        if($null -eq $root){continue};$key=Identity $root
        if(-not (Is-Effect $key)){continue}
        if($status[$key] -ne 'alive' -or $handles[$key].IsExited() -or $windows.Contains([long]$window.Handle)){continue}
        if($windows.Count -ge 1024){throw 'Window budget'}
        if($isMarked){Sync-Scope;if($status[$key] -ne 'alive' -or $handles[$key].IsExited()){continue}}
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
      foreach($key in @($members.Keys)){if($null -ne $handles[$key] -and $handles[$key].IsExited()){
        if($isMarked){Mark-Exited $key $handles[$key]}else{$status[$key]='stopped'}
      }}
      $alive=@($members.Keys|Where-Object {$status[$_] -eq 'alive' -and (Is-Effect $_)});$remaining=$deadline-[int]$clock.ElapsedMilliseconds
      if($alive.Count -and $remaining -gt 0){Start-Sleep -Milliseconds ([Math]::Min(100,$remaining))}
    }while($alive.Count -and $clock.ElapsedMilliseconds -lt $deadline)
  } else {
    while($true) {
      Sync-Scope
      $next=@($members.Values|Where-Object {$status[(Identity $_)] -eq 'alive' -and (Is-Effect (Identity $_))}|Sort-Object depth,pid)|Select-Object -First 1
      if($null -eq $next){break};$key=Identity $next
      if($next.depth -gt 0 -and $status[[string]$next.parentIdentity] -ne 'stopped'){throw 'Parent exit not confirmed'}
      $h=$handles[$key];Validate $next $h
      if($h.IsExited()){Mark-Exited $key $h;continue}
      Budget;$effect=$true;$attempted.Add([int]$next.pid);$h.Kill()
      $remaining=${budgetMs}-[int]$clock.ElapsedMilliseconds
      if($remaining -le 0 -or -not $h.WaitForExit($remaining)){throw 'Exit not confirmed'}
      $forced.Add([int]$next.pid);$status[$key]='stopped'
      if($isMarked){$exitKind[$key]='retained';$exitTimes[$key]=$h.ExitMs}
    }
  }
  if($isMarked){Sync-Scope};$operationComplete=$true
} catch {
  foreach($key in @($members.Keys)){if($status[$key] -ne 'stopped'){$status[$key]='failed'}}
} finally {foreach($h in $handles.Values){$h.Dispose()}}
$identities=@();$stopped=@();$failed=@();$alivePids=@();$validationIdentities=@()
foreach($key in @($members.Keys)) {
  $p=$members[$key];$outcome=$status[$key]
  if($isMarked) {
    $validationIdentities += [pscustomobject]@{pid=[int]$p.pid;ppid=[int]$p.ppid;startedMs=[long]$p.startedMs;executablePath=[string]$p.executablePath;
      sessionId=[int]$p.sessionId;accountSid=[string]$p.accountSid;depth=[int]$p.depth;parentIdentity=$p.parentIdentity;rootIdentity=$p.rootIdentity;rootPid=[int]$p.rootPid;
      evidence=$evidence[$key];parentExitMs=[long]$parentExit[$key];outcome=if($outcome -eq 'stopped'){'exited'}elseif($outcome -eq 'alive'){'alive'}else{'failed'};
      canQuery=$facts[$key].canQuery;critical=$facts[$key].critical;serviceCount=$facts[$key].serviceCount;isShell=$facts[$key].isShell;
      exitEvidence=$exitKind[$key];exitMs=[long]$exitTimes[$key];inventoryAbsent=[bool]$absent[$key];reusedBy=$reusedBy[$key]}
  }
  if(-not (Is-Effect $key)){continue}
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
$validationInitial=if($isMarked){@($plan.validationTargets)}else{@()}
foreach($p in $validationInitial) {
  $key=Identity $p;if($members.Contains($key)){continue}
  $validationIdentities += [pscustomobject]@{pid=[int]$p.pid;ppid=[int]$p.ppid;startedMs=[long]$p.startedMs;executablePath=[string]$p.executablePath;
    sessionId=[int]$p.sessionId;accountSid=[string]$p.accountSid;depth=[int]$p.depth;parentIdentity=$p.parentIdentity;rootIdentity=$p.rootIdentity;rootPid=[int]$p.rootPid;
    evidence='confirmed';parentExitMs=0;outcome='failed';canQuery=$false;critical=$null;serviceCount=$null;isShell=$null}
}
$counts=@();foreach($root in @($plan.roots)){$counts += [pscustomobject]@{pid=[int]$root.pid;requested=[int]$windowCounts[[string]$root.pid]}}
$result=[pscustomobject]@{phase='${phase}';preflightComplete=$preflight;operationComplete=$operationComplete;stopped=@($stopped);failed=@($failed);alive=@($alivePids);
  forced=@($forced.ToArray());forceAttempted=@($attempted.ToArray());alreadyExited=@($already);closeRequested=@($requested);windowCounts=@($counts);
  identities=@($identities);elapsedMs=$clock.ElapsedMilliseconds;discoveryCount=$discovery.count;effectStarted=$effect;
  message='Process phase finished; inspect identity outcomes.'}
if($isMarked){$result|Add-Member -NotePropertyName validationIdentities -NotePropertyValue @($validationIdentities)
  $result|Add-Member -NotePropertyName effectSubstitutions -NotePropertyValue @($effectSubstitutions.ToArray())
  $result|Add-Member -NotePropertyName inventoryComplete -NotePropertyValue $script:inventoryComplete
  $complete=$preflight -and $operationComplete -and $script:inventoryComplete -and @($validationIdentities|Where-Object {$_.outcome -eq 'failed'}).Count -eq 0
  $result|Add-Member -NotePropertyName validationComplete -NotePropertyValue ([bool]$complete)}
$result|ConvertTo-Json -Depth 10 -Compress
`;
}
const sameLineage=(a,b)=>a.ppid===b.ppid&&a.depth===b.depth&&a.parentIdentity===b.parentIdentity
  &&a.rootIdentity===b.rootIdentity&&a.rootPid===b.rootPid;
function markedReceipt(raw,option,phase) {
  const {validationTargets,effectTargets}=phaseScopes(option,phase),r=typeof raw==="string"?JSON.parse(raw.replace(/^\ufeff/,"")):raw;
  if(!r||r.phase!==phase||typeof r.message!=="string"||typeof r.preflightComplete!=="boolean"||typeof r.operationComplete!=="boolean"
    ||typeof r.validationComplete!=="boolean"||typeof r.inventoryComplete!=="boolean"||!Array.isArray(r.validationIdentities)
    ||r.validationIdentities.length>1000||!Array.isArray(r.identities)||r.identities.length>1000)throw new Error("Invalid marked receipt");
  const original=new Map(validationTargets.map(p=>[processIdentity(p),p])),expected=new Map(effectTargets.map(p=>[processIdentity(p),p]));
  const roots=new Map(option.roots.map(p=>[processIdentity(p),p])),validation=new Map(),epochs=new Map();
  for(const p of r.validationIdentities) {
    if(!validIdentity(p)||validation.has(processIdentity(p))||!roots.has(p.rootIdentity)||p.rootPid!==roots.get(p.rootIdentity).pid
      ||!Number.isInteger(p.depth)||p.depth<0||!["alive","exited","failed"].includes(p.outcome))throw new Error("Invalid validation identity");
    validation.set(processIdentity(p),p);const list=epochs.get(p.pid)??[];list.push(p);epochs.set(p.pid,list);
  }
  for(const [id,p] of original)if(!sameProcess(p,validation.get(id))||!sameLineage(p,validation.get(id)))throw new Error("Full validation member missing or changed");
  const positiveExit=p=>{
    if(p.exitEvidence==="retained")return Number.isSafeInteger(p.exitMs)&&p.exitMs>=p.startedMs;
    if(p.exitEvidence==="absent")return r.inventoryComplete&&p.inventoryAbsent===true;
    if(p.exitEvidence==="reused") {
      const replacement=p.reusedBy,current=validation.get(replacement&&processIdentity(replacement));
      return !roots.has(processIdentity(p))&&validIdentity(replacement)&&replacement.pid===p.pid&&replacement.startedMs>p.startedMs
        &&(!current||sameProcess(current,replacement));
    }
    return false;
  };
  for(const [id,p] of validation) {
    const old=original.get(id);
    if(old) {if(p.evidence!=="confirmed")throw new Error("Captured validation evidence changed");}
    else if(!["coobserved","lifetime"].includes(p.evidence))throw new Error("Unverified validation adoption");
    if(roots.has(id)) {
      if(p.depth!==0||p.parentIdentity!==null||p.rootIdentity!==id)throw new Error("Changed validation root");
    } else {
      const parent=validation.get(p.parentIdentity);
      if(!validEdge(parent,p)||parent.depth+1!==p.depth||parent.rootIdentity!==p.rootIdentity)throw new Error("Invalid validation lineage");
      if(p.evidence==="lifetime"&&(!Number.isSafeInteger(p.parentExitMs)||p.parentExitMs<=p.startedMs
        ||parent.outcome!=="exited"||p.parentExitMs!==parent.exitMs))throw new Error("Invalid validation lifetime proof");
    }
    if(p.outcome!=="failed"&&p.accountSid!==option.groupPolicy.accountSid)throw new Error("Other-user validation member");
    if(p.outcome==="alive"&&(p.canQuery!==true||p.critical!==false||p.serviceCount!==0||p.isShell!==false))throw new Error("Unsafe live validation member");
    if(p.outcome==="exited"&&!positiveExit(p))throw new Error("Unproved validation exit");
  }
  for(const list of epochs.values()) {
    const latest=Math.max(...list.map(p=>p.startedMs));
    if(list.some(p=>p.startedMs!==latest&&p.outcome!=="exited"))throw new Error("Unresolved validation PID reuse");
  }
  if(r.operationComplete&&!r.validationComplete||r.validationComplete&&(!r.preflightComplete||!r.inventoryComplete
    ||r.validationIdentities.some(p=>p.outcome==="failed")))throw new Error("Incomplete group validation");
  if(option.mode==="tree"&&phase==="force"&&r.operationComplete&&r.validationIdentities.some(p=>p.outcome!=="exited"))throw new Error("Tree validation survivors");
  const substitutions=r.effectSubstitutions??[],substitutedPids=new Set();
  if(!Array.isArray(substitutions)||substitutions.length>1000)throw new Error("Invalid effect substitutions");
  for(const s of substitutions) {
    const old=validation.get(s?.oldIdentity),replacement=validation.get(s?.newIdentity);
    if(option.mode!=="tree"||phase!=="force"||s?.beforeEffects!==true||!expected.has(s.oldIdentity)||roots.has(s.oldIdentity)
      ||!old||!replacement||original.has(s.newIdentity)||expected.has(s.newIdentity)||substitutedPids.has(old.pid)
      ||old.pid!==replacement.pid||old.startedMs>=replacement.startedMs||old.outcome!=="exited"||old.exitEvidence!=="reused"
      ||!sameProcess(old.reusedBy,replacement))throw new Error("Unproved effect substitution");
    expected.delete(s.oldIdentity);expected.set(s.newIdentity,replacement);substitutedPids.add(old.pid);
  }
  const effects=new Map(),pids=new Set();
  for(const p of r.identities) {
    const id=processIdentity(p),checked=validation.get(id);
    if(!validIdentity(p)||pids.has(p.pid)||!checked||!sameProcess(p,checked)||!sameLineage(p,checked)||p.evidence!==checked.evidence
      ||p.outcome!==(checked.outcome==="exited"?"stopped":checked.outcome))throw new Error("Invalid marked effect identity");
    if(!expected.has(id)&&!(option.mode==="tree"&&phase==="force"&&!original.has(id)))throw new Error("Effect outside mode targets");
    effects.set(id,p);pids.add(p.pid);
  }
  for(const [id,p] of expected)if(!sameProcess(p,effects.get(id)))throw new Error("Mode effect target missing");
  const partition=new Set();
  for(const state of ["stopped","failed","alive"]) {
    if(!Array.isArray(r[state]))throw new Error("Missing effect partition");
    for(const pid of r[state]) {
      const p=r.identities.find(p=>p.pid===pid);if(!p||partition.has(pid)||p.outcome!==state)throw new Error("Contradictory effect partition");partition.add(pid);
    }
  }
  if(partition.size!==effects.size||phase==="force"&&r.alive.length)throw new Error("Incomplete effect partition");
  for(const key of ["forced","forceAttempted","alreadyExited","closeRequested"])if(!Array.isArray(r[key])
    ||new Set(r[key]).size!==r[key].length||r[key].some(pid=>!pids.has(pid)))throw new Error("Invalid marked effect accounting");
  if(r.operationComplete)for(const pid of new Set([...r.forced,...r.forceAttempted,...r.closeRequested])) {
    const effect=r.identities.find(p=>p.pid===pid),checked=validation.get(processIdentity(effect));
    if(checked.canQuery!==true||checked.critical!==false||checked.serviceCount!==0||checked.isShell!==false)
      throw new Error("Completed effect lacks safe validation facts");
  }
  if(r.forced.some(pid=>!r.stopped.includes(pid)||!r.forceAttempted.includes(pid)||r.alreadyExited.includes(pid))
    ||r.alreadyExited.some(pid=>!r.stopped.includes(pid)||r.forceAttempted.includes(pid))
    ||r.closeRequested.some(pid=>!option.roots.some(p=>p.pid===pid))
    ||!r.preflightComplete&&(r.forceAttempted.length||r.closeRequested.length||r.operationComplete)
    ||r.operationComplete&&r.failed.length||phase==="grace"&&(r.forceAttempted.length||r.forced.length)
    ||phase==="force"&&r.closeRequested.length||r.effectStarted===false&&(r.forceAttempted.length||r.closeRequested.length))
    throw new Error("Contradictory marked effects");
  if(phase==="force"&&r.stopped.some(pid=>!r.forced.includes(pid)&&!r.alreadyExited.includes(pid)))throw new Error("Unsupported marked stop");
  const attempted=new Set();
  for(const pid of r.forceAttempted) {
    const p=r.identities.find(p=>p.pid===pid);
    if(p.depth>0) {
      const parent=validation.get(p.parentIdentity),effect=effects.get(p.parentIdentity);
      if(parent.outcome!=="exited"||effect&&(!r.stopped.includes(parent.pid)
        ||!r.alreadyExited.includes(parent.pid)&&!(attempted.has(parent.pid)&&r.forced.includes(parent.pid))))throw new Error("Marked child before confirmed parent exit");
    }
    attempted.add(pid);
  }
  return r;
}
export function readPhaseReceipt(raw,option,phase) {
  if(option?.groupPolicy!==undefined)return markedReceipt(raw,option,phase);
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
