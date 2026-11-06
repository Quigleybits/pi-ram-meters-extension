// Native calls are isolated so fake Windows tests replace this entire prelude.
export const NATIVE_PRELUDE = String.raw`
$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.ComponentModel;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
public sealed class RamWindow { public long Handle; public int Pid; }
public sealed class RamHandle : IDisposable {
  internal IntPtr Handle;
  public int Pid {get;private set;}
  public long StartedMs {get;private set;}
  public string Image {get;private set;}
  public int SessionId {get;private set;}
  public string AccountSid {get;private set;}
  public bool IsCritical() {bool value;if(!RamNative.IsProcessCritical(Handle,out value))throw new Win32Exception();return value;}
  internal RamHandle(int pid,bool action) {
    Handle=RamNative.OpenProcess(0x1000u|0x100000u|(action?1u:0u),false,pid);
    if(Handle==IntPtr.Zero) {int code=Marshal.GetLastWin32Error();if(code==87)throw new ArgumentException("Exited");throw new Win32Exception(code);}
    try {
      Pid=pid; long birth,exit,kernel,user;
      if(!RamNative.GetProcessTimes(Handle,out birth,out exit,out kernel,out user))throw new Win32Exception();
      StartedMs=(DateTime.FromFileTimeUtc(birth).Ticks-621355968000000000L)/10000;
      var path=new StringBuilder(32768);int count=path.Capacity;
      if(!RamNative.QueryFullProcessImageName(Handle,0,path,ref count))throw new Win32Exception();
      Image=path.ToString();uint session;
      if(!RamNative.ProcessIdToSessionId(pid,out session))throw new Win32Exception();SessionId=(int)session;
      IntPtr token;if(!RamNative.OpenProcessToken(Handle,8,out token))throw new Win32Exception();
      try {using(var identity=new WindowsIdentity(token)){AccountSid=identity.User.Value;}} finally {RamNative.CloseHandle(token);}
    } catch {Dispose();throw;}
  }
  public bool IsExited() {uint state=RamNative.WaitForSingleObject(Handle,0);if(state==0)return true;if(state==258)return false;throw new Win32Exception();}
  public long ExitMs {get {long birth,exit,kernel,user;if(!RamNative.GetProcessTimes(Handle,out birth,out exit,out kernel,out user))throw new Win32Exception();
    return exit==0?0:(DateTime.FromFileTimeUtc(exit).Ticks-621355968000000000L)/10000;}}
  public void Kill() {if(!RamNative.TerminateProcess(Handle,1))throw new Win32Exception();}
  public bool WaitForExit(int ms) {uint state=RamNative.WaitForSingleObject(Handle,(uint)Math.Max(0,ms));if(state==0)return true;if(state==258)return false;throw new Win32Exception();}
  public void Dispose() {if(Handle!=IntPtr.Zero){RamNative.CloseHandle(Handle);Handle=IntPtr.Zero;}}
}
public static class RamNative {
  [DllImport("kernel32.dll",SetLastError=true)] internal static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
  [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool GetProcessTimes(IntPtr handle,out long birth,out long exit,out long kernel,out long user);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] internal static extern bool QueryFullProcessImageName(IntPtr handle,int flags,StringBuilder path,ref int count);
  [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool ProcessIdToSessionId(int pid,out uint session);
  [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool IsProcessCritical(IntPtr handle,out bool critical);
  [DllImport("advapi32.dll",SetLastError=true)] internal static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
  [DllImport("kernel32.dll",SetLastError=true)] internal static extern uint WaitForSingleObject(IntPtr handle,uint ms);
  [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool TerminateProcess(IntPtr handle,uint code);
  delegate bool WindowCallback(IntPtr hwnd,IntPtr data);
  [DllImport("user32.dll",SetLastError=true)] static extern bool EnumWindows(WindowCallback callback,IntPtr data);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd,out int pid);
  [DllImport("user32.dll")] static extern IntPtr GetShellWindow();
  [DllImport("user32.dll")] static extern bool IsWindow(IntPtr hwnd);
  [DllImport("user32.dll",SetLastError=true)] static extern bool PostMessage(IntPtr hwnd,uint message,IntPtr wparam,IntPtr lparam);
  public static RamHandle Open(int pid,bool action) {return new RamHandle(pid,action);}
  public static int WindowOwner(long hwnd) {int pid;GetWindowThreadProcessId(new IntPtr(hwnd),out pid);return pid;}
  public static bool WindowExists(long hwnd) {return IsWindow(new IntPtr(hwnd));}
  public static int ShellPid() {int pid;GetWindowThreadProcessId(GetShellWindow(),out pid);return pid;}
  public static RamWindow[] Windows() {
    var rows=new List<RamWindow>();
    if(!EnumWindows(delegate(IntPtr h,IntPtr d){int pid;GetWindowThreadProcessId(h,out pid);rows.Add(new RamWindow{Handle=h.ToInt64(),Pid=pid});return true;},IntPtr.Zero))throw new Win32Exception();
    return rows.ToArray();
  }
  public static bool CloseWindow(long hwnd,int expectedPid) {
    if(!WindowExists(hwnd))return false;
    int owner=WindowOwner(hwnd);
    if(owner!=expectedPid){if(owner==0&&!WindowExists(hwnd))return false;throw new InvalidOperationException("Window owner changed");}
    if(!PostMessage(new IntPtr(hwnd),0x0010,IntPtr.Zero,IntPtr.Zero)){
      int error=Marshal.GetLastWin32Error();
      if(error==1400&&!WindowExists(hwnd))return false;
      throw new Win32Exception(error);
    }
    return true;
  }
}
'@
`;
