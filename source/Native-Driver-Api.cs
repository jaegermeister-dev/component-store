// CLR2-compatible APIs: compiled by Windows 7's own PowerShell/Add-Type.
using System;
using System.Text;
using System.ComponentModel;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class NoMoreBCADriverApi {
    public sealed class DeviceInfo {
        public string PNPDeviceID, Name, Service;
        public string[] HardwareID, CompatibleID;
        public uint ConfigManagerErrorCode, Status;
    }
    [StructLayout(LayoutKind.Sequential)] struct Dev { public uint size; public Guid cls; public uint inst; public IntPtr reserved; }
    [StructLayout(LayoutKind.Sequential)] struct Prop { public uint size,func,state,scope,profile; }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Params {
        public uint size,flags,flagsEx; public IntPtr hwnd,callback,context,queue,reserved; public uint reserved2;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)] public string path;
    }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct CatInfo {
        public uint size; [MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)] public string path;
    }
    // Win7 layout deliberately ends at context (no Windows 8 hCatAdmin member).
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Member {
        public uint size,version;
        [MarshalAs(UnmanagedType.LPWStr)] public string catalog;
        [MarshalAs(UnmanagedType.LPWStr)] public string tag;
        [MarshalAs(UnmanagedType.LPWStr)] public string member;
        public IntPtr file,hash; public uint hashSize; public IntPtr context;
    }
    [StructLayout(LayoutKind.Sequential)] struct Trust {
        public uint size; public IntPtr policy,sip; public uint ui,revocation,choice;
        public IntPtr info; public uint stateAction; public IntPtr state,url; public uint flags,uiContext;
    }
    [DllImport("newdev.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] static extern bool UpdateDriverForPlugAndPlayDevicesW(IntPtr hwnd,string id,string inf,uint flags,[MarshalAs(UnmanagedType.Bool)]out bool reboot);
    [DllImport("setupapi.dll",SetLastError=true)] static extern IntPtr SetupDiCreateDeviceInfoList(IntPtr cls,IntPtr hwnd);
    [DllImport("setupapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr SetupDiGetClassDevs(IntPtr cls,string enumerator,IntPtr hwnd,uint flags);
    [DllImport("setupapi.dll",SetLastError=true)] static extern bool SetupDiEnumDeviceInfo(IntPtr set,uint index,ref Dev dev);
    [DllImport("setupapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool SetupDiGetDeviceInstanceId(IntPtr set,ref Dev dev,StringBuilder id,uint count,out uint required);
    [DllImport("setupapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool SetupDiGetDeviceRegistryProperty(IntPtr set,ref Dev dev,uint property,out uint type,byte[] data,uint count,out uint required);
    [DllImport("cfgmgr32.dll")] static extern uint CM_Get_DevNode_Status(out uint status,out uint problem,uint devInst,uint flags);
    [DllImport("setupapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool SetupDiOpenDeviceInfo(IntPtr set,string id,IntPtr hwnd,uint flags,ref Dev dev);
    [DllImport("setupapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool SetupDiSetDeviceRegistryProperty(IntPtr set,ref Dev dev,uint prop,byte[] data,uint size);
    [DllImport("setupapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool SetupDiSetClassInstallParams(IntPtr set,ref Dev dev,ref Prop prop,uint size);
    [DllImport("setupapi.dll",SetLastError=true)] static extern bool SetupDiCallClassInstaller(uint fn,IntPtr set,ref Dev dev);
    [DllImport("setupapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool SetupDiGetDeviceInstallParams(IntPtr set,ref Dev dev,ref Params param);
    [DllImport("setupapi.dll")] static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
    [DllImport("wintrust.dll",SetLastError=true)] static extern bool CryptCATAdminAcquireContext(out IntPtr ctx,ref Guid system,uint flags);
    [DllImport("wintrust.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CryptCATAdminAddCatalog(IntPtr ctx,string source,string name,uint flags);
    [DllImport("wintrust.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CryptCATAdminRemoveCatalog(IntPtr ctx,string name,uint flags);
    [DllImport("wintrust.dll",SetLastError=true)] static extern bool CryptCATCatalogInfoFromContext(IntPtr cat,ref CatInfo info,uint flags);
    [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseCatalogContext(IntPtr ctx,IntPtr cat,uint flags);
    [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseContext(IntPtr ctx,uint flags);
    [DllImport("wintrust.dll",ExactSpelling=true)] static extern int WinVerifyTrust(IntPtr hwnd,ref Guid action,ref Trust data);
    static void Check(bool ok) { if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static IntPtr Open(string id,out Dev d) {
        IntPtr set=SetupDiCreateDeviceInfoList(IntPtr.Zero,IntPtr.Zero);if(set==new IntPtr(-1))throw new Win32Exception();
        d=new Dev();d.size=(uint)Marshal.SizeOf(typeof(Dev));
        if(!SetupDiOpenDeviceInfo(set,id,IntPtr.Zero,0,ref d)){int error=Marshal.GetLastWin32Error();SetupDiDestroyDeviceInfoList(set);throw new Win32Exception(error);}return set;
    }
    public static bool Install(IntPtr hwnd,string id,string inf) {
        bool reboot;
        if(!UpdateDriverForPlugAndPlayDevicesW(hwnd,id,inf,0,out reboot)) {
            int error=Marshal.GetLastWin32Error();
            // Windows may retain an already installed, equally ranked or newer
            // driver. The caller MUST inspect the resulting device status.
            if(error!=259)throw new Win32Exception(error);
        }
        return reboot;
    }
    static string[] Property(IntPtr set,ref Dev d,uint property) {
        uint type,required;byte[] b=new byte[65536];
        if(!SetupDiGetDeviceRegistryProperty(set,ref d,property,out type,b,(uint)b.Length,out required)) {
            int error=Marshal.GetLastWin32Error();if(error==13)return new string[0];throw new Win32Exception(error);
        }
        if((type!=1 && type!=7) || required>b.Length || required%2!=0)throw new InvalidOperationException("Invalid PnP property data");
        return Encoding.Unicode.GetString(b,0,(int)required).Split(new char[]{'\0'},StringSplitOptions.RemoveEmptyEntries);
    }
    static string First(string[] values) {return values.Length==0?"":values[0];}
    public static DeviceInfo[] Devices() {
        // Present devices only; unlike WMI's Present property this works on 7.
        IntPtr set=SetupDiGetClassDevs(IntPtr.Zero,null,IntPtr.Zero,6);
        if(set==new IntPtr(-1))throw new Win32Exception(Marshal.GetLastWin32Error());
        List<DeviceInfo> result=new List<DeviceInfo>();
        try {
            for(uint i=0;;i++) {
                Dev d=new Dev();d.size=(uint)Marshal.SizeOf(typeof(Dev));
                if(!SetupDiEnumDeviceInfo(set,i,ref d)) {
                    int error=Marshal.GetLastWin32Error();if(error==259)break;throw new Win32Exception(error);
                }
                StringBuilder id=new StringBuilder(4096);uint required;
                Check(SetupDiGetDeviceInstanceId(set,ref d,id,4096,out required));
                DeviceInfo item=new DeviceInfo();item.PNPDeviceID=id.ToString();
                item.HardwareID=Property(set,ref d,1);item.CompatibleID=Property(set,ref d,2);
                item.Name=First(Property(set,ref d,12));if(item.Name=="")item.Name=First(Property(set,ref d,0));
                item.Service=First(Property(set,ref d,4));
                uint errorCode=CM_Get_DevNode_Status(out item.Status,out item.ConfigManagerErrorCode,d.inst,0);
                if(errorCode!=0)throw new InvalidOperationException("Device status unavailable: "+errorCode);
                result.Add(item);
            }
        } finally {SetupDiDestroyDeviceInfoList(set);}
        return result.ToArray();
    }
    public static bool Matches(DeviceInfo device,string id) {
        foreach(string value in device.HardwareID)if(String.Equals(value,id,StringComparison.OrdinalIgnoreCase))return true;
        foreach(string value in device.CompatibleID)if(String.Equals(value,id,StringComparison.OrdinalIgnoreCase))return true;
        return false;
    }
    public static string InstallationTarget(DeviceInfo device,string matchingId) {
        if(!Matches(device,matchingId) || device.HardwareID.Length==0)throw new InvalidOperationException("No exact supported device match");
        // UpdateDriverForPlugAndPlayDevices selects devices by *hardware* ID,
        // even when the INF itself matches a compatible ID. Use the actual,
        // most specific hardware ID instead of the recipe's generic PCI ID.
        return device.HardwareID[0];
    }
    public static void SetLowerFilters(string id,string[] filters) {
        Dev d;IntPtr set=Open(id,out d);
        try { byte[] b=filters.Length==0?null:Encoding.Unicode.GetBytes(String.Join("\0",filters)+"\0\0");
            Check(SetupDiSetDeviceRegistryProperty(set,ref d,0x12,b,b==null?0:(uint)b.Length));
        } finally {SetupDiDestroyDeviceInfoList(set);}
    }
    public static bool Restart(string id) {
        Dev d;IntPtr set=Open(id,out d);
        try {Prop p=new Prop();p.size=8;p.func=0x12;p.state=3;p.scope=2;
            Check(SetupDiSetClassInstallParams(set,ref d,ref p,(uint)Marshal.SizeOf(typeof(Prop))));
            Check(SetupDiCallClassInstaller(0x12,set,ref d));Params r=new Params();r.size=(uint)Marshal.SizeOf(typeof(Params));
            Check(SetupDiGetDeviceInstallParams(set,ref d,ref r));return (r.flags&0x180)!=0;
        } finally {SetupDiDestroyDeviceInfoList(set);}
    }
    public static int VerifyMember(string catalog,string member,string signedTag) {
        Member m=new Member();m.size=(uint)Marshal.SizeOf(typeof(Member));m.catalog=catalog;m.member=member;m.tag=signedTag;
        // The signed SHA256 member tag is pinned for this unchanged package;
        // WinVerifyTrust computes the member digest independently.
        IntPtr ptr=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Member)));Trust t=new Trust();
        t.size=(uint)Marshal.SizeOf(typeof(Trust));t.ui=2;t.choice=2;t.info=ptr;t.stateAction=1;t.flags=0x1000;
        Guid action=new Guid("00aac56b-cd44-11d0-8cc2-00c04fc295ee");
        try {Marshal.StructureToPtr(m,ptr,false);return WinVerifyTrust(new IntPtr(-1),ref action,ref t);}
        finally {t.stateAction=2;WinVerifyTrust(new IntPtr(-1),ref action,ref t);Marshal.DestroyStructure(ptr,typeof(Member));Marshal.FreeHGlobal(ptr);}
    }
    public static string Catalog(string source,string name,bool remove) {
        Guid system=new Guid("f750e6c3-38ee-11d1-85e5-00c04fc295ee");IntPtr ctx;Check(CryptCATAdminAcquireContext(out ctx,ref system,0));
        try {if(remove){Check(CryptCATAdminRemoveCatalog(ctx,name,0));return "Removed owned catalog";}
            IntPtr cat=CryptCATAdminAddCatalog(ctx,source,name,0);if(cat==IntPtr.Zero)throw new Win32Exception();
            try {CatInfo i=new CatInfo();i.size=(uint)Marshal.SizeOf(typeof(CatInfo));Check(CryptCATCatalogInfoFromContext(cat,ref i,0));return i.path;}
            finally {CryptCATAdminReleaseCatalogContext(ctx,cat,0);}
        } finally {CryptCATAdminReleaseContext(ctx,0);}
    }
    public static bool LayoutSelfTest() {
        return IntPtr.Size==8 && Marshal.SizeOf(typeof(Dev))==32 && Marshal.SizeOf(typeof(Member))==64 && Marshal.SizeOf(typeof(Trust))==80;
    }
}
