// CLR2-compatible APIs: compiled by Windows 7's own PowerShell/Add-Type.
using System;
using System.Text;
using System.ComponentModel;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class Windows7DriverApi {
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetShortPathName(string path,StringBuilder output,uint size);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetLongPathName(string path,StringBuilder output,uint size);
    public static string ResourceSafeExecutablePath(string path) {
        // Apple derives its resource folder directly from the Run value. It
        // does not strip command-line quotes. Never publish an ambiguous
        // unquoted path with spaces as a workaround for that parser.
        path=System.IO.Path.GetFullPath(path);
        if(!System.IO.File.Exists(path))throw new System.IO.FileNotFoundException("Original utility must exist before registration",path);
        StringBuilder buffer=new StringBuilder(32768);
        uint count=GetShortPathName(path,buffer,(uint)buffer.Capacity);
        if(count==0||count>=buffer.Capacity)throw new Win32Exception(Marshal.GetLastWin32Error());
        string result=buffer.ToString();
        foreach(char c in result)if(Char.IsWhiteSpace(c)||c=='"')throw new InvalidOperationException("A safe Apple utility path is unavailable. No unsafe startup value was registered.");
        buffer.Length=0;count=GetLongPathName(result,buffer,(uint)buffer.Capacity);
        if(count==0||count>=buffer.Capacity||!String.Equals(path,buffer.ToString(),StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Apple utility short path did not round-trip");
        return result;
    }
    public sealed class DeviceInfo {
        public string PNPDeviceID, Name, Service;
        public string[] HardwareID, CompatibleID;
        public string[] PropertyDiagnostics;
        public uint ConfigManagerErrorCode, Status;
    }
    [StructLayout(LayoutKind.Sequential)] struct Dev { public uint size; public Guid cls; public uint inst; public IntPtr reserved; }
    [StructLayout(LayoutKind.Sequential)] struct Prop { public uint size,func,state,scope,profile; }
    [StructLayout(LayoutKind.Sequential)] struct PropertyKey { public Guid format; public uint pid; }
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
    [DllImport("setupapi.dll",EntryPoint="SetupDiGetDeviceRegistryPropertyW",ExactSpelling=true,SetLastError=true)] static extern bool SetupDiGetDeviceRegistryProperty(IntPtr set,ref Dev dev,uint property,out uint type,[Out] byte[] data,uint count,out uint required);
    [DllImport("setupapi.dll",EntryPoint="SetupDiGetDevicePropertyW",ExactSpelling=true,SetLastError=true)] static extern bool SetupDiGetDeviceProperty(IntPtr set,ref Dev dev,ref PropertyKey key,out uint type,[Out] byte[] data,uint count,out uint required,uint flags);
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
    // Probe the required size, then supply exactly that many bytes. A fixed
    // oversized buffer is not a substitute for the documented two-call query.
    delegate int PropertyQuery(byte[] buffer,out uint type,out uint required);
    static string[] ReadStrings(PropertyQuery query,uint expectedType,out int error) {
        uint type,required;error=query(null,out type,out required);
        if(error!=0 && error!=122)return new string[0];
        for(int attempt=0;attempt<3;attempt++) {
            if(required<2 || required>1048576 || required%2!=0)throw new InvalidOperationException("Invalid PnP property byte count: "+required);
            byte[] buffer=new byte[required];
            error=query(buffer,out type,out required);
            if(error==122)continue; // Property grew between the size and data calls.
            if(error!=0)return new string[0];
            if(type!=expectedType || required<2 || required>buffer.Length || required%2!=0 ||
               buffer[required-1]!=0 || buffer[required-2]!=0)throw new InvalidOperationException("Invalid PnP property type or string data");
            return Encoding.Unicode.GetString(buffer,0,(int)required).Split(new char[]{'\0'},StringSplitOptions.RemoveEmptyEntries);
        }
        throw new InvalidOperationException("PnP property kept changing size");
    }
    static string[] Property(IntPtr set,ref Dev d,uint property,List<string> diagnostics) {
        Dev device=d;int legacyError,unifiedError;
        bool list=property==1 || property==2;
        string[] values=ReadStrings(delegate(byte[] b,out uint type,out uint required) {
            bool ok=SetupDiGetDeviceRegistryProperty(set,ref device,property,out type,b,b==null?0:(uint)b.Length,out required);
            return ok?0:Marshal.GetLastWin32Error();
        },list?7U:1U,out legacyError);
        if(legacyError==0)return values;
        // ERROR_INVALID_DATA from the legacy API ambiguously means missing or
        // unreadable. Ask the Vista/Win7 unified API before declaring it absent.
        PropertyKey key=new PropertyKey();key.format=new Guid("a45c254e-df1c-4efd-8020-67d146a850e0");
        switch(property){case 0:key.pid=2;break;case 1:key.pid=3;break;case 2:key.pid=4;break;case 4:key.pid=6;break;case 12:key.pid=14;break;default:throw new ArgumentException("Unknown property");}
        values=ReadStrings(delegate(byte[] b,out uint type,out uint required) {
            bool ok=SetupDiGetDeviceProperty(set,ref device,ref key,out type,b,b==null?0:(uint)b.Length,out required,0);
            return ok?0:Marshal.GetLastWin32Error();
        },list?0x2012U:0x12U,out unifiedError);
        diagnostics.Add("SPDRP "+property+": legacy error "+legacyError+", unified error "+unifiedError);
        if(unifiedError==0)return values;
        if(legacyError==13 && unifiedError==1168)return new string[0];
        throw new InvalidOperationException("Cannot read PnP property "+property+" for device instance "+d.inst+
            ": legacy error "+legacyError+", unified error "+unifiedError);
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
                List<string> diagnostics=new List<string>();
                item.HardwareID=Property(set,ref d,1,diagnostics);item.CompatibleID=Property(set,ref d,2,diagnostics);
                item.Name=First(Property(set,ref d,12,diagnostics));if(item.Name=="")item.Name=First(Property(set,ref d,0,diagnostics));
                item.Service=First(Property(set,ref d,4,diagnostics));item.PropertyDiagnostics=diagnostics.ToArray();
                uint errorCode=CM_Get_DevNode_Status(out item.Status,out item.ConfigManagerErrorCode,d.inst,0);
                if(errorCode!=0)throw new InvalidOperationException("Device status unavailable: "+errorCode);
                result.Add(item);
            }
        } finally {SetupDiDestroyDeviceInfoList(set);}
        if(result.Count==0)throw new InvalidOperationException("Windows returned no present devices; hardware detection failed, not missing drivers.");
        return result.ToArray();
    }
    public static bool Matches(DeviceInfo device,string id) {
        if(device==null || String.IsNullOrEmpty(id))throw new ArgumentException("A device and a nonempty hardware ID are required");
        foreach(string value in device.HardwareID)if(String.Equals(value,id,StringComparison.OrdinalIgnoreCase))return true;
        foreach(string value in device.CompatibleID)if(String.Equals(value,id,StringComparison.OrdinalIgnoreCase))return true;
        return false;
    }
    public static DeviceInfo[] FilterDevices(DeviceInfo[] devices,string id) {
        if(devices==null || String.IsNullOrEmpty(id))throw new ArgumentException("Missing device inventory or hardware ID");
        List<DeviceInfo> result=new List<DeviceInfo>();
        foreach(DeviceInfo device in devices)if(Matches(device,id))result.Add(device);
        return result.ToArray();
    }
    public static DeviceInfo[] FindPresent(string id) {return FilterDevices(Devices(),id);}
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
        return IntPtr.Size==8 && Marshal.SizeOf(typeof(Dev))==32 && Marshal.SizeOf(typeof(Member))==64 && Marshal.SizeOf(typeof(Trust))==80 && Marshal.SizeOf(typeof(PropertyKey))==20;
    }
    public static bool PropertyReaderSelfTest() {
        byte[] data=Encoding.Unicode.GetBytes("PCI\\VEN_14E4&DEV_43BA\0second-id\0\0");int calls=0,error;
        string[] values=ReadStrings(delegate(byte[] b,out uint type,out uint required) {
            calls++;type=7;required=(uint)data.Length;
            if(b==null)return 122;
            if(b.Length!=data.Length)throw new InvalidOperationException("Query must use the probed size");
            Array.Copy(data,b,data.Length);return 0;
        },7,out error);
        if(error!=0 || calls!=2 || values.Length!=2 || values[1]!="second-id")return false;
        calls=0;
        values=ReadStrings(delegate(byte[] b,out uint type,out uint required) {
            calls++;type=0x2012;required=calls==1?4U:(uint)data.Length;
            if(b==null || b.Length<data.Length)return 122;
            Array.Copy(data,b,data.Length);return 0;
        },0x2012,out error);
        if(error!=0 || calls!=3 || values.Length!=2)return false;
        values=ReadStrings(delegate(byte[] b,out uint type,out uint required) {type=0;required=0;return 1168;},7,out error);
        if(error!=1168 || values.Length!=0)return false;
        bool rejected=false;
        try {ReadStrings(delegate(byte[] b,out uint type,out uint required) {type=7;required=3;return 122;},7,out error);}
        catch(InvalidOperationException){rejected=true;}
        if(!rejected)return false;
        rejected=false;
        try {ReadStrings(delegate(byte[] b,out uint type,out uint required) {type=1;required=(uint)data.Length;if(b==null)return 122;Array.Copy(data,b,data.Length);return 0;},7,out error);}
        catch(InvalidOperationException){rejected=true;}
        return rejected;
    }
}
