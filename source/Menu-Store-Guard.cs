using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
public static class MenuStoreGuard {
 static void Check(bool ok,string s){if(!ok)throw new Exception(s);}
 static byte[] Slice(byte[] b,int start,int length){Check(start>=0&&length>=0&&start+length<=b.Length,"Truncated menu");byte[] r=new byte[length];Array.Copy(b,start,r,0,length);return r;}
 static bool Equal(byte[] a,byte[] b){if(a.Length!=b.Length)return false;for(int i=0;i<a.Length;i++)if(a[i]!=b[i])return false;return true;}
 static byte[] Hash(byte[] b){using(SHA256 h=SHA256.Create())return h.ComputeHash(b);}
 static byte[] Read(string p,int limit){FileInfo f=new FileInfo(p);Check(f.Length<=limit,"Oversize menu file");return File.ReadAllBytes(p);}
 static string Id(byte[] b,int offset){return new Guid(Slice(b,offset,16)).ToString();}
 static string Field(byte[] b,int offset,int length){string s=Encoding.Unicode.GetString(Slice(b,offset,length));int zero=s.IndexOf('\0');Check(zero>=0&&s.Substring(zero).Trim('\0').Length==0,"Invalid menu string");return s.Substring(0,zero);}
 public static void Validate(string root,string disk,string esp,string windows,string exportedBcd){
  string folder=Path.Combine(root,@"EFI\WinDeploy");
  byte[] menu=Read(Path.Combine(folder,"menu.bin"),44+772*16);
  Check(menu.Length>=44&&Encoding.ASCII.GetString(menu,0,8)=="W7DEP001","Invalid menu header");
  int count=BitConverter.ToInt32(menu,8);Check(count>0&&count<=16&&menu.Length==44+772*count,"Invalid menu length");
  Check(Equal(Hash(Slice(menu,44,menu.Length-44)),Slice(menu,12,32)),"Menu checksum mismatch");
  byte[] config=Read(Path.Combine(folder,@"SystemStores\Configuration.bin"),112+32*16);
  Check(config.Length==112+32*count&&Encoding.ASCII.GetString(config,0,8)=="W7DEPC01"&&BitConverter.ToInt32(config,8)==1&&BitConverter.ToInt32(config,12)==count,"Invalid store configuration");
  Check(Id(config,16)==disk&&Id(config,32)==esp&&Equal(Hash(menu),Slice(config,48,32)),"Menu identity mismatch");
  byte[] joined=new byte[80+count*32];Array.Copy(config,joined,80);Array.Copy(config,112,joined,80,count*32);
  Check(Equal(Hash(joined),Slice(config,80,32)),"Store configuration checksum mismatch");
  byte[] state=Read(Path.Combine(folder,@"SystemStores\Active.bin"),88);
  Check(state.Length==88&&Encoding.ASCII.GetString(state,0,8)=="W7DEPS01"&&BitConverter.ToInt32(state,20)==0&&Equal(Hash(config),Slice(state,24,32))&&Equal(Hash(Slice(state,0,56)),Slice(state,56,32)),"Invalid active-store state");
  int active=BitConverter.ToInt32(state,16);Check(active>=0&&active<count,"Invalid active entry");
  int own=-1;
  for(int i=0;i<count;i++){
   string d=Id(config,112+i*32),w=Id(config,128+i*32);
   int offset=44+i*772;
   Check(Id(menu,offset+20)==w,"Menu/store order mismatch");
   BootStoreGuard.Validate(Path.Combine(folder,@"SystemStores\Private-"+i+".BCD"),d,esp,w);
   if(d==disk&&w==windows){Check(own<0,"Duplicate Windows identity");own=i;
    Check(Id(menu,offset+4)==esp&&Field(menu,offset+260,512).Equals(@"\EFI\W7DEP-WIN7-AUTO\WIN7AUTO.efi",StringComparison.OrdinalIgnoreCase),"This entry does not use the verified graphics route");
    Check(BitConverter.ToInt32(menu,offset)==5,"Unexpected graphics entry flags");
    Check(BitConverter.ToString(Slice(menu,offset+36,32)).Replace("-","").ToLowerInvariant()=="e883cafc83e127c09ccec1c6cef96d4cf0b2f39242ba66e68adaa0279c2d7c07","Unrecognised graphics helper binding");
   }
  }
  Check(own==active,"Current Windows and picker active record differ; use explicit menu recovery");
  BootStoreGuard.Validate(exportedBcd,disk,esp,windows);
 }
}
