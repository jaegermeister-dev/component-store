/* Native Win7 x64 entry point. Normal UAC; never changes security policies.
 * The embedded manifest authenticates each private-pack payload before it is
 * copied into a new administrator-only staging directory. No network use.
 * --self-test is read-only and never elevates or invokes the installer.
 */
#ifndef UNICODE
#define UNICODE 1
#endif
#ifndef _UNICODE
#define _UNICODE 1
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <sddl.h>
#include <bcrypt.h>
#include <stdint.h>

typedef struct { const wchar_t *path; ULONGLONG size; const char *sha; int amd; } PackFile;
#include "embedded_pack.h"
#define CAP 32768
static HWND owner;
static BYTE transfer_buffer[65536];
/* No CRT bootstrap or redistributable dependency. The compiler may also emit
 * these basic memory helpers for structure copies. */
void *memcpy(void *dst,const void *src,size_t count) {BYTE *d=dst;const BYTE *s=src;while(count--)*d++=*s++;return dst;}
void *memset(void *dst,int value,size_t count) {BYTE *d=dst;while(count--)*d++=(BYTE)value;return dst;}
static size_t alen(const char *p){size_t n=0;while(p[n])++n;return n;}
static int acmp(const char *a,const char *b){while(*a&&*a==*b){++a;++b;}return (unsigned char)*a-(unsigned char)*b;}
static int append(wchar_t *dst,const wchar_t *src){size_t a=(size_t)lstrlenW(dst),b=(size_t)lstrlenW(src);if(a+b>=CAP)return 0;for(size_t i=0;i<=b;++i)dst[a+i]=src[i];return 1;}
static wchar_t *last_slash(wchar_t *p){wchar_t *last=NULL;for(;*p;++p)if(*p==L'\\')last=p;return last;}

static int safe_relative(const wchar_t *p) {
    if (!p || !*p || *p==L'/' || *p==L'\\') return 0;
    const wchar_t *part=p;
    for (;;) {
        wchar_t c=*p;
        if (c==0 || c==L'\\') {
            size_t n=(size_t)(p-part);
            if (!n || (n==1 && part[0]==L'.') || (n==2 && part[0]==L'.' && part[1]==L'.')) return 0;
            if (!c) return 1;
            part=p+1;
        } else if (c<32 || c==L':' || c==L'/' || c==L'"' || c==L'*' || c==L'?') return 0;
        ++p;
    }
}
static int join(wchar_t *out, const wchar_t *root, const wchar_t *rel) {
    if (!safe_relative(rel)) return 0;
    out[0]=0;return append(out,root)&&append(out,L"\\")&&append(out,rel);
}
static void fail(const wchar_t *message) {
    MessageBoxW(owner,message,L"NoMoreBCA driver setup",MB_ICONERROR|MB_OK);
}
static int sha_handle(HANDLE file, char out[65]) {
    BCRYPT_ALG_HANDLE alg=NULL; BCRYPT_HASH_HANDLE hash=NULL;
    DWORD objectSize=0,got=0; PUCHAR object=NULL; BYTE digest[32];
    LARGE_INTEGER zero; zero.QuadPart=0; int ok=0;
    if (!SetFilePointerEx(file,zero,NULL,FILE_BEGIN)) goto done;
    if (BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,NULL,0)<0) goto done;
    if (BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,(PUCHAR)&objectSize,sizeof(objectSize),&got,0)<0 || !objectSize) goto done;
    object=HeapAlloc(GetProcessHeap(),0,objectSize); if (!object) goto done;
    if (BCryptCreateHash(alg,&hash,object,objectSize,NULL,0,0)<0) goto done;
    for (;;) {
        if (!ReadFile(file,transfer_buffer,sizeof(transfer_buffer),&got,NULL)) goto done;
        if (!got) break;
        if (BCryptHashData(hash,transfer_buffer,got,0)<0) goto done;
    }
    if (BCryptFinishHash(hash,digest,sizeof(digest),0)<0) goto done;
    for (int i=0;i<32;++i){out[2*i]="0123456789abcdef"[digest[i]>>4];out[2*i+1]="0123456789abcdef"[digest[i]&15];}
    out[64]=0; ok=1;
done:
    if(hash)BCryptDestroyHash(hash); if(object)HeapFree(GetProcessHeap(),0,object);
    if(alg)BCryptCloseAlgorithmProvider(alg,0); return ok;
}
/* No write/delete sharing: the verified source stays locked through copying. */
static HANDLE verified_file(const wchar_t *path, const PackFile *item) {
    HANDLE f=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,
                        FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_SEQUENTIAL_SCAN,NULL);
    BY_HANDLE_FILE_INFORMATION info; char digest[65];
    if(f==INVALID_HANDLE_VALUE)return f;
    if(!GetFileInformationByHandle(f,&info) || (info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) ||
       (((ULONGLONG)info.nFileSizeHigh<<32)|info.nFileSizeLow)!=item->size ||
       !sha_handle(f,digest) || acmp(digest,item->sha)) {CloseHandle(f);return INVALID_HANDLE_VALUE;}
    return f;
}
static int copy_locked(HANDLE src, const wchar_t *dst, const PackFile *item) {
    HANDLE out=CreateFileW(dst,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    DWORD n,w; LARGE_INTEGER zero; zero.QuadPart=0; int ok=0;
    if(out==INVALID_HANDLE_VALUE)return 0;
    if(!SetFilePointerEx(src,zero,NULL,FILE_BEGIN))goto done;
    for(;;){if(!ReadFile(src,transfer_buffer,sizeof(transfer_buffer),&n,NULL))goto done;if(!n)break;
        if(!WriteFile(out,transfer_buffer,n,&w,NULL)||w!=n)goto done;}
    ok=FlushFileBuffers(out);
done:
    CloseHandle(out); if(!ok)return 0;
    HANDLE check=verified_file(dst,item);if(check==INVALID_HANDLE_VALUE)return 0;CloseHandle(check);return 1;
}
static int parents(const wchar_t *root,const wchar_t *rel) {
    static wchar_t path[CAP];if(!join(path,root,rel))return 0;
    for(wchar_t *p=path+lstrlenW(root)+1;*p;++p)if(*p==L'\\'){
        *p=0;
        if(!CreateDirectoryW(path,NULL) && GetLastError()!=ERROR_ALREADY_EXISTS)return 0;
        DWORD a=GetFileAttributesW(path);if(a==INVALID_FILE_ATTRIBUTES || !(a&FILE_ATTRIBUTE_DIRECTORY) || (a&FILE_ATTRIBUTE_REPARSE_POINT))return 0;
        *p=L'\\';
    }
    return 1;
}
static int model_from_table(const BYTE *table,size_t bytes,wchar_t model[80]) {
    if(bytes<8)return 0;DWORD len;memcpy(&len,table+4,4);if(len>bytes-8)return 0;
    const BYTE *p=table+8,*end=p+len;
    while(p+4<=end){
        BYTE type=p[0],n=p[1];if(n<4 || p+n>end)return 0;
        const BYTE *s=p+n,*next=s;
        while(next+1<end && (next[0]||next[1]))++next;
        if(next+1>=end)return 0;
        if(type==1 && n>=6 && p[5]){
            BYTE index=1;while(s<next && index<p[5]){while(s<next&&*s)++s;++s;++index;}
            if(index!=p[5]||s>next)return 0;
            size_t count=0;while(s+count<=next&&s[count])++count;
            if(!count||count>=80)return 0;
            for(size_t i=0;i<count;++i){if(s[i]<32||s[i]>126)return 0;model[i]=s[i];}model[count]=0;return 1;
        }
        if(type==127)break;p=next+2;
    }return 0;
}
static int machine_model(wchar_t model[80]) {
    UINT n=GetSystemFirmwareTable(0x52534d42,0,NULL,0);if(n<8||n>16*1024*1024)return 0;
    BYTE *p=HeapAlloc(GetProcessHeap(),0,n);if(!p)return 0;
    int ok=GetSystemFirmwareTable(0x52534d42,0,p,n)==n && model_from_table(p,n,model);
    HeapFree(GetProcessHeap(),0,p);return ok;
}
static int elevated(void) {
    HANDLE token;TOKEN_ELEVATION data;DWORD got;int ok=0;
    if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)){ok=GetTokenInformation(token,TokenElevation,&data,sizeof(data),&got)&&data.TokenIsElevated;CloseHandle(token);}return ok;
}
static int supported_os(void) {
    OSVERSIONINFOEXW v;ZeroMemory(&v,sizeof(v));v.dwOSVersionInfoSize=sizeof(v);
    return sizeof(void*)==8 && GetVersionExW((OSVERSIONINFOW*)&v) && v.dwMajorVersion==6 && v.dwMinorVersion==1 && v.dwBuildNumber==7601 && v.wProductType==VER_NT_WORKSTATION;
}
static int write_embedded(const wchar_t *path,const unsigned char *data,size_t size) {
    HANDLE f=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);DWORD written;
    if(f==INVALID_HANDLE_VALUE || size>0xffffffff)return 0;
    int ok=WriteFile(f,data,(DWORD)size,&written,NULL)&&written==size&&FlushFileBuffers(f);CloseHandle(f);return ok;
}
static int stage_and_run(const wchar_t *source,const wchar_t *model) {
    static wchar_t base[MAX_PATH],root[CAP],src[CAP],dst[CAP],system[MAX_PATH],command[CAP];
    GUID id;wchar_t guid[50];PSECURITY_DESCRIPTOR sd=NULL;SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,FALSE};
    HANDLE files[sizeof(pack_files)/sizeof(pack_files[0])];size_t count=sizeof(pack_files)/sizeof(pack_files[0]);int result=1;
    for(size_t i=0;i<count;++i)files[i]=INVALID_HANDLE_VALUE;
    /* Validate every required byte before creating any permanent output. */
    for(size_t i=0;i<count;++i){if(pack_files[i].amd && !lstrcmpW(model,L"MacBookPro11,4"))continue;
        if(!join(src,source,pack_files[i].path) || (files[i]=verified_file(src,&pack_files[i]))==INVALID_HANDLE_VALUE){fail(L"Driver payload is missing or has changed. No driver was installed.");goto done;}}
    if(FAILED(SHGetFolderPathW(NULL,CSIDL_COMMON_APPDATA,NULL,SHGFP_TYPE_CURRENT,base)) || FAILED(CoCreateGuid(&id)) || !StringFromGUID2(&id,guid,50))goto done;
    root[0]=0;if(!append(root,base)||!append(root,L"\\NoMoreBCA-Driver-Setup-")||!append(root,guid))goto done;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",SDDL_REVISION_1,&sd,NULL))goto done;
    sa.lpSecurityDescriptor=sd;
    if(!CreateDirectoryW(root,&sa))goto done;
    for(size_t i=0;i<count;++i){if(files[i]==INVALID_HANDLE_VALUE)continue;
        if(!parents(root,pack_files[i].path)||!join(dst,root,pack_files[i].path)||!copy_locked(files[i],dst,&pack_files[i])){fail(L"Verified driver staging failed. No driver was installed; staging files were retained for inspection.");goto done;}}
    if(!join(dst,root,L"Driver-Setup.ps1") || !write_embedded(dst,backend_script,sizeof(backend_script)))goto done;
    if(!join(dst,root,L"Native-Driver-Api.cs") || !write_embedded(dst,native_api,sizeof(native_api)))goto done;
    if(!join(dst,root,L"expected-files.csv") || !write_embedded(dst,payload_csv,sizeof(payload_csv)))goto done;
    if(!GetSystemDirectoryW(system,MAX_PATH))goto done;
    if(!join(src,system,L"WindowsPowerShell\\v1.0\\powershell.exe"))goto done;
    command[0]=0;
    if(!append(command,L"\"")||!append(command,src)||!append(command,L"\" -NoLogo -NoProfile -STA -ExecutionPolicy RemoteSigned -File \"")||
       !append(command,root)||!append(command,L"\\Driver-Setup.ps1\" -PackRoot \"")||!append(command,root)||
       !append(command,L"\" -ExpectedModel \"")||!append(command,model)||!append(command,L"\""))goto done;
    STARTUPINFOW si;PROCESS_INFORMATION pi;ZeroMemory(&si,sizeof(si));ZeroMemory(&pi,sizeof(pi));si.cb=sizeof(si);
    if(!CreateProcessW(src,command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,root,&si,&pi)){fail(L"Windows could not start its built-in driver-setup interface. No driver was installed.");goto done;}
    CloseHandle(pi.hThread);WaitForSingleObject(pi.hProcess,INFINITE);DWORD code=1;GetExitCodeProcess(pi.hProcess,&code);CloseHandle(pi.hProcess);result=(int)code;
done:
    for(size_t i=0;i<count;++i)if(files[i]!=INVALID_HANDLE_VALUE)CloseHandle(files[i]);
    if(sd)LocalFree(sd);return result;
}
static int self_test(const wchar_t *fixture) {
    BYTE table[]={0,2,7,0,26,0,0,0,1,6,0,0,1,2,'A','p','p','l','e',0,'M','a','c','B','o','o','k','P','r','o','1','1',',','5',0,0};
    DWORD length=(DWORD)sizeof(table)-8;memcpy(table+4,&length,4);wchar_t m[80];
    if(!model_from_table(table,sizeof(table),m)||lstrcmpW(m,L"MacBookPro11,5"))return 21;
    if(model_from_table(table,sizeof(table)-1,m))return 22;
    if(!safe_relative(L"Payload\\Apple-Trackpad\\AppleMTP.sys"))return 23;
    const wchar_t *bad[]={L"",L"..\\x",L"x\\..\\x",L"x:ads",L"C:\\x",L"\\server\\x",L"x\\",L"x//y",L"x\\.\\y",L"x\\\\y"};
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);++i)if(safe_relative(bad[i]))return 24;
    for(size_t i=0;i<sizeof(pack_files)/sizeof(pack_files[0]);++i)if(!safe_relative(pack_files[i].path)||alen(pack_files[i].sha)!=64||!pack_files[i].size)return 25;
    if(fixture){
        PackFile item={L"fixture",3,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",0};
        HANDLE h=verified_file(fixture,&item);if(h==INVALID_HANDLE_VALUE)return 26;CloseHandle(h);
        item.size=4;h=verified_file(fixture,&item);if(h!=INVALID_HANDLE_VALUE){CloseHandle(h);return 27;}
        item.size=3;item.sha="ca7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        h=verified_file(fixture,&item);if(h!=INVALID_HANDLE_VALUE){CloseHandle(h);return 28;}
    }
    return 0;
}
static int app_main(void) {
    int argc=0;LPWSTR *argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(!argv)return 1;
    if((argc==2||argc==3)&&!lstrcmpW(argv[1],L"--self-test")){int result=self_test(argc==3?argv[2]:NULL);LocalFree(argv);return result;}
    int admin_mode=argc==2&&!lstrcmpW(argv[1],L"--elevated");
    if(argc!=1&&!admin_mode){LocalFree(argv);return 2;}LocalFree(argv);
    if(!supported_os()){fail(L"This optional driver installer is for Windows 7 SP1 x64 only. No changes were made.");return 3;}
    static wchar_t model[80],exe[CAP],source[CAP];
    if(!machine_model(model) || (lstrcmpW(model,L"MacBookPro11,5")&&lstrcmpW(model,L"MacBookPro11,4"))){fail(L"This pack is for MacBookPro11,5 and experimental MacBookPro11,4 only. No changes were made.");return 4;}
    DWORD n=GetModuleFileNameW(NULL,exe,CAP);if(!n||n>=CAP)return 5;source[0]=0;if(!append(source,exe))return 5;wchar_t *sep=last_slash(source);if(!sep)return 5;*sep=0;
    if(!elevated()){
        if(admin_mode)return 6;
        SHELLEXECUTEINFOW se;ZeroMemory(&se,sizeof(se));se.cbSize=sizeof(se);se.fMask=SEE_MASK_NOCLOSEPROCESS;se.lpVerb=L"runas";se.lpFile=exe;se.lpParameters=L"--elevated";se.lpDirectory=source;se.nShow=SW_SHOWNORMAL;
        if(!ShellExecuteExW(&se))return GetLastError()==ERROR_CANCELLED?1223:7;
        WaitForSingleObject(se.hProcess,INFINITE);DWORD status=1;GetExitCodeProcess(se.hProcess,&status);CloseHandle(se.hProcess);return (int)status;
    }
    return stage_and_run(source,model);
}
void WINAPI NoMoreBCAEntry(void) {ExitProcess((UINT)app_main());}
