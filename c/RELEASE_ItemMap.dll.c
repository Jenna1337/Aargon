typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef unsigned short    word;
typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

typedef struct _s_HandlerType HandlerType;

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

typedef int ptrdiff_t;

struct TypeDescriptor {
    void *pVFTable;
    void *spare;
    char name[0];
};

struct _s_HandlerType {
    uint adjectives;
    struct TypeDescriptor *pType;
    ptrdiff_t dispCatchObj;
    void *addressOfHandler;
};

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef int __ehstate_t;

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    void (*action)(void);
};

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

struct _s_TryBlockMapEntry {
    __ehstate_t tryLow;
    __ehstate_t tryHigh;
    __ehstate_t catchHigh;
    int nCatches;
    HandlerType *pHandlerArray;
};

typedef struct _s_TryBlockMapEntry TryBlockMapEntry;

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

typedef struct _s_FuncInfo FuncInfo;

struct _s_FuncInfo {
    uint magicNumber_and_bbtFlags;
    __ehstate_t maxState;
    UnwindMapEntry *pUnwindMap;
    uint nTryBlocks;
    TryBlockMapEntry *pTryBlockMap;
    uint nIPMapEntries;
    void *pIPToStateMap;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef ulong DWORD;

typedef void *LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _WIN32_FIND_DATAA _WIN32_FIND_DATAA, *P_WIN32_FIND_DATAA;

typedef struct _WIN32_FIND_DATAA *LPWIN32_FIND_DATAA;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

typedef char CHAR;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct _WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    CHAR cFileName[260];
    CHAR cAlternateFileName[14];
};

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef CHAR *LPCSTR;

typedef DWORD ACCESS_MASK;

typedef void *HANDLE;

typedef CHAR *LPSTR;

typedef long LONG;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef ulong ULONG_PTR;

typedef ULONG_PTR SIZE_T;

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD *LPDWORD;

typedef ushort WORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef void *LPCVOID;

typedef HANDLE HLOCAL;

typedef struct _FILETIME *LPFILETIME;

typedef int (*FARPROC)(void);

typedef struct HICON__ HICON__, *PHICON__;

struct HICON__ {
    int unused;
};

typedef WORD *LPWORD;

typedef struct HKEY__ *HKEY;

typedef HKEY *PHKEY;

typedef struct HICON__ *HICON;

typedef HICON HCURSOR;

typedef uint UINT;

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_DIRECTORY_ENTRY_EXPORT IMAGE_DIRECTORY_ENTRY_EXPORT, *PIMAGE_DIRECTORY_ENTRY_EXPORT;

struct IMAGE_DIRECTORY_ENTRY_EXPORT {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Name;
    dword Base;
    dword NumberOfFunctions;
    dword NumberOfNames;
    dword AddressOfFunctions;
    dword AddressOfNames;
    dword AddressOfNameOrdinals;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef struct _s_CatchableTypeArray _s_CatchableTypeArray, *P_s_CatchableTypeArray;

typedef struct _s_CatchableTypeArray CatchableTypeArray;

typedef struct _s_CatchableType _s_CatchableType, *P_s_CatchableType;

typedef struct _s_CatchableType CatchableType;


// WARNING! conflicting data type names: /ehdata.h/TypeDescriptor - /TypeDescriptor

typedef struct PMD PMD, *PPMD;

typedef void (*PMFN)(void *);

struct PMD {
    ptrdiff_t mdisp;
    ptrdiff_t pdisp;
    ptrdiff_t vdisp;
};

struct _s_CatchableType {
    uint properties;
    struct TypeDescriptor *pType;
    struct PMD thisDisplacement;
    int sizeOrOffset;
    PMFN copyFunction;
};

struct _s_CatchableTypeArray {
    int nCatchableTypes;
    CatchableType *arrayOfCatchableTypes[0];
};

typedef struct _s_ThrowInfo _s_ThrowInfo, *P_s_ThrowInfo;

typedef struct _s_ThrowInfo ThrowInfo;

struct _s_ThrowInfo {
    uint attributes;
    PMFN pmfnUnwind;
    int (*pForwardCompat)(void);
    CatchableTypeArray *pCatchableTypeArray;
};

typedef ACCESS_MASK REGSAM;

typedef LONG LSTATUS;

typedef struct CFile CFile, *PCFile;

struct CFile { // PlaceHolder Structure
};

typedef struct ITEM ITEM, *PITEM;

struct ITEM { // PlaceHolder Structure
};

typedef struct CDynLinkLibrary CDynLinkLibrary, *PCDynLinkLibrary;

struct CDynLinkLibrary { // PlaceHolder Structure
};

typedef struct AFX_MODULE_STATE AFX_MODULE_STATE, *PAFX_MODULE_STATE;

struct AFX_MODULE_STATE { // PlaceHolder Structure
};

typedef struct CArchive CArchive, *PCArchive;

struct CArchive { // PlaceHolder Structure
};

typedef struct _AFX_THREAD_STATE _AFX_THREAD_STATE, *P_AFX_THREAD_STATE;

struct _AFX_THREAD_STATE { // PlaceHolder Structure
};

typedef struct MAP MAP, *PMAP;

struct MAP { // PlaceHolder Structure
};

typedef struct LEVEL LEVEL, *PLEVEL;

struct LEVEL { // PlaceHolder Structure
};

typedef struct AFX_MAINTAIN_STATE2 AFX_MAINTAIN_STATE2, *PAFX_MAINTAIN_STATE2;

struct AFX_MAINTAIN_STATE2 { // PlaceHolder Structure
};

typedef struct CRuntimeClass CRuntimeClass, *PCRuntimeClass;

struct CRuntimeClass { // PlaceHolder Structure
};

typedef struct CDirection CDirection, *PCDirection;

struct CDirection { // PlaceHolder Structure
};

typedef struct CPlex CPlex, *PCPlex;

struct CPlex { // PlaceHolder Structure
};

typedef struct TILEBLITTER TILEBLITTER, *PTILEBLITTER;

struct TILEBLITTER { // PlaceHolder Structure
};

typedef struct CString CString, *PCString;

struct CString { // PlaceHolder Structure
};

typedef struct DD_SURFACE DD_SURFACE, *PDD_SURFACE;

struct DD_SURFACE { // PlaceHolder Structure
};

typedef struct CFileFind CFileFind, *PCFileFind;

struct CFileFind { // PlaceHolder Structure
};

typedef struct LIST<class_ITEM*> LIST<class_ITEM*>, *PLIST<class_ITEM*>;

struct LIST<class_ITEM*> { // PlaceHolder Structure
};

typedef struct CTypeLibCacheMap CTypeLibCacheMap, *PCTypeLibCacheMap;

struct CTypeLibCacheMap { // PlaceHolder Structure
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef struct CPosition CPosition, *PCPosition;

struct CPosition { // PlaceHolder Structure
};

typedef struct HWND__ HWND__, *PHWND__;

struct HWND__ { // PlaceHolder Structure
};

typedef struct REG REG, *PREG;

struct REG { // PlaceHolder Structure
};

typedef struct STRING STRING, *PSTRING;

struct STRING { // PlaceHolder Structure
};

typedef struct AFX_EXTENSION_MODULE AFX_EXTENSION_MODULE, *PAFX_EXTENSION_MODULE;

struct AFX_EXTENSION_MODULE { // PlaceHolder Structure
};

typedef struct GAME GAME, *PGAME;

struct GAME { // PlaceHolder Structure
};

typedef struct INIFILE INIFILE, *PINIFILE;

struct INIFILE { // PlaceHolder Structure
};

typedef struct CException CException, *PCException;

struct CException { // PlaceHolder Structure
};

typedef struct CObject CObject, *PCObject;

struct CObject { // PlaceHolder Structure
};

typedef struct CColor CColor, *PCColor;

struct CColor { // PlaceHolder Structure
};

typedef struct CCut CCut, *PCCut;

struct CCut { // PlaceHolder Structure
};

typedef struct SPRITE SPRITE, *PSPRITE;

struct SPRITE { // PlaceHolder Structure
};

typedef struct shared_ptr<struct_Concurrency::details::_Task_impl<unsigned_char>_> shared_ptr<struct_Concurrency::details::_Task_impl<unsigned_char>_>, *Pshared_ptr<struct_Concurrency::details::_Task_impl<unsigned_char>_>;

struct shared_ptr<struct_Concurrency::details::_Task_impl<unsigned_char>_> { // PlaceHolder Structure
};

typedef struct SECTION SECTION, *PSECTION;

struct SECTION { // PlaceHolder Structure
};

typedef enum DIRECTION {
} DIRECTION;

typedef int (*_onexit_t)(void);

typedef uint size_t;




// public: static bool __cdecl MAP::CheckBackReflection(char const *)

bool __cdecl MAP::CheckBackReflection(char *param_1)

{
                    // 0x1000  4  ?CheckBackReflection@MAP@@SA_NPBD@Z
  return true;
}



undefined4 __cdecl FUN_10001007(int param_1,int param_2)

{
  CString *pCVar1;
  LPCSTR pCVar2;
  uint uVar3;
  undefined1 local_28;
  CString local_1c [4];
  uint local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e3f9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pCVar1 = FUN_1000b46e(local_1c);
  local_8 = 0;
  pCVar2 = (LPCSTR)FUN_1000a7a0((undefined4 *)pCVar1);
  local_14 = FUN_1000ba5a(pCVar2);
  local_8 = 0xffffffff;
  CString::~CString(local_1c);
  local_18 = DAT_1001324c * DAT_10013250;
  *(uint *)(&DAT_10013c9c + param_2 * 4 + (param_1 + -1) * 0x78) = local_14;
  uVar3 = local_14 / local_18;
  if (local_14 % local_18 == 0) {
    uVar3 = FUN_1000b9a9(param_1,param_2,local_14);
    uVar3 = uVar3 & 0xff;
    if (uVar3 == 0) {
      local_28 = 1;
      goto LAB_100010c8;
    }
  }
  local_28 = 0;
LAB_100010c8:
  ExceptionList = local_10;
  return CONCAT31((int3)(uVar3 >> 8),local_28);
}



// public: static bool __cdecl MAP::RecalculatePath(char const *)

bool __cdecl MAP::RecalculatePath(char *param_1)

{
  bool bVar1;
  uint uVar2;
  uint local_8;
  
                    // 0x10d9  26  ?RecalculatePath@MAP@@SA_NPBD@Z
  uVar2 = FUN_1000ba5a(param_1);
  for (local_8 = (uVar2 / DAT_1001324c) * DAT_1001324c; local_8 % DAT_10013250 == 0;
      local_8 = local_8 - DAT_1001324c) {
    FUN_10001149(&local_8,&DAT_1001324c);
  }
  bVar1 = FUN_1000bb3c(param_1,local_8);
  return bVar1;
}



bool __cdecl FUN_10001149(uint *param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = *param_1;
  uVar1 = *param_2;
  if (uVar2 < uVar1) {
    *param_1 = 0xa8bf;
    *param_1 = *param_1 / *param_2;
    *param_1 = *param_1 * *param_2;
  }
  return uVar2 < uVar1;
}



int __cdecl FUN_1000118c(int param_1,int param_2)

{
  bool bVar1;
  CString *pCVar2;
  LPCSTR pCVar3;
  uint uVar4;
  uint3 extraout_var;
  uint3 uVar6;
  int iVar5;
  CString local_28 [4];
  uint local_24;
  CString local_20 [4];
  uint local_1c;
  uint local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e415;
  local_10 = ExceptionList;
  local_1c = DAT_1001324c * DAT_10013250;
  ExceptionList = &local_10;
  pCVar2 = FUN_1000b46e(local_20);
  local_8 = 0;
  pCVar3 = (LPCSTR)FUN_1000a7a0((undefined4 *)pCVar2);
  local_14 = FUN_1000ba5a(pCVar3);
  local_8 = 0xffffffff;
  CString::~CString(local_20);
  local_14 = (local_14 / local_1c) * local_1c;
  bVar1 = FUN_10001149(&local_14,&local_1c);
  local_18 = CONCAT31(local_18._1_3_,bVar1);
  while( true ) {
    do {
      uVar4 = FUN_1000b9a9(param_1,param_2,local_14);
      if ((uVar4 & 0xff) == 0) {
        uVar4 = local_14;
        pCVar2 = FUN_1000b46e(local_28);
        local_8 = 1;
        pCVar3 = (LPCSTR)FUN_1000a7a0((undefined4 *)pCVar2);
        bVar1 = FUN_1000bb3c(pCVar3,uVar4);
        local_24 = CONCAT31(local_24._1_3_,bVar1);
        local_8 = 0xffffffff;
        uVar6 = extraout_var;
        CString::~CString(local_28);
        if ((local_24 & 0xff) == 0) {
          iVar5 = (uint)uVar6 << 8;
        }
        else {
          iVar5 = (param_1 + -1) * 0x78;
          *(uint *)(&DAT_10013c9c + param_2 * 4 + iVar5) = local_14;
          iVar5 = CONCAT31((int3)((uint)iVar5 >> 8),1);
        }
        ExceptionList = local_10;
        return iVar5;
      }
      local_14 = local_14 - local_1c;
      bVar1 = FUN_10001149(&local_14,&local_1c);
    } while (!bVar1);
    if ((local_18 & 0xff) != 0) break;
    local_18 = CONCAT31(local_18._1_3_,1);
  }
  ExceptionList = local_10;
  return 0;
}



// public: static void __cdecl MAP::SetDemoLevel(struct LEVEL,bool)

void __cdecl MAP::SetDemoLevel(int param_1,int param_2,char param_3)

{
  CString *pCVar1;
  char *pcVar2;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x12fd  36  ?SetDemoLevel@MAP@@SAXULEVEL@@_N@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e428;
  local_10 = ExceptionList;
  if (param_3 == '\0') {
    ExceptionList = &local_10;
    pCVar1 = FUN_1000b46e(local_14);
    local_8 = 0;
    pcVar2 = (char *)FUN_1000a7a0((undefined4 *)pCVar1);
    RecalculatePath(pcVar2);
    local_8 = 0xffffffff;
    CString::~CString(local_14);
  }
  else {
    ExceptionList = &local_10;
    FUN_1000118c(param_1,param_2);
  }
  s___AVtype_info___10013c18[param_2 + (param_1 + -1) * 0x1e + 0xf] = param_3;
  ExceptionList = local_10;
  return;
}



// public: static bool __cdecl MAP::RefreshItemMap(struct LEVEL)

bool __cdecl MAP::RefreshItemMap(uint param_1,int param_2)

{
  char cVar1;
  
                    // 0x139e  28  ?RefreshItemMap@MAP@@SA_NULEVEL@@@Z
  cVar1 = FUN_100013e0(&param_1);
  if (cVar1 == '\0') {
    cVar1 = '\0';
  }
  else {
    cVar1 = s___AVtype_info___10013c18[param_2 + (param_1 - 1) * 0x1e + 0xf];
  }
  return (bool)cVar1;
}



undefined1 __fastcall FUN_100013e0(uint *param_1)

{
  undefined1 local_c;
  
  if ((((*param_1 == 0) || (4 < *param_1)) || (param_1[1] == 0)) || (0x1e < param_1[1])) {
    local_c = 0;
  }
  else {
    local_c = 1;
  }
  return local_c;
}



void __fastcall FUN_10001430(MAP *param_1)

{
  bool bVar1;
  undefined4 *puVar2;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  void *pvVar3;
  uint *puVar4;
  int iVar5;
  undefined4 local_cc [7];
  undefined4 local_b0 [7];
  undefined1 local_94 [8];
  undefined1 local_8c [8];
  undefined1 local_84 [8];
  ITEM *local_7c;
  ITEM *local_78;
  uint local_74;
  CTypeLibCacheMap local_70 [28];
  undefined4 local_54 [7];
  undefined4 local_38 [7];
  uint local_1c;
  uint local_18;
  ITEM *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e473;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  bVar1 = FUN_10002730((char *)(param_1 + 0x43c),'\0');
  if (bVar1) {
    FUN_10001f90(local_70);
    local_8 = 0;
    FUN_10001c50(local_54);
    local_8._0_1_ = 1;
    FUN_10001c50(local_38);
    local_8._0_1_ = 2;
    local_18 = local_18 & 0xffffff00;
    puVar2 = (undefined4 *)default_error_condition(local_84,0,0);
    local_14 = MAP::GetItem(param_1,*puVar2,puVar2[1]);
    local_1c = 0;
    while ((local_1c < 0x14 && ((local_18 & 0xff) == 0))) {
      local_74 = 0;
      while ((local_74 < 0xd && ((local_18 & 0xff) == 0))) {
        local_78 = local_14;
        FUN_10001dc0(local_14,local_70);
        local_74 = local_74 + 1;
        if (local_74 < 0xd) {
          puVar2 = (undefined4 *)default_error_condition(local_8c,local_1c,local_74);
          local_14 = MAP::GetItem(param_1,*puVar2,puVar2[1]);
        }
        else if (local_1c < 0x13) {
          puVar2 = (undefined4 *)default_error_condition(local_94,local_1c + 1,0);
          local_14 = MAP::GetItem(param_1,*puVar2,puVar2[1]);
        }
      }
      local_1c = local_1c + 1;
    }
    bVar1 = IsEmpty((int)local_70);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      memset(&_Dst_10013e80,0,0x1200);
    }
    while (bVar1 = IsEmpty((int)local_70), CONCAT31(extraout_var_00,bVar1) == 0) {
      pvVar3 = FUN_10002480(local_70,local_b0);
      local_8._0_1_ = 3;
      FUN_10001fb0(local_54,(int)pvVar3);
      local_8._0_1_ = 2;
      FUN_10001ce0(local_b0);
      puVar4 = (uint *)FUN_10001d70((int)local_54);
      bVar1 = FUN_10002b40(puVar4);
      if (bVar1) {
        pvVar3 = FUN_10008af0(local_54,local_cc);
        local_8._0_1_ = 4;
        FUN_10001fb0(local_38,(int)pvVar3);
        local_8._0_1_ = 2;
        FUN_10001ce0(local_cc);
      }
      else {
        FUN_10001fb0(local_38,(int)local_54);
      }
      iVar5 = FUN_10001d00(local_38,0x14,0xd);
      if ((iVar5 != 0) && (bVar1 = FUN_100017d7((int)local_38), !bVar1)) {
        FUN_10001737((int)local_38);
        puVar2 = (undefined4 *)FUN_10001d50((int)local_38);
        local_7c = MAP::GetItem(param_1,*puVar2,puVar2[1]);
        FUN_10004084(local_7c,(int)local_38,local_70);
      }
    }
    local_8._0_1_ = 1;
    FUN_10001ce0(local_38);
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_10001ce0(local_54);
    local_8 = 0xffffffff;
    FUN_10001f30((undefined4 *)local_70);
  }
  ExceptionList = local_10;
  return;
}



void __cdecl FUN_10001737(int param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  
  piVar3 = (int *)FUN_10001d50(param_1);
  iVar1 = *piVar3;
  iVar2 = piVar3[1];
  puVar4 = (undefined4 *)FUN_10001d70(param_1);
  iVar5 = FUN_1000a7a0(puVar4);
  puVar4 = (undefined4 *)FUN_10001f70(param_1);
  iVar6 = FUN_10002c10(puVar4);
  uVar7 = iVar1 + iVar2 * 0x14;
  (&_Dst_10013e80)[(uVar7 >> 5) * 0x80 + iVar5 * 8 + iVar6] =
       (void *)((uint)(&_Dst_10013e80)[(uVar7 >> 5) * 0x80 + iVar5 * 8 + iVar6] |
               1 << (sbyte)((ulonglong)uVar7 % 0x20));
  return;
}



bool __cdecl FUN_100017d7(int param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  
  piVar3 = (int *)FUN_10001d50(param_1);
  iVar1 = *piVar3;
  iVar2 = piVar3[1];
  puVar4 = (undefined4 *)FUN_10001d70(param_1);
  iVar5 = FUN_1000a7a0(puVar4);
  puVar4 = (undefined4 *)FUN_10001f70(param_1);
  iVar6 = FUN_10002c10(puVar4);
  uVar7 = iVar1 + iVar2 * 0x14;
  return ((uint)(&_Dst_10013e80)[(uVar7 >> 5) * 0x80 + iVar5 * 8 + iVar6] &
         1 << (sbyte)((ulonglong)uVar7 % 0x20)) != 0;
}



// private: void __thiscall MAP::NewFrame(int)

void __thiscall MAP::NewFrame(MAP *this,int param_1)

{
  MAP MVar1;
  bool bVar2;
  byte bVar3;
  undefined3 extraout_var;
  CString *pCVar4;
  undefined4 *puVar5;
  uint uVar6;
  undefined3 extraout_var_00;
  int iVar7;
  ulong uVar8;
  TILEBLITTER *this_00;
  undefined3 extraout_var_01;
  int iVar9;
  undefined1 local_68 [8];
  undefined1 local_60 [8];
  undefined1 local_58 [8];
  undefined4 local_50;
  int local_4c;
  int *local_48;
  int local_44;
  ITEM *local_40;
  TILEBLITTER *local_3c;
  uint local_38;
  int local_34;
  TILEBLITTER *local_30;
  uint local_2c;
  undefined4 local_28;
  int local_24;
  uint local_20;
  uint local_1c;
  uint local_18;
  ITEM *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x1861  24  ?NewFrame@MAP@@AAEXH@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e486;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  DAT_100151e4 = GetTickCount();
  local_34 = FUN_100026f0(0x10015088);
  FUN_10002060((CString *)&local_28);
  local_8 = 0;
  local_1c = 0;
  bVar2 = IsEmpty(0x10015088);
  if (CONCAT31(extraout_var,bVar2) == 0) {
    pCVar4 = (CString *)FUN_10006070(&local_34);
    FUN_100021b0(&local_28,pCVar4);
  }
  local_1c = 0;
  do {
    uVar6 = FUN_10005970(0x10015088);
    if ((uVar6 <= local_1c) || (bVar2 = IsEmpty(0x10015088), CONCAT31(extraout_var_00,bVar2) != 0))
    {
      FUN_10001430(this);
      this[0x438] = (MAP)0x1;
      this[0x439] = (MAP)0x0;
      local_30 = (TILEBLITTER *)0x0;
      local_2c = CONCAT31(local_2c._1_3_,1);
      local_18 = local_18 & 0xffffff00;
      puVar5 = (undefined4 *)default_error_condition(local_58,0,0);
      local_14 = GetItem(this,*puVar5,puVar5[1]);
      local_20 = 0;
      while ((local_20 < 0x14 && ((local_18 & 0xff) == 0))) {
        local_38 = 0;
        while ((local_38 < 0xd && ((local_18 & 0xff) == 0))) {
          local_40 = local_14;
          local_3c = (TILEBLITTER *)FUN_10007c28(this,local_14);
          if (local_30 != local_3c) {
            if (local_30 != (TILEBLITTER *)0x0) {
              TILEBLITTER::EndLaserEffect(local_30,(DD_SURFACE *)ddsBack_exref);
            }
            bVar2 = TILEBLITTER::SetupLaserEffect(local_3c,(DD_SURFACE *)ddsBack_exref);
            if (!bVar2) {
              local_2c = local_2c & 0xffffff00;
            }
            local_30 = local_3c;
          }
          if ((local_2c & 0xff) != 0) {
            if (param_1 == 0) {
              FUN_100049a8(local_40,local_3c);
            }
            else {
              FUN_10004a41(local_40,local_3c);
            }
          }
          iVar7 = (**(code **)(*(int *)local_40 + 0x44))();
          if (iVar7 == 0) {
            this[0x438] = (MAP)0x0;
          }
          iVar7 = (**(code **)(*(int *)local_40 + 0x48))();
          if (iVar7 != 0) {
            this[0x439] = (MAP)0x1;
          }
          local_38 = local_38 + 1;
          if (local_38 < 0xd) {
            puVar5 = (undefined4 *)default_error_condition(local_60,local_20,local_38);
            local_14 = GetItem(this,*puVar5,puVar5[1]);
          }
          else if (local_20 < 0x13) {
            puVar5 = (undefined4 *)default_error_condition(local_68,local_20 + 1,0);
            local_14 = GetItem(this,*puVar5,puVar5[1]);
          }
        }
        local_20 = local_20 + 1;
      }
      TILEBLITTER::EndLaserEffect(local_30,(DD_SURFACE *)ddsBack_exref);
      this[0x43a] = (MAP)0x0;
      bVar2 = IsEmpty(0x10015218);
      if (CONCAT31(extraout_var_01,bVar2) == 0) {
        local_44 = FUN_100026f0(0x10015218);
        while (local_44 != 0) {
          puVar5 = (undefined4 *)FUN_10002380(&local_44);
          local_48 = (int *)*puVar5;
          (**(code **)(*local_48 + 0x7c))(this);
          MVar1 = this[0x43a];
          bVar3 = (**(code **)(*local_48 + 0x78))();
          this[0x43a] = (MAP)((byte)MVar1 | bVar3);
        }
      }
      local_8 = 0xffffffff;
      FUN_100020f0((CString *)&local_28);
      ExceptionList = local_10;
      return;
    }
    if (this[0x43b] == (MAP)0x0) {
LAB_1000196c:
      if (this[0x43b] == (MAP)0x0) {
        iVar7 = FUN_10002320(&local_24);
        iVar7 = FUN_10002040(iVar7);
        if (iVar7 == 0x20) goto LAB_1000198f;
      }
    }
    else {
      iVar7 = FUN_10002320(&local_24);
      iVar7 = FUN_10002040(iVar7);
      if (iVar7 != 8) goto LAB_1000196c;
LAB_1000198f:
      uVar8 = GKERNEL::GetCurrFrame();
      iVar7 = abs(((int)uVar8 / 3) % 7 + -3);
      iVar7 = iVar7 * 0x14 + 100;
      iVar9 = 0xb;
      this_00 = (TILEBLITTER *)FUN_10002320(&local_24);
      TILEBLITTER::SetLaserSize(this_00,iVar9,iVar7);
    }
    local_1c = local_1c + 1;
    uVar6 = FUN_10005970(0x10015088);
    if (local_1c < uVar6) {
      pCVar4 = (CString *)FUN_10006070(&local_34);
      puVar5 = (undefined4 *)FUN_100021b0(&local_28,pCVar4);
      local_50 = *puVar5;
      local_4c = puVar5[1];
    }
    else {
      local_50 = local_28;
      local_4c = local_24;
    }
  } while( true );
}



undefined4 * __fastcall FUN_10001c50(undefined4 *param_1)

{
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 uVar1;
  
  FUN_10002ab0(param_1 + 1);
  FUN_10002bb0(param_1 + 2);
  FUN_10002b70(param_1 + 3);
  uVar1 = extraout_ECX;
  FUN_10002ad0(&stack0xffffffec,0xfffffc00);
  FUN_10001cc0(param_1 + 5,uVar1);
  uVar1 = extraout_ECX_00;
  FUN_10002ad0(&stack0xffffffec,0xfffffc00);
  FUN_10001cc0(param_1 + 6,uVar1);
  *param_1 = &PTR_FUN_10010200;
  return param_1;
}



void * __thiscall FUN_10001cc0(void *this,undefined4 param_1)

{
  FUN_10002ab0((undefined4 *)this);
  *(undefined4 *)this = param_1;
  return this;
}



void __fastcall FUN_10001ce0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_10010200;
  return;
}



undefined4 __thiscall FUN_10001d00(void *this,int param_1,int param_2)

{
  undefined4 local_c;
  
  if ((((*(int *)((int)this + 0xc) < 0) || (param_1 <= *(int *)((int)this + 0xc))) ||
      (*(int *)((int)this + 0x10) < 0)) || (param_2 <= *(int *)((int)this + 0x10))) {
    local_c = 0;
  }
  else {
    local_c = 1;
  }
  return local_c;
}



int __fastcall FUN_10001d50(int param_1)

{
  return param_1 + 0xc;
}



int __fastcall FUN_10001d70(int param_1)

{
  return param_1 + 4;
}



void * __thiscall FUN_10001d90(void *this,uint param_1)

{
  FUN_10001ce0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __thiscall FUN_10001dc0(void *this,void *param_1)

{
  bool bVar1;
  int iVar2;
  undefined4 *puVar3;
  uint extraout_ECX;
  uint extraout_ECX_00;
  undefined4 extraout_ECX_01;
  int extraout_ECX_02;
  uint extraout_ECX_03;
  uint extraout_ECX_04;
  undefined4 extraout_ECX_05;
  int extraout_ECX_06;
  uint extraout_ECX_07;
  uint uVar4;
  undefined4 extraout_ECX_08;
  undefined4 extraout_ECX_09;
  int extraout_ECX_10;
  undefined4 uVar5;
  void *pvVar6;
  undefined1 local_4c [8];
  undefined1 local_44 [20];
  undefined1 local_30 [8];
  undefined1 local_28 [20];
  undefined1 local_14 [8];
  undefined1 local_c [8];
  
  FUN_10002530((int)this + 0x4c);
  iVar2 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
  if (*(int *)(iVar2 + 0x744) != 0) {
    uVar4 = extraout_ECX;
    FUN_10002bd0(&stack0xffffffa0,4);
    bVar1 = FUN_10002bf0((void *)((int)this + 0x34),uVar4);
    uVar4 = extraout_ECX_00;
    if (bVar1) {
      FUN_10002ad0(&stack0xffffffa0,0);
      FUN_10001cc0(local_c,uVar4);
      uVar5 = extraout_ECX_01;
      FUN_10002ad0(&stack0xffffff9c,0);
      puVar3 = (undefined4 *)FUN_10001cc0(local_14,uVar5);
      uVar5 = *puVar3;
      pvVar6 = param_1;
      FUN_10002bd0(&stack0xffffff94,4);
      iVar2 = extraout_ECX_02;
      FUN_10002ad0(&stack0xffffff90,0);
      FUN_10003a9e(this,iVar2,uVar5,pvVar6);
      uVar4 = extraout_ECX_03;
    }
    FUN_10002bd0(&stack0xffffffa0,2);
    bVar1 = FUN_10002bf0((void *)((int)this + 0x34),uVar4);
    uVar4 = extraout_ECX_04;
    if (bVar1) {
      FUN_10002ad0(&stack0xffffffa0,0);
      FUN_10001cc0(local_28,uVar4);
      uVar5 = extraout_ECX_05;
      FUN_10002ad0(&stack0xffffff9c,0);
      puVar3 = (undefined4 *)FUN_10001cc0(local_30,uVar5);
      uVar5 = *puVar3;
      pvVar6 = param_1;
      FUN_10002bd0(&stack0xffffff94,2);
      iVar2 = extraout_ECX_06;
      FUN_10002ad0(&stack0xffffff90,0);
      FUN_10003a9e(this,iVar2,uVar5,pvVar6);
      uVar4 = extraout_ECX_07;
    }
    FUN_10002bd0(&stack0xffffffa0,1);
    bVar1 = FUN_10002bf0((void *)((int)this + 0x34),uVar4);
    if (bVar1) {
      uVar5 = extraout_ECX_08;
      FUN_10002ad0(&stack0xffffffa0,0);
      FUN_10001cc0(local_44,uVar5);
      uVar5 = extraout_ECX_09;
      FUN_10002ad0(&stack0xffffff9c,0);
      puVar3 = (undefined4 *)FUN_10001cc0(local_4c,uVar5);
      uVar5 = *puVar3;
      FUN_10002bd0(&stack0xffffff94,1);
      iVar2 = extraout_ECX_10;
      FUN_10002ad0(&stack0xffffff90,0);
      FUN_10003a9e(this,iVar2,uVar5,param_1);
    }
  }
  return;
}



void __fastcall FUN_10001f30(undefined4 *param_1)

{
  FUN_10001f50(param_1);
  return;
}



void __fastcall FUN_10001f50(undefined4 *param_1)

{
  FUN_100025b0(param_1);
  return;
}



int __fastcall FUN_10001f70(int param_1)

{
  return param_1 + 8;
}



CTypeLibCacheMap * __fastcall FUN_10001f90(CTypeLibCacheMap *param_1)

{
  CTypeLibCacheMap::CTypeLibCacheMap(param_1);
  *(undefined ***)param_1 = &PTR_LAB_10010204;
  return param_1;
}



void * __thiscall FUN_10001fb0(void *this,int param_1)

{
  undefined4 uVar1;
  
  *(undefined4 *)((int)this + 4) = *(undefined4 *)(param_1 + 4);
  *(undefined4 *)((int)this + 8) = *(undefined4 *)(param_1 + 8);
  uVar1 = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)((int)this + 0xc) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)((int)this + 0x10) = uVar1;
  *(undefined4 *)((int)this + 0x14) = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)((int)this + 0x18) = *(undefined4 *)(param_1 + 0x18);
  return this;
}



void * __thiscall FUN_10002010(void *this,uint param_1)

{
  FUN_10001f30((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_100020b0(this);
  }
  return this;
}



undefined4 __fastcall FUN_10002040(int param_1)

{
  return *(undefined4 *)(param_1 + 0xb0);
}



CString * __fastcall FUN_10002060(CString *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e499;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10002c20(param_1);
  local_8 = 0;
  FUN_100022b0(param_1 + 4,0);
  ExceptionList = local_10;
  return param_1;
}



void FUN_100020b0(void *param_1)

{
  operator_delete(param_1);
  return;
}



void FUN_100020d0(void)

{
  return;
}



void FUN_100020e0(void)

{
  return;
}



void __fastcall FUN_100020f0(CString *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1000e4b9;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  FUN_10007600((int *)(param_1 + 4));
  local_8 = 0xffffffff;
  FUN_10002c40(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10002140(int *param_1)

{
  int iVar1;
  
  if (((*param_1 != 0) && (iVar1 = FUN_10002190(*param_1), iVar1 == 0)) &&
     ((undefined4 *)*param_1 != (undefined4 *)0x0)) {
    (*(code *)**(undefined4 **)*param_1)(1);
  }
  return;
}



undefined4 __fastcall FUN_10002190(int param_1)

{
  *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + -1;
  return *(undefined4 *)(param_1 + 4);
}



void * __thiscall FUN_100021b0(void *this,CString *param_1)

{
  FUN_100021e0(this,param_1);
  FUN_1000dcf0((void *)((int)this + 4),(shared_ptr<> *)(param_1 + 4));
  return this;
}



void * __thiscall FUN_100021e0(void *this,CString *param_1)

{
  CString::operator=((CString *)this,param_1);
  return this;
}



// Library Function - Single Match
//  public: __thiscall std::shared_ptr<struct Concurrency::details::_Task_impl<unsigned char>
// >::shared_ptr<struct Concurrency::details::_Task_impl<unsigned char> >(class
// std::shared_ptr<struct Concurrency::details::_Task_impl<unsigned char> > const &)
// 
// Libraries: Visual Studio 2012 Debug, Visual Studio 2012 Release

shared_ptr<> * __thiscall std::shared_ptr<>::shared_ptr<>(shared_ptr<> *this,shared_ptr<> *param_1)

{
  FUN_10002140((int *)this);
  FUN_10002230(this,(undefined4 *)param_1);
  return this;
}



void * __thiscall FUN_10002230(void *this,undefined4 *param_1)

{
  *(undefined4 *)this = *param_1;
                    // WARNING: Load size is inaccurate
  if (*this != 0) {
                    // WARNING: Load size is inaccurate
    FUN_10002260(*this);
  }
  return this;
}



undefined4 __fastcall FUN_10002260(int param_1)

{
  *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
  return *(undefined4 *)(param_1 + 4);
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_100023b0(this,10);
  *(undefined ***)this = &PTR_LAB_10010218;
  return this;
}



void * __thiscall FUN_100022b0(void *this,int param_1)

{
  undefined4 local_c;
  
  if (param_1 == 0) {
    local_c = 0;
  }
  else {
    local_c = param_1 + 0x98;
  }
  FUN_100022f0(this,local_c);
  return this;
}



void * __thiscall FUN_100022f0(void *this,undefined4 param_1)

{
  *(undefined4 *)this = param_1;
                    // WARNING: Load size is inaccurate
  if (*this != 0) {
                    // WARNING: Load size is inaccurate
    FUN_10002260(*this);
  }
  return this;
}



int __fastcall FUN_10002320(int *param_1)

{
  undefined4 local_c;
  
  if (*param_1 == 0) {
    local_c = 0;
  }
  else {
    local_c = *param_1 + -0x98;
  }
  return local_c;
}



void * __thiscall FUN_10002350(void *this,uint param_1)

{
  FUN_10001f50((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_100020b0(this);
  }
  return this;
}



int FUN_10002380(int *param_1)

{
  int *piVar1;
  
  piVar1 = (int *)*param_1;
  *param_1 = *piVar1;
  return (int)(piVar1 + 2);
}



void * __thiscall FUN_100023b0(void *this,undefined4 param_1)

{
  FUN_10002410((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_1001022c;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



undefined4 * __fastcall FUN_10002410(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_10010240;
  return param_1;
}



void * __thiscall FUN_10002430(void *this,uint param_1)

{
  FUN_10002460((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_100020b0(this);
  }
  return this;
}



void __fastcall FUN_10002460(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_10010240;
  return;
}



void * __thiscall FUN_10002480(void *this,void *param_1)

{
  undefined4 *puVar1;
  undefined4 local_2c [7];
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e4f0;
  local_10 = ExceptionList;
  puVar1 = *(undefined4 **)((int)this + 4);
  ExceptionList = &local_10;
  FUN_10002790(local_2c,(int)(puVar1 + 2));
  local_8 = 1;
  *(undefined4 *)((int)this + 4) = *puVar1;
  if (*(int *)((int)this + 4) == 0) {
    *(undefined4 *)((int)this + 8) = 0;
  }
  else {
    *(undefined4 *)(*(int *)((int)this + 4) + 4) = 0;
  }
  FUN_10002850(this,puVar1);
  FUN_10002790(param_1,(int)local_2c);
  local_8 = local_8 & 0xffffff00;
  FUN_10001ce0(local_2c);
  ExceptionList = local_10;
  return param_1;
}



void __fastcall FUN_10002530(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_100028a0(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



void __fastcall FUN_100025b0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1000e509;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_1001022c;
  local_8 = 0;
  FUN_10002530((int)param_1);
  local_8 = 0xffffffff;
  FUN_10002460(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_10002610(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_34 [7];
  ulong local_18;
  undefined4 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e529;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_100020e0();
  bVar1 = FUN_10002710((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_18 = CArchive::ReadCount(param_1);
    while (local_18 != 0) {
      local_18 = local_18 - 1;
      FUN_10001c50(local_34);
      local_8 = 0;
      FUN_100028d0(param_1,local_34,1);
      FUN_100027f0(this,(int)local_34);
      local_8 = 0xffffffff;
      FUN_10001ce0(local_34);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_14 = *(undefined4 **)((int)this + 4); local_14 != (undefined4 *)0x0;
        local_14 = (undefined4 *)*local_14) {
      FUN_100028d0(param_1,local_14 + 2,1);
    }
  }
  ExceptionList = local_10;
  return;
}



undefined4 __fastcall FUN_100026f0(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



bool __fastcall FUN_10002710(int param_1)

{
  return (bool)('\x01' - ((*(uint *)(param_1 + 0x14) & 1) != 0));
}



bool __cdecl FUN_10002730(char *param_1,char param_2)

{
  char cVar1;
  
  cVar1 = *param_1;
  *param_1 = param_2;
  return cVar1 != param_2;
}



void * __thiscall FUN_10002760(void *this,uint param_1)

{
  FUN_100025b0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_100020b0(this);
  }
  return this;
}



void * __thiscall FUN_10002790(void *this,int param_1)

{
  undefined4 uVar1;
  
  *(undefined4 *)((int)this + 4) = *(undefined4 *)(param_1 + 4);
  *(undefined4 *)((int)this + 8) = *(undefined4 *)(param_1 + 8);
  uVar1 = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)((int)this + 0xc) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)((int)this + 0x10) = uVar1;
  *(undefined4 *)((int)this + 0x14) = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)((int)this + 0x18) = *(undefined4 *)(param_1 + 0x18);
  *(undefined ***)this = &PTR_FUN_10010200;
  return this;
}



undefined4 * __thiscall FUN_100027f0(void *this,int param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_10002910(this,*(undefined4 *)((int)this + 8),0);
  FUN_10001fb0(puVar1 + 2,param_1);
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



void __thiscall FUN_10002850(void *this,undefined4 *param_1)

{
  FUN_100028a0(param_1 + 2,1);
  *param_1 = *(undefined4 *)((int)this + 0x10);
  *(undefined4 **)((int)this + 0x10) = param_1;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + -1;
  if (*(int *)((int)this + 0xc) == 0) {
    FUN_10002530((int)this);
  }
  return;
}



void FUN_100028a0(undefined4 *param_1,int param_2)

{
  while (param_2 != 0) {
    (**(code **)*param_1)(0);
    param_1 = param_1 + 7;
    param_2 = param_2 + -1;
  }
  return;
}



void FUN_100028d0(CArchive *param_1,void *param_2,int param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_10002710((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    CArchive::Read(param_1,param_2,param_3 * 0x1c);
  }
  else {
    CArchive::Write(param_1,param_2,param_3 * 0x1c);
  }
  return;
}



undefined4 * __thiscall FUN_10002910(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0x24);
    iVar3 = FUN_1000e3d0((int)pCVar2);
    local_c = (undefined4 *)(iVar3 + (*(int *)((int)this + 0x18) + -1) * 0x24);
    local_10 = *(int *)((int)this + 0x18);
    while (local_10 = local_10 + -1, -1 < local_10) {
      *local_c = *(undefined4 *)((int)this + 0x10);
      *(undefined4 **)((int)this + 0x10) = local_c;
      local_c = local_c + -9;
    }
  }
  puVar1 = *(undefined4 **)((int)this + 0x10);
  *(undefined4 *)((int)this + 0x10) = **(undefined4 **)((int)this + 0x10);
  puVar1[1] = param_1;
  *puVar1 = param_2;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  FUN_100029f0(puVar1 + 2,1);
  return puVar1;
}



void FUN_100029f0(void *param_1,int param_2)

{
  undefined4 *puVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e551;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  memset(param_1,0,param_2 * 0x1c);
  while (param_2 != 0) {
    puVar1 = (undefined4 *)FUN_10002a90(0x1c,param_1);
    local_8 = 0;
    if (puVar1 != (undefined4 *)0x0) {
      FUN_10001c50(puVar1);
    }
    local_8 = 0xffffffff;
    param_1 = (void *)((int)param_1 + 0x1c);
    param_2 = param_2 + -1;
  }
  ExceptionList = local_10;
  return;
}



undefined4 __cdecl FUN_10002a90(undefined4 param_1,undefined4 param_2)

{
  return param_2;
}



void FUN_10002aa0(void)

{
  return;
}



undefined4 * __fastcall FUN_10002ab0(undefined4 *param_1)

{
  *param_1 = 0xfffffc00;
  return param_1;
}



void * __thiscall FUN_10002ad0(void *this,uint param_1)

{
  FUN_10002af0(this,param_1);
  return this;
}



void __thiscall FUN_10002af0(void *this,uint param_1)

{
  uint uVar1;
  
  uVar1 = FUN_10002b10(param_1);
  *(uint *)this = uVar1;
  return;
}



uint __cdecl FUN_10002b10(uint param_1)

{
  undefined4 local_8;
  
  if (param_1 == 0xfffffc00) {
    local_8 = param_1;
  }
  else {
    local_8 = param_1 & 0xf;
  }
  return local_8;
}



bool __fastcall FUN_10002b40(uint *param_1)

{
  uint uVar1;
  
  uVar1 = *param_1 & 0x80000001;
  if ((int)uVar1 < 0) {
    uVar1 = (uVar1 - 1 | 0xfffffffe) + 1;
  }
  return (bool)('\x01' - (uVar1 != 0));
}



void * __fastcall FUN_10002b70(void *param_1)

{
  FUN_1000be70(param_1,0,0);
  return param_1;
}



// Library Function - Multiple Matches With Same Base Name
//  public: virtual class std::error_condition __thiscall
// std::_System_error_category::default_error_condition(int)const 
//  public: virtual class std::error_condition __thiscall
// std::error_category::default_error_condition(int)const 
// 
// Library: Visual Studio

void * __thiscall default_error_condition(void *this,undefined4 param_1,undefined4 param_2)

{
  FUN_1000be70(this,param_1,param_2);
  return this;
}



undefined4 * __fastcall FUN_10002bb0(undefined4 *param_1)

{
  *param_1 = 7;
  return param_1;
}



void * __thiscall FUN_10002bd0(void *this,undefined4 param_1)

{
  *(undefined4 *)this = param_1;
  return this;
}



bool __thiscall FUN_10002bf0(void *this,uint param_1)

{
                    // WARNING: Load size is inaccurate
  return (*this & param_1) == param_1;
}



undefined4 __fastcall FUN_10002c10(undefined4 *param_1)

{
  return *param_1;
}



CString * __fastcall FUN_10002c20(CString *param_1)

{
  CString::CString(param_1);
  return param_1;
}



void __fastcall FUN_10002c40(CString *param_1)

{
  CString::~CString(param_1);
  return;
}



void FUN_10002c60(void)

{
  FUN_10002c6f();
  FUN_10002c7e();
  return;
}



void FUN_10002c6f(void)

{
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)&DAT_10015088);
  return;
}



void FUN_10002c7e(void)

{
  FUN_1000e1a8(FUN_10002c90);
  return;
}



void FUN_10002c90(void)

{
  if ((DAT_10015080 & 1) == 0) {
    DAT_10015080 = DAT_10015080 | 1;
    FUN_100052a0((undefined4 *)&DAT_10015088);
  }
  return;
}



undefined4 * __fastcall FUN_10002cbc(undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  uint local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e5ea;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10006b70(param_1);
  local_8 = 0;
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)(param_1 + 2));
  local_8._0_1_ = 1;
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)(param_1 + 9));
  local_8._0_1_ = 2;
  FUN_10005310(param_1 + 0x22,0x54,8,FUN_10006c30);
  FUN_10005310(param_1 + 0xca,0x54,8,FUN_10006c30);
  FUN_10006c60(param_1 + 0x172);
  CString::CString((CString *)(param_1 + 0x1cf));
  local_8._0_1_ = 3;
  CString::CString((CString *)(param_1 + 0x1d0));
  local_8._0_1_ = 4;
  CString::CString((CString *)(param_1 + 0x1d3));
  local_8._0_1_ = 5;
  CString::CString((CString *)(param_1 + 0x1d4));
  local_8._0_1_ = 6;
  FUN_10005870(param_1 + 0x1d5);
  local_8._0_1_ = 7;
  FUN_10005870(param_1 + 0x1d6);
  local_8._0_1_ = 8;
  FUN_10006d10(param_1 + 0x1d7);
  local_8 = CONCAT31(local_8._1_3_,9);
  *param_1 = &PTR_FUN_10010254;
  memset(param_1 + 0x10,-1,8);
  for (local_14 = 0; local_14 < 8; local_14 = local_14 + 1) {
    for (local_18 = 0; local_18 < 8; local_18 = local_18 + 1) {
      *(undefined1 *)((int)param_1 + local_18 + local_14 * 8 + 0x48) = 1;
    }
  }
  memset(param_1 + 0x172,0,0x100);
  *(undefined1 *)(param_1 + 0x1b5) = 0;
  puVar2 = &DAT_10013150;
  puVar3 = param_1 + 0x1b6;
  for (iVar1 = 0x18; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined1 *)(param_1 + 0x1ce) = 0;
  *(undefined1 *)((int)param_1 + 0x739) = 0;
  CString::operator=((CString *)(param_1 + 0x1d0),s_INVALID_ITEM_100131b0);
  param_1[0x1d1] = 0;
  param_1[0x1d2] = 0;
  *(undefined1 *)(param_1 + 0x1b2) = 0;
  param_1[0x1b3] = 0;
  param_1[0x1b4] = 0;
  ExceptionList = local_10;
  return param_1;
}



void __fastcall FUN_10002edc(undefined4 *param_1)

{
  undefined4 *puVar1;
  undefined4 local_24 [5];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_1000e687;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_FUN_10010254;
  local_8 = 9;
  if (param_1[0x1d7] != 0) {
    FreeLibrary((HMODULE)param_1[0x1d7]);
    puVar1 = FUN_10006d10(local_24);
    local_8._0_1_ = 10;
    FUN_10005340(param_1 + 0x1d7,puVar1);
    local_8 = CONCAT31(local_8._1_3_,9);
    FUN_10007620((int)local_24);
  }
  local_8._0_1_ = 8;
  FUN_10007620((int)(param_1 + 0x1d7));
  local_8._0_1_ = 7;
  FUN_10007600(param_1 + 0x1d6);
  local_8._0_1_ = 6;
  FUN_10007600(param_1 + 0x1d5);
  local_8._0_1_ = 5;
  CString::~CString((CString *)(param_1 + 0x1d4));
  local_8._0_1_ = 4;
  CString::~CString((CString *)(param_1 + 0x1d3));
  local_8._0_1_ = 3;
  CString::~CString((CString *)(param_1 + 0x1d0));
  local_8._0_1_ = 2;
  CString::~CString((CString *)(param_1 + 0x1cf));
  local_8._0_1_ = 1;
  FUN_100052f0(param_1 + 9);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_100052f0(param_1 + 2);
  local_8 = 0xffffffff;
  FUN_10006ba0(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_10003012(undefined4 *param_1)

{
  int iVar1;
  CString *pCVar2;
  char *pcVar3;
  TILEBLITTER *pTVar4;
  uint uVar5;
  uint uVar6;
  int local_5c;
  int local_58;
  CString local_50 [8];
  CString local_48 [8];
  CString local_40 [4];
  undefined1 *local_3c;
  CString local_38 [4];
  undefined1 *local_34;
  TILEBLITTER *local_30;
  int local_2c;
  shared_ptr<> local_28 [4];
  TILEBLITTER *local_24;
  int local_20;
  shared_ptr<> local_1c [4];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e71c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10006c90(param_1);
  local_8 = 0;
  FUN_10005870(param_1 + 3);
  local_8._0_1_ = 1;
  param_1[4] = 0;
  FUN_10002ab0(param_1 + 0xc);
  FUN_10002bb0(param_1 + 0xd);
  FUN_10002b70(param_1 + 0xe);
  FUN_10001f90((CTypeLibCacheMap *)(param_1 + 0x13));
  local_8._0_1_ = 2;
  FUN_10001f90((CTypeLibCacheMap *)(param_1 + 0x1a));
  local_8._0_1_ = 3;
  *param_1 = &PTR_FUN_10010258;
  param_1[0x12] = 0;
  param_1[0x11] = 0;
  param_1[0x10] = 0;
  param_1[6] = 0;
  param_1[5] = 0x21;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  *(undefined1 *)(param_1 + 0xb) = 1;
  param_1[10] = 0;
  FUN_10002af0(param_1 + 0xc,0);
  if (DAT_100151dc != (int *)0x0) {
    iVar1 = FUN_10005970(0x10015088);
    if (iVar1 == 0) {
      local_24 = (TILEBLITTER *)operator_new(0x22f0);
      local_8._0_1_ = 4;
      if (local_24 == (TILEBLITTER *)0x0) {
        local_58 = 0;
      }
      else {
        local_58 = TILEBLITTER::TILEBLITTER(local_24);
      }
      local_20 = local_58;
      local_8._0_1_ = 3;
      FUN_100022b0(local_1c,local_58);
      local_8._0_1_ = 5;
      FUN_1000dcf0(&DAT_1001523c,local_1c);
      local_8._0_1_ = 3;
      FUN_10007600((int *)local_1c);
      local_30 = (TILEBLITTER *)operator_new(0x22f0);
      local_8._0_1_ = 6;
      if (local_30 == (TILEBLITTER *)0x0) {
        local_5c = 0;
      }
      else {
        local_5c = TILEBLITTER::TILEBLITTER(local_30);
      }
      local_2c = local_5c;
      local_8._0_1_ = 3;
      FUN_100022b0(local_28,local_5c);
      local_8._0_1_ = 7;
      FUN_1000dcf0(&DAT_10015238,local_28);
      local_8._0_1_ = 3;
      FUN_10007600((int *)local_28);
      local_34 = &stack0xffffff78;
      CString::CString((CString *)&stack0xffffff78,s_black_tiles_bmp_100131c0);
      pCVar2 = (CString *)(**(code **)(*DAT_100151dc + 0x54))();
      local_8._0_1_ = 8;
      FUN_100053f0(local_18,pCVar2);
      local_8._0_1_ = 10;
      CString::~CString(local_38);
      local_3c = &stack0xffffff70;
      CString::CString((CString *)&stack0xffffff70,s_black_tiles_small_bmp_100131d0);
      pCVar2 = (CString *)(**(code **)(*DAT_100151dc + 0x54))(local_40);
      local_8._0_1_ = 0xb;
      FUN_100053f0(local_14,pCVar2);
      local_8._0_1_ = 0xd;
      CString::~CString(local_40);
      uVar6 = 0x20;
      uVar5 = 0x20;
      pcVar3 = (char *)FUN_1000a7a0((undefined4 *)local_18);
      pTVar4 = (TILEBLITTER *)FUN_10002320((int *)&DAT_1001523c);
      TILEBLITTER::InitTileSurface(pTVar4,pcVar3,uVar5,uVar6);
      uVar6 = 8;
      uVar5 = 8;
      pcVar3 = (char *)FUN_1000a7a0((undefined4 *)local_14);
      pTVar4 = (TILEBLITTER *)FUN_10002320((int *)&DAT_10015238);
      TILEBLITTER::InitTileSurface(pTVar4,pcVar3,uVar5,uVar6);
      iVar1 = FUN_10002320((int *)&DAT_1001523c);
      pcVar3 = (char *)FUN_1000a7a0((undefined4 *)local_18);
      pCVar2 = (CString *)FUN_10006d50(local_48,pcVar3,iVar1);
      local_8._0_1_ = 0xe;
      FUN_100058c0(&DAT_10015088,pCVar2);
      local_8._0_1_ = 0xd;
      FUN_100020f0(local_48);
      iVar1 = FUN_10002320((int *)&DAT_10015238);
      pcVar3 = (char *)FUN_1000a7a0((undefined4 *)local_14);
      pCVar2 = (CString *)FUN_10006d50(local_50,pcVar3,iVar1);
      local_8._0_1_ = 0xf;
      FUN_100058c0(&DAT_10015088,pCVar2);
      local_8._0_1_ = 0xd;
      FUN_100020f0(local_50);
      local_8._0_1_ = 10;
      FUN_10002c40(local_14);
      local_8 = CONCAT31(local_8._1_3_,3);
      FUN_10002c40(local_18);
    }
  }
  ExceptionList = local_10;
  return param_1;
}



void * FUN_10003380(void *param_1,char *param_2,uint param_3,uint param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  CString *pCVar2;
  undefined4 *puVar3;
  uint uVar4;
  undefined3 extraout_var_00;
  char *pcVar5;
  TILEBLITTER *pTVar6;
  CString aCStack_64 [4];
  TILEBLITTER *local_60;
  CString *local_5c;
  CString *local_58;
  undefined4 local_54;
  uint local_4c;
  TILEBLITTER *local_48;
  TILEBLITTER *local_44;
  undefined4 local_40;
  undefined4 local_3c;
  CString local_38 [4];
  undefined1 *local_34;
  int local_30;
  TILEBLITTER *local_2c;
  CString local_28 [8];
  undefined4 local_20;
  undefined4 local_1c;
  CString local_18 [4];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e76c;
  local_10 = ExceptionList;
  local_4c = 0;
  local_34 = aCStack_64;
  ExceptionList = &local_10;
  local_54 = CString::CString(aCStack_64,param_2);
  local_5c = (CString *)(**(code **)(*DAT_100151dc + 0x54))(local_38);
  local_8 = 1;
  local_58 = local_5c;
  FUN_100053f0(local_18,local_5c);
  local_8._0_1_ = 3;
  CString::~CString(local_38);
  local_30 = FUN_100026f0(0x10015088);
  FUN_10002060((CString *)&local_20);
  local_8 = CONCAT31(local_8._1_3_,4);
  local_14 = 0;
  bVar1 = IsEmpty(0x10015088);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    pCVar2 = (CString *)FUN_10006070(&local_30);
    FUN_100021b0(&local_20,pCVar2);
  }
  local_14 = 0;
  while ((uVar4 = FUN_10005970(0x10015088), local_14 < uVar4 &&
         (bVar1 = IsEmpty(0x10015088), CONCAT31(extraout_var_00,bVar1) == 0))) {
    pcVar5 = (char *)FUN_1000a7a0((undefined4 *)local_18);
    bVar1 = STRING::equi((STRING *)&local_20,pcVar5);
    if (bVar1) {
      FUN_10005390(param_1,(CString *)&local_20);
      local_4c = local_4c | 1;
      local_8._0_1_ = 3;
      FUN_100020f0((CString *)&local_20);
      local_8 = (uint)local_8._1_3_ << 8;
      FUN_10002c40(local_18);
      ExceptionList = local_10;
      return param_1;
    }
    local_14 = local_14 + 1;
    uVar4 = FUN_10005970(0x10015088);
    if (local_14 < uVar4) {
      pCVar2 = (CString *)FUN_10006070(&local_30);
      puVar3 = (undefined4 *)FUN_100021b0(&local_20,pCVar2);
      local_40 = *puVar3;
      local_3c = puVar3[1];
    }
    else {
      local_40 = local_20;
      local_3c = local_1c;
    }
  }
  local_48 = (TILEBLITTER *)operator_new(0x22f0);
  local_8._0_1_ = 5;
  if (local_48 == (TILEBLITTER *)0x0) {
    local_60 = (TILEBLITTER *)0x0;
  }
  else {
    local_60 = (TILEBLITTER *)TILEBLITTER::TILEBLITTER(local_48);
  }
  local_44 = local_60;
  local_8._0_1_ = 4;
  local_2c = local_60;
  pcVar5 = (char *)FUN_1000a7a0((undefined4 *)local_18);
  TILEBLITTER::InitTileSurface(local_2c,pcVar5,param_3,param_4);
  pTVar6 = local_2c;
  pcVar5 = (char *)FUN_1000a7a0((undefined4 *)local_18);
  FUN_10006d50(local_28,pcVar5,(int)pTVar6);
  local_8._0_1_ = 6;
  FUN_100058c0(&DAT_10015088,local_28);
  FUN_10005390(param_1,local_28);
  local_4c = local_4c | 1;
  local_8._0_1_ = 4;
  FUN_100020f0(local_28);
  local_8._0_1_ = 3;
  FUN_100020f0((CString *)&local_20);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_10002c40(local_18);
  ExceptionList = local_10;
  return param_1;
}



void * __fastcall FUN_100035c7(int param_1)

{
  int iVar1;
  char *pcVar2;
  void *pvVar3;
  shared_ptr<> *psVar4;
  uint uVar5;
  uint uVar6;
  void *local_40;
  CString local_20 [8];
  CString local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e793;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  if (DAT_100151dc != 0) {
    ExceptionList = &local_10;
    iVar1 = FUN_1000a7a0((undefined4 *)(param_1 + 0xc));
    iVar1 = FUN_10002320((int *)(iVar1 + 0x754));
    if (iVar1 == 0) {
      uVar6 = 0x20;
      uVar5 = 0x20;
      iVar1 = FUN_1000a7a0((undefined4 *)(param_1 + 0xc));
      pcVar2 = (char *)FUN_1000a7a0((undefined4 *)(iVar1 + 0x74c));
      pvVar3 = FUN_10003380(local_18,pcVar2,uVar5,uVar6);
      local_8 = 0;
      psVar4 = (shared_ptr<> *)((int)pvVar3 + 4);
      iVar1 = FUN_1000a7a0((undefined4 *)(param_1 + 0xc));
      FUN_1000dcf0((void *)(iVar1 + 0x754),psVar4);
      local_8 = 0xffffffff;
      FUN_100020f0(local_18);
      uVar6 = 8;
      uVar5 = 8;
      iVar1 = FUN_1000a7a0((undefined4 *)(param_1 + 0xc));
      pcVar2 = (char *)FUN_1000a7a0((undefined4 *)(iVar1 + 0x750));
      pvVar3 = FUN_10003380(local_20,pcVar2,uVar5,uVar6);
      local_8 = 1;
      psVar4 = (shared_ptr<> *)((int)pvVar3 + 4);
      iVar1 = FUN_1000a7a0((undefined4 *)(param_1 + 0xc));
      FUN_1000dcf0((void *)(iVar1 + 0x758),psVar4);
      local_8 = 0xffffffff;
      FUN_100020f0(local_20);
    }
  }
  pvVar3 = operator_new(0x84);
  local_8 = 2;
  if (pvVar3 == (void *)0x0) {
    local_40 = (void *)0x0;
  }
  else {
    local_40 = FUN_10005410(pvVar3,param_1);
  }
  ExceptionList = local_10;
  return local_40;
}



CString * __thiscall FUN_10003733(void *this,CString *param_1)

{
  int iVar1;
  CString local_34 [4];
  CString local_30 [4];
  CString local_2c [4];
  CString local_28 [4];
  CString local_24 [4];
  CString local_20 [4];
  CString local_1c [4];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_1000e805;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(local_30,(char *)&this_100131e8);
  local_8 = 1;
  CString::CString(local_2c,(char *)&this_100131ec);
  local_8._0_1_ = 2;
  CString::CString(local_28,(char *)&this_100131f0);
  local_8._0_1_ = 3;
  CString::CString(local_24,(char *)&this_100131f4);
  local_8._0_1_ = 4;
  CString::CString(local_20,&DAT_100131f8);
  local_8._0_1_ = 5;
  CString::CString(local_1c,&DAT_100131fc);
  local_8._0_1_ = 6;
  CString::CString(local_18,&DAT_10013200);
  local_8._0_1_ = 7;
  CString::CString(local_14,&DAT_10013204);
  local_8._0_1_ = 8;
  CString::CString(local_34);
  local_8._0_1_ = 9;
  iVar1 = FUN_1000a7a0((undefined4 *)((int)this + 0x30));
  CString::operator=(local_34,local_30 + (iVar1 / 2) * 4);
  CString::CString(param_1,local_34);
  local_8._0_1_ = 8;
  CString::~CString(local_34);
  local_8._0_1_ = 7;
  CString::~CString(local_14);
  local_8._0_1_ = 6;
  CString::~CString(local_18);
  local_8._0_1_ = 5;
  CString::~CString(local_1c);
  local_8._0_1_ = 4;
  CString::~CString(local_20);
  local_8._0_1_ = 3;
  CString::~CString(local_24);
  local_8._0_1_ = 2;
  CString::~CString(local_28);
  local_8._0_1_ = 1;
  CString::~CString(local_2c);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(local_30);
  ExceptionList = local_10;
  return param_1;
}



CString * __thiscall FUN_100038a0(void *this,CString *param_1)

{
  undefined4 uVar1;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e82f;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(local_14);
  local_8 = 1;
  uVar1 = FUN_10002c10((undefined4 *)((int)this + 0x34));
  switch(uVar1) {
  case 0:
    CString::operator=(local_14,(char *)&this_10013208);
    break;
  case 1:
    CString::operator=(local_14,&DAT_10013214);
    break;
  case 2:
    CString::operator=(local_14,&DAT_10013210);
    break;
  case 3:
    CString::operator=(local_14,&DAT_10013218);
    break;
  case 4:
    CString::operator=(local_14,(char *)&this_1001320c);
    break;
  case 5:
    CString::operator=(local_14,&DAT_1001321c);
    break;
  case 6:
    CString::operator=(local_14,&DAT_10013220);
    break;
  case 7:
    CString::operator=(local_14,&DAT_10013224);
  }
  CString::CString(param_1,local_14);
  local_8 = local_8 & 0xffffff00;
  CString::~CString(local_14);
  ExceptionList = local_10;
  return param_1;
}



CString * FUN_100039c0(CString *param_1)

{
  int iVar1;
  int *in_ECX;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_1000e859;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(local_14);
  local_8 = 1;
  iVar1 = (**(code **)(*in_ECX + 0x34))();
  if (iVar1 != 0) {
    iVar1 = (**(code **)(*in_ECX + 0x38))();
    if (iVar1 != 0) {
      CString::operator=(local_14,(char *)&this_10013228);
      goto LAB_10003a6a;
    }
  }
  iVar1 = (**(code **)(*in_ECX + 0x34))();
  if (iVar1 == 0) {
    iVar1 = (**(code **)(*in_ECX + 0x38))();
    if (iVar1 == 0) {
      CString::operator=(local_14,&DAT_10013234);
    }
    else {
      CString::operator=(local_14,(char *)&this_10013230);
    }
  }
  else {
    CString::operator=(local_14,(char *)&this_1001322c);
  }
LAB_10003a6a:
  CString::CString(param_1,local_14);
  local_8 = local_8 & 0xffffff00;
  CString::~CString(local_14);
  ExceptionList = local_10;
  return param_1;
}



void __thiscall FUN_10003a9e(void *this,int param_1,undefined4 param_2,void *param_3)

{
  bool bVar1;
  char cVar2;
  int *piVar3;
  undefined4 *puVar4;
  void *pvVar5;
  undefined1 auStack_200 [4];
  undefined4 uStack_1fc;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  int iVar10;
  undefined1 local_1d8 [8];
  undefined1 local_1d0 [8];
  undefined1 *local_1c8;
  undefined1 local_1c4 [8];
  undefined1 local_1bc [8];
  int local_1b4;
  undefined1 *local_1b0;
  undefined1 local_1ac [8];
  undefined1 local_1a4 [8];
  undefined1 *local_19c;
  undefined1 local_198 [8];
  undefined1 local_190 [8];
  int local_188;
  undefined1 *local_184;
  undefined1 local_180 [8];
  undefined1 local_178 [8];
  undefined1 *local_170;
  undefined1 local_16c [8];
  undefined1 local_164 [8];
  int local_15c;
  undefined1 *local_158;
  undefined1 local_154 [8];
  undefined1 local_14c [8];
  undefined1 *local_144;
  undefined1 local_140 [8];
  undefined1 local_138 [8];
  int local_130;
  undefined1 *local_12c;
  undefined1 local_128 [4];
  undefined4 local_124;
  undefined1 local_120 [4];
  undefined1 local_11c [4];
  undefined4 local_118;
  undefined1 local_114 [4];
  undefined4 local_110 [7];
  undefined4 local_f4 [7];
  undefined4 local_d8 [7];
  undefined4 local_bc [7];
  undefined4 local_a0 [7];
  undefined4 local_84 [7];
  undefined4 local_68 [7];
  undefined4 local_4c [7];
  undefined4 local_30 [7];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e8c3;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_100067f0(&local_14,param_1,*(int *)((int)this + 0x30));
  FUN_10006940(local_30,local_14,param_2,*(undefined4 *)((int)this + 0x38),
               *(undefined4 *)((int)this + 0x3c));
  local_8 = 0;
  bVar1 = FUN_100067c0(&local_14);
  if (bVar1) {
    cVar2 = FUN_10006920((int *)&stack0x00000010);
    if (cVar2 != '\0') {
      iVar10 = *(int *)((int)this + 0x30);
      piVar3 = base(&stack0x00000010,&local_118);
      puVar4 = (undefined4 *)FUN_100067f0(local_11c,*piVar3,iVar10);
      puVar4 = (undefined4 *)FUN_10001cc0(local_114,*puVar4);
      FUN_10006b10(local_30,*puVar4);
    }
  }
  else {
    cVar2 = FUN_10006920((int *)&stack0x00000014);
    if (cVar2 != '\0') {
      iVar10 = *(int *)((int)this + 0x30);
      piVar3 = base(&stack0x00000014,&local_124);
      puVar4 = (undefined4 *)FUN_100067f0(local_128,*piVar3,iVar10);
      puVar4 = (undefined4 *)FUN_10001cc0(local_120,*puVar4);
      FUN_10006b10(local_30,*puVar4);
    }
  }
  FUN_10005990(param_3,(int)local_30);
  local_12c = auStack_200;
  FUN_10002790(auStack_200,(int)local_30);
  FUN_10008e7f((void *)((int)this + 0x4c));
  FUN_10002ad0(&local_130,2);
  piVar3 = &local_130;
  pvVar5 = (void *)FUN_10001d70((int)local_30);
  bVar1 = FUN_10006830(pvVar5,piVar3);
  if (bVar1) {
    piVar3 = (int *)default_error_condition(local_138,0,0xffffffff);
    puVar4 = (undefined4 *)FUN_10006850((void *)((int)this + 0x38),local_140,piVar3);
    uVar6 = puVar4[1];
    uVar9 = *puVar4;
    local_144 = &stack0xfffffe0c;
    uStack_1fc = 0x10003c62;
    uVar7 = param_2;
    uVar8 = uVar6;
    FUN_10002ad0(&stack0xfffffe0c,5);
    FUN_10006940(local_4c,uVar6,uVar7,uVar9,uVar8);
    local_8._0_1_ = 1;
    piVar3 = (int *)default_error_condition(local_14c,1,0);
    puVar4 = (undefined4 *)FUN_10006850((void *)((int)this + 0x38),local_154,piVar3);
    uVar6 = puVar4[1];
    uVar9 = *puVar4;
    local_158 = &stack0xfffffe0c;
    uStack_1fc = 0x10003cae;
    uVar7 = param_2;
    uVar8 = param_2;
    FUN_10002ad0(&stack0xfffffe0c,0xd);
    FUN_10006940(local_68,uVar7,uVar8,uVar9,uVar6);
    local_8._0_1_ = 2;
    FUN_10005990(param_3,(int)local_4c);
    FUN_10005990(param_3,(int)local_68);
    local_8._0_1_ = 1;
    FUN_10001ce0(local_68);
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_10001ce0(local_4c);
  }
  FUN_10002ad0(&local_15c,6);
  piVar3 = &local_15c;
  pvVar5 = (void *)FUN_10001d70((int)local_30);
  bVar1 = FUN_10006830(pvVar5,piVar3);
  if (bVar1) {
    piVar3 = (int *)default_error_condition(local_164,1,0);
    puVar4 = (undefined4 *)FUN_10006850((void *)((int)this + 0x38),local_16c,piVar3);
    uVar6 = puVar4[1];
    uVar9 = *puVar4;
    local_170 = &stack0xfffffe0c;
    uStack_1fc = 0x10003d5a;
    uVar7 = param_2;
    uVar8 = uVar6;
    FUN_10002ad0(&stack0xfffffe0c,9);
    FUN_10006940(local_84,uVar6,uVar7,uVar9,uVar8);
    local_8._0_1_ = 3;
    piVar3 = (int *)default_error_condition(local_178,0,1);
    puVar4 = (undefined4 *)FUN_10006850((void *)((int)this + 0x38),local_180,piVar3);
    uVar6 = puVar4[1];
    uVar9 = *puVar4;
    local_184 = &stack0xfffffe0c;
    uStack_1fc = 0x10003da6;
    uVar7 = param_2;
    uVar8 = param_2;
    FUN_10002ad0(&stack0xfffffe0c,1);
    FUN_10006940(local_a0,uVar7,uVar8,uVar9,uVar6);
    local_8._0_1_ = 4;
    FUN_10005990(param_3,(int)local_84);
    FUN_10005990(param_3,(int)local_a0);
    local_8._0_1_ = 3;
    FUN_10001ce0(local_a0);
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_10001ce0(local_84);
  }
  FUN_10002ad0(&local_188,10);
  piVar3 = &local_188;
  pvVar5 = (void *)FUN_10001d70((int)local_30);
  bVar1 = FUN_10006830(pvVar5,piVar3);
  if (bVar1) {
    piVar3 = (int *)default_error_condition(local_190,0xffffffff,0);
    puVar4 = (undefined4 *)FUN_10006850((void *)((int)this + 0x38),local_198,piVar3);
    uVar6 = puVar4[1];
    uVar9 = *puVar4;
    local_19c = &stack0xfffffe0c;
    uStack_1fc = 0x10003e5b;
    uVar7 = param_2;
    uVar8 = uVar6;
    FUN_10002ad0(&stack0xfffffe0c,5);
    FUN_10006940(local_bc,uVar6,uVar7,uVar9,uVar8);
    local_8._0_1_ = 5;
    piVar3 = (int *)default_error_condition(local_1a4,0,1);
    puVar4 = (undefined4 *)FUN_10006850((void *)((int)this + 0x38),local_1ac,piVar3);
    uVar6 = puVar4[1];
    uVar9 = *puVar4;
    local_1b0 = &stack0xfffffe0c;
    uStack_1fc = 0x10003eaa;
    uVar7 = param_2;
    uVar8 = param_2;
    FUN_10002ad0(&stack0xfffffe0c,0xd);
    FUN_10006940(local_d8,uVar7,uVar8,uVar9,uVar6);
    local_8._0_1_ = 6;
    FUN_10005990(param_3,(int)local_bc);
    FUN_10005990(param_3,(int)local_d8);
    local_8._0_1_ = 5;
    FUN_10001ce0(local_d8);
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_10001ce0(local_bc);
  }
  FUN_10002ad0(&local_1b4,0xe);
  piVar3 = &local_1b4;
  pvVar5 = (void *)FUN_10001d70((int)local_30);
  bVar1 = FUN_10006830(pvVar5,piVar3);
  if (bVar1) {
    piVar3 = (int *)default_error_condition(local_1bc,0,0xffffffff);
    puVar4 = (undefined4 *)FUN_10006850((void *)((int)this + 0x38),local_1c4,piVar3);
    uVar6 = puVar4[1];
    uVar9 = *puVar4;
    local_1c8 = &stack0xfffffe0c;
    uStack_1fc = 0x10003f65;
    uVar7 = param_2;
    uVar8 = uVar6;
    FUN_10002ad0(&stack0xfffffe0c,9);
    FUN_10006940(local_f4,uVar6,uVar7,uVar9,uVar8);
    local_8._0_1_ = 7;
    piVar3 = (int *)default_error_condition(local_1d0,0xffffffff,0);
    puVar4 = (undefined4 *)FUN_10006850((void *)((int)this + 0x38),local_1d8,piVar3);
    uVar6 = puVar4[1];
    uVar9 = *puVar4;
    uStack_1fc = 0x10003fb4;
    uVar7 = param_2;
    FUN_10002ad0(&stack0xfffffe0c,1);
    FUN_10006940(local_110,param_2,uVar7,uVar9,uVar6);
    local_8._0_1_ = 8;
    FUN_10005990(param_3,(int)local_f4);
    FUN_10005990(param_3,(int)local_110);
    local_8._0_1_ = 7;
    FUN_10001ce0(local_110);
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_10001ce0(local_f4);
  }
  local_8 = 0xffffffff;
  FUN_10001ce0(local_30);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_1000401e(void *this,uint param_1,undefined4 *param_2)

{
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  
  iVar1 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
  uVar2 = FUN_10005970(iVar1 + 0x24);
  if (uVar2 < param_1 + 1) {
    puVar3 = &DAT_10013090;
    for (iVar1 = 0x18; iVar1 != 0; iVar1 = iVar1 + -1) {
      *param_2 = *puVar3;
      puVar3 = puVar3 + 1;
      param_2 = param_2 + 1;
    }
  }
  else {
    iVar1 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
    puVar3 = (undefined4 *)FUN_100057c0((void *)(iVar1 + 0x24),param_1);
    for (iVar1 = 0x18; iVar1 != 0; iVar1 = iVar1 + -1) {
      *param_2 = *puVar3;
      puVar3 = puVar3 + 1;
      param_2 = param_2 + 1;
    }
  }
  return;
}



void __thiscall FUN_10004084(void *this,int param_1,void *param_2)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  undefined3 extraout_var;
  undefined4 *puVar4;
  int iVar5;
  void *pvVar6;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  uint uVar7;
  undefined4 *puVar8;
  int *piVar9;
  undefined4 local_198 [24];
  undefined1 local_138 [4];
  uint local_134;
  int local_130;
  undefined4 local_12c [24];
  uint local_cc;
  undefined4 local_c8 [24];
  undefined4 local_68 [24];
  uint local_8;
  
  iVar3 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
  bVar2 = IsEmpty(iVar3 + 8);
  if (CONCAT31(extraout_var,bVar2) == 0) {
    iVar3 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
                    // WARNING: Load size is inaccurate
    puVar4 = (undefined4 *)(**(code **)(*this + 0x7c))(local_138);
    iVar5 = FUN_10002c10(puVar4);
    cVar1 = *(char *)(iVar3 + 0x40 + iVar5);
    local_8 = CONCAT31(local_8._1_3_,cVar1);
    if (cVar1 == -1) {
      local_cc = 0;
      iVar3 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
      local_130 = FUN_100026f0(iVar3 + 8);
      puVar4 = local_198;
      puVar8 = local_12c;
      for (iVar3 = 0x18; iVar3 != 0; iVar3 = iVar3 + -1) {
        *puVar8 = *puVar4;
        puVar4 = puVar4 + 1;
        puVar8 = puVar8 + 1;
      }
      local_134 = 0;
      iVar3 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
      bVar2 = IsEmpty(iVar3 + 8);
      if (CONCAT31(extraout_var_00,bVar2) == 0) {
        piVar9 = &local_130;
        FUN_1000a7a0((undefined4 *)((int)this + 0xc));
        puVar4 = (undefined4 *)FUN_10006070(piVar9);
        puVar8 = local_12c;
        for (iVar3 = 0x18; iVar3 != 0; iVar3 = iVar3 + -1) {
          *puVar8 = *puVar4;
          puVar4 = puVar4 + 1;
          puVar8 = puVar8 + 1;
        }
      }
      local_134 = 0;
      while( true ) {
        iVar3 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
        uVar7 = FUN_10005970(iVar3 + 8);
        if (uVar7 <= local_134) break;
        iVar3 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
        bVar2 = IsEmpty(iVar3 + 8);
        if (CONCAT31(extraout_var_01,bVar2) != 0) {
          return;
        }
        FUN_1000401e(this,local_cc,local_c8);
        FUN_100043a3(this,param_1,(int)local_12c,(int)local_c8,param_2);
        local_cc = local_cc + 1;
        local_134 = local_134 + 1;
        iVar3 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
        uVar7 = FUN_10005970(iVar3 + 8);
        if (local_134 < uVar7) {
          piVar9 = &local_130;
          FUN_1000a7a0((undefined4 *)((int)this + 0xc));
          puVar4 = (undefined4 *)FUN_10006070(piVar9);
          puVar8 = local_12c;
          for (iVar3 = 0x18; iVar3 != 0; iVar3 = iVar3 + -1) {
            *puVar8 = *puVar4;
            puVar4 = puVar4 + 1;
            puVar8 = puVar8 + 1;
          }
        }
      }
    }
    else {
      FUN_1000401e(this,0,local_68);
      puVar4 = local_68;
      uVar7 = local_8 & 0xff;
      iVar3 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
      pvVar6 = FUN_100057c0((void *)(iVar3 + 8),uVar7);
      FUN_100043a3(this,param_1,(int)pvVar6,(int)puVar4,param_2);
    }
  }
  else {
    FUN_100043a3(this,param_1,0x10013030,0x100130f0,param_2);
  }
  return;
}



void * __thiscall FUN_1000430e(void *this,void *param_1,undefined4 *param_2,undefined4 *param_3)

{
  int iVar1;
  int iVar2;
  undefined4 local_c;
  
  iVar1 = FUN_1000a7a0(param_2);
  iVar1 = iVar1 >> 1;
  iVar2 = FUN_10002c10(param_3);
  if (iVar2 == 4) {
    iVar2 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
    local_c = *(undefined4 *)(iVar2 + 0x6d8 + iVar1 * 4);
  }
  else if (iVar2 == 2) {
    iVar2 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
    local_c = *(undefined4 *)(iVar2 + 0x6f8 + iVar1 * 4);
  }
  else {
    iVar2 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
    local_c = *(undefined4 *)(iVar2 + 0x718 + iVar1 * 4);
  }
  FUN_10002bd0(param_1,local_c);
  return param_1;
}



void __thiscall FUN_100043a3(void *this,int param_1,int param_2,int param_3,void *param_4)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  uint *puVar4;
  int *piVar5;
  undefined4 *puVar6;
  void *pvVar7;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  int extraout_ECX_03;
  int extraout_ECX_04;
  int extraout_ECX_05;
  int extraout_ECX_06;
  int extraout_ECX_07;
  int extraout_ECX_08;
  int extraout_ECX_09;
  undefined4 uStack_cc;
  undefined4 uVar8;
  char *pcVar9;
  undefined1 *puVar10;
  undefined1 local_a0 [4];
  undefined4 local_9c;
  undefined1 local_98 [4];
  undefined1 local_94 [4];
  undefined1 *local_90;
  undefined4 local_8c;
  undefined1 local_88 [4];
  undefined1 *local_84;
  undefined4 local_80;
  undefined1 local_7c [4];
  undefined4 local_78;
  undefined1 local_74 [4];
  undefined1 local_70 [4];
  undefined1 *local_6c;
  undefined4 local_68;
  undefined1 local_64 [4];
  undefined1 *local_60;
  undefined4 local_5c;
  undefined1 local_58 [4];
  undefined1 *local_54;
  undefined4 local_50;
  undefined1 local_4c [4];
  undefined1 *local_48;
  undefined4 local_44;
  int local_40;
  undefined4 local_3c;
  undefined1 *local_38;
  undefined1 local_34 [4];
  undefined4 local_30;
  undefined1 *local_2c;
  undefined1 local_28 [4];
  undefined1 *local_24;
  undefined1 local_20 [4];
  undefined1 *local_1c;
  undefined1 local_18 [4];
  undefined1 *local_14;
  int local_10;
  int local_c;
  int local_8;
  
  pcVar9 = s_BRICK_10013238;
  iVar3 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
  bVar1 = FUN_10005600((void *)(iVar3 + 0x740),pcVar9);
  if (bVar1) {
    puVar4 = (uint *)FUN_10001d70(param_1);
    bVar1 = FUN_10002b40(puVar4);
    if (bVar1) {
      return;
    }
  }
  puVar4 = (uint *)FUN_10001d70(param_1);
  bVar1 = FUN_10002b40(puVar4);
  if (bVar1) {
    piVar5 = (int *)FUN_10001d70(param_1);
    FUN_10007260(this,&local_10,*piVar5);
    local_c = -1;
    local_14 = &stack0xffffff4c;
    uVar8 = extraout_ECX;
    FUN_10002ad0(&stack0xffffff4c,0xfffffc00);
    FUN_10001cc0(&local_8,uVar8);
    puVar6 = (undefined4 *)FUN_10001f70(param_1);
    iVar3 = FUN_10002c10(puVar6);
    if (iVar3 == 1) {
      iVar3 = FUN_1000a7a0(&local_10);
      local_c = *(int *)(param_2 + 0x40 + (iVar3 >> 1) * 4);
      iVar3 = FUN_1000a7a0(&local_10);
      local_2c = &stack0xffffff4c;
      uVar8 = extraout_ECX_02;
      FUN_10002ad0(&stack0xffffff4c,*(uint *)(param_3 + 0x40 + (iVar3 >> 1) * 4));
      piVar5 = (int *)FUN_10001cc0(local_28,uVar8);
      local_8 = *piVar5;
    }
    else if (iVar3 == 2) {
      iVar3 = FUN_1000a7a0(&local_10);
      local_c = *(int *)(param_2 + 0x20 + (iVar3 >> 1) * 4);
      iVar3 = FUN_1000a7a0(&local_10);
      local_24 = &stack0xffffff4c;
      uVar8 = extraout_ECX_01;
      FUN_10002ad0(&stack0xffffff4c,*(uint *)(param_3 + 0x20 + (iVar3 >> 1) * 4));
      piVar5 = (int *)FUN_10001cc0(local_20,uVar8);
      local_8 = *piVar5;
    }
    else if (iVar3 == 4) {
      iVar3 = FUN_1000a7a0(&local_10);
      local_c = *(int *)(param_2 + (iVar3 >> 1) * 4);
      iVar3 = FUN_1000a7a0(&local_10);
      local_1c = &stack0xffffff4c;
      uVar8 = extraout_ECX_00;
      FUN_10002ad0(&stack0xffffff4c,*(uint *)(param_3 + (iVar3 >> 1) * 4));
      piVar5 = (int *)FUN_10001cc0(local_18,uVar8);
      local_8 = *piVar5;
    }
    if (local_c != -1) {
      FUN_10002ad0(&local_30,local_c << 1);
      puVar6 = (undefined4 *)FUN_10001f70(param_1);
      uStack_cc = 0x1000457c;
      puVar6 = (undefined4 *)FUN_1000430e(this,local_34,&local_30,puVar6);
      uVar8 = *puVar6;
      local_38 = &stack0xffffff3c;
      uStack_cc = 0x10004590;
      iVar3 = extraout_ECX_03;
      FUN_10002ad0(&stack0xffffff3c,local_c << 1);
      FUN_10003a9e(this,iVar3,uVar8,param_4);
    }
    cVar2 = FUN_10006920(&local_8);
    if (cVar2 != '\0') {
      local_40 = local_10;
      piVar5 = &local_40;
      puVar6 = base(&local_8,&local_3c);
      bVar1 = FUN_10006830(puVar6,piVar5);
      if (!bVar1) {
        local_48 = &stack0xffffff4c;
        iVar3 = extraout_ECX_04;
        FUN_10002ad0(&stack0xffffff4c,2);
        piVar5 = (int *)FUN_100067f0(local_4c,local_10,iVar3);
        puVar6 = base(&local_8,&local_44);
        bVar1 = FUN_10006830(puVar6,piVar5);
        if (!bVar1) {
          local_54 = &stack0xffffff4c;
          iVar3 = extraout_ECX_05;
          FUN_10002ad0(&stack0xffffff4c,1);
          piVar5 = (int *)FUN_100067f0(local_58,local_10,iVar3);
          puVar6 = base(&local_8,&local_50);
          bVar1 = FUN_10006830(puVar6,piVar5);
          if (!bVar1) {
            local_60 = &stack0xffffff4c;
            iVar3 = extraout_ECX_06;
            FUN_10002ad0(&stack0xffffff4c,1);
            piVar5 = (int *)FUN_10006810(local_64,local_10,iVar3);
            puVar6 = base(&local_8,&local_5c);
            bVar1 = FUN_10006830(puVar6,piVar5);
            if (!bVar1) {
              local_6c = &stack0xffffff4c;
              iVar3 = extraout_ECX_07;
              FUN_10002ad0(&stack0xffffff4c,2);
              piVar5 = (int *)FUN_10006810(local_70,local_10,iVar3);
              puVar6 = base(&local_8,&local_68);
              bVar1 = FUN_10006830(puVar6,piVar5);
              if (!bVar1) {
                local_84 = &stack0xffffff4c;
                iVar3 = extraout_ECX_08;
                FUN_10002ad0(&stack0xffffff4c,4);
                piVar5 = (int *)FUN_10006810(local_88,local_10,iVar3);
                puVar6 = base(&local_8,&local_80);
                bVar1 = FUN_10006830(puVar6,piVar5);
                if (!bVar1) {
                  local_90 = &stack0xffffff4c;
                  iVar3 = extraout_ECX_09;
                  FUN_10002ad0(&stack0xffffff4c,4);
                  piVar5 = (int *)FUN_100067f0(local_94,local_10,iVar3);
                  puVar6 = base(&local_8,&local_8c);
                  bVar1 = FUN_10006830(puVar6,piVar5);
                  if (!bVar1) {
                    iVar3 = *(int *)((int)this + 0x30);
                    piVar5 = base(&local_8,&local_9c);
                    puVar6 = (undefined4 *)FUN_100067f0(local_a0,*piVar5,iVar3);
                    uVar8 = *puVar6;
                    pvVar7 = (void *)FUN_10006af0(param_1);
                    FUN_10006900(pvVar7,uVar8);
                    goto LAB_100047f5;
                  }
                }
                puVar10 = local_98;
                pvVar7 = (void *)FUN_10001d70(param_1);
                puVar6 = (undefined4 *)FUN_10006790(pvVar7,puVar10);
                uVar8 = *puVar6;
                pvVar7 = (void *)FUN_10006af0(param_1);
                FUN_10006900(pvVar7,uVar8);
                goto LAB_100047f5;
              }
            }
          }
        }
      }
      piVar5 = (int *)FUN_10006790((void *)((int)this + 0x30),local_74);
      iVar3 = *piVar5;
      piVar5 = base(&local_8,&local_78);
      puVar6 = (undefined4 *)FUN_100067f0(local_7c,*piVar5,iVar3);
      uVar8 = *puVar6;
      pvVar7 = (void *)FUN_10006af0(param_1);
      FUN_10006900(pvVar7,uVar8);
    }
  }
LAB_100047f5:
  FUN_10002790(&uStack_cc,param_1);
  FUN_10008e7f((void *)((int)this + 0x4c));
  return;
}



undefined4 __fastcall FUN_10004823(int param_1)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  void *this;
  int local_c;
  int local_8;
  
  iVar2 = FUN_10005970(param_1 + 0x4c);
  iVar3 = FUN_10005970(param_1 + 0x68);
  if (iVar2 == iVar3) {
    local_c = FUN_100026f0(param_1 + 0x4c);
    local_8 = FUN_100026f0(param_1 + 0x68);
    do {
      if (local_c == 0) {
        return 0;
      }
      this = (void *)FUN_10006070(&local_c);
      iVar2 = FUN_10006070(&local_8);
      bVar1 = FUN_100069d0(this,iVar2);
    } while (!bVar1);
  }
  return 1;
}



void __thiscall FUN_100048bb(void *this,TILEBLITTER *param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  
  if ((*(uint *)((int)this + 0x14) < (uint)(DAT_100151e4 - *(int *)((int)this + 0x18))) &&
     ((*(int *)((int)this + 0x20) != 0 || (*(int *)((int)this + 0x1c) != 0)))) {
    *(int *)((int)this + 0x1c) = *(int *)((int)this + 0x1c) + 1;
    uVar5 = *(undefined4 *)((int)this + 0x1c);
    uVar1 = FUN_1000a7a0((undefined4 *)((int)this + 0x30));
    uVar2 = FUN_10002c10((undefined4 *)((int)this + 0x34));
                    // WARNING: Load size is inaccurate
    iVar3 = (**(code **)(*this + 0x6c))(uVar2,uVar1,uVar5);
    if (iVar3 == -1) {
      iVar3 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
      if (*(int *)(iVar3 + 0x748) == 1) {
        *(undefined4 *)((int)this + 0x1c) = 0;
      }
      else {
        *(int *)((int)this + 0x1c) = *(int *)((int)this + 0x1c) + -1;
      }
    }
    *(int *)((int)this + 0x18) = DAT_100151e4;
  }
  if (param_1 != (TILEBLITTER *)0x0) {
    uVar5 = *(undefined4 *)((int)this + 0x1c);
    uVar1 = FUN_1000a7a0((undefined4 *)((int)this + 0x30));
    uVar2 = FUN_10002c10((undefined4 *)((int)this + 0x34));
                    // WARNING: Load size is inaccurate
    uVar4 = (**(code **)(*this + 0x6c))(uVar2,uVar1,uVar5);
    FUN_10004a88(this,param_1,uVar4);
  }
  return;
}



void __thiscall FUN_100049a8(void *this,TILEBLITTER *param_1)

{
  bool bVar1;
  int iVar2;
  undefined3 extraout_var;
  
  iVar2 = FUN_10004823((int)this);
  if ((((iVar2 == 0) && (*(char *)((int)this + 0x2c) == '\0')) && (*(int *)((int)this + 0x20) == 0))
     && (*(int *)((int)this + 0x1c) == 0)) {
    bVar1 = IsEmpty((int)this + 0x4c);
    if (CONCAT31(extraout_var,bVar1) != 0) goto LAB_100049f2;
  }
  *(undefined4 *)((int)this + 0x48) = 2;
LAB_100049f2:
  if (*(int *)((int)this + 0x48) != 0) {
    *(int *)((int)this + 0x48) = *(int *)((int)this + 0x48) + -1;
    FUN_100048bb(this,param_1);
  }
  iVar2 = FUN_10004823((int)this);
  if (iVar2 != 0) {
    FUN_100055c0((void *)((int)this + 0x68),(void *)((int)this + 0x4c));
  }
  *(undefined1 *)((int)this + 0x2c) = 0;
  return;
}



void __thiscall FUN_10004a41(void *this,TILEBLITTER *param_1)

{
  FUN_100048bb(this,param_1);
  *(undefined4 *)((int)this + 0x48) = 2;
  FUN_10002530((int)this + 0x68);
  FUN_100059f0((void *)((int)this + 0x68),(int)this + 0x4c);
  *(undefined1 *)((int)this + 0x2c) = 0;
  return;
}



void __thiscall FUN_10004a88(void *this,TILEBLITTER *param_1,uint param_2)

{
  uint uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  int local_34;
  undefined4 local_30 [7];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e8d6;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  uVar1 = FUN_10006c10((int)param_1);
  if (uVar1 <= param_2) {
    param_2 = 1;
  }
  local_14 = FUN_10005970((int)this + 0x4c);
  *(uint *)((int)this + 0x24) = param_2;
  if (local_14 == 0) {
    TILEBLITTER::AddTileToScreen
              (param_1,param_2,*(undefined4 *)((int)this + 0x38),*(undefined4 *)((int)this + 0x3c));
  }
  else {
    FUN_10001c50(local_30);
    local_8 = 0;
    local_34 = FUN_100026f0((int)this + 0x4c);
    FUN_10004d11();
    for (; 1 < local_14; local_14 = local_14 - 1) {
      iVar2 = FUN_10006070(&local_34);
      FUN_10001fb0(local_30,iVar2);
      uVar1 = FUN_10004d42(local_30);
      if ((uVar1 & 0xff) == 0) {
        puVar3 = (undefined4 *)FUN_10006b30((int)local_30);
        uVar7 = *puVar3;
        puVar3 = (undefined4 *)FUN_10006af0((int)local_30);
        uVar6 = *puVar3;
        puVar3 = (undefined4 *)FUN_10001f70((int)local_30);
        uVar5 = *puVar3;
        puVar3 = (undefined4 *)FUN_10001d70((int)local_30);
        uVar4 = *puVar3;
        iVar2 = FUN_10006c10((int)param_1);
        TILEBLITTER::AddLaserToTile(param_1,param_2,iVar2 + -1,uVar4,uVar5,uVar6,uVar7);
        iVar2 = FUN_10006c10((int)param_1);
        param_2 = iVar2 - 1;
        FUN_10004c69((int)local_30);
      }
    }
    iVar2 = FUN_10006070(&local_34);
    FUN_10001fb0(local_30,iVar2);
    uVar1 = FUN_10004d42(local_30);
    if ((uVar1 & 0xff) == 0) {
      puVar3 = (undefined4 *)FUN_10006b30((int)local_30);
      uVar7 = *puVar3;
      puVar3 = (undefined4 *)FUN_10006af0((int)local_30);
      uVar6 = *puVar3;
      puVar3 = (undefined4 *)FUN_10001f70((int)local_30);
      uVar5 = *puVar3;
      puVar3 = (undefined4 *)FUN_10001d70((int)local_30);
      uVar4 = *puVar3;
      puVar3 = (undefined4 *)FUN_10001d50((int)local_30);
      TILEBLITTER::AddLaserToScreen(param_1,param_2,*puVar3,puVar3[1],uVar4,uVar5,uVar6,uVar7);
    }
    else {
      TILEBLITTER::AddTileToScreen
                (param_1,param_2,*(undefined4 *)((int)this + 0x38),*(undefined4 *)((int)this + 0x3c)
                );
    }
    local_8 = 0xffffffff;
    FUN_10001ce0(local_30);
  }
  ExceptionList = local_10;
  return;
}



void __cdecl FUN_10004c69(int param_1)

{
  bool bVar1;
  void *pvVar2;
  int *piVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  undefined4 local_18;
  undefined4 local_14;
  int local_10;
  int local_c;
  byte local_8;
  
  DAT_100151b4 = 1;
  local_10 = 10000;
  puVar4 = &local_14;
  pvVar2 = (void *)FUN_10006af0(param_1);
  piVar3 = base(pvVar2,puVar4);
  bVar1 = FUN_10006770(piVar3);
  if (bVar1) {
    puVar4 = &local_18;
    pvVar2 = (void *)FUN_10006af0(param_1);
    puVar4 = base(pvVar2,puVar4);
    local_10 = FUN_1000a7a0(puVar4);
  }
  else {
    local_10 = 0x10;
  }
  puVar4 = (undefined4 *)FUN_10001d70(param_1);
  local_c = FUN_1000a7a0(puVar4);
  puVar4 = (undefined4 *)FUN_10001f70(param_1);
  uVar5 = FUN_10002c10(puVar4);
  local_8 = (byte)uVar5;
  *(byte *)((int)&_Dst_100150a4 + local_10 + local_c * 0x11) =
       *(byte *)((int)&_Dst_100150a4 + local_10 + local_c * 0x11) | local_8;
  return;
}



void FUN_10004d11(void)

{
  bool bVar1;
  
  bVar1 = FUN_10002730(&DAT_100151b4,'\0');
  if (bVar1) {
    memset(&_Dst_100150a4,0,0x110);
  }
  return;
}



uint __cdecl FUN_10004d42(void *param_1)

{
  bool bVar1;
  undefined4 *puVar2;
  uint uVar3;
  int iVar4;
  void *pvVar5;
  void *pvVar6;
  uint local_28;
  undefined1 local_1c [4];
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  puVar2 = (undefined4 *)FUN_10001f70((int)param_1);
  uVar3 = FUN_10002c10(puVar2);
  local_8 = 0;
  local_c = uVar3;
  do {
    if (0x10 < local_8) {
      return uVar3 & 0xffffff00;
    }
    puVar2 = (undefined4 *)FUN_10001d70((int)param_1);
    iVar4 = FUN_1000a7a0(puVar2);
    if (*(char *)((int)&_Dst_100150a4 + local_8 + iVar4 * 0x11) != '\0') {
      if (local_8 < 0x10) {
        local_28 = local_8;
      }
      else {
        local_28 = 0xfffffc00;
      }
      local_10 = local_28;
      FUN_10002ad0(&stack0xffffffd4,local_28);
      pvVar5 = FUN_10001cc0(local_1c,local_28);
      pvVar6 = (void *)FUN_10006af0((int)param_1);
      bVar1 = FUN_10004e4c(pvVar6,pvVar5);
      if (bVar1) {
        puVar2 = (undefined4 *)FUN_10001d70((int)param_1);
        iVar4 = FUN_1000a7a0(puVar2);
        local_14 = (uint)*(byte *)((int)&_Dst_100150a4 + local_8 + iVar4 * 0x11);
        if ((local_c & local_14) == 0) {
          return 0;
        }
        uVar3 = ~local_14;
        local_18 = local_c & uVar3;
        FUN_10002bd0(&stack0xffffffd4,local_18);
        FUN_10006b50(param_1,uVar3);
        return (uint)(local_18 == 0);
      }
    }
    uVar3 = local_8 + 1;
    local_8 = uVar3;
  } while( true );
}



bool __cdecl FUN_10004e4c(void *param_1,void *param_2)

{
  bool bVar1;
  int *piVar2;
  int iVar3;
  undefined1 local_20 [4];
  int local_1c;
  int local_18;
  undefined4 local_14;
  undefined4 local_10;
  uint local_c;
  uint local_8;
  
  base(param_1,&local_10);
  base(param_2,&local_14);
  piVar2 = (int *)FUN_10006790(&local_14,local_20);
  bVar1 = FUN_10006830(&local_10,piVar2);
  if (bVar1) {
    bVar1 = false;
  }
  else {
    local_18 = FUN_1000a7a0(&local_10);
    local_1c = FUN_1000a7a0(&local_14);
    if ((local_18 == -0x400) || (local_1c == -0x400)) {
      bVar1 = true;
    }
    else {
      local_8 = (local_18 - local_1c) + 0x10U & 0x8000000f;
      if ((int)local_8 < 0) {
        local_8 = (local_8 - 1 | 0xfffffff0) + 1;
      }
      local_c = (local_1c - local_18) + 0x10U & 0x8000000f;
      if ((int)local_c < 0) {
        local_c = (local_c - 1 | 0xfffffff0) + 1;
      }
      iVar3 = FUN_10005fb0(local_8,local_c);
      bVar1 = iVar3 < 5;
    }
  }
  return bVar1;
}



undefined4 __fastcall FUN_10004f07(int *param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  int iVar4;
  int local_14;
  undefined1 local_10 [4];
  int local_c;
  uint local_8;
  
  iVar1 = FUN_1000a7a0(param_1 + 3);
  if (*(char *)(iVar1 + 0x738) == '\0') {
    uVar2 = 1;
  }
  else {
    for (local_8 = 0; local_8 < 8; local_8 = local_8 + 1) {
      iVar1 = FUN_1000a7a0(param_1 + 3);
      puVar3 = (undefined4 *)(**(code **)(*param_1 + 0x7c))(local_10);
      iVar4 = FUN_10002c10(puVar3);
      local_c = (int)*(char *)(local_8 + iVar1 + 0x48 + iVar4 * 8);
      if (local_c == 1) {
        FUN_10002bd0(&local_14,local_8);
        iVar1 = FUN_10008cb7(param_1 + 0x13,&local_14);
        if (iVar1 != 0) {
          (**(code **)(*param_1 + 0xc))();
          return 1;
        }
      }
    }
    (**(code **)(*param_1 + 0x10))();
    uVar2 = 0;
  }
  return uVar2;
}



undefined4 __fastcall FUN_10004fc5(int *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  int local_14;
  undefined1 local_10 [4];
  int local_c;
  uint local_8;
  
  iVar1 = FUN_1000a7a0(param_1 + 3);
  if (*(char *)(iVar1 + 0x739) != '\0') {
    for (local_8 = 0; local_8 < 8; local_8 = local_8 + 1) {
      iVar1 = FUN_1000a7a0(param_1 + 3);
      puVar2 = (undefined4 *)(**(code **)(*param_1 + 0x7c))(local_10);
      iVar3 = FUN_10002c10(puVar2);
      local_c = (int)*(char *)(local_8 + iVar1 + 0x48 + iVar3 * 8);
      if (local_c == -1) {
        FUN_10002bd0(&local_14,local_8);
        iVar1 = FUN_10008bed(param_1 + 0x13,&local_14);
        if (iVar1 != 0) {
          return 1;
        }
      }
    }
  }
  return 0;
}



// WARNING: Variable defined which should be unmapped: param_1

CTypeLibCacheMap * __cdecl FUN_10005067(CTypeLibCacheMap *param_1,char *param_2)

{
  char *pcVar1;
  undefined4 *puVar2;
  int iVar3;
  BOOL BVar4;
  LPWIN32_FIND_DATAA p_Var5;
  char *pcVar6;
  HANDLE hFindFile;
  LPWIN32_FIND_DATAA in_stack_ffffff70;
  int *local_6c;
  CString local_68 [4];
  CString local_64 [4];
  CString local_60 [4];
  CString local_5c [4];
  uint local_58;
  CString local_54 [4];
  int *local_50;
  uint local_4c;
  CTypeLibCacheMap local_48 [28];
  CFileFind local_2c [28];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_1000e936;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CFileFind::CFileFind(local_2c);
  local_8 = 1;
  hFindFile = (HANDLE)0x0;
  pcVar6 = s___PCE_10013240;
  pcVar1 = (char *)CString::CString(local_5c,param_2);
  local_8._0_1_ = 2;
  puVar2 = (undefined4 *)operator+(local_60,pcVar1);
  local_8._0_1_ = 3;
  pcVar1 = (char *)FUN_1000a7a0(puVar2);
  iVar3 = CFileFind::FindFile(local_2c,pcVar1,(ulong)pcVar6);
  local_58 = CONCAT31(local_58._1_3_,'\x01' - (iVar3 != 0));
  local_8._0_1_ = 2;
  CString::~CString(local_60);
  local_8._0_1_ = 1;
  CString::~CString(local_5c);
  if ((local_58 & 0xff) == 0) {
    CTypeLibCacheMap::CTypeLibCacheMap(local_48);
    local_8._0_1_ = 4;
    local_4c = CONCAT31(local_4c._1_3_,1);
    while ((local_4c & 0xff) != 0) {
      BVar4 = CFileFind::FindNextFileA(hFindFile,in_stack_ffffff70);
      local_4c = CONCAT31(local_4c._1_3_,BVar4 != 0);
      iVar3 = FUN_100055e0((int *)local_2c);
      if (iVar3 == 0) {
        puVar2 = (undefined4 *)CFileFind::GetFilePath(local_2c);
        local_8._0_1_ = 5;
        pcVar1 = (char *)FUN_1000a7a0(puVar2);
        local_50 = FUN_1000c78c(pcVar1);
        local_8._0_1_ = 4;
        CString::~CString(local_64);
        CFileFind::GetFileName(local_2c);
        local_8._0_1_ = 6;
        CString::MakeUpper(local_54);
        p_Var5 = (LPWIN32_FIND_DATAA)CString::SpanExcluding(local_54,(char *)local_68);
        local_8._0_1_ = 7;
        in_stack_ffffff70 = p_Var5;
        iVar3 = FUN_1000a7a0(local_50 + 3);
        CString::operator=((CString *)(iVar3 + 0x740),(CString *)p_Var5);
        local_8._0_1_ = 6;
        CString::~CString(local_68);
        local_6c = local_50;
        FUN_10005ad0(local_48,&local_6c);
        local_8._0_1_ = 4;
        CString::~CString(local_54);
      }
    }
    FUN_10005730(param_1,(int)local_48);
    local_8._0_1_ = 1;
    FUN_10005640((undefined4 *)local_48);
    local_8 = (uint)local_8._1_3_ << 8;
    CFileFind::~CFileFind(local_2c);
  }
  else {
    CTypeLibCacheMap::CTypeLibCacheMap(param_1);
    local_8 = (uint)local_8._1_3_ << 8;
    CFileFind::~CFileFind(local_2c);
  }
  ExceptionList = local_10;
  return param_1;
}



void __fastcall FUN_10005281(int param_1)

{
  FUN_100091d0(param_1 + 0x4c);
  return;
}



void __fastcall FUN_100052a0(undefined4 *param_1)

{
  FUN_10005e70(param_1);
  return;
}



void * __thiscall FUN_100052c0(void *this,uint param_1)

{
  FUN_10002edc((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_100052f0(undefined4 *param_1)

{
  FUN_10005cb0(param_1);
  return;
}



void FUN_10005310(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  while (param_3 = param_3 + -1, -1 < param_3) {
    (*(code *)param_4)();
  }
  return;
}



void * __thiscall FUN_10005340(void *this,undefined4 *param_1)

{
  *(undefined4 *)this = *param_1;
  CString::operator=((CString *)((int)this + 4),(CString *)(param_1 + 1));
  *(undefined4 *)((int)this + 8) = param_1[2];
  *(undefined4 *)((int)this + 0xc) = param_1[3];
  *(undefined4 *)((int)this + 0x10) = param_1[4];
  return this;
}



void * __thiscall FUN_10005390(void *this,CString *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e949;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_100053f0(this,param_1);
  local_8 = 0;
  FUN_10007640((void *)((int)this + 4),(undefined4 *)(param_1 + 4));
  ExceptionList = local_10;
  return this;
}



void * __thiscall FUN_100053f0(void *this,CString *param_1)

{
  CString::CString((CString *)this,param_1);
  return this;
}



void * __thiscall FUN_10005410(void *this,int param_1)

{
  undefined4 uVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e981;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10005550(this,param_1);
  local_8 = 0;
  FUN_10007640((void *)((int)this + 0xc),(undefined4 *)(param_1 + 0xc));
  local_8._0_1_ = 1;
  *(undefined4 *)((int)this + 0x10) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)((int)this + 0x14) = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)((int)this + 0x18) = *(undefined4 *)(param_1 + 0x18);
  *(undefined4 *)((int)this + 0x1c) = *(undefined4 *)(param_1 + 0x1c);
  *(undefined4 *)((int)this + 0x20) = *(undefined4 *)(param_1 + 0x20);
  *(undefined4 *)((int)this + 0x24) = *(undefined4 *)(param_1 + 0x24);
  *(undefined4 *)((int)this + 0x28) = *(undefined4 *)(param_1 + 0x28);
  *(undefined1 *)((int)this + 0x2c) = *(undefined1 *)(param_1 + 0x2c);
  *(undefined4 *)((int)this + 0x30) = *(undefined4 *)(param_1 + 0x30);
  *(undefined4 *)((int)this + 0x34) = *(undefined4 *)(param_1 + 0x34);
  uVar1 = *(undefined4 *)(param_1 + 0x3c);
  *(undefined4 *)((int)this + 0x38) = *(undefined4 *)(param_1 + 0x38);
  *(undefined4 *)((int)this + 0x3c) = uVar1;
  *(undefined4 *)((int)this + 0x40) = *(undefined4 *)(param_1 + 0x40);
  *(undefined4 *)((int)this + 0x44) = *(undefined4 *)(param_1 + 0x44);
  *(undefined4 *)((int)this + 0x48) = *(undefined4 *)(param_1 + 0x48);
  FUN_10005590((void *)((int)this + 0x4c),param_1 + 0x4c);
  local_8 = CONCAT31(local_8._1_3_,2);
  FUN_10005590((void *)((int)this + 0x68),param_1 + 0x68);
  *(undefined ***)this = &PTR_FUN_10010258;
  ExceptionList = local_10;
  return this;
}



void * __thiscall FUN_10005550(void *this,int param_1)

{
  *(undefined4 *)((int)this + 4) = *(undefined4 *)(param_1 + 4);
  *(undefined4 *)((int)this + 8) = *(undefined4 *)(param_1 + 8);
  *(undefined ***)this = &PTR_FUN_100102dc;
  return this;
}



void * __thiscall FUN_10005590(void *this,int param_1)

{
  FUN_10005660(this,param_1);
  *(undefined ***)this = &PTR_LAB_10010204;
  return this;
}



void * __thiscall FUN_100055c0(void *this,void *param_1)

{
  FUN_100056c0(this,param_1);
  return this;
}



void __fastcall FUN_100055e0(int *param_1)

{
  (**(code **)(*param_1 + 0x40))(0x10);
  return;
}



bool FUN_10005600(void *param_1,char *param_2)

{
  int iVar1;
  
  iVar1 = FUN_10005620(param_1,param_2);
  return (bool)('\x01' - (iVar1 != 0));
}



void __thiscall FUN_10005620(void *this,char *param_1)

{
                    // WARNING: Load size is inaccurate
  strcmp(*this,param_1);
  return;
}



void __fastcall FUN_10005640(undefined4 *param_1)

{
  FUN_10005b30(param_1);
  return;
}



void * __thiscall FUN_10005660(void *this,int param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e999;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_100023b0(this,10);
  local_8 = 0;
  *(undefined ***)this = &PTR_LAB_10010218;
  FUN_100059f0(this,param_1);
  ExceptionList = local_10;
  return this;
}



void * __thiscall FUN_100056c0(void *this,void *param_1)

{
  if (this != param_1) {
    FUN_10002530((int)this);
    FUN_100059f0(this,(int)param_1);
  }
  return this;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_10005a30(this,10);
  *(undefined ***)this = &PTR_LAB_10010360;
  return this;
}



void * __thiscall FUN_10005730(void *this,int param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000e9b9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10005a30(this,10);
  local_8 = 0;
  *(undefined ***)this = &PTR_LAB_10010360;
  FUN_10005a90(this,param_1);
  ExceptionList = local_10;
  return this;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_10005c30(this,10);
  *(undefined ***)this = &PTR_LAB_10010374;
  return this;
}



void * __thiscall FUN_100057c0(void *this,uint param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  void *pvVar2;
  uint uVar3;
  int local_c;
  uint local_8;
  
  bVar1 = IsEmpty((int)this);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    uVar3 = FUN_10005970((int)this);
    if (param_1 < uVar3) {
      local_c = FUN_100026f0((int)this);
      local_8 = 0;
      while ((local_8 < param_1 && (uVar3 = FUN_10005970((int)this), local_8 < uVar3))) {
        FUN_10006070(&local_c);
        local_8 = local_8 + 1;
      }
      pvVar2 = (void *)FUN_10006070(&local_c);
    }
    else {
      pvVar2 = operator_new(0x60);
    }
  }
  else {
    pvVar2 = operator_new(0x60);
  }
  return pvVar2;
}



undefined4 * __fastcall FUN_10005870(undefined4 *param_1)

{
  FUN_10006bf0(param_1);
  return param_1;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_10005db0(this,10);
  *(undefined ***)this = &PTR_LAB_10010388;
  return this;
}



void * __thiscall FUN_100058c0(void *this,CString *param_1)

{
  FUN_10005e10(this,param_1);
  return this;
}



void * __thiscall FUN_100058e0(void *this,uint param_1)

{
  FUN_10005640((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_100020b0(this);
  }
  return this;
}



void * __thiscall FUN_10005910(void *this,uint param_1)

{
  FUN_100052f0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_100020b0(this);
  }
  return this;
}



void * __thiscall FUN_10005940(void *this,uint param_1)

{
  FUN_100052a0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_100020b0(this);
  }
  return this;
}



undefined4 __fastcall FUN_10005970(int param_1)

{
  return *(undefined4 *)(param_1 + 0xc);
}



undefined4 * __thiscall FUN_10005990(void *this,int param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_10002910(this,0,*(undefined4 *)((int)this + 4));
  FUN_10001fb0(puVar1 + 2,param_1);
  if (*(int *)((int)this + 4) == 0) {
    *(undefined4 **)((int)this + 8) = puVar1;
  }
  else {
    *(undefined4 **)(*(int *)((int)this + 4) + 4) = puVar1;
  }
  *(undefined4 **)((int)this + 4) = puVar1;
  return puVar1;
}



void __thiscall FUN_100059f0(void *this,int param_1)

{
  int iVar1;
  int local_8;
  
  local_8 = FUN_100026f0(param_1);
  while (local_8 != 0) {
    iVar1 = FUN_10006070(&local_8);
    FUN_100027f0(this,iVar1);
  }
  return;
}



void * __thiscall FUN_10005a30(void *this,undefined4 param_1)

{
  FUN_10002410((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_1001039c;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



void __thiscall FUN_10005a90(void *this,int param_1)

{
  undefined4 *puVar1;
  int local_8;
  
  local_8 = FUN_100026f0(param_1);
  while (local_8 != 0) {
    puVar1 = (undefined4 *)FUN_10006070(&local_8);
    FUN_10005ad0(this,puVar1);
  }
  return;
}



undefined4 * __thiscall FUN_10005ad0(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_100060a0(this,*(undefined4 *)((int)this + 8),0);
  puVar1[2] = *param_1;
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



void __fastcall FUN_10005b30(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1000e9d9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_1001039c;
  local_8 = 0;
  FUN_10008600((int)param_1);
  local_8 = 0xffffffff;
  FUN_10002460(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_10005b90(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_10;
  ulong local_c;
  undefined4 *local_8;
  
  FUN_100020e0();
  bVar1 = FUN_10002710((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      FUN_10006180(param_1,&local_10,1);
      FUN_10005ad0(this,&local_10);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_10006180(param_1,local_8 + 2,1);
    }
  }
  return;
}



void * __thiscall FUN_10005c30(void *this,undefined4 param_1)

{
  FUN_10002410((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_100103b0;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



// Library Function - Multiple Matches With Same Base Name
//  public: int __thiscall CList<unsigned int,unsigned int>::IsEmpty(void)const 
//  public: int __thiscall CList<unsigned long,unsigned long>::IsEmpty(void)const 
//  public: int __thiscall CList<class CMFCButton *,class CMFCButton *>::IsEmpty(void)const 
//  public: int __thiscall CList<class CMFCPropertyGridProperty *,class CMFCPropertyGridProperty
// *>::IsEmpty(void)const 
//   24 names - too many to list
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

bool __fastcall IsEmpty(int param_1)

{
  return *(int *)(param_1 + 0xc) == 0;
}



void __fastcall FUN_10005cb0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1000e9f9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_100103b0;
  local_8 = 0;
  FUN_10006230((int)param_1);
  local_8 = 0xffffffff;
  FUN_10002460(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_10005d10(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_6c [24];
  ulong local_c;
  undefined4 *local_8;
  
  FUN_100020e0();
  bVar1 = FUN_10002710((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      FUN_100062b0(param_1,local_6c,1);
      FUN_100061c0(this,local_6c);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_100062b0(param_1,local_8 + 2,1);
    }
  }
  return;
}



void * __thiscall FUN_10005db0(void *this,undefined4 param_1)

{
  FUN_10002410((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_100103c4;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



undefined4 * __thiscall FUN_10005e10(void *this,CString *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_10006370(this,*(undefined4 *)((int)this + 8),0);
  FUN_100021b0(puVar1 + 2,param_1);
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



void __fastcall FUN_10005e70(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1000ea19;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_100103c4;
  local_8 = 0;
  FUN_100062f0((int)param_1);
  local_8 = 0xffffffff;
  FUN_10002460(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_10005ed0(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  CString local_20 [8];
  ulong local_18;
  undefined4 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ea39;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_100020e0();
  bVar1 = FUN_10002710((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_18 = CArchive::ReadCount(param_1);
    while (local_18 != 0) {
      local_18 = local_18 - 1;
      FUN_10002060(local_20);
      local_8 = 0;
      FUN_10006450(param_1,local_20,1);
      FUN_10005e10(this,local_20);
      local_8 = 0xffffffff;
      FUN_100020f0(local_20);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_14 = *(undefined4 **)((int)this + 4); local_14 != (undefined4 *)0x0;
        local_14 = (undefined4 *)*local_14) {
      FUN_10006450(param_1,local_14 + 2,1);
    }
  }
  ExceptionList = local_10;
  return;
}



int __cdecl FUN_10005fb0(int param_1,int param_2)

{
  undefined4 local_8;
  
  if (param_1 < param_2) {
    local_8 = param_1;
  }
  else {
    local_8 = param_2;
  }
  return local_8;
}



void * __thiscall FUN_10005fe0(void *this,uint param_1)

{
  FUN_10005b30((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_100020b0(this);
  }
  return this;
}



void * __thiscall FUN_10006010(void *this,uint param_1)

{
  FUN_10005cb0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_100020b0(this);
  }
  return this;
}



void * __thiscall FUN_10006040(void *this,uint param_1)

{
  FUN_10005e70((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_100020b0(this);
  }
  return this;
}



int FUN_10006070(int *param_1)

{
  int *piVar1;
  
  piVar1 = (int *)*param_1;
  *param_1 = *piVar1;
  return (int)(piVar1 + 2);
}



undefined4 * __thiscall FUN_100060a0(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0xc);
    iVar3 = FUN_1000e3d0((int)pCVar2);
    local_c = (undefined4 *)(iVar3 + (*(int *)((int)this + 0x18) + -1) * 0xc);
    local_10 = *(int *)((int)this + 0x18);
    while (local_10 = local_10 + -1, -1 < local_10) {
      *local_c = *(undefined4 *)((int)this + 0x10);
      *(undefined4 **)((int)this + 0x10) = local_c;
      local_c = local_c + -3;
    }
  }
  puVar1 = *(undefined4 **)((int)this + 0x10);
  *(undefined4 *)((int)this + 0x10) = **(undefined4 **)((int)this + 0x10);
  puVar1[1] = param_1;
  *puVar1 = param_2;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  FUN_100064c0(puVar1 + 2,1);
  return puVar1;
}



void FUN_10006180(CArchive *param_1,void *param_2,int param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_10002710((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    CArchive::Read(param_1,param_2,param_3 << 2);
  }
  else {
    CArchive::Write(param_1,param_2,param_3 << 2);
  }
  return;
}



undefined4 * __thiscall FUN_100061c0(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  
  puVar1 = FUN_10006510(this,*(undefined4 *)((int)this + 8),0);
  puVar3 = puVar1 + 2;
  for (iVar2 = 0x18; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar3 = *param_1;
    param_1 = param_1 + 1;
    puVar3 = puVar3 + 1;
  }
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



void __fastcall FUN_10006230(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_100065f0(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



void FUN_100062b0(CArchive *param_1,void *param_2,int param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_10002710((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    CArchive::Read(param_1,param_2,param_3 * 0x60);
  }
  else {
    CArchive::Write(param_1,param_2,param_3 * 0x60);
  }
  return;
}



void __fastcall FUN_100062f0(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_10006620(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



undefined4 * __thiscall FUN_10006370(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0x10);
    iVar3 = FUN_1000e3d0((int)pCVar2);
    local_c = (undefined4 *)(iVar3 + (*(int *)((int)this + 0x18) + -1) * 0x10);
    local_10 = *(int *)((int)this + 0x18);
    while (local_10 = local_10 + -1, -1 < local_10) {
      *local_c = *(undefined4 *)((int)this + 0x10);
      *(undefined4 **)((int)this + 0x10) = local_c;
      local_c = local_c + -4;
    }
  }
  puVar1 = *(undefined4 **)((int)this + 0x10);
  *(undefined4 *)((int)this + 0x10) = **(undefined4 **)((int)this + 0x10);
  puVar1[1] = param_1;
  *puVar1 = param_2;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  FUN_10006650(puVar1 + 2,1);
  return puVar1;
}



void FUN_10006450(CArchive *param_1,void *param_2,int param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_10002710((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    CArchive::Read(param_1,param_2,param_3 << 3);
  }
  else {
    CArchive::Write(param_1,param_2,param_3 << 3);
  }
  return;
}



void FUN_10006490(undefined4 param_1,int param_2)

{
  bool bVar1;
  
  do {
    bVar1 = param_2 != 0;
    param_2 = param_2 + -1;
  } while (bVar1);
  return;
}



void FUN_100064c0(void *param_1,int param_2)

{
  memset(param_1,0,param_2 << 2);
  while (param_2 != 0) {
    FUN_10002a90(4,param_1);
    param_1 = (void *)((int)param_1 + 4);
    param_2 = param_2 + -1;
  }
  return;
}



undefined4 * __thiscall FUN_10006510(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0x68);
    iVar3 = FUN_1000e3d0((int)pCVar2);
    local_c = (undefined4 *)(iVar3 + (*(int *)((int)this + 0x18) + -1) * 0x68);
    local_10 = *(int *)((int)this + 0x18);
    while (local_10 = local_10 + -1, -1 < local_10) {
      *local_c = *(undefined4 *)((int)this + 0x10);
      *(undefined4 **)((int)this + 0x10) = local_c;
      local_c = local_c + -0x1a;
    }
  }
  puVar1 = *(undefined4 **)((int)this + 0x10);
  *(undefined4 *)((int)this + 0x10) = **(undefined4 **)((int)this + 0x10);
  puVar1[1] = param_1;
  *puVar1 = param_2;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  FUN_10006720(puVar1 + 2,1);
  return puVar1;
}



void FUN_100065f0(undefined4 param_1,int param_2)

{
  bool bVar1;
  
  do {
    bVar1 = param_2 != 0;
    param_2 = param_2 + -1;
  } while (bVar1);
  return;
}



void FUN_10006620(void *param_1,int param_2)

{
  while (param_2 != 0) {
    FUN_100066f0(param_1,0);
    param_1 = (void *)((int)param_1 + 8);
    param_2 = param_2 + -1;
  }
  return;
}



void FUN_10006650(void *param_1,int param_2)

{
  CString *pCVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ea61;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  memset(param_1,0,param_2 << 3);
  while (param_2 != 0) {
    pCVar1 = (CString *)FUN_10002a90(8,param_1);
    local_8 = 0;
    if (pCVar1 != (CString *)0x0) {
      FUN_10002060(pCVar1);
    }
    local_8 = 0xffffffff;
    param_1 = (void *)((int)param_1 + 8);
    param_2 = param_2 + -1;
  }
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_100066f0(void *this,uint param_1)

{
  FUN_100020f0((CString *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void FUN_10006720(void *param_1,int param_2)

{
  memset(param_1,0,param_2 * 0x60);
  while (param_2 != 0) {
    FUN_10002a90(0x60,param_1);
    param_1 = (void *)((int)param_1 + 0x60);
    param_2 = param_2 + -1;
  }
  return;
}



bool __fastcall FUN_10006770(int *param_1)

{
  return *param_1 != -0x400;
}



void * __thiscall FUN_10006790(void *this,void *param_1)

{
  uint uVar1;
  
                    // WARNING: Load size is inaccurate
  uVar1 = FUN_10002b10(*this + 8);
  FUN_10002ad0(param_1,uVar1);
  return param_1;
}



bool __fastcall FUN_100067c0(uint *param_1)

{
  uint uVar1;
  
  uVar1 = *param_1 & 0x80000003;
  if ((int)uVar1 < 0) {
    uVar1 = (uVar1 - 1 | 0xfffffffc) + 1;
  }
  return (bool)('\x01' - (uVar1 != 0));
}



void * __cdecl FUN_100067f0(void *param_1,int param_2,int param_3)

{
  FUN_10002ad0(param_1,param_2 + param_3);
  return param_1;
}



void * __cdecl FUN_10006810(void *param_1,int param_2,int param_3)

{
  FUN_10002ad0(param_1,param_2 - param_3);
  return param_1;
}



bool __thiscall FUN_10006830(void *this,int *param_1)

{
                    // WARNING: Load size is inaccurate
  return *this == *param_1;
}



void * __thiscall FUN_10006850(void *this,void *param_1,int *param_2)

{
  undefined4 *puVar1;
  undefined1 local_14 [8];
  int local_c;
  int local_8;
  
  local_c = *param_2;
  local_8 = param_2[1];
  puVar1 = (undefined4 *)FID_conflict_operator_(this,local_14,local_c,local_8);
  FUN_100068c0(param_1,puVar1);
  return param_1;
}



// Library Function - Multiple Matches With Different Base Names
//  public: class CPoint __thiscall CPoint::operator+(struct tagPOINT)const 
//  public: class CPoint __thiscall CPoint::operator+(struct tagSIZE)const 
//  public: class CPoint __thiscall CSize::operator+(struct tagPOINT)const 
// 
// Library: Visual Studio

void * __thiscall FID_conflict_operator_(void *this,void *param_1,int param_2,int param_3)

{
                    // WARNING: Load size is inaccurate
  FUN_1000be70(param_1,*this + param_2,*(int *)((int)this + 4) + param_3);
  return param_1;
}



void * __thiscall FUN_100068c0(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  
  uVar1 = param_1[1];
  *(undefined4 *)this = *param_1;
  *(undefined4 *)((int)this + 4) = uVar1;
  return this;
}



// Library Function - Multiple Matches With Same Base Name
//  public: class std::_Vector_iterator<class std::_Vector_val<struct std::_Simple_types<class
// std::shared_ptr<struct Concurrency::details::_Task_impl<unsigned char> > > > > __thiscall
// std::move_iterator<class std::_Vector_iterator<class std::_Vector_val<struct
// std::_Simple_types<class std::shared_ptr<struct Concurrency::details::_Task_impl<unsigned char> >
// > > > >::base(void)const 
//  public: class std::_Vector_iterator<class std::_Vector_val<struct std::_Simple_types<class
// std::shared_ptr<struct Concurrency::details::_Task_impl<struct std::pair<unsigned char,class
// Concurrency::details::_CancellationTokenState *> > > > > > __thiscall std::move_iterator<class
// std::_Vector_iterator<class std::_Vector_val<struct std::_Simple_types<class
// std::shared_ptr<struct Concurrency::details::_Task_impl<struct std::pair<unsigned char,class
// Concurrency::details::_CancellationTokenState *> > > > > > >::base(void)const 
// 
// Library: Visual Studio 2012 Release

undefined4 * __thiscall base(void *this,undefined4 *param_1)

{
                    // WARNING: Load size is inaccurate
  *param_1 = *this;
  return param_1;
}



void __thiscall FUN_10006900(void *this,undefined4 param_1)

{
  *(undefined4 *)this = param_1;
  return;
}



void __fastcall FUN_10006920(int *param_1)

{
  FUN_10006770(param_1);
  return;
}



void * __thiscall
FUN_10006940(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 uVar1;
  
  FUN_10002ab0((undefined4 *)((int)this + 4));
  FUN_10002bb0((undefined4 *)((int)this + 8));
  FUN_10002b70((void *)((int)this + 0xc));
  uVar1 = extraout_ECX;
  FUN_10002ad0(&stack0xffffffec,0xfffffc00);
  FUN_10001cc0((void *)((int)this + 0x14),uVar1);
  uVar1 = extraout_ECX_00;
  FUN_10002ad0(&stack0xffffffec,0xfffffc00);
  FUN_10001cc0((void *)((int)this + 0x18),uVar1);
  *(undefined ***)this = &PTR_FUN_10010200;
  *(undefined4 *)((int)this + 4) = param_1;
  *(undefined4 *)((int)this + 8) = param_2;
  *(undefined4 *)((int)this + 0xc) = param_3;
  *(undefined4 *)((int)this + 0x10) = param_4;
  return this;
}



bool __thiscall FUN_100069d0(void *this,int param_1)

{
  char cVar1;
  
  cVar1 = FUN_10006a00(this,param_1);
  return (bool)('\x01' - (cVar1 != '\0'));
}



undefined1 __thiscall FUN_10006a00(void *this,int param_1)

{
  bool bVar1;
  int iVar2;
  
  bVar1 = FUN_10006ad0(*(int *)((int)this + 8),*(int *)(param_1 + 8));
  if (((bVar1) && (bVar1 = FUN_10006830((void *)((int)this + 4),(int *)(param_1 + 4)), bVar1)) &&
     (iVar2 = FUN_10006a90((void *)((int)this + 0xc),*(int *)(param_1 + 0xc),
                           *(int *)(param_1 + 0x10)), iVar2 != 0)) {
    return 1;
  }
  return 0;
}



undefined4 __thiscall FUN_10006a90(void *this,int param_1,int param_2)

{
  undefined4 local_c;
  
                    // WARNING: Load size is inaccurate
  if ((*this == param_1) && (*(int *)((int)this + 4) == param_2)) {
    local_c = 1;
  }
  else {
    local_c = 0;
  }
  return local_c;
}



bool __cdecl FUN_10006ad0(int param_1,int param_2)

{
  return param_1 == param_2;
}



int __fastcall FUN_10006af0(int param_1)

{
  return param_1 + 0x14;
}



void __thiscall FUN_10006b10(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 0x14) = param_1;
  return;
}



int __fastcall FUN_10006b30(int param_1)

{
  return param_1 + 0x18;
}



void __thiscall FUN_10006b50(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 8) = param_1;
  return;
}



undefined4 * __fastcall FUN_10006b70(undefined4 *param_1)

{
  param_1[1] = 0;
  *param_1 = &PTR_FUN_100103d8;
  return param_1;
}



void __fastcall FUN_10006ba0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_100103d8;
  return;
}



void * __thiscall FUN_10006bc0(void *this,uint param_1)

{
  FUN_10006ba0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



undefined4 * __fastcall FUN_10006bf0(undefined4 *param_1)

{
  *param_1 = 0;
  return param_1;
}



undefined4 __fastcall FUN_10006c10(int param_1)

{
  return *(undefined4 *)(param_1 + 0xb8);
}



void * __fastcall FUN_10006c30(void *param_1)

{
  *(undefined4 *)((int)param_1 + 0x50) = 0;
  memset(param_1,-1,0x50);
  return param_1;
}



void * __fastcall FUN_10006c60(void *param_1)

{
  memset(param_1,0,0x100);
  return param_1;
}



undefined4 * __fastcall FUN_10006c90(undefined4 *param_1)

{
  param_1[1] = 0;
  param_1[2] = 0;
  *param_1 = &PTR_FUN_100102dc;
  return param_1;
}



void __fastcall FUN_10006cc0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_100102dc;
  return;
}



void * __thiscall FUN_10006ce0(void *this,uint param_1)

{
  FUN_10006cc0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



undefined4 * __fastcall FUN_10006d10(undefined4 *param_1)

{
  *param_1 = 0;
  CString::CString((CString *)(param_1 + 1));
  param_1[2] = 1;
  param_1[3] = 1;
  return param_1;
}



void * __thiscall FUN_10006d50(void *this,char *param_1,int param_2)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ea79;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10006db0(this,param_1);
  local_8 = 0;
  FUN_100022b0((void *)((int)this + 4),param_2);
  ExceptionList = local_10;
  return this;
}



void * __thiscall FUN_10006db0(void *this,char *param_1)

{
  CString::CString((CString *)this,param_1);
  return this;
}



int __thiscall FUN_10006dd0(void *this,uint param_1,uint param_2,uint param_3)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  
  iVar3 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
  if (*(char *)(iVar3 + 0x6c8) == '\0') {
    uVar5 = param_2 >> 1;
    iVar3 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
    iVar3 = FUN_10006f50((void *)(iVar3 + 0x5c8),param_1,uVar5);
    iVar4 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
    if (*(char *)(iVar4 + 0x6d4) != '\0') {
      if ((*(int *)((int)this + 0x28) == 0) ||
         (cVar2 = (**(code **)((int)this + 0x28))(), cVar2 == '\0')) {
        bVar1 = false;
      }
      else {
        bVar1 = true;
      }
      if (bVar1) {
        iVar4 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
        iVar3 = FUN_10006f10((void *)(iVar4 + 0x328 + iVar3 * 0x54),param_3);
      }
      else {
        iVar4 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
        iVar3 = FUN_10006f10((void *)(iVar4 + 0x88 + iVar3 * 0x54),param_3);
      }
    }
  }
  else {
    iVar3 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
    uVar5 = *(uint *)(iVar3 + 0x6cc);
    iVar3 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
    uVar6 = *(uint *)(iVar3 + 0x6d0);
    iVar3 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
    iVar3 = FUN_10006f50((void *)(iVar3 + 0x5c8),uVar6,uVar5);
  }
  return iVar3;
}



undefined4 __thiscall FUN_10006f10(void *this,uint param_1)

{
  undefined4 uVar1;
  
  if (param_1 < 0x14) {
    if (*(int *)((int)this + 0x50) == 0) {
      uVar1 = 0xffffffff;
    }
    else {
      uVar1 = *(undefined4 *)((int)this + param_1 * 4);
    }
  }
  else {
    uVar1 = 0xffffffff;
  }
  return uVar1;
}



undefined4 __thiscall FUN_10006f50(void *this,uint param_1,uint param_2)

{
  undefined4 uVar1;
  
  if ((param_1 < 8) && (param_2 < 8)) {
    uVar1 = *(undefined4 *)((int)this + param_2 * 4 + param_1 * 0x20);
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



void __fastcall FUN_10006f90(int param_1)

{
  *(undefined4 *)(param_1 + 0x20) = 1;
  return;
}



void __fastcall FUN_10006fb0(int param_1)

{
  *(undefined4 *)(param_1 + 0x20) = 0;
  return;
}



bool __fastcall FUN_10006fd0(int param_1)

{
  return *(int *)(param_1 + 0x20) != 0;
}



undefined4 * __thiscall FUN_10006ff0(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)((int)this + 0x3c);
  *param_1 = *(undefined4 *)((int)this + 0x38);
  param_1[1] = uVar1;
  return param_1;
}



void __thiscall FUN_10007020(void *this,undefined4 param_1,undefined4 param_2)

{
  *(undefined4 *)((int)this + 0x38) = param_1;
  *(undefined4 *)((int)this + 0x3c) = param_2;
  return;
}



undefined4 * __thiscall FUN_10007040(void *this,undefined4 *param_1)

{
  *param_1 = *(undefined4 *)((int)this + 0x30);
  return param_1;
}



undefined4 * __thiscall FUN_10007060(void *this,undefined4 *param_1)

{
  *param_1 = *(undefined4 *)((int)this + 0x34);
  return param_1;
}



void __thiscall FUN_10007080(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 0x30) = param_1;
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x30))();
  return;
}



void __fastcall FUN_100070b0(int *param_1)

{
  FUN_100070e0(param_1 + 0xc,1);
  (**(code **)(*param_1 + 0x30))();
  return;
}



void __thiscall FUN_100070e0(void *this,uint param_1)

{
  undefined4 local_8;
  
  for (local_8 = 0; local_8 < param_1; local_8 = local_8 + 1) {
                    // WARNING: Load size is inaccurate
    FUN_10002af0(this,*this + 2);
  }
  return;
}



void __fastcall FUN_10007120(int *param_1)

{
  FUN_10007150(param_1 + 0xc,1);
  (**(code **)(*param_1 + 0x30))();
  return;
}



void __thiscall FUN_10007150(void *this,uint param_1)

{
  undefined4 local_8;
  
  for (local_8 = 0; local_8 < param_1; local_8 = local_8 + 1) {
                    // WARNING: Load size is inaccurate
    FUN_10002af0(this,*this + 0xe);
  }
  return;
}



void __thiscall FUN_10007190(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 0x34) = param_1;
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x30))();
  return;
}



void __thiscall FUN_100071c0(void *this,uint param_1)

{
  FUN_100071f0((void *)((int)this + 0x34),param_1);
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x30))();
  return;
}



void __thiscall FUN_100071f0(void *this,uint param_1)

{
                    // WARNING: Load size is inaccurate
  *(uint *)this = *this ^ param_1;
  return;
}



void __fastcall FUN_10007210(int param_1)

{
  *(undefined1 *)(param_1 + 0x2c) = 1;
  if (*(int *)(param_1 + 0x10) != 0) {
    FUN_10007240(*(int *)(param_1 + 0x10));
  }
  return;
}



void __fastcall FUN_10007240(int param_1)

{
  *(undefined1 *)(param_1 + 0x43c) = 1;
  return;
}



void * __thiscall FUN_10007260(void *this,void *param_1,int param_2)

{
  FUN_10006810(param_1,param_2,*(int *)((int)this + 0x30));
  return param_1;
}



undefined4 __fastcall FUN_10007290(int param_1)

{
  return *(undefined4 *)(param_1 + 0x24);
}



undefined4 __fastcall FUN_100072b0(int param_1)

{
  return *(undefined4 *)(param_1 + 0x44);
}



void __thiscall FUN_100072d0(void *this,undefined4 param_1)

{
  *(undefined1 *)((int)this + 0x2c) = 1;
  *(undefined4 *)((int)this + 0x44) = param_1;
  return;
}



undefined4 __fastcall FUN_100072f0(int param_1)

{
  return *(undefined4 *)(param_1 + 0x40);
}



void __thiscall FUN_10007310(void *this,undefined4 param_1)

{
  *(undefined1 *)((int)this + 0x2c) = 1;
  *(undefined4 *)((int)this + 0x40) = param_1;
  return;
}



undefined1 __fastcall FUN_10007330(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_1000a7a0((undefined4 *)(param_1 + 0xc));
  return *(undefined1 *)(iVar1 + 0x739);
}



CString * __thiscall FUN_10007350(void *this,CString *param_1)

{
  int iVar1;
  
  iVar1 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
  CString::CString(param_1,(CString *)(iVar1 + 0x73c));
  return param_1;
}



CString * __thiscall FUN_10007390(void *this,CString *param_1)

{
  int iVar1;
  
  iVar1 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
  CString::CString(param_1,(CString *)(iVar1 + 0x740));
  return param_1;
}



void __fastcall FUN_100073d0(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_1000a7a0((undefined4 *)(param_1 + 0xc));
  FUN_10002320((int *)(iVar1 + 0x754));
  return;
}



CString * __thiscall FUN_10007400(void *this,CString *param_1)

{
  int iVar1;
  
  iVar1 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
  CString::CString(param_1,(CString *)(iVar1 + 0x74c));
  return param_1;
}



bool __fastcall FUN_10007440(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_10007460(param_1 + 0x4c);
  return iVar1 != 0;
}



undefined4 __fastcall FUN_10007460(int param_1)

{
  bool bVar1;
  uint *puVar2;
  undefined4 local_30 [7];
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ea99;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_14 = FUN_100026f0(param_1);
  while( true ) {
    if (local_14 == 0) {
      ExceptionList = local_10;
      return 0;
    }
    FUN_10007500(local_30,&local_14);
    local_8 = 0;
    puVar2 = (uint *)FUN_10001d70((int)local_30);
    bVar1 = FUN_10002b40(puVar2);
    if (bVar1) break;
    local_8 = 0xffffffff;
    FUN_10001ce0(local_30);
  }
  local_8 = 0xffffffff;
  FUN_10001ce0(local_30);
  ExceptionList = local_10;
  return 1;
}



void * FUN_10007500(void *param_1,int *param_2)

{
  int *piVar1;
  
  piVar1 = (int *)*param_2;
  *param_2 = *piVar1;
  FUN_10002790(param_1,(int)(piVar1 + 2));
  return param_1;
}



void * __thiscall FUN_10007550(void *this,uint param_1)

{
  FUN_10007580((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10007580(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_1000ead1;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_FUN_10010258;
  local_8 = 2;
  FUN_10001f30(param_1 + 0x1a);
  local_8._0_1_ = 1;
  FUN_10001f30(param_1 + 0x13);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_10007600(param_1 + 3);
  local_8 = 0xffffffff;
  FUN_10006cc0(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10007600(int *param_1)

{
  FUN_10002140(param_1);
  return;
}



void __fastcall FUN_10007620(int param_1)

{
  CString::~CString((CString *)(param_1 + 4));
  return;
}



void * __thiscall FUN_10007640(void *this,undefined4 *param_1)

{
  FUN_10002230(this,param_1);
  return this;
}



void FUN_10007660(void)

{
  FUN_1000766f();
  FUN_1000767e();
  return;
}



void FUN_1000766f(void)

{
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)&DAT_100151c0);
  return;
}



void FUN_1000767e(void)

{
  FUN_1000e1a8(FUN_10007690);
  return;
}



void FUN_10007690(void)

{
  if ((DAT_100151b8 & 1) == 0) {
    DAT_100151b8 = DAT_100151b8 | 1;
    FUN_10005640((undefined4 *)&DAT_100151c0);
  }
  return;
}



// public: __thiscall MAP::MAP(void)

MAP * __thiscall MAP::MAP(MAP *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x76bc  1  ??0MAP@@QAE@XZ
  local_8 = 0xffffffff;
  puStack_c = &this_1000eb0d;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString((CString *)(this + 0x414));
  local_8 = 0;
  CString::CString((CString *)(this + 0x418));
  local_8._0_1_ = 1;
  CString::CString((CString *)(this + 0x41c));
  local_8 = CONCAT31(local_8._1_3_,2);
  FUN_10008940((undefined4 *)(this + 0x420));
  FUN_10002b70(this + 0x428);
  FUN_10002b70(this + 0x430);
  this[0x438] = (MAP)0x0;
  this[0x439] = (MAP)0x0;
  this[0x43a] = (MAP)0x0;
  this[0x43b] = (MAP)0x0;
  this[0x43c] = (MAP)0x0;
  *(undefined ***)this = &PTR_FUN_100103dc;
  memset(this + 4,0,0x410);
  ExceptionList = local_10;
  return this;
}



// public: static void __cdecl MAP::Init(class GAME *,unsigned int,unsigned int)

void __cdecl MAP::Init(GAME *param_1,uint param_2,uint param_3)

{
  CString *pCVar1;
  undefined4 *puVar2;
  char *pcVar3;
  CTypeLibCacheMap local_34 [28];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x77a4  19  ?Init@MAP@@SAXPAVGAME@@II@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000eb32;
  local_10 = ExceptionList;
  DAT_100151dc = param_1;
  DAT_1001324c = param_2;
  DAT_10013250 = param_3;
  ExceptionList = &local_10;
  pCVar1 = FUN_100086c0(local_14);
  local_8 = 0;
  puVar2 = (undefined4 *)operator+(local_18,(char *)pCVar1);
  local_8._0_1_ = 1;
  pcVar3 = (char *)FUN_1000a7a0(puVar2);
  FUN_10005067(local_34,pcVar3);
  local_8._0_1_ = 2;
  FUN_100085c0(&DAT_100151c0,pcVar3);
  local_8._0_1_ = 1;
  FUN_10005640((undefined4 *)local_34);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(local_18);
  local_8 = 0xffffffff;
  CString::~CString(local_14);
  ExceptionList = local_10;
  return;
}



// public: class MAP & __thiscall MAP::operator=(class MAP const &)

MAP * __thiscall MAP::operator=(MAP *this,MAP *param_1)

{
                    // 0x7879  3  ??4MAP@@QAEAAV0@ABV0@@Z
  ~MAP(this);
  FUN_10008460(this,(undefined4 *)param_1);
  return this;
}



// public: virtual __thiscall MAP::~MAP(void)

void __thiscall MAP::~MAP(MAP *this)

{
  undefined4 *puVar1;
  undefined1 local_38 [8];
  undefined1 local_30 [8];
  undefined1 local_28 [8];
  uint local_20;
  ITEM *local_1c;
  uint local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x789d  2  ??1MAP@@UAE@XZ
  puStack_c = &LAB_1000eb69;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)this = &PTR_FUN_100103dc;
  local_8 = 2;
  local_14 = local_14 & 0xffffff00;
  puVar1 = (undefined4 *)default_error_condition(local_28,0,0);
  local_1c = GetItem(this,*puVar1,puVar1[1]);
  local_18 = 0;
  while ((local_18 < 0x14 && ((local_14 & 0xff) == 0))) {
    local_20 = 0;
    while ((local_20 < 0xd && ((local_14 & 0xff) == 0))) {
      if (local_1c != (ITEM *)0x0) {
        (*(code *)**(undefined4 **)local_1c)(1);
      }
      local_20 = local_20 + 1;
      if (local_20 < 0xd) {
        puVar1 = (undefined4 *)default_error_condition(local_30,local_18,local_20);
        local_1c = GetItem(this,*puVar1,puVar1[1]);
      }
      else if (local_18 < 0x13) {
        puVar1 = (undefined4 *)default_error_condition(local_38,local_18 + 1,0);
        local_1c = GetItem(this,*puVar1,puVar1[1]);
      }
    }
    local_18 = local_18 + 1;
  }
  local_8._0_1_ = 1;
  CString::~CString((CString *)(this + 0x41c));
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString((CString *)(this + 0x418));
  local_8 = 0xffffffff;
  CString::~CString((CString *)(this + 0x414));
  ExceptionList = local_10;
  return;
}



// public: void __thiscall MAP::Rename(class CString)

void __thiscall MAP::Rename(MAP *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x7a2d  29  ?Rename@MAP@@QAEXVCString@@@Z
  puStack_c = &LAB_1000eb7c;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  CString::operator=((CString *)(this + 0x414),(CString *)&stack0x00000004);
  local_8 = 0xffffffff;
  CString::~CString((CString *)&stack0x00000004);
  ExceptionList = local_10;
  return;
}



// public: void __thiscall MAP::SetScript(class CString)

void __thiscall MAP::SetScript(MAP *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x7a81  41  ?SetScript@MAP@@QAEXVCString@@@Z
  puStack_c = &LAB_1000eb8f;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  CString::operator=((CString *)(this + 0x418),(CString *)&stack0x00000004);
  local_8 = 0xffffffff;
  CString::~CString((CString *)&stack0x00000004);
  ExceptionList = local_10;
  return;
}



// public: void __thiscall MAP::SetCopyrightString(class CString)

void __thiscall MAP::SetCopyrightString(MAP *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x7ad5  34  ?SetCopyrightString@MAP@@QAEXVCString@@@Z
  puStack_c = &LAB_1000eba2;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  CString::operator=((CString *)(this + 0x41c),(CString *)&stack0x00000004);
  local_8 = 0xffffffff;
  CString::~CString((CString *)&stack0x00000004);
  ExceptionList = local_10;
  return;
}



// public: static void __cdecl MAP::SetLevelDir(class CString)

void __cdecl MAP::SetLevelDir(void)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x7b29  39  ?SetLevelDir@MAP@@SAXVCString@@@Z
  puStack_c = &this_1000ebb5;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  CString::operator=((CString *)&param_2_100151f0,(CString *)&stack0x00000004);
  memset(&_Dst_10013c28,0,0x78);
  memset(&_Dst_10013ca0,0,0x1e0);
  local_8 = 0xffffffff;
  CString::~CString((CString *)&stack0x00000004);
  ExceptionList = local_10;
  return;
}



// public: struct STRING __thiscall MAP::Name(void)const 

void * __thiscall MAP::Name(MAP *this)

{
  void *in_stack_00000004;
  
                    // 0x7b98  23  ?Name@MAP@@QBE?AUSTRING@@XZ
  FUN_100053f0(in_stack_00000004,(CString *)(this + 0x414));
  return in_stack_00000004;
}



// public: int __thiscall MAP::HasScript(void)const 

int __thiscall MAP::HasScript(MAP *this)

{
  bool bVar1;
  undefined3 extraout_var;
  
                    // 0x7bcb  18  ?HasScript@MAP@@QBEHXZ
  bVar1 = FUN_10008680((int *)(this + 0x418));
  return (uint)(CONCAT31(extraout_var,bVar1) == 0);
}



// public: void __thiscall MAP::UseSmallTiles(bool)

void __thiscall MAP::UseSmallTiles(MAP *this,bool param_1)

{
                    // 0x7be9  44  ?UseSmallTiles@MAP@@QAEX_N@Z
  this[0x43b] = (MAP)param_1;
  return;
}



// public: class DD_SURFACE * __thiscall MAP::DefaultTiles(void)

DD_SURFACE * __thiscall MAP::DefaultTiles(MAP *this)

{
  DD_SURFACE *pDVar1;
  
                    // 0x7c02  10  ?DefaultTiles@MAP@@QAEPAVDD_SURFACE@@XZ
  if (this[0x43b] == (MAP)0x0) {
    pDVar1 = (DD_SURFACE *)FUN_10008a50();
  }
  else {
    pDVar1 = (DD_SURFACE *)FUN_10008a60();
  }
  return pDVar1;
}



int __thiscall FUN_10007c28(void *this,void *param_1)

{
  int *piVar1;
  int local_24;
  int local_20;
  int local_1c;
  int local_18;
  void *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ebd1;
  local_10 = ExceptionList;
  local_14 = param_1;
  if (*(char *)((int)this + 0x43b) == '\0') {
    ExceptionList = &local_10;
    piVar1 = (int *)FUN_10008a70(param_1,&local_24);
    local_8 = 1;
    local_20 = FUN_10002320(piVar1);
    local_8 = 0xffffffff;
    FUN_10007600(&local_24);
    local_18 = local_20;
  }
  else {
    ExceptionList = &local_10;
    piVar1 = (int *)FUN_10008ab0(param_1,&local_1c);
    local_8 = 0;
    local_18 = FUN_10002320(piVar1);
    local_8 = 0xffffffff;
    FUN_10007600(&local_1c);
  }
  ExceptionList = local_10;
  return local_18;
}



// public: void __thiscall MAP::OnRestore(bool)

void __thiscall MAP::OnRestore(MAP *this,bool param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  CString *pCVar2;
  uint uVar3;
  undefined3 extraout_var_00;
  TILEBLITTER *pTVar4;
  int local_20;
  CString local_1c [4];
  int local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x7cdf  25  ?OnRestore@MAP@@QAEX_N@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ebe4;
  local_10 = ExceptionList;
  if (param_1) {
    ExceptionList = &local_10;
    local_20 = FUN_100026f0(0x10015088);
    FUN_10002060(local_1c);
    local_8 = 0;
    local_14 = 0;
    bVar1 = IsEmpty(0x10015088);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      pCVar2 = (CString *)FUN_10006070(&local_20);
      FUN_100021b0(local_1c,pCVar2);
    }
    local_14 = 0;
    while ((uVar3 = FUN_10005970(0x10015088), local_14 < uVar3 &&
           (bVar1 = IsEmpty(0x10015088), CONCAT31(extraout_var_00,bVar1) == 0))) {
      pTVar4 = (TILEBLITTER *)FUN_10002320(&local_18);
      FUN_100089c0(pTVar4);
      local_14 = local_14 + 1;
      uVar3 = FUN_10005970(0x10015088);
      if (local_14 < uVar3) {
        pCVar2 = (CString *)FUN_10006070(&local_20);
        FUN_100021b0(local_1c,pCVar2);
      }
    }
    local_8 = 0xffffffff;
    FUN_100020f0(local_1c);
  }
  ExceptionList = local_10;
  return;
}



// public: void __thiscall MAP::SetCursor(struct CPosition const &)

HCURSOR MAP::SetCursor(HCURSOR hCursor)

{
  int iVar1;
  HCURSOR pHVar2;
  HCURSOR in_ECX;
  
                    // 0x7df3  35  ?SetCursor@MAP@@QAEXABUCPosition@@@Z
  pHVar2 = (HCURSOR)FUN_100089b0();
  if (hCursor->unused < (int)pHVar2) {
    pHVar2 = (HCURSOR)FUN_100089a0();
    if (hCursor[1].unused < (int)pHVar2) {
      iVar1 = hCursor[1].unused;
      in_ECX[0x10c].unused = hCursor->unused;
      in_ECX[0x10d].unused = iVar1;
      pHVar2 = in_ECX;
    }
  }
  return pHVar2;
}



// public: void __thiscall MAP::SelectTile(struct CPosition)

void __thiscall MAP::SelectTile(MAP *this,int param_2,int param_3)

{
  int iVar1;
  int *piVar2;
  
                    // 0x7e36  32  ?SelectTile@MAP@@QAEXUCPosition@@@Z
  iVar1 = FUN_100089b0();
  if (param_2 < iVar1) {
    iVar1 = FUN_100089a0();
    if (param_3 < iVar1) {
      piVar2 = (int *)FUN_10008970((int)this);
      (**(code **)(*piVar2 + 0x30))();
      *(int *)(this + 0x428) = param_2;
      *(int *)(this + 0x42c) = param_3;
      piVar2 = (int *)FUN_10008970((int)this);
      (**(code **)(*piVar2 + 0x30))();
    }
  }
  return;
}



// public: void __thiscall MAP::SwapTile(struct CPosition)

void __thiscall MAP::SwapTile(MAP *this,int param_2,int param_3)

{
  int iVar1;
  ITEM *pIVar2;
  undefined4 uVar3;
  
                    // 0x7ea0  43  ?SwapTile@MAP@@QAEXUCPosition@@@Z
  iVar1 = FUN_100089b0();
  if (param_2 < iVar1) {
    iVar1 = FUN_100089a0();
    if (param_3 < iVar1) {
      pIVar2 = GetItem(this,param_2,param_3);
      uVar3 = FUN_10008970((int)this);
      SetItem(this,*(undefined4 *)(this + 0x428),*(undefined4 *)(this + 0x42c),pIVar2);
      SetItem(this,param_2,param_3,uVar3);
      *(int *)(this + 0x428) = param_2;
      *(int *)(this + 0x42c) = param_3;
    }
  }
  return;
}



// public: int __thiscall MAP::GetScript(class CString &)const 

int __thiscall MAP::GetScript(MAP *this,CString *param_1)

{
  bool bVar1;
  CString *pCVar2;
  char *pcVar3;
  CString local_20 [4];
  CString local_1c [4];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x7f2d  17  ?GetScript@MAP@@QBEHAAVCString@@@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ec09;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pCVar2 = FUN_1000b46e(local_18);
  local_8 = 0;
  FUN_100053f0(local_14,pCVar2);
  local_8._0_1_ = 2;
  CString::~CString(local_18);
  STRING::strtok((char *)local_1c,(char *)&_Delim_1001325c);
  FUN_10002c40(local_1c);
  pCVar2 = (CString *)operator+((char *)local_20,(CString *)&param_2_10013260);
  local_8._0_1_ = 3;
  CString::operator+=(local_14,pCVar2);
  local_8 = CONCAT31(local_8._1_3_,2);
  CString::~CString(local_20);
  pcVar3 = (char *)FUN_1000a7a0((undefined4 *)local_14);
  bVar1 = exists(pcVar3);
  if (bVar1) {
    CString::operator=(param_1,local_14);
  }
  pcVar3 = (char *)FUN_1000a7a0((undefined4 *)local_14);
  bVar1 = exists(pcVar3);
  local_8 = 0xffffffff;
  FUN_10002c40(local_14);
  ExceptionList = local_10;
  return (uint)bVar1;
}



// public: class ITEM * __thiscall MAP::SetSelectedItem(class ITEM *)

ITEM * __thiscall MAP::SetSelectedItem(MAP *this,ITEM *param_1)

{
  ITEM *pIVar1;
  
                    // 0x804c  42  ?SetSelectedItem@MAP@@QAEPAVITEM@@PAV2@@Z
  pIVar1 = SetItem(this,*(undefined4 *)(this + 0x428),*(undefined4 *)(this + 0x42c),param_1);
  return pIVar1;
}



// public: class ITEM * __thiscall MAP::SetItem(struct CPosition,class ITEM *)

ITEM * __thiscall MAP::SetItem(MAP *this,int param_2,int param_3,int *param_4)

{
  ITEM *pIVar1;
  
                    // 0x8076  38  ?SetItem@MAP@@QAEPAVITEM@@UCPosition@@PAV2@@Z
  pIVar1 = *(ITEM **)(this + param_3 * 4 + param_2 * 0x34 + 4);
  FUN_10008a30(param_4,this);
  (**(code **)(*param_4 + 0x30))();
  (**(code **)(*param_4 + 0x28))(param_2,param_3);
  *(int **)(this + param_3 * 4 + param_2 * 0x34 + 4) = param_4;
  return pIVar1;
}



// public: class ITEM * __thiscall MAP::GetItem(struct CPosition)const 

ITEM * __thiscall MAP::GetItem(MAP *this,int param_2,int param_3)

{
  int iVar1;
  
                    // 0x80de  15  ?GetItem@MAP@@QBEPAVITEM@@UCPosition@@@Z
  iVar1 = FUN_100089b0();
  if ((param_2 < iVar1) && (iVar1 = FUN_100089a0(), param_3 < iVar1)) {
    return *(ITEM **)(this + param_3 * 4 + param_2 * 0x34 + 4);
  }
  return (ITEM *)0x0;
}



// public: static class LIST<class ITEM *> & __cdecl MAP::ItemList(void)

LIST<> * __cdecl MAP::ItemList(void)

{
                    // 0x811c  20  ?ItemList@MAP@@SAAAV?$LIST@PAVITEM@@@@XZ
  return (LIST<> *)&DAT_100151c0;
}



// public: static void __cdecl MAP::Cleanup(void)

void __cdecl MAP::Cleanup(void)

{
  bool bVar1;
  undefined3 extraout_var;
  uint uVar2;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  undefined3 extraout_var_03;
  CString *pCVar3;
  undefined4 *puVar4;
  undefined3 extraout_var_04;
  shared_ptr<> local_54 [4];
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 *local_48;
  undefined4 *local_44;
  undefined4 *local_40;
  undefined4 *local_3c;
  int local_38;
  int local_34;
  uint local_30;
  undefined4 *local_2c;
  undefined4 local_28;
  undefined4 local_24;
  int local_20;
  undefined4 *local_1c;
  uint local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x8126  5  ?Cleanup@MAP@@SAXXZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ec25;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_20 = FUN_100026f0(0x10015218);
  local_1c = (undefined4 *)0x0;
  local_30 = 0;
  bVar1 = IsEmpty(0x10015218);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_1c = (undefined4 *)FUN_10002380(&local_20);
    local_1c = (undefined4 *)*local_1c;
  }
  local_30 = 0;
  while ((uVar2 = FUN_10005970(0x10015218), local_30 < uVar2 &&
         (bVar1 = IsEmpty(0x10015218), CONCAT31(extraout_var_00,bVar1) == 0))) {
    local_40 = local_1c;
    local_3c = local_1c;
    if (local_1c != (undefined4 *)0x0) {
      (**(code **)*local_1c)(1);
    }
    local_30 = local_30 + 1;
    uVar2 = FUN_10005970(0x10015218);
    if (local_30 < uVar2) {
      local_1c = (undefined4 *)FUN_10002380(&local_20);
      local_1c = (undefined4 *)*local_1c;
    }
  }
  FUN_10008600(0x10015218);
  local_34 = FUN_100026f0(0x100151c0);
  local_2c = (undefined4 *)0x0;
  local_14 = 0;
  bVar1 = IsEmpty(0x100151c0);
  if (CONCAT31(extraout_var_01,bVar1) == 0) {
    local_2c = (undefined4 *)FUN_10006070(&local_34);
    local_2c = (undefined4 *)*local_2c;
  }
  local_14 = 0;
  while ((uVar2 = FUN_10005970(0x100151c0), local_14 < uVar2 &&
         (bVar1 = IsEmpty(0x100151c0), CONCAT31(extraout_var_02,bVar1) == 0))) {
    local_48 = local_2c;
    local_44 = local_2c;
    if (local_2c != (undefined4 *)0x0) {
      (**(code **)*local_2c)(1);
    }
    local_14 = local_14 + 1;
    uVar2 = FUN_10005970(0x100151c0);
    if (local_14 < uVar2) {
      local_2c = (undefined4 *)FUN_10006070(&local_34);
      local_2c = (undefined4 *)*local_2c;
    }
  }
  local_38 = FUN_100026f0(0x10015088);
  FUN_10002060((CString *)&local_28);
  local_8 = 0;
  local_18 = 0;
  bVar1 = IsEmpty(0x10015088);
  if (CONCAT31(extraout_var_03,bVar1) == 0) {
    pCVar3 = (CString *)FUN_10006070(&local_38);
    FUN_100021b0(&local_28,pCVar3);
  }
  local_18 = 0;
  while ((uVar2 = FUN_10005970(0x10015088), local_18 < uVar2 &&
         (bVar1 = IsEmpty(0x10015088), CONCAT31(extraout_var_04,bVar1) == 0))) {
    FUN_100022b0(local_54,0);
    local_8._0_1_ = 1;
    FUN_1000dcf0(&local_24,local_54);
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_10007600((int *)local_54);
    local_18 = local_18 + 1;
    uVar2 = FUN_10005970(0x10015088);
    if (local_18 < uVar2) {
      pCVar3 = (CString *)FUN_10006070(&local_38);
      puVar4 = (undefined4 *)FUN_100021b0(&local_28,pCVar3);
      local_50 = *puVar4;
      local_4c = puVar4[1];
    }
    else {
      local_50 = local_28;
      local_4c = local_24;
    }
  }
  FUN_100062f0(0x10015088);
  FUN_10008600(0x100151c0);
  local_8 = 0xffffffff;
  FUN_100020f0((CString *)&local_28);
  ExceptionList = local_10;
  return;
}



// public: static void __cdecl MAP::SetGammaLevel(unsigned int)

void __cdecl MAP::SetGammaLevel(uint param_1)

{
  ITEM *this;
  
                    // 0x83f1  37  ?SetGammaLevel@MAP@@SAXI@Z
  if (param_1 < 8) {
    this = FindItem(s_BLANK_10013264);
    FUN_100089e0(this,0,param_1);
  }
  return;
}



void * __thiscall FUN_10008430(void *this,uint param_1)

{
  MAP::~MAP((MAP *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void * __thiscall FUN_10008460(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ec4e;
  local_10 = ExceptionList;
  iVar2 = 0x104;
  puVar3 = param_1;
  puVar4 = (undefined4 *)this;
  ExceptionList = &local_10;
  while( true ) {
    puVar4 = puVar4 + 1;
    puVar3 = puVar3 + 1;
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    *puVar4 = *puVar3;
  }
  CString::CString((CString *)((int)this + 0x414),(CString *)(param_1 + 0x105));
  local_8 = 0;
  CString::CString((CString *)((int)this + 0x418),(CString *)(param_1 + 0x106));
  local_8 = CONCAT31(local_8._1_3_,1);
  CString::CString((CString *)((int)this + 0x41c),(CString *)(param_1 + 0x107));
  uVar1 = param_1[0x109];
  *(undefined4 *)((int)this + 0x420) = param_1[0x108];
  *(undefined4 *)((int)this + 0x424) = uVar1;
  uVar1 = param_1[0x10b];
  *(undefined4 *)((int)this + 0x428) = param_1[0x10a];
  *(undefined4 *)((int)this + 0x42c) = uVar1;
  uVar1 = param_1[0x10d];
  *(undefined4 *)((int)this + 0x430) = param_1[0x10c];
  *(undefined4 *)((int)this + 0x434) = uVar1;
  *(undefined1 *)((int)this + 0x438) = *(undefined1 *)(param_1 + 0x10e);
  *(undefined1 *)((int)this + 0x439) = *(undefined1 *)((int)param_1 + 0x439);
  *(undefined1 *)((int)this + 0x43a) = *(undefined1 *)((int)param_1 + 0x43a);
  *(undefined1 *)((int)this + 0x43b) = *(undefined1 *)((int)param_1 + 0x43b);
  *(undefined1 *)((int)this + 0x43c) = *(undefined1 *)(param_1 + 0x10f);
  *(undefined ***)this = &PTR_FUN_100103dc;
  ExceptionList = local_10;
  return this;
}



void * __thiscall FUN_100085c0(void *this,void *param_1)

{
  if (this != param_1) {
    FUN_10008600((int)this);
    FUN_10005a90(this,(int)param_1);
  }
  return this;
}



void __fastcall FUN_10008600(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_10006490(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



bool __fastcall FUN_10008680(int *param_1)

{
  int iVar1;
  
  iVar1 = FUN_100086a0(param_1);
  return *(int *)(iVar1 + 4) == 0;
}



int __fastcall FUN_100086a0(int *param_1)

{
  return *param_1 + -0xc;
}



CString * __cdecl FUN_100086c0(CString *param_1)

{
  bool bVar1;
  char cVar2;
  REG *this;
  CString *pCVar3;
  char *pcVar4;
  CString local_24 [4];
  CString local_20 [4];
  undefined4 local_1c;
  uint local_18;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_1000ec9b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(local_14);
  local_8 = 1;
  pCVar3 = local_14;
  pcVar4 = s_DataDir_10013284;
  this = (REG *)FUN_10008870(&local_1c,&param_3_100151e8,s_Software_Twilight__10013270);
  local_8._0_1_ = 2;
  bVar1 = REG::Get(this,pcVar4,pCVar3);
  local_18 = CONCAT31(local_18._1_3_,bVar1);
  local_8._0_1_ = 1;
  FUN_10008920(&local_1c);
  if ((local_18 & 0xff) == 0) {
    REG::RootDir();
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_14);
  }
  else {
    cVar2 = FUN_10008850(local_14,0);
    if ((cVar2 != '\\') && (cVar2 = FUN_10008850(local_14,1), cVar2 != ':')) {
      pCVar3 = (CString *)REG::RootDir();
      local_8._0_1_ = 3;
      pcVar4 = (char *)operator+(local_24,pCVar3);
      local_8._0_1_ = 4;
      operator+(param_1,pcVar4);
      local_8._0_1_ = 3;
      CString::~CString(local_24);
      local_8._0_1_ = 1;
      CString::~CString(local_20);
      local_8 = (uint)local_8._1_3_ << 8;
      CString::~CString(local_14);
      ExceptionList = local_10;
      return param_1;
    }
    operator+(param_1,(char *)local_14);
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_14);
  }
  ExceptionList = local_10;
  return param_1;
}



undefined1 __thiscall FUN_10008850(void *this,int param_1)

{
                    // WARNING: Load size is inaccurate
  return *(undefined1 *)(*this + param_1);
}



void * __thiscall FUN_10008870(void *this,undefined4 param_1,char *param_2)

{
  char *pcVar1;
  LPCSTR lpSubKey;
  DWORD Reserved;
  LPSTR lpClass;
  DWORD dwOptions;
  REGSAM samDesired;
  LPSECURITY_ATTRIBUTES lpSecurityAttributes;
  PHKEY phkResult;
  LPDWORD lpdwDisposition;
  CString local_1c [4];
  CString local_18 [4];
  DWORD local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &lpdwDisposition_1000ecc2;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pcVar1 = (char *)CString::CString(local_1c,param_2);
  local_8 = 0;
  operator+(local_18,pcVar1);
  local_8 = CONCAT31(local_8._1_3_,2);
  CString::~CString(local_1c);
  lpdwDisposition = (LPDWORD)0x0;
  lpSecurityAttributes = (LPSECURITY_ATTRIBUTES)0x0;
  samDesired = 0xf003f;
  dwOptions = 0;
  lpClass = (LPSTR)0x0;
  Reserved = 0;
  phkResult = (PHKEY)this;
  lpSubKey = (LPCSTR)FUN_1000a7a0((undefined4 *)local_18);
  local_14 = RegCreateKeyExA((HKEY)0x80000001,lpSubKey,Reserved,lpClass,dwOptions,samDesired,
                             lpSecurityAttributes,phkResult,lpdwDisposition);
  SetLastError(local_14);
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  ExceptionList = local_10;
  return this;
}



void __fastcall FUN_10008920(undefined4 *param_1)

{
  RegCloseKey((HKEY)*param_1);
  return;
}



undefined4 * __fastcall FUN_10008940(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  return param_1;
}



undefined4 __fastcall FUN_10008970(int param_1)

{
  return *(undefined4 *)
          (param_1 + 4 + *(int *)(param_1 + 0x428) * 0x34 + *(int *)(param_1 + 0x42c) * 4);
}



undefined4 FUN_100089a0(void)

{
  return 0xd;
}



undefined4 FUN_100089b0(void)

{
  return 0x14;
}



void __fastcall FUN_100089c0(TILEBLITTER *param_1)

{
  TILEBLITTER::SetSurfaceInfo(param_1);
  return;
}



void __thiscall FUN_100089e0(void *this,undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  
  iVar1 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
  *(undefined1 *)(iVar1 + 0x6c8) = 1;
  iVar1 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
  *(undefined4 *)(iVar1 + 0x6cc) = param_2;
  iVar1 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
  *(undefined4 *)(iVar1 + 0x6d0) = param_1;
  return;
}



void __thiscall FUN_10008a30(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 0x10) = param_1;
  return;
}



void FUN_10008a50(void)

{
  FUN_10002320((int *)&DAT_1001523c);
  return;
}



void FUN_10008a60(void)

{
  FUN_10002320((int *)&DAT_10015238);
  return;
}



void * __thiscall FUN_10008a70(void *this,void *param_1)

{
  int iVar1;
  
  iVar1 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
  FUN_10007640(param_1,(undefined4 *)(iVar1 + 0x754));
  return param_1;
}



void * __thiscall FUN_10008ab0(void *this,void *param_1)

{
  int iVar1;
  
  iVar1 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
  FUN_10007640(param_1,(undefined4 *)(iVar1 + 0x758));
  return param_1;
}



void * __thiscall FUN_10008af0(void *this,void *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined1 local_74 [8];
  undefined4 local_6c [7];
  int local_50 [2];
  undefined1 local_48 [8];
  undefined1 local_40 [8];
  undefined1 local_38 [8];
  undefined1 local_30 [8];
  undefined1 local_28 [8];
  undefined1 local_20 [8];
  undefined1 local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ecf0;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  default_error_condition(local_50,0,0xffffffff);
  default_error_condition(local_48,1,0xffffffff);
  default_error_condition(local_40,1,0);
  default_error_condition(local_38,1,1);
  default_error_condition(local_30,0,1);
  default_error_condition(local_28,0xffffffff,1);
  default_error_condition(local_20,0xffffffff,0);
  default_error_condition(local_18,0xffffffff,0xffffffff);
  iVar1 = FUN_1000a7a0((undefined4 *)((int)this + 4));
  puVar2 = (undefined4 *)
           FUN_10006850((void *)((int)this + 0xc),local_74,local_50 + (iVar1 >> 1) * 2);
  FUN_10006940(local_6c,*(undefined4 *)((int)this + 4),*(undefined4 *)((int)this + 8),*puVar2,
               puVar2[1]);
  local_8 = 1;
  FUN_10002790(param_1,(int)local_6c);
  local_8 = local_8 & 0xffffff00;
  FUN_10001ce0(local_6c);
  ExceptionList = local_10;
  return param_1;
}



undefined4 __thiscall FUN_10008bed(void *this,int *param_1)

{
  bool bVar1;
  int iVar2;
  uint *puVar3;
  int *piVar4;
  undefined4 local_30 [7];
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ed03;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_14 = FUN_100026f0((int)this);
  do {
    if (local_14 == 0) {
      ExceptionList = local_10;
      return 0;
    }
    iVar2 = FUN_10006070(&local_14);
    FUN_10002790(local_30,iVar2);
    local_8 = 0;
    puVar3 = (uint *)FUN_10001d70((int)local_30);
    bVar1 = FUN_10002b40(puVar3);
    if (bVar1) {
      iVar2 = *param_1;
      piVar4 = (int *)FUN_10001f70((int)local_30);
      bVar1 = FUN_10006ad0(*piVar4,iVar2);
      if (bVar1) {
        local_8 = 0xffffffff;
        FUN_10001ce0(local_30);
        ExceptionList = local_10;
        return 1;
      }
    }
    local_8 = 0xffffffff;
    FUN_10001ce0(local_30);
  } while( true );
}



undefined4 __thiscall FUN_10008cb7(void *this,int *param_1)

{
  bool bVar1;
  int iVar2;
  uint *puVar3;
  int *piVar4;
  void *this_00;
  undefined4 local_5c [7];
  undefined4 local_40 [7];
  int local_24;
  int local_20;
  int local_1c;
  undefined4 local_18;
  char local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ed1f;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  iVar2 = FUN_10002c10(param_1);
  if (iVar2 == 0) {
    local_24 = FUN_100026f0((int)this);
    while (local_24 != 0) {
      iVar2 = FUN_10006070(&local_24);
      FUN_10002790(local_40,iVar2);
      local_8 = 0;
      puVar3 = (uint *)FUN_10001d70((int)local_40);
      bVar1 = FUN_10002b40(puVar3);
      if (bVar1) {
        local_8 = 0xffffffff;
        FUN_10001ce0(local_40);
        ExceptionList = local_10;
        return 0;
      }
      local_8 = 0xffffffff;
      FUN_10001ce0(local_40);
    }
    local_18 = 1;
  }
  else {
    iVar2 = FUN_10005970((int)this);
    if (iVar2 == 0) {
      local_18 = 0;
    }
    else {
      local_14[0] = '\x01';
      local_18 = 0;
      FUN_10002ab0(&local_1c);
      local_20 = FUN_100026f0((int)this);
      while (local_20 != 0) {
        iVar2 = FUN_10006070(&local_20);
        FUN_10002790(local_5c,iVar2);
        local_8 = 1;
        puVar3 = (uint *)FUN_10001d70((int)local_5c);
        bVar1 = FUN_10002b40(puVar3);
        if (bVar1) {
          bVar1 = FUN_10002730(local_14,'\0');
          if (bVar1) {
            piVar4 = (int *)FUN_10001d70((int)local_5c);
            local_1c = *piVar4;
          }
          iVar2 = *param_1;
          piVar4 = (int *)FUN_10001f70((int)local_5c);
          bVar1 = FUN_10006ad0(*piVar4,iVar2);
          if (!bVar1) {
LAB_10008e3d:
            local_8 = 0xffffffff;
            FUN_10001ce0(local_5c);
            ExceptionList = local_10;
            return 0;
          }
          piVar4 = &local_1c;
          this_00 = (void *)FUN_10001d70((int)local_5c);
          bVar1 = FUN_10006830(this_00,piVar4);
          if (!bVar1) goto LAB_10008e3d;
          local_18 = 1;
        }
        local_8 = 0xffffffff;
        FUN_10001ce0(local_5c);
      }
    }
  }
  ExceptionList = local_10;
  return local_18;
}



void __fastcall FUN_10008e7f(void *param_1)

{
  bool bVar1;
  char cVar2;
  uint *puVar3;
  undefined4 *puVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  void *pvVar8;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 uVar9;
  undefined1 *puVar10;
  undefined1 local_50 [4];
  undefined4 local_4c;
  undefined1 *local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined1 *local_3c;
  undefined4 local_38 [7];
  int *local_1c;
  int *local_18;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_1000ed3b;
  local_10 = ExceptionList;
  local_8 = 0;
  local_14 = 1;
  ExceptionList = &local_10;
  puVar3 = (uint *)FUN_10001d70((int)&stack0x00000004);
  bVar1 = FUN_10002b40(puVar3);
  if (bVar1) {
    puVar4 = (undefined4 *)FUN_10001d70((int)&stack0x00000004);
    uVar5 = FUN_1000a7a0(puVar4);
    uVar5 = uVar5 & 0x80000007;
    if ((int)uVar5 < 0) {
      uVar5 = (uVar5 - 1 | 0xfffffff8) + 1;
    }
    local_3c = &stack0xffffffa8;
    uVar9 = extraout_ECX;
    FUN_10002ad0(&stack0xffffffa8,uVar5);
    FUN_10009470(&stack0x00000004,uVar9);
  }
  do {
    if (local_14 == 0) {
      FUN_10005990(param_1,(int)&stack0x00000004);
      local_8 = 0xffffffff;
      FUN_10001ce0((undefined4 *)&stack0x00000004);
      ExceptionList = local_10;
      return;
    }
    local_18 = (int *)FUN_100026f0((int)param_1);
    local_14 = 0;
    while (local_18 != (int *)0x0) {
      local_1c = local_18;
      iVar6 = FUN_10006070((int *)&local_18);
      FUN_10002790(local_38,iVar6);
      local_8._0_1_ = 1;
      piVar7 = (int *)FUN_10001d70((int)&stack0x00000004);
      pvVar8 = (void *)FUN_10001d70((int)local_38);
      bVar1 = FUN_10006830(pvVar8,piVar7);
      if (bVar1) {
        piVar7 = (int *)FUN_10006af0((int)&stack0x00000004);
        pvVar8 = (void *)FUN_10006af0((int)local_38);
        bVar1 = FUN_100093e0(pvVar8,piVar7);
        if (bVar1) {
          piVar7 = (int *)FUN_10006b30((int)&stack0x00000004);
          pvVar8 = (void *)FUN_10006b30((int)local_38);
          bVar1 = FUN_100093e0(pvVar8,piVar7);
          if (bVar1) {
            puVar3 = (uint *)FUN_10001f70((int)local_38);
            FUN_10009490(&stack0x00000004,*puVar3);
            FUN_100092d0(param_1,local_1c);
            local_14 = 1;
            local_8 = (uint)local_8._1_3_ << 8;
            FUN_10001ce0(local_38);
            break;
          }
        }
      }
      piVar7 = (int *)FUN_10001d70((int)&stack0x00000004);
      pvVar8 = (void *)FUN_10001d70((int)local_38);
      bVar1 = FUN_10006830(pvVar8,piVar7);
      if (bVar1) {
        piVar7 = (int *)FUN_10006b30((int)local_38);
        cVar2 = FUN_10006920(piVar7);
        if (cVar2 == '\0') {
          piVar7 = (int *)FUN_10006b30((int)&stack0x00000004);
          cVar2 = FUN_10006920(piVar7);
          if (cVar2 == '\0') {
            piVar7 = (int *)FUN_10006af0((int)local_38);
            cVar2 = FUN_10006920(piVar7);
            if (cVar2 == '\0') {
              puVar3 = (uint *)FUN_10001f70((int)&stack0x00000004);
              uVar5 = *puVar3;
              pvVar8 = (void *)FUN_10001f70((int)local_38);
              bVar1 = FUN_10002bf0(pvVar8,uVar5);
              if (bVar1) goto LAB_1000918f;
            }
            piVar7 = (int *)FUN_10006af0((int)&stack0x00000004);
            cVar2 = FUN_10006920(piVar7);
            if (cVar2 == '\0') {
              puVar3 = (uint *)FUN_10001f70((int)local_38);
              uVar5 = *puVar3;
              pvVar8 = (void *)FUN_10001f70((int)&stack0x00000004);
              bVar1 = FUN_10002bf0(pvVar8,uVar5);
              if (bVar1) goto LAB_1000918f;
            }
            puVar4 = &local_44;
            pvVar8 = (void *)FUN_10006af0((int)&stack0x00000004);
            piVar7 = base(pvVar8,puVar4);
            puVar4 = &local_40;
            pvVar8 = (void *)FUN_10006af0((int)local_38);
            puVar4 = base(pvVar8,puVar4);
            bVar1 = FUN_10009340(puVar4,piVar7);
            if (bVar1) {
              piVar7 = (int *)FUN_10001f70((int)&stack0x00000004);
              iVar6 = *piVar7;
              piVar7 = (int *)FUN_10001f70((int)local_38);
              bVar1 = FUN_10006ad0(*piVar7,iVar6);
              if (bVar1) goto LAB_1000918f;
            }
            piVar7 = (int *)FUN_10006af0((int)&stack0x00000004);
            cVar2 = FUN_10006920(piVar7);
            if (cVar2 == '\0') {
              puVar3 = (uint *)FUN_10001f70((int)&stack0x00000004);
              uVar5 = *puVar3;
              pvVar8 = (void *)FUN_10001f70((int)local_38);
              bVar1 = FUN_10002bf0(pvVar8,uVar5);
              if (bVar1) {
                puVar10 = local_50;
                puVar4 = &local_4c;
                pvVar8 = (void *)FUN_10006af0((int)local_38);
                puVar4 = base(pvVar8,puVar4);
                puVar4 = (undefined4 *)FUN_10006790(puVar4,puVar10);
                local_48 = &stack0xffffffa8;
                uVar9 = extraout_ECX_00;
                FUN_10001cc0(&stack0xffffffa8,*puVar4);
                FUN_10006b10(&stack0x00000004,uVar9);
                local_14 = 1;
                local_8 = (uint)local_8._1_3_ << 8;
                FUN_10001ce0(local_38);
                break;
              }
            }
          }
        }
      }
LAB_1000918f:
      local_8 = (uint)local_8._1_3_ << 8;
      FUN_10001ce0(local_38);
    }
  } while( true );
}



void __fastcall FUN_100091d0(int param_1)

{
  int iVar1;
  void *pvVar2;
  int *piVar3;
  undefined *puVar4;
  undefined *puVar5;
  undefined *puVar6;
  undefined4 *puVar7;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30 [7];
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ed4e;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_14 = FUN_100026f0(param_1);
  while (local_14 != 0) {
    iVar1 = FUN_10006070(&local_14);
    FUN_10002790(local_30,iVar1);
    local_8 = 0;
    FUN_10006b30((int)local_30);
    FUN_100093d0();
    puVar7 = &local_34;
    pvVar2 = (void *)FUN_10006b30((int)local_30);
    piVar3 = base(pvVar2,puVar7);
    FUN_100093a0(piVar3);
    FUN_10006af0((int)local_30);
    FUN_100093d0();
    puVar7 = &local_38;
    pvVar2 = (void *)FUN_10006af0((int)local_30);
    piVar3 = base(pvVar2,puVar7);
    puVar4 = FUN_100093a0(piVar3);
    piVar3 = (int *)FUN_10001d70((int)local_30);
    puVar5 = FUN_10009370(piVar3);
    piVar3 = (int *)FUN_10001f70((int)local_30);
    puVar6 = FUN_10009450(piVar3);
    GKERNEL::DebugTrace(s__s__s__s__2d__s__2d_1001328c,puVar6,puVar5,puVar4);
    local_8 = 0xffffffff;
    FUN_10001ce0(local_30);
  }
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_100092d0(void *this,int *param_1)

{
  if (param_1 == *(int **)((int)this + 4)) {
    *(int *)((int)this + 4) = *param_1;
  }
  else {
    *(int *)param_1[1] = *param_1;
  }
  if (param_1 == *(int **)((int)this + 8)) {
    *(int *)((int)this + 8) = param_1[1];
  }
  else {
    *(int *)(*param_1 + 4) = param_1[1];
  }
  FUN_10002850(this,param_1);
  return;
}



bool __thiscall FUN_10009340(void *this,int *param_1)

{
  int iVar1;
  
                    // WARNING: Load size is inaccurate
  iVar1 = abs(*param_1 - *this);
  return iVar1 == 8;
}



undefined * __fastcall FUN_10009370(int *param_1)

{
  bool bVar1;
  undefined *puVar2;
  
  bVar1 = FUN_10006770(param_1);
  if (bVar1) {
    puVar2 = (&PTR_DAT_100132c8)[*param_1];
  }
  else {
    puVar2 = &DAT_100132c4;
  }
  return puVar2;
}



undefined * __fastcall FUN_100093a0(int *param_1)

{
  bool bVar1;
  undefined *puVar2;
  
  bVar1 = FUN_10006770(param_1);
  if (bVar1) {
    puVar2 = (&PTR_DAT_10013348)[*param_1];
  }
  else {
    puVar2 = &DAT_10013344;
  }
  return puVar2;
}



undefined4 FUN_100093d0(void)

{
  return 0;
}



bool __thiscall FUN_100093e0(void *this,int *param_1)

{
  char cVar1;
  
  cVar1 = FUN_10006920(param_1);
  if (cVar1 == '\0') {
    cVar1 = FUN_10006920((int *)this);
    cVar1 = '\x01' - (cVar1 != '\0');
  }
  else {
    cVar1 = FUN_10006920((int *)this);
    if (cVar1 == '\0') {
      cVar1 = FUN_10006920(param_1);
      cVar1 = '\x01' - (cVar1 != '\0');
    }
    else {
      cVar1 = FUN_10006830(this,param_1);
    }
  }
  return (bool)cVar1;
}



undefined * __fastcall FUN_10009450(int *param_1)

{
  return (&PTR_s_BLACK_100133c8)[*param_1];
}



void __thiscall FUN_10009470(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 4) = param_1;
  return;
}



void __thiscall FUN_10009490(void *this,uint param_1)

{
  FUN_100094b0((void *)((int)this + 8),param_1);
  return;
}



void __thiscall FUN_100094b0(void *this,uint param_1)

{
                    // WARNING: Load size is inaccurate
  *(uint *)this = *this | param_1;
  return;
}



void FUN_100094d0(void)

{
  FUN_100094df();
  FUN_100094ee();
  return;
}



void FUN_100094df(void)

{
  CString::CString((CString *)&param_2_100151f0);
  return;
}



void FUN_100094ee(void)

{
  FUN_1000e1a8(FUN_10009500);
  return;
}



void FUN_10009500(void)

{
  if ((DAT_100151ec & 1) == 0) {
    DAT_100151ec = DAT_100151ec | 1;
    CString::~CString((CString *)&param_2_100151f0);
  }
  return;
}



// public: bool __thiscall MAP::Save(struct LEVEL)

bool __thiscall MAP::Save(MAP *this,uint param_2,undefined4 param_3)

{
  char cVar1;
  bool bVar2;
  CString *pCVar3;
  char *pcVar4;
  CString local_18 [4];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x952c  30  ?Save@MAP@@QAE_NULEVEL@@@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ed69;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  cVar1 = FUN_100013e0(&param_2);
  if (cVar1 == '\0') {
    bVar2 = false;
  }
  else {
    pCVar3 = FUN_1000b46e(local_18);
    local_8 = 0;
    pcVar4 = (char *)FUN_1000a7a0((undefined4 *)pCVar3);
    bVar2 = SaveAs(this,pcVar4);
    local_14 = CONCAT31(local_14._1_3_,bVar2);
    local_8 = 0xffffffff;
    CString::~CString(local_18);
    if ((local_14 & 0xff) == 0) {
      bVar2 = false;
    }
    else {
      bVar2 = true;
    }
  }
  ExceptionList = local_10;
  return bVar2;
}



// public: bool __thiscall MAP::SaveAs(char const *)

bool __thiscall MAP::SaveAs(MAP *this,char *param_1)

{
  undefined1 uVar1;
  char *pcVar2;
  int iVar3;
  CString local_74 [8];
  CFile local_6c [16];
  CArchive local_5c [68];
  CString local_18 [4];
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x95cf  31  ?SaveAs@MAP@@QAE_NPBD@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ed8e;
  local_10 = ExceptionList;
  local_14 = &stack0xffffff64;
  ExceptionList = &local_10;
  FUN_10006db0(local_18,param_1);
  local_8 = 0;
  STRING::strtok((char *)local_74,(char *)&_Delim_1001384c);
  FUN_10002c40(local_74);
  pcVar2 = (char *)FUN_1000a7a0((undefined4 *)local_18);
  iVar3 = MakeDirectory(pcVar2);
  if (iVar3 == 0) {
    local_8 = 0xffffffff;
    FUN_10002c40(local_18);
    ExceptionList = local_10;
    return false;
  }
  local_8._0_1_ = 1;
  CFile::CFile(local_6c,param_1,0x1002);
  local_8._0_1_ = 2;
  CArchive::CArchive(local_5c,local_6c,0,0x1000,(void *)0x0);
  local_8._0_1_ = 3;
  FUN_1000973f(this,local_5c);
  local_8._0_1_ = 2;
  CArchive::~CArchive(local_5c);
  local_8 = CONCAT31(local_8._1_3_,1);
  CFile::~CFile(local_6c);
  uVar1 = FUN_10009703();
  return (bool)uVar1;
}



undefined * Catch_100096be(void)

{
  int unaff_EBP;
  
  if (*(int *)(*(int *)(unaff_EBP + -0x6c) + 8) == 2) {
    CException::Delete(*(CException **)(unaff_EBP + -0x6c));
    *(undefined1 *)(unaff_EBP + -0x7c) = 0;
    return &DAT_100096ef;
  }
  *(undefined4 *)(unaff_EBP + -0x78) = *(undefined4 *)(unaff_EBP + -0x6c);
                    // WARNING: Subroutine does not return
  _CxxThrowException((void *)(unaff_EBP + -0x78),(ThrowInfo *)&pThrowInfo_100113a8);
}



undefined1 FUN_10009703(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -4) = 0;
  MAP::RecalculatePath(*(char **)(unaff_EBP + 8));
  *(undefined1 *)(unaff_EBP + -0x80) = 1;
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  FUN_10002c40((CString *)(unaff_EBP + -0x14));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return *(undefined1 *)(unaff_EBP + -0x80);
}



void __thiscall FUN_1000973f(void *this,CArchive *param_1)

{
  undefined4 *puVar1;
  char *pcVar2;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_1000eda1;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  puVar1 = (undefined4 *)MAP::Data((MAP *)this);
  local_8 = 0;
  pcVar2 = (char *)FUN_1000a7a0(puVar1);
  CArchive::WriteString(param_1,pcVar2);
  local_8 = 0xffffffff;
  FUN_10002c40(local_14);
  ExceptionList = local_10;
  return;
}



// public: static class CString __cdecl MAP::GetLevelData(struct LEVEL)

CString * __cdecl MAP::GetLevelData(CString *param_1,uint param_2,int param_3)

{
  char cVar1;
  bool bVar2;
  CString *pCVar3;
  char *pcVar4;
  undefined4 uVar5;
  LPCSTR pCVar6;
  int iVar7;
  CString local_24 [4];
  CString local_20 [4];
  uint local_1c;
  int local_18 [2];
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
                    // 0x97a9  16  ?GetLevelData@MAP@@SA?AVCString@@ULEVEL@@@Z
  local_8 = 0xffffffff;
  puStack_c = &param_1_1000eddd;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  cVar1 = FUN_100013e0(&param_2);
  if (cVar1 == '\0') {
    CString::CString(param_1,PTR_s__3_n_4_n_4Xn_4_n_4_n_4_n_4_n_4_n_100133e8);
  }
  else {
    pCVar3 = FUN_1000b46e(local_20);
    local_8 = 1;
    pcVar4 = (char *)FUN_1000a7a0((undefined4 *)pCVar3);
    bVar2 = exists(pcVar4);
    local_1c = CONCAT31(local_1c._1_3_,'\x01' - bVar2);
    local_8 = local_8 & 0xffffff00;
    CString::~CString(local_20);
    if ((local_1c & 0xff) == 0) {
      uVar5 = FUN_10001007(param_2,param_3);
      s___AVtype_info___10013c18[param_3 + (param_2 - 1) * 0x1e + 0xf] = (char)uVar5;
      bVar2 = Exists(param_2,param_3);
      if (bVar2) {
        pCVar3 = FUN_1000b46e(local_24);
        local_8 = 2;
        pCVar6 = (LPCSTR)FUN_1000a7a0((undefined4 *)pCVar3);
        FUN_1000a6a0(local_18,pCVar6);
        local_8._0_1_ = 4;
        CString::~CString(local_24);
        iVar7 = FUN_100026f0((int)local_18);
        pcVar4 = (char *)FUN_1000a7a0(local_18);
        CString::CString(param_1,pcVar4,iVar7);
        local_8 = (uint)local_8._1_3_ << 8;
        FUN_1000a780(local_18);
      }
      else {
        CString::CString(param_1,PTR_s__3_n_4_n_4Xn_4_n_4_n_4_n_4_n_4_n_100133e8);
      }
    }
    else {
      CString::CString(param_1,PTR_s__3_n_4_n_4Xn_4_n_4_n_4_n_4_n_4_n_100133e8);
    }
  }
  ExceptionList = local_10;
  return param_1;
}



// public: bool __thiscall MAP::Load(struct LEVEL)

bool __thiscall MAP::Load(MAP *this,undefined4 param_2,undefined4 param_3)

{
  bool bVar1;
  undefined1 uVar2;
  CString *pCVar3;
  char *pcVar4;
  CString local_78 [4];
  CString local_74 [12];
  CFile local_68 [16];
  CArchive local_58 [68];
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x9950  21  ?Load@MAP@@QAE_NULEVEL@@@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ee14;
  local_10 = ExceptionList;
  local_14 = &stack0xffffff54;
  ExceptionList = &local_10;
  *(undefined4 *)(this + 0x420) = param_2;
  *(undefined4 *)(this + 0x424) = param_3;
  bVar1 = Exists(param_2,param_3);
  if (!bVar1) {
    CString::CString(local_74,PTR_s__3_n_4_n_4Xn_4_n_4_n_4_n_4_n_4_n_100133e8);
    local_8 = 0;
    Set(this,local_74);
    local_8 = 0xffffffff;
    CString::~CString(local_74);
    ExceptionList = local_10;
    return false;
  }
  local_8 = 1;
  pCVar3 = FUN_1000b46e(local_78);
  local_8._0_1_ = 2;
  pcVar4 = (char *)FUN_1000a7a0((undefined4 *)pCVar3);
  CFile::CFile(local_68,pcVar4,0);
  local_8._0_1_ = 4;
  CString::~CString(local_78);
  CArchive::CArchive(local_58,local_68,1,0x1000,(void *)0x0);
  local_8._0_1_ = 5;
  FUN_10009b40(this,local_58);
  local_8._0_1_ = 4;
  CArchive::~CArchive(local_58);
  local_8 = CONCAT31(local_8._1_3_,1);
  CFile::~CFile(local_68);
  uVar2 = FUN_10009b24();
  return (bool)uVar2;
}



undefined * Catch_10009a97(void)

{
  int unaff_EBP;
  
  if ((*(int *)(*(int *)(unaff_EBP + -0x6c) + 8) == 2) ||
     (*(int *)(*(int *)(unaff_EBP + -0x6c) + 8) == 3)) {
    *(undefined4 *)(unaff_EBP + -0x9c) = 1;
  }
  else {
    *(undefined4 *)(unaff_EBP + -0x9c) = 0;
  }
  *(undefined4 *)(unaff_EBP + -0x68) = *(undefined4 *)(unaff_EBP + -0x9c);
  CException::Delete(*(CException **)(unaff_EBP + -0x6c));
  CString::CString((CString *)(unaff_EBP + -0x78),PTR_s__3_n_4_n_4Xn_4_n_4_n_4_n_4_n_4_n_100133e8);
  *(undefined1 *)(unaff_EBP + -4) = 7;
  MAP::Set(*(MAP **)(unaff_EBP + -0x84),(CString *)(unaff_EBP + -0x78));
  *(undefined1 *)(unaff_EBP + -4) = 6;
  CString::~CString((CString *)(unaff_EBP + -0x78));
  *(bool *)(unaff_EBP + -0x7c) = *(int *)(unaff_EBP + -0x68) != 0;
  return &DAT_10009b10;
}



undefined * Catch_10009b15(void)

{
  int unaff_EBP;
  
  *(undefined1 *)(unaff_EBP + -0x80) = 0;
  return &DAT_10009b1f;
}



undefined1 FUN_10009b24(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return 1;
}



void __thiscall FUN_10009b40(void *this,CArchive *param_1)

{
  bool bVar1;
  int iVar2;
  CString *pCVar3;
  undefined4 local_20;
  CString local_1c [4];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_1000ee39;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(local_18);
  local_8 = 0;
  CString::CString(local_14);
  local_8._0_1_ = 1;
  while( true ) {
    iVar2 = CArchive::ReadString(param_1,local_14);
    if (iVar2 == 0) break;
    pCVar3 = (CString *)operator+(local_1c,(char *)local_14);
    local_8._0_1_ = 2;
    CString::operator+=(local_18,pCVar3);
    local_8._0_1_ = 1;
    CString::~CString(local_1c);
  }
  bVar1 = MAP::Set((MAP *)this,local_18);
  if (!bVar1) {
    local_20 = 1;
                    // WARNING: Subroutine does not return
    _CxxThrowException(&local_20,(ThrowInfo *)&pThrowInfo_100113e0);
  }
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(local_14);
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  ExceptionList = local_10;
  return;
}



// public: bool __thiscall MAP::Set(class CString const &)

bool __thiscall MAP::Set(MAP *this,CString *param_1)

{
  bool bVar1;
  undefined4 *puVar2;
  CString *pCVar3;
  undefined3 extraout_var;
  STRING *pSVar4;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  char **ppcVar5;
  CString local_a8 [4];
  CString local_a4 [4];
  undefined1 local_a0;
  CString local_9c [4];
  undefined1 *local_98;
  CString local_94 [4];
  CString local_90 [4];
  undefined1 local_8c;
  CString local_88 [4];
  undefined1 *local_84;
  CString local_80 [4];
  CString local_7c [4];
  undefined1 local_78;
  CString local_74 [4];
  CString local_70 [4];
  undefined1 local_6c [8];
  ITEM *local_64;
  ITEM *local_60;
  undefined1 local_5c [4];
  undefined1 *local_58;
  undefined1 *local_54;
  undefined1 *local_50;
  undefined1 *local_4c;
  char *local_48;
  int *local_44;
  char local_40;
  uint local_3c;
  char local_38;
  uint local_34;
  ITEM *local_30;
  int local_2c;
  uint local_28;
  CString local_24 [4];
  undefined4 local_20;
  uint local_1c;
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x9c17  33  ?Set@MAP@@QAE_NABVCString@@@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000eea9;
  local_10 = ExceptionList;
  local_4c = &stack0xfffffef4;
  ExceptionList = &local_10;
  CString::CString((CString *)&stack0xfffffef4,(char *)&this_100151f4);
  Rename(this);
  local_50 = &stack0xfffffef4;
  CString::CString((CString *)&stack0xfffffef4,(char *)&this_100151f8);
  SetScript(this);
  local_54 = &stack0xfffffef4;
  CString::CString((CString *)&stack0xfffffef4,(char *)&this_100151fc);
  SetCopyrightString(this);
  local_1c = 0;
  do {
    if (0xc < local_1c) {
      local_20 = 0x42a;
      pCVar3 = (CString *)CString::Mid(param_1,(int)local_70);
      local_8 = 0;
      FUN_100053f0(local_14,pCVar3);
      local_8._0_1_ = 2;
      CString::~CString(local_70);
      CString::CString(local_18);
      local_8._0_1_ = 3;
      FUN_10002c20(local_24);
      local_8._0_1_ = 4;
      CString::operator=(local_18,&DAT_10015200);
      pCVar3 = (CString *)STRING::strtok((char *)local_74,(char *)&_Delim_10013854);
      local_8._0_1_ = 5;
      FUN_100021e0(local_24,pCVar3);
      local_8._0_1_ = 4;
      FUN_10002c40(local_74);
      bVar1 = FUN_10008680((int *)local_24);
      if (CONCAT31(extraout_var,bVar1) == 0) {
        bVar1 = STRING::headequi((STRING *)local_24,s_MAPTEXT___10013858);
        if (!bVar1) {
          local_78 = 0;
          local_8._0_1_ = 3;
          FUN_10002c40(local_24);
          local_8 = CONCAT31(local_8._1_3_,2);
          CString::~CString(local_18);
          local_8 = 0xffffffff;
          FUN_10002c40(local_14);
          ExceptionList = local_10;
          return (bool)local_78;
        }
        STRING::strtok((char *)local_7c,(char *)&_Delim_10013864);
        FUN_10002c40(local_7c);
        ppcVar5 = &param_1_1001386c;
        pSVar4 = (STRING *)STRING::strtok((char *)local_80,(char *)&_Delim_10013868);
        local_8._0_1_ = 6;
        pSVar4 = STRING::trim(pSVar4,(char *)ppcVar5);
        CString::operator=(local_18,(CString *)pSVar4);
        local_8._0_1_ = 4;
        FUN_10002c40(local_80);
      }
      local_84 = &stack0xfffffef0;
      CString::CString((CString *)&stack0xfffffef0,local_18);
      Rename(this);
      CString::operator=(local_18,&DAT_10015204);
      pCVar3 = (CString *)STRING::strtok((char *)local_88,(char *)&_Delim_10013874);
      local_8._0_1_ = 7;
      FUN_100021e0(local_24,pCVar3);
      local_8._0_1_ = 4;
      FUN_10002c40(local_88);
      bVar1 = FUN_10008680((int *)local_24);
      if (CONCAT31(extraout_var_00,bVar1) == 0) {
        bVar1 = STRING::headequi((STRING *)local_24,s_SCRIPT___10013878);
        if (!bVar1) {
          local_8c = 0;
          local_8._0_1_ = 3;
          FUN_10002c40(local_24);
          local_8 = CONCAT31(local_8._1_3_,2);
          CString::~CString(local_18);
          local_8 = 0xffffffff;
          FUN_10002c40(local_14);
          ExceptionList = local_10;
          return (bool)local_8c;
        }
        STRING::strtok((char *)local_90,(char *)&_Delim_10013884);
        FUN_10002c40(local_90);
        ppcVar5 = &param_1_1001388c;
        pSVar4 = (STRING *)STRING::strtok((char *)local_94,(char *)&_Delim_10013888);
        local_8._0_1_ = 8;
        pSVar4 = STRING::trim(pSVar4,(char *)ppcVar5);
        CString::operator=(local_18,(CString *)pSVar4);
        local_8._0_1_ = 4;
        FUN_10002c40(local_94);
      }
      local_98 = &stack0xfffffef0;
      CString::CString((CString *)&stack0xfffffef0,local_18);
      SetScript(this);
      CString::operator=(local_18,&DAT_10015208);
      pCVar3 = (CString *)STRING::strtok((char *)local_9c,(char *)&_Delim_10013894);
      local_8._0_1_ = 9;
      FUN_100021e0(local_24,pCVar3);
      local_8._0_1_ = 4;
      FUN_10002c40(local_9c);
      bVar1 = FUN_10008680((int *)local_24);
      if (CONCAT31(extraout_var_01,bVar1) == 0) {
        bVar1 = STRING::headequi((STRING *)local_24,s_COPYRIGHT___10013898);
        if (!bVar1) {
          local_a0 = 0;
          local_8._0_1_ = 3;
          FUN_10002c40(local_24);
          local_8 = CONCAT31(local_8._1_3_,2);
          CString::~CString(local_18);
          local_8 = 0xffffffff;
          FUN_10002c40(local_14);
          ExceptionList = local_10;
          return (bool)local_a0;
        }
        STRING::strtok((char *)local_a4,(char *)&_Delim_100138a4);
        FUN_10002c40(local_a4);
        ppcVar5 = &param_1_100138ac;
        pSVar4 = (STRING *)STRING::strtok((char *)local_a8,(char *)&_Delim_100138a8);
        local_8._0_1_ = 10;
        pSVar4 = STRING::trim(pSVar4,(char *)ppcVar5);
        CString::operator=(local_18,(CString *)pSVar4);
        local_8._0_1_ = 4;
        FUN_10002c40(local_a8);
      }
      CString::CString((CString *)&stack0xfffffef0,local_18);
      SetCopyrightString(this);
      local_8._0_1_ = 3;
      FUN_10002c40(local_24);
      local_8 = CONCAT31(local_8._1_3_,2);
      CString::~CString(local_18);
      local_8 = 0xffffffff;
      FUN_10002c40(local_14);
      ExceptionList = local_10;
      return true;
    }
    local_2c = FUN_1000a7a0((undefined4 *)param_1);
    local_2c = local_2c + local_1c * 0x52;
    for (local_28 = 0; local_28 < 0x14; local_28 = local_28 + 1) {
      local_48 = (char *)(local_2c + local_28 * 4);
      local_30 = FindItem(*local_48);
      if (local_30 == (ITEM *)0x0) {
        Clear(this);
        ExceptionList = local_10;
        return false;
      }
      local_44 = (int *)(**(code **)(*(int *)local_30 + 4))();
      local_34 = (uint)local_48[1];
      if (local_34 == 0x20) {
        local_34 = 0x30;
      }
      if ((local_34 < 0x30) || (0x37 < local_34)) {
        ExceptionList = local_10;
        return false;
      }
      local_58 = &stack0xfffffef4;
      FUN_10002ad0(&stack0xfffffef4,local_34 * 2 - 0x60);
      (**(code **)(*local_44 + 0x18))();
      local_40 = local_48[2];
      FUN_1000a5b0(local_5c,local_40);
      (**(code **)(*local_44 + 0x24))();
      local_38 = local_48[3];
      for (local_3c = 0; local_3c < 4; local_3c = local_3c + 1) {
        if (local_38 == s_nmr__3_n_4_n_4Xn_4_n_4_n_4_n_4_n_100133ec[local_3c]) {
          (**(code **)(*local_44 + 0x3c))();
          (**(code **)(*local_44 + 0x40))();
          break;
        }
      }
      puVar2 = (undefined4 *)default_error_condition(local_6c,local_28,local_1c);
      local_64 = SetItem(this,*puVar2);
      local_60 = local_64;
      if (local_64 != (ITEM *)0x0) {
        (*(code *)**(undefined4 **)local_64)();
      }
    }
    local_1c = local_1c + 1;
  } while( true );
}



// public: struct STRING __thiscall MAP::Data(void)const 

void * __thiscall MAP::Data(MAP *this)

{
  int iVar1;
  CString *pCVar2;
  void *in_stack_00000004;
  CString local_30 [4];
  CString local_2c [4];
  CString local_28 [4];
  CString local_24 [4];
  CString local_20 [4];
  int local_1c;
  int local_18;
  int *local_14;
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
                    // 0xa31a  9  ?Data@MAP@@QBE?AUSTRING@@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000eef7;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10002c20(local_20);
  local_8 = 1;
  local_1c = 0;
  while( true ) {
    iVar1 = FUN_100089a0();
    if (iVar1 <= local_1c) break;
    local_18 = 0;
    while( true ) {
      iVar1 = FUN_100089b0();
      if (iVar1 <= local_18) break;
      local_14 = *(int **)(this + local_1c * 4 + local_18 * 0x34 + 4);
      pCVar2 = (CString *)(**(code **)(*local_14 + 0x50))(local_24);
      local_8._0_1_ = 2;
      CString::operator+=(local_20,pCVar2);
      local_8._0_1_ = 1;
      CString::~CString(local_24);
      pCVar2 = (CString *)(**(code **)(*local_14 + 0x58))(local_28);
      local_8._0_1_ = 3;
      CString::operator+=(local_20,pCVar2);
      local_8._0_1_ = 1;
      CString::~CString(local_28);
      pCVar2 = (CString *)(**(code **)(*local_14 + 0x5c))(local_2c);
      local_8._0_1_ = 4;
      CString::operator+=(local_20,pCVar2);
      local_8._0_1_ = 1;
      CString::~CString(local_2c);
      pCVar2 = (CString *)(**(code **)(*local_14 + 0x54))(local_30);
      local_8._0_1_ = 5;
      CString::operator+=(local_20,pCVar2);
      local_8 = CONCAT31(local_8._1_3_,1);
      CString::~CString(local_30);
      local_18 = local_18 + 1;
    }
    CString::operator+=(local_20,&DAT_100138b4);
    local_1c = local_1c + 1;
  }
  CString::operator+=(local_20,s_MAPTEXT___100138b8);
  CString::operator+=(local_20,(CString *)(this + 0x414));
  CString::operator+=(local_20,&DAT_100138c4);
  CString::operator+=(local_20,s_SCRIPT___100138c8);
  CString::operator+=(local_20,(CString *)(this + 0x418));
  CString::operator+=(local_20,&DAT_100138d4);
  CString::operator+=(local_20,s_COPYRIGHT___100138d8);
  CString::operator+=(local_20,(CString *)(this + 0x41c));
  CString::operator+=(local_20,&DAT_100138e4);
  FUN_100053f0(in_stack_00000004,local_20);
  local_8 = local_8 & 0xffffff00;
  FUN_10002c40(local_20);
  ExceptionList = local_10;
  return in_stack_00000004;
}



// public: bool __thiscall MAP::Clear(void)

bool __thiscall MAP::Clear(MAP *this)

{
  CString local_18 [4];
  undefined1 local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0xa547  6  ?Clear@MAP@@QAE_NXZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ef0a;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(local_18,PTR_s__3_n_4_n_4Xn_4_n_4_n_4_n_4_n_4_n_100133e8);
  local_8 = 0;
  local_14 = Set(this,local_18);
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  ExceptionList = local_10;
  return (bool)local_14;
}



void * __cdecl FUN_1000a5b0(void *param_1,undefined1 param_2)

{
  undefined4 local_8;
  
  local_8 = 7;
  switch(param_2) {
  case 0x20:
    local_8 = 7;
    break;
  case 0x42:
    local_8 = 1;
    break;
  case 0x43:
    local_8 = 3;
    break;
  case 0x47:
    local_8 = 2;
    break;
  case 0x4d:
    local_8 = 5;
    break;
  case 0x52:
    local_8 = 4;
    break;
  case 0x58:
    local_8 = 0;
    break;
  case 0x59:
    local_8 = 6;
  }
  FUN_10002bd0(param_1,local_8);
  return param_1;
}



void * __thiscall FUN_1000a6a0(void *this,LPCSTR param_1)

{
  HANDLE hFile;
  DWORD DVar1;
  HANDLE hFileMappingObject;
  LPVOID pvVar2;
  DWORD local_8;
  
  *(undefined4 *)this = 0;
  *(undefined4 *)((int)this + 4) = 0;
  hFile = CreateFileA(param_1,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    local_8 = 0;
    DVar1 = GetFileSize(hFile,&local_8);
    *(DWORD *)((int)this + 4) = DVar1;
    if (local_8 == 0) {
      if (*(int *)((int)this + 4) != 0) {
        hFileMappingObject = CreateFileMappingA(hFile,(LPSECURITY_ATTRIBUTES)0x0,2,0,0,(LPCSTR)0x0);
        if (hFileMappingObject == (HANDLE)0x0) {
          return this;
        }
        pvVar2 = MapViewOfFile(hFileMappingObject,4,0,0,0);
        *(LPVOID *)this = pvVar2;
        CloseHandle(hFileMappingObject);
      }
      CloseHandle(hFile);
    }
  }
  return this;
}



void __fastcall FUN_1000a780(int *param_1)

{
  if (*param_1 != 0) {
    UnmapViewOfFile((LPCVOID)*param_1);
  }
  return;
}



undefined4 __fastcall FUN_1000a7a0(undefined4 *param_1)

{
  return *param_1;
}



// public: void __thiscall MAP::SetPosition(struct CPosition const &)

void __thiscall MAP::SetPosition(MAP *this,CPosition *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  CString *pCVar2;
  uint uVar3;
  undefined3 extraout_var_00;
  int iVar4;
  TILEBLITTER *pTVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  int local_20;
  CString local_1c [4];
  int local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0xa7b0  40  ?SetPosition@MAP@@QAEXABUCPosition@@@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ef29;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_20 = FUN_100026f0(0x10015088);
  FUN_10002060(local_1c);
  local_8 = 0;
  local_14 = 0;
  bVar1 = IsEmpty(0x10015088);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    pCVar2 = (CString *)FUN_10006070(&local_20);
    FUN_100021b0(local_1c,pCVar2);
  }
  local_14 = 0;
  while ((uVar3 = FUN_10005970(0x10015088), local_14 < uVar3 &&
         (bVar1 = IsEmpty(0x10015088), CONCAT31(extraout_var_00,bVar1) == 0))) {
    if (this[0x43b] == (MAP)0x0) {
      iVar4 = FUN_10002320(&local_18);
      iVar4 = FUN_10002040(iVar4);
      if (iVar4 == 0x20) {
        uVar7 = *(undefined4 *)(param_1 + 4);
        uVar6 = *(undefined4 *)param_1;
        pTVar5 = (TILEBLITTER *)FUN_10002320(&local_18);
        TILEBLITTER::SetPosition(pTVar5,uVar6,uVar7);
      }
    }
    else {
      iVar4 = FUN_10002320(&local_18);
      iVar4 = FUN_10002040(iVar4);
      if (iVar4 == 8) {
        uVar7 = *(undefined4 *)(param_1 + 4);
        uVar6 = *(undefined4 *)param_1;
        pTVar5 = (TILEBLITTER *)FUN_10002320(&local_18);
        TILEBLITTER::SetPosition(pTVar5,uVar6,uVar7);
      }
    }
    local_14 = local_14 + 1;
    uVar3 = FUN_10005970(0x10015088);
    if (local_14 < uVar3) {
      pCVar2 = (CString *)FUN_10006070(&local_20);
      FUN_100021b0(local_1c,pCVar2);
    }
  }
  local_8 = 0xffffffff;
  FUN_100020f0(local_1c);
  ExceptionList = local_10;
  return;
}



// WARNING: Removing unreachable block (ram,0x1000aee1)
// WARNING: Removing unreachable block (ram,0x1000aeef)
// WARNING: Removing unreachable block (ram,0x1000aef4)
// WARNING: Removing unreachable block (ram,0x1000adaa)
// WARNING: Removing unreachable block (ram,0x1000adb4)
// WARNING: Removing unreachable block (ram,0x1000adb9)
// WARNING: Removing unreachable block (ram,0x1000ac2f)
// WARNING: Removing unreachable block (ram,0x1000ac3d)
// WARNING: Removing unreachable block (ram,0x1000ac42)
// WARNING: Removing unreachable block (ram,0x1000aaed)
// WARNING: Removing unreachable block (ram,0x1000aaf8)
// WARNING: Removing unreachable block (ram,0x1000aafd)
// WARNING: Removing unreachable block (ram,0x1000ab3c)
// WARNING: Removing unreachable block (ram,0x1000ab47)
// WARNING: Removing unreachable block (ram,0x1000ab4c)
// WARNING: Removing unreachable block (ram,0x1000ac84)
// WARNING: Removing unreachable block (ram,0x1000ac92)
// WARNING: Removing unreachable block (ram,0x1000ac97)
// WARNING: Removing unreachable block (ram,0x1000adf6)
// WARNING: Removing unreachable block (ram,0x1000ae01)
// WARNING: Removing unreachable block (ram,0x1000ae06)
// WARNING: Removing unreachable block (ram,0x1000af34)
// WARNING: Removing unreachable block (ram,0x1000af41)
// WARNING: Removing unreachable block (ram,0x1000af46)
// public: void __thiscall MAP::WipeReset(void)

void __thiscall MAP::WipeReset(MAP *this)

{
  TILEBLITTER *pTVar1;
  undefined4 *puVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  DD_SURFACE *pDVar6;
  undefined4 uVar7;
  undefined1 local_94 [8];
  undefined1 local_8c [8];
  undefined1 local_84 [8];
  undefined1 local_7c [8];
  undefined1 local_74 [8];
  undefined1 local_6c [8];
  undefined1 local_64 [8];
  undefined1 local_5c [8];
  undefined1 local_54 [8];
  undefined1 local_4c [8];
  undefined1 local_44 [8];
  undefined1 local_3c [8];
  ITEM *local_34;
  ITEM *local_30;
  uint local_2c;
  ITEM *local_28;
  ITEM *local_24;
  uint local_20;
  uint local_1c;
  uint local_18;
  ITEM *local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
                    // 0xa919  46  ?WipeReset@MAP@@QAEXXZ
  FUN_1000bec0(this);
  pDVar6 = (DD_SURFACE *)ddsBack_exref;
  pTVar1 = (TILEBLITTER *)FUN_10008a50();
  TILEBLITTER::SetupLaserEffect(pTVar1,pDVar6);
  local_8 = local_8 & 0xffffff00;
  puVar2 = (undefined4 *)default_error_condition(local_3c,0,0);
  local_14 = GetItem(this,*puVar2,puVar2[1]);
  local_c = 0;
  while ((local_c < 0x14 && ((local_8 & 0xff) == 0))) {
    local_1c = 0;
    while ((local_1c < 0xd && ((local_8 & 0xff) == 0))) {
      puVar2 = (undefined4 *)(**(code **)(*(int *)local_14 + 0x74))(local_54);
      uVar7 = puVar2[1];
      uVar5 = *puVar2;
      uVar4 = 200;
      pTVar1 = (TILEBLITTER *)FUN_10008a50();
      TILEBLITTER::AddTileToScreen(pTVar1,uVar4,uVar5,uVar7);
      local_1c = local_1c + 1;
      if (local_1c < 0xd) {
        puVar2 = (undefined4 *)default_error_condition(local_44,local_c,local_1c);
        local_14 = GetItem(this,*puVar2,puVar2[1]);
      }
      else if (local_c < 0x13) {
        puVar2 = (undefined4 *)default_error_condition(local_4c,local_c + 1,0);
        local_14 = GetItem(this,*puVar2,puVar2[1]);
      }
    }
    local_c = local_c + 1;
  }
  pDVar6 = (DD_SURFACE *)ddsBack_exref;
  pTVar1 = (TILEBLITTER *)FUN_10008a50();
  TILEBLITTER::EndLaserEffect(pTVar1,pDVar6);
  for (local_10 = 0; (int)local_10 < 0x14; local_10 = local_10 + 2) {
    for (local_20 = 0; local_20 < 2; local_20 = local_20 + 1) {
      local_18 = local_10 & 0x80000001;
      if ((int)local_18 < 0) {
        local_18 = (local_18 - 1 | 0xfffffffe) + 1;
      }
      while( true ) {
        uVar3 = local_10 & 0x80000001;
        if ((int)uVar3 < 0) {
          uVar3 = (uVar3 - 1 | 0xfffffffe) + 1;
        }
        if ((int)(0xd - uVar3) < (int)local_18) break;
        puVar2 = (undefined4 *)default_error_condition(local_5c,local_10,local_18);
        local_24 = GetItem(this,*puVar2,puVar2[1]);
        pDVar6 = (DD_SURFACE *)ddsBack_exref;
        pTVar1 = (TILEBLITTER *)FUN_10007c28(this,local_24);
        TILEBLITTER::SetupLaserEffect(pTVar1,pDVar6);
        puVar2 = (undefined4 *)default_error_condition(local_64,local_10,local_18);
        uVar7 = puVar2[1];
        uVar5 = *puVar2;
        uVar4 = (**(code **)(*(int *)local_24 + 0x70))(uVar5,uVar7);
        pTVar1 = (TILEBLITTER *)FUN_10007c28(this,local_24);
        TILEBLITTER::AddTileToScreen(pTVar1,uVar4,uVar5,uVar7);
        pDVar6 = (DD_SURFACE *)ddsBack_exref;
        pTVar1 = (TILEBLITTER *)FUN_10007c28(this,local_24);
        TILEBLITTER::EndLaserEffect(pTVar1,pDVar6);
        local_18 = local_18 + 2;
      }
      local_18 = local_10 + 1 & 0x80000001;
      if ((int)local_18 < 0) {
        local_18 = (local_18 - 1 | 0xfffffffe) + 1;
      }
      while( true ) {
        uVar3 = local_10 + 1 & 0x80000001;
        if ((int)uVar3 < 0) {
          uVar3 = (uVar3 - 1 | 0xfffffffe) + 1;
        }
        if ((int)(0xd - uVar3) < (int)local_18) break;
        puVar2 = (undefined4 *)default_error_condition(local_6c,local_10 + 1,local_18);
        local_28 = GetItem(this,*puVar2,puVar2[1]);
        pDVar6 = (DD_SURFACE *)ddsBack_exref;
        pTVar1 = (TILEBLITTER *)FUN_10007c28(this,local_28);
        TILEBLITTER::SetupLaserEffect(pTVar1,pDVar6);
        puVar2 = (undefined4 *)default_error_condition(local_74,local_10 + 1,local_18);
        uVar7 = puVar2[1];
        uVar5 = *puVar2;
        uVar4 = (**(code **)(*(int *)local_28 + 0x70))(uVar5,uVar7);
        pTVar1 = (TILEBLITTER *)FUN_10007c28(this,local_28);
        TILEBLITTER::AddTileToScreen(pTVar1,uVar4,uVar5,uVar7);
        pDVar6 = (DD_SURFACE *)ddsBack_exref;
        pTVar1 = (TILEBLITTER *)FUN_10007c28(this,local_28);
        TILEBLITTER::EndLaserEffect(pTVar1,pDVar6);
        local_18 = local_18 + 2;
      }
      GKERNEL::SpriteFlip();
    }
  }
  for (local_10 = 0; (int)local_10 < 0x14; local_10 = local_10 + 2) {
    for (local_2c = 0; local_2c < 2; local_2c = local_2c + 1) {
      uVar3 = local_10 & 0x80000001;
      if ((int)uVar3 < 0) {
        uVar3 = (uVar3 - 1 | 0xfffffffe) + 1;
      }
      local_18 = (uint)(uVar3 == 0);
      while( true ) {
        uVar3 = local_10 & 0x80000001;
        if ((int)uVar3 < 0) {
          uVar3 = (uVar3 - 1 | 0xfffffffe) + 1;
        }
        if ((int)(0xd - (uint)(uVar3 == 0)) < (int)local_18) break;
        puVar2 = (undefined4 *)default_error_condition(local_7c,local_10,local_18);
        local_30 = GetItem(this,*puVar2,puVar2[1]);
        pDVar6 = (DD_SURFACE *)ddsBack_exref;
        pTVar1 = (TILEBLITTER *)FUN_10007c28(this,local_30);
        TILEBLITTER::SetupLaserEffect(pTVar1,pDVar6);
        puVar2 = (undefined4 *)default_error_condition(local_84,local_10,local_18);
        uVar7 = puVar2[1];
        uVar5 = *puVar2;
        uVar4 = (**(code **)(*(int *)local_30 + 0x70))(uVar5,uVar7);
        pTVar1 = (TILEBLITTER *)FUN_10007c28(this,local_30);
        TILEBLITTER::AddTileToScreen(pTVar1,uVar4,uVar5,uVar7);
        pDVar6 = (DD_SURFACE *)ddsBack_exref;
        pTVar1 = (TILEBLITTER *)FUN_10007c28(this,local_30);
        TILEBLITTER::EndLaserEffect(pTVar1,pDVar6);
        local_18 = local_18 + 2;
      }
      uVar3 = local_10 + 1 & 0x80000001;
      if ((int)uVar3 < 0) {
        uVar3 = (uVar3 - 1 | 0xfffffffe) + 1;
      }
      local_18 = (uint)(uVar3 == 0);
      while( true ) {
        uVar3 = local_10 + 1 & 0x80000001;
        if ((int)uVar3 < 0) {
          uVar3 = (uVar3 - 1 | 0xfffffffe) + 1;
        }
        if ((int)(0xd - (uint)(uVar3 == 0)) < (int)local_18) break;
        puVar2 = (undefined4 *)default_error_condition(local_8c,local_10 + 1,local_18);
        local_34 = GetItem(this,*puVar2,puVar2[1]);
        pDVar6 = (DD_SURFACE *)ddsBack_exref;
        pTVar1 = (TILEBLITTER *)FUN_10007c28(this,local_34);
        TILEBLITTER::SetupLaserEffect(pTVar1,pDVar6);
        puVar2 = (undefined4 *)default_error_condition(local_94,local_10 + 1,local_18);
        uVar7 = puVar2[1];
        uVar5 = *puVar2;
        uVar4 = (**(code **)(*(int *)local_34 + 0x70))(uVar5,uVar7);
        pTVar1 = (TILEBLITTER *)FUN_10007c28(this,local_34);
        TILEBLITTER::AddTileToScreen(pTVar1,uVar4,uVar5,uVar7);
        pDVar6 = (DD_SURFACE *)ddsBack_exref;
        pTVar1 = (TILEBLITTER *)FUN_10007c28(this,local_34);
        TILEBLITTER::EndLaserEffect(pTVar1,pDVar6);
        local_18 = local_18 + 2;
      }
      GKERNEL::SpriteFlip();
    }
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x1000b379)
// WARNING: Removing unreachable block (ram,0x1000b387)
// WARNING: Removing unreachable block (ram,0x1000b38c)
// WARNING: Removing unreachable block (ram,0x1000b2a1)
// WARNING: Removing unreachable block (ram,0x1000b2ac)
// WARNING: Removing unreachable block (ram,0x1000b2b1)
// WARNING: Removing unreachable block (ram,0x1000b1d3)
// WARNING: Removing unreachable block (ram,0x1000b1e0)
// WARNING: Removing unreachable block (ram,0x1000b1e5)
// WARNING: Removing unreachable block (ram,0x1000b0ec)
// WARNING: Removing unreachable block (ram,0x1000b0f6)
// WARNING: Removing unreachable block (ram,0x1000b0fb)
// WARNING: Removing unreachable block (ram,0x1000b0a5)
// WARNING: Removing unreachable block (ram,0x1000b0b0)
// WARNING: Removing unreachable block (ram,0x1000b0b5)
// WARNING: Removing unreachable block (ram,0x1000b2e4)
// WARNING: Removing unreachable block (ram,0x1000b2ef)
// WARNING: Removing unreachable block (ram,0x1000b2f4)
// WARNING: Removing unreachable block (ram,0x1000b3c2)
// WARNING: Removing unreachable block (ram,0x1000b3d0)
// WARNING: Removing unreachable block (ram,0x1000b3d5)
// WARNING: Removing unreachable block (ram,0x1000b186)
// WARNING: Removing unreachable block (ram,0x1000b194)
// WARNING: Removing unreachable block (ram,0x1000b199)
// public: void __thiscall MAP::WipeErase(void)

void __thiscall MAP::WipeErase(MAP *this)

{
  TILEBLITTER *pTVar1;
  undefined4 *puVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  DD_SURFACE *pDVar6;
  undefined4 uVar7;
  undefined1 local_34 [8];
  undefined1 local_2c [8];
  undefined1 local_24 [8];
  undefined1 local_1c [8];
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
                    // 0xb040  45  ?WipeErase@MAP@@QAEXXZ
  for (local_8 = 0; (int)local_8 < 0x14; local_8 = local_8 + 2) {
    for (local_10 = 0; local_10 < 2; local_10 = local_10 + 1) {
      local_c = local_8 & 0x80000001;
      if ((int)local_c < 0) {
        local_c = (local_c - 1 | 0xfffffffe) + 1;
      }
      while( true ) {
        uVar3 = local_8 & 0x80000001;
        if ((int)uVar3 < 0) {
          uVar3 = (uVar3 - 1 | 0xfffffffe) + 1;
        }
        if ((int)(0xd - uVar3) < (int)local_c) break;
        pDVar6 = (DD_SURFACE *)ddsBack_exref;
        pTVar1 = (TILEBLITTER *)FUN_10008a50();
        TILEBLITTER::SetupLaserEffect(pTVar1,pDVar6);
        puVar2 = (undefined4 *)default_error_condition(local_1c,local_8,local_c);
        uVar7 = puVar2[1];
        uVar5 = *puVar2;
        uVar4 = 200;
        pTVar1 = (TILEBLITTER *)FUN_10008a50();
        TILEBLITTER::AddTileToScreen(pTVar1,uVar4,uVar5,uVar7);
        pDVar6 = (DD_SURFACE *)ddsBack_exref;
        pTVar1 = (TILEBLITTER *)FUN_10008a50();
        TILEBLITTER::EndLaserEffect(pTVar1,pDVar6);
        local_c = local_c + 2;
      }
      local_c = local_8 + 1 & 0x80000001;
      if ((int)local_c < 0) {
        local_c = (local_c - 1 | 0xfffffffe) + 1;
      }
      while( true ) {
        uVar3 = local_8 + 1 & 0x80000001;
        if ((int)uVar3 < 0) {
          uVar3 = (uVar3 - 1 | 0xfffffffe) + 1;
        }
        if ((int)(0xd - uVar3) < (int)local_c) break;
        pDVar6 = (DD_SURFACE *)ddsBack_exref;
        pTVar1 = (TILEBLITTER *)FUN_10008a50();
        TILEBLITTER::SetupLaserEffect(pTVar1,pDVar6);
        puVar2 = (undefined4 *)default_error_condition(local_24,local_8 + 1,local_c);
        uVar7 = puVar2[1];
        uVar5 = *puVar2;
        uVar4 = 200;
        pTVar1 = (TILEBLITTER *)FUN_10008a50();
        TILEBLITTER::AddTileToScreen(pTVar1,uVar4,uVar5,uVar7);
        pDVar6 = (DD_SURFACE *)ddsBack_exref;
        pTVar1 = (TILEBLITTER *)FUN_10008a50();
        TILEBLITTER::EndLaserEffect(pTVar1,pDVar6);
        local_c = local_c + 2;
      }
      GKERNEL::SpriteFlip();
    }
  }
  for (local_8 = 0; (int)local_8 < 0x14; local_8 = local_8 + 2) {
    for (local_14 = 0; local_14 < 2; local_14 = local_14 + 1) {
      uVar3 = local_8 & 0x80000001;
      if ((int)uVar3 < 0) {
        uVar3 = (uVar3 - 1 | 0xfffffffe) + 1;
      }
      local_c = (uint)(uVar3 == 0);
      while( true ) {
        uVar3 = local_8 & 0x80000001;
        if ((int)uVar3 < 0) {
          uVar3 = (uVar3 - 1 | 0xfffffffe) + 1;
        }
        if ((int)(0xd - (uint)(uVar3 == 0)) < (int)local_c) break;
        pDVar6 = (DD_SURFACE *)ddsBack_exref;
        pTVar1 = (TILEBLITTER *)FUN_10008a50();
        TILEBLITTER::SetupLaserEffect(pTVar1,pDVar6);
        puVar2 = (undefined4 *)default_error_condition(local_2c,local_8,local_c);
        uVar7 = puVar2[1];
        uVar5 = *puVar2;
        uVar4 = 200;
        pTVar1 = (TILEBLITTER *)FUN_10008a50();
        TILEBLITTER::AddTileToScreen(pTVar1,uVar4,uVar5,uVar7);
        pDVar6 = (DD_SURFACE *)ddsBack_exref;
        pTVar1 = (TILEBLITTER *)FUN_10008a50();
        TILEBLITTER::EndLaserEffect(pTVar1,pDVar6);
        local_c = local_c + 2;
      }
      uVar3 = local_8 + 1 & 0x80000001;
      if ((int)uVar3 < 0) {
        uVar3 = (uVar3 - 1 | 0xfffffffe) + 1;
      }
      local_c = (uint)(uVar3 == 0);
      while( true ) {
        uVar3 = local_8 + 1 & 0x80000001;
        if ((int)uVar3 < 0) {
          uVar3 = (uVar3 - 1 | 0xfffffffe) + 1;
        }
        if ((int)(0xd - (uint)(uVar3 == 0)) < (int)local_c) break;
        pDVar6 = (DD_SURFACE *)ddsBack_exref;
        pTVar1 = (TILEBLITTER *)FUN_10008a50();
        TILEBLITTER::SetupLaserEffect(pTVar1,pDVar6);
        puVar2 = (undefined4 *)default_error_condition(local_34,local_8 + 1,local_c);
        uVar7 = puVar2[1];
        uVar5 = *puVar2;
        uVar4 = 200;
        pTVar1 = (TILEBLITTER *)FUN_10008a50();
        TILEBLITTER::AddTileToScreen(pTVar1,uVar4,uVar5,uVar7);
        pDVar6 = (DD_SURFACE *)ddsBack_exref;
        pTVar1 = (TILEBLITTER *)FUN_10008a50();
        TILEBLITTER::EndLaserEffect(pTVar1,pDVar6);
        local_c = local_c + 2;
      }
      GKERNEL::SpriteFlip();
    }
  }
  return;
}



CString * __cdecl FUN_1000b46e(CString *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  CString *pCVar2;
  CString *this;
  CString local_1c [4];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_1000ef65;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  bVar1 = FUN_10008680((int *)&param_2_100151f0);
  if (CONCAT31(extraout_var,bVar1) != 0) {
    CString::operator=((CString *)&param_2_100151f0,s_Levels__1001395c);
  }
  CString::CString(local_18);
  local_8 = 1;
  CString::CString(local_14);
  local_8._0_1_ = 2;
  CString::Format(local_18,(char *)local_18);
  CString::Format(this,(char *)local_14);
  pCVar2 = (CString *)operator+(local_1c,(CString *)&param_2_100151f0);
  local_8._0_1_ = 3;
  operator+(param_1,pCVar2);
  local_8._0_1_ = 2;
  CString::~CString(local_1c);
  local_8._0_1_ = 1;
  CString::~CString(local_14);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(local_18);
  ExceptionList = local_10;
  return param_1;
}



// public: static bool __cdecl MAP::Exists(struct LEVEL)

bool __cdecl MAP::Exists(void)

{
  bool bVar1;
  CString *pCVar2;
  char *pcVar3;
  CString local_20 [4];
  uint local_1c;
  CString local_18 [4];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0xb560  12  ?Exists@MAP@@SA_NULEVEL@@@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ef81;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pCVar2 = FUN_1000b46e(local_18);
  local_8 = 0;
  pcVar3 = (char *)FUN_1000a7a0((undefined4 *)pCVar2);
  bVar1 = exists(pcVar3);
  local_14 = CONCAT31(local_14._1_3_,'\x01' - bVar1);
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  if ((local_14 & 0xff) == 0) {
    if (DAT_100151e0 == '\0') {
      pCVar2 = FUN_1000b46e(local_20);
      local_8 = 1;
      pcVar3 = (char *)FUN_1000a7a0((undefined4 *)pCVar2);
      bVar1 = CheckBackReflection(pcVar3);
      local_1c = CONCAT31(local_1c._1_3_,'\x01' - bVar1);
      local_8 = 0xffffffff;
      CString::~CString(local_20);
      if ((local_1c & 0xff) != 0) {
        ExceptionList = local_10;
        return false;
      }
    }
    bVar1 = true;
  }
  else {
    bVar1 = false;
  }
  ExceptionList = local_10;
  return bVar1;
}



// public: static class ITEM * __cdecl MAP::FindItem(char const *)

ITEM * __cdecl MAP::FindItem(char *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 *puVar2;
  uint uVar3;
  undefined3 extraout_var_00;
  void *this;
  int iVar4;
  char *pcVar5;
  CString local_24 [4];
  uint local_20;
  int local_1c;
  ITEM *local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0xb65c  14  ?FindItem@MAP@@SAPAVITEM@@PBD@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ef94;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_1c = FUN_100026f0(0x100151c0);
  local_18 = (ITEM *)0x0;
  local_14 = 0;
  bVar1 = IsEmpty(0x100151c0);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar2 = (undefined4 *)FUN_10006070(&local_1c);
    local_18 = (ITEM *)*puVar2;
  }
  local_14 = 0;
  while ((uVar3 = FUN_10005970(0x100151c0), local_14 < uVar3 &&
         (bVar1 = IsEmpty(0x100151c0), CONCAT31(extraout_var_00,bVar1) == 0))) {
    pcVar5 = param_1;
    this = (void *)(**(code **)(*(int *)local_18 + 0x60))(local_24);
    local_8 = 0;
    iVar4 = FUN_1000be10(this,pcVar5);
    local_20 = CONCAT31(local_20._1_3_,'\x01' - (iVar4 != 0));
    local_8 = 0xffffffff;
    CString::~CString(local_24);
    if ((local_20 & 0xff) != 0) {
      ExceptionList = local_10;
      return local_18;
    }
    local_14 = local_14 + 1;
    uVar3 = FUN_10005970(0x100151c0);
    if (local_14 < uVar3) {
      puVar2 = (undefined4 *)FUN_10006070(&local_1c);
      local_18 = (ITEM *)*puVar2;
    }
  }
  ExceptionList = local_10;
  return (ITEM *)0x0;
}



// public: static class ITEM * __cdecl MAP::FindItem(char)

ITEM * __cdecl MAP::FindItem(char param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 *puVar2;
  uint uVar3;
  undefined3 extraout_var_00;
  void *pvVar4;
  char *pcVar5;
  CString local_28 [4];
  uint local_24;
  int local_20;
  ITEM *local_1c;
  char local_18 [4];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0xb77b  13  ?FindItem@MAP@@SAPAVITEM@@D@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000efa7;
  local_10 = ExceptionList;
  local_18[0] = param_1;
  local_18[1] = 0;
  ExceptionList = &local_10;
  local_20 = FUN_100026f0(0x100151c0);
  local_1c = (ITEM *)0x0;
  local_14 = 0;
  bVar1 = IsEmpty(0x100151c0);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar2 = (undefined4 *)FUN_10006070(&local_20);
    local_1c = (ITEM *)*puVar2;
  }
  local_14 = 0;
  while ((uVar3 = FUN_10005970(0x100151c0), local_14 < uVar3 &&
         (bVar1 = IsEmpty(0x100151c0), CONCAT31(extraout_var_00,bVar1) == 0))) {
    pcVar5 = local_18;
    pvVar4 = (void *)(**(code **)(*(int *)local_1c + 0x50))(local_28);
    local_8 = 0;
    bVar1 = FUN_10005600(pvVar4,pcVar5);
    local_24 = CONCAT31(local_24._1_3_,bVar1);
    local_8 = 0xffffffff;
    CString::~CString(local_28);
    if ((local_24 & 0xff) != 0) {
      ExceptionList = local_10;
      return local_1c;
    }
    local_14 = local_14 + 1;
    uVar3 = FUN_10005970(0x100151c0);
    if (local_14 < uVar3) {
      puVar2 = (undefined4 *)FUN_10006070(&local_20);
      local_1c = (ITEM *)*puVar2;
    }
  }
  ExceptionList = local_10;
  return (ITEM *)0x0;
}



// public: void __thiscall MAP::RefreshBothLevelmapBuffers(void)

void __thiscall MAP::RefreshBothLevelmapBuffers(MAP *this)

{
  undefined4 *puVar1;
  undefined1 local_2c [8];
  undefined1 local_24 [8];
  undefined1 local_1c [8];
  uint local_14;
  ITEM *local_10;
  uint local_c;
  uint local_8;
  
                    // 0xb8a0  27  ?RefreshBothLevelmapBuffers@MAP@@QAEXXZ
  local_8 = local_8 & 0xffffff00;
  puVar1 = (undefined4 *)default_error_condition(local_1c,0,0);
  local_10 = GetItem(this,*puVar1,puVar1[1]);
  local_c = 0;
  while ((local_c < 0x14 && ((local_8 & 0xff) == 0))) {
    local_14 = 0;
    while ((local_14 < 0xd && ((local_8 & 0xff) == 0))) {
      (**(code **)(*(int *)local_10 + 0x30))();
      local_14 = local_14 + 1;
      if (local_14 < 0xd) {
        puVar1 = (undefined4 *)default_error_condition(local_24,local_c,local_14);
        local_10 = GetItem(this,*puVar1,puVar1[1]);
      }
      else if (local_c < 0x13) {
        puVar1 = (undefined4 *)default_error_condition(local_2c,local_c + 1,0);
        local_10 = GetItem(this,*puVar1,puVar1[1]);
      }
    }
    local_c = local_c + 1;
  }
  return;
}



uint __cdecl FUN_1000b9a9(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 in_EAX;
  uint uVar1;
  int *piVar2;
  uint uVar3;
  undefined1 local_18 [8];
  uint local_10;
  int local_c;
  uint local_8;
  
  if (param_3 == 0) {
    uVar1 = CONCAT31((int3)((uint)in_EAX >> 8),1);
  }
  else {
    uVar1 = 0;
    local_c = 0;
    for (local_8 = 0; local_8 < 4; local_8 = local_8 + 1) {
      for (local_10 = 0; local_10 < 0x1e; local_10 = local_10 + 1) {
        piVar2 = (int *)FUN_1000be70(local_18,local_8 + 1,local_10 + 1);
        uVar3 = FUN_1000bea0(piVar2);
        uVar1 = FUN_1000bea0(&param_1);
        if (((uVar3 != uVar1) &&
            (uVar1 = local_10, (&_Dst_10013ca0)[local_8 * 0x1e + local_10] == (void *)param_3)) &&
           (local_c = local_c + 1, local_c == 2)) {
          return CONCAT31((int3)(local_10 >> 8),1);
        }
      }
    }
    uVar1 = uVar1 & 0xffffff00;
  }
  return uVar1;
}



int __cdecl FUN_1000ba5a(LPCSTR param_1)

{
  int iVar1;
  undefined4 local_28;
  uint local_24;
  HANDLE local_20;
  int local_1c;
  _FILETIME local_18;
  _FILETIME local_10;
  WORD local_8 [2];
  
  local_20 = CreateFileA(param_1,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  if (local_20 == (HANDLE)0xffffffff) {
    iVar1 = 0;
  }
  else {
    FUN_1000be30(&local_1c,local_20);
    local_10.dwLowDateTime = 0;
    local_10.dwHighDateTime = 0;
    local_18.dwLowDateTime = 0;
    local_18.dwHighDateTime = 0;
    GetFileTime(local_20,(LPFILETIME)0x0,(LPFILETIME)0x0,&local_10);
    FileTimeToLocalFileTime(&local_10,&local_18);
    local_8[0] = 0;
    local_28 = (uint)local_28._2_2_ << 0x10;
    FileTimeToDosDateTime(&local_18,local_8,(LPWORD)&local_28);
    local_24 = local_28 & 0xffff;
    iVar1 = (local_24 >> 0xb) * 0x708 + ((local_28 & 0x7e0) >> 5) * 0x1e + (local_28 & 0x1f);
    FUN_1000be50(&local_1c);
  }
  return iVar1;
}



bool __cdecl FUN_1000bb3c(LPCSTR param_1,uint param_2)

{
  BOOL BVar1;
  bool bVar2;
  WORD local_28 [2];
  HANDLE local_24;
  bool local_20;
  undefined3 uStack_1f;
  _FILETIME local_1c;
  int local_14;
  _FILETIME local_10;
  WORD local_8 [2];
  
  local_24 = CreateFileA(param_1,0x40000000,2,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  if (local_24 == (HANDLE)0xffffffff) {
    bVar2 = false;
  }
  else {
    FUN_1000be30(&local_14,local_24);
    local_10.dwLowDateTime = 0;
    local_10.dwHighDateTime = 0;
    local_1c.dwLowDateTime = 0;
    local_1c.dwHighDateTime = 0;
    GetFileTime(local_24,(LPFILETIME)0x0,(LPFILETIME)0x0,&local_10);
    FileTimeToLocalFileTime(&local_10,&local_1c);
    local_8[0] = 0;
    local_28[0] = 0;
    FileTimeToDosDateTime(&local_1c,local_8,local_28);
    param_2._0_2_ =
         (ushort)(param_2 % 0x1e) | (ushort)((param_2 % 0x708) / 0x1e << 5) |
         (ushort)(param_2 / 0x708 << 0xb);
    local_28[0] = (ushort)param_2;
    BVar1 = DosDateTimeToFileTime(local_8[0],(ushort)param_2,&local_1c);
    bVar2 = BVar1 != 0;
    local_20 = bVar2;
    if (bVar2) {
      LocalFileTimeToFileTime(&local_1c,&local_10);
      BVar1 = SetFileTime(local_24,(FILETIME *)0x0,(FILETIME *)0x0,&local_10);
      local_20 = BVar1 != 0;
    }
    bVar2 = local_20;
    FUN_1000be50(&local_14);
  }
  return bVar2;
}



// public: static void __cdecl MAP::LoadOptimzationTable(char const *,unsigned int,unsigned int)

void __cdecl MAP::LoadOptimzationTable(char *param_1,uint param_2,uint param_3)

{
  bool bVar1;
  char *pcVar2;
  CString local_30 [4];
  undefined1 local_2c [8];
  uint local_24;
  uint local_20;
  uint local_1c;
  CString local_18 [4];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
                    // 0xbc91  22  ?LoadOptimzationTable@MAP@@SAXPBDII@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000efc3;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(local_18,(CString *)&param_2_100151f0);
  local_8 = 0;
  local_1c = DAT_1001324c;
  local_20 = DAT_10013250;
  DAT_1001324c = param_2;
  DAT_10013250 = param_3;
  CString::CString((CString *)&stack0xffffffbc,param_1);
  SetLevelDir();
  for (local_14 = 0; local_14 < 4; local_14 = local_14 + 1) {
    for (local_24 = 0; local_24 < 0x1e; local_24 = local_24 + 1) {
      FUN_1000be70(local_2c,local_14 + 1,local_24 + 1);
      FUN_1000b46e(local_30);
      local_8 = CONCAT31(local_8._1_3_,1);
      pcVar2 = (char *)FUN_1000a7a0((undefined4 *)local_30);
      bVar1 = exists(pcVar2);
      if (bVar1) {
        pcVar2 = (char *)FUN_1000a7a0((undefined4 *)local_30);
        bVar1 = CheckBackReflection(pcVar2);
        if (!bVar1) {
          pcVar2 = (char *)FUN_1000a7a0((undefined4 *)local_30);
          RecalculatePath(pcVar2);
        }
      }
      local_8 = local_8 & 0xffffff00;
      CString::~CString(local_30);
    }
  }
  DAT_1001324c = local_1c;
  DAT_10013250 = local_20;
  CString::CString((CString *)&stack0xffffffbc,local_18);
  SetLevelDir();
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_1000be10(void *this,char *param_1)

{
                    // WARNING: Load size is inaccurate
  _stricmp(*this,param_1);
  return;
}



void * __thiscall FUN_1000be30(void *this,undefined4 param_1)

{
  *(undefined4 *)this = param_1;
  return this;
}



void __fastcall FUN_1000be50(int *param_1)

{
  if (*param_1 != -1) {
    CloseHandle((HANDLE)*param_1);
  }
  return;
}



void * __thiscall FUN_1000be70(void *this,undefined4 param_1,undefined4 param_2)

{
  *(undefined4 *)this = param_1;
  *(undefined4 *)((int)this + 4) = param_2;
  return this;
}



int __fastcall FUN_1000bea0(int *param_1)

{
  return (*param_1 + -1) * 100 + param_1[1];
}



void __fastcall FUN_1000bec0(MAP *param_1)

{
  MAP::NewFrame(param_1,0);
  return;
}



void FUN_1000bee0(void)

{
  FUN_1000beef();
  FUN_1000befe();
  return;
}



void FUN_1000beef(void)

{
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)&DAT_10015218);
  return;
}



void FUN_1000befe(void)

{
  FUN_1000e1a8(FUN_1000bf10);
  return;
}



void FUN_1000bf10(void)

{
  if ((DAT_10015210 & 1) == 0) {
    DAT_10015210 = DAT_10015210 | 1;
    FUN_1000c350((undefined4 *)&DAT_10015218);
  }
  return;
}



void __thiscall FUN_1000bf3c(void *this,void *param_1)

{
  char cVar1;
  undefined4 *puVar2;
  char *pcVar3;
  undefined1 uVar4;
  int iVar5;
  int iVar6;
  CString local_34 [4];
  undefined1 *local_30;
  void *local_2c;
  undefined1 local_28 [4];
  CString local_24 [8];
  int local_1c;
  code *local_18;
  SPRITE *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_5_1000efe2;
  local_10 = ExceptionList;
  local_2c = param_1;
  ExceptionList = &local_10;
  FUN_1000c640(param_1,local_28);
  local_8 = 0;
  local_14 = (SPRITE *)(*local_18)();
  iVar5 = 1;
  local_30 = &stack0xffffffa8;
  iVar6 = local_1c;
  CString::CString((CString *)&stack0xffffffa8,local_24);
  uVar4 = SUB41(local_34,0);
  puVar2 = (undefined4 *)(**(code **)(*DAT_100151dc + 0x54))();
  local_8._0_1_ = 1;
  pcVar3 = (char *)FUN_1000a7a0(puVar2);
  SPRITE::Init(local_14,pcVar3,(bool)uVar4,local_1c,iVar5,iVar6);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(local_34);
  (**(code **)(*(int *)local_14 + 0x74))();
  cVar1 = (**(code **)(*(int *)local_14 + 0x78))();
  if (cVar1 != '\0') {
    *(undefined1 *)((int)this + 0x43a) = 1;
  }
  FUN_1000c3a0(&DAT_10015218,&local_14);
  local_8 = 0xffffffff;
  FUN_10007620((int)local_28);
  ExceptionList = local_10;
  return;
}



// public: void __thiscall MAP::CreateMovingObjectByName(char const *,struct CPosition const &)

void __thiscall MAP::CreateMovingObjectByName(MAP *this,char *param_1,CPosition *param_2)

{
  ITEM *pIVar1;
  
                    // 0xc03e  7  ?CreateMovingObjectByName@MAP@@QAEXPBDABUCPosition@@@Z
  pIVar1 = FindItem(param_1);
  FUN_1000bf3c(this,pIVar1);
  return;
}



// public: bool __thiscall MAP::CreateMovingObjects(void)

bool __thiscall MAP::CreateMovingObjects(MAP *this)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  undefined4 *puVar3;
  undefined3 extraout_var_00;
  void *this_00;
  ITEM *pIVar4;
  undefined4 uVar5;
  undefined3 extraout_var_01;
  undefined1 *puVar6;
  undefined1 *puVar7;
  undefined4 uVar8;
  undefined1 local_50 [8];
  ITEM *local_48;
  ITEM *local_44;
  undefined1 local_40 [8];
  undefined1 local_38 [8];
  undefined1 local_30 [8];
  undefined1 local_28 [8];
  undefined1 local_20 [8];
  ITEM *local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  ITEM *local_8;
  
                    // 0xc064  8  ?CreateMovingObjects@MAP@@QAE_NXZ
  this[0x43a] = (MAP)0x0;
  if (DAT_100151dc == 0) {
    cVar2 = '\0';
  }
  else {
    bVar1 = IsEmpty(0x10015218);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      cVar2 = '\0';
    }
    else {
      local_c = local_c & 0xffffff00;
      puVar3 = (undefined4 *)default_error_condition(local_20,0,0);
      local_8 = GetItem(this,*puVar3,puVar3[1]);
      local_10 = 0;
      while ((local_10 < 0x14 && ((local_c & 0xff) == 0))) {
        local_14 = 0;
        while ((local_14 < 0xd && ((local_c & 0xff) == 0))) {
          local_18 = local_8;
          bVar1 = FUN_1000c610((int)local_8);
          if (CONCAT31(extraout_var_00,bVar1) != 0) {
            uVar8 = 0x20;
            puVar7 = local_40;
            puVar6 = local_38;
            this_00 = (void *)(**(code **)(*(int *)local_18 + 0x74))(puVar6,puVar7,0x20);
            FUN_1000c5e0(this_00,puVar6,(int)puVar7);
            FUN_1000bf3c(this,local_18);
            pIVar4 = FindItem(s_BLANK_10013980);
            uVar5 = (**(code **)(*(int *)pIVar4 + 4))();
            puVar3 = (undefined4 *)(**(code **)(*(int *)local_18 + 0x74))(local_50,uVar5);
            local_48 = SetItem(this,*puVar3,puVar3[1],uVar8);
            local_44 = local_48;
            if (local_48 != (ITEM *)0x0) {
              (*(code *)**(undefined4 **)local_48)(1);
            }
          }
          local_14 = local_14 + 1;
          if (local_14 < 0xd) {
            puVar3 = (undefined4 *)default_error_condition(local_28,local_10,local_14);
            local_8 = GetItem(this,*puVar3,puVar3[1]);
          }
          else if (local_10 < 0x13) {
            puVar3 = (undefined4 *)default_error_condition(local_30,local_10 + 1,0);
            local_8 = GetItem(this,*puVar3,puVar3[1]);
          }
        }
        local_10 = local_10 + 1;
      }
      bVar1 = IsEmpty(0x10015218);
      cVar2 = '\x01' - (CONCAT31(extraout_var_01,bVar1) != 0);
    }
  }
  return (bool)cVar2;
}



// public: void __thiscall MAP::DestroyMovingObjects(void)

void __thiscall MAP::DestroyMovingObjects(MAP *this)

{
  bool bVar1;
  undefined3 extraout_var;
  uint uVar2;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  uint local_10;
  int local_c;
  undefined4 *local_8;
  
                    // 0xc254  11  ?DestroyMovingObjects@MAP@@QAEXXZ
  local_c = FUN_100026f0(0x10015218);
  local_8 = (undefined4 *)0x0;
  bVar1 = IsEmpty(0x10015218);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_8 = (undefined4 *)FUN_10002380(&local_c);
    local_8 = (undefined4 *)*local_8;
  }
  local_10 = 0;
  while ((uVar2 = FUN_10005970(0x10015218), local_10 < uVar2 &&
         (bVar1 = IsEmpty(0x10015218), CONCAT31(extraout_var_00,bVar1) == 0))) {
    if (local_8 != (undefined4 *)0x0) {
      (**(code **)*local_8)(1);
    }
    local_10 = local_10 + 1;
    uVar2 = FUN_10005970(0x10015218);
    if (local_10 < uVar2) {
      local_8 = (undefined4 *)FUN_10002380(&local_c);
      local_8 = (undefined4 *)*local_8;
    }
  }
  bVar1 = IsEmpty(0x10015218);
  if (CONCAT31(extraout_var_01,bVar1) == 0) {
    RefreshBothLevelmapBuffers(this);
  }
  FUN_10008600(0x10015218);
  return;
}



void __fastcall FUN_1000c350(undefined4 *param_1)

{
  FUN_1000c4b0(param_1);
  return;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_1000c3f0(this,10);
  *(undefined ***)this = &PTR_LAB_100103e0;
  return this;
}



void * __thiscall FUN_1000c3a0(void *this,undefined4 *param_1)

{
  FUN_1000c450(this,param_1);
  return this;
}



void * __thiscall FUN_1000c3c0(void *this,uint param_1)

{
  FUN_1000c350((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_100020b0(this);
  }
  return this;
}



void * __thiscall FUN_1000c3f0(void *this,undefined4 param_1)

{
  FUN_10002410((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_100103f4;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



undefined4 * __thiscall FUN_1000c450(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_100060a0(this,*(undefined4 *)((int)this + 8),0);
  puVar1[2] = *param_1;
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



void __fastcall FUN_1000c4b0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1000eff9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_100103f4;
  local_8 = 0;
  FUN_10008600((int)param_1);
  local_8 = 0xffffffff;
  FUN_10002460(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_1000c510(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_10;
  ulong local_c;
  undefined4 *local_8;
  
  FUN_100020e0();
  bVar1 = FUN_10002710((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      FUN_10006180(param_1,&local_10,1);
      FUN_1000c450(this,&local_10);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_10006180(param_1,local_8 + 2,1);
    }
  }
  return;
}



void * __thiscall FUN_1000c5b0(void *this,uint param_1)

{
  FUN_1000c4b0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_100020b0(this);
  }
  return this;
}



void * __thiscall FUN_1000c5e0(void *this,void *param_1,int param_2)

{
                    // WARNING: Load size is inaccurate
  default_error_condition(param_1,*this * param_2,*(int *)((int)this + 4) * param_2);
  return param_1;
}



bool __fastcall FUN_1000c610(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_1000a7a0((undefined4 *)(param_1 + 0xc));
  return *(int *)(iVar1 + 0x75c) != 0;
}



void * __thiscall FUN_1000c640(void *this,void *param_1)

{
  int iVar1;
  
  iVar1 = FUN_1000a7a0((undefined4 *)((int)this + 0xc));
  FUN_1000c680(param_1,(undefined4 *)(iVar1 + 0x75c));
  return param_1;
}



void * __thiscall FUN_1000c680(void *this,undefined4 *param_1)

{
  *(undefined4 *)this = *param_1;
  CString::CString((CString *)((int)this + 4),(CString *)(param_1 + 1));
  *(undefined4 *)((int)this + 8) = param_1[2];
  *(undefined4 *)((int)this + 0xc) = param_1[3];
  *(undefined4 *)((int)this + 0x10) = param_1[4];
  return this;
}



void FUN_1000c6d0(void)

{
  FUN_1000c6df();
  FUN_1000c6f0();
  return;
}



void FUN_1000c6df(void)

{
  FUN_100022b0(&DAT_1001523c,0);
  return;
}



void FUN_1000c6f0(void)

{
  FUN_1000e1a8(FUN_1000c702);
  return;
}



void FUN_1000c702(void)

{
  if ((DAT_10015234 & 1) == 0) {
    DAT_10015234 = DAT_10015234 | 1;
    FUN_10007600((int *)&DAT_1001523c);
  }
  return;
}



void FUN_1000c72e(void)

{
  FUN_1000c73d();
  FUN_1000c74e();
  return;
}



void FUN_1000c73d(void)

{
  FUN_100022b0(&DAT_10015238,0);
  return;
}



void FUN_1000c74e(void)

{
  FUN_1000e1a8(FUN_1000c760);
  return;
}



void FUN_1000c760(void)

{
  if ((DAT_10015234 & 2) == 0) {
    DAT_10015234 = DAT_10015234 | 2;
    FUN_10007600((int *)&DAT_10015238);
  }
  return;
}



int * __cdecl FUN_1000c78c(char *param_1)

{
  int *piVar1;
  bool bVar2;
  CString *pCVar3;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  long lVar4;
  int iVar5;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  int iVar6;
  undefined3 extraout_var_03;
  undefined3 extraout_var_04;
  undefined3 extraout_var_05;
  undefined3 extraout_var_06;
  undefined3 extraout_var_07;
  undefined3 extraout_var_08;
  char *pcVar7;
  undefined3 extraout_var_09;
  undefined3 extraout_var_10;
  undefined3 extraout_var_11;
  STRING *pSVar8;
  void *pvVar9;
  undefined3 extraout_var_12;
  undefined3 extraout_var_13;
  undefined3 extraout_var_14;
  undefined3 extraout_var_15;
  LPCSTR lpLibFileName;
  HMODULE pHVar10;
  FARPROC pFVar11;
  char *unaff_EDI;
  undefined4 *puVar12;
  uint uVar13;
  uint uVar14;
  shared_ptr<> *psVar15;
  undefined4 *local_248;
  int *local_244;
  CString local_23c [4];
  CString local_238 [4];
  CString local_234 [4];
  CString local_230 [4];
  CString local_22c [4];
  shared_ptr<> local_228 [4];
  CString local_224 [4];
  shared_ptr<> local_220 [4];
  CString local_21c [4];
  CString local_218 [4];
  uint local_214;
  CString local_210 [4];
  uint local_20c;
  CString local_208 [4];
  uint local_204;
  CString local_200 [4];
  uint local_1fc;
  CString local_1f8 [4];
  uint local_1f4;
  CString local_1f0 [4];
  CString local_1ec [4];
  CString local_1e8 [4];
  CString local_1e4 [4];
  CString local_1e0 [4];
  CString local_1dc [4];
  CString local_1d8 [4];
  CString local_1d4 [4];
  CString local_1d0 [4];
  CString local_1cc [4];
  CString local_1c8 [4];
  CString local_1c4 [4];
  CString local_1c0 [4];
  CString local_1bc [4];
  CString local_1b8 [4];
  CString local_1b4 [4];
  CString local_1b0 [4];
  CString local_1ac [4];
  CString local_1a8 [4];
  CString local_1a4 [4];
  CString local_1a0 [4];
  CString local_19c [4];
  CString local_198 [4];
  CString local_194 [4];
  CString local_190 [4];
  CString local_18c [4];
  CString local_188 [4];
  CString local_184 [4];
  undefined4 *local_180;
  undefined4 *local_17c;
  shared_ptr<> local_178 [4];
  undefined4 *local_174;
  int *local_170;
  long local_16c;
  undefined4 local_168;
  undefined4 local_164 [23];
  undefined4 local_108;
  undefined4 local_104 [23];
  int local_a8;
  int local_a4;
  CString local_a0 [4];
  long local_9c;
  CString local_98 [4];
  long local_94;
  CString local_90 [4];
  long local_8c;
  CString local_88 [4];
  uint local_84;
  int local_80;
  STRING local_7c [4];
  CString local_78 [4];
  uint local_74;
  long local_70;
  uint local_6c;
  uint local_68;
  int local_64;
  SECTION local_60 [8];
  INIFILE local_58 [36];
  int local_34;
  int *local_30;
  CString local_2c [4];
  uint local_28;
  CString local_24 [4];
  CString local_20 [4];
  CString local_1c [4];
  SECTION local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000f2b2;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_174 = (undefined4 *)operator_new(0x84);
  local_8 = 0;
  if (local_174 == (undefined4 *)0x0) {
    local_244 = (int *)0x0;
  }
  else {
    local_244 = FUN_10003012(local_174);
  }
  local_170 = local_244;
  local_8 = 0xffffffff;
  local_30 = local_244;
  INIFILE::INIFILE(local_58,param_1,1);
  local_8 = 1;
  FUN_10002c20(local_24);
  local_8._0_1_ = 2;
  local_180 = (undefined4 *)operator_new(0x770);
  local_8._0_1_ = 3;
  if (local_180 == (undefined4 *)0x0) {
    local_248 = (undefined4 *)0x0;
  }
  else {
    local_248 = FUN_10002cbc(local_180);
  }
  local_17c = local_248;
  local_8._0_1_ = 2;
  FUN_1000dd10(local_178,local_248);
  local_8._0_1_ = 4;
  FUN_1000dcf0(local_30 + 3,local_178);
  local_8._0_1_ = 2;
  FUN_10007600((int *)local_178);
  pCVar3 = (CString *)INIFILE::GetSection(local_58,(char *)local_184);
  local_8._0_1_ = 5;
  FUN_100021e0(local_24,pCVar3);
  local_8 = CONCAT31(local_8._1_3_,2);
  FUN_10002c40(local_184);
  local_28 = 0;
  while (bVar2 = FUN_10008680((int *)local_24), CONCAT31(extraout_var,bVar2) == 0) {
    STRING::strtok((char *)local_7c,(char *)&_Delim_100139c8);
    local_8._0_1_ = 6;
    STRING::strtok((char *)local_78,(char *)&_Delim_100139cc);
    local_8 = CONCAT31(local_8._1_3_,7);
    local_74 = 0;
    STRING::trim(local_7c,(char *)&this_100139d0);
    local_70 = STRING::atol(unaff_EDI);
    while (bVar2 = FUN_10008680((int *)local_78), CONCAT31(extraout_var_00,bVar2) == 0) {
      STRING::strtok((char *)local_188,(char *)&_Delim_100139d8);
      local_8._0_1_ = 8;
      lVar4 = STRING::atol(unaff_EDI);
      local_80 = lVar4 + local_70;
      local_8 = CONCAT31(local_8._1_3_,7);
      FUN_10002c40(local_188);
      uVar13 = local_28;
      uVar14 = local_74;
      iVar6 = local_80;
      iVar5 = FUN_1000a7a0(local_30 + 3);
      FUN_1000dda0((void *)(iVar5 + 0x5c8),uVar13,uVar14,iVar6);
      local_74 = local_74 + 1;
    }
    local_28 = local_28 + 1;
    local_8._0_1_ = 6;
    FUN_10002c40(local_78);
    local_8 = CONCAT31(local_8._1_3_,2);
    FUN_10002c40((CString *)local_7c);
  }
  pCVar3 = (CString *)INIFILE::GetSection(local_58,(char *)local_18c);
  local_8._0_1_ = 9;
  FUN_100021e0(local_24,pCVar3);
  local_8 = CONCAT31(local_8._1_3_,2);
  FUN_10002c40(local_18c);
  local_6c = 0;
  while (bVar2 = FUN_10008680((int *)local_24), CONCAT31(extraout_var_01,bVar2) == 0) {
    STRING::strtok((char *)local_88,(char *)&_Delim_100139f8);
    local_8._0_1_ = 10;
    local_84 = 0;
    while (bVar2 = FUN_10008680((int *)local_88), CONCAT31(extraout_var_02,bVar2) == 0) {
      STRING::strtok((char *)local_190,(char *)&_Delim_100139fc);
      local_8._0_1_ = 0xb;
      local_8c = STRING::atol(unaff_EDI);
      local_8._0_1_ = 10;
      FUN_10002c40(local_190);
      uVar13 = local_6c;
      uVar14 = local_84;
      lVar4 = local_8c;
      iVar6 = FUN_1000a7a0(local_30 + 3);
      FUN_1000dda0((void *)(iVar6 + 0x5c8),uVar13,uVar14,lVar4);
      local_84 = local_84 + 1;
    }
    local_6c = local_6c + 1;
    local_8 = CONCAT31(local_8._1_3_,2);
    FUN_10002c40(local_88);
  }
  pCVar3 = (CString *)INIFILE::GetSection(local_58,(char *)local_194);
  local_8._0_1_ = 0xc;
  FUN_100021e0(local_24,pCVar3);
  local_8 = CONCAT31(local_8._1_3_,2);
  FUN_10002c40(local_194);
  local_6c = 0;
  while (bVar2 = FUN_10008680((int *)local_24), CONCAT31(extraout_var_03,bVar2) == 0) {
    iVar6 = FUN_1000a7a0(local_30 + 3);
    *(undefined1 *)(iVar6 + 0x6d4) = 1;
    STRING::strtok((char *)local_90,(char *)&_Delim_10013a10);
    local_8._0_1_ = 0xd;
    while (bVar2 = FUN_10008680((int *)local_90), CONCAT31(extraout_var_04,bVar2) == 0) {
      STRING::strtok((char *)local_198,(char *)&_Delim_10013a14);
      local_8._0_1_ = 0xe;
      local_94 = STRING::atol(unaff_EDI);
      local_8._0_1_ = 0xd;
      FUN_10002c40(local_198);
      lVar4 = local_94;
      iVar6 = FUN_1000a7a0(local_30 + 3);
      FUN_1000dd50((void *)(iVar6 + 0x88 + local_6c * 0x54),lVar4);
    }
    local_6c = local_6c + 1;
    local_8 = CONCAT31(local_8._1_3_,2);
    FUN_10002c40(local_90);
  }
  pCVar3 = (CString *)INIFILE::GetSection(local_58,(char *)local_19c);
  local_8._0_1_ = 0xf;
  FUN_100021e0(local_24,pCVar3);
  local_8 = CONCAT31(local_8._1_3_,2);
  FUN_10002c40(local_19c);
  local_6c = 0;
  while (bVar2 = FUN_10008680((int *)local_24), CONCAT31(extraout_var_05,bVar2) == 0) {
    iVar6 = FUN_1000a7a0(local_30 + 3);
    *(undefined1 *)(iVar6 + 0x6d4) = 1;
    STRING::strtok((char *)local_98,(char *)&_Delim_10013a34);
    local_8._0_1_ = 0x10;
    while (bVar2 = FUN_10008680((int *)local_98), CONCAT31(extraout_var_06,bVar2) == 0) {
      STRING::strtok((char *)local_1a0,(char *)&_Delim_10013a38);
      local_8._0_1_ = 0x11;
      local_9c = STRING::atol(unaff_EDI);
      local_8._0_1_ = 0x10;
      FUN_10002c40(local_1a0);
      lVar4 = local_9c;
      iVar6 = FUN_1000a7a0(local_30 + 3);
      FUN_1000dd50((void *)(iVar6 + 0x328 + local_6c * 0x54),lVar4);
    }
    local_6c = local_6c + 1;
    local_8 = CONCAT31(local_8._1_3_,2);
    FUN_10002c40(local_98);
  }
  pCVar3 = (CString *)INIFILE::GetSection(local_58,(char *)local_1a4);
  local_8._0_1_ = 0x12;
  FUN_100021e0(local_24,pCVar3);
  local_8 = CONCAT31(local_8._1_3_,2);
  FUN_10002c40(local_1a4);
  local_34 = 0;
  while (bVar2 = FUN_10008680((int *)local_24), CONCAT31(extraout_var_07,bVar2) == 0) {
    STRING::strtok((char *)local_a0,(char *)&_Delim_10013a58);
    local_8._0_1_ = 0x13;
    local_a4 = 0;
    while (bVar2 = FUN_10008680((int *)local_a0), CONCAT31(extraout_var_08,bVar2) == 0) {
      STRING::strtok((char *)local_1a8,(char *)&_Delim_10013a5c);
      local_8._0_1_ = 0x14;
      local_a8 = STRING::atol(unaff_EDI);
      local_8._0_1_ = 0x13;
      FUN_10002c40(local_1a8);
      if (local_a8 == 0) {
        iVar6 = FUN_1000a7a0(local_30 + 3);
        *(undefined1 *)(iVar6 + 0x738) = 1;
      }
      if (local_a8 == -1) {
        iVar6 = FUN_1000a7a0(local_30 + 3);
        *(undefined1 *)(iVar6 + 0x739) = 1;
      }
      iVar6 = FUN_1000a7a0(local_30 + 3);
      *(undefined1 *)(local_a4 + iVar6 + 0x48 + local_34 * 8) = (undefined1)local_a8;
      local_a4 = local_a4 + 1;
    }
    local_34 = local_34 + 1;
    local_8 = CONCAT31(local_8._1_3_,2);
    FUN_10002c40(local_a0);
  }
  pCVar3 = (CString *)INIFILE::GetSection(local_58,(char *)local_1ac);
  local_8._0_1_ = 0x15;
  FUN_100021e0(local_24,pCVar3);
  local_8._0_1_ = 2;
  FUN_10002c40(local_1ac);
  pcVar7 = (char *)FUN_1000a7a0((undefined4 *)local_24);
  iVar6 = FUN_1000a7a0(local_30 + 3);
  FUN_1000dbc7(iVar6 + 0x6d8,pcVar7);
  pCVar3 = (CString *)INIFILE::GetSection(local_58,(char *)local_1b0);
  local_8._0_1_ = 0x16;
  FUN_100021e0(local_24,pCVar3);
  local_8._0_1_ = 2;
  FUN_10002c40(local_1b0);
  local_68 = 0;
  FUN_10002c20(local_1c);
  local_8._0_1_ = 0x17;
  while (bVar2 = FUN_10008680((int *)local_24), CONCAT31(extraout_var_09,bVar2) == 0) {
    pcVar7 = STRING::strtok((char *)local_1b8,(char *)&_Delim_10013a80);
    local_8._0_1_ = 0x18;
    operator+(local_1bc,pcVar7);
    local_8._0_1_ = 0x19;
    pCVar3 = (CString *)operator+(local_1c0,local_1c);
    local_8._0_1_ = 0x1a;
    FUN_100053f0(local_1b4,pCVar3);
    local_8._0_1_ = 0x1b;
    FUN_100021e0(local_1c,local_1b4);
    local_8._0_1_ = 0x1a;
    FUN_10002c40(local_1b4);
    local_8._0_1_ = 0x19;
    CString::~CString(local_1c0);
    local_8._0_1_ = 0x18;
    CString::~CString(local_1bc);
    local_8._0_1_ = 0x17;
    FUN_10002c40(local_1b8);
    local_68 = local_68 + 1;
    if (2 < local_68) {
      local_108 = 0;
      puVar12 = local_104;
      for (iVar6 = 0x17; iVar6 != 0; iVar6 = iVar6 + -1) {
        *puVar12 = 0;
        puVar12 = puVar12 + 1;
      }
      pcVar7 = (char *)FUN_1000a7a0((undefined4 *)local_1c);
      FUN_1000dbc7((int)&local_108,pcVar7);
      puVar12 = &local_108;
      iVar6 = FUN_1000a7a0(local_30 + 3);
      FUN_100061c0((void *)(iVar6 + 8),puVar12);
      FUN_10006db0(local_1c4,&DAT_10015240);
      local_8._0_1_ = 0x1c;
      FUN_100021e0(local_1c,local_1c4);
      local_8._0_1_ = 0x17;
      FUN_10002c40(local_1c4);
      local_68 = 0;
    }
  }
  pCVar3 = (CString *)INIFILE::GetSection(local_58,(char *)local_1c8);
  local_8._0_1_ = 0x1d;
  FUN_100021e0(local_24,pCVar3);
  local_8._0_1_ = 0x17;
  FUN_10002c40(local_1c8);
  local_68 = 0;
  pCVar3 = (CString *)CString::CString(local_1d0);
  local_8._0_1_ = 0x1e;
  FUN_100053f0(local_1cc,pCVar3);
  local_8._0_1_ = 0x1f;
  FUN_100021e0(local_1c,local_1cc);
  local_8._0_1_ = 0x1e;
  FUN_10002c40(local_1cc);
  local_8 = CONCAT31(local_8._1_3_,0x17);
  CString::~CString(local_1d0);
  while (bVar2 = FUN_10008680((int *)local_24), CONCAT31(extraout_var_10,bVar2) == 0) {
    pcVar7 = STRING::strtok((char *)local_1d8,(char *)&_Delim_10013a8c);
    local_8._0_1_ = 0x20;
    operator+(local_1dc,pcVar7);
    local_8._0_1_ = 0x21;
    pCVar3 = (CString *)operator+(local_1e0,local_1c);
    local_8._0_1_ = 0x22;
    FUN_100053f0(local_1d4,pCVar3);
    local_8._0_1_ = 0x23;
    FUN_100021e0(local_1c,local_1d4);
    local_8._0_1_ = 0x22;
    FUN_10002c40(local_1d4);
    local_8._0_1_ = 0x21;
    CString::~CString(local_1e0);
    local_8._0_1_ = 0x20;
    CString::~CString(local_1dc);
    local_8 = CONCAT31(local_8._1_3_,0x17);
    FUN_10002c40(local_1d8);
    local_68 = local_68 + 1;
    if (2 < local_68) {
      local_168 = 0;
      puVar12 = local_164;
      for (iVar6 = 0x17; iVar6 != 0; iVar6 = iVar6 + -1) {
        *puVar12 = 0;
        puVar12 = puVar12 + 1;
      }
      pcVar7 = (char *)FUN_1000a7a0((undefined4 *)local_1c);
      FUN_1000dbc7((int)&local_168,pcVar7);
      puVar12 = &local_168;
      iVar6 = FUN_1000a7a0(local_30 + 3);
      FUN_100061c0((void *)(iVar6 + 0x24),puVar12);
      FUN_10006db0(local_1e4,&DAT_10015244);
      local_8._0_1_ = 0x24;
      FUN_100021e0(local_1c,local_1e4);
      local_8 = CONCAT31(local_8._1_3_,0x17);
      FUN_10002c40(local_1e4);
      local_68 = 0;
    }
  }
  pCVar3 = (CString *)INIFILE::GetSection(local_58,(char *)local_1e8);
  local_8._0_1_ = 0x25;
  FUN_100021e0(local_24,pCVar3);
  local_8 = CONCAT31(local_8._1_3_,0x17);
  FUN_10002c40(local_1e8);
  local_64 = 0;
  while (bVar2 = FUN_10008680((int *)local_24), CONCAT31(extraout_var_11,bVar2) == 0) {
    STRING::strtok((char *)local_1ec,(char *)&_Delim_10013aa4);
    local_8._0_1_ = 0x26;
    local_16c = STRING::atol(unaff_EDI);
    local_8 = CONCAT31(local_8._1_3_,0x17);
    FUN_10002c40(local_1ec);
    iVar6 = FUN_1000a7a0(local_30 + 3);
    *(undefined1 *)(iVar6 + 0x40 + local_64) = (undefined1)local_16c;
    local_64 = local_64 + 1;
  }
  FUN_1000de30(local_18,local_58,s_FLAGS_10013aa8);
  local_8._0_1_ = 0x27;
  pcVar7 = &DAT_10013ab8;
  pSVar8 = (STRING *)INIFILE::SECTION::Get(local_18,(char *)local_1f0);
  local_8._0_1_ = 0x28;
  pSVar8 = STRING::trim(pSVar8,pcVar7);
  iVar6 = FUN_1000a7a0(local_30 + 3);
  CString::operator=((CString *)(iVar6 + 0x73c),(CString *)pSVar8);
  local_8._0_1_ = 0x27;
  FUN_10002c40(local_1f0);
  pcVar7 = &DAT_10013ac4;
  pSVar8 = (STRING *)INIFILE::SECTION::Get(local_18,(char *)local_1f8);
  local_8._0_1_ = 0x29;
  bVar2 = STRING::equi(pSVar8,pcVar7);
  local_1f4 = CONCAT31(local_1f4._1_3_,bVar2);
  local_8 = CONCAT31(local_8._1_3_,0x27);
  FUN_10002c40(local_1f8);
  if ((local_1f4 & 0xff) != 0) {
    iVar6 = FUN_1000a7a0(local_30 + 3);
    *(undefined4 *)(iVar6 + 0x744) = 1;
  }
  pcVar7 = &DAT_10013ad4;
  pSVar8 = (STRING *)INIFILE::SECTION::Get(local_18,(char *)local_200);
  local_8._0_1_ = 0x2a;
  bVar2 = STRING::equi(pSVar8,pcVar7);
  local_1fc = CONCAT31(local_1fc._1_3_,bVar2);
  local_8 = CONCAT31(local_8._1_3_,0x27);
  FUN_10002c40(local_200);
  if ((local_1fc & 0xff) != 0) {
    iVar6 = FUN_1000a7a0(local_30 + 3);
    *(undefined4 *)(iVar6 + 0x748) = 1;
  }
  pcVar7 = &DAT_10013ae8;
  pSVar8 = (STRING *)INIFILE::SECTION::Get(local_18,(char *)local_208);
  local_8._0_1_ = 0x2b;
  bVar2 = STRING::equi(pSVar8,pcVar7);
  local_204 = CONCAT31(local_204._1_3_,bVar2);
  local_8 = CONCAT31(local_8._1_3_,0x27);
  FUN_10002c40(local_208);
  if ((local_204 & 0xff) != 0) {
    (**(code **)(*local_30 + 0xc))();
  }
  pcVar7 = &DAT_10013aec;
  pvVar9 = (void *)INIFILE::SECTION::Get(local_18,(char *)local_210);
  local_8._0_1_ = 0x2c;
  bVar2 = FUN_10005600(pvVar9,pcVar7);
  local_20c = CONCAT31(local_20c._1_3_,bVar2);
  local_8._0_1_ = 0x27;
  FUN_10002c40(local_210);
  if ((local_20c & 0xff) != 0) {
    local_30[10] = (int)&LAB_1000dd40;
  }
  pcVar7 = &DAT_10013b08;
  pvVar9 = (void *)INIFILE::SECTION::Get(local_18,(char *)local_218);
  local_8._0_1_ = 0x2d;
  bVar2 = FUN_10005600(pvVar9,pcVar7);
  local_214 = CONCAT31(local_214._1_3_,bVar2);
  local_8._0_1_ = 0x27;
  FUN_10002c40(local_218);
  if ((local_214 & 0xff) != 0) {
    local_30[10] = (int)&LAB_1000dd30;
  }
  pcVar7 = s_black_tiles_bmp_10013b24;
  iVar6 = FUN_1000a7a0(local_30 + 3);
  CString::operator=((CString *)(iVar6 + 0x74c),pcVar7);
  psVar15 = (shared_ptr<> *)&DAT_1001523c;
  iVar6 = FUN_1000a7a0(local_30 + 3);
  FUN_1000dcf0((void *)(iVar6 + 0x754),psVar15);
  pCVar3 = (CString *)INIFILE::SECTION::Get(local_18,(char *)local_21c);
  local_8._0_1_ = 0x2e;
  FUN_100021e0(local_24,pCVar3);
  local_8._0_1_ = 0x27;
  FUN_10002c40(local_21c);
  bVar2 = FUN_10008680((int *)local_24);
  if (CONCAT31(extraout_var_12,bVar2) == 0) {
    pCVar3 = local_24;
    iVar6 = FUN_1000a7a0(local_30 + 3);
    CString::operator=((CString *)(iVar6 + 0x74c),pCVar3);
    FUN_100022b0(local_220,0);
    local_8._0_1_ = 0x2f;
    psVar15 = local_220;
    iVar6 = FUN_1000a7a0(local_30 + 3);
    FUN_1000dcf0((void *)(iVar6 + 0x754),psVar15);
    local_8._0_1_ = 0x27;
    FUN_10007600((int *)local_220);
  }
  pcVar7 = s_black_tiles_small_bmp_10013b40;
  iVar6 = FUN_1000a7a0(local_30 + 3);
  CString::operator=((CString *)(iVar6 + 0x750),pcVar7);
  psVar15 = (shared_ptr<> *)&DAT_10015238;
  iVar6 = FUN_1000a7a0(local_30 + 3);
  FUN_1000dcf0((void *)(iVar6 + 0x758),psVar15);
  pCVar3 = (CString *)INIFILE::SECTION::Get(local_18,(char *)local_224);
  local_8._0_1_ = 0x30;
  FUN_100021e0(local_24,pCVar3);
  local_8._0_1_ = 0x27;
  FUN_10002c40(local_224);
  bVar2 = FUN_10008680((int *)local_24);
  if (CONCAT31(extraout_var_13,bVar2) == 0) {
    pCVar3 = local_24;
    iVar6 = FUN_1000a7a0(local_30 + 3);
    CString::operator=((CString *)(iVar6 + 0x750),pCVar3);
    FUN_100022b0(local_228,0);
    local_8._0_1_ = 0x31;
    psVar15 = local_228;
    iVar6 = FUN_1000a7a0(local_30 + 3);
    FUN_1000dcf0((void *)(iVar6 + 0x758),psVar15);
    local_8._0_1_ = 0x27;
    FUN_10007600((int *)local_228);
  }
  FUN_1000de30(local_60,local_58,s_MOVING_10013b68);
  local_8._0_1_ = 0x32;
  INIFILE::SECTION::Get(local_60,(char *)local_2c);
  local_8._0_1_ = 0x33;
  INIFILE::SECTION::Get(local_60,(char *)local_20);
  local_8._0_1_ = 0x34;
  bVar2 = FUN_10008680((int *)local_2c);
  if ((CONCAT31(extraout_var_14,bVar2) == 0) &&
     (bVar2 = FUN_10008680((int *)local_20), CONCAT31(extraout_var_15,bVar2) == 0)) {
    pCVar3 = local_20;
    iVar6 = FUN_1000a7a0(local_30 + 3);
    CString::operator=((CString *)(iVar6 + 0x760),pCVar3);
    iVar6 = FUN_1000a7a0(local_30 + 3);
    INIFILE::SECTION::Get(local_60,&DAT_10013b80,(ulong *)(iVar6 + 0x764));
    iVar6 = FUN_1000a7a0(local_30 + 3);
    INIFILE::SECTION::Get(local_60,&DAT_10013b88,(ulong *)(iVar6 + 0x768));
    pCVar3 = (CString *)operator+((char *)local_230,(CString *)s_RELEASE__10013b90);
    local_8._0_1_ = 0x35;
    FUN_100053f0(local_22c,pCVar3);
    local_8._0_1_ = 0x36;
    FUN_100021e0(local_2c,local_22c);
    local_8._0_1_ = 0x35;
    FUN_10002c40(local_22c);
    local_8._0_1_ = 0x34;
    CString::~CString(local_230);
    bVar2 = IsRelativePath(local_2c);
    if (bVar2) {
      pCVar3 = (CString *)REG::RootDir();
      local_8._0_1_ = 0x37;
      pCVar3 = (CString *)operator+(local_23c,pCVar3);
      local_8._0_1_ = 0x38;
      FUN_100053f0(local_234,pCVar3);
      local_8._0_1_ = 0x39;
      FUN_100021e0(local_2c,local_234);
      local_8._0_1_ = 0x38;
      FUN_10002c40(local_234);
      local_8._0_1_ = 0x37;
      CString::~CString(local_23c);
      local_8._0_1_ = 0x34;
      CString::~CString(local_238);
    }
    lpLibFileName = (LPCSTR)FUN_1000a7a0((undefined4 *)local_2c);
    pHVar10 = LoadLibraryA(lpLibFileName);
    iVar6 = FUN_1000a7a0(local_30 + 3);
    *(HMODULE *)(iVar6 + 0x75c) = pHVar10;
    pcVar7 = s__Create__YAPAVTwMovingObject__XZ_10013988;
    iVar6 = FUN_1000a7a0(local_30 + 3);
    pFVar11 = GetProcAddress(*(HMODULE *)(iVar6 + 0x75c),pcVar7);
    iVar6 = FUN_1000a7a0(local_30 + 3);
    *(FARPROC *)(iVar6 + 0x76c) = pFVar11;
  }
  piVar1 = local_30;
  local_8._0_1_ = 0x33;
  FUN_10002c40(local_20);
  local_8._0_1_ = 0x32;
  FUN_10002c40(local_2c);
  local_8._0_1_ = 0x27;
  FUN_10007620((int)local_60);
  local_8._0_1_ = 0x17;
  FUN_10007620((int)local_18);
  local_8._0_1_ = 2;
  FUN_10002c40(local_1c);
  local_8 = CONCAT31(local_8._1_3_,1);
  FUN_10002c40(local_24);
  local_8 = 0xffffffff;
  INIFILE::~INIFILE(local_58);
  ExceptionList = local_10;
  return piVar1;
}



void __cdecl FUN_1000dbc7(int param_1,char *param_2)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  char *_Str;
  CString local_28 [4];
  long local_24;
  int local_20;
  CString local_1c [4];
  int local_18;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000f2d7;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10006db0(local_14,param_2);
  local_8 = 0;
  local_18 = 0;
  while( true ) {
    bVar1 = FUN_10008680((int *)local_14);
    if (CONCAT31(extraout_var,bVar1) != 0) break;
    STRING::strtok((char *)local_1c,(char *)&_Delim_10013b9c);
    local_8._0_1_ = 1;
    local_20 = 0;
    while( true ) {
      bVar1 = FUN_10008680((int *)local_1c);
      if (CONCAT31(extraout_var_00,bVar1) != 0) break;
      _Str = STRING::strtok((char *)local_28,(char *)&_Delim_10013ba0);
      local_8._0_1_ = 2;
      local_24 = STRING::atol(_Str);
      local_8._0_1_ = 1;
      FUN_10002c40(local_28);
      if (local_18 == 0) {
        *(long *)(param_1 + local_20 * 4) = local_24;
      }
      if (local_18 == 1) {
        *(long *)(param_1 + 0x20 + local_20 * 4) = local_24;
      }
      if (local_18 == 2) {
        *(long *)(param_1 + 0x40 + local_20 * 4) = local_24;
      }
      local_20 = local_20 + 1;
    }
    local_18 = local_18 + 1;
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_10002c40(local_1c);
  }
  local_8 = 0xffffffff;
  FUN_10002c40(local_14);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_1000dcf0(void *this,shared_ptr<> *param_1)

{
  std::shared_ptr<>::shared_ptr<>((shared_ptr<> *)this,param_1);
  return this;
}



void * __thiscall FUN_1000dd10(void *this,undefined4 param_1)

{
  FUN_100022f0(this,param_1);
  return this;
}



bool __thiscall FUN_1000dd50(void *this,undefined4 param_1)

{
  bool bVar1;
  
  if (*(uint *)((int)this + 0x50) < 0x14) {
    if (*(int *)((int)this + 0x50) == 0x14) {
      bVar1 = false;
    }
    else {
      *(undefined4 *)((int)this + *(int *)((int)this + 0x50) * 4) = param_1;
      *(int *)((int)this + 0x50) = *(int *)((int)this + 0x50) + 1;
      bVar1 = true;
    }
  }
  else {
    bVar1 = false;
  }
  return bVar1;
}



uint __thiscall FUN_1000dda0(void *this,uint param_1,uint param_2,undefined4 param_3)

{
  uint in_EAX;
  uint uVar1;
  undefined4 uVar2;
  uint local_8;
  
  if (param_1 < 8) {
    if (param_2 < 8) {
      if ((param_1 < 8) && (param_2 < 8)) {
        if (param_1 == 0) {
          uVar2 = 0;
          for (local_8 = 0; local_8 < 8; local_8 = local_8 + 1) {
            *(undefined4 *)((int)this + param_2 * 4 + local_8 * 0x20) = param_3;
            uVar2 = param_3;
          }
          uVar1 = CONCAT31((int3)((uint)uVar2 >> 8),1);
        }
        else {
          *(undefined4 *)((int)this + param_2 * 4 + param_1 * 0x20) = param_3;
          uVar1 = CONCAT31((int3)(param_2 >> 8),1);
        }
      }
      else {
        uVar1 = 0;
      }
    }
    else {
      uVar1 = 0;
    }
  }
  else {
    uVar1 = in_EAX & 0xffffff00;
  }
  return uVar1;
}



void * __thiscall FUN_1000de30(void *this,undefined4 param_1,char *param_2)

{
  *(undefined4 *)this = param_1;
  CString::CString((CString *)((int)this + 4),param_2);
  return this;
}



void __thiscall CString::~CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x1000de58. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CString(this);
  return;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000de5e. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



CString * __thiscall CString::operator=(CString *this,CString *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000de6a. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator=(this,param_1);
  return pCVar1;
}



void __thiscall CPlex::FreeDataChain(CPlex *this)

{
                    // WARNING: Could not recover jumptable at 0x1000de70. Too many branches
                    // WARNING: Treating indirect jump as call
  FreeDataChain(this);
  return;
}



ulong __thiscall CArchive::ReadCount(CArchive *this)

{
  ulong uVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000de76. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = ReadCount(this);
  return uVar1;
}



void __thiscall CArchive::WriteCount(CArchive *this,ulong param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000de7c. Too many branches
                    // WARNING: Treating indirect jump as call
  WriteCount(this,param_1);
  return;
}



uint __thiscall CArchive::Read(CArchive *this,void *param_1,uint param_2)

{
  uint uVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000de82. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = Read(this,param_1,param_2);
  return uVar1;
}



void __thiscall CArchive::Write(CArchive *this,void *param_1,uint param_2)

{
                    // WARNING: Could not recover jumptable at 0x1000de88. Too many branches
                    // WARNING: Treating indirect jump as call
  Write(this,param_1,param_2);
  return;
}



CPlex * CPlex::Create(CPlex **param_1,uint param_2,uint param_3)

{
  CPlex *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000de8e. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = Create(param_1,param_2,param_3);
  return pCVar1;
}



void __thiscall CString::CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x1000de94. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this);
  return;
}



CString * __thiscall CString::operator=(CString *this,char *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000de9a. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator=(this,param_1);
  return pCVar1;
}



void __thiscall CString::CString(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000dea0. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000dea6. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void __thiscall CString::CString(CString *this,CString *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000deac. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



void __thiscall CString::SpanExcluding(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000deb2. Too many branches
                    // WARNING: Treating indirect jump as call
  SpanExcluding(this,param_1);
  return;
}



void __thiscall CString::MakeUpper(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x1000deb8. Too many branches
                    // WARNING: Treating indirect jump as call
  MakeUpper(this);
  return;
}



void __thiscall CFileFind::GetFileName(CFileFind *this)

{
                    // WARNING: Could not recover jumptable at 0x1000debe. Too many branches
                    // WARNING: Treating indirect jump as call
  GetFileName(this);
  return;
}



void __thiscall CFileFind::GetFilePath(CFileFind *this)

{
                    // WARNING: Could not recover jumptable at 0x1000dec4. Too many branches
                    // WARNING: Treating indirect jump as call
  GetFilePath(this);
  return;
}



BOOL CFileFind::FindNextFileA(HANDLE hFindFile,LPWIN32_FIND_DATAA lpFindFileData)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000deca. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = FindNextFileA(hFindFile,lpFindFileData);
  return BVar1;
}



void __thiscall CFileFind::~CFileFind(CFileFind *this)

{
                    // WARNING: Could not recover jumptable at 0x1000ded0. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CFileFind(this);
  return;
}



int __thiscall CFileFind::FindFile(CFileFind *this,char *param_1,ulong param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000ded6. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = FindFile(this,param_1,param_2);
  return iVar1;
}



void operator+(CString *param_1,char *param_2)

{
                    // WARNING: Could not recover jumptable at 0x1000dedc. Too many branches
                    // WARNING: Treating indirect jump as call
  operator+(param_1,param_2);
  return;
}



void __thiscall CFileFind::CFileFind(CFileFind *this)

{
                    // WARNING: Could not recover jumptable at 0x1000dee2. Too many branches
                    // WARNING: Treating indirect jump as call
  CFileFind(this);
  return;
}



CString * __thiscall CString::operator+=(CString *this,CString *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000dee8. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator+=(this,param_1);
  return pCVar1;
}



void operator+(char *param_1,CString *param_2)

{
                    // WARNING: Could not recover jumptable at 0x1000deee. Too many branches
                    // WARNING: Treating indirect jump as call
  operator+(param_1,param_2);
  return;
}



void operator+(CString *param_1,CString *param_2)

{
                    // WARNING: Could not recover jumptable at 0x1000def4. Too many branches
                    // WARNING: Treating indirect jump as call
  operator+(param_1,param_2);
  return;
}



void __thiscall CException::Delete(CException *this)

{
                    // WARNING: Could not recover jumptable at 0x1000defa. Too many branches
                    // WARNING: Treating indirect jump as call
  Delete(this);
  return;
}



void __thiscall CFile::~CFile(CFile *this)

{
                    // WARNING: Could not recover jumptable at 0x1000df00. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CFile(this);
  return;
}



void __thiscall CArchive::~CArchive(CArchive *this)

{
                    // WARNING: Could not recover jumptable at 0x1000df06. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CArchive(this);
  return;
}



void __thiscall
CArchive::CArchive(CArchive *this,CFile *param_1,uint param_2,int param_3,void *param_4)

{
                    // WARNING: Could not recover jumptable at 0x1000df0c. Too many branches
                    // WARNING: Treating indirect jump as call
  CArchive(this,param_1,param_2,param_3,param_4);
  return;
}



void __thiscall CFile::CFile(CFile *this,char *param_1,uint param_2)

{
                    // WARNING: Could not recover jumptable at 0x1000df12. Too many branches
                    // WARNING: Treating indirect jump as call
  CFile(this,param_1,param_2);
  return;
}



void __thiscall CArchive::WriteString(CArchive *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000df18. Too many branches
                    // WARNING: Treating indirect jump as call
  WriteString(this,param_1);
  return;
}



void __thiscall CString::CString(CString *this,char *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x1000df1e. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1,param_2);
  return;
}



int __thiscall CArchive::ReadString(CArchive *this,CString *param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000df24. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = ReadString(this,param_1);
  return iVar1;
}



void __thiscall CString::Mid(CString *this,int param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000df2a. Too many branches
                    // WARNING: Treating indirect jump as call
  Mid(this,param_1);
  return;
}



CString * __thiscall CString::operator+=(CString *this,char *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000df30. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator+=(this,param_1);
  return pCVar1;
}



void __thiscall CString::Format(CString *this,char *param_1,...)

{
                    // WARNING: Could not recover jumptable at 0x1000df36. Too many branches
                    // WARNING: Treating indirect jump as call
  Format(this,param_1);
  return;
}



undefined4 * FUN_1000df46(void)

{
  AFX_MODULE_STATE::AFX_MODULE_STATE
            ((AFX_MODULE_STATE *)&param_1_10015250,1,AfxWndProcDllStatic,0x600);
  param_1_10015250 = (AFX_MAINTAIN_STATE2 *)&PTR_FUN_10010410;
  return &param_1_10015250;
}



void * __thiscall FUN_1000df6e(void *this,byte param_1)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)this);
  if ((param_1 & 1) != 0) {
    CNoTrackObject::operator_delete(this);
  }
  return this;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x1000e36e. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



void FUN_1000df8e(void)

{
  FUN_1000e1a8(FUN_1000df9a);
  return;
}



void FUN_1000df9a(void)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)&param_1_10015250);
  return;
}



// Library Function - Single Match
//  long __stdcall AfxWndProcDllStatic(struct HWND__ *,unsigned int,unsigned int,long)
// 
// Library: Visual Studio 2003 Release
// param_1 parameter of AFX_MODULE_STATE
// 

long AfxWndProcDllStatic(HWND__ *param_1,uint param_2,uint param_3,long param_4)

{
  long lVar1;
  int unaff_EBP;
  
  FUN_1000e330();
  AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
            ((AFX_MAINTAIN_STATE2 *)(unaff_EBP + -0x14),(AFX_MODULE_STATE *)&param_1_10015250);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  lVar1 = AfxWndProc(*(HWND__ **)(unaff_EBP + 8),*(uint *)(unaff_EBP + 0xc),
                     *(uint *)(unaff_EBP + 0x10),*(long *)(unaff_EBP + 0x14));
  *(undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4) = *(undefined4 *)(unaff_EBP + -0x14);
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return lVar1;
}



int FUN_1000dfe9(HINSTANCE__ *param_1,int param_2)

{
  undefined4 uVar1;
  int *piVar2;
  _AFX_THREAD_STATE *p_Var3;
  int iVar4;
  AFX_MODULE_STATE *pAVar5;
  CDynLinkLibrary *this;
  undefined4 local_c;
  int local_8;
  
  if (param_2 != 1) {
    if (param_2 == 0) {
      pAVar5 = AfxSetModuleState((AFX_MODULE_STATE *)&param_1_10015250);
      p_Var3 = AfxGetThreadState();
      *(AFX_MODULE_STATE **)(p_Var3 + 8) = pAVar5;
      pAVar5 = AfxGetModuleState();
      if (*(int **)(pAVar5 + 4) != (int *)0x0) {
        (**(code **)(**(int **)(pAVar5 + 4) + 0x70))();
      }
      AfxLockTempMaps();
      AfxUnlockTempMaps(-1);
      AfxWinTerm();
      AfxTermExtensionModule((AFX_EXTENSION_MODULE *)&param_1_100162e0,1);
    }
    else if (param_2 == 3) {
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
                ((AFX_MAINTAIN_STATE2 *)&local_c,(AFX_MODULE_STATE *)&param_1_10015250);
      AfxLockTempMaps();
      AfxUnlockTempMaps(-1);
      AfxTermThread(param_1);
      *(undefined4 *)(local_8 + 4) = local_c;
    }
    return 1;
  }
  param_2 = 0;
  AfxCoreInitModule();
  p_Var3 = AfxGetThreadState();
  uVar1 = *(undefined4 *)(p_Var3 + 8);
  iVar4 = AfxWinInit(param_1,(HINSTANCE__ *)0x0,(char *)&param_3_100151e8,0);
  if (iVar4 != 0) {
    pAVar5 = AfxGetModuleState();
    piVar2 = *(int **)(pAVar5 + 4);
    if ((piVar2 == (int *)0x0) || (iVar4 = (**(code **)(*piVar2 + 0x58))(), iVar4 != 0)) {
      *(undefined4 *)(p_Var3 + 8) = uVar1;
      AfxInitExtensionModule((AFX_EXTENSION_MODULE *)&param_1_100162e0,param_1);
      this = (CDynLinkLibrary *)operator_new(0x40);
      if (this != (CDynLinkLibrary *)0x0) {
        CDynLinkLibrary::CDynLinkLibrary(this,(AFX_EXTENSION_MODULE *)&param_1_100162e0,0);
      }
      param_2 = 1;
      goto LAB_1000e075;
    }
    (**(code **)(*piVar2 + 0x70))();
  }
  AfxWinTerm();
LAB_1000e075:
  *(undefined4 *)(p_Var3 + 8) = uVar1;
  p_Var3 = AfxGetThreadState();
  AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var3 + 8));
  return param_2;
}



undefined4 FUN_1000e110(undefined4 param_1,int param_2)

{
  HLOCAL hMem;
  _AFX_THREAD_STATE *p_Var1;
  AFX_MODULE_STATE *pAVar2;
  
  if (param_2 == 1) {
    hMem = LocalAlloc(0,0x2000);
    if (hMem == (HLOCAL)0x0) {
      return 0;
    }
    LocalFree(hMem);
    p_Var1 = AfxGetThreadState();
    pAVar2 = AfxSetModuleState((AFX_MODULE_STATE *)&param_1_10015250);
    *(AFX_MODULE_STATE **)(p_Var1 + 8) = pAVar2;
  }
  else if (param_2 == 0) {
    p_Var1 = AfxGetThreadState();
    AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var1 + 8));
  }
  return 1;
}



void __fastcall FUN_1000e161(undefined4 *param_1)

{
  *(undefined4 *)(param_1[1] + 4) = *param_1;
  return;
}



void __CxxFrameHandler(void)

{
                    // WARNING: Could not recover jumptable at 0x1000e16a. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler();
  return;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000e170. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



int __cdecl abs(int _X)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000e176. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = abs(_X);
  return iVar1;
}



void __cdecl FUN_1000e17c(_onexit_t param_1)

{
  if (DAT_10016308 == -1) {
    _onexit(param_1);
    return;
  }
  __dllonexit(param_1,&DAT_10016308,&DAT_10016304);
  return;
}



int __cdecl FUN_1000e1a8(_onexit_t param_1)

{
  int iVar1;
  
  iVar1 = FUN_1000e17c(param_1);
  return (iVar1 != 0) - 1;
}



int __cdecl strcmp(char *_Str1,char *_Str2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000e1c0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = strcmp(_Str1,_Str2);
  return iVar1;
}



void _CxxThrowException(void *pExceptionObject,ThrowInfo *pThrowInfo)

{
                    // WARNING: Could not recover jumptable at 0x1000e1e2. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  _CxxThrowException(pExceptionObject,pThrowInfo);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_1000e1e8(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 *_Memory;
  undefined4 *puVar2;
  
  if (param_2 == 0) {
    if (0 < DAT_100162fc) {
      DAT_100162fc = DAT_100162fc + -1;
      goto LAB_1000e1fe;
    }
LAB_1000e226:
    uVar1 = 0;
  }
  else {
LAB_1000e1fe:
    _DAT_10016300 = *(undefined4 *)_adjust_fdiv_exref;
    if (param_2 == 1) {
      DAT_10016308 = (undefined4 *)malloc(0x80);
      if (DAT_10016308 == (undefined4 *)0x0) goto LAB_1000e226;
      *DAT_10016308 = 0;
      DAT_10016304 = DAT_10016308;
      initterm(&DAT_10013000,&DAT_10013020);
      DAT_100162fc = DAT_100162fc + 1;
    }
    else if ((param_2 == 0) &&
            (_Memory = DAT_10016308, puVar2 = DAT_10016304, DAT_10016308 != (undefined4 *)0x0)) {
      while (puVar2 = puVar2 + -1, _Memory <= puVar2) {
        if ((code *)*puVar2 != (code *)0x0) {
          (*(code *)*puVar2)();
          _Memory = DAT_10016308;
        }
      }
      free(_Memory);
      DAT_10016308 = (undefined4 *)0x0;
    }
    uVar1 = 1;
  }
  return uVar1;
}



int entry(HINSTANCE__ *param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = param_2;
  iVar2 = DAT_100162fc;
  if (param_2 != 0) {
    if ((param_2 != 1) && (param_2 != 2)) goto LAB_1000e2db;
    if ((PTR_FUN_10013ba4 != (undefined *)0x0) &&
       (iVar2 = (*(code *)PTR_FUN_10013ba4)(param_1,param_2,param_3), iVar2 == 0)) {
      return 0;
    }
    iVar2 = FUN_1000e1e8(param_1,param_2);
  }
  if (iVar2 == 0) {
    return 0;
  }
LAB_1000e2db:
  iVar2 = FUN_1000dfe9(param_1,param_2);
  if (param_2 == 1) {
    if (iVar2 != 0) {
      return iVar2;
    }
    FUN_1000e1e8(param_1,0);
  }
  if ((param_2 != 0) && (param_2 != 3)) {
    return iVar2;
  }
  iVar3 = FUN_1000e1e8(param_1,param_2);
  param_2 = iVar2;
  if (iVar3 == 0) {
    param_2 = 0;
  }
  if (param_2 != 0) {
    if (PTR_FUN_10013ba4 != (undefined *)0x0) {
      iVar2 = (*(code *)PTR_FUN_10013ba4)(param_1,iVar1,param_3);
      return iVar2;
    }
    return param_2;
  }
  return 0;
}



void FUN_1000e330(void)

{
  undefined1 auStack_c [12];
  
  ExceptionList = auStack_c;
  return;
}



void __dllonexit(void)

{
                    // WARNING: Could not recover jumptable at 0x1000e350. Too many branches
                    // WARNING: Treating indirect jump as call
  __dllonexit();
  return;
}



void __thiscall type_info::~type_info(type_info *this)

{
                    // WARNING: Could not recover jumptable at 0x1000e356. Too many branches
                    // WARNING: Treating indirect jump as call
  ~type_info(this);
  return;
}



void __cdecl initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x1000e35c. Too many branches
                    // WARNING: Treating indirect jump as call
  initterm();
  return;
}



void __thiscall
AFX_MODULE_STATE::AFX_MODULE_STATE
          (AFX_MODULE_STATE *this,int param_1,FuncDef37 *param_2,ulong param_3)

{
                    // WARNING: Could not recover jumptable at 0x1000e362. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MODULE_STATE(this,param_1,param_2,param_3);
  return;
}



void CNoTrackObject::operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000e368. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x1000e36e. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



long AfxWndProc(HWND__ *param_1,uint param_2,uint param_3,long param_4)

{
  long lVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000e374. Too many branches
                    // WARNING: Treating indirect jump as call
  lVar1 = AfxWndProc(param_1,param_2,param_3,param_4);
  return lVar1;
}



void __thiscall
AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(AFX_MAINTAIN_STATE2 *this,AFX_MODULE_STATE *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000e37a. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MAINTAIN_STATE2(this,param_1);
  return;
}



void AfxTermThread(HINSTANCE__ *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000e380. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermThread(param_1);
  return;
}



void AfxTermExtensionModule(AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x1000e386. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermExtensionModule(param_1,param_2);
  return;
}



int AfxUnlockTempMaps(int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000e38c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxUnlockTempMaps(param_1);
  return iVar1;
}



void AfxLockTempMaps(void)

{
                    // WARNING: Could not recover jumptable at 0x1000e392. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxLockTempMaps();
  return;
}



AFX_MODULE_STATE * AfxSetModuleState(AFX_MODULE_STATE *param_1)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000e398. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxSetModuleState(param_1);
  return pAVar1;
}



void __thiscall
CDynLinkLibrary::CDynLinkLibrary(CDynLinkLibrary *this,AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x1000e39e. Too many branches
                    // WARNING: Treating indirect jump as call
  CDynLinkLibrary(this,param_1,param_2);
  return;
}



int AfxInitExtensionModule(AFX_EXTENSION_MODULE *param_1,HINSTANCE__ *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000e3a4. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxInitExtensionModule(param_1,param_2);
  return iVar1;
}



void AfxWinTerm(void)

{
                    // WARNING: Could not recover jumptable at 0x1000e3aa. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxWinTerm();
  return;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000e3b0. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



int AfxWinInit(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000e3b6. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinInit(param_1,param_2,param_3,param_4);
  return iVar1;
}



_AFX_THREAD_STATE * AfxGetThreadState(void)

{
  _AFX_THREAD_STATE *p_Var1;
  
                    // WARNING: Could not recover jumptable at 0x1000e3bc. Too many branches
                    // WARNING: Treating indirect jump as call
  p_Var1 = AfxGetThreadState();
  return p_Var1;
}



void AfxCoreInitModule(void)

{
                    // WARNING: Could not recover jumptable at 0x1000e3c2. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxCoreInitModule();
  return;
}



int __fastcall FUN_1000e3d0(int param_1)

{
  return param_1 + 4;
}



void Unwind_1000e3f0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000e403(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000e40c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_1000e41f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000e440(void)

{
  int unaff_EBP;
  
  FUN_10001f30((undefined4 *)(unaff_EBP + -0x6c));
  return;
}



void Unwind_1000e449(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0x50));
  return;
}



void Unwind_1000e452(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0x34));
  return;
}



void Unwind_1000e45b(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0xac));
  return;
}



void Unwind_1000e467(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -200));
  return;
}



void Unwind_1000e47d(void)

{
  int unaff_EBP;
  
  FUN_100020f0((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_1000e490(void)

{
  int unaff_EBP;
  
  FUN_10002c40(*(CString **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000e4b0(void)

{
  int unaff_EBP;
  
  FUN_10002c40(*(CString **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000e4d0(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0x28));
  return;
}



void Unwind_1000e4d9(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x30) & 1) != 0) {
    FUN_10001ce0(*(undefined4 **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000e500(void)

{
  int unaff_EBP;
  
  FUN_10002460(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000e520(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0x30));
  return;
}



void Unwind_1000e540(void)

{
  FUN_10002aa0();
  return;
}



void Unwind_1000e560(void)

{
  int unaff_EBP;
  
  FUN_10006ba0(*(undefined4 **)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000e569(void)

{
  int unaff_EBP;
  
  FUN_100052f0((undefined4 *)(*(int *)(unaff_EBP + -0x18) + 8));
  return;
}



void Unwind_1000e575(void)

{
  int unaff_EBP;
  
  FUN_100052f0((undefined4 *)(*(int *)(unaff_EBP + -0x18) + 0x24));
  return;
}



void Unwind_1000e581(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x18) + 0x73c));
  return;
}



void Unwind_1000e590(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x18) + 0x740));
  return;
}



void Unwind_1000e59f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x18) + 0x74c));
  return;
}



void Unwind_1000e5ae(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x18) + 0x750));
  return;
}



void Unwind_1000e5bd(void)

{
  int unaff_EBP;
  
  FUN_10007600((int *)(*(int *)(unaff_EBP + -0x18) + 0x754));
  return;
}



void Unwind_1000e5cc(void)

{
  int unaff_EBP;
  
  FUN_10007600((int *)(*(int *)(unaff_EBP + -0x18) + 0x758));
  return;
}



void Unwind_1000e5db(void)

{
  int unaff_EBP;
  
  FUN_10007620(*(int *)(unaff_EBP + -0x18) + 0x75c);
  return;
}



void Unwind_1000e5f4(void)

{
  int unaff_EBP;
  
  FUN_10006ba0(*(undefined4 **)(unaff_EBP + -0x24));
  return;
}



void Unwind_1000e5fd(void)

{
  int unaff_EBP;
  
  FUN_100052f0((undefined4 *)(*(int *)(unaff_EBP + -0x24) + 8));
  return;
}



void Unwind_1000e609(void)

{
  int unaff_EBP;
  
  FUN_100052f0((undefined4 *)(*(int *)(unaff_EBP + -0x24) + 0x24));
  return;
}



void Unwind_1000e615(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x24) + 0x73c));
  return;
}



void Unwind_1000e624(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x24) + 0x740));
  return;
}



void Unwind_1000e633(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x24) + 0x74c));
  return;
}



void Unwind_1000e642(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x24) + 0x750));
  return;
}



void Unwind_1000e651(void)

{
  int unaff_EBP;
  
  FUN_10007600((int *)(*(int *)(unaff_EBP + -0x24) + 0x754));
  return;
}



void Unwind_1000e660(void)

{
  int unaff_EBP;
  
  FUN_10007600((int *)(*(int *)(unaff_EBP + -0x24) + 0x758));
  return;
}



void Unwind_1000e66f(void)

{
  int unaff_EBP;
  
  FUN_10007620(*(int *)(unaff_EBP + -0x24) + 0x75c);
  return;
}



void Unwind_1000e67e(void)

{
  int unaff_EBP;
  
  FUN_10007620(unaff_EBP + -0x20);
  return;
}



void Unwind_1000e691(void)

{
  int unaff_EBP;
  
  FUN_10006cc0(*(undefined4 **)(unaff_EBP + -0x50));
  return;
}



void Unwind_1000e69a(void)

{
  int unaff_EBP;
  
  FUN_10007600((int *)(*(int *)(unaff_EBP + -0x50) + 0xc));
  return;
}



void Unwind_1000e6a6(void)

{
  int unaff_EBP;
  
  FUN_10001f30((undefined4 *)(*(int *)(unaff_EBP + -0x50) + 0x4c));
  return;
}



void Unwind_1000e6b2(void)

{
  int unaff_EBP;
  
  FUN_10001f30((undefined4 *)(*(int *)(unaff_EBP + -0x50) + 0x68));
  return;
}



void Unwind_1000e6be(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x20));
  return;
}



void Unwind_1000e6c9(void)

{
  int unaff_EBP;
  
  FUN_10007600((int *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000e6d2(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x2c));
  return;
}



void Unwind_1000e6dd(void)

{
  int unaff_EBP;
  
  FUN_10007600((int *)(unaff_EBP + -0x24));
  return;
}



void Unwind_1000e6e6(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_1000e6ef(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000e6f8(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_1000e701(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000e70a(void)

{
  int unaff_EBP;
  
  FUN_100020f0((CString *)(unaff_EBP + -0x44));
  return;
}



void Unwind_1000e713(void)

{
  int unaff_EBP;
  
  FUN_100020f0((CString *)(unaff_EBP + -0x4c));
  return;
}



void Unwind_1000e726(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_1000e72f(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000e738(void)

{
  int unaff_EBP;
  
  FUN_100020f0((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000e741(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x48) & 1) != 0) {
    FUN_100020f0(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000e758(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x44));
  return;
}



void Unwind_1000e763(void)

{
  int unaff_EBP;
  
  FUN_100020f0((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_1000e776(void)

{
  int unaff_EBP;
  
  FUN_100020f0((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000e77f(void)

{
  int unaff_EBP;
  
  FUN_100020f0((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000e788(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_1000e79d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_1000e7a6(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_1000e7af(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_1000e7b8(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_1000e7c1(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000e7ca(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000e7d3(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000e7dc(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000e7e5(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x30));
  return;
}



void Unwind_1000e7ee(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x34) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000e80f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000e818(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x14) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000e839(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000e842(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x14) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000e863(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_1000e86c(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0x48));
  return;
}



void Unwind_1000e875(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -100));
  return;
}



void Unwind_1000e87e(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0x80));
  return;
}



void Unwind_1000e887(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0x9c));
  return;
}



void Unwind_1000e893(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0xb8));
  return;
}



void Unwind_1000e89f(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0xd4));
  return;
}



void Unwind_1000e8ab(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0xf0));
  return;
}



void Unwind_1000e8b7(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0x10c));
  return;
}



void Unwind_1000e8cd(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_1000e8e0(void)

{
  int unaff_EBP;
  
  CFileFind::~CFileFind((CFileFind *)(unaff_EBP + -0x28));
  return;
}



void Unwind_1000e8e9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x58));
  return;
}



void Unwind_1000e8f2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x5c));
  return;
}



void Unwind_1000e8fb(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x6c) & 1) != 0) {
    FUN_10005640(*(undefined4 **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000e912(void)

{
  int unaff_EBP;
  
  FUN_10005640((undefined4 *)(unaff_EBP + -0x44));
  return;
}



void Unwind_1000e91b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x60));
  return;
}



void Unwind_1000e924(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x50));
  return;
}



void Unwind_1000e92d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -100));
  return;
}



void Unwind_1000e940(void)

{
  int unaff_EBP;
  
  FUN_10002c40(*(CString **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000e960(void)

{
  int unaff_EBP;
  
  FUN_10006cc0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000e969(void)

{
  int unaff_EBP;
  
  FUN_10007600((int *)(*(int *)(unaff_EBP + -0x10) + 0xc));
  return;
}



void Unwind_1000e975(void)

{
  int unaff_EBP;
  
  FUN_10001f30((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x4c));
  return;
}



void Unwind_1000e990(void)

{
  int unaff_EBP;
  
  FUN_100025b0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000e9b0(void)

{
  int unaff_EBP;
  
  FUN_10005b30(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000e9d0(void)

{
  int unaff_EBP;
  
  FUN_10002460(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000e9f0(void)

{
  int unaff_EBP;
  
  FUN_10002460(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000ea10(void)

{
  int unaff_EBP;
  
  FUN_10002460(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000ea30(void)

{
  int unaff_EBP;
  
  FUN_100020f0((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000ea50(void)

{
  FUN_10002aa0();
  return;
}



void Unwind_1000ea70(void)

{
  int unaff_EBP;
  
  FUN_10002c40(*(CString **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000ea90(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_1000eab0(void)

{
  int unaff_EBP;
  
  FUN_10006cc0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000eab9(void)

{
  int unaff_EBP;
  
  FUN_10007600((int *)(*(int *)(unaff_EBP + -0x10) + 0xc));
  return;
}



void Unwind_1000eac5(void)

{
  int unaff_EBP;
  
  FUN_10001f30((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x4c));
  return;
}



void Unwind_1000eae0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x414));
  return;
}



void Unwind_1000eaef(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x418));
  return;
}



void Unwind_1000eafe(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x41c));
  return;
}



void Unwind_1000eb17(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000eb20(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000eb29(void)

{
  int unaff_EBP;
  
  FUN_10005640((undefined4 *)(unaff_EBP + -0x30));
  return;
}



void Unwind_1000eb3c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x40) + 0x414));
  return;
}



void Unwind_1000eb4b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x40) + 0x418));
  return;
}



void Unwind_1000eb5a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x40) + 0x41c));
  return;
}



void Unwind_1000eb73(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 8));
  return;
}



void Unwind_1000eb86(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 8));
  return;
}



void Unwind_1000eb99(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 8));
  return;
}



void Unwind_1000ebac(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 8));
  return;
}



void Unwind_1000ebbf(void)

{
  int unaff_EBP;
  
  FUN_10007600((int *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000ebc8(void)

{
  int unaff_EBP;
  
  FUN_10007600((int *)(unaff_EBP + -0x20));
  return;
}



void Unwind_1000ebdb(void)

{
  int unaff_EBP;
  
  FUN_100020f0((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000ebee(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000ebf7(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000ec00(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000ec13(void)

{
  int unaff_EBP;
  
  FUN_100020f0((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_1000ec1c(void)

{
  int unaff_EBP;
  
  FUN_10007600((int *)(unaff_EBP + -0x50));
  return;
}



void Unwind_1000ec30(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x414));
  return;
}



void Unwind_1000ec3f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x418));
  return;
}



void Unwind_1000ec60(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000ec69(void)

{
  int unaff_EBP;
  
  FUN_10008920((undefined4 *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000ec72(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x24) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000ec89(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000ec92(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_1000ecb0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000ecb9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000ecd0(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0x68));
  return;
}



void Unwind_1000ecd9(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x74) & 1) != 0) {
    FUN_10001ce0(*(undefined4 **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000ecfa(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_1000ed0d(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_1000ed16(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0x58));
  return;
}



void Unwind_1000ed29(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + 8));
  return;
}



void Unwind_1000ed32(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0x34));
  return;
}



void Unwind_1000ed45(void)

{
  int unaff_EBP;
  
  FUN_10001ce0((undefined4 *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_1000ed60(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000ed73(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000ed7c(void)

{
  int unaff_EBP;
  
  CFile::~CFile((CFile *)(unaff_EBP + -0x68));
  return;
}



void Unwind_1000ed85(void)

{
  int unaff_EBP;
  
  CArchive::~CArchive((CArchive *)(unaff_EBP + -0x58));
  return;
}



void Unwind_1000ed98(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000edab(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x24) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000edc2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000edcb(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_1000edd4(void)

{
  int unaff_EBP;
  
  FUN_1000a780((int *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000ede7(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x70));
  return;
}



void Unwind_1000edf0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x74));
  return;
}



void Unwind_1000edf9(void)

{
  int unaff_EBP;
  
  CFile::~CFile((CFile *)(unaff_EBP + -100));
  return;
}



void Unwind_1000ee02(void)

{
  int unaff_EBP;
  
  CArchive::~CArchive((CArchive *)(unaff_EBP + -0x54));
  return;
}



void Unwind_1000ee0b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x78));
  return;
}



void Unwind_1000ee1e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000ee27(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000ee30(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000ee43(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x6c));
  return;
}



void Unwind_1000ee4c(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000ee55(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000ee5e(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_1000ee67(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x70));
  return;
}



void Unwind_1000ee70(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x7c));
  return;
}



void Unwind_1000ee79(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x84));
  return;
}



void Unwind_1000ee85(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x90));
  return;
}



void Unwind_1000ee91(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x98));
  return;
}



void Unwind_1000ee9d(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0xa4));
  return;
}



void Unwind_1000eeb3(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000eebc(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_1000eec5(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_1000eece(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_1000eed7(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_1000eee0(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x30) & 1) != 0) {
    FUN_10002c40(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000ef01(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000ef20(void)

{
  int unaff_EBP;
  
  FUN_100020f0((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000ef33(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000ef3c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000ef45(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000ef4e(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x1c) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000ef6f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000ef78(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000ef8b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_1000ef9e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_1000efb1(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000efba(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_1000efd0(void)

{
  int unaff_EBP;
  
  FUN_10007620(unaff_EBP + -0x24);
  return;
}



void Unwind_1000efd9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x30));
  return;
}



void Unwind_1000eff0(void)

{
  int unaff_EBP;
  
  FUN_10002460(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000f010(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x170));
  return;
}



void Unwind_1000f01e(void)

{
  int unaff_EBP;
  
  INIFILE::~INIFILE((INIFILE *)(unaff_EBP + -0x54));
  return;
}



void Unwind_1000f028(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_1000f031(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x17c));
  return;
}



void Unwind_1000f03f(void)

{
  int unaff_EBP;
  
  FUN_10007600((int *)(unaff_EBP + -0x174));
  return;
}



void Unwind_1000f04b(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x180));
  return;
}



void Unwind_1000f057(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x78));
  return;
}



void Unwind_1000f060(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x74));
  return;
}



void Unwind_1000f069(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x184));
  return;
}



void Unwind_1000f075(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x188));
  return;
}



void Unwind_1000f081(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x84));
  return;
}



void Unwind_1000f08d(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x18c));
  return;
}



void Unwind_1000f099(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -400));
  return;
}



void Unwind_1000f0a5(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x8c));
  return;
}



void Unwind_1000f0b1(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x194));
  return;
}



void Unwind_1000f0bd(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x198));
  return;
}



void Unwind_1000f0c9(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x94));
  return;
}



void Unwind_1000f0d5(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x19c));
  return;
}



void Unwind_1000f0e1(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x1a0));
  return;
}



void Unwind_1000f0ed(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x9c));
  return;
}



void Unwind_1000f0f9(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x1a4));
  return;
}



void Unwind_1000f105(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x1a8));
  return;
}



void Unwind_1000f111(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x1ac));
  return;
}



void Unwind_1000f11d(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000f126(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x1b4));
  return;
}



void Unwind_1000f132(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1b8));
  return;
}



void Unwind_1000f13e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1bc));
  return;
}



void Unwind_1000f14a(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x1b0));
  return;
}



void Unwind_1000f156(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x1c0));
  return;
}



void Unwind_1000f162(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x1c4));
  return;
}



void Unwind_1000f16e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1cc));
  return;
}



void Unwind_1000f17a(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x1c8));
  return;
}



void Unwind_1000f186(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x1d4));
  return;
}



void Unwind_1000f192(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1d8));
  return;
}



void Unwind_1000f19e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1dc));
  return;
}



void Unwind_1000f1aa(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x1d0));
  return;
}



void Unwind_1000f1b6(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x1e0));
  return;
}



void Unwind_1000f1c2(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x1e4));
  return;
}



void Unwind_1000f1ce(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x1e8));
  return;
}



void Unwind_1000f1da(void)

{
  int unaff_EBP;
  
  FUN_10007620(unaff_EBP + -0x14);
  return;
}



void Unwind_1000f1e3(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x1ec));
  return;
}



void Unwind_1000f1ef(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -500));
  return;
}



void Unwind_1000f1fb(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x1fc));
  return;
}



void Unwind_1000f207(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x204));
  return;
}



void Unwind_1000f213(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x20c));
  return;
}



void Unwind_1000f21f(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x214));
  return;
}



void Unwind_1000f22b(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x218));
  return;
}



void Unwind_1000f237(void)

{
  int unaff_EBP;
  
  FUN_10007600((int *)(unaff_EBP + -0x21c));
  return;
}



void Unwind_1000f243(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x220));
  return;
}



void Unwind_1000f24f(void)

{
  int unaff_EBP;
  
  FUN_10007600((int *)(unaff_EBP + -0x224));
  return;
}



void Unwind_1000f25b(void)

{
  int unaff_EBP;
  
  FUN_10007620(unaff_EBP + -0x5c);
  return;
}



void Unwind_1000f264(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_1000f26d(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000f276(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x22c));
  return;
}



void Unwind_1000f282(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x228));
  return;
}



void Unwind_1000f28e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x234));
  return;
}



void Unwind_1000f29a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x238));
  return;
}



void Unwind_1000f2a6(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x230));
  return;
}



void Unwind_1000f2bc(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000f2c5(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000f2ce(void)

{
  int unaff_EBP;
  
  FUN_10002c40((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_1000f2e4(void)

{
  int unaff_EBP;
  
  FUN_1000e161((undefined4 *)(unaff_EBP + -0x14));
  return;
}


