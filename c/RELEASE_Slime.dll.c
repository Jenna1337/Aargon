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

typedef void *HANDLE;

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

typedef HANDLE HLOCAL;

typedef ulong DWORD;

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

typedef struct SPRITE SPRITE, *PSPRITE;

struct SPRITE { // PlaceHolder Structure
};

typedef struct CWave CWave, *PCWave;

struct CWave { // PlaceHolder Structure
};

typedef struct AFX_EXTENSION_MODULE AFX_EXTENSION_MODULE, *PAFX_EXTENSION_MODULE;

struct AFX_EXTENSION_MODULE { // PlaceHolder Structure
};

typedef struct TwMovingObject TwMovingObject, *PTwMovingObject;

struct TwMovingObject { // PlaceHolder Structure
};

typedef struct ITEM ITEM, *PITEM;

struct ITEM { // PlaceHolder Structure
};

typedef struct AFX_MODULE_STATE AFX_MODULE_STATE, *PAFX_MODULE_STATE;

struct AFX_MODULE_STATE { // PlaceHolder Structure
};

typedef struct CDynLinkLibrary CDynLinkLibrary, *PCDynLinkLibrary;

struct CDynLinkLibrary { // PlaceHolder Structure
};

typedef struct OVERLAY OVERLAY, *POVERLAY;

struct OVERLAY { // PlaceHolder Structure
};

typedef struct _AFX_THREAD_STATE _AFX_THREAD_STATE, *P_AFX_THREAD_STATE;

struct _AFX_THREAD_STATE { // PlaceHolder Structure
};

typedef struct MAP MAP, *PMAP;

struct MAP { // PlaceHolder Structure
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef struct AFX_MAINTAIN_STATE2 AFX_MAINTAIN_STATE2, *PAFX_MAINTAIN_STATE2;

struct AFX_MAINTAIN_STATE2 { // PlaceHolder Structure
};

typedef struct tagRECT tagRECT, *PtagRECT;

struct tagRECT { // PlaceHolder Structure
};

typedef struct CString CString, *PCString;

struct CString { // PlaceHolder Structure
};

typedef struct DD_SURFACE DD_SURFACE, *PDD_SURFACE;

struct DD_SURFACE { // PlaceHolder Structure
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ { // PlaceHolder Structure
};

typedef struct CPosition CPosition, *PCPosition;

struct CPosition { // PlaceHolder Structure
};

typedef struct HWND__ HWND__, *PHWND__;

struct HWND__ { // PlaceHolder Structure
};

typedef int (*_onexit_t)(void);

typedef uint size_t;




void FUN_10001000(void)

{
  FUN_1000100f();
  FUN_1000101f();
  return;
}



void FUN_1000100f(void)

{
  CWave::CWave((CWave *)&DAT_10004128);
  return;
}



void FUN_1000101f(void)

{
  FUN_10002934(FUN_10001031);
  return;
}



void FUN_10001031(void)

{
  CWave::~CWave((CWave *)&DAT_10004128);
  return;
}



void FUN_10001041(void)

{
  FUN_10001050();
  FUN_10001060();
  return;
}



void FUN_10001050(void)

{
  CWave::CWave((CWave *)&DAT_10004168);
  return;
}



void FUN_10001060(void)

{
  FUN_10002934(FUN_10001072);
  return;
}



void FUN_10001072(void)

{
  CWave::~CWave((CWave *)&DAT_10004168);
  return;
}



void FUN_10001082(void)

{
  FUN_10001091();
  FUN_100010a1();
  return;
}



void FUN_10001091(void)

{
  CWave::CWave((CWave *)&DAT_100041a8);
  return;
}



void FUN_100010a1(void)

{
  FUN_10002934(FUN_100010b3);
  return;
}



void FUN_100010b3(void)

{
  CWave::~CWave((CWave *)&DAT_100041a8);
  return;
}



// class TwMovingObject * __cdecl Create(void)

TwMovingObject * __cdecl Create(void)

{
  SPRITE *pSVar1;
  SPRITE *local_1c;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x10c3  1  ?Create@@YAPAVTwMovingObject@@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_10002c0b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pSVar1 = (SPRITE *)operator_new(0x125c);
  local_8 = 0;
  if (pSVar1 == (SPRITE *)0x0) {
    local_1c = (SPRITE *)0x0;
  }
  else {
    local_1c = FUN_10001810(pSVar1);
  }
  ExceptionList = local_10;
  return (TwMovingObject *)local_1c;
}



void __thiscall FUN_1000112d(void *this,int param_1,int *param_2)

{
  CString *pCVar1;
  CString local_30 [4];
  undefined1 *local_2c;
  CString local_28 [4];
  undefined1 *local_24;
  CString local_20 [4];
  undefined1 *local_1c;
  int local_18;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_10002c30;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  if (DAT_100041e8 == 0) {
    local_1c = &stack0xffffffa4;
    ExceptionList = &local_10;
    CString::CString((CString *)&stack0xffffffa4,s_Slime_Move_1000404c);
    pCVar1 = (CString *)(**(code **)(*param_2 + 0x58))();
    local_8 = 0;
    CWave::Create((CWave *)&DAT_10004128,pCVar1);
    local_8 = 0xffffffff;
    CString::~CString(local_20);
    local_24 = &stack0xffffff9c;
    CString::CString((CString *)&stack0xffffff9c,s_Slime_Eat_1_10004058);
    pCVar1 = (CString *)(**(code **)(*param_2 + 0x58))();
    local_8 = 1;
    CWave::Create((CWave *)&DAT_10004168,pCVar1);
    local_8 = 0xffffffff;
    CString::~CString(local_28);
    local_2c = &stack0xffffff94;
    CString::CString((CString *)&stack0xffffff94,s_Slime_Eat_2_10004064);
    pCVar1 = (CString *)(**(code **)(*param_2 + 0x58))(local_30);
    local_8 = 2;
    CWave::Create((CWave *)&DAT_100041a8,pCVar1);
    local_8 = 0xffffffff;
    CString::~CString(local_30);
    DAT_100041e8 = 1;
  }
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x2c))();
  *(undefined4 *)((int)this + 0x112c) = 1;
  *(undefined4 *)((int)this + 0x113c) = 0;
  for (local_14 = 0; local_14 < 0x14; local_14 = local_14 + 1) {
    for (local_18 = 0; local_18 < 0xd; local_18 = local_18 + 1) {
      *(undefined1 *)((int)this + local_18 + local_14 * 0xd + 0x1144) = 0;
    }
  }
  *(undefined4 *)((int)this + 0x1248) = 0;
  FUN_10002610((void *)((int)this + 0x1140),0);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_100012fb(void *this,MAP *param_1)

{
  bool bVar1;
  char cVar2;
  undefined4 *puVar3;
  void *pvVar4;
  ITEM *pIVar5;
  undefined4 uVar6;
  CString *pCVar7;
  int iVar8;
  double dVar9;
  CString **ppCVar10;
  undefined1 local_9c;
  CString local_84 [4];
  CString local_80 [4];
  CString local_7c [4];
  CString local_78 [4];
  undefined1 local_74 [8];
  ITEM *local_6c;
  ITEM *local_68;
  CString local_64 [4];
  uint local_60;
  CString local_5c [4];
  uint local_58;
  undefined1 local_54 [8];
  undefined1 local_4c [8];
  undefined1 local_44 [8];
  undefined1 local_3c [8];
  undefined1 local_34 [8];
  ITEM *local_2c;
  ITEM *local_28;
  int local_24;
  ITEM *local_20;
  int local_1c;
  ITEM *local_18;
  ITEM *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10002c70;
  local_10 = ExceptionList;
  if (*(int *)((int)this + 0x1248) != 0) {
    return;
  }
  ExceptionList = &local_10;
  local_1c = OVERLAY::GetXPos((OVERLAY *)this);
  local_24 = OVERLAY::GetYPos((OVERLAY *)this);
  puVar3 = (undefined4 *)
           default_error_condition(local_34,local_1c + 0x10U >> 5,local_24 - 0x10U >> 5);
  local_2c = MAP::GetItem(param_1,*puVar3,puVar3[1]);
  puVar3 = (undefined4 *)
           default_error_condition(local_3c,local_1c + 0x10U >> 5,local_24 + 0x30U >> 5);
  local_20 = MAP::GetItem(param_1,*puVar3,puVar3[1]);
  puVar3 = (undefined4 *)
           default_error_condition(local_44,local_1c - 0x10U >> 5,local_24 + 0x10U >> 5);
  local_14 = MAP::GetItem(param_1,*puVar3,puVar3[1]);
  puVar3 = (undefined4 *)
           default_error_condition(local_4c,local_1c + 0x30U >> 5,local_24 + 0x10U >> 5);
  local_28 = MAP::GetItem(param_1,*puVar3,puVar3[1]);
  puVar3 = (undefined4 *)
           default_error_condition(local_54,local_1c + 0x10U >> 5,local_24 + 0x10U >> 5);
  local_18 = MAP::GetItem(param_1,*puVar3,puVar3[1]);
  pCVar7 = local_5c;
  pvVar4 = (void *)(**(code **)(*(int *)local_18 + 0x50))(pCVar7,&DAT_10004070);
  local_8 = 0;
  bVar1 = FUN_100024a0(pvVar4,(uchar *)pCVar7);
  if (!bVar1) {
    ppCVar10 = &this_10004074;
    pvVar4 = (void *)(**(code **)(*(int *)local_18 + 0x50))(local_64);
    local_8._0_1_ = 1;
    bVar1 = FUN_100024a0(pvVar4,(uchar *)ppCVar10);
    local_60 = CONCAT31(local_60._1_3_,bVar1);
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_64);
    if ((local_60 & 0xff) == 0) {
      local_9c = 0;
      goto LAB_100014e6;
    }
  }
  local_9c = 1;
LAB_100014e6:
  local_58 = CONCAT31(local_58._1_3_,local_9c);
  local_8 = 0xffffffff;
  CString::~CString(local_5c);
  if ((local_58 & 0xff) != 0) {
    dVar9 = RandomProb();
    if (0.5 <= dVar9) {
      CWave::Play((CWave *)&DAT_100041a8,0,0,0);
    }
    else {
      CWave::Play((CWave *)&DAT_10004168,0,0,0);
    }
                    // WARNING: Load size is inaccurate
    (**(code **)(*this + 0x20))();
    FUN_10002330((int)this);
    pIVar5 = MAP::FindItem(s_BLANK_10004078);
    uVar6 = (**(code **)(*(int *)pIVar5 + 4))();
    puVar3 = (undefined4 *)
             default_error_condition(local_74,local_1c + 0x10U >> 5,local_24 + 0x10U >> 5);
    local_6c = MAP::SetItem(param_1,*puVar3,puVar3[1],uVar6);
    local_68 = local_6c;
    if (local_6c != (ITEM *)0x0) {
      (*(code *)**(undefined4 **)local_6c)(1);
    }
  }
  cVar2 = (**(code **)(*(int *)local_2c + 0x80))();
  if (cVar2 == '\0') {
    pCVar7 = (CString *)(**(code **)(*(int *)local_2c + 0x50))(local_78);
    local_8 = 2;
    CString::operator=((CString *)((int)this + 0x124c),pCVar7);
    local_8 = 0xffffffff;
    CString::~CString(local_78);
  }
  else {
    CString::operator=((CString *)((int)this + 0x124c),(char *)&this_10004080);
  }
  cVar2 = (**(code **)(*(int *)local_28 + 0x80))();
  if (cVar2 == '\0') {
    pCVar7 = (CString *)(**(code **)(*(int *)local_28 + 0x50))(local_7c);
    local_8 = 3;
    CString::operator=((CString *)((int)this + 0x1250),pCVar7);
    local_8 = 0xffffffff;
    CString::~CString(local_7c);
  }
  else {
    CString::operator=((CString *)((int)this + 0x1250),&DAT_10004084);
  }
  cVar2 = (**(code **)(*(int *)local_14 + 0x80))();
  if (cVar2 == '\0') {
    pCVar7 = (CString *)(**(code **)(*(int *)local_14 + 0x50))(local_80);
    local_8 = 4;
    CString::operator=((CString *)((int)this + 0x1254),pCVar7);
    local_8 = 0xffffffff;
    CString::~CString(local_80);
  }
  else {
    CString::operator=((CString *)((int)this + 0x1254),&DAT_10004088);
  }
  cVar2 = (**(code **)(*(int *)local_20 + 0x80))();
  if (cVar2 == '\0') {
    pCVar7 = (CString *)(**(code **)(*(int *)local_20 + 0x50))(local_84);
    local_8 = 5;
    CString::operator=((CString *)((int)this + 0x1258),pCVar7);
    local_8 = 0xffffffff;
    CString::~CString(local_84);
  }
  else {
    CString::operator=((CString *)((int)this + 0x1258),&DAT_1000408c);
  }
  iVar8 = FUN_10001a20((int *)this);
  if (iVar8 == 0) {
    FUN_10002350((int *)this);
  }
  ExceptionList = local_10;
  return;
}



SPRITE * __fastcall FUN_10001810(SPRITE *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10002cb6;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10001910(param_1);
  local_8 = 0;
  FUN_10002520((DWORD *)(param_1 + 0x1130));
  FUN_100025f0((undefined4 *)(param_1 + 0x1140));
  CString::CString((CString *)(param_1 + 0x124c));
  local_8._0_1_ = 1;
  CString::CString((CString *)(param_1 + 0x1250));
  local_8._0_1_ = 2;
  CString::CString((CString *)(param_1 + 0x1254));
  local_8 = CONCAT31(local_8._1_3_,3);
  CString::CString((CString *)(param_1 + 0x1258));
  *(undefined ***)param_1 = &PTR_FUN_10003154;
  *(undefined ***)(param_1 + 8) = &PTR_LAB_10003150;
  ExceptionList = local_10;
  return param_1;
}



undefined1 FUN_100018d0(void)

{
  return 0;
}



void * __thiscall FUN_100018e0(void *this,uint param_1)

{
  FUN_10001960((SPRITE *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



SPRITE * __fastcall FUN_10001910(SPRITE *param_1)

{
  SPRITE::SPRITE(param_1);
  *(undefined ***)param_1 = &PTR_FUN_100031d8;
  *(undefined ***)(param_1 + 8) = &PTR_LAB_100031d4;
  return param_1;
}



void __fastcall FUN_10001940(SPRITE *param_1)

{
  SPRITE::~SPRITE(param_1);
  return;
}



void __fastcall FUN_10001960(SPRITE *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &this_10002cf6;
  local_10 = ExceptionList;
  local_8 = 3;
  ExceptionList = &local_10;
  CString::~CString((CString *)(param_1 + 0x1258));
  local_8._0_1_ = 2;
  CString::~CString((CString *)(param_1 + 0x1254));
  local_8._0_1_ = 1;
  CString::~CString((CString *)(param_1 + 0x1250));
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString((CString *)(param_1 + 0x124c));
  local_8 = 0xffffffff;
  FUN_10001940(param_1);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_100019f0(void *this,uint param_1)

{
  FUN_10001940((SPRITE *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



int __fastcall FUN_10001a20(int *param_1)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  
  if (param_1[0x492] == 0) {
    if (param_1[1099] == 1) {
      (**(code **)(*param_1 + 0x54))();
      uVar3 = FUN_10002560(param_1 + 0x44c);
      if (100 < uVar3) {
        param_1[1099] = 0;
        (**(code **)(*param_1 + 0x50))();
        if (*(char *)((int)param_1 +
                     ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5) +
                     ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5) *
                     0xd + 0x1144) == '\x0f') {
          *(undefined1 *)
           ((int)param_1 +
           ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5) +
           ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5) * 0xd +
           0x1144) = 0;
        }
        bVar1 = FUN_100024a0(param_1 + 0x493,&DAT_10004098);
        if ((bVar1) || (bVar1 = FUN_100024a0(param_1 + 0x493,&DAT_10004094), bVar1)) {
          FUN_10002610(param_1 + 0x450,0);
          *(byte *)((int)param_1 +
                   ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5) +
                   ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5) * 0xd
                   + 0x1144) =
               *(byte *)((int)param_1 +
                        ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5)
                        + ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5
                          ) * 0xd + 0x1144) & 0xfe;
          CString::operator=((CString *)(param_1 + 0x493),&DAT_10004090);
        }
        else {
          bVar1 = FUN_100024a0(param_1 + 0x494,&DAT_10004098);
          if ((bVar1) || (bVar1 = FUN_100024a0(param_1 + 0x494,&DAT_10004094), bVar1)) {
            FUN_10002610(param_1 + 0x450,4);
            *(byte *)((int)param_1 +
                     ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5) +
                     ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5) *
                     0xd + 0x1144) =
                 *(byte *)((int)param_1 +
                          ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5
                          ) + ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU))
                              >> 5) * 0xd + 0x1144) & 0xfd;
            CString::operator=((CString *)(param_1 + 0x494),&DAT_10004090);
          }
          else {
            bVar1 = FUN_100024a0(param_1 + 0x496,&DAT_10004098);
            if ((bVar1) || (bVar1 = FUN_100024a0(param_1 + 0x496,&DAT_10004094), bVar1)) {
              FUN_10002610(param_1 + 0x450,8);
              *(byte *)((int)param_1 +
                       ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5) +
                       ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5) *
                       0xd + 0x1144) =
                   *(byte *)((int)param_1 +
                            ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >>
                            5) + ((int)(param_1[0x2d] + 0x10 +
                                       (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5) * 0xd + 0x1144)
                   & 0xfb;
              CString::operator=((CString *)(param_1 + 0x496),&DAT_10004090);
            }
            else {
              bVar1 = FUN_100024a0(param_1 + 0x495,&DAT_10004098);
              if ((bVar1) || (bVar1 = FUN_100024a0(param_1 + 0x495,&DAT_10004094), bVar1)) {
                FUN_10002610(param_1 + 0x450,0xc);
                *(byte *)((int)param_1 +
                         ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5)
                         + ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >>
                           5) * 0xd + 0x1144) =
                     *(byte *)((int)param_1 +
                              ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU))
                              >> 5) + ((int)(param_1[0x2d] + 0x10 +
                                            (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5) * 0xd +
                                      0x1144) & 0xf7;
                CString::operator=((CString *)(param_1 + 0x495),&DAT_10004090);
              }
            }
          }
        }
        uVar4 = FUN_100026a0(param_1 + 0x450);
        switch(uVar4) {
        case 0:
          bVar1 = FUN_10002500(param_1 + 0x493,&DAT_10004090);
          if ((bVar1) ||
             ((*(byte *)((int)param_1 +
                        ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5)
                        + ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5
                          ) * 0xd + 0x1144) & 1) != 0)) {
            FUN_100022f0(param_1);
            FUN_10002660(param_1 + 0x450,1);
            FUN_10002660(param_1 + 0x450,1);
          }
          *(byte *)((int)param_1 +
                   ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5) +
                   ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5) * 0xd
                   + 0x1144) =
               *(byte *)((int)param_1 +
                        ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5)
                        + ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5
                          ) * 0xd + 0x1144) | 1;
          break;
        case 4:
          bVar1 = FUN_10002500(param_1 + 0x494,&DAT_10004090);
          if ((bVar1) ||
             ((*(byte *)((int)param_1 +
                        ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5)
                        + ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5
                          ) * 0xd + 0x1144) & 2) != 0)) {
            FUN_100022f0(param_1);
            FUN_10002660(param_1 + 0x450,1);
            FUN_10002660(param_1 + 0x450,1);
          }
          *(byte *)((int)param_1 +
                   ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5) +
                   ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5) * 0xd
                   + 0x1144) =
               *(byte *)((int)param_1 +
                        ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5)
                        + ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5
                          ) * 0xd + 0x1144) | 2;
          break;
        case 8:
          bVar1 = FUN_10002500(param_1 + 0x496,&DAT_10004090);
          if ((bVar1) ||
             ((*(byte *)((int)param_1 +
                        ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5)
                        + ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5
                          ) * 0xd + 0x1144) & 4) != 0)) {
            FUN_100022f0(param_1);
            FUN_10002660(param_1 + 0x450,1);
            FUN_10002660(param_1 + 0x450,1);
          }
          *(byte *)((int)param_1 +
                   ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5) +
                   ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5) * 0xd
                   + 0x1144) =
               *(byte *)((int)param_1 +
                        ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5)
                        + ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5
                          ) * 0xd + 0x1144) | 4;
          break;
        case 0xc:
          bVar1 = FUN_10002500(param_1 + 0x495,&DAT_10004090);
          if ((bVar1) ||
             ((*(byte *)((int)param_1 +
                        ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5)
                        + ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5
                          ) * 0xd + 0x1144) & 8) != 0)) {
            FUN_100022f0(param_1);
            FUN_10002660(param_1 + 0x450,1);
            FUN_10002660(param_1 + 0x450,1);
          }
          *(byte *)((int)param_1 +
                   ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5) +
                   ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5) * 0xd
                   + 0x1144) =
               *(byte *)((int)param_1 +
                        ((int)(param_1[0x2e] + 0x10 + (param_1[0x2e] + 0x10 >> 0x1f & 0x1fU)) >> 5)
                        + ((int)(param_1[0x2d] + 0x10 + (param_1[0x2d] + 0x10 >> 0x1f & 0x1fU)) >> 5
                          ) * 0xd + 0x1144) | 8;
        }
      }
    }
    iVar2 = param_1[1099];
  }
  else {
    iVar2 = 1;
  }
  return iVar2;
}



void __fastcall FUN_100022f0(int *param_1)

{
  param_1[1099] = 1;
  FUN_10002540((DWORD *)(param_1 + 0x44c));
  (**(code **)(*param_1 + 0x58))(0,0);
  return;
}



void __fastcall FUN_10002330(int param_1)

{
  *(undefined4 *)(param_1 + 0x1248) = 1;
  return;
}



void __fastcall FUN_10002350(int *param_1)

{
  undefined4 uVar1;
  
  if (param_1[0x492] == 0) {
    if (param_1[0x44f] == 0) {
      CWave::Play((CWave *)&DAT_10004128,0,0,0);
    }
    uVar1 = FUN_100026a0(param_1 + 0x450);
    switch(uVar1) {
    case 0:
      param_1[0x2e] = param_1[0x2e] - *(int *)(&DAT_10004020 + param_1[0x44f] * 4);
      break;
    case 4:
      param_1[0x2d] = param_1[0x2d] + *(int *)(&DAT_10004020 + param_1[0x44f] * 4);
      break;
    case 8:
      param_1[0x2e] = param_1[0x2e] + *(int *)(&DAT_10004020 + param_1[0x44f] * 4);
      break;
    case 0xc:
      param_1[0x2d] = param_1[0x2d] - *(int *)(&DAT_10004020 + param_1[0x44f] * 4);
    }
    param_1[0x44f] = param_1[0x44f] + 1;
    if (param_1[0x44f] == 10) {
      param_1[0x44f] = 0;
      FUN_100022f0(param_1);
    }
  }
  return;
}



bool FUN_100024a0(void *param_1,uchar *param_2)

{
  int iVar1;
  
  iVar1 = FUN_100024c0(param_1,param_2);
  return (bool)('\x01' - (iVar1 != 0));
}



void __thiscall FUN_100024c0(void *this,uchar *param_1)

{
                    // WARNING: Load size is inaccurate
  FUN_100024e0(*this,param_1);
  return;
}



void __cdecl FUN_100024e0(uchar *param_1,uchar *param_2)

{
  _mbscmp(param_1,param_2);
  return;
}



bool FUN_10002500(void *param_1,uchar *param_2)

{
  int iVar1;
  
  iVar1 = FUN_100024c0(param_1,param_2);
  return iVar1 != 0;
}



DWORD * __fastcall FUN_10002520(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
  return param_1;
}



void __fastcall FUN_10002540(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
  return;
}



int __fastcall FUN_10002560(int *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  return DVar1 - *param_1;
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
  FUN_100025a0(this,param_1,param_2);
  return this;
}



void * __thiscall FUN_100025a0(void *this,undefined4 param_1,undefined4 param_2)

{
  *(undefined4 *)this = param_1;
  *(undefined4 *)((int)this + 4) = param_2;
  return this;
}



undefined1 __fastcall FUN_100025d0(int param_1)

{
  return *(undefined1 *)(param_1 + 0xa0);
}



undefined4 * __fastcall FUN_100025f0(undefined4 *param_1)

{
  *param_1 = 0xfffffc00;
  return param_1;
}



void __thiscall FUN_10002610(void *this,uint param_1)

{
  uint uVar1;
  
  uVar1 = FUN_10002630(param_1);
  *(uint *)this = uVar1;
  return;
}



uint __cdecl FUN_10002630(uint param_1)

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



void __thiscall FUN_10002660(void *this,uint param_1)

{
  undefined4 local_8;
  
  for (local_8 = 0; local_8 < param_1; local_8 = local_8 + 1) {
                    // WARNING: Load size is inaccurate
    FUN_10002610(this,*this + 2);
  }
  return;
}



undefined4 __fastcall FUN_100026a0(undefined4 *param_1)

{
  return *param_1;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100026b0. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x100026b6. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void __thiscall CString::~CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x100026bc. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CString(this);
  return;
}



void __thiscall CString::CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x100026c2. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this);
  return;
}



void __thiscall CString::CString(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100026c8. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



CString * __thiscall CString::operator=(CString *this,CString *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x100026ce. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator=(this,param_1);
  return pCVar1;
}



CString * __thiscall CString::operator=(CString *this,char *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x100026d4. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator=(this,param_1);
  return pCVar1;
}



undefined4 * FUN_100026e4(void)

{
  AFX_MODULE_STATE::AFX_MODULE_STATE
            ((AFX_MODULE_STATE *)&param_1_100041f0,1,AfxWndProcDllStatic,0x600);
  param_1_100041f0 = (AFX_MAINTAIN_STATE2 *)&PTR_FUN_10003264;
  return &param_1_100041f0;
}



void * __thiscall FUN_1000270c(void *this,byte param_1)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)this);
  if ((param_1 & 1) != 0) {
    CNoTrackObject::operator_delete(this);
  }
  return this;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x10002ba2. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



void FUN_1000272c(void)

{
  FUN_10002934(FUN_10002738);
  return;
}



void FUN_10002738(void)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)&param_1_100041f0);
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
  
  FUN_10002abc();
  AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
            ((AFX_MAINTAIN_STATE2 *)(unaff_EBP + -0x14),(AFX_MODULE_STATE *)&param_1_100041f0);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  lVar1 = AfxWndProc(*(HWND__ **)(unaff_EBP + 8),*(uint *)(unaff_EBP + 0xc),
                     *(uint *)(unaff_EBP + 0x10),*(long *)(unaff_EBP + 0x14));
  *(undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4) = *(undefined4 *)(unaff_EBP + -0x14);
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return lVar1;
}



int FUN_10002787(HINSTANCE__ *param_1,int param_2)

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
      pAVar5 = AfxSetModuleState((AFX_MODULE_STATE *)&param_1_100041f0);
      p_Var3 = AfxGetThreadState();
      *(AFX_MODULE_STATE **)(p_Var3 + 8) = pAVar5;
      pAVar5 = AfxGetModuleState();
      if (*(int **)(pAVar5 + 4) != (int *)0x0) {
        (**(code **)(**(int **)(pAVar5 + 4) + 0x70))();
      }
      AfxLockTempMaps();
      AfxUnlockTempMaps(-1);
      AfxWinTerm();
      AfxTermExtensionModule((AFX_EXTENSION_MODULE *)&param_1_10005280,1);
    }
    else if (param_2 == 3) {
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
                ((AFX_MAINTAIN_STATE2 *)&local_c,(AFX_MODULE_STATE *)&param_1_100041f0);
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
  iVar4 = AfxWinInit(param_1,(HINSTANCE__ *)0x0,(char *)&param_3_10003268,0);
  if (iVar4 != 0) {
    pAVar5 = AfxGetModuleState();
    piVar2 = *(int **)(pAVar5 + 4);
    if ((piVar2 == (int *)0x0) || (iVar4 = (**(code **)(*piVar2 + 0x58))(), iVar4 != 0)) {
      *(undefined4 *)(p_Var3 + 8) = uVar1;
      AfxInitExtensionModule((AFX_EXTENSION_MODULE *)&param_1_10005280,param_1);
      this = (CDynLinkLibrary *)operator_new(0x40);
      if (this != (CDynLinkLibrary *)0x0) {
        CDynLinkLibrary::CDynLinkLibrary(this,(AFX_EXTENSION_MODULE *)&param_1_10005280,0);
      }
      param_2 = 1;
      goto LAB_10002813;
    }
    (**(code **)(*piVar2 + 0x70))();
  }
  AfxWinTerm();
LAB_10002813:
  *(undefined4 *)(p_Var3 + 8) = uVar1;
  p_Var3 = AfxGetThreadState();
  AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var3 + 8));
  return param_2;
}



undefined4 FUN_100028ae(undefined4 param_1,int param_2)

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
    pAVar2 = AfxSetModuleState((AFX_MODULE_STATE *)&param_1_100041f0);
    *(AFX_MODULE_STATE **)(p_Var1 + 8) = pAVar2;
  }
  else if (param_2 == 0) {
    p_Var1 = AfxGetThreadState();
    AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var1 + 8));
  }
  return 1;
}



void __fastcall FUN_100028ff(undefined4 *param_1)

{
  *(undefined4 *)(param_1[1] + 4) = *param_1;
  return;
}



void __cdecl FUN_10002908(_onexit_t param_1)

{
  if (DAT_100052a8 == -1) {
    _onexit(param_1);
    return;
  }
  __dllonexit(param_1,&DAT_100052a8,&DAT_100052a4);
  return;
}



int __cdecl FUN_10002934(_onexit_t param_1)

{
  int iVar1;
  
  iVar1 = FUN_10002908(param_1);
  return (iVar1 != 0) - 1;
}



void __CxxFrameHandler(void)

{
                    // WARNING: Could not recover jumptable at 0x10002946. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10002956(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 *_Memory;
  undefined4 *puVar2;
  
  if (param_2 == 0) {
    if (0 < DAT_1000529c) {
      DAT_1000529c = DAT_1000529c + -1;
      goto LAB_1000296c;
    }
LAB_10002994:
    uVar1 = 0;
  }
  else {
LAB_1000296c:
    _DAT_100052a0 = *(undefined4 *)_adjust_fdiv_exref;
    if (param_2 == 1) {
      DAT_100052a8 = (undefined4 *)malloc(0x80);
      if (DAT_100052a8 == (undefined4 *)0x0) goto LAB_10002994;
      *DAT_100052a8 = 0;
      DAT_100052a4 = DAT_100052a8;
      initterm(&DAT_10004000,&DAT_10004014);
      DAT_1000529c = DAT_1000529c + 1;
    }
    else if ((param_2 == 0) &&
            (_Memory = DAT_100052a8, puVar2 = DAT_100052a4, DAT_100052a8 != (undefined4 *)0x0)) {
      while (puVar2 = puVar2 + -1, _Memory <= puVar2) {
        if ((code *)*puVar2 != (code *)0x0) {
          (*(code *)*puVar2)();
          _Memory = DAT_100052a8;
        }
      }
      free(_Memory);
      DAT_100052a8 = (undefined4 *)0x0;
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
  iVar2 = DAT_1000529c;
  if (param_2 != 0) {
    if ((param_2 != 1) && (param_2 != 2)) goto LAB_10002a49;
    if ((PTR_FUN_1000409c != (undefined *)0x0) &&
       (iVar2 = (*(code *)PTR_FUN_1000409c)(param_1,param_2,param_3), iVar2 == 0)) {
      return 0;
    }
    iVar2 = FUN_10002956(param_1,param_2);
  }
  if (iVar2 == 0) {
    return 0;
  }
LAB_10002a49:
  iVar2 = FUN_10002787(param_1,param_2);
  if (param_2 == 1) {
    if (iVar2 != 0) {
      return iVar2;
    }
    FUN_10002956(param_1,0);
  }
  if ((param_2 != 0) && (param_2 != 3)) {
    return iVar2;
  }
  iVar3 = FUN_10002956(param_1,param_2);
  param_2 = iVar2;
  if (iVar3 == 0) {
    param_2 = 0;
  }
  if (param_2 != 0) {
    if (PTR_FUN_1000409c != (undefined *)0x0) {
      iVar2 = (*(code *)PTR_FUN_1000409c)(param_1,iVar1,param_3);
      return iVar2;
    }
    return param_2;
  }
  return 0;
}



void * __thiscall FUN_10002a9e(void *this,byte param_1)

{
  type_info::~type_info((type_info *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void FUN_10002abc(void)

{
  undefined1 auStack_c [12];
  
  ExceptionList = auStack_c;
  return;
}



void __dllonexit(void)

{
                    // WARNING: Could not recover jumptable at 0x10002adc. Too many branches
                    // WARNING: Treating indirect jump as call
  __dllonexit();
  return;
}



void __cdecl initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x10002ae2. Too many branches
                    // WARNING: Treating indirect jump as call
  initterm();
  return;
}



void __thiscall type_info::~type_info(type_info *this)

{
                    // WARNING: Could not recover jumptable at 0x10002ae8. Too many branches
                    // WARNING: Treating indirect jump as call
  ~type_info(this);
  return;
}



void __thiscall
AFX_MODULE_STATE::AFX_MODULE_STATE
          (AFX_MODULE_STATE *this,int param_1,FuncDef41 *param_2,ulong param_3)

{
                    // WARNING: Could not recover jumptable at 0x10002b96. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MODULE_STATE(this,param_1,param_2,param_3);
  return;
}



void CNoTrackObject::operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002b9c. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x10002ba2. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



long AfxWndProc(HWND__ *param_1,uint param_2,uint param_3,long param_4)

{
  long lVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002ba8. Too many branches
                    // WARNING: Treating indirect jump as call
  lVar1 = AfxWndProc(param_1,param_2,param_3,param_4);
  return lVar1;
}



void __thiscall
AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(AFX_MAINTAIN_STATE2 *this,AFX_MODULE_STATE *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002bae. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MAINTAIN_STATE2(this,param_1);
  return;
}



void AfxTermThread(HINSTANCE__ *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002bb4. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermThread(param_1);
  return;
}



void AfxTermExtensionModule(AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10002bba. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermExtensionModule(param_1,param_2);
  return;
}



int AfxUnlockTempMaps(int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002bc0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxUnlockTempMaps(param_1);
  return iVar1;
}



void AfxLockTempMaps(void)

{
                    // WARNING: Could not recover jumptable at 0x10002bc6. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxLockTempMaps();
  return;
}



AFX_MODULE_STATE * AfxSetModuleState(AFX_MODULE_STATE *param_1)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002bcc. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxSetModuleState(param_1);
  return pAVar1;
}



void __thiscall
CDynLinkLibrary::CDynLinkLibrary(CDynLinkLibrary *this,AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10002bd2. Too many branches
                    // WARNING: Treating indirect jump as call
  CDynLinkLibrary(this,param_1,param_2);
  return;
}



int AfxInitExtensionModule(AFX_EXTENSION_MODULE *param_1,HINSTANCE__ *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002bd8. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxInitExtensionModule(param_1,param_2);
  return iVar1;
}



void AfxWinTerm(void)

{
                    // WARNING: Could not recover jumptable at 0x10002bde. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxWinTerm();
  return;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002be4. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



int AfxWinInit(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002bea. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinInit(param_1,param_2,param_3,param_4);
  return iVar1;
}



_AFX_THREAD_STATE * AfxGetThreadState(void)

{
  _AFX_THREAD_STATE *p_Var1;
  
                    // WARNING: Could not recover jumptable at 0x10002bf0. Too many branches
                    // WARNING: Treating indirect jump as call
  p_Var1 = AfxGetThreadState();
  return p_Var1;
}



void AfxCoreInitModule(void)

{
                    // WARNING: Could not recover jumptable at 0x10002bf6. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxCoreInitModule();
  return;
}



void Unwind_10002c00(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x14));
  return;
}



void Unwind_10002c15(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_10002c1e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_10002c27(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_10002c3a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x58));
  return;
}



void Unwind_10002c43(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x60));
  return;
}



void Unwind_10002c4c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x74));
  return;
}



void Unwind_10002c55(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x78));
  return;
}



void Unwind_10002c5e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x7c));
  return;
}



void Unwind_10002c67(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x80));
  return;
}



void Unwind_10002c80(void)

{
  int unaff_EBP;
  
  FUN_10001940(*(SPRITE **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10002c89(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x124c));
  return;
}



void Unwind_10002c98(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x1250));
  return;
}



void Unwind_10002ca7(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x1254));
  return;
}



void Unwind_10002cc0(void)

{
  int unaff_EBP;
  
  FUN_10001940(*(SPRITE **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10002cc9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x124c));
  return;
}



void Unwind_10002cd8(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x1250));
  return;
}



void Unwind_10002ce7(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x1254));
  return;
}



void Unwind_10002d00(void)

{
  int unaff_EBP;
  
  FUN_100028ff((undefined4 *)(unaff_EBP + -0x14));
  return;
}


