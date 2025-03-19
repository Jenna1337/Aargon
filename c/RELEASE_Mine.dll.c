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

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

typedef int __ehstate_t;

struct _s_TryBlockMapEntry {
    __ehstate_t tryLow;
    __ehstate_t tryHigh;
    __ehstate_t catchHigh;
    int nCatches;
    HandlerType *pHandlerArray;
};

typedef struct _s_TryBlockMapEntry TryBlockMapEntry;

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    void (*action)(void);
};

typedef struct _s_UnwindMapEntry UnwindMapEntry;

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
  CWave::CWave((CWave *)&DAT_100040d8);
  return;
}



void FUN_1000101f(void)

{
  FUN_10001e78(FUN_10001031);
  return;
}



void FUN_10001031(void)

{
  CWave::~CWave((CWave *)&DAT_100040d8);
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
  
                    // 0x1041  1  ?Create@@YAPAVTwMovingObject@@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000214b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pSVar1 = (SPRITE *)operator_new(0x1130);
  local_8 = 0;
  if (pSVar1 == (SPRITE *)0x0) {
    local_1c = (SPRITE *)0x0;
  }
  else {
    local_1c = FUN_10001970(pSVar1);
  }
  ExceptionList = local_10;
  return (TwMovingObject *)local_1c;
}



void __thiscall FUN_100010ab(void *this,undefined4 *param_1,int *param_2)

{
  CString *pCVar1;
  undefined4 uVar2;
  int iVar3;
  double dVar4;
  CString local_18 [4];
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000215e;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  if (DAT_10004118 == 0) {
    local_14 = &stack0xffffffd4;
    ExceptionList = &local_10;
    CString::CString((CString *)&stack0xffffffd4,s_mine_wav_10004020);
    pCVar1 = (CString *)(**(code **)(*param_2 + 0x58))(local_18);
    local_8 = 0;
    CWave::Create((CWave *)&DAT_100040d8,pCVar1);
    local_8 = 0xffffffff;
    CString::~CString(local_18);
    DAT_10004118 = 1;
  }
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x2c))(*param_1);
  RandomProb();
  uVar2 = ftol();
  RandomProb();
  uVar2 = ftol(uVar2);
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x58))(uVar2);
  dVar4 = RandomProb();
  if (0.5 < dVar4) {
    RandomProb();
    iVar3 = ftol();
                    // WARNING: Load size is inaccurate
    (**(code **)(*this + 0x5c))(-iVar3);
  }
  dVar4 = RandomProb();
  if (0.5 < dVar4) {
    RandomProb();
    iVar3 = ftol();
                    // WARNING: Load size is inaccurate
    (**(code **)(*this + 0x60))(-iVar3);
  }
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x4c))(100);
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x50))();
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_10001217(void *this,MAP *param_1)

{
  bool bVar1;
  char cVar2;
  undefined4 *puVar3;
  void *pvVar4;
  int iVar5;
  undefined4 uVar6;
  CString **ppCVar7;
  uchar *puVar8;
  int local_ec;
  int local_e0;
  int local_d4;
  int local_c8;
  CString local_94 [4];
  char local_90;
  undefined3 uStack_8f;
  CString local_8c [4];
  char local_88;
  undefined3 uStack_87;
  CString local_84 [4];
  char local_80;
  undefined3 uStack_7f;
  CString local_7c [4];
  CString local_78 [4];
  uint local_74;
  CString local_70 [4];
  uint local_6c;
  CString local_68 [4];
  uint local_64;
  CString local_60 [4];
  uint local_5c;
  undefined1 local_58 [8];
  undefined1 local_50 [8];
  undefined1 local_48 [8];
  undefined1 local_40 [8];
  ITEM *local_38;
  int local_34;
  ITEM *local_30;
  int local_2c;
  int local_28;
  ITEM *local_24;
  int local_20;
  int local_1c;
  ITEM *local_18;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_100021b6;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_20 = OVERLAY::GetXPos((OVERLAY *)this);
  local_28 = OVERLAY::GetYPos((OVERLAY *)this);
  local_1c = 1;
  local_2c = 1;
  local_14 = 1;
  local_34 = 1;
  local_38 = (ITEM *)0x0;
  local_24 = (ITEM *)0x0;
  local_18 = (ITEM *)0x0;
  local_30 = (ITEM *)0x0;
  puVar3 = (undefined4 *)default_error_condition(local_40,local_20 + 0x10U >> 5,local_28 - 1U >> 5);
  local_38 = MAP::GetItem(param_1,*puVar3,puVar3[1]);
  puVar3 = (undefined4 *)
           default_error_condition(local_48,local_20 + 0x10U >> 5,local_28 + 0x21U >> 5);
  local_24 = MAP::GetItem(param_1,*puVar3,puVar3[1]);
  puVar3 = (undefined4 *)default_error_condition(local_50,local_20 - 1U >> 5,local_28 + 0x10U >> 5);
  local_18 = MAP::GetItem(param_1,*puVar3,puVar3[1]);
  puVar3 = (undefined4 *)
           default_error_condition(local_58,local_20 + 0x21U >> 5,local_28 + 0x10U >> 5);
  local_30 = MAP::GetItem(param_1,*puVar3,puVar3[1]);
  if (local_38 != (ITEM *)0x0) {
    ppCVar7 = &this_1000402c;
    pvVar4 = (void *)(**(code **)(*(int *)local_38 + 0x50))(local_60);
    local_8 = 0;
    bVar1 = FUN_10001ac0(pvVar4,(uchar *)ppCVar7);
    local_5c = CONCAT31(local_5c._1_3_,bVar1);
    local_8 = 0xffffffff;
    CString::~CString(local_60);
    if ((local_5c & 0xff) != 0) {
      FUN_10001bd0(local_38,1);
      FUN_10001bf0(local_38,0);
      ExceptionList = local_10;
      return;
    }
  }
  if (local_24 != (ITEM *)0x0) {
    ppCVar7 = &this_10004030;
    pvVar4 = (void *)(**(code **)(*(int *)local_24 + 0x50))(local_68);
    local_8 = 1;
    bVar1 = FUN_10001ac0(pvVar4,(uchar *)ppCVar7);
    local_64 = CONCAT31(local_64._1_3_,bVar1);
    local_8 = 0xffffffff;
    CString::~CString(local_68);
    if ((local_64 & 0xff) != 0) {
      FUN_10001bd0(local_24,1);
      FUN_10001bf0(local_24,0);
      ExceptionList = local_10;
      return;
    }
  }
  if (local_18 != (ITEM *)0x0) {
    ppCVar7 = &this_10004034;
    pvVar4 = (void *)(**(code **)(*(int *)local_18 + 0x50))(local_70);
    local_8 = 2;
    bVar1 = FUN_10001ac0(pvVar4,(uchar *)ppCVar7);
    local_6c = CONCAT31(local_6c._1_3_,bVar1);
    local_8 = 0xffffffff;
    CString::~CString(local_70);
    if ((local_6c & 0xff) != 0) {
      FUN_10001bd0(local_18,1);
      FUN_10001bf0(local_18,0);
      ExceptionList = local_10;
      return;
    }
  }
  if (local_30 != (ITEM *)0x0) {
    ppCVar7 = &this_10004038;
    pvVar4 = (void *)(**(code **)(*(int *)local_30 + 0x50))(local_78);
    local_8 = 3;
    bVar1 = FUN_10001ac0(pvVar4,(uchar *)ppCVar7);
    local_74 = CONCAT31(local_74._1_3_,bVar1);
    local_8 = 0xffffffff;
    CString::~CString(local_78);
    if ((local_74 & 0xff) != 0) {
      FUN_10001bd0(local_30,1);
      FUN_10001bf0(local_30,0);
      ExceptionList = local_10;
      return;
    }
  }
  if (local_38 != (ITEM *)0x0) {
    puVar8 = &DAT_1000403c;
    pvVar4 = (void *)(**(code **)(*(int *)local_38 + 0x50))(local_7c);
    local_8 = 4;
    bVar1 = FUN_10001b20(pvVar4,puVar8);
    if (bVar1) {
LAB_1000159f:
      local_c8 = 1;
    }
    else {
      cVar2 = (**(code **)(*(int *)local_38 + 0x80))();
      _local_80 = CONCAT31(uStack_7f,cVar2);
      if (cVar2 != '\0') goto LAB_1000159f;
      local_c8 = 0;
    }
    local_1c = local_c8;
    local_8 = 0xffffffff;
    CString::~CString(local_7c);
  }
  if (local_24 != (ITEM *)0x0) {
    puVar8 = &DAT_10004040;
    pvVar4 = (void *)(**(code **)(*(int *)local_24 + 0x50))(local_84);
    local_8 = 5;
    bVar1 = FUN_10001b20(pvVar4,puVar8);
    if (bVar1) {
LAB_1000163d:
      local_d4 = 1;
    }
    else {
      cVar2 = (**(code **)(*(int *)local_24 + 0x80))();
      _local_88 = CONCAT31(uStack_87,cVar2);
      if (cVar2 != '\0') goto LAB_1000163d;
      local_d4 = 0;
    }
    local_2c = local_d4;
    local_8 = 0xffffffff;
    CString::~CString(local_84);
  }
  if (local_18 == (ITEM *)0x0) goto LAB_10001703;
  puVar8 = &DAT_10004044;
  pvVar4 = (void *)(**(code **)(*(int *)local_18 + 0x50))(local_8c);
  local_8 = 6;
  bVar1 = FUN_10001b20(pvVar4,puVar8);
  if (bVar1) {
LAB_100016de:
    local_e0 = 1;
  }
  else {
    cVar2 = (**(code **)(*(int *)local_18 + 0x80))();
    _local_90 = CONCAT31(uStack_8f,cVar2);
    if (cVar2 != '\0') goto LAB_100016de;
    local_e0 = 0;
  }
  local_14 = local_e0;
  local_8 = 0xffffffff;
  CString::~CString(local_8c);
LAB_10001703:
  if (local_30 != (ITEM *)0x0) {
    puVar8 = &DAT_10004048;
    pvVar4 = (void *)(**(code **)(*(int *)local_30 + 0x50))(local_94);
    local_8 = 7;
    bVar1 = FUN_10001b20(pvVar4,puVar8);
    if ((bVar1) || (cVar2 = (**(code **)(*(int *)local_30 + 0x80))(), cVar2 != '\0')) {
      local_ec = 1;
    }
    else {
      local_ec = 0;
    }
    local_34 = local_ec;
    local_8 = 0xffffffff;
    CString::~CString(local_94);
  }
  if ((((local_1c == 0) || (local_2c == 0)) || (local_34 == 0)) || (local_14 == 0)) {
                    // WARNING: Load size is inaccurate
    iVar5 = (**(code **)(*this + 0x68))();
                    // WARNING: Load size is inaccurate
    if ((iVar5 == 0) && (iVar5 = (**(code **)(*this + 100))(), iVar5 == 0)) {
      RandomProb();
      uVar6 = ftol();
      RandomProb();
      uVar6 = ftol(uVar6);
                    // WARNING: Load size is inaccurate
      (**(code **)(*this + 0x58))(uVar6);
    }
                    // WARNING: Load size is inaccurate
    iVar5 = (**(code **)(*this + 0x68))();
    if ((iVar5 < 0) && (local_1c != 0)) {
      RandomProb();
      uVar6 = ftol();
                    // WARNING: Load size is inaccurate
      (**(code **)(*this + 0x60))(uVar6);
    }
    else {
                    // WARNING: Load size is inaccurate
      iVar5 = (**(code **)(*this + 0x68))();
      if ((0 < iVar5) && (local_2c != 0)) {
        RandomProb();
        iVar5 = ftol();
                    // WARNING: Load size is inaccurate
        (**(code **)(*this + 0x60))(-iVar5);
      }
    }
                    // WARNING: Load size is inaccurate
    iVar5 = (**(code **)(*this + 100))();
    if ((iVar5 < 0) && (local_14 != 0)) {
      RandomProb();
      uVar6 = ftol();
                    // WARNING: Load size is inaccurate
      (**(code **)(*this + 0x5c))(uVar6);
    }
    else {
                    // WARNING: Load size is inaccurate
      iVar5 = (**(code **)(*this + 100))();
      if ((0 < iVar5) && (local_34 != 0)) {
        RandomProb();
        iVar5 = ftol();
                    // WARNING: Load size is inaccurate
        (**(code **)(*this + 0x5c))(-iVar5);
      }
    }
  }
  else {
                    // WARNING: Load size is inaccurate
    (**(code **)(*this + 0x58))(0,0);
  }
  ExceptionList = local_10;
  return;
}



SPRITE * __fastcall FUN_10001970(SPRITE *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100021c9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10001a20(param_1);
  local_8 = 0;
  FUN_10001b40((DWORD *)(param_1 + 0x112c));
  *(undefined ***)param_1 = &PTR_FUN_10003144;
  *(undefined ***)(param_1 + 8) = &PTR_LAB_10003140;
  ExceptionList = local_10;
  return param_1;
}



undefined1 FUN_100019e0(void)

{
  return 1;
}



void * __thiscall FUN_100019f0(void *this,uint param_1)

{
  FUN_10001a70((SPRITE *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



SPRITE * __fastcall FUN_10001a20(SPRITE *param_1)

{
  SPRITE::SPRITE(param_1);
  *(undefined ***)param_1 = &PTR_FUN_100031c8;
  *(undefined ***)(param_1 + 8) = &PTR_LAB_100031c4;
  return param_1;
}



void __fastcall FUN_10001a50(SPRITE *param_1)

{
  SPRITE::~SPRITE(param_1);
  return;
}



void __fastcall FUN_10001a70(SPRITE *param_1)

{
  FUN_10001a50(param_1);
  return;
}



void * __thiscall FUN_10001a90(void *this,uint param_1)

{
  FUN_10001a50((SPRITE *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



bool FUN_10001ac0(void *param_1,uchar *param_2)

{
  int iVar1;
  
  iVar1 = FUN_10001ae0(param_1,param_2);
  return (bool)('\x01' - (iVar1 != 0));
}



void __thiscall FUN_10001ae0(void *this,uchar *param_1)

{
                    // WARNING: Load size is inaccurate
  FUN_10001b00(*this,param_1);
  return;
}



void __cdecl FUN_10001b00(uchar *param_1,uchar *param_2)

{
  _mbscmp(param_1,param_2);
  return;
}



bool FUN_10001b20(void *param_1,uchar *param_2)

{
  int iVar1;
  
  iVar1 = FUN_10001ae0(param_1,param_2);
  return iVar1 != 0;
}



DWORD * __fastcall FUN_10001b40(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
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
  FUN_10001b80(this,param_1,param_2);
  return this;
}



void * __thiscall FUN_10001b80(void *this,undefined4 param_1,undefined4 param_2)

{
  *(undefined4 *)this = param_1;
  *(undefined4 *)((int)this + 4) = param_2;
  return this;
}



undefined1 __fastcall FUN_10001bb0(int param_1)

{
  return *(undefined1 *)(param_1 + 0xa0);
}



void __thiscall FUN_10001bd0(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 4) = param_1;
  return;
}



void __thiscall FUN_10001bf0(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 8) = param_1;
  return;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10001c06. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x10001c0c. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void __thiscall CString::~CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x10001c12. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CString(this);
  return;
}



void __thiscall CString::CString(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10001c18. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



void * __thiscall FUN_10001c50(void *this,byte param_1)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)this);
  if ((param_1 & 1) != 0) {
    CNoTrackObject::operator_delete(this);
  }
  return this;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x100020e6. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



int FUN_10001ccb(HINSTANCE__ *param_1,int param_2)

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
      pAVar5 = AfxSetModuleState((AFX_MODULE_STATE *)&this_10004120);
      p_Var3 = AfxGetThreadState();
      *(AFX_MODULE_STATE **)(p_Var3 + 8) = pAVar5;
      pAVar5 = AfxGetModuleState();
      if (*(int **)(pAVar5 + 4) != (int *)0x0) {
        (**(code **)(**(int **)(pAVar5 + 4) + 0x70))();
      }
      AfxLockTempMaps();
      AfxUnlockTempMaps(-1);
      AfxWinTerm();
      AfxTermExtensionModule((AFX_EXTENSION_MODULE *)&param_1_100051b0,1);
    }
    else if (param_2 == 3) {
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
                ((AFX_MAINTAIN_STATE2 *)&local_c,(AFX_MODULE_STATE *)&this_10004120);
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
      AfxInitExtensionModule((AFX_EXTENSION_MODULE *)&param_1_100051b0,param_1);
      this = (CDynLinkLibrary *)operator_new(0x40);
      if (this != (CDynLinkLibrary *)0x0) {
        CDynLinkLibrary::CDynLinkLibrary(this,(AFX_EXTENSION_MODULE *)&param_1_100051b0,0);
      }
      param_2 = 1;
      goto LAB_10001d57;
    }
    (**(code **)(*piVar2 + 0x70))();
  }
  AfxWinTerm();
LAB_10001d57:
  *(undefined4 *)(p_Var3 + 8) = uVar1;
  p_Var3 = AfxGetThreadState();
  AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var3 + 8));
  return param_2;
}



undefined4 FUN_10001df2(undefined4 param_1,int param_2)

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
    pAVar2 = AfxSetModuleState((AFX_MODULE_STATE *)&this_10004120);
    *(AFX_MODULE_STATE **)(p_Var1 + 8) = pAVar2;
  }
  else if (param_2 == 0) {
    p_Var1 = AfxGetThreadState();
    AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var1 + 8));
  }
  return 1;
}



void __fastcall FUN_10001e43(undefined4 *param_1)

{
  *(undefined4 *)(param_1[1] + 4) = *param_1;
  return;
}



void __cdecl FUN_10001e4c(_onexit_t param_1)

{
  if (DAT_100051d8 == -1) {
    _onexit(param_1);
    return;
  }
  __dllonexit(param_1,&DAT_100051d8,&DAT_100051d4);
  return;
}



int __cdecl FUN_10001e78(_onexit_t param_1)

{
  int iVar1;
  
  iVar1 = FUN_10001e4c(param_1);
  return (iVar1 != 0) - 1;
}



void __CxxFrameHandler(void)

{
                    // WARNING: Could not recover jumptable at 0x10001e8a. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler();
  return;
}



void __cdecl ftol(void)

{
                    // WARNING: Could not recover jumptable at 0x10001e96. Too many branches
                    // WARNING: Treating indirect jump as call
  ftol();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10001e9c(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 *_Memory;
  undefined4 *puVar2;
  
  if (param_2 == 0) {
    if (0 < DAT_100051cc) {
      DAT_100051cc = DAT_100051cc + -1;
      goto LAB_10001eb2;
    }
LAB_10001eda:
    uVar1 = 0;
  }
  else {
LAB_10001eb2:
    _DAT_100051d0 = *(undefined4 *)_adjust_fdiv_exref;
    if (param_2 == 1) {
      DAT_100051d8 = (undefined4 *)malloc(0x80);
      if (DAT_100051d8 == (undefined4 *)0x0) goto LAB_10001eda;
      *DAT_100051d8 = 0;
      DAT_100051d4 = DAT_100051d8;
      initterm(&DAT_10004000,&DAT_1000400c);
      DAT_100051cc = DAT_100051cc + 1;
    }
    else if ((param_2 == 0) &&
            (_Memory = DAT_100051d8, puVar2 = DAT_100051d4, DAT_100051d8 != (undefined4 *)0x0)) {
      while (puVar2 = puVar2 + -1, _Memory <= puVar2) {
        if ((code *)*puVar2 != (code *)0x0) {
          (*(code *)*puVar2)();
          _Memory = DAT_100051d8;
        }
      }
      free(_Memory);
      DAT_100051d8 = (undefined4 *)0x0;
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
  iVar2 = DAT_100051cc;
  if (param_2 != 0) {
    if ((param_2 != 1) && (param_2 != 2)) goto LAB_10001f8f;
    if ((PTR_FUN_1000404c != (undefined *)0x0) &&
       (iVar2 = (*(code *)PTR_FUN_1000404c)(param_1,param_2,param_3), iVar2 == 0)) {
      return 0;
    }
    iVar2 = FUN_10001e9c(param_1,param_2);
  }
  if (iVar2 == 0) {
    return 0;
  }
LAB_10001f8f:
  iVar2 = FUN_10001ccb(param_1,param_2);
  if (param_2 == 1) {
    if (iVar2 != 0) {
      return iVar2;
    }
    FUN_10001e9c(param_1,0);
  }
  if ((param_2 != 0) && (param_2 != 3)) {
    return iVar2;
  }
  iVar3 = FUN_10001e9c(param_1,param_2);
  param_2 = iVar2;
  if (iVar3 == 0) {
    param_2 = 0;
  }
  if (param_2 != 0) {
    if (PTR_FUN_1000404c != (undefined *)0x0) {
      iVar2 = (*(code *)PTR_FUN_1000404c)(param_1,iVar1,param_3);
      return iVar2;
    }
    return param_2;
  }
  return 0;
}



void * __thiscall FUN_10001fe4(void *this,byte param_1)

{
  type_info::~type_info((type_info *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __dllonexit(void)

{
                    // WARNING: Could not recover jumptable at 0x10002020. Too many branches
                    // WARNING: Treating indirect jump as call
  __dllonexit();
  return;
}



void __cdecl initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x10002026. Too many branches
                    // WARNING: Treating indirect jump as call
  initterm();
  return;
}



void __thiscall type_info::~type_info(type_info *this)

{
                    // WARNING: Could not recover jumptable at 0x1000202c. Too many branches
                    // WARNING: Treating indirect jump as call
  ~type_info(this);
  return;
}



void CNoTrackObject::operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100020e0. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x100020e6. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



void __thiscall
AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(AFX_MAINTAIN_STATE2 *this,AFX_MODULE_STATE *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100020f2. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MAINTAIN_STATE2(this,param_1);
  return;
}



void AfxTermThread(HINSTANCE__ *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100020f8. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermThread(param_1);
  return;
}



void AfxTermExtensionModule(AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x100020fe. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermExtensionModule(param_1,param_2);
  return;
}



int AfxUnlockTempMaps(int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002104. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxUnlockTempMaps(param_1);
  return iVar1;
}



void AfxLockTempMaps(void)

{
                    // WARNING: Could not recover jumptable at 0x1000210a. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxLockTempMaps();
  return;
}



AFX_MODULE_STATE * AfxSetModuleState(AFX_MODULE_STATE *param_1)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002110. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxSetModuleState(param_1);
  return pAVar1;
}



void __thiscall
CDynLinkLibrary::CDynLinkLibrary(CDynLinkLibrary *this,AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10002116. Too many branches
                    // WARNING: Treating indirect jump as call
  CDynLinkLibrary(this,param_1,param_2);
  return;
}



int AfxInitExtensionModule(AFX_EXTENSION_MODULE *param_1,HINSTANCE__ *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000211c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxInitExtensionModule(param_1,param_2);
  return iVar1;
}



void AfxWinTerm(void)

{
                    // WARNING: Could not recover jumptable at 0x10002122. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxWinTerm();
  return;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002128. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



int AfxWinInit(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000212e. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinInit(param_1,param_2,param_3,param_4);
  return iVar1;
}



_AFX_THREAD_STATE * AfxGetThreadState(void)

{
  _AFX_THREAD_STATE *p_Var1;
  
                    // WARNING: Could not recover jumptable at 0x10002134. Too many branches
                    // WARNING: Treating indirect jump as call
  p_Var1 = AfxGetThreadState();
  return p_Var1;
}



void AfxCoreInitModule(void)

{
                    // WARNING: Could not recover jumptable at 0x1000213a. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxCoreInitModule();
  return;
}



void Unwind_10002140(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x14));
  return;
}



void Unwind_10002155(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_10002168(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x5c));
  return;
}



void Unwind_10002171(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -100));
  return;
}



void Unwind_1000217a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x6c));
  return;
}



void Unwind_10002183(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x74));
  return;
}



void Unwind_1000218c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x78));
  return;
}



void Unwind_10002195(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x80));
  return;
}



void Unwind_1000219e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x88));
  return;
}



void Unwind_100021aa(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x90));
  return;
}



void Unwind_100021c0(void)

{
  int unaff_EBP;
  
  FUN_10001a50(*(SPRITE **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100021d4(void)

{
  int unaff_EBP;
  
  FUN_10001e43((undefined4 *)(unaff_EBP + -0x14));
  return;
}


