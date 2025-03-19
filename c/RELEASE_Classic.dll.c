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

typedef struct AFX_EXTENSION_MODULE AFX_EXTENSION_MODULE, *PAFX_EXTENSION_MODULE;

struct AFX_EXTENSION_MODULE { // PlaceHolder Structure
};

typedef struct AFX_MODULE_STATE AFX_MODULE_STATE, *PAFX_MODULE_STATE;

struct AFX_MODULE_STATE { // PlaceHolder Structure
};

typedef struct OVERLAY OVERLAY, *POVERLAY;

struct OVERLAY { // PlaceHolder Structure
};

typedef struct CDynLinkLibrary CDynLinkLibrary, *PCDynLinkLibrary;

struct CDynLinkLibrary { // PlaceHolder Structure
};

typedef struct CString CString, *PCString;

struct CString { // PlaceHolder Structure
};

typedef struct CMidi CMidi, *PCMidi;

struct CMidi { // PlaceHolder Structure
};

typedef struct GAME GAME, *PGAME;

struct GAME { // PlaceHolder Structure
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ { // PlaceHolder Structure
};

typedef struct _AFX_THREAD_STATE _AFX_THREAD_STATE, *P_AFX_THREAD_STATE;

struct _AFX_THREAD_STATE { // PlaceHolder Structure
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef struct SELECT_SKILL1 SELECT_SKILL1, *PSELECT_SKILL1;

struct SELECT_SKILL1 { // PlaceHolder Structure
};

typedef struct SPRITE SPRITE, *PSPRITE;

struct SPRITE { // PlaceHolder Structure
};

typedef struct HWND__ HWND__, *PHWND__;

struct HWND__ { // PlaceHolder Structure
};

typedef struct AFX_MAINTAIN_STATE2 AFX_MAINTAIN_STATE2, *PAFX_MAINTAIN_STATE2;

struct AFX_MAINTAIN_STATE2 { // PlaceHolder Structure
};

typedef int (*_onexit_t)(void);

typedef uint size_t;




// class SELECT_SKILL1 * __cdecl Create(class GAME *)

SELECT_SKILL1 * __cdecl Create(GAME *param_1)

{
  void *this;
  SELECT_SKILL1 *local_1c;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x1000  1  ?Create@@YAPAVSELECT_SKILL1@@PAVGAME@@@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_10002cfb;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  this = operator_new(0x7998);
  local_8 = 0;
  if (this == (void *)0x0) {
    local_1c = (SELECT_SKILL1 *)0x0;
  }
  else {
    local_1c = (SELECT_SKILL1 *)FUN_10002470(this,param_1);
  }
  ExceptionList = local_10;
  return local_1c;
}



void __fastcall FUN_1000106e(int param_1)

{
  undefined4 *puVar1;
  char *pcVar2;
  int extraout_ECX;
  int extraout_ECX_00;
  int extraout_ECX_01;
  int extraout_ECX_02;
  int extraout_ECX_03;
  int extraout_ECX_04;
  int iVar3;
  undefined1 uVar4;
  int iVar5;
  int iVar6;
  CString local_50 [4];
  undefined1 *local_4c;
  CString local_48 [4];
  undefined1 *local_44;
  CString local_40 [4];
  undefined1 *local_3c;
  CString local_38 [4];
  undefined1 *local_34;
  CString local_30 [4];
  undefined1 *local_2c;
  CString local_28 [4];
  undefined1 *local_24;
  CString local_20 [4];
  undefined1 *local_1c;
  CString local_18 [4];
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_10002d4d;
  local_10 = ExceptionList;
  iVar6 = 1;
  iVar5 = 1;
  local_14 = &stack0xffffff38;
  ExceptionList = &local_10;
  iVar3 = param_1;
  CString::CString((CString *)&stack0xffffff38,s_SPRTITLE_BMP_10004020);
  uVar4 = SUB41(local_18,0);
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x7840) + 0x54))();
  local_8 = 0;
  pcVar2 = (char *)FUN_10002700(puVar1);
  SPRITE::Init((SPRITE *)(param_1 + 0xc),pcVar2,(bool)uVar4,iVar3,iVar5,iVar6);
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  iVar6 = 2;
  iVar5 = 1;
  local_1c = &stack0xffffff30;
  iVar3 = extraout_ECX;
  CString::CString((CString *)&stack0xffffff30,s_SPRSELECT1_BMP_10004030);
  uVar4 = SUB41(local_20,0);
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x7840) + 0x54))();
  local_8 = 1;
  pcVar2 = (char *)FUN_10002700(puVar1);
  SPRITE::Init((SPRITE *)(param_1 + 0x1138),pcVar2,(bool)uVar4,iVar3,iVar5,iVar6);
  local_8 = 0xffffffff;
  CString::~CString(local_20);
  iVar6 = 2;
  iVar5 = 1;
  local_24 = &stack0xffffff28;
  iVar3 = extraout_ECX_00;
  CString::CString((CString *)&stack0xffffff28,s_SPRSELECT2_BMP_10004040);
  uVar4 = SUB41(local_28,0);
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x7840) + 0x54))();
  local_8 = 2;
  pcVar2 = (char *)FUN_10002700(puVar1);
  SPRITE::Init((SPRITE *)(param_1 + 0x2264),pcVar2,(bool)uVar4,iVar3,iVar5,iVar6);
  local_8 = 0xffffffff;
  CString::~CString(local_28);
  iVar6 = 2;
  iVar5 = 1;
  local_2c = &stack0xffffff20;
  iVar3 = extraout_ECX_01;
  CString::CString((CString *)&stack0xffffff20,s_SPRSELECT3_BMP_10004050);
  uVar4 = SUB41(local_30,0);
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x7840) + 0x54))();
  local_8 = 3;
  pcVar2 = (char *)FUN_10002700(puVar1);
  SPRITE::Init((SPRITE *)(param_1 + 0x3390),pcVar2,(bool)uVar4,iVar3,iVar5,iVar6);
  local_8 = 0xffffffff;
  CString::~CString(local_30);
  iVar6 = 2;
  iVar5 = 1;
  local_34 = &stack0xffffff18;
  iVar3 = extraout_ECX_02;
  CString::CString((CString *)&stack0xffffff18,s_SPRSELECT4_BMP_10004060);
  uVar4 = SUB41(local_38,0);
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x7840) + 0x54))();
  local_8 = 4;
  pcVar2 = (char *)FUN_10002700(puVar1);
  SPRITE::Init((SPRITE *)(param_1 + 0x44bc),pcVar2,(bool)uVar4,iVar3,iVar5,iVar6);
  local_8 = 0xffffffff;
  CString::~CString(local_38);
  iVar6 = 2;
  iVar5 = 1;
  local_3c = &stack0xffffff10;
  iVar3 = extraout_ECX_03;
  CString::CString((CString *)&stack0xffffff10,s_SPRSELECT5_BMP_10004070);
  uVar4 = SUB41(local_40,0);
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x7840) + 0x54))();
  local_8 = 5;
  pcVar2 = (char *)FUN_10002700(puVar1);
  SPRITE::Init((SPRITE *)(param_1 + 0x55e8),pcVar2,(bool)uVar4,iVar3,iVar5,iVar6);
  local_8 = 0xffffffff;
  CString::~CString(local_40);
  iVar6 = 2;
  iVar5 = 1;
  local_44 = &stack0xffffff08;
  iVar3 = extraout_ECX_04;
  CString::CString((CString *)&stack0xffffff08,s_SPRSELECT6_BMP_10004080);
  uVar4 = SUB41(local_48,0);
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x7840) + 0x54))();
  local_8 = 6;
  pcVar2 = (char *)FUN_10002700(puVar1);
  SPRITE::Init((SPRITE *)(param_1 + 0x6714),pcVar2,(bool)uVar4,iVar3,iVar5,iVar6);
  local_8 = 0xffffffff;
  CString::~CString(local_48);
  CMidi::Init((CMidi *)(param_1 + 0x7844));
  local_4c = &stack0xffffff10;
  CString::CString((CString *)&stack0xffffff10,s_quartet_rmi_10004090);
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x7840) + 0x58))();
  local_8 = 7;
  pcVar2 = (char *)FUN_10002700(puVar1);
  CMidi::LoadSong((CMidi *)(param_1 + 0x7844),pcVar2);
  local_8 = 0xffffffff;
  CString::~CString(local_50);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10001445(int param_1)

{
  undefined4 *puVar1;
  char *pcVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  CString *pCVar7;
  uint *puVar8;
  CString local_20 [4];
  undefined1 *local_1c;
  uint local_18 [2];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10002d60;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CMidi::Play((CMidi *)(param_1 + 0x7844),1,0,0,0);
  FUN_10002360(param_1);
  local_18[1] = 0;
  local_18[0] = 0;
  puVar8 = local_18;
  local_1c = &stack0xffffffc4;
  CString::CString((CString *)&stack0xffffffc4,s_SPRTITLE_BMP_1000409c);
  pCVar7 = local_20;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x7840) + 0x54))();
  local_8 = 0;
  pcVar2 = (char *)FUN_10002700(puVar1);
  GKTOOLS::GetDIBSize(pcVar2,(uint *)pCVar7,puVar8);
  local_8 = 0xffffffff;
  CString::~CString(local_20);
  (**(code **)(*(int *)(param_1 + 0xc) + 0x1c))();
  (**(code **)(*(int *)(param_1 + 0xc) + 0x2c))(0x280 - local_18[0] >> 1);
  (**(code **)(*(int *)(param_1 + 0xc) + 0x6c))(0x280 - local_18[0] >> 1,0x17,300);
  uVar6 = 0x82;
  iVar3 = FUN_10002830(param_1 + 0x1138);
  (**(code **)(*(int *)(param_1 + 0x1138) + 0x2c))(-(iVar3 / 2),uVar6);
  uVar5 = 300;
  uVar6 = 0x82;
  iVar3 = FUN_10002830(param_1 + 0x1138);
  (**(code **)(*(int *)(param_1 + 0x1138) + 0x6c))(0x280U - iVar3 >> 1,uVar6,uVar5);
  (**(code **)(*(int *)(param_1 + 0x1138) + 0x1c))();
  uVar6 = 0xb9;
  uVar4 = FUN_10002830(param_1 + 0x2264);
  (**(code **)(*(int *)(param_1 + 0x2264) + 0x2c))((uVar4 >> 1) + 0x280,uVar6);
  uVar5 = 300;
  uVar6 = 0xb9;
  iVar3 = FUN_10002830(param_1 + 0x2264);
  (**(code **)(*(int *)(param_1 + 0x2264) + 0x6c))(0x280U - iVar3 >> 1,uVar6,uVar5);
  (**(code **)(*(int *)(param_1 + 0x2264) + 0x1c))();
  uVar6 = 0xf0;
  iVar3 = FUN_10002830(param_1 + 0x3390);
  (**(code **)(*(int *)(param_1 + 0x3390) + 0x2c))(-(iVar3 / 2),uVar6);
  uVar5 = 300;
  uVar6 = 0xf0;
  iVar3 = FUN_10002830(param_1 + 0x3390);
  (**(code **)(*(int *)(param_1 + 0x3390) + 0x6c))(0x280U - iVar3 >> 1,uVar6,uVar5);
  (**(code **)(*(int *)(param_1 + 0x3390) + 0x1c))();
  uVar6 = 0x127;
  uVar4 = FUN_10002830(param_1 + 0x44bc);
  (**(code **)(*(int *)(param_1 + 0x44bc) + 0x2c))((uVar4 >> 1) + 0x280,uVar6);
  uVar5 = 300;
  uVar6 = 0x127;
  iVar3 = FUN_10002830(param_1 + 0x44bc);
  (**(code **)(*(int *)(param_1 + 0x44bc) + 0x6c))(0x280U - iVar3 >> 1,uVar6,uVar5);
  (**(code **)(*(int *)(param_1 + 0x44bc) + 0x1c))();
  uVar6 = 0x15e;
  iVar3 = FUN_10002830(param_1 + 0x55e8);
  (**(code **)(*(int *)(param_1 + 0x55e8) + 0x2c))(-(iVar3 / 2),uVar6);
  uVar5 = 300;
  uVar6 = 0x15e;
  iVar3 = FUN_10002830(param_1 + 0x55e8);
  (**(code **)(*(int *)(param_1 + 0x55e8) + 0x6c))(0x280U - iVar3 >> 1,uVar6,uVar5);
  (**(code **)(*(int *)(param_1 + 0x55e8) + 0x1c))();
  uVar6 = 0x195;
  uVar4 = FUN_10002830(param_1 + 0x6714);
  (**(code **)(*(int *)(param_1 + 0x6714) + 0x2c))((uVar4 >> 1) + 0x280,uVar6);
  uVar5 = 300;
  uVar6 = 0x195;
  iVar3 = FUN_10002830(param_1 + 0x6714);
  (**(code **)(*(int *)(param_1 + 0x6714) + 0x6c))(0x280U - iVar3 >> 1,uVar6,uVar5);
  (**(code **)(*(int *)(param_1 + 0x6714) + 0x1c))();
  *(undefined4 *)(param_1 + 4) = 4;
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10001847(int param_1)

{
  char cVar1;
  bool bVar2;
  undefined3 extraout_var;
  
  if (*(int *)(param_1 + 4) == 4) {
    cVar1 = (**(code **)(*(int *)(param_1 + 0x1138) + 0x44))();
    if (cVar1 == '\0') {
      (**(code **)(*(int *)(param_1 + 0x1138) + 0x70))(0);
    }
    else {
      (**(code **)(*(int *)(param_1 + 0x1138) + 0x70))(1);
    }
    cVar1 = (**(code **)(*(int *)(param_1 + 0x2264) + 0x44))();
    if (cVar1 == '\0') {
      (**(code **)(*(int *)(param_1 + 0x2264) + 0x70))(0);
    }
    else {
      (**(code **)(*(int *)(param_1 + 0x2264) + 0x70))(1);
    }
    cVar1 = (**(code **)(*(int *)(param_1 + 0x3390) + 0x44))();
    if (cVar1 == '\0') {
      (**(code **)(*(int *)(param_1 + 0x3390) + 0x70))(0);
    }
    else {
      (**(code **)(*(int *)(param_1 + 0x3390) + 0x70))(1);
    }
    cVar1 = (**(code **)(*(int *)(param_1 + 0x44bc) + 0x44))();
    if (cVar1 == '\0') {
      (**(code **)(*(int *)(param_1 + 0x44bc) + 0x70))(0);
    }
    else {
      (**(code **)(*(int *)(param_1 + 0x44bc) + 0x70))(1);
    }
    cVar1 = (**(code **)(*(int *)(param_1 + 0x55e8) + 0x44))();
    if (cVar1 == '\0') {
      (**(code **)(*(int *)(param_1 + 0x55e8) + 0x70))(0);
    }
    else {
      (**(code **)(*(int *)(param_1 + 0x55e8) + 0x70))(1);
    }
    cVar1 = (**(code **)(*(int *)(param_1 + 0x6714) + 0x44))();
    if (cVar1 == '\0') {
      (**(code **)(*(int *)(param_1 + 0x6714) + 0x70))(0);
    }
    else {
      (**(code **)(*(int *)(param_1 + 0x6714) + 0x70))(1);
    }
  }
  else {
    bVar2 = FUN_10002750((void *)(param_1 + 8),0x1c2);
    if (CONCAT31(extraout_var,bVar2) != 0) {
      GAME::ChangeState(*(GAME **)(param_1 + 0x7840),2);
    }
  }
  return;
}



void __fastcall FUN_10001a5a(int param_1)

{
  char cVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  
  cVar1 = (**(code **)(*(int *)(param_1 + 0x1138) + 0x44))();
  if (cVar1 == '\0') {
    cVar1 = (**(code **)(*(int *)(param_1 + 0x2264) + 0x44))();
    if (cVar1 == '\0') {
      cVar1 = (**(code **)(*(int *)(param_1 + 0x3390) + 0x44))();
      if (cVar1 == '\0') {
        cVar1 = (**(code **)(*(int *)(param_1 + 0x44bc) + 0x44))();
        if (cVar1 == '\0') {
          cVar1 = (**(code **)(*(int *)(param_1 + 0x6714) + 0x44))();
          if (cVar1 == '\0') {
            cVar1 = (**(code **)(*(int *)(param_1 + 0x55e8) + 0x44))();
            if (cVar1 != '\0') {
              (**(code **)(**(int **)(param_1 + 0x7840) + 0x5c))();
            }
          }
          else {
            GAME::ChangeState(*(GAME **)(param_1 + 0x7840),3);
          }
        }
        else {
          uVar4 = 300;
          iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x1138));
          iVar3 = FUN_10002830(param_1 + 0x1138);
          (**(code **)(*(int *)(param_1 + 0x1138) + 0x6c))(-iVar3,iVar2,uVar4);
          uVar4 = 300;
          iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x2264));
          iVar3 = FUN_10002830(param_1 + 0x2264);
          (**(code **)(*(int *)(param_1 + 0x2264) + 0x6c))(iVar3 + 0x280,iVar2,uVar4);
          uVar4 = 300;
          iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x3390));
          iVar3 = FUN_10002830(param_1 + 0x3390);
          (**(code **)(*(int *)(param_1 + 0x3390) + 0x6c))(-iVar3,iVar2,uVar4);
          uVar4 = 300;
          iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x44bc));
          iVar3 = FUN_10002830(param_1 + 0x44bc);
          (**(code **)(*(int *)(param_1 + 0x44bc) + 0x6c))(iVar3 + 0x280,iVar2,uVar4);
          uVar4 = 300;
          iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x55e8));
          iVar3 = FUN_10002830(param_1 + 0x55e8);
          (**(code **)(*(int *)(param_1 + 0x55e8) + 0x6c))(-iVar3,iVar2,uVar4);
          uVar4 = 300;
          iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x6714));
          iVar3 = FUN_10002830(param_1 + 0x6714);
          (**(code **)(*(int *)(param_1 + 0x6714) + 0x6c))(iVar3 + 0x280,iVar2,uVar4);
          uVar4 = 300;
          iVar2 = FUN_10002850(param_1 + 0xc);
          iVar2 = -iVar2;
          iVar3 = FUN_10002830(param_1 + 0xc);
          (**(code **)(*(int *)(param_1 + 0xc) + 0x6c))(0x280U - iVar3 >> 1,iVar2,uVar4);
          *(undefined4 *)(param_1 + 4) = 3;
          (**(code **)(**(int **)(param_1 + 0x7840) + 0x50))(3);
          FUN_10002730((DWORD *)(param_1 + 8));
        }
      }
      else {
        uVar4 = 300;
        iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x1138));
        iVar3 = FUN_10002830(param_1 + 0x1138);
        (**(code **)(*(int *)(param_1 + 0x1138) + 0x6c))(-iVar3,iVar2,uVar4);
        uVar4 = 300;
        iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x2264));
        iVar3 = FUN_10002830(param_1 + 0x2264);
        (**(code **)(*(int *)(param_1 + 0x2264) + 0x6c))(iVar3 + 0x280,iVar2,uVar4);
        uVar4 = 300;
        iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x3390));
        iVar3 = FUN_10002830(param_1 + 0x3390);
        (**(code **)(*(int *)(param_1 + 0x3390) + 0x6c))(-iVar3,iVar2,uVar4);
        uVar4 = 300;
        iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x44bc));
        iVar3 = FUN_10002830(param_1 + 0x44bc);
        (**(code **)(*(int *)(param_1 + 0x44bc) + 0x6c))(iVar3 + 0x280,iVar2,uVar4);
        uVar4 = 300;
        iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x55e8));
        iVar3 = FUN_10002830(param_1 + 0x55e8);
        (**(code **)(*(int *)(param_1 + 0x55e8) + 0x6c))(-iVar3,iVar2,uVar4);
        uVar4 = 300;
        iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x6714));
        iVar3 = FUN_10002830(param_1 + 0x6714);
        (**(code **)(*(int *)(param_1 + 0x6714) + 0x6c))(iVar3 + 0x280,iVar2,uVar4);
        uVar4 = 300;
        iVar2 = FUN_10002850(param_1 + 0xc);
        iVar2 = -iVar2;
        iVar3 = FUN_10002830(param_1 + 0xc);
        (**(code **)(*(int *)(param_1 + 0xc) + 0x6c))(0x280U - iVar3 >> 1,iVar2,uVar4);
        *(undefined4 *)(param_1 + 4) = 2;
        (**(code **)(**(int **)(param_1 + 0x7840) + 0x50))(2);
        FUN_10002730((DWORD *)(param_1 + 8));
      }
    }
    else {
      uVar4 = 300;
      iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x1138));
      iVar3 = FUN_10002830(param_1 + 0x1138);
      (**(code **)(*(int *)(param_1 + 0x1138) + 0x6c))(-iVar3,iVar2,uVar4);
      uVar4 = 300;
      iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x2264));
      iVar3 = FUN_10002830(param_1 + 0x2264);
      (**(code **)(*(int *)(param_1 + 0x2264) + 0x6c))(iVar3 + 0x280,iVar2,uVar4);
      uVar4 = 300;
      iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x3390));
      iVar3 = FUN_10002830(param_1 + 0x3390);
      (**(code **)(*(int *)(param_1 + 0x3390) + 0x6c))(-iVar3,iVar2,uVar4);
      uVar4 = 300;
      iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x44bc));
      iVar3 = FUN_10002830(param_1 + 0x44bc);
      (**(code **)(*(int *)(param_1 + 0x44bc) + 0x6c))(iVar3 + 0x280,iVar2,uVar4);
      uVar4 = 300;
      iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x55e8));
      iVar3 = FUN_10002830(param_1 + 0x55e8);
      (**(code **)(*(int *)(param_1 + 0x55e8) + 0x6c))(-iVar3,iVar2,uVar4);
      uVar4 = 300;
      iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x6714));
      iVar3 = FUN_10002830(param_1 + 0x6714);
      (**(code **)(*(int *)(param_1 + 0x6714) + 0x6c))(iVar3 + 0x280,iVar2,uVar4);
      uVar4 = 300;
      iVar2 = FUN_10002850(param_1 + 0xc);
      iVar2 = -iVar2;
      iVar3 = FUN_10002830(param_1 + 0xc);
      (**(code **)(*(int *)(param_1 + 0xc) + 0x6c))(0x280U - iVar3 >> 1,iVar2,uVar4);
      *(undefined4 *)(param_1 + 4) = 1;
      (**(code **)(**(int **)(param_1 + 0x7840) + 0x50))(1);
      FUN_10002730((DWORD *)(param_1 + 8));
    }
  }
  else {
    uVar4 = 300;
    iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x1138));
    iVar3 = FUN_10002830(param_1 + 0x1138);
    (**(code **)(*(int *)(param_1 + 0x1138) + 0x6c))(-iVar3,iVar2,uVar4);
    uVar4 = 300;
    iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x2264));
    iVar3 = FUN_10002830(param_1 + 0x2264);
    (**(code **)(*(int *)(param_1 + 0x2264) + 0x6c))(iVar3 + 0x280,iVar2,uVar4);
    uVar4 = 300;
    iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x3390));
    iVar3 = FUN_10002830(param_1 + 0x3390);
    (**(code **)(*(int *)(param_1 + 0x3390) + 0x6c))(-iVar3,iVar2,uVar4);
    uVar4 = 300;
    iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x44bc));
    iVar3 = FUN_10002830(param_1 + 0x44bc);
    (**(code **)(*(int *)(param_1 + 0x44bc) + 0x6c))(iVar3 + 0x280,iVar2,uVar4);
    uVar4 = 300;
    iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x55e8));
    iVar3 = FUN_10002830(param_1 + 0x55e8);
    (**(code **)(*(int *)(param_1 + 0x55e8) + 0x6c))(-iVar3,iVar2,uVar4);
    uVar4 = 300;
    iVar2 = OVERLAY::GetYPos((OVERLAY *)(param_1 + 0x6714));
    iVar3 = FUN_10002830(param_1 + 0x6714);
    (**(code **)(*(int *)(param_1 + 0x6714) + 0x6c))(iVar3 + 0x280,iVar2,uVar4);
    uVar4 = 300;
    iVar2 = FUN_10002850(param_1 + 0xc);
    iVar2 = -iVar2;
    iVar3 = FUN_10002830(param_1 + 0xc);
    (**(code **)(*(int *)(param_1 + 0xc) + 0x6c))(0x280U - iVar3 >> 1,iVar2,uVar4);
    *(undefined4 *)(param_1 + 4) = 0;
    (**(code **)(**(int **)(param_1 + 0x7840) + 0x50))(0);
    FUN_10002730((DWORD *)(param_1 + 8));
  }
  return;
}



void __fastcall FUN_100022a4(int param_1)

{
  (**(code **)(*(int *)(param_1 + 0xc) + 0x20))();
  (**(code **)(*(int *)(param_1 + 0x1138) + 0x20))();
  (**(code **)(*(int *)(param_1 + 0x2264) + 0x20))();
  (**(code **)(*(int *)(param_1 + 0x3390) + 0x20))();
  (**(code **)(*(int *)(param_1 + 0x44bc) + 0x20))();
  (**(code **)(*(int *)(param_1 + 0x55e8) + 0x20))();
  (**(code **)(*(int *)(param_1 + 0x6714) + 0x20))();
  CMidi::Stop((CMidi *)(param_1 + 0x7844));
  return;
}



void __fastcall FUN_1000234b(int param_1)

{
  FUN_10002360(param_1);
  return;
}



void __fastcall FUN_10002360(int param_1)

{
  undefined4 *puVar1;
  char *pcVar2;
  uint extraout_ECX;
  uint extraout_ECX_00;
  CString *pCVar3;
  uint uVar4;
  int iVar5;
  HINSTANCE__ *pHVar6;
  undefined1 uVar7;
  CString local_20 [4];
  undefined1 *local_1c;
  CString local_18 [4];
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_10002d7c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  GKERNEL::NewSpriteBackground();
  uVar7 = 0;
  pHVar6 = (HINSTANCE__ *)0x0;
  iVar5 = 0;
  local_14 = &stack0xffffffac;
  uVar4 = extraout_ECX;
  CString::CString((CString *)&stack0xffffffac,s_SKILL_BMP_100040ac);
  pCVar3 = local_18;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x7840) + 0x54))();
  local_8 = 0;
  pcVar2 = (char *)FUN_10002700(puVar1);
  GKTOOLS::CopyDIBToBack(pcVar2,(uint)pCVar3,uVar4,iVar5,pHVar6,(bool)uVar7);
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  GKERNEL::Flip();
  uVar7 = 0;
  pHVar6 = (HINSTANCE__ *)0x0;
  iVar5 = 0;
  local_1c = &stack0xffffffa4;
  uVar4 = extraout_ECX_00;
  CString::CString((CString *)&stack0xffffffa4,s_SKILL_BMP_100040b8);
  pCVar3 = local_20;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x7840) + 0x54))();
  local_8 = 1;
  pcVar2 = (char *)FUN_10002700(puVar1);
  GKTOOLS::CopyDIBToBack(pcVar2,(uint)pCVar3,uVar4,iVar5,pHVar6,(bool)uVar7);
  local_8 = 0xffffffff;
  CString::~CString(local_20);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_10002470(void *this,undefined4 param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_10002e06;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_100026c0((undefined4 *)this);
  local_8 = 0;
  *(undefined4 *)((int)this + 4) = 4;
  FUN_10002710((DWORD *)((int)this + 8));
  SPRITE::SPRITE((SPRITE *)((int)this + 0xc));
  local_8._0_1_ = 1;
  SPRITE::SPRITE((SPRITE *)((int)this + 0x1138));
  local_8._0_1_ = 2;
  SPRITE::SPRITE((SPRITE *)((int)this + 0x2264));
  local_8._0_1_ = 3;
  SPRITE::SPRITE((SPRITE *)((int)this + 0x3390));
  local_8._0_1_ = 4;
  SPRITE::SPRITE((SPRITE *)((int)this + 0x44bc));
  local_8._0_1_ = 5;
  SPRITE::SPRITE((SPRITE *)((int)this + 0x55e8));
  local_8._0_1_ = 6;
  SPRITE::SPRITE((SPRITE *)((int)this + 0x6714));
  local_8 = CONCAT31(local_8._1_3_,7);
  *(undefined4 *)((int)this + 0x7840) = param_1;
  CMidi::CMidi((CMidi *)((int)this + 0x7844));
  *(undefined ***)this = &PTR_FUN_100030d8;
  ExceptionList = local_10;
  return this;
}



void FUN_10002570(undefined4 *param_1,undefined4 *param_2)

{
  *param_1 = 0xd3;
  *param_2 = 0x11;
  return;
}



undefined1 FUN_10002590(void)

{
  return 1;
}



void * __thiscall FUN_100025a0(void *this,uint param_1)

{
  FUN_100025d0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_100025d0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &this_10002e96;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_FUN_100030d8;
  local_8 = 8;
  CMidi::UnInit((CMidi *)(param_1 + 0x1e11));
  local_8._0_1_ = 7;
  CMidi::~CMidi((CMidi *)(param_1 + 0x1e11));
  local_8._0_1_ = 6;
  SPRITE::~SPRITE((SPRITE *)(param_1 + 0x19c5));
  local_8._0_1_ = 5;
  SPRITE::~SPRITE((SPRITE *)(param_1 + 0x157a));
  local_8._0_1_ = 4;
  SPRITE::~SPRITE((SPRITE *)(param_1 + 0x112f));
  local_8._0_1_ = 3;
  SPRITE::~SPRITE((SPRITE *)(param_1 + 0xce4));
  local_8._0_1_ = 2;
  SPRITE::~SPRITE((SPRITE *)(param_1 + 0x899));
  local_8._0_1_ = 1;
  SPRITE::~SPRITE((SPRITE *)(param_1 + 0x44e));
  local_8 = (uint)local_8._1_3_ << 8;
  SPRITE::~SPRITE((SPRITE *)(param_1 + 3));
  local_8 = 0xffffffff;
  FUN_100027e0(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_100026c0(undefined4 *param_1)

{
  FUN_100026e0(param_1);
  *param_1 = &PTR_FUN_100030fc;
  return param_1;
}



undefined4 * __fastcall FUN_100026e0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_10003120;
  return param_1;
}



undefined4 __fastcall FUN_10002700(undefined4 *param_1)

{
  return *param_1;
}



DWORD * __fastcall FUN_10002710(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
  return param_1;
}



void __fastcall FUN_10002730(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
  return;
}



bool __thiscall FUN_10002750(void *this,uint param_1)

{
  DWORD DVar1;
  bool bVar2;
  
  DVar1 = GetTickCount();
                    // WARNING: Load size is inaccurate
  bVar2 = param_1 <= DVar1 - *this;
  if (bVar2) {
    *(DWORD *)this = DVar1;
  }
  return bVar2;
}



void * __thiscall FUN_10002790(void *this,uint param_1)

{
  FUN_100027c0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_100027c0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_10003120;
  return;
}



void __fastcall FUN_100027e0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_100030fc;
  FUN_100027c0(param_1);
  return;
}



void * __thiscall FUN_10002800(void *this,uint param_1)

{
  FUN_100027e0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



undefined4 __fastcall FUN_10002830(int param_1)

{
  return *(undefined4 *)(param_1 + 0xac);
}



undefined4 __fastcall FUN_10002850(int param_1)

{
  return *(undefined4 *)(param_1 + 0xb0);
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002864. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000286a. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void __thiscall CString::~CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x10002870. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CString(this);
  return;
}



void __thiscall CString::CString(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002876. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



void * __thiscall FUN_100028ae(void *this,byte param_1)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)this);
  if ((param_1 & 1) != 0) {
    CNoTrackObject::operator_delete(this);
  }
  return this;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x10002c96. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



int FUN_10002929(HINSTANCE__ *param_1,int param_2)

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
      pAVar5 = AfxSetModuleState((AFX_MODULE_STATE *)&this_10004150);
      p_Var3 = AfxGetThreadState();
      *(AFX_MODULE_STATE **)(p_Var3 + 8) = pAVar5;
      pAVar5 = AfxGetModuleState();
      if (*(int **)(pAVar5 + 4) != (int *)0x0) {
        (**(code **)(**(int **)(pAVar5 + 4) + 0x70))();
      }
      AfxLockTempMaps();
      AfxUnlockTempMaps(-1);
      AfxWinTerm();
      AfxTermExtensionModule((AFX_EXTENSION_MODULE *)&param_1_100051e0,1);
    }
    else if (param_2 == 3) {
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
                ((AFX_MAINTAIN_STATE2 *)&local_c,(AFX_MODULE_STATE *)&this_10004150);
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
  iVar4 = AfxWinInit(param_1,(HINSTANCE__ *)0x0,(char *)&param_3_10003144,0);
  if (iVar4 != 0) {
    pAVar5 = AfxGetModuleState();
    piVar2 = *(int **)(pAVar5 + 4);
    if ((piVar2 == (int *)0x0) || (iVar4 = (**(code **)(*piVar2 + 0x58))(), iVar4 != 0)) {
      *(undefined4 *)(p_Var3 + 8) = uVar1;
      AfxInitExtensionModule((AFX_EXTENSION_MODULE *)&param_1_100051e0,param_1);
      this = (CDynLinkLibrary *)operator_new(0x40);
      if (this != (CDynLinkLibrary *)0x0) {
        CDynLinkLibrary::CDynLinkLibrary(this,(AFX_EXTENSION_MODULE *)&param_1_100051e0,0);
      }
      param_2 = 1;
      goto LAB_100029b5;
    }
    (**(code **)(*piVar2 + 0x70))();
  }
  AfxWinTerm();
LAB_100029b5:
  *(undefined4 *)(p_Var3 + 8) = uVar1;
  p_Var3 = AfxGetThreadState();
  AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var3 + 8));
  return param_2;
}



undefined4 FUN_10002a50(undefined4 param_1,int param_2)

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
    pAVar2 = AfxSetModuleState((AFX_MODULE_STATE *)&this_10004150);
    *(AFX_MODULE_STATE **)(p_Var1 + 8) = pAVar2;
  }
  else if (param_2 == 0) {
    p_Var1 = AfxGetThreadState();
    AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var1 + 8));
  }
  return 1;
}



void __fastcall FUN_10002aa1(undefined4 *param_1)

{
  *(undefined4 *)(param_1[1] + 4) = *param_1;
  return;
}



void __CxxFrameHandler(void)

{
                    // WARNING: Could not recover jumptable at 0x10002aaa. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10002ab6(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 *_Memory;
  undefined4 *puVar2;
  
  if (param_2 == 0) {
    if (0 < DAT_100051fc) {
      DAT_100051fc = DAT_100051fc + -1;
      goto LAB_10002acc;
    }
LAB_10002af4:
    uVar1 = 0;
  }
  else {
LAB_10002acc:
    _DAT_10005200 = *(undefined4 *)_adjust_fdiv_exref;
    if (param_2 == 1) {
      DAT_10005208 = (undefined4 *)malloc(0x80);
      if (DAT_10005208 == (undefined4 *)0x0) goto LAB_10002af4;
      *DAT_10005208 = 0;
      DAT_10005204 = DAT_10005208;
      initterm(&DAT_10004000,&DAT_10004008);
      DAT_100051fc = DAT_100051fc + 1;
    }
    else if ((param_2 == 0) &&
            (_Memory = DAT_10005208, puVar2 = DAT_10005204, DAT_10005208 != (undefined4 *)0x0)) {
      while (puVar2 = puVar2 + -1, _Memory <= puVar2) {
        if ((code *)*puVar2 != (code *)0x0) {
          (*(code *)*puVar2)();
          _Memory = DAT_10005208;
        }
      }
      free(_Memory);
      DAT_10005208 = (undefined4 *)0x0;
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
  iVar2 = DAT_100051fc;
  if (param_2 != 0) {
    if ((param_2 != 1) && (param_2 != 2)) goto LAB_10002ba9;
    if ((PTR_FUN_100040c4 != (undefined *)0x0) &&
       (iVar2 = (*(code *)PTR_FUN_100040c4)(param_1,param_2,param_3), iVar2 == 0)) {
      return 0;
    }
    iVar2 = FUN_10002ab6(param_1,param_2);
  }
  if (iVar2 == 0) {
    return 0;
  }
LAB_10002ba9:
  iVar2 = FUN_10002929(param_1,param_2);
  if (param_2 == 1) {
    if (iVar2 != 0) {
      return iVar2;
    }
    FUN_10002ab6(param_1,0);
  }
  if ((param_2 != 0) && (param_2 != 3)) {
    return iVar2;
  }
  iVar3 = FUN_10002ab6(param_1,param_2);
  param_2 = iVar2;
  if (iVar3 == 0) {
    param_2 = 0;
  }
  if (param_2 != 0) {
    if (PTR_FUN_100040c4 != (undefined *)0x0) {
      iVar2 = (*(code *)PTR_FUN_100040c4)(param_1,iVar1,param_3);
      return iVar2;
    }
    return param_2;
  }
  return 0;
}



void * __thiscall FUN_10002bfe(void *this,byte param_1)

{
  type_info::~type_info((type_info *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __cdecl initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x10002c78. Too many branches
                    // WARNING: Treating indirect jump as call
  initterm();
  return;
}



void __thiscall type_info::~type_info(type_info *this)

{
                    // WARNING: Could not recover jumptable at 0x10002c7e. Too many branches
                    // WARNING: Treating indirect jump as call
  ~type_info(this);
  return;
}



void CNoTrackObject::operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002c90. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x10002c96. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



void __thiscall
AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(AFX_MAINTAIN_STATE2 *this,AFX_MODULE_STATE *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002ca2. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MAINTAIN_STATE2(this,param_1);
  return;
}



void AfxTermThread(HINSTANCE__ *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002ca8. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermThread(param_1);
  return;
}



void AfxTermExtensionModule(AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10002cae. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermExtensionModule(param_1,param_2);
  return;
}



int AfxUnlockTempMaps(int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002cb4. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxUnlockTempMaps(param_1);
  return iVar1;
}



void AfxLockTempMaps(void)

{
                    // WARNING: Could not recover jumptable at 0x10002cba. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxLockTempMaps();
  return;
}



AFX_MODULE_STATE * AfxSetModuleState(AFX_MODULE_STATE *param_1)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002cc0. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxSetModuleState(param_1);
  return pAVar1;
}



void __thiscall
CDynLinkLibrary::CDynLinkLibrary(CDynLinkLibrary *this,AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10002cc6. Too many branches
                    // WARNING: Treating indirect jump as call
  CDynLinkLibrary(this,param_1,param_2);
  return;
}



int AfxInitExtensionModule(AFX_EXTENSION_MODULE *param_1,HINSTANCE__ *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002ccc. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxInitExtensionModule(param_1,param_2);
  return iVar1;
}



void AfxWinTerm(void)

{
                    // WARNING: Could not recover jumptable at 0x10002cd2. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxWinTerm();
  return;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002cd8. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



int AfxWinInit(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002cde. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinInit(param_1,param_2,param_3,param_4);
  return iVar1;
}



_AFX_THREAD_STATE * AfxGetThreadState(void)

{
  _AFX_THREAD_STATE *p_Var1;
  
                    // WARNING: Could not recover jumptable at 0x10002ce4. Too many branches
                    // WARNING: Treating indirect jump as call
  p_Var1 = AfxGetThreadState();
  return p_Var1;
}



void AfxCoreInitModule(void)

{
                    // WARNING: Could not recover jumptable at 0x10002cea. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxCoreInitModule();
  return;
}



void Unwind_10002cf0(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x14));
  return;
}



void Unwind_10002d05(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_10002d0e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_10002d17(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_10002d20(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_10002d29(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_10002d32(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_10002d3b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x44));
  return;
}



void Unwind_10002d44(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x4c));
  return;
}



void Unwind_10002d57(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_10002d6a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_10002d73(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_10002d90(void)

{
  int unaff_EBP;
  
  FUN_100027e0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10002d99(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0xc));
  return;
}



void Unwind_10002da6(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x1138));
  return;
}



void Unwind_10002db6(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x2264));
  return;
}



void Unwind_10002dc6(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x3390));
  return;
}



void Unwind_10002dd6(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x44bc));
  return;
}



void Unwind_10002de6(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x55e8));
  return;
}



void Unwind_10002df6(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x6714));
  return;
}



void Unwind_10002e10(void)

{
  int unaff_EBP;
  
  FUN_100027e0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10002e19(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0xc));
  return;
}



void Unwind_10002e26(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x1138));
  return;
}



void Unwind_10002e36(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x2264));
  return;
}



void Unwind_10002e46(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x3390));
  return;
}



void Unwind_10002e56(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x44bc));
  return;
}



void Unwind_10002e66(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x55e8));
  return;
}



void Unwind_10002e76(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x6714));
  return;
}



void Unwind_10002e86(void)

{
  int unaff_EBP;
  
  CMidi::~CMidi((CMidi *)(*(int *)(unaff_EBP + -0x10) + 0x7844));
  return;
}



void Unwind_10002ea0(void)

{
  int unaff_EBP;
  
  FUN_10002aa1((undefined4 *)(unaff_EBP + -0x14));
  return;
}


