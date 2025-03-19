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
typedef unsigned long long    undefined8;
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

typedef struct CWave CWave, *PCWave;

struct CWave { // PlaceHolder Structure
};

typedef struct AFX_EXTENSION_MODULE AFX_EXTENSION_MODULE, *PAFX_EXTENSION_MODULE;

struct AFX_EXTENSION_MODULE { // PlaceHolder Structure
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

typedef struct GAME GAME, *PGAME;

struct GAME { // PlaceHolder Structure
};

typedef struct _AFX_THREAD_STATE _AFX_THREAD_STATE, *P_AFX_THREAD_STATE;

struct _AFX_THREAD_STATE { // PlaceHolder Structure
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef struct AFX_MAINTAIN_STATE2 AFX_MAINTAIN_STATE2, *PAFX_MAINTAIN_STATE2;

struct AFX_MAINTAIN_STATE2 { // PlaceHolder Structure
};

typedef struct BUTTON BUTTON, *PBUTTON;

struct BUTTON { // PlaceHolder Structure
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

typedef struct SELECT_SKILL1 SELECT_SKILL1, *PSELECT_SKILL1;

struct SELECT_SKILL1 { // PlaceHolder Structure
};

typedef struct SPRITE SPRITE, *PSPRITE;

struct SPRITE { // PlaceHolder Structure
};

typedef struct HWND__ HWND__, *PHWND__;

struct HWND__ { // PlaceHolder Structure
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
  puStack_c = &LAB_1000364b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  this = operator_new(0x5138);
  local_8 = 0;
  if (this == (void *)0x0) {
    local_1c = (SELECT_SKILL1 *)0x0;
  }
  else {
    local_1c = (SELECT_SKILL1 *)FUN_10002300(this,param_1);
  }
  ExceptionList = local_10;
  return local_1c;
}



void __fastcall FUN_1000106e(int param_1)

{
  undefined4 *puVar1;
  char *pcVar2;
  int iVar3;
  undefined4 uStack_324;
  undefined4 uStack_320;
  int iStack_31c;
  undefined4 uStack_2fc;
  undefined4 uStack_2f8;
  int iStack_2f4;
  undefined4 uStack_2d4;
  undefined4 uStack_2d0;
  undefined4 uStack_2cc;
  undefined4 uStack_2c8;
  CString aCStack_2c0 [4];
  undefined4 uStack_2bc;
  undefined4 uStack_2b8;
  undefined4 uStack_2b4;
  undefined4 uStack_2b0;
  undefined4 uStack_2ac;
  undefined4 uStack_2a8;
  undefined4 uStack_2a4;
  undefined4 uStack_2a0;
  undefined4 uStack_29c;
  undefined4 uStack_298;
  undefined4 uStack_294;
  undefined4 uStack_290;
  undefined4 uStack_28c;
  undefined4 uStack_288;
  CString aCStack_280 [4];
  undefined4 uStack_27c;
  CString aCStack_274 [4];
  undefined4 uStack_270;
  undefined4 uStack_26c;
  CString aCStack_264 [4];
  undefined4 uStack_260;
  CString aCStack_258 [4];
  undefined4 uStack_254;
  undefined4 uStack_250;
  CString aCStack_248 [4];
  undefined4 uStack_244;
  CString aCStack_23c [4];
  undefined4 uStack_238;
  undefined4 uStack_234;
  CString aCStack_22c [4];
  undefined4 uStack_228;
  CString aCStack_220 [4];
  undefined4 uStack_21c;
  undefined4 uStack_218;
  CString aCStack_210 [4];
  undefined4 uStack_20c;
  CString aCStack_204 [4];
  undefined4 uStack_200;
  undefined4 uStack_1fc;
  CString aCStack_1f4 [4];
  undefined4 uStack_1f0;
  CString CVar4;
  int iVar5;
  int iVar6;
  CString local_c0 [4];
  undefined1 *local_bc;
  CString local_b8 [4];
  undefined1 *local_b4;
  CString local_b0 [4];
  undefined1 *local_ac;
  CString local_a8 [4];
  undefined1 *local_a4;
  CString local_a0 [4];
  undefined1 *local_9c;
  CString local_98 [4];
  undefined1 *local_94;
  CString local_90 [4];
  undefined1 *local_8c;
  CString local_88 [4];
  undefined1 *local_84;
  CString local_80 [4];
  undefined1 *local_7c;
  CString local_78 [4];
  undefined1 *local_74;
  CString local_70 [4];
  undefined1 *local_6c;
  CString local_68 [4];
  undefined1 *local_64;
  CString local_60 [4];
  undefined1 *local_5c;
  CString local_58 [4];
  undefined1 *local_54;
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
  puStack_c = &LAB_10003733;
  local_10 = ExceptionList;
  iVar6 = 1;
  iVar5 = 1;
  local_14 = &stack0xfffffe1c;
  ExceptionList = &local_10;
  iVar3 = param_1;
  CString::CString((CString *)&stack0xfffffe1c,s_antennalight_bmp_10005020);
  CVar4 = SUB41(local_18,0);
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))();
  local_8 = 0;
  pcVar2 = (char *)FUN_10002590(puVar1);
  uStack_1f0 = 0x10001106;
  SPRITE::Init((SPRITE *)(param_1 + 0xc),pcVar2,(bool)CVar4,iVar3,iVar5,iVar6);
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  (**(code **)(*(int *)(param_1 + 0xc) + 0x2c))();
  (**(code **)(*(int *)(param_1 + 0xc) + 0x20))();
  local_1c = &stack0xfffffe18;
  uStack_1f0 = 0x10001158;
  CString::CString((CString *)&stack0xfffffe18,s_Training_on_bmp_10005034);
  uStack_1f0 = 0x1000117f;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))();
  local_8 = 1;
  uStack_1f0 = 0x100011a3;
  uStack_1f0 = FUN_10002590(puVar1);
  local_24 = aCStack_1f4;
  uStack_1fc = 0x100011b4;
  CString::CString(aCStack_1f4,s_Training_off_bmp_10005044);
  uStack_1fc = 0x100011db;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))();
  local_8._0_1_ = 2;
  uStack_1fc = 0x100011fc;
  uStack_1fc = FUN_10002590(puVar1);
  uStack_200 = 0x10001218;
  (**(code **)(*(int *)(param_1 + 0x1138) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,1);
  uStack_200 = 0x10001224;
  CString::~CString(local_28);
  local_8 = 0xffffffff;
  uStack_200 = 0x10001233;
  CString::~CString(local_20);
  uStack_200 = 0;
  local_2c = aCStack_204;
  uStack_20c = 0x10001245;
  CString::CString(aCStack_204,s_Recreation_on_bmp_10005058);
  uStack_20c = 0x1000126c;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))();
  local_8 = 3;
  uStack_20c = 0x10001290;
  uStack_20c = FUN_10002590(puVar1);
  local_34 = aCStack_210;
  uStack_218 = 0x100012a1;
  CString::CString(aCStack_210,s_Recreation_off_bmp_1000506c);
  uStack_218 = 0x100012c8;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))();
  local_8._0_1_ = 4;
  uStack_218 = 0x100012e9;
  uStack_218 = FUN_10002590(puVar1);
  uStack_21c = 0x10001305;
  (**(code **)(*(int *)(param_1 + 0x12b4) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,3);
  uStack_21c = 0x10001311;
  CString::~CString(local_38);
  local_8 = 0xffffffff;
  uStack_21c = 0x10001320;
  CString::~CString(local_30);
  uStack_21c = 0;
  local_3c = aCStack_220;
  uStack_228 = 0x10001332;
  CString::CString(aCStack_220,s_Engineering_on_bmp_10005080);
  uStack_228 = 0x10001359;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))();
  local_8 = 5;
  uStack_228 = 0x1000137d;
  uStack_228 = FUN_10002590(puVar1);
  local_44 = aCStack_22c;
  uStack_234 = 0x1000138e;
  CString::CString(aCStack_22c,s_Engineering_off_bmp_10005094);
  uStack_234 = 0x100013b5;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))();
  local_8._0_1_ = 6;
  uStack_234 = 0x100013d6;
  uStack_234 = FUN_10002590(puVar1);
  uStack_238 = 0x100013f2;
  (**(code **)(*(int *)(param_1 + 0x1430) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,5);
  uStack_238 = 0x100013fe;
  CString::~CString(local_48);
  local_8 = 0xffffffff;
  uStack_238 = 0x1000140d;
  CString::~CString(local_40);
  uStack_238 = 0;
  local_4c = aCStack_23c;
  uStack_244 = 0x1000141f;
  CString::CString(aCStack_23c,s_Intelligence_on_bmp_100050a8);
  uStack_244 = 0x10001446;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))();
  local_8 = 7;
  uStack_244 = 0x1000146a;
  uStack_244 = FUN_10002590(puVar1);
  local_54 = aCStack_248;
  uStack_250 = 0x1000147b;
  CString::CString(aCStack_248,s_Intelligence_off_bmp_100050bc);
  uStack_250 = 0x100014a2;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))();
  local_8._0_1_ = 8;
  uStack_250 = 0x100014c3;
  uStack_250 = FUN_10002590(puVar1);
  uStack_254 = 0x100014df;
  (**(code **)(*(int *)(param_1 + 0x15ac) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,7);
  uStack_254 = 0x100014eb;
  CString::~CString(local_58);
  local_8 = 0xffffffff;
  uStack_254 = 0x100014fa;
  CString::~CString(local_50);
  uStack_254 = 0;
  local_5c = aCStack_258;
  uStack_260 = 0x1000150c;
  CString::CString(aCStack_258,s_Quit_on_bmp_100050d4);
  uStack_260 = 0x10001533;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))();
  local_8 = 9;
  uStack_260 = 0x10001557;
  uStack_260 = FUN_10002590(puVar1);
  local_64 = aCStack_264;
  uStack_26c = 0x10001568;
  CString::CString(aCStack_264,s_Quit_off_bmp_100050e0);
  uStack_26c = 0x1000158f;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))();
  local_8._0_1_ = 10;
  uStack_26c = 0x100015b0;
  uStack_26c = FUN_10002590(puVar1);
  uStack_270 = 0x100015cc;
  (**(code **)(*(int *)(param_1 + 0x1728) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,9);
  uStack_270 = 0x100015d8;
  CString::~CString(local_68);
  local_8 = 0xffffffff;
  uStack_270 = 0x100015e7;
  CString::~CString(local_60);
  uStack_270 = 0;
  local_6c = aCStack_274;
  uStack_27c = 0x100015f9;
  CString::CString(aCStack_274,s_Help_on_bmp_100050f0);
  uStack_27c = 0x10001620;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))();
  local_8 = 0xb;
  uStack_27c = 0x10001644;
  uStack_27c = FUN_10002590(puVar1);
  local_74 = aCStack_280;
  uStack_288 = 0x10001655;
  CString::CString(aCStack_280,s_Help_off_bmp_100050fc);
  uStack_288 = 0x1000167c;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))();
  local_8._0_1_ = 0xc;
  uStack_288 = 0x1000169d;
  uStack_288 = FUN_10002590(puVar1);
  uStack_28c = 0x100016b9;
  (**(code **)(*(int *)(param_1 + 0x18a4) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,0xb);
  uStack_28c = 0x100016c5;
  CString::~CString(local_78);
  local_8 = 0xffffffff;
  uStack_28c = 0x100016d4;
  CString::~CString(local_70);
  uStack_28c = 7;
  uStack_290 = 3;
  uStack_294 = 0x100016f3;
  (**(code **)(*(int *)(param_1 + 0x1138) + 0x2c))();
  uStack_294 = 0x3e;
  uStack_298 = 3;
  uStack_29c = 0x10001712;
  (**(code **)(*(int *)(param_1 + 0x12b4) + 0x2c))();
  uStack_29c = 0x75;
  uStack_2a0 = 3;
  uStack_2a4 = 0x10001731;
  (**(code **)(*(int *)(param_1 + 0x1430) + 0x2c))();
  uStack_2a4 = 0xac;
  uStack_2a8 = 3;
  uStack_2ac = 0x10001753;
  (**(code **)(*(int *)(param_1 + 0x15ac) + 0x2c))();
  uStack_2ac = 400;
  uStack_2b0 = 0x1d8;
  uStack_2b4 = 0x10001778;
  (**(code **)(*(int *)(param_1 + 0x1728) + 0x2c))();
  uStack_2b4 = 0x15b;
  uStack_2b8 = 0x1d8;
  uStack_2bc = 0x1000179d;
  (**(code **)(*(int *)(param_1 + 0x18a4) + 0x2c))();
  uStack_2bc = 1;
  local_7c = aCStack_2c0;
  uStack_2c8 = 0x100017af;
  CString::CString(aCStack_2c0,s_deepspace_text1_bmp_1000510c);
  uStack_2c8 = 0x100017d6;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))();
  local_8 = 0xd;
  uStack_2c8 = 0x100017fa;
  uStack_2c8 = FUN_10002590(puVar1);
  uStack_2cc = 0x10001816;
  (**(code **)(*(int *)(param_1 + 0x1a20) + 0x3c))();
  local_8 = 0xffffffff;
  uStack_2cc = 0x10001825;
  CString::~CString(local_80);
  uStack_2cc = 400;
  uStack_2d0 = 0x1e;
  uStack_2d4 = 0x10001847;
  (**(code **)(*(int *)(param_1 + 0x1a20) + 0x2c))();
  local_84 = (undefined1 *)&uStack_2d4;
  CString::CString((CString *)&uStack_2d4,s_space_text_10005120);
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x58))();
  local_8 = 0xe;
  pcVar2 = (char *)FUN_10002590(puVar1);
  FUN_10002af0((void *)(param_1 + 0x1a20),pcVar2);
  local_8 = 0xffffffff;
  CString::~CString(local_88);
  local_8c = &stack0xfffffd24;
  CString::CString((CString *)&stack0xfffffd24,s_deepspace_caret_bmp_1000512c);
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))();
  local_8 = 0xf;
  pcVar2 = (char *)FUN_10002590(puVar1);
  FUN_10002a60((void *)(param_1 + 0x1a20),pcVar2);
  local_8 = 0xffffffff;
  CString::~CString(local_90);
  iStack_2f4 = 0x10001970;
  FUN_10002aa0((void *)(param_1 + 0x1a20),1000,0,2000,0x96);
  local_94 = &stack0xfffffd18;
  CString::CString((CString *)&stack0xfffffd18,s_deepspace_text2_bmp_10005140);
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))();
  local_8 = 0x10;
  FUN_10002590(puVar1);
  iStack_2f4 = 0x100019ef;
  (**(code **)(*(int *)(param_1 + 0x2c7c) + 0x3c))();
  local_8 = 0xffffffff;
  iStack_2f4 = 0x10001a01;
  CString::~CString(local_98);
  iStack_2f4 = 0x10001a12;
  iStack_2f4 = FUN_100026a0(param_1 + 0x1a20);
  iStack_2f4 = iStack_2f4 + 400;
  uStack_2f8 = 0x1e;
  uStack_2fc = 0x10001a35;
  (**(code **)(*(int *)(param_1 + 0x2c7c) + 0x2c))();
  local_9c = (undefined1 *)&uStack_2fc;
  CString::CString((CString *)&uStack_2fc,s_space_text_10005154);
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x58))();
  local_8 = 0x11;
  pcVar2 = (char *)FUN_10002590(puVar1);
  FUN_10002af0((void *)(param_1 + 0x2c7c),pcVar2);
  local_8 = 0xffffffff;
  CString::~CString(local_a0);
  local_a4 = &stack0xfffffcfc;
  CString::CString((CString *)&stack0xfffffcfc,s_deepspace_caret_bmp_10005160);
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))();
  local_8 = 0x12;
  pcVar2 = (char *)FUN_10002590(puVar1);
  FUN_10002a60((void *)(param_1 + 0x2c7c),pcVar2);
  local_8 = 0xffffffff;
  CString::~CString(local_a8);
  iStack_31c = 0x10001b64;
  FUN_10002aa0((void *)(param_1 + 0x2c7c),900,2000,0x76c,0x96);
  local_ac = &stack0xfffffcf0;
  CString::CString((CString *)&stack0xfffffcf0,s_deepspace_text3_bmp_10005174);
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))();
  local_8 = 0x13;
  FUN_10002590(puVar1);
  iStack_31c = 0x10001be3;
  (**(code **)(*(int *)(param_1 + 0x3ed8) + 0x3c))();
  local_8 = 0xffffffff;
  iStack_31c = 0x10001bf5;
  CString::~CString(local_b0);
  iStack_31c = 0x10001c06;
  iVar3 = FUN_100026a0(param_1 + 0x2c7c);
  iStack_31c = 0x10001c19;
  iStack_31c = FUN_100026a0(param_1 + 0x1a20);
  iStack_31c = iVar3 + 400 + iStack_31c;
  uStack_320 = 0x1e;
  uStack_324 = 0x10001c3e;
  (**(code **)(*(int *)(param_1 + 0x3ed8) + 0x2c))();
  local_b4 = (undefined1 *)&uStack_324;
  CString::CString((CString *)&uStack_324,s_space_text_10005188);
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x58))();
  local_8 = 0x14;
  pcVar2 = (char *)FUN_10002590(puVar1);
  FUN_10002af0((void *)(param_1 + 0x3ed8),pcVar2);
  local_8 = 0xffffffff;
  CString::~CString(local_b8);
  local_bc = &stack0xfffffcd4;
  CString::CString((CString *)&stack0xfffffcd4,s_deepspace_caret_bmp_10005194);
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))(local_c0);
  local_8 = 0x15;
  pcVar2 = (char *)FUN_10002590(puVar1);
  FUN_10002a60((void *)(param_1 + 0x3ed8),pcVar2);
  local_8 = 0xffffffff;
  CString::~CString(local_c0);
  FUN_10002aa0((void *)(param_1 + 0x3ed8),700,0xf3c,0x6a4,0x96);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10001d7c(int param_1)

{
  FUN_1000223a(param_1);
  *(undefined4 *)(param_1 + 4) = 4;
  FUN_100029c0(param_1 + 0x1a20);
  FUN_100029c0(param_1 + 0x2c7c);
  FUN_100029c0(param_1 + 0x3ed8);
  return;
}



void __fastcall FUN_10001dc3(int param_1)

{
  char cVar1;
  bool bVar2;
  undefined3 extraout_var;
  
  cVar1 = (**(code **)(*(int *)(param_1 + 0x1138) + 0x44))();
  if (cVar1 == '\0') {
    FUN_100026c0(param_1 + 0x1138);
  }
  else {
    FUN_100026e0(param_1 + 0x1138);
  }
  (**(code **)(*(int *)(param_1 + 0x1138) + 0x14))();
  cVar1 = (**(code **)(*(int *)(param_1 + 0x12b4) + 0x44))();
  if (cVar1 == '\0') {
    FUN_100026c0(param_1 + 0x12b4);
  }
  else {
    FUN_100026e0(param_1 + 0x12b4);
  }
  (**(code **)(*(int *)(param_1 + 0x12b4) + 0x14))();
  cVar1 = (**(code **)(*(int *)(param_1 + 0x1430) + 0x44))();
  if (cVar1 == '\0') {
    FUN_100026c0(param_1 + 0x1430);
  }
  else {
    FUN_100026e0(param_1 + 0x1430);
  }
  (**(code **)(*(int *)(param_1 + 0x1430) + 0x14))();
  cVar1 = (**(code **)(*(int *)(param_1 + 0x15ac) + 0x44))();
  if (cVar1 == '\0') {
    FUN_100026c0(param_1 + 0x15ac);
  }
  else {
    FUN_100026e0(param_1 + 0x15ac);
  }
  (**(code **)(*(int *)(param_1 + 0x15ac) + 0x14))();
  cVar1 = (**(code **)(*(int *)(param_1 + 0x1728) + 0x44))();
  if (cVar1 == '\0') {
    FUN_100026c0(param_1 + 0x1728);
  }
  else {
    FUN_100026e0(param_1 + 0x1728);
  }
  (**(code **)(*(int *)(param_1 + 0x1728) + 0x14))();
  cVar1 = (**(code **)(*(int *)(param_1 + 0x18a4) + 0x44))();
  if (cVar1 == '\0') {
    FUN_100026c0(param_1 + 0x18a4);
  }
  else {
    FUN_100026e0(param_1 + 0x18a4);
  }
  (**(code **)(*(int *)(param_1 + 0x18a4) + 0x14))();
  (**(code **)(*(int *)(param_1 + 0x1a20) + 0x14))();
  (**(code **)(*(int *)(param_1 + 0x2c7c) + 0x14))();
  (**(code **)(*(int *)(param_1 + 0x3ed8) + 0x14))();
  bVar2 = FUN_100025c0((void *)(param_1 + 8),2000);
  if (CONCAT31(extraout_var,bVar2) != 0) {
    cVar1 = (**(code **)(*(int *)(param_1 + 0xc) + 0x18))();
    if (cVar1 == '\0') {
      (**(code **)(*(int *)(param_1 + 0xc) + 0x1c))();
    }
    else {
      (**(code **)(*(int *)(param_1 + 0xc) + 0x20))();
    }
  }
  return;
}



void __fastcall FUN_1000203f(int param_1)

{
  char cVar1;
  
  cVar1 = (**(code **)(*(int *)(param_1 + 0x1138) + 0x44))();
  if (cVar1 == '\0') {
    cVar1 = (**(code **)(*(int *)(param_1 + 0x12b4) + 0x44))();
    if (cVar1 == '\0') {
      cVar1 = (**(code **)(*(int *)(param_1 + 0x1430) + 0x44))();
      if (cVar1 == '\0') {
        cVar1 = (**(code **)(*(int *)(param_1 + 0x15ac) + 0x44))();
        if (cVar1 == '\0') {
          cVar1 = (**(code **)(*(int *)(param_1 + 0x1728) + 0x44))();
          if (cVar1 == '\0') {
            cVar1 = (**(code **)(*(int *)(param_1 + 0x18a4) + 0x44))();
            if (cVar1 != '\0') {
              (**(code **)(**(int **)(param_1 + 0x5134) + 0x5c))();
            }
          }
          else {
            GAME::ChangeState(*(GAME **)(param_1 + 0x5134),3);
          }
        }
        else {
          (**(code **)(**(int **)(param_1 + 0x5134) + 0x50))(3);
          GAME::ChangeState(*(GAME **)(param_1 + 0x5134),2);
        }
      }
      else {
        (**(code **)(**(int **)(param_1 + 0x5134) + 0x50))(2);
        GAME::ChangeState(*(GAME **)(param_1 + 0x5134),2);
      }
    }
    else {
      (**(code **)(**(int **)(param_1 + 0x5134) + 0x50))(1);
      GAME::ChangeState(*(GAME **)(param_1 + 0x5134),2);
    }
  }
  else {
    (**(code **)(**(int **)(param_1 + 0x5134) + 0x50))(0);
    GAME::ChangeState(*(GAME **)(param_1 + 0x5134),2);
  }
  return;
}



void __fastcall FUN_100021e1(int param_1)

{
  (**(code **)(*(int *)(param_1 + 0xc) + 0x20))();
  FUN_10002a20(param_1 + 0x1a20);
  FUN_10002a20(param_1 + 0x2c7c);
  FUN_10002a20(param_1 + 0x3ed8);
  return;
}



void __fastcall FUN_10002225(int param_1)

{
  FUN_1000223a(param_1);
  return;
}



void __fastcall FUN_1000223a(int param_1)

{
  undefined4 *puVar1;
  char *pcVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  HINSTANCE__ *pHVar6;
  undefined1 uVar7;
  CString local_1c [4];
  undefined1 *local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10003746;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  GKERNEL::NewSpriteBackground();
  for (local_14 = 0; local_14 < 2; local_14 = local_14 + 1) {
    uVar7 = 1;
    pHVar6 = (HINSTANCE__ *)0x0;
    iVar5 = 0;
    uVar4 = 0;
    uVar3 = 0;
    local_18 = &stack0xffffffbc;
    CString::CString((CString *)&stack0xffffffbc,s_deepspace_BMP_100051a8);
    puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x5134) + 0x54))(local_1c);
    local_8 = 0;
    pcVar2 = (char *)FUN_10002590(puVar1);
    GKTOOLS::CopyDIBToBack(pcVar2,uVar3,uVar4,iVar5,pHVar6,(bool)uVar7);
    local_8 = 0xffffffff;
    CString::~CString(local_1c);
    GKERNEL::Flip();
  }
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_10002300(void *this,undefined4 param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_100037c0;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10002550((undefined4 *)this);
  local_8 = 0;
  *(undefined4 *)((int)this + 4) = 4;
  FUN_100025a0((DWORD *)((int)this + 8));
  SPRITE::SPRITE((SPRITE *)((int)this + 0xc));
  local_8._0_1_ = 1;
  FUN_10002730((OVERLAY *)((int)this + 0x1138));
  local_8._0_1_ = 2;
  FUN_10002730((OVERLAY *)((int)this + 0x12b4));
  local_8._0_1_ = 3;
  FUN_10002730((OVERLAY *)((int)this + 0x1430));
  local_8._0_1_ = 4;
  FUN_10002730((OVERLAY *)((int)this + 0x15ac));
  local_8._0_1_ = 5;
  FUN_10002730((OVERLAY *)((int)this + 0x1728));
  local_8._0_1_ = 6;
  FUN_10002730((OVERLAY *)((int)this + 0x18a4));
  local_8 = CONCAT31(local_8._1_3_,7);
  FUN_10003240((int)this + 0x1a20,0x125c,3,FUN_10002b60);
  *(undefined4 *)((int)this + 0x5134) = param_1;
  *(undefined ***)this = &PTR_FUN_10004118;
  ExceptionList = local_10;
  return this;
}



void FUN_10002410(undefined4 *param_1,undefined4 *param_2)

{
  *param_1 = 0x139;
  *param_2 = 0x11;
  return;
}



undefined1 FUN_10002430(void)

{
  return 1;
}



void * __thiscall FUN_10002440(void *this,uint param_1)

{
  FUN_10002470((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10002470(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_10003840;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_FUN_10004118;
  local_8 = 7;
  FUN_100032c2(param_1 + 0x688,0x125c,3,FUN_10002f90);
  local_8._0_1_ = 6;
  FUN_10002970(param_1 + 0x629);
  local_8._0_1_ = 5;
  FUN_10002970(param_1 + 0x5ca);
  local_8._0_1_ = 4;
  FUN_10002970(param_1 + 0x56b);
  local_8._0_1_ = 3;
  FUN_10002970(param_1 + 0x50c);
  local_8._0_1_ = 2;
  FUN_10002970(param_1 + 0x4ad);
  local_8._0_1_ = 1;
  FUN_10002970(param_1 + 0x44e);
  local_8 = (uint)local_8._1_3_ << 8;
  SPRITE::~SPRITE((SPRITE *)(param_1 + 3));
  local_8 = 0xffffffff;
  FUN_10002650(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_10002550(undefined4 *param_1)

{
  FUN_10002570(param_1);
  *param_1 = &PTR_FUN_1000413c;
  return param_1;
}



undefined4 * __fastcall FUN_10002570(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_10004160;
  return param_1;
}



undefined4 __fastcall FUN_10002590(undefined4 *param_1)

{
  return *param_1;
}



DWORD * __fastcall FUN_100025a0(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
  return param_1;
}



bool __thiscall FUN_100025c0(void *this,uint param_1)

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



void * __thiscall FUN_10002600(void *this,uint param_1)

{
  FUN_10002630((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10002630(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_10004160;
  return;
}



void __fastcall FUN_10002650(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1000413c;
  FUN_10002630(param_1);
  return;
}



void * __thiscall FUN_10002670(void *this,uint param_1)

{
  FUN_10002650((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



undefined4 __fastcall FUN_100026a0(int param_1)

{
  return *(undefined4 *)(param_1 + 0xb0);
}



void __fastcall FUN_100026c0(int param_1)

{
  *(undefined4 *)(param_1 + 0xd4) = 0;
  FUN_10002700(param_1);
  return;
}



void __fastcall FUN_100026e0(int param_1)

{
  *(undefined4 *)(param_1 + 0xd4) = 1;
  FUN_10002700(param_1);
  return;
}



void __fastcall FUN_10002700(int param_1)

{
  *(undefined4 *)(param_1 + 0x178) = 1;
  *(undefined4 *)(param_1 + 0x174) = 0;
  return;
}



OVERLAY * __fastcall FUN_10002730(OVERLAY *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_10003869;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  OVERLAY::OVERLAY(param_1);
  local_8 = 0;
  FUN_100025a0((DWORD *)(param_1 + 0xd0));
  DD_SURFACE::DD_SURFACE((DD_SURFACE *)(param_1 + 0xdc));
  local_8 = CONCAT31(local_8._1_3_,1);
  *(undefined ***)param_1 = &PTR_FUN_10004180;
  *(undefined ***)(param_1 + 8) = &PTR_FUN_1000417c;
  FUN_100026c0((int)param_1);
  ExceptionList = local_10;
  return param_1;
}



void FUN_100027b0(void)

{
  return;
}



void FUN_100027c0(void)

{
  return;
}



undefined1 __fastcall FUN_100027d0(int param_1)

{
  return *(undefined1 *)(param_1 + 0xcc);
}



void __fastcall FUN_100027f0(int param_1)

{
  *(undefined1 *)(param_1 + 0xcc) = 1;
  return;
}



void __fastcall FUN_10002810(int param_1)

{
  *(undefined1 *)(param_1 + 0xcc) = 0;
  return;
}



void __thiscall FUN_10002830(void *this,undefined4 *param_1)

{
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x2c))(*param_1,param_1[1]);
  return;
}



undefined1 __fastcall FUN_10002860(int param_1)

{
  return *(undefined1 *)(param_1 + 0xa0);
}



void * __thiscall FUN_10002880(void *this,uint param_1)

{
  FUN_10002970((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_100028b0(undefined4 *param_1)

{
  DD_SURFACE *local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_10003889;
  local_10 = ExceptionList;
  local_8 = 0;
  if (param_1 == (undefined4 *)0x0) {
    local_18 = (DD_SURFACE *)0x0;
  }
  else {
    local_18 = (DD_SURFACE *)(param_1 + 2);
  }
  ExceptionList = &local_10;
  DD_SURFACE::~DD_SURFACE(local_18);
  local_8 = 0xffffffff;
  FUN_10002920(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10002920(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_100041d0;
  return;
}



void * __thiscall FUN_10002940(void *this,uint param_1)

{
  FUN_10002920((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10002970(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_100038a9;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(param_1 + 0x37));
  local_8 = 0xffffffff;
  FUN_100028b0(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_100029c0(int param_1)

{
  FUN_10002a00((DWORD *)(param_1 + 0xd8));
  FUN_10002a00((DWORD *)(param_1 + 0xd0));
  *(undefined1 *)(param_1 + 0x1248) = 1;
  *(undefined1 *)(param_1 + 0x1249) = 0;
  return;
}



void __fastcall FUN_10002a00(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
  return;
}



void __fastcall FUN_10002a20(int param_1)

{
  FUN_10002810(param_1);
  (**(code **)(*(int *)(param_1 + 0x11c) + 0x20))();
  CWave::Stop((CWave *)(param_1 + 0xdc));
  return;
}



void __thiscall FUN_10002a60(void *this,char *param_1)

{
  SPRITE::Init((SPRITE *)((int)this + 0x11c),param_1,true,1,1,1);
  (**(code **)(*(int *)((int)this + 0x11c) + 0x20))();
  return;
}



void __thiscall
FUN_10002aa0(void *this,int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  if (param_1 != 0) {
    *(int *)((int)this + 0x124c) = param_1;
    *(undefined4 *)((int)this + 0x1250) = param_3;
    *(undefined4 *)((int)this + 0x1254) = param_2;
    *(undefined4 *)((int)this + 0x1258) = param_4;
  }
  return;
}



void __thiscall FUN_10002af0(void *this,char *param_1)

{
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_100038c9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(local_14,param_1);
  local_8 = 0;
  CWave::Create((CWave *)((int)this + 0xdc),local_14);
  local_8 = 0xffffffff;
  CString::~CString(local_14);
  ExceptionList = local_10;
  return;
}



OVERLAY * __fastcall FUN_10002b60(OVERLAY *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100038f9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  OVERLAY::OVERLAY(param_1);
  local_8 = 0;
  FUN_100025a0((DWORD *)(param_1 + 0xd0));
  FUN_100025a0((DWORD *)(param_1 + 0xd4));
  FUN_100025a0((DWORD *)(param_1 + 0xd8));
  CWave::CWave((CWave *)(param_1 + 0xdc));
  local_8 = CONCAT31(local_8._1_3_,1);
  SPRITE::SPRITE((SPRITE *)(param_1 + 0x11c));
  param_1[0x1248] = (OVERLAY)0x0;
  param_1[0x1249] = (OVERLAY)0x0;
  param_1[0x124a] = (OVERLAY)0x0;
  *(undefined4 *)(param_1 + 0x124c) = 0xffffffff;
  *(undefined4 *)(param_1 + 0x1250) = 0xffffffff;
  *(undefined ***)param_1 = &PTR_FUN_100041fc;
  *(undefined ***)(param_1 + 8) = &PTR_FUN_100041f8;
  ExceptionList = local_10;
  return param_1;
}



void __fastcall FUN_10002c40(int param_1)

{
  FUN_10002a20(param_1);
  return;
}



void __fastcall FUN_10002c60(OVERLAY *param_1)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  uint uVar3;
  int iVar4;
  undefined3 extraout_var_00;
  double local_14;
  uint local_8;
  
  if (param_1[0x1249] == (OVERLAY)0x0) {
    bVar1 = FUN_100025c0(param_1 + 0xd8,*(uint *)(param_1 + 0x1254));
    if (CONCAT31(extraout_var,bVar1) == 0) {
      return;
    }
    FUN_10002a00((DWORD *)(param_1 + 0xd0));
    param_1[0x1249] = (OVERLAY)0x1;
    CWave::Play((CWave *)(param_1 + 0xdc),0,0,1);
  }
  local_8 = FUN_10002f40((int)param_1);
  if (param_1[0x1248] != (OVERLAY)0x0) {
    uVar3 = FUN_10002f20((int *)(param_1 + 0xd0));
    local_14 = (double)uVar3 / (double)*(uint *)(param_1 + 0x124c);
    if (1.0 <= local_14) {
      param_1[0x1248] = (OVERLAY)0x0;
      local_14 = 1.0;
      CWave::Stop((CWave *)(param_1 + 0xdc));
    }
    local_8 = round((double)local_8 * local_14);
  }
  if (local_8 != 0) {
    OVERLAY::DrawToBack(param_1,0,0,local_8,0x32);
  }
  cVar2 = (**(code **)(*(int *)(param_1 + 0x11c) + 0x24))();
  if (cVar2 != '\0') {
    if (param_1[0x1248] == (OVERLAY)0x0) {
      bVar1 = FUN_10002ef0((char *)(param_1 + 0x124a),'\x01');
      if (bVar1) {
        FUN_10002a00((DWORD *)(param_1 + 0xd4));
      }
      uVar3 = FUN_10002f20((int *)(param_1 + 0xd0));
      if (uVar3 < *(uint *)(param_1 + 0x1250)) {
        bVar1 = FUN_100025c0(param_1 + 0xd4,*(uint *)(param_1 + 0x1258));
        if (CONCAT31(extraout_var_00,bVar1) != 0) {
          cVar2 = (**(code **)(*(int *)(param_1 + 0x11c) + 0x18))();
          if (cVar2 == '\0') {
            (**(code **)(*(int *)(param_1 + 0x11c) + 0x1c))();
          }
          else {
            (**(code **)(*(int *)(param_1 + 0x11c) + 0x20))();
          }
        }
      }
      else {
        (**(code **)(*(int *)(param_1 + 0x11c) + 0x20))();
      }
    }
    else {
      (**(code **)(*(int *)(param_1 + 0x11c) + 0x1c))();
      OVERLAY::GetYPos(param_1);
      iVar4 = OVERLAY::GetXPos(param_1);
      (**(code **)(*(int *)(param_1 + 0x11c) + 0x2c))(iVar4 + local_8);
    }
  }
  return;
}



bool __cdecl FUN_10002ef0(char *param_1,char param_2)

{
  char cVar1;
  
  cVar1 = *param_1;
  *param_1 = param_2;
  return cVar1 != param_2;
}



int __fastcall FUN_10002f20(int *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  return DVar1 - *param_1;
}



undefined4 __fastcall FUN_10002f40(int param_1)

{
  return *(undefined4 *)(param_1 + 0xac);
}



void * __thiscall FUN_10002f60(void *this,uint param_1)

{
  FUN_10002f90((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10002f90(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
  puStack_c = &LAB_10003929;
  local_10 = ExceptionList;
  local_8 = 1;
  ExceptionList = &local_10;
  SPRITE::~SPRITE((SPRITE *)(param_1 + 0x47));
  local_8 = local_8 & 0xffffff00;
  CWave::~CWave((CWave *)(param_1 + 0x37));
  local_8 = 0xffffffff;
  FUN_100028b0(param_1);
  ExceptionList = local_10;
  return;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002ff2. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002ff8. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void __thiscall CString::~CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x10002ffe. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CString(this);
  return;
}



void __thiscall CString::CString(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10003004. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



void * __thiscall FUN_1000303c(void *this,byte param_1)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)this);
  if ((param_1 & 1) != 0) {
    CNoTrackObject::operator_delete(this);
  }
  return this;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x100035e6. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



int FUN_100030b7(HINSTANCE__ *param_1,int param_2)

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
      pAVar5 = AfxSetModuleState((AFX_MODULE_STATE *)&param_1_10005250);
      p_Var3 = AfxGetThreadState();
      *(AFX_MODULE_STATE **)(p_Var3 + 8) = pAVar5;
      pAVar5 = AfxGetModuleState();
      if (*(int **)(pAVar5 + 4) != (int *)0x0) {
        (**(code **)(**(int **)(pAVar5 + 4) + 0x70))();
      }
      AfxLockTempMaps();
      AfxUnlockTempMaps(-1);
      AfxWinTerm();
      AfxTermExtensionModule((AFX_EXTENSION_MODULE *)&param_1_100062e0,1);
    }
    else if (param_2 == 3) {
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
                ((AFX_MAINTAIN_STATE2 *)&local_c,(AFX_MODULE_STATE *)&param_1_10005250);
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
  iVar4 = AfxWinInit(param_1,(HINSTANCE__ *)0x0,(char *)&param_3_10004258,0);
  if (iVar4 != 0) {
    pAVar5 = AfxGetModuleState();
    piVar2 = *(int **)(pAVar5 + 4);
    if ((piVar2 == (int *)0x0) || (iVar4 = (**(code **)(*piVar2 + 0x58))(), iVar4 != 0)) {
      *(undefined4 *)(p_Var3 + 8) = uVar1;
      AfxInitExtensionModule((AFX_EXTENSION_MODULE *)&param_1_100062e0,param_1);
      this = (CDynLinkLibrary *)operator_new(0x40);
      if (this != (CDynLinkLibrary *)0x0) {
        CDynLinkLibrary::CDynLinkLibrary(this,(AFX_EXTENSION_MODULE *)&param_1_100062e0,0);
      }
      param_2 = 1;
      goto LAB_10003143;
    }
    (**(code **)(*piVar2 + 0x70))();
  }
  AfxWinTerm();
LAB_10003143:
  *(undefined4 *)(p_Var3 + 8) = uVar1;
  p_Var3 = AfxGetThreadState();
  AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var3 + 8));
  return param_2;
}



undefined4 FUN_100031de(undefined4 param_1,int param_2)

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
    pAVar2 = AfxSetModuleState((AFX_MODULE_STATE *)&param_1_10005250);
    *(AFX_MODULE_STATE **)(p_Var1 + 8) = pAVar2;
  }
  else if (param_2 == 0) {
    p_Var1 = AfxGetThreadState();
    AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var1 + 8));
  }
  return 1;
}



void __fastcall FUN_1000322f(undefined4 *param_1)

{
  *(undefined4 *)(param_1[1] + 4) = *param_1;
  return;
}



void __CxxFrameHandler(void)

{
                    // WARNING: Could not recover jumptable at 0x10003238. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler();
  return;
}



void FUN_10003240(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  int local_20;
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_10004260;
  puStack_10 = &DAT_10003580;
  local_14 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_14;
  for (local_20 = 0; local_20 < param_3; local_20 = local_20 + 1) {
    (*(code *)param_4)();
  }
  local_8 = 0xffffffff;
  FUN_100032aa();
  ExceptionList = local_14;
  return;
}



void FUN_100032aa(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x20) == 0) {
    FUN_10003342(*(undefined4 *)(unaff_EBP + 8),*(undefined4 *)(unaff_EBP + 0xc),
                 *(int *)(unaff_EBP + -0x1c),*(undefined **)(unaff_EBP + 0x18));
  }
  return;
}



void FUN_100032c2(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_10004270;
  puStack_10 = &DAT_10003580;
  local_14 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_14;
  while( true ) {
    param_3 = param_3 + -1;
    if (param_3 < 0) break;
    (*(code *)param_4)();
  }
  local_8 = 0xffffffff;
  FUN_1000332a();
  ExceptionList = local_14;
  return;
}



void FUN_1000332a(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x1c) == 0) {
    FUN_10003342(*(undefined4 *)(unaff_EBP + 8),*(undefined4 *)(unaff_EBP + 0xc),
                 *(int *)(unaff_EBP + 0x10),*(undefined **)(unaff_EBP + 0x14));
  }
  return;
}



void FUN_10003342(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_10004280;
  puStack_10 = &DAT_10003580;
  local_14 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_14;
  while( true ) {
    param_3 = param_3 + -1;
    if (param_3 < 0) break;
    (*(code *)param_4)();
  }
  ExceptionList = local_14;
  return;
}



undefined4 __cdecl FUN_100033a0(undefined4 *param_1)

{
  if (*(int *)*param_1 != -0x1f928c9d) {
    return 0;
  }
                    // WARNING: Subroutine does not return
  terminate();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_100033bc(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 *_Memory;
  undefined4 *puVar2;
  
  if (param_2 == 0) {
    if (0 < DAT_100062fc) {
      DAT_100062fc = DAT_100062fc + -1;
      goto LAB_100033d2;
    }
LAB_100033fa:
    uVar1 = 0;
  }
  else {
LAB_100033d2:
    _DAT_10006300 = *(undefined4 *)_adjust_fdiv_exref;
    if (param_2 == 1) {
      DAT_10006308 = (undefined4 *)malloc(0x80);
      if (DAT_10006308 == (undefined4 *)0x0) goto LAB_100033fa;
      *DAT_10006308 = 0;
      DAT_10006304 = DAT_10006308;
      initterm(&DAT_10005000,&DAT_10005008);
      DAT_100062fc = DAT_100062fc + 1;
    }
    else if ((param_2 == 0) &&
            (_Memory = DAT_10006308, puVar2 = DAT_10006304, DAT_10006308 != (undefined4 *)0x0)) {
      while (puVar2 = puVar2 + -1, _Memory <= puVar2) {
        if ((code *)*puVar2 != (code *)0x0) {
          (*(code *)*puVar2)();
          _Memory = DAT_10006308;
        }
      }
      free(_Memory);
      DAT_10006308 = (undefined4 *)0x0;
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
  iVar2 = DAT_100062fc;
  if (param_2 != 0) {
    if ((param_2 != 1) && (param_2 != 2)) goto LAB_100034af;
    if ((PTR_FUN_100051b8 != (undefined *)0x0) &&
       (iVar2 = (*(code *)PTR_FUN_100051b8)(param_1,param_2,param_3), iVar2 == 0)) {
      return 0;
    }
    iVar2 = FUN_100033bc(param_1,param_2);
  }
  if (iVar2 == 0) {
    return 0;
  }
LAB_100034af:
  iVar2 = FUN_100030b7(param_1,param_2);
  if (param_2 == 1) {
    if (iVar2 != 0) {
      return iVar2;
    }
    FUN_100033bc(param_1,0);
  }
  if ((param_2 != 0) && (param_2 != 3)) {
    return iVar2;
  }
  iVar3 = FUN_100033bc(param_1,param_2);
  param_2 = iVar2;
  if (iVar3 == 0) {
    param_2 = 0;
  }
  if (param_2 != 0) {
    if (PTR_FUN_100051b8 != (undefined *)0x0) {
      iVar2 = (*(code *)PTR_FUN_100051b8)(param_1,iVar1,param_3);
      return iVar2;
    }
    return param_2;
  }
  return 0;
}



void * __thiscall FUN_10003504(void *this,byte param_1)

{
  type_info::~type_info((type_info *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __cdecl terminate(void)

{
                    // WARNING: Could not recover jumptable at 0x10003586. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  terminate();
  return;
}



void __cdecl initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x1000358c. Too many branches
                    // WARNING: Treating indirect jump as call
  initterm();
  return;
}



void __thiscall type_info::~type_info(type_info *this)

{
                    // WARNING: Could not recover jumptable at 0x10003592. Too many branches
                    // WARNING: Treating indirect jump as call
  ~type_info(this);
  return;
}



void CNoTrackObject::operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100035e0. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x100035e6. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



void __thiscall
AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(AFX_MAINTAIN_STATE2 *this,AFX_MODULE_STATE *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100035f2. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MAINTAIN_STATE2(this,param_1);
  return;
}



void AfxTermThread(HINSTANCE__ *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100035f8. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermThread(param_1);
  return;
}



void AfxTermExtensionModule(AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x100035fe. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermExtensionModule(param_1,param_2);
  return;
}



int AfxUnlockTempMaps(int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10003604. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxUnlockTempMaps(param_1);
  return iVar1;
}



void AfxLockTempMaps(void)

{
                    // WARNING: Could not recover jumptable at 0x1000360a. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxLockTempMaps();
  return;
}



AFX_MODULE_STATE * AfxSetModuleState(AFX_MODULE_STATE *param_1)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10003610. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxSetModuleState(param_1);
  return pAVar1;
}



void __thiscall
CDynLinkLibrary::CDynLinkLibrary(CDynLinkLibrary *this,AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10003616. Too many branches
                    // WARNING: Treating indirect jump as call
  CDynLinkLibrary(this,param_1,param_2);
  return;
}



int AfxInitExtensionModule(AFX_EXTENSION_MODULE *param_1,HINSTANCE__ *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000361c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxInitExtensionModule(param_1,param_2);
  return iVar1;
}



void AfxWinTerm(void)

{
                    // WARNING: Could not recover jumptable at 0x10003622. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxWinTerm();
  return;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10003628. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



int AfxWinInit(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000362e. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinInit(param_1,param_2,param_3,param_4);
  return iVar1;
}



_AFX_THREAD_STATE * AfxGetThreadState(void)

{
  _AFX_THREAD_STATE *p_Var1;
  
                    // WARNING: Could not recover jumptable at 0x10003634. Too many branches
                    // WARNING: Treating indirect jump as call
  p_Var1 = AfxGetThreadState();
  return p_Var1;
}



void AfxCoreInitModule(void)

{
                    // WARNING: Could not recover jumptable at 0x1000363a. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxCoreInitModule();
  return;
}



void Unwind_10003640(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x14));
  return;
}



void Unwind_10003655(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000365e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_10003667(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_10003670(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_10003679(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_10003682(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_1000368b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x44));
  return;
}



void Unwind_10003694(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x4c));
  return;
}



void Unwind_1000369d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x54));
  return;
}



void Unwind_100036a6(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x5c));
  return;
}



void Unwind_100036af(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -100));
  return;
}



void Unwind_100036b8(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x6c));
  return;
}



void Unwind_100036c1(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x74));
  return;
}



void Unwind_100036ca(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x7c));
  return;
}



void Unwind_100036d3(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x84));
  return;
}



void Unwind_100036df(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x8c));
  return;
}



void Unwind_100036eb(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x94));
  return;
}



void Unwind_100036f7(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x9c));
  return;
}



void Unwind_10003703(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xa4));
  return;
}



void Unwind_1000370f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xac));
  return;
}



void Unwind_1000371b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xb4));
  return;
}



void Unwind_10003727(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xbc));
  return;
}



void Unwind_1000373d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_10003750(void)

{
  int unaff_EBP;
  
  FUN_10002650(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10003759(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0xc));
  return;
}



void Unwind_10003766(void)

{
  int unaff_EBP;
  
  FUN_10002970((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x1138));
  return;
}



void Unwind_10003775(void)

{
  int unaff_EBP;
  
  FUN_10002970((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x12b4));
  return;
}



void Unwind_10003784(void)

{
  int unaff_EBP;
  
  FUN_10002970((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x1430));
  return;
}



void Unwind_10003793(void)

{
  int unaff_EBP;
  
  FUN_10002970((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x15ac));
  return;
}



void Unwind_100037a2(void)

{
  int unaff_EBP;
  
  FUN_10002970((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x1728));
  return;
}



void Unwind_100037b1(void)

{
  int unaff_EBP;
  
  FUN_10002970((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x18a4));
  return;
}



void Unwind_100037d0(void)

{
  int unaff_EBP;
  
  FUN_10002650(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100037d9(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0xc));
  return;
}



void Unwind_100037e6(void)

{
  int unaff_EBP;
  
  FUN_10002970((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x1138));
  return;
}



void Unwind_100037f5(void)

{
  int unaff_EBP;
  
  FUN_10002970((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x12b4));
  return;
}



void Unwind_10003804(void)

{
  int unaff_EBP;
  
  FUN_10002970((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x1430));
  return;
}



void Unwind_10003813(void)

{
  int unaff_EBP;
  
  FUN_10002970((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x15ac));
  return;
}



void Unwind_10003822(void)

{
  int unaff_EBP;
  
  FUN_10002970((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x1728));
  return;
}



void Unwind_10003831(void)

{
  int unaff_EBP;
  
  FUN_10002970((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x18a4));
  return;
}



void Unwind_10003850(void)

{
  int unaff_EBP;
  
  FUN_100028b0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10003859(void)

{
  int unaff_EBP;
  
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(*(int *)(unaff_EBP + -0x10) + 0xdc));
  return;
}



void Unwind_10003880(void)

{
  int unaff_EBP;
  
  FUN_10002920(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100038a0(void)

{
  int unaff_EBP;
  
  FUN_100028b0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100038c0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_100038e0(void)

{
  int unaff_EBP;
  
  FUN_100028b0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100038e9(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0xdc));
  return;
}



void Unwind_10003910(void)

{
  int unaff_EBP;
  
  FUN_100028b0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10003919(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0xdc));
  return;
}



void Unwind_10003934(void)

{
  int unaff_EBP;
  
  FUN_1000322f((undefined4 *)(unaff_EBP + -0x14));
  return;
}


