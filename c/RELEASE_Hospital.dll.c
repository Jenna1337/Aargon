typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef long long    longlong;
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

typedef struct tm tm, *Ptm;

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
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

typedef struct HWND__ HWND__, *PHWND__;

struct HWND__ { // PlaceHolder Structure
};

typedef int (*_onexit_t)(void);

typedef longlong __time64_t;

typedef uint size_t;

typedef __time64_t time_t;




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
  puStack_c = &LAB_1000322b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  this = operator_new(0x17cc);
  local_8 = 0;
  if (this == (void *)0x0) {
    local_1c = (SELECT_SKILL1 *)0x0;
  }
  else {
    local_1c = (SELECT_SKILL1 *)FUN_10002360(this,param_1);
  }
  ExceptionList = local_10;
  return local_1c;
}



void __fastcall FUN_1000106e(int param_1)

{
  CString *pCVar1;
  char *pcVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  char *pcVar5;
  undefined4 uStack_2b0;
  undefined4 uStack_2a0;
  undefined4 uStack_284;
  undefined4 uStack_274;
  undefined4 uStack_258;
  undefined4 uStack_248;
  undefined4 uStack_22c;
  undefined4 uStack_21c;
  undefined4 uStack_200;
  undefined4 uStack_1f0;
  int iStack_1c4;
  CString local_b4 [4];
  CString local_b0 [4];
  undefined1 *local_ac;
  CString local_a8 [4];
  CString local_a4 [4];
  undefined1 *local_a0;
  CString local_9c [4];
  CString local_98 [4];
  undefined1 *local_94;
  CString local_90 [4];
  CString local_8c [4];
  undefined1 *local_88;
  CString local_84 [4];
  CString local_80 [4];
  undefined1 *local_7c;
  CString local_78 [4];
  CString local_74 [4];
  undefined1 *local_70;
  CString local_6c [4];
  CString local_68 [4];
  undefined1 *local_64;
  CString local_60 [4];
  CString local_5c [4];
  undefined1 *local_58;
  CString local_54 [4];
  CString local_50 [4];
  undefined1 *local_4c;
  CString local_48 [4];
  CString local_44 [4];
  undefined1 *local_40;
  CString local_3c [4];
  undefined1 *local_38;
  CString local_34 [4];
  undefined1 *local_30;
  CString local_2c [4];
  undefined1 *local_28;
  CString local_24 [4];
  undefined1 *local_20;
  CString local_1c [4];
  undefined1 *local_18;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_1000332e;
  local_10 = ExceptionList;
  local_18 = (undefined1 *)&iStack_1c4;
  ExceptionList = &local_10;
  iStack_1c4 = param_1;
  CString::CString((CString *)&iStack_1c4,s_checkup_wav_100050bc);
  pCVar1 = (CString *)(**(code **)(**(int **)(param_1 + 0x17c8) + 0x58))();
  local_8 = 0;
  CWave::Create((CWave *)(param_1 + 0x1688),pCVar1);
  local_8 = 0xffffffff;
  CString::~CString(local_1c);
  local_20 = &stack0xfffffe34;
  CString::CString((CString *)&stack0xfffffe34,s_outpatient_wav_100050c8);
  pCVar1 = (CString *)(**(code **)(**(int **)(param_1 + 0x17c8) + 0x58))();
  local_8 = 1;
  CWave::Create((CWave *)(param_1 + 0x16c8),pCVar1);
  local_8 = 0xffffffff;
  CString::~CString(local_24);
  local_28 = &stack0xfffffe2c;
  CString::CString((CString *)&stack0xfffffe2c,s_intensivecare_wav_100050d8);
  pCVar1 = (CString *)(**(code **)(**(int **)(param_1 + 0x17c8) + 0x58))();
  local_8 = 2;
  CWave::Create((CWave *)(param_1 + 0x1708),pCVar1);
  local_8 = 0xffffffff;
  CString::~CString(local_2c);
  local_30 = &stack0xfffffe24;
  CString::CString((CString *)&stack0xfffffe24,s_emergency_wav_100050ec);
  pCVar1 = (CString *)(**(code **)(**(int **)(param_1 + 0x17c8) + 0x58))();
  local_8 = 3;
  CWave::Create((CWave *)(param_1 + 0x1748),pCVar1);
  local_8 = 0xffffffff;
  CString::~CString(local_34);
  local_38 = &stack0xfffffe1c;
  CString::CString((CString *)&stack0xfffffe1c,s_exit_wav_100050fc);
  pCVar1 = (CString *)(**(code **)(**(int **)(param_1 + 0x17c8) + 0x58))();
  local_8 = 4;
  uStack_1f0 = 0x100012dc;
  CWave::Create((CWave *)(param_1 + 0x1788),pCVar1);
  local_8 = 0xffffffff;
  CString::~CString(local_3c);
  for (local_14 = 0; local_14 < 3; local_14 = local_14 + 1) {
    local_40 = (undefined1 *)&uStack_1f0;
    pcVar2 = (char *)FUN_100027b0(local_44,(&PTR_DAT_10005020)[local_14]);
    local_8 = 5;
    uStack_200 = 0x1000134d;
    operator+((CString *)&uStack_1f0,pcVar2);
    puVar3 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x17c8) + 0x54))();
    local_8._0_1_ = 6;
    FUN_100027a0(puVar3);
    local_4c = (undefined1 *)&uStack_200;
    pcVar2 = (char *)FUN_100027b0(local_50,(&PTR_DAT_10005020)[local_14]);
    local_8._0_1_ = 7;
    operator+((CString *)&uStack_200,pcVar2);
    puVar3 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x17c8) + 0x54))();
    local_8._0_1_ = 8;
    FUN_100027a0(puVar3);
    (**(code **)(*(int *)(param_1 + 8 + local_14 * 0x180) + 0x4c))();
    local_8._0_1_ = 7;
    CString::~CString(local_54);
    local_8._0_1_ = 6;
    FUN_100027d0(local_50);
    local_8 = CONCAT31(local_8._1_3_,5);
    CString::~CString(local_48);
    local_8 = 0xffffffff;
    FUN_100027d0(local_44);
    (**(code **)(*(int *)(param_1 + 8 + local_14 * 0x180) + 0x2c))();
    uStack_21c = 0x100014df;
    FUN_10002740((void *)(param_1 + 8 + local_14 * 0x180),param_1 + 0x1688);
    local_58 = (undefined1 *)&uStack_21c;
    pcVar2 = (char *)FUN_100027b0(local_5c,(&PTR_DAT_10005020)[local_14]);
    local_8 = 9;
    uStack_22c = 0x10001525;
    operator+((CString *)&uStack_21c,pcVar2);
    puVar3 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x17c8) + 0x54))();
    local_8._0_1_ = 10;
    FUN_100027a0(puVar3);
    local_64 = (undefined1 *)&uStack_22c;
    pcVar2 = (char *)FUN_100027b0(local_68,(&PTR_DAT_10005020)[local_14]);
    local_8._0_1_ = 0xb;
    operator+((CString *)&uStack_22c,pcVar2);
    puVar3 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x17c8) + 0x54))();
    local_8._0_1_ = 0xc;
    FUN_100027a0(puVar3);
    (**(code **)(*(int *)(param_1 + 0x488 + local_14 * 0x180) + 0x4c))();
    local_8._0_1_ = 0xb;
    CString::~CString(local_6c);
    local_8._0_1_ = 10;
    FUN_100027d0(local_68);
    local_8 = CONCAT31(local_8._1_3_,9);
    CString::~CString(local_60);
    local_8 = 0xffffffff;
    FUN_100027d0(local_5c);
    (**(code **)(*(int *)(param_1 + 0x488 + local_14 * 0x180) + 0x2c))();
    uStack_248 = 0x100016c6;
    FUN_10002740((void *)(param_1 + 0x488 + local_14 * 0x180),param_1 + 0x16c8);
    local_70 = (undefined1 *)&uStack_248;
    pcVar2 = (char *)FUN_100027b0(local_74,(&PTR_DAT_10005020)[local_14]);
    local_8 = 0xd;
    uStack_258 = 0x1000170c;
    operator+((CString *)&uStack_248,pcVar2);
    puVar3 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x17c8) + 0x54))();
    local_8._0_1_ = 0xe;
    FUN_100027a0(puVar3);
    local_7c = (undefined1 *)&uStack_258;
    pcVar2 = (char *)FUN_100027b0(local_80,(&PTR_DAT_10005020)[local_14]);
    local_8._0_1_ = 0xf;
    operator+((CString *)&uStack_258,pcVar2);
    puVar3 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x17c8) + 0x54))();
    local_8._0_1_ = 0x10;
    FUN_100027a0(puVar3);
    (**(code **)(*(int *)(param_1 + 0x908 + local_14 * 0x180) + 0x4c))();
    local_8._0_1_ = 0xf;
    CString::~CString(local_84);
    local_8._0_1_ = 0xe;
    FUN_100027d0(local_80);
    local_8 = CONCAT31(local_8._1_3_,0xd);
    CString::~CString(local_78);
    local_8 = 0xffffffff;
    FUN_100027d0(local_74);
    (**(code **)(*(int *)(param_1 + 0x908 + local_14 * 0x180) + 0x2c))();
    uStack_274 = 0x100018ad;
    FUN_10002740((void *)(param_1 + 0x908 + local_14 * 0x180),param_1 + 0x1708);
    local_88 = (undefined1 *)&uStack_274;
    pcVar2 = (char *)FUN_100027b0(local_8c,(&PTR_DAT_10005020)[local_14]);
    local_8 = 0x11;
    uStack_284 = 0x100018f9;
    operator+((CString *)&uStack_274,pcVar2);
    puVar3 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x17c8) + 0x54))();
    local_8._0_1_ = 0x12;
    FUN_100027a0(puVar3);
    local_94 = (undefined1 *)&uStack_284;
    pcVar2 = (char *)FUN_100027b0(local_98,(&PTR_DAT_10005020)[local_14]);
    local_8._0_1_ = 0x13;
    operator+((CString *)&uStack_284,pcVar2);
    puVar3 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x17c8) + 0x54))();
    local_8._0_1_ = 0x14;
    FUN_100027a0(puVar3);
    (**(code **)(*(int *)(param_1 + 0xd88 + local_14 * 0x180) + 0x4c))();
    local_8._0_1_ = 0x13;
    CString::~CString(local_9c);
    local_8._0_1_ = 0x12;
    FUN_100027d0(local_98);
    local_8 = CONCAT31(local_8._1_3_,0x11);
    CString::~CString(local_90);
    local_8 = 0xffffffff;
    FUN_100027d0(local_8c);
    (**(code **)(*(int *)(param_1 + 0xd88 + local_14 * 0x180) + 0x2c))();
    uStack_2a0 = 0x10001ab2;
    FUN_10002740((void *)(param_1 + 0xd88 + local_14 * 0x180),param_1 + 0x1748);
    local_a0 = (undefined1 *)&uStack_2a0;
    pcVar2 = (char *)FUN_100027b0(local_a4,(&PTR_DAT_10005020)[local_14]);
    local_8 = 0x15;
    uStack_2b0 = 0x10001afe;
    operator+((CString *)&uStack_2a0,pcVar2);
    puVar3 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x17c8) + 0x54))();
    local_8._0_1_ = 0x16;
    FUN_100027a0(puVar3);
    local_ac = (undefined1 *)&uStack_2b0;
    pcVar5 = s__btn_exit_up_bmp_100051bc;
    pcVar2 = (char *)FUN_100027b0(local_b0,(&PTR_DAT_10005020)[local_14]);
    local_8._0_1_ = 0x17;
    operator+((CString *)&uStack_2b0,pcVar2);
    puVar3 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x17c8) + 0x54))(local_b4,pcVar5);
    local_8._0_1_ = 0x18;
    uVar4 = FUN_100027a0(puVar3);
    (**(code **)(*(int *)(param_1 + 0x1208 + local_14 * 0x180) + 0x4c))(uVar4);
    local_8._0_1_ = 0x17;
    CString::~CString(local_b4);
    local_8._0_1_ = 0x16;
    FUN_100027d0(local_b0);
    local_8 = CONCAT31(local_8._1_3_,0x15);
    CString::~CString(local_a8);
    local_8 = 0xffffffff;
    FUN_100027d0(local_a4);
    (**(code **)(*(int *)(param_1 + 0x1208 + local_14 * 0x180) + 0x2c))
              (*(undefined4 *)(&DAT_10005090 + local_14 * 8),
               *(undefined4 *)(&DAT_10005094 + local_14 * 8));
    uStack_1f0 = 0x10001cb7;
    FUN_10002740((void *)(param_1 + 0x1208 + local_14 * 0x180),param_1 + 0x1788);
  }
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10001ccb(int param_1)

{
  undefined4 local_c;
  tm *local_8;
  
  local_c = 0;
  time((time_t *)&local_c);
  local_8 = localtime((time_t *)&local_c);
  if ((local_8->tm_hour < 6) || (0xf < local_8->tm_hour)) {
    if ((local_8->tm_hour < 0x10) || (0x12 < local_8->tm_hour)) {
      *(undefined4 *)(param_1 + 4) = 2;
    }
    else {
      *(undefined4 *)(param_1 + 4) = 1;
    }
  }
  else {
    *(undefined4 *)(param_1 + 4) = 0;
  }
  FUN_10002265(param_1);
  return;
}



void __fastcall FUN_10001d4a(int param_1)

{
  char cVar1;
  
  cVar1 = (**(code **)(*(int *)(param_1 + 8 + *(int *)(param_1 + 4) * 0x180) + 0x44))();
  if (cVar1 == '\0') {
    FUN_100028c0(param_1 + 8 + *(int *)(param_1 + 4) * 0x180);
  }
  else {
    FUN_10002760(param_1 + 8 + *(int *)(param_1 + 4) * 0x180);
  }
  (**(code **)(*(int *)(param_1 + 8 + *(int *)(param_1 + 4) * 0x180) + 0x14))();
  cVar1 = (**(code **)(*(int *)(param_1 + 0x488 + *(int *)(param_1 + 4) * 0x180) + 0x44))();
  if (cVar1 == '\0') {
    FUN_100028c0(param_1 + 0x488 + *(int *)(param_1 + 4) * 0x180);
  }
  else {
    FUN_10002760(param_1 + 0x488 + *(int *)(param_1 + 4) * 0x180);
  }
  (**(code **)(*(int *)(param_1 + 0x488 + *(int *)(param_1 + 4) * 0x180) + 0x14))();
  cVar1 = (**(code **)(*(int *)(param_1 + 0x908 + *(int *)(param_1 + 4) * 0x180) + 0x44))();
  if (cVar1 == '\0') {
    FUN_100028c0(param_1 + 0x908 + *(int *)(param_1 + 4) * 0x180);
  }
  else {
    FUN_10002760(param_1 + 0x908 + *(int *)(param_1 + 4) * 0x180);
  }
  (**(code **)(*(int *)(param_1 + 0x908 + *(int *)(param_1 + 4) * 0x180) + 0x14))();
  cVar1 = (**(code **)(*(int *)(param_1 + 0xd88 + *(int *)(param_1 + 4) * 0x180) + 0x44))();
  if (cVar1 == '\0') {
    FUN_100028c0(param_1 + 0xd88 + *(int *)(param_1 + 4) * 0x180);
  }
  else {
    FUN_10002760(param_1 + 0xd88 + *(int *)(param_1 + 4) * 0x180);
  }
  (**(code **)(*(int *)(param_1 + 0xd88 + *(int *)(param_1 + 4) * 0x180) + 0x14))();
  cVar1 = (**(code **)(*(int *)(param_1 + 0x1208 + *(int *)(param_1 + 4) * 0x180) + 0x44))();
  if (cVar1 == '\0') {
    FUN_100028c0(param_1 + 0x1208 + *(int *)(param_1 + 4) * 0x180);
  }
  else {
    FUN_10002760(param_1 + 0x1208 + *(int *)(param_1 + 4) * 0x180);
  }
  (**(code **)(*(int *)(param_1 + 0x1208 + *(int *)(param_1 + 4) * 0x180) + 0x14))();
  return;
}



void __fastcall FUN_1000205e(int param_1)

{
  char cVar1;
  
  cVar1 = (**(code **)(*(int *)(param_1 + 8 + *(int *)(param_1 + 4) * 0x180) + 0x44))();
  if (cVar1 == '\0') {
    cVar1 = (**(code **)(*(int *)(param_1 + 0x488 + *(int *)(param_1 + 4) * 0x180) + 0x44))();
    if (cVar1 == '\0') {
      cVar1 = (**(code **)(*(int *)(param_1 + 0x908 + *(int *)(param_1 + 4) * 0x180) + 0x44))();
      if (cVar1 == '\0') {
        cVar1 = (**(code **)(*(int *)(param_1 + 0xd88 + *(int *)(param_1 + 4) * 0x180) + 0x44))();
        if (cVar1 == '\0') {
          cVar1 = (**(code **)(*(int *)(param_1 + 0x1208 + *(int *)(param_1 + 4) * 0x180) + 0x44))()
          ;
          if (cVar1 != '\0') {
            GAME::ChangeState(*(GAME **)(param_1 + 0x17c8),3);
          }
        }
        else {
          (**(code **)(**(int **)(param_1 + 0x17c8) + 0x50))(3);
          GAME::ChangeState(*(GAME **)(param_1 + 0x17c8),2);
        }
      }
      else {
        (**(code **)(**(int **)(param_1 + 0x17c8) + 0x50))(2);
        GAME::ChangeState(*(GAME **)(param_1 + 0x17c8),2);
      }
    }
    else {
      (**(code **)(**(int **)(param_1 + 0x17c8) + 0x50))(1);
      GAME::ChangeState(*(GAME **)(param_1 + 0x17c8),2);
    }
  }
  else {
    (**(code **)(**(int **)(param_1 + 0x17c8) + 0x50))(0);
    GAME::ChangeState(*(GAME **)(param_1 + 0x17c8),2);
  }
  return;
}



void FUN_10002245(void)

{
  return;
}



void __fastcall FUN_10002250(int param_1)

{
  FUN_10002265(param_1);
  return;
}



void __fastcall FUN_10002265(int param_1)

{
  char *pcVar1;
  undefined4 *puVar2;
  char *pcVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  HINSTANCE__ *pHVar7;
  undefined1 uVar8;
  CString local_20 [4];
  CString local_1c [4];
  undefined1 *local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000334a;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  GKERNEL::NewSpriteBackground();
  for (local_14 = 0; local_14 < 2; local_14 = local_14 + 1) {
    uVar8 = 1;
    pHVar7 = (HINSTANCE__ *)0x0;
    iVar6 = 0;
    uVar5 = 0;
    uVar4 = 0;
    local_18 = &stack0xffffffac;
    pcVar3 = s__hospital_bmp_100051d0;
    pcVar1 = (char *)FUN_100027b0(local_1c,(&PTR_DAT_10005020)[*(int *)(param_1 + 4)]);
    local_8 = 0;
    operator+((CString *)&stack0xffffffac,pcVar1);
    puVar2 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x17c8) + 0x54))(local_20,pcVar3);
    local_8._0_1_ = 1;
    pcVar1 = (char *)FUN_100027a0(puVar2);
    GKTOOLS::CopyDIBToBack(pcVar1,uVar4,uVar5,iVar6,pHVar7,(bool)uVar8);
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_20);
    local_8 = 0xffffffff;
    FUN_100027d0(local_1c);
    GKERNEL::Flip();
  }
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_10002360(void *this,undefined4 param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000342e;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10002700((undefined4 *)this);
  local_8 = 0;
  *(undefined4 *)((int)this + 4) = 3;
  FUN_10002f14((int)this + 8,0x180,3,FUN_100024d0);
  local_8._0_1_ = 1;
  FUN_10002f14((int)this + 0x488,0x180,3,FUN_100024d0);
  local_8._0_1_ = 2;
  FUN_10002f14((int)this + 0x908,0x180,3,FUN_100024d0);
  local_8._0_1_ = 3;
  FUN_10002f14((int)this + 0xd88,0x180,3,FUN_100024d0);
  local_8._0_1_ = 4;
  FUN_10002f14((int)this + 0x1208,0x180,3,FUN_100024d0);
  local_8._0_1_ = 5;
  CWave::CWave((CWave *)((int)this + 0x1688));
  local_8._0_1_ = 6;
  CWave::CWave((CWave *)((int)this + 0x16c8));
  local_8._0_1_ = 7;
  CWave::CWave((CWave *)((int)this + 0x1708));
  local_8._0_1_ = 8;
  CWave::CWave((CWave *)((int)this + 0x1748));
  local_8 = CONCAT31(local_8._1_3_,9);
  CWave::CWave((CWave *)((int)this + 0x1788));
  *(undefined4 *)((int)this + 0x17c8) = param_1;
  *(undefined ***)this = &PTR_FUN_10004100;
  ExceptionList = local_10;
  return this;
}



OVERLAY * __fastcall FUN_100024d0(OVERLAY *param_1)

{
  FUN_10002950(param_1);
  *(undefined4 *)(param_1 + 0x17c) = 0;
  *(undefined ***)param_1 = &PTR_FUN_10004128;
  *(undefined ***)(param_1 + 8) = &PTR_FUN_10004124;
  return param_1;
}



void * __thiscall FUN_10002510(void *this,uint param_1)

{
  this_10002540((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



// this parameter of CWave
// 

void __fastcall this_10002540(undefined4 *param_1)

{
  FUN_10002ae0(param_1);
  return;
}



void FUN_10002560(undefined4 *param_1,undefined4 *param_2)

{
  *param_1 = 0x18d;
  *param_2 = 0x13;
  return;
}



undefined1 FUN_10002580(void)

{
  return 0;
}



void * __thiscall FUN_10002590(void *this,uint param_1)

{
  FUN_100025c0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_100025c0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &this_1000350e;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_FUN_10004100;
  local_8 = 9;
  CWave::~CWave((CWave *)(param_1 + 0x5e2));
  local_8._0_1_ = 8;
  CWave::~CWave((CWave *)(param_1 + 0x5d2));
  local_8._0_1_ = 7;
  CWave::~CWave((CWave *)(param_1 + 0x5c2));
  local_8._0_1_ = 6;
  CWave::~CWave((CWave *)(param_1 + 0x5b2));
  local_8._0_1_ = 5;
  CWave::~CWave((CWave *)(param_1 + 0x5a2));
  local_8._0_1_ = 4;
  FUN_10002e20(param_1 + 0x482,0x180,3,this_10002540);
  local_8._0_1_ = 3;
  FUN_10002e20(param_1 + 0x362,0x180,3,this_10002540);
  local_8._0_1_ = 2;
  FUN_10002e20(param_1 + 0x242,0x180,3,this_10002540);
  local_8._0_1_ = 1;
  FUN_10002e20(param_1 + 0x122,0x180,3,this_10002540);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_10002e20(param_1 + 2,0x180,3,this_10002540);
  local_8 = 0xffffffff;
  FUN_10002b80(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_10002700(undefined4 *param_1)

{
  FUN_10002720(param_1);
  *param_1 = &PTR_FUN_10004178;
  return param_1;
}



undefined4 * __fastcall FUN_10002720(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1000419c;
  return param_1;
}



void __thiscall FUN_10002740(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 0x17c) = param_1;
  return;
}



void __fastcall FUN_10002760(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_10002900(param_1);
  if ((iVar1 == 0) && (*(int *)(param_1 + 0x17c) != 0)) {
    CWave::Play(*(CWave **)(param_1 + 0x17c),0,0,0);
  }
  FUN_100028e0(param_1);
  return;
}



undefined4 __fastcall FUN_100027a0(undefined4 *param_1)

{
  return *param_1;
}



void * __thiscall FUN_100027b0(void *this,char *param_1)

{
  CString::CString((CString *)this,param_1);
  return this;
}



void __fastcall FUN_100027d0(CString *param_1)

{
  CString::~CString(param_1);
  return;
}



void FUN_100027f0(void)

{
  return;
}



void FUN_10002800(void)

{
  return;
}



undefined1 __fastcall FUN_10002810(int param_1)

{
  return *(undefined1 *)(param_1 + 0xcc);
}



void __fastcall FUN_10002830(int param_1)

{
  *(undefined1 *)(param_1 + 0xcc) = 1;
  return;
}



void __fastcall FUN_10002850(int param_1)

{
  *(undefined1 *)(param_1 + 0xcc) = 0;
  return;
}



void __thiscall FUN_10002870(void *this,undefined4 *param_1)

{
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x2c))(*param_1,param_1[1]);
  return;
}



undefined1 __fastcall FUN_100028a0(int param_1)

{
  return *(undefined1 *)(param_1 + 0xa0);
}



void __fastcall FUN_100028c0(int param_1)

{
  *(undefined4 *)(param_1 + 0xd4) = 0;
  FUN_10002920(param_1);
  return;
}



void __fastcall FUN_100028e0(int param_1)

{
  *(undefined4 *)(param_1 + 0xd4) = 1;
  FUN_10002920(param_1);
  return;
}



undefined4 __fastcall FUN_10002900(int param_1)

{
  return *(undefined4 *)(param_1 + 0xd4);
}



void __fastcall FUN_10002920(int param_1)

{
  *(undefined4 *)(param_1 + 0x178) = 1;
  *(undefined4 *)(param_1 + 0x174) = 0;
  return;
}



OVERLAY * __fastcall FUN_10002950(OVERLAY *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_10003539;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  OVERLAY::OVERLAY(param_1);
  local_8 = 0;
  FUN_100029d0((DWORD *)(param_1 + 0xd0));
  DD_SURFACE::DD_SURFACE((DD_SURFACE *)(param_1 + 0xdc));
  local_8 = CONCAT31(local_8._1_3_,1);
  *(undefined ***)param_1 = &PTR_FUN_100041bc;
  *(undefined ***)(param_1 + 8) = &PTR_FUN_100041b8;
  FUN_100028c0((int)param_1);
  ExceptionList = local_10;
  return param_1;
}



DWORD * __fastcall FUN_100029d0(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
  return param_1;
}



void * __thiscall FUN_100029f0(void *this,uint param_1)

{
  FUN_10002ae0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10002a20(undefined4 *param_1)

{
  DD_SURFACE *local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_10003559;
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
  FUN_10002a90(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10002a90(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1000420c;
  return;
}



void * __thiscall FUN_10002ab0(void *this,uint param_1)

{
  FUN_10002a90((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10002ae0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_10003579;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(param_1 + 0x37));
  local_8 = 0xffffffff;
  FUN_10002a20(param_1);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_10002b30(void *this,uint param_1)

{
  FUN_10002b60((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10002b60(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1000419c;
  return;
}



void __fastcall FUN_10002b80(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_10004178;
  FUN_10002b60(param_1);
  return;
}



void * __thiscall FUN_10002ba0(void *this,uint param_1)

{
  FUN_10002b80((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002bce. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002bd4. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void operator+(CString *param_1,char *param_2)

{
                    // WARNING: Could not recover jumptable at 0x10002bda. Too many branches
                    // WARNING: Treating indirect jump as call
  operator+(param_1,param_2);
  return;
}



void __thiscall CString::~CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x10002be0. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CString(this);
  return;
}



void __thiscall CString::CString(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002be6. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



void * __thiscall FUN_10002c1e(void *this,byte param_1)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)this);
  if ((param_1 & 1) != 0) {
    CNoTrackObject::operator_delete(this);
  }
  return this;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x100031c6. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



int FUN_10002c99(HINSTANCE__ *param_1,int param_2)

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
      pAVar5 = AfxSetModuleState((AFX_MODULE_STATE *)&this_10005270);
      p_Var3 = AfxGetThreadState();
      *(AFX_MODULE_STATE **)(p_Var3 + 8) = pAVar5;
      pAVar5 = AfxGetModuleState();
      if (*(int **)(pAVar5 + 4) != (int *)0x0) {
        (**(code **)(**(int **)(pAVar5 + 4) + 0x70))();
      }
      AfxLockTempMaps();
      AfxUnlockTempMaps(-1);
      AfxWinTerm();
      AfxTermExtensionModule((AFX_EXTENSION_MODULE *)&param_1_10006300,1);
    }
    else if (param_2 == 3) {
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
                ((AFX_MAINTAIN_STATE2 *)&local_c,(AFX_MODULE_STATE *)&this_10005270);
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
  iVar4 = AfxWinInit(param_1,(HINSTANCE__ *)0x0,(char *)&param_3_1000423c,0);
  if (iVar4 != 0) {
    pAVar5 = AfxGetModuleState();
    piVar2 = *(int **)(pAVar5 + 4);
    if ((piVar2 == (int *)0x0) || (iVar4 = (**(code **)(*piVar2 + 0x58))(), iVar4 != 0)) {
      *(undefined4 *)(p_Var3 + 8) = uVar1;
      AfxInitExtensionModule((AFX_EXTENSION_MODULE *)&param_1_10006300,param_1);
      this = (CDynLinkLibrary *)operator_new(0x40);
      if (this != (CDynLinkLibrary *)0x0) {
        CDynLinkLibrary::CDynLinkLibrary(this,(AFX_EXTENSION_MODULE *)&param_1_10006300,0);
      }
      param_2 = 1;
      goto LAB_10002d25;
    }
    (**(code **)(*piVar2 + 0x70))();
  }
  AfxWinTerm();
LAB_10002d25:
  *(undefined4 *)(p_Var3 + 8) = uVar1;
  p_Var3 = AfxGetThreadState();
  AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var3 + 8));
  return param_2;
}



undefined4 FUN_10002dc0(undefined4 param_1,int param_2)

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
    pAVar2 = AfxSetModuleState((AFX_MODULE_STATE *)&this_10005270);
    *(AFX_MODULE_STATE **)(p_Var1 + 8) = pAVar2;
  }
  else if (param_2 == 0) {
    p_Var1 = AfxGetThreadState();
    AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var1 + 8));
  }
  return 1;
}



void __fastcall FUN_10002e11(undefined4 *param_1)

{
  *(undefined4 *)(param_1[1] + 4) = *param_1;
  return;
}



void __CxxFrameHandler(void)

{
                    // WARNING: Could not recover jumptable at 0x10002e1a. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler();
  return;
}



void FUN_10002e20(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_10004240;
  puStack_10 = &DAT_10003160;
  local_14 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_14;
  while( true ) {
    param_3 = param_3 + -1;
    if (param_3 < 0) break;
    (*(code *)param_4)();
  }
  local_8 = 0xffffffff;
  FUN_10002e88();
  ExceptionList = local_14;
  return;
}



void FUN_10002e88(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x1c) == 0) {
    FUN_10002ea0(*(undefined4 *)(unaff_EBP + 8),*(undefined4 *)(unaff_EBP + 0xc),
                 *(int *)(unaff_EBP + 0x10),*(undefined **)(unaff_EBP + 0x14));
  }
  return;
}



void FUN_10002ea0(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_10004250;
  puStack_10 = &DAT_10003160;
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



undefined4 __cdecl FUN_10002efe(undefined4 *param_1)

{
  if (*(int *)*param_1 != -0x1f928c9d) {
    return 0;
  }
                    // WARNING: Subroutine does not return
  terminate();
}



void FUN_10002f14(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  int local_20;
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_10004260;
  puStack_10 = &DAT_10003160;
  local_14 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_14;
  for (local_20 = 0; local_20 < param_3; local_20 = local_20 + 1) {
    (*(code *)param_4)();
  }
  local_8 = 0xffffffff;
  FUN_10002f7e();
  ExceptionList = local_14;
  return;
}



void FUN_10002f7e(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x20) == 0) {
    FUN_10002ea0(*(undefined4 *)(unaff_EBP + 8),*(undefined4 *)(unaff_EBP + 0xc),
                 *(int *)(unaff_EBP + -0x1c),*(undefined **)(unaff_EBP + 0x18));
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10002f9c(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 *_Memory;
  undefined4 *puVar2;
  
  if (param_2 == 0) {
    if (0 < DAT_1000631c) {
      DAT_1000631c = DAT_1000631c + -1;
      goto LAB_10002fb2;
    }
LAB_10002fda:
    uVar1 = 0;
  }
  else {
LAB_10002fb2:
    _DAT_10006320 = *(undefined4 *)_adjust_fdiv_exref;
    if (param_2 == 1) {
      DAT_10006328 = (undefined4 *)malloc(0x80);
      if (DAT_10006328 == (undefined4 *)0x0) goto LAB_10002fda;
      *DAT_10006328 = 0;
      DAT_10006324 = DAT_10006328;
      initterm(&DAT_10005000,&DAT_10005008);
      DAT_1000631c = DAT_1000631c + 1;
    }
    else if ((param_2 == 0) &&
            (_Memory = DAT_10006328, puVar2 = DAT_10006324, DAT_10006328 != (undefined4 *)0x0)) {
      while (puVar2 = puVar2 + -1, _Memory <= puVar2) {
        if ((code *)*puVar2 != (code *)0x0) {
          (*(code *)*puVar2)();
          _Memory = DAT_10006328;
        }
      }
      free(_Memory);
      DAT_10006328 = (undefined4 *)0x0;
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
  iVar2 = DAT_1000631c;
  if (param_2 != 0) {
    if ((param_2 != 1) && (param_2 != 2)) goto LAB_1000308f;
    if ((PTR_FUN_100051e0 != (undefined *)0x0) &&
       (iVar2 = (*(code *)PTR_FUN_100051e0)(param_1,param_2,param_3), iVar2 == 0)) {
      return 0;
    }
    iVar2 = FUN_10002f9c(param_1,param_2);
  }
  if (iVar2 == 0) {
    return 0;
  }
LAB_1000308f:
  iVar2 = FUN_10002c99(param_1,param_2);
  if (param_2 == 1) {
    if (iVar2 != 0) {
      return iVar2;
    }
    FUN_10002f9c(param_1,0);
  }
  if ((param_2 != 0) && (param_2 != 3)) {
    return iVar2;
  }
  iVar3 = FUN_10002f9c(param_1,param_2);
  param_2 = iVar2;
  if (iVar3 == 0) {
    param_2 = 0;
  }
  if (param_2 != 0) {
    if (PTR_FUN_100051e0 != (undefined *)0x0) {
      iVar2 = (*(code *)PTR_FUN_100051e0)(param_1,iVar1,param_3);
      return iVar2;
    }
    return param_2;
  }
  return 0;
}



void * __thiscall FUN_100030e4(void *this,byte param_1)

{
  type_info::~type_info((type_info *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __cdecl terminate(void)

{
                    // WARNING: Could not recover jumptable at 0x10003166. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  terminate();
  return;
}



void __cdecl initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x1000316c. Too many branches
                    // WARNING: Treating indirect jump as call
  initterm();
  return;
}



void __thiscall type_info::~type_info(type_info *this)

{
                    // WARNING: Could not recover jumptable at 0x10003172. Too many branches
                    // WARNING: Treating indirect jump as call
  ~type_info(this);
  return;
}



void CNoTrackObject::operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100031c0. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x100031c6. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



void __thiscall
AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(AFX_MAINTAIN_STATE2 *this,AFX_MODULE_STATE *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100031d2. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MAINTAIN_STATE2(this,param_1);
  return;
}



void AfxTermThread(HINSTANCE__ *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100031d8. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermThread(param_1);
  return;
}



void AfxTermExtensionModule(AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x100031de. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermExtensionModule(param_1,param_2);
  return;
}



int AfxUnlockTempMaps(int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x100031e4. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxUnlockTempMaps(param_1);
  return iVar1;
}



void AfxLockTempMaps(void)

{
                    // WARNING: Could not recover jumptable at 0x100031ea. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxLockTempMaps();
  return;
}



AFX_MODULE_STATE * AfxSetModuleState(AFX_MODULE_STATE *param_1)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x100031f0. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxSetModuleState(param_1);
  return pAVar1;
}



void __thiscall
CDynLinkLibrary::CDynLinkLibrary(CDynLinkLibrary *this,AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x100031f6. Too many branches
                    // WARNING: Treating indirect jump as call
  CDynLinkLibrary(this,param_1,param_2);
  return;
}



int AfxInitExtensionModule(AFX_EXTENSION_MODULE *param_1,HINSTANCE__ *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x100031fc. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxInitExtensionModule(param_1,param_2);
  return iVar1;
}



void AfxWinTerm(void)

{
                    // WARNING: Could not recover jumptable at 0x10003202. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxWinTerm();
  return;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10003208. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



int AfxWinInit(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000320e. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinInit(param_1,param_2,param_3,param_4);
  return iVar1;
}



_AFX_THREAD_STATE * AfxGetThreadState(void)

{
  _AFX_THREAD_STATE *p_Var1;
  
                    // WARNING: Could not recover jumptable at 0x10003214. Too many branches
                    // WARNING: Treating indirect jump as call
  p_Var1 = AfxGetThreadState();
  return p_Var1;
}



void AfxCoreInitModule(void)

{
                    // WARNING: Could not recover jumptable at 0x1000321a. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxCoreInitModule();
  return;
}



void Unwind_10003220(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x14));
  return;
}



void Unwind_10003235(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000323e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_10003247(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_10003250(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x30));
  return;
}



void Unwind_10003259(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x38));
  return;
}



void Unwind_10003262(void)

{
  int unaff_EBP;
  
  FUN_100027d0((CString *)(unaff_EBP + -0x40));
  return;
}



void Unwind_1000326b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x44));
  return;
}



void Unwind_10003274(void)

{
  int unaff_EBP;
  
  FUN_100027d0((CString *)(unaff_EBP + -0x4c));
  return;
}



void Unwind_1000327d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x50));
  return;
}



void Unwind_10003286(void)

{
  int unaff_EBP;
  
  FUN_100027d0((CString *)(unaff_EBP + -0x58));
  return;
}



void Unwind_1000328f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x5c));
  return;
}



void Unwind_10003298(void)

{
  int unaff_EBP;
  
  FUN_100027d0((CString *)(unaff_EBP + -100));
  return;
}



void Unwind_100032a1(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x68));
  return;
}



void Unwind_100032aa(void)

{
  int unaff_EBP;
  
  FUN_100027d0((CString *)(unaff_EBP + -0x70));
  return;
}



void Unwind_100032b3(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x74));
  return;
}



void Unwind_100032bc(void)

{
  int unaff_EBP;
  
  FUN_100027d0((CString *)(unaff_EBP + -0x7c));
  return;
}



void Unwind_100032c5(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x80));
  return;
}



void Unwind_100032ce(void)

{
  int unaff_EBP;
  
  FUN_100027d0((CString *)(unaff_EBP + -0x88));
  return;
}



void Unwind_100032da(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x8c));
  return;
}



void Unwind_100032e6(void)

{
  int unaff_EBP;
  
  FUN_100027d0((CString *)(unaff_EBP + -0x94));
  return;
}



void Unwind_100032f2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x98));
  return;
}



void Unwind_100032fe(void)

{
  int unaff_EBP;
  
  FUN_100027d0((CString *)(unaff_EBP + -0xa0));
  return;
}



void Unwind_1000330a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xa4));
  return;
}



void Unwind_10003316(void)

{
  int unaff_EBP;
  
  FUN_100027d0((CString *)(unaff_EBP + -0xac));
  return;
}



void Unwind_10003322(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xb0));
  return;
}



void Unwind_10003338(void)

{
  int unaff_EBP;
  
  FUN_100027d0((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_10003341(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_10003360(void)

{
  int unaff_EBP;
  
  FUN_10002b80(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10003369(void)

{
  int unaff_EBP;
  
  FUN_10002e20(*(int *)(unaff_EBP + -0x10) + 8,0x180,3,this_10002540);
  return;
}



void Unwind_10003382(void)

{
  int unaff_EBP;
  
  FUN_10002e20(*(int *)(unaff_EBP + -0x10) + 0x488,0x180,3,this_10002540);
  return;
}



void Unwind_1000339d(void)

{
  int unaff_EBP;
  
  FUN_10002e20(*(int *)(unaff_EBP + -0x10) + 0x908,0x180,3,this_10002540);
  return;
}



void Unwind_100033b8(void)

{
  int unaff_EBP;
  
  FUN_10002e20(*(int *)(unaff_EBP + -0x10) + 0xd88,0x180,3,this_10002540);
  return;
}



void Unwind_100033d3(void)

{
  int unaff_EBP;
  
  FUN_10002e20(*(int *)(unaff_EBP + -0x10) + 0x1208,0x180,3,this_10002540);
  return;
}



void Unwind_100033ee(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x1688));
  return;
}



void Unwind_100033fe(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x16c8));
  return;
}



void Unwind_1000340e(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x1708));
  return;
}



void Unwind_1000341e(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x1748));
  return;
}



void Unwind_10003440(void)

{
  int unaff_EBP;
  
  FUN_10002b80(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10003449(void)

{
  int unaff_EBP;
  
  FUN_10002e20(*(int *)(unaff_EBP + -0x10) + 8,0x180,3,this_10002540);
  return;
}



void Unwind_10003462(void)

{
  int unaff_EBP;
  
  FUN_10002e20(*(int *)(unaff_EBP + -0x10) + 0x488,0x180,3,this_10002540);
  return;
}



void Unwind_1000347d(void)

{
  int unaff_EBP;
  
  FUN_10002e20(*(int *)(unaff_EBP + -0x10) + 0x908,0x180,3,this_10002540);
  return;
}



void Unwind_10003498(void)

{
  int unaff_EBP;
  
  FUN_10002e20(*(int *)(unaff_EBP + -0x10) + 0xd88,0x180,3,this_10002540);
  return;
}



void Unwind_100034b3(void)

{
  int unaff_EBP;
  
  FUN_10002e20(*(int *)(unaff_EBP + -0x10) + 0x1208,0x180,3,this_10002540);
  return;
}



void Unwind_100034ce(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x1688));
  return;
}



void Unwind_100034de(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x16c8));
  return;
}



void Unwind_100034ee(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x1708));
  return;
}



void Unwind_100034fe(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x1748));
  return;
}



void Unwind_10003520(void)

{
  int unaff_EBP;
  
  FUN_10002a20(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10003529(void)

{
  int unaff_EBP;
  
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(*(int *)(unaff_EBP + -0x10) + 0xdc));
  return;
}



void Unwind_10003550(void)

{
  int unaff_EBP;
  
  FUN_10002a90(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10003570(void)

{
  int unaff_EBP;
  
  FUN_10002a20(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10003584(void)

{
  int unaff_EBP;
  
  FUN_10002e11((undefined4 *)(unaff_EBP + -0x14));
  return;
}


