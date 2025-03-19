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

typedef struct SELECT_SKILL SELECT_SKILL, *PSELECT_SKILL;

struct SELECT_SKILL { // PlaceHolder Structure
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

typedef struct HWND__ HWND__, *PHWND__;

struct HWND__ { // PlaceHolder Structure
};

typedef int (*_onexit_t)(void);

typedef uint size_t;




// class SELECT_SKILL * __cdecl Create(class GAME *)

SELECT_SKILL * __cdecl Create(GAME *param_1)

{
  void *this;
  SELECT_SKILL *local_1c;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x1000  1  ?Create@@YAPAVSELECT_SKILL@@PAVGAME@@@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_100025fb;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  this = operator_new(0x6bc);
  local_8 = 0;
  if (this == (void *)0x0) {
    local_1c = (SELECT_SKILL *)0x0;
  }
  else {
    local_1c = (SELECT_SKILL *)FUN_10001ba0(this,param_1);
  }
  ExceptionList = local_10;
  return local_1c;
}



void FUN_1000106e(void)

{
  undefined4 uStack_184;
  undefined4 uStack_180;
  undefined4 uStack_17c;
  undefined4 uStack_178;
  CString aCStack_170 [4];
  undefined4 uStack_16c;
  CString aCStack_164 [4];
  undefined4 uStack_160;
  undefined4 uStack_15c;
  undefined4 uStack_158;
  undefined4 uStack_154;
  CString aCStack_14c [4];
  undefined4 uStack_148;
  CString aCStack_140 [4];
  undefined4 uStack_13c;
  undefined4 uStack_138;
  undefined4 uStack_134;
  undefined4 uStack_130;
  CString aCStack_128 [4];
  undefined4 uStack_124;
  CString aCStack_11c [4];
  undefined4 uStack_118;
  undefined4 uStack_114;
  undefined4 uStack_110;
  undefined4 uStack_10c;
  CString aCStack_104 [4];
  undefined4 uStack_100;
  CString aCStack_f8 [4];
  undefined4 uStack_f4;
  CString *local_f0;
  CString *local_ec;
  undefined4 local_e8;
  CString *local_e4;
  CString *local_e0;
  undefined4 local_dc;
  CString *local_d8;
  CString *local_d4;
  undefined4 local_d0;
  undefined4 *local_cc;
  undefined4 *local_c8;
  undefined4 local_c4;
  undefined4 *local_c0;
  undefined4 *local_bc;
  undefined4 local_b8;
  undefined4 *local_b4;
  undefined4 *local_b0;
  undefined4 local_ac;
  undefined4 *local_a8;
  undefined4 *local_a4;
  undefined4 local_a0;
  undefined4 *local_9c;
  undefined4 *local_98;
  undefined4 local_94;
  undefined4 *local_90;
  undefined4 *local_8c;
  undefined4 local_88;
  undefined4 *local_84;
  undefined4 *local_80;
  undefined4 local_7c;
  undefined4 *local_78;
  undefined4 *local_74;
  undefined4 local_70;
  int local_6c;
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
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10002668;
  local_10 = ExceptionList;
  uStack_f4 = 0;
  local_14 = aCStack_f8;
  uStack_100 = 0x100010a1;
  ExceptionList = &local_10;
  local_70 = CString::CString(aCStack_f8,s_basic_on_bmp_10004020);
  uStack_100 = 0x100010bf;
  local_78 = (undefined4 *)(**(code **)(**(int **)(local_6c + 0x6b8) + 0x54))();
  local_8 = 0;
  uStack_100 = 0x100010d7;
  local_74 = local_78;
  uStack_100 = FUN_10001da0(local_78);
  local_1c = aCStack_104;
  uStack_10c = 0x100010e8;
  local_7c = CString::CString(aCStack_104,s_basic_bmp_10004030);
  uStack_10c = 0x10001106;
  local_84 = (undefined4 *)(**(code **)(**(int **)(local_6c + 0x6b8) + 0x54))();
  local_8._0_1_ = 1;
  uStack_10c = 0x1000111b;
  local_80 = local_84;
  uStack_10c = FUN_10001da0(local_84);
  uStack_110 = 0x10001131;
  (**(code **)(*(int *)(local_6c + 0x184) + 0x4c))();
  local_8 = (uint)local_8._1_3_ << 8;
  uStack_110 = 0x1000113d;
  CString::~CString(local_20);
  local_8 = 0xffffffff;
  uStack_110 = 0x1000114c;
  CString::~CString(local_18);
  uStack_110 = 0x6c;
  uStack_114 = 0x1e;
  uStack_118 = 0x10001165;
  (**(code **)(*(int *)(local_6c + 0x184) + 0x2c))();
  uStack_118 = 0;
  local_24 = aCStack_11c;
  uStack_124 = 0x10001177;
  local_88 = CString::CString(aCStack_11c,s_advanced_on_bmp_1000403c);
  uStack_124 = 0x10001198;
  local_90 = (undefined4 *)(**(code **)(**(int **)(local_6c + 0x6b8) + 0x54))();
  local_8 = 2;
  uStack_124 = 0x100011bc;
  local_8c = local_90;
  uStack_124 = FUN_10001da0(local_90);
  local_2c = aCStack_128;
  uStack_130 = 0x100011cd;
  local_94 = CString::CString(aCStack_128,s_advanced_bmp_1000404c);
  uStack_130 = 0x100011ee;
  local_9c = (undefined4 *)(**(code **)(**(int **)(local_6c + 0x6b8) + 0x54))();
  local_8._0_1_ = 3;
  uStack_130 = 0x1000120f;
  local_98 = local_9c;
  uStack_130 = FUN_10001da0(local_9c);
  uStack_134 = 0x1000121f;
  (**(code **)(*(int *)(local_6c + 8) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,2);
  uStack_134 = 0x1000122b;
  CString::~CString(local_30);
  local_8 = 0xffffffff;
  uStack_134 = 0x1000123a;
  CString::~CString(local_28);
  uStack_134 = 0x7d;
  uStack_138 = 0x13d;
  uStack_13c = 0x10001250;
  (**(code **)(*(int *)(local_6c + 8) + 0x2c))();
  uStack_13c = 0;
  local_34 = aCStack_140;
  uStack_148 = 0x10001262;
  local_a0 = CString::CString(aCStack_140,s_help_on_bmp_1000405c);
  uStack_148 = 0x10001283;
  local_a8 = (undefined4 *)(**(code **)(**(int **)(local_6c + 0x6b8) + 0x54))();
  local_8 = 4;
  uStack_148 = 0x100012a7;
  local_a4 = local_a8;
  uStack_148 = FUN_10001da0(local_a8);
  local_3c = aCStack_14c;
  uStack_154 = 0x100012b8;
  local_ac = CString::CString(aCStack_14c,s_help_bmp_10004068);
  uStack_154 = 0x100012d9;
  local_b4 = (undefined4 *)(**(code **)(**(int **)(local_6c + 0x6b8) + 0x54))();
  local_8._0_1_ = 5;
  uStack_154 = 0x100012fa;
  local_b0 = local_b4;
  uStack_154 = FUN_10001da0(local_b4);
  uStack_158 = 0x10001310;
  (**(code **)(*(int *)(local_6c + 0x300) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,4);
  uStack_158 = 0x1000131c;
  CString::~CString(local_40);
  local_8 = 0xffffffff;
  uStack_158 = 0x1000132b;
  CString::~CString(local_38);
  uStack_158 = 0xe6;
  uStack_15c = 0x4b;
  uStack_160 = 0x10001347;
  (**(code **)(*(int *)(local_6c + 0x300) + 0x2c))();
  uStack_160 = 0;
  local_44 = aCStack_164;
  uStack_16c = 0x10001359;
  local_b8 = CString::CString(aCStack_164,s_quit_on_bmp_10004074);
  uStack_16c = 0x1000137a;
  local_c0 = (undefined4 *)(**(code **)(**(int **)(local_6c + 0x6b8) + 0x54))();
  local_8 = 6;
  uStack_16c = 0x1000139e;
  local_bc = local_c0;
  uStack_16c = FUN_10001da0(local_c0);
  local_4c = aCStack_170;
  uStack_178 = 0x100013af;
  local_c4 = CString::CString(aCStack_170,s_quit_bmp_10004080);
  uStack_178 = 0x100013d0;
  local_cc = (undefined4 *)(**(code **)(**(int **)(local_6c + 0x6b8) + 0x54))();
  local_8._0_1_ = 7;
  uStack_178 = 0x100013f1;
  local_c8 = local_cc;
  uStack_178 = FUN_10001da0(local_cc);
  uStack_17c = 0x10001407;
  (**(code **)(*(int *)(local_6c + 0x47c) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,6);
  uStack_17c = 0x10001413;
  CString::~CString(local_50);
  local_8 = 0xffffffff;
  uStack_17c = 0x10001422;
  CString::~CString(local_48);
  uStack_17c = 0xe9;
  uStack_180 = 0x148;
  uStack_184 = 0x10001441;
  (**(code **)(*(int *)(local_6c + 0x47c) + 0x2c))();
  local_54 = (undefined1 *)&uStack_184;
  local_d0 = CString::CString((CString *)&uStack_184,s_Chalk_Sound_1_1000408c);
  local_d8 = (CString *)(**(code **)(**(int **)(local_6c + 0x6b8) + 0x58))();
  local_8 = 8;
  local_d4 = local_d8;
  CWave::Create((CWave *)(local_6c + 0x5f8),local_d8);
  local_8 = 0xffffffff;
  CString::~CString(local_58);
  local_5c = &stack0xfffffe74;
  local_dc = CString::CString((CString *)&stack0xfffffe74,s_Chalk_Sound_2_1000409c);
  local_e4 = (CString *)(**(code **)(**(int **)(local_6c + 0x6b8) + 0x58))();
  local_8 = 9;
  local_e0 = local_e4;
  CWave::Create((CWave *)(local_6c + 0x638),local_e4);
  local_8 = 0xffffffff;
  CString::~CString(local_60);
  local_64 = &stack0xfffffe6c;
  local_e8 = CString::CString((CString *)&stack0xfffffe6c,s_Lab_Background_100040ac);
  local_f0 = (CString *)(**(code **)(**(int **)(local_6c + 0x6b8) + 0x58))(local_68);
  local_8 = 10;
  local_ec = local_f0;
  CWave::Create((CWave *)(local_6c + 0x678),local_f0);
  local_8 = 0xffffffff;
  CString::~CString(local_68);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_1000159c(int param_1)

{
  FUN_10001a8e(param_1);
  (**(code **)(*(int *)(param_1 + 8) + 0x1c))();
  (**(code **)(*(int *)(param_1 + 0x184) + 0x1c))();
  CWave::Play((CWave *)(param_1 + 0x678),0,0,1);
  *(undefined4 *)(param_1 + 4) = 4;
  return;
}



void __fastcall FUN_100015f2(int param_1)

{
  char cVar1;
  double dVar2;
  
  cVar1 = (**(code **)(*(int *)(param_1 + 0x184) + 0x44))();
  if (cVar1 == '\0') {
    FUN_10001e00(param_1 + 0x184);
  }
  else {
    FUN_10001e20(param_1 + 0x184);
    if (DAT_10004168 == 1) {
      dVar2 = RandomProb();
      if (0.5 <= dVar2) {
        CWave::Play((CWave *)(param_1 + 0x638),0,0,0);
        DAT_10004168 = 0;
      }
      else {
        CWave::Play((CWave *)(param_1 + 0x5f8),0,0,0);
        DAT_10004168 = 0;
      }
    }
  }
  cVar1 = (**(code **)(*(int *)(param_1 + 8) + 0x44))();
  if (cVar1 == '\0') {
    FUN_10001e00(param_1 + 8);
  }
  else {
    FUN_10001e20(param_1 + 8);
    if (DAT_10004168 == 1) {
      dVar2 = RandomProb();
      if (0.5 <= dVar2) {
        CWave::Play((CWave *)(param_1 + 0x638),0,0,0);
        DAT_10004168 = 0;
      }
      else {
        CWave::Play((CWave *)(param_1 + 0x5f8),0,0,0);
        DAT_10004168 = 0;
      }
    }
  }
  cVar1 = (**(code **)(*(int *)(param_1 + 0x300) + 0x44))();
  if (cVar1 == '\0') {
    FUN_10001e00(param_1 + 0x300);
  }
  else {
    FUN_10001e20(param_1 + 0x300);
    if (DAT_10004168 == 1) {
      dVar2 = RandomProb();
      if (0.5 <= dVar2) {
        CWave::Play((CWave *)(param_1 + 0x638),0,0,0);
        DAT_10004168 = 0;
      }
      else {
        CWave::Play((CWave *)(param_1 + 0x5f8),0,0,0);
        DAT_10004168 = 0;
      }
    }
  }
  cVar1 = (**(code **)(*(int *)(param_1 + 0x47c) + 0x44))();
  if (cVar1 == '\0') {
    FUN_10001e00(param_1 + 0x47c);
  }
  else {
    FUN_10001e20(param_1 + 0x47c);
    if (DAT_10004168 == 1) {
      dVar2 = RandomProb();
      if (0.5 <= dVar2) {
        CWave::Play((CWave *)(param_1 + 0x638),0,0,0);
        DAT_10004168 = 0;
      }
      else {
        CWave::Play((CWave *)(param_1 + 0x5f8),0,0,0);
        DAT_10004168 = 0;
      }
    }
  }
  cVar1 = (**(code **)(*(int *)(param_1 + 0x184) + 0x44))();
  if ((((cVar1 == '\0') && (cVar1 = (**(code **)(*(int *)(param_1 + 8) + 0x44))(), cVar1 == '\0'))
      && (cVar1 = (**(code **)(*(int *)(param_1 + 0x300) + 0x44))(), cVar1 == '\0')) &&
     (cVar1 = (**(code **)(*(int *)(param_1 + 0x47c) + 0x44))(), cVar1 == '\0')) {
    DAT_10004168 = 1;
  }
  (**(code **)(*(int *)(param_1 + 0x184) + 0x14))();
  (**(code **)(*(int *)(param_1 + 8) + 0x14))();
  (**(code **)(*(int *)(param_1 + 0x47c) + 0x14))();
  (**(code **)(*(int *)(param_1 + 0x300) + 0x14))();
  return;
}



void __fastcall FUN_1000191b(int param_1)

{
  char cVar1;
  
  cVar1 = (**(code **)(*(int *)(param_1 + 0x184) + 0x44))();
  if (cVar1 == '\0') {
    cVar1 = (**(code **)(*(int *)(param_1 + 8) + 0x44))();
    if (cVar1 == '\0') {
      cVar1 = (**(code **)(*(int *)(param_1 + 0x47c) + 0x44))();
      if (cVar1 == '\0') {
        cVar1 = (**(code **)(*(int *)(param_1 + 0x300) + 0x44))();
        if (cVar1 != '\0') {
          (**(code **)(**(int **)(param_1 + 0x6b8) + 0x5c))();
        }
      }
      else {
        GAME::ChangeState(*(GAME **)(param_1 + 0x6b8),3);
      }
    }
    else {
      (**(code **)(**(int **)(param_1 + 0x6b8) + 0x50))(1);
      GAME::ChangeState(*(GAME **)(param_1 + 0x6b8),2);
    }
  }
  else {
    (**(code **)(**(int **)(param_1 + 0x6b8) + 0x50))(0);
    GAME::ChangeState(*(GAME **)(param_1 + 0x6b8),2);
  }
  return;
}



void __fastcall FUN_10001a1d(int param_1)

{
  (**(code **)(*(int *)(param_1 + 8) + 0x20))();
  (**(code **)(*(int *)(param_1 + 0x184) + 0x20))();
  CWave::Stop((CWave *)(param_1 + 0x678));
  CWave::Stop((CWave *)(param_1 + 0x5f8));
  CWave::Stop((CWave *)(param_1 + 0x638));
  return;
}



void __fastcall FUN_10001a79(int param_1)

{
  FUN_10001a8e(param_1);
  return;
}



void __fastcall FUN_10001a8e(int param_1)

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
  puStack_c = &this_10002684;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  GKERNEL::NewSpriteBackground();
  uVar7 = 0;
  pHVar6 = (HINSTANCE__ *)0x0;
  iVar5 = 0;
  local_14 = &stack0xffffffac;
  uVar4 = extraout_ECX;
  CString::CString((CString *)&stack0xffffffac,s_blackboard_bmp_100040bc);
  pCVar3 = local_18;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x6b8) + 0x54))();
  local_8 = 0;
  pcVar2 = (char *)FUN_10001da0(puVar1);
  GKTOOLS::CopyDIBToBack(pcVar2,(uint)pCVar3,uVar4,iVar5,pHVar6,(bool)uVar7);
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  GKERNEL::Flip();
  uVar7 = 0;
  pHVar6 = (HINSTANCE__ *)0x0;
  iVar5 = 0;
  local_1c = &stack0xffffffa4;
  uVar4 = extraout_ECX_00;
  CString::CString((CString *)&stack0xffffffa4,s_blackboard_bmp_100040cc);
  pCVar3 = local_20;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x6b8) + 0x54))();
  local_8 = 1;
  pcVar2 = (char *)FUN_10001da0(puVar1);
  GKTOOLS::CopyDIBToBack(pcVar2,(uint)pCVar3,uVar4,iVar5,pHVar6,(bool)uVar7);
  local_8 = 0xffffffff;
  CString::~CString(local_20);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_10001ba0(void *this,undefined4 param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100026f2;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10001d80((undefined4 *)this);
  local_8 = 0;
  *(undefined4 *)((int)this + 4) = 4;
  FUN_10001e70((OVERLAY *)((int)this + 8));
  local_8._0_1_ = 1;
  FUN_10001e70((OVERLAY *)((int)this + 0x184));
  local_8._0_1_ = 2;
  FUN_10001e70((OVERLAY *)((int)this + 0x300));
  local_8._0_1_ = 3;
  FUN_10001e70((OVERLAY *)((int)this + 0x47c));
  local_8._0_1_ = 4;
  CWave::CWave((CWave *)((int)this + 0x5f8));
  local_8._0_1_ = 5;
  CWave::CWave((CWave *)((int)this + 0x638));
  local_8 = CONCAT31(local_8._1_3_,6);
  CWave::CWave((CWave *)((int)this + 0x678));
  *(undefined4 *)((int)this + 0x6b8) = param_1;
  *(undefined ***)this = &PTR_FUN_100030f8;
  ExceptionList = local_10;
  return this;
}



void * __thiscall FUN_10001c80(void *this,uint param_1)

{
  FUN_10001cb0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10001cb0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &this_10002762;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_FUN_100030f8;
  local_8 = 6;
  CWave::~CWave((CWave *)(param_1 + 0x19e));
  local_8._0_1_ = 5;
  CWave::~CWave((CWave *)(param_1 + 0x18e));
  local_8._0_1_ = 4;
  CWave::~CWave((CWave *)(param_1 + 0x17e));
  local_8._0_1_ = 3;
  FUN_100020d0(param_1 + 0x11f);
  local_8._0_1_ = 2;
  FUN_100020d0(param_1 + 0xc0);
  local_8._0_1_ = 1;
  FUN_100020d0(param_1 + 0x61);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_100020d0(param_1 + 2);
  local_8 = 0xffffffff;
  FUN_10001db0(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_10001d80(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_10003114;
  return param_1;
}



undefined4 __fastcall FUN_10001da0(undefined4 *param_1)

{
  return *param_1;
}



void __fastcall FUN_10001db0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_10003114;
  return;
}



void * __thiscall FUN_10001dd0(void *this,uint param_1)

{
  FUN_10001db0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10001e00(int param_1)

{
  *(undefined4 *)(param_1 + 0xd4) = 0;
  FUN_10001e40(param_1);
  return;
}



void __fastcall FUN_10001e20(int param_1)

{
  *(undefined4 *)(param_1 + 0xd4) = 1;
  FUN_10001e40(param_1);
  return;
}



void __fastcall FUN_10001e40(int param_1)

{
  *(undefined4 *)(param_1 + 0x178) = 1;
  *(undefined4 *)(param_1 + 0x174) = 0;
  return;
}



OVERLAY * __fastcall FUN_10001e70(OVERLAY *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_10002789;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  OVERLAY::OVERLAY(param_1);
  local_8 = 0;
  FUN_10001ef0((DWORD *)(param_1 + 0xd0));
  DD_SURFACE::DD_SURFACE((DD_SURFACE *)(param_1 + 0xdc));
  local_8 = CONCAT31(local_8._1_3_,1);
  *(undefined ***)param_1 = &PTR_FUN_1000313c;
  *(undefined ***)(param_1 + 8) = &PTR_FUN_10003138;
  FUN_10001e00((int)param_1);
  ExceptionList = local_10;
  return param_1;
}



DWORD * __fastcall FUN_10001ef0(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
  return param_1;
}



void FUN_10001f10(void)

{
  return;
}



void FUN_10001f20(void)

{
  return;
}



undefined1 __fastcall FUN_10001f30(int param_1)

{
  return *(undefined1 *)(param_1 + 0xcc);
}



void __fastcall FUN_10001f50(int param_1)

{
  *(undefined1 *)(param_1 + 0xcc) = 1;
  return;
}



void __fastcall FUN_10001f70(int param_1)

{
  *(undefined1 *)(param_1 + 0xcc) = 0;
  return;
}



void __thiscall FUN_10001f90(void *this,undefined4 *param_1)

{
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x2c))(*param_1,param_1[1]);
  return;
}



undefined1 __fastcall FUN_10001fc0(int param_1)

{
  return *(undefined1 *)(param_1 + 0xa0);
}



void * __thiscall FUN_10001fe0(void *this,uint param_1)

{
  FUN_100020d0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10002010(undefined4 *param_1)

{
  DD_SURFACE *local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_100027a9;
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
  FUN_10002080(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10002080(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1000318c;
  return;
}



void * __thiscall FUN_100020a0(void *this,uint param_1)

{
  FUN_10002080((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_100020d0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_100027c9;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(param_1 + 0x37));
  local_8 = 0xffffffff;
  FUN_10002010(param_1);
  ExceptionList = local_10;
  return;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002120. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002126. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void __thiscall CString::~CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x1000212c. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CString(this);
  return;
}



void __thiscall CString::CString(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002132. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



void * __thiscall FUN_1000216a(void *this,byte param_1)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)this);
  if ((param_1 & 1) != 0) {
    CNoTrackObject::operator_delete(this);
  }
  return this;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x10002592. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



int FUN_100021e5(HINSTANCE__ *param_1,int param_2)

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
      pAVar5 = AfxSetModuleState((AFX_MODULE_STATE *)&param_1_10004170);
      p_Var3 = AfxGetThreadState();
      *(AFX_MODULE_STATE **)(p_Var3 + 8) = pAVar5;
      pAVar5 = AfxGetModuleState();
      if (*(int **)(pAVar5 + 4) != (int *)0x0) {
        (**(code **)(**(int **)(pAVar5 + 4) + 0x70))();
      }
      AfxLockTempMaps();
      AfxUnlockTempMaps(-1);
      AfxWinTerm();
      AfxTermExtensionModule((AFX_EXTENSION_MODULE *)&param_1_10005200,1);
    }
    else if (param_2 == 3) {
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
                ((AFX_MAINTAIN_STATE2 *)&local_c,(AFX_MODULE_STATE *)&param_1_10004170);
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
  iVar4 = AfxWinInit(param_1,(HINSTANCE__ *)0x0,(char *)&param_3_100031bc,0);
  if (iVar4 != 0) {
    pAVar5 = AfxGetModuleState();
    piVar2 = *(int **)(pAVar5 + 4);
    if ((piVar2 == (int *)0x0) || (iVar4 = (**(code **)(*piVar2 + 0x58))(), iVar4 != 0)) {
      *(undefined4 *)(p_Var3 + 8) = uVar1;
      AfxInitExtensionModule((AFX_EXTENSION_MODULE *)&param_1_10005200,param_1);
      this = (CDynLinkLibrary *)operator_new(0x40);
      if (this != (CDynLinkLibrary *)0x0) {
        CDynLinkLibrary::CDynLinkLibrary(this,(AFX_EXTENSION_MODULE *)&param_1_10005200,0);
      }
      param_2 = 1;
      goto LAB_10002271;
    }
    (**(code **)(*piVar2 + 0x70))();
  }
  AfxWinTerm();
LAB_10002271:
  *(undefined4 *)(p_Var3 + 8) = uVar1;
  p_Var3 = AfxGetThreadState();
  AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var3 + 8));
  return param_2;
}



undefined4 FUN_1000230c(undefined4 param_1,int param_2)

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
    pAVar2 = AfxSetModuleState((AFX_MODULE_STATE *)&param_1_10004170);
    *(AFX_MODULE_STATE **)(p_Var1 + 8) = pAVar2;
  }
  else if (param_2 == 0) {
    p_Var1 = AfxGetThreadState();
    AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var1 + 8));
  }
  return 1;
}



void __fastcall FUN_1000235d(undefined4 *param_1)

{
  *(undefined4 *)(param_1[1] + 4) = *param_1;
  return;
}



void __CxxFrameHandler(void)

{
                    // WARNING: Could not recover jumptable at 0x10002366. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10002376(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 *_Memory;
  undefined4 *puVar2;
  
  if (param_2 == 0) {
    if (0 < DAT_1000521c) {
      DAT_1000521c = DAT_1000521c + -1;
      goto LAB_1000238c;
    }
LAB_100023b4:
    uVar1 = 0;
  }
  else {
LAB_1000238c:
    _DAT_10005220 = *(undefined4 *)_adjust_fdiv_exref;
    if (param_2 == 1) {
      DAT_10005228 = (undefined4 *)malloc(0x80);
      if (DAT_10005228 == (undefined4 *)0x0) goto LAB_100023b4;
      *DAT_10005228 = 0;
      DAT_10005224 = DAT_10005228;
      initterm(&DAT_10004000,&DAT_10004008);
      DAT_1000521c = DAT_1000521c + 1;
    }
    else if ((param_2 == 0) &&
            (_Memory = DAT_10005228, puVar2 = DAT_10005224, DAT_10005228 != (undefined4 *)0x0)) {
      while (puVar2 = puVar2 + -1, _Memory <= puVar2) {
        if ((code *)*puVar2 != (code *)0x0) {
          (*(code *)*puVar2)();
          _Memory = DAT_10005228;
        }
      }
      free(_Memory);
      DAT_10005228 = (undefined4 *)0x0;
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
  iVar2 = DAT_1000521c;
  if (param_2 != 0) {
    if ((param_2 != 1) && (param_2 != 2)) goto LAB_10002469;
    if ((PTR_FUN_100040dc != (undefined *)0x0) &&
       (iVar2 = (*(code *)PTR_FUN_100040dc)(param_1,param_2,param_3), iVar2 == 0)) {
      return 0;
    }
    iVar2 = FUN_10002376(param_1,param_2);
  }
  if (iVar2 == 0) {
    return 0;
  }
LAB_10002469:
  iVar2 = FUN_100021e5(param_1,param_2);
  if (param_2 == 1) {
    if (iVar2 != 0) {
      return iVar2;
    }
    FUN_10002376(param_1,0);
  }
  if ((param_2 != 0) && (param_2 != 3)) {
    return iVar2;
  }
  iVar3 = FUN_10002376(param_1,param_2);
  param_2 = iVar2;
  if (iVar3 == 0) {
    param_2 = 0;
  }
  if (param_2 != 0) {
    if (PTR_FUN_100040dc != (undefined *)0x0) {
      iVar2 = (*(code *)PTR_FUN_100040dc)(param_1,iVar1,param_3);
      return iVar2;
    }
    return param_2;
  }
  return 0;
}



void * __thiscall FUN_100024be(void *this,byte param_1)

{
  type_info::~type_info((type_info *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __cdecl initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x10002538. Too many branches
                    // WARNING: Treating indirect jump as call
  initterm();
  return;
}



void __thiscall type_info::~type_info(type_info *this)

{
                    // WARNING: Could not recover jumptable at 0x1000253e. Too many branches
                    // WARNING: Treating indirect jump as call
  ~type_info(this);
  return;
}



void CNoTrackObject::operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000258c. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x10002592. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



void __thiscall
AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(AFX_MAINTAIN_STATE2 *this,AFX_MODULE_STATE *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000259e. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MAINTAIN_STATE2(this,param_1);
  return;
}



void AfxTermThread(HINSTANCE__ *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100025a4. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermThread(param_1);
  return;
}



void AfxTermExtensionModule(AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x100025aa. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermExtensionModule(param_1,param_2);
  return;
}



int AfxUnlockTempMaps(int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x100025b0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxUnlockTempMaps(param_1);
  return iVar1;
}



void AfxLockTempMaps(void)

{
                    // WARNING: Could not recover jumptable at 0x100025b6. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxLockTempMaps();
  return;
}



AFX_MODULE_STATE * AfxSetModuleState(AFX_MODULE_STATE *param_1)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x100025bc. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxSetModuleState(param_1);
  return pAVar1;
}



void __thiscall
CDynLinkLibrary::CDynLinkLibrary(CDynLinkLibrary *this,AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x100025c2. Too many branches
                    // WARNING: Treating indirect jump as call
  CDynLinkLibrary(this,param_1,param_2);
  return;
}



int AfxInitExtensionModule(AFX_EXTENSION_MODULE *param_1,HINSTANCE__ *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x100025c8. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxInitExtensionModule(param_1,param_2);
  return iVar1;
}



void AfxWinTerm(void)

{
                    // WARNING: Could not recover jumptable at 0x100025ce. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxWinTerm();
  return;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x100025d4. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



int AfxWinInit(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x100025da. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinInit(param_1,param_2,param_3,param_4);
  return iVar1;
}



_AFX_THREAD_STATE * AfxGetThreadState(void)

{
  _AFX_THREAD_STATE *p_Var1;
  
                    // WARNING: Could not recover jumptable at 0x100025e0. Too many branches
                    // WARNING: Treating indirect jump as call
  p_Var1 = AfxGetThreadState();
  return p_Var1;
}



void AfxCoreInitModule(void)

{
                    // WARNING: Could not recover jumptable at 0x100025e6. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxCoreInitModule();
  return;
}



void Unwind_100025f0(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x14));
  return;
}



void Unwind_10002605(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000260e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_10002617(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_10002620(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_10002629(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_10002632(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_1000263b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x44));
  return;
}



void Unwind_10002644(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x4c));
  return;
}



void Unwind_1000264d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x54));
  return;
}



void Unwind_10002656(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x5c));
  return;
}



void Unwind_1000265f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -100));
  return;
}



void Unwind_10002672(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000267b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_10002690(void)

{
  int unaff_EBP;
  
  FUN_10001db0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10002699(void)

{
  int unaff_EBP;
  
  FUN_100020d0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 8));
  return;
}



void Unwind_100026a5(void)

{
  int unaff_EBP;
  
  FUN_100020d0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x184));
  return;
}



void Unwind_100026b4(void)

{
  int unaff_EBP;
  
  FUN_100020d0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x300));
  return;
}



void Unwind_100026c3(void)

{
  int unaff_EBP;
  
  FUN_100020d0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x47c));
  return;
}



void Unwind_100026d2(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x5f8));
  return;
}



void Unwind_100026e2(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x638));
  return;
}



void Unwind_10002700(void)

{
  int unaff_EBP;
  
  FUN_10001db0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10002709(void)

{
  int unaff_EBP;
  
  FUN_100020d0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 8));
  return;
}



void Unwind_10002715(void)

{
  int unaff_EBP;
  
  FUN_100020d0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x184));
  return;
}



void Unwind_10002724(void)

{
  int unaff_EBP;
  
  FUN_100020d0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x300));
  return;
}



void Unwind_10002733(void)

{
  int unaff_EBP;
  
  FUN_100020d0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x47c));
  return;
}



void Unwind_10002742(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x5f8));
  return;
}



void Unwind_10002752(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x638));
  return;
}



void Unwind_10002770(void)

{
  int unaff_EBP;
  
  FUN_10002010(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10002779(void)

{
  int unaff_EBP;
  
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(*(int *)(unaff_EBP + -0x10) + 0xdc));
  return;
}



void Unwind_100027a0(void)

{
  int unaff_EBP;
  
  FUN_10002080(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100027c0(void)

{
  int unaff_EBP;
  
  FUN_10002010(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100027d4(void)

{
  int unaff_EBP;
  
  FUN_1000235d((undefined4 *)(unaff_EBP + -0x14));
  return;
}


