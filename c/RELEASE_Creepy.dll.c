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

typedef struct CMidi CMidi, *PCMidi;

struct CMidi { // PlaceHolder Structure
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
  puStack_c = &LAB_100025bb;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  this = operator_new(0x818);
  local_8 = 0;
  if (this == (void *)0x0) {
    local_1c = (SELECT_SKILL1 *)0x0;
  }
  else {
    local_1c = (SELECT_SKILL1 *)FUN_10001990(this,param_1);
  }
  ExceptionList = local_10;
  return local_1c;
}



void FUN_1000106e(void)

{
  char *pcVar1;
  undefined4 uStack_1b0;
  undefined4 uStack_1ac;
  undefined4 uStack_1a8;
  undefined4 uStack_1a4;
  CString aCStack_19c [4];
  undefined4 uStack_198;
  CString aCStack_190 [4];
  undefined4 uStack_18c;
  undefined4 uStack_188;
  undefined4 uStack_184;
  undefined4 uStack_180;
  CString aCStack_178 [4];
  undefined4 uStack_174;
  CString aCStack_16c [4];
  undefined4 uStack_168;
  undefined4 uStack_164;
  undefined4 uStack_160;
  undefined4 uStack_15c;
  CString aCStack_154 [4];
  undefined4 uStack_150;
  CString aCStack_148 [4];
  undefined4 uStack_144;
  undefined4 uStack_140;
  undefined4 uStack_13c;
  undefined4 uStack_138;
  CString aCStack_130 [4];
  undefined4 uStack_12c;
  undefined4 uStack_124;
  CString aCStack_108 [4];
  undefined4 *local_104;
  undefined4 *local_100;
  undefined4 local_fc;
  undefined4 *local_f8;
  undefined4 *local_f4;
  undefined4 local_f0;
  undefined4 *local_ec;
  undefined4 *local_e8;
  undefined4 local_e4;
  undefined4 *local_e0;
  undefined4 *local_dc;
  undefined4 local_d8;
  undefined4 *local_d4;
  undefined4 *local_d0;
  undefined4 local_cc;
  undefined4 *local_c8;
  undefined4 *local_c4;
  undefined4 local_c0;
  undefined4 *local_bc;
  undefined4 *local_b8;
  undefined4 local_b4;
  undefined4 *local_b0;
  undefined4 *local_ac;
  undefined4 local_a8;
  undefined4 *local_a4;
  undefined4 *local_a0;
  undefined4 local_9c;
  CString *local_98;
  CString *local_94;
  undefined4 local_90;
  CString *local_8c;
  CString *local_88;
  undefined4 local_84;
  CString *local_80;
  CString *local_7c;
  undefined4 local_78;
  int local_74;
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
  puStack_c = &this_10002631;
  local_10 = ExceptionList;
  local_14 = aCStack_108;
  ExceptionList = &local_10;
  local_78 = CString::CString(aCStack_108,s_wood_coffin_wav_10004020);
  local_80 = (CString *)(**(code **)(**(int **)(local_74 + 0x814) + 0x58))();
  local_8 = 0;
  local_7c = local_80;
  CWave::Create((CWave *)(local_74 + 0x600),local_80);
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  local_1c = &stack0xfffffef0;
  local_84 = CString::CString((CString *)&stack0xfffffef0,s_stone_squish_coffin_wav_10004030);
  local_8c = (CString *)(**(code **)(**(int **)(local_74 + 0x814) + 0x58))();
  local_8 = 1;
  local_88 = local_8c;
  CWave::Create((CWave *)(local_74 + 0x640),local_8c);
  local_8 = 0xffffffff;
  CString::~CString(local_20);
  local_24 = &stack0xfffffee8;
  local_90 = CString::CString((CString *)&stack0xfffffee8,s_stone_coffin_wav_10004048);
  local_98 = (CString *)(**(code **)(**(int **)(local_74 + 0x814) + 0x58))();
  local_8 = 2;
  uStack_124 = 0x100011bb;
  local_94 = local_98;
  CWave::Create((CWave *)(local_74 + 0x680),local_98);
  local_8 = 0xffffffff;
  CString::~CString(local_28);
  local_2c = (undefined1 *)&uStack_124;
  uStack_12c = 0x100011dc;
  local_9c = CString::CString((CString *)&uStack_124,s_suspense_bmp_1000405c);
  uStack_12c = 0x100011fd;
  local_a4 = (undefined4 *)(**(code **)(**(int **)(local_74 + 0x814) + 0x54))();
  local_8 = 3;
  uStack_12c = 0x10001221;
  local_a0 = local_a4;
  uStack_12c = FUN_10001cf0(local_a4);
  local_34 = aCStack_130;
  uStack_138 = 0x10001232;
  local_a8 = CString::CString(aCStack_130,s_suspense_up_bmp_1000406c);
  uStack_138 = 0x10001253;
  local_b0 = (undefined4 *)(**(code **)(**(int **)(local_74 + 0x814) + 0x54))();
  local_8._0_1_ = 4;
  uStack_138 = 0x10001274;
  local_ac = local_b0;
  uStack_138 = FUN_10001cf0(local_b0);
  uStack_13c = 0x10001284;
  (**(code **)(*(int *)(local_74 + 4) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,3);
  uStack_13c = 0x10001290;
  CString::~CString(local_38);
  local_8 = 0xffffffff;
  uStack_13c = 0x1000129f;
  CString::~CString(local_30);
  uStack_13c = 0x5b;
  uStack_140 = 0x25;
  uStack_144 = 0x100012b2;
  (**(code **)(*(int *)(local_74 + 4) + 0x2c))();
  uStack_144 = 0;
  local_3c = aCStack_148;
  uStack_150 = 0x100012c4;
  local_b4 = CString::CString(aCStack_148,s_fright_bmp_1000407c);
  uStack_150 = 0x100012e5;
  local_bc = (undefined4 *)(**(code **)(**(int **)(local_74 + 0x814) + 0x54))();
  local_8 = 5;
  uStack_150 = 0x10001309;
  local_b8 = local_bc;
  uStack_150 = FUN_10001cf0(local_bc);
  local_44 = aCStack_154;
  uStack_15c = 0x1000131a;
  local_c0 = CString::CString(aCStack_154,s_fright_up_bmp_10004088);
  uStack_15c = 0x1000133b;
  local_c8 = (undefined4 *)(**(code **)(**(int **)(local_74 + 0x814) + 0x54))();
  local_8._0_1_ = 6;
  uStack_15c = 0x1000135c;
  local_c4 = local_c8;
  uStack_15c = FUN_10001cf0(local_c8);
  uStack_160 = 0x10001372;
  (**(code **)(*(int *)(local_74 + 0x184) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,5);
  uStack_160 = 0x1000137e;
  CString::~CString(local_48);
  local_8 = 0xffffffff;
  uStack_160 = 0x1000138d;
  CString::~CString(local_40);
  uStack_160 = 0xb5;
  uStack_164 = 0x27;
  uStack_168 = 0x100013a9;
  (**(code **)(*(int *)(local_74 + 0x184) + 0x2c))();
  uStack_168 = 0;
  local_4c = aCStack_16c;
  uStack_174 = 0x100013bb;
  local_cc = CString::CString(aCStack_16c,s_terror_bmp_10004098);
  uStack_174 = 0x100013dc;
  local_d4 = (undefined4 *)(**(code **)(**(int **)(local_74 + 0x814) + 0x54))();
  local_8 = 7;
  uStack_174 = 0x10001400;
  local_d0 = local_d4;
  uStack_174 = FUN_10001cf0(local_d4);
  local_54 = aCStack_178;
  uStack_180 = 0x10001411;
  local_d8 = CString::CString(aCStack_178,s_terror_up_bmp_100040a4);
  uStack_180 = 0x10001432;
  local_e0 = (undefined4 *)(**(code **)(**(int **)(local_74 + 0x814) + 0x54))();
  local_8._0_1_ = 8;
  uStack_180 = 0x10001453;
  local_dc = local_e0;
  uStack_180 = FUN_10001cf0(local_e0);
  uStack_184 = 0x10001469;
  (**(code **)(*(int *)(local_74 + 0x304) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,7);
  uStack_184 = 0x10001475;
  CString::~CString(local_58);
  local_8 = 0xffffffff;
  uStack_184 = 0x10001484;
  CString::~CString(local_50);
  uStack_184 = 0x10f;
  uStack_188 = 0x25;
  uStack_18c = 0x100014a0;
  (**(code **)(*(int *)(local_74 + 0x304) + 0x2c))();
  uStack_18c = 0;
  local_5c = aCStack_190;
  uStack_198 = 0x100014b2;
  local_e4 = CString::CString(aCStack_190,s_exit_dn_bmp_100040b4);
  uStack_198 = 0x100014d3;
  local_ec = (undefined4 *)(**(code **)(**(int **)(local_74 + 0x814) + 0x54))();
  local_8 = 9;
  uStack_198 = 0x100014f7;
  local_e8 = local_ec;
  uStack_198 = FUN_10001cf0(local_ec);
  local_64 = aCStack_19c;
  uStack_1a4 = 0x10001508;
  local_f0 = CString::CString(aCStack_19c,s_exit_up_bmp_100040c0);
  uStack_1a4 = 0x10001529;
  local_f8 = (undefined4 *)(**(code **)(**(int **)(local_74 + 0x814) + 0x54))();
  local_8._0_1_ = 10;
  uStack_1a4 = 0x1000154a;
  local_f4 = local_f8;
  uStack_1a4 = FUN_10001cf0(local_f8);
  uStack_1a8 = 0x10001560;
  (**(code **)(*(int *)(local_74 + 0x484) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,9);
  uStack_1a8 = 0x1000156c;
  CString::~CString(local_68);
  local_8 = 0xffffffff;
  uStack_1a8 = 0x1000157b;
  CString::~CString(local_60);
  uStack_1a8 = 0x29;
  uStack_1ac = 0xf;
  uStack_1b0 = 0x10001594;
  (**(code **)(*(int *)(local_74 + 0x484) + 0x2c))();
  uStack_1b0 = 0x100015a3;
  CMidi::Init((CMidi *)(local_74 + 0x6c0));
  local_6c = (undefined1 *)&uStack_1b0;
  local_fc = CString::CString((CString *)&uStack_1b0,s_creepy_mid_100040cc);
  local_104 = (undefined4 *)(**(code **)(**(int **)(local_74 + 0x814) + 0x58))(local_70);
  local_8 = 0xb;
  local_100 = local_104;
  pcVar1 = (char *)FUN_10001cf0(local_104);
  CMidi::LoadSong((CMidi *)(local_74 + 0x6c0),pcVar1);
  local_8 = 0xffffffff;
  CString::~CString(local_70);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10001625(int param_1)

{
  CMidi::Play((CMidi *)(param_1 + 0x6c0),0,0,0,0);
  FUN_100018d0(param_1);
  return;
}



void __fastcall FUN_1000164f(int param_1)

{
  char cVar1;
  
  cVar1 = (**(code **)(*(int *)(param_1 + 4) + 0x44))();
  if (cVar1 == '\0') {
    FUN_10001dd0(param_1 + 4);
  }
  else {
    FUN_10001cb0(param_1 + 4);
  }
  (**(code **)(*(int *)(param_1 + 4) + 0x14))();
  cVar1 = (**(code **)(*(int *)(param_1 + 0x184) + 0x44))();
  if (cVar1 == '\0') {
    FUN_10001dd0(param_1 + 0x184);
  }
  else {
    FUN_10001cb0(param_1 + 0x184);
  }
  (**(code **)(*(int *)(param_1 + 0x184) + 0x14))();
  cVar1 = (**(code **)(*(int *)(param_1 + 0x304) + 0x44))();
  if (cVar1 == '\0') {
    FUN_10001dd0(param_1 + 0x304);
  }
  else {
    FUN_10001cb0(param_1 + 0x304);
  }
  (**(code **)(*(int *)(param_1 + 0x304) + 0x14))();
  cVar1 = (**(code **)(*(int *)(param_1 + 0x484) + 0x44))();
  if (cVar1 == '\0') {
    FUN_10001dd0(param_1 + 0x484);
  }
  else {
    FUN_10001df0(param_1 + 0x484);
  }
  (**(code **)(*(int *)(param_1 + 0x484) + 0x14))();
  return;
}



void __fastcall FUN_1000178c(int param_1)

{
  char cVar1;
  
  cVar1 = (**(code **)(*(int *)(param_1 + 4) + 0x44))();
  if (cVar1 == '\0') {
    cVar1 = (**(code **)(*(int *)(param_1 + 0x184) + 0x44))();
    if (cVar1 == '\0') {
      cVar1 = (**(code **)(*(int *)(param_1 + 0x304) + 0x44))();
      if (cVar1 == '\0') {
        cVar1 = (**(code **)(*(int *)(param_1 + 0x484) + 0x44))();
        if (cVar1 != '\0') {
          GAME::ChangeState(*(GAME **)(param_1 + 0x814),3);
        }
      }
      else {
        (**(code **)(**(int **)(param_1 + 0x814) + 0x50))(2);
        GAME::ChangeState(*(GAME **)(param_1 + 0x814),2);
      }
    }
    else {
      (**(code **)(**(int **)(param_1 + 0x814) + 0x50))(1);
      GAME::ChangeState(*(GAME **)(param_1 + 0x814),2);
    }
  }
  else {
    (**(code **)(**(int **)(param_1 + 0x814) + 0x50))(0);
    GAME::ChangeState(*(GAME **)(param_1 + 0x814),2);
  }
  return;
}



void __fastcall FUN_100018a1(int param_1)

{
  CMidi::Stop((CMidi *)(param_1 + 0x6c0));
  return;
}



void __fastcall FUN_100018bb(int param_1)

{
  FUN_100018d0(param_1);
  return;
}



void __fastcall FUN_100018d0(int param_1)

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
  puStack_c = &LAB_10002644;
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
    CString::CString((CString *)&stack0xffffffbc,s_crypt_bmp_100040d8);
    puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 0x814) + 0x54))(local_1c);
    local_8 = 0;
    pcVar2 = (char *)FUN_10001cf0(puVar1);
    GKTOOLS::CopyDIBToBack(pcVar2,uVar3,uVar4,iVar5,pHVar6,(bool)uVar7);
    local_8 = 0xffffffff;
    CString::~CString(local_1c);
    GKERNEL::Flip();
  }
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_10001990(void *this,undefined4 param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100026c2;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10001c70((undefined4 *)this);
  local_8 = 0;
  FUN_10001aa0((void *)((int)this + 4),(int)this + 0x600);
  local_8._0_1_ = 1;
  FUN_10001aa0((void *)((int)this + 0x184),(int)this + 0x640);
  local_8._0_1_ = 2;
  FUN_10001aa0((void *)((int)this + 0x304),(int)this + 0x680);
  local_8._0_1_ = 3;
  FUN_10001e60((OVERLAY *)((int)this + 0x484));
  local_8._0_1_ = 4;
  CWave::CWave((CWave *)((int)this + 0x600));
  local_8._0_1_ = 5;
  CWave::CWave((CWave *)((int)this + 0x640));
  local_8._0_1_ = 6;
  CWave::CWave((CWave *)((int)this + 0x680));
  local_8 = CONCAT31(local_8._1_3_,7);
  CMidi::CMidi((CMidi *)((int)this + 0x6c0));
  *(undefined4 *)((int)this + 0x814) = param_1;
  *(undefined ***)this = &PTR_FUN_10003108;
  ExceptionList = local_10;
  return this;
}



void * __thiscall FUN_10001aa0(void *this,undefined4 param_1)

{
  FUN_10001e60((OVERLAY *)this);
  *(undefined4 *)((int)this + 0x17c) = param_1;
  *(undefined ***)this = &PTR_FUN_10003130;
  *(undefined ***)((int)this + 8) = &PTR_FUN_1000312c;
  return this;
}



void * __thiscall FUN_10001ae0(void *this,uint param_1)

{
  FUN_10001b10((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10001b10(undefined4 *param_1)

{
  FUN_10001ff0(param_1);
  return;
}



void FUN_10001b30(undefined4 *param_1,undefined4 *param_2)

{
  *param_1 = 0x18d;
  *param_2 = 0x13;
  return;
}



undefined1 FUN_10001b50(void)

{
  return 0;
}



void * __thiscall FUN_10001b60(void *this,uint param_1)

{
  FUN_10001b90((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10001b90(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &this_10002742;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_FUN_10003108;
  local_8 = 7;
  CMidi::~CMidi((CMidi *)(param_1 + 0x1b0));
  local_8._0_1_ = 6;
  CWave::~CWave((CWave *)(param_1 + 0x1a0));
  local_8._0_1_ = 5;
  CWave::~CWave((CWave *)(param_1 + 400));
  local_8._0_1_ = 4;
  CWave::~CWave((CWave *)(param_1 + 0x180));
  local_8._0_1_ = 3;
  FUN_10001ff0(param_1 + 0x121);
  local_8._0_1_ = 2;
  FUN_10001b10(param_1 + 0xc1);
  local_8._0_1_ = 1;
  FUN_10001b10(param_1 + 0x61);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_10001b10(param_1 + 1);
  local_8 = 0xffffffff;
  FUN_10002090(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_10001c70(undefined4 *param_1)

{
  FUN_10001c90(param_1);
  *param_1 = &PTR_FUN_10003180;
  return param_1;
}



undefined4 * __fastcall FUN_10001c90(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_100031a4;
  return param_1;
}



void __fastcall FUN_10001cb0(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_10001e10(param_1);
  if (iVar1 == 0) {
    CWave::Play(*(CWave **)(param_1 + 0x17c),0,0,0);
  }
  FUN_10001df0(param_1);
  return;
}



undefined4 __fastcall FUN_10001cf0(undefined4 *param_1)

{
  return *param_1;
}



void FUN_10001d00(void)

{
  return;
}



void FUN_10001d10(void)

{
  return;
}



undefined1 __fastcall FUN_10001d20(int param_1)

{
  return *(undefined1 *)(param_1 + 0xcc);
}



void __fastcall FUN_10001d40(int param_1)

{
  *(undefined1 *)(param_1 + 0xcc) = 1;
  return;
}



void __fastcall FUN_10001d60(int param_1)

{
  *(undefined1 *)(param_1 + 0xcc) = 0;
  return;
}



void __thiscall FUN_10001d80(void *this,undefined4 *param_1)

{
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x2c))(*param_1,param_1[1]);
  return;
}



undefined1 __fastcall FUN_10001db0(int param_1)

{
  return *(undefined1 *)(param_1 + 0xa0);
}



void __fastcall FUN_10001dd0(int param_1)

{
  *(undefined4 *)(param_1 + 0xd4) = 0;
  FUN_10001e30(param_1);
  return;
}



void __fastcall FUN_10001df0(int param_1)

{
  *(undefined4 *)(param_1 + 0xd4) = 1;
  FUN_10001e30(param_1);
  return;
}



undefined4 __fastcall FUN_10001e10(int param_1)

{
  return *(undefined4 *)(param_1 + 0xd4);
}



void __fastcall FUN_10001e30(int param_1)

{
  *(undefined4 *)(param_1 + 0x178) = 1;
  *(undefined4 *)(param_1 + 0x174) = 0;
  return;
}



OVERLAY * __fastcall FUN_10001e60(OVERLAY *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_10002769;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  OVERLAY::OVERLAY(param_1);
  local_8 = 0;
  FUN_10001ee0((DWORD *)(param_1 + 0xd0));
  DD_SURFACE::DD_SURFACE((DD_SURFACE *)(param_1 + 0xdc));
  local_8 = CONCAT31(local_8._1_3_,1);
  *(undefined ***)param_1 = &PTR_FUN_100031c4;
  *(undefined ***)(param_1 + 8) = &PTR_FUN_100031c0;
  FUN_10001dd0((int)param_1);
  ExceptionList = local_10;
  return param_1;
}



DWORD * __fastcall FUN_10001ee0(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
  return param_1;
}



void * __thiscall FUN_10001f00(void *this,uint param_1)

{
  FUN_10001ff0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10001f30(undefined4 *param_1)

{
  DD_SURFACE *local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_10002789;
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
  FUN_10001fa0(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10001fa0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_10003214;
  return;
}



void * __thiscall FUN_10001fc0(void *this,uint param_1)

{
  FUN_10001fa0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10001ff0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_100027a9;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(param_1 + 0x37));
  local_8 = 0xffffffff;
  FUN_10001f30(param_1);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_10002040(void *this,uint param_1)

{
  FUN_10002070((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10002070(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_100031a4;
  return;
}



void __fastcall FUN_10002090(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_10003180;
  FUN_10002070(param_1);
  return;
}



void * __thiscall FUN_100020b0(void *this,uint param_1)

{
  FUN_10002090((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100020de. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x100020e4. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void __thiscall CString::~CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x100020ea. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CString(this);
  return;
}



void __thiscall CString::CString(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100020f0. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



void * __thiscall FUN_10002128(void *this,byte param_1)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)this);
  if ((param_1 & 1) != 0) {
    CNoTrackObject::operator_delete(this);
  }
  return this;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x10002552. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



int FUN_100021a3(HINSTANCE__ *param_1,int param_2)

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
      pAVar5 = AfxSetModuleState((AFX_MODULE_STATE *)&this_10004170);
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
                ((AFX_MAINTAIN_STATE2 *)&local_c,(AFX_MODULE_STATE *)&this_10004170);
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
  iVar4 = AfxWinInit(param_1,(HINSTANCE__ *)0x0,(char *)&param_3_10003244,0);
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
      goto LAB_1000222f;
    }
    (**(code **)(*piVar2 + 0x70))();
  }
  AfxWinTerm();
LAB_1000222f:
  *(undefined4 *)(p_Var3 + 8) = uVar1;
  p_Var3 = AfxGetThreadState();
  AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var3 + 8));
  return param_2;
}



undefined4 FUN_100022ca(undefined4 param_1,int param_2)

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
    pAVar2 = AfxSetModuleState((AFX_MODULE_STATE *)&this_10004170);
    *(AFX_MODULE_STATE **)(p_Var1 + 8) = pAVar2;
  }
  else if (param_2 == 0) {
    p_Var1 = AfxGetThreadState();
    AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var1 + 8));
  }
  return 1;
}



void __fastcall FUN_1000231b(undefined4 *param_1)

{
  *(undefined4 *)(param_1[1] + 4) = *param_1;
  return;
}



void __CxxFrameHandler(void)

{
                    // WARNING: Could not recover jumptable at 0x10002324. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10002336(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 *_Memory;
  undefined4 *puVar2;
  
  if (param_2 == 0) {
    if (0 < DAT_1000521c) {
      DAT_1000521c = DAT_1000521c + -1;
      goto LAB_1000234c;
    }
LAB_10002374:
    uVar1 = 0;
  }
  else {
LAB_1000234c:
    _DAT_10005220 = *(undefined4 *)_adjust_fdiv_exref;
    if (param_2 == 1) {
      DAT_10005228 = (undefined4 *)malloc(0x80);
      if (DAT_10005228 == (undefined4 *)0x0) goto LAB_10002374;
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
    if ((param_2 != 1) && (param_2 != 2)) goto LAB_10002429;
    if ((PTR_FUN_100040e4 != (undefined *)0x0) &&
       (iVar2 = (*(code *)PTR_FUN_100040e4)(param_1,param_2,param_3), iVar2 == 0)) {
      return 0;
    }
    iVar2 = FUN_10002336(param_1,param_2);
  }
  if (iVar2 == 0) {
    return 0;
  }
LAB_10002429:
  iVar2 = FUN_100021a3(param_1,param_2);
  if (param_2 == 1) {
    if (iVar2 != 0) {
      return iVar2;
    }
    FUN_10002336(param_1,0);
  }
  if ((param_2 != 0) && (param_2 != 3)) {
    return iVar2;
  }
  iVar3 = FUN_10002336(param_1,param_2);
  param_2 = iVar2;
  if (iVar3 == 0) {
    param_2 = 0;
  }
  if (param_2 != 0) {
    if (PTR_FUN_100040e4 != (undefined *)0x0) {
      iVar2 = (*(code *)PTR_FUN_100040e4)(param_1,iVar1,param_3);
      return iVar2;
    }
    return param_2;
  }
  return 0;
}



void * __thiscall FUN_1000247e(void *this,byte param_1)

{
  type_info::~type_info((type_info *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __cdecl initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x100024f8. Too many branches
                    // WARNING: Treating indirect jump as call
  initterm();
  return;
}



void __thiscall type_info::~type_info(type_info *this)

{
                    // WARNING: Could not recover jumptable at 0x100024fe. Too many branches
                    // WARNING: Treating indirect jump as call
  ~type_info(this);
  return;
}



void CNoTrackObject::operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000254c. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x10002552. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



void __thiscall
AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(AFX_MAINTAIN_STATE2 *this,AFX_MODULE_STATE *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000255e. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MAINTAIN_STATE2(this,param_1);
  return;
}



void AfxTermThread(HINSTANCE__ *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002564. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermThread(param_1);
  return;
}



void AfxTermExtensionModule(AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x1000256a. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermExtensionModule(param_1,param_2);
  return;
}



int AfxUnlockTempMaps(int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002570. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxUnlockTempMaps(param_1);
  return iVar1;
}



void AfxLockTempMaps(void)

{
                    // WARNING: Could not recover jumptable at 0x10002576. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxLockTempMaps();
  return;
}



AFX_MODULE_STATE * AfxSetModuleState(AFX_MODULE_STATE *param_1)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000257c. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxSetModuleState(param_1);
  return pAVar1;
}



void __thiscall
CDynLinkLibrary::CDynLinkLibrary(CDynLinkLibrary *this,AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10002582. Too many branches
                    // WARNING: Treating indirect jump as call
  CDynLinkLibrary(this,param_1,param_2);
  return;
}



int AfxInitExtensionModule(AFX_EXTENSION_MODULE *param_1,HINSTANCE__ *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002588. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxInitExtensionModule(param_1,param_2);
  return iVar1;
}



void AfxWinTerm(void)

{
                    // WARNING: Could not recover jumptable at 0x1000258e. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxWinTerm();
  return;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002594. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



int AfxWinInit(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000259a. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinInit(param_1,param_2,param_3,param_4);
  return iVar1;
}



_AFX_THREAD_STATE * AfxGetThreadState(void)

{
  _AFX_THREAD_STATE *p_Var1;
  
                    // WARNING: Could not recover jumptable at 0x100025a0. Too many branches
                    // WARNING: Treating indirect jump as call
  p_Var1 = AfxGetThreadState();
  return p_Var1;
}



void AfxCoreInitModule(void)

{
                    // WARNING: Could not recover jumptable at 0x100025a6. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxCoreInitModule();
  return;
}



void Unwind_100025b0(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x14));
  return;
}



void Unwind_100025c5(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_100025ce(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_100025d7(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_100025e0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_100025e9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_100025f2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_100025fb(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x44));
  return;
}



void Unwind_10002604(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x4c));
  return;
}



void Unwind_1000260d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x54));
  return;
}



void Unwind_10002616(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x5c));
  return;
}



void Unwind_1000261f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -100));
  return;
}



void Unwind_10002628(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x6c));
  return;
}



void Unwind_1000263b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_10002650(void)

{
  int unaff_EBP;
  
  FUN_10002090(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10002659(void)

{
  int unaff_EBP;
  
  FUN_10001b10((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_10002665(void)

{
  int unaff_EBP;
  
  FUN_10001b10((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x184));
  return;
}



void Unwind_10002674(void)

{
  int unaff_EBP;
  
  FUN_10001b10((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x304));
  return;
}



void Unwind_10002683(void)

{
  int unaff_EBP;
  
  FUN_10001ff0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x484));
  return;
}



void Unwind_10002692(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x600));
  return;
}



void Unwind_100026a2(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x640));
  return;
}



void Unwind_100026b2(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x680));
  return;
}



void Unwind_100026d0(void)

{
  int unaff_EBP;
  
  FUN_10002090(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100026d9(void)

{
  int unaff_EBP;
  
  FUN_10001b10((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_100026e5(void)

{
  int unaff_EBP;
  
  FUN_10001b10((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x184));
  return;
}



void Unwind_100026f4(void)

{
  int unaff_EBP;
  
  FUN_10001b10((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x304));
  return;
}



void Unwind_10002703(void)

{
  int unaff_EBP;
  
  FUN_10001ff0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x484));
  return;
}



void Unwind_10002712(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x600));
  return;
}



void Unwind_10002722(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x640));
  return;
}



void Unwind_10002732(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x680));
  return;
}



void Unwind_10002750(void)

{
  int unaff_EBP;
  
  FUN_10001f30(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10002759(void)

{
  int unaff_EBP;
  
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(*(int *)(unaff_EBP + -0x10) + 0xdc));
  return;
}



void Unwind_10002780(void)

{
  int unaff_EBP;
  
  FUN_10001fa0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100027a0(void)

{
  int unaff_EBP;
  
  FUN_10001f30(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100027b4(void)

{
  int unaff_EBP;
  
  FUN_1000231b((undefined4 *)(unaff_EBP + -0x14));
  return;
}


