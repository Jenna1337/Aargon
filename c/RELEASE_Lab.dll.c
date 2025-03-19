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

typedef struct TwDialHand TwDialHand, *PTwDialHand;

struct TwDialHand { // PlaceHolder Structure
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

typedef struct TwTransparentOverlay TwTransparentOverlay, *PTwTransparentOverlay;

struct TwTransparentOverlay { // PlaceHolder Structure
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

typedef struct TwSinWave TwSinWave, *PTwSinWave;

struct TwSinWave { // PlaceHolder Structure
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
  puStack_c = &LAB_100036fb;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  this = operator_new(0x1188);
  local_8 = 0;
  if (this == (void *)0x0) {
    local_1c = (SELECT_SKILL *)0x0;
  }
  else {
    local_1c = (SELECT_SKILL *)FUN_100028d0(this,param_1);
  }
  ExceptionList = local_10;
  return local_1c;
}



void FUN_1000106e(void)

{
  char *pcVar1;
  CString aCStack_220 [4];
  undefined4 uStack_21c;
  CString aCStack_214 [4];
  undefined4 uStack_210;
  undefined4 uStack_20c;
  undefined4 uStack_208;
  undefined4 uStack_204;
  CString aCStack_1fc [4];
  undefined4 uStack_1f8;
  CString aCStack_1f0 [4];
  undefined4 uStack_1ec;
  undefined4 uStack_1e8;
  undefined4 uStack_1e4;
  undefined4 uStack_1e0;
  CString aCStack_1d8 [4];
  undefined4 uStack_1d4;
  CString aCStack_1cc [4];
  undefined4 uStack_1c8;
  undefined4 uStack_1c4;
  undefined4 uStack_1c0;
  undefined4 uStack_1bc;
  CString aCStack_1b4 [4];
  undefined4 uStack_1b0;
  CString aCStack_1a8 [4];
  undefined4 uStack_1a4;
  undefined4 uStack_1a0;
  undefined4 uStack_19c;
  undefined4 uStack_198;
  CString aCStack_190 [4];
  undefined4 uStack_18c;
  CString aCStack_184 [4];
  undefined4 uStack_180;
  undefined4 uStack_17c;
  undefined4 uStack_178;
  undefined4 uStack_174;
  CString aCStack_16c [4];
  undefined4 uStack_168;
  CString aCStack_160 [4];
  undefined4 uStack_15c;
  undefined4 *local_158;
  undefined4 *local_154;
  undefined4 local_150;
  CString *local_14c;
  CString *local_148;
  undefined4 local_144;
  CString *local_140;
  CString *local_13c;
  undefined4 local_138;
  CString *local_134;
  CString *local_130;
  undefined4 local_12c;
  undefined4 *local_128;
  undefined4 *local_124;
  undefined4 local_120;
  undefined4 *local_11c;
  undefined4 *local_118;
  undefined4 local_114;
  undefined4 *local_110;
  undefined4 *local_10c;
  undefined4 local_108;
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
  int local_98;
  CString local_94 [4];
  undefined1 *local_90;
  CString local_8c [4];
  undefined1 *local_88;
  CString local_84 [4];
  undefined1 *local_80;
  CString local_7c [4];
  undefined1 *local_78;
  CString local_74 [4];
  undefined1 *local_70;
  CString local_6c [4];
  undefined1 *local_68;
  CString local_64 [4];
  undefined1 *local_60;
  CString local_5c [4];
  undefined1 *local_58;
  CString local_54 [4];
  undefined1 *local_50;
  CString local_4c [4];
  undefined1 *local_48;
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
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000379b;
  local_10 = ExceptionList;
  uStack_15c = 0;
  local_18 = aCStack_160;
  uStack_168 = 0x100010a4;
  ExceptionList = &local_10;
  local_9c = CString::CString(aCStack_160,s_btnbeginner_off_bmp_10005020);
  uStack_168 = 0x100010c5;
  local_a4 = (undefined4 *)(**(code **)(**(int **)(local_98 + 4) + 0x54))();
  local_8 = 0;
  uStack_168 = 0x100010e9;
  local_a0 = local_a4;
  uStack_168 = FUN_10002c50(local_a4);
  local_20 = aCStack_16c;
  uStack_174 = 0x100010fa;
  local_a8 = CString::CString(aCStack_16c,s_btnbeginner_bmp_10005034);
  uStack_174 = 0x1000111b;
  local_b0 = (undefined4 *)(**(code **)(**(int **)(local_98 + 4) + 0x54))();
  local_8._0_1_ = 1;
  uStack_174 = 0x1000113c;
  local_ac = local_b0;
  uStack_174 = FUN_10002c50(local_b0);
  uStack_178 = 0x10001158;
  (**(code **)(*(int *)(local_98 + 0x680) + 0x4c))();
  local_8 = (uint)local_8._1_3_ << 8;
  uStack_178 = 0x10001164;
  CString::~CString(local_24);
  local_8 = 0xffffffff;
  uStack_178 = 0x10001173;
  CString::~CString(local_1c);
  uStack_178 = 0x132;
  uStack_17c = 0x6f;
  uStack_180 = 0x10001195;
  (**(code **)(*(int *)(local_98 + 0x680) + 0x2c))();
  uStack_180 = 0;
  local_28 = aCStack_184;
  uStack_18c = 0x100011a7;
  local_b4 = CString::CString(aCStack_184,s_btneasy_off_bmp_10005044);
  uStack_18c = 0x100011c8;
  local_bc = (undefined4 *)(**(code **)(**(int **)(local_98 + 4) + 0x54))();
  local_8 = 2;
  uStack_18c = 0x100011ec;
  local_b8 = local_bc;
  uStack_18c = FUN_10002c50(local_bc);
  local_30 = aCStack_190;
  uStack_198 = 0x100011fd;
  local_c0 = CString::CString(aCStack_190,s_btneasy_bmp_10005054);
  uStack_198 = 0x1000121e;
  local_c8 = (undefined4 *)(**(code **)(**(int **)(local_98 + 4) + 0x54))();
  local_8._0_1_ = 3;
  uStack_198 = 0x1000123f;
  local_c4 = local_c8;
  uStack_198 = FUN_10002c50(local_c8);
  uStack_19c = 0x1000125b;
  (**(code **)(*(int *)(local_98 + 0x7fc) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,2);
  uStack_19c = 0x10001267;
  CString::~CString(local_34);
  local_8 = 0xffffffff;
  uStack_19c = 0x10001276;
  CString::~CString(local_2c);
  uStack_19c = 0x153;
  uStack_1a0 = 0x65;
  uStack_1a4 = 0x10001298;
  (**(code **)(*(int *)(local_98 + 0x7fc) + 0x2c))();
  uStack_1a4 = 0;
  local_38 = aCStack_1a8;
  uStack_1b0 = 0x100012aa;
  local_cc = CString::CString(aCStack_1a8,s_btnhard_off_bmp_10005060);
  uStack_1b0 = 0x100012cb;
  local_d4 = (undefined4 *)(**(code **)(**(int **)(local_98 + 4) + 0x54))();
  local_8 = 4;
  uStack_1b0 = 0x100012ef;
  local_d0 = local_d4;
  uStack_1b0 = FUN_10002c50(local_d4);
  local_40 = aCStack_1b4;
  uStack_1bc = 0x10001300;
  local_d8 = CString::CString(aCStack_1b4,s_btnhard_bmp_10005070);
  uStack_1bc = 0x10001321;
  local_e0 = (undefined4 *)(**(code **)(**(int **)(local_98 + 4) + 0x54))();
  local_8._0_1_ = 5;
  uStack_1bc = 0x10001342;
  local_dc = local_e0;
  uStack_1bc = FUN_10002c50(local_e0);
  uStack_1c0 = 0x1000135e;
  (**(code **)(*(int *)(local_98 + 0x978) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,4);
  uStack_1c0 = 0x1000136a;
  CString::~CString(local_44);
  local_8 = 0xffffffff;
  uStack_1c0 = 0x10001379;
  CString::~CString(local_3c);
  uStack_1c0 = 0x177;
  uStack_1c4 = 0x59;
  uStack_1c8 = 0x1000139b;
  (**(code **)(*(int *)(local_98 + 0x978) + 0x2c))();
  uStack_1c8 = 0;
  local_48 = aCStack_1cc;
  uStack_1d4 = 0x100013ad;
  local_e4 = CString::CString(aCStack_1cc,s_btnexpert_off_bmp_1000507c);
  uStack_1d4 = 0x100013ce;
  local_ec = (undefined4 *)(**(code **)(**(int **)(local_98 + 4) + 0x54))();
  local_8 = 6;
  uStack_1d4 = 0x100013f2;
  local_e8 = local_ec;
  uStack_1d4 = FUN_10002c50(local_ec);
  local_50 = aCStack_1d8;
  uStack_1e0 = 0x10001403;
  local_f0 = CString::CString(aCStack_1d8,s_btnexpert_bmp_10005090);
  uStack_1e0 = 0x10001424;
  local_f8 = (undefined4 *)(**(code **)(**(int **)(local_98 + 4) + 0x54))();
  local_8._0_1_ = 7;
  uStack_1e0 = 0x10001445;
  local_f4 = local_f8;
  uStack_1e0 = FUN_10002c50(local_f8);
  uStack_1e4 = 0x10001461;
  (**(code **)(*(int *)(local_98 + 0xaf4) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,6);
  uStack_1e4 = 0x1000146d;
  CString::~CString(local_54);
  local_8 = 0xffffffff;
  uStack_1e4 = 0x1000147c;
  CString::~CString(local_4c);
  uStack_1e4 = 0x19f;
  uStack_1e8 = 0x4a;
  uStack_1ec = 0x1000149e;
  (**(code **)(*(int *)(local_98 + 0xaf4) + 0x2c))();
  uStack_1ec = 0;
  local_58 = aCStack_1f0;
  uStack_1f8 = 0x100014b0;
  local_fc = CString::CString(aCStack_1f0,s_btnquit_off_bmp_100050a0);
  uStack_1f8 = 0x100014d1;
  local_104 = (undefined4 *)(**(code **)(**(int **)(local_98 + 4) + 0x54))();
  local_8 = 8;
  uStack_1f8 = 0x100014f5;
  local_100 = local_104;
  uStack_1f8 = FUN_10002c50(local_104);
  local_60 = aCStack_1fc;
  uStack_204 = 0x10001506;
  local_108 = CString::CString(aCStack_1fc,s_btnquit_bmp_100050b0);
  uStack_204 = 0x10001527;
  local_110 = (undefined4 *)(**(code **)(**(int **)(local_98 + 4) + 0x54))();
  local_8._0_1_ = 9;
  uStack_204 = 0x10001548;
  local_10c = local_110;
  uStack_204 = FUN_10002c50(local_110);
  uStack_208 = 0x10001564;
  (**(code **)(*(int *)(local_98 + 0xc70) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,8);
  uStack_208 = 0x10001570;
  CString::~CString(local_64);
  local_8 = 0xffffffff;
  uStack_208 = 0x1000157f;
  CString::~CString(local_5c);
  uStack_208 = 0x126;
  uStack_20c = 0x1ba;
  uStack_210 = 0x100015a4;
  (**(code **)(*(int *)(local_98 + 0xc70) + 0x2c))();
  uStack_210 = 0;
  local_68 = aCStack_214;
  uStack_21c = 0x100015b6;
  local_114 = CString::CString(aCStack_214,s_btnhelp_off_bmp_100050bc);
  uStack_21c = 0x100015d7;
  local_11c = (undefined4 *)(**(code **)(**(int **)(local_98 + 4) + 0x54))();
  local_8 = 10;
  uStack_21c = 0x100015fb;
  local_118 = local_11c;
  uStack_21c = FUN_10002c50(local_11c);
  local_70 = aCStack_220;
  local_120 = CString::CString(aCStack_220,s_btnhelpfile_bmp_100050cc);
  local_128 = (undefined4 *)(**(code **)(**(int **)(local_98 + 4) + 0x54))();
  local_8._0_1_ = 0xb;
  local_124 = local_128;
  FUN_10002c50(local_128);
  (**(code **)(*(int *)(local_98 + 0xdec) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,10);
  CString::~CString(local_74);
  local_8 = 0xffffffff;
  CString::~CString(local_6c);
  (**(code **)(*(int *)(local_98 + 0xdec) + 0x2c))();
  TwSinWave::Init((TwSinWave *)(local_98 + 8),0x3b,0x28,0xff0000,0);
  TwSinWave::SetFramesPerSecond((TwSinWave *)(local_98 + 8),0x3c);
  TwSinWave::SetSpeed((TwSinWave *)(local_98 + 8),1);
  TwSinWave::SetOneSideThickness((TwSinWave *)(local_98 + 8),3);
  TwSinWave::SetNoise((TwSinWave *)(local_98 + 8),0);
  TwSinWave::SetVerticalMargin((TwSinWave *)(local_98 + 8),0x1e);
  TwSinWave::SetColor((TwSinWave *)(local_98 + 8),0xff0000,0);
  for (local_14 = 0; local_14 < 3; local_14 = local_14 + 1) {
    TwTransparentOverlay::Init
              ((TwTransparentOverlay *)(local_98 + 0x1a0 + local_14 * 0x1a0),0x26,0x26);
    TwDialHand::SetLength((TwDialHand *)(local_98 + 0x1a0 + local_14 * 0x1a0),0xf);
    TwDialHand::SetNoise((TwDialHand *)(local_98 + 0x1a0 + local_14 * 0x1a0),10);
    TwDialHand::SetThickness((TwDialHand *)(local_98 + 0x1a0 + local_14 * 0x1a0),3);
    TwDialHand::SetRotation((TwDialHand *)(local_98 + 0x1a0 + local_14 * 0x1a0),0xaa);
  }
  TwDialHand::SetColor((TwDialHand *)(local_98 + 0x1a0),0x161d31,0x39585b);
  TwDialHand::SetColor((TwDialHand *)(local_98 + 0x340),0xd1b2d,0x345254);
  TwDialHand::SetColor((TwDialHand *)(local_98 + 0x4e0),0xc192a,0x335052);
  local_78 = &stack0xfffffdcc;
  local_12c = CString::CString((CString *)&stack0xfffffdcc,s_Lab_Button_Sound_1_100050dc);
  local_134 = (CString *)(**(code **)(**(int **)(local_98 + 4) + 0x58))();
  local_8 = 0xc;
  local_130 = local_134;
  CWave::Create((CWave *)(local_98 + 0xf68),local_134);
  local_8 = 0xffffffff;
  CString::~CString(local_7c);
  local_80 = &stack0xfffffdc4;
  local_138 = CString::CString((CString *)&stack0xfffffdc4,s_Lab_Button_Sound_2_100050f0);
  local_140 = (CString *)(**(code **)(**(int **)(local_98 + 4) + 0x58))();
  local_8 = 0xd;
  local_13c = local_140;
  CWave::Create((CWave *)(local_98 + 0xfa8),local_140);
  local_8 = 0xffffffff;
  CString::~CString(local_84);
  local_88 = &stack0xfffffdbc;
  local_144 = CString::CString((CString *)&stack0xfffffdbc,s_Lab_Background_10005104);
  local_14c = (CString *)(**(code **)(**(int **)(local_98 + 4) + 0x58))();
  local_8 = 0xe;
  local_148 = local_14c;
  CWave::Create((CWave *)(local_98 + 0xfe8),local_14c);
  local_8 = 0xffffffff;
  CString::~CString(local_8c);
  CMidi::Init((CMidi *)(local_98 + 0x1028));
  local_90 = &stack0xfffffdb4;
  local_150 = CString::CString((CString *)&stack0xfffffdb4,s_bachattach_rmi_10005114);
  local_158 = (undefined4 *)(**(code **)(**(int **)(local_98 + 4) + 0x58))(local_94);
  local_8 = 0xf;
  local_154 = local_158;
  pcVar1 = (char *)FUN_10002c50(local_158);
  CMidi::LoadSong((CMidi *)(local_98 + 0x1028),pcVar1);
  local_8 = 0xffffffff;
  CString::~CString(local_94);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10001a3e(int param_1)

{
  char cVar1;
  uint uVar2;
  double dVar3;
  
  (**(code **)(*(int *)(param_1 + 0x680) + 0x14))();
  (**(code **)(*(int *)(param_1 + 0x7fc) + 0x14))();
  (**(code **)(*(int *)(param_1 + 0x978) + 0x14))();
  (**(code **)(*(int *)(param_1 + 0xaf4) + 0x14))();
  (**(code **)(*(int *)(param_1 + 0xc70) + 0x14))();
  (**(code **)(*(int *)(param_1 + 0xdec) + 0x14))();
  uVar2 = FUN_10002ca0((int *)(param_1 + 0x117c));
  if (0xfa < uVar2) {
    *(undefined1 *)(param_1 + 0x1180) = 0;
  }
  TwSinWave::SetSpeed((TwSinWave *)(param_1 + 8),1);
  TwSinWave::SetOneSideThickness((TwSinWave *)(param_1 + 8),1);
  TwSinWave::SetNoise((TwSinWave *)(param_1 + 8),0);
  TwSinWave::SetVerticalMargin((TwSinWave *)(param_1 + 8),0x1e);
  TwSinWave::SetColor((TwSinWave *)(param_1 + 8),0xff0000,0);
  TwDialHand::RotateAnimated((TwDialHand *)(param_1 + 0x1a0),0xaa,3,1,0);
  TwDialHand::RotateAnimated((TwDialHand *)(param_1 + 0x340),0xaa,3,1,0);
  TwDialHand::RotateAnimated((TwDialHand *)(param_1 + 0x4e0),0xaa,3,1,0);
  cVar1 = (**(code **)(*(int *)(param_1 + 0x680) + 0x44))();
  if (cVar1 == '\0') {
    cVar1 = (**(code **)(*(int *)(param_1 + 0x7fc) + 0x44))();
    if (cVar1 == '\0') {
      cVar1 = (**(code **)(*(int *)(param_1 + 0x978) + 0x44))();
      if (cVar1 == '\0') {
        cVar1 = (**(code **)(*(int *)(param_1 + 0xaf4) + 0x44))();
        if (cVar1 == '\0') {
          cVar1 = (**(code **)(*(int *)(param_1 + 0xc70) + 0x44))();
          if (cVar1 == '\0') {
            cVar1 = (**(code **)(*(int *)(param_1 + 0xdec) + 0x44))();
            if (cVar1 == '\0') {
              if (*(char *)(param_1 + 0x1180) == '\0') {
                FUN_10002d10(param_1 + 0x680);
                FUN_10002d10(param_1 + 0x7fc);
                FUN_10002d10(param_1 + 0x978);
                FUN_10002d10(param_1 + 0xaf4);
                FUN_10002d10(param_1 + 0xc70);
                FUN_10002d10(param_1 + 0xdec);
                DAT_100051c8 = 1;
              }
              else {
                FUN_10002d30((void *)(param_1 + 0x680),0x32);
                FUN_10002d30((void *)(param_1 + 0x7fc),0x32);
                FUN_10002d30((void *)(param_1 + 0x978),0x32);
                FUN_10002d30((void *)(param_1 + 0xaf4),0x32);
                FUN_10002d30((void *)(param_1 + 0xc70),0x32);
                FUN_10002d30((void *)(param_1 + 0xdec),0x32);
              }
            }
            else {
              FUN_10002d10(param_1 + 0x680);
              FUN_10002d10(param_1 + 0x7fc);
              FUN_10002d10(param_1 + 0x978);
              FUN_10002d10(param_1 + 0xaf4);
              FUN_10002d10(param_1 + 0xc70);
              FUN_10002d30((void *)(param_1 + 0xdec),0x32);
              if (DAT_100051c8 == 1) {
                dVar3 = RandomProb();
                if (0.5 <= dVar3) {
                  CWave::Play((CWave *)(param_1 + 0xfa8),0,0,0);
                  DAT_100051c8 = 0;
                }
                else {
                  CWave::Play((CWave *)(param_1 + 0xf68),0,0,0);
                  DAT_100051c8 = 0;
                }
              }
            }
          }
          else {
            FUN_10002d30((void *)(param_1 + 0xc70),0x32);
            FUN_10002d10(param_1 + 0x680);
            FUN_10002d10(param_1 + 0x7fc);
            FUN_10002d10(param_1 + 0x978);
            FUN_10002d10(param_1 + 0xaf4);
            FUN_10002d10(param_1 + 0xdec);
            if (DAT_100051c8 == 1) {
              dVar3 = RandomProb();
              if (0.5 <= dVar3) {
                CWave::Play((CWave *)(param_1 + 0xfa8),0,0,0);
                DAT_100051c8 = 0;
              }
              else {
                CWave::Play((CWave *)(param_1 + 0xf68),0,0,0);
                DAT_100051c8 = 0;
              }
            }
          }
        }
        else {
          FUN_10002d30((void *)(param_1 + 0xaf4),0x32);
          FUN_10002d10(param_1 + 0x680);
          FUN_10002d10(param_1 + 0x7fc);
          FUN_10002d10(param_1 + 0x978);
          FUN_10002d10(param_1 + 0xc70);
          FUN_10002d10(param_1 + 0xdec);
          TwSinWave::SetSpeed((TwSinWave *)(param_1 + 8),7);
          TwSinWave::SetOneSideThickness((TwSinWave *)(param_1 + 8),3);
          TwSinWave::SetNoise((TwSinWave *)(param_1 + 8),2);
          TwSinWave::SetVerticalMargin((TwSinWave *)(param_1 + 8),0);
          TwSinWave::SetColor((TwSinWave *)(param_1 + 8),0xff,0);
          TwDialHand::RotateAnimated((TwDialHand *)(param_1 + 0x1a0),10,3,1,0);
          TwDialHand::RotateAnimated((TwDialHand *)(param_1 + 0x340),10,3,1,0);
          TwDialHand::RotateAnimated((TwDialHand *)(param_1 + 0x4e0),10,3,1,0);
          if (DAT_100051c8 == 1) {
            dVar3 = RandomProb();
            if (0.5 <= dVar3) {
              CWave::Play((CWave *)(param_1 + 0xfa8),0,0,0);
              DAT_100051c8 = 0;
            }
            else {
              CWave::Play((CWave *)(param_1 + 0xf68),0,0,0);
              DAT_100051c8 = 0;
            }
          }
        }
      }
      else {
        FUN_10002d30((void *)(param_1 + 0x978),0x32);
        FUN_10002d10(param_1 + 0x680);
        FUN_10002d10(param_1 + 0x7fc);
        FUN_10002d10(param_1 + 0xaf4);
        FUN_10002d10(param_1 + 0xc70);
        FUN_10002d10(param_1 + 0xdec);
        TwSinWave::SetSpeed((TwSinWave *)(param_1 + 8),5);
        TwSinWave::SetOneSideThickness((TwSinWave *)(param_1 + 8),3);
        TwSinWave::SetNoise((TwSinWave *)(param_1 + 8),1);
        TwSinWave::SetVerticalMargin((TwSinWave *)(param_1 + 8),5);
        TwSinWave::SetColor((TwSinWave *)(param_1 + 8),0x80ff,0);
        TwDialHand::RotateAnimated((TwDialHand *)(param_1 + 0x1a0),0x2d,3,1,0);
        TwDialHand::RotateAnimated((TwDialHand *)(param_1 + 0x340),0x2d,3,1,0);
        TwDialHand::RotateAnimated((TwDialHand *)(param_1 + 0x4e0),0x2d,3,1,0);
        if (DAT_100051c8 == 1) {
          dVar3 = RandomProb();
          if (0.5 <= dVar3) {
            CWave::Play((CWave *)(param_1 + 0xfa8),0,0,0);
            DAT_100051c8 = 0;
          }
          else {
            CWave::Play((CWave *)(param_1 + 0xf68),0,0,0);
            DAT_100051c8 = 0;
          }
        }
      }
    }
    else {
      FUN_10002d30((void *)(param_1 + 0x7fc),0x32);
      FUN_10002d10(param_1 + 0x680);
      FUN_10002d10(param_1 + 0x978);
      FUN_10002d10(param_1 + 0xaf4);
      FUN_10002d10(param_1 + 0xc70);
      FUN_10002d10(param_1 + 0xdec);
      TwSinWave::SetSpeed((TwSinWave *)(param_1 + 8),3);
      TwSinWave::SetOneSideThickness((TwSinWave *)(param_1 + 8),3);
      TwSinWave::SetNoise((TwSinWave *)(param_1 + 8),0);
      TwSinWave::SetVerticalMargin((TwSinWave *)(param_1 + 8),10);
      TwSinWave::SetColor((TwSinWave *)(param_1 + 8),0xffff,0);
      TwDialHand::RotateAnimated((TwDialHand *)(param_1 + 0x1a0),0x5a,3,1,0);
      TwDialHand::RotateAnimated((TwDialHand *)(param_1 + 0x340),0x5a,3,1,0);
      TwDialHand::RotateAnimated((TwDialHand *)(param_1 + 0x4e0),0x5a,3,1,0);
      if (DAT_100051c8 == 1) {
        dVar3 = RandomProb();
        if (0.5 <= dVar3) {
          CWave::Play((CWave *)(param_1 + 0xfa8),0,0,0);
          DAT_100051c8 = 0;
        }
        else {
          CWave::Play((CWave *)(param_1 + 0xf68),0,0,0);
          DAT_100051c8 = 0;
        }
      }
    }
  }
  else {
    FUN_10002d30((void *)(param_1 + 0x680),0x32);
    FUN_10002d10(param_1 + 0x7fc);
    FUN_10002d10(param_1 + 0x978);
    FUN_10002d10(param_1 + 0xaf4);
    FUN_10002d10(param_1 + 0xc70);
    FUN_10002d10(param_1 + 0xdec);
    TwSinWave::SetSpeed((TwSinWave *)(param_1 + 8),2);
    TwSinWave::SetOneSideThickness((TwSinWave *)(param_1 + 8),2);
    TwSinWave::SetNoise((TwSinWave *)(param_1 + 8),0);
    TwSinWave::SetVerticalMargin((TwSinWave *)(param_1 + 8),0x14);
    TwSinWave::SetColor((TwSinWave *)(param_1 + 8),0xff00,0);
    TwDialHand::RotateAnimated((TwDialHand *)(param_1 + 0x1a0),0x87,3,1,0);
    TwDialHand::RotateAnimated((TwDialHand *)(param_1 + 0x340),0x87,3,1,0);
    TwDialHand::RotateAnimated((TwDialHand *)(param_1 + 0x4e0),0x87,3,1,0);
    if (DAT_100051c8 == 1) {
      dVar3 = RandomProb();
      if (0.5 <= dVar3) {
        CWave::Play((CWave *)(param_1 + 0xfa8),0,0,0);
        DAT_100051c8 = 0;
      }
      else {
        CWave::Play((CWave *)(param_1 + 0xf68),0,0,0);
        DAT_100051c8 = 0;
      }
    }
  }
  (**(code **)(*(int *)(param_1 + 8) + 0x14))();
  (**(code **)(*(int *)(param_1 + 0x1a0) + 0x14))();
  (**(code **)(*(int *)(param_1 + 0x340) + 0x14))();
  (**(code **)(*(int *)(param_1 + 0x4e0) + 0x14))();
  return;
}



void __fastcall FUN_100023fb(int param_1)

{
  FUN_1000274e(param_1);
  (**(code **)(*(int *)(param_1 + 0x680) + 0x1c))();
  (**(code **)(*(int *)(param_1 + 0x7fc) + 0x1c))();
  (**(code **)(*(int *)(param_1 + 0x978) + 0x1c))();
  (**(code **)(*(int *)(param_1 + 0xaf4) + 0x1c))();
  (**(code **)(*(int *)(param_1 + 0xc70) + 0x1c))();
  (**(code **)(*(int *)(param_1 + 0xdec) + 0x1c))();
  CWave::Play((CWave *)(param_1 + 0xfe8),0,0,1);
  CMidi::Play((CMidi *)(param_1 + 0x1028),1,0,0,0);
  FUN_10002c80((DWORD *)(param_1 + 0x117c));
  *(undefined1 *)(param_1 + 0x1180) = 1;
  return;
}



void __fastcall FUN_100024d0(int param_1)

{
  (**(code **)(*(int *)(param_1 + 0x680) + 0x20))();
  (**(code **)(*(int *)(param_1 + 0x7fc) + 0x20))();
  (**(code **)(*(int *)(param_1 + 0x978) + 0x20))();
  (**(code **)(*(int *)(param_1 + 0xaf4) + 0x20))();
  FUN_10002d10(param_1 + 0xc70);
  (**(code **)(*(int *)(param_1 + 0xc70) + 0x14))();
  GKERNEL::SpriteFlip();
  (**(code **)(*(int *)(param_1 + 0xc70) + 0x14))();
  GKERNEL::SpriteFlip();
  (**(code **)(*(int *)(param_1 + 0xc70) + 0x20))();
  (**(code **)(*(int *)(param_1 + 0xdec) + 0x20))();
  CWave::Stop((CWave *)(param_1 + 0xfe8));
  CWave::Stop((CWave *)(param_1 + 0xf68));
  CWave::Stop((CWave *)(param_1 + 0xfa8));
  CMidi::Stop((CMidi *)(param_1 + 0x1028));
  return;
}



void __fastcall FUN_100025d9(int param_1)

{
  char cVar1;
  
  cVar1 = (**(code **)(*(int *)(param_1 + 0xc70) + 0x44))();
  if (cVar1 == '\0') {
    cVar1 = (**(code **)(*(int *)(param_1 + 0x680) + 0x44))();
    if (cVar1 == '\0') {
      cVar1 = (**(code **)(*(int *)(param_1 + 0x7fc) + 0x44))();
      if (cVar1 == '\0') {
        cVar1 = (**(code **)(*(int *)(param_1 + 0x978) + 0x44))();
        if (cVar1 == '\0') {
          cVar1 = (**(code **)(*(int *)(param_1 + 0xaf4) + 0x44))();
          if (cVar1 == '\0') {
            cVar1 = (**(code **)(*(int *)(param_1 + 0xdec) + 0x44))();
            if (cVar1 != '\0') {
              (**(code **)(**(int **)(param_1 + 4) + 0x5c))();
            }
          }
          else {
            (**(code **)(**(int **)(param_1 + 4) + 0x50))(3);
            GAME::ChangeState(*(GAME **)(param_1 + 4),2);
          }
        }
        else {
          (**(code **)(**(int **)(param_1 + 4) + 0x50))(2);
          GAME::ChangeState(*(GAME **)(param_1 + 4),2);
        }
      }
      else {
        (**(code **)(**(int **)(param_1 + 4) + 0x50))(1);
        GAME::ChangeState(*(GAME **)(param_1 + 4),2);
      }
    }
    else {
      (**(code **)(**(int **)(param_1 + 4) + 0x50))(0);
      GAME::ChangeState(*(GAME **)(param_1 + 4),2);
    }
  }
  else {
    GAME::ChangeState(*(GAME **)(param_1 + 4),3);
  }
  return;
}



void __fastcall FUN_1000274e(int param_1)

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
  puStack_c = &this_100037b7;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  GKERNEL::NewSpriteBackground();
  uVar7 = 0;
  pHVar6 = (HINSTANCE__ *)0x0;
  iVar5 = 0;
  local_14 = &stack0xffffffac;
  uVar4 = extraout_ECX;
  CString::CString((CString *)&stack0xffffffac,s_SKILL_BMP_10005124);
  pCVar3 = local_18;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 4) + 0x54))();
  local_8 = 0;
  pcVar2 = (char *)FUN_10002c50(puVar1);
  GKTOOLS::CopyDIBToBack(pcVar2,(uint)pCVar3,uVar4,iVar5,pHVar6,(bool)uVar7);
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  GKERNEL::Flip();
  uVar7 = 0;
  pHVar6 = (HINSTANCE__ *)0x0;
  iVar5 = 0;
  local_1c = &stack0xffffffa4;
  uVar4 = extraout_ECX_00;
  CString::CString((CString *)&stack0xffffffa4,s_SKILL_BMP_10005130);
  pCVar3 = local_20;
  puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 4) + 0x54))();
  local_8 = 1;
  pcVar2 = (char *)FUN_10002c50(puVar1);
  GKTOOLS::CopyDIBToBack(pcVar2,(uint)pCVar3,uVar4,iVar5,pHVar6,(bool)uVar7);
  local_8 = 0xffffffff;
  CString::~CString(local_20);
  (**(code **)(*(int *)(param_1 + 8) + 0x2c))();
  (**(code **)(*(int *)(param_1 + 0x1a0) + 0x2c))();
  (**(code **)(*(int *)(param_1 + 0x340) + 0x2c))(0x195,0x181);
  (**(code **)(*(int *)(param_1 + 0x4e0) + 0x2c))(0x1cd,0x181);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_100028d0(void *this,undefined4 param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000389b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10002be0((undefined4 *)this);
  local_8 = 0;
  *(undefined4 *)((int)this + 4) = param_1;
  TwSinWave::TwSinWave((TwSinWave *)((int)this + 8));
  local_8._0_1_ = 1;
  FUN_100033e4((int)this + 0x1a0,0x1a0,3,TwDialHand_exref);
  local_8._0_1_ = 2;
  FUN_10002df0((OVERLAY *)((int)this + 0x680));
  local_8._0_1_ = 3;
  FUN_10002df0((OVERLAY *)((int)this + 0x7fc));
  local_8._0_1_ = 4;
  FUN_10002df0((OVERLAY *)((int)this + 0x978));
  local_8._0_1_ = 5;
  FUN_10002df0((OVERLAY *)((int)this + 0xaf4));
  local_8._0_1_ = 6;
  FUN_10002df0((OVERLAY *)((int)this + 0xc70));
  local_8._0_1_ = 7;
  FUN_10002df0((OVERLAY *)((int)this + 0xdec));
  local_8._0_1_ = 8;
  CWave::CWave((CWave *)((int)this + 0xf68));
  local_8._0_1_ = 9;
  CWave::CWave((CWave *)((int)this + 0xfa8));
  local_8._0_1_ = 10;
  CWave::CWave((CWave *)((int)this + 0xfe8));
  local_8._0_1_ = 0xb;
  CMidi::CMidi((CMidi *)((int)this + 0x1028));
  local_8 = CONCAT31(local_8._1_3_,0xc);
  FUN_10002c60((DWORD *)((int)this + 0x117c));
  *(undefined1 *)((int)this + 0x1180) = 0;
  *(undefined ***)this = &PTR_FUN_10004168;
  ExceptionList = local_10;
  return this;
}



void __fastcall FUN_10002a30(int param_1)

{
  FUN_1000274e(param_1);
  return;
}



void * __thiscall FUN_10002a50(void *this,uint param_1)

{
  FUN_10002a80((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10002a80(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &this_1000397b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_FUN_10004168;
  local_8 = 0xc;
  CMidi::UnInit((CMidi *)(param_1 + 0x40a));
  local_8._0_1_ = 0xb;
  CMidi::~CMidi((CMidi *)(param_1 + 0x40a));
  local_8._0_1_ = 10;
  CWave::~CWave((CWave *)(param_1 + 0x3fa));
  local_8._0_1_ = 9;
  CWave::~CWave((CWave *)(param_1 + 0x3ea));
  local_8._0_1_ = 8;
  CWave::~CWave((CWave *)(param_1 + 0x3da));
  local_8._0_1_ = 7;
  FUN_10003050(param_1 + 0x37b);
  local_8._0_1_ = 6;
  FUN_10003050(param_1 + 0x31c);
  local_8._0_1_ = 5;
  FUN_10003050(param_1 + 0x2bd);
  local_8._0_1_ = 4;
  FUN_10003050(param_1 + 0x25e);
  local_8._0_1_ = 3;
  FUN_10003050(param_1 + 0x1ff);
  local_8._0_1_ = 2;
  FUN_10003050(param_1 + 0x1a0);
  local_8._0_1_ = 1;
  FUN_100032f0(param_1 + 0x68,0x1a0,3,FUN_10002bc0);
  local_8 = (uint)local_8._1_3_ << 8;
  TwSinWave::~TwSinWave((TwSinWave *)(param_1 + 2));
  local_8 = 0xffffffff;
  FUN_10002cc0(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10002bc0(undefined4 *param_1)

{
  FUN_10002c00(param_1);
  return;
}



undefined4 * __fastcall FUN_10002be0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_10004184;
  return param_1;
}



void __fastcall FUN_10002c00(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_10003999;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(param_1 + 0x34));
  local_8 = 0xffffffff;
  FUN_10002f90(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 __fastcall FUN_10002c50(undefined4 *param_1)

{
  return *param_1;
}



DWORD * __fastcall FUN_10002c60(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
  return param_1;
}



void __fastcall FUN_10002c80(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
  return;
}



int __fastcall FUN_10002ca0(int *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  return DVar1 - *param_1;
}



void __fastcall FUN_10002cc0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_10004184;
  return;
}



void * __thiscall FUN_10002ce0(void *this,uint param_1)

{
  FUN_10002cc0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10002d10(int param_1)

{
  *(undefined4 *)(param_1 + 0xd4) = 1;
  FUN_10002dc0(param_1);
  return;
}



void __thiscall FUN_10002d30(void *this,uint param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_10002d80((void *)((int)this + 0xd0),param_1);
  if (CONCAT31(extraout_var,bVar1) != 0) {
    *(uint *)((int)this + 0xd4) = (uint)(*(int *)((int)this + 0xd4) == 0);
    FUN_10002dc0((int)this);
  }
  return;
}



bool __thiscall FUN_10002d80(void *this,uint param_1)

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



void __fastcall FUN_10002dc0(int param_1)

{
  *(undefined4 *)(param_1 + 0x178) = 1;
  *(undefined4 *)(param_1 + 0x174) = 0;
  return;
}



OVERLAY * __fastcall FUN_10002df0(OVERLAY *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_100039c9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  OVERLAY::OVERLAY(param_1);
  local_8 = 0;
  FUN_10002c60((DWORD *)(param_1 + 0xd0));
  DD_SURFACE::DD_SURFACE((DD_SURFACE *)(param_1 + 0xdc));
  local_8 = CONCAT31(local_8._1_3_,1);
  *(undefined ***)param_1 = &PTR_FUN_100041ac;
  *(undefined ***)(param_1 + 8) = &PTR_FUN_100041a8;
  FUN_10002f40((int)param_1);
  ExceptionList = local_10;
  return param_1;
}



void FUN_10002e70(void)

{
  return;
}



void FUN_10002e80(void)

{
  return;
}



undefined1 __fastcall FUN_10002e90(int param_1)

{
  return *(undefined1 *)(param_1 + 0xcc);
}



void __fastcall FUN_10002eb0(int param_1)

{
  *(undefined1 *)(param_1 + 0xcc) = 1;
  return;
}



void __fastcall FUN_10002ed0(int param_1)

{
  *(undefined1 *)(param_1 + 0xcc) = 0;
  return;
}



void __thiscall FUN_10002ef0(void *this,undefined4 *param_1)

{
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x2c))(*param_1,param_1[1]);
  return;
}



undefined1 __fastcall FUN_10002f20(int param_1)

{
  return *(undefined1 *)(param_1 + 0xa0);
}



void __fastcall FUN_10002f40(int param_1)

{
  *(undefined4 *)(param_1 + 0xd4) = 0;
  FUN_10002dc0(param_1);
  return;
}



void * __thiscall FUN_10002f60(void *this,uint param_1)

{
  FUN_10003050((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10002f90(undefined4 *param_1)

{
  DD_SURFACE *local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_100039e9;
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
  FUN_10003000(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10003000(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_100041fc;
  return;
}



void * __thiscall FUN_10003020(void *this,uint param_1)

{
  FUN_10003000((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10003050(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_10003a09;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(param_1 + 0x37));
  local_8 = 0xffffffff;
  FUN_10002f90(param_1);
  ExceptionList = local_10;
  return;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100030a0. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x100030a6. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void __thiscall CString::~CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x100030ac. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CString(this);
  return;
}



void __thiscall CString::CString(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100030b2. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



void * __thiscall FUN_100030ea(void *this,byte param_1)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)this);
  if ((param_1 & 1) != 0) {
    CNoTrackObject::operator_delete(this);
  }
  return this;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x10003696. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



int FUN_10003165(HINSTANCE__ *param_1,int param_2)

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
      pAVar5 = AfxSetModuleState((AFX_MODULE_STATE *)&param_1_100051d0);
      p_Var3 = AfxGetThreadState();
      *(AFX_MODULE_STATE **)(p_Var3 + 8) = pAVar5;
      pAVar5 = AfxGetModuleState();
      if (*(int **)(pAVar5 + 4) != (int *)0x0) {
        (**(code **)(**(int **)(pAVar5 + 4) + 0x70))();
      }
      AfxLockTempMaps();
      AfxUnlockTempMaps(-1);
      AfxWinTerm();
      AfxTermExtensionModule((AFX_EXTENSION_MODULE *)&param_1_10006260,1);
    }
    else if (param_2 == 3) {
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
                ((AFX_MAINTAIN_STATE2 *)&local_c,(AFX_MODULE_STATE *)&param_1_100051d0);
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
  iVar4 = AfxWinInit(param_1,(HINSTANCE__ *)0x0,(char *)&param_3_1000422c,0);
  if (iVar4 != 0) {
    pAVar5 = AfxGetModuleState();
    piVar2 = *(int **)(pAVar5 + 4);
    if ((piVar2 == (int *)0x0) || (iVar4 = (**(code **)(*piVar2 + 0x58))(), iVar4 != 0)) {
      *(undefined4 *)(p_Var3 + 8) = uVar1;
      AfxInitExtensionModule((AFX_EXTENSION_MODULE *)&param_1_10006260,param_1);
      this = (CDynLinkLibrary *)operator_new(0x40);
      if (this != (CDynLinkLibrary *)0x0) {
        CDynLinkLibrary::CDynLinkLibrary(this,(AFX_EXTENSION_MODULE *)&param_1_10006260,0);
      }
      param_2 = 1;
      goto LAB_100031f1;
    }
    (**(code **)(*piVar2 + 0x70))();
  }
  AfxWinTerm();
LAB_100031f1:
  *(undefined4 *)(p_Var3 + 8) = uVar1;
  p_Var3 = AfxGetThreadState();
  AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var3 + 8));
  return param_2;
}



undefined4 FUN_1000328c(undefined4 param_1,int param_2)

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
    pAVar2 = AfxSetModuleState((AFX_MODULE_STATE *)&param_1_100051d0);
    *(AFX_MODULE_STATE **)(p_Var1 + 8) = pAVar2;
  }
  else if (param_2 == 0) {
    p_Var1 = AfxGetThreadState();
    AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var1 + 8));
  }
  return 1;
}



void __fastcall FUN_100032dd(undefined4 *param_1)

{
  *(undefined4 *)(param_1[1] + 4) = *param_1;
  return;
}



void __CxxFrameHandler(void)

{
                    // WARNING: Could not recover jumptable at 0x100032e6. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler();
  return;
}



void FUN_100032f0(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_10004230;
  puStack_10 = &DAT_10003630;
  local_14 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_14;
  while( true ) {
    param_3 = param_3 + -1;
    if (param_3 < 0) break;
    (*(code *)param_4)();
  }
  local_8 = 0xffffffff;
  FUN_10003358();
  ExceptionList = local_14;
  return;
}



void FUN_10003358(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x1c) == 0) {
    FUN_10003370(*(undefined4 *)(unaff_EBP + 8),*(undefined4 *)(unaff_EBP + 0xc),
                 *(int *)(unaff_EBP + 0x10),*(undefined **)(unaff_EBP + 0x14));
  }
  return;
}



void FUN_10003370(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_10004240;
  puStack_10 = &DAT_10003630;
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



void FUN_100033e4(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  int local_20;
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_10004250;
  puStack_10 = &DAT_10003630;
  local_14 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_14;
  for (local_20 = 0; local_20 < param_3; local_20 = local_20 + 1) {
    (*(code *)param_4)();
  }
  local_8 = 0xffffffff;
  FUN_1000344e();
  ExceptionList = local_14;
  return;
}



void FUN_1000344e(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x20) == 0) {
    FUN_10003370(*(undefined4 *)(unaff_EBP + 8),*(undefined4 *)(unaff_EBP + 0xc),
                 *(int *)(unaff_EBP + -0x1c),*(undefined **)(unaff_EBP + 0x18));
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_1000346c(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 *_Memory;
  undefined4 *puVar2;
  
  if (param_2 == 0) {
    if (0 < DAT_1000627c) {
      DAT_1000627c = DAT_1000627c + -1;
      goto LAB_10003482;
    }
LAB_100034aa:
    uVar1 = 0;
  }
  else {
LAB_10003482:
    _DAT_10006280 = *(undefined4 *)_adjust_fdiv_exref;
    if (param_2 == 1) {
      DAT_10006288 = (undefined4 *)malloc(0x80);
      if (DAT_10006288 == (undefined4 *)0x0) goto LAB_100034aa;
      *DAT_10006288 = 0;
      DAT_10006284 = DAT_10006288;
      initterm(&DAT_10005000,&DAT_10005008);
      DAT_1000627c = DAT_1000627c + 1;
    }
    else if ((param_2 == 0) &&
            (_Memory = DAT_10006288, puVar2 = DAT_10006284, DAT_10006288 != (undefined4 *)0x0)) {
      while (puVar2 = puVar2 + -1, _Memory <= puVar2) {
        if ((code *)*puVar2 != (code *)0x0) {
          (*(code *)*puVar2)();
          _Memory = DAT_10006288;
        }
      }
      free(_Memory);
      DAT_10006288 = (undefined4 *)0x0;
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
  iVar2 = DAT_1000627c;
  if (param_2 != 0) {
    if ((param_2 != 1) && (param_2 != 2)) goto LAB_1000355f;
    if ((PTR_FUN_1000513c != (undefined *)0x0) &&
       (iVar2 = (*(code *)PTR_FUN_1000513c)(param_1,param_2,param_3), iVar2 == 0)) {
      return 0;
    }
    iVar2 = FUN_1000346c(param_1,param_2);
  }
  if (iVar2 == 0) {
    return 0;
  }
LAB_1000355f:
  iVar2 = FUN_10003165(param_1,param_2);
  if (param_2 == 1) {
    if (iVar2 != 0) {
      return iVar2;
    }
    FUN_1000346c(param_1,0);
  }
  if ((param_2 != 0) && (param_2 != 3)) {
    return iVar2;
  }
  iVar3 = FUN_1000346c(param_1,param_2);
  param_2 = iVar2;
  if (iVar3 == 0) {
    param_2 = 0;
  }
  if (param_2 != 0) {
    if (PTR_FUN_1000513c != (undefined *)0x0) {
      iVar2 = (*(code *)PTR_FUN_1000513c)(param_1,iVar1,param_3);
      return iVar2;
    }
    return param_2;
  }
  return 0;
}



void * __thiscall FUN_100035b4(void *this,byte param_1)

{
  type_info::~type_info((type_info *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __cdecl initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x1000363c. Too many branches
                    // WARNING: Treating indirect jump as call
  initterm();
  return;
}



void __thiscall type_info::~type_info(type_info *this)

{
                    // WARNING: Could not recover jumptable at 0x10003642. Too many branches
                    // WARNING: Treating indirect jump as call
  ~type_info(this);
  return;
}



void CNoTrackObject::operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10003690. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x10003696. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



void __thiscall
AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(AFX_MAINTAIN_STATE2 *this,AFX_MODULE_STATE *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100036a2. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MAINTAIN_STATE2(this,param_1);
  return;
}



void AfxTermThread(HINSTANCE__ *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100036a8. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermThread(param_1);
  return;
}



void AfxTermExtensionModule(AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x100036ae. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermExtensionModule(param_1,param_2);
  return;
}



int AfxUnlockTempMaps(int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x100036b4. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxUnlockTempMaps(param_1);
  return iVar1;
}



void AfxLockTempMaps(void)

{
                    // WARNING: Could not recover jumptable at 0x100036ba. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxLockTempMaps();
  return;
}



AFX_MODULE_STATE * AfxSetModuleState(AFX_MODULE_STATE *param_1)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x100036c0. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxSetModuleState(param_1);
  return pAVar1;
}



void __thiscall
CDynLinkLibrary::CDynLinkLibrary(CDynLinkLibrary *this,AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x100036c6. Too many branches
                    // WARNING: Treating indirect jump as call
  CDynLinkLibrary(this,param_1,param_2);
  return;
}



int AfxInitExtensionModule(AFX_EXTENSION_MODULE *param_1,HINSTANCE__ *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x100036cc. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxInitExtensionModule(param_1,param_2);
  return iVar1;
}



void AfxWinTerm(void)

{
                    // WARNING: Could not recover jumptable at 0x100036d2. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxWinTerm();
  return;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x100036d8. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



int AfxWinInit(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x100036de. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinInit(param_1,param_2,param_3,param_4);
  return iVar1;
}



_AFX_THREAD_STATE * AfxGetThreadState(void)

{
  _AFX_THREAD_STATE *p_Var1;
  
                    // WARNING: Could not recover jumptable at 0x100036e4. Too many branches
                    // WARNING: Treating indirect jump as call
  p_Var1 = AfxGetThreadState();
  return p_Var1;
}



void AfxCoreInitModule(void)

{
                    // WARNING: Could not recover jumptable at 0x100036ea. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxCoreInitModule();
  return;
}



void Unwind_100036f0(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x14));
  return;
}



void Unwind_10003705(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000370e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_10003717(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_10003720(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x30));
  return;
}



void Unwind_10003729(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x38));
  return;
}



void Unwind_10003732(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x40));
  return;
}



void Unwind_1000373b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x48));
  return;
}



void Unwind_10003744(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x50));
  return;
}



void Unwind_1000374d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x58));
  return;
}



void Unwind_10003756(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x60));
  return;
}



void Unwind_1000375f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x68));
  return;
}



void Unwind_10003768(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x70));
  return;
}



void Unwind_10003771(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x78));
  return;
}



void Unwind_1000377a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x80));
  return;
}



void Unwind_10003783(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x88));
  return;
}



void Unwind_1000378f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x90));
  return;
}



void Unwind_100037a5(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_100037ae(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_100037d0(void)

{
  int unaff_EBP;
  
  FUN_10002cc0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100037d9(void)

{
  int unaff_EBP;
  
  TwSinWave::~TwSinWave((TwSinWave *)(*(int *)(unaff_EBP + -0x10) + 8));
  return;
}



void Unwind_100037e6(void)

{
  int unaff_EBP;
  
  FUN_100032f0(*(int *)(unaff_EBP + -0x10) + 0x1a0,0x1a0,3,FUN_10002bc0);
  return;
}



void Unwind_10003801(void)

{
  int unaff_EBP;
  
  FUN_10003050((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x680));
  return;
}



void Unwind_10003810(void)

{
  int unaff_EBP;
  
  FUN_10003050((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x7fc));
  return;
}



void Unwind_1000381f(void)

{
  int unaff_EBP;
  
  FUN_10003050((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x978));
  return;
}



void Unwind_1000382e(void)

{
  int unaff_EBP;
  
  FUN_10003050((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xaf4));
  return;
}



void Unwind_1000383d(void)

{
  int unaff_EBP;
  
  FUN_10003050((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xc70));
  return;
}



void Unwind_1000384c(void)

{
  int unaff_EBP;
  
  FUN_10003050((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xdec));
  return;
}



void Unwind_1000385b(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0xf68));
  return;
}



void Unwind_1000386b(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0xfa8));
  return;
}



void Unwind_1000387b(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0xfe8));
  return;
}



void Unwind_1000388b(void)

{
  int unaff_EBP;
  
  CMidi::~CMidi((CMidi *)(*(int *)(unaff_EBP + -0x10) + 0x1028));
  return;
}



void Unwind_100038b0(void)

{
  int unaff_EBP;
  
  FUN_10002cc0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100038b9(void)

{
  int unaff_EBP;
  
  TwSinWave::~TwSinWave((TwSinWave *)(*(int *)(unaff_EBP + -0x10) + 8));
  return;
}



void Unwind_100038c6(void)

{
  int unaff_EBP;
  
  FUN_100032f0(*(int *)(unaff_EBP + -0x10) + 0x1a0,0x1a0,3,FUN_10002bc0);
  return;
}



void Unwind_100038e1(void)

{
  int unaff_EBP;
  
  FUN_10003050((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x680));
  return;
}



void Unwind_100038f0(void)

{
  int unaff_EBP;
  
  FUN_10003050((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x7fc));
  return;
}



void Unwind_100038ff(void)

{
  int unaff_EBP;
  
  FUN_10003050((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x978));
  return;
}



void Unwind_1000390e(void)

{
  int unaff_EBP;
  
  FUN_10003050((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xaf4));
  return;
}



void Unwind_1000391d(void)

{
  int unaff_EBP;
  
  FUN_10003050((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xc70));
  return;
}



void Unwind_1000392c(void)

{
  int unaff_EBP;
  
  FUN_10003050((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xdec));
  return;
}



void Unwind_1000393b(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0xf68));
  return;
}



void Unwind_1000394b(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0xfa8));
  return;
}



void Unwind_1000395b(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0xfe8));
  return;
}



void Unwind_1000396b(void)

{
  int unaff_EBP;
  
  CMidi::~CMidi((CMidi *)(*(int *)(unaff_EBP + -0x10) + 0x1028));
  return;
}



void Unwind_10003990(void)

{
  int unaff_EBP;
  
  FUN_10002f90(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100039b0(void)

{
  int unaff_EBP;
  
  FUN_10002f90(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100039b9(void)

{
  int unaff_EBP;
  
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(*(int *)(unaff_EBP + -0x10) + 0xdc));
  return;
}



void Unwind_100039e0(void)

{
  int unaff_EBP;
  
  FUN_10003000(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10003a00(void)

{
  int unaff_EBP;
  
  FUN_10002f90(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10003a14(void)

{
  int unaff_EBP;
  
  FUN_100032dd((undefined4 *)(unaff_EBP + -0x14));
  return;
}


