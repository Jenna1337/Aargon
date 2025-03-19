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

typedef struct CDynLinkLibrary CDynLinkLibrary, *PCDynLinkLibrary;

struct CDynLinkLibrary { // PlaceHolder Structure
};

typedef struct _DDSURFACEDESC _DDSURFACEDESC, *P_DDSURFACEDESC;

struct _DDSURFACEDESC { // PlaceHolder Structure
};

typedef struct TILEBLITTER TILEBLITTER, *PTILEBLITTER;

struct TILEBLITTER { // PlaceHolder Structure
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

typedef struct CDirection CDirection, *PCDirection;

struct CDirection { // PlaceHolder Structure
};

typedef struct DD_SURFACE DD_SURFACE, *PDD_SURFACE;

struct DD_SURFACE { // PlaceHolder Structure
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ { // PlaceHolder Structure
};

typedef struct CColor CColor, *PCColor;

struct CColor { // PlaceHolder Structure
};

typedef struct CPosition CPosition, *PCPosition;

struct CPosition { // PlaceHolder Structure
};

typedef struct CCut CCut, *PCCut;

struct CCut { // PlaceHolder Structure
};

typedef struct HWND__ HWND__, *PHWND__;

struct HWND__ { // PlaceHolder Structure
};

typedef int (*_onexit_t)(void);

typedef uint size_t;




// public: __thiscall TILEBLITTER::TILEBLITTER(void)

TILEBLITTER * __thiscall TILEBLITTER::TILEBLITTER(TILEBLITTER *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x1000  1  ??0TILEBLITTER@@QAE@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_10003c69;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  DD_SURFACE::DD_SURFACE((DD_SURFACE *)this);
  local_8 = 0;
  FUN_10003050((undefined4 *)(this + 0x98));
  local_8._0_1_ = 1;
  FUN_10002f90(this + 0xa4);
  DD_SURFACE::DD_SURFACE((DD_SURFACE *)(this + 0x2174));
  local_8 = CONCAT31(local_8._1_3_,2);
  *(undefined ***)this = &PTR_FUN_100040d4;
  *(undefined ***)(this + 0x98) = &PTR_FUN_100040cc;
  DAT_10005180 = DAT_10005180 + 1;
  GKERNEL::DebugTrace(s_Num_Tile_blitters____d_10005074,DAT_10005180);
  ExceptionList = local_10;
  return this;
}



// public: virtual __thiscall TILEBLITTER::~TILEBLITTER(void)

void __thiscall TILEBLITTER::~TILEBLITTER(TILEBLITTER *this)

{
  TILEBLITTER *local_18;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x10b0  2  ??1TILEBLITTER@@UAE@XZ
  puStack_c = &LAB_10003cbe;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)(this + -0x98) = &PTR_FUN_100040d4;
  *(undefined ***)this = &PTR_FUN_100040cc;
  local_8 = 2;
  DAT_10005180 = DAT_10005180 + -1;
  GKERNEL::DebugTrace(s_Num_Tile_blitters____d_1000508c,DAT_10005180);
  local_8._0_1_ = 1;
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(this + 0x20dc));
  local_8 = (uint)local_8._1_3_ << 8;
  local_18 = this;
  if (this == (TILEBLITTER *)0x98) {
    local_18 = (TILEBLITTER *)0x0;
  }
  FUN_10003080((undefined4 *)local_18);
  local_8 = 0xffffffff;
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(this + -0x98));
  ExceptionList = local_10;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// private: void __thiscall TILEBLITTER::SetSurfaceInfo(void)

void __thiscall TILEBLITTER::SetSurfaceInfo(TILEBLITTER *this)

{
  bool bVar1;
  uint uVar2;
  undefined1 local_70 [84];
  uint local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  
                    // 0x116d  15  ?SetSurfaceInfo@TILEBLITTER@@AAEXXZ
  memset(this + 0x220c,0,0x6c);
  bVar1 = DD_SURFACE::Defined((DD_SURFACE *)this);
  if (bVar1) {
    *(undefined4 *)(this + 0xa0) = *(undefined4 *)(this + 0xb0);
    DD_SURFACE::Desc((DD_SURFACE *)this,(ulong)local_70);
    DAT_100050b4 = local_18;
    DAT_100050b0 = local_18 << 0x10;
    DAT_100050a8 = DAT_100050b0 | local_18;
    DAT_100050ac = ~DAT_100050a8;
    _DAT_100050b8 = DAT_100050ac & local_18 << 0x11;
    _DAT_100050bc = DAT_100050ac & local_18 << 1;
    DAT_100050cc = local_14;
    DAT_100050c8 = local_14 << 0x10;
    DAT_100050c0 = DAT_100050c8 | local_14;
    DAT_100050c4 = ~DAT_100050c0;
    _DAT_100050d0 = DAT_100050c4 & local_14 << 0x11;
    _DAT_100050d4 = DAT_100050c4 & local_14 << 1;
    DAT_100050e4 = local_10;
    DAT_100050e0 = local_10 << 0x10;
    DAT_100050d8 = DAT_100050e0 | local_10;
    DAT_100050dc = ~DAT_100050d8;
    _DAT_100050e8 = DAT_100050dc & local_10 << 0x11;
    _DAT_100050ec = DAT_100050dc & local_10 << 1;
    _DAT_100050a4 =
         ~(DAT_100050a8 >> 1 | DAT_100050ac) | ~(DAT_100050c0 >> 1 | DAT_100050c4) |
         ~(DAT_100050d8 >> 1 | DAT_100050dc);
    uVar2 = GKTOOLS::CountBits(local_18);
    *(uint *)(this + 200) = 8 - uVar2;
    uVar2 = GKTOOLS::CountBits(local_14);
    *(uint *)(this + 0xcc) = 8 - uVar2;
    uVar2 = GKTOOLS::CountBits(local_10);
    *(uint *)(this + 0xd0) = 8 - uVar2;
    uVar2 = GKTOOLS::ShiftPosition(local_18);
    *(uint *)(this + 0xd4) = uVar2;
    uVar2 = GKTOOLS::ShiftPosition(local_14);
    *(uint *)(this + 0xd8) = uVar2;
    uVar2 = GKTOOLS::ShiftPosition(local_10);
    *(uint *)(this + 0xdc) = uVar2;
    uVar2 = GKTOOLS::BytePosition(local_18);
    *(uint *)(this + 0xbc) = uVar2;
    uVar2 = GKTOOLS::BytePosition(local_14);
    *(uint *)(this + 0xc0) = uVar2;
    uVar2 = GKTOOLS::BytePosition(local_10);
    *(uint *)(this + 0xc4) = uVar2;
    *(uint *)(this + 0xe0) = local_1c;
    *(uint *)(this + 0xe4) = local_1c >> 3;
    *(int *)(this + 0x22e4) = *(int *)(this + 0xe4) * *(int *)(this + 0xa0);
    *(int *)(this + 0x22e8) = *(int *)(this + 0x22e4) << 1;
    *(int *)(this + 0x22ec) = *(int *)(this + 0x22e4) / 2;
    *(int *)(this + 0x20f4) = *(int *)(this + 0x22e8) - *(int *)(this + 0x22ec);
    *(int *)(this + 0x20f8) = *(int *)(this + 0x22e8) - *(int *)(this + 0x22e4);
    *(int *)(this + 0x20fc) = *(int *)(this + 0x22e8) - *(int *)(this + 0x22e4);
    *(undefined4 *)(this + 0x2100) = 0;
    *(int *)(this + 0x2104) = *(int *)(this + 0x22e8) - *(int *)(this + 0x22ec);
    *(undefined4 *)(this + 0x2108) = 0;
    *(undefined4 *)(this + 0x210c) = *(undefined4 *)(this + 0x22e8);
    *(undefined4 *)(this + 0x2110) = 0;
    *(int *)(this + 0x2114) = *(int *)(this + 0x22e8) - *(int *)(this + 0x22ec);
    *(int *)(this + 0x2118) = *(int *)(this + 0x22e8) + *(int *)(this + 0x22e4);
    *(int *)(this + 0x211c) = *(int *)(this + 0x22e8) - *(int *)(this + 0x22e4);
    *(undefined4 *)(this + 0x2120) = 0;
    *(int *)(this + 0x2124) = *(int *)(this + 0x22e8) - *(int *)(this + 0x22ec);
    *(undefined4 *)(this + 0x2128) = *(undefined4 *)(this + 0x22e8);
    *(undefined4 *)(this + 0x212c) = *(undefined4 *)(this + 0x22e8);
    *(undefined4 *)(this + 0x2130) = 0;
    *(undefined4 *)(this + 0x2134) = 0;
    *(int *)(this + 0x2138) = -*(int *)(this + 0xe4);
    *(undefined4 *)(this + 0x213c) = *(undefined4 *)(this + 0xe4);
    *(undefined4 *)(this + 0x2140) = 0;
    *(undefined4 *)(this + 0x2144) = *(undefined4 *)(this + 0xe4);
    *(undefined4 *)(this + 0x2148) = *(undefined4 *)(this + 0xe4);
    *(int *)(this + 0x214c) = -*(int *)(this + 0xe4);
    *(undefined4 *)(this + 0x2150) = 0;
    *(undefined4 *)(this + 0x2154) = 0;
    *(int *)(this + 0x2158) = -*(int *)(this + 0xe4);
    *(undefined4 *)(this + 0x215c) = *(undefined4 *)(this + 0xe4);
    *(undefined4 *)(this + 0x2160) = 0;
    *(undefined4 *)(this + 0x2164) = *(undefined4 *)(this + 0xe4);
    *(undefined4 *)(this + 0x2168) = *(undefined4 *)(this + 0xe4);
    *(int *)(this + 0x216c) = -*(int *)(this + 0xe4);
    *(undefined4 *)(this + 0x2170) = 0;
  }
  return;
}



// public: void __thiscall TILEBLITTER::InitTileSurface(class DD_SURFACE &,unsigned int,unsigned
// int)

void __thiscall
TILEBLITTER::InitTileSurface(TILEBLITTER *this,DD_SURFACE *param_1,uint param_2,uint param_3)

{
  undefined1 local_70 [8];
  uint local_68;
  uint local_64;
  
                    // 0x16b5  9  ?InitTileSurface@TILEBLITTER@@QAEXAAVDD_SURFACE@@II@Z
  *(undefined4 *)(this + 0xac) = 0;
  DD_SURFACE::operator=((DD_SURFACE *)this,param_1);
  DD_SURFACE::Desc((DD_SURFACE *)this,(ulong)local_70);
  *(uint *)(this + 0xb0) = param_2;
  *(uint *)(this + 0xb4) = param_3;
  *(uint *)(this + 0xb8) = (local_64 / param_2) * (local_68 / param_3);
  SetSurfaceInfo(this);
  return;
}



// public: void __thiscall TILEBLITTER::InitTileSurface(char const *,unsigned int,unsigned int)

void __thiscall
TILEBLITTER::InitTileSurface(TILEBLITTER *this,char *param_1,uint param_2,uint param_3)

{
  int iVar1;
  uint *puVar2;
  uint local_78;
  uint local_74;
  undefined4 local_70;
  uint local_6c [25];
  undefined4 local_8;
  
                    // 0x172b  10  ?InitTileSurface@TILEBLITTER@@QAEXPBDII@Z
  *(undefined4 *)(this + 0xac) = 1;
  GKTOOLS::GetDIBSize(param_1,&local_74,&local_78);
  puVar2 = local_6c;
  for (iVar1 = 0x1a; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  local_70 = 0x6c;
  local_6c[0] = 7;
  local_6c[2] = local_74;
  local_6c[1] = local_78;
  local_8 = 0x840;
  DD_SURFACE::Create((DD_SURFACE *)this,(_DDSURFACEDESC *)&local_70,(HWND__ *)0x0);
  GKTOOLS::CopyDIBToSurface((DD_SURFACE *)this,param_1,0,0,false);
  *(uint *)(this + 0xb0) = param_2;
  *(uint *)(this + 0xb4) = param_3;
  *(uint *)(this + 0xb8) = (local_74 / param_2) * (local_78 / param_3);
  SetSurfaceInfo(this);
  return;
}



void __thiscall
FUN_100017f6(void *this,undefined4 param_1,int *param_2,int *param_3,int *param_4,int *param_5,
            int *param_6,int *param_7)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  int local_50;
  int local_4c;
  int local_48;
  int local_44;
  int local_40;
  int local_3c;
  int local_38;
  int local_34;
  int local_30;
  int local_2c;
  int local_28;
  int local_24;
  int local_20;
  int local_1c;
  int local_18;
  int local_14;
  int local_10;
  int local_c;
  undefined4 local_8;
  
  local_10 = FUN_10002fe0();
  local_c = FUN_10002fe0();
  local_c = local_c * *(int *)((int)this + 0xe4);
  base(&param_1,&local_8);
  *param_2 = 0;
  *param_3 = *(int *)((int)this + 0x22e4);
  *param_4 = *(int *)((int)this + 0x22e4) * -0x10;
  *param_5 = *(int *)((int)this + 0x22e4) << 4;
  cVar1 = FUN_10003010(&param_1);
  if (cVar1 == '\0') {
    *param_6 = 0;
    *param_7 = 0;
  }
  else {
    FUN_10002f00(&local_14,0);
    bVar2 = FUN_10002f70(&local_8,&local_14);
    if (bVar2) {
      *param_3 = *(int *)((int)this + 0xa0) / 2 + local_10;
      *param_6 = 0;
      *param_7 = 0;
    }
    else {
      FUN_10002f00(&local_18,1);
      bVar2 = FUN_10002f70(&local_8,&local_18);
      if (bVar2) {
        *param_4 = -*(int *)((int)this + 0x22e4) / 2 + local_c * -2;
        *param_6 = *(int *)((int)this + 0xe4) << 1;
        *param_7 = *(int *)((int)this + 0xe4) << 1;
      }
      else {
        FUN_10002f00(&local_1c,2);
        bVar2 = FUN_10002f70(&local_8,&local_1c);
        if (bVar2) {
          *param_4 = -local_c;
          *param_6 = *(int *)((int)this + 0xe4);
          *param_7 = *(int *)((int)this + 0xe4);
        }
        else {
          FUN_10002f00(&local_20,3);
          bVar2 = FUN_10002f70(&local_8,&local_20);
          if (bVar2) {
            *param_4 = ((int)(*(int *)((int)this + 0x22e4) +
                             (*(int *)((int)this + 0x22e4) >> 0x1f & 3U)) >> 2) - local_c;
            *param_6 = *(int *)((int)this + 0xe4);
            *param_7 = 0;
          }
          else {
            FUN_10002f00(&local_24,4);
            bVar2 = FUN_10002f70(&local_8,&local_24);
            if (bVar2) {
              *param_4 = *(int *)((int)this + 0x22e4) / 2 - local_c;
              *param_6 = 0;
              *param_7 = 0;
            }
            else {
              FUN_10002f00(&local_28,5);
              bVar2 = FUN_10002f70(&local_8,&local_28);
              if (bVar2) {
                iVar3 = *(int *)((int)this + 0x22e4) * 3;
                *param_4 = ((int)(iVar3 + (iVar3 >> 0x1f & 3U)) >> 2) - local_c;
                *param_6 = -*(int *)((int)this + 0xe4);
                *param_7 = 0;
              }
              else {
                FUN_10002f00(&local_2c,6);
                bVar2 = FUN_10002f70(&local_8,&local_2c);
                if (bVar2) {
                  *param_4 = *(int *)((int)this + 0x22e4) - local_c;
                  *param_6 = -*(int *)((int)this + 0xe4);
                  *param_7 = -*(int *)((int)this + 0xe4);
                }
                else {
                  FUN_10002f00(&local_30,7);
                  bVar2 = FUN_10002f70(&local_8,&local_30);
                  if (bVar2) {
                    *param_4 = (*(int *)((int)this + 0x22e4) * 3) / 2 + local_c * -2;
                    *param_6 = *(int *)((int)this + 0xe4) * -2;
                    *param_7 = *(int *)((int)this + 0xe4) * -2;
                  }
                  else {
                    FUN_10002f00(&local_34,8);
                    bVar2 = FUN_10002f70(&local_8,&local_34);
                    if (bVar2) {
                      *param_2 = *(int *)((int)this + 0xa0) / 2 - local_10;
                      *param_6 = 0;
                      *param_7 = 0;
                    }
                    else {
                      FUN_10002f00(&local_38,9);
                      bVar2 = FUN_10002f70(&local_8,&local_38);
                      if (bVar2) {
                        *param_5 = -*(int *)((int)this + 0x22e4) / 2 + local_c * 2;
                        *param_6 = *(int *)((int)this + 0xe4) << 1;
                        *param_7 = *(int *)((int)this + 0xe4) << 1;
                      }
                      else {
                        FUN_10002f00(&local_3c,10);
                        bVar2 = FUN_10002f70(&local_8,&local_3c);
                        if (bVar2) {
                          *param_5 = local_c;
                          *param_6 = *(int *)((int)this + 0xe4);
                          *param_7 = *(int *)((int)this + 0xe4);
                        }
                        else {
                          FUN_10002f00(&local_40,0xb);
                          bVar2 = FUN_10002f70(&local_8,&local_40);
                          if (bVar2) {
                            *param_5 = ((int)(*(int *)((int)this + 0x22e4) +
                                             (*(int *)((int)this + 0x22e4) >> 0x1f & 3U)) >> 2) +
                                       local_c;
                            *param_6 = *(int *)((int)this + 0xe4);
                            *param_7 = 0;
                          }
                          else {
                            FUN_10002f00(&local_44,0xc);
                            bVar2 = FUN_10002f70(&local_8,&local_44);
                            if (bVar2) {
                              *param_5 = *(int *)((int)this + 0x22e4) / 2 + local_c;
                              *param_6 = 0;
                              *param_7 = 0;
                            }
                            else {
                              FUN_10002f00(&local_48,0xd);
                              bVar2 = FUN_10002f70(&local_8,&local_48);
                              if (bVar2) {
                                iVar3 = *(int *)((int)this + 0x22e4) * 3;
                                *param_5 = ((int)(iVar3 + (iVar3 >> 0x1f & 3U)) >> 2) + local_c;
                                *param_6 = -*(int *)((int)this + 0xe4);
                                *param_7 = 0;
                              }
                              else {
                                FUN_10002f00(&local_4c,0xe);
                                bVar2 = FUN_10002f70(&local_8,&local_4c);
                                if (bVar2) {
                                  *param_5 = *(int *)((int)this + 0x22e4) + local_c;
                                  *param_6 = -*(int *)((int)this + 0xe4);
                                  *param_7 = -*(int *)((int)this + 0xe4);
                                }
                                else {
                                  FUN_10002f00(&local_50,0xf);
                                  bVar2 = FUN_10002f70(&local_8,&local_50);
                                  if (bVar2) {
                                    *param_5 = (*(int *)((int)this + 0x22e4) * 3) / 2 + local_c * 2;
                                    *param_6 = *(int *)((int)this + 0xe4) * -2;
                                    *param_7 = *(int *)((int)this + 0xe4) * -2;
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return;
}



void __thiscall
FUN_10001dde(void *this,undefined4 param_1,undefined4 param_2,int *param_3,undefined4 *param_4,
            undefined4 *param_5)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int local_c;
  int local_8;
  
  iVar2 = FUN_10002ef0(&param_2);
  iVar3 = FUN_10002ef0(&param_1);
  *param_3 = (int)this + *(int *)((int)this + iVar3 * 4 + 0x20f4) + iVar2 * 0x200 + 0xf4;
  iVar2 = FUN_10002ef0(&param_1);
  *param_5 = *(undefined4 *)((int)this + iVar2 * 4 + 0x2134);
  FUN_10002f00(&local_8,4);
  bVar1 = FUN_10002f70(&param_1,&local_8);
  if (!bVar1) {
    FUN_10002f00(&local_c,0xc);
    bVar1 = FUN_10002f70(&param_1,&local_c);
    if (!bVar1) {
      *param_4 = *(undefined4 *)((int)this + 0xe4);
      return;
    }
  }
  *param_4 = 0;
  return;
}



// private: void __thiscall TILEBLITTER::SetPimaryColorLaser(unsigned char *,unsigned char
// *,int,int)

void __thiscall
TILEBLITTER::SetPimaryColorLaser
          (TILEBLITTER *this,uchar *param_1,uchar *param_2,int param_3,int param_4)

{
  int local_8;
  
                    // 0x1e89  13  ?SetPimaryColorLaser@TILEBLITTER@@AAEXPAE0HH@Z
  for (local_8 = 0; local_8 < 0x80; local_8 = local_8 + 1) {
    *(uint *)param_2 = (uint)(*param_1 >> ((byte)param_3 & 0x1f)) << ((byte)param_4 & 0x1f);
    param_1 = param_1 + 1;
    param_2 = param_2 + *(int *)(this + 0xe4);
  }
  return;
}



// private: void __thiscall TILEBLITTER::MakeCompositLaser(int)

void __thiscall TILEBLITTER::MakeCompositLaser(TILEBLITTER *this,int param_1)

{
  TILEBLITTER *local_28;
  TILEBLITTER *local_24;
  TILEBLITTER *local_20;
  TILEBLITTER *local_18;
  TILEBLITTER *local_14;
  int local_10;
  TILEBLITTER *local_8;
  
                    // 0x1ee9  11  ?MakeCompositLaser@TILEBLITTER@@AAEXH@Z
  local_18 = this + 0xf4;
  local_14 = this + 0x10f4;
  local_20 = this + 0xf4;
  local_24 = this + 0x10f4;
  local_28 = this + 0xf4;
  local_8 = this + 0x10f4;
  if ((param_1 & 4U) != 0) {
    local_18 = this + 0x8f4;
    local_14 = this + 0x18f4;
  }
  if ((param_1 & 2U) != 0) {
    local_20 = this + 0x4f4;
    local_24 = this + 0x14f4;
  }
  if ((param_1 & 1U) != 0) {
    local_28 = this + 0x2f4;
    local_8 = this + 0x12f4;
  }
  for (local_10 = 0; local_10 < 0x80; local_10 = local_10 + 1) {
    *(int *)(this + local_10 * 4 + param_1 * 0x200 + 0xf4) =
         *(int *)(local_28 + local_10 * 4) + *(int *)(local_20 + local_10 * 4) +
         *(int *)(local_18 + local_10 * 4);
    *(int *)(this + local_10 * 4 + param_1 * 0x200 + 0x10f4) =
         *(int *)(local_8 + local_10 * 4) + *(int *)(local_24 + local_10 * 4) +
         *(int *)(local_14 + local_10 * 4);
  }
  return;
}



// public: void __thiscall TILEBLITTER::SetLaserSize(int,int)

void __thiscall TILEBLITTER::SetLaserSize(TILEBLITTER *this,int param_1,int param_2)

{
  undefined4 local_10c;
  uchar local_108 [128];
  undefined4 local_88;
  uchar local_84 [128];
  
                    // 0x202f  12  ?SetLaserSize@TILEBLITTER@@QAEXHH@Z
  local_10c = *(int *)(this + 0xa0) * 2;
  if (*(int *)(this + 0xa0) == 8) {
    *(int *)(this + 0xe8) = param_1 >> 2;
  }
  else {
    *(int *)(this + 0xe8) = param_1;
  }
  *(int *)(this + 0xec) = (*(int *)(this + 0xe8) * 0xe) / 10;
  *(uint *)(this + 0xf0) = param_2 & 0xff;
  for (local_88 = 0; local_88 < 0x80; local_88 = local_88 + 1) {
    local_84[local_88] = '\0';
    local_108[local_88] = '\0';
  }
  for (local_88 = 1; local_88 <= *(int *)(this + 0xe8); local_88 = local_88 + 1) {
    if ((0 < (local_10c - *(int *)(this + 0xe8)) + local_88) &&
       (0 < (local_10c - *(int *)(this + 0xe8)) + local_88)) {
      local_84[(local_10c - *(int *)(this + 0xe8)) + local_88] =
           (uchar)((*(int *)(this + 0xf0) * local_88) / *(int *)(this + 0xe8));
      local_84[(local_10c + *(int *)(this + 0xe8)) - local_88] =
           (uchar)((*(int *)(this + 0xf0) * local_88) / *(int *)(this + 0xe8));
    }
  }
  local_84[local_10c] = 0xff;
  if (0x1f < *(int *)(this + 0xa0)) {
    local_84[local_10c + 1] = 0xff;
    local_84[local_10c + -1] = 0xff;
  }
  for (local_88 = 1; local_88 <= *(int *)(this + 0xec); local_88 = local_88 + 1) {
    if ((0 < (local_10c - *(int *)(this + 0xec)) + 1 + local_88) &&
       (0 < (local_10c - *(int *)(this + 0xec)) + local_88)) {
      local_108[(local_10c - *(int *)(this + 0xec)) + local_88] =
           (uchar)((*(int *)(this + 0xf0) * local_88) / *(int *)(this + 0xec));
      local_108[((local_10c + *(int *)(this + 0xec)) - local_88) + 1] =
           (uchar)((*(int *)(this + 0xf0) * local_88) / *(int *)(this + 0xec));
    }
  }
  local_108[local_10c] = 0xff;
  if (0x1f < *(int *)(this + 0xa0)) {
    local_108[local_10c + 2] = 0xff;
    local_108[local_10c + 1] = 0xff;
    local_108[local_10c + -1] = 0xff;
  }
  memset(this + 0xf4,0,0x1000);
  memset(this + 0x10f4,0,0x1000);
  SetPimaryColorLaser(this,local_84,(uchar *)(this + 0x2f4),*(int *)(this + 0xd0),
                      *(int *)(this + 0xc4));
  SetPimaryColorLaser(this,local_108,(uchar *)(this + 0x12f4),*(int *)(this + 0xd0),
                      *(int *)(this + 0xc4));
  SetPimaryColorLaser(this,local_84,(uchar *)(this + 0x4f4),*(int *)(this + 0xcc),
                      *(int *)(this + 0xd8));
  SetPimaryColorLaser(this,local_108,(uchar *)(this + 0x14f4),*(int *)(this + 0xcc),
                      *(int *)(this + 0xd8));
  SetPimaryColorLaser(this,local_84,(uchar *)(this + 0x8f4),*(int *)(this + 200),
                      *(int *)(this + 0xd4));
  SetPimaryColorLaser(this,local_108,(uchar *)(this + 0x18f4),*(int *)(this + 200),
                      *(int *)(this + 0xd4));
  MakeCompositLaser(this,3);
  MakeCompositLaser(this,5);
  MakeCompositLaser(this,6);
  MakeCompositLaser(this,7);
  return;
}



// public: bool __thiscall TILEBLITTER::SetupLaserEffect(class DD_SURFACE &)

bool __thiscall TILEBLITTER::SetupLaserEffect(TILEBLITTER *this,DD_SURFACE *param_1)

{
  bool bVar1;
  int iVar2;
  
                    // 0x2520  16  ?SetupLaserEffect@TILEBLITTER@@QAE_NAAVDD_SURFACE@@@Z
  DD_SURFACE::operator=((DD_SURFACE *)(this + 0x2174),param_1);
  iVar2 = DD_SURFACE::Lock(param_1,(_DDSURFACEDESC *)(this + 0x2278));
  if (iVar2 == 0) {
    bVar1 = false;
  }
  else {
    iVar2 = DD_SURFACE::Lock((DD_SURFACE *)this,(_DDSURFACEDESC *)(this + 0x220c));
    if (iVar2 == 0) {
      bVar1 = false;
    }
    else {
      bVar1 = true;
    }
  }
  return bVar1;
}



// public: void __thiscall TILEBLITTER::EndLaserEffect(class DD_SURFACE &)

void __thiscall TILEBLITTER::EndLaserEffect(TILEBLITTER *this,DD_SURFACE *param_1)

{
                    // 0x2578  8  ?EndLaserEffect@TILEBLITTER@@QAEXAAVDD_SURFACE@@@Z
  DD_SURFACE::Unlock((DD_SURFACE *)(this + 0x2174));
  DD_SURFACE::Unlock((DD_SURFACE *)this);
  return;
}



// private: void __thiscall TILEBLITTER::DoLaserBlt(unsigned char *,int,int,unsigned char
// *,int,int,unsigned char *,int,int,class CCut,class CCut)

void __thiscall
TILEBLITTER::DoLaserBlt
          (TILEBLITTER *this,uint *param_1,undefined4 param_2,int param_3,uint *param_4,int param_5,
          int param_6,ushort *param_7,undefined4 param_8,int param_9,int param_11,int param_12)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int local_70;
  uint local_68;
  int local_64;
  int local_60;
  int local_5c;
  int local_58;
  int local_54;
  int local_50;
  int local_4c;
  int local_48;
  int local_44;
  int local_40;
  int local_3c;
  uint local_38;
  int local_34;
  int local_30;
  int local_2c;
  uint local_28;
  int local_24;
  int local_20;
  int local_1c;
  int local_18;
  int local_14;
  int local_10;
  uint local_c;
  int local_8;
  
                    // 0x259d  7  ?DoLaserBlt@TILEBLITTER@@AAEXPAEHH0HH0HHVCCut@@1@Z
  bVar1 = DD_SURFACE::IsLost((DD_SURFACE *)this);
  if ((!bVar1) && (bVar1 = DD_SURFACE::IsLost((DD_SURFACE *)(this + 0x2174)), !bVar1)) {
    cVar2 = FUN_10003010(&param_11);
    if (cVar2 == '\0') {
      for (local_8 = 0; local_8 < *(int *)(this + 0xa0); local_8 = local_8 + 1) {
        FUN_100030f4(param_1,param_4,param_7,*(int *)(this + 0x22e4),param_5,*(int *)(this + 0xe0));
        param_1 = (uint *)((int)param_1 + param_3);
        param_4 = (uint *)((int)param_4 + param_6);
        param_7 = (ushort *)((int)param_7 + param_9);
      }
    }
    else {
      cVar2 = FUN_10003010(&param_12);
      if (cVar2 == '\0') {
        FUN_100017f6(this,param_11,&local_14,&local_10,&local_20,&local_24,&local_1c,&local_18);
        for (local_c = 0; (int)local_c < *(int *)(this + 0xa0); local_c = local_c + 1) {
          iVar4 = local_18;
          if ((local_c & 1) == 0) {
            iVar4 = local_1c;
          }
          local_20 = local_20 + iVar4;
          local_24 = local_24 + iVar4;
          if (((int)local_c < local_14) || (local_10 <= (int)local_c)) {
            local_28 = 0;
            local_30 = 0;
          }
          else {
            local_28 = FUN_10002e00(0,local_20,*(int *)(this + 0x22e4));
            local_30 = FUN_10002e00(0,local_24,*(int *)(this + 0x22e4));
          }
          local_2c = FUN_10002e80(local_30 - local_28,0);
          if (0 < (int)local_28) {
            FUN_10003772((int)param_1,(int)param_7,local_28);
          }
          FUN_100030f4((uint *)((int)param_1 + local_28),
                       (uint *)((int)param_4 + (-(uint)(param_5 != 0) & local_28)),
                       (ushort *)((int)param_7 + local_28),local_2c,param_5,*(int *)(this + 0xe0));
          if (local_30 < *(int *)(this + 0x22e4)) {
            FUN_10003772((int)param_1 + local_30,(int)param_7 + local_30,
                         *(int *)(this + 0x22e4) - local_30);
          }
          param_1 = (uint *)((int)param_1 + param_3);
          param_4 = (uint *)((int)param_4 + param_6);
          param_7 = (ushort *)((int)param_7 + param_9);
        }
      }
      else {
        FUN_100017f6(this,param_11,&local_44,&local_3c,&local_5c,&local_60,&local_4c,&local_48);
        FUN_100017f6(this,param_12,&local_54,&local_34,&local_58,&local_64,&local_50,&local_40);
        for (local_38 = 0; (int)local_38 < *(int *)(this + 0xa0); local_38 = local_38 + 1) {
          iVar4 = local_40;
          iVar3 = local_48;
          if ((local_38 & 1) == 0) {
            iVar4 = local_50;
            iVar3 = local_4c;
          }
          local_58 = local_58 + iVar4;
          local_5c = local_5c + iVar3;
          local_60 = local_60 + iVar3;
          local_64 = local_64 + iVar4;
          if (((((int)local_38 < local_44) || (local_3c <= (int)local_38)) ||
              ((int)local_38 < local_54)) || (local_34 <= (int)local_38)) {
            local_68 = 0;
            local_70 = 0;
          }
          else {
            iVar4 = *(int *)(this + 0x22e4);
            iVar3 = FUN_10002e80(local_5c,local_58);
            local_68 = FUN_10002e00(0,iVar3,iVar4);
            iVar4 = *(int *)(this + 0x22e4);
            iVar3 = FUN_10002eb0(local_60,local_64);
            local_70 = FUN_10002e00(0,iVar3,iVar4);
          }
          iVar4 = FUN_10002e80(local_70 - local_68,0);
          if (0 < (int)local_68) {
            FUN_10003772((int)param_1,(int)param_7,local_68);
          }
          FUN_100030f4((uint *)((int)param_1 + local_68),
                       (uint *)((int)param_4 + (-(uint)(param_5 != 0) & local_68)),
                       (ushort *)((int)param_7 + local_68),iVar4,param_5,*(int *)(this + 0xe0));
          if (local_70 < *(int *)(this + 0x22e4)) {
            FUN_10003772((int)param_1 + local_70,(int)param_7 + local_70,
                         *(int *)(this + 0x22e4) - local_70);
          }
          param_1 = (uint *)((int)param_1 + param_3);
          param_4 = (uint *)((int)param_4 + param_6);
          param_7 = (ushort *)((int)param_7 + param_9);
        }
      }
    }
  }
  return;
}



// private: void __thiscall TILEBLITTER::DoCopyBlt(unsigned char *,int,int,unsigned char *,int,int)

void __thiscall
TILEBLITTER::DoCopyBlt
          (TILEBLITTER *this,uchar *param_1,int param_2,int param_3,uchar *param_4,int param_5,
          int param_6)

{
  bool bVar1;
  int local_8;
  
                    // 0x29f5  6  ?DoCopyBlt@TILEBLITTER@@AAEXPAEHH0HH@Z
  bVar1 = DD_SURFACE::IsLost((DD_SURFACE *)this);
  if ((!bVar1) && (bVar1 = DD_SURFACE::IsLost((DD_SURFACE *)(this + 0x2174)), !bVar1)) {
    for (local_8 = 0; local_8 < *(int *)(this + 0xa0); local_8 = local_8 + 1) {
      FUN_10003772((int)param_1,(int)param_4,*(int *)(this + 0x22e4));
      param_1 = param_1 + param_3;
      param_4 = param_4 + param_6;
    }
  }
  return;
}



void __thiscall FUN_10002a80(void *this,uint param_1,undefined4 *param_2,int *param_3,int *param_4)

{
  uint uVar1;
  
  uVar1 = *(uint *)((int)this + 0x2218);
  *param_2 = *(undefined4 *)((int)this + 0xe4);
  *param_3 = *(int *)((int)this + 0x221c);
  *param_4 = *(int *)((int)this + 0x2230) +
             (int)((ulonglong)param_1 % ((ulonglong)uVar1 / (ulonglong)*(uint *)((int)this + 0xb0)))
             * *(int *)((int)this + 0x22e4) +
             (int)((ulonglong)param_1 / ((ulonglong)uVar1 / (ulonglong)*(uint *)((int)this + 0xb0)))
             * *(int *)((int)this + 0xa0) * *param_3;
  return;
}



void __thiscall
FUN_10002b1f(void *this,int param_1,int param_2,int *param_3,int *param_4,int *param_5)

{
  *param_3 = *(int *)((int)this + 0xe4);
  *param_4 = *(int *)((int)this + 0x2288);
  *param_5 = *(int *)((int)this + 0x229c) +
             (param_1 * *(int *)((int)this + 0xa0) + *(int *)((int)this + 0xa4)) * *param_3 +
             (param_2 * *(int *)((int)this + 0xa0) + *(int *)((int)this + 0xa8)) * *param_4;
  return;
}



// public: void __thiscall TILEBLITTER::AddLaserToScreen(unsigned int,struct CPosition,class
// CDirection,class CColor,class CCut,class CCut)

void __thiscall
TILEBLITTER::AddLaserToScreen
          (TILEBLITTER *this,uint param_1,int param_3,int param_4,undefined4 param_5,
          undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  int local_28;
  undefined4 local_24;
  int local_20;
  int local_1c;
  int local_18;
  undefined4 local_14;
  int local_10;
  undefined4 local_c;
  int local_8;
  
                    // 0x2b92  3
                    // ?AddLaserToScreen@TILEBLITTER@@QAEXIUCPosition@@VCDirection@@VCColor@@VCCut@@3@Z
  local_24 = 0xffffffff;
  local_8 = -1;
  FUN_10002a80(this,param_1,&local_24,&local_8,&local_20);
  local_14 = 0xffffffff;
  local_c = 0xffffffff;
  FUN_10001dde(this,param_5,param_6,&local_1c,&local_14,&local_c);
  local_10 = -1;
  local_28 = -1;
  FUN_10002b1f(this,param_3,param_4,&local_10,&local_28,&local_18);
  DoLaserBlt(this,local_20,local_24,local_8,local_1c,local_14,local_c,local_18,local_10,local_28,
             param_7,param_8);
  return;
}



// public: void __thiscall TILEBLITTER::AddLaserToTile(unsigned int,unsigned int,class
// CDirection,class CColor,class CCut,class CCut)

void __thiscall
TILEBLITTER::AddLaserToTile
          (TILEBLITTER *this,uint param_1,uint param_2,undefined4 param_4,undefined4 param_5,
          undefined4 param_6,undefined4 param_7)

{
  int local_28;
  undefined4 local_24;
  int local_20;
  int local_1c;
  int local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  int local_8;
  
                    // 0x2c4f  4
                    // ?AddLaserToTile@TILEBLITTER@@QAEXIIVCDirection@@VCColor@@VCCut@@2@Z
  FUN_10002a80(this,param_1,&local_24,&local_8,&local_20);
  FUN_10001dde(this,param_4,param_5,&local_1c,&local_14,&local_c);
  FUN_10002a80(this,param_2,&local_10,&local_28,&local_18);
  DoLaserBlt(this,local_20,local_24,local_8,local_1c,local_14,local_c,local_18,local_10,local_28,
             param_6,param_7);
  return;
}



// public: void __thiscall TILEBLITTER::AddTileToScreen(unsigned int,struct CPosition)

void __thiscall TILEBLITTER::AddTileToScreen(TILEBLITTER *this,uint param_1,int param_3,int param_4)

{
  bool bVar1;
  int local_2c;
  int local_28;
  uchar *local_24;
  uchar *local_20;
  int local_1c;
  int local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x2cde  5  ?AddTileToScreen@TILEBLITTER@@QAEXIUCPosition@@@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_10003cc8;
  local_10 = ExceptionList;
  local_14 = &stack0xffffffc4;
  ExceptionList = &local_10;
  bVar1 = DD_SURFACE::IsLost((DD_SURFACE *)this);
  if ((!bVar1) && (bVar1 = DD_SURFACE::IsLost((DD_SURFACE *)(this + 0x2174)), !bVar1)) {
    FUN_10002a80(this,param_1,&local_28,&local_18,(int *)&local_24);
    FUN_10002b1f(this,param_3,param_4,&local_1c,&local_2c,(int *)&local_20);
    local_8 = 0;
    DoCopyBlt(this,local_24,local_28,local_18,local_20,local_1c,local_2c);
    FUN_10002d97();
    return;
  }
  ExceptionList = local_10;
  return;
}



undefined * Catch_10002d91(void)

{
  return FUN_10002d97;
}



void FUN_10002d97(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



int __thiscall FUN_10002dc0(void *this,uint param_1)

{
  TILEBLITTER::~TILEBLITTER((TILEBLITTER *)this);
  if ((param_1 & 1) != 0) {
    operator_delete((void *)((int)this + -0x98));
  }
  return (int)this + -0x98;
}



int __cdecl FUN_10002e00(int param_1,int param_2,int param_3)

{
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  if (param_1 < param_3) {
    if (param_2 < param_1) {
      local_8 = param_1;
    }
    else {
      if (param_3 < param_2) {
        local_c = param_3;
      }
      else {
        local_c = param_2;
      }
      local_8 = local_c;
    }
    local_10 = local_8;
  }
  else {
    if (param_2 < param_3) {
      local_14 = param_3;
    }
    else {
      if (param_1 < param_2) {
        local_18 = param_1;
      }
      else {
        local_18 = param_2;
      }
      local_14 = local_18;
    }
    local_10 = local_14;
  }
  return local_10;
}



int __cdecl FUN_10002e80(int param_1,int param_2)

{
  undefined4 local_8;
  
  if (param_2 < param_1) {
    local_8 = param_1;
  }
  else {
    local_8 = param_2;
  }
  return local_8;
}



int __cdecl FUN_10002eb0(int param_1,int param_2)

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



void FUN_10002ee0(void)

{
  return;
}



undefined4 __fastcall FUN_10002ef0(undefined4 *param_1)

{
  return *param_1;
}



void * __thiscall FUN_10002f00(void *this,uint param_1)

{
  FUN_10002f20(this,param_1);
  return this;
}



void __thiscall FUN_10002f20(void *this,uint param_1)

{
  uint uVar1;
  
  uVar1 = FUN_10002f40(param_1);
  *(uint *)this = uVar1;
  return;
}



uint __cdecl FUN_10002f40(uint param_1)

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



bool __thiscall FUN_10002f70(void *this,int *param_1)

{
                    // WARNING: Load size is inaccurate
  return *this == *param_1;
}



void * __fastcall FUN_10002f90(void *param_1)

{
  FUN_10002fb0(param_1,0,0);
  return param_1;
}



void * __thiscall FUN_10002fb0(void *this,undefined4 param_1,undefined4 param_2)

{
  *(undefined4 *)this = param_1;
  *(undefined4 *)((int)this + 4) = param_2;
  return this;
}



undefined4 FUN_10002fe0(void)

{
  return 0;
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



void __fastcall FUN_10003010(int *param_1)

{
  FUN_10003030(param_1);
  return;
}



bool __fastcall FUN_10003030(int *param_1)

{
  return *param_1 != -0x400;
}



undefined4 * __fastcall FUN_10003050(undefined4 *param_1)

{
  param_1[1] = 0;
  *param_1 = &PTR_FUN_100040dc;
  return param_1;
}



void __fastcall FUN_10003080(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_100040dc;
  return;
}



void * __thiscall FUN_100030a0(void *this,uint param_1)

{
  FUN_10003080((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



// public: void __thiscall TILEBLITTER::SetPosition(struct CPosition)

void __thiscall TILEBLITTER::SetPosition(TILEBLITTER *this,undefined4 param_2,undefined4 param_3)

{
                    // 0x30d0  14  ?SetPosition@TILEBLITTER@@QAEXUCPosition@@@Z
  *(undefined4 *)(this + 0xa4) = param_2;
  *(undefined4 *)(this + 0xa8) = param_3;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl
FUN_100030f4(uint *param_1,uint *param_2,ushort *param_3,int param_4,int param_5,int param_6)

{
  byte bVar1;
  char cVar2;
  ushort uVar3;
  ushort uVar4;
  byte bVar6;
  uint uVar5;
  int iVar7;
  int iVar8;
  byte bVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint3 uVar14;
  
  if (param_5 != 0) {
    if (param_6 != 0x10) {
      iVar7 = param_4 + -4;
      do {
        while( true ) {
          if (iVar7 < 0) {
            iVar8 = iVar7 + 3;
            if (iVar8 < 0) {
              return;
            }
            cVar2 = *(byte *)(iVar8 + (int)param_1) + *(byte *)(iVar8 + (int)param_2);
            if (CARRY1(*(byte *)(iVar8 + (int)param_1),*(byte *)(iVar8 + (int)param_2))) {
              cVar2 = -1;
            }
            *(char *)(iVar8 + (int)param_3) = cVar2;
            iVar8 = iVar7 + 2;
            if (iVar8 < 0) {
              return;
            }
            cVar2 = *(byte *)(iVar8 + (int)param_1) + *(byte *)(iVar8 + (int)param_2);
            if (CARRY1(*(byte *)(iVar8 + (int)param_1),*(byte *)(iVar8 + (int)param_2))) {
              cVar2 = -1;
            }
            *(char *)(iVar8 + (int)param_3) = cVar2;
            iVar7 = iVar7 + 1;
            if (iVar7 < 0) {
              return;
            }
            cVar2 = *(byte *)(iVar7 + (int)param_1) + *(byte *)(iVar7 + (int)param_2);
            if (CARRY1(*(byte *)(iVar7 + (int)param_1),*(byte *)(iVar7 + (int)param_2))) {
              cVar2 = -1;
            }
            *(char *)(iVar7 + (int)param_3) = cVar2;
            return;
          }
          uVar5 = *(uint *)(iVar7 + (int)param_1);
          uVar11 = *(uint *)(iVar7 + (int)param_2);
          if (uVar5 != 0) break;
          *(uint *)(iVar7 + (int)param_3) = uVar11;
joined_r0x10003706:
          iVar7 = iVar7 + -4;
        }
        if (uVar11 == 0) {
          *(uint *)(iVar7 + (int)param_3) = uVar5;
          goto joined_r0x10003706;
        }
        if (((uVar5 | uVar11) & 0x80808080) == 0) {
          *(uint *)(iVar7 + (int)param_3) = uVar5 + uVar11;
          goto joined_r0x10003706;
        }
        cVar2 = (byte)uVar5 + (byte)uVar11;
        if (CARRY1((byte)uVar5,(byte)uVar11)) {
          cVar2 = -1;
        }
        bVar6 = (byte)(uVar5 >> 8);
        bVar1 = (byte)(uVar11 >> 8);
        uVar3 = CONCAT11(bVar6 + bVar1,cVar2);
        if (CARRY1(bVar6,bVar1)) {
          uVar3 = CONCAT11(0xff,cVar2);
        }
        bVar6 = (byte)(uVar11 >> 0x10);
        bVar1 = (byte)(uVar5 >> 0x18);
        bVar9 = (byte)(uVar11 >> 0x18);
        cVar2 = bVar1 + bVar9;
        if (CARRY1(bVar1,bVar9)) {
          cVar2 = -1;
        }
        bVar1 = (byte)(uVar5 >> 0x10);
        uVar4 = CONCAT11(bVar1 + bVar6,cVar2);
        if (CARRY1(bVar1,bVar6)) {
          uVar4 = CONCAT11(0xff,cVar2);
        }
        *(uint *)(iVar7 + (int)param_3) =
             uVar3 & 0xff | ((uint)(uVar3 >> 8) << 0x10) >> 8 | (uVar4 & 0xff00) << 8 |
             CONCAT22(uVar3 >> 8,uVar4) << 0x18;
        iVar7 = iVar7 + -4;
      } while( true );
    }
    iVar7 = param_4 + -4;
    do {
      while( true ) {
        if (iVar7 < 0) {
          if (iVar7 != -2) {
            return;
          }
          uVar5 = (*param_1 & DAT_100050a8) + (*param_2 & DAT_100050a8);
          if (CARRY4(*param_1 & DAT_100050a8,*param_2 & DAT_100050a8)) {
            uVar5 = uVar5 | DAT_100050b0;
          }
          if ((_DAT_100050b8 & uVar5) != 0) {
            uVar5 = uVar5 | DAT_100050b0;
          }
          if ((_DAT_100050bc & uVar5) != 0) {
            uVar5 = uVar5 | DAT_100050b4;
          }
          uVar11 = (*param_1 & DAT_100050c0) + (*param_2 & DAT_100050c0);
          if (CARRY4(*param_1 & DAT_100050c0,*param_2 & DAT_100050c0)) {
            uVar11 = uVar11 | DAT_100050c8;
          }
          if ((_DAT_100050d0 & uVar11) != 0) {
            uVar11 = uVar11 | DAT_100050c8;
          }
          if ((_DAT_100050d4 & uVar11) != 0) {
            uVar11 = uVar11 | DAT_100050cc;
          }
          uVar12 = (*param_1 & DAT_100050d8) + (*param_2 & DAT_100050d8);
          if (CARRY4(*param_1 & DAT_100050d8,*param_2 & DAT_100050d8)) {
            uVar12 = uVar12 | DAT_100050e0;
          }
          if ((_DAT_100050e8 & uVar12) != 0) {
            uVar12 = uVar12 | DAT_100050e0;
          }
          if ((_DAT_100050ec & uVar12) != 0) {
            uVar12 = uVar12 | DAT_100050e4;
          }
          *param_3 = (ushort)uVar5 & (ushort)DAT_100050a8 | (ushort)uVar11 & (ushort)DAT_100050c0 |
                     (ushort)uVar12 & (ushort)DAT_100050d8;
          return;
        }
        uVar5 = *(uint *)(iVar7 + (int)param_1);
        uVar11 = *(uint *)(iVar7 + (int)param_2);
        if (uVar5 != 0) break;
        *(uint *)(iVar7 + (int)param_3) = uVar11;
joined_r0x1000350c:
        iVar7 = iVar7 + -4;
      }
      if (uVar11 == 0) {
        *(uint *)(iVar7 + (int)param_3) = uVar5;
        goto joined_r0x1000350c;
      }
      if (((uVar5 | uVar11) & _DAT_100050a4) == 0) {
        *(uint *)(iVar7 + (int)param_3) = uVar5 + uVar11;
        goto joined_r0x1000350c;
      }
      uVar5 = *(uint *)(iVar7 + (int)param_1) & DAT_100050a8;
      uVar12 = *(uint *)(iVar7 + (int)param_2) & DAT_100050a8;
      uVar11 = uVar5 + uVar12;
      if (CARRY4(uVar5,uVar12)) {
        uVar11 = uVar11 | DAT_100050b0;
      }
      if ((_DAT_100050b8 & uVar11) != 0) {
        uVar11 = uVar11 | DAT_100050b0;
      }
      if ((_DAT_100050bc & uVar11) != 0) {
        uVar11 = uVar11 | DAT_100050b4;
      }
      uVar5 = *(uint *)(iVar7 + (int)param_1) & DAT_100050c0;
      uVar13 = *(uint *)(iVar7 + (int)param_2) & DAT_100050c0;
      uVar12 = uVar5 + uVar13;
      if (CARRY4(uVar5,uVar13)) {
        uVar12 = uVar12 | DAT_100050c8;
      }
      if ((_DAT_100050d0 & uVar12) != 0) {
        uVar12 = uVar12 | DAT_100050c8;
      }
      if ((_DAT_100050d4 & uVar12) != 0) {
        uVar12 = uVar12 | DAT_100050cc;
      }
      uVar5 = *(uint *)(iVar7 + (int)param_1) & DAT_100050d8;
      uVar10 = *(uint *)(iVar7 + (int)param_2) & DAT_100050d8;
      uVar13 = uVar5 + uVar10;
      if (CARRY4(uVar5,uVar10)) {
        uVar13 = uVar13 | DAT_100050e0;
      }
      if ((_DAT_100050e8 & uVar13) != 0) {
        uVar13 = uVar13 | DAT_100050e0;
      }
      if ((_DAT_100050ec & uVar13) != 0) {
        uVar13 = uVar13 | DAT_100050e4;
      }
      *(uint *)(iVar7 + (int)param_3) =
           uVar11 & DAT_100050a8 | uVar12 & DAT_100050c0 | uVar13 & DAT_100050d8;
      iVar7 = iVar7 + -4;
    } while( true );
  }
  if (param_6 != 0x10) {
    if (param_6 == 0x18) {
      iVar7 = param_4 + -4;
      if (-1 < iVar7) {
        uVar5 = *param_2;
        do {
          while( true ) {
            uVar11 = *(uint *)(iVar7 + (int)param_1);
            bVar6 = (byte)(uVar5 >> 0x10);
            uVar14 = (uint3)(ushort)uVar5 | (uint3)(((uVar5 >> 0x10) << 0x18) >> 8);
            uVar12 = CONCAT31(uVar14,bVar6);
            if (uVar11 != 0) break;
            *(uint *)(iVar7 + (int)param_3) = uVar12;
joined_r0x10003383:
            iVar7 = iVar7 + -4;
            uVar5 = uVar12;
            if (iVar7 < 0) goto LAB_100033b1;
          }
          if (uVar12 == 0) {
            *(uint *)(iVar7 + (int)param_3) = uVar11;
            goto joined_r0x10003383;
          }
          if (((uVar11 | uVar12) & 0x80808080) == 0) {
            *(uint *)(iVar7 + (int)param_3) = uVar11 + uVar12;
            goto joined_r0x10003383;
          }
          cVar2 = (byte)uVar11 + bVar6;
          if (CARRY1((byte)uVar11,bVar6)) {
            cVar2 = -1;
          }
          bVar1 = (byte)(uVar11 >> 8);
          uVar3 = CONCAT11(bVar1 + (byte)uVar5,cVar2);
          if (CARRY1(bVar1,(byte)uVar5)) {
            uVar3 = CONCAT11(0xff,cVar2);
          }
          bVar1 = (byte)(uVar11 >> 0x18);
          cVar2 = bVar1 + bVar6;
          if (CARRY1(bVar1,bVar6)) {
            cVar2 = -1;
          }
          bVar1 = (byte)(uVar11 >> 0x10);
          bVar9 = (byte)((uVar14 & 0xff00) >> 8);
          uVar4 = CONCAT11(bVar1 + bVar9,cVar2);
          if (CARRY1(bVar1,bVar9)) {
            uVar4 = CONCAT11(0xff,cVar2);
          }
          uVar5 = (uint)bVar6 | ((uVar14 & 0xff) << 0x10) >> 8 | (uVar14 & 0xff00) << 8;
          *(uint *)(iVar7 + (int)param_3) =
               uVar3 & 0xff | ((uint)(uVar3 >> 8) << 0x10) >> 8 | (uVar4 & 0xff00) << 8 |
               CONCAT22(uVar3 >> 8,uVar4) << 0x18;
          iVar7 = iVar7 + -4;
        } while (-1 < iVar7);
      }
LAB_100033b1:
      iVar8 = iVar7 + 3;
      if (-1 < iVar8) {
        cVar2 = *(byte *)(iVar8 + (int)param_1) + *(byte *)(iVar8 + (int)param_2);
        if (CARRY1(*(byte *)(iVar8 + (int)param_1),*(byte *)(iVar8 + (int)param_2))) {
          cVar2 = -1;
        }
        *(char *)(iVar8 + (int)param_3) = cVar2;
        iVar8 = iVar7 + 2;
        if (-1 < iVar8) {
          cVar2 = *(byte *)(iVar8 + (int)param_1) + *(byte *)(iVar8 + (int)param_2);
          if (CARRY1(*(byte *)(iVar8 + (int)param_1),*(byte *)(iVar8 + (int)param_2))) {
            cVar2 = -1;
          }
          *(char *)(iVar8 + (int)param_3) = cVar2;
          iVar7 = iVar7 + 1;
          if (-1 < iVar7) {
            cVar2 = *(byte *)(iVar7 + (int)param_1) + *(byte *)(iVar7 + (int)param_2);
            if (CARRY1(*(byte *)(iVar7 + (int)param_1),*(byte *)(iVar7 + (int)param_2))) {
              cVar2 = -1;
            }
            *(char *)(iVar7 + (int)param_3) = cVar2;
          }
        }
      }
    }
    else {
      iVar7 = param_4 + -4;
      if (-1 < iVar7) {
        uVar5 = *param_2;
        do {
          while (uVar11 = *(uint *)(iVar7 + (int)param_1), uVar11 == 0) {
            *(uint *)(iVar7 + (int)param_3) = uVar5;
            iVar7 = iVar7 + -4;
            if (iVar7 < 0) goto LAB_1000346b;
          }
          if (uVar5 == 0) {
            *(uint *)(iVar7 + (int)param_3) = uVar11;
          }
          else if (((uVar11 | uVar5) & 0x80808080) == 0) {
            *(uint *)(iVar7 + (int)param_3) = uVar11 + uVar5;
          }
          else {
            cVar2 = (byte)uVar11 + (byte)uVar5;
            if (CARRY1((byte)uVar11,(byte)uVar5)) {
              cVar2 = -1;
            }
            bVar6 = (byte)(uVar11 >> 8);
            bVar1 = (byte)(uVar5 >> 8);
            uVar3 = CONCAT11(bVar6 + bVar1,cVar2);
            if (CARRY1(bVar6,bVar1)) {
              uVar3 = CONCAT11(0xff,cVar2);
            }
            bVar6 = (byte)(uVar5 >> 0x10);
            bVar1 = (byte)(uVar11 >> 0x18);
            bVar9 = (byte)(uVar5 >> 0x18);
            cVar2 = bVar1 + bVar9;
            if (CARRY1(bVar1,bVar9)) {
              cVar2 = -1;
            }
            bVar1 = (byte)(uVar11 >> 0x10);
            uVar4 = CONCAT11(bVar1 + bVar6,cVar2);
            if (CARRY1(bVar1,bVar6)) {
              uVar4 = CONCAT11(0xff,cVar2);
            }
            *(uint *)(iVar7 + (int)param_3) =
                 uVar3 & 0xff | ((uint)(uVar3 >> 8) << 0x10) >> 8 | (uVar4 & 0xff00) << 8 |
                 CONCAT22(uVar3 >> 8,uVar4) << 0x18;
          }
          iVar7 = iVar7 + -4;
        } while (-1 < iVar7);
      }
LAB_1000346b:
      iVar8 = iVar7 + 3;
      if (-1 < iVar8) {
        cVar2 = *(byte *)(iVar8 + (int)param_1) + *(byte *)(iVar8 + (int)param_2);
        if (CARRY1(*(byte *)(iVar8 + (int)param_1),*(byte *)(iVar8 + (int)param_2))) {
          cVar2 = -1;
        }
        *(char *)(iVar8 + (int)param_3) = cVar2;
        iVar8 = iVar7 + 2;
        if (-1 < iVar8) {
          cVar2 = *(byte *)(iVar8 + (int)param_1) + *(byte *)(iVar8 + (int)param_2);
          if (CARRY1(*(byte *)(iVar8 + (int)param_1),*(byte *)(iVar8 + (int)param_2))) {
            cVar2 = -1;
          }
          *(char *)(iVar8 + (int)param_3) = cVar2;
          iVar7 = iVar7 + 1;
          if (-1 < iVar7) {
            cVar2 = *(byte *)(iVar7 + (int)param_1) + *(byte *)(iVar7 + (int)param_2);
            if (CARRY1(*(byte *)(iVar7 + (int)param_1),*(byte *)(iVar7 + (int)param_2))) {
              cVar2 = -1;
            }
            *(char *)(iVar7 + (int)param_3) = cVar2;
          }
        }
      }
    }
    return;
  }
  iVar7 = param_4 + -4;
  do {
    while( true ) {
      if (iVar7 < 0) {
        if (iVar7 != -2) {
          return;
        }
        uVar11 = CONCAT22((short)(*param_2 >> 0x10),*(undefined2 *)((int)param_2 + 2)) &
                 DAT_100050a8;
        uVar5 = (*param_1 & DAT_100050a8) + uVar11;
        if (CARRY4(*param_1 & DAT_100050a8,uVar11)) {
          uVar5 = uVar5 | DAT_100050b0;
        }
        if ((_DAT_100050b8 & uVar5) != 0) {
          uVar5 = uVar5 | DAT_100050b0;
        }
        if ((_DAT_100050bc & uVar5) != 0) {
          uVar5 = uVar5 | DAT_100050b4;
        }
        uVar12 = CONCAT22((short)(*param_2 >> 0x10),*(undefined2 *)((int)param_2 + 2)) &
                 DAT_100050c0;
        uVar11 = (*param_1 & DAT_100050c0) + uVar12;
        if (CARRY4(*param_1 & DAT_100050c0,uVar12)) {
          uVar11 = uVar11 | DAT_100050c8;
        }
        if ((_DAT_100050d0 & uVar11) != 0) {
          uVar11 = uVar11 | DAT_100050c8;
        }
        if ((_DAT_100050d4 & uVar11) != 0) {
          uVar11 = uVar11 | DAT_100050cc;
        }
        uVar13 = CONCAT22((short)(*param_2 >> 0x10),*(undefined2 *)((int)param_2 + 2)) &
                 DAT_100050d8;
        uVar12 = (*param_1 & DAT_100050d8) + uVar13;
        if (CARRY4(*param_1 & DAT_100050d8,uVar13)) {
          uVar12 = uVar12 | DAT_100050e0;
        }
        if ((_DAT_100050e8 & uVar12) != 0) {
          uVar12 = uVar12 | DAT_100050e0;
        }
        if ((_DAT_100050ec & uVar12) != 0) {
          uVar12 = uVar12 | DAT_100050e4;
        }
        *param_3 = (ushort)uVar5 & (ushort)DAT_100050a8 | (ushort)uVar11 & (ushort)DAT_100050c0 |
                   (ushort)uVar12 & (ushort)DAT_100050d8;
        return;
      }
      uVar5 = *(uint *)(iVar7 + (int)param_1);
      uVar11 = CONCAT22((short)(*param_2 >> 0x10),*(undefined2 *)((int)param_2 + 2));
      if (uVar5 != 0) break;
      *(uint *)(iVar7 + (int)param_3) = uVar11;
joined_r0x10003164:
      iVar7 = iVar7 + -4;
    }
    if (uVar11 == 0) {
      *(uint *)(iVar7 + (int)param_3) = uVar5;
      goto joined_r0x10003164;
    }
    if (((uVar5 | uVar11) & _DAT_100050a4) == 0) {
      *(uint *)(iVar7 + (int)param_3) = uVar5 + uVar11;
      goto joined_r0x10003164;
    }
    uVar5 = *(uint *)(iVar7 + (int)param_1) & DAT_100050a8;
    uVar12 = CONCAT22((short)(*param_2 >> 0x10),*(undefined2 *)((int)param_2 + 2)) & DAT_100050a8;
    uVar11 = uVar5 + uVar12;
    if (CARRY4(uVar5,uVar12)) {
      uVar11 = uVar11 | DAT_100050b0;
    }
    if ((_DAT_100050b8 & uVar11) != 0) {
      uVar11 = uVar11 | DAT_100050b0;
    }
    if ((_DAT_100050bc & uVar11) != 0) {
      uVar11 = uVar11 | DAT_100050b4;
    }
    uVar5 = *(uint *)(iVar7 + (int)param_1) & DAT_100050c0;
    uVar13 = CONCAT22((short)(*param_2 >> 0x10),*(undefined2 *)((int)param_2 + 2)) & DAT_100050c0;
    uVar12 = uVar5 + uVar13;
    if (CARRY4(uVar5,uVar13)) {
      uVar12 = uVar12 | DAT_100050c8;
    }
    if ((_DAT_100050d0 & uVar12) != 0) {
      uVar12 = uVar12 | DAT_100050c8;
    }
    if ((_DAT_100050d4 & uVar12) != 0) {
      uVar12 = uVar12 | DAT_100050cc;
    }
    uVar5 = *(uint *)(iVar7 + (int)param_1) & DAT_100050d8;
    uVar10 = CONCAT22((short)(*param_2 >> 0x10),*(undefined2 *)((int)param_2 + 2)) & DAT_100050d8;
    uVar13 = uVar5 + uVar10;
    if (CARRY4(uVar5,uVar10)) {
      uVar13 = uVar13 | DAT_100050e0;
    }
    if ((_DAT_100050e8 & uVar13) != 0) {
      uVar13 = uVar13 | DAT_100050e0;
    }
    if ((_DAT_100050ec & uVar13) != 0) {
      uVar13 = uVar13 | DAT_100050e4;
    }
    *(uint *)(iVar7 + (int)param_3) =
         uVar11 & DAT_100050a8 | uVar12 & DAT_100050c0 | uVar13 & DAT_100050d8;
    iVar7 = iVar7 + -4;
  } while( true );
}



void __cdecl FUN_10003772(int param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  
  for (iVar1 = param_3 + -4; -1 < iVar1; iVar1 = iVar1 + -4) {
    *(undefined4 *)(iVar1 + param_2) = *(undefined4 *)(iVar1 + param_1);
  }
  iVar2 = iVar1 + 3;
  if (-1 < iVar2) {
    *(undefined1 *)(iVar2 + param_2) = *(undefined1 *)(iVar2 + param_1);
    iVar2 = iVar1 + 2;
    if (-1 < iVar2) {
      *(undefined1 *)(iVar2 + param_2) = *(undefined1 *)(iVar2 + param_1);
      iVar1 = iVar1 + 1;
      if (-1 < iVar1) {
        *(undefined1 *)(iVar1 + param_2) = *(undefined1 *)(iVar1 + param_1);
      }
    }
  }
  return;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100037b2. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void * __thiscall FUN_100037ea(void *this,byte param_1)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)this);
  if ((param_1 & 1) != 0) {
    CNoTrackObject::operator_delete(this);
  }
  return this;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x10003be0. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



int FUN_10003865(HINSTANCE__ *param_1,int param_2)

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
      pAVar5 = AfxSetModuleState((AFX_MODULE_STATE *)&this_10005188);
      p_Var3 = AfxGetThreadState();
      *(AFX_MODULE_STATE **)(p_Var3 + 8) = pAVar5;
      pAVar5 = AfxGetModuleState();
      if (*(int **)(pAVar5 + 4) != (int *)0x0) {
        (**(code **)(**(int **)(pAVar5 + 4) + 0x70))();
      }
      AfxLockTempMaps();
      AfxUnlockTempMaps(-1);
      AfxWinTerm();
      AfxTermExtensionModule((AFX_EXTENSION_MODULE *)&param_1_10006218,1);
    }
    else if (param_2 == 3) {
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
                ((AFX_MAINTAIN_STATE2 *)&local_c,(AFX_MODULE_STATE *)&this_10005188);
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
  iVar4 = AfxWinInit(param_1,(HINSTANCE__ *)0x0,(char *)&param_3_100040e8,0);
  if (iVar4 != 0) {
    pAVar5 = AfxGetModuleState();
    piVar2 = *(int **)(pAVar5 + 4);
    if ((piVar2 == (int *)0x0) || (iVar4 = (**(code **)(*piVar2 + 0x58))(), iVar4 != 0)) {
      *(undefined4 *)(p_Var3 + 8) = uVar1;
      AfxInitExtensionModule((AFX_EXTENSION_MODULE *)&param_1_10006218,param_1);
      this = (CDynLinkLibrary *)operator_new(0x40);
      if (this != (CDynLinkLibrary *)0x0) {
        CDynLinkLibrary::CDynLinkLibrary(this,(AFX_EXTENSION_MODULE *)&param_1_10006218,0);
      }
      param_2 = 1;
      goto LAB_100038f1;
    }
    (**(code **)(*piVar2 + 0x70))();
  }
  AfxWinTerm();
LAB_100038f1:
  *(undefined4 *)(p_Var3 + 8) = uVar1;
  p_Var3 = AfxGetThreadState();
  AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var3 + 8));
  return param_2;
}



undefined4 FUN_1000398c(undefined4 param_1,int param_2)

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
    pAVar2 = AfxSetModuleState((AFX_MODULE_STATE *)&this_10005188);
    *(AFX_MODULE_STATE **)(p_Var1 + 8) = pAVar2;
  }
  else if (param_2 == 0) {
    p_Var1 = AfxGetThreadState();
    AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var1 + 8));
  }
  return 1;
}



void __fastcall FUN_100039dd(undefined4 *param_1)

{
  *(undefined4 *)(param_1[1] + 4) = *param_1;
  return;
}



void * __thiscall FUN_100039e6(void *this,byte param_1)

{
  type_info::~type_info((type_info *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __CxxFrameHandler(void)

{
                    // WARNING: Could not recover jumptable at 0x10003a02. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler();
  return;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x10003a10. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10003a16(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 *_Memory;
  undefined4 *puVar2;
  
  if (param_2 == 0) {
    if (0 < DAT_10006234) {
      DAT_10006234 = DAT_10006234 + -1;
      goto LAB_10003a2c;
    }
LAB_10003a54:
    uVar1 = 0;
  }
  else {
LAB_10003a2c:
    _DAT_10006238 = *(undefined4 *)_adjust_fdiv_exref;
    if (param_2 == 1) {
      DAT_10006240 = (undefined4 *)malloc(0x80);
      if (DAT_10006240 == (undefined4 *)0x0) goto LAB_10003a54;
      *DAT_10006240 = 0;
      DAT_1000623c = DAT_10006240;
      initterm(&DAT_10005000,&DAT_10005008);
      DAT_10006234 = DAT_10006234 + 1;
    }
    else if ((param_2 == 0) &&
            (_Memory = DAT_10006240, puVar2 = DAT_1000623c, DAT_10006240 != (undefined4 *)0x0)) {
      while (puVar2 = puVar2 + -1, _Memory <= puVar2) {
        if ((code *)*puVar2 != (code *)0x0) {
          (*(code *)*puVar2)();
          _Memory = DAT_10006240;
        }
      }
      free(_Memory);
      DAT_10006240 = (undefined4 *)0x0;
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
  iVar2 = DAT_10006234;
  if (param_2 != 0) {
    if ((param_2 != 1) && (param_2 != 2)) goto LAB_10003b09;
    if ((PTR_FUN_100050f0 != (undefined *)0x0) &&
       (iVar2 = (*(code *)PTR_FUN_100050f0)(param_1,param_2,param_3), iVar2 == 0)) {
      return 0;
    }
    iVar2 = FUN_10003a16(param_1,param_2);
  }
  if (iVar2 == 0) {
    return 0;
  }
LAB_10003b09:
  iVar2 = FUN_10003865(param_1,param_2);
  if (param_2 == 1) {
    if (iVar2 != 0) {
      return iVar2;
    }
    FUN_10003a16(param_1,0);
  }
  if ((param_2 != 0) && (param_2 != 3)) {
    return iVar2;
  }
  iVar3 = FUN_10003a16(param_1,param_2);
  param_2 = iVar2;
  if (iVar3 == 0) {
    param_2 = 0;
  }
  if (param_2 != 0) {
    if (PTR_FUN_100050f0 != (undefined *)0x0) {
      iVar2 = (*(code *)PTR_FUN_100050f0)(param_1,iVar1,param_3);
      return iVar2;
    }
    return param_2;
  }
  return 0;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x10003bbc. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void __thiscall type_info::~type_info(type_info *this)

{
                    // WARNING: Could not recover jumptable at 0x10003bc2. Too many branches
                    // WARNING: Treating indirect jump as call
  ~type_info(this);
  return;
}



void __cdecl initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x10003bc8. Too many branches
                    // WARNING: Treating indirect jump as call
  initterm();
  return;
}



void CNoTrackObject::operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10003bda. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x10003be0. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



void __thiscall
AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(AFX_MAINTAIN_STATE2 *this,AFX_MODULE_STATE *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10003bec. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MAINTAIN_STATE2(this,param_1);
  return;
}



void AfxTermThread(HINSTANCE__ *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10003bf2. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermThread(param_1);
  return;
}



void AfxTermExtensionModule(AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10003bf8. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermExtensionModule(param_1,param_2);
  return;
}



int AfxUnlockTempMaps(int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10003bfe. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxUnlockTempMaps(param_1);
  return iVar1;
}



void AfxLockTempMaps(void)

{
                    // WARNING: Could not recover jumptable at 0x10003c04. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxLockTempMaps();
  return;
}



AFX_MODULE_STATE * AfxSetModuleState(AFX_MODULE_STATE *param_1)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10003c0a. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxSetModuleState(param_1);
  return pAVar1;
}



void __thiscall
CDynLinkLibrary::CDynLinkLibrary(CDynLinkLibrary *this,AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10003c10. Too many branches
                    // WARNING: Treating indirect jump as call
  CDynLinkLibrary(this,param_1,param_2);
  return;
}



int AfxInitExtensionModule(AFX_EXTENSION_MODULE *param_1,HINSTANCE__ *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10003c16. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxInitExtensionModule(param_1,param_2);
  return iVar1;
}



void AfxWinTerm(void)

{
                    // WARNING: Could not recover jumptable at 0x10003c1c. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxWinTerm();
  return;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10003c22. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



int AfxWinInit(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10003c28. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinInit(param_1,param_2,param_3,param_4);
  return iVar1;
}



_AFX_THREAD_STATE * AfxGetThreadState(void)

{
  _AFX_THREAD_STATE *p_Var1;
  
                    // WARNING: Could not recover jumptable at 0x10003c2e. Too many branches
                    // WARNING: Treating indirect jump as call
  p_Var1 = AfxGetThreadState();
  return p_Var1;
}



void AfxCoreInitModule(void)

{
                    // WARNING: Could not recover jumptable at 0x10003c34. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxCoreInitModule();
  return;
}



void Unwind_10003c40(void)

{
  int unaff_EBP;
  
  DD_SURFACE::~DD_SURFACE(*(DD_SURFACE **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10003c4a(void)

{
  int unaff_EBP;
  
  FUN_10003080((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x98));
  return;
}



void Unwind_10003c59(void)

{
  int unaff_EBP;
  
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(*(int *)(unaff_EBP + -0x10) + 0x2174));
  return;
}



void Unwind_10003c73(void)

{
  int unaff_EBP;
  
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(*(int *)(unaff_EBP + -0x10) + -0x98));
  return;
}



void Unwind_10003c83(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x10) == 0x98) {
    *(undefined4 *)(unaff_EBP + -0x14) = 0;
  }
  else {
    *(undefined4 *)(unaff_EBP + -0x14) = *(undefined4 *)(unaff_EBP + -0x10);
  }
  FUN_10003080(*(undefined4 **)(unaff_EBP + -0x14));
  return;
}



void Unwind_10003cae(void)

{
  int unaff_EBP;
  
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(*(int *)(unaff_EBP + -0x10) + 0x20dc));
  return;
}



void Unwind_10003cd4(void)

{
  int unaff_EBP;
  
  FUN_100039dd((undefined4 *)(unaff_EBP + -0x14));
  return;
}


