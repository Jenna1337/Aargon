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

typedef struct tagRECT tagRECT, *PtagRECT;

typedef struct tagRECT RECT;

struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

typedef struct HDC__ HDC__, *PHDC__;

typedef struct HDC__ *HDC;

struct HDC__ {
    int unused;
};

typedef struct tagRECT *LPRECT;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

typedef ulong DWORD;

typedef HANDLE HLOCAL;

typedef int BOOL;

typedef DWORD COLORREF;

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

typedef struct CString CString, *PCString;

struct CString { // PlaceHolder Structure
};

typedef struct _DDSURFACEDESC _DDSURFACEDESC, *P_DDSURFACEDESC;

struct _DDSURFACEDESC { // PlaceHolder Structure
};

typedef struct CRect CRect, *PCRect;

struct CRect { // PlaceHolder Structure
};

typedef struct DD_SURFACE DD_SURFACE, *PDD_SURFACE;

struct DD_SURFACE { // PlaceHolder Structure
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

typedef struct FONT FONT, *PFONT;

struct FONT { // PlaceHolder Structure
};


// WARNING! conflicting data type names: /Demangler/HWND__ - /WinDef.h/HWND__

typedef struct AFX_MAINTAIN_STATE2 AFX_MAINTAIN_STATE2, *PAFX_MAINTAIN_STATE2;

struct AFX_MAINTAIN_STATE2 { // PlaceHolder Structure
};

typedef struct STRING STRING, *PSTRING;

struct STRING { // PlaceHolder Structure
};

typedef enum DIRECTION {
} DIRECTION;

typedef int (*_onexit_t)(void);

typedef uint size_t;




// public: __thiscall FONT::FONT(void)

FONT * __thiscall FONT::FONT(FONT *this)

{
                    // 0x1000  1  ??0FONT@@QAE@XZ
  DD_SURFACE::DD_SURFACE((DD_SURFACE *)this);
  *(undefined ***)this = &PTR_FUN_100020e8;
  *(undefined4 *)(this + 0x98) = 0;
  *(undefined4 *)(this + 0x109c) = 0;
  return this;
}



// public: void __thiscall FONT::FakeExtrude(unsigned int)

void __thiscall FONT::FakeExtrude(FONT *this,uint param_1)

{
                    // 0x103a  4  ?FakeExtrude@FONT@@QAEXI@Z
  *(uint *)(this + 0x109c) = param_1;
  return;
}



int __thiscall FUN_10001053(void *this,int param_1)

{
  int local_18;
  HWND__ local_14;
  COLORREF local_10;
  HDC local_c;
  COLORREF local_8;
  
  local_18 = param_1;
  local_c = DD_SURFACE::GetDC(&local_14);
  if (local_c != (HDC)0x0) {
    local_10 = GetPixel((HDC)local_14.unused,param_1,0);
    do {
      if ((uint)((HDC)((int)this + 0x10a0))->unused < local_18 + 1U) break;
      local_18 = local_18 + 1;
      local_8 = GetPixel((HDC)local_14.unused,local_18,0);
    } while (local_10 == local_8);
    DD_SURFACE::ReleaseDC((HWND)local_14.unused,(HDC)this);
  }
  return local_18;
}



void __thiscall FUN_100010f0(void *this,int param_1,int *param_2)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = FUN_10001053(this,*param_2);
  param_2[2] = iVar2;
  piVar1 = (int *)((int)this + param_1 * 0x10 + 0x9c);
  *piVar1 = *param_2;
  piVar1[1] = param_2[1];
  piVar1[2] = param_2[2];
  piVar1[3] = param_2[3];
  *param_2 = param_2[2];
  return;
}



void __fastcall FUN_10001145(void *param_1)

{
  undefined4 *puVar1;
  uint local_18;
  int local_14 [4];
  
  FUN_100017f0(local_14,0,1,0,*(int *)((int)param_1 + 0x10a8) + 1);
  FUN_100010f0(param_1,0x20,local_14);
  for (local_18 = 0; local_18 < 0x100; local_18 = local_18 + 1) {
    puVar1 = (undefined4 *)((int)param_1 + local_18 * 0x10 + 0x9c);
    *puVar1 = *(undefined4 *)((int)param_1 + 0x29c);
    puVar1[1] = *(undefined4 *)((int)param_1 + 0x2a0);
    puVar1[2] = *(undefined4 *)((int)param_1 + 0x2a4);
    puVar1[3] = *(undefined4 *)((int)param_1 + 0x2a8);
  }
  FUN_100010f0(param_1,0x7c,local_14);
  FUN_100010f0(param_1,0x2e,local_14);
  FUN_100010f0(param_1,0x27,local_14);
  FUN_100010f0(param_1,0x2c,local_14);
  FUN_100010f0(param_1,0x22,local_14);
  FUN_100010f0(param_1,0x3f,local_14);
  for (local_18 = 0x41; local_18 < 0x5b; local_18 = local_18 + 1) {
    FUN_100010f0(param_1,local_18,local_14);
  }
  for (local_18 = 0x30; local_18 < 0x3a; local_18 = local_18 + 1) {
    FUN_100010f0(param_1,local_18,local_14);
  }
  FUN_100010f0(param_1,0x21,local_14);
  FUN_100010f0(param_1,0x40,local_14);
  FUN_100010f0(param_1,0x23,local_14);
  FUN_100010f0(param_1,0x24,local_14);
  FUN_100010f0(param_1,0x25,local_14);
  FUN_100010f0(param_1,0x5e,local_14);
  FUN_100010f0(param_1,0x26,local_14);
  FUN_100010f0(param_1,0x2a,local_14);
  FUN_100010f0(param_1,0x28,local_14);
  FUN_100010f0(param_1,0x29,local_14);
  return;
}



// public: void __thiscall FONT::InitFont(char const *)

void __thiscall FONT::InitFont(FONT *this,char *param_1)

{
  uint local_78;
  uint local_74;
  undefined4 local_70;
  undefined4 local_6c;
  uint local_68;
  uint local_64;
  undefined4 local_8;
  
                    // 0x12fb  6  ?InitFont@FONT@@QAEXPBD@Z
  *(undefined4 *)(this + 0x98) = 1;
  GKTOOLS::GetDIBSize(param_1,&local_74,&local_78);
  memset(&local_70,0,0x6c);
  local_70 = 0x6c;
  local_6c = 7;
  local_64 = local_74;
  local_68 = local_78;
  local_8 = 0x840;
  DD_SURFACE::Create((DD_SURFACE *)this,(_DDSURFACEDESC *)&local_70,(HWND__ *)0x0);
  *(uint *)(this + 0x10a8) = local_68 - 1;
  *(uint *)(this + 0x10a0) = local_64;
  GKTOOLS::CopyDIBToSurface((DD_SURFACE *)this,param_1,0,0,false);
  DD_SURFACE::SetColorKeyFromPixel00((DD_SURFACE *)this);
  FUN_10001145(this);
  return;
}



// public: void __thiscall FONT::OutText(char const *,unsigned int,unsigned int,int)

void __thiscall FONT::OutText(FONT *this,char *param_1,uint param_2,uint param_3,int param_4)

{
  FONT *pFVar1;
  int *piVar2;
  int iVar3;
  void *pvVar4;
  int iVar5;
  undefined1 local_48 [16];
  undefined1 local_38 [16];
  uint local_28;
  uint local_24;
  byte *local_20;
  uint local_1c;
  RECT local_18;
  uint local_8;
  
                    // 0x13af  7  ?OutText@FONT@@QAEXPBDIIH@Z
  if (param_1 != (char *)0x0) {
    for (local_8 = 0; local_8 <= *(uint *)(this + 0x109c); local_8 = local_8 + 1) {
      local_1c = param_2;
      for (local_20 = (byte *)param_1; *local_20 != 0; local_20 = local_20 + 1) {
        pFVar1 = this + (uint)*local_20 * 0x10 + 0x9c;
        local_18.left = *(LONG *)pFVar1;
        local_18.top = *(LONG *)(pFVar1 + 4);
        local_18.right = *(LONG *)(pFVar1 + 8);
        local_18.bottom = *(LONG *)(pFVar1 + 0xc);
        local_24 = GKERNEL::ScrXRes();
        local_28 = GKERNEL::ScrYRes();
        iVar5 = local_1c + local_8;
        piVar2 = (int *)CRect(local_38,&local_18);
        iVar3 = FUN_10001850(piVar2);
        if ((uint)(iVar5 + iVar3) < local_24) {
          iVar5 = param_3 + local_8;
          pvVar4 = CRect(local_48,&local_18);
          iVar3 = FUN_10001870((int)pvVar4);
          if ((uint)(iVar5 + iVar3) < local_28) {
            if (param_4 == 1) {
              DD_SURFACE::BltFast((DD_SURFACE *)ddsPrimary_exref,(DD_SURFACE *)this,
                                  local_1c + local_8,param_3 + local_8,&local_18);
            }
            else {
              DD_SURFACE::BltFast((DD_SURFACE *)ddsBack_exref,(DD_SURFACE *)this,local_1c + local_8,
                                  param_3 + local_8,&local_18);
            }
          }
        }
        local_1c = local_1c + (local_18.right - local_18.left);
      }
    }
  }
  return;
}



// public: unsigned int __thiscall FONT::CalcWidth(char const *)

uint __thiscall FONT::CalcWidth(FONT *this,char *param_1)

{
  uint uVar1;
  int iVar2;
  int local_1c [4];
  byte *local_c;
  int local_8;
  
                    // 0x14f9  2  ?CalcWidth@FONT@@QAEIPBD@Z
  local_8 = 0;
  if (param_1 == (char *)0x0) {
    uVar1 = 0;
  }
  else {
    local_c = (byte *)param_1;
    FUN_100017e0(local_1c);
    for (; *local_c != 0; local_c = local_c + 1) {
      FUN_10001890(local_1c,(RECT *)(this + (uint)*local_c * 0x10 + 0x9c));
      iVar2 = FUN_10001850(local_1c);
      local_8 = local_8 + iVar2;
    }
    uVar1 = local_8 + *(int *)(this + 0x109c);
  }
  return uVar1;
}



// public: void __thiscall FONT::WrapText(char const *,class CRect,int)

void __thiscall
FONT::WrapText(FONT *this,char *param_1,uint param_3,uint param_4,uint param_5,uint param_6,
              int param_7)

{
  bool bVar1;
  undefined3 extraout_var;
  CString *pCVar2;
  char *pcVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  CString local_30 [4];
  CString local_2c [4];
  CString local_28 [4];
  uint local_24;
  CString local_20 [4];
  uint local_1c;
  uint local_18;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x1581  8  ?WrapText@FONT@@QAEXPBDVCRect@@H@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_10001e3d;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_100018f0(local_14,param_1);
  local_8 = 0;
  FUN_100018b0(local_20);
  local_8._0_1_ = 1;
  local_18 = param_3;
  local_1c = param_4;
  while (bVar1 = FUN_10001790((int *)local_14), CONCAT31(extraout_var,bVar1) == 0) {
    STRING::strtok((char *)local_2c,(char *)&_Delim_10003020);
    local_8._0_1_ = 2;
    pCVar2 = (CString *)operator+((char *)local_30,(CString *)&param_2_10003024);
    local_8._0_1_ = 3;
    FUN_100018d0(local_28,pCVar2);
    local_8._0_1_ = 4;
    FUN_10001770(local_20,local_28);
    local_8._0_1_ = 3;
    FUN_10001910(local_28);
    local_8._0_1_ = 2;
    CString::~CString(local_30);
    local_8._0_1_ = 1;
    FUN_10001910(local_2c);
    pcVar3 = (char *)FUN_100017d0((undefined4 *)local_20);
    local_24 = CalcWidth(this,pcVar3);
    if (param_5 < local_24 + local_18) {
      uVar4 = GetHeight(this);
      local_1c = local_1c + uVar4;
      local_18 = param_3;
    }
    uVar4 = GetHeight(this);
    if (local_1c + uVar4 < param_6) {
      uVar4 = local_18;
      uVar5 = local_1c;
      iVar6 = param_7;
      pcVar3 = (char *)FUN_100017d0((undefined4 *)local_20);
      OutText(this,pcVar3,uVar4,uVar5,iVar6);
      local_18 = local_18 + local_24;
    }
  }
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_10001910(local_20);
  local_8 = 0xffffffff;
  FUN_10001910(local_14);
  ExceptionList = local_10;
  return;
}



// public: void __thiscall FONT::CenterText(char const *,class CRect,int)

void __thiscall
FONT::CenterText(FONT *this,char *param_1,int param_3,uint param_4,undefined4 param_5,
                undefined4 param_6,int param_7)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  
                    // 0x16f7  3  ?CenterText@FONT@@QAEXPBDVCRect@@H@Z
  iVar1 = FUN_10001850(&param_3);
  if (0 < iVar1) {
    uVar2 = CalcWidth(this,param_1);
    uVar3 = FUN_10001850(&param_3);
    if (uVar2 < uVar3) {
      iVar1 = FUN_10001850(&param_3);
      OutText(this,param_1,param_3 + (iVar1 - uVar2 >> 1),param_4,param_7);
    }
  }
  return;
}



void * __thiscall FUN_10001770(void *this,CString *param_1)

{
  CString::operator=((CString *)this,param_1);
  return this;
}



bool __fastcall FUN_10001790(int *param_1)

{
  int iVar1;
  
  iVar1 = FUN_100017b0(param_1);
  return *(int *)(iVar1 + 4) == 0;
}



int __fastcall FUN_100017b0(int *param_1)

{
  return *param_1 + -0xc;
}



undefined4 __fastcall FUN_100017d0(undefined4 *param_1)

{
  return *param_1;
}



undefined4 __fastcall FUN_100017e0(undefined4 param_1)

{
  return param_1;
}



void * __thiscall
FUN_100017f0(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  *(undefined4 *)this = param_1;
  *(undefined4 *)((int)this + 4) = param_2;
  *(undefined4 *)((int)this + 8) = param_3;
  *(undefined4 *)((int)this + 0xc) = param_4;
  return this;
}



// Library Function - Multiple Matches With Same Base Name
//  public: __thiscall CRect::CRect(struct tagRECT const &)
//  public: __thiscall CRect::CRect(struct tagRECT const *)
// 
// Library: Visual Studio

void * __thiscall CRect(void *this,RECT *param_1)

{
  CopyRect((LPRECT)this,param_1);
  return this;
}



int __fastcall FUN_10001850(int *param_1)

{
  return param_1[2] - *param_1;
}



int __fastcall FUN_10001870(int param_1)

{
  return *(int *)(param_1 + 0xc) - *(int *)(param_1 + 4);
}



void __thiscall FUN_10001890(void *this,RECT *param_1)

{
  CopyRect((LPRECT)this,param_1);
  return;
}



CString * __fastcall FUN_100018b0(CString *param_1)

{
  CString::CString(param_1);
  return param_1;
}



void * __thiscall FUN_100018d0(void *this,CString *param_1)

{
  CString::CString((CString *)this,param_1);
  return this;
}



void * __thiscall FUN_100018f0(void *this,char *param_1)

{
  CString::CString((CString *)this,param_1);
  return this;
}



void __fastcall FUN_10001910(CString *param_1)

{
  CString::~CString(param_1);
  return;
}



void FUN_10001930(void)

{
  return;
}



// public: unsigned int __thiscall FONT::GetHeight(void)const 

uint __thiscall FONT::GetHeight(FONT *this)

{
                    // 0x1940  5  ?GetHeight@FONT@@QBEIXZ
  return *(uint *)(this + 0x10a8);
}



void __thiscall CString::~CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x10001954. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CString(this);
  return;
}



void operator+(char *param_1,CString *param_2)

{
                    // WARNING: Could not recover jumptable at 0x1000195a. Too many branches
                    // WARNING: Treating indirect jump as call
  operator+(param_1,param_2);
  return;
}



CString * __thiscall CString::operator=(CString *this,CString *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x10001960. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator=(this,param_1);
  return pCVar1;
}



void __thiscall CString::CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x10001966. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this);
  return;
}



void __thiscall CString::CString(CString *this,CString *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000196c. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



void __thiscall CString::CString(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10001972. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



void * __thiscall FUN_100019aa(void *this,byte param_1)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)this);
  if ((param_1 & 1) != 0) {
    CNoTrackObject::operator_delete(this);
  }
  return this;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x10001dae. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



int FUN_10001a25(HINSTANCE__ *param_1,int param_2)

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
      pAVar5 = AfxSetModuleState((AFX_MODULE_STATE *)&this_100030c0);
      p_Var3 = AfxGetThreadState();
      *(AFX_MODULE_STATE **)(p_Var3 + 8) = pAVar5;
      pAVar5 = AfxGetModuleState();
      if (*(int **)(pAVar5 + 4) != (int *)0x0) {
        (**(code **)(**(int **)(pAVar5 + 4) + 0x70))();
      }
      AfxLockTempMaps();
      AfxUnlockTempMaps(-1);
      AfxWinTerm();
      AfxTermExtensionModule((AFX_EXTENSION_MODULE *)&param_1_10004150,1);
    }
    else if (param_2 == 3) {
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
                ((AFX_MAINTAIN_STATE2 *)&local_c,(AFX_MODULE_STATE *)&this_100030c0);
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
  iVar4 = AfxWinInit(param_1,(HINSTANCE__ *)0x0,(char *)&param_3_100020f4,0);
  if (iVar4 != 0) {
    pAVar5 = AfxGetModuleState();
    piVar2 = *(int **)(pAVar5 + 4);
    if ((piVar2 == (int *)0x0) || (iVar4 = (**(code **)(*piVar2 + 0x58))(), iVar4 != 0)) {
      *(undefined4 *)(p_Var3 + 8) = uVar1;
      AfxInitExtensionModule((AFX_EXTENSION_MODULE *)&param_1_10004150,param_1);
      this = (CDynLinkLibrary *)operator_new(0x40);
      if (this != (CDynLinkLibrary *)0x0) {
        CDynLinkLibrary::CDynLinkLibrary(this,(AFX_EXTENSION_MODULE *)&param_1_10004150,0);
      }
      param_2 = 1;
      goto LAB_10001ab1;
    }
    (**(code **)(*piVar2 + 0x70))();
  }
  AfxWinTerm();
LAB_10001ab1:
  *(undefined4 *)(p_Var3 + 8) = uVar1;
  p_Var3 = AfxGetThreadState();
  AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var3 + 8));
  return param_2;
}



undefined4 FUN_10001b4c(undefined4 param_1,int param_2)

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
    pAVar2 = AfxSetModuleState((AFX_MODULE_STATE *)&this_100030c0);
    *(AFX_MODULE_STATE **)(p_Var1 + 8) = pAVar2;
  }
  else if (param_2 == 0) {
    p_Var1 = AfxGetThreadState();
    AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var1 + 8));
  }
  return 1;
}



void __fastcall FUN_10001b9d(undefined4 *param_1)

{
  *(undefined4 *)(param_1[1] + 4) = *param_1;
  return;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x10001ba6. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



void __CxxFrameHandler(void)

{
                    // WARNING: Could not recover jumptable at 0x10001bac. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10001bc0(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 *_Memory;
  undefined4 *puVar2;
  
  if (param_2 == 0) {
    if (0 < DAT_1000416c) {
      DAT_1000416c = DAT_1000416c + -1;
      goto LAB_10001bd6;
    }
LAB_10001bfe:
    uVar1 = 0;
  }
  else {
LAB_10001bd6:
    _DAT_10004170 = *(undefined4 *)_adjust_fdiv_exref;
    if (param_2 == 1) {
      DAT_10004178 = (undefined4 *)malloc(0x80);
      if (DAT_10004178 == (undefined4 *)0x0) goto LAB_10001bfe;
      *DAT_10004178 = 0;
      DAT_10004174 = DAT_10004178;
      initterm(&DAT_10003000,&DAT_10003008);
      DAT_1000416c = DAT_1000416c + 1;
    }
    else if ((param_2 == 0) &&
            (_Memory = DAT_10004178, puVar2 = DAT_10004174, DAT_10004178 != (undefined4 *)0x0)) {
      while (puVar2 = puVar2 + -1, _Memory <= puVar2) {
        if ((code *)*puVar2 != (code *)0x0) {
          (*(code *)*puVar2)();
          _Memory = DAT_10004178;
        }
      }
      free(_Memory);
      DAT_10004178 = (undefined4 *)0x0;
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
  iVar2 = DAT_1000416c;
  if (param_2 != 0) {
    if ((param_2 != 1) && (param_2 != 2)) goto LAB_10001cb3;
    if ((PTR_FUN_10003028 != (undefined *)0x0) &&
       (iVar2 = (*(code *)PTR_FUN_10003028)(param_1,param_2,param_3), iVar2 == 0)) {
      return 0;
    }
    iVar2 = FUN_10001bc0(param_1,param_2);
  }
  if (iVar2 == 0) {
    return 0;
  }
LAB_10001cb3:
  iVar2 = FUN_10001a25(param_1,param_2);
  if (param_2 == 1) {
    if (iVar2 != 0) {
      return iVar2;
    }
    FUN_10001bc0(param_1,0);
  }
  if ((param_2 != 0) && (param_2 != 3)) {
    return iVar2;
  }
  iVar3 = FUN_10001bc0(param_1,param_2);
  param_2 = iVar2;
  if (iVar3 == 0) {
    param_2 = 0;
  }
  if (param_2 != 0) {
    if (PTR_FUN_10003028 != (undefined *)0x0) {
      iVar2 = (*(code *)PTR_FUN_10003028)(param_1,iVar1,param_3);
      return iVar2;
    }
    return param_2;
  }
  return 0;
}



void * __thiscall FUN_10001d08(void *this,byte param_1)

{
  type_info::~type_info((type_info *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x10001d84. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void __cdecl initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x10001d8a. Too many branches
                    // WARNING: Treating indirect jump as call
  initterm();
  return;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10001d90. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall type_info::~type_info(type_info *this)

{
                    // WARNING: Could not recover jumptable at 0x10001d96. Too many branches
                    // WARNING: Treating indirect jump as call
  ~type_info(this);
  return;
}



void CNoTrackObject::operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10001da8. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x10001dae. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



void __thiscall
AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(AFX_MAINTAIN_STATE2 *this,AFX_MODULE_STATE *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10001dba. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MAINTAIN_STATE2(this,param_1);
  return;
}



void AfxTermThread(HINSTANCE__ *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10001dc0. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermThread(param_1);
  return;
}



void AfxTermExtensionModule(AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10001dc6. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermExtensionModule(param_1,param_2);
  return;
}



int AfxUnlockTempMaps(int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10001dcc. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxUnlockTempMaps(param_1);
  return iVar1;
}



void AfxLockTempMaps(void)

{
                    // WARNING: Could not recover jumptable at 0x10001dd2. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxLockTempMaps();
  return;
}



AFX_MODULE_STATE * AfxSetModuleState(AFX_MODULE_STATE *param_1)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10001dd8. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxSetModuleState(param_1);
  return pAVar1;
}



void __thiscall
CDynLinkLibrary::CDynLinkLibrary(CDynLinkLibrary *this,AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10001dde. Too many branches
                    // WARNING: Treating indirect jump as call
  CDynLinkLibrary(this,param_1,param_2);
  return;
}



int AfxInitExtensionModule(AFX_EXTENSION_MODULE *param_1,HINSTANCE__ *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10001de4. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxInitExtensionModule(param_1,param_2);
  return iVar1;
}



void AfxWinTerm(void)

{
                    // WARNING: Could not recover jumptable at 0x10001dea. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxWinTerm();
  return;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10001df0. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



int AfxWinInit(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10001df6. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinInit(param_1,param_2,param_3,param_4);
  return iVar1;
}



_AFX_THREAD_STATE * AfxGetThreadState(void)

{
  _AFX_THREAD_STATE *p_Var1;
  
                    // WARNING: Could not recover jumptable at 0x10001dfc. Too many branches
                    // WARNING: Treating indirect jump as call
  p_Var1 = AfxGetThreadState();
  return p_Var1;
}



void AfxCoreInitModule(void)

{
                    // WARNING: Could not recover jumptable at 0x10001e02. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxCoreInitModule();
  return;
}



void Unwind_10001e10(void)

{
  int unaff_EBP;
  
  FUN_10001910((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_10001e19(void)

{
  int unaff_EBP;
  
  FUN_10001910((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_10001e22(void)

{
  int unaff_EBP;
  
  FUN_10001910((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_10001e2b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_10001e34(void)

{
  int unaff_EBP;
  
  FUN_10001910((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_10001e48(void)

{
  int unaff_EBP;
  
  FUN_10001b9d((undefined4 *)(unaff_EBP + -0x14));
  return;
}


