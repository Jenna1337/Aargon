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

typedef struct AFX_MODULE_STATE AFX_MODULE_STATE, *PAFX_MODULE_STATE;

struct AFX_MODULE_STATE { // PlaceHolder Structure
};

typedef struct ITEM ITEM, *PITEM;

struct ITEM { // PlaceHolder Structure
};

typedef struct CDynLinkLibrary CDynLinkLibrary, *PCDynLinkLibrary;

struct CDynLinkLibrary { // PlaceHolder Structure
};

typedef struct OVERLAY OVERLAY, *POVERLAY;

struct OVERLAY { // PlaceHolder Structure
};

typedef struct GKGOBJ GKGOBJ, *PGKGOBJ;

struct GKGOBJ { // PlaceHolder Structure
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




void * __thiscall FUN_10001000(void *this,void *param_1)

{
  int iVar1;
  int iVar2;
  
  iVar1 = (*(int *)((int)this + 0xb4) + 0x20 + *(int *)((int)this + 0xb4)) / 2;
  iVar2 = (*(int *)((int)this + 0xb8) + 0x20 + *(int *)((int)this + 0xb8)) / 2;
  default_error_condition
            (param_1,(int)(iVar1 + (iVar1 >> 0x1f & 0x1fU)) >> 5,
             (int)(iVar2 + (iVar2 >> 0x1f & 0x1fU)) >> 5);
  return param_1;
}



undefined4 FUN_10001070(int *param_1)

{
  return CONCAT31((int3)((uint)param_1[1] >> 8),
                  *(undefined1 *)((int)&_Dst_10005158 + param_1[1] + *param_1 * 0xd));
}



void __thiscall FUN_10001092(void *this,int *param_1)

{
  *(undefined1 *)((int)&_Dst_10005158 + param_1[1] + *param_1 * 0xd) = 1;
  *(undefined1 *)((int)this + param_1[1] + *param_1 * 0xd + 0x4580) = 1;
  return;
}



void __fastcall FUN_100010d1(int param_1)

{
  int local_c;
  int local_8;
  
  for (local_8 = 0; local_8 < 0x14; local_8 = local_8 + 1) {
    for (local_c = 0; local_c < 0xd; local_c = local_c + 1) {
      if (*(char *)(param_1 + 0x4580 + local_c + local_8 * 0xd) != '\0') {
        *(undefined1 *)((int)&_Dst_10005158 + local_c + local_8 * 0xd) = 0;
      }
    }
  }
  memset((void *)(param_1 + 0x4580),0,0x104);
  return;
}



void __fastcall FUN_10001157(int *param_1)

{
  FUN_100010d1((int)param_1);
  (**(code **)(*param_1 + 0x20))();
  (**(code **)(param_1[0x47b] + 0x20))();
  CWave::Stop((CWave *)(param_1 + 1099));
  (**(code **)(param_1[0x8c6] + 0x20))();
  *(undefined1 *)((int)param_1 + 0x4571) = 1;
  return;
}



void __fastcall FUN_100011b8(int param_1)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 local_1c [5];
  uint local_8;
  
  for (local_8 = 0; local_8 < 4; local_8 = local_8 + 1) {
    puVar1 = FUN_10001260(local_1c);
    puVar3 = (undefined4 *)(param_1 + 0x4688 + local_8 * 0x14);
    for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar3 = *puVar1;
      puVar1 = puVar1 + 1;
      puVar3 = puVar3 + 1;
    }
  }
  return;
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
  FUN_10001230(this,param_1,param_2);
  return this;
}



void * __thiscall FUN_10001230(void *this,undefined4 param_1,undefined4 param_2)

{
  *(undefined4 *)this = param_1;
  *(undefined4 *)((int)this + 4) = param_2;
  return this;
}



undefined4 * __fastcall FUN_10001260(undefined4 *param_1)

{
  *param_1 = 0;
  *(undefined1 *)(param_1 + 2) = 0;
  FUN_10001290(param_1 + 3);
  return param_1;
}



void * __fastcall FUN_10001290(void *param_1)

{
  FUN_10001230(param_1,0,0);
  return param_1;
}



void FUN_100012b0(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  while (param_3 = param_3 + -1, -1 < param_3) {
    (*(code *)param_4)();
  }
  return;
}



void __thiscall FUN_100012e0(void *this,MAP *param_1,int param_2,void *param_3)

{
  bool bVar1;
  int *piVar2;
  undefined4 uVar3;
  undefined1 local_4c [8];
  undefined1 local_44 [8];
  undefined1 local_3c [8];
  undefined1 local_34 [8];
  undefined1 local_2c [8];
  undefined1 local_24 [8];
  undefined1 local_1c [8];
  undefined1 local_14 [8];
  int local_c;
  int local_8;
  
  FUN_10001290(&local_c);
  if (param_2 == 0) {
    piVar2 = (int *)default_error_condition(local_14,0xffffffff,0);
    piVar2 = (int *)FUN_100017a0(param_3,local_1c,piVar2);
    local_c = *piVar2;
    local_8 = piVar2[1];
  }
  else if (param_2 == 2) {
    piVar2 = (int *)default_error_condition(local_24,0,0xffffffff);
    piVar2 = (int *)FUN_100017a0(param_3,local_2c,piVar2);
    local_c = *piVar2;
    local_8 = piVar2[1];
  }
  else if (param_2 == 1) {
    piVar2 = (int *)default_error_condition(local_34,1,0);
    piVar2 = (int *)FUN_100017a0(param_3,local_3c,piVar2);
    local_c = *piVar2;
    local_8 = piVar2[1];
  }
  else if (param_2 == 3) {
    piVar2 = (int *)default_error_condition(local_44,0,1);
    piVar2 = (int *)FUN_100017a0(param_3,local_4c,piVar2);
    local_c = *piVar2;
    local_8 = piVar2[1];
  }
  if (*(char *)((int)this + param_2 * 0x14 + 0x4690) != '\0') {
    FUN_10003064(this,param_1,(int *)((int)this + param_2 * 0x14 + 0x4694));
    *(undefined1 *)((int)this + param_2 * 0x14 + 0x4690) = 0;
  }
  bVar1 = FUN_10001750(this,param_2);
  if (bVar1) {
    uVar3 = FUN_1000143f(&local_c);
                    // WARNING: Load size is inaccurate
    (**(code **)(*this + 0x6c))(local_c << 5,local_8 << 5,uVar3);
    FUN_10001092(this,&local_c);
  }
  *(int *)((int)this + 0x46d8) = param_2;
  return;
}



undefined4 FUN_1000143f(int *param_1)

{
  uint uVar1;
  undefined4 uVar2;
  
  uVar1 = FUN_10001070(param_1);
  if ((uVar1 & 0xff) == 0) {
    uVar2 = 200;
  }
  else {
    uVar2 = 300;
  }
  return uVar2;
}



void __thiscall FUN_1000146d(void *this,MAP *param_1)

{
  uint uVar1;
  bool bVar2;
  int local_18 [2];
  uint local_10;
  uint local_c;
  uint local_8;
  
  if ((*(char *)((int)this + 0x4570) == '\0') && (bVar2 = SPRITE::InMotion((SPRITE *)this), !bVar2))
  {
    FUN_10001000(this,local_18);
    FUN_10001092(this,local_18);
    FUN_10002730(this,param_1,local_18);
    local_10 = 4;
    local_8 = 0xffffffff;
    bVar2 = FUN_10001776(this,*(int *)((int)this + 0x46d8));
    if (bVar2) {
      local_10 = *(uint *)((int)this + 0x46d8);
      local_8 = *(uint *)((int)this + local_10 * 0x14 + 0x468c);
    }
    for (local_c = 0; uVar1 = local_c, local_c < 4; local_c = local_c + 1) {
      bVar2 = FUN_10001776(this,local_c);
      if ((bVar2) && (*(uint *)((int)this + local_c * 0x14 + 0x468c) < local_8)) {
        local_10 = uVar1;
        local_8 = *(uint *)((int)this + local_c * 0x14 + 0x468c);
      }
    }
    if (local_10 == 4) {
      bVar2 = FUN_10001830(this,1);
      if ((bVar2) || (bVar2 = FUN_10001830(this,2), bVar2)) {
        bVar2 = FUN_10001750(this,1);
        if (bVar2) {
          FUN_100012e0(this,param_1,1,local_18);
          return;
        }
        bVar2 = FUN_10001750(this,0);
        if (bVar2) {
          FUN_100012e0(this,param_1,0,local_18);
          return;
        }
      }
      else {
        bVar2 = FUN_10001830(this,0);
        if ((bVar2) || (bVar2 = FUN_10001830(this,3), bVar2)) {
          bVar2 = FUN_10001750(this,0);
          if (bVar2) {
            FUN_100012e0(this,param_1,0,local_18);
            return;
          }
          bVar2 = FUN_10001750(this,1);
          if (bVar2) {
            FUN_100012e0(this,param_1,1,local_18);
            return;
          }
        }
      }
      bVar2 = FUN_10001750(this,3);
      if ((!bVar2) || (bVar2 = FUN_10001830(this,2), bVar2)) {
        bVar2 = FUN_10001750(this,2);
        if ((!bVar2) || (bVar2 = FUN_10001830(this,3), bVar2)) {
          FUN_100010d1((int)this);
          bVar2 = FUN_10001830(this,3);
          if (bVar2) {
            *(undefined4 *)((int)this + 0x46d8) = 2;
          }
          else {
            bVar2 = FUN_10001830(this,2);
            if (bVar2) {
              *(undefined4 *)((int)this + 0x46d8) = 3;
            }
          }
        }
        else {
          FUN_100012e0(this,param_1,2,local_18);
        }
      }
      else {
        FUN_100012e0(this,param_1,3,local_18);
      }
    }
    else {
      FUN_100012e0(this,param_1,local_10,local_18);
    }
  }
  return;
}



bool __thiscall FUN_10001750(void *this,int param_1)

{
  return (*(uint *)((int)this + param_1 * 0x14 + 0x4688) & 1) != 0;
}



bool __thiscall FUN_10001776(void *this,int param_1)

{
  return (*(uint *)((int)this + param_1 * 0x14 + 0x4688) & 2) != 0;
}



void * __thiscall FUN_100017a0(void *this,void *param_1,int *param_2)

{
  undefined4 *puVar1;
  undefined1 local_14 [8];
  int local_c;
  int local_8;
  
  local_c = *param_2;
  local_8 = param_2[1];
  puVar1 = (undefined4 *)FID_conflict_operator_(this,local_14,local_c,local_8);
  FUN_10001810(param_1,puVar1);
  return param_1;
}



// Library Function - Multiple Matches With Different Base Names
//  public: class CPoint __thiscall CPoint::operator+(struct tagPOINT)const 
//  public: class CPoint __thiscall CPoint::operator+(struct tagSIZE)const 
//  public: class CPoint __thiscall CSize::operator+(struct tagPOINT)const 
// 
// Library: Visual Studio

void * __thiscall FID_conflict_operator_(void *this,void *param_1,int param_2,int param_3)

{
                    // WARNING: Load size is inaccurate
  FUN_10001230(param_1,*this + param_2,*(int *)((int)this + 4) + param_3);
  return param_1;
}



void * __thiscall FUN_10001810(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  
  uVar1 = param_1[1];
  *(undefined4 *)this = *param_1;
  *(undefined4 *)((int)this + 4) = uVar1;
  return this;
}



bool __thiscall FUN_10001830(void *this,int param_1)

{
  return *(int *)((int)this + 0x46d8) == param_1;
}



// class TwMovingObject * __cdecl Create(void)

TwMovingObject * __cdecl Create(void)

{
  SPRITE *pSVar1;
  SPRITE *local_1c;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x1850  1  ?Create@@YAPAVTwMovingObject@@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000377b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pSVar1 = (SPRITE *)operator_new(0x46dc);
  local_8 = 0;
  if (pSVar1 == (SPRITE *)0x0) {
    local_1c = (SPRITE *)0x0;
  }
  else {
    local_1c = FUN_10002410(pSVar1);
  }
  ExceptionList = local_10;
  return (TwMovingObject *)local_1c;
}



void __thiscall FUN_100018ba(void *this,undefined4 param_1,int *param_2)

{
  undefined4 *puVar1;
  char *pcVar2;
  CString *pCVar3;
  int extraout_ECX;
  int extraout_ECX_00;
  int extraout_ECX_01;
  int iVar4;
  undefined1 uVar5;
  int iVar6;
  int iVar7;
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
  puStack_c = &param_5_100037bb;
  local_10 = ExceptionList;
                    // WARNING: Load size is inaccurate
  ExceptionList = &local_10;
  (**(code **)(*this + 0x28))();
  iVar7 = 1;
  iVar6 = 1;
  local_14 = &stack0xffffff5c;
  iVar4 = extraout_ECX;
  CString::CString((CString *)&stack0xffffff5c,s_Tractor_bmp_10005020);
  uVar5 = SUB41(local_18,0);
  puVar1 = (undefined4 *)(**(code **)(*param_2 + 0x54))();
  local_8 = 0;
  pcVar2 = (char *)FUN_10002230(puVar1);
  SPRITE::Init((SPRITE *)((int)this + 0x11ec),pcVar2,(bool)uVar5,iVar4,iVar6,iVar7);
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  (**(code **)(*(int *)((int)this + 0x11ec) + 0x20))();
  iVar7 = 9;
  iVar6 = 1;
  local_1c = &stack0xffffff54;
  iVar4 = extraout_ECX_00;
  CString::CString((CString *)&stack0xffffff54,s_ForceField_bmp_1000502c);
  uVar5 = SUB41(local_20,0);
  puVar1 = (undefined4 *)(**(code **)(*param_2 + 0x54))();
  local_8 = 1;
  pcVar2 = (char *)FUN_10002230(puVar1);
  SPRITE::Init((SPRITE *)((int)this + 0x2318),pcVar2,(bool)uVar5,iVar4,iVar6,iVar7);
  local_8 = 0xffffffff;
  CString::~CString(local_20);
  (**(code **)(*(int *)((int)this + 0x2318) + 0x20))();
  iVar7 = 1;
  iVar6 = 1;
  local_24 = &stack0xffffff4c;
  iVar4 = extraout_ECX_01;
  CString::CString((CString *)&stack0xffffff4c,s_Spark_bmp_1000503c);
  uVar5 = SUB41(local_28,0);
  puVar1 = (undefined4 *)(**(code **)(*param_2 + 0x54))();
  local_8 = 2;
  pcVar2 = (char *)FUN_10002230(puVar1);
  SPRITE::Init((SPRITE *)((int)this + 0x3444),pcVar2,(bool)uVar5,iVar4,iVar6,iVar7);
  local_8 = 0xffffffff;
  CString::~CString(local_28);
  (**(code **)(*(int *)((int)this + 0x3444) + 0x20))();
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x4c))();
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x50))();
  (**(code **)(*(int *)((int)this + 0x2318) + 0x4c))();
  (**(code **)(*(int *)((int)this + 0x2318) + 0x50))();
  local_2c = &stack0xffffff4c;
  CString::CString((CString *)&stack0xffffff4c,s_Tractor_10005048);
  pCVar3 = (CString *)(**(code **)(*param_2 + 0x58))();
  local_8 = 3;
  CWave::Create((CWave *)((int)this + 0x112c),pCVar3);
  local_8 = 0xffffffff;
  CString::~CString(local_30);
  local_34 = &stack0xffffff44;
  CString::CString((CString *)&stack0xffffff44,s_Eliminate_10005050);
  pCVar3 = (CString *)(**(code **)(*param_2 + 0x58))();
  local_8 = 4;
  CWave::Create((CWave *)((int)this + 0x116c),pCVar3);
  local_8 = 0xffffffff;
  CString::~CString(local_38);
  local_3c = &stack0xffffff3c;
  CString::CString((CString *)&stack0xffffff3c,s_Fire_Shot_1000505c);
  pCVar3 = (CString *)(**(code **)(*param_2 + 0x58))(local_40);
  local_8 = 5;
  CWave::Create((CWave *)((int)this + 0x11ac),pCVar3);
  local_8 = 0xffffffff;
  CString::~CString(local_40);
  memset(&_Dst_10005158,0,0x104);
  GKERNEL::UnRegisterSprite((GKGOBJ *)((int)this + 0x3444));
  GKERNEL::RegisterSprite((GKGOBJ *)((int)this + 0x3444));
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_10001bde(void *this,MAP *param_1)

{
  bool bVar1;
  int iVar2;
  int *piVar3;
  void *pvVar4;
  undefined4 *puVar5;
  undefined3 extraout_var;
  ITEM *pIVar6;
  undefined4 uVar7;
  int *piVar8;
  char cVar9;
  undefined1 *puVar10;
  CString *pCVar11;
  CString **ppCVar12;
  undefined1 local_ec;
  undefined1 local_d0;
  undefined1 local_b8 [8];
  undefined1 local_b0 [16];
  undefined1 local_a0 [8];
  char local_98;
  undefined3 uStack_97;
  bool local_94;
  undefined3 uStack_93;
  CString local_90 [4];
  uint local_8c;
  undefined1 local_88 [8];
  undefined1 local_80 [8];
  undefined1 local_78 [8];
  ITEM *local_70;
  ITEM *local_6c;
  CString local_68 [4];
  uint local_64;
  CString local_60 [4];
  uint local_5c;
  CString local_58 [4];
  uint local_54;
  undefined1 local_50 [8];
  undefined1 local_48 [8];
  undefined1 local_40 [8];
  int local_38;
  int local_34;
  int local_30;
  int local_2c;
  uint local_28;
  int local_24;
  undefined4 local_20;
  ITEM *local_1c;
  uint local_18;
  ITEM *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100037ec;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10002f22(this,param_1);
  if (*(char *)((int)this + 0x4571) != '\0') {
    ExceptionList = local_10;
    return;
  }
  iVar2 = FUN_10002370((int)this + 0x2318);
  local_28 = iVar2 - 0x20U >> 1;
  iVar2 = FUN_10002390((int)this + 0x2318);
  local_18 = iVar2 - 0x20U >> 1;
  (**(code **)(*(int *)((int)this + 0x2318) + 0x2c))
            (*(int *)((int)this + 0xb4) - local_28,*(int *)((int)this + 0xb8) - local_18);
  FUN_1000146d(this,param_1);
  if (*(char *)((int)this + 0x4571) != '\0') {
    ExceptionList = local_10;
    return;
  }
  piVar3 = (int *)default_error_condition(local_48,0,1);
  piVar8 = &local_24;
  pvVar4 = FUN_10001000(this,local_40);
  FUN_100017a0(pvVar4,piVar8,piVar3);
  puVar5 = (undefined4 *)FUN_10001000(this,local_50);
  local_14 = MAP::GetItem(param_1,*puVar5,puVar5[1]);
  pCVar11 = local_58;
  pvVar4 = (void *)(**(code **)(*(int *)local_14 + 0x60))(pCVar11,s_FUELCELL_10005068);
  local_8 = 0;
  bVar1 = FUN_10002240(pvVar4,(uchar *)pCVar11);
  if (bVar1) {
LAB_10001da4:
    local_d0 = 1;
  }
  else {
    ppCVar12 = &this_10005074;
    pvVar4 = (void *)(**(code **)(*(int *)local_14 + 0x60))(local_60);
    local_8._0_1_ = 1;
    bVar1 = FUN_10002240(pvVar4,(uchar *)ppCVar12);
    local_5c = CONCAT31(local_5c._1_3_,bVar1);
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_60);
    if ((local_5c & 0xff) != 0) goto LAB_10001da4;
    local_d0 = 0;
  }
  local_54 = CONCAT31(local_54._1_3_,local_d0);
  local_8 = 0xffffffff;
  CString::~CString(local_58);
  if ((local_54 & 0xff) != 0) {
    FUN_100023b0(local_14,1);
    FUN_100023d0(local_14,0);
    ExceptionList = local_10;
    return;
  }
  pCVar11 = local_68;
  pvVar4 = (void *)(**(code **)(*(int *)local_14 + 0x60))(pCVar11,s_BLACKHOLE_10005078);
  local_8 = 2;
  bVar1 = FUN_10002240(pvVar4,(uchar *)pCVar11);
  local_64 = CONCAT31(local_64._1_3_,bVar1);
  local_8 = 0xffffffff;
  CString::~CString(local_68);
  if ((local_64 & 0xff) != 0) {
    FUN_10001157((int *)this);
    ExceptionList = local_10;
    return;
  }
  local_1c = MAP::GetItem(param_1,local_24,local_20);
  if (local_1c == (ITEM *)0x0) {
    ExceptionList = local_10;
    return;
  }
  if ((*(char *)((int)this + 0x4570) != '\0') &&
     (bVar1 = FUN_10002300((void *)((int)this + 0x457c),2000), CONCAT31(extraout_var,bVar1) != 0)) {
    pIVar6 = MAP::FindItem(s_BLANK_10005084);
    uVar7 = (**(code **)(*(int *)pIVar6 + 4))();
    piVar8 = (int *)default_error_condition(local_80,0,1);
    puVar10 = local_88;
    pvVar4 = FUN_10001000(this,local_78);
    puVar5 = (undefined4 *)FUN_100017a0(pvVar4,puVar10,piVar8);
    local_70 = MAP::SetItem(param_1,*puVar5,puVar5[1],uVar7);
    local_6c = local_70;
    if (local_70 != (ITEM *)0x0) {
      (*(code *)**(undefined4 **)local_70)(1);
    }
    *(undefined1 *)((int)this + 0x4570) = 0;
    (**(code **)(*(int *)((int)this + 0x11ec) + 0x20))();
    CWave::Stop((CWave *)((int)this + 0x112c));
    (**(code **)(*(int *)((int)this + 0x2318) + 0x1c))();
    MAP::RefreshBothLevelmapBuffers(param_1);
    *(undefined1 *)((int)this + 0x4572) = 1;
    ExceptionList = local_10;
    return;
  }
  bVar1 = FUN_100021f0(&local_24,*(int *)((int)this + 0x4574),*(int *)((int)this + 0x4578));
  if (!bVar1) {
    ExceptionList = local_10;
    return;
  }
  pCVar11 = local_90;
  pvVar4 = (void *)(**(code **)(*(int *)local_1c + 0x60))(pCVar11,s_FUELCELL_1000508c);
  local_8 = 3;
  bVar1 = FUN_10002240(pvVar4,(uchar *)pCVar11);
  if (bVar1) {
    iVar2 = FUN_100023f0((int)local_1c);
    _local_94 = CONCAT31(uStack_93,iVar2 != 0x14d);
    if (iVar2 != 0x14d) {
      cVar9 = '\x01' - (*(char *)((int)this + 0x4572) != '\0');
      _local_98 = CONCAT31(uStack_97,cVar9);
      if (cVar9 != '\0') {
        local_ec = 1;
        goto LAB_10002081;
      }
    }
  }
  local_ec = 0;
LAB_10002081:
  local_8c = CONCAT31(local_8c._1_3_,local_ec);
  local_8 = 0xffffffff;
  CString::~CString(local_90);
  if ((local_8c & 0xff) != 0) {
    FUN_10001000(this,&local_38);
    pvVar4 = FUN_10002340(&local_38,local_a0,0x20);
                    // WARNING: Load size is inaccurate
    (**(code **)(*this + 0x28))(pvVar4);
                    // WARNING: Load size is inaccurate
    (**(code **)(*this + 0x6c))(local_38 << 5,local_34 << 5,0);
    local_2c = FUN_10002370((int)this + 0x11ec);
    local_30 = (local_2c + -0x20) / 2;
    piVar8 = (int *)default_error_condition(local_b0,-local_30,0x18);
    puVar10 = local_b8;
    pvVar4 = (void *)OVERLAY::Position((OVERLAY *)this);
    pvVar4 = FUN_100017a0(pvVar4,puVar10,piVar8);
    (**(code **)(*(int *)((int)this + 0x11ec) + 0x28))(pvVar4);
    (**(code **)(*(int *)((int)this + 0x11ec) + 0x1c))();
    CWave::Play((CWave *)((int)this + 0x112c),0,0,1);
    MAP::RefreshBothLevelmapBuffers(param_1);
    FUN_100023b0(local_1c,0x14d);
    *(undefined1 *)((int)this + 0x4570) = 1;
    FUN_100022e0((DWORD *)((int)this + 0x457c));
  }
  ExceptionList = local_10;
  return;
}



bool __cdecl FUN_100021f0(int *param_1,int param_2,int param_3)

{
  int iVar1;
  
  iVar1 = FUN_100022a0(param_1,param_2,param_3);
  *param_1 = param_2;
  param_1[1] = param_3;
  return iVar1 != 0;
}



undefined4 __fastcall FUN_10002230(undefined4 *param_1)

{
  return *param_1;
}



bool FUN_10002240(void *param_1,uchar *param_2)

{
  int iVar1;
  
  iVar1 = FUN_10002260(param_1,param_2);
  return (bool)('\x01' - (iVar1 != 0));
}



void __thiscall FUN_10002260(void *this,uchar *param_1)

{
                    // WARNING: Load size is inaccurate
  FUN_10002280(*this,param_1);
  return;
}



void __cdecl FUN_10002280(uchar *param_1,uchar *param_2)

{
  _mbscmp(param_1,param_2);
  return;
}



undefined4 __thiscall FUN_100022a0(void *this,int param_1,int param_2)

{
  undefined4 local_c;
  
                    // WARNING: Load size is inaccurate
  if ((*this == param_1) && (*(int *)((int)this + 4) == param_2)) {
    local_c = 0;
  }
  else {
    local_c = 1;
  }
  return local_c;
}



void __fastcall FUN_100022e0(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
  return;
}



bool __thiscall FUN_10002300(void *this,uint param_1)

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



void * __thiscall FUN_10002340(void *this,void *param_1,int param_2)

{
                    // WARNING: Load size is inaccurate
  default_error_condition(param_1,*this * param_2,*(int *)((int)this + 4) * param_2);
  return param_1;
}



undefined4 __fastcall FUN_10002370(int param_1)

{
  return *(undefined4 *)(param_1 + 0xac);
}



undefined4 __fastcall FUN_10002390(int param_1)

{
  return *(undefined4 *)(param_1 + 0xb0);
}



void __thiscall FUN_100023b0(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 4) = param_1;
  return;
}



void __thiscall FUN_100023d0(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 8) = param_1;
  return;
}



undefined4 __fastcall FUN_100023f0(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



SPRITE * __fastcall FUN_10002410(SPRITE *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_10003869;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10002600(param_1);
  local_8 = 0;
  CWave::CWave((CWave *)(param_1 + 0x112c));
  local_8._0_1_ = 1;
  CWave::CWave((CWave *)(param_1 + 0x116c));
  local_8._0_1_ = 2;
  CWave::CWave((CWave *)(param_1 + 0x11ac));
  local_8._0_1_ = 3;
  SPRITE::SPRITE(param_1 + 0x11ec);
  local_8._0_1_ = 4;
  SPRITE::SPRITE(param_1 + 0x2318);
  local_8._0_1_ = 5;
  SPRITE::SPRITE(param_1 + 0x3444);
  local_8 = CONCAT31(local_8._1_3_,6);
  param_1[0x4570] = (SPRITE)0x0;
  param_1[0x4571] = (SPRITE)0x0;
  param_1[0x4572] = (SPRITE)0x0;
  param_1[0x4573] = (SPRITE)0x0;
  FUN_10001290(param_1 + 0x4574);
  FUN_10002570((DWORD *)(param_1 + 0x457c));
  param_1[0x4685] = (SPRITE)0x0;
  FUN_100012b0(param_1 + 0x4688,0x14,4,FUN_10001260);
  *(undefined4 *)(param_1 + 0x46d8) = 1;
  *(undefined ***)param_1 = &PTR_FUN_1000415c;
  *(undefined ***)(param_1 + 8) = &PTR_LAB_10004158;
  memset(param_1 + 0x4580,0,0x104);
  ExceptionList = local_10;
  return param_1;
}



DWORD * __fastcall FUN_10002570(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
  return param_1;
}



undefined1 __fastcall FUN_10002590(int param_1)

{
  return *(undefined1 *)(param_1 + 0xa0);
}



bool __fastcall FUN_100025b0(int param_1)

{
  return (bool)('\x01' - (*(char *)(param_1 + 0x4571) != '\0'));
}



void * __thiscall FUN_100025d0(void *this,uint param_1)

{
  FUN_10002650((SPRITE *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



SPRITE * __fastcall FUN_10002600(SPRITE *param_1)

{
  SPRITE::SPRITE(param_1);
  *(undefined ***)param_1 = &PTR_FUN_100041e0;
  *(undefined ***)(param_1 + 8) = &PTR_LAB_100041dc;
  return param_1;
}



void __fastcall FUN_10002630(SPRITE *param_1)

{
  SPRITE::~SPRITE(param_1);
  return;
}



void __fastcall FUN_10002650(SPRITE *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &this_100038d9;
  local_10 = ExceptionList;
  local_8 = 5;
  ExceptionList = &local_10;
  SPRITE::~SPRITE(param_1 + 0x3444);
  local_8._0_1_ = 4;
  SPRITE::~SPRITE(param_1 + 0x2318);
  local_8._0_1_ = 3;
  SPRITE::~SPRITE(param_1 + 0x11ec);
  local_8._0_1_ = 2;
  CWave::~CWave((CWave *)(param_1 + 0x11ac));
  local_8._0_1_ = 1;
  CWave::~CWave((CWave *)(param_1 + 0x116c));
  local_8 = (uint)local_8._1_3_ << 8;
  CWave::~CWave((CWave *)(param_1 + 0x112c));
  local_8 = 0xffffffff;
  FUN_10002630(param_1);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_10002700(void *this,uint param_1)

{
  FUN_10002630((SPRITE *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __thiscall FUN_10002730(void *this,MAP *param_1,int *param_2)

{
  FUN_100011b8((int)this);
  FUN_10002a0e(this,param_1,param_2);
  FUN_10002b50(this,param_1,param_2);
  FUN_10002c97(this,param_1,param_2);
  FUN_10002dda(this,param_1,param_2);
  return;
}



undefined4 __thiscall FUN_10002785(void *this,MAP *param_1,int *param_2,int param_3)

{
  char cVar1;
  bool bVar2;
  void *pvVar3;
  uint uVar4;
  CString *pCVar5;
  char *pcVar6;
  undefined1 local_68;
  CString local_40 [4];
  uint local_3c;
  CString local_38 [4];
  uint local_34;
  CString local_30 [4];
  uint local_2c;
  CString local_28 [4];
  uint local_24;
  CString local_20 [4];
  uint local_1c;
  ITEM *local_18;
  undefined4 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000391d;
  local_10 = ExceptionList;
  local_14 = (undefined4 *)((int)this + param_3 * 0x14 + 0x4688);
  ExceptionList = &local_10;
  local_18 = MAP::GetItem(param_1,*param_2,param_2[1]);
  cVar1 = (**(code **)(*(int *)local_18 + 0x80))();
  if (cVar1 != '\0') {
    pCVar5 = local_20;
    pvVar3 = (void *)(**(code **)(*(int *)local_18 + 0x60))(pCVar5,s_BLANK_10005098);
    local_8 = 0;
    bVar2 = FUN_10002240(pvVar3,(uchar *)pCVar5);
    local_1c = CONCAT31(local_1c._1_3_,bVar2);
    local_8 = 0xffffffff;
    CString::~CString(local_20);
    if ((local_1c & 0xff) == 0) {
      ExceptionList = local_10;
      return 0;
    }
    ExceptionList = local_10;
    return 2;
  }
  uVar4 = FUN_10003008(this,param_1,param_2);
  if ((uVar4 & 0xff) != 0) {
    *local_14 = 1;
    ExceptionList = local_10;
    return 3;
  }
  pCVar5 = local_28;
  pvVar3 = (void *)(**(code **)(*(int *)local_18 + 0x60))(pCVar5,s_BLANK_100050a0);
  local_8 = 1;
  bVar2 = FUN_10002240(pvVar3,(uchar *)pCVar5);
  local_24 = CONCAT31(local_24._1_3_,bVar2);
  local_8 = 0xffffffff;
  CString::~CString(local_28);
  if ((local_24 & 0xff) != 0) {
    uVar4 = FUN_10001070(param_2);
    if ((uVar4 & 0xff) == 0) {
      *local_14 = 1;
    }
    ExceptionList = local_10;
    return 1;
  }
  pCVar5 = local_30;
  pvVar3 = (void *)(**(code **)(*(int *)local_18 + 0x60))(pCVar5,&DAT_100050a8);
  local_8 = 2;
  bVar2 = FUN_10002240(pvVar3,(uchar *)pCVar5);
  if (!bVar2) {
    pcVar6 = s_FUELCELL_100050ac;
    pvVar3 = (void *)(**(code **)(*(int *)local_18 + 0x60))(local_38);
    local_8._0_1_ = 3;
    bVar2 = FUN_10002240(pvVar3,(uchar *)pcVar6);
    local_34 = CONCAT31(local_34._1_3_,bVar2);
    local_8 = CONCAT31(local_8._1_3_,2);
    CString::~CString(local_38);
    if ((local_34 & 0xff) == 0) {
      local_68 = 0;
      goto LAB_1000296c;
    }
  }
  local_68 = 1;
LAB_1000296c:
  local_2c = CONCAT31(local_2c._1_3_,local_68);
  local_8 = 0xffffffff;
  CString::~CString(local_30);
  if ((local_2c & 0xff) == 0) {
    pCVar5 = local_40;
    pvVar3 = (void *)(**(code **)(*(int *)local_18 + 0x60))(pCVar5,s_BLACKHOLE_100050b8);
    local_8 = 4;
    bVar2 = FUN_10002240(pvVar3,(uchar *)pCVar5);
    local_3c = CONCAT31(local_3c._1_3_,bVar2);
    local_8 = 0xffffffff;
    CString::~CString(local_40);
    if ((local_3c & 0xff) != 0) {
      FUN_100010d1((int)this);
      *local_14 = 3;
    }
  }
  else {
    *local_14 = 1;
  }
  ExceptionList = local_10;
  return 0;
}



void __thiscall FUN_10002a0e(void *this,MAP *param_1,int *param_2)

{
  bool bVar1;
  int iVar2;
  uint *puVar3;
  uint *puVar4;
  uint local_34;
  uint local_30;
  int local_2c;
  uint local_28;
  uint local_24;
  uint *local_20;
  uint local_1c [5];
  uint local_8;
  
  local_20 = (uint *)((int)this + 0x4688);
  puVar3 = local_20;
  puVar4 = local_1c;
  for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar4 = *puVar3;
    puVar3 = puVar3 + 1;
    puVar4 = puVar4 + 1;
  }
  local_8 = local_8 & 0xffffff00;
  local_28 = local_28 & 0xffffff00;
  local_24 = 1;
  while( true ) {
    if (*param_2 < (int)local_24) {
      return;
    }
    default_error_condition(&local_34,*param_2 - local_24,param_2[1]);
    local_2c = FUN_10002785(this,param_1,(int *)&local_34,0);
    if (local_2c == 2) {
      bVar1 = FUN_10003180((char *)&local_28,'\x01');
      if (bVar1) {
        puVar3 = local_20;
        puVar4 = local_1c;
        for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
          *puVar4 = *puVar3;
          puVar3 = puVar3 + 1;
          puVar4 = puVar4 + 1;
        }
      }
      if (local_24 == 1) {
        local_8 = CONCAT31(local_8._1_3_,1);
      }
    }
    if (((local_28 & 0xff) == 0) && (local_2c == 3)) {
      local_20[3] = local_34;
      local_20[4] = local_30;
      *(undefined1 *)(local_20 + 2) = 1;
      return;
    }
    if (local_2c == 0) break;
    local_24 = local_24 + 1;
  }
  if ((*local_20 & 2) != 0) {
    local_20[1] = local_24;
  }
  if ((local_8 & 0xff) != 0) {
    *local_20 = *local_20 & 0xfffffffe;
    return;
  }
  if ((local_28 & 0xff) == 0) {
    return;
  }
  if ((*local_20 & 2) != 0) {
    return;
  }
  puVar3 = local_1c;
  for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
    *local_20 = *puVar3;
    puVar3 = puVar3 + 1;
    local_20 = local_20 + 1;
  }
  return;
}



void __thiscall FUN_10002b50(void *this,MAP *param_1,int *param_2)

{
  bool bVar1;
  int iVar2;
  uint *puVar3;
  uint *puVar4;
  uint local_34;
  uint local_30;
  int local_2c;
  uint local_28;
  uint local_24;
  uint *local_20;
  uint local_1c [5];
  uint local_8;
  
  local_20 = (uint *)((int)this + 0x469c);
  puVar3 = local_20;
  puVar4 = local_1c;
  for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar4 = *puVar3;
    puVar3 = puVar3 + 1;
    puVar4 = puVar4 + 1;
  }
  local_8 = local_8 & 0xffffff00;
  local_28 = local_28 & 0xffffff00;
  local_24 = 1;
  while( true ) {
    if (0x14 - *param_2 <= (int)local_24) {
      return;
    }
    default_error_condition(&local_34,*param_2 + local_24,param_2[1]);
    local_2c = FUN_10002785(this,param_1,(int *)&local_34,1);
    if (local_2c == 2) {
      bVar1 = FUN_10003180((char *)&local_28,'\x01');
      if (bVar1) {
        puVar3 = local_20;
        puVar4 = local_1c;
        for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
          *puVar4 = *puVar3;
          puVar3 = puVar3 + 1;
          puVar4 = puVar4 + 1;
        }
      }
      if (local_24 == 1) {
        local_8 = CONCAT31(local_8._1_3_,1);
      }
    }
    if (((local_28 & 0xff) == 0) && (local_2c == 3)) {
      local_20[3] = local_34;
      local_20[4] = local_30;
      *(undefined1 *)(local_20 + 2) = 1;
      return;
    }
    if (local_2c == 0) break;
    local_24 = local_24 + 1;
  }
  if ((*local_20 & 2) != 0) {
    local_20[1] = local_24;
  }
  if ((local_8 & 0xff) != 0) {
    *local_20 = *local_20 & 0xfffffffe;
    return;
  }
  if ((local_28 & 0xff) == 0) {
    return;
  }
  if ((*local_20 & 2) != 0) {
    return;
  }
  puVar3 = local_1c;
  for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
    *local_20 = *puVar3;
    puVar3 = puVar3 + 1;
    local_20 = local_20 + 1;
  }
  return;
}



void __thiscall FUN_10002c97(void *this,MAP *param_1,undefined4 *param_2)

{
  bool bVar1;
  int iVar2;
  uint *puVar3;
  uint *puVar4;
  uint local_34;
  uint local_30;
  int local_2c;
  uint local_28;
  uint local_24;
  uint *local_20;
  uint local_1c [5];
  uint local_8;
  
  local_20 = (uint *)((int)this + 0x46b0);
  puVar3 = local_20;
  puVar4 = local_1c;
  for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar4 = *puVar3;
    puVar3 = puVar3 + 1;
    puVar4 = puVar4 + 1;
  }
  local_8 = local_8 & 0xffffff00;
  local_28 = local_28 & 0xffffff00;
  local_24 = 1;
  while( true ) {
    if ((int)param_2[1] < (int)local_24) {
      return;
    }
    default_error_condition(&local_34,*param_2,param_2[1] - local_24);
    local_2c = FUN_10002785(this,param_1,(int *)&local_34,2);
    if (local_2c == 2) {
      bVar1 = FUN_10003180((char *)&local_28,'\x01');
      if (bVar1) {
        puVar3 = local_20;
        puVar4 = local_1c;
        for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
          *puVar4 = *puVar3;
          puVar3 = puVar3 + 1;
          puVar4 = puVar4 + 1;
        }
      }
      if (local_24 == 1) {
        local_8 = CONCAT31(local_8._1_3_,1);
      }
    }
    if (((local_28 & 0xff) == 0) && (local_2c == 3)) {
      local_20[3] = local_34;
      local_20[4] = local_30;
      *(undefined1 *)(local_20 + 2) = 1;
      return;
    }
    if (local_2c == 0) break;
    local_24 = local_24 + 1;
  }
  if ((*local_20 & 2) != 0) {
    local_20[1] = local_24;
  }
  if ((local_8 & 0xff) != 0) {
    *local_20 = *local_20 & 0xfffffffe;
    return;
  }
  if ((local_28 & 0xff) == 0) {
    return;
  }
  if ((*local_20 & 2) != 0) {
    return;
  }
  puVar3 = local_1c;
  for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
    *local_20 = *puVar3;
    puVar3 = puVar3 + 1;
    local_20 = local_20 + 1;
  }
  return;
}



void __thiscall FUN_10002dda(void *this,MAP *param_1,undefined4 *param_2)

{
  bool bVar1;
  int iVar2;
  uint *puVar3;
  uint *puVar4;
  uint local_34;
  uint local_30;
  int local_2c;
  uint local_28;
  uint local_24;
  uint *local_20;
  uint local_1c [5];
  uint local_8;
  
  local_20 = (uint *)((int)this + 0x46c4);
  puVar3 = local_20;
  puVar4 = local_1c;
  for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar4 = *puVar3;
    puVar3 = puVar3 + 1;
    puVar4 = puVar4 + 1;
  }
  local_8 = local_8 & 0xffffff00;
  local_28 = local_28 & 0xffffff00;
  local_24 = 1;
  while( true ) {
    if (0xd - param_2[1] <= (int)local_24) {
      return;
    }
    default_error_condition(&local_34,*param_2,param_2[1] + local_24);
    local_2c = FUN_10002785(this,param_1,(int *)&local_34,3);
    if (local_2c == 2) {
      bVar1 = FUN_10003180((char *)&local_28,'\x01');
      if (bVar1) {
        puVar3 = local_20;
        puVar4 = local_1c;
        for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
          *puVar4 = *puVar3;
          puVar3 = puVar3 + 1;
          puVar4 = puVar4 + 1;
        }
      }
      if (local_24 == 1) {
        local_8 = CONCAT31(local_8._1_3_,1);
      }
    }
    if (((local_28 & 0xff) == 0) && (local_2c == 3)) {
      local_20[3] = local_34;
      local_20[4] = local_30;
      *(undefined1 *)(local_20 + 2) = 1;
      return;
    }
    if (local_2c == 0) break;
    local_24 = local_24 + 1;
  }
  if ((*local_20 & 2) != 0) {
    local_20[1] = local_24;
  }
  if ((local_8 & 0xff) != 0) {
    *local_20 = *local_20 & 0xfffffffe;
    return;
  }
  if ((local_28 & 0xff) == 0) {
    return;
  }
  if ((*local_20 & 2) != 0) {
    return;
  }
  puVar3 = local_1c;
  for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
    *local_20 = *puVar3;
    puVar3 = puVar3 + 1;
    local_20 = local_20 + 1;
  }
  return;
}



void __thiscall FUN_10002f22(void *this,MAP *param_1)

{
  bool bVar1;
  ITEM *pIVar2;
  undefined4 uVar3;
  void *this_00;
  undefined4 *puVar4;
  undefined1 *puVar5;
  int iVar6;
  undefined1 local_1c [16];
  ITEM *local_c;
  ITEM *local_8;
  
  if ((*(char *)((int)this + 0x4573) != '\0') &&
     (bVar1 = SPRITE::InMotion((SPRITE *)((int)this + 0x3444)), !bVar1)) {
    (**(code **)(*(int *)((int)this + 0x3444) + 0x20))();
    pIVar2 = MAP::FindItem(s_BLANK_100050c4);
    uVar3 = (**(code **)(*(int *)pIVar2 + 4))();
    iVar6 = 0x20;
    puVar5 = local_1c;
    this_00 = (void *)OVERLAY::Position((OVERLAY *)((int)this + 0x3444));
    puVar4 = (undefined4 *)FUN_100031e0(this_00,puVar5,iVar6);
    local_c = MAP::SetItem(param_1,*puVar4,puVar4[1],uVar3);
    local_8 = local_c;
    if (local_c != (ITEM *)0x0) {
      (*(code *)**(undefined4 **)local_c)(1);
    }
    *(undefined1 *)((int)this + 0x4573) = 0;
    CWave::Play((CWave *)((int)this + 0x116c),0,0,0);
  }
  return;
}



uint __thiscall FUN_10003008(void *this,MAP *param_1,undefined4 *param_2)

{
  ITEM *pIVar1;
  uint uVar2;
  
  if (*(char *)((int)this + 0x4572) == '\0') {
    uVar2 = (uint)this & 0xffffff00;
  }
  else {
    pIVar1 = MAP::GetItem(param_1,*param_2,param_2[1]);
    uVar2 = (**(code **)(*(int *)pIVar1 + 0x4c))();
    if ((uVar2 != 0) && (uVar2 = FUN_100023f0((int)pIVar1), uVar2 != 0x14d)) {
      return CONCAT31((int3)(uVar2 >> 8),1);
    }
    uVar2 = uVar2 & 0xffffff00;
  }
  return uVar2;
}



void __thiscall FUN_10003064(void *this,MAP *param_1,int *param_2)

{
  ITEM *this_00;
  undefined4 uVar1;
  int local_10;
  int local_c;
  int local_8;
  
  FUN_10001000(this,&local_10);
  local_8 = FUN_100031b0(((*param_2 - local_10) + param_2[1]) - local_c);
  (**(code **)(*(int *)((int)this + 0x3444) + 0x2c))(local_10 * 0x20 + 0x10,local_c * 0x20 + 0x10);
  (**(code **)(*(int *)((int)this + 0x3444) + 0x1c))();
  (**(code **)(*(int *)((int)this + 0x3444) + 0x6c))
            (*param_2 * 0x20 + 0x10,param_2[1] * 0x20 + 0x10,local_8 * 0x50);
  *(undefined1 *)((int)this + 0x4572) = 0;
  (**(code **)(*(int *)((int)this + 0x2318) + 0x20))();
  uVar1 = 0x14d;
  this_00 = MAP::GetItem(param_1,*param_2,param_2[1]);
  FUN_100023b0(this_00,uVar1);
  *(undefined1 *)((int)this + 0x4573) = 1;
  MAP::RefreshBothLevelmapBuffers(param_1);
  CWave::Play((CWave *)((int)this + 0x11ac),0,0,0);
  return;
}



bool __cdecl FUN_10003180(char *param_1,char param_2)

{
  char cVar1;
  
  cVar1 = *param_1;
  *param_1 = param_2;
  return cVar1 != param_2;
}



int __cdecl FUN_100031b0(int param_1)

{
  undefined4 local_8;
  
  if (param_1 < 0) {
    local_8 = -param_1;
  }
  else {
    local_8 = param_1;
  }
  return local_8;
}



void * __thiscall FUN_100031e0(void *this,void *param_1,int param_2)

{
  if (param_2 == 0) {
    default_error_condition(param_1,0xffffffff,0xffffffff);
  }
  else {
                    // WARNING: Load size is inaccurate
    default_error_condition(param_1,*this / param_2,*(int *)((int)this + 4) / param_2);
  }
  return param_1;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000322a. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x10003230. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void __thiscall CString::~CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x10003236. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CString(this);
  return;
}



void __thiscall CString::CString(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000323c. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



void * __thiscall FUN_10003274(void *this,byte param_1)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)this);
  if ((param_1 & 1) != 0) {
    CNoTrackObject::operator_delete(this);
  }
  return this;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x1000370e. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



int FUN_100032ef(HINSTANCE__ *param_1,int param_2)

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
      pAVar5 = AfxSetModuleState((AFX_MODULE_STATE *)&this_10005260);
      p_Var3 = AfxGetThreadState();
      *(AFX_MODULE_STATE **)(p_Var3 + 8) = pAVar5;
      pAVar5 = AfxGetModuleState();
      if (*(int **)(pAVar5 + 4) != (int *)0x0) {
        (**(code **)(**(int **)(pAVar5 + 4) + 0x70))();
      }
      AfxLockTempMaps();
      AfxUnlockTempMaps(-1);
      AfxWinTerm();
      AfxTermExtensionModule((AFX_EXTENSION_MODULE *)&param_1_100062f0,1);
    }
    else if (param_2 == 3) {
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
                ((AFX_MAINTAIN_STATE2 *)&local_c,(AFX_MODULE_STATE *)&this_10005260);
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
  iVar4 = AfxWinInit(param_1,(HINSTANCE__ *)0x0,(char *)&param_3_10004268,0);
  if (iVar4 != 0) {
    pAVar5 = AfxGetModuleState();
    piVar2 = *(int **)(pAVar5 + 4);
    if ((piVar2 == (int *)0x0) || (iVar4 = (**(code **)(*piVar2 + 0x58))(), iVar4 != 0)) {
      *(undefined4 *)(p_Var3 + 8) = uVar1;
      AfxInitExtensionModule((AFX_EXTENSION_MODULE *)&param_1_100062f0,param_1);
      this = (CDynLinkLibrary *)operator_new(0x40);
      if (this != (CDynLinkLibrary *)0x0) {
        CDynLinkLibrary::CDynLinkLibrary(this,(AFX_EXTENSION_MODULE *)&param_1_100062f0,0);
      }
      param_2 = 1;
      goto LAB_1000337b;
    }
    (**(code **)(*piVar2 + 0x70))();
  }
  AfxWinTerm();
LAB_1000337b:
  *(undefined4 *)(p_Var3 + 8) = uVar1;
  p_Var3 = AfxGetThreadState();
  AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var3 + 8));
  return param_2;
}



undefined4 FUN_10003416(undefined4 param_1,int param_2)

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
    pAVar2 = AfxSetModuleState((AFX_MODULE_STATE *)&this_10005260);
    *(AFX_MODULE_STATE **)(p_Var1 + 8) = pAVar2;
  }
  else if (param_2 == 0) {
    p_Var1 = AfxGetThreadState();
    AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var1 + 8));
  }
  return 1;
}



void __fastcall FUN_10003467(undefined4 *param_1)

{
  *(undefined4 *)(param_1[1] + 4) = *param_1;
  return;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x10003470. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



void __CxxFrameHandler(void)

{
                    // WARNING: Could not recover jumptable at 0x10003476. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10003486(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 *_Memory;
  undefined4 *puVar2;
  
  if (param_2 == 0) {
    if (0 < DAT_1000630c) {
      DAT_1000630c = DAT_1000630c + -1;
      goto LAB_1000349c;
    }
LAB_100034c4:
    uVar1 = 0;
  }
  else {
LAB_1000349c:
    _DAT_10006310 = *(undefined4 *)_adjust_fdiv_exref;
    if (param_2 == 1) {
      DAT_10006318 = (undefined4 *)malloc(0x80);
      if (DAT_10006318 == (undefined4 *)0x0) goto LAB_100034c4;
      *DAT_10006318 = 0;
      DAT_10006314 = DAT_10006318;
      initterm(&DAT_10005000,&DAT_10005008);
      DAT_1000630c = DAT_1000630c + 1;
    }
    else if ((param_2 == 0) &&
            (_Memory = DAT_10006318, puVar2 = DAT_10006314, DAT_10006318 != (undefined4 *)0x0)) {
      while (puVar2 = puVar2 + -1, _Memory <= puVar2) {
        if ((code *)*puVar2 != (code *)0x0) {
          (*(code *)*puVar2)();
          _Memory = DAT_10006318;
        }
      }
      free(_Memory);
      DAT_10006318 = (undefined4 *)0x0;
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
  iVar2 = DAT_1000630c;
  if (param_2 != 0) {
    if ((param_2 != 1) && (param_2 != 2)) goto LAB_10003579;
    if ((PTR_FUN_100050cc != (undefined *)0x0) &&
       (iVar2 = (*(code *)PTR_FUN_100050cc)(param_1,param_2,param_3), iVar2 == 0)) {
      return 0;
    }
    iVar2 = FUN_10003486(param_1,param_2);
  }
  if (iVar2 == 0) {
    return 0;
  }
LAB_10003579:
  iVar2 = FUN_100032ef(param_1,param_2);
  if (param_2 == 1) {
    if (iVar2 != 0) {
      return iVar2;
    }
    FUN_10003486(param_1,0);
  }
  if ((param_2 != 0) && (param_2 != 3)) {
    return iVar2;
  }
  iVar3 = FUN_10003486(param_1,param_2);
  param_2 = iVar2;
  if (iVar3 == 0) {
    param_2 = 0;
  }
  if (param_2 != 0) {
    if (PTR_FUN_100050cc != (undefined *)0x0) {
      iVar2 = (*(code *)PTR_FUN_100050cc)(param_1,iVar1,param_3);
      return iVar2;
    }
    return param_2;
  }
  return 0;
}



void * __thiscall FUN_100035ce(void *this,byte param_1)

{
  type_info::~type_info((type_info *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __cdecl initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x10003648. Too many branches
                    // WARNING: Treating indirect jump as call
  initterm();
  return;
}



void __thiscall type_info::~type_info(type_info *this)

{
                    // WARNING: Could not recover jumptable at 0x1000364e. Too many branches
                    // WARNING: Treating indirect jump as call
  ~type_info(this);
  return;
}



void CNoTrackObject::operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10003708. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x1000370e. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



void __thiscall
AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(AFX_MAINTAIN_STATE2 *this,AFX_MODULE_STATE *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000371a. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MAINTAIN_STATE2(this,param_1);
  return;
}



void AfxTermThread(HINSTANCE__ *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10003720. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermThread(param_1);
  return;
}



void AfxTermExtensionModule(AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10003726. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermExtensionModule(param_1,param_2);
  return;
}



int AfxUnlockTempMaps(int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000372c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxUnlockTempMaps(param_1);
  return iVar1;
}



void AfxLockTempMaps(void)

{
                    // WARNING: Could not recover jumptable at 0x10003732. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxLockTempMaps();
  return;
}



AFX_MODULE_STATE * AfxSetModuleState(AFX_MODULE_STATE *param_1)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10003738. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxSetModuleState(param_1);
  return pAVar1;
}



void __thiscall
CDynLinkLibrary::CDynLinkLibrary(CDynLinkLibrary *this,AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x1000373e. Too many branches
                    // WARNING: Treating indirect jump as call
  CDynLinkLibrary(this,param_1,param_2);
  return;
}



int AfxInitExtensionModule(AFX_EXTENSION_MODULE *param_1,HINSTANCE__ *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10003744. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxInitExtensionModule(param_1,param_2);
  return iVar1;
}



void AfxWinTerm(void)

{
                    // WARNING: Could not recover jumptable at 0x1000374a. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxWinTerm();
  return;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10003750. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



int AfxWinInit(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10003756. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinInit(param_1,param_2,param_3,param_4);
  return iVar1;
}



_AFX_THREAD_STATE * AfxGetThreadState(void)

{
  _AFX_THREAD_STATE *p_Var1;
  
                    // WARNING: Could not recover jumptable at 0x1000375c. Too many branches
                    // WARNING: Treating indirect jump as call
  p_Var1 = AfxGetThreadState();
  return p_Var1;
}



void AfxCoreInitModule(void)

{
                    // WARNING: Could not recover jumptable at 0x10003762. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxCoreInitModule();
  return;
}



void Unwind_10003770(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x14));
  return;
}



void Unwind_10003785(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000378e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_10003797(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_100037a0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_100037a9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_100037b2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_100037c5(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x54));
  return;
}



void Unwind_100037ce(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x5c));
  return;
}



void Unwind_100037d7(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -100));
  return;
}



void Unwind_100037e0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x8c));
  return;
}



void Unwind_10003800(void)

{
  int unaff_EBP;
  
  FUN_10002630(*(SPRITE **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10003809(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x112c));
  return;
}



void Unwind_10003819(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x116c));
  return;
}



void Unwind_10003829(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x11ac));
  return;
}



void Unwind_10003839(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x11ec));
  return;
}



void Unwind_10003849(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x2318));
  return;
}



void Unwind_10003859(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x3444));
  return;
}



void Unwind_10003880(void)

{
  int unaff_EBP;
  
  FUN_10002630(*(SPRITE **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10003889(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x112c));
  return;
}



void Unwind_10003899(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x116c));
  return;
}



void Unwind_100038a9(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x11ac));
  return;
}



void Unwind_100038b9(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x11ec));
  return;
}



void Unwind_100038c9(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x2318));
  return;
}



void Unwind_100038f0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_100038f9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_10003902(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_1000390b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_10003914(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_10003928(void)

{
  int unaff_EBP;
  
  FUN_10003467((undefined4 *)(unaff_EBP + -0x14));
  return;
}


