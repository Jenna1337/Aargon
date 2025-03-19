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

typedef struct tagBITMAPINFOHEADER tagBITMAPINFOHEADER, *PtagBITMAPINFOHEADER;

typedef ulong DWORD;

typedef long LONG;

typedef ushort WORD;

struct tagBITMAPINFOHEADER {
    DWORD biSize;
    LONG biWidth;
    LONG biHeight;
    WORD biPlanes;
    WORD biBitCount;
    DWORD biCompression;
    DWORD biSizeImage;
    LONG biXPelsPerMeter;
    LONG biYPelsPerMeter;
    DWORD biClrUsed;
    DWORD biClrImportant;
};

typedef struct tagRGBQUAD tagRGBQUAD, *PtagRGBQUAD;

typedef uchar BYTE;

struct tagRGBQUAD {
    BYTE rgbBlue;
    BYTE rgbGreen;
    BYTE rgbRed;
    BYTE rgbReserved;
};

typedef struct tagBITMAPINFO tagBITMAPINFO, *PtagBITMAPINFO;

typedef struct tagBITMAPINFOHEADER BITMAPINFOHEADER;

typedef struct tagRGBQUAD RGBQUAD;

struct tagBITMAPINFO {
    BITMAPINFOHEADER bmiHeader;
    RGBQUAD bmiColors[1];
};

typedef struct tagBITMAPINFO *LPBITMAPINFO;

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void *LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef char CHAR;

typedef CHAR *LPCSTR;

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

typedef struct HDC__ HDC__, *PHDC__;

typedef struct HDC__ *HDC;

struct HDC__ {
    int unused;
};

typedef struct HBITMAP__ HBITMAP__, *PHBITMAP__;

struct HBITMAP__ {
    int unused;
};

typedef DWORD *LPDWORD;

typedef HANDLE HGLOBAL;

typedef void *HGDIOBJ;

typedef void *LPCVOID;

typedef HANDLE HLOCAL;

typedef DWORD COLORREF;

typedef struct HBITMAP__ *HBITMAP;

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

typedef struct CRuntimeClass CRuntimeClass, *PCRuntimeClass;

struct CRuntimeClass { // PlaceHolder Structure
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

typedef struct CRect CRect, *PCRect;

struct CRect { // PlaceHolder Structure
};

typedef struct CArchive CArchive, *PCArchive;

struct CArchive { // PlaceHolder Structure
};

typedef struct LIST<unsigned_long> LIST<unsigned_long>, *PLIST<unsigned_long>;

struct LIST<unsigned_long> { // PlaceHolder Structure
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

typedef struct CPlex CPlex, *PCPlex;

struct CPlex { // PlaceHolder Structure
};

typedef struct CObject CObject, *PCObject;

struct CObject { // PlaceHolder Structure
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ { // PlaceHolder Structure
};

typedef struct CTypeLibCacheMap CTypeLibCacheMap, *PCTypeLibCacheMap;

struct CTypeLibCacheMap { // PlaceHolder Structure
};

typedef struct HWND__ HWND__, *PHWND__;

struct HWND__ { // PlaceHolder Structure
};

typedef struct CGdiObject CGdiObject, *PCGdiObject;

struct CGdiObject { // PlaceHolder Structure
};

typedef struct TwCompatibleBitmap TwCompatibleBitmap, *PTwCompatibleBitmap;

struct TwCompatibleBitmap { // PlaceHolder Structure
};

typedef int (*_onexit_t)(void);

typedef uint size_t;




// public: bool __thiscall TwCompatibleBitmap::LoadFromFile(char const *,class CRect)

bool __thiscall TwCompatibleBitmap::LoadFromFile(TwCompatibleBitmap *this,char *param_1)

{
  int iVar1;
  int iVar2;
  uchar *puVar3;
  HDC__ *pHVar4;
  int iVar5;
  char *pcVar6;
  void *pvVar7;
  uint *puVar8;
  int *piVar9;
  int *piVar10;
  int *piVar11;
  int iVar12;
  char local_4c [8];
  char local_44 [8];
  undefined1 local_3c;
  uint local_38;
  int local_34;
  int local_30;
  int local_2c;
  int local_28;
  ulong local_24;
  char local_20 [8];
  char local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x1000  12  ?LoadFromFile@TwCompatibleBitmap@@QAE_NPBDVCRect@@@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_10003054;
  local_10 = ExceptionList;
  if (param_1 == (char *)0x0) {
    local_3c = 0;
  }
  else if (*(int *)(this + 8) == 0) {
    local_3c = 0;
  }
  else {
    ExceptionList = &local_10;
    iVar1 = FUN_10001570((int)&stack0x00000008);
    iVar2 = FUN_10001550((int *)&stack0x00000008);
    iVar1 = FUN_100015c0(this,*(int *)(this + 8),iVar2,iVar1);
    if (iVar1 == 0) {
      local_3c = 0;
    }
    else {
      local_38 = 0;
      local_24 = 0;
      puVar3 = ExtractColorData(param_1,(CRect *)&stack0x00000008,&local_38,&local_24);
      FUN_10001450(local_20,(int)puVar3);
      local_8 = 0;
      local_34 = 0;
      local_30 = 0;
      local_28 = 0;
      piVar11 = &local_28;
      piVar10 = &local_30;
      piVar9 = &local_34;
      pHVar4 = (HDC__ *)FUN_100015f0(*(int *)(this + 8));
      iVar1 = GetRGBBitsPerPixel(pHVar4,piVar9,piVar10,piVar11);
      if (iVar1 == 0) {
        local_3c = 0;
        local_8 = 0xffffffff;
        FUN_10001500(local_20);
      }
      else {
        local_2c = FUN_10001620(*(void **)(this + 8),0xc);
        FUN_10001450(local_18,0);
        local_8._0_1_ = 1;
        if (local_24 == 0x18) {
          if (local_2c == 0x10) {
            puVar8 = &local_38;
            iVar1 = local_34;
            iVar2 = local_30;
            iVar12 = local_28;
            iVar5 = FUN_10002220((int)local_20);
            pvVar7 = FUN_1000135e(iVar5,puVar8,(char)iVar1,(char)iVar2,(byte)iVar12);
            pcVar6 = (char *)FUN_10001450(local_44,(int)pvVar7);
            local_8._0_1_ = 2;
            FUN_10001480(local_18,pcVar6);
            local_8._0_1_ = 1;
            FUN_10001500(local_44);
          }
          else if (local_2c == 0x18) {
            FUN_10001480(local_18,local_20);
          }
          else if (local_2c == 0x20) {
            puVar8 = &local_38;
            iVar1 = local_34;
            iVar2 = local_30;
            iVar12 = local_28;
            iVar5 = FUN_10002220((int)local_20);
            pvVar7 = FUN_10001274(iVar5,puVar8,(char)iVar1,(char)iVar2,(byte)iVar12);
            pcVar6 = (char *)FUN_10001450(local_4c,(int)pvVar7);
            local_8._0_1_ = 3;
            FUN_10001480(local_18,pcVar6);
            local_8._0_1_ = 1;
            FUN_10001500(local_4c);
          }
        }
        iVar1 = FUN_10002220((int)local_18);
        if (iVar1 == 0) {
          local_8 = (uint)local_8._1_3_ << 8;
          FUN_10001500(local_18);
          local_8 = 0xffffffff;
          FUN_10001500(local_20);
          local_3c = 0;
        }
        else {
          pvVar7 = (void *)FUN_10002220((int)local_18);
          FUN_10001590(this,local_38,pvVar7);
          local_8 = (uint)local_8._1_3_ << 8;
          FUN_10001500(local_18);
          local_8 = 0xffffffff;
          FUN_10001500(local_20);
          local_3c = 1;
        }
      }
    }
  }
  ExceptionList = local_10;
  return (bool)local_3c;
}



void * __cdecl FUN_10001274(int param_1,uint *param_2,char param_3,char param_4,byte param_5)

{
  void *pvVar1;
  undefined4 local_10;
  undefined4 local_c;
  
  pvVar1 = malloc(*param_2 + *param_2 / 3);
  local_10 = 0;
  for (local_c = 0; local_c + 2U < *param_2; local_c = local_c + 3) {
    *(uint *)((int)pvVar1 + local_10) =
         ((uint)*(byte *)(param_1 + local_c + 2) << (param_3 - 8U & 0x1f)) <<
         (param_4 + param_5 & 0x1f) |
         ((uint)*(byte *)(param_1 + local_c + 1) << (param_4 - 8U & 0x1f)) << (param_5 & 0x1f) |
         (uint)*(byte *)(param_1 + local_c) << (param_5 - 8 & 0x1f);
    local_10 = local_10 + 4;
  }
  *param_2 = *param_2 + *param_2 / 3;
  return pvVar1;
}



void * __cdecl FUN_1000135e(int param_1,uint *param_2,char param_3,char param_4,byte param_5)

{
  void *pvVar1;
  undefined2 local_18;
  undefined4 local_10;
  undefined4 local_c;
  
  pvVar1 = malloc(*param_2 - *param_2 / 3);
  local_10 = 0;
  for (local_c = 0; local_c + 2U < *param_2; local_c = local_c + 3) {
    local_18 = (ushort)(((int)(uint)*(byte *)(param_1 + local_c + 2) >> (8U - param_3 & 0x1f)) <<
                       (param_4 + param_5 & 0x1f)) |
               (ushort)(((int)(uint)*(byte *)(param_1 + local_c + 1) >> (8U - param_4 & 0x1f)) <<
                       (param_5 & 0x1f)) |
               (ushort)((int)(uint)*(byte *)(param_1 + local_c) >> (8 - param_5 & 0x1f));
    *(ushort *)((int)pvVar1 + local_10) = local_18;
    local_10 = local_10 + 2;
  }
  *param_2 = *param_2 - *param_2 / 3;
  return pvVar1;
}



void * __thiscall FUN_10001450(void *this,int param_1)

{
  *(bool *)this = param_1 != 0;
  *(int *)((int)this + 4) = param_1;
  return this;
}



void * __thiscall FUN_10001480(void *this,char *param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  if ((char *)this != param_1) {
    iVar1 = FUN_10002220((int)param_1);
    if (*(int *)((int)this + 4) == iVar1) {
      if (*param_1 != '\0') {
        *(undefined1 *)this = 1;
      }
    }
    else {
                    // WARNING: Load size is inaccurate
      if (*this != '\0') {
        operator_delete(*(void **)((int)this + 4));
      }
      *(char *)this = *param_1;
    }
    uVar2 = FUN_10001530(param_1);
    *(undefined4 *)((int)this + 4) = uVar2;
  }
  return this;
}



void __fastcall FUN_10001500(char *param_1)

{
  if (*param_1 != '\0') {
    operator_delete(*(void **)(param_1 + 4));
  }
  return;
}



undefined4 __fastcall FUN_10001530(undefined1 *param_1)

{
  *param_1 = 0;
  return *(undefined4 *)(param_1 + 4);
}



int __fastcall FUN_10001550(int *param_1)

{
  return param_1[2] - *param_1;
}



int __fastcall FUN_10001570(int param_1)

{
  return *(int *)(param_1 + 0xc) - *(int *)(param_1 + 4);
}



void __thiscall FUN_10001590(void *this,DWORD param_1,void *param_2)

{
  SetBitmapBits(*(HBITMAP *)((int)this + 4),param_1,param_2);
  return;
}



void __thiscall FUN_100015c0(void *this,int param_1,int param_2,int param_3)

{
  HBITMAP pHVar1;
  
  pHVar1 = CreateCompatibleBitmap(*(HDC *)(param_1 + 4),param_2,param_3);
  CGdiObject::Attach((CGdiObject *)this,pHVar1);
  return;
}



undefined4 __fastcall FUN_100015f0(int param_1)

{
  undefined4 local_c;
  
  if (param_1 == 0) {
    local_c = 0;
  }
  else {
    local_c = *(undefined4 *)(param_1 + 4);
  }
  return local_c;
}



void __thiscall FUN_10001620(void *this,int param_1)

{
  GetDeviceCaps(*(HDC *)((int)this + 8),param_1);
  return;
}



// unsigned long __cdecl TwColorTools::InterpolateColor(unsigned long,unsigned long,unsigned
// int,unsigned int)

ulong __cdecl TwColorTools::InterpolateColor(ulong param_1,ulong param_2,uint param_3,uint param_4)

{
  char cVar1;
  char cVar2;
  char cVar3;
  ulong uVar4;
  
                    // 0x1640  11  ?InterpolateColor@TwColorTools@@YAKKKII@Z
  if (param_3 == 0) {
    uVar4 = 0xffffff;
  }
  else {
    cVar1 = ftol();
    cVar2 = ftol();
    cVar3 = ftol();
    uVar4 = (ulong)CONCAT12((char)(param_1 >> 0x10) - cVar2,
                            CONCAT11((char)(param_1 >> 8) - cVar3,(char)param_1 - cVar1));
  }
  return uVar4;
}



// WARNING: Variable defined which should be unmapped: param_1
// class LIST<unsigned long> __cdecl TwColorTools::GetColorInterpolationsInclusive(unsigned
// long,unsigned long,unsigned int)

ulong __cdecl
TwColorTools::GetColorInterpolationsInclusive(ulong param_1,ulong param_2,uint param_3)

{
  uint in_stack_00000010;
  ulong local_34;
  CTypeLibCacheMap local_30 [28];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
                    // 0x176b  7
                    // ?GetColorInterpolationsInclusive@TwColorTools@@YA?AV?$LIST@K@@KKI@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_10003080;
  local_10 = ExceptionList;
  if (in_stack_00000010 < 2) {
    ExceptionList = &local_10;
    CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)param_1);
  }
  else {
    ExceptionList = &local_10;
    CTypeLibCacheMap::CTypeLibCacheMap(local_30);
    local_8 = 1;
    for (local_14 = 0; local_14 < in_stack_00000010; local_14 = local_14 + 1) {
      local_34 = InterpolateColor(param_2,param_3,in_stack_00000010,local_14);
      FUN_10001e60(local_30,&local_34);
    }
    FUN_10001e00((void *)param_1,(int)local_30);
    local_8 = local_8 & 0xffffff00;
    FUN_10001db0((undefined4 *)local_30);
  }
  ExceptionList = local_10;
  return param_1;
}



// class LIST<unsigned long> __cdecl TwColorTools::GetColorInterpolationsExclusive(unsigned
// long,unsigned long,unsigned int)

ulong __cdecl
TwColorTools::GetColorInterpolationsExclusive(ulong param_1,ulong param_2,uint param_3)

{
  uint in_stack_00000010;
  undefined4 local_2c [7];
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
                    // 0x1832  6
                    // ?GetColorInterpolationsExclusive@TwColorTools@@YA?AV?$LIST@K@@KKI@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_100030aa;
  local_10 = ExceptionList;
  if (in_stack_00000010 < 2) {
    ExceptionList = &local_10;
    CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)param_1);
  }
  else {
    ExceptionList = &local_10;
    GetColorInterpolationsInclusive((ulong)local_2c,param_2,param_3);
    local_8 = 1;
    FUN_10001f10(local_2c);
    FUN_10001f70(local_2c);
    FUN_10001e00((void *)param_1,(int)local_2c);
    local_8 = local_8 & 0xffffff00;
    FUN_10001db0(local_2c);
  }
  ExceptionList = local_10;
  return param_1;
}



// int __cdecl GetOptimalDIBFormat(struct HDC__ *,struct tagBITMAPINFOHEADER *)

int __cdecl GetOptimalDIBFormat(HDC__ *param_1,tagBITMAPINFOHEADER *param_2)

{
  HBITMAP hbm;
  int local_8;
  
                    // 0x18d6  9  ?GetOptimalDIBFormat@@YAHPAUHDC__@@PAUtagBITMAPINFOHEADER@@@Z
  hbm = CreateCompatibleBitmap(param_1,1,1);
  if (hbm == (HBITMAP)0x0) {
    local_8 = 0;
  }
  else {
    memset(param_2,0,0x28);
    param_2->biSize = 0x28;
    local_8 = GetDIBits(param_1,hbm,0,1,(LPVOID)0x0,(LPBITMAPINFO)param_2,0);
    if (local_8 != 0) {
      local_8 = GetDIBits(param_1,hbm,0,1,(LPVOID)0x0,(LPBITMAPINFO)param_2,0);
    }
    DeleteObject(hbm);
  }
  return local_8;
}



// int __cdecl GetRGBBitsPerPixel(struct HDC__ *,int *,int *,int *)

int __cdecl GetRGBBitsPerPixel(HDC__ *param_1,int *param_2,int *param_3,int *param_4)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  tagBITMAPINFOHEADER *hMem;
  uint local_8;
  
                    // 0x1968  10  ?GetRGBBitsPerPixel@@YAHPAUHDC__@@PAH11@Z
  uVar2 = GetDeviceCaps(param_1,0x26);
  if ((uVar2 & 0x100) == 0) {
    iVar3 = GetDeviceCaps(param_1,0xe);
    iVar4 = GetDeviceCaps(param_1,0xc);
    if (iVar3 * iVar4 == 0x18) {
      *param_4 = 8;
      *param_3 = 8;
      *param_2 = 8;
      local_8 = 1;
    }
    else {
      hMem = (tagBITMAPINFOHEADER *)GlobalAlloc(0x40,0x428);
      if (hMem == (tagBITMAPINFOHEADER *)0x0) {
        local_8 = 0;
      }
      else {
        iVar3 = GetOptimalDIBFormat(param_1,hMem);
        if (iVar3 != 0) {
          bVar1 = CountBits(hMem[1].biSize);
          *param_2 = (uint)bVar1;
          bVar1 = CountBits(hMem[1].biWidth);
          *param_3 = (uint)bVar1;
          bVar1 = CountBits(hMem[1].biHeight);
          *param_4 = (uint)bVar1;
        }
        local_8 = (uint)(iVar3 != 0);
        GlobalFree(hMem);
      }
    }
  }
  else {
    local_8 = 0;
  }
  return local_8;
}



// unsigned char * __cdecl ExtractColorData(char const *,class CRect const &,unsigned int &,unsigned
// long &)

uchar * __cdecl ExtractColorData(char *param_1,CRect *param_2,uint *param_3,ulong *param_4)

{
  bool bVar1;
  short *psVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  uchar *puVar6;
  int iVar7;
  void *_Src;
  int iVar8;
  uint uVar9;
  size_t _Size;
  int local_38;
  int local_34;
  int local_18 [2];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x1a7b  5  ?ExtractColorData@@YAPAEPBDABVCRect@@AAIAAK@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_100030bd;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10002550(local_18,param_1);
  local_8 = 0;
  bVar1 = FUN_10002660(local_18);
  if (bVar1) {
    psVar2 = (short *)FUN_10002650(local_18);
    iVar3 = FUN_10002650(local_18);
    if (*psVar2 == 0x4d42) {
      uVar4 = (int)(uint)*(ushort *)(iVar3 + 0x1c) >> 3;
      uVar9 = *(int *)(iVar3 + 0x12) * uVar4 + uVar4 & ~uVar4;
      iVar8 = *(int *)(iVar3 + 0x16);
      *param_4 = (uint)*(ushort *)(iVar3 + 0x1c);
      local_34 = FUN_10002650(local_18);
      local_34 = local_34 + *(int *)(psVar2 + 5);
      if (*(int *)(iVar3 + 0x2e) != 0) {
        local_34 = local_34 + *(int *)(iVar3 + 0x2e) * 4;
      }
      if (*(int *)(iVar3 + 0x16) < 1) {
        local_8 = 0xffffffff;
        FUN_10002630(local_18);
        puVar6 = (uchar *)0x0;
      }
      else {
        iVar3 = FUN_10001570((int)param_2);
        iVar5 = FUN_10001550((int *)param_2);
        puVar6 = (uchar *)malloc(iVar3 * iVar5 * uVar4);
        for (local_38 = 0; iVar3 = FUN_10001570((int)param_2), local_38 < iVar3;
            local_38 = local_38 + 1) {
          iVar3 = *(int *)(param_2 + 4);
          iVar5 = *(int *)param_2;
          iVar7 = FUN_10001550((int *)param_2);
          _Size = uVar4 * iVar7;
          _Src = (void *)(local_34 +
                         (uVar9 * iVar8 - (iVar3 + 1 + local_38) * uVar9) + uVar4 * iVar5);
          iVar3 = FUN_10001550((int *)param_2);
          memcpy(puVar6 + local_38 * uVar4 * iVar3,_Src,_Size);
        }
        iVar3 = FUN_10001550((int *)param_2);
        iVar8 = FUN_10001570((int)param_2);
        *param_3 = uVar4 * iVar3 * iVar8;
        local_8 = 0xffffffff;
        FUN_10002630(local_18);
      }
    }
    else {
      local_8 = 0xffffffff;
      FUN_10002630(local_18);
      puVar6 = (uchar *)0x0;
    }
  }
  else {
    local_8 = 0xffffffff;
    FUN_10002630(local_18);
    puVar6 = (uchar *)0x0;
  }
  ExceptionList = local_10;
  return puVar6;
}



// unsigned long __cdecl GetInvertedColor(unsigned long)

ulong __cdecl GetInvertedColor(ulong param_1)

{
                    // 0x1cb5  8  ?GetInvertedColor@@YAKK@Z
  return (0xff - (param_1 >> 0x10 & 0xff) & 0xff) << 0x10 |
         0xff - (param_1 & 0xff) & 0xff | (0xffU - ((int)(param_1 & 0xffff) >> 8) & 0xff) << 8;
}



// void __cdecl RotateAndCopy90(struct HDC__ *,class CRect const &,unsigned int,unsigned int)

void __cdecl RotateAndCopy90(HDC__ *param_1,CRect *param_2,uint param_3,uint param_4)

{
  int iVar1;
  COLORREF color;
  int y;
  int local_c;
  int local_8;
  
                    // 0x1d0f  13  ?RotateAndCopy90@@YAXPAUHDC__@@ABVCRect@@II@Z
  local_8 = 0;
  while( true ) {
    iVar1 = FUN_10001570((int)param_2);
    if (iVar1 <= local_8) break;
    local_c = 0;
    while( true ) {
      iVar1 = FUN_10001550((int *)param_2);
      if (iVar1 <= local_c) break;
      color = GetPixel(param_1,*(int *)param_2 + local_c,*(int *)(param_2 + 4) + local_8);
      y = param_4 + local_c;
      iVar1 = FUN_10001550((int *)param_2);
      SetPixelV(param_1,((param_3 - 1) + iVar1) - local_8,y,color);
      local_c = local_c + 1;
    }
    local_8 = local_8 + 1;
  }
  return;
}



void __fastcall FUN_10001db0(undefined4 *param_1)

{
  FUN_10002070(param_1);
  return;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_10001eb0(this,10);
  *(undefined ***)this = &PTR_LAB_100040f8;
  return this;
}



void * __thiscall FUN_10001e00(void *this,int param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100030d9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10001eb0(this,10);
  local_8 = 0;
  *(undefined ***)this = &PTR_LAB_100040f8;
  FUN_10001fd0(this,param_1);
  ExceptionList = local_10;
  return this;
}



void * __thiscall FUN_10001e60(void *this,undefined4 *param_1)

{
  FUN_10002010(this,param_1);
  return this;
}



void * __thiscall FUN_10001e80(void *this,uint param_1)

{
  FUN_10001db0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_100024e0(this);
  }
  return this;
}



void * __thiscall FUN_10001eb0(void *this,undefined4 param_1)

{
  FUN_10002460((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_1000410c;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



undefined4 __fastcall FUN_10001f10(void *param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  puVar1 = *(undefined4 **)((int)param_1 + 4);
  uVar2 = puVar1[2];
  *(undefined4 *)((int)param_1 + 4) = *puVar1;
  if (*(int *)((int)param_1 + 4) == 0) {
    *(undefined4 *)((int)param_1 + 8) = 0;
  }
  else {
    *(undefined4 *)(*(int *)((int)param_1 + 4) + 4) = 0;
  }
  FUN_10002350(param_1,puVar1);
  return uVar2;
}



undefined4 __fastcall FUN_10001f70(void *param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  puVar1 = *(undefined4 **)((int)param_1 + 8);
  uVar2 = puVar1[2];
  *(undefined4 *)((int)param_1 + 8) = puVar1[1];
  if (*(int *)((int)param_1 + 8) == 0) {
    *(undefined4 *)((int)param_1 + 4) = 0;
  }
  else {
    **(undefined4 **)((int)param_1 + 8) = 0;
  }
  FUN_10002350(param_1,puVar1);
  return uVar2;
}



void __thiscall FUN_10001fd0(void *this,int param_1)

{
  undefined4 *puVar1;
  int local_8;
  
  local_8 = FUN_10002220(param_1);
  while (local_8 != 0) {
    puVar1 = (undefined4 *)FUN_10002240(&local_8);
    FUN_10002010(this,puVar1);
  }
  return;
}



undefined4 * __thiscall FUN_10002010(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_10002270(this,*(undefined4 *)((int)this + 8),0);
  puVar1[2] = *param_1;
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



void __fastcall FUN_10002070(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_100030f9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_1000410c;
  local_8 = 0;
  FUN_100021a0((int)param_1);
  local_8 = 0xffffffff;
  FUN_100024b0(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_100020d0(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_10;
  ulong local_c;
  undefined4 *local_8;
  
  FUN_100024d0();
  bVar1 = FUN_10002520((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      FUN_100023a0(param_1,&local_10,1);
      FUN_10002010(this,&local_10);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_100023a0(param_1,local_8 + 2,1);
    }
  }
  return;
}



void * __thiscall FUN_10002170(void *this,uint param_1)

{
  FUN_10002070((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_100024e0(this);
  }
  return this;
}



void __fastcall FUN_100021a0(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_100023e0(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



undefined4 __fastcall FUN_10002220(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



int FUN_10002240(int *param_1)

{
  int *piVar1;
  
  piVar1 = (int *)*param_1;
  *param_1 = *piVar1;
  return (int)(piVar1 + 2);
}



undefined4 * __thiscall FUN_10002270(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0xc);
    iVar3 = FUN_10003010((int)pCVar2);
    local_c = (undefined4 *)(iVar3 + (*(int *)((int)this + 0x18) + -1) * 0xc);
    local_10 = *(int *)((int)this + 0x18);
    while (local_10 = local_10 + -1, -1 < local_10) {
      *local_c = *(undefined4 *)((int)this + 0x10);
      *(undefined4 **)((int)this + 0x10) = local_c;
      local_c = local_c + -3;
    }
  }
  puVar1 = *(undefined4 **)((int)this + 0x10);
  *(undefined4 *)((int)this + 0x10) = **(undefined4 **)((int)this + 0x10);
  puVar1[1] = param_1;
  *puVar1 = param_2;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  FUN_10002410(puVar1 + 2,1);
  return puVar1;
}



void __thiscall FUN_10002350(void *this,undefined4 *param_1)

{
  FUN_100023e0(param_1 + 2,1);
  *param_1 = *(undefined4 *)((int)this + 0x10);
  *(undefined4 **)((int)this + 0x10) = param_1;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + -1;
  if (*(int *)((int)this + 0xc) == 0) {
    FUN_100021a0((int)this);
  }
  return;
}



void FUN_100023a0(CArchive *param_1,void *param_2,int param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_10002520((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    CArchive::Read(param_1,param_2,param_3 << 2);
  }
  else {
    CArchive::Write(param_1,param_2,param_3 << 2);
  }
  return;
}



void FUN_100023e0(undefined4 param_1,int param_2)

{
  bool bVar1;
  
  do {
    bVar1 = param_2 != 0;
    param_2 = param_2 + -1;
  } while (bVar1);
  return;
}



void FUN_10002410(void *param_1,int param_2)

{
  memset(param_1,0,param_2 << 2);
  while (param_2 != 0) {
    FUN_10002540(4,param_1);
    param_1 = (void *)((int)param_1 + 4);
    param_2 = param_2 + -1;
  }
  return;
}



undefined4 * __fastcall FUN_10002460(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_10004120;
  return param_1;
}



void * __thiscall FUN_10002480(void *this,uint param_1)

{
  FUN_100024b0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_100024e0(this);
  }
  return this;
}



void __fastcall FUN_100024b0(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_10004120;
  return;
}



void FUN_100024d0(void)

{
  return;
}



void FUN_100024e0(void *param_1)

{
  operator_delete(param_1);
  return;
}



void FUN_10002500(void)

{
  return;
}



void FUN_10002510(void)

{
  return;
}



bool __fastcall FUN_10002520(int param_1)

{
  return (bool)('\x01' - ((*(uint *)(param_1 + 0x14) & 1) != 0));
}



undefined4 __cdecl FUN_10002540(undefined4 param_1,undefined4 param_2)

{
  return param_2;
}



void * __thiscall FUN_10002550(void *this,LPCSTR param_1)

{
  HANDLE hFile;
  DWORD DVar1;
  HANDLE hFileMappingObject;
  LPVOID pvVar2;
  DWORD local_8;
  
  *(undefined4 *)this = 0;
  *(undefined4 *)((int)this + 4) = 0;
  hFile = CreateFileA(param_1,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    local_8 = 0;
    DVar1 = GetFileSize(hFile,&local_8);
    *(DWORD *)((int)this + 4) = DVar1;
    if (local_8 == 0) {
      if (*(int *)((int)this + 4) != 0) {
        hFileMappingObject = CreateFileMappingA(hFile,(LPSECURITY_ATTRIBUTES)0x0,2,0,0,(LPCSTR)0x0);
        if (hFileMappingObject == (HANDLE)0x0) {
          return this;
        }
        pvVar2 = MapViewOfFile(hFileMappingObject,4,0,0,0);
        *(LPVOID *)this = pvVar2;
        CloseHandle(hFileMappingObject);
      }
      CloseHandle(hFile);
    }
  }
  return this;
}



void __fastcall FUN_10002630(int *param_1)

{
  if (*param_1 != 0) {
    UnmapViewOfFile((LPCVOID)*param_1);
  }
  return;
}



undefined4 __fastcall FUN_10002650(undefined4 *param_1)

{
  return *param_1;
}



bool __fastcall FUN_10002660(int *param_1)

{
  return *param_1 != 0;
}



// void __cdecl TwPrimitives::DrawLine(struct HDC__ *,unsigned int,unsigned int,unsigned
// int,unsigned int,unsigned long)

void __cdecl
TwPrimitives::DrawLine
          (HDC__ *param_1,uint param_2,uint param_3,uint param_4,uint param_5,ulong param_6)

{
  bool bVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int local_38;
  uint local_34;
  int local_2c;
  uint local_28;
  int local_20;
  int local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  int local_8;
  
                    // 0x2680  3  ?DrawLine@TwPrimitives@@YAXPAUHDC__@@IIIIK@Z
  iVar4 = abs(param_4 - param_2);
  local_1c = abs(param_5 - param_3);
  bVar1 = iVar4 < local_1c;
  if (bVar1) {
    local_8 = iVar4 * 2 - local_1c;
    local_38 = iVar4 - local_1c;
    local_2c = iVar4;
  }
  else {
    local_8 = local_1c * 2 - iVar4;
    local_38 = local_1c - iVar4;
    local_2c = local_1c;
    local_1c = iVar4;
  }
  local_1c = local_1c + 1;
  local_2c = local_2c << 1;
  local_38 = local_38 * 2;
  local_c = (uint)!bVar1;
  local_10 = 1;
  local_28 = (uint)bVar1;
  local_34 = 1;
  if (param_4 < param_2) {
    local_c = -local_c;
    local_10 = 0xffffffff;
  }
  if (param_5 < param_3) {
    local_28 = -local_28;
    local_34 = 0xffffffff;
  }
  local_14 = param_2;
  local_18 = param_3;
  for (local_20 = 1; local_20 <= local_1c; local_20 = local_20 + 1) {
    SetPixelV(param_1,local_14,local_18,param_6);
    uVar2 = local_34;
    uVar3 = local_10;
    iVar4 = local_38;
    if (local_8 < 0) {
      uVar2 = local_28;
      uVar3 = local_c;
      iVar4 = local_2c;
    }
    local_8 = local_8 + iVar4;
    local_14 = local_14 + uVar3;
    local_18 = local_18 + uVar2;
  }
  return;
}



// void __cdecl TwPrimitives::DrawRectangle(struct HDC__ *,unsigned int,unsigned int,unsigned
// int,unsigned int,unsigned long)

void __cdecl
TwPrimitives::DrawRectangle
          (HDC__ *param_1,uint param_2,uint param_3,uint param_4,uint param_5,ulong param_6)

{
                    // 0x2845  4  ?DrawRectangle@TwPrimitives@@YAXPAUHDC__@@IIIIK@Z
  DrawLine(param_1,param_2,param_3,param_4,param_3,param_6);
  DrawLine(param_1,param_4,param_3 + 1,param_4,param_5 - 1,param_6);
  DrawLine(param_1,param_4,param_5,param_2,param_5,param_6);
  DrawLine(param_1,param_2,param_5 - 1,param_2,param_3 + 1,param_6);
  return;
}



// void __cdecl TwPrimitives::DrawInvertedRectangle(struct HDC__ *,unsigned int,unsigned
// int,unsigned int,unsigned int)

void __cdecl
TwPrimitives::DrawInvertedRectangle
          (HDC__ *param_1,uint param_2,uint param_3,uint param_4,uint param_5)

{
                    // 0x28d6  2  ?DrawInvertedRectangle@TwPrimitives@@YAXPAUHDC__@@IIII@Z
  DrawInvertedLine(param_1,param_2,param_3,param_4,param_3);
  DrawInvertedLine(param_1,param_4,param_3 + 1,param_4,param_5 - 1);
  DrawInvertedLine(param_1,param_4,param_5,param_2,param_5);
  DrawInvertedLine(param_1,param_2,param_5 - 1,param_2,param_3 + 1);
  return;
}



// void __cdecl TwPrimitives::DrawInvertedLine(struct HDC__ *,unsigned int,unsigned int,unsigned
// int,unsigned int)

void __cdecl
TwPrimitives::DrawInvertedLine(HDC__ *param_1,uint param_2,uint param_3,uint param_4,uint param_5)

{
  bool bVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  COLORREF CVar5;
  ulong color;
  int local_38;
  uint local_34;
  int local_2c;
  uint local_28;
  int local_20;
  int local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  int local_8;
  
                    // 0x2957  1  ?DrawInvertedLine@TwPrimitives@@YAXPAUHDC__@@IIII@Z
  iVar4 = abs(param_4 - param_2);
  local_1c = abs(param_5 - param_3);
  bVar1 = iVar4 < local_1c;
  if (bVar1) {
    local_8 = iVar4 * 2 - local_1c;
    local_38 = iVar4 - local_1c;
    local_2c = iVar4;
  }
  else {
    local_8 = local_1c * 2 - iVar4;
    local_38 = local_1c - iVar4;
    local_2c = local_1c;
    local_1c = iVar4;
  }
  local_1c = local_1c + 1;
  local_2c = local_2c << 1;
  local_38 = local_38 * 2;
  local_c = (uint)!bVar1;
  local_10 = 1;
  local_28 = (uint)bVar1;
  local_34 = 1;
  if (param_4 < param_2) {
    local_c = -local_c;
    local_10 = 0xffffffff;
  }
  if (param_5 < param_3) {
    local_28 = -local_28;
    local_34 = 0xffffffff;
  }
  local_14 = param_2;
  local_18 = param_3;
  for (local_20 = 1; local_20 <= local_1c; local_20 = local_20 + 1) {
    CVar5 = GetPixel(param_1,local_14,local_18);
    color = GetInvertedColor(CVar5);
    SetPixelV(param_1,local_14,local_18,color);
    uVar2 = local_34;
    uVar3 = local_10;
    iVar4 = local_38;
    if (local_8 < 0) {
      uVar2 = local_28;
      uVar3 = local_c;
      iVar4 = local_2c;
    }
    local_8 = local_8 + iVar4;
    local_14 = local_14 + uVar3;
    local_18 = local_18 + uVar2;
  }
  return;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002b44. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



int __thiscall CGdiObject::Attach(CGdiObject *this,void *param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002b4a. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Attach(this,param_1);
  return iVar1;
}



ulong __thiscall CArchive::ReadCount(CArchive *this)

{
  ulong uVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002b56. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = ReadCount(this);
  return uVar1;
}



void __thiscall CArchive::WriteCount(CArchive *this,ulong param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002b5c. Too many branches
                    // WARNING: Treating indirect jump as call
  WriteCount(this,param_1);
  return;
}



void __thiscall CPlex::FreeDataChain(CPlex *this)

{
                    // WARNING: Could not recover jumptable at 0x10002b62. Too many branches
                    // WARNING: Treating indirect jump as call
  FreeDataChain(this);
  return;
}



CPlex * CPlex::Create(CPlex **param_1,uint param_2,uint param_3)

{
  CPlex *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002b68. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = Create(param_1,param_2,param_3);
  return pCVar1;
}



uint __thiscall CArchive::Read(CArchive *this,void *param_1,uint param_2)

{
  uint uVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002b6e. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = Read(this,param_1,param_2);
  return uVar1;
}



void __thiscall CArchive::Write(CArchive *this,void *param_1,uint param_2)

{
                    // WARNING: Could not recover jumptable at 0x10002b74. Too many branches
                    // WARNING: Treating indirect jump as call
  Write(this,param_1,param_2);
  return;
}



void * __thiscall FUN_10002bac(void *this,byte param_1)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)this);
  if ((param_1 & 1) != 0) {
    CNoTrackObject::operator_delete(this);
  }
  return this;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x10002fb0. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



int FUN_10002c27(HINSTANCE__ *param_1,int param_2)

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
      pAVar5 = AfxSetModuleState((AFX_MODULE_STATE *)&this_100050b0);
      p_Var3 = AfxGetThreadState();
      *(AFX_MODULE_STATE **)(p_Var3 + 8) = pAVar5;
      pAVar5 = AfxGetModuleState();
      if (*(int **)(pAVar5 + 4) != (int *)0x0) {
        (**(code **)(**(int **)(pAVar5 + 4) + 0x70))();
      }
      AfxLockTempMaps();
      AfxUnlockTempMaps(-1);
      AfxWinTerm();
      AfxTermExtensionModule((AFX_EXTENSION_MODULE *)&param_1_10006140,1);
    }
    else if (param_2 == 3) {
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
                ((AFX_MAINTAIN_STATE2 *)&local_c,(AFX_MODULE_STATE *)&this_100050b0);
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
  iVar4 = AfxWinInit(param_1,(HINSTANCE__ *)0x0,(char *)&param_3_1000413c,0);
  if (iVar4 != 0) {
    pAVar5 = AfxGetModuleState();
    piVar2 = *(int **)(pAVar5 + 4);
    if ((piVar2 == (int *)0x0) || (iVar4 = (**(code **)(*piVar2 + 0x58))(), iVar4 != 0)) {
      *(undefined4 *)(p_Var3 + 8) = uVar1;
      AfxInitExtensionModule((AFX_EXTENSION_MODULE *)&param_1_10006140,param_1);
      this = (CDynLinkLibrary *)operator_new(0x40);
      if (this != (CDynLinkLibrary *)0x0) {
        CDynLinkLibrary::CDynLinkLibrary(this,(AFX_EXTENSION_MODULE *)&param_1_10006140,0);
      }
      param_2 = 1;
      goto LAB_10002cb3;
    }
    (**(code **)(*piVar2 + 0x70))();
  }
  AfxWinTerm();
LAB_10002cb3:
  *(undefined4 *)(p_Var3 + 8) = uVar1;
  p_Var3 = AfxGetThreadState();
  AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var3 + 8));
  return param_2;
}



undefined4 FUN_10002d4e(undefined4 param_1,int param_2)

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
    pAVar2 = AfxSetModuleState((AFX_MODULE_STATE *)&this_100050b0);
    *(AFX_MODULE_STATE **)(p_Var1 + 8) = pAVar2;
  }
  else if (param_2 == 0) {
    p_Var1 = AfxGetThreadState();
    AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var1 + 8));
  }
  return 1;
}



void __fastcall FUN_10002d9f(undefined4 *param_1)

{
  *(undefined4 *)(param_1[1] + 4) = *param_1;
  return;
}



void __CxxFrameHandler(void)

{
                    // WARNING: Could not recover jumptable at 0x10002da8. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler();
  return;
}



void __cdecl ftol(void)

{
                    // WARNING: Could not recover jumptable at 0x10002db0. Too many branches
                    // WARNING: Treating indirect jump as call
  ftol();
  return;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002db6. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002dbc. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}



int __cdecl abs(int _X)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002dc2. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = abs(_X);
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10002dc8(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 *_Memory;
  undefined4 *puVar2;
  
  if (param_2 == 0) {
    if (0 < DAT_1000615c) {
      DAT_1000615c = DAT_1000615c + -1;
      goto LAB_10002dde;
    }
LAB_10002e06:
    uVar1 = 0;
  }
  else {
LAB_10002dde:
    _DAT_10006160 = *(undefined4 *)_adjust_fdiv_exref;
    if (param_2 == 1) {
      DAT_10006168 = (undefined4 *)malloc(0x80);
      if (DAT_10006168 == (undefined4 *)0x0) goto LAB_10002e06;
      *DAT_10006168 = 0;
      DAT_10006164 = DAT_10006168;
      initterm(&DAT_10005000,&DAT_10005008);
      DAT_1000615c = DAT_1000615c + 1;
    }
    else if ((param_2 == 0) &&
            (_Memory = DAT_10006168, puVar2 = DAT_10006164, DAT_10006168 != (undefined4 *)0x0)) {
      while (puVar2 = puVar2 + -1, _Memory <= puVar2) {
        if ((code *)*puVar2 != (code *)0x0) {
          (*(code *)*puVar2)();
          _Memory = DAT_10006168;
        }
      }
      free(_Memory);
      DAT_10006168 = (undefined4 *)0x0;
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
  iVar2 = DAT_1000615c;
  if (param_2 != 0) {
    if ((param_2 != 1) && (param_2 != 2)) goto LAB_10002ebb;
    if ((PTR_FUN_10005020 != (undefined *)0x0) &&
       (iVar2 = (*(code *)PTR_FUN_10005020)(param_1,param_2,param_3), iVar2 == 0)) {
      return 0;
    }
    iVar2 = FUN_10002dc8(param_1,param_2);
  }
  if (iVar2 == 0) {
    return 0;
  }
LAB_10002ebb:
  iVar2 = FUN_10002c27(param_1,param_2);
  if (param_2 == 1) {
    if (iVar2 != 0) {
      return iVar2;
    }
    FUN_10002dc8(param_1,0);
  }
  if ((param_2 != 0) && (param_2 != 3)) {
    return iVar2;
  }
  iVar3 = FUN_10002dc8(param_1,param_2);
  param_2 = iVar2;
  if (iVar3 == 0) {
    param_2 = 0;
  }
  if (param_2 != 0) {
    if (PTR_FUN_10005020 != (undefined *)0x0) {
      iVar2 = (*(code *)PTR_FUN_10005020)(param_1,iVar1,param_3);
      return iVar2;
    }
    return param_2;
  }
  return 0;
}



void * __thiscall FUN_10002f10(void *this,byte param_1)

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
  
                    // WARNING: Could not recover jumptable at 0x10002f8c. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void __cdecl initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x10002f92. Too many branches
                    // WARNING: Treating indirect jump as call
  initterm();
  return;
}



void __thiscall type_info::~type_info(type_info *this)

{
                    // WARNING: Could not recover jumptable at 0x10002f98. Too many branches
                    // WARNING: Treating indirect jump as call
  ~type_info(this);
  return;
}



void CNoTrackObject::operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002faa. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x10002fb0. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



void __thiscall
AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(AFX_MAINTAIN_STATE2 *this,AFX_MODULE_STATE *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002fbc. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MAINTAIN_STATE2(this,param_1);
  return;
}



void AfxTermThread(HINSTANCE__ *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10002fc2. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermThread(param_1);
  return;
}



void AfxTermExtensionModule(AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10002fc8. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermExtensionModule(param_1,param_2);
  return;
}



int AfxUnlockTempMaps(int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002fce. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxUnlockTempMaps(param_1);
  return iVar1;
}



void AfxLockTempMaps(void)

{
                    // WARNING: Could not recover jumptable at 0x10002fd4. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxLockTempMaps();
  return;
}



AFX_MODULE_STATE * AfxSetModuleState(AFX_MODULE_STATE *param_1)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002fda. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxSetModuleState(param_1);
  return pAVar1;
}



void __thiscall
CDynLinkLibrary::CDynLinkLibrary(CDynLinkLibrary *this,AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10002fe0. Too many branches
                    // WARNING: Treating indirect jump as call
  CDynLinkLibrary(this,param_1,param_2);
  return;
}



int AfxInitExtensionModule(AFX_EXTENSION_MODULE *param_1,HINSTANCE__ *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002fe6. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxInitExtensionModule(param_1,param_2);
  return iVar1;
}



void AfxWinTerm(void)

{
                    // WARNING: Could not recover jumptable at 0x10002fec. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxWinTerm();
  return;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002ff2. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



int AfxWinInit(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10002ff8. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinInit(param_1,param_2,param_3,param_4);
  return iVar1;
}



_AFX_THREAD_STATE * AfxGetThreadState(void)

{
  _AFX_THREAD_STATE *p_Var1;
  
                    // WARNING: Could not recover jumptable at 0x10002ffe. Too many branches
                    // WARNING: Treating indirect jump as call
  p_Var1 = AfxGetThreadState();
  return p_Var1;
}



void AfxCoreInitModule(void)

{
                    // WARNING: Could not recover jumptable at 0x10003004. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxCoreInitModule();
  return;
}



int __fastcall FUN_10003010(int param_1)

{
  return param_1 + 4;
}



void Unwind_10003030(void)

{
  int unaff_EBP;
  
  FUN_10001500((char *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_10003039(void)

{
  int unaff_EBP;
  
  FUN_10001500((char *)(unaff_EBP + -0x14));
  return;
}



void Unwind_10003042(void)

{
  int unaff_EBP;
  
  FUN_10001500((char *)(unaff_EBP + -0x40));
  return;
}



void Unwind_1000304b(void)

{
  int unaff_EBP;
  
  FUN_10001500((char *)(unaff_EBP + -0x48));
  return;
}



void Unwind_10003060(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x34) & 1) != 0) {
    FUN_10001db0(*(undefined4 **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_10003077(void)

{
  int unaff_EBP;
  
  FUN_10001db0((undefined4 *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_1000308a(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x2c) & 1) != 0) {
    FUN_10001db0(*(undefined4 **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_100030a1(void)

{
  int unaff_EBP;
  
  FUN_10001db0((undefined4 *)(unaff_EBP + -0x28));
  return;
}



void Unwind_100030b4(void)

{
  int unaff_EBP;
  
  FUN_10002630((int *)(unaff_EBP + -0x14));
  return;
}



void Unwind_100030d0(void)

{
  int unaff_EBP;
  
  FUN_10002070(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100030f0(void)

{
  int unaff_EBP;
  
  FUN_100024b0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10003104(void)

{
  int unaff_EBP;
  
  FUN_10002d9f((undefined4 *)(unaff_EBP + -0x14));
  return;
}


