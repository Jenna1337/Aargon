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
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
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

typedef ulong DWORD;

typedef DWORD ULONG;

typedef struct _s_CatchableTypeArray _s_CatchableTypeArray, *P_s_CatchableTypeArray;

typedef struct _s_CatchableTypeArray CatchableTypeArray;

typedef struct _s_CatchableType _s_CatchableType, *P_s_CatchableType;

typedef struct _s_CatchableType CatchableType;


// WARNING! conflicting data type names: /ehdata.h/TypeDescriptor - /TypeDescriptor

typedef struct PMD PMD, *PPMD;

typedef void (*PMFN)(void *);

struct PMD {
    ptrdiff_t mdisp;
    ptrdiff_t pdisp;
    ptrdiff_t vdisp;
};

struct _s_CatchableType {
    uint properties;
    struct TypeDescriptor *pType;
    struct PMD thisDisplacement;
    int sizeOrOffset;
    PMFN copyFunction;
};

struct _s_CatchableTypeArray {
    int nCatchableTypes;
    CatchableType *arrayOfCatchableTypes[0];
};

typedef struct _s_ThrowInfo _s_ThrowInfo, *P_s_ThrowInfo;

typedef struct _s_ThrowInfo ThrowInfo;

struct _s_ThrowInfo {
    uint attributes;
    PMFN pmfnUnwind;
    int (*pForwardCompat)(void);
    CatchableTypeArray *pCatchableTypeArray;
};

typedef uint size_t;

typedef struct _GUID _GUID, *P_GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};


// WARNING! conflicting data type names: /guiddef.h/GUID - /GUID

typedef GUID IID;

typedef long HRESULT;

typedef wchar_t WCHAR;

typedef char CHAR;

typedef CHAR *LPCSTR;

typedef CHAR *LPSTR;

typedef void *HANDLE;

typedef WCHAR *LPWSTR;

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

typedef long LONG_PTR;

typedef LONG_PTR LPARAM;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef void *LPVOID;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

typedef struct HRSRC__ HRSRC__, *PHRSRC__;

struct HRSRC__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef struct HTASK__ HTASK__, *PHTASK__;

struct HTASK__ {
    int unused;
};

typedef HANDLE HLOCAL;

typedef struct HTASK__ *HTASK;

typedef LONG_PTR LRESULT;

typedef HANDLE HGLOBAL;

typedef void *LPCVOID;

typedef struct HRSRC__ *HRSRC;

typedef int BOOL;

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

typedef struct _MMCKINFO _MMCKINFO, *P_MMCKINFO;

typedef struct _MMCKINFO MMCKINFO;

typedef DWORD FOURCC;

struct _MMCKINFO {
    FOURCC ckid;
    DWORD cksize;
    FOURCC fccType;
    DWORD dwDataOffset;
    DWORD dwFlags;
};

typedef struct _MMIOINFO _MMIOINFO, *P_MMIOINFO;

typedef struct _MMIOINFO *LPMMIOINFO;

typedef LRESULT (MMIOPROC)(LPSTR, UINT, LPARAM, LPARAM);

typedef MMIOPROC *LPMMIOPROC;

typedef char *HPSTR;

typedef struct HMMIO__ HMMIO__, *PHMMIO__;

typedef struct HMMIO__ *HMMIO;

struct HMMIO__ {
    int unused;
};

struct _MMIOINFO {
    DWORD dwFlags;
    FOURCC fccIOProc;
    LPMMIOPROC pIOProc;
    UINT wErrorRet;
    HTASK htask;
    LONG cchBuffer;
    HPSTR pchBuffer;
    HPSTR pchNext;
    HPSTR pchEndRead;
    HPSTR pchEndWrite;
    LONG lBufOffset;
    LONG lDiskOffset;
    DWORD adwInfo[3];
    DWORD dwReserved1;
    DWORD dwReserved2;
    HMMIO hmmio;
};

typedef UINT MMRESULT;

typedef struct _MMCKINFO *LPMMCKINFO;

typedef struct CRuntimeClass CRuntimeClass, *PCRuntimeClass;

struct CRuntimeClass { // PlaceHolder Structure
};

typedef struct CWave CWave, *PCWave;

struct CWave { // PlaceHolder Structure
};

typedef struct IDirectSound IDirectSound, *PIDirectSound;

struct IDirectSound { // PlaceHolder Structure
};

typedef struct IDirectMusicPerformance IDirectMusicPerformance, *PIDirectMusicPerformance;

struct IDirectMusicPerformance { // PlaceHolder Structure
};

typedef struct AFX_EXTENSION_MODULE AFX_EXTENSION_MODULE, *PAFX_EXTENSION_MODULE;

struct AFX_EXTENSION_MODULE { // PlaceHolder Structure
};

typedef struct AFX_MODULE_STATE AFX_MODULE_STATE, *PAFX_MODULE_STATE;

struct AFX_MODULE_STATE { // PlaceHolder Structure
};

typedef struct CFile CFile, *PCFile;

struct CFile { // PlaceHolder Structure
};

typedef struct CDynLinkLibrary CDynLinkLibrary, *PCDynLinkLibrary;

struct CDynLinkLibrary { // PlaceHolder Structure
};

typedef struct CMidi CMidi, *PCMidi;

struct CMidi { // PlaceHolder Structure
};

typedef struct CArchive CArchive, *PCArchive;

struct CArchive { // PlaceHolder Structure
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

typedef struct CFileException CFileException, *PCFileException;

struct CFileException { // PlaceHolder Structure
};

typedef struct LIST<class_CMidi*> LIST<class_CMidi*>, *PLIST<class_CMidi*>;

struct LIST<class_CMidi*> { // PlaceHolder Structure
};

typedef struct CPlex CPlex, *PCPlex;

struct CPlex { // PlaceHolder Structure
};

typedef struct CObject CObject, *PCObject;

struct CObject { // PlaceHolder Structure
};

typedef struct LIST<class_CString> LIST<class_CString>, *PLIST<class_CString>;

struct LIST<class_CString> { // PlaceHolder Structure
};

typedef struct CString CString, *PCString;

struct CString { // PlaceHolder Structure
};

typedef struct CTypeLibCacheMap CTypeLibCacheMap, *PCTypeLibCacheMap;

struct CTypeLibCacheMap { // PlaceHolder Structure
};

typedef struct STRING STRING, *PSTRING;

struct STRING { // PlaceHolder Structure
};

typedef enum DIRECTION {
} DIRECTION;

typedef int (*_onexit_t)(void);

typedef struct IUnknownVtbl IUnknownVtbl, *PIUnknownVtbl;

typedef struct IUnknown IUnknown, *PIUnknown;

struct IUnknownVtbl {
    HRESULT (*QueryInterface)(struct IUnknown *, IID *, void **);
    ULONG (*AddRef)(struct IUnknown *);
    ULONG (*Release)(struct IUnknown *);
};

struct IUnknown {
    struct IUnknownVtbl *lpVtbl;
};

typedef struct IUnknown *LPUNKNOWN;




// public: __thiscall CMidi::CMidi(void)

CMidi * __thiscall CMidi::CMidi(CMidi *this)

{
  LIST<> *local_24;
  CMidi *local_1c;
  CTypeLibCacheMap *local_18;
  LIST<> *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x1000  2  ??0CMidi@@QAE@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_10004db6;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *this = (CMidi)0x0;
  this[1] = (CMidi)0x0;
  *(undefined4 *)(this + 4) = 0xffffffff;
  *(undefined4 *)(this + 8) = 0xffffffff;
  *(undefined4 *)(this + 0xc) = 0xffffffff;
  CString::CString((CString *)(this + 0x10));
  local_8 = 0;
  *(undefined4 *)(this + 0x14) = 0;
  *(undefined4 *)(this + 0x18) = 0;
  *(undefined4 *)(this + 0x1c) = 0;
  if (plstAllSounds == (LIST<> *)0x0) {
    local_18 = (CTypeLibCacheMap *)FUN_10002890(0x1c);
    local_8._0_1_ = 1;
    if (local_18 == (CTypeLibCacheMap *)0x0) {
      local_24 = (LIST<> *)0x0;
    }
    else {
      local_24 = (LIST<> *)CTypeLibCacheMap::CTypeLibCacheMap(local_18);
    }
    local_14 = local_24;
    local_8 = (uint)local_8._1_3_ << 8;
    plstAllSounds = local_24;
  }
  local_1c = this;
  FUN_100021d0(plstAllSounds,&local_1c);
  ExceptionList = local_10;
  return this;
}



// public: __thiscall CMidi::~CMidi(void)

void __thiscall CMidi::~CMidi(CMidi *this)

{
  bool bVar1;
  undefined3 extraout_var;
  CMidi *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x10e9  7  ??1CMidi@@QAE@XZ
  puStack_c = &LAB_10004dcc;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  local_14 = this;
  FUN_100021f0(plstAllSounds,(int *)&local_14);
  bVar1 = IsEmpty((int)plstAllSounds);
  if ((CONCAT31(extraout_var,bVar1) != 0) && (plstAllSounds != (LIST<> *)0x0)) {
    (**(code **)(*(int *)plstAllSounds + 4))(1);
  }
  local_8 = 0xffffffff;
  CString::~CString((CString *)(this + 0x10));
  ExceptionList = local_10;
  return;
}



// public: int __thiscall CMidi::Init(void)

int __thiscall CMidi::Init(CMidi *this)

{
  undefined1 *puVar1;
  int iVar2;
  HRESULT HVar3;
  HWND__ *pHVar4;
  CWave *this_00;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  CWave local_60 [64];
  undefined4 local_20;
  int local_1c;
  undefined4 local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x1180  25  ?Init@CMidi@@QAEHXZ
  puStack_c = &LAB_10004ddf;
  local_10 = ExceptionList;
  local_14 = &stack0xffffff6c;
  if (m_bEnabled == 0) {
    iVar2 = 0;
  }
  else if (*(int *)(this + 0x1c) == 0) {
    local_18 = 1;
    local_8 = 0;
    ExceptionList = &local_10;
    puVar1 = &stack0xffffff6c;
    if (ppv_1000711c != (IDirectMusicPerformance *)0x0) {
LAB_100012f6:
      local_14 = puVar1;
      m_pPerformanceRefCount = m_pPerformanceRefCount + 1;
      HVar3 = CoCreateInstance((IID *)&rclsid_1000528c,(LPUNKNOWN)0x0,3,(IID *)&riid_1000522c,
                               (LPVOID *)(this + 0x14));
      if (-1 < HVar3) {
        *(undefined4 *)(this + 0x1c) = 1;
        SetVolume(this,m_dwDefaultVolume);
        iVar2 = FUN_10001360();
        return iVar2;
      }
      local_6c = 0;
                    // WARNING: Subroutine does not return
      _CxxThrowException(&local_6c,(ThrowInfo *)&pThrowInfo_10005518);
    }
    ExceptionList = &local_10;
    HVar3 = CoCreateInstance((IID *)&rclsid_100052ac,(LPUNKNOWN)0x0,3,(IID *)&riid_1000520c,
                             &ppv_1000711c);
    if (HVar3 < 0) {
      local_20 = 0;
                    // WARNING: Subroutine does not return
      _CxxThrowException(&local_20,(ThrowInfo *)&pThrowInfo_10005518);
    }
    pHVar4 = CWave::GetHWND();
    if (pHVar4 == (HWND__ *)0x0) {
      iVar2 = 0;
    }
    else {
      if (CWave::m_pDirectSound != (IDirectSound *)0x0) {
        this_00 = (CWave *)CWave::CWave(local_60);
        local_8._0_1_ = 1;
        CWave::SetCooperativeLevel(this_00);
        local_8 = (uint)local_8._1_3_ << 8;
        CWave::~CWave(local_60);
        pHVar4 = CWave::GetHWND();
        local_1c = (**(code **)(*(int *)ppv_1000711c + 0xc))
                             (ppv_1000711c,0,CWave::m_pDirectSound,pHVar4);
        if (local_1c < 0) {
          local_64 = 0;
                    // WARNING: Subroutine does not return
          _CxxThrowException(&local_64,(ThrowInfo *)&pThrowInfo_10005518);
        }
        local_1c = (**(code **)(*(int *)ppv_1000711c + 0x60))(ppv_1000711c,0);
        puVar1 = local_14;
        if (local_1c < 0) {
          local_68 = 0;
                    // WARNING: Subroutine does not return
          _CxxThrowException(&local_68,(ThrowInfo *)&pThrowInfo_10005518);
        }
        goto LAB_100012f6;
      }
      iVar2 = 0;
    }
  }
  else {
    iVar2 = 1;
  }
  ExceptionList = local_10;
  return iVar2;
}



undefined * Catch_10001353(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -0x14) = 0;
  return FUN_10001360;
}



undefined4 FUN_10001360(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return *(undefined4 *)(unaff_EBP + -0x14);
}



// public: int __thiscall CMidi::LoadSong(char const *)

int __thiscall CMidi::LoadSong(CMidi *this,char *param_1)

{
  char cVar1;
  int iVar2;
  CString *pCVar3;
  char *pcVar4;
  undefined4 local_9a8;
  undefined4 local_9a4;
  undefined4 local_9a0;
  undefined4 local_99c;
  CString local_998 [4];
  CString local_994 [4];
  char local_990 [260];
  CString local_88c [4];
  undefined4 local_888;
  undefined4 local_884;
  undefined4 local_870;
  undefined4 local_86c;
  undefined4 local_868;
  undefined4 local_864;
  wchar_t local_750 [268];
  int local_538;
  WCHAR local_534 [260];
  undefined4 local_32c;
  char local_328 [260];
  WCHAR local_224 [260];
  char local_1c [4];
  CString local_18 [4];
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x137b  31  ?LoadSong@CMidi@@QAEHPBD@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_10004e1f;
  local_10 = ExceptionList;
  local_14 = &stack0xfffff624;
  if (param_1 == (char *)0x0) {
    iVar2 = 0;
  }
  else {
    ExceptionList = &local_10;
    CString::operator=((CString *)(this + 0x10),param_1);
    if (((m_bEnabled == 0) || (*(int *)(this + 0x1c) == 0)) || (*(int *)(this + 0x18) != 0)) {
      iVar2 = 1;
    }
    else {
      if (*(int *)(this + 0x18) == 0) {
        local_32c = 1;
        CString::CString(local_88c,param_1);
        local_8 = 0;
        CString::TrimLeft(local_88c);
        cVar1 = FUN_10002910(local_88c,1);
        if (cVar1 == ':') {
          pCVar3 = (CString *)CString::Left(local_88c,(int)local_994);
          local_8._0_1_ = 1;
          CString::operator=(local_88c,pCVar3);
          local_8 = (uint)local_8._1_3_ << 8;
          CString::~CString(local_994);
        }
        else {
          CString::operator=(local_88c,(char *)&this_10007124);
        }
        ExtractDirectory((char *)local_18);
        local_8._0_1_ = 2;
        ExtractFileName(local_1c);
        local_8._0_1_ = 3;
        pCVar3 = (CString *)operator+(local_998,local_88c);
        local_8._0_1_ = 4;
        CString::operator=(local_18,pCVar3);
        local_8._0_1_ = 3;
        CString::~CString(local_998);
        pcVar4 = (char *)FUN_10002900((undefined4 *)local_18);
        strcpy(local_990,pcVar4);
        pcVar4 = (char *)FUN_10002900((undefined4 *)local_1c);
        strcpy(local_328,pcVar4);
        MultiByteToWideChar(0,1,local_990,-1,local_224,0x104);
        MultiByteToWideChar(0,1,local_328,-1,local_534,0x104);
        local_8 = CONCAT31(local_8._1_3_,5);
        local_538 = (**(code **)(**(int **)(this + 0x14) + 0x14))
                              (*(undefined4 *)(this + 0x14),&DAT_1000527c,local_224,0);
        if (local_538 < 0) {
          local_99c = 0;
                    // WARNING: Subroutine does not return
          _CxxThrowException(&local_99c,(ThrowInfo *)&pThrowInfo_10005518);
        }
        memset(&local_888,0,0x350);
        local_888 = 0x350;
        local_870 = 0xd2ac2882;
        local_86c = 0x11d1b39b;
        local_868 = 0x60000487;
        local_864 = 0xbdb19308;
        wcscpy(local_750,local_534);
        local_884 = 0x12;
        local_538 = (**(code **)(**(int **)(this + 0x14) + 0xc))
                              (*(undefined4 *)(this + 0x14),&local_888,&DAT_1000521c,this + 0x18);
        if (local_538 < 0) {
          local_9a0 = 0;
                    // WARNING: Subroutine does not return
          _CxxThrowException(&local_9a0,(ThrowInfo *)&pThrowInfo_10005518);
        }
        local_538 = (**(code **)(**(int **)(this + 0x18) + 0x4c))
                              (*(undefined4 *)(this + 0x18),&DAT_1000524c,0xffffffff,0,0,
                               ppv_1000711c);
        if (-1 < local_538) {
          local_538 = (**(code **)(**(int **)(this + 0x18) + 0x4c))
                                (*(undefined4 *)(this + 0x18),&DAT_1000526c,0xffffffff,0,0,
                                 ppv_1000711c);
          if (-1 < local_538) {
            iVar2 = FUN_1000178e();
            return iVar2;
          }
          local_9a8 = 0;
                    // WARNING: Subroutine does not return
          _CxxThrowException(&local_9a8,(ThrowInfo *)&pThrowInfo_10005518);
        }
        local_9a4 = 0;
                    // WARNING: Subroutine does not return
        _CxxThrowException(&local_9a4,(ThrowInfo *)&pThrowInfo_10005518);
      }
      iVar2 = 0;
    }
  }
  ExceptionList = local_10;
  return iVar2;
}



undefined * Catch_1000177e(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -0x328) = 0;
  return FUN_1000178e;
}



undefined4 FUN_1000178e(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -4) = 3;
  *(undefined4 *)(unaff_EBP + -0x9a8) = *(undefined4 *)(unaff_EBP + -0x328);
  *(undefined1 *)(unaff_EBP + -4) = 2;
  CString::~CString((CString *)(unaff_EBP + -0x18));
  *(undefined1 *)(unaff_EBP + -4) = 0;
  CString::~CString((CString *)(unaff_EBP + -0x14));
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  CString::~CString((CString *)(unaff_EBP + -0x888));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return *(undefined4 *)(unaff_EBP + -0x9a8);
}



// public: int __thiscall CMidi::ReadyThisObjectForPlay(void)

int __thiscall CMidi::ReadyThisObjectForPlay(CMidi *this)

{
  bool bVar1;
  undefined3 extraout_var;
  uint uVar2;
  undefined3 extraout_var_00;
  undefined4 *puVar3;
  undefined3 extraout_var_01;
  char *pcVar4;
  int iVar5;
  CMidi *local_10;
  uint local_c;
  int local_8;
  
                    // 0x17e4  37  ?ReadyThisObjectForPlay@CMidi@@QAEHXZ
  bVar1 = FUN_100028c0((int *)(this + 0x10));
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_8 = FUN_10002390((int)plstAllSounds);
    local_10 = (CMidi *)0x0;
    bVar1 = IsEmpty((int)plstAllSounds);
    if (CONCAT31(extraout_var_00,bVar1) == 0) {
      puVar3 = (undefined4 *)FUN_10004270(&local_8);
      local_10 = (CMidi *)*puVar3;
    }
    local_c = 0;
    while ((uVar2 = FUN_100022f0((int)plstAllSounds), local_c < uVar2 &&
           (bVar1 = IsEmpty((int)plstAllSounds), CONCAT31(extraout_var_01,bVar1) == 0))) {
      Stop(local_10);
      UnInit(local_10);
      local_c = local_c + 1;
      uVar2 = FUN_100022f0((int)plstAllSounds);
      if (local_c < uVar2) {
        puVar3 = (undefined4 *)FUN_10004270(&local_8);
        local_10 = (CMidi *)*puVar3;
      }
    }
    Init(this);
    pcVar4 = (char *)FUN_10002900((undefined4 *)(this + 0x10));
    iVar5 = LoadSong(this,pcVar4);
    this[1] = (CMidi)(iVar5 != 0);
    uVar2 = (uint)(byte)this[1];
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



// public: int __thiscall CMidi::Play(int,unsigned long,unsigned int,unsigned int)

int __thiscall CMidi::Play(CMidi *this,int param_1,ulong param_2,uint param_3,uint param_4)

{
  bool bVar1;
  int iVar2;
  undefined3 extraout_var;
  undefined4 *puVar3;
  uint uVar4;
  undefined3 extraout_var_00;
  char *pcVar5;
  undefined4 local_2c;
  uint local_28;
  undefined4 local_24;
  uint local_20;
  int local_1c;
  undefined4 local_18;
  CMidi *local_14;
  uint local_10;
  int local_c;
  int local_8;
  
                    // 0x18f3  35  ?Play@CMidi@@QAEHHKII@Z
  if (param_4 % 4 == 0) {
    if (param_1 == -1) {
      iVar2 = 0;
    }
    else if (param_3 == 0xffffffff) {
      iVar2 = 0;
    }
    else if (param_4 == 0xffffffff) {
      iVar2 = 0;
    }
    else {
      bVar1 = FUN_10002520((char *)(this + 1),'\0');
      if (!bVar1) {
        local_c = FUN_10002390((int)plstAllSounds);
        local_14 = (CMidi *)0x0;
        local_10 = 0;
        bVar1 = IsEmpty((int)plstAllSounds);
        if (CONCAT31(extraout_var,bVar1) == 0) {
          puVar3 = (undefined4 *)FUN_10004270(&local_c);
          local_14 = (CMidi *)*puVar3;
        }
        local_10 = 0;
        while ((uVar4 = FUN_100022f0((int)plstAllSounds), local_10 < uVar4 &&
               (bVar1 = IsEmpty((int)plstAllSounds), CONCAT31(extraout_var_00,bVar1) == 0))) {
          if (local_14[1] == (CMidi)0x0) {
            Stop(local_14);
            UnInit(local_14);
          }
          local_10 = local_10 + 1;
          uVar4 = FUN_100022f0((int)plstAllSounds);
          if (local_10 < uVar4) {
            puVar3 = (undefined4 *)FUN_10004270(&local_c);
            local_14 = (CMidi *)*puVar3;
          }
        }
        Init(this);
        pcVar5 = (char *)FUN_10002900((undefined4 *)(this + 0x10));
        LoadSong(this,pcVar5);
      }
      *(int *)(this + 4) = param_1;
      *(uint *)(this + 8) = param_3;
      *(uint *)(this + 0xc) = param_4;
      if (m_bEnabled == 0) {
        iVar2 = 0;
      }
      else if (*(int *)(this + 0x1c) == 0) {
        iVar2 = 0;
      }
      else if (m_bEnabled == 0) {
        iVar2 = 0;
      }
      else if (*(int *)(this + 0x18) == 0) {
        iVar2 = 0;
      }
      else {
        local_8 = (**(code **)(**(int **)(this + 0x18) + 0x54))
                            (*(undefined4 *)(this + 0x18),param_3 * 0x300);
        if (local_8 < 0) {
          iVar2 = 0;
        }
        else {
          if (param_1 != 0) {
            local_8 = (**(code **)(**(int **)(this + 0x18) + 0x18))
                                (*(undefined4 *)(this + 0x18),0xffffffff);
            if (local_8 < 0) {
              return 0;
            }
            if (param_4 != 0) {
              local_18 = 0;
              local_8 = (**(code **)(**(int **)(this + 0x18) + 0xc))
                                  (*(undefined4 *)(this + 0x18),&local_18);
              if (local_8 < 0) {
                return 0;
              }
              local_8 = (**(code **)(**(int **)(this + 0x18) + 0x5c))
                                  (*(undefined4 *)(this + 0x18),param_4 * 0x300,local_18);
              if (local_8 < 0) {
                return 0;
              }
            }
          }
          if (param_2 == 0) {
            local_2c = 0;
            local_8 = (**(code **)(*(int *)ppv_1000711c + 0x3c))(ppv_1000711c,0,&local_2c);
            if (local_8 < 0) {
              return 0;
            }
            local_8 = (**(code **)(*(int *)ppv_1000711c + 0x78))(ppv_1000711c,local_2c,0);
            if (local_8 < 0) {
              return 0;
            }
            local_8 = (**(code **)(*(int *)ppv_1000711c + 0x10))
                                (ppv_1000711c,*(undefined4 *)(this + 0x18),0,0,0,0);
          }
          else {
            local_20 = 0;
            local_1c = 0;
            local_8 = (**(code **)(*(int *)ppv_1000711c + 0x3c))(ppv_1000711c,&local_20,0);
            local_28 = param_2 * 10000;
            local_24 = 0;
            bVar1 = CARRY4(local_20,local_28);
            local_20 = local_20 + local_28;
            local_1c = local_1c + (uint)bVar1;
            local_8 = (**(code **)(*(int *)ppv_1000711c + 0x10))
                                (ppv_1000711c,*(undefined4 *)(this + 0x18),0x40,local_20,local_1c,0)
            ;
          }
          if (local_8 < 0) {
            iVar2 = 0;
          }
          else {
            iVar2 = 1;
          }
        }
      }
    }
  }
  else {
    iVar2 = 0;
  }
  return iVar2;
}



// public: void __thiscall CMidi::UnInit(void)

void __thiscall CMidi::UnInit(CMidi *this)

{
                    // 0x1c8f  48  ?UnInit@CMidi@@QAEXXZ
  if (*(int *)(this + 0x1c) != 0) {
    if (*(int *)(this + 0x18) != 0) {
      (**(code **)(**(int **)(this + 0x18) + 0x4c))
                (*(undefined4 *)(this + 0x18),&DAT_1000525c,0xffffffff,0,0,ppv_1000711c);
      (**(code **)(**(int **)(this + 0x18) + 8))(*(undefined4 *)(this + 0x18));
      *(undefined4 *)(this + 0x18) = 0;
    }
    if (*(int *)(this + 0x14) != 0) {
      (**(code **)(**(int **)(this + 0x14) + 8))(*(undefined4 *)(this + 0x14));
      *(undefined4 *)(this + 0x14) = 0;
    }
    m_pPerformanceRefCount = m_pPerformanceRefCount - 1;
    if ((ppv_1000711c != (IDirectMusicPerformance *)0x0) && (m_pPerformanceRefCount == 0)) {
      (**(code **)(*(int *)ppv_1000711c + 0x98))(ppv_1000711c);
      (**(code **)(*(int *)ppv_1000711c + 8))(ppv_1000711c);
      ppv_1000711c = (IDirectMusicPerformance *)0x0;
    }
    *(undefined4 *)(this + 0x1c) = 0;
    this[1] = (CMidi)0x0;
  }
  return;
}



// public: int __thiscall CMidi::Stop(void)

int __thiscall CMidi::Stop(CMidi *this)

{
  int iVar1;
  int local_8;
  
                    // 0x1d75  45  ?Stop@CMidi@@QAEHXZ
  if (*this == (CMidi)0x0) {
    *(undefined4 *)(this + 4) = 1;
    *(undefined4 *)(this + 8) = 0xffffffff;
    *(undefined4 *)(this + 0xc) = 0xffffffff;
  }
  if (m_bEnabled == 0) {
    local_8 = 0;
  }
  else if (*(int *)(this + 0x1c) == 0) {
    local_8 = 0;
  }
  else {
    local_8 = 0;
    if ((((*(int *)(this + 0x18) != 0) && (ppv_1000711c != (IDirectMusicPerformance *)0x0)) &&
        (iVar1 = (**(code **)(**(int **)(this + 0x18) + 0x18))(*(undefined4 *)(this + 0x18),0),
        -1 < iVar1)) &&
       (iVar1 = (**(code **)(*(int *)ppv_1000711c + 0x14))
                          (ppv_1000711c,*(undefined4 *)(this + 0x18),0,0,0), -1 < iVar1)) {
      local_8 = 1;
    }
  }
  return local_8;
}



// public: static void __cdecl CMidi::StopAll(void)

void __cdecl CMidi::StopAll(void)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 *puVar2;
  uint uVar3;
  undefined3 extraout_var_00;
  CMidi *local_10;
  uint local_c;
  int local_8;
  
                    // 0x1e2c  47  ?StopAll@CMidi@@SAXXZ
  local_8 = FUN_10002390((int)plstAllSounds);
  local_10 = (CMidi *)0x0;
  bVar1 = IsEmpty((int)plstAllSounds);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar2 = (undefined4 *)FUN_10004270(&local_8);
    local_10 = (CMidi *)*puVar2;
  }
  local_c = 0;
  while ((uVar3 = FUN_100022f0((int)plstAllSounds), local_c < uVar3 &&
         (bVar1 = IsEmpty((int)plstAllSounds), CONCAT31(extraout_var_00,bVar1) == 0))) {
    if (*(int *)(local_10 + 0x1c) != 0) {
      Stop(local_10);
    }
    local_c = local_c + 1;
    uVar3 = FUN_100022f0((int)plstAllSounds);
    if (local_c < uVar3) {
      puVar2 = (undefined4 *)FUN_10004270(&local_8);
      local_10 = (CMidi *)*puVar2;
    }
  }
  return;
}



// public: static void __cdecl CMidi::PauseAll(bool)

void __cdecl CMidi::PauseAll(bool param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 *puVar2;
  uint uVar3;
  undefined3 extraout_var_00;
  CMidi *local_10;
  uint local_c;
  int local_8;
  
                    // 0x1eeb  34  ?PauseAll@CMidi@@SAX_N@Z
  local_8 = FUN_10002390((int)plstAllSounds);
  local_10 = (CMidi *)0x0;
  bVar1 = IsEmpty((int)plstAllSounds);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar2 = (undefined4 *)FUN_10004270(&local_8);
    local_10 = (CMidi *)*puVar2;
  }
  local_c = 0;
  while ((uVar3 = FUN_100022f0((int)plstAllSounds), local_c < uVar3 &&
         (bVar1 = IsEmpty((int)plstAllSounds), CONCAT31(extraout_var_00,bVar1) == 0))) {
    if (*(int *)(local_10 + 0x1c) != 0) {
      if (param_1) {
        Pause(local_10);
      }
      else {
        Continue(local_10);
      }
    }
    local_c = local_c + 1;
    uVar3 = FUN_100022f0((int)plstAllSounds);
    if (local_c < uVar3) {
      puVar2 = (undefined4 *)FUN_10004270(&local_8);
      local_10 = (CMidi *)*puVar2;
    }
  }
  return;
}



// public: int __thiscall CMidi::Pause(void)

int __thiscall CMidi::Pause(CMidi *this)

{
  int iVar1;
  
                    // 0x1fc4  32  ?Pause@CMidi@@QAEHXZ
  if (m_bEnabled == 0) {
    iVar1 = 0;
  }
  else if (*(int *)(this + 8) == -1) {
    iVar1 = 0;
  }
  else {
    *this = (CMidi)0x1;
    iVar1 = Stop(this);
  }
  return iVar1;
}



// public: int __thiscall CMidi::Continue(void)

int __thiscall CMidi::Continue(CMidi *this)

{
  bool bVar1;
  int iVar2;
  
                    // 0x1ff7  14  ?Continue@CMidi@@QAEHXZ
  bVar1 = FUN_10002520((char *)this,'\0');
  if (bVar1) {
    if (m_bEnabled == 0) {
      iVar2 = 0;
    }
    else if (*(int *)(this + 4) == 0) {
      iVar2 = 0;
    }
    else {
      iVar2 = Play(this,*(int *)(this + 4),0,*(uint *)(this + 8),*(uint *)(this + 0xc));
    }
  }
  else {
    iVar2 = 0;
  }
  return iVar2;
}



// public: unsigned long __thiscall CMidi::GetVolume(void)

ulong __thiscall CMidi::GetVolume(CMidi *this)

{
  ulong uVar1;
  int local_8;
  
                    // 0x2056  24  ?GetVolume@CMidi@@QAEKXZ
  if (m_bEnabled == 0) {
    uVar1 = 0;
  }
  else if (*(int *)(this + 0x1c) == 0) {
    uVar1 = 0;
  }
  else {
    local_8 = 0;
    (**(code **)(*(int *)ppv_1000711c + 0x84))(ppv_1000711c,&DAT_1000523c,&local_8,4);
    local_8 = local_8 + 2000;
    uVar1 = ftol();
  }
  return uVar1;
}



// public: static void __cdecl CMidi::SetDefaultVolume(unsigned long)

void __cdecl CMidi::SetDefaultVolume(ulong param_1)

{
                    // 0x20c8  41  ?SetDefaultVolume@CMidi@@SAXK@Z
  if (m_bEnabled != 0) {
    m_dwDefaultVolume = param_1;
  }
  return;
}



// public: int __thiscall CMidi::SetVolume(unsigned long)

int __thiscall CMidi::SetVolume(CMidi *this,ulong param_1)

{
  int iVar1;
  int local_10 [2];
  int local_8;
  
                    // 0x20e0  43  ?SetVolume@CMidi@@QAEHK@Z
  if (m_bEnabled == 0) {
    local_8 = 0;
  }
  else {
    local_8 = 0;
    if (*(int *)(this + 0x1c) == 0) {
      local_8 = 0;
    }
    else {
      local_10[0] = 0x9c4;
      local_10[0] = ftol(param_1,0);
      local_10[0] = local_10[0] + -2000;
      iVar1 = (**(code **)(*(int *)ppv_1000711c + 0x88))(ppv_1000711c,&DAT_1000523c,local_10,4);
      if (-1 < iVar1) {
        local_8 = 1;
      }
    }
  }
  return local_8;
}



// public: static void __cdecl CMidi::Disable(void)

void __cdecl CMidi::Disable(void)

{
                    // 0x2181  17  ?Disable@CMidi@@SAXXZ
  m_bEnabled = 0;
  return;
}



// public: static void __cdecl CMidi::Enable(void)

void __cdecl CMidi::Enable(void)

{
                    // 0x2190  18  ?Enable@CMidi@@SAXXZ
  m_bEnabled = 1;
  return;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_10002290(this,10);
  *(undefined ***)this = &PTR_LAB_10005190;
  return this;
}



void * __thiscall FUN_100021d0(void *this,undefined4 *param_1)

{
  FUN_10002330(this,param_1);
  return this;
}



void __thiscall FUN_100021f0(void *this,int *param_1)

{
  int *piVar1;
  int *piVar2;
  int *local_8;
  
  local_8 = (int *)FUN_10002390((int)this);
  while (piVar1 = local_8, local_8 != (int *)0x0) {
    piVar2 = (int *)FUN_10004270((int *)&local_8);
    if (*piVar2 == *param_1) {
      FUN_100023b0(this,piVar1);
    }
  }
  return;
}



void * __thiscall FUN_10002240(void *this,uint param_1)

{
  FUN_10002270((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10002870(this);
  }
  return this;
}



void __fastcall FUN_10002270(undefined4 *param_1)

{
  FUN_10002420(param_1);
  return;
}



void * __thiscall FUN_10002290(void *this,undefined4 param_1)

{
  FUN_100027f0((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_100051a4;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



undefined4 __fastcall FUN_100022f0(int param_1)

{
  return *(undefined4 *)(param_1 + 0xc);
}



// Library Function - Multiple Matches With Same Base Name
//  public: int __thiscall CList<unsigned int,unsigned int>::IsEmpty(void)const 
//  public: int __thiscall CList<unsigned long,unsigned long>::IsEmpty(void)const 
//  public: int __thiscall CList<class CMFCButton *,class CMFCButton *>::IsEmpty(void)const 
//  public: int __thiscall CList<class CMFCPropertyGridProperty *,class CMFCPropertyGridProperty
// *>::IsEmpty(void)const 
//   24 names - too many to list
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

bool __fastcall IsEmpty(int param_1)

{
  return *(int *)(param_1 + 0xc) == 0;
}



undefined4 * __thiscall FUN_10002330(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_10002600(this,*(undefined4 *)((int)this + 8),0);
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



undefined4 __fastcall FUN_10002390(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



void __thiscall FUN_100023b0(void *this,int *param_1)

{
  if (param_1 == *(int **)((int)this + 4)) {
    *(int *)((int)this + 4) = *param_1;
  }
  else {
    *(int *)param_1[1] = *param_1;
  }
  if (param_1 == *(int **)((int)this + 8)) {
    *(int *)((int)this + 8) = param_1[1];
  }
  else {
    *(int *)(*param_1 + 4) = param_1[1];
  }
  FUN_100026e0(this,param_1);
  return;
}



void __fastcall FUN_10002420(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_10004e39;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_100051a4;
  local_8 = 0;
  FUN_10002580((int)param_1);
  local_8 = 0xffffffff;
  FUN_10002840(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_10002480(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_10;
  ulong local_c;
  undefined4 *local_8;
  
  FUN_10002860();
  bVar1 = FUN_10002930((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      FUN_10002730(param_1,&local_10,1);
      FUN_10002330(this,&local_10);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_10002730(param_1,local_8 + 2,1);
    }
  }
  return;
}



bool __cdecl FUN_10002520(char *param_1,char param_2)

{
  char cVar1;
  
  cVar1 = *param_1;
  *param_1 = param_2;
  return cVar1 != param_2;
}



void * __thiscall FUN_10002550(void *this,uint param_1)

{
  FUN_10002420((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10002870(this);
  }
  return this;
}



void __fastcall FUN_10002580(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_10002770(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



undefined4 * __thiscall FUN_10002600(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0xc);
    iVar3 = FUN_10004d80((int)pCVar2);
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
  FUN_100027a0(puVar1 + 2,1);
  return puVar1;
}



void __thiscall FUN_100026e0(void *this,undefined4 *param_1)

{
  FUN_10002770(param_1 + 2,1);
  *param_1 = *(undefined4 *)((int)this + 0x10);
  *(undefined4 **)((int)this + 0x10) = param_1;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + -1;
  if (*(int *)((int)this + 0xc) == 0) {
    FUN_10002580((int)this);
  }
  return;
}



void FUN_10002730(CArchive *param_1,void *param_2,int param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_10002930((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    CArchive::Read(param_1,param_2,param_3 << 2);
  }
  else {
    CArchive::Write(param_1,param_2,param_3 << 2);
  }
  return;
}



void FUN_10002770(undefined4 param_1,int param_2)

{
  bool bVar1;
  
  do {
    bVar1 = param_2 != 0;
    param_2 = param_2 + -1;
  } while (bVar1);
  return;
}



void FUN_100027a0(void *param_1,int param_2)

{
  memset(param_1,0,param_2 << 2);
  while (param_2 != 0) {
    FUN_10002950(4,param_1);
    param_1 = (void *)((int)param_1 + 4);
    param_2 = param_2 + -1;
  }
  return;
}



undefined4 * __fastcall FUN_100027f0(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_100051b8;
  return param_1;
}



void * __thiscall FUN_10002810(void *this,uint param_1)

{
  FUN_10002840((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10002870(this);
  }
  return this;
}



void __fastcall FUN_10002840(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_100051b8;
  return;
}



void FUN_10002860(void)

{
  return;
}



void FUN_10002870(void *param_1)

{
  operator_delete(param_1);
  return;
}



void FUN_10002890(uint param_1)

{
  operator_new(param_1);
  return;
}



void FUN_100028b0(void)

{
  return;
}



bool __fastcall FUN_100028c0(int *param_1)

{
  int iVar1;
  
  iVar1 = FUN_100028e0(param_1);
  return *(int *)(iVar1 + 4) == 0;
}



int __fastcall FUN_100028e0(int *param_1)

{
  return *param_1 + -0xc;
}



undefined4 __fastcall FUN_10002900(undefined4 *param_1)

{
  return *param_1;
}



undefined1 __thiscall FUN_10002910(void *this,int param_1)

{
                    // WARNING: Load size is inaccurate
  return *(undefined1 *)(*this + param_1);
}



bool __fastcall FUN_10002930(int param_1)

{
  return (bool)('\x01' - ((*(uint *)(param_1 + 0x14) & 1) != 0));
}



undefined4 __cdecl FUN_10002950(undefined4 param_1,undefined4 param_2)

{
  return param_2;
}



// public: static void __cdecl CWave::Enable(bool)

void __cdecl CWave::Enable(bool param_1)

{
                    // 0x2960  19  ?Enable@CWave@@SAX_N@Z
  m_bEnableSound = param_1;
  return;
}



// protected: int __thiscall CWave::IsValid(void)const 

int __thiscall CWave::IsValid(CWave *this)

{
                    // 0x2970  28  ?IsValid@CWave@@IBEHXZ
  return (uint)(*(int *)(this + 8) != 0);
}



// public: __thiscall CWave::CWave(class CWave const &)

CWave * __thiscall CWave::CWave(CWave *this,CWave *param_1)

{
                    // 0x2990  3  ??0CWave@@QAE@ABV0@@Z
  *(undefined4 *)(this + 4) = *(undefined4 *)(param_1 + 4);
  *(undefined4 *)(this + 8) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(this + 0xc) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(this + 0x10) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(this + 0x14) = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)(this + 0x18) = *(undefined4 *)(param_1 + 0x18);
  *(undefined4 *)(this + 0x1c) = *(undefined4 *)(param_1 + 0x1c);
  *(undefined4 *)(this + 0x20) = *(undefined4 *)(param_1 + 0x20);
  *(undefined4 *)(this + 0x24) = *(undefined4 *)(param_1 + 0x24);
  CString::CString((CString *)(this + 0x28),(CString *)(param_1 + 0x28));
  *(undefined4 *)(this + 0x2c) = *(undefined4 *)(param_1 + 0x2c);
  *(undefined4 *)(this + 0x30) = *(undefined4 *)(param_1 + 0x30);
  *(undefined4 *)(this + 0x34) = *(undefined4 *)(param_1 + 0x34);
  *(undefined4 *)(this + 0x38) = *(undefined4 *)(param_1 + 0x38);
  *(undefined2 *)(this + 0x3c) = *(undefined2 *)(param_1 + 0x3c);
  *(undefined ***)this = &_vftable_;
  return this;
}



// public: class CWave & __thiscall CWave::operator=(class CWave const &)

CWave * __thiscall CWave::operator=(CWave *this,CWave *param_1)

{
                    // 0x2a60  10  ??4CWave@@QAEAAV0@ABV0@@Z
  *(undefined4 *)(this + 4) = *(undefined4 *)(param_1 + 4);
  *(undefined4 *)(this + 8) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(this + 0xc) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(this + 0x10) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(this + 0x14) = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)(this + 0x18) = *(undefined4 *)(param_1 + 0x18);
  *(undefined4 *)(this + 0x1c) = *(undefined4 *)(param_1 + 0x1c);
  *(undefined4 *)(this + 0x20) = *(undefined4 *)(param_1 + 0x20);
  *(undefined4 *)(this + 0x24) = *(undefined4 *)(param_1 + 0x24);
  CString::operator=((CString *)(this + 0x28),(CString *)(param_1 + 0x28));
  *(undefined4 *)(this + 0x2c) = *(undefined4 *)(param_1 + 0x2c);
  *(undefined4 *)(this + 0x30) = *(undefined4 *)(param_1 + 0x30);
  *(undefined4 *)(this + 0x34) = *(undefined4 *)(param_1 + 0x34);
  *(undefined4 *)(this + 0x38) = *(undefined4 *)(param_1 + 0x38);
  *(undefined2 *)(this + 0x3c) = *(undefined2 *)(param_1 + 0x3c);
  return this;
}



void * __thiscall FUN_10002b20(void *this,uint param_1)

{
  if ((param_1 & 2) == 0) {
    CWave::~CWave((CWave *)this);
    if ((param_1 & 1) != 0) {
      operator_delete(this);
    }
  }
  else {
    FUN_10004a54(this,0x40,*(int *)((int)this + -4),CWave::~CWave);
    if ((param_1 & 1) != 0) {
      operator_delete((void *)((int)this + -4));
    }
    this = (void *)((int)this + -4);
  }
  return this;
}



// public: void __thiscall CMidi::LoadConsistentDSSounds(void)

void __thiscall CMidi::LoadConsistentDSSounds(CMidi *this)

{
                    // 0x2b90  30  ?LoadConsistentDSSounds@CMidi@@QAEXXZ
  return;
}



// public: __thiscall CMidi::CMidi(class CMidi const &)

CMidi * __thiscall CMidi::CMidi(CMidi *this,CMidi *param_1)

{
  int iVar1;
  CMidi *pCVar2;
  CMidi *pCVar3;
  
                    // 0x2ba0  1  ??0CMidi@@QAE@ABV0@@Z
  *this = *param_1;
  this[1] = param_1[1];
  *(undefined4 *)(this + 4) = *(undefined4 *)(param_1 + 4);
  *(undefined4 *)(this + 8) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(this + 0xc) = *(undefined4 *)(param_1 + 0xc);
  CString::CString((CString *)(this + 0x10),(CString *)(param_1 + 0x10));
  *(undefined4 *)(this + 0x14) = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)(this + 0x18) = *(undefined4 *)(param_1 + 0x18);
  *(undefined4 *)(this + 0x1c) = *(undefined4 *)(param_1 + 0x1c);
  pCVar2 = param_1 + 0x20;
  pCVar3 = this + 0x20;
  for (iVar1 = 0x4d; iVar1 != 0; iVar1 = iVar1 + -1) {
    *(undefined4 *)pCVar3 = *(undefined4 *)pCVar2;
    pCVar2 = pCVar2 + 4;
    pCVar3 = pCVar3 + 4;
  }
  return this;
}



// public: class CMidi & __thiscall CMidi::operator=(class CMidi const &)

CMidi * __thiscall CMidi::operator=(CMidi *this,CMidi *param_1)

{
  int iVar1;
  CMidi *pCVar2;
  CMidi *pCVar3;
  
                    // 0x2c40  9  ??4CMidi@@QAEAAV0@ABV0@@Z
  *this = *param_1;
  this[1] = param_1[1];
  *(undefined4 *)(this + 4) = *(undefined4 *)(param_1 + 4);
  *(undefined4 *)(this + 8) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(this + 0xc) = *(undefined4 *)(param_1 + 0xc);
  CString::operator=((CString *)(this + 0x10),(CString *)(param_1 + 0x10));
  *(undefined4 *)(this + 0x14) = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)(this + 0x18) = *(undefined4 *)(param_1 + 0x18);
  *(undefined4 *)(this + 0x1c) = *(undefined4 *)(param_1 + 0x1c);
  pCVar2 = param_1 + 0x20;
  pCVar3 = this + 0x20;
  for (iVar1 = 0x4d; iVar1 != 0; iVar1 = iVar1 + -1) {
    *(undefined4 *)pCVar3 = *(undefined4 *)pCVar2;
    pCVar2 = pCVar2 + 4;
    pCVar3 = pCVar3 + 4;
  }
  return this;
}



void __thiscall FUN_10002ce0(void *this,LPSTR param_1,DWORD param_2)

{
  HMMIO pHVar1;
  
  pHVar1 = mmioOpenA(param_1,(LPMMIOINFO)0x0,param_2);
  *(HMMIO *)((int)this + 4) = pHVar1;
  return;
}



void __thiscall FUN_10002d03(void *this,LPMMIOINFO param_1)

{
  HMMIO pHVar1;
  
  pHVar1 = mmioOpenA((LPSTR)0x0,param_1,2);
  *(HMMIO *)((int)this + 4) = pHVar1;
  return;
}



void FUN_10002d30(void)

{
  FUN_10002d3f();
  FUN_10002d4e();
  return;
}



void FUN_10002d3f(void)

{
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)&CWave::m_lstDisabledSounds);
  return;
}



void FUN_10002d4e(void)

{
  FUN_10004b74(FUN_10002d60);
  return;
}



void FUN_10002d60(void)

{
  if ((DAT_10007128 & 1) == 0) {
    DAT_10007128 = DAT_10007128 | 1;
    FUN_10003e30((undefined4 *)&CWave::m_lstDisabledSounds);
  }
  return;
}



// public: static struct HWND__ * __cdecl CWave::GetHWND(void)

HWND__ * __cdecl CWave::GetHWND(void)

{
                    // 0x2d8c  23  ?GetHWND@CWave@@SAPAUHWND__@@XZ
  return m_hwnd;
}



// public: __thiscall CWave::CWave(void)

CWave * __thiscall CWave::CWave(CWave *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x2d96  6  ??0CWave@@QAE@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_10004e5c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined4 *)(this + 4) = 0;
  *(undefined4 *)(this + 8) = 0;
  *(undefined4 *)(this + 0xc) = 0;
  *(undefined4 *)(this + 0x10) = 0;
  *(undefined4 *)(this + 0x14) = 0;
  *(undefined4 *)(this + 0x18) = 0;
  *(undefined4 *)(this + 0x1c) = 1;
  *(undefined4 *)(this + 0x20) = 0;
  *(undefined4 *)(this + 0x24) = 0;
  CString::CString((CString *)(this + 0x28));
  local_8 = 0;
  *(undefined ***)this = &_vftable_;
  InitDirectSound(this);
  ExceptionList = local_10;
  return this;
}



// public: __thiscall CWave::CWave(class CString const &)

CWave * __thiscall CWave::CWave(CWave *this,CString *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x2e47  4  ??0CWave@@QAE@ABVCString@@@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_10004e72;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined4 *)(this + 4) = 0;
  *(undefined4 *)(this + 8) = 0;
  *(undefined4 *)(this + 0xc) = 0;
  *(undefined4 *)(this + 0x10) = 0;
  *(undefined4 *)(this + 0x14) = 0;
  *(undefined4 *)(this + 0x18) = 0;
  *(undefined4 *)(this + 0x1c) = 1;
  *(undefined4 *)(this + 0x20) = 0;
  *(undefined4 *)(this + 0x24) = 0;
  CString::CString((CString *)(this + 0x28));
  local_8 = 0;
  *(undefined ***)this = &_vftable_;
  InitDirectSound(this);
  Create(this,param_1);
  ExceptionList = local_10;
  return this;
}



// public: __thiscall CWave::CWave(unsigned int,struct HINSTANCE__ *)

CWave * __thiscall CWave::CWave(CWave *this,uint param_1,HINSTANCE__ *param_2)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x2f06  5  ??0CWave@@QAE@IPAUHINSTANCE__@@@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_10004e88;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined4 *)(this + 4) = 0;
  *(undefined4 *)(this + 8) = 0;
  *(undefined4 *)(this + 0xc) = 0;
  *(undefined4 *)(this + 0x10) = 0;
  *(undefined4 *)(this + 0x14) = 0;
  *(undefined4 *)(this + 0x18) = 0;
  *(undefined4 *)(this + 0x1c) = 1;
  *(undefined4 *)(this + 0x20) = 0;
  *(undefined4 *)(this + 0x24) = 0;
  CString::CString((CString *)(this + 0x28));
  local_8 = 0;
  *(undefined ***)this = &_vftable_;
  InitDirectSound(this);
  Create(this,param_1,param_2);
  ExceptionList = local_10;
  return this;
}



// public: virtual __thiscall CWave::~CWave(void)

void __thiscall CWave::~CWave(CWave *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x2fc9  8  ??1CWave@@UAE@XZ
  puStack_c = &this_10004e9e;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)this = &_vftable_;
  local_8 = 0;
  Free(this);
  CleanupDirectSound(this);
  local_8 = 0xffffffff;
  CString::~CString((CString *)(this + 0x28));
  ExceptionList = local_10;
  return;
}



// public: static void __cdecl CWave::SetIgnoreList(class LIST<class CString> const &)

void __cdecl CWave::SetIgnoreList(LIST<> *param_1)

{
                    // 0x3025  42  ?SetIgnoreList@CWave@@SAXABV?$LIST@VCString@@@@@Z
  FUN_10003e80(&m_lstDisabledSounds,param_1);
  return;
}



// WARNING: Type propagation algorithm not settling
// private: int __thiscall CWave::ZeroBuffer(void)

int __thiscall CWave::ZeroBuffer(CWave *this)

{
  byte bVar1;
  bool bVar2;
  int iVar3;
  undefined3 extraout_var;
  DWORD local_30;
  byte local_2c;
  undefined3 uStack_2b;
  void *local_28;
  int local_24;
  size_t local_20 [2];
  undefined2 local_18;
  undefined4 local_16;
  undefined4 local_12;
  undefined4 local_e;
  uint local_a;
  
                    // 0x3038  49  ?ZeroBuffer@CWave@@AAEHXZ
  if (*(int *)(this + 4) == 0) {
    iVar3 = 0;
  }
  else if (*(int *)(this + 0x1c) == 0) {
    local_18 = 0;
    local_16 = 0;
    local_12 = 0;
    local_e = 0;
    local_a = 0;
    local_20[1] = 0;
    (**(code **)(**(int **)(this + 4) + 0x14))
              (*(undefined4 *)(this + 4),&local_18,0x12,local_20 + 1);
    local_28 = (void *)0x0;
    local_20[0] = GetDataLen(this);
    local_24 = (**(code **)(**(int **)(this + 4) + 0x2c))
                         (*(undefined4 *)(this + 4),0,local_20[0],&local_28,local_20,0,0,0);
    if (-1 < local_24) {
      bVar1 = (-((local_a & 0xffff) != 8) & 0x80U) + 0x80;
      _local_2c = CONCAT31(uStack_2b,bVar1);
      memset(local_28,(uint)bVar1,local_20[0]);
      FUN_10004690(&local_30);
      local_24 = -1;
      while ((local_24 < 0 &&
             (bVar2 = FUN_100046b0(&local_30,5000), CONCAT31(extraout_var,bVar2) == 0))) {
        local_24 = (**(code **)(**(int **)(this + 4) + 0x4c))
                             (*(undefined4 *)(this + 4),local_28,local_20[0],0,0);
      }
    }
    *(uint *)(this + 0x1c) = (uint)(-1 < local_24);
    iVar3 = *(int *)(this + 0x1c);
  }
  else {
    iVar3 = 1;
  }
  return iVar3;
}



// private: int __thiscall CWave::ReloadBuffer(void)

int __thiscall CWave::ReloadBuffer(CWave *this)

{
  int iVar1;
  ulong local_c;
  uchar *local_8;
  
                    // 0x3177  39  ?ReloadBuffer@CWave@@AAEHXZ
  if (*(int *)(this + 4) == 0) {
    iVar1 = 0;
  }
  else if (*(int *)(this + 0x1c) == 0) {
    iVar1 = 1;
  }
  else {
    local_c = GetDataLen(this);
    local_8 = (uchar *)0x0;
    iVar1 = (**(code **)(**(int **)(this + 4) + 0x2c))
                      (*(undefined4 *)(this + 4),0,local_c,&local_8,&local_c,0,0,0);
    if (iVar1 == 0) {
      local_c = GetData(this,&local_8,local_c);
      iVar1 = (**(code **)(**(int **)(this + 4) + 0x4c))
                        (*(undefined4 *)(this + 4),local_8,local_c,0,0);
      if (iVar1 == 0) {
        *(undefined4 *)(this + 0x1c) = 0;
        iVar1 = 1;
      }
      else {
        iVar1 = 0;
      }
    }
    else {
      iVar1 = 0;
    }
  }
  return iVar1;
}



// protected: void __thiscall CWave::LoadAudio(void)

void __thiscall CWave::LoadAudio(CWave *this)

{
                    // 0x3235  29  ?LoadAudio@CWave@@IAEXXZ
  CheckFormat(this);
  InitDSBuffer(this);
  return;
}



// public: static void __cdecl CWave::RegisterWindow(struct HWND__ * const)

void __cdecl CWave::RegisterWindow(HWND__ *param_1)

{
                    // 0x3250  38  ?RegisterWindow@CWave@@SAXQAUHWND__@@@Z
  m_hwnd = param_1;
  return;
}



// public: int __thiscall CWave::Create(class CString const &)

int __thiscall CWave::Create(CWave *this,CString *param_1)

{
  bool bVar1;
  int iVar2;
  CString *pCVar3;
  char *pcVar4;
  ulong uVar5;
  HGLOBAL hMem;
  LPVOID pvVar6;
  uint uVar7;
  CFileException *pCVar8;
  CString local_40 [4];
  CString local_3c [4];
  CString local_38 [4];
  int local_34;
  CString local_30 [4];
  uint local_2c;
  CFile local_28 [16];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x325d  15  ?Create@CWave@@QAEHABVCString@@@Z
  local_8 = 0xffffffff;
  puStack_c = &this_10004ee7;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  iVar2 = CString::Find(param_1,'.');
  if (iVar2 == -1) {
    pCVar3 = (CString *)operator+(local_30,(char *)param_1);
    local_8 = 0;
    iVar2 = Create(this,pCVar3);
    local_2c = CONCAT31(local_2c._1_3_,'\x01' - (iVar2 != 0));
    local_8 = 0xffffffff;
    CString::~CString(local_30);
    if ((local_2c & 0xff) == 0) {
      local_34 = 1;
    }
    else {
      pCVar3 = (CString *)operator+(local_38,(char *)param_1);
      local_8 = 1;
      local_34 = Create(this,pCVar3);
      local_8 = 0xffffffff;
      CString::~CString(local_38);
    }
  }
  else {
    Free(this);
    FUN_10002900((undefined4 *)param_1);
    pCVar3 = (CString *)ExtractFileName((char *)local_3c);
    local_8 = 2;
    FUN_100046f0(local_14,pCVar3);
    local_8._0_1_ = 4;
    CString::~CString(local_3c);
    pcVar4 = STRING::strtok((char *)local_40,(char *)&_Delim_10007048);
    local_8._0_1_ = 5;
    pCVar3 = (CString *)STRING::toupper((int)pcVar4);
    CString::operator=((CString *)(this + 0x28),pCVar3);
    local_8._0_1_ = 4;
    FUN_10004710(local_40);
    CFile::CFile(local_28);
    local_8._0_1_ = 6;
    pCVar8 = (CFileException *)0x0;
    uVar7 = 0;
    pcVar4 = (char *)FUN_10002900((undefined4 *)param_1);
    iVar2 = CFile::Open(local_28,pcVar4,uVar7,pCVar8);
    if (iVar2 == 0) {
      local_8 = CONCAT31(local_8._1_3_,4);
      CFile::~CFile(local_28);
      local_8 = 0xffffffff;
      FUN_10004710(local_14);
      local_34 = 0;
    }
    else {
      uVar5 = CFile::GetLength(local_28);
      *(ulong *)(this + 0xc) = uVar5;
      hMem = GlobalAlloc(0x2002,*(SIZE_T *)(this + 0xc));
      pvVar6 = GlobalLock(hMem);
      *(LPVOID *)(this + 8) = pvVar6;
      if (*(int *)(this + 8) == 0) {
        local_8 = CONCAT31(local_8._1_3_,4);
        CFile::~CFile(local_28);
        local_8 = 0xffffffff;
        FUN_10004710(local_14);
        local_34 = 0;
      }
      else {
        CString::Right(param_1,(int)local_18);
        local_8 = CONCAT31(local_8._1_3_,7);
        CString::MakeUpper(local_18);
        bVar1 = FUN_100043e0(local_18,&DAT_1000704c);
        if (bVar1) {
          CFile::Read(local_28,*(void **)(this + 8),0x46);
          *(int *)(this + 0xc) = *(int *)(this + 0xc) + -0x46;
        }
        CFile::Read(local_28,*(void **)(this + 8),*(uint *)(this + 0xc));
        LoadAudio(this);
        local_8._0_1_ = 6;
        CString::~CString(local_18);
        local_8 = CONCAT31(local_8._1_3_,4);
        CFile::~CFile(local_28);
        local_8 = 0xffffffff;
        FUN_10004710(local_14);
        local_34 = 1;
      }
    }
  }
  ExceptionList = local_10;
  return local_34;
}



// public: int __thiscall CWave::Create(unsigned int,struct HINSTANCE__ *)

int __thiscall CWave::Create(CWave *this,uint param_1,HINSTANCE__ *param_2)

{
  HRSRC hResInfo;
  DWORD DVar1;
  HGLOBAL pvVar2;
  LPVOID pvVar3;
  
                    // 0x3519  16  ?Create@CWave@@QAEHIPAUHINSTANCE__@@@Z
  Free(this);
  hResInfo = FindResourceA(param_2,(LPCSTR)(param_1 & 0xffff),s_AUDIO_10007050);
  DVar1 = SizeofResource(param_2,hResInfo);
  *(DWORD *)(this + 0xc) = DVar1;
  pvVar2 = GlobalAlloc(0x2002,*(SIZE_T *)(this + 0xc));
  pvVar3 = GlobalLock(pvVar2);
  *(LPVOID *)(this + 8) = pvVar3;
  pvVar2 = LoadResource(param_2,hResInfo);
  pvVar3 = LockResource(pvVar2);
  memcpy(*(void **)(this + 8),pvVar3,*(size_t *)(this + 0xc));
  LoadAudio(this);
  return 1;
}



// public: int __thiscall CWave::Play(long,long,int)

int __thiscall CWave::Play(CWave *this,long param_1,long param_2,int param_3)

{
  bool bVar1;
  int iVar2;
  undefined3 extraout_var;
  
                    // 0x35c3  36  ?Play@CWave@@QAEHJJH@Z
  if (m_bEnableSound) {
    bVar1 = FUN_100028c0((int *)(this + 0x28));
    if ((CONCAT31(extraout_var,bVar1) == 0) &&
       (bVar1 = FUN_10003ec0(&m_lstDisabledSounds,(undefined4 *)(this + 0x28)), bVar1)) {
      return 1;
    }
    if (m_pDirectSound == (IDirectSound *)0x0) {
      iVar2 = 0;
    }
    else if (*(int *)(this + 4) == 0) {
      iVar2 = 1;
    }
    else {
      if (m_CooperativeLevelSet == 0) {
        SetCooperativeLevel(this);
      }
      *(undefined4 *)(this + 0x24) = 0;
      Stop(this);
      iVar2 = Start(this,param_1,param_2,param_3);
    }
  }
  else {
    iVar2 = 1;
  }
  return iVar2;
}



// public: int __thiscall CWave::Stop(void)

int __thiscall CWave::Stop(CWave *this)

{
  int iVar1;
  uint local_8;
  
                    // 0x3669  46  ?Stop@CWave@@QAEHXZ
  if (m_bEnableSound) {
    if (m_pDirectSound == (IDirectSound *)0x0) {
      iVar1 = 0;
    }
    else if (*(int *)(this + 4) == 0) {
      iVar1 = 1;
    }
    else {
      if (m_CooperativeLevelSet == 0) {
        SetCooperativeLevel(this);
      }
      (**(code **)(**(int **)(this + 4) + 0x24))(*(undefined4 *)(this + 4),&local_8);
      if ((local_8 & 1) != 0) {
        (**(code **)(**(int **)(this + 4) + 0x34))(*(undefined4 *)(this + 4),0);
        ZeroBuffer(this);
      }
      iVar1 = 1;
    }
  }
  else {
    iVar1 = 1;
  }
  return iVar1;
}



// public: int __thiscall CWave::Pause(void)

int __thiscall CWave::Pause(CWave *this)

{
  int iVar1;
  uint local_8;
  
                    // 0x36f7  33  ?Pause@CWave@@QAEHXZ
  if (m_bEnableSound) {
    if (m_pDirectSound == (IDirectSound *)0x0) {
      iVar1 = 0;
    }
    else if (*(int *)(this + 4) == 0) {
      iVar1 = 1;
    }
    else {
      if (m_CooperativeLevelSet == 0) {
        SetCooperativeLevel(this);
      }
      local_8 = 0;
      (**(code **)(**(int **)(this + 4) + 0x24))(*(undefined4 *)(this + 4),&local_8);
      if ((local_8 & 1) == 0) {
        Start(this,*(long *)(this + 0x10),*(long *)(this + 0x14),*(int *)(this + 0x18));
      }
      else {
        (**(code **)(**(int **)(this + 4) + 0x48))(*(undefined4 *)(this + 4));
      }
      iVar1 = 1;
    }
  }
  else {
    iVar1 = 1;
  }
  return iVar1;
}



// protected: int __thiscall CWave::Start(long,long,int)

int __thiscall CWave::Start(CWave *this,long param_1,long param_2,int param_3)

{
  int iVar1;
  uint local_8;
  
                    // 0x37a4  44  ?Start@CWave@@IAEHJJH@Z
  if (!m_bEnableSound) {
    return 1;
  }
  if (m_pDirectSound == (IDirectSound *)0x0) {
    return 0;
  }
  *(long *)(this + 0x10) = param_2;
  *(long *)(this + 0x14) = param_1;
  *(int *)(this + 0x18) = param_3;
  iVar1 = IsValid(this);
  if (iVar1 == 0) {
    return 0;
  }
  if (*(int *)(this + 4) != 0) {
    local_8 = 0;
    (**(code **)(**(int **)(this + 4) + 0x24))(*(undefined4 *)(this + 4),&local_8);
    if (((local_8 & 2) == 0) ||
       ((iVar1 = (**(code **)(**(int **)(this + 4) + 0x50))(*(undefined4 *)(this + 4)), iVar1 == 0
        && (iVar1 = InitDSBuffer(this), iVar1 == 0)))) {
      ReloadBuffer(this);
      (**(code **)(**(int **)(this + 4) + 0x40))(*(undefined4 *)(this + 4),param_2);
      (**(code **)(**(int **)(this + 4) + 0x3c))(*(undefined4 *)(this + 4),param_1);
      (**(code **)(**(int **)(this + 4) + 0x30))(*(undefined4 *)(this + 4),0,0,param_3 != 0);
      iVar1 = 1;
    }
    else {
      iVar1 = 0;
    }
    return iVar1;
  }
  return 1;
}



// protected: void __thiscall CWave::SetCooperativeLevel(void)

void __thiscall CWave::SetCooperativeLevel(CWave *this)

{
  int iVar1;
  
                    // 0x38bf  40  ?SetCooperativeLevel@CWave@@IAEXXZ
  if ((m_pDirectSound != (IDirectSound *)0x0) && (m_CooperativeLevelSet == 0)) {
    iVar1 = (**(code **)(*(int *)m_pDirectSound + 0x18))(m_pDirectSound,m_hwnd,1);
    if (iVar1 == 0) {
      m_CooperativeLevelSet = 1;
    }
    else {
      MessageBoxA((HWND)0x0,s_Could_not_set_cooperative_level__1000706c,s_DirectSound_Error_10007058
                  ,0x10);
      CleanupDirectSound(this);
      AfxThrowUserException();
    }
  }
  return;
}



// protected: int __thiscall CWave::InitDirectSound(void)

int __thiscall CWave::InitDirectSound(CWave *this)

{
  int iVar1;
  
                    // 0x392a  27  ?InitDirectSound@CWave@@IAEHXZ
  if (m_nDirectSoundReferences == 0) {
    iVar1 = Ordinal_1(0,&m_pDirectSound,0,this);
    if (iVar1 != 0) {
      m_pDirectSound = (IDirectSound *)0x0;
    }
    m_nDirectSoundReferences = m_nDirectSoundReferences + 1;
  }
  else {
    m_nDirectSoundReferences = m_nDirectSoundReferences + 1;
  }
  return 1;
}



// protected: void __thiscall CWave::CleanupDirectSound(void)

void __thiscall CWave::CleanupDirectSound(CWave *this)

{
                    // 0x397d  13  ?CleanupDirectSound@CWave@@IAEXXZ
  if ((m_pDirectSound != (IDirectSound *)0x0) &&
     (m_nDirectSoundReferences = m_nDirectSoundReferences + -1, m_nDirectSoundReferences == 0)) {
    (**(code **)(*(int *)m_pDirectSound + 8))(m_pDirectSound,this);
    m_pDirectSound = (IDirectSound *)0x0;
    m_CooperativeLevelSet = 0;
  }
  return;
}



// protected: int __thiscall CWave::InitDSBuffer(void)

int __thiscall CWave::InitDSBuffer(CWave *this)

{
  int iVar1;
  ulong uVar2;
  undefined4 local_18;
  undefined4 local_14;
  ulong local_10;
  CWave *local_8;
  
                    // 0x39ce  26  ?InitDSBuffer@CWave@@IAEHXZ
  if (m_pDirectSound == (IDirectSound *)0x0) {
    iVar1 = 0;
  }
  else {
    uVar2 = GetDataLen(this);
    memset(&local_18,0,0x14);
    local_18 = 0x14;
    local_14 = 0xe2;
    local_8 = this + 0x2c;
    local_10 = uVar2;
    iVar1 = (**(code **)(*(int *)m_pDirectSound + 0xc))(m_pDirectSound,&local_18,this + 4,0);
    if (iVar1 == 0) {
      ReloadBuffer(this);
      iVar1 = 1;
    }
    else {
      iVar1 = 0;
    }
  }
  return iVar1;
}



// protected: int __thiscall CWave::Free(void)

int __thiscall CWave::Free(CWave *this)

{
  HGLOBAL hMem;
  
                    // 0x3a54  20  ?Free@CWave@@IAEHXZ
  if (*(int *)(this + 8) != 0) {
    *(undefined4 *)(this + 0x1c) = 1;
    if (*(int *)(this + 4) != 0) {
      (**(code **)(**(int **)(this + 4) + 8))(*(undefined4 *)(this + 4));
      *(undefined4 *)(this + 4) = 0;
    }
    hMem = GlobalHandle(*(LPCVOID *)(this + 8));
    if (hMem != (HGLOBAL)0x0) {
      GlobalUnlock(hMem);
      GlobalFree(hMem);
      *(undefined4 *)(this + 8) = 0;
      *(undefined4 *)(this + 0xc) = 0;
      return 1;
    }
  }
  return 0;
}



// protected: int __thiscall CWave::CheckFormat(void)

int __thiscall CWave::CheckFormat(CWave *this)

{
  int iVar1;
  MMCKINFO *local_94;
  _MMIOINFO local_90;
  undefined4 local_48 [2];
  _MMCKINFO local_40;
  CWave *local_2c;
  LONG local_28;
  _MMCKINFO local_24;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x3ae0  12  ?CheckFormat@CWave@@IAEHXZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_10004efa;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  iVar1 = IsValid(this);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    FUN_100044b0(&local_90,*(undefined4 *)(this + 8),*(undefined4 *)(this + 0xc),0);
    FUN_10004540(local_48,&local_90);
    local_8 = 0;
    FUN_10004460(&local_40,0x57,0x41,0x56,0x45);
    local_94 = (MMCKINFO *)0x0;
    local_28 = 0;
    local_2c = (CWave *)0x0;
    iVar1 = FUN_10004630(local_48,&local_40,0x20);
    if (iVar1 == 0) {
      local_94 = &local_40;
      local_28 = 0x12;
      local_2c = this + 0x2c;
    }
    FUN_10004400(&local_24,0x66,0x6d,0x74,0x20);
    FUN_10004660(local_48,&local_24,local_94,0x10);
    FUN_100045d0(local_48,(HPSTR)local_2c,local_28);
    FUN_10004600(local_48,&local_24,0);
    local_8 = 0xffffffff;
    FUN_10004520(local_48);
    iVar1 = 1;
  }
  ExceptionList = local_10;
  return iVar1;
}



// protected: unsigned long __thiscall CWave::GetDataLen(void)const 

ulong __thiscall CWave::GetDataLen(CWave *this)

{
  int iVar1;
  _MMIOINFO local_88;
  undefined4 local_40 [2];
  _MMCKINFO local_38;
  _MMCKINFO local_24;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x3c17  22  ?GetDataLen@CWave@@IBEKXZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_10004f0d;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  iVar1 = IsValid(this);
  if (iVar1 == 0) {
    local_24.cksize = 0;
  }
  else {
    FUN_100044b0(&local_88,*(undefined4 *)(this + 8),*(undefined4 *)(this + 0xc),0);
    FUN_10004540(local_40,&local_88);
    local_8 = 0;
    FUN_10004460(&local_38,0x57,0x41,0x56,0x45);
    FUN_10004630(local_40,&local_38,0x20);
    FUN_10004400(&local_24,100,0x61,0x74,0x61);
    FUN_10004660(local_40,&local_24,&local_38,0x10);
    local_8 = 0xffffffff;
    FUN_10004520(local_40);
  }
  ExceptionList = local_10;
  return local_24.cksize;
}



// protected: unsigned long __thiscall CWave::GetData(unsigned char * &,unsigned long)const 

ulong __thiscall CWave::GetData(CWave *this,uchar **param_1,ulong param_2)

{
  int iVar1;
  ulong uVar2;
  HGLOBAL hMem;
  uchar *puVar3;
  _MMIOINFO local_8c;
  undefined4 local_44 [2];
  ulong local_3c;
  _MMCKINFO local_38;
  _MMCKINFO local_24;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x3cf4  21  ?GetData@CWave@@IBEKAAPAEK@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_10004f20;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  iVar1 = IsValid(this);
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    FUN_100044b0(&local_8c,*(undefined4 *)(this + 8),*(undefined4 *)(this + 0xc),0);
    FUN_10004540(local_44,&local_8c);
    local_8 = 0;
    FUN_10004460(&local_38,0x57,0x41,0x56,0x45);
    FUN_10004630(local_44,&local_38,0x20);
    FUN_10004400(&local_24,100,0x61,0x74,0x61);
    FUN_10004660(local_44,&local_24,&local_38,0x10);
    local_3c = local_24.cksize;
    if (*param_1 == (uchar *)0x0) {
      hMem = GlobalAlloc(2,local_24.cksize);
      puVar3 = (uchar *)GlobalLock(hMem);
      *param_1 = puVar3;
    }
    else if (param_2 < local_24.cksize) {
      local_3c = param_2;
    }
    if (*param_1 != (uchar *)0x0) {
      FUN_100045d0(local_44,(HPSTR)*param_1,local_3c);
    }
    uVar2 = local_3c;
    local_8 = 0xffffffff;
    FUN_10004520(local_44);
  }
  ExceptionList = local_10;
  return uVar2;
}



void __fastcall FUN_10003e30(undefined4 *param_1)

{
  FUN_100040a0(param_1);
  return;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_10003f20(this,10);
  *(undefined ***)this = &PTR_LAB_100051d0;
  return this;
}



void * __thiscall FUN_10003e80(void *this,void *param_1)

{
  if (this != param_1) {
    FUN_10003fc0((int)this);
    FUN_10003f80(this,(int)param_1);
  }
  return this;
}



bool __thiscall FUN_10003ec0(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_10004040(this,param_1,(undefined4 *)0x0);
  return puVar1 != (undefined4 *)0x0;
}



void * __thiscall FUN_10003ef0(void *this,uint param_1)

{
  FUN_10003e30((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10002870(this);
  }
  return this;
}



void * __thiscall FUN_10003f20(void *this,undefined4 param_1)

{
  FUN_100027f0((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_100051e4;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



void __thiscall FUN_10003f80(void *this,int param_1)

{
  CString *pCVar1;
  int local_8;
  
  local_8 = FUN_10002390(param_1);
  while (local_8 != 0) {
    pCVar1 = (CString *)FUN_10004270(&local_8);
    FUN_10004210(this,pCVar1);
  }
  return;
}



void __fastcall FUN_10003fc0(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    DestructElements((CString *)(local_8 + 2),1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



undefined4 * __thiscall FUN_10004040(void *this,undefined4 *param_1,undefined4 *param_2)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 *local_8;
  
  if (param_2 == (undefined4 *)0x0) {
    local_8 = *(undefined4 **)((int)this + 4);
  }
  else {
    local_8 = (undefined4 *)*param_2;
  }
  while( true ) {
    if (local_8 == (undefined4 *)0x0) {
      return (undefined4 *)0x0;
    }
    bVar1 = FUN_100042a0(local_8 + 2,param_1);
    if (CONCAT31(extraout_var,bVar1) != 0) break;
    local_8 = (undefined4 *)*local_8;
  }
  return local_8;
}



void __fastcall FUN_100040a0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_10004f39;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_100051e4;
  local_8 = 0;
  FUN_10003fc0((int)param_1);
  local_8 = 0xffffffff;
  FUN_10002840(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_10004100(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  CString local_1c [4];
  ulong local_18;
  undefined4 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10004f59;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10002860();
  bVar1 = FUN_10002930((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_18 = CArchive::ReadCount(param_1);
    while (local_18 != 0) {
      local_18 = local_18 - 1;
      CString::CString(local_1c);
      local_8 = 0;
      SerializeElements(param_1,local_1c,1);
      FUN_10004210(this,local_1c);
      local_8 = 0xffffffff;
      CString::~CString(local_1c);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_14 = *(undefined4 **)((int)this + 4); local_14 != (undefined4 *)0x0;
        local_14 = (undefined4 *)*local_14) {
      SerializeElements(param_1,(CString *)(local_14 + 2),1);
    }
  }
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_100041e0(void *this,uint param_1)

{
  FUN_100040a0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10002870(this);
  }
  return this;
}



undefined4 * __thiscall FUN_10004210(void *this,CString *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_100042c0(this,*(undefined4 *)((int)this + 8),0);
  CString::operator=((CString *)(puVar1 + 2),param_1);
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



int FUN_10004270(int *param_1)

{
  int *piVar1;
  
  piVar1 = (int *)*param_1;
  *param_1 = *piVar1;
  return (int)(piVar1 + 2);
}



bool FUN_100042a0(void *param_1,undefined4 *param_2)

{
  bool bVar1;
  
  bVar1 = FUN_100043a0(param_1,param_2);
  return bVar1;
}



undefined4 * __thiscall FUN_100042c0(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0xc);
    iVar3 = FUN_10004d80((int)pCVar2);
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
  ConstructElements((CString *)(puVar1 + 2),1);
  return puVar1;
}



bool FUN_100043a0(void *param_1,undefined4 *param_2)

{
  char *pcVar1;
  int iVar2;
  
  pcVar1 = (char *)FUN_10002900(param_2);
  iVar2 = FUN_100043c0(param_1,pcVar1);
  return (bool)('\x01' - (iVar2 != 0));
}



void __thiscall FUN_100043c0(void *this,char *param_1)

{
                    // WARNING: Load size is inaccurate
  strcmp(*this,param_1);
  return;
}



bool FUN_100043e0(void *param_1,char *param_2)

{
  int iVar1;
  
  iVar1 = FUN_100043c0(param_1,param_2);
  return (bool)('\x01' - (iVar1 != 0));
}



void * __thiscall FUN_10004400(void *this,uint param_1,uint param_2,uint param_3,int param_4)

{
  FUN_10004450(this);
  *(uint *)this =
       param_1 & 0xff | (param_2 & 0xff) << 8 | (param_3 & 0xff) << 0x10 | param_4 << 0x18;
  return this;
}



undefined4 __fastcall FUN_10004450(undefined4 param_1)

{
  return param_1;
}



void * __thiscall FUN_10004460(void *this,uint param_1,uint param_2,uint param_3,int param_4)

{
  FUN_10004450(this);
  *(uint *)((int)this + 8) =
       param_1 & 0xff | (param_2 & 0xff) << 8 | (param_3 & 0xff) << 0x10 | param_4 << 0x18;
  return this;
}



void * __thiscall FUN_100044b0(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_10004500(this);
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0x204d454d;
  *(undefined4 *)((int)this + 0x18) = param_1;
  *(undefined4 *)((int)this + 0x14) = param_2;
  *(undefined4 *)((int)this + 0x30) = param_3;
  return this;
}



void * __fastcall FUN_10004500(void *param_1)

{
  memset(param_1,0,0x48);
  return param_1;
}



void __fastcall FUN_10004520(undefined4 *param_1)

{
  FUN_10002840(param_1);
  return;
}



void * __thiscall FUN_10004540(void *this,LPMMIOINFO param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10004f79;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_100027f0((undefined4 *)this);
  local_8 = 0;
  *(undefined ***)this = &PTR_LAB_100051f8;
  FUN_10002d03(this,param_1);
  ExceptionList = local_10;
  return this;
}



void * __thiscall FUN_100045a0(void *this,uint param_1)

{
  FUN_10004520((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10002870(this);
  }
  return this;
}



void __thiscall FUN_100045d0(void *this,HPSTR param_1,LONG param_2)

{
  mmioRead(*(HMMIO *)((int)this + 4),param_1,param_2);
  return;
}



void __thiscall FUN_10004600(void *this,LPMMCKINFO param_1,UINT param_2)

{
  mmioAscend(*(HMMIO *)((int)this + 4),param_1,param_2);
  return;
}



void __thiscall FUN_10004630(void *this,LPMMCKINFO param_1,UINT param_2)

{
  mmioDescend(*(HMMIO *)((int)this + 4),param_1,(MMCKINFO *)0x0,param_2);
  return;
}



void __thiscall FUN_10004660(void *this,LPMMCKINFO param_1,MMCKINFO *param_2,UINT param_3)

{
  mmioDescend(*(HMMIO *)((int)this + 4),param_1,param_2,param_3);
  return;
}



DWORD * __fastcall FUN_10004690(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
  return param_1;
}



bool __thiscall FUN_100046b0(void *this,uint param_1)

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



void * __thiscall FUN_100046f0(void *this,CString *param_1)

{
  CString::CString((CString *)this,param_1);
  return this;
}



void __fastcall FUN_10004710(CString *param_1)

{
  CString::~CString(param_1);
  return;
}



void Ordinal_1(void)

{
                    // WARNING: Could not recover jumptable at 0x10004724. Too many branches
                    // WARNING: Treating indirect jump as call
  Ordinal_1();
  return;
}



void __thiscall CString::~CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x1000472a. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CString(this);
  return;
}



void __thiscall CString::CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x10004730. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this);
  return;
}



void operator+(CString *param_1,CString *param_2)

{
                    // WARNING: Could not recover jumptable at 0x10004736. Too many branches
                    // WARNING: Treating indirect jump as call
  operator+(param_1,param_2);
  return;
}



CString * __thiscall CString::operator=(CString *this,CString *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000473c. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator=(this,param_1);
  return pCVar1;
}



void __thiscall CString::Left(CString *this,int param_1)

{
                    // WARNING: Could not recover jumptable at 0x10004742. Too many branches
                    // WARNING: Treating indirect jump as call
  Left(this,param_1);
  return;
}



void __thiscall CString::TrimLeft(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x10004748. Too many branches
                    // WARNING: Treating indirect jump as call
  TrimLeft(this);
  return;
}



void __thiscall CString::CString(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000474e. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



CString * __thiscall CString::operator=(CString *this,char *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x10004754. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator=(this,param_1);
  return pCVar1;
}



ulong __thiscall CArchive::ReadCount(CArchive *this)

{
  ulong uVar1;
  
                    // WARNING: Could not recover jumptable at 0x10004760. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = ReadCount(this);
  return uVar1;
}



void __thiscall CArchive::WriteCount(CArchive *this,ulong param_1)

{
                    // WARNING: Could not recover jumptable at 0x10004766. Too many branches
                    // WARNING: Treating indirect jump as call
  WriteCount(this,param_1);
  return;
}



void __thiscall CPlex::FreeDataChain(CPlex *this)

{
                    // WARNING: Could not recover jumptable at 0x1000476c. Too many branches
                    // WARNING: Treating indirect jump as call
  FreeDataChain(this);
  return;
}



CPlex * CPlex::Create(CPlex **param_1,uint param_2,uint param_3)

{
  CPlex *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x10004772. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = Create(param_1,param_2,param_3);
  return pCVar1;
}



uint __thiscall CArchive::Read(CArchive *this,void *param_1,uint param_2)

{
  uint uVar1;
  
                    // WARNING: Could not recover jumptable at 0x10004778. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = Read(this,param_1,param_2);
  return uVar1;
}



void __thiscall CArchive::Write(CArchive *this,void *param_1,uint param_2)

{
                    // WARNING: Could not recover jumptable at 0x1000477e. Too many branches
                    // WARNING: Treating indirect jump as call
  Write(this,param_1,param_2);
  return;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10004784. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000478a. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void __thiscall CString::CString(CString *this,CString *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10004790. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



uint __thiscall CFile::Read(CFile *this,void *param_1,uint param_2)

{
  uint uVar1;
  
                    // WARNING: Could not recover jumptable at 0x10004796. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = Read(this,param_1,param_2);
  return uVar1;
}



void __thiscall CString::MakeUpper(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x1000479c. Too many branches
                    // WARNING: Treating indirect jump as call
  MakeUpper(this);
  return;
}



void __thiscall CString::Right(CString *this,int param_1)

{
                    // WARNING: Could not recover jumptable at 0x100047a2. Too many branches
                    // WARNING: Treating indirect jump as call
  Right(this,param_1);
  return;
}



ulong __thiscall CFile::GetLength(CFile *this)

{
  ulong uVar1;
  
                    // WARNING: Could not recover jumptable at 0x100047a8. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = GetLength(this);
  return uVar1;
}



void __thiscall CFile::~CFile(CFile *this)

{
                    // WARNING: Could not recover jumptable at 0x100047ae. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CFile(this);
  return;
}



int __thiscall CFile::Open(CFile *this,char *param_1,uint param_2,CFileException *param_3)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x100047b4. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Open(this,param_1,param_2,param_3);
  return iVar1;
}



void __thiscall CFile::CFile(CFile *this)

{
                    // WARNING: Could not recover jumptable at 0x100047ba. Too many branches
                    // WARNING: Treating indirect jump as call
  CFile(this);
  return;
}



void operator+(CString *param_1,char *param_2)

{
                    // WARNING: Could not recover jumptable at 0x100047c0. Too many branches
                    // WARNING: Treating indirect jump as call
  operator+(param_1,param_2);
  return;
}



int __thiscall CString::Find(CString *this,char param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x100047c6. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Find(this,param_1);
  return iVar1;
}



void AfxThrowUserException(void)

{
                    // WARNING: Could not recover jumptable at 0x100047cc. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxThrowUserException();
  return;
}



void DestructElements(CString *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x100047d2. Too many branches
                    // WARNING: Treating indirect jump as call
  DestructElements(param_1,param_2);
  return;
}



void SerializeElements(CArchive *param_1,CString *param_2,int param_3)

{
                    // WARNING: Could not recover jumptable at 0x100047d8. Too many branches
                    // WARNING: Treating indirect jump as call
  SerializeElements(param_1,param_2,param_3);
  return;
}



void ConstructElements(CString *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x100047de. Too many branches
                    // WARNING: Treating indirect jump as call
  ConstructElements(param_1,param_2);
  return;
}



void * __thiscall FUN_10004816(void *this,byte param_1)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)this);
  if ((param_1 & 1) != 0) {
    CNoTrackObject::operator_delete(this);
  }
  return this;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x10004d26. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



int FUN_10004891(HINSTANCE__ *param_1,int param_2)

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
      pAVar5 = AfxSetModuleState((AFX_MODULE_STATE *)&param_1_10007160);
      p_Var3 = AfxGetThreadState();
      *(AFX_MODULE_STATE **)(p_Var3 + 8) = pAVar5;
      pAVar5 = AfxGetModuleState();
      if (*(int **)(pAVar5 + 4) != (int *)0x0) {
        (**(code **)(**(int **)(pAVar5 + 4) + 0x70))();
      }
      AfxLockTempMaps();
      AfxUnlockTempMaps(-1);
      AfxWinTerm();
      AfxTermExtensionModule((AFX_EXTENSION_MODULE *)&param_1_100081f0,1);
    }
    else if (param_2 == 3) {
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
                ((AFX_MAINTAIN_STATE2 *)&local_c,(AFX_MODULE_STATE *)&param_1_10007160);
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
  iVar4 = AfxWinInit(param_1,(HINSTANCE__ *)0x0,(char *)&param_3_100052c4,0);
  if (iVar4 != 0) {
    pAVar5 = AfxGetModuleState();
    piVar2 = *(int **)(pAVar5 + 4);
    if ((piVar2 == (int *)0x0) || (iVar4 = (**(code **)(*piVar2 + 0x58))(), iVar4 != 0)) {
      *(undefined4 *)(p_Var3 + 8) = uVar1;
      AfxInitExtensionModule((AFX_EXTENSION_MODULE *)&param_1_100081f0,param_1);
      this = (CDynLinkLibrary *)operator_new(0x40);
      if (this != (CDynLinkLibrary *)0x0) {
        CDynLinkLibrary::CDynLinkLibrary(this,(AFX_EXTENSION_MODULE *)&param_1_100081f0,0);
      }
      param_2 = 1;
      goto LAB_1000491d;
    }
    (**(code **)(*piVar2 + 0x70))();
  }
  AfxWinTerm();
LAB_1000491d:
  *(undefined4 *)(p_Var3 + 8) = uVar1;
  p_Var3 = AfxGetThreadState();
  AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var3 + 8));
  return param_2;
}



undefined4 FUN_100049b8(undefined4 param_1,int param_2)

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
    pAVar2 = AfxSetModuleState((AFX_MODULE_STATE *)&param_1_10007160);
    *(AFX_MODULE_STATE **)(p_Var1 + 8) = pAVar2;
  }
  else if (param_2 == 0) {
    p_Var1 = AfxGetThreadState();
    AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var1 + 8));
  }
  return 1;
}



void __fastcall FUN_10004a09(undefined4 *param_1)

{
  *(undefined4 *)(param_1[1] + 4) = *param_1;
  return;
}



void __CxxFrameHandler(void)

{
                    // WARNING: Could not recover jumptable at 0x10004a12. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler();
  return;
}



void * __thiscall FUN_10004a20(void *this,byte param_1)

{
  type_info::~type_info((type_info *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void _CxxThrowException(void *pExceptionObject,ThrowInfo *pThrowInfo)

{
                    // WARNING: Could not recover jumptable at 0x10004a3c. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  _CxxThrowException(pExceptionObject,pThrowInfo);
  return;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x10004a42. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



char * __cdecl strcpy(char *_Dest,char *_Source)

{
  char *pcVar1;
  
                    // WARNING: Could not recover jumptable at 0x10004a48. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = strcpy(_Dest,_Source);
  return pcVar1;
}



void __cdecl ftol(void)

{
                    // WARNING: Could not recover jumptable at 0x10004a4e. Too many branches
                    // WARNING: Treating indirect jump as call
  ftol();
  return;
}



void FUN_10004a54(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_100052d0;
  puStack_10 = &DAT_10004d02;
  local_14 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_14;
  while( true ) {
    param_3 = param_3 + -1;
    if (param_3 < 0) break;
    (*(code *)param_4)();
  }
  local_8 = 0xffffffff;
  FUN_10004abc();
  ExceptionList = local_14;
  return;
}



void FUN_10004abc(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x1c) == 0) {
    FUN_10004ad4(*(undefined4 *)(unaff_EBP + 8),*(undefined4 *)(unaff_EBP + 0xc),
                 *(int *)(unaff_EBP + 0x10),*(undefined **)(unaff_EBP + 0x14));
  }
  return;
}



void FUN_10004ad4(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_100052e0;
  puStack_10 = &DAT_10004d02;
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



void __cdecl FUN_10004b48(_onexit_t param_1)

{
  if (DAT_10008218 == -1) {
    _onexit(param_1);
    return;
  }
  __dllonexit(param_1,&DAT_10008218,&DAT_10008214);
  return;
}



int __cdecl FUN_10004b74(_onexit_t param_1)

{
  int iVar1;
  
  iVar1 = FUN_10004b48(param_1);
  return (iVar1 != 0) - 1;
}



void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x10004b86. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}



int __cdecl strcmp(char *_Str1,char *_Str2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10004b8c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = strcmp(_Str1,_Str2);
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10004b92(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 *_Memory;
  undefined4 *puVar2;
  
  if (param_2 == 0) {
    if (0 < DAT_1000820c) {
      DAT_1000820c = DAT_1000820c + -1;
      goto LAB_10004ba8;
    }
LAB_10004bd0:
    uVar1 = 0;
  }
  else {
LAB_10004ba8:
    _DAT_10008210 = *(undefined4 *)_adjust_fdiv_exref;
    if (param_2 == 1) {
      DAT_10008218 = (undefined4 *)malloc(0x80);
      if (DAT_10008218 == (undefined4 *)0x0) goto LAB_10004bd0;
      *DAT_10008218 = 0;
      DAT_10008214 = DAT_10008218;
      initterm(&DAT_10007000,&DAT_1000700c);
      DAT_1000820c = DAT_1000820c + 1;
    }
    else if ((param_2 == 0) &&
            (_Memory = DAT_10008218, puVar2 = DAT_10008214, DAT_10008218 != (undefined4 *)0x0)) {
      while (puVar2 = puVar2 + -1, _Memory <= puVar2) {
        if ((code *)*puVar2 != (code *)0x0) {
          (*(code *)*puVar2)();
          _Memory = DAT_10008218;
        }
      }
      free(_Memory);
      DAT_10008218 = (undefined4 *)0x0;
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
  iVar2 = DAT_1000820c;
  if (param_2 != 0) {
    if ((param_2 != 1) && (param_2 != 2)) goto LAB_10004c85;
    if ((PTR_FUN_10007090 != (undefined *)0x0) &&
       (iVar2 = (*(code *)PTR_FUN_10007090)(param_1,param_2,param_3), iVar2 == 0)) {
      return 0;
    }
    iVar2 = FUN_10004b92(param_1,param_2);
  }
  if (iVar2 == 0) {
    return 0;
  }
LAB_10004c85:
  iVar2 = FUN_10004891(param_1,param_2);
  if (param_2 == 1) {
    if (iVar2 != 0) {
      return iVar2;
    }
    FUN_10004b92(param_1,0);
  }
  if ((param_2 != 0) && (param_2 != 3)) {
    return iVar2;
  }
  iVar3 = FUN_10004b92(param_1,param_2);
  param_2 = iVar2;
  if (iVar3 == 0) {
    param_2 = 0;
  }
  if (param_2 != 0) {
    if (PTR_FUN_10007090 != (undefined *)0x0) {
      iVar2 = (*(code *)PTR_FUN_10007090)(param_1,iVar1,param_3);
      return iVar2;
    }
    return param_2;
  }
  return 0;
}



void __thiscall type_info::~type_info(type_info *this)

{
                    // WARNING: Could not recover jumptable at 0x10004cfc. Too many branches
                    // WARNING: Treating indirect jump as call
  ~type_info(this);
  return;
}



void __dllonexit(void)

{
                    // WARNING: Could not recover jumptable at 0x10004d0e. Too many branches
                    // WARNING: Treating indirect jump as call
  __dllonexit();
  return;
}



void __cdecl initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x10004d14. Too many branches
                    // WARNING: Treating indirect jump as call
  initterm();
  return;
}



void CNoTrackObject::operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10004d20. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x10004d26. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



void __thiscall
AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(AFX_MAINTAIN_STATE2 *this,AFX_MODULE_STATE *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10004d32. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MAINTAIN_STATE2(this,param_1);
  return;
}



void AfxTermThread(HINSTANCE__ *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10004d38. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermThread(param_1);
  return;
}



void AfxTermExtensionModule(AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10004d3e. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermExtensionModule(param_1,param_2);
  return;
}



int AfxUnlockTempMaps(int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10004d44. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxUnlockTempMaps(param_1);
  return iVar1;
}



void AfxLockTempMaps(void)

{
                    // WARNING: Could not recover jumptable at 0x10004d4a. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxLockTempMaps();
  return;
}



AFX_MODULE_STATE * AfxSetModuleState(AFX_MODULE_STATE *param_1)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10004d50. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxSetModuleState(param_1);
  return pAVar1;
}



void __thiscall
CDynLinkLibrary::CDynLinkLibrary(CDynLinkLibrary *this,AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10004d56. Too many branches
                    // WARNING: Treating indirect jump as call
  CDynLinkLibrary(this,param_1,param_2);
  return;
}



int AfxInitExtensionModule(AFX_EXTENSION_MODULE *param_1,HINSTANCE__ *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10004d5c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxInitExtensionModule(param_1,param_2);
  return iVar1;
}



void AfxWinTerm(void)

{
                    // WARNING: Could not recover jumptable at 0x10004d62. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxWinTerm();
  return;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x10004d68. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



int AfxWinInit(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10004d6e. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinInit(param_1,param_2,param_3,param_4);
  return iVar1;
}



_AFX_THREAD_STATE * AfxGetThreadState(void)

{
  _AFX_THREAD_STATE *p_Var1;
  
                    // WARNING: Could not recover jumptable at 0x10004d74. Too many branches
                    // WARNING: Treating indirect jump as call
  p_Var1 = AfxGetThreadState();
  return p_Var1;
}



void AfxCoreInitModule(void)

{
                    // WARNING: Could not recover jumptable at 0x10004d7a. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxCoreInitModule();
  return;
}



int __fastcall FUN_10004d80(int param_1)

{
  return param_1 + 4;
}



void Unwind_10004da0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x1c) + 0x10));
  return;
}



void Unwind_10004dac(void)

{
  int unaff_EBP;
  
  FUN_10002870(*(void **)(unaff_EBP + -0x14));
  return;
}



void Unwind_10004dc0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x1c) + 0x10));
  return;
}



void Unwind_10004dd6(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(unaff_EBP + -0x5c));
  return;
}



void Unwind_10004de9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x888));
  return;
}



void Unwind_10004df5(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x990));
  return;
}



void Unwind_10004e01(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_10004e0a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_10004e13(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x994));
  return;
}



void Unwind_10004e30(void)

{
  int unaff_EBP;
  
  FUN_10002840(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10004e50(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x28));
  return;
}



void Unwind_10004e66(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x28));
  return;
}



void Unwind_10004e7c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x28));
  return;
}



void Unwind_10004e92(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x28));
  return;
}



void Unwind_10004ea8(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_10004eb1(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_10004eba(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x38));
  return;
}



void Unwind_10004ec3(void)

{
  int unaff_EBP;
  
  FUN_10004710((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_10004ecc(void)

{
  int unaff_EBP;
  
  FUN_10004710((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_10004ed5(void)

{
  int unaff_EBP;
  
  CFile::~CFile((CFile *)(unaff_EBP + -0x24));
  return;
}



void Unwind_10004ede(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_10004ef1(void)

{
  int unaff_EBP;
  
  FUN_10004520((undefined4 *)(unaff_EBP + -0x44));
  return;
}



void Unwind_10004f04(void)

{
  int unaff_EBP;
  
  FUN_10004520((undefined4 *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_10004f17(void)

{
  int unaff_EBP;
  
  FUN_10004520((undefined4 *)(unaff_EBP + -0x40));
  return;
}



void Unwind_10004f30(void)

{
  int unaff_EBP;
  
  FUN_10002840(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10004f50(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_10004f70(void)

{
  int unaff_EBP;
  
  FUN_10002840(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10004f84(void)

{
  int unaff_EBP;
  
  FUN_10004a09((undefined4 *)(unaff_EBP + -0x14));
  return;
}


