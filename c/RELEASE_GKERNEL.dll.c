typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
float10
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

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
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

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef ulong DWORD;

typedef void *LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

typedef HINSTANCE HMODULE;

typedef char CHAR;

typedef CHAR *LPCSTR;

typedef CHAR *LPSTR;

typedef long LONG_PTR;

typedef BOOL (*ENUMRESNAMEPROCA)(HMODULE, LPCSTR, LPSTR, LONG_PTR);

struct HINSTANCE__ {
    int unused;
};

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulong ULONG_PTR;

typedef union _union_518 _union_518, *P_union_518;

typedef void *HANDLE;

typedef struct _struct_519 _struct_519, *P_struct_519;

typedef void *PVOID;

struct _struct_519 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_518 {
    struct _struct_519 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_518 u;
    HANDLE hEvent;
};

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef DWORD ULONG;

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char *_ptr;
    int _cnt;
    char *_base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char *_tmpfname;
};

typedef struct _iobuf FILE;

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

typedef char *va_list;

typedef uint size_t;

typedef struct tagMSG tagMSG, *PtagMSG;

typedef struct tagMSG MSG;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

typedef uint UINT;

typedef uint UINT_PTR;

typedef UINT_PTR WPARAM;

typedef LONG_PTR LPARAM;

typedef struct tagPOINT tagPOINT, *PtagPOINT;

typedef struct tagPOINT POINT;

typedef long LONG;

struct tagPOINT {
    LONG x;
    LONG y;
};

struct tagMSG {
    HWND hwnd;
    UINT message;
    WPARAM wParam;
    LPARAM lParam;
    DWORD time;
    POINT pt;
};

struct HWND__ {
    int unused;
};

typedef struct tagWNDCLASSA tagWNDCLASSA, *PtagWNDCLASSA;

typedef LONG_PTR LRESULT;

typedef LRESULT (*WNDPROC)(HWND, UINT, WPARAM, LPARAM);

typedef struct HICON__ HICON__, *PHICON__;

typedef struct HICON__ *HICON;

typedef HICON HCURSOR;

typedef struct HBRUSH__ HBRUSH__, *PHBRUSH__;

typedef struct HBRUSH__ *HBRUSH;

struct HBRUSH__ {
    int unused;
};

struct tagWNDCLASSA {
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HCURSOR hCursor;
    HBRUSH hbrBackground;
    LPCSTR lpszMenuName;
    LPCSTR lpszClassName;
};

struct HICON__ {
    int unused;
};

typedef struct tagMSG *LPMSG;

typedef struct tagWNDCLASSA WNDCLASSA;

typedef struct _GUID _GUID, *P_GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};


// WARNING! conflicting data type names: /guiddef.h/GUID - /GUID

typedef GUID IID;

typedef struct _devicemodeA _devicemodeA, *P_devicemodeA;

typedef struct _devicemodeA DEVMODEA;

typedef uchar BYTE;

typedef ushort WORD;

typedef union _union_655 _union_655, *P_union_655;

typedef union _union_658 _union_658, *P_union_658;

typedef struct _struct_656 _struct_656, *P_struct_656;

typedef struct _struct_657 _struct_657, *P_struct_657;

typedef struct _POINTL _POINTL, *P_POINTL;

typedef struct _POINTL POINTL;

struct _POINTL {
    LONG x;
    LONG y;
};

struct _struct_657 {
    POINTL dmPosition;
    DWORD dmDisplayOrientation;
    DWORD dmDisplayFixedOutput;
};

struct _struct_656 {
    short dmOrientation;
    short dmPaperSize;
    short dmPaperLength;
    short dmPaperWidth;
    short dmScale;
    short dmCopies;
    short dmDefaultSource;
    short dmPrintQuality;
};

union _union_655 {
    struct _struct_656 field0;
    struct _struct_657 field1;
};

union _union_658 {
    DWORD dmDisplayFlags;
    DWORD dmNup;
};

struct _devicemodeA {
    BYTE dmDeviceName[32];
    WORD dmSpecVersion;
    WORD dmDriverVersion;
    WORD dmSize;
    WORD dmDriverExtra;
    DWORD dmFields;
    union _union_655 field6_0x2c;
    short dmColor;
    short dmDuplex;
    short dmYResolution;
    short dmTTOption;
    short dmCollate;
    BYTE dmFormName[32];
    WORD dmLogPixels;
    DWORD dmBitsPerPel;
    DWORD dmPelsWidth;
    DWORD dmPelsHeight;
    union _union_658 field17_0x74;
    DWORD dmDisplayFrequency;
    DWORD dmICMMethod;
    DWORD dmICMIntent;
    DWORD dmMediaType;
    DWORD dmDitherType;
    DWORD dmReserved1;
    DWORD dmReserved2;
    DWORD dmPanningWidth;
    DWORD dmPanningHeight;
};

typedef long HRESULT;

typedef DWORD ACCESS_MASK;

typedef short SHORT;

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

typedef int INT_PTR;

typedef ULONG_PTR SIZE_T;

typedef struct tagPOINT *LPPOINT;

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef HANDLE HLOCAL;

typedef struct tagRECT tagRECT, *PtagRECT;

typedef struct tagRECT RECT;

struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

typedef int (*FARPROC)(void);

typedef struct HDC__ HDC__, *PHDC__;

struct HDC__ {
    int unused;
};

typedef WORD ATOM;

typedef struct tagRECT *LPRECT;

typedef void *HGDIOBJ;

typedef struct HKEY__ *HKEY;

typedef DWORD COLORREF;

typedef DWORD *LPDWORD;

typedef void *LPCVOID;

typedef struct HMENU__ HMENU__, *PHMENU__;

typedef struct HMENU__ *HMENU;

struct HMENU__ {
    int unused;
};

typedef struct HDC__ *HDC;

typedef HKEY *PHKEY;

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

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
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

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
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

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
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

typedef ACCESS_MASK REGSAM;

typedef LONG LSTATUS;

typedef struct TwDialHand TwDialHand, *PTwDialHand;

struct TwDialHand { // PlaceHolder Structure
};

typedef struct CWinThread CWinThread, *PCWinThread;

struct CWinThread { // PlaceHolder Structure
};

typedef struct long_(__stdcall**)(struct_HWND__*,unsigned_int,unsigned_int,long) long_(__stdcall**)(struct_HWND__*,unsigned_int,unsigned_int,long), *Plong_(__stdcall**)(struct_HWND__*,unsigned_int,unsigned_int,long);

struct long_(__stdcall**)(struct_HWND__*,unsigned_int,unsigned_int,long) { // PlaceHolder Structure
};

typedef struct CArchive CArchive, *PCArchive;

struct CArchive { // PlaceHolder Structure
};

typedef struct _DDSURFACEDESC _DDSURFACEDESC, *P_DDSURFACEDESC;

struct _DDSURFACEDESC { // PlaceHolder Structure
};

typedef struct CDataExchange CDataExchange, *PCDataExchange;

struct CDataExchange { // PlaceHolder Structure
};

typedef struct AFX_EVENTSINKMAP AFX_EVENTSINKMAP, *PAFX_EVENTSINKMAP;

struct AFX_EVENTSINKMAP { // PlaceHolder Structure
};

typedef struct AFX_CONNECTIONMAP AFX_CONNECTIONMAP, *PAFX_CONNECTIONMAP;

struct AFX_CONNECTIONMAP { // PlaceHolder Structure
};

typedef struct AFX_CMDHANDLERINFO AFX_CMDHANDLERINFO, *PAFX_CMDHANDLERINFO;

struct AFX_CMDHANDLERINFO { // PlaceHolder Structure
};

typedef struct CMiniDockFrameWnd CMiniDockFrameWnd, *PCMiniDockFrameWnd;

struct CMiniDockFrameWnd { // PlaceHolder Structure
};

typedef struct TwLightning TwLightning, *PTwLightning;

struct TwLightning { // PlaceHolder Structure
};

typedef struct AFX_MAINTAIN_STATE2 AFX_MAINTAIN_STATE2, *PAFX_MAINTAIN_STATE2;

struct AFX_MAINTAIN_STATE2 { // PlaceHolder Structure
};

typedef struct CScrollBar CScrollBar, *PCScrollBar;

struct CScrollBar { // PlaceHolder Structure
};

typedef struct IDirectDrawPalette IDirectDrawPalette, *PIDirectDrawPalette;

struct IDirectDrawPalette { // PlaceHolder Structure
};

typedef struct tagVARIANT tagVARIANT, *PtagVARIANT;

struct tagVARIANT { // PlaceHolder Structure
};

typedef struct IConnectionPoint IConnectionPoint, *PIConnectionPoint;

struct IConnectionPoint { // PlaceHolder Structure
};

typedef struct AFX_DISPMAP AFX_DISPMAP, *PAFX_DISPMAP;

struct AFX_DISPMAP { // PlaceHolder Structure
};

typedef struct BUTTON BUTTON, *PBUTTON;

struct BUTTON { // PlaceHolder Structure
};

typedef struct CString CString, *PCString;

struct CString { // PlaceHolder Structure
};

typedef struct DD_SURFACE DD_SURFACE, *PDD_SURFACE;

struct DD_SURFACE { // PlaceHolder Structure
};

typedef struct CTypeLibCache CTypeLibCache, *PCTypeLibCache;

struct CTypeLibCache { // PlaceHolder Structure
};

typedef struct CTypeLibCacheMap CTypeLibCacheMap, *PCTypeLibCacheMap;

struct CTypeLibCacheMap { // PlaceHolder Structure
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef struct CPtrArray CPtrArray, *PCPtrArray;

struct CPtrArray { // PlaceHolder Structure
};

typedef struct CGdiObject CGdiObject, *PCGdiObject;

struct CGdiObject { // PlaceHolder Structure
};

typedef struct REG REG, *PREG;

struct REG { // PlaceHolder Structure
};

typedef struct CWinApp CWinApp, *PCWinApp;

struct CWinApp { // PlaceHolder Structure
};

typedef struct AFX_EXTENSION_MODULE AFX_EXTENSION_MODULE, *PAFX_EXTENSION_MODULE;

struct AFX_EXTENSION_MODULE { // PlaceHolder Structure
};

typedef struct GKERNEL GKERNEL, *PGKERNEL;

struct GKERNEL { // PlaceHolder Structure
};

typedef struct TwPixel TwPixel, *PTwPixel;

struct TwPixel { // PlaceHolder Structure
};

typedef struct LIST<unsigned_long> LIST<unsigned_long>, *PLIST<unsigned_long>;

struct LIST<unsigned_long> { // PlaceHolder Structure
};

typedef struct CBrush CBrush, *PCBrush;

struct CBrush { // PlaceHolder Structure
};

typedef struct TwLissajous TwLissajous, *PTwLissajous;

struct TwLissajous { // PlaceHolder Structure
};

typedef struct TwTransparentOverlay TwTransparentOverlay, *PTwTransparentOverlay;

struct TwTransparentOverlay { // PlaceHolder Structure
};

typedef struct CFont CFont, *PCFont;

struct CFont { // PlaceHolder Structure
};

typedef struct TwDisablableButton TwDisablableButton, *PTwDisablableButton;

struct TwDisablableButton { // PlaceHolder Structure
};

typedef struct CCmdTarget CCmdTarget, *PCCmdTarget;

struct CCmdTarget { // PlaceHolder Structure
};

typedef struct CException CException, *PCException;

struct CException { // PlaceHolder Structure
};

typedef struct CCreateContext CCreateContext, *PCCreateContext;

struct CCreateContext { // PlaceHolder Structure
};

typedef struct CPosition CPosition, *PCPosition;

struct CPosition { // PlaceHolder Structure
};

typedef struct ITypeLib ITypeLib, *PITypeLib;

struct ITypeLib { // PlaceHolder Structure
};

typedef struct TwDirectXDialog TwDirectXDialog, *PTwDirectXDialog;

struct TwDirectXDialog { // PlaceHolder Structure
};

typedef struct _AFX_OCC_DIALOG_INFO _AFX_OCC_DIALOG_INFO, *P_AFX_OCC_DIALOG_INFO;

struct _AFX_OCC_DIALOG_INFO { // PlaceHolder Structure
};

typedef struct SPRITE SPRITE, *PSPRITE;

struct SPRITE { // PlaceHolder Structure
};

typedef struct tagTOOLINFOA tagTOOLINFOA, *PtagTOOLINFOA;

struct tagTOOLINFOA { // PlaceHolder Structure
};

typedef struct _AFX_THREAD_STATE _AFX_THREAD_STATE, *P_AFX_THREAD_STATE;

struct _AFX_THREAD_STATE { // PlaceHolder Structure
};

typedef struct CPlex CPlex, *PCPlex;

struct CPlex { // PlaceHolder Structure
};

typedef struct CDynLinkLibrary CDynLinkLibrary, *PCDynLinkLibrary;

struct CDynLinkLibrary { // PlaceHolder Structure
};

typedef struct CDocument CDocument, *PCDocument;

struct CDocument { // PlaceHolder Structure
};

typedef struct AFX_OLECMDMAP AFX_OLECMDMAP, *PAFX_OLECMDMAP;

struct AFX_OLECMDMAP { // PlaceHolder Structure
};

typedef struct AFX_MODULE_STATE AFX_MODULE_STATE, *PAFX_MODULE_STATE;

struct AFX_MODULE_STATE { // PlaceHolder Structure
};

typedef struct AFX_MSGMAP_ENTRY AFX_MSGMAP_ENTRY, *PAFX_MSGMAP_ENTRY;

struct AFX_MSGMAP_ENTRY { // PlaceHolder Structure
};

typedef struct CDialog CDialog, *PCDialog;

struct CDialog { // PlaceHolder Structure
};

typedef struct COleControlSite COleControlSite, *PCOleControlSite;

struct COleControlSite { // PlaceHolder Structure
};

typedef struct CRuntimeClass CRuntimeClass, *PCRuntimeClass;

struct CRuntimeClass { // PlaceHolder Structure
};

typedef struct CWnd CWnd, *PCWnd;

struct CWnd { // PlaceHolder Structure
};

typedef struct OVERLAY OVERLAY, *POVERLAY;

struct OVERLAY { // PlaceHolder Structure
};

typedef struct AFX_INTERFACEMAP AFX_INTERFACEMAP, *PAFX_INTERFACEMAP;

struct AFX_INTERFACEMAP { // PlaceHolder Structure
};

typedef struct tagCREATESTRUCTA tagCREATESTRUCTA, *PtagCREATESTRUCTA;

struct tagCREATESTRUCTA { // PlaceHolder Structure
};

typedef struct AFX_MSGMAP AFX_MSGMAP, *PAFX_MSGMAP;

struct AFX_MSGMAP { // PlaceHolder Structure
};

typedef struct IDirectDrawSurface IDirectDrawSurface, *PIDirectDrawSurface;

struct IDirectDrawSurface { // PlaceHolder Structure
};

typedef struct TwAutoButton TwAutoButton, *PTwAutoButton;

struct TwAutoButton { // PlaceHolder Structure
};

typedef struct TwProgressBar TwProgressBar, *PTwProgressBar;

struct TwProgressBar { // PlaceHolder Structure
};

typedef struct GKGOBJ GKGOBJ, *PGKGOBJ;

struct GKGOBJ { // PlaceHolder Structure
};

typedef struct TIMER TIMER, *PTIMER;

struct TIMER { // PlaceHolder Structure
};

typedef struct GAME GAME, *PGAME;

struct GAME { // PlaceHolder Structure
};

typedef struct TwMapfile TwMapfile, *PTwMapfile;

struct TwMapfile { // PlaceHolder Structure
};

typedef struct TwHighlightButton TwHighlightButton, *PTwHighlightButton;

struct TwHighlightButton { // PlaceHolder Structure
};

typedef struct CObject CObject, *PCObject;

struct CObject { // PlaceHolder Structure
};

typedef struct CPen CPen, *PCPen;

struct CPen { // PlaceHolder Structure
};

typedef struct TwSinWave TwSinWave, *PTwSinWave;

struct TwSinWave { // PlaceHolder Structure
};

typedef struct CPoint CPoint, *PCPoint;

struct CPoint { // PlaceHolder Structure
};

typedef enum STYLE {
} STYLE;

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




// public: __thiscall TwDialHand::TwDialHand(void)

TwDialHand * __thiscall TwDialHand::TwDialHand(TwDialHand *this)

{
                    // 0x1000  5  ??0TwDialHand@@QAE@XZ
  TwTransparentOverlay::TwTransparentOverlay((TwTransparentOverlay *)this);
  *(undefined ***)this = &PTR_FUN_100113c4;
  *(undefined ***)(this + 8) = &PTR_FUN_100113c0;
  *(undefined4 *)(this + 0x178) = 0;
  *(undefined4 *)(this + 0x17c) = 0;
  *(undefined4 *)(this + 400) = 0;
  *(undefined4 *)(this + 0x16c) = 0;
  *(undefined4 *)(this + 0x170) = 0;
  *(undefined4 *)(this + 0x198) = 0;
  *(undefined4 *)(this + 0x19c) = 0;
  return this;
}



// public: void __thiscall TwDialHand::SetColor(unsigned long,unsigned long)

void __thiscall TwDialHand::SetColor(TwDialHand *this,ulong param_1,ulong param_2)

{
                    // 0x1081  143  ?SetColor@TwDialHand@@QAEXKK@Z
  *(ulong *)(this + 400) = param_1;
  *(ulong *)(this + 0x194) = param_2;
  return;
}



// public: virtual void __thiscall TwDialHand::DrawToBack(void)

void __thiscall TwDialHand::DrawToBack(TwDialHand *this)

{
  bool bVar1;
  HDC pHVar2;
  HGDIOBJ pvVar3;
  int iVar4;
  undefined3 extraout_var;
  ulong *puVar5;
  uint uVar6;
  undefined3 extraout_var_00;
  ulong uVar7;
  uint uVar8;
  int y;
  double dVar9;
  double dVar10;
  double dVar11;
  double in_stack_ffffff38;
  CPen local_64 [8];
  uint local_5c;
  HWND__ local_58;
  double local_54;
  HGDIOBJ local_4c;
  int local_48;
  int local_44;
  double local_40;
  ulong local_38;
  undefined4 local_34 [7];
  CPen local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
                    // 0x10a6  53  ?DrawToBack@TwDialHand@@UAEXXZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_1001071b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  TwTransparentOverlay::EraseInternalSurface((TwTransparentOverlay *)this);
  pHVar2 = DD_SURFACE::GetDC(&local_58);
  if (pHVar2 != (HDC)0x0) {
    TwColorTools::GetColorInterpolationsInclusive
              ((ulong)local_34,*(ulong *)(this + 0x194),*(uint *)(this + 400));
    local_8 = 0;
    FUN_10001850(local_34);
    local_48 = 0;
    CPen::CPen(local_18,0,1,0);
    local_8 = CONCAT31(local_8._1_3_,1);
    pvVar3 = (HGDIOBJ)FUN_10001c50((int)local_18);
    local_4c = SelectObject((HDC)local_58.unused,pvVar3);
    if (*(double *)(this + 0x188) != 0.0) {
      dVar11 = 0.01;
      dVar9 = fmod(*(double *)(this + 0x178),6.28318530717958);
      dVar10 = fmod(*(double *)(this + 0x180),6.28318530717958);
      iVar4 = fcomp(dVar10,dVar9,dVar11);
      if ((iVar4 == 0) && (*(int *)(this + 0x19c) == 0)) {
        if (*(int *)(this + 0x19c) == 0) {
          *(undefined4 *)(this + 0x188) = 0;
          *(undefined4 *)(this + 0x18c) = 0;
        }
      }
      else {
        *(double *)(this + 0x178) = *(double *)(this + 0x178) + *(double *)(this + 0x188);
      }
    }
    local_54 = ((double)*(uint *)(this + 0x170) * 3.14159265358979) / 180.0;
    dVar9 = RandomProb();
    local_40 = (dVar9 + dVar9) * local_54 - local_54;
    local_44 = FUN_1000e790((int)local_34);
    local_38 = 0;
    local_5c = 0;
    bVar1 = IsEmpty((int)local_34);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      puVar5 = (ulong *)FUN_100018b0(&local_44);
      local_38 = *puVar5;
    }
    local_5c = 0;
    while( true ) {
      pHVar2 = SUB84(in_stack_ffffff38,0);
      uVar6 = FUN_1000ff30((int)local_34);
      if ((uVar6 <= local_5c) ||
         (bVar1 = IsEmpty((int)local_34), CONCAT31(extraout_var_00,bVar1) != 0)) break;
      iVar4 = (*(int *)(this + 0x198) + 1) - local_48;
      uVar7 = TwTransparentOverlay::GetColor((TwTransparentOverlay *)this,local_38);
      CPen::CPen(local_64,0,iVar4,uVar7);
      local_8._0_1_ = 2;
      pvVar3 = (HGDIOBJ)FUN_10001c50((int)local_64);
      pvVar3 = SelectObject((HDC)local_58.unused,pvVar3);
      MoveToEx((HDC)local_58.unused,*(uint *)(this + 0xa4) >> 1,*(uint *)(this + 0xa8) >> 1,
               (LPPOINT)0x0);
      iVar4 = FUN_1000ff30((int)local_34);
      uVar8 = *(uint *)(this + 0x16c) / (uint)(iVar4 - local_48);
      uVar6 = *(uint *)(this + 0xa4);
      dVar9 = cos(local_40 + *(double *)(this + 0x178));
      iVar4 = round(dVar9 * (double)uVar8 + (double)uVar6 / 2.0);
      uVar6 = *(uint *)(this + 0xa8);
      in_stack_ffffff38 = (double)uVar8;
      dVar9 = sin(local_40 + *(double *)(this + 0x178));
      y = round((double)uVar6 / 2.0 - dVar9 * in_stack_ffffff38);
      LineTo((HDC)local_58.unused,iVar4,y);
      SelectObject((HDC)local_58.unused,pvVar3);
      local_48 = local_48 + 1;
      local_8 = CONCAT31(local_8._1_3_,1);
      FUN_10001c80((undefined4 *)local_64);
      local_5c = local_5c + 1;
      uVar6 = FUN_1000ff30((int)local_34);
      if (local_5c < uVar6) {
        puVar5 = (ulong *)FUN_100018b0(&local_44);
        local_38 = *puVar5;
      }
    }
    SelectObject((HDC)local_58.unused,local_4c);
    DD_SURFACE::ReleaseDC((HWND)local_58.unused,pHVar2);
    TwTransparentOverlay::DrawToBack((TwTransparentOverlay *)this);
    local_8 = local_8 & 0xffffff00;
    FUN_10001c80((undefined4 *)local_18);
    local_8 = 0xffffffff;
    FUN_10001810(local_34);
  }
  ExceptionList = local_10;
  return;
}



// public: void __thiscall TwDialHand::SetNoise(unsigned int)

void __thiscall TwDialHand::SetNoise(TwDialHand *this,uint param_1)

{
                    // 0x1501  156  ?SetNoise@TwDialHand@@QAEXI@Z
  *(uint *)(this + 0x170) = param_1;
  return;
}



// public: void __thiscall TwDialHand::SetRotation(int)

void __thiscall TwDialHand::SetRotation(TwDialHand *this,int param_1)

{
                    // 0x151a  174  ?SetRotation@TwDialHand@@QAEXH@Z
  *(double *)(this + 0x178) = ((double)param_1 * 3.14159265358979) / 180.0;
  *(undefined4 *)(this + 0x180) = *(undefined4 *)(this + 0x178);
  *(undefined4 *)(this + 0x184) = *(undefined4 *)(this + 0x17c);
  return;
}



// public: virtual void __thiscall TwDialHand::SetPosition(int,int)

void __thiscall TwDialHand::SetPosition(TwDialHand *this,int param_1,int param_2)

{
                    // 0x155d  171  ?SetPosition@TwDialHand@@UAEXHH@Z
  TwTransparentOverlay::SetPosition
            ((TwTransparentOverlay *)this,param_1 - (*(uint *)(this + 0xa4) >> 1),
             param_2 - (*(uint *)(this + 0xa8) >> 1));
  return;
}



// public: void __thiscall TwDialHand::SetLength(unsigned int)

void __thiscall TwDialHand::SetLength(TwDialHand *this,uint param_1)

{
                    // 0x1594  155  ?SetLength@TwDialHand@@QAEXI@Z
  if ((*(int *)(this + 0x198) + param_1) * 2 < *(uint *)(this + 0xa4)) {
    *(uint *)(this + 0x16c) = param_1;
  }
  return;
}



// public: void __thiscall TwDialHand::SetThickness(unsigned int)

void __thiscall TwDialHand::SetThickness(TwDialHand *this,uint param_1)

{
                    // 0x15ce  177  ?SetThickness@TwDialHand@@QAEXI@Z
  if ((param_1 + *(int *)(this + 0x16c)) * 2 < *(uint *)(this + 0xa4)) {
    *(uint *)(this + 0x198) = param_1;
  }
  return;
}



// public: void __thiscall TwDialHand::RotateAnimated(int,int,int,int)

void __thiscall
TwDialHand::RotateAnimated(TwDialHand *this,int param_1,int param_2,int param_3,int param_4)

{
  double dVar1;
  double dVar2;
  
                    // 0x1608  133  ?RotateAnimated@TwDialHand@@QAEXHHHH@Z
  *(double *)(this + 0x180) = ((double)param_1 * 3.14159265358979) / 180.0;
  *(double *)(this + 0x188) = ((double)param_2 * 3.14159265358979) / 180.0;
  *(int *)(this + 0x19c) = param_4;
  if (param_3 != 0) {
    dVar1 = fmod(*(double *)(this + 0x180),6.28318530717958);
    dVar2 = fmod(*(double *)(this + 0x178),6.28318530717958);
    dVar1 = fmod((dVar1 - dVar2) + 6.28318530717958,6.28318530717958);
    if ((3.14159265358979 < dVar1) && (0 < param_2)) {
      *(double *)(this + 0x188) = *(double *)(this + 0x188) * -1.0;
    }
  }
  return;
}



// public: void __thiscall TwDialHand::Rotate(int)

void __thiscall TwDialHand::Rotate(TwDialHand *this,int param_1)

{
                    // 0x16fe  132  ?Rotate@TwDialHand@@QAEXH@Z
  *(double *)(this + 0x178) =
       ((double)param_1 * 3.14159265358979) / 180.0 + *(double *)(this + 0x178);
  return;
}



// public: unsigned int __thiscall TwDialHand::CurrRotation(void)

uint __thiscall TwDialHand::CurrRotation(TwDialHand *this)

{
  uint uVar1;
  
                    // 0x1734  41  ?CurrRotation@TwDialHand@@QAEIXZ
  uVar1 = round((*(double *)(this + 0x178) / 3.14159265358979) * 180.0);
  return uVar1;
}



void * __thiscall FUN_10001770(void *this,uint param_1)

{
  FUN_100017a0((CMiniDockFrameWnd *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_100017a0(CMiniDockFrameWnd *param_1)

{
  CMiniDockFrameWnd::~CMiniDockFrameWnd(param_1);
  return;
}



// Library Function - Single Match
//  public: virtual __thiscall CMiniDockFrameWnd::~CMiniDockFrameWnd(void)
// 
// Library: Visual Studio 2003 Debug

void __thiscall CMiniDockFrameWnd::~CMiniDockFrameWnd(CMiniDockFrameWnd *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_100106e9;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(this + 0xd0));
  local_8 = 0xffffffff;
  FUN_10001ec0((undefined4 *)this);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10001810(undefined4 *param_1)

{
  FUN_100018e0(param_1);
  return;
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



undefined4 __fastcall FUN_10001850(void *param_1)

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
  FUN_10001af0(param_1,puVar1);
  return uVar2;
}



int FUN_100018b0(int *param_1)

{
  int *piVar1;
  
  piVar1 = (int *)*param_1;
  *param_1 = *piVar1;
  return (int)(piVar1 + 2);
}



void __fastcall FUN_100018e0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_10010739;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_10011440;
  local_8 = 0;
  FUN_10001a70((int)param_1);
  local_8 = 0xffffffff;
  FUN_10001bb0(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_10001940(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_10;
  ulong local_c;
  undefined4 *local_8;
  
  FUN_10001c00();
  bVar1 = FUN_10001c30((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      FUN_10001b40(param_1,&local_10,1);
      FUN_10001a10(this,&local_10);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_10001b40(param_1,local_8 + 2,1);
    }
  }
  return;
}



void * __thiscall FUN_100019e0(void *this,uint param_1)

{
  FUN_100018e0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001c10(this);
  }
  return this;
}



undefined4 * __thiscall FUN_10001a10(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_10007e50(this,*(undefined4 *)((int)this + 8),0);
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



void __fastcall FUN_10001a70(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_10001b80(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



void __thiscall FUN_10001af0(void *this,undefined4 *param_1)

{
  FUN_10001b80(param_1 + 2,1);
  *param_1 = *(undefined4 *)((int)this + 0x10);
  *(undefined4 **)((int)this + 0x10) = param_1;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + -1;
  if (*(int *)((int)this + 0xc) == 0) {
    FUN_10001a70((int)this);
  }
  return;
}



void FUN_10001b40(CArchive *param_1,void *param_2,int param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_10001c30((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    CArchive::Read(param_1,param_2,param_3 << 2);
  }
  else {
    CArchive::Write(param_1,param_2,param_3 << 2);
  }
  return;
}



void FUN_10001b80(undefined4 param_1,int param_2)

{
  bool bVar1;
  
  do {
    bVar1 = param_2 != 0;
    param_2 = param_2 + -1;
  } while (bVar1);
  return;
}



void __fastcall FUN_10001bb0(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_10011454;
  return;
}



void * __thiscall FUN_10001bd0(void *this,uint param_1)

{
  FUN_10001bb0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001c10(this);
  }
  return this;
}



void FUN_10001c00(void)

{
  return;
}



void FUN_10001c10(void *param_1)

{
  operator_delete(param_1);
  return;
}



bool __fastcall FUN_10001c30(int param_1)

{
  return (bool)('\x01' - ((*(uint *)(param_1 + 0x14) & 1) != 0));
}



undefined4 __fastcall FUN_10001c50(int param_1)

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



void __fastcall FUN_10001c80(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_10011468;
  FUN_10001ca0(param_1);
  return;
}



void __fastcall FUN_10001ca0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_10010759;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_1001147c;
  local_8 = 0;
  CGdiObject::DeleteObject(param_1);
  local_8 = 0xffffffff;
  FUN_10001bb0(param_1);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_10001d00(void *this,uint param_1)

{
  FUN_10001ca0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001c10(this);
  }
  return this;
}



void * __thiscall FUN_10001d30(void *this,uint param_1)

{
  FUN_10001c80((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001c10(this);
  }
  return this;
}



undefined4 __cdecl FUN_10001d60(undefined4 param_1,undefined4 param_2)

{
  return param_2;
}



// public: static unsigned int __cdecl GKERNEL::GetTotalVideoMemory(void)

uint __cdecl GKERNEL::GetTotalVideoMemory(void)

{
                    // 0x1d70  82  ?GetTotalVideoMemory@GKERNEL@@SAIXZ
  return DAT_1001b4f8;
}



// public: static void __cdecl GKERNEL::RegisterThis(class GAME *)

void __cdecl GKERNEL::RegisterThis(GAME *param_1)

{
                    // 0x1d80  124  ?RegisterThis@GKERNEL@@SAXPAVGAME@@@Z
  DAT_1001b36c = param_1;
  return;
}



void FUN_10001d90(void)

{
  return;
}



void __fastcall FUN_10001da0(int param_1)

{
  *(undefined1 *)(param_1 + 0xcc) = 1;
  return;
}



void __fastcall FUN_10001dc0(int param_1)

{
  *(undefined1 *)(param_1 + 0xcc) = 0;
  return;
}



// public: int __thiscall OVERLAY::GetXPos(void)

int __thiscall OVERLAY::GetXPos(OVERLAY *this)

{
                    // 0x1de0  83  ?GetXPos@OVERLAY@@QAEHXZ
  return *(int *)(this + 0xb4);
}



// public: int __thiscall OVERLAY::GetYPos(void)

int __thiscall OVERLAY::GetYPos(OVERLAY *this)

{
                    // 0x1e00  85  ?GetYPos@OVERLAY@@QAEHXZ
  return *(int *)(this + 0xb8);
}



// public: struct CPosition __thiscall OVERLAY::Position(void)const 

void * __thiscall OVERLAY::Position(OVERLAY *this)

{
  void *in_stack_00000004;
  
                    // 0x1e20  120  ?Position@OVERLAY@@QBE?AUCPosition@@XZ
  default_error_condition
            (in_stack_00000004,*(undefined4 *)(this + 0xb4),*(undefined4 *)(this + 0xb8));
  return in_stack_00000004;
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
  FUN_10001e70(this,param_1,param_2);
  return this;
}



void * __thiscall FUN_10001e70(void *this,undefined4 param_1,undefined4 param_2)

{
  *(undefined4 *)this = param_1;
  *(undefined4 *)((int)this + 4) = param_2;
  return this;
}



undefined1 __fastcall FUN_10001ea0(int param_1)

{
  return *(undefined1 *)(param_1 + 0xa0);
}



void __fastcall FUN_10001ec0(undefined4 *param_1)

{
  DD_SURFACE *local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_10010779;
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
  FUN_10001f30(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10001f30(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_10011490;
  return;
}



void * __thiscall FUN_10001f50(void *this,uint param_1)

{
  FUN_10001f30((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



// public: virtual void __thiscall SPRITE::SetPosition(struct CPosition const &)

void __thiscall SPRITE::SetPosition(SPRITE *this,CPosition *param_1)

{
                    // 0x1f80  169  ?SetPosition@SPRITE@@UAEXABUCPosition@@@Z
  (**(code **)(*(int *)this + 0x2c))(*(undefined4 *)param_1,*(undefined4 *)(param_1 + 4));
  return;
}



// public: bool __thiscall SPRITE::InMotion(void)const 

bool __thiscall SPRITE::InMotion(SPRITE *this)

{
  char cVar1;
  bool local_c;
  
                    // 0x1fb0  89  ?InMotion@SPRITE@@QBE_NXZ
  cVar1 = FUN_10002000(this + 0xe0);
  if (((cVar1 == '\0') && (*(int *)(this + 0xd0) == 0)) && (*(int *)(this + 0xd4) == 0)) {
    local_c = false;
  }
  else {
    local_c = true;
  }
  return local_c;
}



undefined1 __fastcall FUN_10002000(undefined1 *param_1)

{
  return *param_1;
}



// public: virtual bool __thiscall SPRITE::IsVisible(void)

bool __thiscall SPRITE::IsVisible(SPRITE *this)

{
                    // 0x2010  109  ?IsVisible@SPRITE@@UAE_NXZ
  return (bool)this[0xcc];
}



// public: __thiscall TwHighlightButton::TwHighlightButton(void)

TwHighlightButton * __thiscall TwHighlightButton::TwHighlightButton(TwHighlightButton *this)

{
                    // 0x2030  7  ??0TwHighlightButton@@QAE@XZ
  FUN_10002330((OVERLAY *)this);
  *(undefined ***)this = &PTR_FUN_100114bc;
  *(undefined ***)(this + 8) = &PTR_OnRestore_100114b8;
  *(undefined4 *)(this + 0x17c) = 0;
  *(undefined4 *)(this + 0x180) = 0;
  *(undefined4 *)(this + 0x184) = 3;
  return this;
}



// public: void __thiscall TwHighlightButton::AutoHighlight(void)

void __thiscall TwHighlightButton::AutoHighlight(TwHighlightButton *this)

{
  char cVar1;
  
                    // 0x2080  21  ?AutoHighlight@TwHighlightButton@@QAEXXZ
  cVar1 = (**(code **)(*(int *)this + 0x18))();
  if (cVar1 != '\0') {
    cVar1 = (**(code **)(*(int *)this + 0x44))();
    if (cVar1 == '\0') {
      SetHighlightOn(this,0);
    }
    else {
      SetHighlightOn(this,1);
    }
  }
  return;
}



// private: virtual void __thiscall TwHighlightButton::OnRestore(bool)

void __thiscall TwHighlightButton::OnRestore(TwHighlightButton *this,bool param_1)

{
                    // 0x20cb  118  ?OnRestore@TwHighlightButton@@EAEX_N@Z
  FUN_10001c00();
  if (*(int *)(this + 0x174) != 0) {
    FUN_10002148((int)(this + -8));
  }
  return;
}



// public: void __thiscall TwHighlightButton::SetHighlightOn(int)

void __thiscall TwHighlightButton::SetHighlightOn(TwHighlightButton *this,int param_1)

{
  bool bVar1;
  
                    // 0x20fb  153  ?SetHighlightOn@TwHighlightButton@@QAEXH@Z
  bVar1 = FUN_10002300((int *)(this + 0x17c),param_1);
  if (bVar1) {
    FUN_10002148((int)this);
  }
  return;
}



// public: void __thiscall TwHighlightButton::SetHighlightStyle(enum TwHighlightButton::STYLE)

void __thiscall TwHighlightButton::SetHighlightStyle(TwHighlightButton *this,STYLE param_1)

{
                    // 0x212f  154  ?SetHighlightStyle@TwHighlightButton@@QAEXW4STYLE@1@@Z
  *(STYLE *)(this + 0x180) = param_1;
  return;
}



void __fastcall FUN_10002148(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x180);
  if (iVar1 == 0) {
    FUN_1000219d(param_1,0,1);
  }
  else if (iVar1 == 1) {
    FUN_1000219d(param_1,2,1);
  }
  else if (iVar1 == 2) {
    FUN_1000219d(param_1,0,2);
  }
  return;
}



void __thiscall FUN_1000219d(HDC param_1_00,int param_2,int param_3)

{
  HDC pHVar1;
  uint local_c;
  HWND__ local_8;
  
  pHVar1 = DD_SURFACE::GetDC(&local_8);
  if (pHVar1 != (HDC)0x0) {
    if (((uint)param_1_00[0x61].unused >> 1 <=
         (uint)((param_1_00[0x29].unused - param_2) - param_3 * param_1_00[0x61].unused)) &&
       ((uint)param_1_00[0x61].unused >> 1 <=
        (uint)((param_1_00[0x2a].unused - param_2) - param_3 * param_1_00[0x61].unused))) {
      for (local_c = 0; local_c < (uint)param_1_00[0x61].unused; local_c = local_c + 1) {
        TwPrimitives::DrawInvertedRectangle
                  ((HDC__ *)local_8.unused,local_c * param_3 + param_2,local_c * param_3 + param_2,
                   ((param_1_00[0x29].unused - local_c * param_3) - param_2) - 1,
                   ((param_1_00[0x2a].unused - local_c * param_3) - param_2) - 1);
      }
    }
    DD_SURFACE::ReleaseDC((HWND)local_8.unused,param_1_00);
  }
  return;
}



void * __thiscall FUN_100022b0(void *this,uint param_1)

{
  FUN_100022e0((CMiniDockFrameWnd *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_100022e0(CMiniDockFrameWnd *param_1)

{
  CMiniDockFrameWnd::~CMiniDockFrameWnd(param_1);
  return;
}



bool __cdecl FUN_10002300(int *param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *param_1;
  *param_1 = param_2;
  return iVar1 != param_2;
}



OVERLAY * __fastcall FUN_10002330(OVERLAY *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100107a8;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  OVERLAY::OVERLAY(param_1);
  local_8 = 0;
  FUN_100023b0((DWORD *)(param_1 + 0xd0));
  DD_SURFACE::DD_SURFACE((DD_SURFACE *)(param_1 + 0xdc));
  local_8 = CONCAT31(local_8._1_3_,1);
  *(undefined ***)param_1 = &PTR_FUN_10011510;
  *(undefined ***)(param_1 + 8) = &PTR_FUN_1001150c;
  FUN_100023d0((int)param_1);
  ExceptionList = local_10;
  return param_1;
}



DWORD * __fastcall FUN_100023b0(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
  return param_1;
}



void __fastcall FUN_100023d0(int param_1)

{
  *(undefined4 *)(param_1 + 0xd4) = 0;
  FUN_100023f0(param_1);
  return;
}



void __fastcall FUN_100023f0(int param_1)

{
  *(undefined4 *)(param_1 + 0x178) = 1;
  *(undefined4 *)(param_1 + 0x174) = 0;
  return;
}



void * __thiscall FUN_10002420(void *this,uint param_1)

{
  CMiniDockFrameWnd::~CMiniDockFrameWnd((CMiniDockFrameWnd *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



// Library Function - Single Match
//  public: virtual __thiscall CMiniDockFrameWnd::~CMiniDockFrameWnd(void)
// 
// Library: Visual Studio 2003 Debug

void __thiscall CMiniDockFrameWnd::~CMiniDockFrameWnd(CMiniDockFrameWnd *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_100107c9;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(this + 0xdc));
  local_8 = 0xffffffff;
  FUN_10001ec0((undefined4 *)this);
  ExceptionList = local_10;
  return;
}



void FUN_100024a0(void)

{
  FUN_100024aa();
  return;
}



void FUN_100024aa(void)

{
  FUN_10003d00(&DAT_10018f68,0x50,3,FUN_10004040);
  return;
}



// public: __thiscall TwLightning::TwLightning(void)

TwLightning * __thiscall TwLightning::TwLightning(TwLightning *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x24c2  8  ??0TwLightning@@QAE@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_100107f8;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  TwTransparentOverlay::TwTransparentOverlay((TwTransparentOverlay *)this);
  local_8 = 0;
  FUN_10004040((float *)(this + 0x170));
  FUN_10003d00(this + 0x1c8,0xc,0x100,FUN_10006b80);
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)(this + 0xdd4));
  local_8 = CONCAT31(local_8._1_3_,1);
  FUN_100023b0((DWORD *)(this + 0xdf0));
  FUN_100023b0((DWORD *)(this + 0xdf4));
  FUN_100023b0((DWORD *)(this + 0xdf8));
  *(undefined ***)this = &PTR_FUN_10011564;
  *(undefined ***)(this + 8) = &PTR_FUN_10011560;
  *(undefined4 *)(this + 0x16c) = 1;
  *(undefined4 *)(this + 0xdc8) = 0;
  *(undefined4 *)(this + 0xdfc) = 0;
  *(undefined4 *)(this + 0xe04) = 0;
  ExceptionList = local_10;
  return this;
}



// public: virtual __thiscall TwLightning::~TwLightning(void)

void __thiscall TwLightning::~TwLightning(TwLightning *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x25b0  16  ??1TwLightning@@UAE@XZ
  puStack_c = &LAB_1001080b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)this = &PTR_FUN_10011564;
  *(undefined ***)(this + 8) = &PTR_FUN_10011560;
  local_8 = 0;
  if (*(int *)(this + 0xdc8) != 0) {
    free(*(void **)(this + 0xdc8));
  }
  if (*(int *)(this + 0xdfc) != 0) {
    free(*(void **)(this + 0xdfc));
  }
  if (*(int *)(this + 0xe04) != 0) {
    free(*(void **)(this + 0xe04));
  }
  FUN_10001810((undefined4 *)(this + 0xdd4));
  local_8 = 0xffffffff;
  CMiniDockFrameWnd::~CMiniDockFrameWnd((CMiniDockFrameWnd *)this);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_1000266e(int param_1)

{
  *(uint *)(param_1 + 0x34) = *(uint *)(param_1 + 0x3c) >> 1;
  *(uint *)(param_1 + 0x38) = *(uint *)(param_1 + 0x40) >> 1;
  if (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x24)) {
    *(float *)(param_1 + 0x20) = *(float *)(param_1 + 0x1c) / (float)*(uint *)(param_1 + 0x3c);
    *(float *)(param_1 + 0x18) =
         1.0 - ((*(float *)(param_1 + 0xc) / (float)*(uint *)(param_1 + 0x3c)) /
               *(float *)(param_1 + 0xc)) / 10.0;
  }
  else {
    *(float *)(param_1 + 0x20) = *(float *)(param_1 + 0x1c) / (float)*(uint *)(param_1 + 0x40);
    *(float *)(param_1 + 0x18) =
         1.0 - ((*(float *)(param_1 + 0xc) / (float)*(uint *)(param_1 + 0x40)) /
               *(float *)(param_1 + 0xc)) / 10.0;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// public: void __thiscall TwLightning::Init(unsigned int,unsigned int,unsigned long,unsigned long)

void __thiscall
TwLightning::Init(TwLightning *this,uint param_1,uint param_2,ulong param_3,ulong param_4)

{
  int iVar1;
  int iVar2;
  void *pvVar3;
  uint uVar4;
  double dVar5;
  uint local_8;
  
                    // 0x2747  99  ?Init@TwLightning@@QAEXIIKK@Z
  TwTransparentOverlay::Init((TwTransparentOverlay *)this,param_1,param_2);
  SetColor(this,param_3,param_4);
  DAT_10019044 = param_1;
  DAT_10018ff4 = param_1;
  DAT_10018fa4 = param_1;
  *(uint *)(this + 0x1ac) = param_1;
  DAT_10019048 = param_2;
  DAT_10018ff8 = param_2;
  DAT_10018fa8 = param_2;
  *(uint *)(this + 0x1b0) = param_2;
  _DAT_10018f94 = 4;
  DAT_10019054 = 1;
  _DAT_10019034 = 1;
  _DAT_1001902c = 0;
  _DAT_10019030 = 1;
  dVar5 = RandomProb();
  _DAT_10019008 = (float)dVar5 * 35.0 + 35.0;
  FUN_1000266e(0x10018fb8);
  FUN_1000266e((int)(this + 0x170));
  FUN_1000266e(0x10018f68);
  FUN_1000266e(0x10018fb8);
  FUN_1000266e(0x10019008);
  if (*(int *)(this + 0xdc8) != 0) {
    free(*(void **)(this + 0xdc8));
    *(undefined4 *)(this + 0xdc8) = 0;
  }
  if (*(int *)(this + 0xdfc) != 0) {
    free(*(void **)(this + 0xdfc));
    *(undefined4 *)(this + 0xdfc) = 0;
  }
  if (*(int *)(this + 0xe04) != 0) {
    free(*(void **)(this + 0xe04));
    *(undefined4 *)(this + 0xe04) = 0;
  }
  iVar1 = FUN_10004000((int)this);
  iVar2 = FUN_10004020((int)this);
  pvVar3 = malloc(iVar1 * iVar2 * 0xc);
  *(void **)(this + 0xdc8) = pvVar3;
  iVar1 = FUN_10004000((int)this);
  iVar2 = FUN_10004020((int)this);
  pvVar3 = malloc(iVar1 * iVar2 * 4);
  *(void **)(this + 0xdfc) = pvVar3;
  iVar1 = FUN_10004000((int)this);
  pvVar3 = malloc(iVar1 << 2);
  *(void **)(this + 0xe04) = pvVar3;
  for (local_8 = 0; uVar4 = FUN_10004000((int)this), local_8 < uVar4; local_8 = local_8 + 1) {
    iVar1 = FUN_10004020((int)this);
    *(uint *)(*(int *)(this + 0xe04) + local_8 * 4) = *(int *)(this + 0xdfc) + local_8 * iVar1 * 4;
  }
  iVar1 = FUN_10004000((int)this);
  iVar2 = FUN_10004020((int)this);
  memset(*(void **)(this + 0xdfc),0,iVar1 * iVar2 * 4);
  FUN_10003fa0((DWORD *)(this + 0xdf4));
  TwTransparentOverlay::EraseInternalSurface((TwTransparentOverlay *)this);
  return;
}



// public: void __thiscall TwLightning::SetColor(unsigned long,unsigned long)

void __thiscall TwLightning::SetColor(TwLightning *this,ulong param_1,ulong param_2)

{
  void *pvVar1;
  ulong *puVar2;
  ulong uVar3;
  undefined4 local_30 [7];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x29ec  144  ?SetColor@TwLightning@@QAEXKK@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1001081e;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(ulong *)(this + 0x1b8) = param_2;
  *(ulong *)(this + 0x1b4) = param_1;
  pvVar1 = (void *)TwColorTools::GetColorInterpolationsInclusive((ulong)local_30,param_2,param_1);
  local_8 = 0;
  FUN_10003d90(this + 0xdd4,pvVar1);
  local_8 = 0xffffffff;
  FUN_10001810(local_30);
  for (local_14 = 0; local_14 < 0x100; local_14 = local_14 + 1) {
    puVar2 = (ulong *)FUN_10003dd0(this + 0xdd4,local_14);
    uVar3 = TwTransparentOverlay::GetColor((TwTransparentOverlay *)this,*puVar2);
    this[local_14 * 0xc + 0x1c8] = SUB41(uVar3,0);
    puVar2 = (ulong *)FUN_10003dd0(this + 0xdd4,local_14);
    uVar3 = TwTransparentOverlay::GetColor((TwTransparentOverlay *)this,*puVar2);
    this[local_14 * 0xc + 0x1c9] = SUB41(uVar3 >> 8,0);
    puVar2 = (ulong *)FUN_10003dd0(this + 0xdd4,local_14);
    uVar3 = TwTransparentOverlay::GetColor((TwTransparentOverlay *)this,*puVar2);
    this[local_14 * 0xc + 0x1ca] = SUB41(uVar3 >> 0x10,0);
  }
  ExceptionList = local_10;
  return;
}



// public: void __thiscall TwLightning::SetFramesPerSecond(unsigned long)

void __thiscall TwLightning::SetFramesPerSecond(TwLightning *this,ulong param_1)

{
                    // 0x2b33  150  ?SetFramesPerSecond@TwLightning@@QAEXK@Z
  if (param_1 == 0) {
    *(undefined4 *)(this + 0xdcc) = 0xffffffff;
  }
  else {
    *(int *)(this + 0xdcc) = (int)(1000 / (ulonglong)param_1);
    FUN_10003fa0((DWORD *)(this + 0xdf0));
  }
  return;
}



void __thiscall FUN_10002b76(void *this,float param_1,int param_2,int param_3)

{
  int iVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  int local_28;
  int local_1c;
  int local_8;
  
  if ((((*(int *)((int)this + 0x194) != -1) || (param_2 != 1)) &&
      ((*(int *)((int)this + 0x194) != 1 || (iVar1 = FUN_10004000((int)this), param_2 != iVar1 + -1)
       ))) && ((param_3 != 0 && (iVar1 = FUN_10004020((int)this), param_3 != iVar1)))) {
    if (10.0 < param_1 / 1.0) {
      *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + param_3 * 4) =
           param_1 / 1.0 +
           *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + param_3 * 4);
    }
    if (*(float *)((int)this + 0x178) <
        *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + param_3 * 4)) {
      *(undefined4 *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + param_3 * 4) =
           *(undefined4 *)((int)this + 0x178);
    }
    if (10.0 < param_1 / 2.0) {
      *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -4 + param_3 * 4) =
           param_1 / 2.0 +
           *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -4 + param_3 * 4);
    }
    if (*(float *)((int)this + 0x178) <
        *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -4 + param_3 * 4)) {
      *(undefined4 *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -4 + param_3 * 4) =
           *(undefined4 *)((int)this + 0x178);
    }
    if (10.0 < param_1 / 2.0) {
      *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 4 + param_3 * 4) =
           param_1 / 2.0 +
           *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 4 + param_3 * 4);
    }
    if (*(float *)((int)this + 0x178) <
        *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 4 + param_3 * 4)) {
      *(undefined4 *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 4 + param_3 * 4) =
           *(undefined4 *)((int)this + 0x178);
    }
    if (10.0 < param_1 / 4.0) {
      *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -8 + param_3 * 4) =
           param_1 / 4.0 +
           *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -8 + param_3 * 4);
    }
    if (*(float *)((int)this + 0x178) <
        *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -8 + param_3 * 4)) {
      *(undefined4 *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -8 + param_3 * 4) =
           *(undefined4 *)((int)this + 0x178);
    }
    if (10.0 < param_1 / 4.0) {
      *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 8 + param_3 * 4) =
           param_1 / 4.0 +
           *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 8 + param_3 * 4);
    }
    if (*(float *)((int)this + 0x178) <
        *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 8 + param_3 * 4)) {
      *(undefined4 *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 8 + param_3 * 4) =
           *(undefined4 *)((int)this + 0x178);
    }
    if (10.0 < param_1 / 8.0) {
      *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -0xc + param_3 * 4) =
           param_1 / 8.0 +
           *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -0xc + param_3 * 4);
    }
    if (*(float *)((int)this + 0x178) <
        *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -0xc + param_3 * 4)) {
      *(undefined4 *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -0xc + param_3 * 4) =
           *(undefined4 *)((int)this + 0x178);
    }
    if (10.0 < param_1 / 8.0) {
      *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 0xc + param_3 * 4) =
           param_1 / 8.0 +
           *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 0xc + param_3 * 4);
    }
    if (*(float *)((int)this + 0x178) <
        *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 0xc + param_3 * 4)) {
      *(undefined4 *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 0xc + param_3 * 4) =
           *(undefined4 *)((int)this + 0x178);
    }
    if (10.0 < param_1 / 16.0) {
      *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -0x10 + param_3 * 4) =
           param_1 / 16.0 +
           *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -0x10 + param_3 * 4);
    }
    if (*(float *)((int)this + 0x178) <
        *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -0x10 + param_3 * 4)) {
      *(undefined4 *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -0x10 + param_3 * 4) =
           *(undefined4 *)((int)this + 0x178);
    }
    if (10.0 < param_1 / 16.0) {
      *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 0x10 + param_3 * 4) =
           param_1 / 16.0 +
           *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 0x10 + param_3 * 4);
    }
    if (*(float *)((int)this + 0x178) <
        *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 0x10 + param_3 * 4)) {
      *(undefined4 *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 0x10 + param_3 * 4) =
           *(undefined4 *)((int)this + 0x178);
    }
    dVar2 = RandomProb();
    dVar3 = RandomProb();
    dVar4 = RandomProb();
    if ((dVar2 <= dVar3) || (dVar2 <= dVar4)) {
      if ((dVar3 <= dVar2) || (dVar3 <= dVar4)) {
        local_1c = param_3 + 1;
        local_28 = param_3;
        local_8 = param_3 + -1;
      }
      else {
        local_1c = param_3;
        local_28 = param_3 + -1;
        local_8 = param_3 + 1;
      }
    }
    else {
      local_1c = param_3 + -1;
      local_28 = param_3;
      local_8 = param_3 + 1;
    }
    param_1 = param_1 * *(float *)((int)this + 0x188);
    dVar2 = RandomProb();
    if (dVar2 < (double)*(float *)((int)this + 400)) {
      param_1 = param_1 / 2.0;
      *(float *)((int)this + 400) = *(float *)((int)this + 400) / 2.0;
      dVar2 = RandomProb();
      if (0.5 <= dVar2) {
        FUN_10002b76(this,param_1,param_2 + *(int *)((int)this + 0x194),local_8);
      }
      else {
        FUN_10002b76(this,param_1,param_2 + *(int *)((int)this + 0x194),local_28);
      }
    }
    FUN_10002b76(this,param_1,param_2 + *(int *)((int)this + 0x194),local_1c);
  }
  return;
}



void __thiscall FUN_1000323e(void *this,float param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  int iVar3;
  double dVar4;
  int local_1c;
  int local_14;
  int local_8;
  
  if ((((*(int *)((int)this + 0x198) != -1) || (param_3 != 0)) &&
      ((*(int *)((int)this + 0x198) != 1 || (iVar3 = FUN_10004020((int)this), param_3 != iVar3 + -1)
       ))) && ((param_2 != 0 && (iVar3 = FUN_10004000((int)this), param_2 != iVar3)))) {
    if (10.0 < param_1 / 1.0) {
      *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + param_3 * 4) =
           param_1 / 1.0 +
           *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + param_3 * 4);
    }
    if (*(float *)((int)this + 0x178) <
        *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + param_3 * 4)) {
      *(undefined4 *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + param_3 * 4) =
           *(undefined4 *)((int)this + 0x178);
    }
    if (10.0 < param_1 / 1.5) {
      *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -4 + param_3 * 4) =
           param_1 / 1.5 +
           *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -4 + param_3 * 4);
    }
    if (*(float *)((int)this + 0x178) <
        *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -4 + param_3 * 4)) {
      *(undefined4 *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -4 + param_3 * 4) =
           *(undefined4 *)((int)this + 0x178);
    }
    if (10.0 < param_1 / 1.5) {
      *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 4 + param_3 * 4) =
           param_1 / 1.5 +
           *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 4 + param_3 * 4);
    }
    if (*(float *)((int)this + 0x178) <
        *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 4 + param_3 * 4)) {
      *(undefined4 *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 4 + param_3 * 4) =
           *(undefined4 *)((int)this + 0x178);
    }
    if (10.0 < param_1 / 3.0) {
      *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -8 + param_3 * 4) =
           param_1 / 3.0 +
           *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -8 + param_3 * 4);
    }
    if (*(float *)((int)this + 0x178) <
        *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -8 + param_3 * 4)) {
      *(undefined4 *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -8 + param_3 * 4) =
           *(undefined4 *)((int)this + 0x178);
    }
    if (10.0 < param_1 / 3.0) {
      *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 8 + param_3 * 4) =
           param_1 / 3.0 +
           *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 8 + param_3 * 4);
    }
    if (*(float *)((int)this + 0x178) <
        *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 8 + param_3 * 4)) {
      *(undefined4 *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 8 + param_3 * 4) =
           *(undefined4 *)((int)this + 0x178);
    }
    if (10.0 < param_1 / 6.0) {
      *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -0xc + param_3 * 4) =
           param_1 / 6.0 +
           *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -0xc + param_3 * 4);
    }
    if (*(float *)((int)this + 0x178) <
        *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -0xc + param_3 * 4)) {
      *(undefined4 *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + -0xc + param_3 * 4) =
           *(undefined4 *)((int)this + 0x178);
    }
    if (10.0 < param_1 / 6.0) {
      *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 0xc + param_3 * 4) =
           param_1 / 6.0 +
           *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 0xc + param_3 * 4);
    }
    if (*(float *)((int)this + 0x178) <
        *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 0xc + param_3 * 4)) {
      *(undefined4 *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + 0xc + param_3 * 4) =
           *(undefined4 *)((int)this + 0x178);
    }
    dVar4 = RandomProb();
    fVar1 = (float)dVar4;
    dVar4 = RandomProb();
    fVar2 = (float)dVar4;
    dVar4 = RandomProb();
    if ((fVar1 <= fVar2) || (fVar1 <= (float)dVar4)) {
      if ((fVar2 <= fVar1) || (fVar2 <= (float)dVar4)) {
        local_14 = param_2 + 1;
        local_1c = param_2;
        local_8 = param_2 + -1;
      }
      else {
        local_14 = param_2;
        local_1c = param_2 + -1;
        local_8 = param_2 + 1;
      }
    }
    else {
      local_14 = param_2 + -1;
      local_1c = param_2;
      local_8 = param_2 + 1;
    }
    param_1 = param_1 * *(float *)((int)this + 0x188);
    dVar4 = RandomProb();
    if (dVar4 < (double)*(float *)((int)this + 400)) {
      param_1 = param_1 / 2.0;
      *(float *)((int)this + 400) = *(float *)((int)this + 400) / 2.0;
      dVar4 = RandomProb();
      if (0.5 <= dVar4) {
        FUN_1000323e(this,param_1,local_8,param_3 + *(int *)((int)this + 0x198));
      }
      else {
        FUN_1000323e(this,param_1,local_1c,param_3 + *(int *)((int)this + 0x198));
      }
    }
    FUN_1000323e(this,param_1,local_14,param_3 + *(int *)((int)this + 0x198));
  }
  return;
}



void __fastcall FUN_100037e6(TwTransparentOverlay *param_1)

{
  float *pfVar1;
  uint uVar2;
  int iVar3;
  TwTransparentOverlay *pTVar4;
  undefined4 *puVar5;
  uint local_10;
  int local_c;
  uint local_8;
  
  TwTransparentOverlay::EraseInternalSurface(param_1);
  local_c = 0;
  local_8 = 0;
  while( true ) {
    uVar2 = FUN_10004000((int)param_1);
    if (uVar2 <= local_8) break;
    local_10 = 0;
    while( true ) {
      uVar2 = FUN_10004020((int)param_1);
      if (uVar2 <= local_10) break;
      pfVar1 = (float *)(*(int *)(*(int *)(param_1 + 0xe04) + local_8 * 4) + local_10 * 4);
      if (10.0 < *pfVar1) {
        iVar3 = ftol();
        pTVar4 = param_1 + iVar3 * 0xc + 0x1c8;
        puVar5 = (undefined4 *)(*(int *)(param_1 + 0xdc8) + local_c * 0xc);
        *puVar5 = *(undefined4 *)pTVar4;
        puVar5[1] = *(undefined4 *)(pTVar4 + 4);
        puVar5[2] = *(undefined4 *)(pTVar4 + 8);
        *(uint *)(*(int *)(param_1 + 0xdc8) + 4 + local_c * 0xc) = local_8;
        *(uint *)(*(int *)(param_1 + 0xdc8) + 8 + local_c * 0xc) = local_10;
        local_c = local_c + 1;
      }
      if ((*(float *)(param_1 + 0x174) < *pfVar1) &&
         (*pfVar1 = *pfVar1 - *(float *)(param_1 + 0x170), *pfVar1 < *(float *)(param_1 + 0x174))) {
        *pfVar1 = *(float *)(param_1 + 0x174);
      }
      local_10 = local_10 + 1;
    }
    local_8 = local_8 + 1;
  }
  if (param_1 == (TwTransparentOverlay *)0x0) {
    pTVar4 = (TwTransparentOverlay *)0x0;
  }
  else {
    pTVar4 = param_1 + 8;
  }
  GKTOOLS::SetPixel((HDC)pTVar4,*(int *)(param_1 + 0xdc8),local_c,(COLORREF)pTVar4);
  return;
}



// public: virtual void __thiscall TwLightning::DrawToBack(void)

void __thiscall TwLightning::DrawToBack(TwLightning *this)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  int iVar2;
  int iVar3;
  
                    // 0x3972  55  ?DrawToBack@TwLightning@@UAEXXZ
  bVar1 = FUN_10003fc0(this + 0xdf0,*(uint *)(this + 0xdcc));
  if (CONCAT31(extraout_var,bVar1) != 0) {
    bVar1 = FUN_10003fc0(this + 0xdf4,*(uint *)(this + 0x180));
    if (CONCAT31(extraout_var_00,bVar1) != 0) {
      if ((this[0x1bc] == (TwLightning)0x0) || (this[0x1bd] == (TwLightning)0x0)) {
        FUN_1000266e((int)(this + 0x170));
        if (*(int *)(this + 0x194) == 0) {
          (**(code **)(*(int *)this + 0x4c))();
          FUN_1000323e(this,*(float *)(this + 0x17c),*(int *)(this + 0x1a4),0);
        }
        else if (*(int *)(this + 0x1a0) == 0) {
          *(undefined4 *)(this + 0x1a0) = 1;
          *(undefined4 *)(this + 0x194) = 1;
          (**(code **)(*(int *)this + 0x4c))();
          FUN_10002b76(this,*(float *)(this + 0x17c),0,*(int *)(this + 0x1a8));
        }
        else {
          *(undefined4 *)(this + 0x1a0) = 0;
          *(undefined4 *)(this + 0x194) = 0xffffffff;
          (**(code **)(*(int *)this + 0x4c))();
          iVar3 = *(int *)(this + 0x1a8);
          iVar2 = FUN_10004000((int)this);
          FUN_10002b76(this,*(float *)(this + 0x17c),iVar2 + -1,iVar3);
        }
      }
      FUN_10003fa0((DWORD *)(this + 0xdf4));
      this[0x1bd] = (TwLightning)0x1;
    }
    FUN_100037e6((TwTransparentOverlay *)this);
  }
  TwTransparentOverlay::DrawToBack((TwTransparentOverlay *)this);
  return;
}



void __thiscall FUN_10003aee(void *this,float param_1,int param_2,uint param_3)

{
  uint uVar1;
  float10 fVar2;
  undefined4 local_c;
  undefined4 local_8;
  
  if (-1 < (int)param_3) {
    uVar1 = FUN_10004020((int)this);
    if (param_3 < uVar1) {
      *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + param_3 * 4) =
           param_1 / 1.0 +
           *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + param_3 * 4);
      fVar2 = FUN_10003f50(*(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) +
                                     param_3 * 4),*(float *)((int)this + 0x178));
      *(float *)(*(int *)(*(int *)((int)this + 0xe04) + param_2 * 4) + param_3 * 4) = (float)fVar2;
    }
  }
  for (local_8 = 1; local_8 < *(uint *)((int)this + 0x184); local_8 = local_8 + 1) {
    local_c = local_8 * local_8;
    if (local_8 == 1) {
      local_c = 2;
    }
    if (10.0 < param_1 / (float)local_c) {
      if (-1 < (int)param_3) {
        uVar1 = FUN_10004020((int)this);
        if (param_3 < uVar1) {
          *(float *)(*(int *)(*(int *)((int)this + 0xe04) + (param_2 - local_8) * 4) + param_3 * 4)
               = param_1 / (float)local_c +
                 *(float *)(*(int *)(*(int *)((int)this + 0xe04) + (param_2 - local_8) * 4) +
                           param_3 * 4);
          fVar2 = FUN_10003f50(*(float *)(*(int *)(*(int *)((int)this + 0xe04) +
                                                  (param_2 - local_8) * 4) + param_3 * 4),
                               *(float *)((int)this + 0x178));
          *(float *)(*(int *)(*(int *)((int)this + 0xe04) + (param_2 - local_8) * 4) + param_3 * 4)
               = (float)fVar2;
        }
      }
      if (-1 < (int)param_3) {
        uVar1 = FUN_10004020((int)this);
        if (param_3 < uVar1) {
          *(float *)(*(int *)(*(int *)((int)this + 0xe04) + (param_2 + local_8) * 4) + param_3 * 4)
               = param_1 / (float)local_c +
                 *(float *)(*(int *)(*(int *)((int)this + 0xe04) + (param_2 + local_8) * 4) +
                           param_3 * 4);
          fVar2 = FUN_10003f50(*(float *)(*(int *)(*(int *)((int)this + 0xe04) +
                                                  (param_2 + local_8) * 4) + param_3 * 4),
                               *(float *)((int)this + 0x178));
          *(float *)(*(int *)(*(int *)((int)this + 0xe04) + (param_2 + local_8) * 4) + param_3 * 4)
               = (float)fVar2;
        }
      }
    }
  }
  return;
}



void FUN_10003d00(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  while (param_3 = param_3 + -1, -1 < param_3) {
    (*(code *)param_4)();
  }
  return;
}



void * __thiscall FUN_10003d30(void *this,uint param_1)

{
  TwLightning::~TwLightning((TwLightning *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_10003eb0(this,10);
  *(undefined ***)this = &PTR_LAB_100115f0;
  return this;
}



void * __thiscall FUN_10003d90(void *this,void *param_1)

{
  if (this != param_1) {
    FUN_10001a70((int)this);
    FUN_10003f10(this,(int)param_1);
  }
  return this;
}



void * __thiscall FUN_10003dd0(void *this,uint param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  void *pvVar2;
  uint uVar3;
  int local_c;
  uint local_8;
  
  bVar1 = IsEmpty((int)this);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    uVar3 = FUN_1000ff30((int)this);
    if (param_1 < uVar3) {
      local_c = FUN_1000e790((int)this);
      local_8 = 0;
      while ((local_8 < param_1 && (uVar3 = FUN_1000ff30((int)this), local_8 < uVar3))) {
        FUN_100018b0(&local_c);
        local_8 = local_8 + 1;
      }
      pvVar2 = (void *)FUN_100018b0(&local_c);
    }
    else {
      pvVar2 = operator_new(4);
    }
  }
  else {
    pvVar2 = operator_new(4);
  }
  return pvVar2;
}



void * __thiscall FUN_10003e80(void *this,uint param_1)

{
  FUN_10001810((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001c10(this);
  }
  return this;
}



void * __thiscall FUN_10003eb0(void *this,undefined4 param_1)

{
  FUN_10003f80((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_10011440;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



void __thiscall FUN_10003f10(void *this,int param_1)

{
  undefined4 *puVar1;
  int local_8;
  
  local_8 = FUN_1000e790(param_1);
  while (local_8 != 0) {
    puVar1 = (undefined4 *)FUN_100018b0(&local_8);
    FUN_10001a10(this,puVar1);
  }
  return;
}



float10 __cdecl FUN_10003f50(float param_1,float param_2)

{
  undefined4 local_8;
  
  if (param_2 <= param_1) {
    local_8 = param_2;
  }
  else {
    local_8 = param_1;
  }
  return (float10)local_8;
}



undefined4 * __fastcall FUN_10003f80(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_10011454;
  return param_1;
}



void __fastcall FUN_10003fa0(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
  return;
}



bool __thiscall FUN_10003fc0(void *this,uint param_1)

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



undefined4 __fastcall FUN_10004000(int param_1)

{
  return *(undefined4 *)(param_1 + 0xac);
}



undefined4 __fastcall FUN_10004020(int param_1)

{
  return *(undefined4 *)(param_1 + 0xb0);
}



float * __fastcall FUN_10004040(float *param_1)

{
  double dVar1;
  
  param_1[0xf] = 1.4013e-43;
  param_1[0x10] = 1.4013e-43;
  param_1[0xd] = 7.00649e-44;
  param_1[0xe] = 7.00649e-44;
  dVar1 = RandomProb();
  *param_1 = (float)dVar1 * 25.0 + 250.0;
  param_1[1] = 10.0;
  param_1[2] = 2550.0;
  param_1[3] = 2550.0;
  param_1[4] = 4.2039e-43;
  param_1[5] = 4.2039e-45;
  param_1[6] = 0.99;
  param_1[7] = 5.0;
  param_1[8] = 0.0;
  param_1[10] = 0.0;
  param_1[9] = 1.4013e-45;
  param_1[0xc] = 0.0;
  param_1[0xb] = 0.0;
  param_1[0xd] = 0.0;
  param_1[0xe] = 0.0;
  param_1[0x11] = 2.3504484e-38;
  param_1[0x12] = 4.591775e-39;
  *(undefined1 *)(param_1 + 0x13) = 0;
  *(undefined1 *)((int)param_1 + 0x4d) = 0;
  return param_1;
}



// public: __thiscall TwLissajous::TwLissajous(void)

TwLissajous * __thiscall TwLissajous::TwLissajous(TwLissajous *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x4140  9  ??0TwLissajous@@QAE@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_10010839;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  TwTransparentOverlay::TwTransparentOverlay((TwTransparentOverlay *)this);
  local_8 = 0;
  FUN_100023b0((DWORD *)(this + 0x18c));
  *(undefined ***)this = &PTR_FUN_10011610;
  *(undefined ***)(this + 8) = &PTR_FUN_1001160c;
  *(undefined4 *)(this + 0x16c) = 0xffffff;
  *(undefined4 *)(this + 0x170) = 2;
  *(undefined4 *)(this + 0x174) = 0;
  *(undefined4 *)(this + 0x178) = 0;
  *(undefined4 *)(this + 0x17c) = 0;
  *(undefined4 *)(this + 0x180) = 0;
  *(undefined4 *)(this + 400) = 0xffffffff;
  ExceptionList = local_10;
  return this;
}



// public: void __thiscall TwLissajous::Init(unsigned int,unsigned int,unsigned long)

void __thiscall TwLissajous::Init(TwLissajous *this,uint param_1,uint param_2,ulong param_3)

{
                    // 0x41ff  100  ?Init@TwLissajous@@QAEXIIK@Z
  TwTransparentOverlay::Init((TwTransparentOverlay *)this,param_1,param_2);
  *(ulong *)(this + 0x16c) = param_3;
  return;
}



// public: void __thiscall TwLissajous::SetPhaseDrift(unsigned int,unsigned int)

void __thiscall TwLissajous::SetPhaseDrift(TwLissajous *this,uint param_1,uint param_2)

{
                    // 0x4228  164  ?SetPhaseDrift@TwLissajous@@QAEXII@Z
  *(uint *)(this + 0x17c) = param_1;
  *(uint *)(this + 0x180) = param_2;
  return;
}



// public: void __thiscall TwLissajous::SetPhaseMultiplier(unsigned int,unsigned int)

void __thiscall TwLissajous::SetPhaseMultiplier(TwLissajous *this,uint param_1,uint param_2)

{
                    // 0x424d  165  ?SetPhaseMultiplier@TwLissajous@@QAEXII@Z
  *(uint *)(this + 0x184) = param_1;
  *(uint *)(this + 0x188) = param_2;
  return;
}



// public: void __thiscall TwLissajous::SetFramesPerSecond(unsigned long)

void __thiscall TwLissajous::SetFramesPerSecond(TwLissajous *this,ulong param_1)

{
                    // 0x4272  151  ?SetFramesPerSecond@TwLissajous@@QAEXK@Z
  if (param_1 == 0) {
    *(undefined4 *)(this + 400) = 0xffffffff;
  }
  else {
    *(int *)(this + 400) = (int)(1000 / (ulonglong)param_1);
    FUN_10003fa0((DWORD *)(this + 0x18c));
  }
  return;
}



// public: virtual void __thiscall TwLissajous::DrawToBack(void)

void __thiscall TwLissajous::DrawToBack(TwLissajous *this)

{
  bool bVar1;
  undefined3 extraout_var;
  
                    // 0x42b5  56  ?DrawToBack@TwLissajous@@UAEXXZ
  if ((*(int *)(this + 0x174) != 0) || (*(int *)(this + 0x178) != 0)) {
    bVar1 = FUN_10003fc0(this + 0x18c,*(uint *)(this + 400));
    if (CONCAT31(extraout_var,bVar1) == 0) goto LAB_1000432e;
  }
  *(int *)(this + 0x174) = *(int *)(this + 0x174) + *(int *)(this + 0x17c);
  *(int *)(this + 0x178) = *(int *)(this + 0x178) + *(int *)(this + 0x180);
  FUN_10004353((TwTransparentOverlay *)this);
LAB_1000432e:
  TwTransparentOverlay::DrawToBack((TwTransparentOverlay *)this);
  return;
}



// public: void __thiscall TwLissajous::SetOneSideThickness(unsigned int)

void __thiscall TwLissajous::SetOneSideThickness(TwLissajous *this,uint param_1)

{
                    // 0x433a  158  ?SetOneSideThickness@TwLissajous@@QAEXI@Z
  *(uint *)(this + 0x170) = param_1;
  return;
}



void __fastcall FUN_10004353(TwTransparentOverlay *param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  HDC pHVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  ulong color;
  double dVar8;
  double dVar9;
  HDC in_stack_ffffff5c;
  HWND__ local_18;
  double local_14;
  double local_c;
  
  TwTransparentOverlay::EraseInternalSurface(param_1);
  pHVar4 = DD_SURFACE::GetDC(&local_18);
  if (pHVar4 != (HDC)0x0) {
    uVar5 = FUN_10004610(*(uint *)(param_1 + 0x184),*(uint *)(param_1 + 0x188));
    local_c = (double)uVar5 + 1.0;
    for (local_14 = 0.0; local_14 < local_c * 360.0; local_14 = local_14 + 1.0) {
      iVar6 = *(int *)(param_1 + 0x170);
      iVar7 = *(int *)(param_1 + 0xa4);
      iVar1 = *(int *)(param_1 + 0x170);
      iVar2 = *(int *)(param_1 + 0xa8);
      dVar9 = local_14 / (local_c * 6.28318530717958);
      uVar5 = *(uint *)(param_1 + 0x178);
      uVar3 = *(uint *)(param_1 + 0x188);
      dVar8 = cos((double)*(uint *)(param_1 + 0x184) *
                  (dVar9 + (double)*(uint *)(param_1 + 0x174) /
                           ((double)*(uint *)(param_1 + 0x184) * 10.0)));
      in_stack_ffffff5c = *(HDC *)(param_1 + 0x188);
      dVar9 = sin((double)in_stack_ffffff5c * (dVar9 + (double)uVar5 / ((double)uVar3 * 10.0)));
      iVar6 = round(((dVar8 + 1.0) * (double)(uint)(iVar7 + iVar6 * -2)) / 2.0);
      iVar7 = round(((dVar9 + 1.0) * (double)(uint)(iVar2 + iVar1 * -2)) / 2.0);
      color = TwTransparentOverlay::GetColor(param_1,*(ulong *)(param_1 + 0x16c));
      SetPixelV((HDC)local_18.unused,iVar6,iVar7,color);
    }
    DD_SURFACE::ReleaseDC((HWND)local_18.unused,in_stack_ffffff5c);
  }
  return;
}



void * __thiscall FUN_100045c0(void *this,uint param_1)

{
  FUN_100045f0((CMiniDockFrameWnd *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_100045f0(CMiniDockFrameWnd *param_1)

{
  CMiniDockFrameWnd::~CMiniDockFrameWnd(param_1);
  return;
}



uint __cdecl FUN_10004610(uint param_1,uint param_2)

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



// public: __thiscall OVERLAY::OVERLAY(void)

OVERLAY * __thiscall OVERLAY::OVERLAY(OVERLAY *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x4640  3  ??0OVERLAY@@QAE@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_10010859;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10004ec0((undefined4 *)this);
  local_8 = 0;
  DD_SURFACE::DD_SURFACE((DD_SURFACE *)(this + 8));
  *(undefined ***)this = &PTR_FUN_10011674;
  *(undefined ***)(this + 8) = &PTR_FUN_10011670;
  *(undefined4 *)(this + 0xc0) = 0;
  *(undefined4 *)(this + 0xbc) = 0;
  *(undefined4 *)(this + 0xc4) = 1;
  *(undefined4 *)(this + 200) = 1;
  *(int *)(this + 0xac) = *(int *)(this + 0xc4) - *(int *)(this + 0xbc);
  *(int *)(this + 0xb0) = *(int *)(this + 200) - *(int *)(this + 0xc0);
  this[0xa0] = (OVERLAY)0x0;
  this[0xcc] = (OVERLAY)0x1;
  ExceptionList = local_10;
  return this;
}



uint __thiscall FUN_1000471f(void *this,int *param_1,undefined4 *param_2,undefined4 *param_3)

{
  uint uVar1;
  uint uVar2;
  void *pvVar3;
  undefined4 local_28;
  undefined4 local_24;
  int local_20;
  int local_1c;
  int local_18;
  int local_14;
  
  uVar1 = GKERNEL::ScrXRes();
  uVar2 = GKERNEL::ScrYRes();
  pvVar3 = this;
  if ((((*(int *)((int)this + 0xb4) < (int)uVar1) &&
       (pvVar3 = *(void **)((int)this + 0xb8), (int)*(void **)((int)this + 0xb8) < (int)uVar2)) &&
      (pvVar3 = this, 0 < *(int *)((int)this + 0xb4) + *(int *)((int)this + 0xac))) &&
     (0 < *(int *)((int)this + 0xb8) + *(int *)((int)this + 0xb0))) {
    if (*(int *)((int)this + 0xb4) < 0) {
      local_14 = labs(*(long *)((int)this + 0xb4));
    }
    else {
      local_14 = 0;
    }
    *param_1 = *(int *)((int)this + 0xbc) + local_14;
    if (uVar1 < (uint)(*(int *)((int)this + 0xb4) + *(int *)((int)this + 0xac))) {
      local_18 = (*(int *)((int)this + 0xb4) + *(int *)((int)this + 0xac)) - uVar1;
    }
    else {
      local_18 = 0;
    }
    param_1[2] = *(int *)((int)this + 0xbc) + (*(int *)((int)this + 0xac) - local_18);
    if (*(int *)((int)this + 0xb8) < 0) {
      local_1c = labs(*(long *)((int)this + 0xb8));
    }
    else {
      local_1c = 0;
    }
    param_1[1] = *(int *)((int)this + 0xc0) + local_1c;
    if (uVar2 < (uint)(*(int *)((int)this + 0xb8) + *(int *)((int)this + 0xb0))) {
      local_20 = (*(int *)((int)this + 0xb8) + *(int *)((int)this + 0xb0)) - uVar2;
    }
    else {
      local_20 = 0;
    }
    param_1[3] = *(int *)((int)this + 0xc0) + (*(int *)((int)this + 0xb0) - local_20);
    if (*(int *)((int)this + 0xb4) < 0) {
      local_24 = 0;
    }
    else {
      local_24 = *(undefined4 *)((int)this + 0xb4);
    }
    *param_2 = local_24;
    if (*(int *)((int)this + 0xb8) < 0) {
      local_28 = 0;
    }
    else {
      local_24 = *(undefined4 *)((int)this + 0xb8);
      local_28 = local_24;
    }
    *param_3 = local_28;
    uVar1 = CONCAT31((int3)((uint)local_24 >> 8),1);
  }
  else {
    uVar1 = (uint)pvVar3 & 0xffffff00;
  }
  return uVar1;
}



// public: virtual void __thiscall OVERLAY::Init(unsigned int,unsigned int)

void __thiscall OVERLAY::Init(OVERLAY *this,uint param_1,uint param_2)

{
  undefined4 local_84 [2];
  undefined4 local_7c;
  undefined4 local_78;
  uint local_74;
  uint local_70;
  undefined4 local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x4902  93  ?Init@OVERLAY@@UAEXII@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1001086c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10004e70(local_84,this + 0xa0,1);
  local_8 = 0;
  memset(&local_7c,0,0x6c);
  local_7c = 0x6c;
  local_78 = 7;
  local_14 = 0x40;
  local_70 = param_1;
  local_74 = param_2;
  DD_SURFACE::Create((DD_SURFACE *)(this + 8),(_DDSURFACEDESC *)&local_7c,(HWND__ *)0x0);
  *(uint *)(this + 0xa4) = local_70;
  *(uint *)(this + 0xa8) = local_74;
  *(undefined4 *)(this + 0xac) = *(undefined4 *)(this + 0xa4);
  *(undefined4 *)(this + 0xb0) = *(undefined4 *)(this + 0xa8);
  *(undefined4 *)(this + 0xb4) = 0;
  *(undefined4 *)(this + 0xb8) = 0;
  local_8 = 0xffffffff;
  FUN_10004ea0(local_84);
  ExceptionList = local_10;
  return;
}



// public: virtual void __thiscall OVERLAY::Init(char const *,bool)

void __thiscall OVERLAY::Init(OVERLAY *this,char *param_1,bool param_2)

{
  DD_SURFACE *local_14;
  uint local_c;
  uint local_8;
  
                    // 0x4a12  94  ?Init@OVERLAY@@UAEXPBD_N@Z
  local_8 = 0;
  local_c = 0;
  GKTOOLS::GetDIBSize(param_1,&local_8,&local_c);
  (**(code **)(*(int *)this + 0x40))(local_8,local_c);
  if (this == (OVERLAY *)0x0) {
    local_14 = (DD_SURFACE *)0x0;
  }
  else {
    local_14 = (DD_SURFACE *)(this + 8);
  }
  GKTOOLS::CopyDIBToSurface(local_14,param_1,0,0,false);
  if (param_2) {
    DD_SURFACE::SetColorKeyFromPixel00((DD_SURFACE *)(this + 8));
  }
  return;
}



// public: virtual void __thiscall OVERLAY::Init(class DD_SURFACE const &,bool)

void __thiscall OVERLAY::Init(OVERLAY *this,DD_SURFACE *param_1,bool param_2)

{
  undefined4 local_84 [2];
  undefined1 local_7c [8];
  undefined4 local_74;
  undefined4 local_70;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x4a9c  92  ?Init@OVERLAY@@UAEXABVDD_SURFACE@@_N@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1001087f;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10004e70(local_84,this + 0xa0,1);
  local_8 = 0;
  DD_SURFACE::operator=((DD_SURFACE *)(this + 8),param_1);
  DD_SURFACE::Desc((DD_SURFACE *)(this + 8),(ulong)local_7c);
  *(undefined4 *)(this + 0xa4) = local_70;
  *(undefined4 *)(this + 0xa8) = local_74;
  *(undefined4 *)(this + 0xc4) = local_70;
  *(undefined4 *)(this + 200) = local_74;
  *(int *)(this + 0xac) = *(int *)(this + 0xc4) - *(int *)(this + 0xbc);
  *(int *)(this + 0xb0) = *(int *)(this + 200) - *(int *)(this + 0xc0);
  *(undefined4 *)(this + 0xb4) = 0;
  *(undefined4 *)(this + 0xb8) = 0;
  if (param_2) {
    DD_SURFACE::SetColorKeyFromPixel00((DD_SURFACE *)(this + 8));
  }
  local_8 = 0xffffffff;
  FUN_10004ea0(local_84);
  ExceptionList = local_10;
  return;
}



// public: virtual bool __thiscall OVERLAY::IntersectsCursor(void)

bool __thiscall OVERLAY::IntersectsCursor(OVERLAY *this)

{
  undefined1 uVar1;
  tagPOINT local_c;
  
                    // 0x4bdd  105  ?IntersectsCursor@OVERLAY@@UAE_NXZ
  GKERNEL::GetCursorPos(&local_c);
  if ((((local_c.x < *(int *)(this + 0xb4)) ||
       (*(int *)(this + 0xb4) + *(int *)(this + 0xac) <= local_c.x)) ||
      (local_c.y < *(int *)(this + 0xb8))) ||
     (*(int *)(this + 0xb8) + *(int *)(this + 0xb0) <= local_c.y)) {
    uVar1 = 0;
  }
  else {
    uVar1 = (**(code **)(*(int *)this + 0x18))();
  }
  return (bool)uVar1;
}



// public: virtual void __thiscall OVERLAY::SetPosition(int,int)

void __thiscall OVERLAY::SetPosition(OVERLAY *this,int param_1,int param_2)

{
                    // 0x4c4f  168  ?SetPosition@OVERLAY@@UAEXHH@Z
  *(int *)(this + 0xb4) = param_1;
  *(int *)(this + 0xb8) = param_2;
  return;
}



// public: virtual void __thiscall OVERLAY::SetSubImage(struct tagRECT *)

void __thiscall OVERLAY::SetSubImage(OVERLAY *this,tagRECT *param_1)

{
                    // 0x4c74  176  ?SetSubImage@OVERLAY@@UAEXPAUtagRECT@@@Z
  *(LONG *)(this + 0xbc) = param_1->left;
  *(LONG *)(this + 0xc0) = param_1->top;
  *(LONG *)(this + 0xc4) = param_1->right;
  *(LONG *)(this + 200) = param_1->bottom;
  *(int *)(this + 0xac) = *(int *)(this + 0xc4) - *(int *)(this + 0xbc);
  *(int *)(this + 0xb0) = *(int *)(this + 200) - *(int *)(this + 0xc0);
  return;
}



// public: virtual void __thiscall OVERLAY::DrawToFront(void)

void __thiscall OVERLAY::DrawToFront(OVERLAY *this)

{
  uint uVar1;
  DD_SURFACE *local_24;
  undefined4 local_1c;
  undefined4 local_18;
  tagRECT local_14;
  
                    // 0x4cd9  60  ?DrawToFront@OVERLAY@@UAEXXZ
  uVar1 = FUN_1000471f(this,&local_14.left,&local_18,&local_1c);
  if ((uVar1 & 0xff) != 0) {
    if (this == (OVERLAY *)0x0) {
      local_24 = (DD_SURFACE *)0x0;
    }
    else {
      local_24 = (DD_SURFACE *)(this + 8);
    }
    DD_SURFACE::BltFast(&GKERNEL::ddsPrimary,local_24,*(uint *)(this + 0xb4),*(uint *)(this + 0xb8),
                        &local_14);
  }
  return;
}



// public: virtual void __thiscall OVERLAY::DrawToBack(unsigned int,unsigned int,unsigned
// int,unsigned int)

void __thiscall
OVERLAY::DrawToBack(OVERLAY *this,uint param_1,uint param_2,uint param_3,uint param_4)

{
  uint uVar1;
  DD_SURFACE *local_24;
  uint local_1c;
  uint local_18;
  tagRECT local_14;
  
                    // 0x4d41  50  ?DrawToBack@OVERLAY@@UAEXIIII@Z
  uVar1 = FUN_1000471f(this,&local_14.left,&local_18,&local_1c);
  if ((uVar1 & 0xff) != 0) {
    if ((uint)local_14.left < param_1) {
      local_14.left = param_1;
    }
    if ((uint)local_14.top < param_2) {
      local_14.top = param_2;
    }
    if (param_3 < (uint)local_14.right) {
      local_14.right = param_3;
    }
    if (param_4 < (uint)local_14.bottom) {
      local_14.bottom = param_4;
    }
    if (this == (OVERLAY *)0x0) {
      local_24 = (DD_SURFACE *)0x0;
    }
    else {
      local_24 = (DD_SURFACE *)(this + 8);
    }
    DD_SURFACE::BltFast(&GKERNEL::ddsBack,local_24,local_18,local_1c,&local_14);
  }
  return;
}



// public: virtual void __thiscall OVERLAY::DrawToBack(void)

void __thiscall OVERLAY::DrawToBack(OVERLAY *this)

{
  uint uVar1;
  DD_SURFACE *local_24;
  uint local_1c;
  uint local_18;
  tagRECT local_14;
  
                    // 0x4dd7  51  ?DrawToBack@OVERLAY@@UAEXXZ
  uVar1 = FUN_1000471f(this,&local_14.left,&local_18,&local_1c);
  if ((uVar1 & 0xff) != 0) {
    if (this == (OVERLAY *)0x0) {
      local_24 = (DD_SURFACE *)0x0;
    }
    else {
      local_24 = (DD_SURFACE *)(this + 8);
    }
    DD_SURFACE::BltFast(&GKERNEL::ddsBack,local_24,local_18,local_1c,&local_14);
  }
  return;
}



void * __thiscall FUN_10004e40(void *this,uint param_1)

{
  FUN_10001ec0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void * __thiscall FUN_10004e70(void *this,undefined4 param_1,undefined1 param_2)

{
  *(undefined4 *)this = param_1;
  *(undefined1 *)((int)this + 4) = param_2;
  return this;
}



void __fastcall FUN_10004ea0(undefined4 *param_1)

{
  *(undefined1 *)*param_1 = *(undefined1 *)(param_1 + 1);
  return;
}



undefined4 * __fastcall FUN_10004ec0(undefined4 *param_1)

{
  param_1[1] = 0;
  *param_1 = &PTR_FUN_10011490;
  return param_1;
}



// public: virtual void __thiscall BUTTON::DrawToBack(void)

void __thiscall BUTTON::DrawToBack(BUTTON *this)

{
  uint uVar1;
  uint local_20;
  uint local_1c;
  tagRECT local_18;
  
                    // 0x4ef0  49  ?DrawToBack@BUTTON@@UAEXXZ
  if (((*(int *)(this + 0xd4) == 0) && (*(int *)(this + 0x178) == 1)) && (this[0xcc] == (BUTTON)0x1)
     ) {
    *(int *)(this + 0x174) = *(int *)(this + 0x174) + 1;
    if (*(int *)(this + 0x174) == 2) {
      *(undefined4 *)(this + 0x178) = 0;
      *(undefined4 *)(this + 0x174) = 0;
    }
    OVERLAY::DrawToBack((OVERLAY *)this);
  }
  else if (((*(int *)(this + 0xd4) == 1) && (*(int *)(this + 0x178) == 1)) &&
          (this[0xcc] == (BUTTON)0x1)) {
    *(int *)(this + 0x174) = *(int *)(this + 0x174) + 1;
    if (*(int *)(this + 0x174) == 2) {
      *(undefined4 *)(this + 0x178) = 0;
      *(undefined4 *)(this + 0x174) = 0;
    }
    uVar1 = FUN_1000471f(this,&local_18.left,&local_1c,&local_20);
    if ((uVar1 & 0xff) != 0) {
      DD_SURFACE::BltFast(&GKERNEL::ddsBack,(DD_SURFACE *)(this + 0xdc),local_1c,local_20,&local_18)
      ;
    }
  }
  return;
}



// public: virtual void __thiscall BUTTON::Init(char const *,char const *,bool)

void __thiscall BUTTON::Init(BUTTON *this,char *param_1,char *param_2,bool param_3)

{
  uint local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_c;
  uint local_8;
  
                    // 0x5018  90  ?Init@BUTTON@@UAEXPBD0_N@Z
  GKTOOLS::GetDIBSize(param_2,(uint *)(this + 0xa4),(uint *)(this + 0xa8));
  GKTOOLS::GetDIBSize(param_1,&local_78,&local_8);
  memset(&local_74,0,0x6c);
  local_74 = 0x6c;
  local_70 = 7;
  local_68 = *(undefined4 *)(this + 0xa4);
  local_6c = *(undefined4 *)(this + 0xa8);
  local_c = 0x840;
  DD_SURFACE::Create((DD_SURFACE *)(this + 0xdc),(_DDSURFACEDESC *)&local_74,(HWND__ *)0x0);
  GKTOOLS::CopyDIBToSurface((DD_SURFACE *)(this + 0xdc),param_2,0,0,false);
  *(undefined4 *)(this + 0x174) = 0;
  *(undefined4 *)(this + 0x178) = 1;
  OVERLAY::Init((OVERLAY *)this,param_1,param_3);
  return;
}



// public: __thiscall TwDisablableButton::TwDisablableButton(void)

TwDisablableButton * __thiscall TwDisablableButton::TwDisablableButton(TwDisablableButton *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x50f1  6  ??0TwDisablableButton@@QAE@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_10010899;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10002330((OVERLAY *)this);
  local_8 = 0;
  DD_SURFACE::DD_SURFACE((DD_SURFACE *)(this + 0x180));
  *(undefined ***)this = &PTR_FUN_100116c4;
  *(undefined ***)(this + 8) = &PTR_FUN_100116c0;
  this[0x17c] = (TwDisablableButton)0x1;
  ExceptionList = local_10;
  return this;
}



// public: virtual bool __thiscall TwDisablableButton::IntersectsCursor(void)

bool __thiscall TwDisablableButton::IntersectsCursor(TwDisablableButton *this)

{
  bool bVar1;
  
                    // 0x515f  106  ?IntersectsCursor@TwDisablableButton@@UAE_NXZ
  if (this[0x17c] == (TwDisablableButton)0x0) {
    bVar1 = false;
  }
  else {
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)this);
  }
  return bVar1;
}



// public: void __thiscall TwDisablableButton::Init(char const *,char const *,char const *,bool)

void __thiscall
TwDisablableButton::Init
          (TwDisablableButton *this,char *param_1,char *param_2,char *param_3,bool param_4)

{
  uint local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_c;
  uint local_8;
  
                    // 0x5185  98  ?Init@TwDisablableButton@@QAEXPBD00_N@Z
  BUTTON::Init((BUTTON *)this,param_1,param_2,param_4);
  GKTOOLS::GetDIBSize(param_2,(uint *)(this + 0xa4),(uint *)(this + 0xa8));
  GKTOOLS::GetDIBSize(param_3,&local_78,&local_8);
  memset(&local_74,0,0x6c);
  local_74 = 0x6c;
  local_70 = 7;
  local_68 = *(undefined4 *)(this + 0xa4);
  local_6c = *(undefined4 *)(this + 0xa8);
  local_c = 0x840;
  DD_SURFACE::Create((DD_SURFACE *)(this + 0x180),(_DDSURFACEDESC *)&local_74,(HWND__ *)0x0);
  GKTOOLS::CopyDIBToSurface((DD_SURFACE *)(this + 0x180),param_3,0,0,false);
  return;
}



// public: virtual void __thiscall TwDisablableButton::DrawToBack(void)

void __thiscall TwDisablableButton::DrawToBack(TwDisablableButton *this)

{
  uint uVar1;
  uint local_20;
  uint local_1c;
  tagRECT local_18;
  
                    // 0x5248  54  ?DrawToBack@TwDisablableButton@@UAEXXZ
  if (((this[0x17c] == (TwDisablableButton)0x0) && (*(int *)(this + 0x178) == 1)) &&
     (this[0xcc] == (TwDisablableButton)0x1)) {
    *(int *)(this + 0x174) = *(int *)(this + 0x174) + 1;
    if (*(int *)(this + 0x174) == 2) {
      *(undefined4 *)(this + 0x178) = 0;
      *(undefined4 *)(this + 0x174) = 0;
    }
    uVar1 = FUN_1000471f(this,&local_18.left,&local_1c,&local_20);
    if ((uVar1 & 0xff) != 0) {
      DD_SURFACE::BltFast(&GKERNEL::ddsBack,(DD_SURFACE *)(this + 0x180),local_1c,local_20,&local_18
                         );
    }
  }
  else {
    BUTTON::DrawToBack((BUTTON *)this);
  }
  return;
}



// public: virtual void __thiscall TwAutoButton::Init(char const *,bool)

void __thiscall TwAutoButton::Init(TwAutoButton *this,char *param_1,bool param_2)

{
                    // 0x530d  97  ?Init@TwAutoButton@@UAEXPBD_N@Z
  BUTTON::Init((BUTTON *)this,param_1,param_1,param_2);
  return;
}



// public: void __thiscall TwAutoButton::Up(void)

void __thiscall TwAutoButton::Up(TwAutoButton *this)

{
  int iVar1;
  
                    // 0x532e  198  ?Up@TwAutoButton@@QAEXXZ
  iVar1 = FUN_10005460((int)this);
  if (iVar1 == 1) {
    (**(code **)(*(int *)this + 0x2c))(*(int *)(this + 0xb4) + -1,*(int *)(this + 0xb8) + -1);
  }
  FUN_100023d0((int)this);
  return;
}



// public: void __thiscall TwAutoButton::Down(void)

void __thiscall TwAutoButton::Down(TwAutoButton *this)

{
  int iVar1;
  
                    // 0x5373  47  ?Down@TwAutoButton@@QAEXXZ
  iVar1 = FUN_10005460((int)this);
  if (iVar1 == 0) {
    (**(code **)(*(int *)this + 0x2c))(*(int *)(this + 0xb4) + 1,*(int *)(this + 0xb8) + 1);
  }
  FUN_10005440((int)this);
  return;
}



void * __thiscall FUN_100053c0(void *this,uint param_1)

{
  CMiniDockFrameWnd::~CMiniDockFrameWnd((CMiniDockFrameWnd *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



// Library Function - Single Match
//  public: virtual __thiscall CMiniDockFrameWnd::~CMiniDockFrameWnd(void)
// 
// Library: Visual Studio 2003 Debug

void __thiscall CMiniDockFrameWnd::~CMiniDockFrameWnd(CMiniDockFrameWnd *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_100108b9;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(this + 0x180));
  local_8 = 0xffffffff;
  ~CMiniDockFrameWnd(this);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10005440(int param_1)

{
  *(undefined4 *)(param_1 + 0xd4) = 1;
  FUN_100023f0(param_1);
  return;
}



undefined4 __fastcall FUN_10005460(int param_1)

{
  return *(undefined4 *)(param_1 + 0xd4);
}



// protected: __thiscall TwTransparentOverlay::TwTransparentOverlay(void)

TwTransparentOverlay * __thiscall
TwTransparentOverlay::TwTransparentOverlay(TwTransparentOverlay *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x5480  12  ??0TwTransparentOverlay@@IAE@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_100108d9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  OVERLAY::OVERLAY((OVERLAY *)this);
  local_8 = 0;
  DD_SURFACE::DD_SURFACE((DD_SURFACE *)(this + 0xd0));
  *(undefined ***)this = &PTR_FUN_10011718;
  *(undefined ***)(this + 8) = &PTR_FUN_10011714;
  *(undefined4 *)(this + 0x168) = 0xff00;
  ExceptionList = local_10;
  return this;
}



// public: virtual void __thiscall TwTransparentOverlay::SetPosition(int,int)

void __thiscall
TwTransparentOverlay::SetPosition(TwTransparentOverlay *this,int param_1,int param_2)

{
                    // 0x54f1  172  ?SetPosition@TwTransparentOverlay@@UAEXHH@Z
  OVERLAY::SetPosition((OVERLAY *)this,param_1,param_2);
  CopyBackground(this);
  return;
}



// public: void __thiscall TwTransparentOverlay::CopyBackground(void)

void __thiscall TwTransparentOverlay::CopyBackground(TwTransparentOverlay *this)

{
  tagRECT local_14;
  
                    // 0x5516  33  ?CopyBackground@TwTransparentOverlay@@QAEXXZ
  local_14.left = *(LONG *)(this + 0xb4);
  local_14.top = *(LONG *)(this + 0xb8);
  local_14.right = *(int *)(this + 0xb4) + *(int *)(this + 0xa4);
  local_14.bottom = *(int *)(this + 0xb8) + *(int *)(this + 0xa8);
  DD_SURFACE::BltFast((DD_SURFACE *)(this + 0xd0),&GKERNEL::ddsBack,0,0,&local_14);
  return;
}



// public: void __thiscall TwTransparentOverlay::Init(int,int)

void __thiscall TwTransparentOverlay::Init(TwTransparentOverlay *this,int param_1,int param_2)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 local_70;
  undefined4 local_6c [25];
  undefined4 local_8;
  
                    // 0x5580  102  ?Init@TwTransparentOverlay@@QAEXHH@Z
  OVERLAY::Init((OVERLAY *)this,param_1,param_2);
  puVar2 = local_6c;
  for (iVar1 = 0x1a; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  local_70 = 0x6c;
  local_6c[0] = 7;
  local_6c[2] = *(undefined4 *)(this + 0xa4);
  local_6c[1] = *(undefined4 *)(this + 0xa8);
  local_8 = 0x840;
  DD_SURFACE::Create((DD_SURFACE *)(this + 0xd0),(_DDSURFACEDESC *)&local_70,(HWND__ *)0x0);
  CopyBackground(this);
  DD_SURFACE::SetColorKey((DD_SURFACE *)(this + 8),*(ulong *)(this + 0x168));
  return;
}



// protected: void __thiscall TwTransparentOverlay::SetTransparentColor(unsigned long)

void __thiscall TwTransparentOverlay::SetTransparentColor(TwTransparentOverlay *this,ulong param_1)

{
                    // 0x5612  178  ?SetTransparentColor@TwTransparentOverlay@@IAEXK@Z
  *(ulong *)(this + 0x168) = param_1;
  DD_SURFACE::SetColorKey((DD_SURFACE *)(this + 8),*(ulong *)(this + 0x168));
  return;
}



// protected: unsigned long __thiscall TwTransparentOverlay::GetColor(unsigned long)const 

ulong __thiscall TwTransparentOverlay::GetColor(TwTransparentOverlay *this,ulong param_1)

{
  bool bVar1;
  uint uVar2;
  ulong uVar3;
  uint local_10;
  
                    // 0x5640  71  ?GetColor@TwTransparentOverlay@@IBEKK@Z
  uVar2 = FUN_100056f8(param_1,*(uint *)(this + 0x168));
  uVar3 = param_1;
  if ((uVar2 & 0xff) != 0) {
    local_10 = param_1 & 0xff00;
    if (local_10 < 0xf801) {
      local_10 = local_10 + 0x800;
    }
    else {
      local_10 = local_10 - 0x800;
    }
    uVar3 = param_1 & 0xff | local_10 | param_1 & 0xff0000;
    bVar1 = FUN_10005950(&DAT_10019058,'\x01');
    if (bVar1) {
      GKERNEL::DebugTrace(s_WARNING__Remapping_transparent_c_10016040,param_1,uVar3);
    }
  }
  return uVar3;
}



uint __cdecl FUN_100056f8(uint param_1,uint param_2)

{
  uint uVar1;
  int iVar2;
  uint3 uVar3;
  
  uVar1 = abs((param_1 & 0xff) - (param_2 & 0xff));
  if ((int)uVar1 < 8) {
    uVar1 = abs(((param_1 & 0xff00) >> 8) - ((param_2 & 0xff00) >> 8));
    if ((int)uVar1 < 8) {
      iVar2 = abs(((param_1 & 0xff0000) >> 0x10) - ((param_2 & 0xff0000) >> 0x10));
      uVar3 = (uint3)((uint)iVar2 >> 8);
      if (iVar2 < 8) {
        uVar1 = CONCAT31(uVar3,1);
      }
      else {
        uVar1 = (uint)uVar3 << 8;
      }
    }
    else {
      uVar1 = uVar1 & 0xffffff00;
    }
  }
  else {
    uVar1 = uVar1 & 0xffffff00;
  }
  return uVar1;
}



// public: virtual void __thiscall TwTransparentOverlay::DrawToBack(void)

void __thiscall TwTransparentOverlay::DrawToBack(TwTransparentOverlay *this)

{
  tagRECT local_14;
  
                    // 0x579d  59  ?DrawToBack@TwTransparentOverlay@@UAEXXZ
  local_14.left = 0;
  local_14.top = 0;
  local_14.right = *(LONG *)(this + 0xa4);
  local_14.bottom = *(LONG *)(this + 0xa8);
  DD_SURFACE::BltFast(&GKERNEL::ddsBack,(DD_SURFACE *)(this + 0xd0),*(uint *)(this + 0xb4),
                      *(uint *)(this + 0xb8),&local_14);
  OVERLAY::DrawToBack((OVERLAY *)this);
  return;
}



// protected: void __thiscall TwTransparentOverlay::EraseInternalSurface(void)

void __thiscall TwTransparentOverlay::EraseInternalSurface(TwTransparentOverlay *this)

{
  HDC pHVar1;
  HGDIOBJ pvVar2;
  CBrush local_30 [8];
  HGDIOBJ local_28;
  HWND__ local_24;
  HGDIOBJ local_20;
  BOOL local_1c;
  CPen local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x5803  63  ?EraseInternalSurface@TwTransparentOverlay@@IAEXXZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_100108f5;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pHVar1 = DD_SURFACE::GetDC(&local_24);
  if (pHVar1 != (HDC)0x0) {
    CBrush::CBrush(local_30,*(ulong *)(this + 0x168));
    local_8 = 0;
    pvVar2 = (HGDIOBJ)FUN_10005980((int)local_30);
    local_28 = SelectObject((HDC)local_24.unused,pvVar2);
    CPen::CPen(local_18,0,1,*(ulong *)(this + 0x168));
    local_8._0_1_ = 1;
    pvVar2 = (HGDIOBJ)FUN_10001c50((int)local_18);
    local_20 = SelectObject((HDC)local_24.unused,pvVar2);
    local_1c = Rectangle((HDC)local_24.unused,0,0,*(int *)(this + 0xa4),*(int *)(this + 0xa8));
    SelectObject((HDC)local_24.unused,local_20);
    SelectObject((HDC)local_24.unused,local_28);
    DD_SURFACE::ReleaseDC((HWND)local_24.unused,(HDC)this);
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_10001c80((undefined4 *)local_18);
    local_8 = 0xffffffff;
    FUN_100059b0((undefined4 *)local_30);
  }
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_10005920(void *this,uint param_1)

{
  CMiniDockFrameWnd::~CMiniDockFrameWnd((CMiniDockFrameWnd *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



bool __cdecl FUN_10005950(char *param_1,char param_2)

{
  char cVar1;
  
  cVar1 = *param_1;
  *param_1 = param_2;
  return cVar1 != param_2;
}



undefined4 __fastcall FUN_10005980(int param_1)

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



void __fastcall FUN_100059b0(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_10011764;
  FUN_10001ca0(param_1);
  return;
}



void * __thiscall FUN_100059d0(void *this,uint param_1)

{
  FUN_100059b0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001c10(this);
  }
  return this;
}



void * __thiscall FUN_10005a00(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10010909;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  DD_SURFACE::DD_SURFACE((DD_SURFACE *)this);
  local_8 = 0;
  FUN_10006a50((void *)((int)this + 0x98),0,0,0,0);
  FUN_10006a50((void *)((int)this + 0xa8),0,0,0,0);
  FUN_10006b80((int)this + 0xb8);
  *(undefined ***)this = &PTR_FUN_10011778;
  uVar1 = param_1[1];
  *(undefined4 *)((int)this + 0xb8) = *param_1;
  *(undefined4 *)((int)this + 0xbc) = uVar1;
  memset(&local_7c,0,0x6c);
  local_7c = 0x6c;
  local_78 = 7;
  local_70 = *(undefined4 *)((int)this + 0xb8);
  local_74 = *(undefined4 *)((int)this + 0xbc);
  local_14 = 0x40;
  DD_SURFACE::Create((DD_SURFACE *)this,(_DDSURFACEDESC *)&local_7c,(HWND__ *)0x0);
  ExceptionList = local_10;
  return this;
}



void __thiscall FUN_10005aec(void *this,undefined4 *param_1,undefined4 *param_2)

{
  *(undefined4 *)((int)this + 0x98) = *param_1;
  *(undefined4 *)((int)this + 0x9c) = param_1[1];
  *(undefined4 *)((int)this + 0xa0) = param_1[2];
  *(undefined4 *)((int)this + 0xa4) = param_1[3];
  *(undefined4 *)((int)this + 0xa8) = *param_2;
  *(undefined4 *)((int)this + 0xac) = param_2[1];
  *(undefined4 *)((int)this + 0xb0) = param_2[2];
  *(undefined4 *)((int)this + 0xb4) = param_2[3];
  return;
}



void __thiscall
FUN_10005b3d(void *this,DD_SURFACE *param_1,undefined4 *param_2,DD_SURFACE *param_3,uint *param_4)

{
  bool bVar1;
  tagRECT *ptVar2;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  bVar1 = FUN_10005cda((int)this);
  if (bVar1) {
    local_24 = *param_2;
    local_20 = param_2[1];
    local_1c = param_2[2];
    local_18 = param_2[3];
    local_14 = *param_4;
    local_10 = param_4[1];
    local_c = param_4[2];
    local_8 = param_4[3];
    ptVar2 = (tagRECT *)FUN_10006ad0(&local_24);
    DD_SURFACE::BltFast(param_3,param_1,local_14,local_10,ptVar2);
  }
  return;
}



// public: virtual void __thiscall SPRITE::Show(void)

void __thiscall SPRITE::Show(SPRITE *this)

{
  char cVar1;
  
                    // 0x5bae  185  ?Show@SPRITE@@UAEXXZ
  cVar1 = (**(code **)(*(int *)this + 0x18))();
  if (cVar1 == '\0') {
    DD_SURFACE::Recreate((DD_SURFACE *)(this + 8));
    FUN_10001da0((int)this);
  }
  return;
}



// public: virtual void __thiscall SPRITE::Hide(void)

void __thiscall SPRITE::Hide(SPRITE *this)

{
  char cVar1;
  
                    // 0x5be0  87  ?Hide@SPRITE@@UAEXXZ
  cVar1 = (**(code **)(*(int *)this + 0x18))();
  if (cVar1 != '\0') {
    FUN_10001dc0((int)this);
    *(undefined4 *)(this + 4) = 2;
    DD_SURFACE::Release((DD_SURFACE *)(this + 8));
  }
  return;
}



// public: virtual void __thiscall SPRITE::OnRestore(bool)

void __thiscall SPRITE::OnRestore(SPRITE *this,bool param_1)

{
  char cVar1;
  
                    // 0x5c1c  117  ?OnRestore@SPRITE@@UAEX_N@Z
  FUN_10001c00();
  cVar1 = (**(code **)(*(int *)(this + -8) + 0x18))();
  if (cVar1 == '\0') {
    DD_SURFACE::Release((DD_SURFACE *)this);
  }
  return;
}



void __fastcall FUN_10005c55(void *param_1)

{
  FUN_10005b3d(param_1,&GKERNEL::ddsBack,(undefined4 *)((int)param_1 + 0x98),(DD_SURFACE *)param_1,
               (uint *)((int)param_1 + 0xa8));
  return;
}



void __fastcall FUN_10005c84(void *param_1)

{
  FUN_10005b3d(param_1,(DD_SURFACE *)param_1,(undefined4 *)((int)param_1 + 0xa8),&GKERNEL::ddsBack,
               (uint *)((int)param_1 + 0x98));
  return;
}



void __fastcall FUN_10005cb3(int param_1)

{
  FUN_10006b00((LPRECT)(param_1 + 0x98));
  FUN_10006b00((LPRECT)(param_1 + 0xa8));
  return;
}



bool __fastcall FUN_10005cda(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_10006ae0((RECT *)(param_1 + 0x98));
  return (bool)('\x01' - (iVar1 != 0));
}



// public: __thiscall SPRITE::SPRITE(void)

SPRITE * __thiscall SPRITE::SPRITE(SPRITE *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x5cf8  4  ??0SPRITE@@QAE@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_1001091c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  OVERLAY::OVERLAY((OVERLAY *)this);
  local_8 = 0;
  *(undefined4 *)(this + 0xd0) = 0;
  *(undefined4 *)(this + 0xd4) = 0;
  FUN_10006b40(this + 0xe0);
  *(undefined4 *)(this + 0x1100) = 0;
  *(undefined4 *)(this + 0x1104) = 0;
  *(undefined4 *)(this + 0x1108) = 1;
  *(undefined4 *)(this + 0x110c) = 1;
  *(undefined4 *)(this + 0x1118) = 0;
  *(undefined4 *)(this + 0x111c) = 0;
  *(undefined4 *)(this + 0x1120) = 1;
  FUN_100023b0((DWORD *)(this + 0x1124));
  *(undefined ***)this = &PTR_FUN_10011780;
  *(undefined ***)(this + 8) = &PTR_OnRestore_1001177c;
  GKERNEL::RegisterSprite((GKGOBJ *)this);
  *(undefined4 *)(this + 0x1128) = 0;
  ExceptionList = local_10;
  return this;
}



// public: virtual __thiscall SPRITE::~SPRITE(void)

void __thiscall SPRITE::~SPRITE(SPRITE *this)

{
  bool bVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x5df8  15  ??1SPRITE@@UAE@XZ
  puStack_c = &LAB_1001092f;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)this = &PTR_FUN_10011780;
  *(undefined ***)(this + 8) = &PTR_OnRestore_1001177c;
  local_8 = 0;
  bVar1 = GKERNEL::Initialized();
  if (bVar1) {
    GKERNEL::UnRegisterSprite((GKGOBJ *)this);
  }
  if (*(void **)(this + 0x1100) != (void *)0x0) {
    FUN_100069d0(*(void **)(this + 0x1100),1);
  }
  *(undefined4 *)(this + 0x1100) = 0;
  if (*(void **)(this + 0x1104) != (void *)0x0) {
    FUN_100069d0(*(void **)(this + 0x1104),1);
  }
  *(undefined4 *)(this + 0x1104) = 0;
  local_8 = 0xffffffff;
  FUN_10001ec0((undefined4 *)this);
  ExceptionList = local_10;
  return;
}



// public: virtual void __thiscall SPRITE::SetVelocity(int,int)

void __thiscall SPRITE::SetVelocity(SPRITE *this,int param_1,int param_2)

{
                    // 0x5edd  179  ?SetVelocity@SPRITE@@UAEXHH@Z
  (**(code **)(*(int *)this + 0x5c))(param_1);
  (**(code **)(*(int *)this + 0x60))(param_2);
  return;
}



// public: virtual void __thiscall SPRITE::SetXVelocity(int)

void __thiscall SPRITE::SetXVelocity(SPRITE *this,int param_1)

{
  uint uVar1;
  
                    // 0x5f08  182  ?SetXVelocity@SPRITE@@UAEXH@Z
  uVar1 = GKERNEL::FramesPerSecond();
  *(int *)(this + 0xd0) = (param_1 * 1000) / (int)uVar1;
  if (*(int *)(this + 0xd0) < 0x2ee1) {
    if (*(int *)(this + 0xd0) < -12000) {
      *(undefined4 *)(this + 0xd0) = 0xffffd120;
    }
  }
  else {
    *(undefined4 *)(this + 0xd0) = 12000;
  }
  return;
}



// public: virtual void __thiscall SPRITE::SetYVelocity(int)

void __thiscall SPRITE::SetYVelocity(SPRITE *this,int param_1)

{
  uint uVar1;
  
                    // 0x5f6f  183  ?SetYVelocity@SPRITE@@UAEXH@Z
  uVar1 = GKERNEL::FramesPerSecond();
  *(int *)(this + 0xd4) = (param_1 * 1000) / (int)uVar1;
  if (*(int *)(this + 0xd4) < 0x2ee1) {
    if (*(int *)(this + 0xd4) < -12000) {
      *(undefined4 *)(this + 0xd4) = 0xffffd120;
    }
  }
  else {
    *(undefined4 *)(this + 0xd4) = 12000;
  }
  return;
}



// public: virtual int __thiscall SPRITE::GetXVelocity(void)

int __thiscall SPRITE::GetXVelocity(SPRITE *this)

{
  uint uVar1;
  
                    // 0x5fd6  84  ?GetXVelocity@SPRITE@@UAEHXZ
  uVar1 = GKERNEL::FramesPerSecond();
  return (int)(uVar1 * *(int *)(this + 0xd0)) / 1000;
}



// public: virtual int __thiscall SPRITE::GetYVelocity(void)

int __thiscall SPRITE::GetYVelocity(SPRITE *this)

{
  uint uVar1;
  
                    // 0x5ffa  86  ?GetYVelocity@SPRITE@@UAEHXZ
  uVar1 = GKERNEL::FramesPerSecond();
  return (int)(uVar1 * *(int *)(this + 0xd4)) / 1000;
}



// public: void __thiscall SPRITE::Init(char const *,bool,int,int,int)

void __thiscall
SPRITE::Init(SPRITE *this,char *param_1,bool param_2,int param_3,int param_4,int param_5)

{
                    // 0x601e  96  ?Init@SPRITE@@QAEXPBD_NHHH@Z
  OVERLAY::Init((OVERLAY *)this,param_1,param_2);
  InitBuffers(this,param_2,param_3,param_4,param_5);
  return;
}



// public: void __thiscall SPRITE::Init(class DD_SURFACE const &,bool,int,int,int)

void __thiscall
SPRITE::Init(SPRITE *this,DD_SURFACE *param_1,bool param_2,int param_3,int param_4,int param_5)

{
                    // 0x6053  95  ?Init@SPRITE@@QAEXABVDD_SURFACE@@_NHHH@Z
  OVERLAY::Init((OVERLAY *)this,param_1,param_2);
  InitBuffers(this,param_2,param_3,param_4,param_5);
  return;
}



// public: virtual void __thiscall SPRITE::SetPosition(int,int)

void __thiscall SPRITE::SetPosition(SPRITE *this,int param_1,int param_2)

{
                    // 0x6088  170  ?SetPosition@SPRITE@@UAEXHH@Z
  *(int *)(this + 0xb4) = param_1;
  *(int *)(this + 0xb8) = param_2;
  *(int *)(this + 0xd8) = param_1 * 1000;
  *(int *)(this + 0xdc) = param_2 * 1000;
  return;
}



// public: void __thiscall SPRITE::ResetSurfaceInfo(class DD_SURFACE const &,bool,int,int,int)

void __thiscall
SPRITE::ResetSurfaceInfo
          (SPRITE *this,DD_SURFACE *param_1,bool param_2,int param_3,int param_4,int param_5)

{
  uint local_10;
  undefined1 local_c [8];
  
                    // 0x60d1  129  ?ResetSurfaceInfo@SPRITE@@QAEXABVDD_SURFACE@@_NHHH@Z
  OVERLAY::Position((OVERLAY *)this);
  OVERLAY::Init((OVERLAY *)this,param_1,param_2);
  if (*(int *)(this + 0x1100) == 0) {
    InitBuffers(this,param_2,param_3,param_4,param_5);
  }
  else {
    *(int *)(this + 0x1108) = param_4;
    *(int *)(this + 0x110c) = param_3;
    *(int *)(this + 0x1120) = param_5;
    *(uint *)(this + 0x1110) = *(uint *)(this + 0xa4) / *(uint *)(this + 0x110c);
    *(uint *)(this + 0x1114) = *(uint *)(this + 0xa8) / *(uint *)(this + 0x1108);
    (**(code **)(*(int *)this + 0x70))(0);
    for (local_10 = 0; local_10 < *(uint *)(this + 0x1120); local_10 = local_10 + 1) {
      *(uint *)(this + local_10 * 4 + 0xfc) = local_10;
    }
    *(undefined4 *)(this + 0x10fc) = *(undefined4 *)(this + 0x1120);
  }
  (**(code **)(*(int *)this + 0x28))(local_c);
  return;
}



// public: void __thiscall SPRITE::InitBuffers(bool,int,int,int)

void __thiscall SPRITE::InitBuffers(SPRITE *this,bool param_1,int param_2,int param_3,int param_4)

{
  undefined4 *puVar1;
  void *local_58;
  void *local_50;
  undefined1 local_44 [8];
  void *local_3c;
  void *local_34;
  void *local_30;
  undefined1 local_2c [8];
  void *local_24;
  void *local_20;
  void *local_1c;
  void *local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x61e6  103  ?InitBuffers@SPRITE@@QAEX_NHHH@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1001094f;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(int *)(this + 0x1108) = param_3;
  *(int *)(this + 0x110c) = param_2;
  *(int *)(this + 0x1120) = param_4;
  *(uint *)(this + 0x1110) = *(uint *)(this + 0xa4) / *(uint *)(this + 0x110c);
  *(uint *)(this + 0x1114) = *(uint *)(this + 0xa8) / *(uint *)(this + 0x1108);
  (**(code **)(*(int *)this + 0x70))(0);
  for (local_14 = 0; local_14 < *(uint *)(this + 0x1120); local_14 = local_14 + 1) {
    *(uint *)(this + local_14 * 4 + 0xfc) = local_14;
  }
  *(undefined4 *)(this + 0x10fc) = *(undefined4 *)(this + 0x1120);
  local_1c = *(void **)(this + 0x1100);
  local_18 = local_1c;
  if (local_1c != (void *)0x0) {
    FUN_100069d0(local_1c,1);
  }
  *(undefined4 *)(this + 0x1100) = 0;
  local_24 = operator_new(0xc0);
  local_8 = 0;
  if (local_24 == (void *)0x0) {
    local_50 = (void *)0x0;
  }
  else {
    puVar1 = (undefined4 *)
             FUN_10001e70(local_2c,*(uint *)(this + 0xa4) / *(uint *)(this + 0x110c),
                          *(uint *)(this + 0xa8) / *(uint *)(this + 0x1108));
    local_50 = FUN_10005a00(local_24,puVar1);
  }
  local_20 = local_50;
  local_8 = 0xffffffff;
  *(void **)(this + 0x1100) = local_50;
  local_34 = *(void **)(this + 0x1104);
  local_30 = local_34;
  if (local_34 != (void *)0x0) {
    FUN_100069d0(local_34,1);
  }
  *(undefined4 *)(this + 0x1104) = 0;
  local_3c = operator_new(0xc0);
  local_8 = 1;
  if (local_3c == (void *)0x0) {
    local_58 = (void *)0x0;
  }
  else {
    puVar1 = (undefined4 *)
             FUN_10001e70(local_44,*(uint *)(this + 0xa4) / *(uint *)(this + 0x110c),
                          *(uint *)(this + 0xa8) / *(uint *)(this + 0x1108));
    local_58 = FUN_10005a00(local_3c,puVar1);
  }
  *(void **)(this + 0x1104) = local_58;
  ExceptionList = local_10;
  return;
}



// public: virtual void __thiscall SPRITE::SetCurrentImage(unsigned int)

void __thiscall SPRITE::SetCurrentImage(SPRITE *this,uint param_1)

{
  int local_14;
  int local_10;
  int local_c;
  int local_8;
  
                    // 0x6435  148  ?SetCurrentImage@SPRITE@@UAEXI@Z
  *(uint *)(this + 0x1118) = param_1;
  local_14 = (*(int *)(this + 0x1118) % *(int *)(this + 0x110c)) * *(int *)(this + 0x1110);
  local_c = (*(int *)(this + 0x1118) % *(int *)(this + 0x110c) + 1) * *(int *)(this + 0x1110);
  local_10 = (*(int *)(this + 0x1118) / *(int *)(this + 0x110c)) * *(int *)(this + 0x1114);
  local_8 = (*(int *)(this + 0x1118) / *(int *)(this + 0x110c) + 1) * *(int *)(this + 0x1114);
  (**(code **)(*(int *)this + 0x48))(&local_14);
  return;
}



// public: virtual void __thiscall SPRITE::SetAnimationDelay(unsigned int)

void __thiscall SPRITE::SetAnimationDelay(SPRITE *this,uint param_1)

{
                    // 0x64e7  140  ?SetAnimationDelay@SPRITE@@UAEXI@Z
  *(uint *)(this + 0x1128) = param_1;
  return;
}



// public: virtual void __thiscall SPRITE::StartAnimation(void)

void __thiscall SPRITE::StartAnimation(SPRITE *this)

{
                    // 0x6500  188  ?StartAnimation@SPRITE@@UAEXXZ
  *(undefined4 *)(this + 0x111c) = 1;
  return;
}



// public: virtual void __thiscall SPRITE::StopAnimation(void)

void __thiscall SPRITE::StopAnimation(SPRITE *this)

{
                    // 0x6518  192  ?StopAnimation@SPRITE@@UAEXXZ
  *(undefined4 *)(this + 0x111c) = 0;
  return;
}



// public: virtual void __thiscall SPRITE::FlipSprite(void)

void __thiscall SPRITE::FlipSprite(SPRITE *this)

{
                    // 0x6530  67  ?FlipSprite@SPRITE@@UAEXXZ
  FUN_10006a20((undefined4 *)(this + 0x1100),(undefined4 *)(this + 0x1104));
  return;
}



// public: virtual void __thiscall SPRITE::ZeroSaveBufs(void)

void __thiscall SPRITE::ZeroSaveBufs(SPRITE *this)

{
                    // 0x6556  202  ?ZeroSaveBufs@SPRITE@@UAEXXZ
  FUN_10005cb3(*(int *)(this + 0x1100));
  FUN_10005cb3(*(int *)(this + 0x1104));
  return;
}



// public: virtual void __thiscall SPRITE::SaveUnderSprite(void)

void __thiscall SPRITE::SaveUnderSprite(SPRITE *this)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  undefined1 local_3c [16];
  undefined1 local_2c [16];
  int local_1c;
  int local_18;
  int local_14 [4];
  
                    // 0x657d  136  ?SaveUnderSprite@SPRITE@@UAEXXZ
  local_18 = 0;
  local_1c = 0;
  FUN_10006b80(local_14);
  uVar1 = FUN_1000471f(this,local_14,&local_18,&local_1c);
  if ((uVar1 & 0xff) == 0) {
    FUN_10005cb3(*(int *)(this + 0x1100));
  }
  else {
    iVar2 = FUN_10006ab0((int)local_14);
    iVar3 = FUN_10006a90(local_14);
    puVar4 = (undefined4 *)FUN_10006a50(local_2c,0,0,iVar3,iVar2);
    iVar2 = FUN_10006ab0((int)local_14);
    iVar2 = local_1c + iVar2;
    iVar3 = FUN_10006a90(local_14);
    puVar5 = (undefined4 *)FUN_10006a50(local_3c,local_18,local_1c,local_18 + iVar3,iVar2);
    FUN_10005aec(*(void **)(this + 0x1100),puVar5,puVar4);
  }
  FUN_10005c55(*(void **)(this + 0x1100));
  return;
}



// public: virtual void __thiscall SPRITE::RestoreUnderSprite(void)

void __thiscall SPRITE::RestoreUnderSprite(SPRITE *this)

{
                    // 0x6635  131  ?RestoreUnderSprite@SPRITE@@UAEXXZ
  FUN_10005c84(*(void **)(this + 0x1100));
  return;
}



// public: virtual void __thiscall SPRITE::DrawToBack(void)

void __thiscall SPRITE::DrawToBack(SPRITE *this)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  undefined4 local_c;
  undefined4 local_8;
  
                    // 0x664e  52  ?DrawToBack@SPRITE@@UAEXXZ
  if (*(int *)(this + 0x111c) != 0) {
    bVar1 = FUN_10003fc0(this + 0x1124,*(uint *)(this + 0x1128));
    if (CONCAT31(extraout_var,bVar1) != 0) {
      (**(code **)(*(int *)this + 0x70))
                (*(undefined4 *)
                  (this + ((*(int *)(this + 0x1118) + 1U) % *(uint *)(this + 0x10fc)) * 4 + 0xfc));
    }
  }
  OVERLAY::DrawToBack((OVERLAY *)this);
  cVar2 = FUN_10002000(this + 0xe0);
  if (cVar2 == '\0') {
    if ((*(int *)(this + 0xd0) != 0) || (*(int *)(this + 0xd4) != 0)) {
      *(int *)(this + 0xd8) = *(int *)(this + 0xd8) + *(int *)(this + 0xd0);
      *(int *)(this + 0xdc) = *(int *)(this + 0xdc) + *(int *)(this + 0xd4);
      *(int *)(this + 0xb4) = *(int *)(this + 0xd8) / 1000;
      *(int *)(this + 0xb8) = *(int *)(this + 0xdc) / 1000;
    }
  }
  else {
    FUN_1000686e(this + 0xe0,&local_c);
    *(undefined4 *)(this + 0xb4) = local_c;
    *(undefined4 *)(this + 0xb8) = local_8;
  }
  return;
}



// public: void __thiscall SPRITE::SetAnimationSet(unsigned int *,unsigned int)

void __thiscall SPRITE::SetAnimationSet(SPRITE *this,uint *param_1,uint param_2)

{
  uint local_8;
  
                    // 0x6780  142  ?SetAnimationSet@SPRITE@@QAEXPAII@Z
  for (local_8 = 0; local_8 < param_2; local_8 = local_8 + 1) {
    *(uint *)(this + local_8 * 4 + 0xfc) = param_1[local_8];
  }
  *(uint *)(this + 0x10fc) = param_2;
  return;
}



// public: void __thiscall SPRITE::SetAnimationRange(unsigned int,unsigned int)

void __thiscall SPRITE::SetAnimationRange(SPRITE *this,uint param_1,uint param_2)

{
  uint local_8;
  
                    // 0x67cf  141  ?SetAnimationRange@SPRITE@@QAEXII@Z
  *(uint *)(this + 0x10fc) = (param_2 - param_1) + 1;
  for (local_8 = 0; local_8 < *(uint *)(this + 0x10fc); local_8 = local_8 + 1) {
    *(uint *)(this + local_8 * 4 + 0xfc) = param_1 + local_8;
  }
  return;
}



void __thiscall FUN_10006825(void *this,undefined4 *param_1,undefined4 *param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  *(undefined1 *)this = 1;
  uVar1 = param_1[1];
  *(undefined4 *)((int)this + 8) = *param_1;
  *(undefined4 *)((int)this + 0xc) = uVar1;
  uVar1 = param_2[1];
  *(undefined4 *)((int)this + 0x10) = *param_2;
  *(undefined4 *)((int)this + 0x14) = uVar1;
  *(undefined4 *)((int)this + 0x18) = param_3;
  FUN_10003fa0((DWORD *)((int)this + 4));
  return;
}



undefined4 * __thiscall FUN_1000686e(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  double dVar2;
  bool bVar3;
  undefined3 extraout_var;
  uint uVar4;
  int iVar5;
  int iVar6;
  
  bVar3 = FUN_10003fc0((void *)((int)this + 4),*(uint *)((int)this + 0x18));
  if (CONCAT31(extraout_var,bVar3) == 0) {
    uVar4 = FUN_10006b20((int *)((int)this + 4));
    dVar2 = (double)uVar4 / (double)*(uint *)((int)this + 0x18);
    iVar5 = round((double)(*(int *)((int)this + 0x10) - *(int *)((int)this + 8)) * dVar2);
    iVar6 = round((double)(*(int *)((int)this + 0x14) - *(int *)((int)this + 0xc)) * dVar2);
    FUN_10001e70(param_1,*(int *)((int)this + 8) + iVar5,*(int *)((int)this + 0xc) + iVar6);
  }
  else {
    *(undefined1 *)this = 0;
    uVar1 = *(undefined4 *)((int)this + 0x14);
    *param_1 = *(undefined4 *)((int)this + 0x10);
    param_1[1] = uVar1;
  }
  return param_1;
}



// public: virtual void __thiscall SPRITE::MoveTo(unsigned int,unsigned int,unsigned int)

void __thiscall SPRITE::MoveTo(SPRITE *this,uint param_1,uint param_2,uint param_3)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined1 local_14 [8];
  undefined1 local_c [8];
  
                    // 0x694f  112  ?MoveTo@SPRITE@@UAEXIII@Z
  puVar1 = (undefined4 *)FUN_10001e70(local_c,param_1,param_2);
  puVar2 = (undefined4 *)
           FUN_10001e70(local_14,*(undefined4 *)(this + 0xb4),*(undefined4 *)(this + 0xb8));
  FUN_10006825(this + 0xe0,puVar2,puVar1,param_3);
  return;
}



void * __thiscall FUN_100069a0(void *this,uint param_1)

{
  SPRITE::~SPRITE((SPRITE *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void * __thiscall FUN_100069d0(void *this,uint param_1)

{
  FUN_10006a00((DD_SURFACE *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_10006a00(DD_SURFACE *param_1)

{
  DD_SURFACE::~DD_SURFACE(param_1);
  return;
}



void __cdecl FUN_10006a20(undefined4 *param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  
  uVar1 = *param_1;
  *param_1 = *param_2;
  *param_2 = uVar1;
  return;
}



void * __thiscall
FUN_10006a50(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  *(undefined4 *)this = param_1;
  *(undefined4 *)((int)this + 4) = param_2;
  *(undefined4 *)((int)this + 8) = param_3;
  *(undefined4 *)((int)this + 0xc) = param_4;
  return this;
}



int __fastcall FUN_10006a90(int *param_1)

{
  return param_1[2] - *param_1;
}



int __fastcall FUN_10006ab0(int param_1)

{
  return *(int *)(param_1 + 0xc) - *(int *)(param_1 + 4);
}



undefined4 __fastcall FUN_10006ad0(undefined4 param_1)

{
  return param_1;
}



void __fastcall FUN_10006ae0(RECT *param_1)

{
  IsRectEmpty(param_1);
  return;
}



void __fastcall FUN_10006b00(LPRECT param_1)

{
  SetRectEmpty(param_1);
  return;
}



int __fastcall FUN_10006b20(int *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  return DVar1 - *param_1;
}



undefined1 * __fastcall FUN_10006b40(undefined1 *param_1)

{
  *param_1 = 0;
  FUN_100023b0((DWORD *)(param_1 + 4));
  FUN_10006b80(param_1 + 8);
  FUN_10006b80(param_1 + 0x10);
  return param_1;
}



undefined4 __fastcall FUN_10006b80(undefined4 param_1)

{
  return param_1;
}



// public: __thiscall TwProgressBar::TwProgressBar(void)

TwProgressBar * __thiscall TwProgressBar::TwProgressBar(TwProgressBar *this)

{
                    // 0x6b90  10  ??0TwProgressBar@@QAE@XZ
  TwTransparentOverlay::TwTransparentOverlay((TwTransparentOverlay *)this);
  *(undefined ***)this = &PTR_FUN_100117f8;
  *(undefined ***)(this + 8) = &PTR_FUN_100117f4;
  *(undefined4 *)(this + 0x170) = 0;
  this[0x16c] = (TwProgressBar)0x0;
  return this;
}



// public: void __thiscall TwProgressBar::SetParams(unsigned int,unsigned long,unsigned long)

void __thiscall
TwProgressBar::SetParams(TwProgressBar *this,uint param_1,ulong param_2,ulong param_3)

{
                    // 0x6bd0  162  ?SetParams@TwProgressBar@@QAEXIKK@Z
  *(uint *)(this + 0x174) = param_1;
  *(ulong *)(this + 0x178) = param_2;
  *(ulong *)(this + 0x17c) = param_3;
  TwTransparentOverlay::SetTransparentColor((TwTransparentOverlay *)this,param_3);
  return;
}



void __fastcall FUN_10006c0d(TwTransparentOverlay *param_1)

{
  HDC pHVar1;
  HGDIOBJ pvVar2;
  int iVar3;
  CBrush local_4c [8];
  uint local_44;
  HWND__ local_40;
  HGDIOBJ local_3c;
  CPen local_38 [8];
  CBrush local_30 [8];
  uint local_28;
  undefined4 local_24 [2];
  HGDIOBJ local_1c;
  CPen local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1001098d;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  TwTransparentOverlay::EraseInternalSurface(param_1);
  pHVar1 = DD_SURFACE::GetDC(&local_40);
  if (pHVar1 != (HDC)0x0) {
    FUN_10004e70(local_24,param_1 + 0x16c,1);
    local_8 = 0;
    CPen::CPen(local_18,0,1,*(ulong *)(param_1 + 0x178));
    local_8._0_1_ = 1;
    CBrush::CBrush(local_4c,*(ulong *)(param_1 + 0x178));
    local_8._0_1_ = 2;
    CPen::CPen(local_38,0,1,*(ulong *)(param_1 + 0x17c));
    local_8._0_1_ = 3;
    CBrush::CBrush(local_30,*(ulong *)(param_1 + 0x17c));
    local_8 = CONCAT31(local_8._1_3_,4);
    pvVar2 = (HGDIOBJ)FUN_10001c50((int)local_18);
    local_3c = SelectObject((HDC)local_40.unused,pvVar2);
    pvVar2 = (HGDIOBJ)FUN_10005980((int)local_4c);
    local_1c = SelectObject((HDC)local_40.unused,pvVar2);
    local_44 = (uint)(*(int *)(param_1 + 0x170) * *(int *)(param_1 + 0x174)) / 100;
    for (local_28 = 0; local_28 < *(uint *)(param_1 + 0x174); local_28 = local_28 + 1) {
      iVar3 = local_28 * 6;
      if (local_28 == local_44) {
        pvVar2 = (HGDIOBJ)FUN_10001c50((int)local_38);
        SelectObject((HDC)local_40.unused,pvVar2);
        pvVar2 = (HGDIOBJ)FUN_10005980((int)local_30);
        SelectObject((HDC)local_40.unused,pvVar2);
      }
      Rectangle((HDC)local_40.unused,iVar3 + 0x61,0x10,iVar3 + 0x65,0x1a);
    }
    SelectObject((HDC)local_40.unused,local_3c);
    SelectObject((HDC)local_40.unused,local_1c);
    DD_SURFACE::ReleaseDC((HWND)local_40.unused,(HDC)param_1);
    local_8._0_1_ = 3;
    FUN_100059b0((undefined4 *)local_30);
    local_8._0_1_ = 2;
    FUN_10001c80((undefined4 *)local_38);
    local_8._0_1_ = 1;
    FUN_100059b0((undefined4 *)local_4c);
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_10001c80((undefined4 *)local_18);
    local_8 = 0xffffffff;
    FUN_10004ea0(local_24);
  }
  ExceptionList = local_10;
  return;
}



// public: virtual void __thiscall TwProgressBar::DrawToBack(void)

void __thiscall TwProgressBar::DrawToBack(TwProgressBar *this)

{
                    // 0x6e0c  57  ?DrawToBack@TwProgressBar@@UAEXXZ
  if (this[0x16c] == (TwProgressBar)0x0) {
    FUN_10006c0d((TwTransparentOverlay *)this);
  }
  TwTransparentOverlay::DrawToBack((TwTransparentOverlay *)this);
  return;
}



// public: void __thiscall TwProgressBar::SetPercentage(unsigned int)

void __thiscall TwProgressBar::SetPercentage(TwProgressBar *this,uint param_1)

{
                    // 0x6e36  163  ?SetPercentage@TwProgressBar@@QAEXI@Z
  if (100 < param_1) {
    param_1 = 100;
  }
  *(uint *)(this + 0x170) = param_1;
  this[0x16c] = (TwProgressBar)0x0;
  return;
}



// public: __thiscall TwSinWave::TwSinWave(void)

TwSinWave * __thiscall TwSinWave::TwSinWave(TwSinWave *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x6e70  11  ??0TwSinWave@@QAE@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_100109a9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  TwTransparentOverlay::TwTransparentOverlay((TwTransparentOverlay *)this);
  local_8 = 0;
  FUN_100023b0((DWORD *)(this + 0x194));
  *(undefined ***)this = &PTR_FUN_10011848;
  *(undefined ***)(this + 8) = &PTR_FUN_10011844;
  *(undefined4 *)(this + 400) = 0;
  *(undefined4 *)(this + 0x18c) = 0;
  *(undefined4 *)(this + 0x16c) = 0xffffff;
  *(undefined4 *)(this + 0x184) = 0;
  *(undefined4 *)(this + 0x188) = 0;
  *(undefined4 *)(this + 0x178) = 2;
  *(undefined4 *)(this + 0x180) = 1;
  ExceptionList = local_10;
  return this;
}



// public: virtual __thiscall TwSinWave::~TwSinWave(void)

void __thiscall TwSinWave::~TwSinWave(TwSinWave *this)

{
                    // 0x6f2f  17  ??1TwSinWave@@UAE@XZ
  *(undefined ***)this = &PTR_FUN_10011848;
  *(undefined ***)(this + 8) = &PTR_FUN_10011844;
  if (*(int *)(this + 400) != 0) {
    free(*(void **)(this + 400));
  }
  if (*(int *)(this + 0x18c) != 0) {
    free(*(void **)(this + 0x18c));
  }
  CMiniDockFrameWnd::~CMiniDockFrameWnd((CMiniDockFrameWnd *)this);
  return;
}



// public: void __thiscall TwSinWave::Init(unsigned int,unsigned int,unsigned long,unsigned long)

void __thiscall
TwSinWave::Init(TwSinWave *this,uint param_1,uint param_2,ulong param_3,ulong param_4)

{
  void *pvVar1;
  
                    // 0x6f93  101  ?Init@TwSinWave@@QAEXIIKK@Z
  TwTransparentOverlay::Init((TwTransparentOverlay *)this,param_1,param_2);
  if (*(int *)(this + 400) != 0) {
    free(*(void **)(this + 400));
    *(undefined4 *)(this + 400) = 0;
  }
  if (*(int *)(this + 0x18c) != 0) {
    free(*(void **)(this + 0x18c));
    *(undefined4 *)(this + 0x18c) = 0;
  }
  pvVar1 = malloc(param_1 * 0xf0);
  *(void **)(this + 400) = pvVar1;
  pvVar1 = malloc(0x78);
  *(void **)(this + 0x18c) = pvVar1;
  SetColor(this,param_3,param_4);
  SetSpeed(this,0);
  *(undefined4 *)(this + 0x17c) = 0;
  return;
}



// public: void __thiscall TwSinWave::SetColor(unsigned long,unsigned long)

void __thiscall TwSinWave::SetColor(TwSinWave *this,ulong param_1,ulong param_2)

{
  bool bVar1;
  ulong uVar2;
  undefined3 extraout_var;
  ulong *puVar3;
  uint uVar4;
  undefined3 extraout_var_00;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined1 uVar7;
  undefined1 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined1 local_48 [12];
  uint local_3c;
  undefined4 local_38 [7];
  int local_1c;
  int local_18;
  ulong local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x706b  145  ?SetColor@TwSinWave@@QAEXKK@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_100109bc;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  uVar2 = TwTransparentOverlay::GetColor((TwTransparentOverlay *)this,param_2);
  *(ulong *)(this + 0x170) = uVar2;
  uVar2 = TwTransparentOverlay::GetColor((TwTransparentOverlay *)this,param_1);
  *(ulong *)(this + 0x16c) = uVar2;
  TwColorTools::GetColorInterpolationsExclusive
            ((ulong)local_38,*(ulong *)(this + 0x16c),*(uint *)(this + 0x170));
  local_8 = 0;
  local_1c = 0;
  local_18 = FUN_1000e790((int)local_38);
  local_14 = 0;
  local_3c = 0;
  bVar1 = IsEmpty((int)local_38);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar3 = (ulong *)FUN_100018b0(&local_18);
    local_14 = *puVar3;
  }
  local_3c = 0;
  while ((uVar4 = FUN_1000ff30((int)local_38), local_3c < uVar4 &&
         (bVar1 = IsEmpty((int)local_38), CONCAT31(extraout_var_00,bVar1) == 0))) {
    uVar10 = 0;
    uVar9 = 0;
    uVar2 = TwTransparentOverlay::GetColor((TwTransparentOverlay *)this,local_14);
    uVar8 = (undefined1)(uVar2 >> 0x10);
    uVar2 = TwTransparentOverlay::GetColor((TwTransparentOverlay *)this,local_14);
    uVar7 = (undefined1)(uVar2 >> 8);
    uVar2 = TwTransparentOverlay::GetColor((TwTransparentOverlay *)this,local_14);
    puVar5 = (undefined4 *)FUN_100076f0(local_48,(char)uVar2,uVar7,uVar8,uVar9,uVar10);
    puVar6 = (undefined4 *)(*(int *)(this + 0x18c) + local_1c * 0xc);
    *puVar6 = *puVar5;
    puVar6[1] = puVar5[1];
    puVar6[2] = puVar5[2];
    local_1c = local_1c + 1;
    local_3c = local_3c + 1;
    uVar4 = FUN_1000ff30((int)local_38);
    if (local_3c < uVar4) {
      puVar3 = (ulong *)FUN_100018b0(&local_18);
      local_14 = *puVar3;
    }
  }
  local_8 = 0xffffffff;
  FUN_10001810(local_38);
  ExceptionList = local_10;
  return;
}



// public: void __thiscall TwSinWave::SetFramesPerSecond(unsigned long)

void __thiscall TwSinWave::SetFramesPerSecond(TwSinWave *this,ulong param_1)

{
                    // 0x7208  152  ?SetFramesPerSecond@TwSinWave@@QAEXK@Z
  if (param_1 == 0) {
    *(undefined4 *)(this + 0x174) = 0xffffffff;
  }
  else {
    *(int *)(this + 0x174) = (int)(1000 / (ulonglong)param_1);
    FUN_10003fa0((DWORD *)(this + 0x194));
  }
  return;
}



// public: void __thiscall TwSinWave::SetSpeed(unsigned long)

void __thiscall TwSinWave::SetSpeed(TwSinWave *this,ulong param_1)

{
                    // 0x724b  175  ?SetSpeed@TwSinWave@@QAEXK@Z
  *(ulong *)(this + 0x180) = param_1;
  return;
}



void __fastcall FUN_10007264(TwTransparentOverlay *param_1)

{
  ulonglong uVar1;
  int iVar2;
  undefined4 uVar3;
  ulong uVar4;
  undefined4 *puVar5;
  TwTransparentOverlay *hdc;
  undefined4 *puVar6;
  double dVar7;
  undefined1 uVar8;
  undefined1 uVar9;
  uint uVar10;
  undefined1 local_38 [12];
  uint local_2c;
  uint local_28;
  double local_24;
  double local_1c;
  int local_14;
  double local_10;
  uint local_8;
  
  local_1c = 0.0;
  local_24 = 0.0;
  local_10 = (double)*(uint *)(param_1 + 0x17c);
  TwTransparentOverlay::EraseInternalSurface(param_1);
  local_14 = 0;
  for (local_8 = 0; local_8 < *(uint *)(param_1 + 0xa4); local_8 = local_8 + 1) {
    local_2c = (*(int *)(param_1 + 0xa8) + *(int *)(param_1 + 0x178) * -2) -
               *(int *)(param_1 + 0x184);
    local_1c = (double)local_8 * (12.56637061435916 / (double)*(uint *)(param_1 + 0xa4));
    uVar1 = (ulonglong)local_2c;
    dVar7 = sin(local_10 / 6.28318530717958 + local_1c);
    local_24 = (double)(*(uint *)(param_1 + 0x184) >> 1) +
               (double)*(uint *)(param_1 + 0x178) + (1.0 - dVar7) * ((double)uVar1 / 2.0);
    dVar7 = RandomProb();
    local_24 = ((double)*(uint *)(param_1 + 0x188) * (dVar7 + dVar7) -
               (double)*(uint *)(param_1 + 0x188)) + local_24;
    if ((0.0 <= local_24) &&
       (iVar2 = ftol(), (uint)(iVar2 + *(int *)(param_1 + 0x178)) < *(uint *)(param_1 + 0xa8))) {
      uVar3 = ftol();
      uVar10 = local_8;
      uVar4 = TwTransparentOverlay::GetColor(param_1,*(ulong *)(param_1 + 0x16c));
      uVar9 = (undefined1)(uVar4 >> 0x10);
      uVar4 = TwTransparentOverlay::GetColor(param_1,*(ulong *)(param_1 + 0x16c));
      uVar8 = (undefined1)(uVar4 >> 8);
      uVar4 = TwTransparentOverlay::GetColor(param_1,*(ulong *)(param_1 + 0x16c));
      puVar5 = (undefined4 *)FUN_100076f0(local_38,(char)uVar4,uVar8,uVar9,uVar10,uVar3);
      puVar6 = (undefined4 *)(*(int *)(param_1 + 400) + local_14 * 0xc);
      *puVar6 = *puVar5;
      puVar6[1] = puVar5[1];
      puVar6[2] = puVar5[2];
      local_14 = local_14 + 1;
      for (local_28 = 0; local_28 < *(uint *)(param_1 + 0x178); local_28 = local_28 + 1) {
        if (0.0 <= local_24 - (double)(local_28 + 1)) {
          puVar6 = (undefined4 *)(*(int *)(param_1 + 0x18c) + local_28 * 0xc);
          puVar5 = (undefined4 *)(*(int *)(param_1 + 400) + local_14 * 0xc);
          *puVar5 = *puVar6;
          puVar5[1] = puVar6[1];
          puVar5[2] = puVar6[2];
          puVar6 = (undefined4 *)(*(int *)(param_1 + 0x18c) + local_28 * 0xc);
          puVar5 = (undefined4 *)(*(int *)(param_1 + 400) + (local_14 + 1) * 0xc);
          *puVar5 = *puVar6;
          puVar5[1] = puVar6[1];
          puVar5[2] = puVar6[2];
          *(uint *)(*(int *)(param_1 + 400) + 4 + local_14 * 0xc) = local_8;
          *(uint *)(*(int *)(param_1 + 400) + 4 + (local_14 + 1) * 0xc) = local_8;
          iVar2 = ftol();
          *(uint *)(*(int *)(param_1 + 400) + 8 + local_14 * 0xc) = iVar2 + 1 + local_28;
          iVar2 = ftol();
          *(uint *)(*(int *)(param_1 + 400) + 8 + (local_14 + 1) * 0xc) = iVar2 - (local_28 + 1);
          local_14 = local_14 + 2;
        }
      }
    }
  }
  if (param_1 == (TwTransparentOverlay *)0x0) {
    hdc = (TwTransparentOverlay *)0x0;
  }
  else {
    hdc = param_1 + 8;
  }
  GKTOOLS::SetPixel((HDC)hdc,*(int *)(param_1 + 400),local_14,(COLORREF)hdc);
  return;
}



// public: virtual void __thiscall TwSinWave::DrawToBack(void)

void __thiscall TwSinWave::DrawToBack(TwSinWave *this)

{
  bool bVar1;
  undefined3 extraout_var;
  
                    // 0x7615  58  ?DrawToBack@TwSinWave@@UAEXXZ
  if (*(int *)(this + 0x17c) != 0) {
    bVar1 = FUN_10003fc0(this + 0x194,*(uint *)(this + 0x174));
    if (CONCAT31(extraout_var,bVar1) == 0) goto LAB_10007667;
  }
  *(int *)(this + 0x17c) = *(int *)(this + 0x17c) + *(int *)(this + 0x180);
  FUN_10007264((TwTransparentOverlay *)this);
LAB_10007667:
  TwTransparentOverlay::DrawToBack((TwTransparentOverlay *)this);
  return;
}



// public: void __thiscall TwSinWave::SetOneSideThickness(unsigned int)

void __thiscall TwSinWave::SetOneSideThickness(TwSinWave *this,uint param_1)

{
                    // 0x7673  159  ?SetOneSideThickness@TwSinWave@@QAEXI@Z
  *(uint *)(this + 0x178) = param_1;
  return;
}



// public: void __thiscall TwSinWave::SetNoise(unsigned int)

void __thiscall TwSinWave::SetNoise(TwSinWave *this,uint param_1)

{
                    // 0x768c  157  ?SetNoise@TwSinWave@@QAEXI@Z
  *(uint *)(this + 0x188) = param_1;
  return;
}



// public: void __thiscall TwSinWave::SetVerticalMargin(unsigned int)

void __thiscall TwSinWave::SetVerticalMargin(TwSinWave *this,uint param_1)

{
                    // 0x76a5  180  ?SetVerticalMargin@TwSinWave@@QAEXI@Z
  *(uint *)(this + 0x184) = param_1;
  return;
}



void * __thiscall FUN_100076c0(void *this,uint param_1)

{
  TwSinWave::~TwSinWave((TwSinWave *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void * __thiscall
FUN_100076f0(void *this,undefined1 param_1,undefined1 param_2,undefined1 param_3,undefined4 param_4,
            undefined4 param_5)

{
  *(undefined1 *)this = param_1;
  *(undefined1 *)((int)this + 1) = param_2;
  *(undefined1 *)((int)this + 2) = param_3;
  *(undefined4 *)((int)this + 4) = param_4;
  *(undefined4 *)((int)this + 8) = param_5;
  return this;
}



// protected: static struct AFX_MSGMAP const * __stdcall TwDirectXDialog::_GetBaseMessageMap(void)

AFX_MSGMAP * TwDirectXDialog::_GetBaseMessageMap(void)

{
                    // 0x7730  203  ?_GetBaseMessageMap@TwDirectXDialog@@KGPBUAFX_MSGMAP@@XZ
  return (AFX_MSGMAP *)messageMap_exref;
}



// protected: virtual struct AFX_MSGMAP const * __thiscall TwDirectXDialog::GetMessageMap(void)const
// 

AFX_MSGMAP * __thiscall TwDirectXDialog::GetMessageMap(TwDirectXDialog *this)

{
                    // 0x773a  80  ?GetMessageMap@TwDirectXDialog@@MBEPBUAFX_MSGMAP@@XZ
  return (AFX_MSGMAP *)&messageMap;
}



void FUN_1000774a(void)

{
  FUN_10007759();
  FUN_10007768();
  return;
}



void FUN_10007759(void)

{
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)&DAT_10019060);
  return;
}



void FUN_10007768(void)

{
  FUN_100104a2(FUN_1000777a);
  return;
}



void FUN_1000777a(void)

{
  if ((DAT_1001907c & 1) == 0) {
    DAT_1001907c = DAT_1001907c | 1;
    FUN_10007a80((undefined4 *)&DAT_10019060);
  }
  return;
}



// public: static void __cdecl TwDirectXDialog::EnableFullScreenSupport(bool)

void __cdecl TwDirectXDialog::EnableFullScreenSupport(bool param_1)

{
  bool bVar1;
  HWND__ *pHVar2;
  UINT UVar3;
  WPARAM WVar4;
  LPARAM LVar5;
  int iVar6;
  
                    // 0x77a6  62  ?EnableFullScreenSupport@TwDirectXDialog@@SAX_N@Z
  DAT_1001907d = param_1;
  if (param_1) {
    bVar1 = GKERNEL::SupportsFullScreenGDIClipping();
    if (!bVar1) {
      bVar1 = GKERNEL::Windowed();
      if (!bVar1) {
        if (DAT_100188ac != '\0') {
          ShowMouse(true);
        }
        LVar5 = 0;
        WVar4 = 0xf020;
        UVar3 = 0x112;
        pHVar2 = GKERNEL::GetHwnd();
        SendMessageA(pHVar2,UVar3,WVar4,LVar5);
        iVar6 = 0;
        pHVar2 = GKERNEL::GetHwnd();
        ShowWindow(pHVar2,iVar6);
      }
    }
  }
  if (!param_1) {
    bVar1 = GKERNEL::SupportsFullScreenGDIClipping();
    if (!bVar1) {
      bVar1 = GKERNEL::Windowed();
      if (!bVar1) {
        if (DAT_100188ac != '\0') {
          ShowMouse(false);
        }
        iVar6 = 1;
        pHVar2 = GKERNEL::GetHwnd();
        ShowWindow(pHVar2,iVar6);
        LVar5 = 0;
        WVar4 = 0xf120;
        UVar3 = 0x112;
        pHVar2 = GKERNEL::GetHwnd();
        SendMessageA(pHVar2,UVar3,WVar4,LVar5);
      }
    }
  }
  return;
}



// protected: virtual int __thiscall TwDirectXDialog::OnInitDialog(void)

int __thiscall TwDirectXDialog::OnInitDialog(TwDirectXDialog *this)

{
  bool bVar1;
  HWND__ *pHVar2;
  int iVar3;
  
                    // 0x787e  115  ?OnInitDialog@TwDirectXDialog@@MAEHXZ
  if (DAT_1001907d != '\0') {
    bVar1 = GKERNEL::Initialized();
    if (bVar1) {
      bVar1 = GKERNEL::Windowed();
      if (!bVar1) {
        bVar1 = GKERNEL::SupportsFullScreenGDIClipping();
        if (bVar1) {
          pHVar2 = GKERNEL::GetHwnd();
          DD_SURFACE::AttatchClipper(&GKERNEL::ddsPrimary,pHVar2);
          GKERNEL::Animate(false);
        }
      }
    }
  }
  FUN_10008010((int)this);
  iVar3 = CDialog::OnInitDialog((CDialog *)this);
  return iVar3;
}



// protected: void __thiscall TwDirectXDialog::OnMove(int,int)

void __thiscall TwDirectXDialog::OnMove(TwDirectXDialog *this,int param_1,int param_2)

{
  bool bVar1;
  void *pvVar2;
  tagRECT *ptVar3;
  tagRECT *ptVar4;
  undefined1 local_14 [16];
  
                    // 0x78e8  116  ?OnMove@TwDirectXDialog@@IAEXHH@Z
  FUN_10008030((CWnd *)this);
  if (DAT_1001907d != '\0') {
    bVar1 = GKERNEL::Initialized();
    if (bVar1) {
      bVar1 = GKERNEL::Windowed();
      if (!bVar1) {
        bVar1 = GKERNEL::SupportsFullScreenGDIClipping();
        if (bVar1) {
          ptVar4 = (tagRECT *)0x0;
          pvVar2 = FUN_10006a50(local_14,0,0,0x280,0x1e0);
          ptVar3 = (tagRECT *)FUN_10006ad0(pvVar2);
          DD_SURFACE::Blt(&GKERNEL::ddsPrimary,&GKERNEL::ddsBack,ptVar3,ptVar4);
        }
      }
    }
  }
  return;
}



// protected: void __thiscall TwDirectXDialog::OnDestroy(void)

void __thiscall TwDirectXDialog::OnDestroy(TwDirectXDialog *this)

{
  bool bVar1;
  void *pvVar2;
  tagRECT *ptVar3;
  tagRECT *ptVar4;
  undefined1 local_14 [16];
  
                    // 0x796c  114  ?OnDestroy@TwDirectXDialog@@IAEXXZ
  if (*(int *)(this + 0x30) == -1) {
    CDialog::EndDialog((HWND)0x0,(INT_PTR)this);
  }
  CWnd::OnDestroy((CWnd *)this);
  if (DAT_1001907d != '\0') {
    bVar1 = GKERNEL::Initialized();
    if (bVar1) {
      bVar1 = GKERNEL::Windowed();
      if (!bVar1) {
        bVar1 = GKERNEL::SupportsFullScreenGDIClipping();
        if (bVar1) {
          DD_SURFACE::AttatchClipper(&GKERNEL::ddsPrimary,(HWND__ *)0x0);
          ptVar4 = (tagRECT *)0x0;
          pvVar2 = FUN_10006a50(local_14,0,0,0x280,0x1e0);
          ptVar3 = (tagRECT *)FUN_10006ad0(pvVar2);
          DD_SURFACE::Blt(&GKERNEL::ddsPrimary,&GKERNEL::ddsBack,ptVar3,ptVar4);
          GKERNEL::Animate(true);
        }
      }
    }
  }
  return;
}



// public: virtual int __thiscall TwDirectXDialog::DoModal(void)

int __thiscall TwDirectXDialog::DoModal(TwDirectXDialog *this)

{
  bool bVar1;
  TwDirectXDialog *local_10;
  TwDirectXDialog *local_c;
  int local_8;
  
                    // 0x7a0f  46  ?DoModal@TwDirectXDialog@@UAEHXZ
  if (((DAT_1001907d == '\0') && (bVar1 = GKERNEL::Initialized(), bVar1)) &&
     (bVar1 = GKERNEL::Windowed(), !bVar1)) {
    return 1;
  }
  local_c = this;
  FUN_10007ad0(&DAT_10019060,&local_c);
  local_8 = CDialog::DoModal((CDialog *)this);
  local_10 = this;
  FUN_10007af0(&DAT_10019060,(int *)&local_10);
  return local_8;
}



void __fastcall FUN_10007a80(undefined4 *param_1)

{
  FUN_10007ca0(param_1);
  return;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_10007b70(this,10);
  *(undefined ***)this = &PTR_LAB_100118f0;
  return this;
}



void * __thiscall FUN_10007ad0(void *this,undefined4 *param_1)

{
  FUN_10007bd0(this,param_1);
  return this;
}



void __thiscall FUN_10007af0(void *this,int *param_1)

{
  int *piVar1;
  int *piVar2;
  int *local_8;
  
  local_8 = (int *)FUN_1000e790((int)this);
  while (piVar1 = local_8, local_8 != (int *)0x0) {
    piVar2 = (int *)FUN_1000d1b0((int *)&local_8);
    if (*piVar2 == *param_1) {
      FUN_10007c30(this,piVar1);
    }
  }
  return;
}



void * __thiscall FUN_10007b40(void *this,uint param_1)

{
  FUN_10007a80((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001c10(this);
  }
  return this;
}



void * __thiscall FUN_10007b70(void *this,undefined4 param_1)

{
  FUN_10003f80((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_10011904;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



undefined4 * __thiscall FUN_10007bd0(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_10007e50(this,*(undefined4 *)((int)this + 8),0);
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



void __thiscall FUN_10007c30(void *this,int *param_1)

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
  FUN_10007f30(this,param_1);
  return;
}



void __fastcall FUN_10007ca0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_100109d9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_10011904;
  local_8 = 0;
  FUN_10007dd0((int)param_1);
  local_8 = 0xffffffff;
  FUN_10001bb0(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_10007d00(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_10;
  ulong local_c;
  undefined4 *local_8;
  
  FUN_10001c00();
  bVar1 = FUN_10001c30((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      FUN_10007f80(param_1,&local_10,1);
      FUN_10007bd0(this,&local_10);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_10007f80(param_1,local_8 + 2,1);
    }
  }
  return;
}



void * __thiscall FUN_10007da0(void *this,uint param_1)

{
  FUN_10007ca0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001c10(this);
  }
  return this;
}



void __fastcall FUN_10007dd0(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_10001b80(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



undefined4 * __thiscall FUN_10007e50(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0xc);
    iVar3 = FUN_100106c0((int)pCVar2);
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
  FUN_10007fc0(puVar1 + 2,1);
  return puVar1;
}



void __thiscall FUN_10007f30(void *this,undefined4 *param_1)

{
  FUN_10001b80(param_1 + 2,1);
  *param_1 = *(undefined4 *)((int)this + 0x10);
  *(undefined4 **)((int)this + 0x10) = param_1;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + -1;
  if (*(int *)((int)this + 0xc) == 0) {
    FUN_10007dd0((int)this);
  }
  return;
}



void FUN_10007f80(CArchive *param_1,void *param_2,int param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_10001c30((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    CArchive::Read(param_1,param_2,param_3 << 2);
  }
  else {
    CArchive::Write(param_1,param_2,param_3 << 2);
  }
  return;
}



void FUN_10007fc0(void *param_1,int param_2)

{
  memset(param_1,0,param_2 << 2);
  while (param_2 != 0) {
    FUN_10001d60(4,param_1);
    param_1 = (void *)((int)param_1 + 4);
    param_2 = param_2 + -1;
  }
  return;
}



void __fastcall FUN_10008010(int param_1)

{
  SetForegroundWindow(*(HWND *)(param_1 + 0x20));
  return;
}



void __fastcall FUN_10008030(CWnd *param_1)

{
  CWnd::Default(param_1);
  return;
}



void * __thiscall FUN_10008050(void *this,CWnd *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_10010a05;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10008230(this,0x65,param_1);
  local_8 = 0;
  CString::CString((CString *)((int)this + 0x60));
  local_8 = CONCAT31(local_8._1_3_,1);
  *(undefined ***)this = &PTR_LAB_10011950;
  CString::operator=((CString *)((int)this + 0x60),(char *)&this_10019080);
  ExceptionList = local_10;
  return this;
}



void __thiscall FUN_100080c3(void *this,CDataExchange *param_1)

{
  FUN_100081e0();
  DDX_Text(param_1,1000,(CString *)((int)this + 0x60));
  DDV_MaxChars(param_1,(CString *)((int)this + 0x60),20000);
  return;
}



undefined ** FUN_10008106(void)

{
  return &TwDirectXDialog::messageMap;
}



undefined ** FUN_10008110(void)

{
  return &PTR_FUN_10011918;
}



undefined4 __fastcall FUN_10008120(TwDirectXDialog *param_1)

{
  TwDirectXDialog::OnInitDialog(param_1);
  FUN_10008010((int)param_1);
  return 1;
}



void __fastcall FUN_10008140(TwDirectXDialog *param_1)

{
  TwDirectXDialog::OnDestroy(param_1);
  return;
}



void * __thiscall FUN_10008160(void *this,uint param_1)

{
  FUN_10008190((CDialog *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001c10(this);
  }
  return this;
}



void __fastcall FUN_10008190(CDialog *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_10010a19;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  CString::~CString((CString *)(param_1 + 0x60));
  local_8 = 0xffffffff;
  FUN_10008290(param_1);
  ExceptionList = local_10;
  return;
}



void FUN_100081e0(void)

{
  return;
}



void __fastcall FUN_100081f0(int param_1)

{
  EnableWindow(*(HWND *)(param_1 + 0x20),0);
  return;
}



void __fastcall FUN_10008210(int param_1)

{
  EnableWindow(*(HWND *)(param_1 + 0x20),1);
  return;
}



void * __thiscall FUN_10008230(void *this,uint param_1,CWnd *param_2)

{
  CDialog::CDialog((CDialog *)this,param_1,param_2);
  *(undefined ***)this = &PTR_LAB_10011a28;
  return this;
}



void * __thiscall FUN_10008260(void *this,uint param_1)

{
  FUN_10008290((CDialog *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001c10(this);
  }
  return this;
}



void __fastcall FUN_10008290(CDialog *param_1)

{
  CDialog::~CDialog(param_1);
  return;
}



void __cdecl FUN_100082b0(int *param_1,DD_SURFACE *param_2,int param_3,int param_4)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  undefined1 uVar4;
  undefined1 uVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;
  bool bVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  int *piVar22;
  ushort *local_110;
  uint local_10c;
  byte *local_108;
  uint local_104;
  ushort *local_e4;
  uint local_e0;
  byte *local_dc;
  int local_d8;
  uint local_c0;
  int local_bc;
  int local_b0;
  ushort *local_9c;
  byte *local_90;
  int local_84;
  undefined4 local_70;
  int local_6c [8];
  int local_4c;
  uint local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  
  bVar9 = FUN_10008aa0(param_1);
  if (bVar9) {
    iVar10 = FUN_10008a90(param_1);
    iVar11 = FUN_10008a90(param_1);
    iVar12 = FUN_10008a90(param_1);
    if ((0 < *(int *)(iVar11 + 0x12)) && (0 < *(int *)(iVar11 + 0x16))) {
      uVar13 = *(uint *)(iVar11 + 0x12);
      local_84 = 0;
      if (uVar13 % 4 != 0) {
        local_84 = (uVar13 + 3 & 0xfffffffc) - uVar13;
      }
      local_84 = uVar13 + local_84;
      local_90 = (byte *)((iVar10 + *(int *)(iVar10 + 10) + local_84 * *(int *)(iVar11 + 0x16)) -
                         local_84);
      local_70 = 0;
      piVar22 = local_6c;
      for (iVar10 = 0x1a; iVar10 != 0; iVar10 = iVar10 + -1) {
        *piVar22 = 0;
        piVar22 = piVar22 + 1;
      }
      iVar10 = DD_SURFACE::Lock(param_2,(_DDSURFACEDESC *)&local_70);
      if (iVar10 != 0) {
        local_9c = (ushort *)(local_4c + (param_3 * local_1c >> 3) + param_4 * local_6c[3]);
        if (local_1c == 0x10) {
          local_b0 = 0;
          local_bc = 0;
          local_d8 = 0;
          uVar13 = GKTOOLS::CountBits(local_18);
          bVar6 = -(char)uVar13 + 8;
          uVar14 = GKTOOLS::CountBits(local_14);
          bVar7 = -(char)uVar14 + 8;
          uVar15 = GKTOOLS::CountBits(local_10);
          bVar8 = -(char)uVar15 + 8;
          uVar16 = GKTOOLS::ShiftPosition(local_18);
          uVar17 = GKTOOLS::ShiftPosition(local_14);
          uVar18 = GKTOOLS::ShiftPosition(local_10);
          for (local_c0 = 0; local_c0 < *(uint *)(iVar11 + 0x16); local_c0 = local_c0 + 1) {
            local_e4 = local_9c;
            local_dc = local_90;
            for (local_e0 = 0; local_e0 < *(uint *)(iVar11 + 0x12); local_e0 = local_e0 + 1) {
              bVar1 = *local_dc;
              bVar2 = *(byte *)(iVar12 + 0x37 + (uint)bVar1 * 4);
              bVar3 = *(byte *)(iVar12 + 0x36 + (uint)bVar1 * 4);
              local_b0 = FUN_10008a10(0,(uint)*(byte *)(iVar12 + 0x38 + (uint)bVar1 * 4) +
                                        (1 << (-(char)uVar13 + 7U & 0x1f)) + local_b0,0xff);
              local_bc = FUN_10008a10(0,(uint)bVar2 + (1 << (-(char)uVar14 + 7U & 0x1f)) + local_bc,
                                      0xff);
              local_d8 = FUN_10008a10(0,(uint)bVar3 + (1 << (-(char)uVar15 + 7U & 0x1f)) + local_d8,
                                      0xff);
              uVar20 = local_b0 >> (bVar6 & 0x1f);
              uVar19 = local_bc >> (bVar7 & 0x1f);
              uVar21 = local_d8 >> (bVar8 & 0x1f);
              local_b0 = local_b0 - (uVar20 << (bVar6 & 0x1f));
              local_bc = local_bc - (uVar19 << (bVar7 & 0x1f));
              local_d8 = local_d8 - (uVar21 << (bVar8 & 0x1f));
              *local_e4 = (ushort)((uVar20 & 0xffff) << ((byte)uVar16 & 0x1f)) |
                          (ushort)((uVar19 & 0xffff) << ((byte)uVar17 & 0x1f)) |
                          (ushort)((uVar21 & 0xffff) << ((byte)uVar18 & 0x1f));
              local_e4 = (ushort *)((int)local_e4 + (local_1c >> 3));
              local_dc = local_dc + 1;
            }
            local_9c = (ushort *)((int)local_9c + local_6c[3]);
            local_90 = local_90 + -local_84;
          }
        }
        else {
          for (local_104 = 0; local_104 < *(uint *)(iVar11 + 0x16); local_104 = local_104 + 1) {
            local_110 = local_9c;
            local_108 = local_90;
            for (local_10c = 0; local_10c < *(uint *)(iVar11 + 0x12); local_10c = local_10c + 1) {
              bVar6 = *local_108;
              uVar4 = *(undefined1 *)(iVar12 + 0x38 + (uint)bVar6 * 4);
              uVar5 = *(undefined1 *)(iVar12 + 0x37 + (uint)bVar6 * 4);
              *(undefined1 *)local_110 = *(undefined1 *)(iVar12 + 0x36 + (uint)bVar6 * 4);
              *(undefined1 *)((int)local_110 + 1) = uVar5;
              *(undefined1 *)(local_110 + 1) = uVar4;
              local_110 = (ushort *)((int)local_110 + (local_1c >> 3));
              local_108 = local_108 + 1;
            }
            local_9c = (ushort *)((int)local_9c + local_6c[3]);
            local_90 = local_90 + -local_84;
          }
        }
        DD_SURFACE::Unlock(param_2);
      }
    }
  }
  return;
}



// public: static void __cdecl GKTOOLS::Set256PaletteFromDIB(char const *)

void __cdecl GKTOOLS::Set256PaletteFromDIB(char *param_1)

{
  HANDLE hFile;
  IDirectDrawPalette *local_850;
  undefined1 local_84c [1024];
  BOOL local_44c;
  int local_448;
  undefined1 local_444 [16];
  undefined1 local_434 [1024];
  undefined4 local_34;
  DWORD local_30;
  undefined1 local_2c [40];
  
                    // 0x88b0  139  ?Set256PaletteFromDIB@GKTOOLS@@SAXPBD@Z
  hFile = CreateFileA(param_1,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    local_44c = ReadFile(hFile,local_444,0xe,&local_30,(LPOVERLAPPED)0x0);
    ReadFile(hFile,local_2c,0x28,&local_30,(LPOVERLAPPED)0x0);
    local_44c = ReadFile(hFile,local_434,0x400,&local_30,(LPOVERLAPPED)0x0);
    CloseHandle(hFile);
    for (local_448 = 0; local_448 < 0x100; local_448 = local_448 + 1) {
      local_84c[local_448 * 4] = local_434[local_448 * 4 + 2];
      local_84c[local_448 * 4 + 1] = local_434[local_448 * 4 + 1];
      local_84c[local_448 * 4 + 2] = local_434[local_448 * 4];
    }
    local_34 = (**(code **)(*DAT_1001b598 + 0x14))(DAT_1001b598,4,local_84c,&local_850,0);
    DD_SURFACE::SetPalette(&GKERNEL::ddsPrimary,local_850);
  }
  return;
}



int __cdecl FUN_10008a10(int param_1,int param_2,int param_3)

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



undefined4 __fastcall FUN_10008a90(undefined4 *param_1)

{
  return *param_1;
}



bool __fastcall FUN_10008aa0(int *param_1)

{
  return *param_1 != 0;
}



// public: static unsigned long __cdecl TwDXVersion::GetDXVersion(void)

ulong __cdecl TwDXVersion::GetDXVersion(void)

{
  int iVar1;
  int *local_a8;
  HMODULE local_a4;
  int *local_a0;
  int *local_9c;
  FARPROC local_98;
  int *local_94;
  int local_90;
  FARPROC local_8c;
  FARPROC local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_18;
  undefined4 local_14;
  HMODULE local_10;
  HMODULE local_c;
  int *local_8;
  
                    // 0x8ac0  77  ?GetDXVersion@TwDXVersion@@SAKXZ
  if (DAT_10016070 == 0xffffffff) {
    local_8c = (FARPROC)0x0;
    local_98 = (FARPROC)0x0;
    local_88 = (FARPROC)0x0;
    local_10 = (HMODULE)0x0;
    local_c = (HMODULE)0x0;
    local_a4 = (HMODULE)0x0;
    local_a0 = (int *)0x0;
    local_9c = (int *)0x0;
    local_94 = (int *)0x0;
    local_14 = 0;
    local_84 = 0;
    local_10 = LoadLibraryA(s_DDRAW_DLL_10016074);
    if (local_10 == (HMODULE)0x0) {
      DAT_10016070 = 0;
    }
    else {
      local_8c = GetProcAddress(local_10,s_DirectDrawCreate_10016080);
      if (local_8c == (FARPROC)0x0) {
        DAT_10016070 = 0;
        FreeLibrary(local_10);
        OutputDebugStringA(s_Couldn_t_LoadLibrary_DDraw_10016094);
      }
      else {
        local_90 = (*local_8c)(0,&local_a0,0);
        if (local_90 < 0) {
          DAT_10016070 = 0;
          FreeLibrary(local_10);
          OutputDebugStringA(s_Couldn_t_create_DDraw_100160b4);
        }
        else {
          DAT_10016070 = 0x100;
          local_90 = (**(code **)*local_a0)(local_a0,&DAT_10011b60,&local_9c);
          if (local_90 < 0) {
            (**(code **)(*local_a0 + 8))(local_a0);
            FreeLibrary(local_10);
            OutputDebugStringA(s_Couldn_t_QI_DDraw2_100160cc);
          }
          else {
            (**(code **)(*local_9c + 8))(local_9c);
            DAT_10016070 = 0x200;
            local_c = LoadLibraryA(s_DINPUT_DLL_100160e4);
            if (local_c == (HMODULE)0x0) {
              OutputDebugStringA(s_Couldn_t_LoadLibrary_DInput_100160f0);
              (**(code **)(*local_a0 + 8))(local_a0);
            }
            else {
              local_88 = GetProcAddress(local_c,s_DirectInputCreateA_10016110);
              if (local_88 == (FARPROC)0x0) {
                FreeLibrary(local_c);
                FreeLibrary(local_10);
                (**(code **)(*local_a0 + 8))(local_a0);
                OutputDebugStringA(s_Couldn_t_GetProcAddress_DInputCr_10016124);
              }
              else {
                DAT_10016070 = 0x300;
                FreeLibrary(local_c);
                memset(&local_80,0,0x6c);
                local_80 = 0x6c;
                local_7c = 1;
                local_18 = 0x200;
                local_90 = (**(code **)(*local_a0 + 0x50))(local_a0,0,8);
                if (local_90 < 0) {
                  (**(code **)(*local_a0 + 8))(local_a0);
                  FreeLibrary(local_10);
                  DAT_10016070 = 0;
                  OutputDebugStringA(s_Couldn_t_Set_coop_level_1001614c);
                }
                else {
                  local_90 = (**(code **)(*local_a0 + 0x18))(local_a0,&local_80,&local_94,0);
                  if (local_90 < 0) {
                    (**(code **)(*local_a0 + 8))(local_a0);
                    FreeLibrary(local_10);
                    DAT_10016070 = 0;
                    OutputDebugStringA(s_Couldn_t_CreateSurface_10016168);
                  }
                  else {
                    iVar1 = (**(code **)*local_94)(local_94,&DAT_10011bb0,&local_14);
                    if (iVar1 < 0) {
                      (**(code **)(*local_a0 + 8))(local_a0);
                      FreeLibrary(local_10);
                    }
                    else {
                      DAT_10016070 = 0x500;
                      iVar1 = (**(code **)*local_94)(local_94,&DAT_10011bc0,&local_84);
                      if (iVar1 < 0) {
                        (**(code **)(*local_a0 + 8))(local_a0);
                        FreeLibrary(local_10);
                      }
                      else {
                        DAT_10016070 = 0x600;
                        (**(code **)(*local_94 + 8))(local_94);
                        (**(code **)(*local_a0 + 8))(local_a0);
                        local_a8 = (int *)0x0;
                        CoInitialize((LPVOID)0x0);
                        local_90 = CoCreateInstance((IID *)&rclsid_10011b00,(LPUNKNOWN)0x0,1,
                                                    (IID *)&riid_10011b10,&local_a8);
                        if (local_90 < 0) {
                          OutputDebugStringA(s_Couldn_t_create_CLSID_DirectMusi_10016184);
                          FreeLibrary(local_10);
                        }
                        else {
                          DAT_10016070 = 0x601;
                          (**(code **)(*local_a8 + 8))(local_a8);
                          CoUninitialize();
                          local_98 = GetProcAddress(local_10,s_DirectDrawCreateEx_100161a8);
                          if (local_98 == (FARPROC)0x0) {
                            FreeLibrary(local_10);
                          }
                          else {
                            iVar1 = (*local_98)(0,&local_8,&DAT_10011b80,0);
                            if (iVar1 < 0) {
                              FreeLibrary(local_10);
                            }
                            else {
                              DAT_10016070 = 0x700;
                              (**(code **)(*local_8 + 8))(local_8);
                              local_a4 = LoadLibraryA(s_D3D8_DLL_100161bc);
                              if (local_a4 == (HMODULE)0x0) {
                                FreeLibrary(local_10);
                              }
                              else {
                                DAT_10016070 = 0x800;
                                FreeLibrary(local_10);
                                FreeLibrary(local_a4);
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
  return DAT_10016070;
}



void __fastcall
FUN_10009020(int *param_1,undefined4 param_2,int param_3,int param_4,char param_5,char param_6)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined1 local_24 [8];
  undefined1 local_1c [8];
  undefined1 local_14 [8];
  undefined1 local_c [8];
  
  if ((DAT_10019088 & 1) == 0) {
    DAT_10019088 = DAT_10019088 | 1;
    FUN_100023b0((DWORD *)&DAT_10019084);
    FUN_100104a2(FUN_10009270);
  }
  (**(code **)(*param_1 + 0x28))(param_3,param_4,param_5,param_6);
  if (param_5 == '\0') {
    DAT_100161c8 = -1;
    DAT_100161cc = -1;
    if (DAT_10019089 != '\0') {
      bVar1 = FUN_10003fc0(&DAT_10019084,100);
      if (CONCAT31(extraout_var,bVar1) != 0) {
        FUN_10001e70(local_c,param_3,param_4);
        (**(code **)(*param_1 + 0x2c))(local_c);
      }
    }
    DAT_10019089 = 0;
  }
  else {
    if (((DAT_10019089 != '\0') && (DAT_100161c8 != -1)) &&
       ((5 < param_3 - DAT_100161c8 ||
        (((param_3 - DAT_100161c8 < -5 || (5 < param_4 - DAT_100161cc)) ||
         (param_4 - DAT_100161cc < -5)))))) {
      FUN_10001e70(local_14,DAT_100161c8,DAT_100161cc);
      (**(code **)(*param_1 + 0x38))(local_14);
    }
    if (DAT_100161c8 == -1) {
      DAT_100161c8 = param_3;
      DAT_100161cc = param_4;
    }
    DAT_10019089 = 1;
  }
  if (param_6 == '\0') {
    DAT_100161d0 = -1;
    DAT_100161d4 = -1;
    if (DAT_1001908a != '\0') {
      bVar1 = FUN_10003fc0(&DAT_10019084,100);
      if (CONCAT31(extraout_var_00,bVar1) != 0) {
        FUN_10001e70(local_1c,param_3,param_4);
        (**(code **)(*param_1 + 0x30))(local_1c);
      }
    }
    DAT_1001908a = 0;
  }
  else {
    if (((DAT_1001908a != '\0') && (DAT_100161d0 != -1)) &&
       (((5 < param_3 - DAT_100161d0 ||
         ((param_3 - DAT_100161d0 < -5 || (5 < param_4 - DAT_100161d4)))) ||
        (param_4 - DAT_100161d4 < -5)))) {
      FUN_10001e70(local_24,DAT_100161d0,DAT_100161d4);
      (**(code **)(*param_1 + 0x34))(local_24);
    }
    if (DAT_100161d0 == -1) {
      DAT_100161d0 = param_3;
      DAT_100161d4 = param_4;
    }
    DAT_1001908a = 1;
  }
  return;
}



void FUN_10009270(void)

{
  return;
}



void __fastcall FUN_10009275(int *param_1)

{
  (**(code **)(*param_1 + 0x3c))();
  if ((char)param_1[4] != '\0') {
    GKERNEL::Flip();
  }
  (**(code **)(*param_1 + 0x40))();
  return;
}



// public: virtual void __thiscall GAME::StartGame(class CString)

void __thiscall GAME::StartGame(GAME *this)

{
  char cVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x92a7  189  ?StartGame@GAME@@UAEXVCString@@@Z
  puStack_c = &LAB_10010a39;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  CString::operator=((CString *)(this + 0x30),(CString *)&stack0x00000004);
  cVar1 = (**(code **)(*(int *)this + 0x1c))();
  if (cVar1 != '\0') {
    local_8 = CONCAT31(local_8._1_3_,1);
    cVar1 = (*(code *)**(undefined4 **)this)();
    if (cVar1 != '\0') {
      GKERNEL::RegisterThis(this);
      GKERNEL::Start();
    }
    FUN_10009368();
    return;
  }
  cVar1 = (*(code *)**(undefined4 **)this)();
  if (cVar1 != '\0') {
    GKERNEL::RegisterThis(this);
    GKERNEL::Start();
  }
  local_8 = 0xffffffff;
  CString::~CString((CString *)&stack0x00000004);
  ExceptionList = local_10;
  return;
}



undefined * Catch_10009327(void)

{
  int unaff_EBP;
  
  ShowMouse(true);
  (**(code **)(**(int **)(unaff_EBP + -0x18) + 0x10))(*(undefined4 *)(unaff_EBP + -0x14));
  return FUN_10009368;
}



undefined * Catch_10009347(void)

{
  int unaff_EBP;
  
  ShowMouse(true);
  (**(code **)(**(int **)(unaff_EBP + -0x18) + 0x10))(s_UNHANDLED_EXCEPTION_100161d8);
  return FUN_10009368;
}



void FUN_10009368(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -4) = 0;
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  CString::~CString((CString *)(unaff_EBP + 8));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



// protected: bool __thiscall GAME::IsKeyDown(unsigned int)const 

bool __thiscall GAME::IsKeyDown(GAME *this,uint param_1)

{
  SHORT SVar1;
  
                    // 0x93b7  107  ?IsKeyDown@GAME@@IBE_NI@Z
  SVar1 = GetKeyState(param_1);
  return ((int)SVar1 & 0x8000U) != 0;
}



// public: void __thiscall GAME::PushState(unsigned int)

void __thiscall GAME::PushState(GAME *this,uint param_1)

{
                    // 0x93e3  121  ?PushState@GAME@@QAEXI@Z
  FUN_100095b0(this + 0x14,param_1);
  ChangeState(this,param_1);
  return;
}



// public: void __thiscall GAME::PopState(void)

void __thiscall GAME::PopState(GAME *this)

{
  uint *puVar1;
  
                    // 0x940b  119  ?PopState@GAME@@QAEXXZ
  FUN_10009550(this + 0x14);
  puVar1 = (uint *)FUN_10009530((int)(this + 0x14));
  ChangeState(this,*puVar1);
  return;
}



// public: void __thiscall GAME::SetReturnState(unsigned int)

void __thiscall GAME::SetReturnState(GAME *this,uint param_1)

{
                    // 0x9437  173  ?SetReturnState@GAME@@QAEXI@Z
  *(uint *)(this + 0xc) = param_1;
  return;
}



// public: void __thiscall GAME::StateReturn(void)

void __thiscall GAME::StateReturn(GAME *this)

{
                    // 0x944d  190  ?StateReturn@GAME@@QAEXXZ
  ChangeState(this,*(uint *)(this + 0xc));
  return;
}



// public: void __thiscall GAME::ChangeState(unsigned int)

void __thiscall GAME::ChangeState(GAME *this,uint param_1)

{
  int iVar1;
  
                    // 0x9467  27  ?ChangeState@GAME@@QAEXI@Z
  *(undefined4 *)(this + 8) = *(undefined4 *)(this + 4);
  if (param_1 == *(uint *)(this + 4)) {
    (**(code **)(*(int *)this + 0x14))(*(undefined4 *)(this + 4),param_1);
    (**(code **)(*(int *)this + 0x18))(param_1);
  }
  else {
    (**(code **)(*(int *)this + 0x14))(*(undefined4 *)(this + 4),param_1);
    (**(code **)(*(int *)this + 0x18))(param_1);
  }
  if (*(int *)(this + 4) == *(int *)(this + 8)) {
    *(uint *)(this + 4) = param_1;
    iVar1 = FUN_1000ff30((int)(this + 0x14));
    if (iVar1 != 0) {
      FUN_10009550(this + 0x14);
    }
    FUN_100095b0(this + 0x14,param_1);
    GKERNEL::FlushInputQueue();
  }
  return;
}



// public: static void __cdecl GKERNEL::EnableAltEnter(bool)

void __cdecl GKERNEL::EnableAltEnter(bool param_1)

{
                    // 0x951c  61  ?EnableAltEnter@GKERNEL@@SAX_N@Z
  DAT_100188ad = param_1;
  return;
}



int __fastcall FUN_10009530(int param_1)

{
  return *(int *)(param_1 + 4) + 8;
}



undefined4 __fastcall FUN_10009550(void *param_1)

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
  FUN_10009610(param_1,puVar1);
  return uVar2;
}



undefined4 * __thiscall FUN_100095b0(void *this,undefined4 param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_1000bfd0(this,0,*(undefined4 *)((int)this + 4));
  puVar1[2] = param_1;
  if (*(int *)((int)this + 4) == 0) {
    *(undefined4 **)((int)this + 8) = puVar1;
  }
  else {
    *(undefined4 **)(*(int *)((int)this + 4) + 4) = puVar1;
  }
  *(undefined4 **)((int)this + 4) = puVar1;
  return puVar1;
}



void __thiscall FUN_10009610(void *this,undefined4 *param_1)

{
  FUN_10001b80(param_1 + 2,1);
  *param_1 = *(undefined4 *)((int)this + 0x10);
  *(undefined4 **)((int)this + 0x10) = param_1;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + -1;
  if (*(int *)((int)this + 0xc) == 0) {
    FUN_10001a70((int)this);
  }
  return;
}



void FUN_10009660(void *param_1,int param_2)

{
  memset(param_1,0,param_2 << 2);
  while (param_2 != 0) {
    FUN_10001d60(4,param_1);
    param_1 = (void *)((int)param_1 + 4);
    param_2 = param_2 + -1;
  }
  return;
}



// public: static void __cdecl GKTOOLS::assert(char *,char *,unsigned int)

void __cdecl GKTOOLS::assert(char *param_1,char *param_2,uint param_3)

{
  CString *pCVar1;
  undefined4 *puVar2;
  char *_Filename;
  int iVar3;
  char *_Mode;
  CString local_224 [4];
  CString local_220 [4];
  FILE *local_21c;
  char local_218;
  undefined4 local_217;
  undefined1 local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x96b0  205  ?assert@GKTOOLS@@SAXPAD0I@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_10010a71;
  local_10 = ExceptionList;
  if (DAT_1001b290 != '\0') {
    return;
  }
  DAT_1001b290 = '\x01';
  ExceptionList = &local_10;
  FUN_10004e70(local_18,&DAT_1001b290,0);
  local_8 = 0;
  local_218 = '\0';
  puVar2 = &local_217;
  for (iVar3 = 0x7f; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined1 *)((int)puVar2 + 2) = 0;
  _snprintf(&local_218,0x1ff,s_FILE___s_LINE___u_EXPRESSION___s_10016200,param_2,param_3,param_1);
  _Mode = s_GKASSERT_TXT_10016228;
  pCVar1 = FUN_1000a550(local_220);
  local_8._0_1_ = 1;
  puVar2 = (undefined4 *)operator+(local_224,(char *)pCVar1);
  local_8._0_1_ = 2;
  _Filename = (char *)FUN_1000a540(puVar2);
  local_21c = fopen(_Filename,_Mode);
  local_8._0_1_ = 1;
  CString::~CString(local_224);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(local_220);
  if (local_21c != (FILE *)0x0) {
    fprintf(local_21c,s_FILE___s_10016238,param_2);
  }
  if (local_21c != (FILE *)0x0) {
    fprintf(local_21c,s_LINE___u_10016244,param_3);
  }
  if (local_21c != (FILE *)0x0) {
    fprintf(local_21c,s_EXPRESSION___s_10016250,param_1);
  }
  if (local_21c != (FILE *)0x0) {
    fclose(local_21c);
  }
                    // WARNING: Subroutine does not return
  _exit(1);
}



// public: static void __cdecl GKTOOLS::dxassert(long,char *,unsigned int)

void __cdecl GKTOOLS::dxassert(long param_1,char *param_2,uint param_3)

{
  char *pcVar1;
  CString *pCVar2;
  undefined4 *puVar3;
  int iVar4;
  char *_Mode;
  CString local_224 [4];
  CString local_220 [4];
  char local_21c;
  undefined4 local_21b;
  FILE *local_1c;
  undefined1 local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x9862  210  ?dxassert@GKTOOLS@@SAXJPADI@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_10010a9c;
  local_10 = ExceptionList;
  if (DAT_1001b291 != '\0') {
    return;
  }
  DAT_1001b291 = '\x01';
  ExceptionList = &local_10;
  FUN_10004e70(local_18,&DAT_1001b291,0);
  local_8 = 0;
  local_21c = '\0';
  puVar3 = &local_21b;
  for (iVar4 = 0x7f; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = 0;
  *(undefined1 *)((int)puVar3 + 2) = 0;
  pcVar1 = GetDDError(param_1);
  _snprintf(&local_21c,0x1ff,s_FILE___s_LINE___u_ERROR___s_10016260,param_2,param_3,pcVar1);
  _Mode = s_DXASSERT_ERR_10016284;
  pCVar2 = FUN_1000a550(local_220);
  local_8._0_1_ = 1;
  puVar3 = (undefined4 *)operator+(local_224,(char *)pCVar2);
  local_8._0_1_ = 2;
  pcVar1 = (char *)FUN_1000a540(puVar3);
  local_1c = fopen(pcVar1,_Mode);
  local_8._0_1_ = 1;
  CString::~CString(local_224);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(local_220);
  if (local_1c != (FILE *)0x0) {
    fprintf(local_1c,(char *)&_Format_10016294,&local_21c);
    fclose(local_1c);
  }
                    // WARNING: Subroutine does not return
  _exit(1);
}



// public: static void __cdecl GKTOOLS::DebugInfo(char const *,...)

void __cdecl GKTOOLS::DebugInfo(char *param_1,...)

{
  HGDIOBJ pvVar1;
  HGDIOBJ pvVar2;
  size_t sVar3;
  HWND__ in_stack_fffffbec;
  char local_408 [1024];
  HGDIOBJ local_8;
  
                    // 0x99c7  42  ?DebugInfo@GKTOOLS@@SAXPBDZZ
  vsprintf(local_408,param_1,&stack0x00000008);
  DD_SURFACE::GetDC((HWND)&stack0xfffffbec);
  pvVar1 = GetStockObject(7);
  pvVar1 = SelectObject((HDC)in_stack_fffffbec.unused,pvVar1);
  pvVar2 = GetStockObject(0);
  local_8 = SelectObject((HDC)in_stack_fffffbec.unused,pvVar2);
  sVar3 = strlen(local_408);
  TextOutA((HDC)in_stack_fffffbec.unused,0,0,local_408,sVar3);
  SelectObject((HDC)in_stack_fffffbec.unused,pvVar1);
  SelectObject((HDC)in_stack_fffffbec.unused,local_8);
  DD_SURFACE::ReleaseDC((HWND)in_stack_fffffbec.unused,(HDC)in_stack_fffffbec.unused);
  DD_SURFACE::GetDC((HWND)&stack0xfffffbec);
  pvVar1 = GetStockObject(7);
  pvVar1 = SelectObject((HDC)in_stack_fffffbec.unused,pvVar1);
  pvVar2 = GetStockObject(0);
  local_8 = SelectObject((HDC)in_stack_fffffbec.unused,pvVar2);
  sVar3 = strlen(local_408);
  TextOutA((HDC)in_stack_fffffbec.unused,0,0,local_408,sVar3);
  SelectObject((HDC)in_stack_fffffbec.unused,pvVar1);
  SelectObject((HDC)in_stack_fffffbec.unused,local_8);
  DD_SURFACE::ReleaseDC((HWND)in_stack_fffffbec.unused,(HDC)in_stack_fffffbec.unused);
  return;
}



// public: static char * __cdecl GKTOOLS::GetDDError(long)

char * __cdecl GKTOOLS::GetDDError(long param_1)

{
  char *local_8;
  
                    // 0x9b40  75  ?GetDDError@GKTOOLS@@SAPADJ@Z
  local_8 = (char *)0x0;
  if (param_1 < -0x7789fe5b) {
    if (param_1 == -0x7789fe5c) {
      local_8 = s_DDERR_SURFACEALREADYDEPENDENT__T_10017438;
    }
    else if (param_1 < -0x7789ff23) {
      if (param_1 == -0x7789ff24) {
        local_8 = s_DDERR_NOCOLORKEYHW__Operation_co_10016998;
      }
      else if (param_1 < -0x7789ff9b) {
        if (param_1 == -0x7789ff9c) {
          local_8 = s_DDERR_INVALIDCAPS__One_or_more_o_10016510;
        }
        else if (param_1 < -0x7789fff5) {
          if (param_1 == -0x7789fff6) {
            local_8 = s_DDERR_CANNOTATTACHSURFACE__This_s_100162d8;
          }
          else if (param_1 < -0x7ff8fff1) {
            if (param_1 == -0x7ff8fff2) {
              local_8 = s_DDERR_OUTOFMEMORY__DirectDraw_do_100171b4;
            }
            else if (param_1 == -0x7fffbfff) {
              local_8 = s_DDERR_UNSUPPORTED__Action_not_su_10017854;
            }
            else if (param_1 == -0x7fffbffb) {
              local_8 = s_DDERR_GENERIC__Generic_failure__10016424;
            }
            else if (param_1 == -0x7ffbfe10) {
              local_8 = s_DDERR_NOTINITIALIZED__An_attempt_100187f0;
            }
          }
          else if (param_1 == -0x7ff8ffa9) {
            local_8 = s_DDERR_INVALIDPARAMS__One_or_more_10016650;
          }
          else if (param_1 == -0x7789fffb) {
            local_8 = s_DDERR_ALREADYINITIALIZED__This_o_10016298;
          }
        }
        else {
          switch(param_1) {
          case -0x7789ffec:
            local_8 = s_DDERR_CANNOTDETACHSURFACE__This_s_10016330;
            break;
          case -0x7789ffd8:
            local_8 = s_DDERR_CURRENTLYNOTAVAIL__Support_1001638c;
            break;
          case -0x7789ffc9:
            local_8 = s_DDERR_EXCEPTION__An_exception_wa_100163cc;
            break;
          case -0x7789ffa6:
            local_8 = s_DDERR_HEIGHTALIGN__Height_of_rec_10016448;
            break;
          case -0x7789ffa1:
            local_8 = s_DDERR_INCOMPATIBLEPRIMARY__Unabl_100164a0;
          }
        }
      }
      else {
        switch(param_1) {
        case -0x7789ff92:
          local_8 = s_DDERR_INVALIDCLIPLIST__DirectDra_10016568;
          break;
        case -0x7789ff88:
          local_8 = s_DDERR_INVALIDMODE__DirectDraw_do_100165b0;
          break;
        case -0x7789ff7e:
          local_8 = s_DDERR_INVALIDOBJECT__DirectDraw_r_100165f4;
          break;
        case -0x7789ff6f:
          local_8 = s_DDERR_INVALIDPIXELFORMAT__pixel_f_100166b4;
          break;
        case -0x7789ff6a:
          local_8 = s_DDERR_INVALIDRECT__Rectangle_pro_100166f8;
          break;
        case -0x7789ff60:
          local_8 = s_DDERR_LOCKEDSURFACES__Operation_c_1001672c;
          break;
        case -0x7789ff56:
          local_8 = s_DDERR_NO3D__There_is_no_3D_prese_10016790;
          break;
        case -0x7789ff4c:
          local_8 = s_DDERR_NOALPHAHW__Operation_could_100167b8;
          break;
        case -0x7789ff33:
          local_8 = s_DDERR_NOCLIPLIST__no_clip_list_a_10016834;
          break;
        case -0x7789ff2e:
          local_8 = s_DDERR_NOCOLORCONVHW__Operation_c_10016860;
          break;
        case -0x7789ff2c:
          local_8 = s_DDERR_NOCOOPERATIVELEVELSET__Cre_100168e0;
          break;
        case -0x7789ff29:
          local_8 = s_DDERR_NOCOLORKEY__Surface_doesn__10016958;
        }
      }
    }
    else {
      switch(param_1) {
      case -0x7789ff22:
        local_8 = s_DDERR_NODIRECTDRAWSUPPORT__No_Di_10016a0c;
        break;
      case -0x7789ff1f:
        local_8 = s_DDERR_NOEXCLUSIVEMODE__Operation_10016a64;
        break;
      case -0x7789ff1a:
        local_8 = s_DDERR_NOFLIPHW__Flipping_visible_10016ae8;
        break;
      case -0x7789ff10:
        local_8 = s_DDERR_NOGDI__There_is_no_GDI_pre_10016b28;
        break;
      case -0x7789ff06:
        local_8 = s_DDERR_NOMIRRORHW__Operation_coul_10016b50;
        break;
      case -0x7789ff01:
        local_8 = s_DDERR_NOTFOUND__Requested_item_w_10016bbc;
        break;
      case -0x7789fefc:
        local_8 = s_DDERR_NOOVERLAYHW__Operation_cou_10016bec;
        break;
      case -0x7789fee8:
        local_8 = s_DDERR_NORASTEROPHW__Operation_co_10016c60;
        break;
      case -0x7789fede:
        local_8 = s_DDERR_NOROTATIONHW__Operation_co_10016ce4;
        break;
      case -0x7789feca:
        local_8 = s_DDERR_NOSTRETCHHW__Operation_cou_10016d58;
        break;
      case -0x7789fec4:
        local_8 = s_DDERR_NOT4BITCOLOR__DirectDrawSu_10016dc4;
        break;
      case -0x7789fec3:
        local_8 = s_DDERR_NOT4BITCOLORINDEX__DirectD_10016e44;
        break;
      case -0x7789fec0:
        local_8 = s_DDERR_NOT8BITCOLOR__DirectDraw_S_10016ed4;
        break;
      case -0x7789feb6:
        local_8 = s_DDERR_NOTEXTUREHW__Operation_cou_10016f4c;
        break;
      case -0x7789feb1:
        local_8 = s_DDERR_NOVSYNCHW__Operation_could_10016fc8;
        break;
      case -0x7789feac:
        local_8 = s_DDERR_NOZBUFFERHW__Operation_cou_10017050;
        break;
      case -0x7789fea2:
        local_8 = s_DDERR_NOZOVERLAYHW__Overlay_surf_100170c0;
        break;
      case -0x7789fe98:
        local_8 = s_DDERR_OUTOFCAPS__The_hardware_ne_10017154;
        break;
      case -0x7789fe84:
        local_8 = s_DDERR_OUTOFVIDEOMEMORY__DirectDr_1001720c;
        break;
      case -0x7789fe82:
        local_8 = s_DDERR_OVERLAYCANTCLIP__hardware_d_10017268;
        break;
      case -0x7789fe80:
        local_8 = s_DDERR_OVERLAYCOLORKEYONLYONEACTI_100172ac;
        break;
      case -0x7789fe7d:
        local_8 = s_DDERR_PALETTEBUSY__Access_to_thi_10017310;
        break;
      case -0x7789fe70:
        local_8 = s_DDERR_COLORKEYNOTSET__No_src_col_10017388;
        break;
      case -0x7789fe66:
        local_8 = s_DDERR_SURFACEALREADYATTACHED__Th_100173d0;
      }
    }
  }
  else {
    switch(param_1) {
    case -0x7789fe52:
      local_8 = s_DDERR_SURFACEBUSY__Access_to_thi_100174b0;
      break;
    case -0x7789fe4d:
      local_8 = s_DDERR_CANTLOCKSURFACE__Access_to_10017528;
      break;
    case -0x7789fe48:
      local_8 = s_DDERR_SURFACEISOBSCURED__Access_t_10017618;
      break;
    case -0x7789fe3e:
      local_8 = s_DDERR_SURFACELOST__Access_to_thi_1001766c;
      break;
    case -0x7789fe34:
      local_8 = s_DDERR_SURFACENOTATTACHED__The_re_10017720;
      break;
    case -0x7789fe2a:
      local_8 = s_DDERR_TOOBIGHEIGHT__Height_reque_10017764;
      break;
    case -0x7789fe20:
      local_8 = s_DDERR_TOOBIGSIZE__Size_requested_100177a8;
      break;
    case -0x7789fe16:
      local_8 = s_DDERR_TOOBIGWIDTH__Width_request_10017814;
      break;
    case -0x7789fe02:
      local_8 = s_DDERR_UNSUPPORTEDFORMAT__FOURCC_f_10017880;
      break;
    case -0x7789fdf8:
      local_8 = s_DDERR_UNSUPPORTEDMASK__Bitmask_i_100178d0;
      break;
    case -0x7789fde7:
      local_8 = s_DDERR_VERTICALBLANKINPROGRESS__v_1001792c;
      break;
    case -0x7789fde4:
      local_8 = s_DDERR_WASSTILLDRAWING__Informs_D_1001796c;
      break;
    case -0x7789fdd0:
      local_8 = s_DDERR_XALIGN__Rectangle_provided_100179f8;
      break;
    case -0x7789fdcf:
      local_8 = s_DDERR_INVALIDDIRECTDRAWGUID__The_10017a4c;
      break;
    case -0x7789fdce:
      local_8 = s_DDERR_DIRECTDRAWALREADYCREATED__A_10017abc;
      break;
    case -0x7789fdcd:
      local_8 = s_DDERR_NODIRECTDRAWHW__A_hardware_10017b38;
      break;
    case -0x7789fdcc:
      local_8 = s_DDERR_PRIMARYSURFACEALREADYEXIST_10017bb8;
      break;
    case -0x7789fdcb:
      local_8 = s_DDERR_NOEMULATION__software_emul_10017c10;
      break;
    case -0x7789fdca:
      local_8 = s_DDERR_REGIONTOOSMALL__region_pas_10017c48;
      break;
    case -0x7789fdc9:
      local_8 = s_DDERR_CLIPPERISUSINGHWND__an_att_10017c94;
      break;
    case -0x7789fdc8:
      local_8 = s_DDERR_NOCLIPPERATTACHED__No_clip_10017d10;
      break;
    case -0x7789fdc7:
      local_8 = s_DDERR_NOHWND__Clipper_notificati_10017d58;
      break;
    case -0x7789fdc6:
      local_8 = s_DDERR_HWNDSUBCLASSED__HWND_used_b_10017dd0;
      break;
    case -0x7789fdc5:
      local_8 = s_DDERR_HWNDALREADYSET__The_Cooper_10017e54;
      break;
    case -0x7789fdc4:
      local_8 = s_DDERR_NOPALETTEATTACHED__No_pale_10017ee4;
      break;
    case -0x7789fdc3:
      local_8 = s_DDERR_NOPALETTEHW__No_hardware_s_10017f2c;
      break;
    case -0x7789fdc2:
      local_8 = s_DDERR_BLTFASTCANTCLIP__If_a_clip_10017f74;
      break;
    case -0x7789fdc1:
      local_8 = s_DDERR_NOBLTHW__No_blter__10017fe0;
      break;
    case -0x7789fdc0:
      local_8 = s_DDERR_NODDROPSHW__No_DirectDraw_R_10017ffc;
      break;
    case -0x7789fdbf:
      local_8 = s_DDERR_OVERLAYNOTVISIBLE__returne_1001802c;
      break;
    case -0x7789fdbe:
      local_8 = s_DDERR_NOOVERLAYDEST__returned_wh_10018088;
      break;
    case -0x7789fdbd:
      local_8 = s_DDERR_INVALIDPOSITION__returned_w_10018120;
      break;
    case -0x7789fdbc:
      local_8 = s_DDERR_NOTAOVERLAYSURFACE__return_100181a0;
      break;
    case -0x7789fdbb:
      local_8 = s_DDERR_EXCLUSIVEMODEALREADYSET__A_10018200;
      break;
    case -0x7789fdba:
      local_8 = s_DDERR_NOTFLIPPABLE__An_attempt_h_10018278;
      break;
    case -0x7789fdb9:
      local_8 = s_DDERR_CANTDUPLICATE__Can_t_dupli_100182d0;
      break;
    case -0x7789fdb8:
      local_8 = s_DDERR_NOTLOCKED__Surface_was_not_10018338;
      break;
    case -0x7789fdb7:
      local_8 = s_DDERR_CANTCREATEDC__Windows_can_n_100183c8;
      break;
    case -0x7789fdb6:
      local_8 = s_DDERR_NODC__No_DC_was_ever_creat_10018404;
      break;
    case -0x7789fdb5:
      local_8 = s_DDERR_WRONGMODE__This_surface_ca_1001843c;
      break;
    case -0x7789fdb4:
      local_8 = s_DDERR_IMPLICITLYCREATED__This_su_1001849c;
      break;
    case -0x7789fdb3:
      local_8 = s_DDERR_NOTPALETTIZED__The_surface_10018504;
      break;
    case -0x7789fdb2:
      local_8 = s_DDERR_UNSUPPORTEDMODE__The_displ_10018550;
      break;
    case -0x7789fdb1:
      local_8 = s_DDERR_NOMIPMAPHW__Operation_coul_10018598;
      break;
    case -0x7789fdb0:
      local_8 = s_DDERR_INVALIDSURFACETYPE__The_re_1001861c;
      break;
    case -0x7789fd94:
      local_8 = s_DDERR_DCALREADYCREATED__A_DC_has_10018690;
      break;
    case -0x7789fd80:
      local_8 = s_DDERR_CANTPAGELOCK__The_attempt_t_10018708;
      break;
    case -0x7789fd6c:
      local_8 = s_DDERR_CANTPAGEUNLOCK__The_attemp_10018748;
      break;
    case -0x7789fd58:
      local_8 = s_DDERR_NOTPAGELOCKED__An_attempt_w_1001878c;
    }
  }
  return local_8;
}



// public: static void __cdecl GKERNEL::DebugTrace(char const *,...)

void __cdecl GKERNEL::DebugTrace(char *param_1,...)

{
                    // 0xa52c  43  ?DebugTrace@GKERNEL@@SAXPBDZZ
  return;
}



undefined4 __fastcall FUN_1000a540(undefined4 *param_1)

{
  return *param_1;
}



CString * __cdecl FUN_1000a550(CString *param_1)

{
  bool bVar1;
  char cVar2;
  REG *this;
  CString *pCVar3;
  char *pcVar4;
  CString local_24 [4];
  CString local_20 [4];
  undefined4 local_1c;
  uint local_18;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_10010aeb;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(local_14);
  local_8 = 1;
  pCVar3 = local_14;
  pcVar4 = s_LogDir_100188a4;
  this = (REG *)FUN_1000a700(&local_1c,&param_3_1001b294,s_Software_Twilight__10018890);
  local_8._0_1_ = 2;
  bVar1 = REG::Get(this,pcVar4,pCVar3);
  local_18 = CONCAT31(local_18._1_3_,bVar1);
  local_8._0_1_ = 1;
  FUN_1000a7b0(&local_1c);
  if ((local_18 & 0xff) == 0) {
    REG::RootDir();
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_14);
  }
  else {
    cVar2 = FUN_1000a6e0(local_14,0);
    if ((cVar2 != '\\') && (cVar2 = FUN_1000a6e0(local_14,1), cVar2 != ':')) {
      pCVar3 = (CString *)REG::RootDir();
      local_8._0_1_ = 3;
      pcVar4 = (char *)operator+(local_24,pCVar3);
      local_8._0_1_ = 4;
      operator+(param_1,pcVar4);
      local_8._0_1_ = 3;
      CString::~CString(local_24);
      local_8._0_1_ = 1;
      CString::~CString(local_20);
      local_8 = (uint)local_8._1_3_ << 8;
      CString::~CString(local_14);
      ExceptionList = local_10;
      return param_1;
    }
    operator+(param_1,(char *)local_14);
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_14);
  }
  ExceptionList = local_10;
  return param_1;
}



undefined1 __thiscall FUN_1000a6e0(void *this,int param_1)

{
                    // WARNING: Load size is inaccurate
  return *(undefined1 *)(*this + param_1);
}



void * __thiscall FUN_1000a700(void *this,undefined4 param_1,char *param_2)

{
  char *pcVar1;
  LPCSTR lpSubKey;
  DWORD Reserved;
  LPSTR lpClass;
  DWORD dwOptions;
  REGSAM samDesired;
  LPSECURITY_ATTRIBUTES lpSecurityAttributes;
  PHKEY phkResult;
  LPDWORD lpdwDisposition;
  CString local_1c [4];
  CString local_18 [4];
  DWORD local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &lpdwDisposition_10010b12;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pcVar1 = (char *)CString::CString(local_1c,param_2);
  local_8 = 0;
  operator+(local_18,pcVar1);
  local_8 = CONCAT31(local_8._1_3_,2);
  CString::~CString(local_1c);
  lpdwDisposition = (LPDWORD)0x0;
  lpSecurityAttributes = (LPSECURITY_ATTRIBUTES)0x0;
  samDesired = 0xf003f;
  dwOptions = 0;
  lpClass = (LPSTR)0x0;
  Reserved = 0;
  phkResult = (PHKEY)this;
  lpSubKey = (LPCSTR)FUN_1000a540((undefined4 *)local_18);
  local_14 = RegCreateKeyExA((HKEY)0x80000001,lpSubKey,Reserved,lpClass,dwOptions,samDesired,
                             lpSecurityAttributes,phkResult,lpdwDisposition);
  SetLastError(local_14);
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  ExceptionList = local_10;
  return this;
}



void __fastcall FUN_1000a7b0(undefined4 *param_1)

{
  RegCloseKey((HKEY)*param_1);
  return;
}



void FUN_1000a7d0(void)

{
  FUN_1000a7df();
  FUN_1000a7ee();
  return;
}



void FUN_1000a7df(void)

{
  GKERNEL::GKERNEL((GKERNEL *)&DAT_1001b458);
  return;
}



void FUN_1000a7ee(void)

{
  FUN_100104a2(FUN_1000a800);
  return;
}



void FUN_1000a800(void)

{
  GKERNEL::~GKERNEL((GKERNEL *)&DAT_1001b458);
  return;
}



void FUN_1000a80f(void)

{
  FUN_1000a819();
  return;
}



void FUN_1000a819(void)

{
  FUN_100023b0((DWORD *)&DAT_1001b3bc);
  return;
}



void FUN_1000a828(void)

{
  FUN_1000a832();
  return;
}



void FUN_1000a832(void)

{
  FUN_100023b0((DWORD *)&DAT_1001b39c);
  return;
}



void FUN_1000a841(void)

{
  FUN_1000a850();
  FUN_1000a85f();
  return;
}



void FUN_1000a850(void)

{
  DD_SURFACE::DD_SURFACE(&GKERNEL::ddsPrimary);
  return;
}



void FUN_1000a85f(void)

{
  FUN_100104a2(FUN_1000a871);
  return;
}



void FUN_1000a871(void)

{
  if ((DAT_1001b29c & 1) == 0) {
    DAT_1001b29c = DAT_1001b29c | 1;
    DD_SURFACE::~DD_SURFACE(&GKERNEL::ddsPrimary);
  }
  return;
}



void FUN_1000a89d(void)

{
  FUN_1000a8ac();
  FUN_1000a8bb();
  return;
}



void FUN_1000a8ac(void)

{
  DD_SURFACE::DD_SURFACE(&GKERNEL::ddsBack);
  return;
}



void FUN_1000a8bb(void)

{
  FUN_100104a2(FUN_1000a8cd);
  return;
}



void FUN_1000a8cd(void)

{
  if ((DAT_1001b29c & 2) == 0) {
    DAT_1001b29c = DAT_1001b29c | 2;
    DD_SURFACE::~DD_SURFACE(&GKERNEL::ddsBack);
  }
  return;
}



void FUN_1000a8f9(void)

{
  FUN_1000a908();
  FUN_1000a917();
  return;
}



void FUN_1000a908(void)

{
  DD_SURFACE::DD_SURFACE(&GKERNEL::ddsVisible);
  return;
}



void FUN_1000a917(void)

{
  FUN_100104a2(FUN_1000a929);
  return;
}



void FUN_1000a929(void)

{
  if ((DAT_1001b29c & 4) == 0) {
    DAT_1001b29c = DAT_1001b29c | 4;
    DD_SURFACE::~DD_SURFACE(&GKERNEL::ddsVisible);
  }
  return;
}



void FUN_1000a955(void)

{
  FUN_1000a964();
  FUN_1000a973();
  return;
}



void FUN_1000a964(void)

{
  FUN_1000bb50((CTypeLibCacheMap *)&DAT_1001b370);
  return;
}



void FUN_1000a973(void)

{
  FUN_100104a2(FUN_1000a985);
  return;
}



void FUN_1000a985(void)

{
  if ((DAT_1001b29c & 8) == 0) {
    DAT_1001b29c = DAT_1001b29c | 8;
    FUN_1000bb30((undefined4 *)&DAT_1001b370);
  }
  return;
}



void FUN_1000a9b1(void)

{
  FUN_1000a9c0();
  FUN_1000a9cf();
  return;
}



void FUN_1000a9c0(void)

{
  FUN_1000bbe0((CWinApp *)&DAT_1001b2a0);
  return;
}



void FUN_1000a9cf(void)

{
  FUN_100104a2(FUN_1000a9e1);
  return;
}



void FUN_1000a9e1(void)

{
  FUN_1000bbc0((CWinApp *)&DAT_1001b2a0);
  return;
}



// public: static unsigned long __cdecl GKERNEL::GetCurrFrame(void)

ulong __cdecl GKERNEL::GetCurrFrame(void)

{
                    // 0xa9f0  72  ?GetCurrFrame@GKERNEL@@SAKXZ
  return DAT_1001b398;
}



// public: static bool __cdecl GKERNEL::SetPalette(unsigned long *)

bool __cdecl GKERNEL::SetPalette(ulong *param_1)

{
                    // 0xa9fa  161  ?SetPalette@GKERNEL@@SA_NPAK@Z
  return true;
}



// public: static bool __cdecl GKERNEL::Initialized(void)

bool __cdecl GKERNEL::Initialized(void)

{
                    // 0xaa01  104  ?Initialized@GKERNEL@@SA_NXZ
  return (bool)DAT_1001b3b8;
}



void __cdecl FUN_1000aa0b(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  if (param_1 == 0) {
    *param_2 = 0x280;
    *param_3 = 0x1e0;
    *param_4 = 0x10;
  }
  else if (param_1 == 1) {
    *param_2 = 0x280;
    *param_3 = 0x1e0;
    *param_4 = 0x18;
  }
  return;
}



void FUN_1000aa5f(void)

{
  BOOL BVar1;
  int iVar2;
  UINT *pUVar3;
  tagMSG local_20;
  
  DAT_1001b59c = 1;
  DestroyWindow(DAT_1001b394);
  do {
    local_20.hwnd = (HWND)0x0;
    pUVar3 = &local_20.message;
    for (iVar2 = 6; iVar2 != 0; iVar2 = iVar2 + -1) {
      *pUVar3 = 0;
      pUVar3 = pUVar3 + 1;
    }
    BVar1 = PeekMessageA(&local_20,(HWND)0x0,0,0,0);
  } while ((BVar1 == 0) || (BVar1 = GetMessageA(&local_20,(HWND)0x0,0,0), BVar1 != 0));
  DAT_1001b59c = 0;
  DAT_1001b394 = (HWND)0x0;
  return;
}



void FUN_1000aad9(void)

{
  BOOL BVar1;
  undefined4 local_28;
  REG local_24 [4];
  tagRECT local_20;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10010b32;
  local_10 = ExceptionList;
  if ((DAT_1001b394 != (HWND)0x0) &&
     (ExceptionList = &local_10, BVar1 = GetWindowRect(DAT_1001b394,&local_20), BVar1 != 0)) {
    FUN_1000c0d0(&local_28,(undefined4 *)&DAT_1001b458,s_Aargon_Deluxe_100188b0);
    local_8 = 0;
    FUN_1000c0d0(local_24,&local_28,s_WindowCoords_100188c0);
    local_8._0_1_ = 1;
    REG::Put(local_24,(char *)&this_100188d0,local_20.left);
    REG::Put(local_24,(char *)&this_100188d8,local_20.top);
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_1000a7b0((undefined4 *)local_24);
    local_8 = 0xffffffff;
    FUN_1000a7b0(&local_28);
  }
  ExceptionList = local_10;
  return;
}



void __cdecl FUN_1000ab92(LPRECT param_1)

{
  bool bVar1;
  BOOL BVar2;
  int iVar3;
  int iVar4;
  tagRECT local_40;
  HWND local_30;
  int local_2c;
  ulong local_28;
  ulong local_24;
  int local_20;
  undefined4 local_1c;
  REG local_18 [4];
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10010b4e;
  local_10 = ExceptionList;
  if (param_1 != (LPRECT)0x0) {
    ExceptionList = &local_10;
    local_2c = GetSystemMetrics(7);
    local_14 = GetSystemMetrics(8);
    local_20 = GetSystemMetrics(4);
    SetRect(param_1,0,0,DAT_1001b390 + local_2c * 2,DAT_1001b298 + local_20 + local_14 * 2);
    local_24 = 0;
    local_28 = 0;
    FUN_1000c0d0(&local_1c,(undefined4 *)&DAT_1001b458,s_Aargon_Deluxe_100188dc);
    local_8 = 0;
    FUN_1000c0d0(local_18,&local_1c,s_WindowCoords_100188ec);
    local_8 = CONCAT31(local_8._1_3_,1);
    bVar1 = REG::Get(local_18,(char *)&this_100188fc,&local_24);
    if ((bVar1) && (bVar1 = REG::Get(local_18,(char *)&this_10018904,&local_28), bVar1)) {
      iVar3 = FUN_1000be10(local_24,0);
      iVar4 = FUN_1000be10(local_28,0);
      SetRect(param_1,iVar3,iVar4,iVar3 + DAT_1001b390 + local_2c * 2,
              iVar4 + DAT_1001b298 + local_20 + local_14 * 2);
    }
    else {
      local_30 = GetDesktopWindow();
      if ((local_30 != (HWND)0x0) && (BVar2 = GetWindowRect(local_30,&local_40), BVar2 != 0)) {
        iVar3 = local_40.right - local_40.left;
        iVar4 = local_40.bottom - local_40.top;
        if ((DAT_1001b390 <= iVar3) && (DAT_1001b298 <= iVar4)) {
          SetRect(param_1,(uint)((iVar3 - DAT_1001b390) + local_2c * -2) >> 1,
                  (uint)(((iVar4 - DAT_1001b298) + local_14 * -2) - local_20) >> 1,
                  (uint)(iVar3 + DAT_1001b390 + local_2c * 2) >> 1,
                  (uint)(local_20 + iVar4 + DAT_1001b298 + local_14 * 2) >> 1);
        }
      }
    }
    local_8 = local_8 & 0xffffff00;
    FUN_1000a7b0((undefined4 *)local_18);
    local_8 = 0xffffffff;
    FUN_1000a7b0(&local_1c);
  }
  ExceptionList = local_10;
  return;
}



void FUN_1000adaf(void)

{
  HMODULE hInstance;
  int iVar1;
  undefined4 *puVar2;
  LPVOID lpParam;
  char *local_8c;
  undefined4 local_88;
  undefined4 local_84 [4];
  undefined4 local_74;
  undefined1 *local_64;
  undefined4 local_20;
  int local_1c;
  tagRECT local_18;
  uint local_8;
  
  local_88 = 0;
  puVar2 = local_84;
  for (iVar1 = 0x1a; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  FUN_1000e2ee();
  FUN_1000e580(0x1001b500);
  if (DAT_1001b394 != (HWND)0x0) {
    FUN_1000aad9();
    FUN_1000aa5f();
  }
  lpParam = (LPVOID)0x0;
  hInstance = GetModuleHandleA((LPCSTR)0x0);
  DAT_1001b394 = CreateWindowExA(8,s_GKERNELWIND_10018914,s_GKERNELWIND_10018908,0x90080000,0,0,
                                 0x280,0x1e0,(HWND)0x0,(HMENU)0x0,hInstance,lpParam);
  if (DAT_100188ac != '\0') {
    ShowCursor(0);
  }
  local_1c = 0;
  local_1c = (**(code **)(*DAT_1001b598 + 0x50))(DAT_1001b598,DAT_1001b394,0x15);
  local_1c = (**(code **)(*DAT_1001b598 + 0x54))
                       (DAT_1001b598,DAT_1001b390,DAT_1001b298,DAT_1001b3a0,0,0);
  if (local_1c < 0) {
    local_8c = s_Cannot_set_display_mode_10018920;
                    // WARNING: Subroutine does not return
    _CxxThrowException(&local_8c,(ThrowInfo *)&pThrowInfo_10012550);
  }
  memset(&local_88,0,0x6c);
  local_88 = 0x6c;
  local_84[0] = 0x21;
  local_20 = 0x218;
  local_74 = 1;
  DD_SURFACE::Create(&GKERNEL::ddsPrimary,(_DDSURFACEDESC *)&local_88,(HWND__ *)0x0);
  DD_SURFACE::BackBuffer(&GKERNEL::ddsBack,&GKERNEL::ddsPrimary);
  local_18.left = 0;
  local_18.right = 10;
  local_18.top = 0;
  local_18.bottom = 10;
  memset(&local_88,0,0x6c);
  local_88 = 0x6c;
  local_1c = DD_SURFACE::Lock(&GKERNEL::ddsBack,&local_18,(_DDSURFACEDESC *)&local_88,1);
  *local_64 = 0;
  DD_SURFACE::Unlock(&GKERNEL::ddsBack);
  GKERNEL::Flip();
  memset(&local_88,0,0x6c);
  local_88 = 0x6c;
  local_1c = DD_SURFACE::Lock(&GKERNEL::ddsBack,&local_18,(_DDSURFACEDESC *)&local_88,1);
  *local_64 = 0xff;
  DD_SURFACE::Unlock(&GKERNEL::ddsBack);
  GKERNEL::Flip();
  memset(&local_88,0,0x6c);
  local_88 = 0x6c;
  local_1c = DD_SURFACE::Lock(&GKERNEL::ddsBack,&local_18,(_DDSURFACEDESC *)&local_88,1);
  local_8 = CONCAT31(local_8._1_3_,*local_64);
  DD_SURFACE::Unlock(&GKERNEL::ddsBack);
  DAT_1001b38c = '\x01' - ((local_8 & 0xff) != 0);
  return;
}



void FUN_1000b02c(void)

{
  HMODULE hInstance;
  int iVar1;
  undefined4 *puVar2;
  LPVOID lpParam;
  undefined4 local_84;
  undefined4 local_80 [25];
  undefined4 local_1c;
  tagRECT local_18;
  undefined4 local_8;
  
  local_84 = 0;
  puVar2 = local_80;
  for (iVar1 = 0x1a; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  FUN_1000e2ee();
  if (DAT_1001b394 != (HWND__ *)0x0) {
    FUN_1000aa5f();
  }
  FUN_1000ab92(&local_18);
  lpParam = (LPVOID)0x0;
  hInstance = GetModuleHandleA((LPCSTR)0x0);
  DAT_1001b394 = CreateWindowExA(0,s_GKERNELWIND_10018948,s_Aargon_Deluxe_10018938,0x108b0000,
                                 local_18.left,local_18.top,local_18.right - local_18.left,
                                 local_18.bottom - local_18.top,(HWND)0x0,(HMENU)0x0,hInstance,
                                 lpParam);
  local_8 = (**(code **)(*DAT_1001b598 + 0x4c))(DAT_1001b598);
  DAT_1001b4f8 = 0;
  local_8 = (**(code **)(*DAT_1001b598 + 0x50))(DAT_1001b598,DAT_1001b394,8);
  memset(&local_84,0,0x6c);
  local_84 = 0x6c;
  local_80[0] = 1;
  local_1c = 0x200;
  DD_SURFACE::Create(&GKERNEL::ddsVisible,(_DDSURFACEDESC *)&local_84,DAT_1001b394);
  memset(&local_84,0,0x6c);
  local_84 = 0x6c;
  local_80[0] = 7;
  local_1c = 0x40;
  local_80[2] = DAT_1001b390;
  local_80[1] = DAT_1001b298;
  DD_SURFACE::Create(&GKERNEL::ddsPrimary,(_DDSURFACEDESC *)&local_84,(HWND__ *)0x0);
  memset(&local_84,0,0x6c);
  local_84 = 0x6c;
  local_80[0] = 7;
  local_1c = 0x40;
  local_80[2] = DAT_1001b390;
  local_80[1] = DAT_1001b298;
  DD_SURFACE::Create(&GKERNEL::ddsBack,(_DDSURFACEDESC *)&local_84,(HWND__ *)0x0);
  DAT_1001b38c = 1;
  return;
}



// public: static struct HWND__ * __cdecl GKERNEL::GetHwnd(void)

HWND__ * __cdecl GKERNEL::GetHwnd(void)

{
                    // 0xb1c1  79  ?GetHwnd@GKERNEL@@SAPAUHWND__@@XZ
  return DAT_1001b394;
}



// lpEnumFunc parameter of EnumResourceNamesA
// 

bool lpEnumFunc_1000b1cb(HINSTANCE param_1,int param_2,LPCSTR param_3,int param_4)

{
  HICON pHVar1;
  
  if (param_2 == 0xe) {
    pHVar1 = LoadIconA(param_1,param_3);
    *(HICON *)(param_4 + 0x14) = pHVar1;
  }
  return param_2 == 0xe;
}



// public: static void __cdecl GKERNEL::Init(bool)

void __cdecl GKERNEL::Init(bool param_1)

{
  bool bVar1;
  HWND pHVar2;
  int iVar3;
  undefined4 *puVar4;
  uint *puVar5;
  WNDPROC *ppWVar6;
  char *local_228;
  int local_224;
  undefined4 local_220 [2];
  int *local_218;
  WNDCLASSA local_214;
  undefined1 local_1ec [148];
  uint local_158;
  DWORD local_154;
  undefined4 local_150;
  uint local_14c [78];
  ATOM local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0xb1fe  91  ?Init@GKERNEL@@SAX_N@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_10010b64;
  local_10 = ExceptionList;
  local_1ec[0] = '\0';
  puVar4 = (undefined4 *)(local_1ec + 1);
  for (iVar3 = 0x24; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  *(undefined2 *)puVar4 = 0;
  *(undefined1 *)((int)puVar4 + 2) = 0;
  local_1ec._36_2_ = 0x94;
  ExceptionList = &local_10;
  EnumDisplaySettingsA((LPCSTR)0x0,0xffffffff,(DEVMODEA *)local_1ec);
  if ((uint)local_1ec._104_4_ < 0x10) {
    param_1_1001b368._0_1_ = '\0';
    DisplayWarning(s_Aargon_Deluxe_Tip_10018a60,s_Your_Windows_desktop_is_set_to_2_10018960,
                   s_256Color_10018954);
  }
  else {
    REG::GetPut((REG *)&DAT_1001b458,s_Windowed_10018a74,(bool *)&param_1_1001b368,false);
  }
  DAT_100188ac = param_1;
  FUN_10004e70(local_220,&DAT_1001b3b8,1);
  local_8 = 0;
  pHVar2 = FindWindowA(s_GKERNELWIND_10018a80,(LPCSTR)0x0);
  if (pHVar2 != (HWND)0x0) {
                    // WARNING: Subroutine does not return
    exit(0);
  }
  local_154 = DirectDrawCreate(0,&local_218,0);
  if (local_154 == 0x88760231) {
    MessageBoxA((HWND)0x0,s_DirectX_5_0_or_greater_was_not_d_10018a9c,s_Aargon_Error_10018a8c,0x10);
                    // WARNING: Subroutine does not return
    exit(0);
  }
  if (-1 < (int)local_154) {
    local_154 = (**(code **)*local_218)(local_218,&DAT_10011b60,&DAT_1001b598);
    (**(code **)(*local_218 + 8))(local_218);
    puVar5 = local_14c;
    for (iVar3 = 0x4e; iVar3 != 0; iVar3 = iVar3 + -1) {
      *puVar5 = 0;
      puVar5 = puVar5 + 1;
    }
    local_150 = 0x13c;
    (**(code **)(*DAT_1001b598 + 0x2c))(DAT_1001b598,&local_150,0);
    DAT_1001b59e = (local_14c[1] & 0x80000) != 0;
    DAT_1001b390 = 0x280;
    DAT_1001b298 = 0x1e0;
    DAT_1001b3a0 = 0x10;
    local_158 = local_158 & 0xffffff00;
    bVar1 = REG::Get((REG *)&DAT_1001b458,s_UseTrueColor_10018b24,(bool *)&local_158);
    iVar3 = DAT_1001b3a0;
    if (((bVar1) && ((local_158 & 0xff) != 0)) &&
       (local_224 = FUN_1000eccb(), iVar3 = local_224, local_224 == -1)) {
      MessageBoxA((HWND)0x0,s_Cannot_use_TrueColor_with_curren_10018b3c,s_Warning_10018b34,0x30);
      iVar3 = DAT_1001b3a0;
    }
    DAT_1001b3a0 = iVar3;
    ppWVar6 = &local_214.lpfnWndProc;
    for (iVar3 = 9; iVar3 != 0; iVar3 = iVar3 + -1) {
      *ppWVar6 = (WNDPROC)0x0;
      ppWVar6 = ppWVar6 + 1;
    }
    local_214.style = 3;
    local_214.lpfnWndProc = FUN_1000f550;
    local_214.cbClsExtra = 0;
    local_214.cbWndExtra = 0;
    local_214.hInstance = GetModuleHandleA((LPCSTR)0x0);
    EnumResourceNamesA(local_214.hInstance,(LPCSTR)0xe,lpEnumFunc_1000b1cb,(LONG_PTR)&local_214);
    local_214.hCursor = LoadCursorA((HINSTANCE)0x0,(LPCSTR)0x7f00);
    local_214.hbrBackground = (HBRUSH)0x0;
    local_214.lpszMenuName = (LPCSTR)0x0;
    local_214.lpszClassName = s_GKERNELWIND_10018b98;
    local_14 = RegisterClassA(&local_214);
    SetFocus(DAT_1001b394);
    if ((char)param_1_1001b368 == '\0') {
      FUN_1000adaf();
    }
    else {
      FUN_1000b02c();
    }
    local_8 = 0xffffffff;
    FUN_10004ea0(local_220);
    ExceptionList = local_10;
    return;
  }
  local_228 = s_DirectX_Initialization_failed_10018b04;
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_228,(ThrowInfo *)&pThrowInfo_10012550);
}



// public: static void __cdecl GKERNEL::ResetFrameCounter(void)

void __cdecl GKERNEL::ResetFrameCounter(void)

{
                    // 0xb533  128  ?ResetFrameCounter@GKERNEL@@SAXXZ
  DAT_1001b5a4 = 0;
  return;
}



// public: static void __cdecl GKERNEL::CalcFramesPerSecond(void)

void __cdecl GKERNEL::CalcFramesPerSecond(void)

{
  uint uVar1;
  
                    // 0xb542  26  ?CalcFramesPerSecond@GKERNEL@@SAXXZ
  if (DAT_1001b5a4 == 3) {
    FUN_10003fa0((DWORD *)&DAT_1001b3bc);
  }
  if (DAT_1001b5a4 == 0xd) {
    uVar1 = FUN_1000c120((DWORD *)&DAT_1001b3bc);
    DAT_1001b5a0 = (uint)(10000 / (ulonglong)uVar1);
    if (DAT_1001b5a0 < 0x19) {
      DAT_1001b5a0 = 0x19;
    }
  }
  DAT_1001b5a4 = DAT_1001b5a4 + 1;
  return;
}



// public: static unsigned int __cdecl GKERNEL::FramesPerSecond(void)

uint __cdecl GKERNEL::FramesPerSecond(void)

{
                    // 0xb5a2  70  ?FramesPerSecond@GKERNEL@@SAIXZ
  return DAT_1001b5a0;
}



// public: static void __cdecl GKERNEL::Flip(void)

void __cdecl GKERNEL::Flip(void)

{
  HWND__ *pHVar1;
  RECT *lpRect;
  BOOL bErase;
  RECT local_14;
  
                    // 0xb5ac  66  ?Flip@GKERNEL@@SAXXZ
  if ((DAT_1001b598 != 0) && (bAnimate)) {
    DAT_1001b398 = DAT_1001b398 + 1;
    if ((char)param_1_1001b368 == '\0') {
      DD_SURFACE::Flip(&ddsPrimary);
      DD_SURFACE::WaitForFlipToComplete(&ddsPrimary);
    }
    else {
      local_14.left = 0;
      local_14.top = 0;
      local_14.right = 0x280;
      local_14.bottom = 0x1e0;
      FUN_1000be40(&ddsPrimary,&ddsBack);
      bErase = 0;
      lpRect = &local_14;
      pHVar1 = GetHwnd();
      InvalidateRect(pHVar1,lpRect,bErase);
      pHVar1 = GetHwnd();
      UpdateWindow(pHVar1);
    }
    CalcFramesPerSecond();
  }
  return;
}



// public: static void __cdecl GKERNEL::Animate(bool)

void __cdecl GKERNEL::Animate(bool param_1)

{
                    // 0xb654  19  ?Animate@GKERNEL@@SAX_N@Z
  (**(code **)(*DAT_1001b598 + 0x28))(DAT_1001b598);
  bAnimate = param_1;
  return;
}



// public: static void __cdecl GKERNEL::CloseDirectDraw(void)

void __cdecl GKERNEL::CloseDirectDraw(void)

{
                    // 0xb672  29  ?CloseDirectDraw@GKERNEL@@SAXXZ
  if (DAT_1001b598 != (int *)0x0) {
    FUN_1000e2ee();
    (**(code **)(*DAT_1001b598 + 0x4c))(DAT_1001b598);
    (**(code **)(*DAT_1001b598 + 8))(DAT_1001b598);
    DAT_1001b598 = (int *)0x0;
  }
  ShowWindow(DAT_1001b394,0);
  return;
}



// public: static void __cdecl GKERNEL::SetCursorPos(struct tagPOINT const &)

BOOL GKERNEL::SetCursorPos(int X,int Y)

{
  HWND__ *hWnd;
  BOOL BVar1;
  tagPOINT *lpPoint;
  tagPOINT local_c;
  
                    // 0xb6bf  149  ?SetCursorPos@GKERNEL@@SAXABUtagPOINT@@@Z
  local_c.x = *(LONG *)X;
  local_c.y = *(int *)(X + 4);
  lpPoint = &local_c;
  hWnd = GetHwnd();
  ClientToScreen(hWnd,lpPoint);
  BVar1 = ::SetCursorPos(local_c.x,local_c.y);
  return BVar1;
}



// public: static void __cdecl GKERNEL::IgnoreUserInput(bool)

void __cdecl GKERNEL::IgnoreUserInput(bool param_1)

{
                    // 0xb6f5  88  ?IgnoreUserInput@GKERNEL@@SAX_N@Z
  DAT_1001b59d = param_1;
  return;
}



// public: static void __cdecl GKERNEL::FlushInputQueue(void)

void __cdecl GKERNEL::FlushInputQueue(void)

{
  BOOL BVar1;
  int iVar2;
  UINT *pUVar3;
  tagMSG local_20;
  
                    // 0xb702  69  ?FlushInputQueue@GKERNEL@@SAXXZ
  local_20.hwnd = (HWND)0x0;
  pUVar3 = &local_20.message;
  for (iVar2 = 6; iVar2 != 0; iVar2 = iVar2 + -1) {
    *pUVar3 = 0;
    pUVar3 = pUVar3 + 1;
  }
  do {
    BVar1 = PeekMessageA(&local_20,(HWND)0x0,0x200,0x209,1);
  } while (BVar1 != 0);
  do {
    BVar1 = PeekMessageA(&local_20,(HWND)0x0,0x100,0x108,1);
  } while (BVar1 != 0);
  return;
}



// public: static bool __cdecl GKERNEL::GetCursorPos(struct tagPOINT *)

BOOL GKERNEL::GetCursorPos(LPPOINT lpPoint)

{
  HWND__ *hWnd;
  uint uVar1;
  tagPOINT *lpPoint_00;
  tagPOINT local_c;
  
                    // 0xb75d  73  ?GetCursorPos@GKERNEL@@SA_NPAUtagPOINT@@@Z
  local_c.x = 0;
  local_c.y = 0;
  ::GetCursorPos(&local_c);
  lpPoint_00 = &local_c;
  hWnd = GetHwnd();
  uVar1 = ScreenToClient(hWnd,lpPoint_00);
  if ((((local_c.x < 0) || (0x27f < local_c.x)) || (local_c.y < 0)) || (0x1df < local_c.y)) {
    uVar1 = uVar1 & 0xffffff00;
  }
  else {
    lpPoint->x = local_c.x;
    lpPoint->y = local_c.y;
    uVar1 = CONCAT31((int3)((uint)lpPoint >> 8),1);
  }
  return uVar1;
}



// public: static void __cdecl GKERNEL::ErrorMessage(char const *)

void __cdecl GKERNEL::ErrorMessage(char *param_1)

{
  AFX_MODULE_STATE *pAVar1;
  HWND__ *pHVar2;
  CWnd *pCVar3;
  TwDirectXDialog local_7c [96];
  CString local_1c [4];
  AFX_MAINTAIN_STATE2 local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0xb7bf  64  ?ErrorMessage@GKERNEL@@SAXPBD@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_10010b80;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pAVar1 = (AFX_MODULE_STATE *)FUN_100102bd();
  AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(local_18,pAVar1);
  local_8 = 0;
  ShowMouse(true);
  TwDirectXDialog::EnableFullScreenSupport(true);
  pHVar2 = GetHwnd();
  pCVar3 = CWnd::FromHandle(pHVar2);
  FUN_10008050(local_7c,pCVar3);
  local_8._0_1_ = 1;
  CString::operator=(local_1c,param_1);
  TwDirectXDialog::DoModal(local_7c);
  TwDirectXDialog::EnableFullScreenSupport(false);
  ShowMouse(DAT_100188ac == '\0');
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_10008190((CDialog *)local_7c);
  local_8 = 0xffffffff;
  FUN_1000c0b0((undefined4 *)local_18);
  ExceptionList = local_10;
  return;
}



// public: static bool __cdecl GKERNEL::SupportsFullScreenGDIClipping(void)

bool __cdecl GKERNEL::SupportsFullScreenGDIClipping(void)

{
                    // 0xb87a  193  ?SupportsFullScreenGDIClipping@GKERNEL@@SA_NXZ
  return (bool)DAT_1001b59e;
}



// public: static bool __cdecl GKERNEL::SupportsWindowedMode(void)

bool __cdecl GKERNEL::SupportsWindowedMode(void)

{
  int iVar1;
  undefined4 *puVar2;
  BYTE local_98;
  undefined4 local_97;
  WORD local_74;
  uint local_30;
  
                    // 0xb884  194  ?SupportsWindowedMode@GKERNEL@@SA_NXZ
  local_98 = '\0';
  puVar2 = &local_97;
  for (iVar1 = 0x24; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined1 *)((int)puVar2 + 2) = 0;
  local_74 = 0x94;
  EnumDisplaySettingsA((LPCSTR)0x0,0xfffffffe,(DEVMODEA *)&local_98);
  return (bool)('\x01' - (local_30 < 0x10));
}



// public: static bool __cdecl GKERNEL::SetWindowedMode(bool)

bool __cdecl GKERNEL::SetWindowedMode(bool param_1)

{
  bool bVar1;
  undefined4 local_18 [2];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0xb8ca  181  ?SetWindowedMode@GKERNEL@@SA_N_N@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_10010b93;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  bVar1 = Initialized();
  if (bVar1) {
    if (DAT_1001b5a8 == '\0') {
      DAT_1001b5a8 = '\x01';
      FUN_10004e70(local_18,&DAT_1001b5a8,0);
      local_8 = 0;
      if ((param_1) && (bVar1 = SupportsWindowedMode(), !bVar1)) {
        if ((char)param_1_1001b368 == '\0') {
          ErrorMessage(s_Cannot_switch_to_windowed_mode_A_10018ba4);
          REG::Put((REG *)&DAT_1001b458,s_Windowed_10018c5c,false);
          local_8 = 0xffffffff;
          FUN_10004ea0(local_18);
          ExceptionList = local_10;
          return false;
        }
        ErrorMessage(s_Cannot_continue_in_windowed_mode_10018c68);
        param_1 = false;
      }
      param_1_1001b368._0_1_ = param_1;
      if (param_1 == false) {
        FUN_1000adaf();
      }
      else {
        FUN_1000b02c();
      }
      FUN_1000e481();
      NewSpriteBackground();
      Flip();
      if (DAT_1001b36c != (int *)0x0) {
        ResetFrameCounter();
        FUN_1000c150();
        (**(code **)(*DAT_1001b36c + 8))(1);
      }
      REG::Put((REG *)&DAT_1001b458,s_Windowed_10018d20,(bool)(char)param_1_1001b368);
      local_8 = 0xffffffff;
      FUN_10004ea0(local_18);
      bVar1 = true;
    }
    else {
      bVar1 = true;
    }
  }
  else {
    bVar1 = false;
  }
  ExceptionList = local_10;
  return bVar1;
}



// public: static void __cdecl GKERNEL::Stop(void)

void __cdecl GKERNEL::Stop(void)

{
                    // 0xba2b  191  ?Stop@GKERNEL@@SAXXZ
  (**(code **)(*DAT_1001b36c + 4))();
  DAT_1001b3b8 = 0;
  CloseDirectDraw();
  FUN_10003fa0((DWORD *)&DAT_1001b39c);
  DAT_1001b59f = 1;
  if (DAT_1001b394 != (HWND)0x0) {
    if ((char)param_1_1001b368 != '\0') {
      FUN_1000aad9();
    }
    DestroyWindow(DAT_1001b394);
    DAT_1001b394 = (HWND)0x0;
  }
  return;
}



// public: __thiscall GKERNEL::~GKERNEL(void)

void __thiscall GKERNEL::~GKERNEL(GKERNEL *this)

{
                    // 0xba8d  14  ??1GKERNEL@@QAE@XZ
  CoUninitialize();
  FUN_1000a7b0((undefined4 *)this);
  return;
}



// public: static unsigned int __cdecl GKERNEL::ScrXRes(void)

uint __cdecl GKERNEL::ScrXRes(void)

{
                    // 0xbaa6  137  ?ScrXRes@GKERNEL@@SAIXZ
  return DAT_1001b390;
}



// public: static unsigned int __cdecl GKERNEL::ScrYRes(void)

uint __cdecl GKERNEL::ScrYRes(void)

{
                    // 0xbab0  138  ?ScrYRes@GKERNEL@@SAIXZ
  return DAT_1001b298;
}



// public: static bool __cdecl GKERNEL::Windowed(void)

bool __cdecl GKERNEL::Windowed(void)

{
                    // 0xbaba  201  ?Windowed@GKERNEL@@SA_NXZ
  return (bool)param_1_1001b368._0_1_;
}



// public: __thiscall GKERNEL::GKERNEL(void)

GKERNEL * __thiscall GKERNEL::GKERNEL(GKERNEL *this)

{
                    // 0xbac4  2  ??0GKERNEL@@QAE@XZ
  FUN_1000a700(this,s_Gkernel_10018d40,s_Software_Twilight__10018d2c);
  DAT_1001b3b8 = 0;
  DAT_1001b398 = 0;
  DAT_1001b394 = 0;
  DAT_1001b390 = 0;
  DAT_1001b298 = 0;
  DAT_1001b3a0 = 0;
  param_1_1001b368._0_1_ = 0;
  DAT_1001b598 = 0;
  return this;
}



void __fastcall FUN_1000bb30(undefined4 *param_1)

{
  FUN_1000bb70(param_1);
  return;
}



CTypeLibCacheMap * __fastcall FUN_1000bb50(CTypeLibCacheMap *param_1)

{
  CTypeLibCacheMap::CTypeLibCacheMap(param_1);
  *(undefined ***)param_1 = &PTR_LAB_10011c20;
  return param_1;
}



void __fastcall FUN_1000bb70(undefined4 *param_1)

{
  FUN_1000bd10(param_1);
  return;
}



void * __thiscall FUN_1000bb90(void *this,uint param_1)

{
  FUN_1000bb30((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001c10(this);
  }
  return this;
}



void __fastcall FUN_1000bbc0(CWinApp *param_1)

{
  CWinApp::~CWinApp(param_1);
  return;
}



CWinApp * __fastcall FUN_1000bbe0(CWinApp *param_1)

{
  CWinApp::CWinApp(param_1,(char *)0x0);
  *(undefined ***)param_1 = &PTR_LAB_10011c34;
  return param_1;
}



undefined4 FUN_1000bc10(void)

{
  return 1;
}



void * __thiscall FUN_1000bc20(void *this,uint param_1)

{
  FUN_1000bbc0((CWinApp *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001c10(this);
  }
  return this;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_1000bcb0(this,10);
  *(undefined ***)this = &PTR_LAB_10011cd8;
  return this;
}



void * __thiscall FUN_1000bc80(void *this,uint param_1)

{
  FUN_1000bb70((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001c10(this);
  }
  return this;
}



void * __thiscall FUN_1000bcb0(void *this,undefined4 param_1)

{
  FUN_10003f80((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_10011cec;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



void __fastcall FUN_1000bd10(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_10010ba9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_10011cec;
  local_8 = 0;
  FUN_1000bf50((int)param_1);
  local_8 = 0xffffffff;
  FUN_10001bb0(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_1000bd70(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_10;
  ulong local_c;
  undefined4 *local_8;
  
  FUN_10001c00();
  bVar1 = FUN_10001c30((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      FUN_1000eb50(param_1,&local_10,1);
      FUN_1000bef0(this,&local_10);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_1000eb50(param_1,local_8 + 2,1);
    }
  }
  return;
}



int __cdecl FUN_1000be10(int param_1,int param_2)

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



void __cdecl FUN_1000be40(DD_SURFACE *param_1,DD_SURFACE *param_2)

{
  DD_SURFACE local_a8 [152];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10010bcc;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  DD_SURFACE::DD_SURFACE(local_a8);
  local_8 = 0;
  DD_SURFACE::operator=(local_a8,param_1);
  DD_SURFACE::operator=(param_1,param_2);
  DD_SURFACE::operator=(param_2,local_a8);
  local_8 = 0xffffffff;
  DD_SURFACE::~DD_SURFACE(local_a8);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_1000bec0(void *this,uint param_1)

{
  FUN_1000bd10((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001c10(this);
  }
  return this;
}



undefined4 * __thiscall FUN_1000bef0(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_1000bfd0(this,*(undefined4 *)((int)this + 8),0);
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



void __fastcall FUN_1000bf50(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_10001b80(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



undefined4 * __thiscall FUN_1000bfd0(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0xc);
    iVar3 = FUN_100106c0((int)pCVar2);
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
  FUN_10009660(puVar1 + 2,1);
  return puVar1;
}



void __fastcall FUN_1000c0b0(undefined4 *param_1)

{
  *(undefined4 *)(param_1[1] + 4) = *param_1;
  return;
}



void * __thiscall FUN_1000c0d0(void *this,undefined4 *param_1,LPCSTR param_2)

{
  DWORD dwErrCode;
  
  dwErrCode = RegCreateKeyExA((HKEY)*param_1,param_2,0,(LPSTR)0x0,0,0xf003f,
                              (LPSECURITY_ATTRIBUTES)0x0,(PHKEY)this,(LPDWORD)0x0);
  SetLastError(dwErrCode);
  return this;
}



int __fastcall FUN_1000c120(DWORD *param_1)

{
  DWORD DVar1;
  DWORD DVar2;
  
  DVar2 = GetTickCount();
  DVar1 = *param_1;
  *param_1 = DVar2;
  return DVar2 - DVar1;
}



void FUN_1000c150(void)

{
  DAT_1001b5b4 = 0;
  return;
}



// public: static void __cdecl GKTOOLS::CopyAndRotate90(struct IDirectDrawSurface *,unsigned
// int,unsigned int,struct IDirectDrawSurface *,struct tagRECT)

void __cdecl
GKTOOLS::CopyAndRotate90
          (IDirectDrawSurface *param_1,uint param_2,uint param_3,IDirectDrawSurface *param_4,
          tagRECT param_5)

{
                    // 0xc160  32
                    // ?CopyAndRotate90@GKTOOLS@@SAXPAUIDirectDrawSurface@@II0UtagRECT@@@Z
  return;
}



// public: static void __cdecl GKTOOLS::CopyAndRotate180(struct IDirectDrawSurface *,unsigned
// int,unsigned int,struct IDirectDrawSurface *,struct tagRECT)

void __cdecl
GKTOOLS::CopyAndRotate180
          (IDirectDrawSurface *param_1,uint param_2,uint param_3,IDirectDrawSurface *param_4,
          tagRECT param_5)

{
                    // 0xc165  30
                    // ?CopyAndRotate180@GKTOOLS@@SAXPAUIDirectDrawSurface@@II0UtagRECT@@@Z
  CopyAndRotate90(param_1,param_2,param_3,param_4,param_5);
  CopyAndRotate90(param_1,param_2,param_3,param_4,param_5);
  return;
}



// public: static void __cdecl GKTOOLS::CopyAndRotate270(struct IDirectDrawSurface *,unsigned
// int,unsigned int,struct IDirectDrawSurface *,struct tagRECT)

void __cdecl
GKTOOLS::CopyAndRotate270
          (IDirectDrawSurface *param_1,uint param_2,uint param_3,IDirectDrawSurface *param_4,
          tagRECT param_5)

{
                    // 0xc1cf  31
                    // ?CopyAndRotate270@GKTOOLS@@SAXPAUIDirectDrawSurface@@II0UtagRECT@@@Z
  CopyAndRotate90(param_1,param_2,param_3,param_4,param_5);
  CopyAndRotate90(param_1,param_2,param_3,param_4,param_5);
  CopyAndRotate90(param_1,param_2,param_3,param_4,param_5);
  return;
}



// public: static void __cdecl GKTOOLS::CopyResourceDIBToSurface(struct IDirectDrawSurface *,char
// const *,struct HINSTANCE__ *,unsigned int,unsigned int,bool)

void __cdecl
GKTOOLS::CopyResourceDIBToSurface
          (IDirectDrawSurface *param_1,char *param_2,HINSTANCE__ *param_3,uint param_4,uint param_5,
          bool param_6)

{
                    // 0xc26a  38
                    // ?CopyResourceDIBToSurface@GKTOOLS@@SAXPAUIDirectDrawSurface@@PBDPAUHINSTANCE__@@II_N@Z
  return;
}



// public: static void __cdecl GKTOOLS::CopyDIBToSurface(class DD_SURFACE &,class TwMapfile const
// &,unsigned int,unsigned int,bool)

void __cdecl
GKTOOLS::CopyDIBToSurface
          (DD_SURFACE *param_1,TwMapfile *param_2,uint param_3,uint param_4,bool param_5)

{
  bool bVar1;
  int iVar2;
  
                    // 0xc26f  36  ?CopyDIBToSurface@GKTOOLS@@SAXAAVDD_SURFACE@@ABVTwMapfile@@II_N@Z
  bVar1 = FUN_10008aa0((int *)param_2);
  if (bVar1) {
    iVar2 = FUN_10008a90((undefined4 *)param_2);
    if (*(short *)(iVar2 + 0x1c) == 8) {
      FUN_100082b0((int *)param_2,param_1,param_3,param_4);
    }
    else {
      FUN_1000eeb8((int *)param_2,param_1,param_3,param_4,param_5);
    }
  }
  return;
}



// public: static void __cdecl GKTOOLS::TileDIBToSurface(class DD_SURFACE &,char const *,bool)

void __cdecl GKTOOLS::TileDIBToSurface(DD_SURFACE *param_1,char *param_2,bool param_3)

{
  uint local_94;
  uint local_90;
  uint local_8c;
  undefined1 local_88 [8];
  uint local_80;
  uint local_7c;
  uint local_1c;
  TwMapfile local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0xc2e2  195  ?TileDIBToSurface@GKTOOLS@@SAXAAVDD_SURFACE@@PBD_N@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_10010be9;
  local_10 = ExceptionList;
  local_90 = 0;
  local_1c = 0;
  ExceptionList = &local_10;
  DD_SURFACE::Desc(param_1,(ulong)local_88);
  GetDIBSize(param_2,&local_90,&local_1c);
  if ((local_7c % local_90 == 0) && (local_80 % local_1c == 0)) {
    FUN_1000c780(local_18,param_2);
    local_8 = 0;
    for (local_8c = 0; local_8c < local_7c; local_8c = local_8c + local_90) {
      for (local_94 = 0; local_94 < local_80; local_94 = local_94 + local_1c) {
        CopyDIBToSurface(param_1,local_18,local_8c,local_94,param_3);
      }
    }
    local_8 = 0xffffffff;
    FUN_1000c860((int *)local_18);
  }
  ExceptionList = local_10;
  return;
}



// public: static void __cdecl GKTOOLS::CopyDIBToSurface(class DD_SURFACE &,char const *,unsigned
// int,unsigned int,bool)

void __cdecl
GKTOOLS::CopyDIBToSurface(DD_SURFACE *param_1,char *param_2,uint param_3,uint param_4,bool param_5)

{
  bool bVar1;
  char *local_1c;
  TwMapfile local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0xc40f  37  ?CopyDIBToSurface@GKTOOLS@@SAXAAVDD_SURFACE@@PBDII_N@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_10010bfc;
  local_10 = ExceptionList;
  if (param_2 != (char *)0x0) {
    ExceptionList = &local_10;
    FUN_1000c780(local_18,param_2);
    local_8 = 0;
    bVar1 = FUN_10008aa0((int *)local_18);
    if (bVar1) {
      bVar1 = FUN_10008aa0((int *)local_18);
      if (!bVar1) {
        local_1c = s_Required_file_missing_10018d58;
                    // WARNING: Subroutine does not return
        _CxxThrowException(&local_1c,(ThrowInfo *)&pThrowInfo_10012550);
      }
      CopyDIBToSurface(param_1,local_18,param_3,param_4,param_5);
      CString::operator=((CString *)(param_1 + 0xc),param_2);
      *(uint *)(param_1 + 0x10) = param_3;
      *(uint *)(param_1 + 0x14) = param_4;
      param_1[0x18] = (DD_SURFACE)param_5;
      local_8 = 0xffffffff;
      FUN_1000c860((int *)local_18);
    }
    else {
      local_8 = 0xffffffff;
      FUN_1000c860((int *)local_18);
    }
  }
  ExceptionList = local_10;
  return;
}



// public: static void __cdecl GKTOOLS::GetDIBSize(char const *,unsigned int *,unsigned int *)

void __cdecl GKTOOLS::GetDIBSize(char *param_1,uint *param_2,uint *param_3)

{
  HANDLE hFile;
  undefined1 local_40 [16];
  undefined1 local_30 [4];
  uint local_2c;
  uint local_28;
  DWORD local_8;
  
                    // 0xc502  76  ?GetDIBSize@GKTOOLS@@SAXPBDPAI1@Z
  hFile = CreateFileA(param_1,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  ReadFile(hFile,local_40,0xe,&local_8,(LPOVERLAPPED)0x0);
  ReadFile(hFile,local_30,0x28,&local_8,(LPOVERLAPPED)0x0);
  *param_2 = local_2c;
  *param_3 = local_28;
  return;
}



// public: static void __cdecl GKTOOLS::CopyDIBToBack(char const *,unsigned int,unsigned
// int,int,struct HINSTANCE__ *,bool)

void __cdecl
GKTOOLS::CopyDIBToBack
          (char *param_1,uint param_2,uint param_3,int param_4,HINSTANCE__ *param_5,bool param_6)

{
                    // 0xc56a  34  ?CopyDIBToBack@GKTOOLS@@SAXPBDIIHPAUHINSTANCE__@@_N@Z
  CopyDIBToSurface(&GKERNEL::ddsBack,param_1,param_2,param_3,param_6);
  return;
}



// public: static void __cdecl GKTOOLS::CopyDIBToFront(char const *,unsigned int,unsigned
// int,int,struct HINSTANCE__ *,bool)

void __cdecl
GKTOOLS::CopyDIBToFront
          (char *param_1,uint param_2,uint param_3,int param_4,HINSTANCE__ *param_5,bool param_6)

{
                    // 0xc58c  35  ?CopyDIBToFront@GKTOOLS@@SAXPBDIIHPAUHINSTANCE__@@_N@Z
  CopyDIBToSurface(&GKERNEL::ddsPrimary,param_1,param_2,param_3,param_6);
  return;
}



// public: static void __cdecl GKTOOLS::ClipRectToScreen(struct tagRECT *)

void __cdecl GKTOOLS::ClipRectToScreen(tagRECT *param_1)

{
  uint uVar1;
  
                    // 0xc5ae  28  ?ClipRectToScreen@GKTOOLS@@SAXPAUtagRECT@@@Z
  if (param_1->left < 0) {
    param_1->left = 0;
  }
  if (param_1->top < 0) {
    param_1->top = 0;
  }
  uVar1 = GKERNEL::ScrXRes();
  if ((int)uVar1 < param_1->right) {
    uVar1 = GKERNEL::ScrXRes();
    param_1->right = uVar1;
  }
  uVar1 = GKERNEL::ScrYRes();
  if ((int)uVar1 < param_1->bottom) {
    uVar1 = GKERNEL::ScrYRes();
    param_1->bottom = uVar1;
  }
  return;
}



// public: static class CString __cdecl GKTOOLS::GetDXVersionString(unsigned long)

ulong __cdecl GKTOOLS::GetDXVersionString(ulong param_1)

{
  uint in_stack_00000008;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
                    // 0xc607  78  ?GetDXVersionString@GKTOOLS@@SA?AVCString@@K@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_10010c26;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(local_14);
  local_8 = 1;
  if (in_stack_00000008 < 0x501) {
    if (in_stack_00000008 == 0x500) {
      CString::operator=(local_14,s_Detected_DirectX_version_5__10018ddc);
    }
    else if (in_stack_00000008 < 0x201) {
      if (in_stack_00000008 == 0x200) {
        CString::operator=(local_14,s_Detected_DirectX_version_2_10018da4);
      }
      else if (in_stack_00000008 == 0) {
        CString::operator=(local_14,s_DirectX_not_installed_10018d70);
      }
      else if (in_stack_00000008 == 0x100) {
        CString::operator=(local_14,s_Detected_DirectX_version_1_10018d88);
      }
    }
    else if (in_stack_00000008 == 0x300) {
      CString::operator=(local_14,s_Detected_DirectX_version_3_10018dc0);
    }
  }
  else if (in_stack_00000008 < 0x701) {
    if (in_stack_00000008 == 0x700) {
      CString::operator=(local_14,s_Detected_DirectX_version_7_10018e34);
    }
    else if (in_stack_00000008 == 0x600) {
      CString::operator=(local_14,s_Detected_DirectX_version_6_10018df8);
    }
    else if (in_stack_00000008 == 0x601) {
      CString::operator=(local_14,s_Detected_DirectX_version_6_1_10018e14);
    }
  }
  else if (in_stack_00000008 == 0x800) {
    CString::operator=(local_14,s_Detected_DirectX_version_8_10018e50);
  }
  CString::CString((CString *)param_1,local_14);
  local_8 = local_8 & 0xffffff00;
  CString::~CString(local_14);
  ExceptionList = local_10;
  return param_1;
}



void * __thiscall FUN_1000c780(void *this,LPCSTR param_1)

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



void __fastcall FUN_1000c860(int *param_1)

{
  if (*param_1 != 0) {
    UnmapViewOfFile((LPCVOID)*param_1);
  }
  return;
}



void __cdecl FUN_1000c880(DD_SURFACE *param_1)

{
  uint uVar1;
  undefined4 local_80 [21];
  uint local_2c;
  uint local_28;
  uint local_24;
  uint local_20;
  tagRECT local_14;
  
  DAT_1001b5b4 = 1;
  local_14.left = 0;
  local_14.top = 0;
  local_14.right = 1;
  local_14.bottom = 1;
  local_80[0] = 0x6c;
  DD_SURFACE::Lock(param_1,&local_14,(_DDSURFACEDESC *)local_80,0x11);
  uVar1 = GKTOOLS::ShiftPosition(local_28);
  DAT_1001b5ac = (undefined1)uVar1;
  uVar1 = GKTOOLS::ShiftPosition(local_24);
  DAT_1001b5ad = (undefined1)uVar1;
  uVar1 = GKTOOLS::ShiftPosition(local_20);
  DAT_1001b5ae = (undefined1)uVar1;
  uVar1 = GKTOOLS::CountBits(local_28);
  DAT_1001b5af = (undefined1)uVar1;
  uVar1 = GKTOOLS::CountBits(local_24);
  DAT_1001b5b0 = (undefined1)uVar1;
  uVar1 = GKTOOLS::CountBits(local_20);
  DAT_1001b5b1 = (undefined1)uVar1;
  DAT_1001b5b2 = (undefined1)(local_2c >> 3);
  DD_SURFACE::Unlock(param_1);
  return;
}



// public: static void __cdecl GKTOOLS::GetPixel(struct IDirectDrawSurface *,unsigned int,unsigned
// int,unsigned long *)

COLORREF GKTOOLS::GetPixel(HDC hdc,int x,int y)

{
  COLORREF CVar1;
  uint *in_stack_00000010;
  undefined4 local_80 [9];
  uint *local_5c;
  int local_2c;
  int local_14;
  int local_10;
  int local_c;
  int local_8;
  
                    // 0xc943  81  ?GetPixel@GKTOOLS@@SAXPAUIDirectDrawSurface@@IIPAK@Z
  local_14 = x;
  local_10 = y;
  local_c = x + 1;
  local_8 = y + 1;
  local_80[0] = 0x6c;
  (**(code **)(hdc->unused + 100))(hdc,&local_14,local_80,0x11,0);
  if (local_2c == 8) {
    *in_stack_00000010 = (uint)(byte)*local_5c;
    *in_stack_00000010 = *in_stack_00000010 & 0xff;
  }
  else if (local_2c == 0x10) {
    *in_stack_00000010 = (uint)(ushort)*local_5c;
    *in_stack_00000010 = *in_stack_00000010 & 0xffff;
  }
  else {
    *in_stack_00000010 = *local_5c;
  }
  CVar1 = (**(code **)(hdc->unused + 0x80))(hdc,0);
  return CVar1;
}



// public: static void __cdecl GKTOOLS::SetPixel(class DD_SURFACE *,struct TwPixel *,unsigned long)

COLORREF GKTOOLS::SetPixel(HDC hdc,int x,int y,COLORREF color)

{
  int iVar1;
  COLORREF CVar2;
  uint uVar3;
  uint *puVar4;
  uint local_8c;
  uint local_74;
  undefined4 local_70 [2];
  int local_68;
  int local_60;
  int local_4c;
  int local_1c;
  
                    // 0xca06  166  ?SetPixel@GKTOOLS@@SAXPAVDD_SURFACE@@PAUTwPixel@@K@Z
  if (DAT_1001b5b4 == 0) {
    FUN_1000c880((DD_SURFACE *)hdc);
  }
  local_70[0] = 0x6c;
  iVar1 = DD_SURFACE::Lock((DD_SURFACE *)hdc,(tagRECT *)0x0,(_DDSURFACEDESC *)local_70,1);
  if (iVar1 == 0) {
    CVar2 = 0;
  }
  else {
    for (local_74 = 0; local_74 < (uint)y; local_74 = local_74 + 1) {
      uVar3 = (uint)DAT_1001b5b2 * *(int *)(x + 4 + local_74 * 0xc) +
              *(int *)(x + 8 + local_74 * 0xc) * local_60;
      if (uVar3 < (uint)(local_68 * local_60)) {
        puVar4 = (uint *)(local_4c + uVar3);
        if (local_1c == 0x10) {
          *(char *)(x + local_74 * 0xc) =
               (char)((int)(uint)*(byte *)(x + local_74 * 0xc) >> (8U - DAT_1001b5af & 0x1f));
          *(char *)(x + 2 + local_74 * 0xc) =
               (char)((int)(uint)*(byte *)(x + 2 + local_74 * 0xc) >> (8U - DAT_1001b5b1 & 0x1f));
          *(char *)(x + 1 + local_74 * 0xc) =
               (char)((int)(uint)*(byte *)(x + 1 + local_74 * 0xc) >> (8U - DAT_1001b5b0 & 0x1f));
          *(ushort *)puVar4 =
               (ushort)*(byte *)(x + local_74 * 0xc) << (DAT_1001b5ac & 0x1f) |
               (ushort)*(byte *)(x + 2 + local_74 * 0xc) << (DAT_1001b5ae & 0x1f) |
               (ushort)*(byte *)(x + 1 + local_74 * 0xc) << (DAT_1001b5ad & 0x1f);
        }
        else if (local_1c == 0x18) {
          local_8c = (uint)(byte)*puVar4;
          *puVar4 = (uint)*(byte *)(x + local_74 * 0xc) << (DAT_1001b5ac & 0x1f) |
                    (uint)*(byte *)(x + 2 + local_74 * 0xc) << (DAT_1001b5ae & 0x1f) |
                    (uint)*(byte *)(x + 1 + local_74 * 0xc) << (DAT_1001b5ad & 0x1f) |
                    local_8c << 0x18;
        }
        else if (local_1c == 0x20) {
          *puVar4 = (uint)*(byte *)(x + local_74 * 0xc) << (DAT_1001b5ac & 0x1f) |
                    (uint)*(byte *)(x + 2 + local_74 * 0xc) << (DAT_1001b5ae & 0x1f) |
                    (uint)*(byte *)(x + 1 + local_74 * 0xc) << (DAT_1001b5ad & 0x1f);
        }
      }
    }
    CVar2 = DD_SURFACE::Unlock((DD_SURFACE *)hdc);
  }
  return CVar2;
}



// public: static void __cdecl GKTOOLS::SetPixelRGB(struct IDirectDrawSurface *,unsigned
// int,unsigned int,unsigned long)

void __cdecl
GKTOOLS::SetPixelRGB(IDirectDrawSurface *param_1,uint param_2,uint param_3,ulong param_4)

{
                    // 0xcca6  167  ?SetPixelRGB@GKTOOLS@@SAXPAUIDirectDrawSurface@@IIK@Z
  return;
}



// public: static void __cdecl GKERNEL::FlipSprites(void)

void __cdecl GKERNEL::FlipSprites(void)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  undefined4 *puVar3;
  uint uVar4;
  undefined3 extraout_var_00;
  int *local_10;
  uint local_c;
  int local_8;
  
                    // 0xccb0  68  ?FlipSprites@GKERNEL@@SAXXZ
  if (DAT_1001b38c != '\0') {
    local_8 = FUN_1000e790(0x1001b370);
    local_10 = (int *)0x0;
    bVar1 = IsEmpty(0x1001b370);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      puVar3 = (undefined4 *)FUN_1000d1b0(&local_8);
      local_10 = (int *)*puVar3;
    }
    local_c = 0;
    while ((uVar4 = FUN_1000ff30(0x1001b370), local_c < uVar4 &&
           (bVar1 = IsEmpty(0x1001b370), CONCAT31(extraout_var_00,bVar1) == 0))) {
      cVar2 = (**(code **)(*local_10 + 0x24))();
      if (cVar2 != '\0') {
        (**(code **)(*local_10 + 0xc))();
      }
      local_c = local_c + 1;
      uVar4 = FUN_1000ff30(0x1001b370);
      if (local_c < uVar4) {
        puVar3 = (undefined4 *)FUN_1000d1b0(&local_8);
        local_10 = (int *)*puVar3;
      }
    }
  }
  return;
}



// public: static void __cdecl GKERNEL::SaveSprites(void)

void __cdecl GKERNEL::SaveSprites(void)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  undefined4 *puVar3;
  uint uVar4;
  undefined3 extraout_var_00;
  int *local_10;
  uint local_c;
  int local_8;
  
                    // 0xcd85  135  ?SaveSprites@GKERNEL@@SAXXZ
  DD_SURFACE::WaitForBlitToComplete(&ddsPrimary);
  local_8 = FUN_1000e790(0x1001b370);
  local_10 = (int *)0x0;
  bVar1 = IsEmpty(0x1001b370);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar3 = (undefined4 *)FUN_1000d1b0(&local_8);
    local_10 = (int *)*puVar3;
  }
  local_c = 0;
  while ((uVar4 = FUN_1000ff30(0x1001b370), local_c < uVar4 &&
         (bVar1 = IsEmpty(0x1001b370), CONCAT31(extraout_var_00,bVar1) == 0))) {
    cVar2 = (**(code **)(*local_10 + 0x24))();
    if ((cVar2 != '\0') &&
       ((cVar2 = (**(code **)(*local_10 + 0x18))(), cVar2 != '\0' || (local_10[1] != 0)))) {
      (**(code **)(*local_10 + 4))();
    }
    local_c = local_c + 1;
    uVar4 = FUN_1000ff30(0x1001b370);
    if (local_c < uVar4) {
      puVar3 = (undefined4 *)FUN_1000d1b0(&local_8);
      local_10 = (int *)*puVar3;
    }
  }
  DD_SURFACE::WaitForBlitToComplete(&ddsPrimary);
  return;
}



// public: static void __cdecl GKERNEL::DrawSprites(void)

void __cdecl GKERNEL::DrawSprites(void)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  undefined4 *puVar3;
  uint uVar4;
  undefined3 extraout_var_00;
  int *local_10;
  uint local_c;
  int local_8;
  
                    // 0xce7f  48  ?DrawSprites@GKERNEL@@SAXXZ
  DD_SURFACE::WaitForBlitToComplete(&ddsPrimary);
  local_8 = FUN_1000e790(0x1001b370);
  local_10 = (int *)0x0;
  bVar1 = IsEmpty(0x1001b370);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar3 = (undefined4 *)FUN_1000d1b0(&local_8);
    local_10 = (int *)*puVar3;
  }
  local_c = 0;
  while ((uVar4 = FUN_1000ff30(0x1001b370), local_c < uVar4 &&
         (bVar1 = IsEmpty(0x1001b370), CONCAT31(extraout_var_00,bVar1) == 0))) {
    cVar2 = (**(code **)(*local_10 + 0x24))();
    if ((cVar2 != '\0') && (cVar2 = (**(code **)(*local_10 + 0x18))(), cVar2 != '\0')) {
      (**(code **)(*local_10 + 0x14))();
    }
    local_c = local_c + 1;
    uVar4 = FUN_1000ff30(0x1001b370);
    if (local_c < uVar4) {
      puVar3 = (undefined4 *)FUN_1000d1b0(&local_8);
      local_10 = (int *)*puVar3;
    }
  }
  DD_SURFACE::WaitForBlitToComplete(&ddsPrimary);
  return;
}



// public: static void __cdecl GKERNEL::RestoreSprites(void)

void __cdecl GKERNEL::RestoreSprites(void)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  undefined4 *puVar3;
  uint uVar4;
  undefined3 extraout_var_00;
  int *local_10;
  uint local_c;
  int local_8;
  
                    // 0xcf70  130  ?RestoreSprites@GKERNEL@@SAXXZ
  DD_SURFACE::WaitForBlitToComplete(&ddsPrimary);
  local_8 = FUN_1000e7b0(0x1001b370);
  local_10 = (int *)0x0;
  bVar1 = IsEmpty(0x1001b370);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar3 = (undefined4 *)FUN_1000e7d0(&local_8);
    local_10 = (int *)*puVar3;
  }
  local_c = 0;
  while ((uVar4 = FUN_1000ff30(0x1001b370), local_c < uVar4 &&
         (bVar1 = IsEmpty(0x1001b370), CONCAT31(extraout_var_00,bVar1) == 0))) {
    cVar2 = (**(code **)(*local_10 + 0x24))();
    if (cVar2 != '\0') {
      cVar2 = (**(code **)(*local_10 + 0x18))();
      if ((cVar2 != '\0') || (local_10[1] != 0)) {
        (**(code **)(*local_10 + 8))();
      }
      if (local_10[1] != 0) {
        local_10[1] = local_10[1] + -1;
      }
    }
    local_c = local_c + 1;
    uVar4 = FUN_1000ff30(0x1001b370);
    if (local_c < uVar4) {
      puVar3 = (undefined4 *)FUN_1000e7d0(&local_8);
      local_10 = (int *)*puVar3;
    }
  }
  DD_SURFACE::WaitForBlitToComplete(&ddsPrimary);
  return;
}



// public: static void __cdecl GKERNEL::SpriteFlip(void)

void __cdecl GKERNEL::SpriteFlip(void)

{
                    // 0xd082  186  ?SpriteFlip@GKERNEL@@SAXXZ
  SaveSprites();
  DrawSprites();
  Flip();
  FlipSprites();
  RestoreSprites();
  return;
}



// public: static void __cdecl GKERNEL::RegisterSprite(class GKGOBJ *)

void __cdecl GKERNEL::RegisterSprite(GKGOBJ *param_1)

{
                    // 0xd0a0  123  ?RegisterSprite@GKERNEL@@SAXPAVGKGOBJ@@@Z
  FUN_1000bef0(&DAT_1001b370,&param_1);
  return;
}



// public: static void __cdecl GKERNEL::UnRegisterSprite(class GKGOBJ *)

void __cdecl GKERNEL::UnRegisterSprite(GKGOBJ *param_1)

{
  int *piVar1;
  
                    // 0xd0b3  196  ?UnRegisterSprite@GKERNEL@@SAXPAVGKGOBJ@@@Z
  piVar1 = FUN_1000d250(&DAT_1001b370,(int *)&param_1,(undefined4 *)0x0);
  if (piVar1 != (int *)0x0) {
    FUN_1000d1e0(&DAT_1001b370,piVar1);
  }
  return;
}



// public: static void __cdecl GKERNEL::NewSpriteBackground(void)

void __cdecl GKERNEL::NewSpriteBackground(void)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  undefined4 *puVar3;
  uint uVar4;
  undefined3 extraout_var_00;
  int local_10;
  int *local_c;
  uint local_8;
  
                    // 0xd0e2  113  ?NewSpriteBackground@GKERNEL@@SAXXZ
  local_10 = FUN_1000e790(0x1001b370);
  local_c = (int *)0x0;
  local_8 = 0;
  bVar1 = IsEmpty(0x1001b370);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar3 = (undefined4 *)FUN_1000d1b0(&local_10);
    local_c = (int *)*puVar3;
  }
  local_8 = 0;
  while ((uVar4 = FUN_1000ff30(0x1001b370), local_8 < uVar4 &&
         (bVar1 = IsEmpty(0x1001b370), CONCAT31(extraout_var_00,bVar1) == 0))) {
    cVar2 = (**(code **)(*local_c + 0x24))();
    if (cVar2 != '\0') {
      (**(code **)(*local_c + 0x10))();
    }
    local_8 = local_8 + 1;
    uVar4 = FUN_1000ff30(0x1001b370);
    if (local_8 < uVar4) {
      puVar3 = (undefined4 *)FUN_1000d1b0(&local_10);
      local_c = (int *)*puVar3;
    }
  }
  return;
}



int FUN_1000d1b0(int *param_1)

{
  int *piVar1;
  
  piVar1 = (int *)*param_1;
  *param_1 = *piVar1;
  return (int)(piVar1 + 2);
}



void __thiscall FUN_1000d1e0(void *this,int *param_1)

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
  FUN_1000d2b0(this,param_1);
  return;
}



undefined4 * __thiscall FUN_1000d250(void *this,int *param_1,undefined4 *param_2)

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
    bVar1 = FUN_1000d300(local_8 + 2,param_1);
    if (CONCAT31(extraout_var,bVar1) != 0) break;
    local_8 = (undefined4 *)*local_8;
  }
  return local_8;
}



void __thiscall FUN_1000d2b0(void *this,undefined4 *param_1)

{
  FUN_10001b80(param_1 + 2,1);
  *param_1 = *(undefined4 *)((int)this + 0x10);
  *(undefined4 **)((int)this + 0x10) = param_1;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + -1;
  if (*(int *)((int)this + 0xc) == 0) {
    FUN_1000bf50((int)this);
  }
  return;
}



bool FUN_1000d300(int *param_1,int *param_2)

{
  return *param_1 == *param_2;
}



// public: bool __thiscall DD_SURFACE::IsLost(void)const 

bool __thiscall DD_SURFACE::IsLost(DD_SURFACE *this)

{
  int iVar1;
  bool bVar2;
  
                    // 0xd320  108  ?IsLost@DD_SURFACE@@QBE_NXZ
  if (*(int *)(this + 0x24) == 0) {
    bVar2 = true;
  }
  else {
    iVar1 = (**(code **)(**(int **)(this + 0x24) + 0x60))(*(undefined4 *)(this + 0x24));
    bVar2 = iVar1 == -0x7789fe3e;
  }
  return bVar2;
}



// public: int __thiscall DD_SURFACE::RotateBlt90(class DD_SURFACE const &,struct tagRECT const
// *,struct tagRECT const *,unsigned int)

int __thiscall
DD_SURFACE::RotateBlt90
          (DD_SURFACE *this,DD_SURFACE *param_1,tagRECT *param_2,tagRECT *param_3,uint param_4)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 local_68;
  undefined4 local_64 [24];
  
                    // 0xd35b  134  ?RotateBlt90@DD_SURFACE@@QAEHABV1@PBUtagRECT@@1I@Z
  if (param_4 < 3) {
    bVar1 = IsLost(this);
    if (bVar1) {
      uVar2 = 1;
    }
    else {
      bVar1 = IsLost(param_1);
      if (bVar1) {
        uVar2 = 1;
      }
      else {
        puVar4 = local_64;
        for (iVar3 = 0x18; iVar3 != 0; iVar3 = iVar3 + -1) {
          *puVar4 = 0;
          puVar4 = puVar4 + 1;
        }
        local_68 = 100;
        if (param_4 == 0) {
          local_64[0] = 0x40;
        }
        else if (param_4 == 1) {
          local_64[0] = 0x10;
        }
        else if (param_4 == 2) {
          local_64[0] = 0x20;
        }
        iVar3 = (**(code **)(**(int **)(this + 0x24) + 0x14))
                          (*(undefined4 *)(this + 0x24),param_2,*(undefined4 *)(param_1 + 0x24),
                           param_3,0x800,&local_68);
        uVar2 = (uint)(-1 < iVar3);
      }
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



// public: int __thiscall DD_SURFACE::Blt(class DD_SURFACE const &,struct tagRECT const *,struct
// tagRECT const *)

int __thiscall
DD_SURFACE::Blt(DD_SURFACE *this,DD_SURFACE *param_1,tagRECT *param_2,tagRECT *param_3)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  
                    // 0xd438  23  ?Blt@DD_SURFACE@@QAEHABV1@PBUtagRECT@@1@Z
  bVar1 = IsLost(this);
  if (bVar1) {
    uVar2 = 1;
  }
  else {
    bVar1 = IsLost(param_1);
    if (bVar1) {
      uVar2 = 1;
    }
    else {
      iVar3 = (**(code **)(**(int **)(this + 0x24) + 0x14))
                        (*(undefined4 *)(this + 0x24),param_2,*(undefined4 *)(param_1 + 0x24),
                         param_3,*(undefined4 *)(param_1 + 4),0);
      uVar2 = (uint)(-1 < iVar3);
    }
  }
  return uVar2;
}



// public: int __thiscall DD_SURFACE::BltFast(class DD_SURFACE const &,unsigned int,unsigned
// int,struct tagRECT const *)

int __thiscall
DD_SURFACE::BltFast(DD_SURFACE *this,DD_SURFACE *param_1,uint param_2,uint param_3,tagRECT *param_4)

{
  bool bVar1;
  uint uVar2;
  tagRECT local_18;
  int local_8;
  
                    // 0xd4ad  24  ?BltFast@DD_SURFACE@@QAEHABV1@IIPBUtagRECT@@@Z
  bVar1 = IsLost(this);
  if (bVar1) {
    uVar2 = 1;
  }
  else {
    bVar1 = IsLost(param_1);
    if (bVar1) {
      uVar2 = 1;
    }
    else {
      local_8 = (**(code **)(**(int **)(this + 0x24) + 0x1c))
                          (*(undefined4 *)(this + 0x24),param_2,param_3,
                           *(undefined4 *)(param_1 + 0x24),param_4,*(undefined4 *)(param_1 + 8));
      if (local_8 == -0x7fffbfff) {
        local_18.top = param_3;
        local_18.left = param_2;
        local_18.right = param_2 + (param_4->right - param_4->left);
        local_18.bottom = param_3 + (param_4->bottom - param_4->top);
        uVar2 = Blt(this,param_1,&local_18,param_4);
      }
      else {
        uVar2 = (uint)(-1 < local_8);
      }
    }
  }
  return uVar2;
}



// public: void __thiscall DD_SURFACE::WaitForBlitToComplete(void)

void __thiscall DD_SURFACE::WaitForBlitToComplete(DD_SURFACE *this)

{
  bool bVar1;
  int iVar2;
  
                    // 0xd57c  199  ?WaitForBlitToComplete@DD_SURFACE@@QAEXXZ
  iVar2 = 0;
  do {
    iVar2 = (**(code **)(**(int **)(this + 0x24) + 0x34))(*(undefined4 *)(this + 0x24),2,this,iVar2)
    ;
    if (-1 < iVar2) {
      return;
    }
    bVar1 = IsLost(this);
  } while (!bVar1);
  return;
}



// public: int __thiscall DD_SURFACE::Flip(void)

int __thiscall DD_SURFACE::Flip(DD_SURFACE *this)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  
                    // 0xd5be  65  ?Flip@DD_SURFACE@@QAEHXZ
  bVar1 = IsLost(this);
  if (bVar1) {
    Sleep(0x1e);
    uVar2 = 1;
  }
  else {
    iVar3 = (**(code **)(**(int **)(this + 0x24) + 0x2c))(*(undefined4 *)(this + 0x24),0,1);
    uVar2 = (uint)(-1 < iVar3);
  }
  return uVar2;
}



// public: void __thiscall DD_SURFACE::WaitForFlipToComplete(void)

void __thiscall DD_SURFACE::WaitForFlipToComplete(DD_SURFACE *this)

{
  bool bVar1;
  int iVar2;
  
                    // 0xd60d  200  ?WaitForFlipToComplete@DD_SURFACE@@QAEXXZ
  iVar2 = 0;
  do {
    iVar2 = (**(code **)(**(int **)(this + 0x24) + 0x48))(*(undefined4 *)(this + 0x24),2,this,iVar2)
    ;
    if (-1 < iVar2) {
      return;
    }
    bVar1 = IsLost(this);
  } while (!bVar1);
  return;
}



// public: int __thiscall DD_SURFACE::GetDC(struct HDC__ * &)

HDC DD_SURFACE::GetDC(HWND hWnd)

{
  bool bVar1;
  HDC pHVar2;
  int iVar3;
  DD_SURFACE *in_ECX;
  
                    // 0xd64f  74  ?GetDC@DD_SURFACE@@QAEHAAPAUHDC__@@@Z
  bVar1 = IsLost(in_ECX);
  if (bVar1) {
    pHVar2 = (HDC)0x0;
  }
  else {
    iVar3 = (**(code **)(**(int **)(in_ECX + 0x24) + 0x44))(*(undefined4 *)(in_ECX + 0x24),hWnd);
    pHVar2 = (HDC)(uint)(-1 < iVar3);
  }
  return pHVar2;
}



// public: int __thiscall DD_SURFACE::ReleaseDC(struct HDC__ *)

int DD_SURFACE::ReleaseDC(HWND hWnd,HDC hDC)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  DD_SURFACE *in_ECX;
  
                    // 0xd695  126  ?ReleaseDC@DD_SURFACE@@QAEHPAUHDC__@@@Z
  bVar1 = IsLost(in_ECX);
  if (bVar1) {
    uVar2 = 0;
  }
  else {
    iVar3 = (**(code **)(**(int **)(in_ECX + 0x24) + 0x68))(*(undefined4 *)(in_ECX + 0x24),hWnd);
    uVar2 = (uint)(-1 < iVar3);
  }
  return uVar2;
}



// public: struct _DDSURFACEDESC __thiscall DD_SURFACE::Desc(unsigned long)

ulong __thiscall DD_SURFACE::Desc(DD_SURFACE *this,ulong param_1)

{
  bool bVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined4 local_e0 [27];
  undefined4 local_74;
  undefined4 local_70 [27];
  
                    // 0xd6db  45  ?Desc@DD_SURFACE@@QAE?AU_DDSURFACEDESC@@K@Z
  bVar1 = IsLost(this);
  if (bVar1) {
    puVar3 = local_e0;
    puVar4 = (undefined4 *)param_1;
    for (iVar2 = 0x1b; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar4 = *puVar3;
      puVar3 = puVar3 + 1;
      puVar4 = puVar4 + 1;
    }
  }
  else {
    puVar3 = local_70;
    for (iVar2 = 0x1a; puVar3 = puVar3 + 1, iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar3 = 0;
    }
    local_74 = 0x80004005;
    local_70[0] = 0x6c;
    local_74 = (**(code **)(**(int **)(this + 0x24) + 0x58))(*(undefined4 *)(this + 0x24),local_70);
    puVar3 = local_70;
    puVar4 = (undefined4 *)param_1;
    for (iVar2 = 0x1b; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar4 = *puVar3;
      puVar3 = puVar3 + 1;
      puVar4 = puVar4 + 1;
    }
  }
  return param_1;
}



// public: int __thiscall DD_SURFACE::Lock(struct tagRECT const *,struct _DDSURFACEDESC *,unsigned
// long)

int __thiscall
DD_SURFACE::Lock(DD_SURFACE *this,tagRECT *param_1,_DDSURFACEDESC *param_2,ulong param_3)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  
                    // 0xd779  111  ?Lock@DD_SURFACE@@QAEHPBUtagRECT@@PAU_DDSURFACEDESC@@K@Z
  bVar1 = IsLost(this);
  if (bVar1) {
    uVar2 = 0;
  }
  else {
    iVar3 = (**(code **)(**(int **)(this + 0x24) + 100))
                      (*(undefined4 *)(this + 0x24),param_1,param_2,param_3,0);
    uVar2 = (uint)(-1 < iVar3);
  }
  return uVar2;
}



// public: int __thiscall DD_SURFACE::Unlock(void)

int __thiscall DD_SURFACE::Unlock(DD_SURFACE *this)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  
                    // 0xd7c9  197  ?Unlock@DD_SURFACE@@QAEHXZ
  bVar1 = IsLost(this);
  if (bVar1) {
    uVar2 = 0;
  }
  else {
    iVar3 = (**(code **)(**(int **)(this + 0x24) + 0x80))(*(undefined4 *)(this + 0x24),0);
    if (iVar3 == -0x7789fdb8) {
      uVar2 = 1;
    }
    else {
      uVar2 = (uint)(-1 < iVar3);
    }
  }
  return uVar2;
}



// public: int __thiscall DD_SURFACE::Lock(struct _DDSURFACEDESC &)

int __thiscall DD_SURFACE::Lock(DD_SURFACE *this,_DDSURFACEDESC *param_1)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  
                    // 0xd81e  110  ?Lock@DD_SURFACE@@QAEHAAU_DDSURFACEDESC@@@Z
  bVar1 = IsLost(this);
  if (bVar1) {
    uVar2 = 0;
  }
  else {
    memset(param_1,0,0x6c);
    *(undefined4 *)param_1 = 0x6c;
    iVar3 = (**(code **)(**(int **)(this + 0x24) + 100))(*(undefined4 *)(this + 0x24),0,param_1,1,0)
    ;
    uVar2 = (uint)(-1 < iVar3);
  }
  return uVar2;
}



// public: int __thiscall DD_SURFACE::SetPalette(struct IDirectDrawPalette *)

int __thiscall DD_SURFACE::SetPalette(DD_SURFACE *this,IDirectDrawPalette *param_1)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  
                    // 0xd883  160  ?SetPalette@DD_SURFACE@@QAEHPAUIDirectDrawPalette@@@Z
  bVar1 = IsLost(this);
  if (bVar1) {
    uVar2 = 0;
  }
  else {
    iVar3 = (**(code **)(**(int **)(this + 0x24) + 0x7c))(*(undefined4 *)(this + 0x24),param_1);
    uVar2 = (uint)(-1 < iVar3);
  }
  return uVar2;
}



// public: int __thiscall DD_SURFACE::SetColorKeyFromPixel00(void)

int __thiscall DD_SURFACE::SetColorKeyFromPixel00(DD_SURFACE *this)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  uint local_98;
  uint local_94;
  undefined1 *local_90;
  undefined4 local_88;
  undefined4 *local_84;
  _DDSURFACEDESC local_80 [36];
  undefined1 *local_5c;
  uint local_2c;
  uint local_28;
  uint local_24;
  uint local_20;
  tagRECT local_14;
  
                    // 0xd8c9  147  ?SetColorKeyFromPixel00@DD_SURFACE@@QAEHXZ
  *(uint *)(this + 4) = *(uint *)(this + 4) | 0x8000;
  *(undefined4 *)(this + 8) = *(undefined4 *)(this + 8);
  *(uint *)(this + 8) = *(uint *)(this + 8) | 1;
  this[0x19] = (DD_SURFACE)0x1;
  bVar1 = IsLost(this);
  if (bVar1) {
    uVar2 = 0;
  }
  else {
    local_14.left = 0;
    local_14.top = 0;
    local_14.right = 2;
    local_14.bottom = 2;
    local_90 = (undefined1 *)0x0;
    Desc(this,(ulong)local_80);
    Lock(this,&local_14,local_80,0x11);
    local_84 = &local_88;
    local_90 = local_5c;
                    // WARNING: Ignoring partial resolution of indirect
    local_88._0_1_ = *local_5c;
    if (((local_2c != 0x10) && (local_2c != 0x18)) && (local_2c == 0x20)) {
                    // WARNING: Ignoring partial resolution of indirect
      local_88._3_1_ = local_5c[3];
    }
    local_88 = local_88 & (local_28 | local_24 | local_20);
    Unlock(this);
    if (local_2c < 9) {
      local_94 = 0xff;
    }
    else {
      local_94 = local_88;
    }
    local_98 = local_94;
    iVar3 = (**(code **)(**(int **)(this + 0x24) + 0x74))(*(undefined4 *)(this + 0x24),8,&local_98);
    uVar2 = (uint)(-1 < iVar3);
  }
  return uVar2;
}



// public: int __thiscall DD_SURFACE::SetColorKey(unsigned long)

int __thiscall DD_SURFACE::SetColorKey(DD_SURFACE *this,ulong param_1)

{
  bool bVar1;
  int iVar2;
  HDC pHVar3;
  HWND__ local_8;
  
                    // 0xda96  146  ?SetColorKey@DD_SURFACE@@QAEHK@Z
  *(ulong *)(this + 0x1c) = param_1;
  bVar1 = IsLost(this);
  if (bVar1) {
    iVar2 = 0;
  }
  else {
    local_8.unused = 0;
    pHVar3 = GetDC(&local_8);
    if (pHVar3 == (HDC)0x0) {
      iVar2 = 0;
    }
    else {
      SetPixelV((HDC)local_8.unused,0,0,param_1);
      ReleaseDC((HWND)local_8.unused,(HDC)this);
      iVar2 = SetColorKeyFromPixel00(this);
    }
  }
  return iVar2;
}



// public: int __thiscall DD_SURFACE::RemoveColorKey(void)

int __thiscall DD_SURFACE::RemoveColorKey(DD_SURFACE *this)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  
                    // 0xdb04  127  ?RemoveColorKey@DD_SURFACE@@QAEHXZ
  bVar1 = IsLost(this);
  if (bVar1) {
    uVar2 = 0;
  }
  else {
    *(uint *)(this + 4) = *(uint *)(this + 4) & 0xffff7fff;
    *(uint *)(this + 8) = *(uint *)(this + 8) & 0xfffffffe;
    *(undefined4 *)(this + 8) = *(undefined4 *)(this + 8);
    if (this[0x19] == (DD_SURFACE)0x0) {
      uVar2 = 1;
    }
    else {
      iVar3 = (**(code **)(**(int **)(this + 0x24) + 0x74))(*(undefined4 *)(this + 0x24),8,0);
      this[0x19] = (DD_SURFACE)0x0;
      uVar2 = (uint)(-1 < iVar3);
    }
  }
  return uVar2;
}



// public: __thiscall DD_SURFACE::DD_SURFACE(void)

DD_SURFACE * __thiscall DD_SURFACE::DD_SURFACE(DD_SURFACE *this)

{
  void *local_24;
  DD_SURFACE *local_1c;
  CTypeLibCacheMap *local_18;
  void *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0xdb90  1  ??0DD_SURFACE@@QAE@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_10010c46;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined4 *)(this + 4) = 0x1000000;
  *(undefined4 *)(this + 8) = 0x10;
  CString::CString((CString *)(this + 0xc));
  local_8 = 0;
  *(undefined4 *)(this + 0x10) = 0xffffffff;
  *(undefined4 *)(this + 0x14) = 0xffffffff;
  this[0x18] = (DD_SURFACE)0x0;
  this[0x19] = (DD_SURFACE)0x0;
  *(undefined4 *)(this + 0x1c) = 0xffffffff;
  *(undefined4 *)(this + 0x24) = 0;
  *(undefined4 *)(this + 0x94) = 0;
  *(undefined ***)this = &PTR_FUN_10011d00;
  FUN_1000e580((int)this);
  if (DAT_1001b5b8 == (void *)0x0) {
    local_18 = (CTypeLibCacheMap *)FUN_1000ec10(0x1c);
    local_8._0_1_ = 1;
    if (local_18 == (CTypeLibCacheMap *)0x0) {
      local_24 = (void *)0x0;
    }
    else {
      local_24 = (void *)CTypeLibCacheMap::CTypeLibCacheMap(local_18);
    }
    local_14 = local_24;
    local_8 = (uint)local_8._1_3_ << 8;
    DAT_1001b5b8 = local_24;
  }
  local_1c = this;
  FUN_1000e630(DAT_1001b5b8,&local_1c);
  ExceptionList = local_10;
  return this;
}



// public: class DD_SURFACE & __thiscall DD_SURFACE::Create(struct _DDSURFACEDESC const &,struct
// HWND__ *)

DD_SURFACE * __thiscall DD_SURFACE::Create(DD_SURFACE *this,_DDSURFACEDESC *param_1,HWND__ *param_2)

{
  int iVar1;
  _DDSURFACEDESC *p_Var2;
  DD_SURFACE *pDVar3;
  undefined4 *puVar4;
  char *local_e8;
  undefined1 local_e4 [108];
  int local_78;
  undefined4 local_74;
  undefined4 local_70 [27];
  
                    // 0xdc99  40  ?Create@DD_SURFACE@@QAEAAV1@ABU_DDSURFACEDESC@@PAUHWND__@@@Z
  if (*(int *)(this + 0x24) != 0) {
    Release(this);
  }
  *(HWND__ **)(this + 0x20) = param_2;
  p_Var2 = param_1;
  pDVar3 = this + 0x28;
  for (iVar1 = 0x1b; iVar1 != 0; iVar1 = iVar1 + -1) {
    *(undefined4 *)pDVar3 = *(undefined4 *)p_Var2;
    p_Var2 = p_Var2 + 4;
    pDVar3 = pDVar3 + 4;
  }
  pDVar3 = this + 0x28;
  puVar4 = local_70;
  for (iVar1 = 0x1b; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar4 = *(undefined4 *)pDVar3;
    pDVar3 = pDVar3 + 4;
    puVar4 = puVar4 + 1;
  }
  local_74 = (**(code **)(*DAT_1001b598 + 0x18))(DAT_1001b598,local_70,this + 0x24,0);
  if ((*(uint *)(param_1 + 0x68) & 0x200) == 0x200) {
    DAT_1001b5bc = this;
  }
  if (*(int *)(this + 0x20) != 0) {
    AttatchClipper(this,*(HWND__ **)(this + 0x20));
  }
  iVar1 = Desc(this,(ulong)local_e4);
  local_78 = *(int *)(iVar1 + 0x54);
  if (((local_78 != 0x10) && (local_78 != 0x20)) && (local_78 != 0x18)) {
    local_e8 = s_Unexpected_video_mode_switch__10018e6c;
                    // WARNING: Subroutine does not return
    _CxxThrowException(&local_e8,(ThrowInfo *)&pThrowInfo_10012550);
  }
  return this;
}



// public: int __thiscall DD_SURFACE::AttatchClipper(struct HWND__ *)

int __thiscall DD_SURFACE::AttatchClipper(DD_SURFACE *this,HWND__ *param_1)

{
  uint uVar1;
  int *local_c;
  int local_8;
  
                    // 0xddaf  20  ?AttatchClipper@DD_SURFACE@@QAEHPAUHWND__@@@Z
  local_8 = 0;
  local_c = (int *)0x0;
  local_8 = (**(code **)(**(int **)(this + 0x24) + 0x3c))(*(undefined4 *)(this + 0x24),&local_c);
  if (-1 < local_8) {
    (**(code **)(*local_c + 8))(local_c);
  }
  if (param_1 == (HWND__ *)0x0) {
    if (local_8 < 0) {
      uVar1 = 0;
    }
    else {
      *(int *)(this + 0x94) = *(int *)(this + 0x94) + -1;
      if (*(int *)(this + 0x94) == 0) {
        GKERNEL::DebugTrace(s_Releasing_clipper_10018e8c);
        (**(code **)(*local_c + 8))(local_c);
        local_8 = (**(code **)(**(int **)(this + 0x24) + 0x70))(*(undefined4 *)(this + 0x24),0);
      }
      uVar1 = (uint)(-1 < local_8);
    }
  }
  else {
    if (local_8 == -0x7789fdc8) {
      local_8 = (**(code **)(*DAT_1001b598 + 0x10))(DAT_1001b598,0,&local_c,0);
      local_8 = (**(code **)(*local_c + 0x20))(local_c,0,param_1);
      local_8 = (**(code **)(**(int **)(this + 0x24) + 0x70))(*(undefined4 *)(this + 0x24),local_c);
    }
    *(int *)(this + 0x94) = *(int *)(this + 0x94) + 1;
    uVar1 = (uint)(-1 < local_8);
  }
  return uVar1;
}



// public: class DD_SURFACE & __thiscall DD_SURFACE::BackBuffer(class DD_SURFACE const &)

DD_SURFACE * __thiscall DD_SURFACE::BackBuffer(DD_SURFACE *this,DD_SURFACE *param_1)

{
  undefined4 local_10;
  undefined4 local_c [2];
  
                    // 0xdee0  22  ?BackBuffer@DD_SURFACE@@QAEAAV1@ABV1@@Z
  local_10 = 0;
  local_c[0] = 4;
  (**(code **)(**(int **)(param_1 + 0x24) + 0x30))
            (*(undefined4 *)(param_1 + 0x24),local_c,&local_10);
  *(undefined4 *)(this + 0x24) = local_10;
  return this;
}



// public: class DD_SURFACE & __thiscall DD_SURFACE::operator=(class DD_SURFACE const &)

DD_SURFACE * __thiscall DD_SURFACE::operator=(DD_SURFACE *this,DD_SURFACE *param_1)

{
  int iVar1;
  DD_SURFACE *pDVar2;
  DD_SURFACE *pDVar3;
  
                    // 0xdf26  18  ??4DD_SURFACE@@QAEAAV0@ABV0@@Z
  if (*(int *)(this + 0x24) != 0) {
    Release(this);
  }
  *(undefined4 *)(this + 0x24) = *(undefined4 *)(param_1 + 0x24);
  CString::operator=((CString *)(this + 0xc),(CString *)(param_1 + 0xc));
  *(undefined4 *)(this + 0x10) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(this + 0x14) = *(undefined4 *)(param_1 + 0x14);
  this[0x18] = param_1[0x18];
  this[0x19] = param_1[0x19];
  *(undefined4 *)(this + 0x1c) = *(undefined4 *)(param_1 + 0x1c);
  *(undefined4 *)(this + 0x20) = *(undefined4 *)(param_1 + 0x20);
  pDVar2 = param_1 + 0x28;
  pDVar3 = this + 0x28;
  for (iVar1 = 0x1b; iVar1 != 0; iVar1 = iVar1 + -1) {
    *(undefined4 *)pDVar3 = *(undefined4 *)pDVar2;
    pDVar2 = pDVar2 + 4;
    pDVar3 = pDVar3 + 4;
  }
  *(undefined4 *)(this + 4) = *(undefined4 *)(param_1 + 4);
  *(undefined4 *)(this + 8) = *(undefined4 *)(param_1 + 8);
  if (*(int *)(this + 0x24) != 0) {
    (**(code **)(**(int **)(this + 0x24) + 4))(*(undefined4 *)(this + 0x24));
  }
  return this;
}



// public: __thiscall DD_SURFACE::~DD_SURFACE(void)

void __thiscall DD_SURFACE::~DD_SURFACE(DD_SURFACE *this)

{
  bool bVar1;
  undefined3 extraout_var;
  DD_SURFACE *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0xdff7  13  ??1DD_SURFACE@@QAE@XZ
  puStack_c = &LAB_10010c5c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)this = &PTR_FUN_10011d00;
  local_8 = 0;
  if (*(int *)(this + 0x24) != 0) {
    Release(this);
  }
  local_14 = this;
  FUN_1000e650(DAT_1001b5b8,(int *)&local_14);
  bVar1 = IsEmpty((int)DAT_1001b5b8);
  if (CONCAT31(extraout_var,bVar1) != 0) {
    if (DAT_1001b5b8 != (int *)0x0) {
      (**(code **)(*DAT_1001b5b8 + 4))(1);
    }
    DAT_1001b5b8 = (int *)0x0;
  }
  local_8 = 0xffffffff;
  CString::~CString((CString *)(this + 0xc));
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_1000e0b2(DD_SURFACE *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  char *pcVar2;
  uint uVar3;
  uint uVar4;
  DD_SURFACE DVar5;
  
  bVar1 = DD_SURFACE::Defined(param_1);
  if ((bVar1) && (bVar1 = FUN_1000ec30((int *)(param_1 + 0xc)), CONCAT31(extraout_var,bVar1) == 0))
  {
    DVar5 = param_1[0x18];
    uVar4 = *(uint *)(param_1 + 0x14);
    uVar3 = *(uint *)(param_1 + 0x10);
    pcVar2 = (char *)FUN_1000a540((undefined4 *)(param_1 + 0xc));
    GKTOOLS::CopyDIBToSurface(param_1,pcVar2,uVar3,uVar4,(bool)DVar5);
  }
  return;
}



bool FUN_1000e10e(void)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 *puVar2;
  uint uVar3;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  int iVar4;
  int local_44;
  uint local_40;
  CTypeLibCacheMap local_3c [28];
  DD_SURFACE *local_20;
  int local_1c;
  DD_SURFACE *local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10010c6f;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CTypeLibCacheMap::CTypeLibCacheMap(local_3c);
  local_8 = 0;
  local_44 = FUN_1000e790(DAT_1001b5b8);
  local_20 = (DD_SURFACE *)0x0;
  local_14 = 0;
  bVar1 = IsEmpty(DAT_1001b5b8);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar2 = (undefined4 *)FUN_1000d1b0(&local_44);
    local_20 = (DD_SURFACE *)*puVar2;
  }
  local_14 = 0;
  while ((uVar3 = FUN_1000ff30(DAT_1001b5b8), local_14 < uVar3 &&
         (bVar1 = IsEmpty(DAT_1001b5b8), CONCAT31(extraout_var_00,bVar1) == 0))) {
    if ((*(int *)(local_20 + 0x24) != 0) && (bVar1 = DD_SURFACE::IsLost(local_20), bVar1)) {
      (**(code **)(**(int **)(local_20 + 0x24) + 0x6c))(*(undefined4 *)(local_20 + 0x24));
      FUN_1000e630(local_3c,&local_20);
    }
    local_14 = local_14 + 1;
    uVar3 = FUN_1000ff30(DAT_1001b5b8);
    if (local_14 < uVar3) {
      puVar2 = (undefined4 *)FUN_1000d1b0(&local_44);
      local_20 = (DD_SURFACE *)*puVar2;
    }
  }
  local_1c = FUN_1000e790((int)local_3c);
  local_18 = (DD_SURFACE *)0x0;
  local_40 = 0;
  bVar1 = IsEmpty((int)local_3c);
  if (CONCAT31(extraout_var_01,bVar1) == 0) {
    puVar2 = (undefined4 *)FUN_1000d1b0(&local_1c);
    local_18 = (DD_SURFACE *)*puVar2;
  }
  local_40 = 0;
  while ((uVar3 = FUN_1000ff30((int)local_3c), local_40 < uVar3 &&
         (bVar1 = IsEmpty((int)local_3c), CONCAT31(extraout_var_02,bVar1) == 0))) {
    FUN_1000e0b2(local_18);
    (*(code *)**(undefined4 **)local_18)(0);
    local_40 = local_40 + 1;
    uVar3 = FUN_1000ff30((int)local_3c);
    if (local_40 < uVar3) {
      puVar2 = (undefined4 *)FUN_1000d1b0(&local_1c);
      local_18 = (DD_SURFACE *)*puVar2;
    }
  }
  iVar4 = FUN_1000ff30((int)local_3c);
  local_8 = 0xffffffff;
  FUN_1000e5e0((undefined4 *)local_3c);
  ExceptionList = local_10;
  return iVar4 != 0;
}



void FUN_1000e2ee(void)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 *puVar2;
  uint uVar3;
  undefined3 extraout_var_00;
  int local_10;
  DD_SURFACE *local_c;
  uint local_8;
  
  local_10 = FUN_1000e7b0(DAT_1001b5b8);
  local_c = (DD_SURFACE *)0x0;
  local_8 = 0;
  bVar1 = IsEmpty(DAT_1001b5b8);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar2 = (undefined4 *)FUN_1000e7d0(&local_10);
    local_c = (DD_SURFACE *)*puVar2;
  }
  local_8 = 0;
  while ((uVar3 = FUN_1000ff30(DAT_1001b5b8), local_8 < uVar3 &&
         (bVar1 = IsEmpty(DAT_1001b5b8), CONCAT31(extraout_var_00,bVar1) == 0))) {
    if (local_c != (DD_SURFACE *)0x0) {
      DD_SURFACE::Release(local_c);
    }
    local_8 = local_8 + 1;
    uVar3 = FUN_1000ff30(DAT_1001b5b8);
    if (local_8 < uVar3) {
      puVar2 = (undefined4 *)FUN_1000e7d0(&local_10);
      local_c = (DD_SURFACE *)*puVar2;
    }
  }
  return;
}



// protected: void __thiscall DD_SURFACE::Release(void)

void __thiscall DD_SURFACE::Release(DD_SURFACE *this)

{
                    // 0xe3aa  125  ?Release@DD_SURFACE@@IAEXXZ
  if (*(int *)(this + 0x20) != 0) {
    AttatchClipper(this,(HWND__ *)0x0);
  }
  if (*(int *)(this + 0x24) != 0) {
    (**(code **)(**(int **)(this + 0x24) + 8))(*(undefined4 *)(this + 0x24));
    *(undefined4 *)(this + 0x24) = 0;
  }
  return;
}



// protected: void __thiscall DD_SURFACE::Recreate(void)

void __thiscall DD_SURFACE::Recreate(DD_SURFACE *this)

{
  bool bVar1;
  
                    // 0xe3ed  122  ?Recreate@DD_SURFACE@@IAEXXZ
  if (((*(int *)(this + 0x24) == 0) && (bVar1 = Defined(this), bVar1)) &&
     ((DAT_1001b5bc == (DD_SURFACE *)0x0 || (bVar1 = IsLost(DAT_1001b5bc), !bVar1)))) {
    Create(this,(_DDSURFACEDESC *)(this + 0x28),*(HWND__ **)(this + 0x20));
    FUN_1000e0b2(this);
    if (this[0x19] != (DD_SURFACE)0x0) {
      if (*(int *)(this + 0x1c) == -1) {
        SetColorKeyFromPixel00(this);
      }
      else {
        SetColorKey(this,*(ulong *)(this + 0x1c));
      }
    }
  }
  return;
}



void FUN_1000e481(void)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 *puVar2;
  uint uVar3;
  undefined3 extraout_var_00;
  int local_10;
  DD_SURFACE *local_c;
  uint local_8;
  
  local_10 = FUN_1000e790(DAT_1001b5b8);
  local_c = (DD_SURFACE *)0x0;
  local_8 = 0;
  bVar1 = IsEmpty(DAT_1001b5b8);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar2 = (undefined4 *)FUN_1000d1b0(&local_10);
    local_c = (DD_SURFACE *)*puVar2;
  }
  local_8 = 0;
  while ((uVar3 = FUN_1000ff30(DAT_1001b5b8), local_8 < uVar3 &&
         (bVar1 = IsEmpty(DAT_1001b5b8), CONCAT31(extraout_var_00,bVar1) == 0))) {
    DD_SURFACE::Recreate(local_c);
    (*(code *)**(undefined4 **)local_c)(1);
    local_8 = local_8 + 1;
    uVar3 = FUN_1000ff30(DAT_1001b5b8);
    if (local_8 < uVar3) {
      puVar2 = (undefined4 *)FUN_1000d1b0(&local_10);
      local_c = (DD_SURFACE *)*puVar2;
    }
  }
  return;
}



// public: bool __thiscall DD_SURFACE::Defined(void)const 

bool __thiscall DD_SURFACE::Defined(DD_SURFACE *this)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 local_70;
  undefined4 local_6c [26];
  
                    // 0xe543  44  ?Defined@DD_SURFACE@@QBE_NXZ
  local_70 = 0;
  puVar2 = local_6c;
  for (iVar1 = 0x1a; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  iVar1 = memcmp(this + 0x28,&local_70,0x6c);
  return iVar1 != 0;
}



void __fastcall FUN_1000e580(int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 local_70 [27];
  
  local_70[0] = 0;
  puVar2 = local_70;
  for (iVar1 = 0x1a; puVar2 = puVar2 + 1, iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
  }
  puVar2 = local_70;
  puVar3 = (undefined4 *)(param_1 + 0x28);
  for (iVar1 = 0x1b; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined4 *)(param_1 + 0x20) = 0;
  if (param_1 == DAT_1001b5bc) {
    DAT_1001b5bc = 0;
  }
  return;
}



void __fastcall FUN_1000e5e0(undefined4 *param_1)

{
  FUN_1000e870(param_1);
  return;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_1000e6d0(this,10);
  *(undefined ***)this = &PTR_LAB_10011d04;
  return this;
}



void * __thiscall FUN_1000e630(void *this,undefined4 *param_1)

{
  FUN_1000e730(this,param_1);
  return this;
}



void __thiscall FUN_1000e650(void *this,int *param_1)

{
  int *piVar1;
  int *piVar2;
  int *local_8;
  
  local_8 = (int *)FUN_1000e790((int)this);
  while (piVar1 = local_8, local_8 != (int *)0x0) {
    piVar2 = (int *)FUN_1000d1b0((int *)&local_8);
    if (*piVar2 == *param_1) {
      FUN_1000e800(this,piVar1);
    }
  }
  return;
}



void * __thiscall FUN_1000e6a0(void *this,uint param_1)

{
  FUN_1000e5e0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001c10(this);
  }
  return this;
}



void * __thiscall FUN_1000e6d0(void *this,undefined4 param_1)

{
  FUN_10003f80((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_10011d18;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



undefined4 * __thiscall FUN_1000e730(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_1000ea20(this,*(undefined4 *)((int)this + 8),0);
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



undefined4 __fastcall FUN_1000e790(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



undefined4 __fastcall FUN_1000e7b0(int param_1)

{
  return *(undefined4 *)(param_1 + 8);
}



int FUN_1000e7d0(int *param_1)

{
  int iVar1;
  
  iVar1 = *param_1;
  *param_1 = *(int *)(iVar1 + 4);
  return iVar1 + 8;
}



void __thiscall FUN_1000e800(void *this,int *param_1)

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
  FUN_1000eb00(this,param_1);
  return;
}



void __fastcall FUN_1000e870(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_10010c89;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_10011d18;
  local_8 = 0;
  FUN_1000e9a0((int)param_1);
  local_8 = 0xffffffff;
  FUN_10001bb0(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_1000e8d0(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_10;
  ulong local_c;
  undefined4 *local_8;
  
  FUN_10001c00();
  bVar1 = FUN_10001c30((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      FUN_1000eb50(param_1,&local_10,1);
      FUN_1000e730(this,&local_10);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_1000eb50(param_1,local_8 + 2,1);
    }
  }
  return;
}



void * __thiscall FUN_1000e970(void *this,uint param_1)

{
  FUN_1000e870((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001c10(this);
  }
  return this;
}



void __fastcall FUN_1000e9a0(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_1000eb90(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



undefined4 * __thiscall FUN_1000ea20(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0xc);
    iVar3 = FUN_100106c0((int)pCVar2);
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
  FUN_1000ebc0(puVar1 + 2,1);
  return puVar1;
}



void __thiscall FUN_1000eb00(void *this,undefined4 *param_1)

{
  FUN_1000eb90(param_1 + 2,1);
  *param_1 = *(undefined4 *)((int)this + 0x10);
  *(undefined4 **)((int)this + 0x10) = param_1;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + -1;
  if (*(int *)((int)this + 0xc) == 0) {
    FUN_1000e9a0((int)this);
  }
  return;
}



void FUN_1000eb50(CArchive *param_1,void *param_2,int param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_10001c30((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    CArchive::Read(param_1,param_2,param_3 << 2);
  }
  else {
    CArchive::Write(param_1,param_2,param_3 << 2);
  }
  return;
}



void FUN_1000eb90(undefined4 param_1,int param_2)

{
  bool bVar1;
  
  do {
    bVar1 = param_2 != 0;
    param_2 = param_2 + -1;
  } while (bVar1);
  return;
}



void FUN_1000ebc0(void *param_1,int param_2)

{
  memset(param_1,0,param_2 << 2);
  while (param_2 != 0) {
    FUN_10001d60(4,param_1);
    param_1 = (void *)((int)param_1 + 4);
    param_2 = param_2 + -1;
  }
  return;
}



void FUN_1000ec10(uint param_1)

{
  operator_new(param_1);
  return;
}



bool __fastcall FUN_1000ec30(int *param_1)

{
  int iVar1;
  
  iVar1 = FUN_1000ec50(param_1);
  return *(int *)(iVar1 + 4) == 0;
}



int __fastcall FUN_1000ec50(int *param_1)

{
  return *param_1 + -0xc;
}



undefined4 FUN_1000ec70(int param_1)

{
  uint uVar1;
  
  if (((*(int *)(param_1 + 0xc) == 0x280) && (*(int *)(param_1 + 8) == 0x1e0)) &&
     ((uVar1 = *(uint *)(param_1 + 0x54), uVar1 == 0x18 || (uVar1 == 0x20)))) {
    DAT_10018ea0 = FUN_1000f490(DAT_10018ea0,uVar1);
  }
  return 1;
}



undefined4 FUN_1000eccb(void)

{
  (**(code **)(*DAT_1001b598 + 0x20))(DAT_1001b598,0,0,0,FUN_1000ec70);
  return DAT_10018ea0;
}



// public: static unsigned int __cdecl GKTOOLS::ShiftPosition(unsigned int)

uint __cdecl GKTOOLS::ShiftPosition(uint param_1)

{
  undefined4 local_8;
  
                    // 0xecf1  184  ?ShiftPosition@GKTOOLS@@SAII@Z
  local_8 = 0;
  for (; (param_1 & 1) != 1; param_1 = param_1 >> 1) {
    local_8 = local_8 + 1;
  }
  return local_8;
}



// public: static unsigned int __cdecl GKTOOLS::BytePosition(unsigned int)

uint __cdecl GKTOOLS::BytePosition(uint param_1)

{
  uint local_8;
  
                    // 0xed21  25  ?BytePosition@GKTOOLS@@SAII@Z
  for (local_8 = 0; *(char *)((int)&param_1 + local_8) == '\0'; local_8 = local_8 + 1) {
  }
  return local_8;
}



// public: static unsigned int __cdecl GKTOOLS::CountBits(unsigned int)

uint __cdecl GKTOOLS::CountBits(uint param_1)

{
  undefined4 local_8;
  
                    // 0xed51  39  ?CountBits@GKTOOLS@@SAII@Z
  local_8 = 0;
  for (; param_1 != 0; param_1 = param_1 >> 1) {
    if ((param_1 & 1) != 0) {
      local_8 = local_8 + 1;
    }
  }
  return local_8;
}



void FUN_1000ed86(void)

{
  return;
}



void __cdecl
FUN_1000ed8b(ushort *param_1,byte *param_2,uint param_3,uint param_4,uint param_5,int param_6)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  
  bVar1 = *param_2;
  bVar2 = param_2[1];
  bVar3 = param_2[2];
  if (param_6 == 0x10) {
    uVar4 = GKTOOLS::CountBits(param_3);
    uVar5 = GKTOOLS::CountBits(param_4);
    uVar6 = GKTOOLS::CountBits(param_5);
    uVar7 = GKTOOLS::ShiftPosition(param_3);
    uVar8 = GKTOOLS::ShiftPosition(param_4);
    uVar9 = GKTOOLS::ShiftPosition(param_5);
    *param_1 = (ushort)(((int)(uint)bVar3 >> (8U - (char)uVar4 & 0x1f) & 0xffU) <<
                       ((byte)uVar7 & 0x1f)) |
               (ushort)(((int)(uint)bVar1 >> (8U - (char)uVar5 & 0x1f) & 0xffU) <<
                       ((byte)uVar8 & 0x1f)) |
               (ushort)(((int)(uint)bVar2 >> (8U - (char)uVar6 & 0x1f) & 0xffU) <<
                       ((byte)uVar9 & 0x1f));
  }
  else {
    uVar4 = GKTOOLS::BytePosition(param_3);
    *(byte *)((int)param_1 + uVar4) = bVar3;
    uVar4 = GKTOOLS::BytePosition(param_4);
    *(byte *)((int)param_1 + uVar4) = bVar1;
    uVar4 = GKTOOLS::BytePosition(param_5);
    *(byte *)((int)param_1 + uVar4) = bVar2;
  }
  return;
}



void __cdecl FUN_1000eeb8(int *param_1,DD_SURFACE *param_2,int param_3,int param_4,char param_5)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  bool bVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  int iVar13;
  uint uVar14;
  uint uVar15;
  int iVar16;
  uint uVar17;
  int *piVar18;
  uint local_108;
  uint local_104;
  int local_f0;
  int local_e8;
  int local_e4;
  uint local_dc;
  int local_d8;
  uint local_c0;
  int local_bc;
  int local_b0;
  ushort *local_98;
  byte *local_94;
  ushort *local_90;
  byte *local_88;
  undefined4 local_70;
  int local_6c [8];
  int local_4c;
  uint local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  
  bVar6 = FUN_10008aa0(param_1);
  if (bVar6) {
    iVar7 = FUN_10008a90(param_1);
    uVar8 = *(int *)(iVar7 + 0x12) * 3 + 3U & 0xfffffffc;
    iVar13 = *(int *)(iVar7 + 0x16);
    iVar9 = FUN_10008a90(param_1);
    local_70 = 0;
    piVar18 = local_6c;
    for (iVar16 = 0x1a; iVar16 != 0; iVar16 = iVar16 + -1) {
      *piVar18 = 0;
      piVar18 = piVar18 + 1;
    }
    iVar16 = DD_SURFACE::Lock(param_2,(_DDSURFACEDESC *)&local_70);
    if (iVar16 != 0) {
      local_98 = (ushort *)(local_4c + (param_3 * local_1c >> 3) + param_4 * local_6c[3]);
      local_94 = (byte *)((iVar9 + 0x36 + uVar8 * iVar13) - uVar8);
      if (local_1c == 0x10) {
        local_b0 = 0;
        local_bc = 0;
        local_d8 = 0;
        uVar10 = GKTOOLS::CountBits(local_18);
        bVar3 = -(char)uVar10 + 8;
        uVar11 = GKTOOLS::CountBits(local_14);
        bVar4 = -(char)uVar11 + 8;
        uVar12 = GKTOOLS::CountBits(local_10);
        bVar5 = -(char)uVar12 + 8;
        iVar9 = 1 << (-(char)uVar10 + 7U & 0x1f);
        iVar13 = 1 << (-(char)uVar11 + 7U & 0x1f);
        iVar16 = 1 << (-(char)uVar12 + 7U & 0x1f);
        uVar10 = GKTOOLS::ShiftPosition(local_18);
        uVar11 = GKTOOLS::ShiftPosition(local_14);
        uVar12 = GKTOOLS::ShiftPosition(local_10);
        for (local_c0 = 0; local_c0 < *(uint *)(iVar7 + 0x16); local_c0 = local_c0 + 1) {
          local_90 = local_98;
          local_88 = local_94;
          for (local_dc = 0; local_dc < *(uint *)(iVar7 + 0x12); local_dc = local_dc + 1) {
            bVar1 = local_88[1];
            bVar2 = *local_88;
            if (param_5 == '\0') {
              local_e4 = FUN_10008a10(0,(uint)local_88[2] + iVar9,0xff);
              local_e8 = FUN_10008a10(0,(uint)bVar1 + iVar13,0xff);
              local_f0 = FUN_10008a10(0,(uint)bVar2 + iVar16,0xff);
            }
            else {
              local_e4 = FUN_10008a10(0,(uint)local_88[2] + iVar9 + local_b0,0xff);
              local_e8 = FUN_10008a10(0,(uint)bVar1 + iVar13 + local_bc,0xff);
              local_f0 = FUN_10008a10(0,(uint)bVar2 + iVar16 + local_d8,0xff);
            }
            uVar14 = local_e4 >> (bVar3 & 0x1f);
            uVar17 = local_e8 >> (bVar4 & 0x1f);
            uVar15 = local_f0 >> (bVar5 & 0x1f);
            local_b0 = local_e4 - (uVar14 << (bVar3 & 0x1f));
            local_bc = local_e8 - (uVar17 << (bVar4 & 0x1f));
            local_d8 = local_f0 - (uVar15 << (bVar5 & 0x1f));
            *local_90 = (ushort)((uVar14 & 0xffff) << ((byte)uVar10 & 0x1f)) |
                        (ushort)((uVar17 & 0xffff) << ((byte)uVar11 & 0x1f)) |
                        (ushort)((uVar15 & 0xffff) << ((byte)uVar12 & 0x1f));
            local_90 = (ushort *)((int)local_90 + (local_1c >> 3));
            local_88 = local_88 + 3;
          }
          local_98 = (ushort *)((int)local_98 + local_6c[3]);
          local_94 = local_94 + -uVar8;
        }
      }
      else {
        uVar10 = GKTOOLS::BytePosition(local_18);
        uVar11 = GKTOOLS::BytePosition(local_14);
        uVar12 = GKTOOLS::BytePosition(local_10);
        for (local_104 = 0; local_104 < *(uint *)(iVar7 + 0x16); local_104 = local_104 + 1) {
          local_90 = local_98;
          local_88 = local_94;
          for (local_108 = 0; local_108 < *(uint *)(iVar7 + 0x12); local_108 = local_108 + 1) {
            *(byte *)((int)local_90 + uVar10) = local_88[2];
            *(byte *)((int)local_90 + uVar11) = local_88[1];
            *(byte *)((int)local_90 + uVar12) = *local_88;
            local_90 = (ushort *)((int)local_90 + (local_1c >> 3));
            local_88 = local_88 + 3;
          }
          local_98 = (ushort *)((int)local_98 + local_6c[3]);
          local_94 = local_94 + -uVar8;
        }
      }
      DD_SURFACE::Unlock(param_2);
    }
  }
  return;
}



uint __cdecl FUN_1000f490(uint param_1,uint param_2)

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



undefined8 FUN_1000f4c0(void)

{
  undefined8 uVar1;
  
  uVar1 = rdtsc();
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1000f4ec(void)

{
  longlong lVar1;
  
  lVar1 = FUN_1000f4c0();
  lVar1 = lVar1 - CONCAT44(_DAT_1001b5c4,_DAT_1001b5c0);
  DAT_1001b5c8 = (undefined4)lVar1;
  DAT_1001b5cc = (undefined4)((ulonglong)lVar1 >> 0x20);
  printf(s__I64d_10018ea4,DAT_1001b5c8,DAT_1001b5cc);
  _DAT_1001b5c0 = FUN_1000f4c0();
  return;
}



void FUN_1000f538(void)

{
  FUN_1000f4ec();
  FUN_1000f4ec();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

LRESULT FUN_1000f550(HWND param_1,uint param_2,uint param_3,uint param_4)

{
  bool bVar1;
  SHORT SVar2;
  LRESULT LVar3;
  int xRight;
  HWND__ *pHVar4;
  BOOL BVar5;
  int iVar6;
  undefined3 extraout_var;
  undefined4 *puVar7;
  uint uVar8;
  undefined3 extraout_var_00;
  UINT Msg;
  WPARAM wParam;
  LPARAM lParam;
  uint local_18;
  int local_14;
  void *local_10;
  uint local_c;
  uint local_8;
  
  if (DAT_1001b5d8 == '\0') {
    EnumDisplaySettingsA((LPCSTR)0x0,0xfffffffe,(DEVMODEA *)&lpDevMode_1001b5e0);
    DAT_1001b5d8 = '\x01';
  }
  if ((DAT_1001b648 < 0x10) && ((char)param_1_1001b368 != '\0')) {
    LVar3 = DefWindowProcA(param_1,param_2,param_3,param_4);
    return LVar3;
  }
  if ((DAT_1001b36c != (int *)0x0) && (0x3ff < param_2)) {
    (**(code **)(*DAT_1001b36c + 0x20))(param_2 - 0x400,param_3,param_4);
  }
  uVar8 = local_c;
  if (param_2 < 0x101) {
    if (param_2 == 0x100) {
      if ((((((DAT_1001b36c != (int *)0x0) && (DAT_1001b59d == '\0')) && (param_3 == 0x2e)) ||
           ((param_3 == 0x25 || (param_3 == 0x27)))) ||
          ((param_3 == 0x26 || ((param_3 == 0x28 || (param_3 == 0x21)))))) || (param_3 == 0x22)) {
        (**(code **)(*DAT_1001b36c + 0x24))(param_3 << 0x10,1);
      }
    }
    else {
      switch(param_2) {
      case 1:
        SetForegroundWindow(param_1);
        break;
      case 2:
        PostQuitMessage(0);
        break;
      case 3:
      case 5:
        if ((char)param_1_1001b368 == '\0') {
          iVar6 = GetSystemMetrics(1);
          xRight = GetSystemMetrics(0);
          SetRect((LPRECT)&lprc_1001b3a8,0,0,xRight,iVar6);
        }
        else {
          GetClientRect(param_1,(LPRECT)&lprc_1001b3a8);
          ClientToScreen(param_1,(LPPOINT)&lprc_1001b3a8);
          _DAT_1001b3b0 = (int)&lprc_1001b3a8->left + DAT_1001b390;
          _DAT_1001b3b4 = DAT_1001b3ac + DAT_1001b298;
          if (DAT_1001b36c != (int *)0x0) {
            (**(code **)(*DAT_1001b36c + 0x44))(param_4 & 0xffff,param_4 >> 0x10);
          }
        }
        break;
      case 0xf:
        if ((char)param_1_1001b368 != '\0') {
          DD_SURFACE::Blt(&GKERNEL::ddsVisible,&GKERNEL::ddsPrimary,(tagRECT *)&lprc_1001b3a8,
                          (tagRECT *)0x0);
        }
      default:
switchD_1000f685_caseD_122:
        LVar3 = DefWindowProcA(param_1,param_2,param_3,param_4);
        return LVar3;
      case 0x1c:
        if ((DAT_1001b3b8 != '\0') && (DAT_1001b59c == '\0')) {
          if (DAT_1001b36c != (int *)0x0) {
            (**(code **)(*DAT_1001b36c + 0xc))(param_3 != 0);
          }
          if (param_3 == 1) {
            if (DAT_10018eac == '\0') {
              (**(code **)(*DAT_1001b598 + 0x54))
                        (DAT_1001b598,DAT_1001b390,DAT_1001b298,DAT_1001b3a0,0,0);
              DAT_10018eac = '\x01';
            }
            bVar1 = FUN_1000e10e();
            if (bVar1) {
              GKERNEL::DebugTrace(s_restored_some_surfaces_10018eb0);
              GKERNEL::NewSpriteBackground();
              GKERNEL::Flip();
              if (DAT_1001b36c != (int *)0x0) {
                (**(code **)(*DAT_1001b36c + 8))(0);
              }
            }
          }
          else if ((char)param_1_1001b368 == '\0') {
            pHVar4 = GKERNEL::GetHwnd();
            BVar5 = IsIconic(pHVar4);
            if (BVar5 == 0) {
              iVar6 = FUN_1000ff30(0x10019060);
              if (iVar6 != 0) {
                local_14 = FUN_1000e790(0x10019060);
                local_10 = (void *)0x0;
                bVar1 = IsEmpty(0x10019060);
                if (CONCAT31(extraout_var,bVar1) == 0) {
                  puVar7 = (undefined4 *)FUN_1000d1b0(&local_14);
                  local_10 = (void *)*puVar7;
                }
                local_18 = 0;
                while ((uVar8 = FUN_1000ff30(0x10019060), local_18 < uVar8 &&
                       (bVar1 = IsEmpty(0x10019060), CONCAT31(extraout_var_00,bVar1) == 0))) {
                  FUN_1000ff80(local_10,0x111,2,0);
                  local_18 = local_18 + 1;
                  uVar8 = FUN_1000ff30(0x10019060);
                  if (local_18 < uVar8) {
                    puVar7 = (undefined4 *)FUN_1000d1b0(&local_14);
                    local_10 = (void *)*puVar7;
                  }
                }
                PostMessageA(param_1,param_2,param_3,param_4);
                return 0;
              }
              lParam = 0;
              wParam = 0xf020;
              Msg = 0x112;
              pHVar4 = GKERNEL::GetHwnd();
              SendMessageA(pHVar4,Msg,wParam,lParam);
              GKERNEL::DebugTrace(s_Restoring_display_mode_10018ec8);
              (**(code **)(*DAT_1001b598 + 0x4c))(DAT_1001b598);
              DAT_10018eac = '\0';
            }
          }
        }
        break;
      case 0x7e:
        _DAT_1001b604 = 0x94;
        EnumDisplaySettingsA((LPCSTR)0x0,0xfffffffe,(DEVMODEA *)&lpDevMode_1001b5e0);
        if ((bool)(char)param_1_1001b368 != false) {
          GKERNEL::SetWindowedMode((bool)(char)param_1_1001b368);
        }
        break;
      case 0xa0:
        if (DAT_100188ac != '\0') {
          ShowMouse(true);
        }
      }
    }
  }
  else {
    if (0x112 < param_2) {
      switch(param_2) {
      case 0x121:
        ShowMouse(true);
        break;
      default:
        goto switchD_1000f685_caseD_122;
      case 0x200:
      case 0x201:
      case 0x202:
      case 0x204:
      case 0x205:
        ShowMouse(DAT_100188ac == '\0');
        if ((DAT_1001b36c != (int *)0x0) && (DAT_1001b59d == '\0')) {
          FUN_10009020(DAT_1001b36c,param_4 & 0xffff,param_4 & 0xffff,param_4 >> 0x10,
                       (param_3 & 1) != 0,(param_3 & 2) != 0);
        }
      }
      goto LAB_1000fc0c;
    }
    if (param_2 != 0x112) {
      if (param_2 == 0x101) goto LAB_1000fc0c;
      if (param_2 == 0x102) {
        if ((DAT_1001b36c != (int *)0x0) && (DAT_1001b59d == '\0')) {
          (**(code **)(*DAT_1001b36c + 0x24))(param_3,1);
        }
        goto LAB_1000fc0c;
      }
      if (param_2 != 0x104) goto switchD_1000f685_caseD_122;
    }
    if ((param_2 == 0x112) && ((param_3 & 0xfff0) == 0xf060)) {
      GKERNEL::Stop();
      return 0;
    }
    if ((param_2 == 0x112) && ((param_3 & 0xfff0) == 0xf030)) {
      bVar1 = true;
    }
    else {
      bVar1 = false;
    }
    local_8 = CONCAT31(local_8._1_3_,bVar1);
    local_c = local_c & 0xffffff00;
    if (bVar1) {
      local_c._1_3_ = SUB43(uVar8,1);
      local_c = CONCAT31(local_c._1_3_,1);
    }
    else if (param_2 == 0x104) {
      if ((param_3 == 0x73) && ((param_4 & 0x20000000) != 0)) {
        GKERNEL::Stop();
        return 0;
      }
      SVar2 = GetKeyState(0xd);
      local_c = CONCAT31(local_c._1_3_,((int)SVar2 & 0x8000U) != 0);
    }
    if (((DAT_100188ad == '\0') || ((local_c & 0xff) == 0)) || (DAT_1001b59c != '\0')) {
      if ((local_8 & 0xff) != 0) {
        return 0;
      }
    }
    else {
      GKERNEL::SetWindowedMode((char)param_1_1001b368 == '\0');
    }
    if (param_2 == 0x104) {
      return 0;
    }
  }
LAB_1000fc0c:
  LVar3 = DefWindowProcA(param_1,param_2,param_3,param_4);
  return LVar3;
}



// public: static void __cdecl GKERNEL::Start(void)

void __cdecl GKERNEL::Start(void)

{
  bool bVar1;
  undefined3 extraout_var;
  BOOL BVar2;
  undefined3 extraout_var_00;
  DWORD dwMilliseconds;
  int iVar3;
  uint uVar4;
  UINT *pUVar5;
  int iVar6;
  tagMSG local_20;
  
                    // 0xfdd9  187  ?Start@GKERNEL@@SAXXZ
  local_20.hwnd = (HWND)0x0;
  pUVar5 = &local_20.message;
  for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
    *pUVar5 = 0;
    pUVar5 = pUVar5 + 1;
  }
  while ((DAT_1001b59f == '\0' ||
         (bVar1 = FUN_10003fc0(&DAT_1001b39c,10000), CONCAT31(extraout_var,bVar1) == 0))) {
    BVar2 = PeekMessageA(&local_20,(HWND)0x0,0,0,0);
    if (BVar2 == 0) {
      if ((DAT_1001b5d0 & 1) == 0) {
        DAT_1001b5d0 = DAT_1001b5d0 | 1;
        FUN_100023b0((DWORD *)&DAT_1001b5d4);
        FUN_100104a2(FUN_1000ff20);
      }
      uVar4 = -(uint)((char)param_1_1001b368 != '\0') & 0x14;
      bVar1 = FUN_10003fc0(&DAT_1001b5d4,uVar4);
      if (CONCAT31(extraout_var_00,bVar1) == 0) {
        iVar6 = 0;
        iVar3 = FUN_10006b20((int *)&DAT_1001b5d4);
        dwMilliseconds = FUN_1000ff50((uVar4 + 5) - iVar3,iVar6);
        Sleep(dwMilliseconds);
      }
      else if ((DAT_1001b36c != (int *)0x0) && (BVar2 = IsWindow(DAT_1001b394), BVar2 != 0)) {
        FUN_10009275(DAT_1001b36c);
      }
    }
    else {
      BVar2 = GetMessageA(&local_20,(HWND)0x0,0,0);
      if (BVar2 == 0) {
        return;
      }
      TranslateMessage(&local_20);
      DispatchMessageA(&local_20);
    }
  }
                    // WARNING: Subroutine does not return
  _exit(1);
}



void FUN_1000ff20(void)

{
  return;
}



undefined4 __fastcall FUN_1000ff30(int param_1)

{
  return *(undefined4 *)(param_1 + 0xc);
}



int __cdecl FUN_1000ff50(int param_1,int param_2)

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



void __thiscall FUN_1000ff80(void *this,UINT param_1,WPARAM param_2,LPARAM param_3)

{
  PostMessageA(*(HWND *)((int)this + 0x20),param_1,param_2,param_3);
  return;
}



void DirectDrawCreate(void)

{
                    // WARNING: Could not recover jumptable at 0x1000ffa6. Too many branches
                    // WARNING: Treating indirect jump as call
  DirectDrawCreate();
  return;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000ffac. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall CPen::CPen(CPen *this,int param_1,int param_2,ulong param_3)

{
                    // WARNING: Could not recover jumptable at 0x1000ffb2. Too many branches
                    // WARNING: Treating indirect jump as call
  CPen(this,param_1,param_2,param_3);
  return;
}



ulong __thiscall CArchive::ReadCount(CArchive *this)

{
  ulong uVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000ffbe. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = ReadCount(this);
  return uVar1;
}



void __thiscall CArchive::WriteCount(CArchive *this,ulong param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000ffc4. Too many branches
                    // WARNING: Treating indirect jump as call
  WriteCount(this,param_1);
  return;
}



void __thiscall CPlex::FreeDataChain(CPlex *this)

{
                    // WARNING: Could not recover jumptable at 0x1000ffca. Too many branches
                    // WARNING: Treating indirect jump as call
  FreeDataChain(this);
  return;
}



uint __thiscall CArchive::Read(CArchive *this,void *param_1,uint param_2)

{
  uint uVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000ffd0. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = Read(this,param_1,param_2);
  return uVar1;
}



void __thiscall CArchive::Write(CArchive *this,void *param_1,uint param_2)

{
                    // WARNING: Could not recover jumptable at 0x1000ffd6. Too many branches
                    // WARNING: Treating indirect jump as call
  Write(this,param_1,param_2);
  return;
}



CPlex * CPlex::Create(CPlex **param_1,uint param_2,uint param_3)

{
  CPlex *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000ffdc. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = Create(param_1,param_2,param_3);
  return pCVar1;
}



BOOL CGdiObject::DeleteObject(HGDIOBJ ho)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000ffee. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = DeleteObject(ho);
  return BVar1;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000fff4. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void __thiscall CBrush::CBrush(CBrush *this,ulong param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000fffa. Too many branches
                    // WARNING: Treating indirect jump as call
  CBrush(this,param_1);
  return;
}



int __thiscall CDialog::OnInitDialog(CDialog *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10010006. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = OnInitDialog(this);
  return iVar1;
}



void __thiscall CWnd::OnDestroy(CWnd *this)

{
                    // WARNING: Could not recover jumptable at 0x1001000c. Too many branches
                    // WARNING: Treating indirect jump as call
  OnDestroy(this);
  return;
}



BOOL CDialog::EndDialog(HWND hDlg,INT_PTR nResult)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x10010012. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = EndDialog(hDlg,nResult);
  return BVar1;
}



int __thiscall CDialog::DoModal(CDialog *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10010018. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = DoModal(this);
  return iVar1;
}



long __thiscall CWnd::Default(CWnd *this)

{
  long lVar1;
  
                    // WARNING: Could not recover jumptable at 0x1001001e. Too many branches
                    // WARNING: Treating indirect jump as call
  lVar1 = Default(this);
  return lVar1;
}



void __thiscall CString::~CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x1001012c. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CString(this);
  return;
}



CString * __thiscall CString::operator=(CString *this,char *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x10010132. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator=(this,param_1);
  return pCVar1;
}



void __thiscall CString::CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x10010138. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this);
  return;
}



void DDV_MaxChars(CDataExchange *param_1,CString *param_2,int param_3)

{
                    // WARNING: Could not recover jumptable at 0x1001013e. Too many branches
                    // WARNING: Treating indirect jump as call
  DDV_MaxChars(param_1,param_2,param_3);
  return;
}



void DDX_Text(CDataExchange *param_1,int param_2,CString *param_3)

{
                    // WARNING: Could not recover jumptable at 0x10010144. Too many branches
                    // WARNING: Treating indirect jump as call
  DDX_Text(param_1,param_2,param_3);
  return;
}



void __thiscall CDialog::CDialog(CDialog *this,uint param_1,CWnd *param_2)

{
                    // WARNING: Could not recover jumptable at 0x1001014a. Too many branches
                    // WARNING: Treating indirect jump as call
  CDialog(this,param_1,param_2);
  return;
}



void __thiscall CDialog::~CDialog(CDialog *this)

{
                    // WARNING: Could not recover jumptable at 0x10010150. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CDialog(this);
  return;
}



CString * __thiscall CString::operator=(CString *this,CString *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x10010156. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator=(this,param_1);
  return pCVar1;
}



void operator+(CString *param_1,char *param_2)

{
                    // WARNING: Could not recover jumptable at 0x1001015c. Too many branches
                    // WARNING: Treating indirect jump as call
  operator+(param_1,param_2);
  return;
}



void operator+(CString *param_1,CString *param_2)

{
                    // WARNING: Could not recover jumptable at 0x10010162. Too many branches
                    // WARNING: Treating indirect jump as call
  operator+(param_1,param_2);
  return;
}



void __thiscall CString::CString(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10010168. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



void __thiscall CWinApp::~CWinApp(CWinApp *this)

{
                    // WARNING: Could not recover jumptable at 0x1001016e. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CWinApp(this);
  return;
}



void __thiscall CWinApp::CWinApp(CWinApp *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100101f8. Too many branches
                    // WARNING: Treating indirect jump as call
  CWinApp(this,param_1);
  return;
}



CWnd * CWnd::FromHandle(HWND__ *param_1)

{
  CWnd *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x100101fe. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = FromHandle(param_1);
  return pCVar1;
}



void __thiscall
AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(AFX_MAINTAIN_STATE2 *this,AFX_MODULE_STATE *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10010204. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MAINTAIN_STATE2(this,param_1);
  return;
}



void __thiscall CString::CString(CString *this,CString *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1001020a. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



undefined4 * FUN_1001021a(void)

{
  AFX_MODULE_STATE::AFX_MODULE_STATE
            ((AFX_MODULE_STATE *)&param_1_1001b680,1,AfxWndProcDllStatic,0x600);
  param_1_1001b680 = (AFX_MAINTAIN_STATE2 *)&PTR_FUN_10011d30;
  return &param_1_1001b680;
}



void * __thiscall FUN_10010242(void *this,byte param_1)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)this);
  if ((param_1 & 1) != 0) {
    CNoTrackObject::operator_delete(this);
  }
  return this;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x1001066a. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



void FUN_10010262(void)

{
  FUN_100104a2(FUN_1001026e);
  return;
}



void FUN_1001026e(void)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)&param_1_1001b680);
  return;
}



// Library Function - Single Match
//  long __stdcall AfxWndProcDllStatic(struct HWND__ *,unsigned int,unsigned int,long)
// 
// Library: Visual Studio 2003 Release
// param_1 parameter of AFX_MODULE_STATE
// 

long AfxWndProcDllStatic(HWND__ *param_1,uint param_2,uint param_3,long param_4)

{
  long lVar1;
  int unaff_EBP;
  
  FUN_1001062c();
  AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
            ((AFX_MAINTAIN_STATE2 *)(unaff_EBP + -0x14),(AFX_MODULE_STATE *)&param_1_1001b680);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  lVar1 = AfxWndProc(*(HWND__ **)(unaff_EBP + 8),*(uint *)(unaff_EBP + 0xc),
                     *(uint *)(unaff_EBP + 0x10),*(long *)(unaff_EBP + 0x14));
  *(undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4) = *(undefined4 *)(unaff_EBP + -0x14);
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return lVar1;
}



undefined4 * FUN_100102bd(void)

{
  return &param_1_1001b680;
}



int FUN_100102c3(HINSTANCE__ *param_1,int param_2)

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
      pAVar5 = AfxSetModuleState((AFX_MODULE_STATE *)&param_1_1001b680);
      p_Var3 = AfxGetThreadState();
      *(AFX_MODULE_STATE **)(p_Var3 + 8) = pAVar5;
      pAVar5 = AfxGetModuleState();
      if (*(int **)(pAVar5 + 4) != (int *)0x0) {
        (**(code **)(**(int **)(pAVar5 + 4) + 0x70))();
      }
      AfxLockTempMaps();
      AfxUnlockTempMaps(-1);
      AfxWinTerm();
      AfxTermExtensionModule((AFX_EXTENSION_MODULE *)&param_1_1001c710,1);
    }
    else if (param_2 == 3) {
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
                ((AFX_MAINTAIN_STATE2 *)&local_c,(AFX_MODULE_STATE *)&param_1_1001b680);
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
  iVar4 = AfxWinInit(param_1,(HINSTANCE__ *)0x0,(char *)&param_3_1001b294,0);
  if (iVar4 != 0) {
    pAVar5 = AfxGetModuleState();
    piVar2 = *(int **)(pAVar5 + 4);
    if ((piVar2 == (int *)0x0) || (iVar4 = (**(code **)(*piVar2 + 0x58))(), iVar4 != 0)) {
      *(undefined4 *)(p_Var3 + 8) = uVar1;
      AfxInitExtensionModule((AFX_EXTENSION_MODULE *)&param_1_1001c710,param_1);
      this = (CDynLinkLibrary *)operator_new(0x40);
      if (this != (CDynLinkLibrary *)0x0) {
        CDynLinkLibrary::CDynLinkLibrary(this,(AFX_EXTENSION_MODULE *)&param_1_1001c710,0);
      }
      param_2 = 1;
      goto LAB_1001034f;
    }
    (**(code **)(*piVar2 + 0x70))();
  }
  AfxWinTerm();
LAB_1001034f:
  *(undefined4 *)(p_Var3 + 8) = uVar1;
  p_Var3 = AfxGetThreadState();
  AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var3 + 8));
  return param_2;
}



undefined4 FUN_100103ea(undefined4 param_1,int param_2)

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
    pAVar2 = AfxSetModuleState((AFX_MODULE_STATE *)&param_1_1001b680);
    *(AFX_MODULE_STATE **)(p_Var1 + 8) = pAVar2;
  }
  else if (param_2 == 0) {
    p_Var1 = AfxGetThreadState();
    AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var1 + 8));
  }
  return 1;
}



void __CxxFrameHandler(void)

{
                    // WARNING: Could not recover jumptable at 0x10010440. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler();
  return;
}



double __cdecl sin(double _X)

{
  double dVar1;
  
                    // WARNING: Could not recover jumptable at 0x10010446. Too many branches
                    // WARNING: Treating indirect jump as call
  dVar1 = sin(_X);
  return dVar1;
}



double __cdecl cos(double _X)

{
  double dVar1;
  
                    // WARNING: Could not recover jumptable at 0x1001044c. Too many branches
                    // WARNING: Treating indirect jump as call
  dVar1 = cos(_X);
  return dVar1;
}



double __cdecl fmod(double _X,double _Y)

{
  double dVar1;
  
                    // WARNING: Could not recover jumptable at 0x10010452. Too many branches
                    // WARNING: Treating indirect jump as call
  dVar1 = fmod(_X,_Y);
  return dVar1;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x10010458. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



void __cdecl ftol(void)

{
                    // WARNING: Could not recover jumptable at 0x10010464. Too many branches
                    // WARNING: Treating indirect jump as call
  ftol();
  return;
}



long __cdecl labs(long _X)

{
  long lVar1;
  
                    // WARNING: Could not recover jumptable at 0x1001046a. Too many branches
                    // WARNING: Treating indirect jump as call
  lVar1 = labs(_X);
  return lVar1;
}



int __cdecl abs(int _X)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10010470. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = abs(_X);
  return iVar1;
}



void __cdecl FUN_10010476(_onexit_t param_1)

{
  if (DAT_1001c734 == -1) {
    _onexit(param_1);
    return;
  }
  __dllonexit(param_1,&DAT_1001c734,&DAT_1001c730);
  return;
}



int __cdecl FUN_100104a2(_onexit_t param_1)

{
  int iVar1;
  
  iVar1 = FUN_10010476(param_1);
  return (iVar1 != 0) - 1;
}



void * __thiscall FUN_100104b4(void *this,byte param_1)

{
  type_info::~type_info((type_info *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



size_t __cdecl strlen(char *_Str)

{
  size_t sVar1;
  
                    // WARNING: Could not recover jumptable at 0x100104d0. Too many branches
                    // WARNING: Treating indirect jump as call
  sVar1 = strlen(_Str);
  return sVar1;
}



void _CxxThrowException(void *pExceptionObject,ThrowInfo *pThrowInfo)

{
                    // WARNING: Could not recover jumptable at 0x100104d6. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  _CxxThrowException(pExceptionObject,pThrowInfo);
  return;
}



int __cdecl memcmp(void *_Buf1,void *_Buf2,size_t _Size)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x100104dc. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = memcmp(_Buf1,_Buf2,_Size);
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_100104e2(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 *_Memory;
  undefined4 *puVar2;
  
  if (param_2 == 0) {
    if (0 < DAT_1001c728) {
      DAT_1001c728 = DAT_1001c728 + -1;
      goto LAB_100104f8;
    }
LAB_10010520:
    uVar1 = 0;
  }
  else {
LAB_100104f8:
    _DAT_1001c72c = *(undefined4 *)_adjust_fdiv_exref;
    if (param_2 == 1) {
      DAT_1001c734 = (undefined4 *)malloc(0x80);
      if (DAT_1001c734 == (undefined4 *)0x0) goto LAB_10010520;
      *DAT_1001c734 = 0;
      DAT_1001c730 = DAT_1001c734;
      initterm(&DAT_10016000,&DAT_10016030);
      DAT_1001c728 = DAT_1001c728 + 1;
    }
    else if ((param_2 == 0) &&
            (_Memory = DAT_1001c734, puVar2 = DAT_1001c730, DAT_1001c734 != (undefined4 *)0x0)) {
      while (puVar2 = puVar2 + -1, _Memory <= puVar2) {
        if ((code *)*puVar2 != (code *)0x0) {
          (*(code *)*puVar2)();
          _Memory = DAT_1001c734;
        }
      }
      free(_Memory);
      DAT_1001c734 = (undefined4 *)0x0;
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
  iVar2 = DAT_1001c728;
  if (param_2 != 0) {
    if ((param_2 != 1) && (param_2 != 2)) goto LAB_100105d5;
    if ((PTR_FUN_10018ee0 != (undefined *)0x0) &&
       (iVar2 = (*(code *)PTR_FUN_10018ee0)(param_1,param_2,param_3), iVar2 == 0)) {
      return 0;
    }
    iVar2 = FUN_100104e2(param_1,param_2);
  }
  if (iVar2 == 0) {
    return 0;
  }
LAB_100105d5:
  iVar2 = FUN_100102c3(param_1,param_2);
  if (param_2 == 1) {
    if (iVar2 != 0) {
      return iVar2;
    }
    FUN_100104e2(param_1,0);
  }
  if ((param_2 != 0) && (param_2 != 3)) {
    return iVar2;
  }
  iVar3 = FUN_100104e2(param_1,param_2);
  param_2 = iVar2;
  if (iVar3 == 0) {
    param_2 = 0;
  }
  if (param_2 != 0) {
    if (PTR_FUN_10018ee0 != (undefined *)0x0) {
      iVar2 = (*(code *)PTR_FUN_10018ee0)(param_1,iVar1,param_3);
      return iVar2;
    }
    return param_2;
  }
  return 0;
}



void FUN_1001062c(void)

{
  undefined1 auStack_c [12];
  
  ExceptionList = auStack_c;
  return;
}



void __dllonexit(void)

{
                    // WARNING: Could not recover jumptable at 0x1001064c. Too many branches
                    // WARNING: Treating indirect jump as call
  __dllonexit();
  return;
}



void __thiscall type_info::~type_info(type_info *this)

{
                    // WARNING: Could not recover jumptable at 0x10010652. Too many branches
                    // WARNING: Treating indirect jump as call
  ~type_info(this);
  return;
}



void __cdecl initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x10010658. Too many branches
                    // WARNING: Treating indirect jump as call
  initterm();
  return;
}



void __thiscall
AFX_MODULE_STATE::AFX_MODULE_STATE
          (AFX_MODULE_STATE *this,int param_1,FuncDef36 *param_2,ulong param_3)

{
                    // WARNING: Could not recover jumptable at 0x1001065e. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MODULE_STATE(this,param_1,param_2,param_3);
  return;
}



void CNoTrackObject::operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10010664. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x1001066a. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



long AfxWndProc(HWND__ *param_1,uint param_2,uint param_3,long param_4)

{
  long lVar1;
  
                    // WARNING: Could not recover jumptable at 0x10010670. Too many branches
                    // WARNING: Treating indirect jump as call
  lVar1 = AfxWndProc(param_1,param_2,param_3,param_4);
  return lVar1;
}



void AfxTermThread(HINSTANCE__ *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10010676. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermThread(param_1);
  return;
}



void AfxTermExtensionModule(AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x1001067c. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermExtensionModule(param_1,param_2);
  return;
}



int AfxUnlockTempMaps(int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10010682. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxUnlockTempMaps(param_1);
  return iVar1;
}



void AfxLockTempMaps(void)

{
                    // WARNING: Could not recover jumptable at 0x10010688. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxLockTempMaps();
  return;
}



AFX_MODULE_STATE * AfxSetModuleState(AFX_MODULE_STATE *param_1)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x1001068e. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxSetModuleState(param_1);
  return pAVar1;
}



void __thiscall
CDynLinkLibrary::CDynLinkLibrary(CDynLinkLibrary *this,AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10010694. Too many branches
                    // WARNING: Treating indirect jump as call
  CDynLinkLibrary(this,param_1,param_2);
  return;
}



int AfxInitExtensionModule(AFX_EXTENSION_MODULE *param_1,HINSTANCE__ *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1001069a. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxInitExtensionModule(param_1,param_2);
  return iVar1;
}



void AfxWinTerm(void)

{
                    // WARNING: Could not recover jumptable at 0x100106a0. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxWinTerm();
  return;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x100106a6. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



int AfxWinInit(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x100106ac. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinInit(param_1,param_2,param_3,param_4);
  return iVar1;
}



_AFX_THREAD_STATE * AfxGetThreadState(void)

{
  _AFX_THREAD_STATE *p_Var1;
  
                    // WARNING: Could not recover jumptable at 0x100106b2. Too many branches
                    // WARNING: Treating indirect jump as call
  p_Var1 = AfxGetThreadState();
  return p_Var1;
}



void AfxCoreInitModule(void)

{
                    // WARNING: Could not recover jumptable at 0x100106b8. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxCoreInitModule();
  return;
}



int __fastcall FUN_100106c0(int param_1)

{
  return param_1 + 4;
}



void Unwind_100106e0(void)

{
  int unaff_EBP;
  
  FUN_10001ec0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10010700(void)

{
  int unaff_EBP;
  
  FUN_10001810((undefined4 *)(unaff_EBP + -0x30));
  return;
}



void Unwind_10010709(void)

{
  int unaff_EBP;
  
  FUN_10001c80((undefined4 *)(unaff_EBP + -0x14));
  return;
}



void Unwind_10010712(void)

{
  int unaff_EBP;
  
  FUN_10001c80((undefined4 *)(unaff_EBP + -0x60));
  return;
}



void Unwind_10010730(void)

{
  int unaff_EBP;
  
  FUN_10001bb0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10010750(void)

{
  int unaff_EBP;
  
  FUN_10001bb0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10010770(void)

{
  int unaff_EBP;
  
  FUN_10001f30(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10010790(void)

{
  int unaff_EBP;
  
  FUN_10001ec0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10010799(void)

{
  int unaff_EBP;
  
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(*(int *)(unaff_EBP + -0x10) + 0xdc));
  return;
}



void Unwind_100107c0(void)

{
  int unaff_EBP;
  
  FUN_10001ec0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100107e0(void)

{
  int unaff_EBP;
  
  CMiniDockFrameWnd::~CMiniDockFrameWnd(*(CMiniDockFrameWnd **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100107e9(void)

{
  int unaff_EBP;
  
  FUN_10001810((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xdd4));
  return;
}



void Unwind_10010802(void)

{
  int unaff_EBP;
  
  CMiniDockFrameWnd::~CMiniDockFrameWnd(*(CMiniDockFrameWnd **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10010815(void)

{
  int unaff_EBP;
  
  FUN_10001810((undefined4 *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_10010830(void)

{
  int unaff_EBP;
  
  CMiniDockFrameWnd::~CMiniDockFrameWnd(*(CMiniDockFrameWnd **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10010850(void)

{
  int unaff_EBP;
  
  FUN_10001f30(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10010863(void)

{
  int unaff_EBP;
  
  FUN_10004ea0((undefined4 *)(unaff_EBP + -0x80));
  return;
}



void Unwind_10010876(void)

{
  int unaff_EBP;
  
  FUN_10004ea0((undefined4 *)(unaff_EBP + -0x80));
  return;
}



void Unwind_10010890(void)

{
  int unaff_EBP;
  
  CMiniDockFrameWnd::~CMiniDockFrameWnd(*(CMiniDockFrameWnd **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100108b0(void)

{
  int unaff_EBP;
  
  CMiniDockFrameWnd::~CMiniDockFrameWnd(*(CMiniDockFrameWnd **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100108d0(void)

{
  int unaff_EBP;
  
  FUN_10001ec0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100108e3(void)

{
  int unaff_EBP;
  
  FUN_100059b0((undefined4 *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_100108ec(void)

{
  int unaff_EBP;
  
  FUN_10001c80((undefined4 *)(unaff_EBP + -0x14));
  return;
}



void Unwind_10010900(void)

{
  int unaff_EBP;
  
  DD_SURFACE::~DD_SURFACE(*(DD_SURFACE **)(unaff_EBP + -0x7c));
  return;
}



void Unwind_10010913(void)

{
  int unaff_EBP;
  
  FUN_10001ec0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10010926(void)

{
  int unaff_EBP;
  
  FUN_10001ec0(*(undefined4 **)(unaff_EBP + -0x20));
  return;
}



void Unwind_10010939(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x20));
  return;
}



void Unwind_10010944(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x38));
  return;
}



void Unwind_10010960(void)

{
  int unaff_EBP;
  
  FUN_10004ea0((undefined4 *)(unaff_EBP + -0x20));
  return;
}



void Unwind_10010969(void)

{
  int unaff_EBP;
  
  FUN_10001c80((undefined4 *)(unaff_EBP + -0x14));
  return;
}



void Unwind_10010972(void)

{
  int unaff_EBP;
  
  FUN_100059b0((undefined4 *)(unaff_EBP + -0x48));
  return;
}



void Unwind_1001097b(void)

{
  int unaff_EBP;
  
  FUN_10001c80((undefined4 *)(unaff_EBP + -0x34));
  return;
}



void Unwind_10010984(void)

{
  int unaff_EBP;
  
  FUN_100059b0((undefined4 *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_100109a0(void)

{
  int unaff_EBP;
  
  CMiniDockFrameWnd::~CMiniDockFrameWnd(*(CMiniDockFrameWnd **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100109b3(void)

{
  int unaff_EBP;
  
  FUN_10001810((undefined4 *)(unaff_EBP + -0x34));
  return;
}



void Unwind_100109d0(void)

{
  int unaff_EBP;
  
  FUN_10001bb0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100109f0(void)

{
  int unaff_EBP;
  
  FUN_10008290(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100109f9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_10010a10(void)

{
  int unaff_EBP;
  
  FUN_10008290(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10010a30(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 8));
  return;
}



void Unwind_10010a50(void)

{
  int unaff_EBP;
  
  FUN_10004ea0((undefined4 *)(unaff_EBP + -0x14));
  return;
}



void Unwind_10010a59(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x21c));
  return;
}



void Unwind_10010a65(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x220));
  return;
}



void Unwind_10010a7b(void)

{
  int unaff_EBP;
  
  FUN_10004ea0((undefined4 *)(unaff_EBP + -0x14));
  return;
}



void Unwind_10010a84(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x21c));
  return;
}



void Unwind_10010a90(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x220));
  return;
}



void Unwind_10010ab0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_10010ab9(void)

{
  int unaff_EBP;
  
  FUN_1000a7b0((undefined4 *)(unaff_EBP + -0x18));
  return;
}



void Unwind_10010ac2(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x24) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_10010ad9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_10010ae2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_10010b00(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_10010b09(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_10010b20(void)

{
  int unaff_EBP;
  
  FUN_1000a7b0((undefined4 *)(unaff_EBP + -0x24));
  return;
}



void Unwind_10010b29(void)

{
  int unaff_EBP;
  
  FUN_1000a7b0((undefined4 *)(unaff_EBP + -0x20));
  return;
}



void Unwind_10010b3c(void)

{
  int unaff_EBP;
  
  FUN_1000a7b0((undefined4 *)(unaff_EBP + -0x18));
  return;
}



void Unwind_10010b45(void)

{
  int unaff_EBP;
  
  FUN_1000a7b0((undefined4 *)(unaff_EBP + -0x14));
  return;
}



void Unwind_10010b58(void)

{
  int unaff_EBP;
  
  FUN_10004ea0((undefined4 *)(unaff_EBP + -0x21c));
  return;
}



void Unwind_10010b6e(void)

{
  int unaff_EBP;
  
  FUN_1000c0b0((undefined4 *)(unaff_EBP + -0x14));
  return;
}



void Unwind_10010b77(void)

{
  int unaff_EBP;
  
  FUN_10008190((CDialog *)(unaff_EBP + -0x78));
  return;
}



void Unwind_10010b8a(void)

{
  int unaff_EBP;
  
  FUN_10004ea0((undefined4 *)(unaff_EBP + -0x14));
  return;
}



void Unwind_10010ba0(void)

{
  int unaff_EBP;
  
  FUN_10001bb0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10010bc0(void)

{
  int unaff_EBP;
  
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(unaff_EBP + -0xa4));
  return;
}



void Unwind_10010be0(void)

{
  int unaff_EBP;
  
  FUN_1000c860((int *)(unaff_EBP + -0x14));
  return;
}



void Unwind_10010bf3(void)

{
  int unaff_EBP;
  
  FUN_1000c860((int *)(unaff_EBP + -0x14));
  return;
}



void Unwind_10010c06(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_10010c0f(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x14) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_10010c30(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x1c) + 0xc));
  return;
}



void Unwind_10010c3c(void)

{
  int unaff_EBP;
  
  FUN_10001c10(*(void **)(unaff_EBP + -0x14));
  return;
}



void Unwind_10010c50(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x1c) + 0xc));
  return;
}



void Unwind_10010c66(void)

{
  int unaff_EBP;
  
  FUN_1000e5e0((undefined4 *)(unaff_EBP + -0x38));
  return;
}



void Unwind_10010c80(void)

{
  int unaff_EBP;
  
  FUN_10001bb0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10010c94(void)

{
  int unaff_EBP;
  
  FUN_1000c0b0((undefined4 *)(unaff_EBP + -0x14));
  return;
}


