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

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef int __ehstate_t;

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    void (*action)(void);
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

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef ulong DWORD;

typedef void *LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _WIN32_FIND_DATAA _WIN32_FIND_DATAA, *P_WIN32_FIND_DATAA;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

typedef char CHAR;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct _WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    CHAR cFileName[260];
    CHAR cAlternateFileName[14];
};

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef CHAR *LPSTR;

typedef ushort WORD;

typedef uchar BYTE;

typedef BYTE *LPBYTE;

typedef void *HANDLE;

struct _STARTUPINFOA {
    DWORD cb;
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _PROCESS_INFORMATION _PROCESS_INFORMATION, *P_PROCESS_INFORMATION;

struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
};

typedef struct _STARTUPINFOA *LPSTARTUPINFOA;

typedef struct _WIN32_FIND_DATAA *LPWIN32_FIND_DATAA;

typedef struct _PROCESS_INFORMATION *LPPROCESS_INFORMATION;

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

typedef longlong __time64_t;

typedef uint size_t;

typedef __time64_t time_t;

typedef struct tagLOGFONTA tagLOGFONTA, *PtagLOGFONTA;

typedef long LONG;

struct tagLOGFONTA {
    LONG lfHeight;
    LONG lfWidth;
    LONG lfEscapement;
    LONG lfOrientation;
    LONG lfWeight;
    BYTE lfItalic;
    BYTE lfUnderline;
    BYTE lfStrikeOut;
    BYTE lfCharSet;
    BYTE lfOutPrecision;
    BYTE lfClipPrecision;
    BYTE lfQuality;
    BYTE lfPitchAndFamily;
    CHAR lfFaceName[32];
};

typedef struct tagBITMAPINFO tagBITMAPINFO, *PtagBITMAPINFO;

typedef struct tagBITMAPINFOHEADER tagBITMAPINFOHEADER, *PtagBITMAPINFOHEADER;

typedef struct tagBITMAPINFOHEADER BITMAPINFOHEADER;

typedef struct tagRGBQUAD tagRGBQUAD, *PtagRGBQUAD;

typedef struct tagRGBQUAD RGBQUAD;

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

struct tagRGBQUAD {
    BYTE rgbBlue;
    BYTE rgbGreen;
    BYTE rgbRed;
    BYTE rgbReserved;
};

struct tagBITMAPINFO {
    BITMAPINFOHEADER bmiHeader;
    RGBQUAD bmiColors[1];
};

typedef struct tagBITMAPINFO BITMAPINFO;

typedef struct tagLOGPALETTE tagLOGPALETTE, *PtagLOGPALETTE;

typedef struct tagLOGPALETTE LOGPALETTE;

typedef struct tagPALETTEENTRY tagPALETTEENTRY, *PtagPALETTEENTRY;

typedef struct tagPALETTEENTRY PALETTEENTRY;

struct tagPALETTEENTRY {
    BYTE peRed;
    BYTE peGreen;
    BYTE peBlue;
    BYTE peFlags;
};

struct tagLOGPALETTE {
    WORD palVersion;
    WORD palNumEntries;
    PALETTEENTRY palPalEntry[1];
};

typedef struct tagLOGFONTA LOGFONTA;

typedef struct _MEMORY_BASIC_INFORMATION _MEMORY_BASIC_INFORMATION, *P_MEMORY_BASIC_INFORMATION;

typedef void *PVOID;

typedef ulong ULONG_PTR;

typedef ULONG_PTR SIZE_T;

struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
};

typedef CHAR *LPCSTR;

typedef struct _MEMORY_BASIC_INFORMATION *PMEMORY_BASIC_INFORMATION;

typedef LONG *PLONG;

typedef DWORD ACCESS_MASK;

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

typedef uint UINT_PTR;

typedef long LONG_PTR;

typedef struct tagPOINT tagPOINT, *PtagPOINT;

typedef struct tagPOINT *LPPOINT;

struct tagPOINT {
    LONG x;
    LONG y;
};

typedef struct HFONT__ HFONT__, *PHFONT__;

struct HFONT__ {
    int unused;
};

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef struct HBRUSH__ HBRUSH__, *PHBRUSH__;

struct HBRUSH__ {
    int unused;
};

typedef struct tagSIZE tagSIZE, *PtagSIZE;

struct tagSIZE {
    LONG cx;
    LONG cy;
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef struct HPALETTE__ HPALETTE__, *PHPALETTE__;

struct HPALETTE__ {
    int unused;
};

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef HANDLE HLOCAL;

typedef struct tagRECT tagRECT, *PtagRECT;

typedef struct tagRECT RECT;

struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

typedef struct HICON__ HICON__, *PHICON__;

struct HICON__ {
    int unused;
};

typedef struct HRGN__ HRGN__, *PHRGN__;

typedef struct HRGN__ *HRGN;

struct HRGN__ {
    int unused;
};

typedef LONG_PTR LRESULT;

typedef struct tagRECT *LPRECT;

typedef void *HGDIOBJ;

typedef struct HKEY__ *HKEY;

typedef struct HICON__ *HICON;

typedef HICON HCURSOR;

typedef struct HBRUSH__ *HBRUSH;

typedef uint UINT;

typedef struct HFONT__ *HFONT;

typedef UINT_PTR WPARAM;

typedef DWORD *LPDWORD;

typedef struct HPALETTE__ *HPALETTE;

typedef LONG_PTR LPARAM;

typedef struct HDC__ HDC__, *PHDC__;

struct HDC__ {
    int unused;
};

typedef struct tagSIZE *LPSIZE;

typedef struct HDC__ *HDC;

typedef HKEY *PHKEY;

typedef int HFILE;

typedef HANDLE HGLOBAL;

typedef void *LPCVOID;

typedef struct tagPOINT POINT;

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

typedef struct CDC CDC, *PCDC;

struct CDC { // PlaceHolder Structure
};

typedef struct CWinThread CWinThread, *PCWinThread;

struct CWinThread { // PlaceHolder Structure
};

typedef struct CStatic CStatic, *PCStatic;

struct CStatic { // PlaceHolder Structure
};

typedef struct long_(__stdcall**)(struct_HWND__*,unsigned_int,unsigned_int,long) long_(__stdcall**)(struct_HWND__*,unsigned_int,unsigned_int,long), *Plong_(__stdcall**)(struct_HWND__*,unsigned_int,unsigned_int,long);

struct long_(__stdcall**)(struct_HWND__*,unsigned_int,unsigned_int,long) { // PlaceHolder Structure
};

typedef struct CArchive CArchive, *PCArchive;

struct CArchive { // PlaceHolder Structure
};

typedef struct __POSITION __POSITION, *P__POSITION;

struct __POSITION { // PlaceHolder Structure
};

typedef struct _GUID _GUID, *P_GUID;

struct _GUID { // PlaceHolder Structure
};

typedef struct CDataExchange CDataExchange, *PCDataExchange;

struct CDataExchange { // PlaceHolder Structure
};

typedef struct AFX_EVENTSINKMAP AFX_EVENTSINKMAP, *PAFX_EVENTSINKMAP;

struct AFX_EVENTSINKMAP { // PlaceHolder Structure
};

typedef struct AFX_CMDHANDLERINFO AFX_CMDHANDLERINFO, *PAFX_CMDHANDLERINFO;

struct AFX_CMDHANDLERINFO { // PlaceHolder Structure
};

typedef struct AFX_CONNECTIONMAP AFX_CONNECTIONMAP, *PAFX_CONNECTIONMAP;

struct AFX_CONNECTIONMAP { // PlaceHolder Structure
};

typedef struct AFX_MAINTAIN_STATE2 AFX_MAINTAIN_STATE2, *PAFX_MAINTAIN_STATE2;

struct AFX_MAINTAIN_STATE2 { // PlaceHolder Structure
};

typedef struct CScrollBar CScrollBar, *PCScrollBar;

struct CScrollBar { // PlaceHolder Structure
};

typedef struct IConnectionPoint IConnectionPoint, *PIConnectionPoint;

struct IConnectionPoint { // PlaceHolder Structure
};

typedef struct tagVARIANT tagVARIANT, *PtagVARIANT;

struct tagVARIANT { // PlaceHolder Structure
};

typedef struct AFX_DISPMAP AFX_DISPMAP, *PAFX_DISPMAP;

struct AFX_DISPMAP { // PlaceHolder Structure
};

typedef struct CHyperLink CHyperLink, *PCHyperLink;

struct CHyperLink { // PlaceHolder Structure
};

typedef struct CString CString, *PCString;

struct CString { // PlaceHolder Structure
};

typedef struct sockaddr sockaddr, *Psockaddr;

struct sockaddr { // PlaceHolder Structure
};

typedef struct CAsyncSocket CAsyncSocket, *PCAsyncSocket;

struct CAsyncSocket { // PlaceHolder Structure
};

typedef struct CTypeLibCache CTypeLibCache, *PCTypeLibCache;

struct CTypeLibCache { // PlaceHolder Structure
};

typedef struct CDIBStatic CDIBStatic, *PCDIBStatic;

struct CDIBStatic { // PlaceHolder Structure
};

typedef struct CTypeLibCacheMap CTypeLibCacheMap, *PCTypeLibCacheMap;

struct CTypeLibCacheMap { // PlaceHolder Structure
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef struct CSharedFile CSharedFile, *PCSharedFile;

struct CSharedFile { // PlaceHolder Structure
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

typedef struct STRING STRING, *PSTRING;

struct STRING { // PlaceHolder Structure
};

typedef struct CWinApp CWinApp, *PCWinApp;

struct CWinApp { // PlaceHolder Structure
};

typedef struct CDib CDib, *PCDib;

struct CDib { // PlaceHolder Structure
};

typedef struct AFX_EXTENSION_MODULE AFX_EXTENSION_MODULE, *PAFX_EXTENSION_MODULE;

struct AFX_EXTENSION_MODULE { // PlaceHolder Structure
};

typedef struct CToolTipCtrl CToolTipCtrl, *PCToolTipCtrl;

struct CToolTipCtrl { // PlaceHolder Structure
};

typedef struct IUnknown IUnknown, *PIUnknown;

struct IUnknown { // PlaceHolder Structure
};

typedef struct CFont CFont, *PCFont;

struct CFont { // PlaceHolder Structure
};

typedef struct tagMSG tagMSG, *PtagMSG;

struct tagMSG { // PlaceHolder Structure
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

typedef struct ITypeLib ITypeLib, *PITypeLib;

struct ITypeLib { // PlaceHolder Structure
};

typedef struct _AFX_OCC_DIALOG_INFO _AFX_OCC_DIALOG_INFO, *P_AFX_OCC_DIALOG_INFO;

struct _AFX_OCC_DIALOG_INFO { // PlaceHolder Structure
};

typedef struct _AFX_THREAD_STATE _AFX_THREAD_STATE, *P_AFX_THREAD_STATE;

struct _AFX_THREAD_STATE { // PlaceHolder Structure
};

typedef struct tagTOOLINFOA tagTOOLINFOA, *PtagTOOLINFOA;

struct tagTOOLINFOA { // PlaceHolder Structure
};

typedef struct LIST<struct_HWND__*> LIST<struct_HWND__*>, *PLIST<struct_HWND__*>;

struct LIST<struct_HWND__*> { // PlaceHolder Structure
};

typedef struct CPlex CPlex, *PCPlex;

struct CPlex { // PlaceHolder Structure
};

typedef struct CClientDC CClientDC, *PCClientDC;

struct CClientDC { // PlaceHolder Structure
};

typedef struct CFile CFile, *PCFile;

struct CFile { // PlaceHolder Structure
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

typedef struct CPalette CPalette, *PCPalette;

struct CPalette { // PlaceHolder Structure
};

typedef struct CWnd CWnd, *PCWnd;

struct CWnd { // PlaceHolder Structure
};

typedef struct LIST<class_CString> LIST<class_CString>, *PLIST<class_CString>;

struct LIST<class_CString> { // PlaceHolder Structure
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

typedef struct CFileFind CFileFind, *PCFileFind;

struct CFileFind { // PlaceHolder Structure
};

typedef struct LIST<class_INIFILE*> LIST<class_INIFILE*>, *PLIST<class_INIFILE*>;

struct LIST<class_INIFILE*> { // PlaceHolder Structure
};

typedef struct INIFILE INIFILE, *PINIFILE;

struct INIFILE { // PlaceHolder Structure
};

typedef struct CObject CObject, *PCObject;

struct CObject { // PlaceHolder Structure
};

typedef struct CPoint CPoint, *PCPoint;

struct CPoint { // PlaceHolder Structure
};

typedef enum DIRECTION {
} DIRECTION;

typedef struct SECTION SECTION, *PSECTION;

struct SECTION { // PlaceHolder Structure
};

typedef int (*_onexit_t)(void);




// public: __thiscall CDIBStatic::CDIBStatic(void)

CDIBStatic * __thiscall CDIBStatic::CDIBStatic(CDIBStatic *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x1000  1  ??0CDIBStatic@@QAE@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a1a9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10001870((CWnd *)this);
  local_8 = 0;
  CDib::CDib((CDib *)(this + 0x40));
  *(undefined ***)this = &PTR_LAB_1000b4e8;
  ExceptionList = local_10;
  return this;
}



// public: virtual __thiscall CDIBStatic::~CDIBStatic(void)

void __thiscall CDIBStatic::~CDIBStatic(CDIBStatic *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x1057  7  ??1CDIBStatic@@UAE@XZ
  puStack_c = &LAB_1000a1bc;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)this = &PTR_LAB_1000b4e8;
  local_8 = 0;
  CDib::~CDib((CDib *)(this + 0x40));
  local_8 = 0xffffffff;
  CStatic::~CStatic((CStatic *)this);
  ExceptionList = local_10;
  return;
}



undefined * FUN_100010ab(void)

{
  return messageMap_exref;
}



undefined ** FUN_100010b5(void)

{
  return &PTR_FUN_1000b480;
}



// public: int __thiscall CDIBStatic::LoadDib(char const *)

int __thiscall CDIBStatic::LoadDib(CDIBStatic *this,char *param_1)

{
  int iVar1;
  CFile local_24 [16];
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x10c5  63  ?LoadDib@CDIBStatic@@QAEHPBD@Z
  puStack_c = &LAB_1000a1cf;
  local_10 = ExceptionList;
  local_14 = &stack0xffffffb8;
  local_8 = 0;
  ExceptionList = &local_10;
  CFile::CFile(local_24,param_1,0);
  local_8._0_1_ = 1;
  LoadDib(this,local_24);
  local_8 = (uint)local_8._1_3_ << 8;
  CFile::~CFile(local_24);
  iVar1 = FUN_10001144();
  return iVar1;
}



undefined * Catch_1000112c(void)

{
  int unaff_EBP;
  
  CException::Delete(*(CException **)(unaff_EBP + -0x24));
  *(undefined4 *)(unaff_EBP + -0x2c) = 0;
  return &DAT_10001141;
}



void FUN_10001144(void)

{
  int unaff_EBP;
  
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



// public: int __thiscall CDIBStatic::LoadDib(class CFile &)

int __thiscall CDIBStatic::LoadDib(CDIBStatic *this,CFile *param_1)

{
  ulong uVar1;
  uint local_8;
  
                    // 0x1157  62  ?LoadDib@CDIBStatic@@QAEHAAVCFile@@@Z
  uVar1 = CDib::Read((CDib *)(this + 0x40),param_1);
  local_8 = (uint)(uVar1 != 0);
  FUN_10001517(this,0);
  UpdateDib(this);
  return local_8;
}



// protected: void __thiscall CDIBStatic::ClearDib(void)

void __thiscall CDIBStatic::ClearDib(CDIBStatic *this)

{
  HGDIOBJ pvVar1;
  tagRECT local_38;
  CClientDC local_28 [20];
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x119c  17  ?ClearDib@CDIBStatic@@IAEXXZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a1e2;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CClientDC::CClientDC(local_28,(CWnd *)this);
  local_8 = 0;
  FUN_10004b30(&local_38);
  FUN_10001800(this,&local_38);
  FUN_10001720(&local_38,-1,-1);
  pvVar1 = GetStockObject(1);
  local_14 = FUN_10001740(pvVar1);
  FUN_100017a0(local_28,&local_38,local_14);
  local_8 = 0xffffffff;
  CClientDC::~CClientDC(local_28);
  ExceptionList = local_10;
  return;
}



// protected: void __thiscall CDIBStatic::PaintDib(int)

void __thiscall CDIBStatic::PaintDib(CDIBStatic *this,int param_1)

{
  ulong uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  ulong uVar5;
  HDC__ *pHVar6;
  tagRECT *ptVar7;
  tagRECT *ptVar8;
  ulong local_64;
  ulong local_60;
  int local_5c;
  int local_58;
  tagRECT local_54;
  tagRECT local_44;
  CClientDC local_34 [20];
  tagRECT local_20;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x122b  71  ?PaintDib@CDIBStatic@@IAEXH@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a1f5;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  ClearDib(this);
  FUN_10004b30(&local_20);
  FUN_10001800(this,&local_20);
  FUN_10001720(&local_20,-1,-1);
  CClientDC::CClientDC(local_34,(CWnd *)this);
  local_8 = 0;
  if (param_1 == 0) goto LAB_10001492;
  uVar1 = CDib::Width((CDib *)(this + 0x40));
  uVar2 = FUN_100016e0(&local_20.left);
  if (uVar1 < uVar2) {
    uVar1 = CDib::Height((CDib *)(this + 0x40));
    uVar2 = FUN_10001700((int)&local_20);
    if (uVar2 <= uVar1) goto LAB_10001324;
    iVar3 = FUN_100016e0(&local_20.left);
    uVar1 = CDib::Width((CDib *)(this + 0x40));
    local_58 = local_20.left + (iVar3 - uVar1 >> 1);
    iVar3 = FUN_10001700((int)&local_20);
    uVar1 = CDib::Height((CDib *)(this + 0x40));
    local_5c = local_20.top + (iVar3 - uVar1 >> 1);
    local_64 = CDib::Height((CDib *)(this + 0x40));
    local_60 = CDib::Width((CDib *)(this + 0x40));
  }
  else {
LAB_10001324:
    iVar3 = FUN_100016e0(&local_20.left);
    uVar1 = CDib::Width((CDib *)(this + 0x40));
    iVar4 = FUN_10001700((int)&local_20);
    uVar5 = CDib::Height((CDib *)(this + 0x40));
    if ((float)iVar4 / (float)uVar5 < (float)iVar3 / (float)uVar1) {
      local_60 = FUN_10001700((int)&local_20);
      uVar1 = CDib::Width((CDib *)(this + 0x40));
      local_64 = CDib::Height((CDib *)(this + 0x40));
      local_64 = (local_60 * uVar1) / local_64;
      iVar3 = FUN_100016e0(&local_20.left);
      local_58 = local_20.left + (int)(iVar3 - local_64) / 2;
      local_5c = local_20.top;
    }
    else {
      local_64 = FUN_100016e0(&local_20.left);
      uVar1 = CDib::Height((CDib *)(this + 0x40));
      local_60 = CDib::Width((CDib *)(this + 0x40));
      local_60 = (local_64 * uVar1) / local_60;
      local_58 = local_20.left;
      iVar3 = FUN_10001700((int)&local_20);
      local_5c = local_20.top + (int)(iVar3 - local_60) / 2;
    }
  }
  FUN_100016a0(&local_54,local_58,local_5c,local_58 + local_64,local_5c + local_60);
  uVar1 = CDib::Height((CDib *)(this + 0x40));
  uVar5 = CDib::Width((CDib *)(this + 0x40));
  FUN_100016a0(&local_44,0,0,uVar5,uVar1);
  ptVar8 = &local_44;
  ptVar7 = &local_54;
  pHVar6 = (HDC__ *)FUN_10001750((int)local_34);
  CDib::Paint((CDib *)(this + 0x40),pHVar6,ptVar7,ptVar8);
LAB_10001492:
  local_8 = 0xffffffff;
  CClientDC::~CClientDC(local_34);
  ExceptionList = local_10;
  return;
}



// public: void __thiscall CDIBStatic::UpdateDib(void)

void __thiscall CDIBStatic::UpdateDib(CDIBStatic *this)

{
  int iVar1;
  
                    // 0x14b2  99  ?UpdateDib@CDIBStatic@@QAEXXZ
  iVar1 = FUN_100018c0((int)this);
  PaintDib(this,iVar1);
  return;
}



void __fastcall FUN_100014ce(CDIBStatic *param_1)

{
  CDIBStatic::UpdateDib(param_1);
  GetStockObject(5);
  return;
}



void __fastcall FUN_100014eb(void *param_1)

{
  FUN_10001517(param_1,0);
  return;
}



void __fastcall FUN_10001500(void *param_1)

{
  FUN_10001517(param_1,1);
  return;
}



undefined4 __thiscall FUN_10001517(void *this,BOOL param_1)

{
  int iVar1;
  HDC pHVar2;
  HPALETTE pHVar3;
  BOOL bForceBkgd;
  CClientDC local_2c [20];
  HPALETTE local_18;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_1000a208;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  iVar1 = FUN_100018c0((int)this);
  if (iVar1 != 0) {
    CClientDC::CClientDC(local_2c,(CWnd *)this);
    local_8 = 0;
    if (*(int *)((int)this + 0x4c) == 0) {
      local_8 = 0xffffffff;
      CClientDC::~CClientDC(local_2c);
      ExceptionList = local_10;
      return 0;
    }
    pHVar3 = *(HPALETTE *)(*(int *)((int)this + 0x4c) + 4);
    local_18 = pHVar3;
    pHVar2 = (HDC)FUN_10001750((int)local_2c);
    pHVar3 = SelectPalette(pHVar2,pHVar3,param_1);
    local_14 = FUN_10001780((int)local_2c);
    bForceBkgd = 1;
    pHVar2 = (HDC)FUN_10001750((int)local_2c);
    SelectPalette(pHVar2,pHVar3,bForceBkgd);
    if (local_14 == 0) {
      local_8 = 0xffffffff;
      CClientDC::~CClientDC(local_2c);
      ExceptionList = local_10;
      return 0;
    }
    CDIBStatic::UpdateDib((CDIBStatic *)this);
    local_8 = 0xffffffff;
    CClientDC::~CClientDC(local_2c);
  }
  ExceptionList = local_10;
  return 1;
}



void * __thiscall FUN_10001620(void *this,uint param_1)

{
  CDIBStatic::~CDIBStatic((CDIBStatic *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001660(this);
  }
  return this;
}



void FUN_10001650(void)

{
  return;
}



void FUN_10001660(void *param_1)

{
  operator_delete(param_1);
  return;
}



void FUN_10001680(void)

{
  return;
}



void FUN_10001690(void)

{
  return;
}



void * __thiscall
FUN_100016a0(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  *(undefined4 *)this = param_1;
  *(undefined4 *)((int)this + 4) = param_2;
  *(undefined4 *)((int)this + 8) = param_3;
  *(undefined4 *)((int)this + 0xc) = param_4;
  return this;
}



int __fastcall FUN_100016e0(int *param_1)

{
  return param_1[2] - *param_1;
}



int __fastcall FUN_10001700(int param_1)

{
  return *(int *)(param_1 + 0xc) - *(int *)(param_1 + 4);
}



void __thiscall FUN_10001720(void *this,int param_1,int param_2)

{
  InflateRect((LPRECT)this,param_1,param_2);
  return;
}



void FUN_10001740(void *param_1)

{
  CGdiObject::FromHandle(param_1);
  return;
}



undefined4 __fastcall FUN_10001750(int param_1)

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



void __fastcall FUN_10001780(int param_1)

{
  RealizePalette(*(HDC *)(param_1 + 4));
  return;
}



void __thiscall FUN_100017a0(void *this,RECT *param_1,int param_2)

{
  HBRUSH hbr;
  
  hbr = (HBRUSH)FUN_100017d0(param_2);
  FillRect(*(HDC *)((int)this + 4),param_1,hbr);
  return;
}



undefined4 __fastcall FUN_100017d0(int param_1)

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



void __thiscall FUN_10001800(void *this,LPRECT param_1)

{
  GetClientRect(*(HWND *)((int)this + 0x20),param_1);
  return;
}



void FUN_10001820(void)

{
  return;
}



void __fastcall FUN_10001830(int param_1)

{
  EnableWindow(*(HWND *)(param_1 + 0x20),0);
  return;
}



void __fastcall FUN_10001850(int param_1)

{
  EnableWindow(*(HWND *)(param_1 + 0x20),1);
  return;
}



CWnd * __fastcall FUN_10001870(CWnd *param_1)

{
  CWnd::CWnd(param_1);
  *(undefined ***)param_1 = &PTR_LAB_1000b5a8;
  return param_1;
}



void * __thiscall FUN_10001890(void *this,uint param_1)

{
  CStatic::~CStatic((CStatic *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001660(this);
  }
  return this;
}



void __fastcall FUN_100018c0(int param_1)

{
  FUN_100018e0(param_1 + 0x40);
  return;
}



bool __fastcall FUN_100018e0(int param_1)

{
  return *(int *)(param_1 + 8) != 0;
}



// public: __thiscall CHyperLink::CHyperLink(void)

CHyperLink * __thiscall CHyperLink::CHyperLink(CHyperLink *this)

{
  DWORD DVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x1900  3  ??0CHyperLink@@QAE@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a24d;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10001870((CWnd *)this);
  local_8 = 0;
  CString::CString((CString *)(this + 0x5c));
  local_8._0_1_ = 1;
  FUN_100027d0((CGdiObject *)(this + 0x60));
  local_8._0_1_ = 2;
  CToolTipCtrl::CToolTipCtrl((CToolTipCtrl *)(this + 0x6c));
  local_8 = CONCAT31(local_8._1_3_,3);
  *(undefined ***)this = &_vftable_;
  *(undefined4 *)(this + 0x68) = 0;
  *(undefined4 *)(this + 0x40) = 0xee0000;
  *(undefined4 *)(this + 0x44) = 0x8b1a55;
  DVar1 = GetSysColor(0xd);
  *(DWORD *)(this + 0x48) = DVar1;
  *(undefined4 *)(this + 0x4c) = 0;
  *(undefined4 *)(this + 0x50) = 0;
  *(undefined4 *)(this + 0x54) = 1;
  *(undefined4 *)(this + 0x58) = 1;
  CString::Empty((CString *)(this + 0x5c));
  ExceptionList = local_10;
  return this;
}



// public: virtual __thiscall CHyperLink::~CHyperLink(void)

void __thiscall CHyperLink::~CHyperLink(CHyperLink *this)

{
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x19d8  9  ??1CHyperLink@@UAE@XZ
  puStack_c = &LAB_1000a284;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)this = &_vftable_;
  local_8 = 3;
  CGdiObject::DeleteObject(this);
  local_8._0_1_ = 2;
  CToolTipCtrl::~CToolTipCtrl((CToolTipCtrl *)(this + 0x6c));
  local_8._0_1_ = 1;
  FUN_10002950((undefined4 *)(this + 0x60));
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString((CString *)(this + 0x5c));
  local_8 = 0xffffffff;
  CStatic::~CStatic((CStatic *)this);
  ExceptionList = local_10;
  return;
}



// protected: static struct AFX_MSGMAP const * __stdcall CHyperLink::_GetBaseMessageMap(void)

AFX_MSGMAP * CHyperLink::_GetBaseMessageMap(void)

{
                    // 0x1a59  102  ?_GetBaseMessageMap@CHyperLink@@KGPBUAFX_MSGMAP@@XZ
  return (AFX_MSGMAP *)messageMap_exref;
}



// protected: virtual struct AFX_MSGMAP const * __thiscall CHyperLink::GetMessageMap(void)const 

AFX_MSGMAP * __thiscall CHyperLink::GetMessageMap(CHyperLink *this)

{
                    // 0x1a63  43  ?GetMessageMap@CHyperLink@@MBEPBUAFX_MSGMAP@@XZ
  return (AFX_MSGMAP *)&messageMap;
}



// public: virtual int __thiscall CHyperLink::PreTranslateMessage(struct tagMSG *)

int __thiscall CHyperLink::PreTranslateMessage(CHyperLink *this,tagMSG *param_1)

{
  int iVar1;
  
                    // 0x1a73  75  ?PreTranslateMessage@CHyperLink@@UAEHPAUtagMSG@@@Z
  FUN_10002c00(this + 0x6c,(LPARAM)param_1);
  iVar1 = CWnd::PreTranslateMessage((CWnd *)this,param_1);
  return iVar1;
}



// protected: void __thiscall CHyperLink::OnClicked(void)

void __thiscall CHyperLink::OnClicked(CHyperLink *this)

{
  char *pcVar1;
  DWORD DVar2;
  int iVar3;
  
                    // 0x1a9b  67  ?OnClicked@CHyperLink@@IAEXXZ
  iVar3 = 5;
  pcVar1 = (char *)FUN_10004990((undefined4 *)(this + 0x5c));
  iVar3 = GotoURL(this,pcVar1,iVar3);
  if (iVar3 == 0) {
    MessageBeep(0x30);
    DVar2 = GetLastError();
    ReportError(this,DVar2);
  }
  else {
    SetVisited(this,1);
  }
  return;
}



// protected: struct HBRUSH__ * __thiscall CHyperLink::CtlColor(class CDC *,unsigned int)

HBRUSH__ * __thiscall CHyperLink::CtlColor(CHyperLink *this,CDC *param_1,uint param_2)

{
  HBRUSH__ *pHVar1;
  int mode;
  
                    // 0x1aea  21  ?CtlColor@CHyperLink@@IAEPAUHBRUSH__@@PAVCDC@@I@Z
  if (*(int *)(this + 0x4c) == 0) {
    if (*(int *)(this + 0x50) == 0) {
      mode = *(int *)(this + 0x40);
      (**(code **)(*(int *)param_1 + 0x38))();
    }
    else {
      mode = *(int *)(this + 0x44);
      (**(code **)(*(int *)param_1 + 0x38))();
    }
  }
  else {
    mode = *(int *)(this + 0x48);
    (**(code **)(*(int *)param_1 + 0x38))();
  }
  CDC::SetBkMode((HDC)0x1,mode);
  pHVar1 = (HBRUSH__ *)GetStockObject(5);
  return pHVar1;
}



// protected: void __thiscall CHyperLink::OnMouseMove(unsigned int,class CPoint)

void __thiscall
CHyperLink::OnMouseMove(CHyperLink *this,undefined4 param_1,LONG param_3,LONG param_4)

{
  LPRECT ptVar1;
  int iVar2;
  undefined1 local_14 [16];
  
                    // 0x1b55  68  ?OnMouseMove@CHyperLink@@IAEXIVCPoint@@@Z
  FUN_10002be0((CWnd *)this);
  if (*(int *)(this + 0x4c) == 0) {
    *(undefined4 *)(this + 0x4c) = 1;
    FUN_10002b70(this,(RECT *)0x0,0,0x105);
    FUN_10002ba0((int)this);
  }
  else {
    FUN_10004b30(local_14);
    ptVar1 = (LPRECT)FUN_10002770(local_14);
    FUN_10001800(this,ptVar1);
    iVar2 = FUN_10002780(local_14,param_3,param_4);
    if (iVar2 == 0) {
      *(undefined4 *)(this + 0x4c) = 0;
      ReleaseCapture();
      FUN_10002b70(this,(RECT *)0x0,0,0x105);
    }
  }
  return;
}



// protected: int __thiscall CHyperLink::OnSetCursor(class CWnd *,unsigned int,unsigned int)

int __thiscall CHyperLink::OnSetCursor(CHyperLink *this,CWnd *param_1,uint param_2,uint param_3)

{
  int iVar1;
  
                    // 0x1c02  69  ?OnSetCursor@CHyperLink@@IAEHPAVCWnd@@II@Z
  iVar1 = *(int *)(this + 0x68);
  if (iVar1 != 0) {
    SetCursor(*(HCURSOR *)(this + 0x68));
  }
  return (uint)(iVar1 != 0);
}



// protected: virtual void __thiscall CHyperLink::PreSubclassWindow(void)

void __thiscall CHyperLink::PreSubclassWindow(CHyperLink *this)

{
  bool bVar1;
  ulong nMaxCount;
  HWND pHVar2;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  void *this_00;
  LPRECT ptVar3;
  tagRECT *ptVar4;
  char *pcVar5;
  int nIndex;
  LOGFONTA *pLVar6;
  uint uVar7;
  LOGFONTA local_60;
  HWND__ local_24;
  undefined1 local_20 [16];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x1c2e  74  ?PreSubclassWindow@CHyperLink@@MAEXXZ
  local_8 = 0xffffffff;
  puStack_c = &dwNewLong_1000a297;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  nMaxCount = CWnd::GetStyle((CWnd *)this);
  uVar7 = nMaxCount | 0x100;
  nIndex = -0x10;
  pHVar2 = (HWND)FUN_10002a40((int)this);
  SetWindowLongA(pHVar2,nIndex,uVar7);
  bVar1 = FUN_10002730((int *)(this + 0x5c));
  if (CONCAT31(extraout_var,bVar1) != 0) {
    CWnd::GetWindowTextA((HWND)(this + 0x5c),(LPSTR)this,nMaxCount);
  }
  CString::CString((CString *)&local_24);
  local_8 = 0;
  CWnd::GetWindowTextA(&local_24,(LPSTR)this,nMaxCount);
  bVar1 = FUN_10002730(&local_24.unused);
  if (CONCAT31(extraout_var_00,bVar1) != 0) {
    pHVar2 = (HWND)FUN_10004990((undefined4 *)(this + 0x5c));
    CWnd::SetWindowTextA(pHVar2,(LPCSTR)this);
  }
  pLVar6 = &local_60;
  this_00 = (void *)FUN_10002aa0((int)this);
  FUN_10002990(this_00,pLVar6);
  local_60.lfUnderline = *(BYTE *)(this + 0x54);
  FUN_10002970(this + 0x60,&local_60);
  FUN_10002a70(this,(int)(this + 0x60),1);
  PositionWindow(this);
  SetDefaultCursor(this);
  FUN_10004b30(local_20);
  ptVar3 = (LPRECT)FUN_10002770(local_20);
  FUN_10001800(this,ptVar3);
  CToolTipCtrl::Create((CToolTipCtrl *)((CWnd *)this + 0x6c),(CWnd *)this,0);
  uVar7 = 1;
  ptVar4 = (tagRECT *)FUN_10002770(local_20);
  pcVar5 = (char *)FUN_10004990((undefined4 *)((CWnd *)this + 0x5c));
  CToolTipCtrl::AddTool((CToolTipCtrl *)((CWnd *)this + 0x6c),(CWnd *)this,pcVar5,ptVar4,uVar7);
  CWnd::PreSubclassWindow((CWnd *)this);
  local_8 = 0xffffffff;
  CString::~CString((CString *)&local_24);
  ExceptionList = local_10;
  return;
}



// public: void __thiscall CHyperLink::SetURL(class CString)

void __thiscall CHyperLink::SetURL(CHyperLink *this)

{
  HWND hWnd;
  BOOL BVar1;
  char *pcVar2;
  CHyperLink *pCVar3;
  uint uVar4;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x1d89  95  ?SetURL@CHyperLink@@QAEXVCString@@@Z
  puStack_c = &LAB_1000a2aa;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  CString::operator=((CString *)(this + 0x5c),(CString *)&stack0x00000004);
  hWnd = (HWND)FUN_10002a40((int)this);
  BVar1 = IsWindow(hWnd);
  if (BVar1 != 0) {
    PositionWindow(this);
    uVar4 = 1;
    pCVar3 = this;
    pcVar2 = (char *)FUN_10004990((undefined4 *)&stack0x00000004);
    CToolTipCtrl::UpdateTipText((CToolTipCtrl *)(this + 0x6c),pcVar2,(CWnd *)pCVar3,uVar4);
  }
  local_8 = 0xffffffff;
  CString::~CString((CString *)&stack0x00000004);
  ExceptionList = local_10;
  return;
}



// public: class CString __thiscall CHyperLink::GetURL(void)const 

CString * __thiscall CHyperLink::GetURL(CHyperLink *this)

{
  CString *in_stack_00000004;
  
                    // 0x1e0f  53  ?GetURL@CHyperLink@@QBE?AVCString@@XZ
  CString::CString(in_stack_00000004,(CString *)(this + 0x5c));
  return in_stack_00000004;
}



// public: void __thiscall CHyperLink::SetColours(unsigned long,unsigned long,unsigned long)

void __thiscall CHyperLink::SetColours(CHyperLink *this,ulong param_1,ulong param_2,ulong param_3)

{
  DWORD DVar1;
  BOOL BVar2;
  
                    // 0x1e40  92  ?SetColours@CHyperLink@@QAEXKKK@Z
  *(ulong *)(this + 0x40) = param_1;
  *(ulong *)(this + 0x44) = param_2;
  if (param_3 == 0xffffffff) {
    DVar1 = GetSysColor(0xd);
    *(DWORD *)(this + 0x48) = DVar1;
  }
  else {
    *(ulong *)(this + 0x48) = param_3;
  }
  BVar2 = IsWindow(*(HWND *)(this + 0x20));
  if (BVar2 != 0) {
    FUN_10002b50(this,1);
  }
  return;
}



// public: unsigned long __thiscall CHyperLink::GetLinkColour(void)const 

ulong __thiscall CHyperLink::GetLinkColour(CHyperLink *this)

{
                    // 0x1e99  41  ?GetLinkColour@CHyperLink@@QBEKXZ
  return *(ulong *)(this + 0x40);
}



// public: unsigned long __thiscall CHyperLink::GetVisitedColour(void)const 

ulong __thiscall CHyperLink::GetVisitedColour(CHyperLink *this)

{
                    // 0x1eaa  57  ?GetVisitedColour@CHyperLink@@QBEKXZ
  return *(ulong *)(this + 0x44);
}



// public: unsigned long __thiscall CHyperLink::GetHoverColour(void)const 

ulong __thiscall CHyperLink::GetHoverColour(CHyperLink *this)

{
                    // 0x1ebb  40  ?GetHoverColour@CHyperLink@@QBEKXZ
  return *(ulong *)(this + 0x48);
}



// public: void __thiscall CHyperLink::SetVisited(int)

void __thiscall CHyperLink::SetVisited(CHyperLink *this,int param_1)

{
  HWND hWnd;
  BOOL BVar1;
  
                    // 0x1ecc  97  ?SetVisited@CHyperLink@@QAEXH@Z
  *(int *)(this + 0x50) = param_1;
  hWnd = (HWND)FUN_10002a40((int)this);
  BVar1 = IsWindow(hWnd);
  if (BVar1 != 0) {
    FUN_10002b50(this,1);
  }
  return;
}



// public: int __thiscall CHyperLink::GetVisited(void)const 

int __thiscall CHyperLink::GetVisited(CHyperLink *this)

{
                    // 0x1eff  56  ?GetVisited@CHyperLink@@QBEHXZ
  return *(int *)(this + 0x50);
}



// public: void __thiscall CHyperLink::SetLinkCursor(struct HICON__ *)

void __thiscall CHyperLink::SetLinkCursor(CHyperLink *this,HICON__ *param_1)

{
                    // 0x1f10  94  ?SetLinkCursor@CHyperLink@@QAEXPAUHICON__@@@Z
  *(HICON__ **)(this + 0x68) = param_1;
  if (*(int *)(this + 0x68) == 0) {
    SetDefaultCursor(this);
  }
  return;
}



// public: struct HICON__ * __thiscall CHyperLink::GetLinkCursor(void)const 

HICON__ * __thiscall CHyperLink::GetLinkCursor(CHyperLink *this)

{
                    // 0x1f37  42  ?GetLinkCursor@CHyperLink@@QBEPAUHICON__@@XZ
  return *(HICON__ **)(this + 0x68);
}



// public: void __thiscall CHyperLink::SetUnderline(int)

void __thiscall CHyperLink::SetUnderline(CHyperLink *this,int param_1)

{
  HWND hWnd;
  BOOL BVar1;
  void *this_00;
  LOGFONTA *pLVar2;
  LOGFONTA local_40;
  
                    // 0x1f48  96  ?SetUnderline@CHyperLink@@QAEXH@Z
  *(int *)(this + 0x54) = param_1;
  hWnd = (HWND)FUN_10002a40((int)this);
  BVar1 = IsWindow(hWnd);
  if (BVar1 != 0) {
    pLVar2 = &local_40;
    this_00 = (void *)FUN_10002aa0((int)this);
    FUN_10002990(this_00,pLVar2);
    local_40.lfUnderline = *(BYTE *)(this + 0x54);
    CGdiObject::DeleteObject(this);
    FUN_10002970(this + 0x60,&local_40);
    FUN_10002a70(this,(int)(this + 0x60),1);
    FUN_10002b50(this,1);
  }
  return;
}



// public: int __thiscall CHyperLink::GetUnderline(void)const 

int __thiscall CHyperLink::GetUnderline(CHyperLink *this)

{
                    // 0x1fc4  54  ?GetUnderline@CHyperLink@@QBEHXZ
  return *(int *)(this + 0x54);
}



// public: void __thiscall CHyperLink::SetAutoSize(int)

void __thiscall CHyperLink::SetAutoSize(CHyperLink *this,int param_1)

{
  HWND hWnd;
  BOOL BVar1;
  
                    // 0x1fd5  91  ?SetAutoSize@CHyperLink@@QAEXH@Z
  *(int *)(this + 0x58) = param_1;
  hWnd = (HWND)FUN_10002a40((int)this);
  BVar1 = IsWindow(hWnd);
  if (BVar1 != 0) {
    PositionWindow(this);
  }
  return;
}



// public: int __thiscall CHyperLink::GetAutoSize(void)const 

int __thiscall CHyperLink::GetAutoSize(CHyperLink *this)

{
                    // 0x2006  36  ?GetAutoSize@CHyperLink@@QBEHXZ
  return *(int *)(this + 0x58);
}



// public: void __thiscall CHyperLink::PositionWindow(void)

void __thiscall CHyperLink::PositionWindow(CHyperLink *this)

{
  HWND pHVar1;
  BOOL BVar2;
  LPRECT ptVar3;
  int *this_00;
  ulong uVar4;
  int iVar5;
  int iVar6;
  int cy;
  UINT uFlags;
  int in_stack_ffffffc4;
  HWND__ local_34;
  HWND local_30;
  int local_2c;
  int local_28;
  int local_24;
  UINT local_20;
  int local_1c;
  int local_18;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x2017  73  ?PositionWindow@CHyperLink@@QAEXXZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a2bd;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pHVar1 = (HWND)FUN_10002a40((int)this);
  BVar2 = IsWindow(pHVar1);
  if ((BVar2 != 0) && (((LPPOINT)((int)this + 0x58))->x != 0)) {
    FUN_10004b30(&local_30);
    ptVar3 = (LPRECT)FUN_10002770(&local_30);
    FUN_10002ae0(this,ptVar3);
    local_14 = FUN_10002bc0((int)this);
    if (local_14 != 0) {
      pHVar1 = (HWND)FUN_10002770(&local_30);
      CWnd::ScreenToClient(pHVar1,(LPPOINT)this);
    }
    CString::CString((CString *)&local_34);
    local_8 = 0;
    CWnd::GetWindowTextA(&local_34,(LPSTR)this,in_stack_ffffffc4);
    this_00 = (int *)FUN_10002b00((int)this);
    local_20 = (**(code **)(*this_00 + 0x30))((LPPOINT)((int)this + 0x60));
    FUN_100029b0(this_00,&local_1c,&local_34.unused);
    uFlags = local_20;
    (**(code **)(*this_00 + 0x30))();
    FUN_10002b20(this,(int)this_00);
    uVar4 = CWnd::GetStyle((CWnd *)this);
    if ((uVar4 & 0x200) == 0) {
      local_24 = local_2c + local_18;
    }
    else {
      iVar5 = FUN_10001700((int)&local_30);
      FUN_100027a0(&local_30,0,(iVar5 - local_18) / 2);
    }
    if ((uVar4 & 1) == 0) {
      if ((uVar4 & 2) == 0) {
        local_28 = (int)&local_30->unused + local_1c;
      }
      else {
        local_30 = (HWND)(local_28 - local_1c);
      }
    }
    else {
      iVar6 = 0;
      iVar5 = FUN_100016e0((int *)&local_30);
      FUN_100027a0(&local_30,(iVar5 - local_1c) / 2,iVar6);
    }
    cy = 4;
    iVar5 = FUN_10001700((int)&local_30);
    iVar6 = FUN_100016e0((int *)&local_30);
    CWnd::SetWindowPos((HWND)0x0,local_30,local_2c,iVar6,iVar5,cy,uFlags);
    local_8 = 0xffffffff;
    CString::~CString((CString *)&local_34);
  }
  ExceptionList = local_10;
  return;
}



// public: void __thiscall CHyperLink::SetDefaultCursor(void)

void __thiscall CHyperLink::SetDefaultCursor(CHyperLink *this)

{
  char *lpBuffer;
  LPCSTR lpLibFileName;
  HCURSOR hIcon;
  HICON pHVar1;
  UINT uSize;
  CString local_18 [4];
  HMODULE local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x21bd  93  ?SetDefaultCursor@CHyperLink@@QAEXXZ
  local_8 = 0xffffffff;
  puStack_c = &uSize_1000a2d0;
  local_10 = ExceptionList;
  if (*(int *)(this + 0x68) == 0) {
    ExceptionList = &local_10;
    CString::CString(local_18);
    local_8 = 0;
    uSize = 0x104;
    lpBuffer = CString::GetBuffer(local_18,0x104);
    GetWindowsDirectoryA(lpBuffer,uSize);
    CString::ReleaseBuffer(local_18,-1);
    CString::operator+=(local_18,s__winhlp32_exe_1000f040);
    lpLibFileName = (LPCSTR)FUN_10004990((undefined4 *)local_18);
    local_14 = LoadLibraryA(lpLibFileName);
    if (local_14 != (HMODULE)0x0) {
      hIcon = LoadCursorA(local_14,(LPCSTR)0x6a);
      if (hIcon != (HCURSOR)0x0) {
        pHVar1 = CopyIcon(hIcon);
        *(HICON *)(this + 0x68) = pHVar1;
      }
    }
    FreeLibrary(local_14);
    local_8 = 0xffffffff;
    CString::~CString(local_18);
  }
  ExceptionList = local_10;
  return;
}



// public: long __thiscall CHyperLink::GetRegKey(struct HKEY__ *,char const *,char *)

long __thiscall CHyperLink::GetRegKey(CHyperLink *this,HKEY__ *param_1,char *param_2,char *param_3)

{
  LONG local_114;
  CHAR local_110 [260];
  HKEY local_c;
  LSTATUS local_8;
  
                    // 0x228b  49  ?GetRegKey@CHyperLink@@QAEJPAUHKEY__@@PBDPAD@Z
  local_8 = RegOpenKeyExA(param_1,param_2,0,1,&local_c);
  if (local_8 == 0) {
    local_114 = 0x104;
    RegQueryValueA(local_c,(LPCSTR)0x0,local_110,&local_114);
    lstrcpyA(param_3,local_110);
    RegCloseKey(local_c);
  }
  return local_8;
}



// public: void __thiscall CHyperLink::ReportError(int)

void __thiscall CHyperLink::ReportError(CHyperLink *this,int param_1)

{
  char *pcVar1;
  uint uVar2;
  uint uVar3;
  
                    // 0x2301  87  ?ReportError@CHyperLink@@QAEXH@Z
  uVar3 = 0;
  uVar2 = 0x30;
  pcVar1 = Win32ErrorDesc(param_1);
  AfxMessageBox(pcVar1,uVar2,uVar3);
  return;
}



// public: int __thiscall CHyperLink::GotoURL(char const *,int)

int __thiscall CHyperLink::GotoURL(CHyperLink *this,char *param_1,int param_2)

{
  LPCSTR pCVar1;
  char *pcVar2;
  CString *pCVar3;
  STRING *this_00;
  int iVar4;
  UINT unaff_EDI;
  LPSTR *ppCVar5;
  undefined4 *puVar6;
  size_t _Count;
  char cVar7;
  LPCSTR lpDirectory;
  CHAR *lpResult;
  LPSTR in_stack_fffffc1c;
  CString local_3ac [4];
  CString local_3a8 [4];
  CString local_3a4 [4];
  CString local_3a0 [4];
  uint local_39c;
  CString local_398 [4];
  CString local_394 [4];
  int local_390;
  HINSTANCE local_38c;
  CString local_388 [4];
  BOOL local_384;
  HFILE local_380;
  _STARTUPINFOA local_37c;
  char local_338;
  undefined4 local_337 [130];
  CHAR local_12c;
  undefined4 local_12b;
  char local_28;
  CString local_24 [4];
  _PROCESS_INFORMATION local_20;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x2324  58  ?GotoURL@CHyperLink@@QAEHPBDH@Z
  local_8 = 0xffffffff;
  puStack_c = &iAttribute_1000a337;
  local_10 = ExceptionList;
  local_12c = '\0';
  puVar6 = &local_12b;
  for (iVar4 = 0x40; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  *(undefined2 *)puVar6 = 0;
  *(undefined1 *)((int)puVar6 + 2) = 0;
  ExceptionList = &local_10;
  GetTempFileNameA((LPCSTR)local_388,&DAT_1000f050,unaff_EDI,in_stack_fffffc1c);
  local_8 = 0;
  iVar4 = 0;
  pCVar1 = (LPCSTR)FUN_10004990((undefined4 *)local_388);
  local_380 = _lcreat(pCVar1,iVar4);
  _lclose(local_380);
  lpResult = &local_12c;
  lpDirectory = (LPCSTR)0x0;
  pCVar1 = (LPCSTR)FUN_10004990((undefined4 *)local_388);
  local_38c = FindExecutableA(pCVar1,lpDirectory,lpResult);
  pcVar2 = (char *)FUN_10004990((undefined4 *)local_388);
  iVar4 = remove(pcVar2);
  local_28 = '\x01' - (iVar4 != 0);
  if (local_38c < (HINSTANCE)0x21) {
    local_390 = 0;
    local_8 = 0xffffffff;
    CString::~CString(local_388);
    iVar4 = local_390;
  }
  else {
    ppCVar5 = &local_37c.lpReserved;
    for (iVar4 = 0x10; iVar4 != 0; iVar4 = iVar4 + -1) {
      *ppCVar5 = (LPSTR)0x0;
      ppCVar5 = ppCVar5 + 1;
    }
    local_37c.cb = 0x44;
    local_37c.dwFlags = 1;
    local_37c.wShowWindow = (WORD)param_2;
    local_20.hProcess = (HANDLE)0x0;
    local_20.hThread = (HANDLE)0x0;
    local_20.dwProcessId = 0;
    local_20.dwThreadId = 0;
    pcVar2 = (char *)FUN_10002c50(local_394,&local_12c);
    local_8._0_1_ = 1;
    pCVar3 = (CString *)operator+(local_398,pcVar2);
    local_8._0_1_ = 2;
    FUN_10002c30(local_24,pCVar3);
    local_8._0_1_ = 5;
    CString::~CString(local_398);
    local_8._0_1_ = 4;
    FUN_10002ca0(local_394);
    cVar7 = ' ';
    pCVar3 = (CString *)FUN_10002c50(local_3a0,param_1);
    local_8._0_1_ = 6;
    iVar4 = CString::Find(pCVar3,cVar7);
    local_39c = CONCAT31(local_39c._1_3_,iVar4 != -1);
    local_8._0_1_ = 4;
    FUN_10002ca0(local_3a0);
    if ((local_39c & 0xff) == 0) {
      CString::operator+=(local_24,param_1);
    }
    else {
      pcVar2 = &DAT_1000f060;
      this_00 = (STRING *)FUN_10002c50(local_3a4,param_1);
      local_8._0_1_ = 7;
      STRING::trim(this_00,pcVar2);
      pcVar2 = (char *)operator+((char *)local_3a8,(CString *)&param_2_1000f064);
      local_8._0_1_ = 8;
      pCVar3 = (CString *)operator+(local_3ac,pcVar2);
      local_8._0_1_ = 9;
      CString::operator+=(local_24,pCVar3);
      local_8._0_1_ = 8;
      CString::~CString(local_3ac);
      local_8._0_1_ = 7;
      CString::~CString(local_3a8);
      local_8._0_1_ = 4;
      FUN_10002ca0(local_3a4);
    }
    local_338 = '\0';
    puVar6 = local_337;
    for (iVar4 = 0x82; iVar4 != 0; iVar4 = iVar4 + -1) {
      *puVar6 = 0;
      puVar6 = puVar6 + 1;
    }
    *(undefined1 *)puVar6 = 0;
    _Count = 0x20a;
    pcVar2 = (char *)FUN_10004990((undefined4 *)local_24);
    strncpy(&local_338,pcVar2,_Count);
    iVar4 = CreateProcessA((LPCSTR)0x0,&local_338,(LPSECURITY_ATTRIBUTES)0x0,
                           (LPSECURITY_ATTRIBUTES)0x0,0,0,(LPVOID)0x0,(LPCSTR)0x0,&local_37c,
                           &local_20);
    local_8 = (uint)local_8._1_3_ << 8;
    local_384 = iVar4;
    FUN_10002ca0(local_24);
    local_8 = 0xffffffff;
    CString::~CString(local_388);
  }
  ExceptionList = local_10;
  return iVar4;
}



void * __thiscall FUN_100026c0(void *this,uint param_1)

{
  if ((param_1 & 2) == 0) {
    CHyperLink::~CHyperLink((CHyperLink *)this);
    if ((param_1 & 1) != 0) {
      FUN_10001660(this);
    }
  }
  else {
    FUN_10009e0c(this,200,*(int *)((int)this + -4),CHyperLink::~CHyperLink);
    if ((param_1 & 1) != 0) {
      operator_delete((void *)((int)this + -4));
    }
    this = (void *)((int)this + -4);
  }
  return this;
}



bool __fastcall FUN_10002730(int *param_1)

{
  int iVar1;
  
  iVar1 = FUN_10002750(param_1);
  return *(int *)(iVar1 + 4) == 0;
}



int __fastcall FUN_10002750(int *param_1)

{
  return *param_1 + -0xc;
}



undefined4 __fastcall FUN_10002770(undefined4 param_1)

{
  return param_1;
}



void __thiscall FUN_10002780(void *this,LONG param_1,LONG param_2)

{
  POINT pt;
  
  pt.y = param_2;
  pt.x = param_1;
  PtInRect((RECT *)this,pt);
  return;
}



void __thiscall FUN_100027a0(void *this,int param_1,int param_2)

{
  InflateRect((LPRECT)this,-param_1,-param_2);
  return;
}



CGdiObject * __fastcall FUN_100027d0(CGdiObject *param_1)

{
  CGdiObject::CGdiObject(param_1);
  *(undefined ***)param_1 = &PTR_LAB_1000b7a8;
  return param_1;
}



// Library Function - Single Match
//  public: __thiscall CGdiObject::CGdiObject(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CGdiObject * __thiscall CGdiObject::CGdiObject(CGdiObject *this)

{
  FUN_10002820((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_1000b7bc;
  *(undefined4 *)(this + 4) = 0;
  return this;
}



undefined4 * __fastcall FUN_10002820(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_1000b7d0;
  return param_1;
}



void * __thiscall FUN_10002840(void *this,uint param_1)

{
  FUN_10002870((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001660(this);
  }
  return this;
}



void __fastcall FUN_10002870(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_1000b7d0;
  return;
}



void * __thiscall FUN_10002890(void *this,uint param_1)

{
  FUN_100028c0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001660(this);
  }
  return this;
}



void __fastcall FUN_100028c0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1000a359;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_1000b7bc;
  local_8 = 0;
  CGdiObject::DeleteObject(param_1);
  local_8 = 0xffffffff;
  FUN_10002870(param_1);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_10002920(void *this,uint param_1)

{
  FUN_10002950((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001660(this);
  }
  return this;
}



void __fastcall FUN_10002950(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_1000b7a8;
  FUN_100028c0(param_1);
  return;
}



void __thiscall FUN_10002970(void *this,LOGFONTA *param_1)

{
  HFONT pHVar1;
  
  pHVar1 = CreateFontIndirectA(param_1);
  CGdiObject::Attach((CGdiObject *)this,pHVar1);
  return;
}



void __thiscall FUN_10002990(void *this,LPVOID param_1)

{
  GetObjectA(*(HANDLE *)((int)this + 4),0x3c,param_1);
  return;
}



void * __thiscall FUN_100029b0(void *this,void *param_1,int *param_2)

{
  int c;
  LPCSTR lpString;
  tagSIZE *psizl;
  tagSIZE local_c;
  
  psizl = &local_c;
  c = FUN_10002a00(param_2);
  lpString = (LPCSTR)FUN_10004990(param_2);
  GetTextExtentPoint32A(*(HDC *)((int)this + 8),lpString,c,psizl);
  FUN_10002a20(param_1,local_c.cx,local_c.cy);
  return param_1;
}



undefined4 __fastcall FUN_10002a00(int *param_1)

{
  int iVar1;
  
  iVar1 = FUN_10002750(param_1);
  return *(undefined4 *)(iVar1 + 4);
}



void * __thiscall FUN_10002a20(void *this,undefined4 param_1,undefined4 param_2)

{
  *(undefined4 *)this = param_1;
  *(undefined4 *)((int)this + 4) = param_2;
  return this;
}



undefined4 __fastcall FUN_10002a40(int param_1)

{
  undefined4 local_c;
  
  if (param_1 == 0) {
    local_c = 0;
  }
  else {
    local_c = *(undefined4 *)(param_1 + 0x20);
  }
  return local_c;
}



void __thiscall FUN_10002a70(void *this,int param_1,LPARAM param_2)

{
  WPARAM wParam;
  
  wParam = FUN_100017d0(param_1);
  SendMessageA(*(HWND *)((int)this + 0x20),0x30,wParam,param_2);
  return;
}



void __fastcall FUN_10002aa0(int param_1)

{
  void *pvVar1;
  
  pvVar1 = (void *)SendMessageA(*(HWND *)(param_1 + 0x20),0x31,0,0);
  FUN_10002ad0(pvVar1);
  return;
}



void FUN_10002ad0(void *param_1)

{
  CGdiObject::FromHandle(param_1);
  return;
}



void __thiscall FUN_10002ae0(void *this,LPRECT param_1)

{
  GetWindowRect(*(HWND *)((int)this + 0x20),param_1);
  return;
}



void __fastcall FUN_10002b00(int param_1)

{
  HDC pHVar1;
  
  pHVar1 = GetDC(*(HWND *)(param_1 + 0x20));
  CDC::FromHandle(pHVar1);
  return;
}



void __thiscall FUN_10002b20(void *this,int param_1)

{
  ReleaseDC(*(HWND *)((int)this + 0x20),*(HDC *)(param_1 + 4));
  return;
}



void __thiscall FUN_10002b50(void *this,BOOL param_1)

{
  InvalidateRect(*(HWND *)((int)this + 0x20),(RECT *)0x0,param_1);
  return;
}



void __thiscall FUN_10002b70(void *this,RECT *param_1,int param_2,UINT param_3)

{
  HRGN hrgnUpdate;
  
  hrgnUpdate = (HRGN)FUN_100017d0(param_2);
  RedrawWindow(*(HWND *)((int)this + 0x20),param_1,hrgnUpdate,param_3);
  return;
}



void __fastcall FUN_10002ba0(int param_1)

{
  HWND pHVar1;
  
  pHVar1 = SetCapture(*(HWND *)(param_1 + 0x20));
  CWnd::FromHandle(pHVar1);
  return;
}



void __fastcall FUN_10002bc0(int param_1)

{
  HWND pHVar1;
  
  pHVar1 = GetParent(*(HWND *)(param_1 + 0x20));
  CWnd::FromHandle(pHVar1);
  return;
}



void __fastcall FUN_10002be0(CWnd *param_1)

{
  CWnd::Default(param_1);
  return;
}



void __thiscall FUN_10002c00(void *this,LPARAM param_1)

{
  SendMessageA(*(HWND *)((int)this + 0x20),0x407,0,param_1);
  return;
}



void * __thiscall FUN_10002c30(void *this,CString *param_1)

{
  CString::CString((CString *)this,param_1);
  return this;
}



void * __thiscall FUN_10002c50(void *this,char *param_1)

{
  CString::CString((CString *)this,param_1);
  return this;
}



// public: bool __thiscall STRING::contains(char)const 

bool __thiscall STRING::contains(STRING *this,char param_1)

{
  int iVar1;
  
                    // 0x2c70  105  ?contains@STRING@@QBE_ND@Z
  iVar1 = CString::Find((CString *)this,param_1);
  return iVar1 != -1;
}



void __fastcall FUN_10002ca0(CString *param_1)

{
  CString::~CString(param_1);
  return;
}



void * __thiscall FUN_10002cc0(void *this,CString *param_1,CString *param_2,CWnd *param_3)

{
  char *pcVar1;
  ulong *puVar2;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_1000a3a9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CDialog::CDialog((CDialog *)this,0x8b,param_3);
  local_8 = 0;
  FUN_10002f40((void *)((int)this + 0x60),s_Warnings_1000f07c,s_Software_Twilight__1000f068);
  local_8._0_1_ = 1;
  CString::CString((CString *)((int)this + 100),param_2);
  local_8._0_1_ = 2;
  CString::CString((CString *)((int)this + 0x68),param_1);
  local_8._0_1_ = 3;
  CString::CString((CString *)((int)this + 0x70));
  local_8 = CONCAT31(local_8._1_3_,4);
  *(undefined ***)this = &PTR_LAB_1000b820;
  *(undefined4 *)((int)this + 0x6c) = 0;
  CString::operator=((CString *)((int)this + 0x70),&DAT_1000f360);
  puVar2 = (ulong *)((int)this + 0x6c);
  pcVar1 = (char *)FUN_10004990((undefined4 *)((int)this + 100));
  REG::Get((REG *)((int)this + 0x60),pcVar1,puVar2);
  ExceptionList = local_10;
  return this;
}



void __thiscall FUN_10002d9d(void *this,CDataExchange *param_1)

{
  FUN_10001820();
  DDX_Check(param_1,0x41a,(int *)((int)this + 0x6c));
  DDX_Text(param_1,0x41b,(CString *)((int)this + 0x70));
  return;
}



undefined * FUN_10002de0(void)

{
  return messageMap_exref;
}



undefined ** FUN_10002dea(void)

{
  return &PTR_FUN_1000b7e8;
}



void __fastcall FUN_10002dfa(CWnd *param_1)

{
  char *pcVar1;
  ulong uVar2;
  
  CWnd::UpdateData(param_1,1);
  uVar2 = *(ulong *)(param_1 + 0x6c);
  pcVar1 = (char *)FUN_10004990((undefined4 *)(param_1 + 100));
  REG::Put((REG *)(param_1 + 0x60),pcVar1,uVar2);
  return;
}



int __fastcall FUN_10002e2d(CDialog *param_1)

{
  int iVar1;
  
  if (*(int *)(param_1 + 0x6c) == 0) {
    iVar1 = CDialog::DoModal(param_1);
  }
  else {
    iVar1 = 1;
  }
  return iVar1;
}



undefined4 __fastcall FUN_10002e50(CDialog *param_1)

{
  HWND hWnd;
  
  hWnd = (HWND)FUN_10004990((undefined4 *)(param_1 + 0x68));
  CWnd::SetWindowTextA(hWnd,(LPCSTR)param_1);
  CDialog::OnInitDialog(param_1);
  return 1;
}



void * __thiscall FUN_10002e80(void *this,uint param_1)

{
  FUN_10002eb0((CDialog *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001660(this);
  }
  return this;
}



void __fastcall FUN_10002eb0(CDialog *param_1)

{
  CDialog *local_18;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &this_1000a409;
  local_10 = ExceptionList;
  local_8 = 3;
  ExceptionList = &local_10;
  CString::~CString((CString *)(param_1 + 0x70));
  local_8._0_1_ = 2;
  CString::~CString((CString *)(param_1 + 0x68));
  local_8._0_1_ = 1;
  CString::~CString((CString *)(param_1 + 100));
  local_8 = (uint)local_8._1_3_ << 8;
  if (param_1 == (CDialog *)0x0) {
    local_18 = (CDialog *)0x0;
  }
  else {
    local_18 = param_1 + 0x60;
  }
  FUN_10002ff0((undefined4 *)local_18);
  local_8 = 0xffffffff;
  CDialog::~CDialog(param_1);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_10002f40(void *this,undefined4 param_1,char *param_2)

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
  puStack_c = &lpdwDisposition_1000a432;
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
  lpSubKey = (LPCSTR)FUN_10004990((undefined4 *)local_18);
  local_14 = RegCreateKeyExA((HKEY)0x80000001,lpSubKey,Reserved,lpClass,dwOptions,samDesired,
                             lpSecurityAttributes,phkResult,lpdwDisposition);
  SetLastError(local_14);
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  ExceptionList = local_10;
  return this;
}



void __fastcall FUN_10002ff0(undefined4 *param_1)

{
  RegCloseKey((HKEY)*param_1);
  return;
}



// void __cdecl DisplayWarning(char const *,char const *,char const *)

void __cdecl DisplayWarning(char *param_1,char *param_2,char *param_3)

{
  AFX_MODULE_STATE *pAVar1;
  CString local_94 [4];
  CString local_90 [4];
  CDialog local_8c [112];
  CString local_1c [4];
  AFX_MAINTAIN_STATE2 local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x3010  23  ?DisplayWarning@@YAXPBD00@Z
  local_8 = 0xffffffff;
  puStack_c = &param_1_1000a46d;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pAVar1 = (AFX_MODULE_STATE *)FUN_10009c65();
  AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(local_18,pAVar1);
  local_8 = 0;
  CString::CString(local_90,param_3);
  local_8._0_1_ = 1;
  CString::CString(local_94,param_1);
  local_8._0_1_ = 2;
  FUN_10002cc0(local_8c,local_94,local_90,(CWnd *)0x0);
  local_8._0_1_ = 5;
  CString::~CString(local_94);
  local_8._0_1_ = 4;
  CString::~CString(local_90);
  CString::operator=(local_1c,param_2);
  FUN_10002e2d(local_8c);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_10002eb0(local_8c);
  local_8 = 0xffffffff;
  FUN_10004910((undefined4 *)local_18);
  ExceptionList = local_10;
  return;
}



// bool __cdecl IsRelativePath(class CString const &)

bool __cdecl IsRelativePath(CString *param_1)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  void *pvVar3;
  uchar *puVar4;
  CString local_18 [4];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x30e5  60  ?IsRelativePath@@YA_NABVCString@@@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a480;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  bVar1 = FUN_10002730((int *)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar4 = (uchar *)0x2;
    pvVar3 = (void *)CString::Mid(param_1,(int)local_18,1);
    local_8 = 0;
    bVar1 = FUN_100048b0(pvVar3,puVar4);
    local_14 = CONCAT31(local_14._1_3_,bVar1);
    local_8 = 0xffffffff;
    CString::~CString(local_18);
    if ((local_14 & 0xff) == 0) {
      cVar2 = FUN_10004890(param_1,0);
      if (cVar2 == '\\') {
        bVar1 = false;
      }
      else {
        bVar1 = true;
      }
    }
    else {
      bVar1 = false;
    }
  }
  else {
    bVar1 = true;
  }
  ExceptionList = local_10;
  return bVar1;
}



// class CString __cdecl GetTempFileNameA(char const *)

UINT GetTempFileNameA(LPCSTR lpPathName,LPCSTR lpPrefixString,UINT uUnique,LPSTR lpTempFileName)

{
  undefined1 uVar1;
  char cVar2;
  bool bVar3;
  CString *pCVar4;
  undefined4 *puVar5;
  char *pcVar6;
  int iVar7;
  CString local_150 [4];
  CString local_14c [4];
  CString local_148 [4];
  CString local_144 [4];
  CString local_140 [4];
  CString local_13c [4];
  CString local_138 [4];
  uint local_134;
  CString local_130 [4];
  CString local_12c [4];
  CString local_128 [4];
  CString local_124 [4];
  CString local_120 [4];
  int local_11c;
  CHAR local_118;
  undefined4 local_117;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x3186  52  ?GetTempFileNameA@@YA?AVCString@@PBD@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a53d;
  local_10 = ExceptionList;
  local_118 = '\0';
  puVar5 = &local_117;
  for (iVar7 = 0x40; iVar7 != 0; iVar7 = iVar7 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  *(undefined2 *)puVar5 = 0;
  *(undefined1 *)((int)puVar5 + 2) = 0;
  ExceptionList = &local_10;
  GetTempPathA(0x104,&local_118);
  FUN_10002c50(local_124,&DAT_1000f08c);
  local_8 = 1;
  FUN_10002c50(local_14,&local_118);
  local_8._0_1_ = 2;
  FUN_10002c50(local_120,&DAT_1000f090);
  local_8._0_1_ = 3;
  uVar1 = (undefined1)local_8;
  local_8._0_1_ = 3;
  if (lpPrefixString != (LPCSTR)0x0) {
    FUN_10002c50(local_128,lpPrefixString);
    local_8._0_1_ = 4;
    FUN_10004340(local_120,local_128);
    local_8._0_1_ = 3;
    FUN_10002ca0(local_128);
    cVar2 = FUN_10004890(local_120,0);
    uVar1 = (undefined1)local_8;
    if (cVar2 != '.') {
      pCVar4 = (CString *)operator+((char)local_130,(CString *)0x2e);
      local_8._0_1_ = 5;
      FUN_10002c30(local_12c,pCVar4);
      local_8._0_1_ = 6;
      FUN_10004340(local_120,local_12c);
      local_8._0_1_ = 5;
      FUN_10002ca0(local_12c);
      local_8._0_1_ = 3;
      CString::~CString(local_130);
      uVar1 = (undefined1)local_8;
    }
  }
  local_8._0_1_ = uVar1;
  local_11c = 0;
  while( true ) {
    FUN_10004b60(local_138);
    local_8._0_1_ = 7;
    pCVar4 = (CString *)operator+(local_13c,local_14);
    local_8._0_1_ = 8;
    pCVar4 = (CString *)operator+(local_140,pCVar4);
    local_8._0_1_ = 9;
    puVar5 = (undefined4 *)operator+(local_144,pCVar4);
    local_8._0_1_ = 10;
    pcVar6 = (char *)FUN_10004990(puVar5);
    bVar3 = exists(pcVar6);
    local_134 = CONCAT31(local_134._1_3_,bVar3);
    local_8._0_1_ = 9;
    CString::~CString(local_144);
    local_8._0_1_ = 8;
    CString::~CString(local_140);
    local_8._0_1_ = 7;
    CString::~CString(local_13c);
    local_8._0_1_ = 3;
    CString::~CString(local_138);
    if ((local_134 & 0xff) == 0) break;
    local_11c = local_11c + 1;
  }
  FUN_10004b60(local_148);
  local_8._0_1_ = 0xb;
  pCVar4 = (CString *)operator+(local_14c,local_14);
  local_8._0_1_ = 0xc;
  pCVar4 = (CString *)operator+(local_150,pCVar4);
  local_8._0_1_ = 0xd;
  operator+((CString *)lpPathName,pCVar4);
  local_8._0_1_ = 0xc;
  CString::~CString(local_150);
  local_8._0_1_ = 0xb;
  CString::~CString(local_14c);
  local_8._0_1_ = 3;
  CString::~CString(local_148);
  local_8._0_1_ = 2;
  FUN_10002ca0(local_120);
  local_8._0_1_ = 1;
  FUN_10002ca0(local_14);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_10002ca0(local_124);
  ExceptionList = local_10;
  return (UINT)lpPathName;
}



// class CString __cdecl ExtractFileName(char const *)

char * __cdecl ExtractFileName(char *param_1)

{
  char *pcVar1;
  char *in_stack_00000008;
  CString local_318 [4];
  char local_314 [4];
  char local_310 [256];
  char local_210 [256];
  char local_110 [256];
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
                    // 0x3531  26  ?ExtractFileName@@YA?AVCString@@PBD@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a56d;
  local_10 = ExceptionList;
  if (in_stack_00000008 == (char *)0x0) {
    ExceptionList = &local_10;
    CString::CString((CString *)param_1);
  }
  else {
    ExceptionList = &local_10;
    _splitpath(in_stack_00000008,local_314,local_310,local_110,local_210);
    pcVar1 = (char *)CString::CString(local_318,local_110);
    local_8 = 1;
    operator+((CString *)param_1,pcVar1);
    local_8 = local_8 & 0xffffff00;
    CString::~CString(local_318);
  }
  ExceptionList = local_10;
  return param_1;
}



// class CString __cdecl ExtractDirectory(char const *)

char * __cdecl ExtractDirectory(char *param_1)

{
  char *in_stack_00000008;
  char local_308 [4];
  char local_304 [256];
  char local_204 [256];
  char local_104 [256];
  
                    // 0x361c  24  ?ExtractDirectory@@YA?AVCString@@PBD@Z
  if (in_stack_00000008 == (char *)0x0) {
    CString::CString((CString *)param_1);
  }
  else {
    _splitpath(in_stack_00000008,local_308,local_304,local_104,local_204);
    CString::CString((CString *)param_1,local_304);
  }
  return param_1;
}



// class CString __cdecl ExtractFileExt(char const *)

char * __cdecl ExtractFileExt(char *param_1)

{
  char *in_stack_00000008;
  char local_308 [4];
  char local_304 [256];
  char local_204 [256];
  char local_104 [256];
  
                    // 0x36a4  25  ?ExtractFileExt@@YA?AVCString@@PBD@Z
  if (in_stack_00000008 == (char *)0x0) {
    CString::CString((CString *)param_1);
  }
  else {
    _splitpath(in_stack_00000008,local_308,local_304,local_104,local_204);
    CString::CString((CString *)param_1,local_204);
  }
  return param_1;
}



// int __cdecl MakeDirectory(char const *)

int __cdecl MakeDirectory(char *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  char *pcVar2;
  CString *pCVar3;
  uint uVar4;
  int *piVar5;
  CString local_24 [4];
  CString local_20 [4];
  int local_1c;
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x372c  64  ?MakeDirectory@@YAHPBD@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a59b;
  local_10 = ExceptionList;
  if (param_1 != (char *)0x0) {
    ExceptionList = &local_10;
    FUN_10002c50(local_18,param_1);
    local_8 = 0;
    FUN_10004b40(local_14);
    local_8._0_1_ = 1;
    do {
      do {
        bVar1 = FUN_10002730((int *)local_18);
        if (CONCAT31(extraout_var,bVar1) != 0) {
          local_8 = (uint)local_8._1_3_ << 8;
          FUN_10002ca0(local_14);
          local_8 = 0xffffffff;
          FUN_10002ca0(local_18);
          ExceptionList = local_10;
          return 1;
        }
        pcVar2 = STRING::strtok((char *)local_20,&DAT_1000f09c);
        local_8._0_1_ = 2;
        pCVar3 = (CString *)operator+(local_24,pcVar2);
        local_8._0_1_ = 3;
        CString::operator+=(local_14,pCVar3);
        local_8._0_1_ = 2;
        CString::~CString(local_24);
        local_8._0_1_ = 1;
        FUN_10002ca0(local_20);
        uVar4 = FUN_10003881(local_14);
      } while (uVar4 != 0);
      pcVar2 = (char *)FUN_10004990((undefined4 *)local_14);
      local_1c = _mkdir(pcVar2);
    } while ((local_1c == 0) || (piVar5 = _errno(), *piVar5 == 0x11));
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_10002ca0(local_14);
    local_8 = 0xffffffff;
    FUN_10002ca0(local_18);
  }
  ExceptionList = local_10;
  return 0;
}



uint __cdecl FUN_10003881(CString *param_1)

{
  bool bVar1;
  void *pvVar2;
  uchar *puVar3;
  CString local_18 [4];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a5ae;
  local_10 = ExceptionList;
  puVar3 = (uchar *)0x1;
  ExceptionList = &local_10;
  pvVar2 = (void *)CString::Mid(param_1,(int)local_18);
  local_8 = 0;
  bVar1 = FUN_100048b0(pvVar2,puVar3);
  local_14 = (uint)bVar1;
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  ExceptionList = local_10;
  return local_14;
}



// bool __cdecl exists(char const *)

bool __cdecl exists(char *param_1)

{
  HANDLE pvVar1;
  bool bVar2;
  int local_8;
  
                    // 0x38f0  108  ?exists@@YA_NPBD@Z
  if (param_1 == (char *)0x0) {
    bVar2 = false;
  }
  else {
    pvVar1 = CreateFileA(param_1,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x20000080,(HANDLE)0x0);
    FUN_10004950(&local_8,pvVar1);
    bVar2 = pvVar1 != (HANDLE)0xffffffff;
    FUN_10004970(&local_8);
  }
  return bVar2;
}



// double __cdecl RandomProb(void)

double __cdecl RandomProb(void)

{
  int iVar1;
  time_t tVar2;
  
                    // 0x394c  84  ?RandomProb@@YANXZ
  if (DAT_1000f39c == 0) {
    tVar2 = time((time_t *)0x0);
    srand((uint)tVar2);
    DAT_1000f39c = 1;
  }
  iVar1 = rand();
  return (double)iVar1 / 32767.0;
}



// int __cdecl round(double)

int __cdecl round(double param_1)

{
  int iVar1;
  double dVar2;
  
                    // 0x3993  117  ?round@@YAHN@Z
  iVar1 = ftol();
  dVar2 = fabs(param_1 - (double)iVar1);
  if (((0.5 <= dVar2) && (0.0 <= param_1)) || ((dVar2 < 0.5 && (param_1 < 0.0)))) {
    ceil(param_1);
    iVar1 = ftol();
  }
  else {
    floor(param_1);
    iVar1 = ftol();
  }
  return iVar1;
}



// int __cdecl fcomp(double,double,double)

int __cdecl fcomp(double param_1,double param_2,double param_3)

{
  double dVar1;
  undefined4 local_8;
  
                    // 0x3a2d  109  ?fcomp@@YAHNNN@Z
  dVar1 = fabs(param_1 - param_2);
  if (param_3 <= dVar1) {
    if (0.0 <= param_1 - param_2) {
      local_8 = 1;
    }
    else {
      local_8 = -1;
    }
  }
  else {
    local_8 = 0;
  }
  return local_8;
}



// char const * __cdecl Win32ErrorDesc(unsigned long)

char * __cdecl Win32ErrorDesc(ulong param_1)

{
  char *local_8;
  
                    // 0x3a7d  101  ?Win32ErrorDesc@@YAPBDK@Z
  FormatMessageA(0x1300,(LPCVOID)0x0,param_1,0x400,(LPSTR)&local_8,0,(va_list *)0x0);
  return local_8;
}



// struct HINSTANCE__ * __cdecl AddressToHinst(void const *)

HINSTANCE__ * __cdecl AddressToHinst(void *param_1)

{
  undefined4 *puVar1;
  void *pvVar2;
  SIZE_T SVar3;
  DWORD DVar4;
  undefined1 local_134 [4];
  HMODULE local_130;
  CHAR local_12c [260];
  _MEMORY_BASIC_INFORMATION local_28;
  HINSTANCE__ *local_c;
  LPCVOID local_8;
  
                    // 0x3aa6  12  ?AddressToHinst@@YAPAUHINSTANCE__@@PBX@Z
  if (param_1 == (void *)0x0) {
    puVar1 = (undefined4 *)FUN_100049a0(local_134,0,0);
    pvVar2 = (void *)FUN_10004990(puVar1);
    local_c = AddressToHinst(pvVar2);
  }
  else {
    local_8 = (LPCVOID)0x0;
    local_c = (HINSTANCE__ *)0x0;
    while ((local_8 < param_1 && (SVar3 = VirtualQuery(local_8,&local_28,0x1c), SVar3 == 0x1c))) {
      if ((local_28.State != 0x10000) &&
         (((HMODULE)local_28.AllocationBase != (HMODULE)0x0 &&
          (local_28.AllocationBase == local_28.BaseAddress)))) {
        local_130 = (HMODULE)local_28.AllocationBase;
        DVar4 = GetModuleFileNameA((HMODULE)local_28.AllocationBase,local_12c,0x104);
        if (DVar4 != 0) {
          local_c = (HINSTANCE__ *)local_28.AllocationBase;
        }
      }
      local_8 = (LPCVOID)((int)local_8 + local_28.RegionSize);
    }
  }
  return local_c;
}



// struct HINSTANCE__ * __cdecl CallersHinst(void)

HINSTANCE__ * __cdecl CallersHinst(void)

{
  undefined4 *puVar1;
  void *pvVar2;
  HINSTANCE__ *pHVar3;
  undefined1 local_8 [4];
  
                    // 0x3b5a  15  ?CallersHinst@@YAPAUHINSTANCE__@@XZ
  puVar1 = (undefined4 *)FUN_100049a0(local_8,1,0);
  pvVar2 = (void *)FUN_10004990(puVar1);
  pHVar3 = AddressToHinst(pvVar2);
  return pHVar3;
}



// unsigned char __cdecl CountBits(unsigned long)

uchar __cdecl CountBits(ulong param_1)

{
  undefined4 local_8;
  
                    // 0x3b82  19  ?CountBits@@YAEK@Z
  local_8 = 0;
  for (; param_1 != 0; param_1 = param_1 >> 1) {
    local_8 = local_8 + (param_1 & 1);
  }
  return (uchar)local_8;
}



// struct HWND__ * __cdecl FindTopLevelWindow(class CString,struct HWND__ *)

HWND__ * __cdecl FindTopLevelWindow(undefined4 param_1,HWND param_2)

{
  HWND__ *pHVar1;
  char *pcVar2;
  int iVar3;
  STRING local_1c [4];
  HWND local_18;
  HWND__ *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x3bb2  28  ?FindTopLevelWindow@@YAPAUHWND__@@VCString@@PAU1@@Z
  puStack_c = &LAB_1000a5ca;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  local_18 = GetTopWindow(param_2);
  local_14 = (HWND__ *)FUN_10004360(local_18,2);
  do {
    if (local_14 == (HWND__ *)0x0) {
LAB_10003c4b:
      pHVar1 = local_14;
      local_8 = 0xffffffff;
      CString::~CString((CString *)&param_1);
      ExceptionList = local_10;
      return pHVar1;
    }
    STRING::STRING(local_1c,local_14);
    local_8._0_1_ = 1;
    pcVar2 = (char *)FUN_10004990(&param_1);
    iVar3 = CString::Find((CString *)local_1c,pcVar2);
    if (iVar3 != -1) {
      local_8 = (uint)local_8._1_3_ << 8;
      FUN_10002ca0((CString *)local_1c);
      goto LAB_10003c4b;
    }
    local_14 = (HWND__ *)FUN_10004360(local_14,2);
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_10002ca0((CString *)local_1c);
  } while( true );
}



// void __cdecl GetAllTopLevelWindows(class LIST<struct HWND__ *> &,struct HWND__ *)

void __cdecl GetAllTopLevelWindows(LIST<> *param_1,HWND__ *param_2)

{
  HWND pHVar1;
  HWND local_8;
  
                    // 0x3c71  35  ?GetAllTopLevelWindows@@YAXAAV?$LIST@PAUHWND__@@@@PAUHWND__@@@Z
  FUN_10004500((int)param_1);
  pHVar1 = GetTopWindow(param_2);
  for (local_8 = (HWND)FUN_10004360(pHVar1,2); local_8 != (HWND)0x0;
      local_8 = (HWND)FUN_10004360(local_8,2)) {
    FUN_10004420(param_1,&local_8);
  }
  return;
}



// void __cdecl ShowMouse(bool)

void __cdecl ShowMouse(bool param_1)

{
  undefined4 local_c;
  undefined4 local_8;
  
                    // 0x3cc6  98  ?ShowMouse@@YAX_N@Z
  if (param_1) {
    local_8 = ShowCursor(1);
    while (local_8 < 0) {
      local_8 = ShowCursor(1);
    }
    while (local_8 != 0) {
      local_8 = ShowCursor(0);
    }
  }
  else {
    local_c = ShowCursor(0);
    while (0 < local_c) {
      local_c = ShowCursor(0);
    }
    while (local_c != -1) {
      local_c = ShowCursor(1);
    }
  }
  return;
}



// class CString __cdecl GetModuleFileNameA(struct HINSTANCE__ *)

DWORD GetModuleFileNameA(HMODULE hModule,LPSTR lpFilename,DWORD nSize)

{
  int iVar1;
  undefined4 *puVar2;
  CHAR local_10c;
  undefined4 local_10b [65];
  
                    // 0x3d41  44  ?GetModuleFileNameA@@YA?AVCString@@PAUHINSTANCE__@@@Z
  local_10c = '\0';
  puVar2 = local_10b;
  for (iVar1 = 0x41; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  GetModuleFileNameA((HMODULE)lpFilename,&local_10c,0x105);
  CString::CString((CString *)hModule,&local_10c);
  return (DWORD)hModule;
}



// int __cdecl AlreadyRunning(char const *)

int __cdecl AlreadyRunning(char *param_1)

{
  size_t sVar1;
  DWORD DVar2;
  uint local_8;
  
                    // 0x3da6  13  ?AlreadyRunning@@YAHPBD@Z
  sVar1 = strlen(param_1);
  if (sVar1 < 0x104) {
    CreateMutexA((LPSECURITY_ATTRIBUTES)0x0,0,param_1);
    DVar2 = GetLastError();
    local_8 = (uint)(DVar2 == 0xb7);
  }
  else {
    local_8 = 0;
  }
  return local_8;
}



// bool __cdecl FindDriver(char const *)

bool __cdecl FindDriver(char *param_1)

{
  bool bVar1;
  SECTION *this;
  char *pcVar2;
  ulong *puVar3;
  ulong local_1c;
  CString local_18 [4];
  ulong local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x3df7  27  ?FindDriver@@YA_NPBD@Z
  local_8 = 0xffffffff;
  puStack_c = &this_1000a5dd;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10002c50(local_18,param_1);
  local_8 = 0;
  this = (SECTION *)FUN_10003ec5();
  local_1c = 0;
  CString::MakeReverse(local_18);
  local_14 = 0;
  puVar3 = &local_14;
  pcVar2 = (char *)FUN_10004990((undefined4 *)local_18);
  bVar1 = INIFILE::SECTION::Get(this,pcVar2,puVar3);
  if (bVar1) {
    local_1c = local_14;
  }
  bVar1 = local_1c != 0;
  if (bVar1) {
    local_8 = 0xffffffff;
    FUN_10002ca0(local_18);
  }
  else {
    local_14 = 1;
    puVar3 = &local_1c;
    pcVar2 = (char *)FUN_10004990((undefined4 *)local_18);
    INIFILE::SECTION::Put(this,pcVar2,puVar3);
    local_8 = 0xffffffff;
    FUN_10002ca0(local_18);
  }
  ExceptionList = local_10;
  return !bVar1;
}



undefined * FUN_10003ec5(void)

{
  undefined *puVar1;
  char *pcVar2;
  
  if ((DAT_1000f399 & 1) == 0) {
    DAT_1000f399 = DAT_1000f399 | 1;
    pcVar2 = s__52762720_e233_4d5f_a3df_d9029a5_1000f0a4;
    puVar1 = FUN_10003f0e();
    FUN_10004c30(&DAT_1000f390,puVar1,pcVar2);
    FUN_10009f3e(FUN_1000414e);
  }
  return &DAT_1000f390;
}



undefined * FUN_10003f0e(void)

{
  int iVar1;
  undefined4 *puVar2;
  CString local_22c [4];
  CString local_228 [4];
  CHAR local_224;
  undefined4 local_223 [65];
  CHAR local_11c;
  undefined4 local_11b;
  int local_18;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a620;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  if ((DAT_1000f398 & 1) == 0) {
    DAT_1000f398 = DAT_1000f398 | 1;
    ExceptionList = &local_10;
    INIFILE::INIFILE((INIFILE *)&DAT_1000f368);
    FUN_10009f3e(FUN_1000413f);
  }
  if (DAT_1000f3a0 != '\0') {
    ExceptionList = local_10;
    return &DAT_1000f368;
  }
  DAT_1000f3a0 = 1;
  local_11c = '\0';
  puVar2 = &local_11b;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined1 *)((int)puVar2 + 2) = 0;
  local_18 = SHGetSpecialFolderPathA((HWND)0x0,&local_11c,0x23,0);
  FUN_10004b40(local_14);
  local_8 = 0;
  if (-1 < local_18) {
    FUN_10002c50(local_228,&local_11c);
    local_8._0_1_ = 1;
    FUN_10004340(local_14,local_228);
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_10002ca0(local_228);
                    // WARNING: Subroutine does not return
    STRING::terminate((STRING *)local_14,&DAT_1000f0e4);
  }
  local_224 = '\0';
  puVar2 = local_223;
  for (iVar1 = 0x41; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  GetWindowsDirectoryA(&local_224,0x105);
  FUN_10002c50(local_22c,&local_224);
  local_8._0_1_ = 2;
  FUN_10004340(local_14,local_22c);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_10002ca0(local_22c);
                    // WARNING: Subroutine does not return
  STRING::terminate((STRING *)local_14,&DAT_1000f0cc);
}



void FUN_1000413f(void)

{
  INIFILE::~INIFILE((INIFILE *)&DAT_1000f368);
  return;
}



void FUN_1000414e(void)

{
  FUN_100043c0(0x1000f390);
  return;
}



// unsigned long __cdecl GetDriverVersion_UAG(char const *)

ulong __cdecl GetDriverVersion_UAG(char *param_1)

{
  bool bVar1;
  CString *pCVar2;
  char *pcVar3;
  ulong *puVar4;
  CString local_24 [4];
  undefined1 *local_20;
  uint local_1c;
  SECTION *local_18;
  ulong local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x415d  37  ?GetDriverVersion_UAG@@YAKPBD@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a633;
  local_10 = ExceptionList;
  if ((param_1 == (char *)0x0) || (*param_1 == '\0')) {
    local_14 = 0;
  }
  else {
    ExceptionList = &local_10;
    local_18 = (SECTION *)FUN_10003ec5();
    local_14 = 0;
    puVar4 = &local_14;
    local_20 = &stack0xffffffc8;
    CString::CString((CString *)&stack0xffffffc8,param_1);
    pCVar2 = FUN_10004218(local_24);
    local_8 = 0;
    pcVar3 = (char *)FUN_10004990((undefined4 *)pCVar2);
    bVar1 = INIFILE::SECTION::Get(local_18,pcVar3,puVar4);
    local_1c = CONCAT31(local_1c._1_3_,bVar1);
    local_8 = 0xffffffff;
    CString::~CString(local_24);
    if ((local_1c & 0xff) == 0) {
      local_14 = 0;
    }
  }
  ExceptionList = local_10;
  return local_14;
}



CString * __cdecl FUN_10004218(CString *param_1)

{
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &this_1000a666;
  local_10 = ExceptionList;
  local_8 = 1;
  ExceptionList = &local_10;
  operator+((char *)local_14,(CString *)s_Aargon_Deluxe_1000f11c);
  local_8._0_1_ = 2;
  CString::MakeReverse(local_14);
  CString::CString(param_1,local_14);
  local_8._0_1_ = 1;
  CString::~CString(local_14);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString((CString *)&stack0x00000008);
  ExceptionList = local_10;
  return param_1;
}



// void __cdecl GetDriverVersion_UAP(char const *,unsigned long)

void __cdecl GetDriverVersion_UAP(char *param_1,ulong param_2)

{
  CString *pCVar1;
  char *pcVar2;
  ulong *puVar3;
  CString local_1c [4];
  undefined1 *local_18;
  SECTION *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x429c  38  ?GetDriverVersion_UAP@@YAXPBDK@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a679;
  local_10 = ExceptionList;
  if ((param_1 != (char *)0x0) && (*param_1 != '\0')) {
    ExceptionList = &local_10;
    local_14 = (SECTION *)FUN_10003ec5();
    puVar3 = &param_2;
    local_18 = &stack0xffffffd0;
    CString::CString((CString *)&stack0xffffffd0,param_1);
    pCVar1 = FUN_10004218(local_1c);
    local_8 = 0;
    pcVar2 = (char *)FUN_10004990((undefined4 *)pCVar1);
    INIFILE::SECTION::Put(local_14,pcVar2,puVar3);
    local_8 = 0xffffffff;
    CString::~CString(local_1c);
  }
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_10004340(void *this,CString *param_1)

{
  CString::operator=((CString *)this,param_1);
  return this;
}



void __cdecl FUN_10004360(HWND param_1,UINT param_2)

{
  GetWindow(param_1,param_2);
  return;
}



void * __thiscall FUN_10004380(void *this,CString *param_1)

{
  CString::operator=((CString *)this,param_1);
  FUN_100043e0((void *)((int)this + 4),param_1 + 4);
  *(undefined4 *)((int)this + 0x20) = *(undefined4 *)(param_1 + 0x20);
  return this;
}



void __fastcall FUN_100043c0(int param_1)

{
  CString::~CString((CString *)(param_1 + 4));
  return;
}



void * __thiscall FUN_100043e0(void *this,void *param_1)

{
  if (this != param_1) {
    FUN_10004480((int)this);
    FUN_10004440(this,(int)param_1);
  }
  return this;
}



void * __thiscall FUN_10004420(void *this,undefined4 *param_1)

{
  FUN_10008150(this,param_1);
  return this;
}



void __thiscall FUN_10004440(void *this,int param_1)

{
  CString *pCVar1;
  int local_8;
  
  local_8 = FUN_100045e0(param_1);
  while (local_8 != 0) {
    pCVar1 = (CString *)FUN_10008420(&local_8);
    FUN_10004580(this,pCVar1);
  }
  return;
}



void __fastcall FUN_10004480(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_10004600(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



void __fastcall FUN_10004500(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_10004630(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



undefined4 * __thiscall FUN_10004580(void *this,CString *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_10004710(this,*(undefined4 *)((int)this + 8),0);
  FUN_10004660(puVar1 + 2,param_1);
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



undefined4 __fastcall FUN_100045e0(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



void FUN_10004600(void *param_1,int param_2)

{
  while (param_2 != 0) {
    FUN_10004690(param_1,0);
    param_1 = (void *)((int)param_1 + 8);
    param_2 = param_2 + -1;
  }
  return;
}



void FUN_10004630(undefined4 param_1,int param_2)

{
  bool bVar1;
  
  do {
    bVar1 = param_2 != 0;
    param_2 = param_2 + -1;
  } while (bVar1);
  return;
}



void * __thiscall FUN_10004660(void *this,CString *param_1)

{
  CString::operator=((CString *)this,param_1);
  CString::operator=((CString *)((int)this + 4),param_1 + 4);
  return this;
}



void * __thiscall FUN_10004690(void *this,uint param_1)

{
  FUN_100046c0((CString *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_100046c0(CString *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1000a699;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  CString::~CString(param_1 + 4);
  local_8 = 0xffffffff;
  CString::~CString(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __thiscall FUN_10004710(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0x10);
    iVar3 = FUN_1000a180((int)pCVar2);
    local_c = (undefined4 *)(iVar3 + (*(int *)((int)this + 0x18) + -1) * 0x10);
    local_10 = *(int *)((int)this + 0x18);
    while (local_10 = local_10 + -1, -1 < local_10) {
      *local_c = *(undefined4 *)((int)this + 0x10);
      *(undefined4 **)((int)this + 0x10) = local_c;
      local_c = local_c + -4;
    }
  }
  puVar1 = *(undefined4 **)((int)this + 0x10);
  *(undefined4 *)((int)this + 0x10) = **(undefined4 **)((int)this + 0x10);
  puVar1[1] = param_1;
  *puVar1 = param_2;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  FUN_100047f0(puVar1 + 2,1);
  return puVar1;
}



void FUN_100047f0(void *param_1,int param_2)

{
  CString *pCVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a6c1;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  memset(param_1,0,param_2 << 3);
  while (param_2 != 0) {
    pCVar1 = (CString *)FUN_10004930(8,param_1);
    local_8 = 0;
    if (pCVar1 != (CString *)0x0) {
      FUN_10004be0(pCVar1);
    }
    local_8 = 0xffffffff;
    param_1 = (void *)((int)param_1 + 8);
    param_2 = param_2 + -1;
  }
  ExceptionList = local_10;
  return;
}



undefined1 __thiscall FUN_10004890(void *this,int param_1)

{
                    // WARNING: Load size is inaccurate
  return *(undefined1 *)(*this + param_1);
}



bool FUN_100048b0(void *param_1,uchar *param_2)

{
  int iVar1;
  
  iVar1 = FUN_100048d0(param_1,param_2);
  return (bool)('\x01' - (iVar1 != 0));
}



void __thiscall FUN_100048d0(void *this,uchar *param_1)

{
                    // WARNING: Load size is inaccurate
  FUN_100048f0(*this,param_1);
  return;
}



void __cdecl FUN_100048f0(uchar *param_1,uchar *param_2)

{
  _mbscmp(param_1,param_2);
  return;
}



void __fastcall FUN_10004910(undefined4 *param_1)

{
  *(undefined4 *)(param_1[1] + 4) = *param_1;
  return;
}



undefined4 __cdecl FUN_10004930(undefined4 param_1,undefined4 param_2)

{
  return param_2;
}



void FUN_10004940(void)

{
  return;
}



void * __thiscall FUN_10004950(void *this,undefined4 param_1)

{
  *(undefined4 *)this = param_1;
  return this;
}



void __fastcall FUN_10004970(int *param_1)

{
  if (*param_1 != -1) {
    CloseHandle((HANDLE)*param_1);
  }
  return;
}



undefined4 __fastcall FUN_10004990(undefined4 *param_1)

{
  return *param_1;
}



void * __cdecl FUN_100049a0(void *param_1,int param_2,int param_3)

{
  undefined4 *this;
  void *this_00;
  undefined1 *puVar1;
  int iVar2;
  void *pvVar3;
  undefined1 local_c [4];
  undefined4 local_8;
  
  iVar2 = 4;
  puVar1 = local_c;
  pvVar3 = param_1;
  this = FUN_10004a90(&local_8,param_2 + (uint)(param_3 == 0),param_3);
  this_00 = FUN_10004a60(this,puVar1,iVar2);
  FUN_100049f0(this_00,pvVar3);
  return param_1;
}



void * __thiscall FUN_100049f0(void *this,void *param_1)

{
  BOOL BVar1;
  undefined4 local_c;
  
                    // WARNING: Load size is inaccurate
  BVar1 = IsBadReadPtr(*this,4);
  if (BVar1 == 0) {
                    // WARNING: Load size is inaccurate
    local_c = **this;
  }
  else {
    local_c = 0;
  }
  FUN_10004a40(param_1,local_c);
  return param_1;
}



void * __thiscall FUN_10004a40(void *this,undefined4 param_1)

{
  *(undefined4 *)this = param_1;
  return this;
}



void * __thiscall FUN_10004a60(void *this,void *param_1,int param_2)

{
                    // WARNING: Load size is inaccurate
  FUN_10004a40(param_1,*this + param_2);
  return param_1;
}



undefined4 * __cdecl FUN_10004a90(undefined4 *param_1,int param_2,int param_3)

{
  void *this;
  undefined4 *puVar1;
  undefined1 *puVar2;
  undefined1 local_1c [4];
  undefined1 local_18 [4];
  undefined1 local_14 [4];
  undefined4 local_10;
  undefined1 *local_c;
  undefined4 local_8;
  
  local_c = (undefined1 *)0x0;
  FUN_10004b30(&local_8);
  if (param_3 == 0) {
    puVar2 = local_18;
    local_c = &stack0xfffffffc;
    this = FUN_10004a40(local_14,&stack0xfffffffc);
    puVar1 = (undefined4 *)FUN_100049f0(this,puVar2);
    local_8 = *puVar1;
  }
  else {
    local_c = *(undefined1 **)(param_3 + 0xb4);
    FUN_10004a40(&local_10,local_c);
    local_8 = local_10;
  }
  while (param_2 != 0) {
    puVar1 = (undefined4 *)FUN_100049f0(&local_8,local_1c);
    local_8 = *puVar1;
    param_2 = param_2 + -1;
  }
  *param_1 = local_8;
  return param_1;
}



undefined4 __fastcall FUN_10004b30(undefined4 param_1)

{
  return param_1;
}



CString * __fastcall FUN_10004b40(CString *param_1)

{
  CString::CString(param_1);
  return param_1;
}



CString * __cdecl FUN_10004b60(CString *param_1)

{
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_1000a6f0;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(local_14);
  local_8 = 1;
  CString::Format(local_14,(char *)local_14);
  CString::CString(param_1,local_14);
  local_8 = local_8 & 0xffffff00;
  CString::~CString(local_14);
  ExceptionList = local_10;
  return param_1;
}



CString * __fastcall FUN_10004be0(CString *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a709;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(param_1);
  local_8 = 0;
  CString::CString(param_1 + 4);
  ExceptionList = local_10;
  return param_1;
}



void * __thiscall FUN_10004c30(void *this,undefined4 param_1,char *param_2)

{
  *(undefined4 *)this = param_1;
  CString::CString((CString *)((int)this + 4),param_2);
  return this;
}



void FUN_10004c60(void)

{
  FUN_10004c6f();
  FUN_10004c7e();
  return;
}



void FUN_10004c6f(void)

{
  FUN_10004d40((CWinApp *)&DAT_1000f3a8);
  return;
}



void FUN_10004c7e(void)

{
  FUN_10009f3e(FUN_10004c90);
  return;
}



void FUN_10004c90(void)

{
  FUN_10004d20((CWinApp *)&DAT_1000f3a8);
  return;
}



undefined4 FUN_10004c9f(void)

{
  CString *pCVar1;
  char *pcVar2;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_1000a729;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pCVar1 = FUN_10004da0(local_14);
  local_8 = 0;
  pcVar2 = (char *)FUN_10004990((undefined4 *)pCVar1);
  MakeDirectory(pcVar2);
  local_8 = 0xffffffff;
  CString::~CString(local_14);
  ExceptionList = local_10;
  return 1;
}



undefined4 FUN_10004d0c(void)

{
  return 0;
}



void __fastcall FUN_10004d20(CWinApp *param_1)

{
  CWinApp::~CWinApp(param_1);
  return;
}



CWinApp * __fastcall FUN_10004d40(CWinApp *param_1)

{
  CWinApp::CWinApp(param_1,(char *)0x0);
  *(undefined ***)param_1 = &PTR_LAB_1000b910;
  return param_1;
}



void * __thiscall FUN_10004d70(void *this,uint param_1)

{
  FUN_10004d20((CWinApp *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001660(this);
  }
  return this;
}



CString * __cdecl FUN_10004da0(CString *param_1)

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
  puStack_c = &LAB_1000a77b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(local_14);
  local_8 = 1;
  pCVar3 = local_14;
  pcVar4 = s_LogDir_1000f148;
  this = (REG *)FUN_10002f40(&local_1c,&param_3_1000f494,s_Software_Twilight__1000f134);
  local_8._0_1_ = 2;
  bVar1 = REG::Get(this,pcVar4,pCVar3);
  local_18 = CONCAT31(local_18._1_3_,bVar1);
  local_8._0_1_ = 1;
  FUN_10002ff0(&local_1c);
  if ((local_18 & 0xff) == 0) {
    REG::RootDir();
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_14);
  }
  else {
    cVar2 = FUN_10004890(local_14,0);
    if ((cVar2 != '\\') && (cVar2 = FUN_10004890(local_14,1), cVar2 != ':')) {
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



// public: __thiscall STRING::STRING(struct HWND__ *)

STRING * __thiscall STRING::STRING(STRING *this,HWND__ *param_1)

{
  LRESULT LVar1;
  undefined4 *puVar2;
  LPARAM lParam;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x4f20  6  ??0STRING@@QAE@PAUHWND__@@@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a799;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString((CString *)this);
  local_8 = 0;
  LVar1 = DefWindowProcA(param_1,0xe,0,0);
  if (LVar1 != 0) {
    puVar2 = (undefined4 *)FUN_100054f0(this,'@',LVar1);
    FUN_10004990(puVar2);
    lParam = FUN_10004990((undefined4 *)this);
    DefWindowProcA(param_1,0xd,LVar1 + 1,lParam);
  }
  ExceptionList = local_10;
  return this;
}



// public: bool __thiscall STRING::contains_only(char const *)const 

bool __thiscall STRING::contains_only(STRING *this,char *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  char *_Str;
  size_t sVar2;
  size_t sVar3;
  
                    // 0x4fba  106  ?contains_only@STRING@@QBE_NPBD@Z
  bVar1 = FUN_10002730((int *)this);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    _Str = (char *)FUN_10004990((undefined4 *)this);
    sVar2 = strspn(_Str,param_1);
    sVar3 = FUN_10002a00((int *)this);
    bVar1 = sVar2 == sVar3;
  }
  else {
    bVar1 = false;
  }
  return bVar1;
}



// public: bool __thiscall STRING::isblank(void)const 

bool __thiscall STRING::isblank(STRING *this)

{
  bool bVar1;
  undefined3 extraout_var;
  
                    // 0x5002  114  ?isblank@STRING@@QBE_NXZ
  bVar1 = FUN_10002730((int *)this);
  if ((CONCAT31(extraout_var,bVar1) == 0) && (bVar1 = contains_only(this,&DAT_1000f150), !bVar1)) {
    return false;
  }
  return true;
}



// public: int __thiscall STRING::atol(void)const 

long __cdecl STRING::atol(char *_Str)

{
  bool bVar1;
  undefined3 extraout_var;
  long lVar2;
  char *_Str_00;
  int *in_ECX;
  
                    // 0x5044  104  ?atol@STRING@@QBEHXZ
  bVar1 = FUN_10002730(in_ECX);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    _Str_00 = (char *)FUN_10004990(in_ECX);
    lVar2 = ::atol(_Str_00);
  }
  else {
    lVar2 = 0;
  }
  return lVar2;
}



// public: struct STRING & __thiscall STRING::toupper(void)

int __cdecl STRING::toupper(int _C)

{
  CString *in_ECX;
  
                    // 0x5071  121  ?toupper@STRING@@QAEAAU1@XZ
  CString::MakeUpper(in_ECX);
  return (int)in_ECX;
}



// public: struct STRING & __thiscall STRING::terminate(char const *)

STRING * __thiscall STRING::terminate(STRING *this,char *param_1)

{
  bool bVar1;
  
                    // 0x5087  120  ?terminate@STRING@@QAEAAU1@PBD@Z
  bVar1 = tailequ(this,param_1);
  if (!bVar1) {
    CString::operator+=((CString *)this,param_1);
  }
  return this;
}



// public: char __thiscall STRING::last(void)const 

char __thiscall STRING::last(STRING *this)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  int iVar3;
  
                    // 0x50b8  115  ?last@STRING@@QBEDXZ
  bVar1 = FUN_10002730((int *)this);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    iVar3 = FUN_10002a00((int *)this);
    cVar2 = FUN_10004890(this,iVar3 + -1);
  }
  else {
    cVar2 = -1;
  }
  return cVar2;
}



// public: char __thiscall STRING::first(void)const 

char __thiscall STRING::first(STRING *this)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  
                    // 0x50ed  110  ?first@STRING@@QBEDXZ
  bVar1 = FUN_10002730((int *)this);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    cVar2 = FUN_10004890(this,0);
  }
  else {
    cVar2 = -1;
  }
  return cVar2;
}



// public: struct STRING & __thiscall STRING::trim(char const *)

STRING * __thiscall STRING::trim(STRING *this,char *param_1)

{
                    // 0x5118  122  ?trim@STRING@@QAEAAU1@PBD@Z
  CString::TrimLeft((CString *)this,param_1);
  CString::TrimRight((CString *)this,param_1);
  return this;
}



// public: struct STRING __thiscall STRING::strtok(char const *,enum STRING::DIRECTION)

char * __cdecl STRING::strtok(char *_Str,char *_Delim)

{
  int iVar1;
  uint uVar2;
  CString *in_ECX;
  int in_stack_0000000c;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
                    // 0x5140  118  ?strtok@STRING@@QAE?AU1@PBDW4DIRECTION@1@@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a7c3;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  if (in_stack_0000000c == 1) {
    ExceptionList = &local_10;
    CString::MakeReverse(in_ECX);
  }
  CString::SpanExcluding(in_ECX,(char *)local_14);
  local_8 = 1;
  iVar1 = FUN_10002a00((int *)local_14);
  uVar2 = FUN_10002a00((int *)in_ECX);
  uVar2 = FUN_100054c0(iVar1 + 1,uVar2);
  CString::Delete(in_ECX,0,uVar2);
  if (in_stack_0000000c == 1) {
    CString::MakeReverse(in_ECX);
    CString::MakeReverse(local_14);
  }
  FUN_10002c30(_Str,local_14);
  local_8 = local_8 & 0xffffff00;
  CString::~CString(local_14);
  ExceptionList = local_10;
  return _Str;
}



// public: bool __thiscall STRING::headequ(char const *)const 

bool __thiscall STRING::headequ(STRING *this,char *param_1)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  size_t _MaxCount;
  char *_Str1;
  int iVar3;
  
                    // 0x5208  112  ?headequ@STRING@@QBE_NPBD@Z
  if ((param_1 == (char *)0x0) || (*param_1 == '\0')) {
    cVar2 = '\0';
  }
  else {
    bVar1 = FUN_10002730((int *)this);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      _MaxCount = strlen(param_1);
      _Str1 = (char *)FUN_10004990((undefined4 *)this);
      iVar3 = strncmp(_Str1,param_1,_MaxCount);
      cVar2 = '\x01' - (iVar3 != 0);
    }
    else {
      cVar2 = '\0';
    }
  }
  return (bool)cVar2;
}



// public: bool __thiscall STRING::headequi(char const *)const 

bool __thiscall STRING::headequi(STRING *this,char *param_1)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  size_t _MaxCount;
  char *_Str1;
  int iVar3;
  
                    // 0x5269  113  ?headequi@STRING@@QBE_NPBD@Z
  if ((param_1 == (char *)0x0) || (*param_1 == '\0')) {
    cVar2 = '\0';
  }
  else {
    bVar1 = FUN_10002730((int *)this);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      _MaxCount = strlen(param_1);
      _Str1 = (char *)FUN_10004990((undefined4 *)this);
      iVar3 = _strnicmp(_Str1,param_1,_MaxCount);
      cVar2 = '\x01' - (iVar3 != 0);
    }
    else {
      cVar2 = '\0';
    }
  }
  return (bool)cVar2;
}



// public: bool __thiscall STRING::tailequ(char const *)const 

bool __thiscall STRING::tailequ(STRING *this,char *param_1)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  size_t sVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  size_t _MaxCount;
  
                    // 0x52ca  119  ?tailequ@STRING@@QBE_NPBD@Z
  if ((param_1 == (char *)0x0) || (*param_1 == '\0')) {
    cVar2 = '\0';
  }
  else {
    bVar1 = FUN_10002730((int *)this);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      sVar3 = strlen(param_1);
      uVar4 = FUN_10002a00((int *)this);
      if (uVar4 < sVar3) {
        cVar2 = '\0';
      }
      else {
        _MaxCount = sVar3;
        iVar5 = FUN_10004990((undefined4 *)this);
        iVar6 = FUN_10002a00((int *)this);
        iVar5 = strncmp((char *)((iVar5 + iVar6) - sVar3),param_1,_MaxCount);
        cVar2 = '\x01' - (iVar5 != 0);
      }
    }
    else {
      cVar2 = '\0';
    }
  }
  return (bool)cVar2;
}



// public: bool __thiscall STRING::equi(char const *)const 

bool __thiscall STRING::equi(STRING *this,char *param_1)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  char *_Str1;
  int iVar3;
  
                    // 0x534d  107  ?equi@STRING@@QBE_NPBD@Z
  if ((param_1 == (char *)0x0) || (*param_1 == '\0')) {
    cVar2 = '\0';
  }
  else {
    bVar1 = FUN_10002730((int *)this);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      _Str1 = (char *)FUN_10004990((undefined4 *)this);
      iVar3 = _stricmp(_Str1,param_1);
      cVar2 = '\x01' - (iVar3 != 0);
    }
    else {
      cVar2 = '\0';
    }
  }
  return (bool)cVar2;
}



// public: struct STRING & __thiscall STRING::Center(unsigned int)

STRING * __thiscall STRING::Center(STRING *this,uint param_1)

{
  CString *pCVar1;
  CString local_28 [4];
  CString local_24 [4];
  CString local_20 [4];
  uint local_1c;
  uint local_18;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x5399  16  ?Center@STRING@@QAEAAU1@I@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a7f1;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_1c = FUN_10002a00((int *)this);
  if (local_1c < param_1) {
    local_18 = param_1 - local_1c >> 1;
    CString::CString(local_14,' ',local_18);
    local_8 = 0;
    if (local_1c + local_18 * 2 != param_1) {
      CString::operator+=((CString *)this,(char *)&this_1000f158);
    }
    pCVar1 = (CString *)operator+(local_24,local_14);
    local_8._0_1_ = 1;
    pCVar1 = (CString *)operator+(local_28,pCVar1);
    local_8._0_1_ = 2;
    FUN_10002c30(local_20,pCVar1);
    local_8._0_1_ = 3;
    FUN_10004340(this,local_20);
    local_8._0_1_ = 2;
    FUN_10002ca0(local_20);
    local_8._0_1_ = 1;
    CString::~CString(local_28);
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_24);
    local_8 = 0xffffffff;
    CString::~CString(local_14);
  }
  ExceptionList = local_10;
  return this;
}



uint __cdecl FUN_100054c0(uint param_1,uint param_2)

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



void * __thiscall FUN_100054f0(void *this,char param_1,int param_2)

{
  CString::CString((CString *)this,param_1,param_2);
  return this;
}



undefined * FUN_10005510(void)

{
  return classCObject_exref;
}



undefined ** FUN_1000551a(void)

{
  return &PTR_DAT_1000b9b8;
}



// public: __thiscall CDib::CDib(void)

CDib * __thiscall CDib::CDib(CDib *this)

{
                    // 0x552a  2  ??0CDib@@QAE@XZ
  FUN_10002820((undefined4 *)this);
  *(undefined ***)this = &PTR_FUN_1000b9d0;
  *(undefined4 *)(this + 8) = 0;
  *(undefined4 *)(this + 4) = 0;
  *(undefined4 *)(this + 0xc) = 0;
  return this;
}



// public: virtual __thiscall CDib::~CDib(void)

void __thiscall CDib::~CDib(CDib *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x5567  8  ??1CDib@@UAE@XZ
  puStack_c = &LAB_1000a809;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)this = &PTR_FUN_1000b9d0;
  local_8 = 0;
  Free(this);
  local_8 = 0xffffffff;
  FUN_10002870((undefined4 *)this);
  ExceptionList = local_10;
  return;
}



// protected: void __thiscall CDib::Free(void)

void __thiscall CDib::Free(CDib *this)

{
  HGLOBAL pvVar1;
  HGDIOBJ in_stack_ffffffec;
  
                    // 0x55b8  29  ?Free@CDib@@IAEXXZ
  if (*(int *)(this + 4) != 0) {
    pvVar1 = GlobalHandle(*(LPCVOID *)(this + 4));
    GlobalUnlock(pvVar1);
    pvVar1 = GlobalHandle(*(LPCVOID *)(this + 4));
    GlobalFree(pvVar1);
    *(undefined4 *)(this + 4) = 0;
  }
  if (*(int *)(this + 8) != 0) {
    pvVar1 = GlobalHandle(*(LPCVOID *)(this + 8));
    GlobalUnlock(pvVar1);
    pvVar1 = GlobalHandle(*(LPCVOID *)(this + 8));
    GlobalFree(pvVar1);
    *(undefined4 *)(this + 8) = 0;
  }
  if (*(int *)(this + 0xc) != 0) {
    CGdiObject::DeleteObject(in_stack_ffffffec);
    if (*(int **)(this + 0xc) != (int *)0x0) {
      (**(code **)(**(int **)(this + 0xc) + 4))(1);
    }
    *(undefined4 *)(this + 0xc) = 0;
  }
  return;
}



// public: int __thiscall CDib::Paint(struct HDC__ *,struct tagRECT *,struct tagRECT *)const 

int __thiscall CDib::Paint(CDib *this,HDC__ *param_1,tagRECT *param_2,tagRECT *param_3)

{
  int iVar1;
  HPALETTE local_10;
  
                    // 0x5687  70  ?Paint@CDib@@QBEHPAUHDC__@@PAUtagRECT@@1@Z
  if (*(int *)(this + 8) == 0) {
    iVar1 = 0;
  }
  else {
    local_10 = (HPALETTE)0x0;
    if (*(int *)(this + 0xc) != 0) {
      local_10 = SelectPalette(param_1,*(HPALETTE *)(*(int *)(this + 0xc) + 4),1);
    }
    SetStretchBltMode(param_1,3);
    iVar1 = StretchDIBits(param_1,param_2->left,param_2->top,param_2->right - param_2->left,
                          param_2->bottom - param_2->top,param_3->left,param_3->top,
                          param_3->right - param_3->left,param_3->bottom - param_3->top,
                          *(void **)(this + 4),*(BITMAPINFO **)(this + 8),0,0xcc0020);
    if (local_10 != (HPALETTE)0x0) {
      SelectPalette(param_1,local_10,1);
    }
  }
  return iVar1;
}



// protected: int __thiscall CDib::CreatePalette(void)

HPALETTE CDib::CreatePalette(LOGPALETTE *plpal)

{
  ushort uVar1;
  HPALETTE pHVar2;
  HGLOBAL hMem;
  LOGPALETTE *pLVar3;
  CGdiObject *pCVar4;
  CDib *in_ECX;
  HGDIOBJ unaff_ESI;
  CGdiObject *local_40;
  int local_20;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x576f  20  ?CreatePalette@CDib@@IAEHXZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a81d;
  local_10 = ExceptionList;
  if (*(int *)(in_ECX + 8) == 0) {
    pHVar2 = (HPALETTE)0x0;
  }
  else {
    ExceptionList = &local_10;
    uVar1 = NumColors(in_ECX);
    if (uVar1 == 0) {
      pHVar2 = (HPALETTE)0x1;
    }
    else {
      hMem = GlobalAlloc(0x42,(uint)uVar1 * 4 + 8);
      if (hMem == (HGLOBAL)0x0) {
        pHVar2 = (HPALETTE)0x0;
      }
      else {
        pLVar3 = (LOGPALETTE *)GlobalLock(hMem);
        pLVar3->palVersion = 0x300;
        pLVar3->palNumEntries = uVar1;
        for (local_20 = 0; local_20 < (int)(uint)uVar1; local_20 = local_20 + 1) {
          pLVar3->palPalEntry[local_20].peRed =
               *(BYTE *)(*(int *)(in_ECX + 8) + 0x2a + local_20 * 4);
          pLVar3->palPalEntry[local_20].peGreen =
               *(BYTE *)(*(int *)(in_ECX + 8) + 0x29 + local_20 * 4);
          pLVar3->palPalEntry[local_20].peBlue =
               *(BYTE *)(*(int *)(in_ECX + 8) + 0x28 + local_20 * 4);
          pLVar3->palPalEntry[local_20].peFlags = '\0';
        }
        if (*(int *)(in_ECX + 0xc) != 0) {
          CGdiObject::DeleteObject(unaff_ESI);
          if (*(int **)(in_ECX + 0xc) != (int *)0x0) {
            (**(code **)(**(int **)(in_ECX + 0xc) + 4))(1);
          }
        }
        pCVar4 = (CGdiObject *)FUN_10005fb0(8);
        local_8 = 0;
        if (pCVar4 == (CGdiObject *)0x0) {
          local_40 = (CGdiObject *)0x0;
        }
        else {
          local_40 = FUN_10006050(pCVar4);
        }
        local_8 = 0xffffffff;
        *(CGdiObject **)(in_ECX + 0xc) = local_40;
        pHVar2 = (HPALETTE)FUN_100060c0(*(void **)(in_ECX + 0xc),pLVar3);
        GlobalUnlock(hMem);
        GlobalFree(hMem);
      }
    }
  }
  ExceptionList = local_10;
  return pHVar2;
}



// public: unsigned long __thiscall CDib::Width(void)const 

ulong __thiscall CDib::Width(CDib *this)

{
  ulong uVar1;
  
                    // 0x5937  100  ?Width@CDib@@QBEKXZ
  if (*(int *)(this + 8) == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = *(ulong *)(*(int *)(this + 8) + 4);
  }
  return uVar1;
}



// public: unsigned long __thiscall CDib::Height(void)const 

ulong __thiscall CDib::Height(CDib *this)

{
  ulong uVar1;
  
                    // 0x5958  59  ?Height@CDib@@QBEKXZ
  if (*(int *)(this + 8) == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = *(ulong *)(*(int *)(this + 8) + 8);
  }
  return uVar1;
}



// protected: unsigned short __thiscall CDib::PaletteSize(void)const 

ushort __thiscall CDib::PaletteSize(CDib *this)

{
  ushort uVar1;
  
                    // 0x5979  72  ?PaletteSize@CDib@@IBEGXZ
  if (*(int *)(this + 8) == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = NumColors(this);
    uVar1 = uVar1 << 2;
  }
  return uVar1;
}



// public: unsigned short __thiscall CDib::NumColors(void)const 

ushort __thiscall CDib::NumColors(CDib *this)

{
  short sVar1;
  ushort local_8;
  
                    // 0x59a2  66  ?NumColors@CDib@@QBEGXZ
  if (*(int *)(this + 8) == 0) {
    local_8 = 0;
  }
  else if (*(int *)(*(int *)(this + 8) + 0x20) == 0) {
    sVar1 = *(short *)(*(int *)(this + 8) + 0xe);
    if (sVar1 == 1) {
      local_8 = 2;
    }
    else if (sVar1 == 4) {
      local_8 = 0x10;
    }
    else if (sVar1 == 8) {
      local_8 = 0x100;
    }
    else {
      local_8 = 0;
    }
  }
  else {
    local_8 = (ushort)*(int *)(*(int *)(this + 8) + 0x20);
  }
  return local_8;
}



// public: unsigned long __thiscall CDib::Save(class CFile &)const 

ulong __thiscall CDib::Save(CDib *this,CFile *param_1)

{
  int *piVar1;
  int iVar2;
  ushort uVar3;
  ulong uVar4;
  uint local_24;
  int local_1c;
  undefined2 local_18;
  int local_16;
  undefined2 local_12;
  undefined2 local_10;
  int local_e;
  ulong local_8;
  
                    // 0x5a18  89  ?Save@CDib@@QBEKAAVCFile@@@Z
  if (*(int *)(this + 8) == 0) {
    local_8 = 0;
  }
  else {
    local_18 = 0x4d42;
    piVar1 = *(int **)(this + 8);
    uVar3 = PaletteSize(this);
    iVar2 = *piVar1;
    if ((*(int *)(*(int *)(this + 8) + 0x10) == 1) || (*(int *)(*(int *)(this + 8) + 0x10) == 2)) {
      local_1c = *(int *)(*(int *)(this + 8) + 0x14);
    }
    else {
      local_1c = (*(int *)(*(int *)(this + 8) + 4) * (uint)*(ushort *)(*(int *)(this + 8) + 0xe) +
                  0x1f >> 5) * 4 * *(int *)(*(int *)(this + 8) + 8);
      *(int *)(*(int *)(this + 8) + 0x14) = local_1c;
    }
    local_1c = iVar2 + (uint)uVar3 + local_1c;
    local_16 = local_1c + 0xe;
    local_12 = 0;
    local_10 = 0;
    iVar2 = **(int **)(this + 8);
    uVar3 = PaletteSize(this);
    local_e = iVar2 + 0xe + (uint)uVar3;
    (**(code **)(*(int *)param_1 + 0x40))(&local_18,0xe);
    local_8 = 0xe;
    uVar3 = NumColors(this);
    iVar2 = (uint)uVar3 * 4 + 0x28;
    local_8 = local_8 + iVar2;
    (**(code **)(*(int *)param_1 + 0x40))(*(undefined4 *)(this + 8),iVar2);
    uVar3 = *(ushort *)(*(int *)(this + 8) + 0xe);
    uVar4 = Width(this);
    local_24 = uVar3 * uVar4;
    if (local_24 % 0x20 == 0) {
      local_24 = local_24 >> 3;
    }
    else {
      local_24 = (local_24 >> 3) + (0x20 - local_24 % 0x20 >> 3) +
                 (uint)((0x20 - local_24 % 0x20) % 8 != 0);
    }
    uVar4 = Height(this);
    local_8 = local_8 + local_24 * uVar4;
    FUN_10005ff0(param_1,*(undefined4 *)(this + 4),local_24 * uVar4);
  }
  return local_8;
}



// public: unsigned long __thiscall CDib::Read(class CFile &)

ulong __thiscall CDib::Read(CDib *this,CFile *param_1)

{
  int iVar1;
  ulong uVar2;
  HGLOBAL pvVar3;
  LPVOID pvVar4;
  int iVar5;
  int iVar6;
  LOGPALETTE *plpal;
  uint local_14 [2];
  int local_a;
  
                    // 0x5bf2  85  ?Read@CDib@@QAEKAAVCFile@@@Z
  Free(this);
  iVar1 = (**(code **)(*(int *)param_1 + 0x3c))(local_14,0xe);
  if (iVar1 == 0xe) {
    if ((local_14[0] & 0xffff) == 0x4d42) {
      pvVar3 = GlobalAlloc(0x42,local_a + 0x3f2);
      pvVar4 = GlobalLock(pvVar3);
      *(LPVOID *)(this + 8) = pvVar4;
      if (*(int *)(this + 8) == 0) {
        uVar2 = 0;
      }
      else {
        plpal = *(LOGPALETTE **)(this + 8);
        iVar5 = (**(code **)(*(int *)param_1 + 0x3c))(plpal,local_a + -0xe);
        iVar1 = local_a;
        if (iVar5 == local_a + -0xe) {
          iVar5 = (**(code **)(*(int *)param_1 + 0x38))();
          pvVar3 = GlobalAlloc(0x42,iVar5 - local_a);
          pvVar4 = GlobalLock(pvVar3);
          *(LPVOID *)(this + 4) = pvVar4;
          if (*(int *)(this + 4) == 0) {
            pvVar3 = GlobalHandle(*(LPCVOID *)(this + 8));
            GlobalUnlock(pvVar3);
            pvVar3 = GlobalHandle(*(LPCVOID *)(this + 8));
            GlobalFree(pvVar3);
            *(undefined4 *)(this + 8) = 0;
            uVar2 = 0;
          }
          else {
            iVar6 = CAsyncSocket::Connect
                              ((CAsyncSocket *)param_1,*(sockaddr **)(this + 4),iVar5 - local_a);
            if (iVar6 == iVar5 - local_a) {
              uVar2 = iVar1 + (iVar5 - local_a);
              CreatePalette(plpal);
            }
            else {
              pvVar3 = GlobalHandle(*(LPCVOID *)(this + 8));
              GlobalUnlock(pvVar3);
              pvVar3 = GlobalHandle(*(LPCVOID *)(this + 8));
              GlobalFree(pvVar3);
              *(undefined4 *)(this + 8) = 0;
              pvVar3 = GlobalHandle(*(LPCVOID *)(this + 4));
              GlobalUnlock(pvVar3);
              pvVar3 = GlobalHandle(*(LPCVOID *)(this + 4));
              GlobalFree(pvVar3);
              *(undefined4 *)(this + 4) = 0;
              uVar2 = 0;
            }
          }
        }
        else {
          pvVar3 = GlobalHandle(*(LPCVOID *)(this + 8));
          GlobalUnlock(pvVar3);
          pvVar3 = GlobalHandle(*(LPCVOID *)(this + 8));
          GlobalFree(pvVar3);
          *(undefined4 *)(this + 8) = 0;
          uVar2 = 0;
        }
      }
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



// public: void * __thiscall CDib::CopyToHandle(void)const 

void * __thiscall CDib::CopyToHandle(CDib *this)

{
  ulong uVar1;
  void *pvVar2;
  CSharedFile local_48 [52];
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x5de8  18  ?CopyToHandle@CDib@@QBEPAXXZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a830;
  local_10 = ExceptionList;
  local_14 = &stack0xffffff94;
  ExceptionList = &local_10;
  CSharedFile::CSharedFile(local_48,0x2002,0x1000);
  local_8 = 1;
  uVar1 = Save(this,(CFile *)local_48);
  if (uVar1 == 0) {
    local_8 = 0xffffffff;
    CSharedFile::~CSharedFile(local_48);
    ExceptionList = local_10;
    return (void *)0x0;
  }
  pvVar2 = (void *)FUN_10005e85();
  return pvVar2;
}



undefined * Catch_10005e5c(void)

{
  int unaff_EBP;
  
  CException::Delete(*(CException **)(unaff_EBP + -0x48));
  *(undefined4 *)(unaff_EBP + -0x50) = 0;
  return &DAT_10005e71;
}



undefined4 FUN_10005e85(void)

{
  void *pvVar1;
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -4) = 0;
  pvVar1 = CSharedFile::Detach((CSharedFile *)(unaff_EBP + -0x44));
  *(void **)(unaff_EBP + -0x54) = pvVar1;
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  CSharedFile::~CSharedFile((CSharedFile *)(unaff_EBP + -0x44));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return *(undefined4 *)(unaff_EBP + -0x54);
}



// public: unsigned long __thiscall CDib::ReadFromHandle(void *)

ulong __thiscall CDib::ReadFromHandle(CDib *this,void *param_1)

{
  ulong uVar1;
  CSharedFile local_48 [52];
  ulong local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x5eba  86  ?ReadFromHandle@CDib@@QAEKPAX@Z
  local_8 = 0xffffffff;
  puStack_c = &param_2_1000a843;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CSharedFile::CSharedFile(local_48,0x2002,0x1000);
  local_8 = 0;
  CSharedFile::SetHandle(local_48,param_1,0);
  local_14 = Read(this,(CFile *)local_48);
  CSharedFile::Detach(local_48);
  uVar1 = local_14;
  local_8 = 0xffffffff;
  CSharedFile::~CSharedFile(local_48);
  ExceptionList = local_10;
  return uVar1;
}



// public: virtual void __thiscall CDib::Serialize(class CArchive &)

void __thiscall CDib::Serialize(CDib *this,CArchive *param_1)

{
  bool bVar1;
  CFile *pCVar2;
  undefined3 extraout_var;
  
                    // 0x5f3e  90  ?Serialize@CDib@@UAEXAAVCArchive@@@Z
  pCVar2 = (CFile *)FUN_10006030((int)param_1);
  bVar1 = FUN_10006010((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    Read(this,pCVar2);
  }
  else {
    Save(this,pCVar2);
  }
  return;
}



void * __thiscall FUN_10005f80(void *this,uint param_1)

{
  CDib::~CDib((CDib *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001660(this);
  }
  return this;
}



void FUN_10005fb0(uint param_1)

{
  operator_new(param_1);
  return;
}



// Library Function - Single Match
//  public: int __thiscall CAsyncSocket::Connect(struct sockaddr const *,int)
// 
// Library: Visual Studio 2003 Debug

int __thiscall CAsyncSocket::Connect(CAsyncSocket *this,sockaddr *param_1,int param_2)

{
  int iVar1;
  
  iVar1 = (**(code **)(*(int *)this + 0x3c))(param_1,param_2);
  return iVar1;
}



void __thiscall FUN_10005ff0(void *this,undefined4 param_1,undefined4 param_2)

{
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x40))(param_1,param_2);
  return;
}



bool __fastcall FUN_10006010(int param_1)

{
  return (bool)('\x01' - ((*(uint *)(param_1 + 0x14) & 1) != 0));
}



undefined4 __fastcall FUN_10006030(int param_1)

{
  return *(undefined4 *)(param_1 + 0x20);
}



CGdiObject * __fastcall FUN_10006050(CGdiObject *param_1)

{
  CGdiObject::CGdiObject(param_1);
  *(undefined ***)param_1 = &PTR_LAB_1000b9e4;
  return param_1;
}



void * __thiscall FUN_10006070(void *this,uint param_1)

{
  FUN_100060a0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001660(this);
  }
  return this;
}



void __fastcall FUN_100060a0(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_1000b9e4;
  FUN_100028c0(param_1);
  return;
}



void __thiscall FUN_100060c0(void *this,LOGPALETTE *param_1)

{
  HPALETTE pHVar1;
  
  pHVar1 = CreatePalette(param_1);
  CGdiObject::Attach((CGdiObject *)this,pHVar1);
  return;
}



// public: __thiscall INIFILE::INIFILE(void)

INIFILE * __thiscall INIFILE::INIFILE(INIFILE *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x60e0  5  ??0INIFILE@@QAE@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a859;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString((CString *)this);
  local_8 = 0;
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)(this + 4));
  ExceptionList = local_10;
  return this;
}



// public: __thiscall INIFILE::INIFILE(char const *,int)

INIFILE * __thiscall INIFILE::INIFILE(INIFILE *this,char *param_1,int param_2)

{
  char cVar1;
  char *pcVar2;
  CString *pCVar3;
  int iVar4;
  undefined4 *puVar5;
  CString local_43c [8];
  CString local_434 [4];
  undefined1 *local_430;
  undefined1 *local_42c;
  CString local_428 [8];
  CString local_420 [4];
  FILE *local_41c;
  CString local_418 [4];
  CString local_414 [4];
  char local_410;
  undefined4 local_40f;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x612e  4  ??0INIFILE@@QAE@PBDH@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a8de;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString((CString *)this,param_1);
  local_8 = 0;
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)(this + 4));
  local_8 = CONCAT31(local_8._1_3_,1);
  *(int *)(this + 0x20) = param_2;
  local_41c = fopen(param_1,(char *)&_Mode_1000f164);
  if (local_41c == (FILE *)0x0) {
    local_41c = fopen(param_1,(char *)&_Mode_1000f168);
    fclose(local_41c);
  }
  else if (local_41c != (FILE *)0x0) {
    local_410 = '\0';
    puVar5 = &local_40f;
    for (iVar4 = 0xff; iVar4 != 0; iVar4 = iVar4 + -1) {
      *puVar5 = 0;
      puVar5 = puVar5 + 1;
    }
    *(undefined2 *)puVar5 = 0;
    *(undefined1 *)((int)puVar5 + 2) = 0;
    CString::CString(local_414,s_NO_SECTION_1000f16c);
    local_8._0_1_ = 2;
    CString::CString(local_418);
    local_8._0_1_ = 3;
    while (pcVar2 = fgets(&local_410,0x400,local_41c), pcVar2 != (char *)0x0) {
      FUN_10002c50(local_420,&local_410);
      local_8._0_1_ = 4;
      cVar1 = FUN_10004890(local_420,0);
      if (cVar1 == '[') {
        local_42c = &stack0xfffffb80;
        CString::CString((CString *)&stack0xfffffb80,local_418);
        local_8._0_1_ = 5;
        local_430 = &stack0xfffffb7c;
        CString::CString((CString *)&stack0xfffffb7c,local_414);
        local_8._0_1_ = 4;
        pCVar3 = FUN_10008660(local_428);
        local_8._0_1_ = 6;
        FUN_10007af0(this + 4,pCVar3);
        local_8._0_1_ = 4;
        FUN_100046c0(local_428);
        pCVar3 = (CString *)CString::SpanExcluding(local_420,(char *)local_434);
        local_8._0_1_ = 7;
        CString::operator=(local_414,pCVar3);
        local_8._0_1_ = 4;
        CString::~CString(local_434);
        CString::TrimLeft(local_414,&DAT_1000f17c);
        CString::operator=(local_418,&DAT_1000f498);
        local_8._0_1_ = 3;
        FUN_10002ca0(local_420);
      }
      else {
        CString::operator+=(local_418,&local_410);
        local_8._0_1_ = 3;
        FUN_10002ca0(local_420);
      }
    }
    CString::CString((CString *)&stack0xfffffb80,local_418);
    local_8._0_1_ = 8;
    CString::CString((CString *)&stack0xfffffb7c,local_414);
    local_8._0_1_ = 3;
    pCVar3 = FUN_10008660(local_43c);
    local_8._0_1_ = 9;
    FUN_10007af0(this + 4,pCVar3);
    local_8._0_1_ = 3;
    FUN_100046c0(local_43c);
    fclose(local_41c);
    local_8._0_1_ = 2;
    CString::~CString(local_418);
    local_8 = CONCAT31(local_8._1_3_,1);
    CString::~CString(local_414);
  }
  ExceptionList = local_10;
  return this;
}



CString * __thiscall FUN_1000648a(void *this,CString *param_1,undefined4 *param_2)

{
  bool bVar1;
  bool bVar2;
  undefined3 extraout_var;
  CString *pCVar3;
  uint uVar4;
  undefined3 extraout_var_00;
  uchar *puVar5;
  CString local_30 [8];
  CString local_28 [8];
  uint local_20;
  int local_1c;
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a928;
  local_10 = ExceptionList;
  bVar1 = false;
  ExceptionList = &local_10;
  local_1c = FUN_100045e0((int)this + 4);
  FUN_10004be0(local_18);
  local_8 = 1;
  local_20 = 0;
  bVar2 = IsEmpty((int)this + 4);
  if (CONCAT31(extraout_var,bVar2) == 0) {
    pCVar3 = (CString *)FUN_10007eb0(local_28,&local_1c);
    local_8._0_1_ = 2;
    FUN_10004660(local_18,pCVar3);
    local_8 = CONCAT31(local_8._1_3_,1);
    FUN_100046c0(local_28);
  }
  local_20 = 0;
  while ((uVar4 = FUN_10007e90((int)this + 4), local_20 < uVar4 &&
         (bVar2 = IsEmpty((int)this + 4), CONCAT31(extraout_var_00,bVar2) == 0))) {
    puVar5 = (uchar *)FUN_10004990(param_2);
    bVar2 = FUN_10008600(local_18,puVar5);
    if (bVar2) {
      CString::CString(param_1,local_14);
      local_8 = local_8 & 0xffffff00;
      FUN_100046c0(local_18);
      ExceptionList = local_10;
      return param_1;
    }
    local_20 = local_20 + 1;
    uVar4 = FUN_10007e90((int)this + 4);
    if (local_20 < uVar4) {
      pCVar3 = (CString *)FUN_10007eb0(local_30,&local_1c);
      bVar1 = true;
      local_8 = CONCAT31(local_8._1_3_,3);
      FUN_10004660(local_18,pCVar3);
    }
    local_8 = 1;
    if (bVar1) {
      bVar1 = false;
      FUN_100046c0(local_30);
    }
  }
  CString::CString(param_1);
  local_8 = local_8 & 0xffffff00;
  FUN_100046c0(local_18);
  ExceptionList = local_10;
  return param_1;
}



CString * FUN_1000663e(CString *param_1,CString *param_2)

{
  bool bVar1;
  undefined3 extraout_var;
  CString *pCVar2;
  STRING *pSVar3;
  CString local_20 [4];
  STRING local_1c [4];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a96d;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10004b40(local_18);
  local_8 = 1;
  FUN_10002c30(local_14,param_2);
  local_8._0_1_ = 2;
  do {
    while( true ) {
      bVar1 = FUN_10002730((int *)local_14);
      if (CONCAT31(extraout_var,bVar1) != 0) {
        pSVar3 = STRING::trim((STRING *)local_18,&DAT_1000f18c);
        CString::CString(param_1,(CString *)pSVar3);
        local_8._0_1_ = 1;
        FUN_10002ca0(local_14);
        local_8 = (uint)local_8._1_3_ << 8;
        FUN_10002ca0(local_18);
        ExceptionList = local_10;
        return param_1;
      }
      STRING::strtok((char *)local_1c,&DAT_1000f180);
      local_8._0_1_ = 3;
      bVar1 = STRING::headequ(local_1c,&DAT_1000f184);
      if (!bVar1) break;
LAB_100066d0:
      local_8._0_1_ = 2;
      FUN_10002ca0((CString *)local_1c);
    }
    bVar1 = STRING::isblank(local_1c);
    if (bVar1) goto LAB_100066d0;
    pCVar2 = (CString *)operator+(local_20,(char *)local_1c);
    local_8._0_1_ = 4;
    CString::operator+=(local_18,pCVar2);
    local_8._0_1_ = 3;
    CString::~CString(local_20);
    local_8._0_1_ = 2;
    FUN_10002ca0((CString *)local_1c);
  } while( true );
}



// public: struct STRING __thiscall INIFILE::GetSection(char const *)const 

char * __thiscall INIFILE::GetSection(INIFILE *this,char *param_1)

{
  CString *pCVar1;
  char *in_stack_00000008;
  CString local_1c [4];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x676f  50  ?GetSection@INIFILE@@QBE?AUSTRING@@PBD@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a9a9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(local_14,in_stack_00000008);
  local_8 = 1;
  pCVar1 = FUN_1000648a(this,local_18,(undefined4 *)local_14);
  local_8._0_1_ = 2;
  pCVar1 = FUN_1000663e(local_1c,pCVar1);
  local_8._0_1_ = 3;
  FUN_10002c30(param_1,pCVar1);
  local_8._0_1_ = 2;
  CString::~CString(local_1c);
  local_8._0_1_ = 1;
  CString::~CString(local_18);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(local_14);
  ExceptionList = local_10;
  return param_1;
}



// public: void __thiscall INIFILE::DeleteSection(char const *)

void __thiscall INIFILE::DeleteSection(INIFILE *this,char *param_1)

{
  CString *pCVar1;
  CString local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x682d  22  ?DeleteSection@INIFILE@@QAEXPBD@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a9c5;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString((CString *)&stack0xffffffc4,(char *)&this_1000f49c);
  local_8 = 0;
  CString::CString((CString *)&stack0xffffffc0,param_1);
  local_8 = 0xffffffff;
  pCVar1 = FUN_10008660(local_18);
  local_8 = 1;
  FUN_10007c40(this + 4,(undefined4 *)pCVar1);
  local_8 = 0xffffffff;
  FUN_100046c0(local_18);
  if (*(int *)(this + 0x20) != 0) {
    flush(this);
  }
  ExceptionList = local_10;
  return;
}



// public: void __thiscall INIFILE::PutSection(char const *,char const *)

void __thiscall INIFILE::PutSection(INIFILE *this,char *param_1,char *param_2)

{
  STRING *this_00;
  char *pcVar1;
  undefined1 local_30 [32];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x68db  81  ?PutSection@INIFILE@@QAEXPBD0@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000a9fc;
  local_10 = ExceptionList;
  pcVar1 = &DAT_1000f190;
  ExceptionList = &local_10;
  this_00 = (STRING *)FUN_10002c50(local_30,param_2);
  local_8 = 0;
                    // WARNING: Subroutine does not return
  STRING::terminate(this_00,pcVar1);
}



// public: void __thiscall INIFILE::flush(void)

void __thiscall INIFILE::flush(INIFILE *this)

{
  bool bVar1;
  undefined4 *puVar2;
  char *pcVar3;
  undefined3 extraout_var;
  CString *pCVar4;
  uint uVar5;
  undefined3 extraout_var_00;
  CString *this_00;
  char *_Mode;
  FILE *_File;
  CString local_30 [4];
  CString local_2c [4];
  FILE *local_28;
  uint local_24;
  int local_20;
  CString local_1c [4];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x6aed  111  ?flush@INIFILE@@QAEXXZ
  local_8 = 0xffffffff;
  puStack_c = &_Mode_1000aa2a;
  local_10 = ExceptionList;
  _Mode = &DAT_1000f194;
  ExceptionList = &local_10;
  puVar2 = (undefined4 *)base(this,local_30);
  local_8 = 0;
  pcVar3 = (char *)FUN_10004990(puVar2);
  local_28 = fopen(pcVar3,_Mode);
  local_8 = 0xffffffff;
  FUN_10002ca0(local_30);
  if (local_28 != (FILE *)0x0) {
    CString::CString(local_1c);
    local_8 = 1;
    local_20 = FUN_100045e0((int)(this + 4));
    FUN_10004be0(local_18);
    local_8 = CONCAT31(local_8._1_3_,2);
    local_24 = 0;
    bVar1 = IsEmpty((int)(this + 4));
    if (CONCAT31(extraout_var,bVar1) == 0) {
      pCVar4 = (CString *)FUN_10008420(&local_20);
      FUN_10004660(local_18,pCVar4);
    }
    local_24 = 0;
    while ((uVar5 = FUN_10007e90((int)(this + 4)), local_24 < uVar5 &&
           (bVar1 = IsEmpty((int)(this + 4)), CONCAT31(extraout_var_00,bVar1) == 0))) {
      bVar1 = FUN_10008600(local_18,(uchar *)s_NO_SECTION_1000f198);
      if (bVar1) {
        CString::operator+=(local_1c,local_14);
      }
      else {
        CString::CString(local_2c);
        local_8._0_1_ = 3;
        FUN_10004990((undefined4 *)local_14);
        FUN_10004990((undefined4 *)local_18);
        CString::Format(this_00,(char *)local_2c);
        CString::operator+=(local_1c,local_2c);
        local_8 = CONCAT31(local_8._1_3_,2);
        CString::~CString(local_2c);
      }
      local_24 = local_24 + 1;
      uVar5 = FUN_10007e90((int)(this + 4));
      if (local_24 < uVar5) {
        pCVar4 = (CString *)FUN_10008420(&local_20);
        FUN_10004660(local_18,pCVar4);
      }
    }
    _File = local_28;
    pcVar3 = (char *)FUN_10004990((undefined4 *)local_1c);
    fputs(pcVar3,_File);
    fclose(local_28);
    local_8 = CONCAT31(local_8._1_3_,1);
    FUN_100046c0(local_18);
    local_8 = 0xffffffff;
    CString::~CString(local_1c);
  }
  ExceptionList = local_10;
  return;
}



// WARNING: Variable defined which should be unmapped: param_1
// public: struct STRING __thiscall INIFILE::GetValue(char const *,char const *)const 

char * __thiscall INIFILE::GetValue(INIFILE *this,char *param_1,char *param_2)

{
  bool bVar1;
  undefined3 extraout_var;
  STRING *pSVar2;
  char *_Str1;
  int iVar3;
  char *in_stack_0000000c;
  char *pcVar4;
  CString local_20 [4];
  STRING local_1c [4];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
                    // 0x6ce6  55  ?GetValue@INIFILE@@QBE?AUSTRING@@PBD0@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000aa6f;
  local_10 = ExceptionList;
  if (param_2 == (char *)0x0) {
    ExceptionList = &local_10;
    FUN_10002c50(param_1,(char *)0x0);
  }
  else if (in_stack_0000000c == (char *)0x0) {
    ExceptionList = &local_10;
    FUN_10002c50(param_1,(char *)0x0);
  }
  else {
    ExceptionList = &local_10;
    GetSection(this,(char *)local_14);
    local_8 = 1;
    while (bVar1 = FUN_10002730((int *)local_14), CONCAT31(extraout_var,bVar1) == 0) {
      STRING::strtok((char *)local_1c,&DAT_1000f1ac);
      local_8._0_1_ = 2;
      pcVar4 = &DAT_1000f1b4;
      pSVar2 = (STRING *)STRING::strtok((char *)local_20,&DAT_1000f1b0);
      local_8._0_1_ = 3;
      pSVar2 = STRING::trim(pSVar2,pcVar4);
      FUN_10007a80(local_18,(CString *)pSVar2);
      local_8._0_1_ = 5;
      FUN_10002ca0(local_20);
      pcVar4 = in_stack_0000000c;
      _Str1 = (char *)FUN_10004990((undefined4 *)local_18);
      iVar3 = _stricmp(_Str1,pcVar4);
      if (iVar3 == 0) {
        pSVar2 = STRING::trim(local_1c,&DAT_1000f1bc);
        FUN_10007a80(param_1,(CString *)pSVar2);
        local_8._0_1_ = 2;
        FUN_10002ca0(local_18);
        local_8._0_1_ = 1;
        FUN_10002ca0((CString *)local_1c);
        local_8 = (uint)local_8._1_3_ << 8;
        FUN_10002ca0(local_14);
        ExceptionList = local_10;
        return param_1;
      }
      local_8._0_1_ = 2;
      FUN_10002ca0(local_18);
      local_8 = CONCAT31(local_8._1_3_,1);
      FUN_10002ca0((CString *)local_1c);
    }
    FUN_10004b40((CString *)param_1);
    local_8 = local_8 & 0xffffff00;
    FUN_10002ca0(local_14);
  }
  ExceptionList = local_10;
  return param_1;
}



// public: void __thiscall INIFILE::PutValue(char const *,char const *,char const *)

void __thiscall INIFILE::PutValue(INIFILE *this,char *param_1,char *param_2,char *param_3)

{
  undefined1 uVar1;
  bool bVar2;
  CString *pCVar3;
  undefined3 extraout_var;
  char *pcVar4;
  undefined4 *puVar5;
  undefined3 extraout_var_00;
  STRING *this_00;
  undefined3 extraout_var_01;
  CString local_8c [4];
  CString local_88 [4];
  CString local_84 [4];
  CString local_80 [4];
  CString local_7c [4];
  CString local_78 [4];
  CString local_74 [4];
  CString local_70 [4];
  CString local_6c [4];
  CString local_68 [4];
  CString local_64 [4];
  CString local_60 [4];
  CString local_5c [4];
  CString local_58 [4];
  CString local_54 [4];
  CString local_50 [4];
  CString local_4c [4];
  CString local_48 [4];
  CString local_44 [4];
  CString local_40 [4];
  CString local_3c [4];
  CString local_38 [4];
  CString local_34 [4];
  STRING local_30 [4];
  CString local_2c [4];
  CString local_28 [4];
  STRING local_24 [4];
  CString local_20 [4];
  CString local_1c [4];
  CString local_18 [4];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x6e87  83  ?PutValue@INIFILE@@QAEXPBD00@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ab8d;
  local_10 = ExceptionList;
  if (((param_1 != (char *)0x0) && (param_2 != (char *)0x0)) && (param_3 != (char *)0x0)) {
    ExceptionList = &local_10;
    FUN_10004b40(local_18);
    local_8 = 0;
    CString::CString(local_38,param_1);
    local_8._0_1_ = 1;
    pCVar3 = FUN_1000648a(this,local_3c,(undefined4 *)local_38);
    local_8._0_1_ = 2;
    FUN_10002c30(local_34,pCVar3);
    local_8._0_1_ = 3;
    FUN_10004340(local_18,local_34);
    local_8._0_1_ = 2;
    FUN_10002ca0(local_34);
    local_8._0_1_ = 1;
    CString::~CString(local_3c);
    local_8._0_1_ = 0;
    CString::~CString(local_38);
    bVar2 = FUN_10002730((int *)local_18);
    if (CONCAT31(extraout_var,bVar2) == 0) {
      FUN_10002c50(local_1c,param_2);
      local_8._0_1_ = 7;
      FUN_10004b40(local_20);
      local_8._0_1_ = 8;
      local_14 = local_14 & 0xffffff00;
      while (bVar2 = FUN_10002730((int *)local_18), CONCAT31(extraout_var_00,bVar2) == 0) {
        STRING::strtok((char *)local_2c,&DAT_1000f1c8);
        local_8._0_1_ = 9;
        FUN_10007a80(local_28,local_2c);
        local_8._0_1_ = 10;
        STRING::strtok((char *)local_24,&DAT_1000f1cc);
        local_8._0_1_ = 0xb;
        pcVar4 = param_2;
        this_00 = STRING::trim(local_24,&DAT_1000f1d0);
        bVar2 = STRING::equi(this_00,pcVar4);
        if (bVar2) {
          local_14 = CONCAT31(local_14._1_3_,1);
          pcVar4 = (char *)operator+(local_4c,(char *)local_24);
          local_8._0_1_ = 0xc;
          pcVar4 = (char *)operator+(local_50,pcVar4);
          local_8._0_1_ = 0xd;
          pCVar3 = (CString *)operator+(local_54,pcVar4);
          local_8._0_1_ = 0xe;
          CString::operator+=(local_20,pCVar3);
          local_8._0_1_ = 0xd;
          CString::~CString(local_54);
          local_8._0_1_ = 0xc;
          CString::~CString(local_50);
          local_8 = CONCAT31(local_8._1_3_,0xb);
          CString::~CString(local_4c);
        }
        else {
          pCVar3 = (CString *)operator+(local_58,(char *)local_28);
          local_8._0_1_ = 0xf;
          CString::operator+=(local_20,pCVar3);
          local_8 = CONCAT31(local_8._1_3_,0xb);
          CString::~CString(local_58);
        }
        local_8._0_1_ = 10;
        FUN_10002ca0((CString *)local_24);
        local_8._0_1_ = 9;
        FUN_10002ca0(local_28);
        local_8._0_1_ = 8;
        FUN_10002ca0(local_2c);
      }
      if ((local_14 & 0xff) == 0) {
        CString::CString(local_60,param_1);
        local_8._0_1_ = 0x10;
        pCVar3 = FUN_1000648a(this,local_64,(undefined4 *)local_60);
        local_8._0_1_ = 0x11;
        FUN_10002c30(local_5c,pCVar3);
        local_8._0_1_ = 0x12;
        FUN_10004340(local_18,local_5c);
        local_8._0_1_ = 0x11;
        FUN_10002ca0(local_5c);
        local_8._0_1_ = 0x10;
        CString::~CString(local_64);
        local_8._0_1_ = 8;
        CString::~CString(local_60);
        FUN_10002c50(local_68,&DAT_1000f4a0);
        local_8._0_1_ = 0x13;
        FUN_10004340(local_20,local_68);
        local_8._0_1_ = 8;
        FUN_10002ca0(local_68);
        while (bVar2 = FUN_10002730((int *)local_18), CONCAT31(extraout_var_01,bVar2) == 0) {
          STRING::strtok((char *)local_30,&DAT_1000f1e4);
          local_8._0_1_ = 0x14;
          uVar1 = (undefined1)local_8;
          local_8._0_1_ = 0x14;
          if (((local_14 & 0xff) == 0) &&
             (bVar2 = STRING::isblank(local_30), uVar1 = (undefined1)local_8, bVar2)) {
            local_14 = CONCAT31(local_14._1_3_,1);
            pcVar4 = (char *)FUN_10002c50(local_6c,param_2);
            local_8._0_1_ = 0x15;
            pcVar4 = (char *)operator+(local_70,pcVar4);
            local_8._0_1_ = 0x16;
            pcVar4 = (char *)operator+(local_74,pcVar4);
            local_8._0_1_ = 0x17;
            pCVar3 = (CString *)operator+(local_78,pcVar4);
            local_8._0_1_ = 0x18;
            CString::operator+=(local_20,pCVar3);
            local_8._0_1_ = 0x17;
            CString::~CString(local_78);
            local_8._0_1_ = 0x16;
            CString::~CString(local_74);
            local_8._0_1_ = 0x15;
            CString::~CString(local_70);
            local_8._0_1_ = 0x14;
            FUN_10002ca0(local_6c);
            uVar1 = (undefined1)local_8;
          }
          local_8._0_1_ = uVar1;
          pCVar3 = (CString *)operator+(local_7c,(char *)local_30);
          local_8._0_1_ = 0x19;
          CString::operator+=(local_20,pCVar3);
          local_8._0_1_ = 0x14;
          CString::~CString(local_7c);
          local_8._0_1_ = 8;
          FUN_10002ca0((CString *)local_30);
        }
        if ((local_14 & 0xff) == 0) {
          pcVar4 = (char *)FUN_10002c50(local_80,param_2);
          local_8._0_1_ = 0x1a;
          pcVar4 = (char *)operator+(local_84,pcVar4);
          local_8._0_1_ = 0x1b;
          pcVar4 = (char *)operator+(local_88,pcVar4);
          local_8._0_1_ = 0x1c;
          pCVar3 = (CString *)operator+(local_8c,pcVar4);
          local_8._0_1_ = 0x1d;
          CString::operator+=(local_20,pCVar3);
          local_8._0_1_ = 0x1c;
          CString::~CString(local_8c);
          local_8._0_1_ = 0x1b;
          CString::~CString(local_88);
          local_8._0_1_ = 0x1a;
          CString::~CString(local_84);
          local_8._0_1_ = 8;
          FUN_10002ca0(local_80);
        }
      }
      pcVar4 = (char *)FUN_10004990((undefined4 *)local_20);
      PutSection(this,param_1,pcVar4);
      local_8._0_1_ = 7;
      FUN_10002ca0(local_20);
      local_8 = (uint)local_8._1_3_ << 8;
      FUN_10002ca0(local_1c);
      local_8 = 0xffffffff;
      FUN_10002ca0(local_18);
    }
    else {
      pcVar4 = (char *)FUN_10002c50(local_40,param_2);
      local_8._0_1_ = 4;
      pcVar4 = (char *)operator+(local_44,pcVar4);
      local_8._0_1_ = 5;
      puVar5 = (undefined4 *)operator+(local_48,pcVar4);
      local_8._0_1_ = 6;
      pcVar4 = (char *)FUN_10004990(puVar5);
      PutSection(this,param_1,pcVar4);
      local_8._0_1_ = 5;
      CString::~CString(local_48);
      local_8._0_1_ = 4;
      CString::~CString(local_44);
      local_8 = (uint)local_8._1_3_ << 8;
      FUN_10002ca0(local_40);
      local_8 = 0xffffffff;
      FUN_10002ca0(local_18);
    }
  }
  ExceptionList = local_10;
  return;
}



// public: __thiscall INIFILE::~INIFILE(void)

void __thiscall INIFILE::~INIFILE(INIFILE *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x757e  10  ??1INIFILE@@QAE@XZ
  puStack_c = &LAB_1000aba0;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  FUN_10007a60((undefined4 *)(this + 4));
  local_8 = 0xffffffff;
  CString::~CString((CString *)this);
  ExceptionList = local_10;
  return;
}



// public: struct STRING __thiscall INIFILE::SECTION::Get(char const *)

char * __thiscall INIFILE::SECTION::Get(SECTION *this,char *param_1)

{
  char *pcVar1;
  
                    // 0x75c9  33  ?Get@SECTION@INIFILE@@QAE?AUSTRING@@PBD@Z
  pcVar1 = (char *)FUN_10004990((undefined4 *)(this + 4));
  GetValue(*(INIFILE **)this,param_1,pcVar1);
  return param_1;
}



// public: void __thiscall INIFILE::SECTION::Put(char const *,char const *)

void __thiscall INIFILE::SECTION::Put(SECTION *this,char *param_1,char *param_2)

{
  char *pcVar1;
  
                    // 0x7608  79  ?Put@SECTION@INIFILE@@QAEXPBD0@Z
  pcVar1 = (char *)FUN_10004990((undefined4 *)(this + 4));
  PutValue(*(INIFILE **)this,pcVar1,param_1,param_2);
  return;
}



// public: bool __thiscall INIFILE::SECTION::Get(char const *,unsigned long &)

bool __thiscall INIFILE::SECTION::Get(SECTION *this,char *param_1,ulong *param_2)

{
  bool bVar1;
  ulong uVar2;
  STRING local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x7633  34  ?Get@SECTION@INIFILE@@QAE_NPBDAAK@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000abb3;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  Get(this,(char *)local_14);
  local_8 = 0;
  bVar1 = STRING::isblank(local_14);
  if (bVar1) {
    local_8 = 0xffffffff;
    FUN_10002ca0((CString *)local_14);
    bVar1 = false;
  }
  else {
    bVar1 = STRING::contains_only(local_14,s_1234567890_1000f1fc);
    if (bVar1) {
      uVar2 = STRING::atol((char *)this);
      *param_2 = uVar2;
      local_8 = 0xffffffff;
      FUN_10002ca0((CString *)local_14);
      bVar1 = true;
    }
    else {
      local_8 = 0xffffffff;
      FUN_10002ca0((CString *)local_14);
      bVar1 = false;
    }
  }
  ExceptionList = local_10;
  return bVar1;
}



// public: void __thiscall INIFILE::SECTION::Put(char const *,unsigned long &)

void __thiscall INIFILE::SECTION::Put(SECTION *this,char *param_1,ulong *param_2)

{
  SECTION *this_00;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x76f2  80  ?Put@SECTION@INIFILE@@QAEXPBDAAK@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000abc6;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10004b40(local_14);
  local_8 = 0;
  CString::Format((CString *)*param_2,(char *)local_14);
  this_00 = (SECTION *)FUN_10004990((undefined4 *)local_14);
  Put(this_00,param_1,(char *)this_00);
  local_8 = 0xffffffff;
  FUN_10002ca0(local_14);
  ExceptionList = local_10;
  return;
}



// WARNING: Variable defined which should be unmapped: param_1
// public: static class LIST<class INIFILE *> __cdecl INIFILE::LoadAllInifiles(char const *,char *)

char * __cdecl INIFILE::LoadAllInifiles(char *param_1,char *param_2)

{
  bool bVar1;
  char *pcVar2;
  undefined4 *puVar3;
  int iVar4;
  BOOL BVar5;
  HANDLE in_stack_0000000c;
  CString *pCVar6;
  char **ppcVar7;
  LPWIN32_FIND_DATAA lpFindFileData;
  undefined4 local_94;
  CString local_6c [4];
  INIFILE *local_68;
  undefined4 local_64;
  CString local_60 [4];
  CString local_5c [4];
  CString local_58 [4];
  uint local_54;
  undefined4 local_50;
  uint local_4c;
  CTypeLibCacheMap local_48 [28];
  CFileFind local_2c [28];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x776a  61  ?LoadAllInifiles@INIFILE@@SA?AV?$LIST@PAVINIFILE@@@@PBDPAD@Z
  local_8 = 0xffffffff;
  puStack_c = &param_2_1000ac36;
  local_10 = ExceptionList;
  bVar1 = false;
  ExceptionList = &local_10;
  CFileFind::CFileFind(local_2c);
  local_8 = 1;
  lpFindFileData = (LPWIN32_FIND_DATAA)0x0;
  ppcVar7 = &param_1_1000f20c;
  pcVar2 = (char *)CString::CString(local_58,param_2);
  local_8._0_1_ = 2;
  pcVar2 = (char *)operator+(local_5c,pcVar2);
  local_8._0_1_ = 3;
  puVar3 = (undefined4 *)operator+(local_60,pcVar2);
  local_8._0_1_ = 4;
  pcVar2 = (char *)FUN_10004990(puVar3);
  iVar4 = CFileFind::FindFile(local_2c,pcVar2,(ulong)ppcVar7);
  local_54 = CONCAT31(local_54._1_3_,'\x01' - (iVar4 != 0));
  local_8._0_1_ = 3;
  CString::~CString(local_60);
  local_8._0_1_ = 2;
  CString::~CString(local_5c);
  local_8._0_1_ = 1;
  CString::~CString(local_58);
  if ((local_54 & 0xff) == 0) {
    CTypeLibCacheMap::CTypeLibCacheMap(local_48);
    local_8._0_1_ = 5;
    local_4c = CONCAT31(local_4c._1_3_,1);
    while ((local_4c & 0xff) != 0) {
      BVar5 = CFileFind::FindNextFileA(in_stack_0000000c,lpFindFileData);
      local_4c = CONCAT31(local_4c._1_3_,BVar5 != 0);
      iVar4 = FUN_100085c0((int *)local_2c);
      if (iVar4 == 0) {
        local_68 = (INIFILE *)operator_new(0x24);
        local_8._0_1_ = 6;
        if (local_68 == (INIFILE *)0x0) {
          local_94 = 0;
        }
        else {
          pCVar6 = local_6c;
          puVar3 = (undefined4 *)CFileFind::GetFilePath(local_2c);
          bVar1 = true;
          local_8 = CONCAT31(local_8._1_3_,7);
          pcVar2 = (char *)FUN_10004990(puVar3);
          local_94 = INIFILE(local_68,pcVar2,(int)pCVar6);
        }
        local_64 = local_94;
        local_50 = local_94;
        local_8._0_1_ = 5;
        local_8._1_3_ = 0;
        if (bVar1) {
          bVar1 = false;
          CString::~CString(local_6c);
        }
        FUN_10008150(local_48,&local_50);
      }
    }
    FUN_10007d10(param_1,(int)local_48);
    local_8._0_1_ = 1;
    FUN_10007aa0((undefined4 *)local_48);
    local_8 = (uint)local_8._1_3_ << 8;
    CFileFind::~CFileFind(local_2c);
  }
  else {
    CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)param_1);
    local_8 = (uint)local_8._1_3_ << 8;
    CFileFind::~CFileFind(local_2c);
  }
  ExceptionList = local_10;
  return param_1;
}



// public: class INIFILE::SECTION __thiscall INIFILE::NullSection(void)

void * __thiscall INIFILE::NullSection(INIFILE *this)

{
  void *in_stack_00000004;
  
                    // 0x7996  65  ?NullSection@INIFILE@@QAE?AVSECTION@1@XZ
  FUN_10004c30(in_stack_00000004,this,s_NO_SECTION_1000f210);
  return in_stack_00000004;
}



// public: struct __POSITION * __thiscall INIFILE::GetFirstSection(void)const 

__POSITION * __thiscall INIFILE::GetFirstSection(INIFILE *this)

{
  CString local_10 [8];
  __POSITION *local_8;
  
                    // 0x79c9  39  ?GetFirstSection@INIFILE@@QBEPAU__POSITION@@XZ
  local_8 = (__POSITION *)FUN_100045e0((int)(this + 4));
  if (local_8 == (__POSITION *)0x0) {
    local_8 = (__POSITION *)0x0;
  }
  else {
    FUN_10007eb0(local_10,(int *)&local_8);
    FUN_100046c0(local_10);
  }
  return local_8;
}



// public: class INIFILE::SECTION __thiscall INIFILE::GetNextSection(struct __POSITION * &)

__POSITION ** __thiscall INIFILE::GetNextSection(INIFILE *this,__POSITION **param_1)

{
  undefined4 *puVar1;
  char *pcVar2;
  int *in_stack_00000008;
  
                    // 0x7a12  45  ?GetNextSection@INIFILE@@QAE?AVSECTION@1@AAPAU__POSITION@@@Z
  puVar1 = (undefined4 *)FUN_10008420(in_stack_00000008);
  pcVar2 = (char *)FUN_10004990(puVar1);
  FUN_10004c30(param_1,this,pcVar2);
  return param_1;
}



void __fastcall FUN_10007a60(undefined4 *param_1)

{
  FUN_10007f70(param_1);
  return;
}



void * __thiscall FUN_10007a80(void *this,CString *param_1)

{
  CString::CString((CString *)this,param_1);
  return this;
}



void __fastcall FUN_10007aa0(undefined4 *param_1)

{
  FUN_100081b0(param_1);
  return;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_10007e30(this,10);
  *(undefined ***)this = &PTR_LAB_1000b9f8;
  return this;
}



void * __thiscall FUN_10007af0(void *this,CString *param_1)

{
  FUN_10004580(this,param_1);
  return this;
}



CString * __thiscall FUN_10007b10(void *this,uint param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  CString *pCVar2;
  uint uVar3;
  CString *local_34;
  CString *local_30;
  int local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ac56;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  bVar1 = IsEmpty((int)this);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    uVar3 = FUN_10007e90((int)this);
    if (param_1 < uVar3) {
      local_18 = FUN_100045e0((int)this);
      local_14 = 0;
      while ((local_14 < param_1 && (uVar3 = FUN_10007e90((int)this), local_14 < uVar3))) {
        FUN_10008420(&local_18);
        local_14 = local_14 + 1;
      }
      local_30 = (CString *)FUN_10008420(&local_18);
    }
    else {
      pCVar2 = (CString *)operator_new(8);
      local_8 = 1;
      if (pCVar2 == (CString *)0x0) {
        local_34 = (CString *)0x0;
        local_30 = local_34;
      }
      else {
        local_30 = FUN_10004be0(pCVar2);
      }
    }
  }
  else {
    pCVar2 = (CString *)operator_new(8);
    local_8 = 0;
    if (pCVar2 == (CString *)0x0) {
      local_30 = (CString *)0x0;
    }
    else {
      local_30 = FUN_10004be0(pCVar2);
    }
  }
  ExceptionList = local_10;
  return local_30;
}



void __thiscall FUN_10007c40(void *this,undefined4 *param_1)

{
  char cVar1;
  CString *pCVar2;
  CString local_20 [8];
  int *local_18;
  int *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ac69;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_14 = (int *)FUN_100045e0((int)this);
  while (local_14 != (int *)0x0) {
    local_18 = local_14;
    pCVar2 = (CString *)FUN_10008420((int *)&local_14);
    FUN_10007da0(local_20,pCVar2);
    local_8 = 0;
    cVar1 = FUN_100085e0(local_20,param_1);
    if (cVar1 != '\0') {
      FUN_10007f00(this,local_18);
    }
    local_8 = 0xffffffff;
    FUN_100046c0(local_20);
  }
  ExceptionList = local_10;
  return;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_100080b0(this,10);
  *(undefined ***)this = &PTR_LAB_1000ba0c;
  return this;
}



void * __thiscall FUN_10007d10(void *this,int param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ac89;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_100080b0(this,10);
  local_8 = 0;
  *(undefined ***)this = &PTR_LAB_1000ba0c;
  FUN_10008110(this,param_1);
  ExceptionList = local_10;
  return this;
}



void * __thiscall FUN_10007d70(void *this,uint param_1)

{
  FUN_10007a60((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001660(this);
  }
  return this;
}



void * __thiscall FUN_10007da0(void *this,CString *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000aca9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString((CString *)this,param_1);
  local_8 = 0;
  CString::CString((CString *)((int)this + 4),param_1 + 4);
  ExceptionList = local_10;
  return this;
}



void * __thiscall FUN_10007e00(void *this,uint param_1)

{
  FUN_10007aa0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001660(this);
  }
  return this;
}



void * __thiscall FUN_10007e30(void *this,undefined4 param_1)

{
  FUN_10002820((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_1000ba20;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



undefined4 __fastcall FUN_10007e90(int param_1)

{
  return *(undefined4 *)(param_1 + 0xc);
}



void * FUN_10007eb0(void *param_1,int *param_2)

{
  int *piVar1;
  
  piVar1 = (int *)*param_2;
  *param_2 = *piVar1;
  FUN_10007da0(param_1,(CString *)(piVar1 + 2));
  return param_1;
}



void __thiscall FUN_10007f00(void *this,int *param_1)

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
  FUN_10008310(this,param_1);
  return;
}



void __fastcall FUN_10007f70(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1000acc9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_1000ba20;
  local_8 = 0;
  FUN_10004480((int)param_1);
  local_8 = 0xffffffff;
  FUN_10002870(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_10007fd0(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  CString local_20 [8];
  ulong local_18;
  undefined4 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ace9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10001650();
  bVar1 = FUN_10006010((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_18 = CArchive::ReadCount(param_1);
    while (local_18 != 0) {
      local_18 = local_18 - 1;
      FUN_10004be0(local_20);
      local_8 = 0;
      FUN_10008360(param_1,local_20,1);
      FUN_10004580(this,local_20);
      local_8 = 0xffffffff;
      FUN_100046c0(local_20);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_14 = *(undefined4 **)((int)this + 4); local_14 != (undefined4 *)0x0;
        local_14 = (undefined4 *)*local_14) {
      FUN_10008360(param_1,local_14 + 2,1);
    }
  }
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_100080b0(void *this,undefined4 param_1)

{
  FUN_10002820((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_1000ba34;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



void __thiscall FUN_10008110(void *this,int param_1)

{
  undefined4 *puVar1;
  int local_8;
  
  local_8 = FUN_100045e0(param_1);
  while (local_8 != 0) {
    puVar1 = (undefined4 *)FUN_10008420(&local_8);
    FUN_10008150(this,puVar1);
  }
  return;
}



undefined4 * __thiscall FUN_10008150(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_10008450(this,*(undefined4 *)((int)this + 8),0);
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



void __fastcall FUN_100081b0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1000ad09;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_1000ba34;
  local_8 = 0;
  FUN_100083a0((int)param_1);
  local_8 = 0xffffffff;
  FUN_10002870(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_10008210(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_10;
  ulong local_c;
  undefined4 *local_8;
  
  FUN_10001650();
  bVar1 = FUN_10006010((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      FUN_10008530(param_1,&local_10,1);
      FUN_10008150(this,&local_10);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_10008530(param_1,local_8 + 2,1);
    }
  }
  return;
}



void * __thiscall FUN_100082b0(void *this,uint param_1)

{
  FUN_10007f70((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001660(this);
  }
  return this;
}



void * __thiscall FUN_100082e0(void *this,uint param_1)

{
  FUN_100081b0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_10001660(this);
  }
  return this;
}



void __thiscall FUN_10008310(void *this,undefined4 *param_1)

{
  FUN_10004600(param_1 + 2,1);
  *param_1 = *(undefined4 *)((int)this + 0x10);
  *(undefined4 **)((int)this + 0x10) = param_1;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + -1;
  if (*(int *)((int)this + 0xc) == 0) {
    FUN_10004480((int)this);
  }
  return;
}



void FUN_10008360(CArchive *param_1,void *param_2,int param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_10006010((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    CArchive::Read(param_1,param_2,param_3 << 3);
  }
  else {
    CArchive::Write(param_1,param_2,param_3 << 3);
  }
  return;
}



void __fastcall FUN_100083a0(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_10004630(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



int FUN_10008420(int *param_1)

{
  int *piVar1;
  
  piVar1 = (int *)*param_1;
  *param_1 = *piVar1;
  return (int)(piVar1 + 2);
}



undefined4 * __thiscall FUN_10008450(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0xc);
    iVar3 = FUN_1000a180((int)pCVar2);
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
  FUN_10008570(puVar1 + 2,1);
  return puVar1;
}



void FUN_10008530(CArchive *param_1,void *param_2,int param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_10006010((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    CArchive::Read(param_1,param_2,param_3 << 2);
  }
  else {
    CArchive::Write(param_1,param_2,param_3 << 2);
  }
  return;
}



void FUN_10008570(void *param_1,int param_2)

{
  memset(param_1,0,param_2 << 2);
  while (param_2 != 0) {
    FUN_10004930(4,param_1);
    param_1 = (void *)((int)param_1 + 4);
    param_2 = param_2 + -1;
  }
  return;
}



void __fastcall FUN_100085c0(int *param_1)

{
  (**(code **)(*param_1 + 0x40))(0x10);
  return;
}



void __thiscall FUN_100085e0(void *this,undefined4 *param_1)

{
  uchar *puVar1;
  
  puVar1 = (uchar *)FUN_10004990(param_1);
  FUN_10008600(this,puVar1);
  return;
}



bool __thiscall FUN_10008600(void *this,uchar *param_1)

{
  int iVar1;
  
  iVar1 = FUN_10008620(this,param_1);
  return (bool)('\x01' - (iVar1 != 0));
}



void __thiscall FUN_10008620(void *this,uchar *param_1)

{
                    // WARNING: Load size is inaccurate
  FUN_10008640(*this,param_1);
  return;
}



void __cdecl FUN_10008640(uchar *param_1,uchar *param_2)

{
  _mbsicmp(param_1,param_2);
  return;
}



CString * __fastcall FUN_10008660(CString *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &this_1000ad3b;
  local_10 = ExceptionList;
  local_8 = 1;
  ExceptionList = &local_10;
  CString::CString(param_1,(CString *)&stack0x00000004);
  local_8._0_1_ = 2;
  CString::CString(param_1 + 4,(CString *)&stack0x00000008);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString((CString *)&stack0x00000004);
  local_8 = 0xffffffff;
  CString::~CString((CString *)&stack0x00000008);
  ExceptionList = local_10;
  return param_1;
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
// Libraries: Visual Studio 2012 Debug, Visual Studio 2012 Release

void * __thiscall base(void *this,void *param_1)

{
  FUN_10002c30(param_1,(CString *)this);
  return param_1;
}



// public: bool __thiscall REG::Get(char const *,unsigned long &)

bool __thiscall REG::Get(REG *this,char *param_1,ulong *param_2)

{
  bool bVar1;
  LSTATUS LVar2;
  DWORD local_10;
  DWORD local_c;
  LSTATUS local_8;
  
                    // 0x8700  30  ?Get@REG@@QAE_NPBDAAK@Z
  local_10 = 0;
  local_c = 0;
  local_8 = RegQueryValueExA(*(HKEY *)this,param_1,(LPDWORD)0x0,&local_c,(LPBYTE)0x0,&local_10);
  if (local_8 == 0) {
    if (local_c == 4) {
      if (local_10 == 4) {
        LVar2 = RegQueryValueExA(*(HKEY *)this,param_1,(LPDWORD)0x0,&local_c,(LPBYTE)param_2,
                                 &local_10);
        if (LVar2 == 0) {
          bVar1 = true;
        }
        else {
          bVar1 = false;
        }
      }
      else {
        bVar1 = false;
      }
    }
    else {
      bVar1 = false;
    }
  }
  else {
    bVar1 = false;
  }
  return bVar1;
}



// public: bool __thiscall REG::Get(char const *,bool &)

bool __thiscall REG::Get(REG *this,char *param_1,bool *param_2)

{
  bool bVar1;
  ulong local_8;
  
                    // 0x8799  32  ?Get@REG@@QAE_NPBDAA_N@Z
  local_8 = 0;
  bVar1 = Get(this,param_1,&local_8);
  if (bVar1) {
    *param_2 = local_8 != 0;
  }
  return bVar1;
}



// public: bool __thiscall REG::Get(char const *,class CString &)

bool __thiscall REG::Get(REG *this,char *param_1,CString *param_2)

{
  bool bVar1;
  DWORD local_14;
  DWORD local_10;
  LPBYTE local_c;
  LSTATUS local_8;
  
                    // 0x87dc  31  ?Get@REG@@QAE_NPBDAAVCString@@@Z
  local_14 = 0;
  local_10 = 0;
  local_8 = RegQueryValueExA(*(HKEY *)this,param_1,(LPDWORD)0x0,&local_10,(LPBYTE)0x0,&local_14);
  if (local_8 == 0) {
    if (local_10 == 1) {
      local_c = (LPBYTE)malloc(local_14);
      local_8 = RegQueryValueExA(*(HKEY *)this,param_1,(LPDWORD)0x0,&local_10,local_c,&local_14);
      if (local_8 == 0) {
        FUN_10009750(param_2,(char *)local_c);
        free(local_c);
        bVar1 = true;
      }
      else {
        bVar1 = false;
      }
    }
    else {
      bVar1 = false;
    }
  }
  else {
    bVar1 = false;
  }
  return bVar1;
}



// public: bool __thiscall REG::GetStrList(char const *,class LIST<class CString> &)

bool __thiscall REG::GetStrList(REG *this,char *param_1,LIST<> *param_2)

{
  undefined1 *local_58;
  undefined1 *local_54;
  undefined1 *local_50;
  REG *local_4c;
  undefined1 local_48;
  CString local_44 [4];
  undefined1 local_40;
  undefined1 local_3c;
  undefined1 *local_38;
  uint local_34;
  LPSTR local_30;
  DWORD local_2c;
  char *local_28;
  DWORD local_24;
  DWORD local_20;
  LSTATUS local_1c;
  DWORD local_18;
  HKEY local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x888e  51  ?GetStrList@REG@@QAE_NPBDAAV?$LIST@VCString@@@@@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000ad62;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_4c = this;
  FUN_10009570((int)param_2);
  FUN_100097d0(&local_14,*(HKEY *)local_4c,param_1);
  local_8 = 0;
  local_18 = 0;
  do {
    local_2c = 0;
    local_20 = 0;
    local_24 = 0;
    local_1c = 0x103;
    do {
      local_2c = local_2c + 0x400;
      FUN_10009f60();
      local_34 = local_2c;
      local_50 = (undefined1 *)&local_58;
      local_38 = (undefined1 *)&local_58;
      local_1c = RegEnumValueA(local_14,local_18,(LPSTR)&local_58,&local_2c,(LPDWORD)0x0,&local_20,
                               (LPBYTE)0x0,&local_24);
      if (local_1c == 0x103) goto LAB_100089a8;
      if ((local_1c != 0xea) && (local_1c != 0)) {
        local_3c = 0;
        local_8 = 0xffffffff;
        FUN_10002ff0(&local_14);
        ExceptionList = local_10;
        return (bool)local_3c;
      }
    } while (local_34 <= local_2c);
    local_2c = local_2c + 1;
LAB_100089a8:
    if (local_1c == 0x103) {
      local_48 = 1;
      local_8 = 0xffffffff;
      FUN_10002ff0(&local_14);
      ExceptionList = local_10;
      return (bool)local_48;
    }
    if ((local_20 == 1) && (local_24 != 0)) {
      FUN_10009f60();
      local_54 = (undefined1 *)&local_58;
      local_30 = (LPSTR)&local_58;
      FUN_10009f60();
      local_58 = (undefined1 *)&local_58;
      local_28 = (char *)&local_58;
      local_1c = RegEnumValueA(local_14,local_18,local_30,&local_2c,(LPDWORD)0x0,&local_20,
                               (LPBYTE)&local_58,&local_24);
      if ((local_1c != 0xea) && (local_1c != 0)) {
        local_40 = 0;
        local_8 = 0xffffffff;
        FUN_10002ff0(&local_14);
        ExceptionList = local_10;
        return (bool)local_40;
      }
      CString::CString(local_44,local_28);
      local_8._0_1_ = 1;
      FUN_100094d0(param_2,local_44);
      local_8 = (uint)local_8._1_3_ << 8;
      CString::~CString(local_44);
    }
    local_18 = local_18 + 1;
  } while( true );
}



// public: bool __thiscall REG::PutStrList(char const *,class LIST<class CString> const &)

bool __thiscall REG::PutStrList(REG *this,char *param_1,LIST<> *param_2)

{
  bool bVar1;
  bool bVar2;
  undefined3 extraout_var;
  CString *pCVar3;
  uint uVar4;
  undefined3 extraout_var_00;
  char *pcVar5;
  char *pcVar6;
  CString local_444 [4];
  CString local_440 [4];
  undefined1 local_43c;
  CString local_438 [4];
  DWORD local_434;
  CHAR local_430 [1024];
  DWORD local_30 [3];
  int local_24;
  HKEY local_20;
  int local_1c;
  CString local_18 [4];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x8aa2  82  ?PutStrList@REG@@QAE_NPBDABV?$LIST@VCString@@@@@Z
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000adb3;
  local_10 = ExceptionList;
  bVar1 = false;
  ExceptionList = &local_10;
  FUN_100097d0(&local_20,*(HKEY *)this,param_1);
  local_8 = 0;
  while( true ) {
    local_434 = 0x400;
    local_30[1] = 0;
    local_30[0] = 0;
    local_30[2] = RegEnumValueA(local_20,0,local_430,&local_434,(LPDWORD)0x0,local_30 + 1,
                                (LPBYTE)0x0,local_30);
    if (local_30[2] == 0x103) {
      local_24 = 1;
      local_1c = FUN_100045e0((int)param_2);
      CString::CString(local_18);
      local_8._0_1_ = 1;
      local_14 = 0;
      bVar2 = IsEmpty((int)param_2);
      if (CONCAT31(extraout_var,bVar2) == 0) {
        pCVar3 = FUN_100095f0(local_440,&local_1c);
        local_8._0_1_ = 2;
        CString::operator=(local_18,pCVar3);
        local_8._0_1_ = 1;
        CString::~CString(local_440);
      }
      local_14 = 0;
      while ((uVar4 = FUN_10007e90((int)param_2), local_14 < uVar4 &&
             (bVar2 = IsEmpty((int)param_2), CONCAT31(extraout_var_00,bVar2) == 0))) {
        FUN_10009770(local_438,s_New_Value___d_1000f21c);
        local_8._0_1_ = 4;
        pcVar5 = (char *)FUN_10004990((undefined4 *)local_18);
        pcVar6 = (char *)FUN_10004990((undefined4 *)local_438);
        Put((REG *)&local_20,pcVar6,pcVar5);
        local_24 = local_24 + 1;
        local_8._0_1_ = 1;
        FUN_100094b0(local_438);
        local_14 = local_14 + 1;
        uVar4 = FUN_10007e90((int)param_2);
        if (local_14 < uVar4) {
          pCVar3 = FUN_100095f0(local_444,&local_1c);
          bVar1 = true;
          local_8 = CONCAT31(local_8._1_3_,3);
          CString::operator=(local_18,pCVar3);
        }
        local_8._0_1_ = 1;
        local_8._1_3_ = 0;
        if (bVar1) {
          bVar1 = false;
          CString::~CString(local_444);
        }
      }
      local_8 = (uint)local_8._1_3_ << 8;
      CString::~CString(local_18);
      local_8 = 0xffffffff;
      FUN_10002ff0(&local_20);
      ExceptionList = local_10;
      return true;
    }
    if ((local_30[2] != 0xea) && (local_30[2] != 0)) break;
    local_30[2] = RegDeleteValueA(local_20,local_430);
  }
  local_43c = 0;
  local_8 = 0xffffffff;
  FUN_10002ff0(&local_20);
  ExceptionList = local_10;
  return (bool)local_43c;
}



// public: bool __thiscall REG::Put(char const *,unsigned long)

bool __thiscall REG::Put(REG *this,char *param_1,ulong param_2)

{
  LSTATUS LVar1;
  bool bVar2;
  DWORD local_10;
  DWORD local_c;
  LSTATUS local_8;
  
                    // 0x8d47  77  ?Put@REG@@QAE_NPBDK@Z
  local_10 = 0;
  local_c = 0;
  local_8 = RegQueryValueExA(*(HKEY *)this,param_1,(LPDWORD)0x0,&local_c,(LPBYTE)0x0,&local_10);
  if ((local_8 == 0) && (local_c != 4)) {
    bVar2 = false;
  }
  else {
    LVar1 = RegSetValueExA(*(HKEY *)this,param_1,0,4,(BYTE *)&param_2,4);
    if (LVar1 == 0) {
      bVar2 = true;
    }
    else {
      bVar2 = false;
    }
  }
  return bVar2;
}



// public: bool __thiscall REG::Put(char const *,char const *)

bool __thiscall REG::Put(REG *this,char *param_1,char *param_2)

{
  size_t cbData;
  LSTATUS LVar1;
  bool bVar2;
  DWORD local_10;
  DWORD local_c;
  LSTATUS local_8;
  
                    // 0x8dcf  76  ?Put@REG@@QAE_NPBD0@Z
  if (param_2 == (char *)0x0) {
    bVar2 = false;
  }
  else {
    local_10 = 0;
    local_c = 0;
    local_8 = RegQueryValueExA(*(HKEY *)this,param_1,(LPDWORD)0x0,&local_c,(LPBYTE)0x0,&local_10);
    if ((local_8 == 0) && (local_c != 1)) {
      bVar2 = false;
    }
    else {
      cbData = strlen(param_2);
      LVar1 = RegSetValueExA(*(HKEY *)this,param_1,0,1,(BYTE *)param_2,cbData);
      if (LVar1 == 0) {
        bVar2 = true;
      }
      else {
        bVar2 = false;
      }
    }
  }
  return bVar2;
}



// public: bool __thiscall REG::Put(char const *,bool)

bool __thiscall REG::Put(REG *this,char *param_1,bool param_2)

{
  bool bVar1;
  
                    // 0x8e75  78  ?Put@REG@@QAE_NPBD_N@Z
  bVar1 = Put(this,param_1,(uint)param_2);
  return bVar1;
}



// public: bool __thiscall REG::GetPut(char const *,class CString &,char const *)

bool __thiscall REG::GetPut(REG *this,char *param_1,CString *param_2,char *param_3)

{
  bool bVar1;
  
                    // 0x8e97  47  ?GetPut@REG@@QAE_NPBDAAVCString@@0@Z
  bVar1 = Get(this,param_1,param_2);
  if (bVar1) {
    bVar1 = true;
  }
  else {
    CString::operator=(param_2,param_3);
    bVar1 = Put(this,param_1,param_3);
  }
  return bVar1;
}



// public: bool __thiscall REG::GetPut(char const *,unsigned long &,unsigned long)

bool __thiscall REG::GetPut(REG *this,char *param_1,ulong *param_2,ulong param_3)

{
  bool bVar1;
  
                    // 0x8edd  46  ?GetPut@REG@@QAE_NPBDAAKK@Z
  bVar1 = Get(this,param_1,param_2);
  if (bVar1) {
    bVar1 = true;
  }
  else {
    *param_2 = param_3;
    bVar1 = Put(this,param_1,*param_2);
  }
  return bVar1;
}



// public: bool __thiscall REG::GetPut(char const *,bool &,bool)

bool __thiscall REG::GetPut(REG *this,char *param_1,bool *param_2,bool param_3)

{
  bool bVar1;
  
                    // 0x8f21  48  ?GetPut@REG@@QAE_NPBDAA_N_N@Z
  bVar1 = Get(this,param_1,param_2);
  if (bVar1) {
    bVar1 = true;
  }
  else {
    *param_2 = param_3;
    bVar1 = Put(this,param_1,*param_2);
  }
  return bVar1;
}



// public: static class CString __cdecl REG::RootDir(void)

CString * __cdecl REG::RootDir(void)

{
  bool bVar1;
  REG *this;
  CString *in_stack_00000004;
  char *pcVar2;
  CString *pCVar3;
  CString local_128 [4];
  undefined4 local_124;
  uint local_120;
  CString local_11c [4];
  CHAR local_118 [260];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x8f65  88  ?RootDir@REG@@SA?AVCString@@XZ
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000adf8;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(local_14);
  local_8 = 1;
  pCVar3 = local_14;
  pcVar2 = s_RootDir_1000f240;
  this = (REG *)FUN_10002f40(&local_124,&DAT_1000f4a8,s_Software_Twilight__1000f22c);
  local_8._0_1_ = 2;
  bVar1 = Get(this,pcVar2,pCVar3);
  local_120 = CONCAT31(local_120._1_3_,bVar1);
  local_8._0_1_ = 1;
  FUN_10002ff0(&local_124);
  if ((local_120 & 0xff) == 0) {
    GetModuleFileNameA((HMODULE)0x0,local_118,0x104);
    FUN_10002c50(local_11c,local_118);
    local_8._0_1_ = 3;
    STRING::strtok((char *)local_128,&DAT_1000f24c);
    FUN_10002ca0(local_128);
    operator+(in_stack_00000004,(char *)local_11c);
    local_8._0_1_ = 1;
    FUN_10002ca0(local_11c);
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_14);
  }
  else {
    operator+(in_stack_00000004,(char *)local_14);
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_14);
  }
  ExceptionList = local_10;
  return in_stack_00000004;
}



// public: static class CString __cdecl REG::AppData(void)

CString * __cdecl REG::AppData(void)

{
  bool bVar1;
  CString *pCVar2;
  char *pcVar3;
  undefined3 extraout_var;
  LPCSTR pCVar4;
  uint uVar5;
  undefined4 *puVar6;
  int iVar7;
  CString *in_stack_00000004;
  CString local_144 [4];
  CString local_140 [4];
  CString local_13c [4];
  char *local_138;
  CString local_134 [4];
  CString local_130 [4];
  CString local_12c [4];
  CString local_128 [4];
  CString local_124 [4];
  STRING local_120 [4];
  CHAR local_11c;
  undefined4 local_11b;
  STRING local_18 [4];
  BOOL local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    // 0x90d3  14  ?AppData@REG@@SA?AVCString@@XZ
  local_8 = 0xffffffff;
  puStack_c = &this_1000ae91;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pCVar2 = (CString *)RootDir();
  local_8 = 1;
  FUN_10002c30(local_18,pCVar2);
  local_8._0_1_ = 3;
  CString::~CString(local_124);
  STRING::trim(local_18,&DAT_1000f254);
  STRING::strtok((char *)local_12c,&DAT_1000f25c);
  local_8._0_1_ = 4;
  pcVar3 = (char *)operator+((char *)local_130,(CString *)s__Twilight_Games__1000f260);
  local_8._0_1_ = 5;
  pCVar2 = (CString *)operator+(local_134,pcVar3);
  local_8._0_1_ = 6;
  FUN_10002c30(local_128,pCVar2);
  local_8._0_1_ = 7;
  FUN_10004340(local_18,local_128);
  local_8._0_1_ = 6;
  FUN_10002ca0(local_128);
  local_8._0_1_ = 5;
  CString::~CString(local_134);
  local_8._0_1_ = 4;
  CString::~CString(local_130);
  local_8 = CONCAT31(local_8._1_3_,3);
  FUN_10002ca0(local_12c);
  local_11c = '\0';
  puVar6 = &local_11b;
  for (iVar7 = 0x40; iVar7 != 0; iVar7 = iVar7 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  *(undefined2 *)puVar6 = 0;
  *(undefined1 *)((int)puVar6 + 2) = 0;
  local_14 = SHGetSpecialFolderPathA((HWND)0x0,&local_11c,0x1a,0);
  if (local_14 < 0) {
    pcVar3 = getenv(s_APPDATA_1000f274);
    FUN_10002c50(local_120,pcVar3);
    local_8 = CONCAT31(local_8._1_3_,8);
    bVar1 = FUN_10002730((int *)local_120);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      pCVar4 = (LPCSTR)FUN_10004990((undefined4 *)local_120);
      uVar5 = FUN_10009481(pCVar4);
      if ((uVar5 & 0xff) != 0) {
                    // WARNING: Subroutine does not return
        STRING::terminate(local_120,&DAT_1000f27c);
      }
    }
    local_138 = s__Application_Data__folder_not_fo_1000f280;
                    // WARNING: Subroutine does not return
    _CxxThrowException(&local_138,(ThrowInfo *)&pThrowInfo_1000cb70);
  }
  bVar1 = FUN_10009640(&DAT_1000f4a4,'\x01');
  if (bVar1) {
    pCVar2 = (CString *)FUN_10002c50(local_13c,&local_11c);
    local_8._0_1_ = 9;
    puVar6 = (undefined4 *)operator+(local_140,pCVar2);
    local_8._0_1_ = 10;
    pcVar3 = (char *)FUN_10004990(puVar6);
    MakeDirectory(pcVar3);
    local_8._0_1_ = 9;
    CString::~CString(local_140);
    local_8 = CONCAT31(local_8._1_3_,3);
    FUN_10002ca0(local_13c);
  }
  pCVar2 = (CString *)FUN_10002c50(local_144,&local_11c);
  local_8._0_1_ = 0xb;
  operator+(in_stack_00000004,pCVar2);
  local_8._0_1_ = 3;
  FUN_10002ca0(local_144);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_10002ca0((CString *)local_18);
  ExceptionList = local_10;
  return in_stack_00000004;
}



uint __cdecl FUN_10009481(LPCSTR param_1)

{
  uint in_EAX;
  uint uVar1;
  DWORD DVar2;
  
  if (param_1 == (LPCSTR)0x0) {
    uVar1 = in_EAX & 0xffffff00;
  }
  else {
    DVar2 = GetFileAttributesA(param_1);
    uVar1 = (uint)((DVar2 & 0x10) == 0x10);
  }
  return uVar1;
}



void __fastcall FUN_100094b0(CString *param_1)

{
  FUN_10002ca0(param_1);
  return;
}



void * __thiscall FUN_100094d0(void *this,CString *param_1)

{
  FUN_10009510(this,param_1);
  return this;
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



undefined4 * __thiscall FUN_10009510(void *this,CString *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_10009670(this,*(undefined4 *)((int)this + 8),0);
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



void __fastcall FUN_10009570(int param_1)

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



CString * FUN_100095f0(CString *param_1,int *param_2)

{
  int *piVar1;
  
  piVar1 = (int *)*param_2;
  *param_2 = *piVar1;
  CString::CString(param_1,(CString *)(piVar1 + 2));
  return param_1;
}



bool __cdecl FUN_10009640(char *param_1,char param_2)

{
  char cVar1;
  
  cVar1 = *param_1;
  *param_1 = param_2;
  return cVar1 != param_2;
}



undefined4 * __thiscall FUN_10009670(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0xc);
    iVar3 = FUN_1000a180((int)pCVar2);
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



void * __thiscall FUN_10009750(void *this,char *param_1)

{
  CString::operator=((CString *)this,param_1);
  return this;
}



CString * __cdecl FUN_10009770(CString *param_1,char *param_2)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1000aea9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10004b40(param_1);
  local_8 = 0;
  CString::FormatV(param_1,param_2,&stack0x0000000c);
  ExceptionList = local_10;
  return param_1;
}



void * __thiscall FUN_100097d0(void *this,HKEY param_1,LPCSTR param_2)

{
  DWORD dwErrCode;
  
  dwErrCode = RegCreateKeyExA(param_1,param_2,0,(LPSTR)0x0,0,0xf003f,(LPSECURITY_ATTRIBUTES)0x0,
                              (PHKEY)this,(LPDWORD)0x0);
  SetLastError(dwErrCode);
  return this;
}



int __thiscall CWnd::PreTranslateMessage(CWnd *this,tagMSG *param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009846. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = PreTranslateMessage(this,param_1);
  return iVar1;
}



void __thiscall CWnd::PreSubclassWindow(CWnd *this)

{
                    // WARNING: Could not recover jumptable at 0x10009894. Too many branches
                    // WARNING: Treating indirect jump as call
  PreSubclassWindow(this);
  return;
}



void __thiscall CStatic::~CStatic(CStatic *this)

{
                    // WARNING: Could not recover jumptable at 0x10009900. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CStatic(this);
  return;
}



void __thiscall CException::Delete(CException *this)

{
                    // WARNING: Could not recover jumptable at 0x10009906. Too many branches
                    // WARNING: Treating indirect jump as call
  Delete(this);
  return;
}



void __thiscall CFile::~CFile(CFile *this)

{
                    // WARNING: Could not recover jumptable at 0x1000990c. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CFile(this);
  return;
}



void __thiscall CFile::CFile(CFile *this,char *param_1,uint param_2)

{
                    // WARNING: Could not recover jumptable at 0x10009912. Too many branches
                    // WARNING: Treating indirect jump as call
  CFile(this,param_1,param_2);
  return;
}



void __thiscall CClientDC::~CClientDC(CClientDC *this)

{
                    // WARNING: Could not recover jumptable at 0x10009918. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CClientDC(this);
  return;
}



void __thiscall CClientDC::CClientDC(CClientDC *this,CWnd *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000991e. Too many branches
                    // WARNING: Treating indirect jump as call
  CClientDC(this,param_1);
  return;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10009924. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



CGdiObject * CGdiObject::FromHandle(void *param_1)

{
  CGdiObject *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000992a. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = FromHandle(param_1);
  return pCVar1;
}



void __thiscall CWnd::CWnd(CWnd *this)

{
                    // WARNING: Could not recover jumptable at 0x10009936. Too many branches
                    // WARNING: Treating indirect jump as call
  CWnd(this);
  return;
}



void __thiscall CToolTipCtrl::~CToolTipCtrl(CToolTipCtrl *this)

{
                    // WARNING: Could not recover jumptable at 0x1000993c. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CToolTipCtrl(this);
  return;
}



void __thiscall CString::~CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x10009942. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CString(this);
  return;
}



void __thiscall CString::Empty(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x10009948. Too many branches
                    // WARNING: Treating indirect jump as call
  Empty(this);
  return;
}



void __thiscall CToolTipCtrl::CToolTipCtrl(CToolTipCtrl *this)

{
                    // WARNING: Could not recover jumptable at 0x1000994e. Too many branches
                    // WARNING: Treating indirect jump as call
  CToolTipCtrl(this);
  return;
}



void __thiscall CString::CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x10009954. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this);
  return;
}



BOOL CGdiObject::DeleteObject(HGDIOBJ ho)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000995a. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = DeleteObject(ho);
  return BVar1;
}



int CDC::SetBkMode(HDC hdc,int mode)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009960. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = SetBkMode(hdc,mode);
  return iVar1;
}



int __thiscall
CToolTipCtrl::AddTool(CToolTipCtrl *this,CWnd *param_1,char *param_2,tagRECT *param_3,uint param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009966. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AddTool(this,param_1,param_2,param_3,param_4);
  return iVar1;
}



int __thiscall CToolTipCtrl::Create(CToolTipCtrl *this,CWnd *param_1,ulong param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000996c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Create(this,param_1,param_2);
  return iVar1;
}



BOOL CWnd::SetWindowTextA(HWND hWnd,LPCSTR lpString)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009972. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = SetWindowTextA(hWnd,lpString);
  return BVar1;
}



int CWnd::GetWindowTextA(HWND hWnd,LPSTR lpString,int nMaxCount)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009978. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = GetWindowTextA(hWnd,lpString,nMaxCount);
  return iVar1;
}



ulong __thiscall CWnd::GetStyle(CWnd *this)

{
  ulong uVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000997e. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = GetStyle(this);
  return uVar1;
}



void __thiscall
CToolTipCtrl::UpdateTipText(CToolTipCtrl *this,char *param_1,CWnd *param_2,uint param_3)

{
                    // WARNING: Could not recover jumptable at 0x10009984. Too many branches
                    // WARNING: Treating indirect jump as call
  UpdateTipText(this,param_1,param_2,param_3);
  return;
}



CString * __thiscall CString::operator=(CString *this,CString *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000998a. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator=(this,param_1);
  return pCVar1;
}



void __thiscall CString::CString(CString *this,CString *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10009990. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



BOOL CWnd::SetWindowPos(HWND hWnd,HWND hWndInsertAfter,int X,int Y,int cx,int cy,UINT uFlags)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009996. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = SetWindowPos(hWnd,hWndInsertAfter,X,Y,cx,cy,uFlags);
  return BVar1;
}



BOOL CWnd::ScreenToClient(HWND hWnd,LPPOINT lpPoint)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000999c. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = ScreenToClient(hWnd,lpPoint);
  return BVar1;
}



CString * __thiscall CString::operator+=(CString *this,char *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x100099a2. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator+=(this,param_1);
  return pCVar1;
}



void __thiscall CString::ReleaseBuffer(CString *this,int param_1)

{
                    // WARNING: Could not recover jumptable at 0x100099a8. Too many branches
                    // WARNING: Treating indirect jump as call
  ReleaseBuffer(this,param_1);
  return;
}



char * __thiscall CString::GetBuffer(CString *this,int param_1)

{
  char *pcVar1;
  
                    // WARNING: Could not recover jumptable at 0x100099ae. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = GetBuffer(this,param_1);
  return pcVar1;
}



int AfxMessageBox(char *param_1,uint param_2,uint param_3)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x100099b4. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxMessageBox(param_1,param_2,param_3);
  return iVar1;
}



CString * __thiscall CString::operator+=(CString *this,CString *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x100099ba. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator+=(this,param_1);
  return pCVar1;
}



void operator+(char *param_1,CString *param_2)

{
                    // WARNING: Could not recover jumptable at 0x100099c0. Too many branches
                    // WARNING: Treating indirect jump as call
  operator+(param_1,param_2);
  return;
}



int __thiscall CString::Find(CString *this,char param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x100099c6. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Find(this,param_1);
  return iVar1;
}



void operator+(CString *param_1,char *param_2)

{
                    // WARNING: Could not recover jumptable at 0x100099cc. Too many branches
                    // WARNING: Treating indirect jump as call
  operator+(param_1,param_2);
  return;
}



int __thiscall CGdiObject::Attach(CGdiObject *this,void *param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x100099e4. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Attach(this,param_1);
  return iVar1;
}



CDC * CDC::FromHandle(HDC__ *param_1)

{
  CDC *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x100099ea. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = FromHandle(param_1);
  return pCVar1;
}



CWnd * CWnd::FromHandle(HWND__ *param_1)

{
  CWnd *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x100099f0. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = FromHandle(param_1);
  return pCVar1;
}



long __thiscall CWnd::Default(CWnd *this)

{
  long lVar1;
  
                    // WARNING: Could not recover jumptable at 0x100099f6. Too many branches
                    // WARNING: Treating indirect jump as call
  lVar1 = Default(this);
  return lVar1;
}



void __thiscall CString::CString(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x100099fc. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



void __thiscall CDialog::~CDialog(CDialog *this)

{
                    // WARNING: Could not recover jumptable at 0x10009a38. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CDialog(this);
  return;
}



CString * __thiscall CString::operator=(CString *this,char *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009a3e. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator=(this,param_1);
  return pCVar1;
}



void __thiscall CDialog::CDialog(CDialog *this,uint param_1,CWnd *param_2)

{
                    // WARNING: Could not recover jumptable at 0x10009a44. Too many branches
                    // WARNING: Treating indirect jump as call
  CDialog(this,param_1,param_2);
  return;
}



void DDX_Text(CDataExchange *param_1,int param_2,CString *param_3)

{
                    // WARNING: Could not recover jumptable at 0x10009a4a. Too many branches
                    // WARNING: Treating indirect jump as call
  DDX_Text(param_1,param_2,param_3);
  return;
}



void DDX_Check(CDataExchange *param_1,int param_2,int *param_3)

{
                    // WARNING: Could not recover jumptable at 0x10009a50. Too many branches
                    // WARNING: Treating indirect jump as call
  DDX_Check(param_1,param_2,param_3);
  return;
}



int __thiscall CWnd::UpdateData(CWnd *this,int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009a56. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = UpdateData(this,param_1);
  return iVar1;
}



int __thiscall CDialog::DoModal(CDialog *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009a5c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = DoModal(this);
  return iVar1;
}



int __thiscall CDialog::OnInitDialog(CDialog *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009a62. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = OnInitDialog(this);
  return iVar1;
}



void __thiscall
AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(AFX_MAINTAIN_STATE2 *this,AFX_MODULE_STATE *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10009a68. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MAINTAIN_STATE2(this,param_1);
  return;
}



void __thiscall CString::Mid(CString *this,int param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10009a6e. Too many branches
                    // WARNING: Treating indirect jump as call
  Mid(this,param_1,param_2);
  return;
}



void operator+(CString *param_1,CString *param_2)

{
                    // WARNING: Could not recover jumptable at 0x10009a74. Too many branches
                    // WARNING: Treating indirect jump as call
  operator+(param_1,param_2);
  return;
}



void operator+(char param_1,CString *param_2)

{
                    // WARNING: Could not recover jumptable at 0x10009a7a. Too many branches
                    // WARNING: Treating indirect jump as call
  operator+(param_1,param_2);
  return;
}



void __thiscall CString::Mid(CString *this,int param_1)

{
                    // WARNING: Could not recover jumptable at 0x10009a80. Too many branches
                    // WARNING: Treating indirect jump as call
  Mid(this,param_1);
  return;
}



int __thiscall CString::Find(CString *this,char *param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009a86. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Find(this,param_1);
  return iVar1;
}



void __thiscall CString::MakeReverse(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x10009a8c. Too many branches
                    // WARNING: Treating indirect jump as call
  MakeReverse(this);
  return;
}



void __thiscall CPlex::FreeDataChain(CPlex *this)

{
                    // WARNING: Could not recover jumptable at 0x10009a92. Too many branches
                    // WARNING: Treating indirect jump as call
  FreeDataChain(this);
  return;
}



CPlex * CPlex::Create(CPlex **param_1,uint param_2,uint param_3)

{
  CPlex *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009a98. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = Create(param_1,param_2,param_3);
  return pCVar1;
}



void __thiscall CString::Format(CString *this,char *param_1,...)

{
                    // WARNING: Could not recover jumptable at 0x10009a9e. Too many branches
                    // WARNING: Treating indirect jump as call
  Format(this,param_1);
  return;
}



void __thiscall CWinApp::~CWinApp(CWinApp *this)

{
                    // WARNING: Could not recover jumptable at 0x10009aa4. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CWinApp(this);
  return;
}



void __thiscall CWinApp::CWinApp(CWinApp *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10009b22. Too many branches
                    // WARNING: Treating indirect jump as call
  CWinApp(this,param_1);
  return;
}



void __thiscall CString::MakeUpper(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x10009b28. Too many branches
                    // WARNING: Treating indirect jump as call
  MakeUpper(this);
  return;
}



void __thiscall CString::TrimRight(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10009b2e. Too many branches
                    // WARNING: Treating indirect jump as call
  TrimRight(this,param_1);
  return;
}



void __thiscall CString::TrimLeft(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10009b34. Too many branches
                    // WARNING: Treating indirect jump as call
  TrimLeft(this,param_1);
  return;
}



int __thiscall CString::Delete(CString *this,int param_1,int param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009b3a. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Delete(this,param_1,param_2);
  return iVar1;
}



void __thiscall CString::SpanExcluding(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x10009b40. Too many branches
                    // WARNING: Treating indirect jump as call
  SpanExcluding(this,param_1);
  return;
}



void __thiscall CString::CString(CString *this,char param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10009b46. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1,param_2);
  return;
}



void * __thiscall CSharedFile::Detach(CSharedFile *this)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009b4c. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = Detach(this);
  return pvVar1;
}



void __thiscall CSharedFile::~CSharedFile(CSharedFile *this)

{
                    // WARNING: Could not recover jumptable at 0x10009b52. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CSharedFile(this);
  return;
}



void __thiscall CSharedFile::CSharedFile(CSharedFile *this,uint param_1,uint param_2)

{
                    // WARNING: Could not recover jumptable at 0x10009b58. Too many branches
                    // WARNING: Treating indirect jump as call
  CSharedFile(this,param_1,param_2);
  return;
}



void __thiscall CSharedFile::SetHandle(CSharedFile *this,void *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10009b5e. Too many branches
                    // WARNING: Treating indirect jump as call
  SetHandle(this,param_1,param_2);
  return;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009b64. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void __thiscall CFileFind::GetFilePath(CFileFind *this)

{
                    // WARNING: Could not recover jumptable at 0x10009b70. Too many branches
                    // WARNING: Treating indirect jump as call
  GetFilePath(this);
  return;
}



BOOL CFileFind::FindNextFileA(HANDLE hFindFile,LPWIN32_FIND_DATAA lpFindFileData)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009b76. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = FindNextFileA(hFindFile,lpFindFileData);
  return BVar1;
}



void __thiscall CFileFind::~CFileFind(CFileFind *this)

{
                    // WARNING: Could not recover jumptable at 0x10009b7c. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CFileFind(this);
  return;
}



int __thiscall CFileFind::FindFile(CFileFind *this,char *param_1,ulong param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009b82. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = FindFile(this,param_1,param_2);
  return iVar1;
}



void __thiscall CFileFind::CFileFind(CFileFind *this)

{
                    // WARNING: Could not recover jumptable at 0x10009b88. Too many branches
                    // WARNING: Treating indirect jump as call
  CFileFind(this);
  return;
}



ulong __thiscall CArchive::ReadCount(CArchive *this)

{
  ulong uVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009b8e. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = ReadCount(this);
  return uVar1;
}



void __thiscall CArchive::WriteCount(CArchive *this,ulong param_1)

{
                    // WARNING: Could not recover jumptable at 0x10009b94. Too many branches
                    // WARNING: Treating indirect jump as call
  WriteCount(this,param_1);
  return;
}



uint __thiscall CArchive::Read(CArchive *this,void *param_1,uint param_2)

{
  uint uVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009b9a. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = Read(this,param_1,param_2);
  return uVar1;
}



void __thiscall CArchive::Write(CArchive *this,void *param_1,uint param_2)

{
                    // WARNING: Could not recover jumptable at 0x10009ba0. Too many branches
                    // WARNING: Treating indirect jump as call
  Write(this,param_1,param_2);
  return;
}



void DestructElements(CString *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10009ba6. Too many branches
                    // WARNING: Treating indirect jump as call
  DestructElements(param_1,param_2);
  return;
}



void ConstructElements(CString *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x10009bac. Too many branches
                    // WARNING: Treating indirect jump as call
  ConstructElements(param_1,param_2);
  return;
}



void __thiscall CString::FormatV(CString *this,char *param_1,char *param_2)

{
                    // WARNING: Could not recover jumptable at 0x10009bb2. Too many branches
                    // WARNING: Treating indirect jump as call
  FormatV(this,param_1,param_2);
  return;
}



undefined4 * FUN_10009bc2(void)

{
  AFX_MODULE_STATE::AFX_MODULE_STATE
            ((AFX_MODULE_STATE *)&param_1_1000f4b0,1,AfxWndProcDllStatic,0x600);
  param_1_1000f4b0 = (AFX_MAINTAIN_STATE2 *)&PTR_FUN_1000ba4c;
  return &param_1_1000f4b0;
}



void * __thiscall FUN_10009bea(void *this,byte param_1)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)this);
  if ((param_1 & 1) != 0) {
    CNoTrackObject::operator_delete(this);
  }
  return this;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x1000a12c. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



void FUN_10009c0a(void)

{
  FUN_10009f3e(FUN_10009c16);
  return;
}



void FUN_10009c16(void)

{
  AFX_MODULE_STATE::~AFX_MODULE_STATE((AFX_MODULE_STATE *)&param_1_1000f4b0);
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
  
  FUN_1000a0e0();
  AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
            ((AFX_MAINTAIN_STATE2 *)(unaff_EBP + -0x14),(AFX_MODULE_STATE *)&param_1_1000f4b0);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  lVar1 = AfxWndProc(*(HWND__ **)(unaff_EBP + 8),*(uint *)(unaff_EBP + 0xc),
                     *(uint *)(unaff_EBP + 0x10),*(long *)(unaff_EBP + 0x14));
  *(undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4) = *(undefined4 *)(unaff_EBP + -0x14);
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return lVar1;
}



undefined4 * FUN_10009c65(void)

{
  return &param_1_1000f4b0;
}



int FUN_10009c6b(HINSTANCE__ *param_1,int param_2)

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
      pAVar5 = AfxSetModuleState((AFX_MODULE_STATE *)&param_1_1000f4b0);
      p_Var3 = AfxGetThreadState();
      *(AFX_MODULE_STATE **)(p_Var3 + 8) = pAVar5;
      pAVar5 = AfxGetModuleState();
      if (*(int **)(pAVar5 + 4) != (int *)0x0) {
        (**(code **)(**(int **)(pAVar5 + 4) + 0x70))();
      }
      AfxLockTempMaps();
      AfxUnlockTempMaps(-1);
      AfxWinTerm();
      AfxTermExtensionModule((AFX_EXTENSION_MODULE *)&param_1_10010540,1);
    }
    else if (param_2 == 3) {
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
                ((AFX_MAINTAIN_STATE2 *)&local_c,(AFX_MODULE_STATE *)&param_1_1000f4b0);
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
  iVar4 = AfxWinInit(param_1,(HINSTANCE__ *)0x0,(char *)&param_3_1000f494,0);
  if (iVar4 != 0) {
    pAVar5 = AfxGetModuleState();
    piVar2 = *(int **)(pAVar5 + 4);
    if ((piVar2 == (int *)0x0) || (iVar4 = (**(code **)(*piVar2 + 0x58))(), iVar4 != 0)) {
      *(undefined4 *)(p_Var3 + 8) = uVar1;
      AfxInitExtensionModule((AFX_EXTENSION_MODULE *)&param_1_10010540,param_1);
      this = (CDynLinkLibrary *)operator_new(0x40);
      if (this != (CDynLinkLibrary *)0x0) {
        CDynLinkLibrary::CDynLinkLibrary(this,(AFX_EXTENSION_MODULE *)&param_1_10010540,0);
      }
      param_2 = 1;
      goto LAB_10009cf7;
    }
    (**(code **)(*piVar2 + 0x70))();
  }
  AfxWinTerm();
LAB_10009cf7:
  *(undefined4 *)(p_Var3 + 8) = uVar1;
  p_Var3 = AfxGetThreadState();
  AfxSetModuleState(*(AFX_MODULE_STATE **)(p_Var3 + 8));
  return param_2;
}



undefined4 FUN_10009d92(undefined4 param_1,int param_2)

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
    pAVar2 = AfxSetModuleState((AFX_MODULE_STATE *)&param_1_1000f4b0);
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
                    // WARNING: Could not recover jumptable at 0x10009de4. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler();
  return;
}



void * __thiscall FUN_10009df0(void *this,byte param_1)

{
  type_info::~type_info((type_info *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void FUN_10009e0c(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_1000ba58;
  puStack_10 = &DAT_1000a106;
  local_14 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_14;
  while( true ) {
    param_3 = param_3 + -1;
    if (param_3 < 0) break;
    (*(code *)param_4)();
  }
  local_8 = 0xffffffff;
  FUN_10009e74();
  ExceptionList = local_14;
  return;
}



void FUN_10009e74(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x1c) == 0) {
    FUN_10009e8c(*(undefined4 *)(unaff_EBP + 8),*(undefined4 *)(unaff_EBP + 0xc),
                 *(int *)(unaff_EBP + 0x10),*(undefined **)(unaff_EBP + 0x14));
  }
  return;
}



void FUN_10009e8c(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_1000ba68;
  puStack_10 = &DAT_1000a106;
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



undefined4 __cdecl FUN_10009eea(undefined4 *param_1)

{
  if (*(int *)*param_1 != -0x1f928c9d) {
    return 0;
  }
                    // WARNING: Subroutine does not return
  terminate();
}



double __cdecl fabs(double _X)

{
  double dVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009f00. Too many branches
                    // WARNING: Treating indirect jump as call
  dVar1 = fabs(_X);
  return dVar1;
}



void __cdecl ftol(void)

{
                    // WARNING: Could not recover jumptable at 0x10009f06. Too many branches
                    // WARNING: Treating indirect jump as call
  ftol();
  return;
}



size_t __cdecl strlen(char *_Str)

{
  size_t sVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009f0c. Too many branches
                    // WARNING: Treating indirect jump as call
  sVar1 = strlen(_Str);
  return sVar1;
}



void __cdecl FUN_10009f12(_onexit_t param_1)

{
  if (DAT_10010568 == -1) {
    _onexit(param_1);
    return;
  }
  __dllonexit(param_1,&DAT_10010568,&DAT_10010564);
  return;
}



int __cdecl FUN_10009f3e(_onexit_t param_1)

{
  int iVar1;
  
  iVar1 = FUN_10009f12(param_1);
  return (iVar1 != 0) - 1;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x10009f50. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



// WARNING: Unable to track spacebase fully for stack

void FUN_10009f60(void)

{
  uint in_EAX;
  undefined1 *puVar1;
  undefined4 unaff_retaddr;
  
  puVar1 = &stack0x00000004;
  if (0xfff < in_EAX) {
    do {
      puVar1 = puVar1 + -0x1000;
      in_EAX = in_EAX - 0x1000;
    } while (0xfff < in_EAX);
  }
  *(undefined4 *)(puVar1 + (-4 - in_EAX)) = unaff_retaddr;
  return;
}



void _CxxThrowException(void *pExceptionObject,ThrowInfo *pThrowInfo)

{
                    // WARNING: Could not recover jumptable at 0x10009f90. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  _CxxThrowException(pExceptionObject,pThrowInfo);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10009f96(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 *_Memory;
  undefined4 *puVar2;
  
  if (param_2 == 0) {
    if (0 < DAT_1001055c) {
      DAT_1001055c = DAT_1001055c + -1;
      goto LAB_10009fac;
    }
LAB_10009fd4:
    uVar1 = 0;
  }
  else {
LAB_10009fac:
    _DAT_10010560 = *(undefined4 *)_adjust_fdiv_exref;
    if (param_2 == 1) {
      DAT_10010568 = (undefined4 *)malloc(0x80);
      if (DAT_10010568 == (undefined4 *)0x0) goto LAB_10009fd4;
      *DAT_10010568 = 0;
      DAT_10010564 = DAT_10010568;
      initterm(&DAT_1000f000,&DAT_1000f00c);
      DAT_1001055c = DAT_1001055c + 1;
    }
    else if ((param_2 == 0) &&
            (_Memory = DAT_10010568, puVar2 = DAT_10010564, DAT_10010568 != (undefined4 *)0x0)) {
      while (puVar2 = puVar2 + -1, _Memory <= puVar2) {
        if ((code *)*puVar2 != (code *)0x0) {
          (*(code *)*puVar2)();
          _Memory = DAT_10010568;
        }
      }
      free(_Memory);
      DAT_10010568 = (undefined4 *)0x0;
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
  iVar2 = DAT_1001055c;
  if (param_2 != 0) {
    if ((param_2 != 1) && (param_2 != 2)) goto LAB_1000a089;
    if ((PTR_FUN_1000f2c8 != (undefined *)0x0) &&
       (iVar2 = (*(code *)PTR_FUN_1000f2c8)(param_1,param_2,param_3), iVar2 == 0)) {
      return 0;
    }
    iVar2 = FUN_10009f96(param_1,param_2);
  }
  if (iVar2 == 0) {
    return 0;
  }
LAB_1000a089:
  iVar2 = FUN_10009c6b(param_1,param_2);
  if (param_2 == 1) {
    if (iVar2 != 0) {
      return iVar2;
    }
    FUN_10009f96(param_1,0);
  }
  if ((param_2 != 0) && (param_2 != 3)) {
    return iVar2;
  }
  iVar3 = FUN_10009f96(param_1,param_2);
  param_2 = iVar2;
  if (iVar3 == 0) {
    param_2 = 0;
  }
  if (param_2 != 0) {
    if (PTR_FUN_1000f2c8 != (undefined *)0x0) {
      iVar2 = (*(code *)PTR_FUN_1000f2c8)(param_1,iVar1,param_3);
      return iVar2;
    }
    return param_2;
  }
  return 0;
}



void FUN_1000a0e0(void)

{
  undefined1 auStack_c [12];
  
  ExceptionList = auStack_c;
  return;
}



void __thiscall type_info::~type_info(type_info *this)

{
                    // WARNING: Could not recover jumptable at 0x1000a100. Too many branches
                    // WARNING: Treating indirect jump as call
  ~type_info(this);
  return;
}



void __cdecl terminate(void)

{
                    // WARNING: Could not recover jumptable at 0x1000a10c. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  terminate();
  return;
}



void __dllonexit(void)

{
                    // WARNING: Could not recover jumptable at 0x1000a112. Too many branches
                    // WARNING: Treating indirect jump as call
  __dllonexit();
  return;
}



void __cdecl initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x1000a118. Too many branches
                    // WARNING: Treating indirect jump as call
  initterm();
  return;
}



void __thiscall
AFX_MODULE_STATE::AFX_MODULE_STATE
          (AFX_MODULE_STATE *this,int param_1,FuncDef16 *param_2,ulong param_3)

{
                    // WARNING: Could not recover jumptable at 0x1000a120. Too many branches
                    // WARNING: Treating indirect jump as call
  AFX_MODULE_STATE(this,param_1,param_2,param_3);
  return;
}



void CNoTrackObject::operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000a126. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(AFX_MODULE_STATE *this)

{
                    // WARNING: Could not recover jumptable at 0x1000a12c. Too many branches
                    // WARNING: Treating indirect jump as call
  ~AFX_MODULE_STATE(this);
  return;
}



long AfxWndProc(HWND__ *param_1,uint param_2,uint param_3,long param_4)

{
  long lVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000a132. Too many branches
                    // WARNING: Treating indirect jump as call
  lVar1 = AfxWndProc(param_1,param_2,param_3,param_4);
  return lVar1;
}



void AfxTermThread(HINSTANCE__ *param_1)

{
                    // WARNING: Could not recover jumptable at 0x1000a138. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermThread(param_1);
  return;
}



void AfxTermExtensionModule(AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x1000a13e. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxTermExtensionModule(param_1,param_2);
  return;
}



int AfxUnlockTempMaps(int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000a144. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxUnlockTempMaps(param_1);
  return iVar1;
}



void AfxLockTempMaps(void)

{
                    // WARNING: Could not recover jumptable at 0x1000a14a. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxLockTempMaps();
  return;
}



AFX_MODULE_STATE * AfxSetModuleState(AFX_MODULE_STATE *param_1)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000a150. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxSetModuleState(param_1);
  return pAVar1;
}



void __thiscall
CDynLinkLibrary::CDynLinkLibrary(CDynLinkLibrary *this,AFX_EXTENSION_MODULE *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x1000a156. Too many branches
                    // WARNING: Treating indirect jump as call
  CDynLinkLibrary(this,param_1,param_2);
  return;
}



int AfxInitExtensionModule(AFX_EXTENSION_MODULE *param_1,HINSTANCE__ *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000a15c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxInitExtensionModule(param_1,param_2);
  return iVar1;
}



void AfxWinTerm(void)

{
                    // WARNING: Could not recover jumptable at 0x1000a162. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxWinTerm();
  return;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000a168. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



int AfxWinInit(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x1000a16e. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinInit(param_1,param_2,param_3,param_4);
  return iVar1;
}



_AFX_THREAD_STATE * AfxGetThreadState(void)

{
  _AFX_THREAD_STATE *p_Var1;
  
                    // WARNING: Could not recover jumptable at 0x1000a174. Too many branches
                    // WARNING: Treating indirect jump as call
  p_Var1 = AfxGetThreadState();
  return p_Var1;
}



void AfxCoreInitModule(void)

{
                    // WARNING: Could not recover jumptable at 0x1000a17a. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxCoreInitModule();
  return;
}



int __fastcall FUN_1000a180(int param_1)

{
  return param_1 + 4;
}



void Unwind_1000a1a0(void)

{
  int unaff_EBP;
  
  CStatic::~CStatic(*(CStatic **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a1b3(void)

{
  int unaff_EBP;
  
  CStatic::~CStatic(*(CStatic **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a1c6(void)

{
  int unaff_EBP;
  
  CFile::~CFile((CFile *)(unaff_EBP + -0x20));
  return;
}



void Unwind_1000a1d9(void)

{
  int unaff_EBP;
  
  CClientDC::~CClientDC((CClientDC *)(unaff_EBP + -0x24));
  return;
}



void Unwind_1000a1ec(void)

{
  int unaff_EBP;
  
  CClientDC::~CClientDC((CClientDC *)(unaff_EBP + -0x30));
  return;
}



void Unwind_1000a1ff(void)

{
  int unaff_EBP;
  
  CClientDC::~CClientDC((CClientDC *)(unaff_EBP + -0x28));
  return;
}



void Unwind_1000a220(void)

{
  int unaff_EBP;
  
  CStatic::~CStatic(*(CStatic **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a229(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x5c));
  return;
}



void Unwind_1000a235(void)

{
  int unaff_EBP;
  
  FUN_10002950((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_1000a241(void)

{
  int unaff_EBP;
  
  CToolTipCtrl::~CToolTipCtrl((CToolTipCtrl *)(*(int *)(unaff_EBP + -0x10) + 0x6c));
  return;
}



void Unwind_1000a257(void)

{
  int unaff_EBP;
  
  CStatic::~CStatic(*(CStatic **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a260(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x5c));
  return;
}



void Unwind_1000a26c(void)

{
  int unaff_EBP;
  
  FUN_10002950((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_1000a278(void)

{
  int unaff_EBP;
  
  CToolTipCtrl::~CToolTipCtrl((CToolTipCtrl *)(*(int *)(unaff_EBP + -0x10) + 0x6c));
  return;
}



void Unwind_1000a28e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_1000a2a1(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 8));
  return;
}



void Unwind_1000a2b4(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x30));
  return;
}



void Unwind_1000a2c7(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000a2da(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -900));
  return;
}



void Unwind_1000a2e6(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x390));
  return;
}



void Unwind_1000a2f2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x394));
  return;
}



void Unwind_1000a2fe(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_1000a307(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x39c));
  return;
}



void Unwind_1000a313(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x3a0));
  return;
}



void Unwind_1000a31f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3a4));
  return;
}



void Unwind_1000a32b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3a8));
  return;
}



void Unwind_1000a350(void)

{
  int unaff_EBP;
  
  FUN_10002870(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a370(void)

{
  int unaff_EBP;
  
  CDialog::~CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a379(void)

{
  int unaff_EBP;
  
  FUN_10002ff0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_1000a385(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 100));
  return;
}



void Unwind_1000a391(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x68));
  return;
}



void Unwind_1000a39d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x70));
  return;
}



void Unwind_1000a3c0(void)

{
  int unaff_EBP;
  
  CDialog::~CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a3c9(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x10) == 0) {
    *(undefined4 *)(unaff_EBP + -0x14) = 0;
  }
  else {
    *(int *)(unaff_EBP + -0x14) = *(int *)(unaff_EBP + -0x10) + 0x60;
  }
  FUN_10002ff0(*(undefined4 **)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000a3f1(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 100));
  return;
}



void Unwind_1000a3fd(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x68));
  return;
}



void Unwind_1000a420(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000a429(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000a440(void)

{
  int unaff_EBP;
  
  FUN_10004910((undefined4 *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000a449(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x8c));
  return;
}



void Unwind_1000a455(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x90));
  return;
}



void Unwind_1000a461(void)

{
  int unaff_EBP;
  
  FUN_10002eb0((CDialog *)(unaff_EBP + -0x88));
  return;
}



void Unwind_1000a477(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000a48a(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x120));
  return;
}



void Unwind_1000a496(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a49f(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x11c));
  return;
}



void Unwind_1000a4ab(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x124));
  return;
}



void Unwind_1000a4b7(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -300));
  return;
}



void Unwind_1000a4c3(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x128));
  return;
}



void Unwind_1000a4cf(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x134));
  return;
}



void Unwind_1000a4db(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x138));
  return;
}



void Unwind_1000a4e7(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x13c));
  return;
}



void Unwind_1000a4f3(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x140));
  return;
}



void Unwind_1000a4ff(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x144));
  return;
}



void Unwind_1000a50b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x148));
  return;
}



void Unwind_1000a517(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14c));
  return;
}



void Unwind_1000a523(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x150) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000a547(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x318) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000a561(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x314));
  return;
}



void Unwind_1000a577(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000a580(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a589(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000a592(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_1000a5a5(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000a5b8(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 8));
  return;
}



void Unwind_1000a5c1(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000a5d4(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000a5e7(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a5f0(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x224));
  return;
}



void Unwind_1000a5fc(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x228));
  return;
}



void Unwind_1000a608(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x250));
  return;
}



void Unwind_1000a614(void)

{
  int unaff_EBP;
  
  INIFILE::~INIFILE((INIFILE *)(unaff_EBP + -0x24c));
  return;
}



void Unwind_1000a62a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_1000a63d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 0xc));
  return;
}



void Unwind_1000a646(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a64f(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x14) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000a670(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000a690(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a6b0(void)

{
  FUN_10004940();
  return;
}



void Unwind_1000a6d0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a6d9(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x14) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000a700(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a720(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a740(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a749(void)

{
  int unaff_EBP;
  
  FUN_10002ff0((undefined4 *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000a752(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x24) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000a769(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000a772(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_1000a790(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000a7a3(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a7ac(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x18) & 1) != 0) {
    FUN_10002ca0(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000a7cd(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a7d6(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_1000a7df(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_1000a7e8(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000a800(void)

{
  int unaff_EBP;
  
  FUN_10002870(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a813(void)

{
  int unaff_EBP;
  
  FUN_10001660(*(void **)(unaff_EBP + -0x30));
  return;
}



void Unwind_1000a827(void)

{
  int unaff_EBP;
  
  CSharedFile::~CSharedFile((CSharedFile *)(unaff_EBP + -0x44));
  return;
}



void Unwind_1000a83a(void)

{
  int unaff_EBP;
  
  CSharedFile::~CSharedFile((CSharedFile *)(unaff_EBP + -0x44));
  return;
}



void Unwind_1000a850(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a863(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x444));
  return;
}



void Unwind_1000a86f(void)

{
  int unaff_EBP;
  
  FUN_10007a60((undefined4 *)(*(int *)(unaff_EBP + -0x444) + 4));
  return;
}



void Unwind_1000a87e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x410));
  return;
}



void Unwind_1000a88a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x414));
  return;
}



void Unwind_1000a896(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x41c));
  return;
}



void Unwind_1000a8a2(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x428));
  return;
}



void Unwind_1000a8ae(void)

{
  int unaff_EBP;
  
  FUN_100046c0((CString *)(unaff_EBP + -0x424));
  return;
}



void Unwind_1000a8ba(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x430));
  return;
}



void Unwind_1000a8c6(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x43c));
  return;
}



void Unwind_1000a8d2(void)

{
  int unaff_EBP;
  
  FUN_100046c0((CString *)(unaff_EBP + -0x438));
  return;
}



void Unwind_1000a8e8(void)

{
  int unaff_EBP;
  
  FUN_100046c0((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000a8f1(void)

{
  int unaff_EBP;
  
  FUN_100046c0((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_1000a8fa(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x38) & 1) != 0) {
    FUN_100046c0((CString *)(unaff_EBP + -0x2c));
  }
  return;
}



void Unwind_1000a911(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x38) & 2) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000a932(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000a93b(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a944(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000a94d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000a956(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x20) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000a977(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000a980(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000a989(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000a992(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x1c) & 1) != 0) {
    FUN_10002ca0(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000a9b3(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000a9bc(void)

{
  int unaff_EBP;
  
  FUN_100046c0((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000a9cf(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_1000a9d8(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_1000a9e1(void)

{
  int unaff_EBP;
  
  FUN_100046c0((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000a9ea(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x40));
  return;
}



void Unwind_1000a9f3(void)

{
  int unaff_EBP;
  
  FUN_100046c0((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_1000aa06(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_1000aa0f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000aa18(void)

{
  int unaff_EBP;
  
  FUN_100046c0((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000aa21(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_1000aa34(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x20) & 1) != 0) {
    FUN_10002ca0(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000aa4b(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000aa54(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000aa5d(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000aa66(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000aa79(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000aa82(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_1000aa8b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x38));
  return;
}



void Unwind_1000aa94(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x30));
  return;
}



void Unwind_1000aa9d(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_1000aaa6(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x40));
  return;
}



void Unwind_1000aaaf(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x44));
  return;
}



void Unwind_1000aab8(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_1000aac1(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000aaca(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_1000aad3(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_1000aadc(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_1000aae5(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x48));
  return;
}



void Unwind_1000aaee(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x4c));
  return;
}



void Unwind_1000aaf7(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x50));
  return;
}



void Unwind_1000ab00(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x54));
  return;
}



void Unwind_1000ab09(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x5c));
  return;
}



void Unwind_1000ab12(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x60));
  return;
}



void Unwind_1000ab1b(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x58));
  return;
}



void Unwind_1000ab24(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -100));
  return;
}



void Unwind_1000ab2d(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_1000ab36(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x68));
  return;
}



void Unwind_1000ab3f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x6c));
  return;
}



void Unwind_1000ab48(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x70));
  return;
}



void Unwind_1000ab51(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x74));
  return;
}



void Unwind_1000ab5a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x78));
  return;
}



void Unwind_1000ab63(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x7c));
  return;
}



void Unwind_1000ab6c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x80));
  return;
}



void Unwind_1000ab75(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x84));
  return;
}



void Unwind_1000ab81(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x88));
  return;
}



void Unwind_1000ab97(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000abaa(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000abbd(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000abd0(void)

{
  int unaff_EBP;
  
  CFileFind::~CFileFind((CFileFind *)(unaff_EBP + -0x28));
  return;
}



void Unwind_1000abd9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x54));
  return;
}



void Unwind_1000abe2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x58));
  return;
}



void Unwind_1000abeb(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x5c));
  return;
}



void Unwind_1000abf4(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x6c) & 1) != 0) {
    FUN_10007aa0(*(undefined4 **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000ac0b(void)

{
  int unaff_EBP;
  
  FUN_10007aa0((undefined4 *)(unaff_EBP + -0x44));
  return;
}



void Unwind_1000ac14(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -100));
  return;
}



void Unwind_1000ac1f(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x6c) & 2) != 0) {
    CString::~CString((CString *)(unaff_EBP + -0x68));
  }
  return;
}



void Unwind_1000ac40(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000ac4b(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_1000ac60(void)

{
  int unaff_EBP;
  
  FUN_100046c0((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000ac80(void)

{
  int unaff_EBP;
  
  FUN_100081b0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000aca0(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000acc0(void)

{
  int unaff_EBP;
  
  FUN_10002870(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000ace0(void)

{
  int unaff_EBP;
  
  FUN_100046c0((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000ad00(void)

{
  int unaff_EBP;
  
  FUN_10002870(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000ad20(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 0xc));
  return;
}



void Unwind_1000ad29(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 8));
  return;
}



void Unwind_1000ad32(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000ad50(void)

{
  int unaff_EBP;
  
  FUN_10002ff0((undefined4 *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000ad59(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x40));
  return;
}



void Unwind_1000ad6c(void)

{
  int unaff_EBP;
  
  FUN_10002ff0((undefined4 *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_1000ad75(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000ad7e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x43c));
  return;
}



void Unwind_1000ad8a(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x44c) & 1) != 0) {
    CString::~CString((CString *)(unaff_EBP + -0x440));
  }
  return;
}



void Unwind_1000ada7(void)

{
  int unaff_EBP;
  
  FUN_100094b0((CString *)(unaff_EBP + -0x434));
  return;
}



void Unwind_1000adbd(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_1000adc6(void)

{
  int unaff_EBP;
  
  FUN_10002ff0((undefined4 *)(unaff_EBP + -0x120));
  return;
}



void Unwind_1000add2(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x128) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000adec(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x118));
  return;
}



void Unwind_1000ae02(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x120));
  return;
}



void Unwind_1000ae0e(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_1000ae17(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x128));
  return;
}



void Unwind_1000ae23(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -300));
  return;
}



void Unwind_1000ae2f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x130));
  return;
}



void Unwind_1000ae3b(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x124));
  return;
}



void Unwind_1000ae47(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x11c));
  return;
}



void Unwind_1000ae53(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x144) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_1000ae6d(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x138));
  return;
}



void Unwind_1000ae79(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x13c));
  return;
}



void Unwind_1000ae85(void)

{
  int unaff_EBP;
  
  FUN_10002ca0((CString *)(unaff_EBP + -0x140));
  return;
}



void Unwind_1000aea0(void)

{
  int unaff_EBP;
  
  FUN_10002ca0(*(CString **)(unaff_EBP + 8));
  return;
}



void Unwind_1000aeb4(void)

{
  int unaff_EBP;
  
  FUN_10004910((undefined4 *)(unaff_EBP + -0x14));
  return;
}


