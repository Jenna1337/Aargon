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
typedef unsigned short    word;
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

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

struct TypeDescriptor {
    dword hash;
    void *spare;
    char name[0];
};

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

typedef struct _s_TryBlockMapEntry TryBlockMapEntry;

typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

typedef struct _s_HandlerType HandlerType;

typedef int ptrdiff_t;

struct _s_HandlerType {
    uint adjectives;
    struct TypeDescriptor *pType;
    ptrdiff_t dispCatchObj;
    void *addressOfHandler;
};

struct _s_TryBlockMapEntry {
    __ehstate_t tryLow;
    __ehstate_t tryHigh;
    __ehstate_t catchHigh;
    int nCatches;
    HandlerType *pHandlerArray;
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

struct _s_FuncInfo {
    uint magicNumber_and_bbtFlags;
    __ehstate_t maxState;
    UnwindMapEntry *pUnwindMap;
    uint nTryBlocks;
    TryBlockMapEntry *pTryBlockMap;
    uint nIPMapEntries;
    void *pIPToStateMap;
};

typedef struct _s_FuncInfo FuncInfo;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef ulong DWORD;

typedef char CHAR;

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

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void *LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _STARTUPINFOA *LPSTARTUPINFOA;

typedef struct _WIN32_FIND_DATAA _WIN32_FIND_DATAA, *P_WIN32_FIND_DATAA;

typedef struct _WIN32_FIND_DATAA *LPWIN32_FIND_DATAA;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

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

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _FLOATING_SAVE_AREA _FLOATING_SAVE_AREA, *P_FLOATING_SAVE_AREA;

typedef struct _FLOATING_SAVE_AREA FLOATING_SAVE_AREA;

struct _FLOATING_SAVE_AREA {
    DWORD ControlWord;
    DWORD StatusWord;
    DWORD TagWord;
    DWORD ErrorOffset;
    DWORD ErrorSelector;
    DWORD DataOffset;
    DWORD DataSelector;
    BYTE RegisterArea[80];
    DWORD Cr0NpxState;
};

struct _CONTEXT {
    DWORD ContextFlags;
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr6;
    DWORD Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs;
    DWORD SegFs;
    DWORD SegEs;
    DWORD SegDs;
    DWORD Edi;
    DWORD Esi;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Ebp;
    DWORD Eip;
    DWORD SegCs;
    DWORD EFlags;
    DWORD Esp;
    DWORD SegSs;
    BYTE ExtendedRegisters[512];
};

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef void *PVOID;

typedef ulong ULONG_PTR;

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

typedef struct _CONTEXT CONTEXT;

typedef CONTEXT *PCONTEXT;

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef struct tagOFNA tagOFNA, *PtagOFNA;

typedef struct tagOFNA *LPOPENFILENAMEA;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

typedef CHAR *LPCSTR;

typedef long LONG_PTR;

typedef LONG_PTR LPARAM;

typedef uint UINT_PTR;

typedef uint UINT;

typedef UINT_PTR WPARAM;

typedef UINT_PTR (*LPOFNHOOKPROC)(HWND, UINT, WPARAM, LPARAM);

struct tagOFNA {
    DWORD lStructSize;
    HWND hwndOwner;
    HINSTANCE hInstance;
    LPCSTR lpstrFilter;
    LPSTR lpstrCustomFilter;
    DWORD nMaxCustFilter;
    DWORD nFilterIndex;
    LPSTR lpstrFile;
    DWORD nMaxFile;
    LPSTR lpstrFileTitle;
    DWORD nMaxFileTitle;
    LPCSTR lpstrInitialDir;
    LPCSTR lpstrTitle;
    DWORD Flags;
    WORD nFileOffset;
    WORD nFileExtension;
    LPCSTR lpstrDefExt;
    LPARAM lCustData;
    LPOFNHOOKPROC lpfnHook;
    LPCSTR lpTemplateName;
    void *pvReserved;
    DWORD dwReserved;
    DWORD FlagsEx;
};

struct HINSTANCE__ {
    int unused;
};

struct HWND__ {
    int unused;
};

typedef uint size_t;

typedef struct _startupinfo _startupinfo, *P_startupinfo;

struct _startupinfo {
    int newmode;
};

typedef LONG_PTR LRESULT;

typedef LRESULT (*WNDPROC)(HWND, UINT, WPARAM, LPARAM);

typedef BOOL (*WNDENUMPROC)(HWND, LPARAM);

typedef long HRESULT;

typedef long LONG;

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

typedef ULONG_PTR SIZE_T;

typedef int INT_PTR;

typedef struct _IMAGELIST _IMAGELIST, *P_IMAGELIST;

typedef struct _IMAGELIST *HIMAGELIST;

struct _IMAGELIST {
};

typedef struct tagPOINT tagPOINT, *PtagPOINT;

typedef struct tagPOINT *LPPOINT;

struct tagPOINT {
    LONG x;
    LONG y;
};

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef struct HBITMAP__ HBITMAP__, *PHBITMAP__;

struct HBITMAP__ {
    int unused;
};

typedef struct tagRECT tagRECT, *PtagRECT;

typedef struct tagRECT RECT;

struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

typedef int (*FARPROC)(void);

typedef struct HICON__ HICON__, *PHICON__;

struct HICON__ {
    int unused;
};

typedef struct HDC__ HDC__, *PHDC__;

struct HDC__ {
    int unused;
};

typedef struct tagRECT *LPRECT;

typedef void *HGDIOBJ;

typedef struct HKEY__ *HKEY;

typedef struct HICON__ *HICON;

typedef HICON HCURSOR;

typedef DWORD *LPDWORD;

typedef void *LPCVOID;

typedef struct HDC__ *HDC;

typedef int INT;

typedef HKEY *PHKEY;

typedef struct HBITMAP__ *HBITMAP;

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

typedef struct Var Var, *PVar;

struct Var {
    word wLength;
    word wValueLength;
    word wType;
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

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo {
    word wLength;
    word wValueLength;
    word wType;
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

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
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

typedef struct VS_VERSION_INFO VS_VERSION_INFO, *PVS_VERSION_INFO;

struct VS_VERSION_INFO {
    word StructLength;
    word ValueLength;
    word StructType;
    wchar16 Info[16];
    byte Padding[2];
    dword Signature;
    word StructVersion[2];
    word FileVersion[4];
    word ProductVersion[4];
    dword FileFlagsMask[2];
    dword FileFlags;
    dword FileOS;
    dword FileType;
    dword FileSubtype;
    dword FileTimestamp;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
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

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef ACCESS_MASK REGSAM;

typedef LONG LSTATUS;

typedef struct CDC CDC, *PCDC;

struct CDC { // PlaceHolder Structure
};

typedef struct CWave CWave, *PCWave;

struct CWave { // PlaceHolder Structure
};

typedef struct CWinThread CWinThread, *PCWinThread;

struct CWinThread { // PlaceHolder Structure
};

typedef struct CListBox CListBox, *PCListBox;

struct CListBox { // PlaceHolder Structure
};

typedef struct long_(__stdcall**)(struct_HWND__*,unsigned_int,unsigned_int,long) long_(__stdcall**)(struct_HWND__*,unsigned_int,unsigned_int,long), *Plong_(__stdcall**)(struct_HWND__*,unsigned_int,unsigned_int,long);

struct long_(__stdcall**)(struct_HWND__*,unsigned_int,unsigned_int,long) { // PlaceHolder Structure
};

typedef struct __POSITION __POSITION, *P__POSITION;

struct __POSITION { // PlaceHolder Structure
};

typedef struct CArchive CArchive, *PCArchive;

struct CArchive { // PlaceHolder Structure
};

typedef struct _DDSURFACEDESC _DDSURFACEDESC, *P_DDSURFACEDESC;

struct _DDSURFACEDESC { // PlaceHolder Structure
};

typedef struct _GUID _GUID, *P_GUID;

struct _GUID { // PlaceHolder Structure
};

typedef struct CDataExchange CDataExchange, *PCDataExchange;

struct CDataExchange { // PlaceHolder Structure
};

typedef struct MAP MAP, *PMAP;

struct MAP { // PlaceHolder Structure
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

typedef struct CImageList CImageList, *PCImageList;

struct CImageList { // PlaceHolder Structure
};

typedef struct INIFILE INIFILE, *PINIFILE;

struct INIFILE { // PlaceHolder Structure
};

typedef struct TwLightning TwLightning, *PTwLightning;

struct TwLightning { // PlaceHolder Structure
};

typedef struct CScrollBar CScrollBar, *PCScrollBar;

struct CScrollBar { // PlaceHolder Structure
};

typedef struct tagMEASUREITEMSTRUCT tagMEASUREITEMSTRUCT, *PtagMEASUREITEMSTRUCT;

struct tagMEASUREITEMSTRUCT { // PlaceHolder Structure
};

typedef struct tagCOMPAREITEMSTRUCT tagCOMPAREITEMSTRUCT, *PtagCOMPAREITEMSTRUCT;

struct tagCOMPAREITEMSTRUCT { // PlaceHolder Structure
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

typedef struct CDIBStatic CDIBStatic, *PCDIBStatic;

struct CDIBStatic { // PlaceHolder Structure
};

typedef struct tagDELETEITEMSTRUCT tagDELETEITEMSTRUCT, *PtagDELETEITEMSTRUCT;

struct tagDELETEITEMSTRUCT { // PlaceHolder Structure
};

typedef struct FONT FONT, *PFONT;

struct FONT { // PlaceHolder Structure
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

typedef struct TwCompatibleBitmap TwCompatibleBitmap, *PTwCompatibleBitmap;

struct TwCompatibleBitmap { // PlaceHolder Structure
};

typedef struct CListCtrl CListCtrl, *PCListCtrl;

struct CListCtrl { // PlaceHolder Structure
};

typedef struct CDib CDib, *PCDib;

struct CDib { // PlaceHolder Structure
};

typedef struct CBrush CBrush, *PCBrush;

struct CBrush { // PlaceHolder Structure
};

typedef struct tagDRAWITEMSTRUCT tagDRAWITEMSTRUCT, *PtagDRAWITEMSTRUCT;

struct tagDRAWITEMSTRUCT { // PlaceHolder Structure
};

typedef struct CFindReplaceDialog CFindReplaceDialog, *PCFindReplaceDialog;

struct CFindReplaceDialog { // PlaceHolder Structure
};

typedef struct TwTransparentOverlay TwTransparentOverlay, *PTwTransparentOverlay;

struct TwTransparentOverlay { // PlaceHolder Structure
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

typedef struct CChevronOwnerDrawMenu CChevronOwnerDrawMenu, *PCChevronOwnerDrawMenu;

struct CChevronOwnerDrawMenu { // PlaceHolder Structure
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

typedef struct LIST<class_ITEM*> LIST<class_ITEM*>, *PLIST<class_ITEM*>;

struct LIST<class_ITEM*> { // PlaceHolder Structure
};

typedef struct _AFX_OCC_DIALOG_INFO _AFX_OCC_DIALOG_INFO, *P_AFX_OCC_DIALOG_INFO;

struct _AFX_OCC_DIALOG_INFO { // PlaceHolder Structure
};

typedef struct CHyperLink CHyperLink, *PCHyperLink;

struct CHyperLink { // PlaceHolder Structure
};

typedef struct SPRITE SPRITE, *PSPRITE;

struct SPRITE { // PlaceHolder Structure
};

typedef struct tagTOOLINFOA tagTOOLINFOA, *PtagTOOLINFOA;

struct tagTOOLINFOA { // PlaceHolder Structure
};

typedef struct CPlex CPlex, *PCPlex;

struct CPlex { // PlaceHolder Structure
};

typedef struct ITEM ITEM, *PITEM;

struct ITEM { // PlaceHolder Structure
};

typedef struct CRect CRect, *PCRect;

struct CRect { // PlaceHolder Structure
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

typedef struct CSliderCtrl CSliderCtrl, *PCSliderCtrl;

struct CSliderCtrl { // PlaceHolder Structure
};

typedef struct CMFCOutlookBarPane CMFCOutlookBarPane, *PCMFCOutlookBarPane;

struct CMFCOutlookBarPane { // PlaceHolder Structure
};

typedef struct LEVEL LEVEL, *PLEVEL;

struct LEVEL { // PlaceHolder Structure
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

typedef struct CDHtmlElementEventSink CDHtmlElementEventSink, *PCDHtmlElementEventSink;

struct CDHtmlElementEventSink { // PlaceHolder Structure
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

typedef struct TwAutoButton TwAutoButton, *PTwAutoButton;

struct TwAutoButton { // PlaceHolder Structure
};

typedef struct TwProgressBar TwProgressBar, *PTwProgressBar;

struct TwProgressBar { // PlaceHolder Structure
};

typedef struct LIST<class_INIFILE*> LIST<class_INIFILE*>, *PLIST<class_INIFILE*>;

struct LIST<class_INIFILE*> { // PlaceHolder Structure
};

typedef struct CComboBox CComboBox, *PCComboBox;

struct CComboBox { // PlaceHolder Structure
};

typedef struct CBitmap CBitmap, *PCBitmap;

struct CBitmap { // PlaceHolder Structure
};

typedef struct TIMER TIMER, *PTIMER;

struct TIMER { // PlaceHolder Structure
};

typedef struct GAME GAME, *PGAME;

struct GAME { // PlaceHolder Structure
};

typedef struct CMFCWindowsManagerDialog CMFCWindowsManagerDialog, *PCMFCWindowsManagerDialog;

struct CMFCWindowsManagerDialog { // PlaceHolder Structure
};

typedef struct CObject CObject, *PCObject;

struct CObject { // PlaceHolder Structure
};

typedef struct CPen CPen, *PCPen;

struct CPen { // PlaceHolder Structure
};

typedef struct CMidi CMidi, *PCMidi;

struct CMidi { // PlaceHolder Structure
};

typedef struct CPoint CPoint, *PCPoint;

struct CPoint { // PlaceHolder Structure
};

typedef struct shared_ptr<struct_Concurrency::details::_Task_impl<unsigned_char>_> shared_ptr<struct_Concurrency::details::_Task_impl<unsigned_char>_>, *Pshared_ptr<struct_Concurrency::details::_Task_impl<unsigned_char>_>;

struct shared_ptr<struct_Concurrency::details::_Task_impl<unsigned_char>_> { // PlaceHolder Structure
};

typedef struct SafeSQueue<class_Concurrency::details::UMSThreadProxy,class_Concurrency::details::_NonReentrantLock> SafeSQueue<class_Concurrency::details::UMSThreadProxy,class_Concurrency::details::_NonReentrantLock>, *PSafeSQueue<class_Concurrency::details::UMSThreadProxy,class_Concurrency::details::_NonReentrantLock>;

struct SafeSQueue<class_Concurrency::details::UMSThreadProxy,class_Concurrency::details::_NonReentrantLock> { // PlaceHolder Structure
};

typedef struct SECTION SECTION, *PSECTION;

struct SECTION { // PlaceHolder Structure
};

typedef enum DIRECTION {
} DIRECTION;

typedef int (*_onexit_t)(void);




void * __thiscall FUN_00401000(void *this,CWnd *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004281b9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00401770(this,0x67,param_1);
  local_8 = 0;
  CDIBStatic::CDIBStatic((CDIBStatic *)((int)this + 0x60));
  *(undefined ***)this = &PTR_LAB_0042c7a0;
  ExceptionList = local_10;
  return this;
}



void __thiscall FUN_00401060(void *this,CDataExchange *param_1)

{
  FUN_00401480();
  DDX_Control(param_1,0x3ec,(CWnd *)((int)this + 0x60));
  return;
}



undefined * FUN_0040108e(void)

{
  return messageMap_exref;
}



undefined ** FUN_00401098(void)

{
  return &PTR_FUN_0042c780;
}



undefined4 __fastcall FUN_004010a8(TwDirectXDialog *param_1)

{
  CString *pCVar1;
  undefined4 *puVar2;
  char *pcVar3;
  HWND hWnd;
  char *pcVar4;
  LPCSTR lpString;
  CString local_48 [4];
  CString local_44 [4];
  CString local_40 [4];
  CString local_3c [4];
  CString local_38 [4];
  INIFILE local_34 [36];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004281fa;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  TwDirectXDialog::OnInitDialog(param_1);
  FUN_004017f0((CDIBStatic *)(param_1 + 0x60));
  pCVar1 = FUN_004014f0(local_38);
  local_8 = 0;
  puVar2 = (undefined4 *)operator+(local_3c,(char *)pCVar1);
  local_8._0_1_ = 1;
  pcVar3 = (char *)FUN_00401470(puVar2);
  CDIBStatic::LoadDib((CDIBStatic *)(param_1 + 0x60),pcVar3);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(local_3c);
  local_8 = 0xffffffff;
  CString::~CString(local_38);
  CDIBStatic::UpdateDib((CDIBStatic *)(param_1 + 0x60));
  lpString = (LPCSTR)0x1;
  pcVar4 = s_game_ini_004340cc;
  pCVar1 = FUN_004014f0(local_40);
  local_8 = 2;
  puVar2 = (undefined4 *)operator+(local_44,(char *)pCVar1);
  local_8._0_1_ = 3;
  pcVar3 = (char *)FUN_00401470(puVar2);
  INIFILE::INIFILE(local_34,pcVar3,(int)pcVar4);
  local_8._0_1_ = 6;
  CString::~CString(local_44);
  local_8._0_1_ = 5;
  CString::~CString(local_40);
  puVar2 = (undefined4 *)INIFILE::GetValue(local_34,(char *)local_48,s_OtherGames_004340e0);
  local_8._0_1_ = 7;
  hWnd = (HWND)FUN_00401470(puVar2);
  CWnd::GetDlgItem((HWND)&hDlg_000003ed,(int)hWnd);
  CWnd::SetWindowTextA(hWnd,lpString);
  local_8 = CONCAT31(local_8._1_3_,5);
  FUN_004014d0(local_48);
  local_8 = 0xffffffff;
  INIFILE::~INIFILE(local_34);
  ExceptionList = local_10;
  return 1;
}



void __fastcall FUN_0040122d(CDialog *param_1)

{
  bool bVar1;
  CString *pCVar2;
  undefined4 *puVar3;
  char *pcVar4;
  undefined3 extraout_var;
  CHyperLink *this;
  char *pcVar5;
  int iVar6;
  CHyperLink local_108 [200];
  CString local_40 [4];
  CString local_3c [4];
  INIFILE local_38 [36];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_2_00428236;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CDialog::OnOK(param_1);
  pcVar5 = s_game_ini_004340ec;
  pCVar2 = FUN_004014f0(local_3c);
  local_8 = 0;
  puVar3 = (undefined4 *)operator+(local_40,(char *)pCVar2);
  local_8._0_1_ = 1;
  pcVar4 = (char *)FUN_00401470(puVar3);
  INIFILE::INIFILE(local_38,pcVar4,(int)pcVar5);
  local_8._0_1_ = 4;
  CString::~CString(local_40);
  local_8._0_1_ = 3;
  CString::~CString(local_3c);
  INIFILE::GetValue(local_38,(char *)local_14,s_OtherGames_004340fc);
  local_8._0_1_ = 5;
  bVar1 = FUN_00401430((int *)local_14);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    iVar6 = 1;
    pcVar4 = (char *)FUN_00401470((undefined4 *)local_14);
    this = (CHyperLink *)CHyperLink::CHyperLink(local_108);
    local_8._0_1_ = 6;
    CHyperLink::GotoURL(this,pcVar4,iVar6);
    local_8._0_1_ = 5;
    CHyperLink::~CHyperLink(local_108);
  }
  local_8 = CONCAT31(local_8._1_3_,3);
  FUN_004014d0(local_14);
  local_8 = 0xffffffff;
  INIFILE::~INIFILE(local_38);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_00401380(void *this,uint param_1)

{
  FUN_004013b0((CDialog *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_004013b0(CDialog *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00428249;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  CDIBStatic::~CDIBStatic((CDIBStatic *)(param_1 + 0x60));
  local_8 = 0xffffffff;
  FUN_004017d0(param_1);
  ExceptionList = local_10;
  return;
}



void FUN_00401400(void)

{
  return;
}



void FUN_00401410(void *param_1)

{
  operator_delete(param_1);
  return;
}



bool __fastcall FUN_00401430(int *param_1)

{
  int iVar1;
  
  iVar1 = FUN_00401450(param_1);
  return *(int *)(iVar1 + 4) == 0;
}



int __fastcall FUN_00401450(int *param_1)

{
  return *param_1 + -0xc;
}



undefined4 __fastcall FUN_00401470(undefined4 *param_1)

{
  return *param_1;
}



void FUN_00401480(void)

{
  return;
}



void __fastcall FUN_00401490(int param_1)

{
  EnableWindow(*(HWND *)(param_1 + 0x20),0);
  return;
}



void __fastcall FUN_004014b0(int param_1)

{
  EnableWindow(*(HWND *)(param_1 + 0x20),1);
  return;
}



void __fastcall FUN_004014d0(CString *param_1)

{
  CString::~CString(param_1);
  return;
}



CString * __cdecl FUN_004014f0(CString *param_1)

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
  puStack_c = &param_1_0042829b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(local_14);
  local_8 = 1;
  pCVar3 = local_14;
  pcVar4 = s_DataDir_00434120;
  this = (REG *)FUN_004016a0(&local_1c,&DAT_00435ec8,s_Software_Twilight__0043410c);
  local_8._0_1_ = 2;
  bVar1 = REG::Get(this,pcVar4,pCVar3);
  local_18 = CONCAT31(local_18._1_3_,bVar1);
  local_8._0_1_ = 1;
  FUN_00401750(&local_1c);
  if ((local_18 & 0xff) == 0) {
    REG::RootDir();
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_14);
  }
  else {
    cVar2 = FUN_00401680(local_14,0);
    if ((cVar2 != '\\') && (cVar2 = FUN_00401680(local_14,1), cVar2 != ':')) {
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



undefined1 __thiscall FUN_00401680(void *this,int param_1)

{
                    // WARNING: Load size is inaccurate
  return *(undefined1 *)(*this + param_1);
}



void * __thiscall FUN_004016a0(void *this,undefined4 param_1,char *param_2)

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
  puStack_c = &lpdwDisposition_004282c2;
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
  lpSubKey = (LPCSTR)FUN_00401470((undefined4 *)local_18);
  local_14 = RegCreateKeyExA((HKEY)0x80000001,lpSubKey,Reserved,lpClass,dwOptions,samDesired,
                             lpSecurityAttributes,phkResult,lpdwDisposition);
  SetLastError(local_14);
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  ExceptionList = local_10;
  return this;
}



void __fastcall FUN_00401750(undefined4 *param_1)

{
  RegCloseKey((HKEY)*param_1);
  return;
}



void * __thiscall FUN_00401770(void *this,uint param_1,CWnd *param_2)

{
  CDialog::CDialog((CDialog *)this,param_1,param_2);
  *(undefined ***)this = &PTR_LAB_0042c878;
  return this;
}



void * __thiscall FUN_004017a0(void *this,uint param_1)

{
  FUN_004017d0((CDialog *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_004017d0(CDialog *param_1)

{
  CDialog::~CDialog(param_1);
  return;
}



void __fastcall FUN_004017f0(CDIBStatic *param_1)

{
  FUN_00401810((CDib *)(param_1 + 0x40));
  CDIBStatic::UpdateDib(param_1);
  return;
}



void __fastcall FUN_00401810(CDib *param_1)

{
  CDib::Free(param_1);
  return;
}



void * __thiscall FUN_00401830(void *this,CWnd *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_00428309;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00401770(this,0x87,param_1);
  local_8 = 0;
  FUN_004016a0((void *)((int)this + 0x60),s_Aargon_Deluxe_Editor_0043413c,
               s_Software_Twilight__00434128);
  local_8._0_1_ = 1;
  CImageList::CImageList((CImageList *)((int)this + 100));
  local_8._0_1_ = 2;
  FUN_00404f20((int)this + 0x6c);
  *(undefined4 *)((int)this + 0x74) = 0xffffffff;
  CString::CString((CString *)((int)this + 0x78));
  local_8._0_1_ = 3;
  CString::CString((CString *)((int)this + 0x7c));
  local_8 = CONCAT31(local_8._1_3_,4);
  *(undefined1 *)((int)this + 0x80) = 0;
  *(undefined4 *)((int)this + 0x84) = 0;
  *(undefined4 *)((int)this + 0x88) = 0;
  FUN_00405430((CWnd *)((int)this + 0x8c));
  *(undefined ***)this = &PTR_LAB_0042cbe0;
  ExceptionList = local_10;
  return this;
}



// Library Function - Single Match
//  protected: virtual void __thiscall CMFCWindowsManagerDialog::DoDataExchange(class CDataExchange
// *)
// 
// Library: Visual Studio 2010 Debug

void __thiscall
CMFCWindowsManagerDialog::DoDataExchange(CMFCWindowsManagerDialog *this,CDataExchange *param_1)

{
  FUN_00401480();
  DDX_Control(param_1,0x3fb,(CWnd *)(this + 0x8c));
  return;
}



undefined * FUN_00401945(void)

{
  return messageMap_exref;
}



undefined ** FUN_0040194f(void)

{
  return &PTR_FUN_0042c950;
}



void __thiscall FUN_0040195f(void *this,uint param_1)

{
  BOOL BVar1;
  LPRECT ptVar2;
  HWND__ *hWnd;
  uint nHeight;
  int nWidth;
  int Y;
  tagPOINT *lpPoint;
  tagPOINT local_1c;
  int local_14 [4];
  
  BVar1 = IsWindow(*(HWND *)((int)this + 0x20));
  if (BVar1 != 0) {
    FUN_00404f20(local_14);
    ptVar2 = (LPRECT)FUN_00404f70(local_14);
    FUN_004053f0(this,ptVar2);
    local_1c.x = *(undefined4 *)((int)this + 0x6c);
    local_1c.y = *(int *)((int)this + 0x70);
    lpPoint = &local_1c;
    hWnd = GKERNEL::GetHwnd();
    ClientToScreen(hWnd,lpPoint);
    nHeight = param_1 & 0xff;
    nWidth = FUN_00404f50((int)local_14);
    Y = FUN_00404f30(local_14);
    CWnd::MoveWindow((HWND)local_1c.x,local_1c.y,Y,nWidth,nHeight,(BOOL)this);
  }
  return;
}



void __thiscall FUN_004019e5(void *this,char *param_1)

{
  HWND hWnd;
  CWnd *pCVar1;
  TwDirectXDialog local_74 [100];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042831c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pCVar1 = (CWnd *)this;
  CString::CString((CString *)&stack0xffffff74,param_1);
  hWnd = (HWND)FUN_00405bf0(local_74,this,pCVar1);
  local_8 = 0;
  TwDirectXDialog::DoModal(local_74);
  CWnd::SetFocus(hWnd);
  local_8 = 0xffffffff;
  FUN_004046a0((CDialog *)local_74);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_00401a5b(void *this,int param_1,uint param_2)

{
  uint bEnable;
  HWND hWnd;
  
  bEnable = param_2 & 0xff;
  hWnd = GetDlgItem(*(HWND *)((int)this + 0x20),param_1);
  EnableWindow(hWnd,bEnable);
  return;
}



void __thiscall FUN_00401a89(void *this,uint param_1)

{
  undefined4 local_c;
  uint local_8;
  
  local_c = *(undefined4 *)((int)this + 0x20);
  local_8 = param_1 & 0xff;
  EnumChildWindows(*(HWND *)((int)this + 0x20),lpEnumFunc_00401acb,(LPARAM)&local_c);
  CWnd::SetFocus((HWND)this);
  return;
}



// lpEnumFunc parameter of EnumChildWindows
// 

undefined4 lpEnumFunc_00401acb(HWND param_1,undefined4 *param_2)

{
  HWND pHVar1;
  HWND pHVar2;
  
  pHVar1 = GetDlgItem((HWND)*param_2,0x40b);
  pHVar2 = GetDlgItem((HWND)*param_2,0x3e9);
  if ((param_1 != pHVar1) && (param_1 != pHVar2)) {
    EnableWindow(param_1,param_2[1]);
  }
  return 1;
}



void __fastcall FUN_00401b25(int param_1)

{
  (**(code **)(**(int **)(*(int *)(param_1 + 0x88) + 0xe00c) + 0x20))();
  return;
}



void __fastcall FUN_00401b53(int param_1)

{
  CString *pCVar1;
  undefined1 auStack_80 [36];
  undefined4 uStack_5c;
  CString local_40 [4];
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_00428338;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_004046f0(&local_3c);
  local_8 = 0;
  local_34 = 3;
  uStack_5c = 0x401ba0;
  pCVar1 = (CString *)MAP::Data((MAP *)(*(int *)(param_1 + 0x88) + 0xe23c));
  local_8._0_1_ = 1;
  uStack_5c = 0x401bb9;
  CString::operator=(local_14,pCVar1);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_004014d0(local_40);
  local_3c = *(undefined4 *)(*(int *)(param_1 + 0x88) + 0xe01c);
  local_38 = *(undefined4 *)(*(int *)(param_1 + 0x88) + 0xe020);
  FUN_004047a0(auStack_80,&local_3c);
  FUN_00426d66(*(GAME **)(param_1 + 0x88));
  local_8 = 0xffffffff;
  FUN_00404750((int)&local_3c);
  ExceptionList = local_10;
  return;
}



undefined4 __fastcall FUN_00401c1f(TwDirectXDialog *param_1)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  undefined3 extraout_var;
  uint uVar4;
  undefined3 extraout_var_00;
  int *piVar5;
  undefined3 extraout_var_01;
  char *pcVar6;
  undefined4 uVar7;
  undefined3 extraout_var_02;
  undefined4 *puVar8;
  undefined3 extraout_var_03;
  undefined3 extraout_var_04;
  CString *pCVar9;
  int iVar10;
  LPARAM unaff_EDI;
  uint *puVar11;
  uint *puVar12;
  CString local_cc [4];
  CString local_c8 [4];
  CString local_c4 [4];
  CString local_c0 [4];
  int local_bc;
  CString local_b8 [4];
  int local_b4;
  undefined1 *local_b0;
  undefined4 local_ac;
  int local_a8 [4];
  char *local_98;
  int local_90;
  CString local_84 [4];
  TwCompatibleBitmap local_80 [12];
  uint local_74;
  CString local_70 [4];
  uint local_6c;
  int local_68;
  int local_64;
  uint local_60;
  uint local_5c;
  uint local_58;
  int local_54;
  undefined4 local_50;
  CTypeLibCacheMap local_4c [28];
  int local_30;
  int *local_2c;
  int local_28;
  LIST<> *local_24;
  uint local_20;
  uint local_1c;
  int *local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_3_004283a2;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  TwDirectXDialog::OnInitDialog(param_1);
  EnumChildWindows(*(HWND *)(param_1 + 0x20),lpEnumFunc_004022e8,(LPARAM)param_1);
  lpEnumFunc_004022e8(*(HWND *)(param_1 + 0x20),param_1);
  REG::GetPut((REG *)(param_1 + 0x60),(char *)&this_00434154,(ulong *)(param_1 + 0x6c),0);
  REG::GetPut((REG *)(param_1 + 0x60),(char *)&this_0043415c,(ulong *)(param_1 + 0x70),0);
  REG::GetPut((REG *)(param_1 + 0x60),(char *)&this_00434164,(bool *)(param_1 + 0x80),false);
  CWnd::SendDlgItemMessageA((HWND)&hDlg_0000040b,0xf1,(uint)(byte)param_1[0x80],0,unaff_EDI);
  FUN_0040195f(param_1,0);
  iVar3 = FUN_004056c0(*(int *)(param_1 + 0x88));
  FUN_00401a89(param_1,(uint)(iVar3 == 6));
  bVar1 = GKERNEL::Windowed();
  if (bVar1) {
    CImageList::DeleteImageList((CImageList *)(param_1 + 100));
    CImageList::Create((CImageList *)(param_1 + 100),0x20,0x20,0x18,0,4);
    local_50 = FUN_00405410((int)(param_1 + 0x8c));
    local_1c = 0;
    local_58 = 0;
    local_24 = MAP::ItemList();
    CTypeLibCacheMap::CTypeLibCacheMap(local_4c);
    local_8._0_1_ = 0;
    local_8._1_3_ = 0;
    local_30 = FUN_00423770((int)local_24);
    local_2c = (int *)0x0;
    local_14 = 0;
    bVar1 = IsEmpty((int)local_24);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      local_2c = (int *)FUN_00408430(&local_30);
    }
    local_14 = 0;
    while ((uVar4 = FUN_00423620((int)local_24), local_14 < uVar4 &&
           (bVar1 = IsEmpty((int)local_24), CONCAT31(extraout_var_00,bVar1) == 0))) {
      local_b0 = &stack0xfffffeec;
      (**(code **)(*local_2c + 0x68))(&stack0xfffffeec);
      (**(code **)(**(int **)(param_1 + 0x88) + 0x54))(local_70);
      local_8._0_1_ = 1;
      piVar5 = (int *)(**(code **)(*local_2c + 0x50))(local_b8);
      local_8._0_1_ = 2;
      bVar1 = FUN_00401430(piVar5);
      local_b4 = CONCAT31(extraout_var_01,bVar1);
      local_8._0_1_ = 1;
      CString::~CString(local_b8);
      if (local_b4 == 0) {
        pcVar6 = (char *)FUN_00401470((undefined4 *)local_70);
        bVar1 = exists(pcVar6);
        if (bVar1) {
          puVar12 = &local_58;
          puVar11 = &local_1c;
          pcVar6 = (char *)FUN_00401470((undefined4 *)local_70);
          GKTOOLS::GetDIBSize(pcVar6,puVar11,puVar12);
          local_6c = local_1c >> 5;
          FUN_00405990(local_80,local_50);
          local_8 = CONCAT31(local_8._1_3_,3);
          local_74 = (**(code **)(*local_2c + 0x6c))(7,0);
          FUN_00404f20(&local_68);
          iVar10 = (local_74 % local_6c) * 0x20;
          iVar3 = (local_74 / local_6c) * 0x20;
          uVar4 = iVar10 + 0x20;
          local_5c = iVar3 + 0x20;
          local_68 = iVar10;
          local_64 = iVar3;
          local_60 = uVar4;
          if ((uVar4 <= local_1c) && (local_5c <= local_58)) {
            uVar7 = FUN_00401470((undefined4 *)local_70);
            TwCompatibleBitmap::LoadFromFile(local_80,uVar7,iVar10,iVar3,uVar4);
            FUN_004055e0(param_1 + 100,(int)local_80,0);
            FUN_00404970(local_4c,&local_2c);
          }
          local_8._0_1_ = 1;
          FUN_00405b20((undefined4 *)local_80);
          local_8._0_1_ = 0;
          CString::~CString(local_70);
        }
        else {
          local_8._0_1_ = 0;
          CString::~CString(local_70);
        }
      }
      else {
        local_8._0_1_ = 0;
        CString::~CString(local_70);
      }
      local_14 = local_14 + 1;
      uVar4 = FUN_00423620((int)local_24);
      if (local_14 < uVar4) {
        local_2c = (int *)FUN_00408430(&local_30);
      }
    }
    FUN_00405480(param_1 + 0x8c,(int)(param_1 + 100),0);
    local_28 = 0;
    local_54 = FUN_00423770((int)local_4c);
    local_18 = (int *)0x0;
    local_20 = 0;
    bVar1 = IsEmpty((int)local_4c);
    if (CONCAT31(extraout_var_02,bVar1) == 0) {
      puVar8 = (undefined4 *)FUN_0041be90(&local_54);
      local_18 = (int *)*puVar8;
    }
    local_20 = 0;
    while ((uVar4 = FUN_00423620((int)local_4c), local_20 < uVar4 &&
           (bVar1 = IsEmpty((int)local_4c), CONCAT31(extraout_var_03,bVar1) == 0))) {
      piVar5 = (int *)(**(code **)(*local_18 + 0x50))();
      local_8._0_1_ = 4;
      bVar1 = FUN_00401430(piVar5);
      local_bc = CONCAT31(extraout_var_04,bVar1);
      local_8._0_1_ = 0;
      CString::~CString(local_c0);
      if (local_bc == 0) {
        (**(code **)(*local_18 + 0x60))();
        local_8._0_1_ = 5;
        CString::MakeLower(local_84);
        (**(code **)(*local_18 + 0x50))(local_c4,&this_0043416c);
        local_8._0_1_ = 6;
        pcVar6 = (char *)operator+((char *)local_c8,(CString *)&param_2_00434170);
        local_8._0_1_ = 7;
        pCVar9 = (CString *)operator+(local_cc,pcVar6);
        local_8._0_1_ = 8;
        CString::operator+=(local_84,pCVar9);
        local_8._0_1_ = 7;
        CString::~CString(local_cc);
        local_8._0_1_ = 6;
        CString::~CString(local_c8);
        local_8 = CONCAT31(local_8._1_3_,5);
        CString::~CString(local_c4);
        cVar2 = FUN_00401680(local_84,0);
        iVar3 = toupper((int)cVar2);
        CString::SetAt(local_84,0,(char)iVar3);
        piVar5 = local_a8;
        for (iVar3 = 9; iVar3 != 0; iVar3 = iVar3 + -1) {
          *piVar5 = 0;
          piVar5 = piVar5 + 1;
        }
        local_ac = 3;
        local_a8[0] = local_28;
        local_90 = local_28;
        pcVar6 = (char *)FUN_00401470((undefined4 *)local_84);
        local_98 = _strdup(pcVar6);
        FUN_004054f0(param_1 + 0x8c,(LPARAM)&local_ac);
        free(local_98);
        local_28 = local_28 + 1;
        local_8._0_1_ = 0;
        CString::~CString(local_84);
      }
      local_20 = local_20 + 1;
      uVar4 = FUN_00423620((int)local_4c);
      if (local_20 < uVar4) {
        puVar8 = (undefined4 *)FUN_0041be90(&local_54);
        local_18 = (int *)*puVar8;
      }
    }
    local_8 = 0xffffffff;
    FUN_00404840((undefined4 *)local_4c);
  }
  ExceptionList = local_10;
  return 1;
}



// lpEnumFunc parameter of EnumChildWindows
// 

undefined4 lpEnumFunc_004022e8(HWND param_1,undefined4 param_2)

{
  LONG LVar1;
  undefined4 *dwNewLong;
  
  SetClassLongA(param_1,-0xc,0);
  LVar1 = SetWindowLongA(param_1,-4,0x40234f);
  dwNewLong = (undefined4 *)operator_new(8);
  dwNewLong[1] = LVar1;
  *dwNewLong = param_2;
  SetWindowLongA(param_1,-0x15,(LONG)dwNewLong);
  return 1;
}



// dwNewLong parameter of SetWindowLongA
// 

void dwNewLong_0040234f(HWND param_1,UINT param_2,WPARAM param_3,LPARAM param_4)

{
  WNDPROC lpPrevWndFunc;
  bool bVar1;
  int *piVar2;
  HWND__ *hWnd;
  
  piVar2 = (int *)GetWindowLongA(param_1,-0x15);
  if (((param_2 == 0x100) || (param_2 == 0x102)) || (param_2 == 0x104)) {
    hWnd = GKERNEL::GetHwnd();
    SendMessageA(hWnd,param_2,param_3,param_4);
  }
  else {
    if ((((param_2 == 0x201) || (param_2 == 0x200)) ||
        ((param_2 == 0x204 || ((param_2 == 0x205 || (param_2 == 0x202)))))) || (param_2 == 0xa0)) {
      bVar1 = GKERNEL::Windowed();
      ShowMouse(bVar1);
      FUN_00401b25(*piVar2);
    }
    else if (param_2 == 2) {
      SetWindowLongA(param_1,-0x15,0);
      SetWindowLongA(param_1,-4,piVar2[1]);
      lpPrevWndFunc = (WNDPROC)piVar2[1];
      operator_delete(piVar2);
      CallWindowProcA(lpPrevWndFunc,param_1,2,param_3,param_4);
      return;
    }
    CallWindowProcA((WNDPROC)piVar2[1],param_1,param_2,param_3,param_4);
  }
  return;
}



void __fastcall FUN_00402470(TwDirectXDialog *param_1)

{
  undefined4 uVar1;
  LPRECT ptVar2;
  undefined4 *puVar3;
  HWND__ *hWnd;
  LPPOINT lpPoint;
  undefined1 local_1c [8];
  undefined4 local_14;
  undefined4 local_10;
  
  TwDirectXDialog::OnMove(param_1,-1,-1);
  FUN_00404f20(&local_14);
  ptVar2 = (LPRECT)FUN_00404f70(&local_14);
  FUN_004053f0(param_1,ptVar2);
  puVar3 = (undefined4 *)FUN_004163a0(local_1c,local_14,local_10);
  uVar1 = puVar3[1];
  *(undefined4 *)(param_1 + 0x6c) = *puVar3;
  *(undefined4 *)(param_1 + 0x70) = uVar1;
  lpPoint = (LPPOINT)(param_1 + 0x6c);
  hWnd = GKERNEL::GetHwnd();
  ScreenToClient(hWnd,lpPoint);
  return;
}



void __fastcall FUN_004024d7(TwDirectXDialog *param_1)

{
  HWND__ *hWnd;
  
  REG::Put((REG *)(param_1 + 0x60),(char *)&this_00434174,*(ulong *)(param_1 + 0x6c));
  REG::Put((REG *)(param_1 + 0x60),(char *)&this_0043417c,*(ulong *)(param_1 + 0x70));
  REG::Put((REG *)(param_1 + 0x60),&DAT_00434184,(bool)param_1[0x80]);
  FUN_004040c5((int)param_1);
  TwDirectXDialog::OnDestroy(param_1);
  hWnd = GKERNEL::GetHwnd();
  SetFocus(hWnd);
  return;
}



void __fastcall FUN_0040254b(LPARAM param_1)

{
  LRESULT LVar1;
  
  LVar1 = CWnd::SendDlgItemMessageA((HWND)&hDlg_0000040b,0xf0,0,0,param_1);
  *(char *)(param_1 + 0x80) = '\x01' - (LVar1 != 1);
  return;
}



CString * __thiscall FUN_0040257d(void *this,CString *param_1)

{
  STRING *pSVar1;
  int iVar2;
  WPARAM *pWVar3;
  CString *_Str;
  char **_Delim;
  STRING **ppSVar4;
  CString local_14c [4];
  CString local_148 [4];
  int local_144;
  WPARAM local_140;
  char local_13c [260];
  undefined4 local_38;
  WPARAM local_34 [4];
  char *local_24;
  undefined4 local_20;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004283de;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_144 = FUN_00405520((void *)((int)this + 0x8c));
  if (local_144 == 0) {
    CString::CString(param_1);
  }
  else {
    local_140 = FUN_00405570((void *)((int)this + 0x8c),&local_144);
    pWVar3 = local_34;
    for (iVar2 = 9; iVar2 != 0; iVar2 = iVar2 + -1) {
      *pWVar3 = 0;
      pWVar3 = pWVar3 + 1;
    }
    local_38 = 1;
    local_24 = local_13c;
    local_20 = 0x101;
    local_34[0] = local_140;
    FUN_004054c0((void *)((int)this + 0x8c),(LPARAM)&local_38);
    ppSVar4 = &this_00434190;
    _Delim = &_Str_0043418c;
    _Str = local_14c;
    FUN_004056a0(local_148,local_24);
    local_8 = 1;
    pSVar1 = (STRING *)STRING::strtok((char *)_Str,(char *)_Delim);
    local_8._0_1_ = 2;
    pSVar1 = STRING::trim(pSVar1,(char *)ppSVar4);
    CString::CString(param_1,(CString *)pSVar1);
    local_8._0_1_ = 1;
    FUN_004014d0(local_14c);
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_004014d0(local_148);
  }
  ExceptionList = local_10;
  return param_1;
}



void __thiscall FUN_00402702(void *this,undefined4 param_1,undefined4 *param_2)

{
  CString *pCVar1;
  char *pcVar2;
  ITEM *pIVar3;
  CString local_18 [4];
  ITEM *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004283f1;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00401b53((int)this);
  FUN_0040f3a1();
  pCVar1 = FUN_0040257d(this,local_18);
  local_8 = 0;
  pcVar2 = (char *)FUN_00401470((undefined4 *)pCVar1);
  pIVar3 = MAP::FindItem(pcVar2);
  local_14 = (ITEM *)(**(code **)(*(int *)pIVar3 + 4))();
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  FUN_0040f49d(*(void **)((int)this + 0x88));
  pIVar3 = MAP::SetSelectedItem((MAP *)(*(int *)((int)this + 0x88) + 0xe23c),local_14);
  if (pIVar3 != (ITEM *)0x0) {
    (*(code *)**(undefined4 **)pIVar3)(1);
  }
  *param_2 = 0;
  FUN_0040f6ea(*(void **)((int)this + 0x88),(undefined4 *)(*(int *)((int)this + 0x88) + 0xe01c));
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_00402809(void *this,undefined4 param_1,undefined4 *param_2)

{
  bool bVar1;
  
  bVar1 = FUN_00405940((int)this);
  if (bVar1) {
    FUN_00403d43(this);
  }
  *param_2 = 0;
  return;
}



void __fastcall FUN_00402838(CWnd *param_1)

{
  CString *pCVar1;
  int iVar2;
  HWND in_stack_ffffff6c;
  CString local_80 [4];
  TwDirectXDialog local_7c [96];
  CString local_1c [4];
  undefined1 local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_0042840d;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00408e60(local_7c,param_1);
  local_8 = 0;
  CString::operator=(local_14,s_Enter_New_Level_Name___00434198);
  pCVar1 = (CString *)MAP::Name((MAP *)(*(int *)(param_1 + 0x88) + 0xe23c));
  local_8._0_1_ = 1;
  FUN_004048d0(local_18,pCVar1);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_004014d0(local_80);
  CString::operator=(local_1c,s_New_Level_Name_004341b0);
  iVar2 = TwDirectXDialog::DoModal(local_7c);
  if (iVar2 == 1) {
    FUN_00401b53((int)param_1);
    pCVar1 = (CString *)STRING::toupper((int)in_stack_ffffff6c);
    in_stack_ffffff6c = (HWND)CString::CString((CString *)&stack0xffffff68,pCVar1);
    MAP::Rename((MAP *)(*(int *)(param_1 + 0x88) + 0xe23c));
    iVar2 = FUN_004056c0(*(int *)(param_1 + 0x88));
    FUN_004132e0(*(void **)(param_1 + 0x88),iVar2);
    FUN_0040f3a1();
  }
  CWnd::SetFocus(in_stack_ffffff6c);
  local_8 = 0xffffffff;
  FUN_00404860((CDialog *)local_7c);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00402981(void *param_1)

{
  undefined1 uVar1;
  bool bVar2;
  undefined3 extraout_var;
  undefined4 *puVar3;
  CString *pCVar4;
  CString local_20 [4];
  undefined4 local_1c [2];
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00428420;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  uVar1 = FUN_00414141(*(int *)((int)param_1 + 0x88));
  if (CONCAT31(extraout_var,uVar1) == 0) {
    if (*(char *)(*(int *)((int)param_1 + 0x88) + 0x1281c) != '\0') {
      local_14 = &stack0xffffffcc;
      CString::CString((CString *)&stack0xffffffcc,s_Copyright__C__2001_TwilightGames_004341e0);
      MAP::SetCopyrightString((MAP *)(*(int *)((int)param_1 + 0x88) + 0xe23c));
    }
    puVar3 = FUN_00405910((void *)(*(int *)((int)param_1 + 0x88) + 0xe23c),local_1c);
    bVar2 = MAP::Save((MAP *)(*(int *)((int)param_1 + 0x88) + 0xe23c),*puVar3);
    if (bVar2) {
      FUN_00411cca(*(void **)((int)param_1 + 0x88));
      pCVar4 = (CString *)MAP::Data((MAP *)(*(int *)((int)param_1 + 0x88) + 0xe23c));
      local_8 = 0;
      CString::operator=((CString *)((int)param_1 + 0x7c),pCVar4);
      local_8 = 0xffffffff;
      FUN_004014d0(local_20);
    }
  }
  else {
    FUN_004019e5(param_1,s_Action_disabled_in_demo_mode_004341c0);
  }
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00402aa0(void *param_1)

{
  undefined1 uVar1;
  bool bVar2;
  undefined3 extraout_var;
  CString *pCVar3;
  char *pcVar4;
  HWND__ *pHVar5;
  LPCSTR pCVar6;
  int iVar7;
  HWND unaff_EDI;
  undefined4 *puVar8;
  HWND *ppHVar9;
  BOOL BVar10;
  CString local_5d4 [4];
  CString local_5d0 [4];
  CString local_5cc [4];
  uint local_5c8;
  CString local_5c4 [4];
  MAP local_5c0 [1088];
  CString local_180 [4];
  int local_17c [2];
  REG local_174 [4];
  CString local_170 [4];
  char local_16c;
  undefined4 local_16b [65];
  BOOL local_64;
  CString local_60 [4];
  tagOFNA local_5c;
  
  local_5c.FlagsEx = 0xffffffff;
  local_5c.dwReserved = (DWORD)&LAB_00428494;
  local_5c.pvReserved = ExceptionList;
  ExceptionList = &local_5c.pvReserved;
  uVar1 = FUN_00414141(*(int *)((int)param_1 + 0x88));
  if (CONCAT31(extraout_var,uVar1) == 0) {
    bVar2 = GKERNEL::Windowed();
    if (bVar2) {
      FUN_004016a0(local_174,s_Shell_Folders_0043426c,s_Software_Microsoft_Windows_Curre_00434238);
      local_5c.FlagsEx = 0;
      CString::CString(local_60);
      local_5c.FlagsEx._0_1_ = 1;
      bVar2 = REG::Get(local_174,s_Personal_0043427c,local_60);
      if (!bVar2) {
        pCVar3 = FUN_004014f0(local_5c4);
        local_5c.FlagsEx._0_1_ = 2;
        CString::operator=(local_60,pCVar3);
        local_5c.FlagsEx._0_1_ = 1;
        CString::~CString(local_5c4);
      }
      CString::CString(local_170);
      local_5c.FlagsEx = CONCAT31(local_5c.FlagsEx._1_3_,3);
      pcVar4 = (char *)FUN_00401470((undefined4 *)local_60);
      REG::GetPut((REG *)((int)param_1 + 0x60),s_LastLoadDir_00434288,local_170,pcVar4);
      local_16c = '\0';
      puVar8 = local_16b;
      for (iVar7 = 0x41; iVar7 != 0; iVar7 = iVar7 + -1) {
        *puVar8 = 0;
        puVar8 = puVar8 + 1;
      }
      strcpy(&local_16c,s___MAP_00434294);
      ppHVar9 = &local_5c.hwndOwner;
      for (iVar7 = 0x12; iVar7 != 0; iVar7 = iVar7 + -1) {
        *ppHVar9 = (HWND)0x0;
        ppHVar9 = ppHVar9 + 1;
      }
      local_5c.lStructSize = 0x4c;
      local_5c.hwndOwner = *(HWND *)((int)param_1 + 0x20);
      local_5c.hInstance = GetModuleHandleA((LPCSTR)0x0);
      local_5c.lpstrFile = &local_16c;
      local_5c.nMaxFile = 0x105;
      local_5c.lpstrFilter = s_Map_Files____MAP__0043429c;
      local_5c.lpstrInitialDir = (LPCSTR)FUN_00401470((undefined4 *)local_170);
      local_5c.lpstrTitle = s_Open_Level_Map_File_004342b8;
      local_5c.lpstrDefExt = &DAT_004342cc;
      ShowMouse(true);
      BVar10 = 0;
      pHVar5 = GKERNEL::GetHwnd();
      EnableWindow(pHVar5,BVar10);
      local_64 = GetOpenFileNameA(&local_5c);
      BVar10 = 1;
      pHVar5 = GKERNEL::GetHwnd();
      EnableWindow(pHVar5,BVar10);
      if (local_64 != 0) {
        if ((*(char *)(*(int *)((int)param_1 + 0x88) + 0x1281c) == '\0') &&
           (bVar2 = MAP::CheckBackReflection(&local_16c), !bVar2)) {
          FUN_004019e5(param_1,s_This_file_cannot_be_edited__004342d0);
          local_5c.FlagsEx._0_1_ = 1;
          CString::~CString(local_170);
          local_5c.FlagsEx = (uint)local_5c.FlagsEx._1_3_ << 8;
          CString::~CString(local_60);
          local_5c.FlagsEx = 0xffffffff;
          FUN_00401750((undefined4 *)local_174);
          ExceptionList = local_5c.pvReserved;
          return;
        }
        FUN_004056a0(local_180,&local_16c);
        local_5c.FlagsEx._0_1_ = 4;
        pCVar6 = (LPCSTR)FUN_00401470((undefined4 *)local_180);
        FUN_004056e0(local_17c,pCVar6);
        local_5c.FlagsEx._0_1_ = 5;
        bVar2 = FUN_004057e0(local_17c);
        if (bVar2) {
          MAP::MAP(local_5c0);
          local_5c.FlagsEx._0_1_ = 6;
          iVar7 = FUN_00423770((int)local_17c);
          pcVar4 = (char *)FUN_00401470(local_17c);
          pCVar3 = (CString *)CString::CString(local_5cc,pcVar4,iVar7);
          local_5c.FlagsEx._0_1_ = 7;
          bVar2 = MAP::Set(local_5c0,pCVar3);
          local_5c8 = CONCAT31(local_5c8._1_3_,'\x01' - bVar2);
          local_5c.FlagsEx._0_1_ = 6;
          CString::~CString(local_5cc);
          if ((local_5c8 & 0xff) != 0) {
            FUN_004019e5(param_1,s_Error_loading_MAP_file_004342ec);
            local_5c.FlagsEx._0_1_ = 5;
            MAP::~MAP(local_5c0);
            local_5c.FlagsEx._0_1_ = 4;
            FUN_004057c0(local_17c);
            local_5c.FlagsEx._0_1_ = 3;
            FUN_004014d0(local_180);
            local_5c.FlagsEx._0_1_ = 1;
            CString::~CString(local_170);
            local_5c.FlagsEx = (uint)local_5c.FlagsEx._1_3_ << 8;
            CString::~CString(local_60);
            local_5c.FlagsEx = 0xffffffff;
            FUN_00401750((undefined4 *)local_174);
            ExceptionList = local_5c.pvReserved;
            return;
          }
          FUN_00401b53((int)param_1);
          iVar7 = FUN_00423770((int)local_17c);
          pcVar4 = (char *)FUN_00401470(local_17c);
          pCVar3 = (CString *)CString::CString(local_5d0,pcVar4,iVar7);
          local_5c.FlagsEx._0_1_ = 8;
          MAP::Set((MAP *)(*(int *)((int)param_1 + 0x88) + 0xe23c),pCVar3);
          local_5c.FlagsEx._0_1_ = 6;
          CString::~CString(local_5d0);
          iVar7 = FUN_004056c0(*(int *)((int)param_1 + 0x88));
          FUN_004132e0(*(void **)((int)param_1 + 0x88),iVar7);
          FUN_0040f3a1();
          local_5c.FlagsEx._0_1_ = 5;
          MAP::~MAP(local_5c0);
        }
        STRING::strtok((char *)local_5d4,(char *)&_Delim_00434304);
        FUN_004014d0(local_5d4);
        pcVar4 = (char *)FUN_00401470((undefined4 *)local_180);
        REG::Put((REG *)((int)param_1 + 0x60),s_LastLoadDir_00434308,pcVar4);
        local_5c.FlagsEx._0_1_ = 4;
        FUN_004057c0(local_17c);
        local_5c.FlagsEx = CONCAT31(local_5c.FlagsEx._1_3_,3);
        FUN_004014d0(local_180);
      }
      CWnd::SetFocus(unaff_EDI);
      local_5c.FlagsEx._0_1_ = 1;
      CString::~CString(local_170);
      local_5c.FlagsEx = (uint)local_5c.FlagsEx._1_3_ << 8;
      CString::~CString(local_60);
      local_5c.FlagsEx = 0xffffffff;
      FUN_00401750((undefined4 *)local_174);
    }
  }
  else {
    FUN_004019e5(param_1,s_Action_disabled_in_demo_mode_00434218);
  }
  ExceptionList = local_5c.pvReserved;
  return;
}



void __fastcall FUN_00402fa2(CWnd *param_1)

{
  undefined1 uVar1;
  bool bVar2;
  undefined3 extraout_var;
  CString *pCVar3;
  char *pcVar4;
  undefined4 *puVar5;
  HWND__ *pHVar6;
  int iVar7;
  HWND unaff_EDI;
  HWND *ppHVar8;
  BOOL BVar9;
  CString local_1e8 [4];
  CString local_1e4 [4];
  CString local_1e0 [4];
  TwDirectXDialog local_1dc [96];
  CString local_17c [4];
  CString local_178 [4];
  REG local_174 [4];
  CString local_170 [4];
  char local_16c;
  undefined4 local_16b [65];
  BOOL local_64;
  CString local_60 [4];
  tagOFNA local_5c;
  
  local_5c.FlagsEx = 0xffffffff;
  local_5c.dwReserved = (DWORD)&LAB_004284ef;
  local_5c.pvReserved = ExceptionList;
  ExceptionList = &local_5c.pvReserved;
  uVar1 = FUN_00414141(*(int *)(param_1 + 0x88));
  if (CONCAT31(extraout_var,uVar1) == 0) {
    bVar2 = GKERNEL::Windowed();
    if (bVar2) {
      FUN_004016a0(local_174,s_Shell_Folders_00434368,s_Software_Microsoft_Windows_Curre_00434334);
      local_5c.FlagsEx = 0;
      CString::CString(local_60);
      local_5c.FlagsEx._0_1_ = 1;
      bVar2 = REG::Get(local_174,s_Personal_00434378,local_60);
      if (!bVar2) {
        pCVar3 = FUN_004014f0(local_1e0);
        local_5c.FlagsEx._0_1_ = 2;
        CString::operator=(local_60,pCVar3);
        local_5c.FlagsEx._0_1_ = 1;
        CString::~CString(local_1e0);
      }
      CString::CString(local_170);
      local_5c.FlagsEx = CONCAT31(local_5c.FlagsEx._1_3_,3);
      pcVar4 = (char *)FUN_00401470((undefined4 *)local_60);
      REG::GetPut((REG *)(param_1 + 0x60),s_LastSaveDir_00434384,local_170,pcVar4);
      local_16c = '\0';
      puVar5 = local_16b;
      for (iVar7 = 0x41; iVar7 != 0; iVar7 = iVar7 + -1) {
        *puVar5 = 0;
        puVar5 = puVar5 + 1;
      }
      puVar5 = (undefined4 *)MAP::Name((MAP *)(*(int *)(param_1 + 0x88) + 0xe23c));
      local_5c.FlagsEx._0_1_ = 4;
      pcVar4 = (char *)FUN_00401470(puVar5);
      strcpy(&local_16c,pcVar4);
      local_5c.FlagsEx = CONCAT31(local_5c.FlagsEx._1_3_,3);
      FUN_004014d0(local_1e4);
      ppHVar8 = &local_5c.hwndOwner;
      for (iVar7 = 0x12; iVar7 != 0; iVar7 = iVar7 + -1) {
        *ppHVar8 = (HWND)0x0;
        ppHVar8 = ppHVar8 + 1;
      }
      local_5c.lStructSize = 0x4c;
      local_5c.hwndOwner = *(HWND *)(param_1 + 0x20);
      local_5c.hInstance = GetModuleHandleA((LPCSTR)0x0);
      local_5c.lpstrFile = &local_16c;
      local_5c.nMaxFile = 0x105;
      local_5c.lpstrFilter = s_Map_Files____MAP__00434390;
      local_5c.lpstrInitialDir = (LPCSTR)FUN_00401470((undefined4 *)local_170);
      local_5c.lpstrTitle = s_Save_Level_Map_File_004343ac;
      local_5c.lpstrDefExt = &DAT_004343c0;
      ShowMouse(true);
      BVar9 = 0;
      pHVar6 = GKERNEL::GetHwnd();
      EnableWindow(pHVar6,BVar9);
      local_64 = GetSaveFileNameA(&local_5c);
      BVar9 = 1;
      pHVar6 = GKERNEL::GetHwnd();
      EnableWindow(pHVar6,BVar9);
      if (local_64 != 0) {
        FUN_004056a0(local_178,&local_16c);
        local_5c.FlagsEx._0_1_ = 5;
        pcVar4 = (char *)FUN_00401470((undefined4 *)local_178);
        bVar2 = exists(pcVar4);
        if (bVar2) {
          FUN_00409fb0(local_1dc,param_1);
          local_5c.FlagsEx._0_1_ = 6;
          CString::operator=(local_17c,s_File_already_exists__Replace__004343c4);
          iVar7 = TwDirectXDialog::DoModal(local_1dc);
          if (iVar7 == 0) {
            CWnd::SetFocus(unaff_EDI);
            local_5c.FlagsEx._0_1_ = 5;
            FUN_004048f0((CDialog *)local_1dc);
            local_5c.FlagsEx._0_1_ = 3;
            FUN_004014d0(local_178);
            local_5c.FlagsEx._0_1_ = 1;
            CString::~CString(local_170);
            local_5c.FlagsEx = (uint)local_5c.FlagsEx._1_3_ << 8;
            CString::~CString(local_60);
            local_5c.FlagsEx = 0xffffffff;
            FUN_00401750((undefined4 *)local_174);
            ExceptionList = local_5c.pvReserved;
            return;
          }
          local_5c.FlagsEx._0_1_ = 5;
          FUN_004048f0((CDialog *)local_1dc);
        }
        pcVar4 = (char *)FUN_00401470((undefined4 *)local_178);
        bVar2 = MAP::SaveAs((MAP *)(*(int *)(param_1 + 0x88) + 0xe23c),pcVar4);
        if (!bVar2) {
          FUN_004019e5(param_1,s_Save_file_failed__004343e4);
          CWnd::SetFocus(unaff_EDI);
          local_5c.FlagsEx._0_1_ = 3;
          FUN_004014d0(local_178);
          local_5c.FlagsEx._0_1_ = 1;
          CString::~CString(local_170);
          local_5c.FlagsEx = (uint)local_5c.FlagsEx._1_3_ << 8;
          CString::~CString(local_60);
          local_5c.FlagsEx = 0xffffffff;
          FUN_00401750((undefined4 *)local_174);
          ExceptionList = local_5c.pvReserved;
          return;
        }
        STRING::strtok((char *)local_1e8,(char *)&_Delim_004343f8);
        FUN_004014d0(local_1e8);
        pcVar4 = (char *)FUN_00401470((undefined4 *)local_178);
        REG::Put((REG *)(param_1 + 0x60),s_LastSaveDir_004343fc,pcVar4);
        local_5c.FlagsEx = CONCAT31(local_5c.FlagsEx._1_3_,3);
        FUN_004014d0(local_178);
      }
      CWnd::SetFocus(unaff_EDI);
      local_5c.FlagsEx._0_1_ = 1;
      CString::~CString(local_170);
      local_5c.FlagsEx = (uint)local_5c.FlagsEx._1_3_ << 8;
      CString::~CString(local_60);
      local_5c.FlagsEx = 0xffffffff;
      FUN_00401750((undefined4 *)local_174);
    }
  }
  else {
    FUN_004019e5(param_1,s_Action_disabled_in_demo_mode_00434314);
  }
  ExceptionList = local_5c.pvReserved;
  return;
}



void __fastcall FUN_004033d5(int param_1)

{
  int iVar1;
  
  FUN_00401b53(param_1);
  MAP::Clear((MAP *)(*(int *)(param_1 + 0x88) + 0xe23c));
  iVar1 = FUN_004056c0(*(int *)(param_1 + 0x88));
  FUN_004132e0(*(void **)(param_1 + 0x88),iVar1);
  FUN_0040f3a1();
  if (*(char *)(*(int *)(param_1 + 0x88) + 0x1281c) != '\0') {
    CString::CString((CString *)&stack0xffffffec,s_Copyright__C__2001_TwilightGames_00434408);
    MAP::SetCopyrightString((MAP *)(*(int *)(param_1 + 0x88) + 0xe23c));
  }
  return;
}



void __fastcall FUN_00403467(void *param_1)

{
  char cVar1;
  CString *pCVar2;
  int *piVar3;
  int local_2c;
  undefined4 local_1c [2];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00428502;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pCVar2 = (CString *)MAP::Data((MAP *)(*(int *)((int)param_1 + 0x88) + 0xe23c));
  local_8 = 0;
  CString::operator=((CString *)((int)param_1 + 0x78),pCVar2);
  local_8 = 0xffffffff;
  FUN_004014d0(local_14);
  cVar1 = FUN_0040f42e();
  if (cVar1 == '\0') {
    piVar3 = FUN_00405910((void *)(*(int *)((int)param_1 + 0x88) + 0xe23c),local_1c);
    local_2c = FUN_004058f0(piVar3);
  }
  else {
    local_2c = -1;
  }
  *(int *)((int)param_1 + 0x74) = local_2c;
  FUN_00401a5b(param_1,0x405,1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00403534(void *param_1)

{
  undefined1 uVar1;
  bool bVar2;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  int iVar3;
  
  uVar1 = FUN_00414141(*(int *)((int)param_1 + 0x88));
  if (CONCAT31(extraout_var,uVar1) == 0) {
    bVar2 = FUN_00401430((int *)((int)param_1 + 0x78));
    if (CONCAT31(extraout_var_00,bVar2) == 0) {
      FUN_00401b53((int)param_1);
      MAP::Set((MAP *)(*(int *)((int)param_1 + 0x88) + 0xe23c),(CString *)((int)param_1 + 0x78));
      iVar3 = FUN_004056c0(*(int *)((int)param_1 + 0x88));
      FUN_004132e0(*(void **)((int)param_1 + 0x88),iVar3);
      FUN_0040f3a1();
    }
  }
  else {
    FUN_004019e5(param_1,s_Action_disabled_in_demo_mode_00434440);
  }
  return;
}



void __fastcall FUN_004035c0(CWnd *param_1)

{
  undefined1 uVar1;
  char cVar2;
  bool bVar3;
  undefined3 extraout_var;
  int *piVar4;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  CString *hWnd;
  int iVar5;
  HWND in_stack_fffffb14;
  undefined4 local_4e0 [2];
  undefined1 *local_4d8;
  CString local_4d4 [4];
  undefined4 local_4d0 [2];
  undefined4 local_4c8 [2];
  TwDirectXDialog local_4c0 [96];
  CString local_460 [4];
  int local_45c;
  MAP local_458 [1088];
  char local_18;
  char local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00428531;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  uVar1 = FUN_00414141(*(int *)(param_1 + 0x88));
  if (CONCAT31(extraout_var,uVar1) == 0) {
    if (*(int *)(param_1 + 0x74) == -1) {
      MessageBeep(0);
    }
    else {
      cVar2 = FUN_0040f42e();
      if (cVar2 != '\0') {
        FUN_00409fb0(local_4c0,param_1);
        local_8 = 0;
        CString::operator=(local_460,s_Swap_and_lose_changes__00434480);
        local_45c = TwDirectXDialog::DoModal(local_4c0);
        CWnd::SetFocus(in_stack_fffffb14);
        if (local_45c == 2) {
          local_8 = 0xffffffff;
          FUN_004048f0((CDialog *)local_4c0);
          ExceptionList = local_10;
          return;
        }
        FUN_00405910((void *)(*(int *)(param_1 + 0x88) + 0xe23c),local_4c8);
        MAP::Load((MAP *)(*(int *)(param_1 + 0x88) + 0xe23c));
        local_8 = 0xffffffff;
        FUN_004048f0((CDialog *)local_4c0);
      }
      piVar4 = FUN_00405910((void *)(*(int *)(param_1 + 0x88) + 0xe23c),local_4d0);
      FUN_004058f0(piVar4);
      bVar3 = FUN_00411392(*(void **)(param_1 + 0x88));
      local_18 = CONCAT31(extraout_var_00,bVar3) != 0;
      bVar3 = FUN_00411392(*(void **)(param_1 + 0x88));
      local_14 = CONCAT31(extraout_var_01,bVar3) != 0;
      MAP::MAP(local_458);
      local_8 = 1;
      hWnd = (CString *)MAP::Data((MAP *)(*(int *)(param_1 + 0x88) + 0xe23c));
      local_8._0_1_ = 2;
      MAP::Set(local_458,hWnd);
      local_8 = CONCAT31(local_8._1_3_,1);
      FUN_004014d0(local_4d4);
      FUN_00403534(param_1);
      local_4d8 = &stack0xfffffb0c;
      FUN_004058b0(&stack0xfffffb0c,*(uint *)(param_1 + 0x74));
      MAP::Save(local_458);
      FUN_00402981(param_1);
      FUN_00401a5b(param_1,0x406,0);
      cVar2 = local_14;
      piVar4 = FUN_00405910((void *)(*(int *)(param_1 + 0x88) + 0xe23c),local_4e0);
      iVar5 = FUN_004058f0(piVar4);
      FUN_00411531(*(void **)(param_1 + 0x88),iVar5,cVar2);
      FUN_00411531(*(void **)(param_1 + 0x88),*(undefined4 *)(param_1 + 0x74),local_18);
      *(undefined4 *)(param_1 + 0x74) = 0xffffffff;
      CWnd::SetFocus((HWND)hWnd);
      local_8 = 0xffffffff;
      MAP::~MAP(local_458);
    }
  }
  else {
    FUN_004019e5(param_1,s_Action_disabled_in_demo_mode_00434460);
  }
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_004038a9(int param_1)

{
  undefined4 *puVar1;
  undefined1 local_10 [8];
  ITEM *local_8;
  
  FUN_00401b53(param_1);
  FUN_0040f3a1();
  puVar1 = (undefined4 *)FUN_00405800((void *)(*(int *)(param_1 + 0x88) + 0xe01c),local_10,0x20);
  local_8 = MAP::GetItem((MAP *)(*(int *)(param_1 + 0x88) + 0xe23c),*puVar1);
  FUN_00405890(&stack0xffffffe4,4);
  (**(code **)(*(int *)local_8 + 0x2c))();
  FUN_0040f6ea(*(void **)(param_1 + 0x88),(undefined4 *)(*(int *)(param_1 + 0x88) + 0xe01c));
  return;
}



void __fastcall FUN_00403938(int param_1)

{
  undefined4 *puVar1;
  undefined1 local_10 [8];
  ITEM *local_8;
  
  FUN_00401b53(param_1);
  FUN_0040f3a1();
  puVar1 = (undefined4 *)FUN_00405800((void *)(*(int *)(param_1 + 0x88) + 0xe01c),local_10,0x20);
  local_8 = MAP::GetItem((MAP *)(*(int *)(param_1 + 0x88) + 0xe23c),*puVar1);
  FUN_00405890(&stack0xffffffe4,2);
  (**(code **)(*(int *)local_8 + 0x2c))();
  FUN_0040f6ea(*(void **)(param_1 + 0x88),(undefined4 *)(*(int *)(param_1 + 0x88) + 0xe01c));
  return;
}



void __fastcall FUN_004039c7(int param_1)

{
  undefined4 *puVar1;
  undefined1 local_10 [8];
  ITEM *local_8;
  
  FUN_00401b53(param_1);
  FUN_0040f3a1();
  puVar1 = (undefined4 *)FUN_00405800((void *)(*(int *)(param_1 + 0x88) + 0xe01c),local_10,0x20);
  local_8 = MAP::GetItem((MAP *)(*(int *)(param_1 + 0x88) + 0xe23c),*puVar1);
  FUN_00405890(&stack0xffffffe4,1);
  (**(code **)(*(int *)local_8 + 0x2c))();
  FUN_0040f6ea(*(void **)(param_1 + 0x88),(undefined4 *)(*(int *)(param_1 + 0x88) + 0xe01c));
  return;
}



void __fastcall FUN_00403a56(int param_1)

{
  undefined4 *puVar1;
  int iVar2;
  undefined1 local_10 [8];
  ITEM *local_8;
  
  FUN_00401b53(param_1);
  FUN_0040f3a1();
  puVar1 = (undefined4 *)FUN_00405800((void *)(*(int *)(param_1 + 0x88) + 0xe01c),local_10,0x20);
  local_8 = MAP::GetItem((MAP *)(*(int *)(param_1 + 0x88) + 0xe23c),*puVar1,puVar1[1]);
  iVar2 = (**(code **)(*(int *)local_8 + 0x34))();
  (**(code **)(*(int *)local_8 + 0x3c))(iVar2 == 0);
  FUN_0040f6ea(*(void **)(param_1 + 0x88),(undefined4 *)(*(int *)(param_1 + 0x88) + 0xe01c));
  return;
}



void __fastcall FUN_00403aec(int param_1)

{
  undefined4 *puVar1;
  int iVar2;
  undefined1 local_10 [8];
  ITEM *local_8;
  
  FUN_00401b53(param_1);
  FUN_0040f3a1();
  puVar1 = (undefined4 *)FUN_00405800((void *)(*(int *)(param_1 + 0x88) + 0xe01c),local_10,0x20);
  local_8 = MAP::GetItem((MAP *)(*(int *)(param_1 + 0x88) + 0xe23c),*puVar1,puVar1[1]);
  iVar2 = (**(code **)(*(int *)local_8 + 0x38))();
  (**(code **)(*(int *)local_8 + 0x40))(iVar2 == 0);
  FUN_0040f6ea(*(void **)(param_1 + 0x88),(undefined4 *)(*(int *)(param_1 + 0x88) + 0xe01c));
  return;
}



void __fastcall FUN_00403b82(int param_1)

{
  HWND__ *hWnd;
  UINT Msg;
  WPARAM wParam;
  LPARAM lParam;
  
  FUN_0040fade(*(int *)(param_1 + 0x88));
  lParam = 0;
  wParam = 0;
  Msg = 0x401;
  hWnd = GKERNEL::GetHwnd();
  PostMessageA(hWnd,Msg,wParam,lParam);
  return;
}



void __fastcall FUN_00403bb1(int param_1)

{
  bool bVar1;
  undefined1 uVar2;
  int *piVar3;
  undefined3 extraout_var;
  int iVar4;
  undefined4 local_18 [2];
  uint local_10;
  int local_c;
  uint local_8;
  
  piVar3 = FUN_00405910((void *)(*(int *)(param_1 + 0x88) + 0xe23c),local_18);
  local_c = FUN_004058f0(piVar3);
  bVar1 = FUN_00411392(*(void **)(param_1 + 0x88));
  local_10 = CONCAT31(local_10._1_3_,CONCAT31(extraout_var,bVar1) != 0);
  uVar2 = FUN_0040f42e();
  local_8 = CONCAT31(local_8._1_3_,uVar2);
  FUN_00411531(*(void **)(param_1 + 0x88),local_c,(local_10 & 0xff) == 0);
  iVar4 = FUN_004056c0(*(int *)(param_1 + 0x88));
  FUN_004132e0(*(void **)(param_1 + 0x88),iVar4);
  if ((local_8 & 0xff) != 0) {
    FUN_0040f3a1();
  }
  return;
}



void __fastcall FUN_00403c65(int param_1)

{
  LRESULT LVar1;
  undefined4 uVar2;
  ITEM *pIVar3;
  LPARAM in_stack_ffffffe4;
  
  CWnd::SendDlgItemMessageA((HWND)&hDlg_0000040f,0xf1,0,0,in_stack_ffffffe4);
  CWnd::SendDlgItemMessageA((HWND)&hDlg_0000040e,0xf1,0,0,in_stack_ffffffe4);
  LVar1 = CWnd::SendDlgItemMessageA((HWND)&hDlg_00000410,0xf0,0,0,in_stack_ffffffe4);
  if (*(undefined4 **)(param_1 + 0x84) == (undefined4 *)0x0) {
    uVar2 = 0;
  }
  else {
    uVar2 = (**(code **)**(undefined4 **)(param_1 + 0x84))(1);
  }
  *(undefined4 *)(param_1 + 0x84) = 0;
  if (LVar1 == 1) {
    pIVar3 = MAP::FindItem(s_BLANK_00434498);
    uVar2 = (**(code **)(*(int *)pIVar3 + 4))(pIVar3,uVar2);
    *(undefined4 *)(param_1 + 0x84) = uVar2;
    FUN_00414038(*(void **)(param_1 + 0x88),0xd0,(int *)0x0);
  }
  return;
}



void __fastcall FUN_00403d43(void *param_1)

{
  char cVar1;
  bool bVar2;
  LRESULT LVar3;
  CString *pCVar4;
  undefined3 extraout_var;
  char *pcVar5;
  ITEM *pIVar6;
  undefined4 uVar7;
  int iVar8;
  int *piVar9;
  LPARAM in_stack_ffffffbc;
  CString local_28 [4];
  undefined4 *local_24;
  undefined4 *local_20;
  CString local_1c [4];
  int local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042854d;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  LVar3 = CWnd::SendDlgItemMessageA((HWND)&hDlg_0000040e,0xf0,0,0,in_stack_ffffffbc);
  cVar1 = '\x01' - (LVar3 != 1);
  local_14 = CONCAT31(local_14._1_3_,cVar1);
  if (cVar1 != '\0') {
    pCVar4 = FUN_0040257d(param_1,local_1c);
    local_8 = 0;
    bVar2 = FUN_00401430((int *)pCVar4);
    local_18 = CONCAT31(extraout_var,bVar2);
    local_8 = 0xffffffff;
    CString::~CString(local_1c);
    if (local_18 != 0) {
      FUN_004019e5(param_1,s_No_item_selected__004344a0);
      CWnd::SendDlgItemMessageA((HWND)&hDlg_0000040e,0xf1,0,0,in_stack_ffffffbc);
      ExceptionList = local_10;
      return;
    }
  }
  CWnd::SendDlgItemMessageA((HWND)&hDlg_0000040f,0xf1,0,0,in_stack_ffffffbc);
  CWnd::SendDlgItemMessageA((HWND)&hDlg_00000410,0xf1,0,0,in_stack_ffffffbc);
  local_24 = *(undefined4 **)((int)param_1 + 0x84);
  local_20 = local_24;
  if (local_24 != (undefined4 *)0x0) {
    (**(code **)*local_24)(1);
  }
  *(undefined4 *)((int)param_1 + 0x84) = 0;
  if ((local_14 & 0xff) != 0) {
    pCVar4 = FUN_0040257d(param_1,local_28);
    local_8 = 1;
    pcVar5 = (char *)FUN_00401470((undefined4 *)pCVar4);
    pIVar6 = MAP::FindItem(pcVar5);
    uVar7 = (**(code **)(*(int *)pIVar6 + 4))();
    *(undefined4 *)((int)param_1 + 0x84) = uVar7;
    local_8 = 0xffffffff;
    CString::~CString(local_28);
    piVar9 = (int *)0x7;
    iVar8 = (**(code **)(**(int **)((int)param_1 + 0x84) + 0x6c))
                      (7,0,0,*(undefined4 *)((int)param_1 + 0x84));
    FUN_00414038(*(void **)((int)param_1 + 0x88),iVar8,piVar9);
  }
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00403f04(void *param_1)

{
  char cVar1;
  bool bVar2;
  undefined4 *puVar3;
  LRESULT LVar4;
  void *pvVar5;
  undefined4 uVar6;
  int iVar7;
  char *pcVar8;
  int *piVar9;
  LPARAM in_stack_ffffffc0;
  CString local_28 [4];
  uint local_24;
  undefined1 local_20 [8];
  uint local_18;
  ITEM *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &lParam_00428560;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  puVar3 = (undefined4 *)
           FUN_00405800((void *)(*(int *)((int)param_1 + 0x88) + 0xe01c),local_20,0x20);
  local_14 = MAP::GetItem((MAP *)(*(int *)((int)param_1 + 0x88) + 0xe23c),*puVar3,puVar3[1]);
  LVar4 = CWnd::SendDlgItemMessageA((HWND)&hDlg_0000040f,0xf0,0,0,in_stack_ffffffc0);
  cVar1 = '\x01' - (LVar4 != 1);
  local_18 = CONCAT31(local_18._1_3_,cVar1);
  if (cVar1 != '\0') {
    pcVar8 = s_BLANK_004344b4;
    pvVar5 = (void *)(**(code **)(*(int *)local_14 + 0x60))(local_28);
    local_8 = 0;
    bVar2 = FUN_00404990(pvVar5,pcVar8);
    local_24 = CONCAT31(local_24._1_3_,bVar2);
    local_8 = 0xffffffff;
    CString::~CString(local_28);
    if ((local_24 & 0xff) != 0) {
      FUN_004019e5(param_1,s_Cannot_clone_a_blank_square__Use_004344bc);
      CWnd::SendDlgItemMessageA((HWND)&hDlg_0000040f,0xf1,0,0,in_stack_ffffffc0);
      ExceptionList = local_10;
      return;
    }
  }
  CWnd::SendDlgItemMessageA((HWND)&hDlg_0000040e,0xf1,0,0,in_stack_ffffffc0);
  CWnd::SendDlgItemMessageA((HWND)&hDlg_00000410,0xf1,0,0,in_stack_ffffffc0);
  if (*(undefined4 **)((int)param_1 + 0x84) == (undefined4 *)0x0) {
    uVar6 = 0;
  }
  else {
    uVar6 = (**(code **)**(undefined4 **)((int)param_1 + 0x84))(1);
  }
  *(undefined4 *)((int)param_1 + 0x84) = 0;
  if ((local_18 & 0xff) != 0) {
    uVar6 = (**(code **)(*(int *)local_14 + 4))(uVar6);
    *(undefined4 *)((int)param_1 + 0x84) = uVar6;
    piVar9 = *(int **)((int)param_1 + 0x84);
    iVar7 = (**(code **)(**(int **)((int)param_1 + 0x84) + 0x70))();
    FUN_00414038(*(void **)((int)param_1 + 0x88),iVar7,piVar9);
  }
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_004040c5(int param_1)

{
  HWND hWnd;
  
  if (*(undefined4 **)(param_1 + 0x84) == (undefined4 *)0x0) {
    hWnd = (HWND)0x0;
  }
  else {
    hWnd = (HWND)(**(code **)**(undefined4 **)(param_1 + 0x84))(1);
  }
  *(undefined4 *)(param_1 + 0x84) = 0;
  CWnd::SendDlgItemMessageA((HWND)&hDlg_0000040e,0xf1,0,0,(LPARAM)hWnd);
  CWnd::SendDlgItemMessageA((HWND)&hDlg_00000410,0xf1,0,0,(LPARAM)hWnd);
  CWnd::SendDlgItemMessageA((HWND)&hDlg_0000040f,0xf1,0,0,(LPARAM)hWnd);
  FUN_00414038(*(void **)(param_1 + 0x88),0xcc,(int *)0x0);
  CWnd::SetFocus(hWnd);
  return;
}



void __fastcall FUN_0040416e(int param_1)

{
  int iVar1;
  HWND in_stack_ffffff78;
  TwDirectXDialog local_7c [96];
  CString local_1c [4];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_00428573;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00408e60(local_7c,(CWnd *)0x0);
  local_8 = 0;
  CString::operator=(local_14,s_Enter_copyright_string__004344e8);
  CString::operator=(local_1c,s_Copyright_String_00434500);
  iVar1 = TwDirectXDialog::DoModal(local_7c);
  if (iVar1 == 1) {
    in_stack_ffffff78 = (HWND)CString::CString((CString *)&stack0xffffff74,local_18);
    MAP::SetCopyrightString((MAP *)(*(int *)(param_1 + 0x88) + 0xe23c));
    FUN_00401b53(param_1);
    FUN_0040f3a1();
  }
  CWnd::SetFocus(in_stack_ffffff78);
  local_8 = 0xffffffff;
  FUN_00404860((CDialog *)local_7c);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_0040422a(CWnd *param_1)

{
  bool bVar1;
  CString *pCVar2;
  int iVar3;
  undefined3 extraout_var;
  char *pcVar4;
  HWND__ *hWnd;
  CString local_100 [4];
  CString local_fc [4];
  undefined1 *local_f8;
  CString local_f4 [4];
  CString local_f0 [4];
  TwDirectXDialog local_ec [96];
  CString local_8c [4];
  int local_88;
  CString local_84 [4];
  TwDirectXDialog local_80 [96];
  CString local_20 [4];
  HWND__ local_1c;
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004285d4;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00408e60(local_80,(CWnd *)0x0);
  local_8 = 0;
  FUN_00405660(local_14);
  local_8._0_1_ = 1;
  MAP::GetScript((MAP *)(*(int *)(param_1 + 0x88) + 0xe23c),local_14);
  FUN_00401470((undefined4 *)local_14);
  pCVar2 = (CString *)ExtractFileName((char *)local_f4);
  local_8._0_1_ = 2;
  FUN_00405680(local_f0,pCVar2);
  local_8._0_1_ = 3;
  FUN_004048d0(local_14,local_f0);
  local_8._0_1_ = 2;
  FUN_004014d0(local_f0);
  local_8._0_1_ = 1;
  CString::~CString(local_f4);
  FUN_004048d0(&local_1c,local_14);
  CString::operator=(local_18,s_Enter_Tutorial_script_file_name__00434514);
  hWnd = (HWND)0x40431f;
  CString::operator=(local_20,s_Tutorial_Script_00434538);
  iVar3 = TwDirectXDialog::DoModal(local_80);
  if (iVar3 == 1) {
    FUN_00401b53((int)param_1);
    local_f8 = &stack0xfffffedc;
    CString::CString((CString *)&stack0xfffffedc,(CString *)&local_1c);
    hWnd = (HWND)0x40436c;
    MAP::SetScript((MAP *)(*(int *)(param_1 + 0x88) + 0xe23c));
    FUN_00405660(local_84);
    local_8._0_1_ = 4;
    bVar1 = FUN_00401430(&local_1c.unused);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      hWnd = (HWND)0x4043a4;
      iVar3 = MAP::GetScript((MAP *)(*(int *)(param_1 + 0x88) + 0xe23c),local_84);
      if (iVar3 == 0) {
        FUN_00409fb0(local_ec,param_1);
        local_8._0_1_ = 5;
        CString::MakeUpper((CString *)&local_1c);
        hWnd = &local_1c;
        pcVar4 = (char *)operator+((char *)local_fc,(CString *)s_File____0043456c);
        local_8._0_1_ = 6;
        pCVar2 = (CString *)operator+(local_100,pcVar4);
        local_8._0_1_ = 7;
        CString::operator=(local_8c,pCVar2);
        local_8._0_1_ = 6;
        CString::~CString(local_100);
        local_8._0_1_ = 5;
        CString::~CString(local_fc);
        local_88 = TwDirectXDialog::DoModal(local_ec);
        CWnd::SetFocus(hWnd);
        if (local_88 == 2) {
          FUN_004272f7(*(void **)(param_1 + 0x88));
          local_8._0_1_ = 4;
          FUN_004048f0((CDialog *)local_ec);
          local_8._0_1_ = 1;
          FUN_004014d0(local_84);
          local_8 = (uint)local_8._1_3_ << 8;
          FUN_004014d0(local_14);
          local_8 = 0xffffffff;
          FUN_00404860((CDialog *)local_80);
          ExceptionList = local_10;
          return;
        }
        local_8._0_1_ = 4;
        FUN_004048f0((CDialog *)local_ec);
      }
    }
    FUN_0040f3a1();
    local_8._0_1_ = 1;
    FUN_004014d0(local_84);
  }
  CWnd::SetFocus(hWnd);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_004014d0(local_14);
  local_8 = 0xffffffff;
  FUN_00404860((CDialog *)local_80);
  ExceptionList = local_10;
  return;
}



void FUN_00404522(void)

{
  CString *pCVar1;
  int *piVar2;
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004285f0;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pCVar1 = FUN_004014f0(local_14);
  local_8 = 0;
  piVar2 = (int *)operator+(local_18,(char *)pCVar1);
  local_8._0_1_ = 1;
  FUN_0040a219(piVar2);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(local_18);
  local_8 = 0xffffffff;
  CString::~CString(local_14);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_004045c0(void *this,uint param_1)

{
  FUN_004045f0((CDialog *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_004045f0(CDialog *param_1)

{
  CDialog *local_18;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &this_00428655;
  local_10 = ExceptionList;
  local_8 = 4;
  ExceptionList = &local_10;
  CListCtrl::~CListCtrl((CListCtrl *)(param_1 + 0x8c));
  local_8._0_1_ = 3;
  CString::~CString((CString *)(param_1 + 0x7c));
  local_8._0_1_ = 2;
  CString::~CString((CString *)(param_1 + 0x78));
  local_8._0_1_ = 1;
  CImageList::~CImageList((CImageList *)(param_1 + 100));
  local_8 = (uint)local_8._1_3_ << 8;
  if (param_1 == (CDialog *)0x0) {
    local_18 = (CDialog *)0x0;
  }
  else {
    local_18 = param_1 + 0x60;
  }
  FUN_00401750((undefined4 *)local_18);
  local_8 = 0xffffffff;
  FUN_004017d0(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_004046a0(CDialog *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00428669;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  CString::~CString((CString *)(param_1 + 0x60));
  local_8 = 0xffffffff;
  FUN_004017d0(param_1);
  ExceptionList = local_10;
  return;
}



void * __fastcall FUN_004046f0(void *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_0042868c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00405850(param_1);
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)((int)param_1 + 0xc));
  local_8 = 0;
  CString::CString((CString *)((int)param_1 + 0x28));
  ExceptionList = local_10;
  return param_1;
}



void __fastcall FUN_00404750(int param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004286ac;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  CString::~CString((CString *)(param_1 + 0x28));
  local_8 = 0xffffffff;
  FUN_00404820((undefined4 *)(param_1 + 0xc));
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_004047a0(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004286cc;
  local_10 = ExceptionList;
  uVar1 = param_1[1];
  ExceptionList = &local_10;
  *(undefined4 *)this = *param_1;
  *(undefined4 *)((int)this + 4) = uVar1;
  *(undefined4 *)((int)this + 8) = param_1[2];
  FUN_00404a00((void *)((int)this + 0xc),(int)(param_1 + 3));
  local_8 = 0;
  CString::CString((CString *)((int)this + 0x28),(CString *)(param_1 + 10));
  ExceptionList = local_10;
  return this;
}



void __fastcall FUN_00404820(undefined4 *param_1)

{
  FUN_00404db0(param_1);
  return;
}



void __fastcall FUN_00404840(undefined4 *param_1)

{
  FUN_00404bf0(param_1);
  return;
}



void __fastcall FUN_00404860(CDialog *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &this_00428701;
  local_10 = ExceptionList;
  local_8 = 2;
  ExceptionList = &local_10;
  CString::~CString((CString *)(param_1 + 0x68));
  local_8._0_1_ = 1;
  FUN_004014d0((CString *)(param_1 + 100));
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString((CString *)(param_1 + 0x60));
  local_8 = 0xffffffff;
  FUN_004017d0(param_1);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_004048d0(void *this,CString *param_1)

{
  CString::operator=((CString *)this,param_1);
  return this;
}



void __fastcall FUN_004048f0(CDialog *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00428719;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  CString::~CString((CString *)(param_1 + 0x60));
  local_8 = 0xffffffff;
  FUN_004017d0(param_1);
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
  FUN_00404ac0(this,10);
  *(undefined ***)this = &PTR_LAB_0042ccb8;
  return this;
}



void * __thiscall FUN_00404970(void *this,undefined4 *param_1)

{
  FUN_00404b90(this,param_1);
  return this;
}



bool FUN_00404990(void *param_1,char *param_2)

{
  int iVar1;
  
  iVar1 = FUN_004049b0(param_1,param_2);
  return (bool)('\x01' - (iVar1 != 0));
}



void __thiscall FUN_004049b0(void *this,char *param_1)

{
                    // WARNING: Load size is inaccurate
  strcmp(*this,param_1);
  return;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_00404d10(this,10);
  *(undefined ***)this = &PTR_LAB_0042cccc;
  return this;
}



void * __thiscall FUN_00404a00(void *this,int param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00428739;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00404d10(this,10);
  local_8 = 0;
  *(undefined ***)this = &PTR_LAB_0042cccc;
  FUN_00404d70(this,param_1);
  ExceptionList = local_10;
  return this;
}



void * __thiscall FUN_00404a60(void *this,uint param_1)

{
  FUN_00404840((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void * __thiscall FUN_00404a90(void *this,uint param_1)

{
  FUN_00404820((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void * __thiscall FUN_00404ac0(void *this,undefined4 param_1)

{
  FUN_00404b20((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_0042cce0;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



undefined4 * __fastcall FUN_00404b20(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_0042ccf4;
  return param_1;
}



void * __thiscall FUN_00404b40(void *this,uint param_1)

{
  FUN_00404b70((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_00404b70(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_0042ccf4;
  return;
}



undefined4 * __thiscall FUN_00404b90(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_00405000(this,*(undefined4 *)((int)this + 8),0);
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



void __fastcall FUN_00404bf0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00428759;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_0042cce0;
  local_8 = 0;
  FUN_00404f80((int)param_1);
  local_8 = 0xffffffff;
  FUN_00404b70(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_00404c50(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_10;
  ulong local_c;
  undefined4 *local_8;
  
  FUN_00401400();
  bVar1 = FUN_00404cf0((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      FUN_00408820(param_1,&local_10,1);
      FUN_00404b90(this,&local_10);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_00408820(param_1,local_8 + 2,1);
    }
  }
  return;
}



bool __fastcall FUN_00404cf0(int param_1)

{
  return (bool)('\x01' - ((*(uint *)(param_1 + 0x14) & 1) != 0));
}



void * __thiscall FUN_00404d10(void *this,undefined4 param_1)

{
  FUN_00404b20((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_0042cd08;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



void __thiscall FUN_00404d70(void *this,int param_1)

{
  undefined4 *puVar1;
  int local_8;
  
  local_8 = FUN_00423770(param_1);
  while (local_8 != 0) {
    puVar1 = (undefined4 *)FUN_0041be90(&local_8);
    FUN_004050e0(this,puVar1);
  }
  return;
}



void __fastcall FUN_00404db0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00428779;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_0042cd08;
  local_8 = 0;
  FUN_00405150((int)param_1);
  local_8 = 0xffffffff;
  FUN_00404b70(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_00404e10(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_1c [4];
  ulong local_c;
  undefined4 *local_8;
  
  FUN_00401400();
  bVar1 = FUN_00404cf0((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      FUN_00405960(local_1c);
      FUN_004051d0(param_1,local_1c,1);
      FUN_004050e0(this,local_1c);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_004051d0(param_1,local_8 + 2,1);
    }
  }
  return;
}



void * __thiscall FUN_00404ec0(void *this,uint param_1)

{
  FUN_00404bf0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void * __thiscall FUN_00404ef0(void *this,uint param_1)

{
  FUN_00404db0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



undefined4 __fastcall FUN_00404f20(undefined4 param_1)

{
  return param_1;
}



int __fastcall FUN_00404f30(int *param_1)

{
  return param_1[2] - *param_1;
}



int __fastcall FUN_00404f50(int param_1)

{
  return *(int *)(param_1 + 0xc) - *(int *)(param_1 + 4);
}



undefined4 __fastcall FUN_00404f70(undefined4 param_1)

{
  return param_1;
}



void __fastcall FUN_00404f80(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_00405210(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



undefined4 * __thiscall FUN_00405000(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0xc);
    iVar3 = FUN_00428190((int)pCVar2);
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
  FUN_0041bfb0(puVar1 + 2,1);
  return puVar1;
}



undefined4 * __thiscall FUN_004050e0(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_00405240(this,*(undefined4 *)((int)this + 8),0);
  puVar1[2] = *param_1;
  puVar1[3] = param_1[1];
  puVar1[4] = param_1[2];
  puVar1[5] = param_1[3];
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



void __fastcall FUN_00405150(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_00405320(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



void FUN_004051d0(CArchive *param_1,void *param_2,int param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_00404cf0((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    CArchive::Read(param_1,param_2,param_3 << 4);
  }
  else {
    CArchive::Write(param_1,param_2,param_3 << 4);
  }
  return;
}



void FUN_00405210(undefined4 param_1,int param_2)

{
  bool bVar1;
  
  do {
    bVar1 = param_2 != 0;
    param_2 = param_2 + -1;
  } while (bVar1);
  return;
}



undefined4 * __thiscall FUN_00405240(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0x18);
    iVar3 = FUN_00428190((int)pCVar2);
    local_c = (undefined4 *)(iVar3 + (*(int *)((int)this + 0x18) + -1) * 0x18);
    local_10 = *(int *)((int)this + 0x18);
    while (local_10 = local_10 + -1, -1 < local_10) {
      *local_c = *(undefined4 *)((int)this + 0x10);
      *(undefined4 **)((int)this + 0x10) = local_c;
      local_c = local_c + -6;
    }
  }
  puVar1 = *(undefined4 **)((int)this + 0x10);
  *(undefined4 *)((int)this + 0x10) = **(undefined4 **)((int)this + 0x10);
  puVar1[1] = param_1;
  *puVar1 = param_2;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  FUN_00405350(puVar1 + 2,1);
  return puVar1;
}



void FUN_00405320(undefined4 param_1,int param_2)

{
  bool bVar1;
  
  do {
    bVar1 = param_2 != 0;
    param_2 = param_2 + -1;
  } while (bVar1);
  return;
}



void FUN_00405350(void *param_1,int param_2)

{
  void *pvVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004287a1;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  memset(param_1,0,param_2 << 4);
  while (param_2 != 0) {
    pvVar1 = (void *)FUN_00405640(0x10,param_1);
    local_8 = 0;
    if (pvVar1 != (void *)0x0) {
      FUN_00405960(pvVar1);
    }
    local_8 = 0xffffffff;
    param_1 = (void *)((int)param_1 + 0x10);
    param_2 = param_2 + -1;
  }
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_004053f0(void *this,LPRECT param_1)

{
  GetWindowRect(*(HWND *)((int)this + 0x20),param_1);
  return;
}



void __fastcall FUN_00405410(int param_1)

{
  HDC pHVar1;
  
  pHVar1 = GetDC(*(HWND *)(param_1 + 0x20));
  CDC::FromHandle(pHVar1);
  return;
}



CWnd * __fastcall FUN_00405430(CWnd *param_1)

{
  CWnd::CWnd(param_1);
  *(undefined ***)param_1 = &PTR_LAB_0042cd1c;
  return param_1;
}



void * __thiscall FUN_00405450(void *this,uint param_1)

{
  CListCtrl::~CListCtrl((CListCtrl *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __thiscall FUN_00405480(void *this,int param_1,WPARAM param_2)

{
  LPARAM lParam;
  _IMAGELIST *p_Var1;
  
  lParam = FUN_004055b0(param_1);
  p_Var1 = (_IMAGELIST *)SendMessageA(*(HWND *)((int)this + 0x20),0x1003,param_2,lParam);
  CImageList::FromHandle(p_Var1);
  return;
}



void __thiscall FUN_004054c0(void *this,LPARAM param_1)

{
  SendMessageA(*(HWND *)((int)this + 0x20),0x1005,0,param_1);
  return;
}



void __thiscall FUN_004054f0(void *this,LPARAM param_1)

{
  SendMessageA(*(HWND *)((int)this + 0x20),0x1007,0,param_1);
  return;
}



int __fastcall FUN_00405520(void *param_1)

{
  int iVar1;
  
  iVar1 = FUN_00405540(param_1,0xffffffff,2);
  return iVar1 + 1;
}



void __thiscall FUN_00405540(void *this,WPARAM param_1,uint param_2)

{
  SendMessageA(*(HWND *)((int)this + 0x20),0x100c,param_1,param_2 & 0xffff);
  return;
}



WPARAM __thiscall FUN_00405570(void *this,int *param_1)

{
  int iVar1;
  int iVar2;
  
  iVar1 = *param_1;
  iVar2 = FUN_00405540(this,iVar1 - 1U,2);
  *param_1 = iVar2 + 1;
  return iVar1 - 1U;
}



undefined4 __fastcall FUN_004055b0(int param_1)

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



void __thiscall FUN_004055e0(void *this,int param_1,int param_2)

{
  HBITMAP hbmMask;
  HBITMAP hbmImage;
  
  hbmMask = (HBITMAP)FUN_00405610(param_2);
  hbmImage = (HBITMAP)FUN_00405610(param_1);
  ImageList_Add(*(HIMAGELIST *)((int)this + 4),hbmImage,hbmMask);
  return;
}



undefined4 __fastcall FUN_00405610(int param_1)

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



undefined4 __cdecl FUN_00405640(undefined4 param_1,undefined4 param_2)

{
  return param_2;
}



void FUN_00405650(void)

{
  return;
}



CString * __fastcall FUN_00405660(CString *param_1)

{
  CString::CString(param_1);
  return param_1;
}



void * __thiscall FUN_00405680(void *this,CString *param_1)

{
  CString::CString((CString *)this,param_1);
  return this;
}



void * __thiscall FUN_004056a0(void *this,char *param_1)

{
  CString::CString((CString *)this,param_1);
  return this;
}



undefined4 __fastcall FUN_004056c0(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



void * __thiscall FUN_004056e0(void *this,LPCSTR param_1)

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



void __fastcall FUN_004057c0(int *param_1)

{
  if (*param_1 != 0) {
    UnmapViewOfFile((LPCVOID)*param_1);
  }
  return;
}



bool __fastcall FUN_004057e0(int *param_1)

{
  return *param_1 != 0;
}



void * __thiscall FUN_00405800(void *this,void *param_1,int param_2)

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



void * __fastcall FUN_00405850(void *param_1)

{
  FUN_004163a0(param_1,0,0);
  return param_1;
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
  FUN_004163a0(this,param_1,param_2);
  return this;
}



void * __thiscall FUN_00405890(void *this,undefined4 param_1)

{
  *(undefined4 *)this = param_1;
  return this;
}



void * __thiscall FUN_004058b0(void *this,uint param_1)

{
  *(uint *)this = param_1 / 100 + 1;
  *(uint *)((int)this + 4) = param_1 % 100;
  return this;
}



int __fastcall FUN_004058f0(int *param_1)

{
  return (*param_1 + -1) * 100 + param_1[1];
}



undefined4 * __thiscall FUN_00405910(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)((int)this + 0x424);
  *param_1 = *(undefined4 *)((int)this + 0x420);
  param_1[1] = uVar1;
  return param_1;
}



bool __fastcall FUN_00405940(int param_1)

{
  return *(int *)(param_1 + 0x84) != 0;
}



void * __fastcall FUN_00405960(void *param_1)

{
  FUN_00405850(param_1);
  FUN_00405850((void *)((int)param_1 + 8));
  return param_1;
}



void * __thiscall FUN_00405990(void *this,undefined4 param_1)

{
  FUN_004059c0((CGdiObject *)this);
  *(undefined4 *)((int)this + 8) = param_1;
  *(undefined ***)this = &PTR_LAB_0042cde0;
  return this;
}



CGdiObject * __fastcall FUN_004059c0(CGdiObject *param_1)

{
  CGdiObject::CGdiObject(param_1);
  *(undefined ***)param_1 = &PTR_LAB_0042cdf4;
  return param_1;
}



// Library Function - Single Match
//  public: __thiscall CGdiObject::CGdiObject(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CGdiObject * __thiscall CGdiObject::CGdiObject(CGdiObject *this)

{
  FUN_00404b20((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_0042ce08;
  *(undefined4 *)(this + 4) = 0;
  return this;
}



void * __thiscall FUN_00405a10(void *this,uint param_1)

{
  FUN_00405a40((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_00405a40(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004287b9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_0042ce08;
  local_8 = 0;
  CGdiObject::DeleteObject(param_1);
  local_8 = 0xffffffff;
  FUN_00404b70(param_1);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_00405aa0(void *this,uint param_1)

{
  FUN_00405ad0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_00405ad0(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_0042cdf4;
  FUN_00405a40(param_1);
  return;
}



void * __thiscall FUN_00405af0(void *this,uint param_1)

{
  FUN_00405b20((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_00405b20(undefined4 *param_1)

{
  FUN_00405ad0(param_1);
  return;
}



void * __thiscall FUN_00405b40(void *this,CWnd *param_1)

{
  FUN_00401770(this,0x8d,param_1);
  *(undefined ***)this = &PTR_LAB_0042ce40;
  return this;
}



// Library Function - Single Match
//  protected: virtual void __thiscall CFindReplaceDialog::DoDataExchange(class CDataExchange *)
// 
// Library: Visual Studio 2008 Debug

void __thiscall CFindReplaceDialog::DoDataExchange(CFindReplaceDialog *this,CDataExchange *param_1)

{
  FUN_00401480();
  return;
}



undefined * FUN_00405b83(void)

{
  return messageMap_exref;
}



undefined ** FUN_00405b8d(void)

{
  return &PTR_FUN_0042ce20;
}



void * __thiscall FUN_00405ba0(void *this,uint param_1)

{
  FUN_00405bd0((CDialog *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_00405bd0(CDialog *param_1)

{
  FUN_004017d0(param_1);
  return;
}



void * __thiscall FUN_00405bf0(void *this,undefined4 param_1,CWnd *param_2)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &param_1_004287ee;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  FUN_00401770(this,0x88,param_2);
  local_8._0_1_ = 1;
  CString::CString((CString *)((int)this + 0x60));
  local_8 = CONCAT31(local_8._1_3_,2);
  *(undefined ***)this = &PTR_LAB_0042cf38;
  CString::operator=((CString *)((int)this + 0x60),(CString *)&param_1);
  local_8 = 0xffffffff;
  CString::~CString((CString *)&param_1);
  ExceptionList = local_10;
  return this;
}



void __thiscall FUN_00405c71(void *this,CDataExchange *param_1)

{
  FUN_00401480();
  DDX_Text(param_1,0x3f5,(CString *)((int)this + 0x60));
  return;
}



undefined * FUN_00405c9f(void)

{
  return messageMap_exref;
}



undefined ** FUN_00405ca9(void)

{
  return &PTR_FUN_0042cf18;
}



void __thiscall FUN_00405cb9(void *this,HWND param_1,UINT param_2,WPARAM param_3)

{
  ShowMouse(true);
  CWnd::DefWindowProcA(param_1,param_2,param_3,(LPARAM)this);
  return;
}



undefined4 __fastcall FUN_00405ce5(TwDirectXDialog *param_1)

{
  HWND__ *pHVar1;
  CWnd *pCVar2;
  
  TwDirectXDialog::OnInitDialog(param_1);
  pHVar1 = GKERNEL::GetHwnd();
  pCVar2 = CWnd::FromHandle(pHVar1);
  CWnd::CenterWindow((CWnd *)param_1,pCVar2);
  return 1;
}



void * __thiscall FUN_00405d20(void *this,uint param_1)

{
  FUN_004046a0((CDialog *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void * __thiscall FUN_00405d50(void *this,undefined4 *param_1,undefined4 param_2,CWnd *param_3)

{
  bool bVar1;
  STRING *this_00;
  char *pcVar2;
  CString local_20 [4];
  uint local_1c;
  REG local_18 [4];
  char *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00428860;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00401770(this,0x85,param_3);
  local_8 = 0;
  FUN_00408b40((void *)((int)this + 0x60),param_1,&DAT_00435ecc);
  local_8._0_1_ = 1;
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)((int)this + 100));
  local_8._0_1_ = 2;
  *(undefined4 *)((int)this + 0x80) = param_2;
  CString::CString((CString *)((int)this + 0x84));
  local_8._0_1_ = 3;
  FUN_00408860((CWnd *)((int)this + 0x88));
  local_8._0_1_ = 4;
  FUN_004089a0((CWnd *)((int)this + 200));
  local_8._0_1_ = 5;
  *(undefined ***)this = &PTR_LAB_0042d0f0;
  local_14 = s_Default_Player_plr_0043458c;
  CString::operator=((CString *)((int)this + 0x84),s_Default_Player_plr_0043458c);
  REG::GetPut((REG *)((int)this + 0x60),s_EnableSounds_004345a0,(ulong *)((int)this + 0x108),1);
  REG::GetPut((REG *)((int)this + 0x60),s_EnableMusic_004345b0,(ulong *)((int)this + 0x10c),1);
  REG::GetPut((REG *)((int)this + 0x60),s_MusicVolume_004345bc,(ulong *)((int)this + 0x110),0x28);
  REG::GetPut((REG *)((int)this + 0x60),s_GammaLevel_004345c8,(ulong *)((int)this + 0x118),0);
  REG::GetPut((REG *)((int)this + 0x60),s_CurrentPlayerFile_004345d4,(CString *)((int)this + 0x84),
              local_14);
  pcVar2 = &DAT_004345e8;
  FUN_00405680(local_20,(CString *)((int)this + 0x84));
  local_8._0_1_ = 6;
  this_00 = (STRING *)STRING::toupper((int)pcVar2);
  bVar1 = STRING::tailequ(this_00,pcVar2);
  local_1c = CONCAT31(local_1c._1_3_,'\x01' - bVar1);
  local_8 = CONCAT31(local_8._1_3_,5);
  FUN_004014d0(local_20);
  if ((local_1c & 0xff) != 0) {
    CString::operator=((CString *)((int)this + 0x84),local_14);
    pcVar2 = (char *)FUN_00401470((undefined4 *)((int)this + 0x84));
    REG::Put((REG *)((int)this + 0x60),s_CurrentPlayerFile_004345f0,pcVar2);
  }
  FUN_004016a0(local_18,s_Gkernel_00434618,s_Software_Twilight__00434604);
  local_8._0_1_ = 7;
  REG::GetPut(local_18,s_Windowed_00434620,(ulong *)((int)this + 0x114),0);
  local_8 = CONCAT31(local_8._1_3_,5);
  FUN_00401750((undefined4 *)local_18);
  ExceptionList = local_10;
  return this;
}



void __fastcall FUN_00405f84(CDialog *param_1)

{
  bool bVar1;
  uint uVar2;
  CDialog *local_20;
  uint local_18;
  REG local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_004288dd;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)param_1 = &PTR_LAB_0042d0f0;
  local_8 = 5;
  local_18 = local_18 & 0xffffff00;
  FUN_004016a0(local_14,s_Gkernel_00434640,s_Software_Twilight__0043462c);
  local_8 = CONCAT31(local_8._1_3_,6);
  REG::Get(local_14,s_Windowed_00434648,(bool *)&local_18);
  uVar2 = local_18 & 0xff;
  bVar1 = GKERNEL::Windowed();
  if (uVar2 != bVar1) {
    GKERNEL::SetWindowedMode(local_18._0_1_);
  }
  local_8._0_1_ = 5;
  FUN_00401750((undefined4 *)local_14);
  local_8._0_1_ = 4;
  CComboBox::~CComboBox((CComboBox *)(param_1 + 200));
  local_8._0_1_ = 3;
  CListBox::~CListBox((CListBox *)(param_1 + 0x88));
  local_8._0_1_ = 2;
  CString::~CString((CString *)(param_1 + 0x84));
  local_8._0_1_ = 1;
  FUN_00407d30((undefined4 *)(param_1 + 100));
  local_8 = (uint)local_8._1_3_ << 8;
  if (param_1 == (CDialog *)0x0) {
    local_20 = (CDialog *)0x0;
  }
  else {
    local_20 = param_1 + 0x60;
  }
  FUN_00401750((undefined4 *)local_20);
  local_8 = 0xffffffff;
  FUN_004017d0(param_1);
  ExceptionList = local_10;
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  protected: virtual void __thiscall CMFCKeyMapDialog::DoDataExchange(class CDataExchange *)
//  protected: virtual void __thiscall CMFCToolBarsListPropertyPage::DoDataExchange(class
// CDataExchange *)
// 
// Library: Visual Studio 2010 Debug

void __thiscall DoDataExchange(void *this,CDataExchange *param_1)

{
  FUN_00401480();
  DDX_Control(param_1,0x419,(CWnd *)((int)this + 0x88));
  DDX_Control(param_1,0x3ec,(CWnd *)((int)this + 200));
  DDX_Check(param_1,0x412,(int *)((int)this + 0x108));
  DDX_Check(param_1,0x413,(int *)((int)this + 0x10c));
  DDX_Slider(param_1,0x417,(int *)((int)this + 0x110));
  DDX_Radio(param_1,0x416,(int *)((int)this + 0x114));
  DDX_Slider(param_1,0x41a,(int *)((int)this + 0x118));
  return;
}



undefined * FUN_00406156(void)

{
  return messageMap_exref;
}



undefined ** FUN_00406160(void)

{
  return &PTR_FUN_0042d010;
}



bool __fastcall FUN_00406170(int param_1)

{
  bool bVar1;
  void *this;
  undefined4 *puVar2;
  CString *pCVar3;
  CString local_20 [4];
  CString local_1c [4];
  STRING local_18 [4];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00428902;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_14 = FUN_004089f0(param_1 + 200);
  if (local_14 == 0xffffffff) {
    bVar1 = false;
  }
  else {
    pCVar3 = local_1c;
    this = (void *)FUN_00407ed0((void *)(param_1 + 100),local_14);
    puVar2 = (undefined4 *)base(this,pCVar3);
    local_8 = 0;
    FUN_00401470(puVar2);
    pCVar3 = (CString *)ExtractFileName((char *)local_20);
    local_8._0_1_ = 1;
    FUN_00405680(local_18,pCVar3);
    local_8._0_1_ = 4;
    CString::~CString(local_20);
    local_8 = CONCAT31(local_8._1_3_,3);
    FUN_004014d0(local_1c);
    bVar1 = STRING::equi(local_18,s_Default_Player_plr_00434654);
    local_8 = 0xffffffff;
    FUN_004014d0((CString *)local_18);
  }
  ExceptionList = local_10;
  return bVar1;
}



undefined4 __fastcall FUN_00406259(TwDirectXDialog *param_1)

{
  bool bVar1;
  undefined4 *puVar2;
  char *pcVar3;
  void *pvVar4;
  undefined3 extraout_var;
  uint uVar5;
  undefined3 extraout_var_00;
  LPARAM LVar6;
  CString *pCVar7;
  BOOL BVar8;
  CString *pCVar9;
  int iVar10;
  undefined *puVar11;
  HWND pHVar12;
  char *lpFindFileData;
  int in_stack_fffffee4;
  CString local_c0 [4];
  uint local_bc;
  CString local_b8 [4];
  CString local_b4 [4];
  CString local_b0 [4];
  int local_ac;
  CString local_a8 [4];
  CString local_a4 [4];
  CString local_a0 [4];
  CString local_9c [4];
  char local_98 [28];
  CString local_7c [4];
  LPARAM local_78;
  STRING local_74 [4];
  STRING local_70 [4];
  uint local_6c;
  STRING local_68 [4];
  uint local_64;
  int local_60;
  CSliderCtrl *local_5c;
  CString local_58 [4];
  ulong local_54;
  WPARAM local_50;
  INIFILE *local_4c;
  CFileFind local_48 [28];
  CTypeLibCacheMap local_2c [28];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004289b7;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  TwDirectXDialog::OnInitDialog(param_1);
  puVar2 = (undefined4 *)REG::AppData();
  local_8 = 0;
  pcVar3 = (char *)FUN_00401470(puVar2);
  pvVar4 = (void *)INIFILE::LoadAllInifiles(local_98,pcVar3);
  local_8._0_1_ = 1;
  FUN_00407e90(param_1 + 100,pvVar4);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_00407d30((undefined4 *)local_98);
  local_8 = 0xffffffff;
  CString::~CString(local_7c);
  local_50 = 0;
  local_60 = FUN_00423770((int)(param_1 + 100));
  local_4c = (INIFILE *)0x0;
  local_64 = 0;
  bVar1 = IsEmpty((int)(param_1 + 100));
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar2 = (undefined4 *)FUN_0041be90(&local_60);
    local_4c = (INIFILE *)*puVar2;
  }
  local_64 = 0;
  while ((uVar5 = FUN_00423620((int)(param_1 + 100)), local_64 < uVar5 &&
         (bVar1 = IsEmpty((int)(param_1 + 100)), CONCAT31(extraout_var_00,bVar1) == 0))) {
    puVar2 = (undefined4 *)INIFILE::GetValue(local_4c,(char *)local_9c,s_Params_00434678);
    local_8 = 2;
    LVar6 = FUN_00401470(puVar2);
    FUN_00408a50(param_1 + 200,LVar6);
    local_8 = 0xffffffff;
    FUN_004014d0(local_9c);
    puVar2 = (undefined4 *)base(local_4c,local_a0);
    local_8 = 3;
    FUN_00401470(puVar2);
    pCVar7 = (CString *)ExtractFileName((char *)local_a4);
    local_8._0_1_ = 4;
    FUN_00405680(local_68,pCVar7);
    local_8._0_1_ = 7;
    CString::~CString(local_a4);
    local_8 = CONCAT31(local_8._1_3_,6);
    FUN_004014d0(local_a0);
    pcVar3 = (char *)FUN_00401470((undefined4 *)(param_1 + 0x84));
    bVar1 = STRING::equi(local_68,pcVar3);
    if (bVar1) {
      FUN_00408a20(param_1 + 200,local_50);
    }
    local_50 = local_50 + 1;
    local_8 = 0xffffffff;
    FUN_004014d0((CString *)local_68);
    local_64 = local_64 + 1;
    uVar5 = FUN_00423620((int)(param_1 + 100));
    if (local_64 < uVar5) {
      puVar2 = (undefined4 *)FUN_0041be90(&local_60);
      local_4c = (INIFILE *)*puVar2;
    }
  }
  local_5c = (CSliderCtrl *)CWnd::GetDlgItem((HWND)&hDlg_00000417,in_stack_fffffee4);
  CSliderCtrl::SetRange(local_5c,0,100,0);
  FUN_00408ae0(local_5c,*(LPARAM *)(param_1 + 0x110));
  FUN_00408b10(local_5c,10);
  local_5c = (CSliderCtrl *)CWnd::GetDlgItem((HWND)&DAT_0000041a,in_stack_fffffee4);
  CSliderCtrl::SetRange(local_5c,0,2,0);
  FUN_00408ae0(local_5c,*(LPARAM *)(param_1 + 0x118));
  FUN_00408b10(local_5c,1);
  lpFindFileData = s_Sounds__00434680;
  pCVar7 = FUN_004014f0(local_a8);
  local_8 = 8;
  operator+(local_58,(char *)pCVar7);
  local_8._0_1_ = 10;
  CString::~CString(local_a8);
  CFileFind::CFileFind(local_48);
  local_8._0_1_ = 0xb;
  CTypeLibCacheMap::CTypeLibCacheMap(local_2c);
  local_8._0_1_ = 0xc;
  REG::GetStrList((REG *)(param_1 + 0x60),s_DisabledSounds_00434688,(LIST<> *)local_2c);
  pCVar7 = (CString *)0x0;
  puVar11 = &DAT_00434698;
  puVar2 = (undefined4 *)operator+(local_b0,(char *)local_58);
  local_8._0_1_ = 0xd;
  pcVar3 = (char *)FUN_00401470(puVar2);
  local_ac = CFileFind::FindFile(local_48,pcVar3,(ulong)puVar11);
  local_8 = CONCAT31(local_8._1_3_,0xc);
  CString::~CString(local_b0);
  if (local_ac != 0) {
    local_6c = CONCAT31(local_6c._1_3_,1);
    while ((local_6c & 0xff) != 0) {
      BVar8 = CFileFind::FindNextFileA(pCVar7,(LPWIN32_FIND_DATAA)lpFindFileData);
      local_6c = CONCAT31(local_6c._1_3_,BVar8 != 0);
      pCVar7 = local_b4;
      puVar2 = (undefined4 *)CFileFind::GetFilePath(local_48);
      local_8._0_1_ = 0xe;
      FUN_00401470(puVar2);
      pCVar9 = (CString *)ExtractFileName((char *)local_b8);
      local_8._0_1_ = 0xf;
      FUN_00405680(local_70,pCVar9);
      local_8._0_1_ = 0x12;
      CString::~CString(local_b8);
      local_8._0_1_ = 0x11;
      CString::~CString(local_b4);
      STRING::strtok((char *)local_74,(char *)&_Delim_0043469c);
      local_8 = CONCAT31(local_8._1_3_,0x13);
      iVar10 = FUN_004080f0((int *)local_48);
      if ((iVar10 == 0) &&
         (((bVar1 = STRING::equi(local_70,&DAT_004346a0), bVar1 ||
           (bVar1 = STRING::equi(local_70,&DAT_004346a4), bVar1)) &&
          (bVar1 = STRING::equi(local_74,s_Buffer_Stuffer_004346a8), !bVar1)))) {
        LVar6 = FUN_00401470((undefined4 *)local_74);
        local_78 = FUN_00408970(param_1 + 0x88,LVar6);
        FUN_00407d70(local_c0,(CString *)local_74);
        local_8._0_1_ = 0x14;
        puVar2 = (undefined4 *)STRING::toupper((int)pCVar7);
        bVar1 = FUN_00407e30(local_2c,puVar2);
        local_bc = CONCAT31(local_bc._1_3_,'\x01' - bVar1);
        local_8 = CONCAT31(local_8._1_3_,0x13);
        FUN_004014d0(local_c0);
        if ((local_bc & 0xff) != 0) {
          FUN_00408940(param_1 + 0x88,local_78,1);
        }
        local_78 = local_78 + 1;
      }
      local_8._0_1_ = 0x11;
      FUN_004014d0((CString *)local_74);
      local_8 = CONCAT31(local_8._1_3_,0xc);
      FUN_004014d0((CString *)local_70);
    }
  }
  FUN_004088e0(param_1 + 0x88,0);
  pHVar12 = *(HWND *)(param_1 + 0x108);
  CWnd::GetDlgItem((HWND)&param_2_00000419,(int)pHVar12);
  CWnd::EnableWindow(pHVar12,(BOOL)pCVar7);
  local_54 = TwDXVersion::GetDXVersion();
  if (local_54 < 0x601) {
    pHVar12 = (HWND)0x0;
    CWnd::GetDlgItem((HWND)&hDlg_00000417,0);
    CWnd::EnableWindow(pHVar12,(BOOL)pCVar7);
    pHVar12 = (HWND)0x0;
    CWnd::GetDlgItem((HWND)&hDlg_00000413,0);
    CWnd::EnableWindow(pHVar12,(BOOL)pCVar7);
  }
  local_8._0_1_ = 0xb;
  FUN_00407d50((undefined4 *)local_2c);
  local_8 = CONCAT31(local_8._1_3_,10);
  CFileFind::~CFileFind(local_48);
  local_8 = 0xffffffff;
  CString::~CString(local_58);
  ExceptionList = local_10;
  return 1;
}



void __fastcall FUN_00406923(int param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 *puVar2;
  uint uVar3;
  undefined3 extraout_var_00;
  char *pcVar4;
  CString *pCVar5;
  SECTION *this;
  LPARAM LVar6;
  int iVar7;
  char *unaff_EDI;
  int *piVar8;
  char *pcVar9;
  undefined4 local_208;
  undefined1 local_1e4 [8];
  INIFILE *local_1dc;
  undefined4 local_1d8;
  CString local_1d4 [4];
  CString local_1d0 [4];
  CString local_1cc [4];
  CString local_1c8 [4];
  undefined4 local_1c4;
  int local_1c0;
  CString local_1bc [4];
  CString local_1b8 [4];
  uint local_1b4;
  int local_1b0;
  CString local_1ac [4];
  int local_1a8 [100];
  uint local_18;
  void *local_14;
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
  puStack_c = &LAB_00428a38;
  local_10 = ExceptionList;
  local_8 = 0;
  local_1a8[0] = 0;
  piVar8 = local_1a8;
  for (iVar7 = 99; piVar8 = piVar8 + 1, iVar7 != 0; iVar7 = iVar7 + -1) {
    *piVar8 = 0;
  }
  ExceptionList = &local_10;
  REG::AppData();
  local_8 = CONCAT31(local_8._1_3_,1);
  local_1b0 = FUN_00423770(param_1 + 100);
  local_14 = (void *)0x0;
  local_1b4 = 0;
  bVar1 = IsEmpty(param_1 + 100);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar2 = (undefined4 *)FUN_0041be90(&local_1b0);
    local_14 = (void *)*puVar2;
  }
  local_1b4 = 0;
  while ((uVar3 = FUN_00423620(param_1 + 100), local_1b4 < uVar3 &&
         (bVar1 = IsEmpty(param_1 + 100), CONCAT31(extraout_var_00,bVar1) == 0))) {
    base(local_14,local_1bc);
    local_8._0_1_ = 2;
    STRING::strtok((char *)local_1b8,(char *)&_Delim_004346b8);
    local_8._0_1_ = 3;
    CString::MakeUpper(local_1b8);
    bVar1 = STRING::headequ((STRING *)local_1b8,s_PLAYER_004346bc);
    if (bVar1) {
      CString::Delete(local_1b8,0,6);
      STRING::strtok((char *)local_1cc,(char *)&_Delim_004346c4);
      local_8._0_1_ = 4;
      local_1c0 = STRING::atol(unaff_EDI);
      local_8._0_1_ = 3;
      FUN_004014d0(local_1cc);
      if (local_1c0 < 100) {
        local_1a8[local_1c0] = 1;
        goto LAB_00406b53;
      }
      local_8._0_1_ = 2;
      FUN_004014d0(local_1b8);
      local_8 = CONCAT31(local_8._1_3_,1);
      FUN_004014d0(local_1bc);
    }
    else {
LAB_00406b53:
      local_8._0_1_ = 2;
      FUN_004014d0(local_1b8);
      local_8 = CONCAT31(local_8._1_3_,1);
      FUN_004014d0(local_1bc);
    }
    local_1b4 = local_1b4 + 1;
    uVar3 = FUN_00423620(param_1 + 100);
    if (local_1b4 < uVar3) {
      puVar2 = (undefined4 *)FUN_0041be90(&local_1b0);
      local_14 = (void *)*puVar2;
    }
  }
  local_18 = 0;
  do {
    if (99 < local_18) {
LAB_00406d73:
      local_8 = local_8 & 0xffffff00;
      CString::~CString(local_1ac);
      local_8 = 0xffffffff;
      CString::~CString((CString *)&stack0x00000004);
      ExceptionList = local_10;
      return;
    }
    if (local_1a8[local_18] == 0) {
      pcVar4 = (char *)REG::AppData();
      local_8._0_1_ = 5;
      pCVar5 = (CString *)operator+(local_1d4,pcVar4);
      local_8._0_1_ = 6;
      FUN_00405680(local_1c8,pCVar5);
      local_8._0_1_ = 9;
      CString::~CString(local_1d4);
      local_8._0_1_ = 8;
      CString::~CString(local_1d0);
      CString::GetBuffer(local_1c8,440000);
      CString::Format(local_1c8,(char *)local_1c8);
      local_1dc = (INIFILE *)operator_new(0x24);
      local_8._0_1_ = 10;
      if (local_1dc == (INIFILE *)0x0) {
        local_208 = 0;
      }
      else {
        iVar7 = 1;
        pcVar4 = (char *)FUN_00401470((undefined4 *)local_1c8);
        local_208 = INIFILE::INIFILE(local_1dc,pcVar4,iVar7);
      }
      local_1d8 = local_208;
      local_8._0_1_ = 8;
      local_1c4 = local_208;
      pcVar4 = (char *)FUN_00401470((undefined4 *)&stack0x00000004);
      pcVar9 = &DAT_004346e4;
      this = (SECTION *)FUN_00408bc0(local_1e4,local_1c4,s_Params_004346dc);
      local_8._0_1_ = 0xb;
      INIFILE::SECTION::Put(this,pcVar9,pcVar4);
      local_8._0_1_ = 8;
      FUN_00407d90((int)local_1e4);
      FUN_0041bdb0((void *)(param_1 + 100),&local_1c4);
      LVar6 = FUN_00401470((undefined4 *)&stack0x00000004);
      FUN_00408a50((void *)(param_1 + 200),LVar6);
      iVar7 = FUN_00423620(param_1 + 100);
      FUN_00408a20((void *)(param_1 + 200),iVar7 - 1);
      local_8 = CONCAT31(local_8._1_3_,1);
      FUN_004014d0(local_1c8);
      goto LAB_00406d73;
    }
    local_18 = local_18 + 1;
  } while( true );
}



undefined4 __fastcall FUN_00406da2(int param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 *puVar2;
  uint uVar3;
  undefined3 extraout_var_00;
  char *pcVar4;
  STRING local_20 [4];
  uint local_1c;
  int local_18;
  INIFILE *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_00428a54;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  local_18 = FUN_00423770(param_1 + 100);
  local_14 = (INIFILE *)0x0;
  local_1c = 0;
  bVar1 = IsEmpty(param_1 + 100);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar2 = (undefined4 *)FUN_0041be90(&local_18);
    local_14 = (INIFILE *)*puVar2;
  }
  local_1c = 0;
  while ((uVar3 = FUN_00423620(param_1 + 100), local_1c < uVar3 &&
         (bVar1 = IsEmpty(param_1 + 100), CONCAT31(extraout_var_00,bVar1) == 0))) {
    INIFILE::GetValue(local_14,(char *)local_20,s_Params_004346f4);
    local_8._0_1_ = 1;
    pcVar4 = (char *)FUN_00401470((undefined4 *)&stack0x00000004);
    bVar1 = STRING::equi(local_20,pcVar4);
    if (bVar1) {
      local_8 = (uint)local_8._1_3_ << 8;
      FUN_004014d0((CString *)local_20);
      local_8 = 0xffffffff;
      CString::~CString((CString *)&stack0x00000004);
      ExceptionList = local_10;
      return 0;
    }
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_004014d0((CString *)local_20);
    local_1c = local_1c + 1;
    uVar3 = FUN_00423620(param_1 + 100);
    if (local_1c < uVar3) {
      puVar2 = (undefined4 *)FUN_0041be90(&local_18);
      local_14 = (INIFILE *)*puVar2;
    }
  }
  local_8 = 0xffffffff;
  CString::~CString((CString *)&stack0x00000004);
  ExceptionList = local_10;
  return 1;
}



void __fastcall FUN_00406f00(int param_1)

{
  bool bVar1;
  int iVar2;
  undefined3 extraout_var;
  char *pcVar3;
  CString *pCVar4;
  HWND in_stack_ffffff54;
  CString local_88 [4];
  CString local_84 [4];
  undefined1 *local_80;
  TwDirectXDialog local_7c [100];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_00428a7c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00408e60(local_7c,(CWnd *)0x0);
  local_8 = 0;
  CString::operator=(local_14,s_Enter_New_Player_Name___004346fc);
LAB_00406f42:
  do {
    iVar2 = TwDirectXDialog::DoModal(local_7c);
    if (iVar2 != 1) {
LAB_0040704c:
      CWnd::GetDlgItem((HWND)0x1,(int)in_stack_ffffff54);
      CWnd::SetFocus(in_stack_ffffff54);
      local_8 = 0xffffffff;
      FUN_00404860((CDialog *)local_7c);
      ExceptionList = local_10;
      return;
    }
    bVar1 = FUN_00401430((int *)local_18);
    if (CONCAT31(extraout_var,bVar1) != 0) {
      MessageBeep(0);
      goto LAB_00406f42;
    }
    local_80 = &stack0xffffff50;
    CString::CString((CString *)&stack0xffffff50,local_18);
    iVar2 = FUN_00406da2(param_1);
    if (iVar2 != 0) {
      in_stack_ffffff54 = (HWND)CString::CString((CString *)&stack0xffffff50,local_18);
      FUN_00406923(param_1);
      goto LAB_0040704c;
    }
    pcVar3 = (char *)operator+((char *)local_84,(CString *)s_The_player_name_00434740);
    local_8._0_1_ = 1;
    pCVar4 = (CString *)operator+(local_88,pcVar3);
    local_8._0_1_ = 2;
    CString::operator=(local_14,pCVar4);
    local_8._0_1_ = 1;
    CString::~CString(local_88);
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_84);
  } while( true );
}



void __fastcall FUN_0040707d(int param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  int *piVar2;
  int iVar3;
  char *pcVar4;
  CString *pCVar5;
  undefined3 extraout_var_00;
  undefined4 *puVar6;
  SECTION *this;
  LPARAM LVar7;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  char *pcVar8;
  undefined4 uVar9;
  HWND__ *hWnd;
  CWnd *pCVar10;
  undefined1 local_174 [8];
  CString local_16c [4];
  CString local_168 [4];
  undefined1 *local_164;
  CString local_160 [4];
  CString local_15c [4];
  undefined1 *local_158;
  CDialog local_154 [100];
  undefined1 *local_f0;
  CDialog local_ec [100];
  undefined4 local_88;
  TwDirectXDialog local_84 [100];
  CString local_20 [4];
  CString local_1c [4];
  HWND__ local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00428aec;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  bVar1 = FUN_00406170(param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    iVar3 = FUN_00423620(param_1 + 100);
    if (iVar3 == 0) {
      pCVar10 = (CWnd *)0x0;
      local_158 = &stack0xfffffe30;
      uVar9 = extraout_ECX_00;
      CString::CString((CString *)&stack0xfffffe30,s_There_are_no_defined_players__00434774);
      piVar2 = (int *)FUN_00405bf0(local_154,uVar9,pCVar10);
      local_8 = 1;
      (**(code **)(*piVar2 + 0xc0))();
      local_8 = 0xffffffff;
      FUN_004046a0(local_154);
    }
    else {
      local_14 = FUN_004089f0(param_1 + 200);
      CString::CString((CString *)&local_18);
      local_8 = 2;
      CComboBox::GetLBText((CComboBox *)(param_1 + 200),local_14,(CString *)&local_18);
      FUN_00408e60(local_84,(CWnd *)0x0);
      local_8._0_1_ = 3;
      hWnd = &local_18;
      pcVar4 = (char *)operator+((char *)local_15c,(CString *)s_Rename_player_0043479c);
      local_8._0_1_ = 4;
      pCVar5 = (CString *)operator+(local_160,pcVar4);
      local_8._0_1_ = 5;
      CString::operator=(local_1c,pCVar5);
      local_8._0_1_ = 4;
      CString::~CString(local_160);
      local_8 = CONCAT31(local_8._1_3_,3);
      CString::~CString(local_15c);
      while (iVar3 = TwDirectXDialog::DoModal(local_84), iVar3 == 1) {
        bVar1 = FUN_00401430((int *)local_20);
        if (CONCAT31(extraout_var_00,bVar1) == 0) {
          local_164 = &stack0xfffffe2c;
          CString::CString((CString *)&stack0xfffffe2c,local_20);
          iVar3 = FUN_00406da2(param_1);
          if (iVar3 != 0) {
            puVar6 = (undefined4 *)FUN_00407f60((void *)(param_1 + 100),local_14);
            local_88 = *puVar6;
            pcVar4 = (char *)FUN_00401470((undefined4 *)local_20);
            pcVar8 = &DAT_004347f4;
            this = (SECTION *)FUN_00408bc0(local_174,local_88,s_Params_004347ec);
            local_8._0_1_ = 8;
            INIFILE::SECTION::Put(this,pcVar8,pcVar4);
            local_8 = CONCAT31(local_8._1_3_,3);
            FUN_00407d90((int)local_174);
            LVar7 = FUN_00401470((undefined4 *)local_20);
            FUN_00408ab0((void *)(param_1 + 200),local_14,LVar7);
            FUN_00408a80((void *)(param_1 + 200),local_14 + 1);
            FUN_00408a20((void *)(param_1 + 200),local_14);
            break;
          }
          pcVar4 = (char *)operator+((char *)local_168,(CString *)s_The_player_name_004347d8);
          local_8._0_1_ = 6;
          pCVar5 = (CString *)operator+(local_16c,pcVar4);
          local_8._0_1_ = 7;
          CString::operator=(local_1c,pCVar5);
          local_8._0_1_ = 6;
          CString::~CString(local_16c);
          local_8 = CONCAT31(local_8._1_3_,3);
          CString::~CString(local_168);
        }
        else {
          MessageBeep(0);
        }
      }
      CWnd::GetDlgItem((HWND)0x1,(int)hWnd);
      CWnd::SetFocus(hWnd);
      local_8 = CONCAT31(local_8._1_3_,2);
      FUN_00404860((CDialog *)local_84);
      local_8 = 0xffffffff;
      CString::~CString((CString *)&local_18);
    }
  }
  else {
    MessageBeep(0x30);
    pCVar10 = (CWnd *)0x0;
    local_f0 = &stack0xfffffe30;
    uVar9 = extraout_ECX;
    CString::CString((CString *)&stack0xfffffe30,s_Cannot_rename_default_player_00434754);
    piVar2 = (int *)FUN_00405bf0(local_ec,uVar9,pCVar10);
    local_8 = 0;
    (**(code **)(*piVar2 + 0xc0))();
    local_8 = 0xffffffff;
    FUN_004046a0(local_ec);
  }
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00407471(int param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  int *piVar2;
  int iVar3;
  char *pcVar4;
  CString *pCVar5;
  undefined4 *puVar6;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 uVar7;
  HWND__ *hWnd;
  CWnd *pCVar8;
  CString local_15c [4];
  CString local_158 [4];
  CString local_154 [4];
  undefined1 *local_150;
  CDialog local_14c [100];
  undefined1 *local_e8;
  CDialog local_e4 [100];
  void *local_80;
  TwDirectXDialog local_7c [96];
  CString local_1c [4];
  HWND__ local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00428b44;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  bVar1 = FUN_00406170(param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    iVar3 = FUN_00423620(param_1 + 100);
    if (iVar3 == 0) {
      pCVar8 = (CWnd *)0x0;
      local_150 = &stack0xfffffe54;
      uVar7 = extraout_ECX_00;
      CString::CString((CString *)&stack0xfffffe54,s_There_are_no_players_defined__0043481c);
      piVar2 = (int *)FUN_00405bf0(local_14c,uVar7,pCVar8);
      local_8 = 1;
      (**(code **)(*piVar2 + 0xc0))();
      local_8 = 0xffffffff;
      FUN_004046a0(local_14c);
    }
    else {
      local_14 = FUN_004089f0(param_1 + 200);
      CString::CString((CString *)&local_18);
      local_8 = 2;
      CComboBox::GetLBText((CComboBox *)(param_1 + 200),local_14,(CString *)&local_18);
      MessageBeep(0);
      FUN_00409fb0(local_7c,(CWnd *)0x0);
      local_8._0_1_ = 3;
      hWnd = &local_18;
      pcVar4 = (char *)operator+((char *)local_154,
                                 (CString *)s_Do_you_really_want_to_delete_pla_00434840);
      local_8._0_1_ = 4;
      pCVar5 = (CString *)operator+(local_158,pcVar4);
      local_8._0_1_ = 5;
      CString::operator=(local_1c,pCVar5);
      local_8._0_1_ = 4;
      CString::~CString(local_158);
      local_8._0_1_ = 3;
      CString::~CString(local_154);
      iVar3 = TwDirectXDialog::DoModal(local_7c);
      if (iVar3 == 1) {
        puVar6 = (undefined4 *)FUN_00407f60((void *)(param_1 + 100),local_14);
        local_80 = (void *)*puVar6;
        FUN_00408a80((void *)(param_1 + 200),local_14);
        FUN_00408010((void *)(param_1 + 100),local_14);
        puVar6 = (undefined4 *)base(local_80,local_15c);
        local_8._0_1_ = 6;
        pcVar4 = (char *)FUN_00401470(puVar6);
        remove(pcVar4);
        local_8._0_1_ = 3;
        FUN_004014d0(local_15c);
        if (local_80 != (void *)0x0) {
          FUN_00407db0(local_80,1);
        }
        FUN_00408a20((void *)(param_1 + 200),0);
      }
      CWnd::GetDlgItem((HWND)0x1,(int)hWnd);
      CWnd::SetFocus(hWnd);
      local_8 = CONCAT31(local_8._1_3_,2);
      FUN_004048f0((CDialog *)local_7c);
      local_8 = 0xffffffff;
      CString::~CString((CString *)&local_18);
    }
  }
  else {
    MessageBeep(0x30);
    pCVar8 = (CWnd *)0x0;
    local_e8 = &stack0xfffffe54;
    uVar7 = extraout_ECX;
    CString::CString((CString *)&stack0xfffffe54,s_Cannot_delete_default_player_004347fc);
    piVar2 = (int *)FUN_00405bf0(local_e4,uVar7,pCVar8);
    local_8 = 0;
    (**(code **)(*piVar2 + 0xc0))();
    local_8 = 0xffffffff;
    FUN_004046a0(local_e4);
  }
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_004077a8(TwDirectXDialog *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 *puVar2;
  uint uVar3;
  undefined3 extraout_var_00;
  uint local_10;
  int local_c;
  void *local_8;
  
  local_c = FUN_00423770((int)(param_1 + 100));
  local_8 = (void *)0x0;
  bVar1 = IsEmpty((int)(param_1 + 100));
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar2 = (undefined4 *)FUN_0041be90(&local_c);
    local_8 = (void *)*puVar2;
  }
  local_10 = 0;
  while ((uVar3 = FUN_00423620((int)(param_1 + 100)), local_10 < uVar3 &&
         (bVar1 = IsEmpty((int)(param_1 + 100)), CONCAT31(extraout_var_00,bVar1) == 0))) {
    if (local_8 != (void *)0x0) {
      FUN_00407db0(local_8,1);
    }
    local_10 = local_10 + 1;
    uVar3 = FUN_00423620((int)(param_1 + 100));
    if (local_10 < uVar3) {
      puVar2 = (undefined4 *)FUN_0041be90(&local_c);
      local_8 = (void *)*puVar2;
    }
  }
  TwDirectXDialog::OnDestroy(param_1);
  return;
}



void __fastcall FUN_0040788d(CWnd *param_1)

{
  undefined4 *puVar1;
  char *pcVar2;
  int iVar3;
  CString *pCVar4;
  CString *in_stack_ffffffa4;
  CString local_48 [4];
  CString local_44 [4];
  CString local_40 [4];
  uint local_3c;
  uint local_38;
  uint local_34;
  CTypeLibCacheMap local_30 [28];
  REG local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00428b7b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_38 = FUN_004089f0((int)(param_1 + 200));
  if (local_38 != 0xffffffff) {
    pCVar4 = local_44;
    puVar1 = (undefined4 *)FUN_00407f60(param_1 + 100,local_38);
    puVar1 = (undefined4 *)base((void *)*puVar1,pCVar4);
    local_8 = 0;
    FUN_00401470(puVar1);
    in_stack_ffffffa4 = (CString *)ExtractFileName((char *)local_48);
    local_8._0_1_ = 1;
    CString::operator=((CString *)(param_1 + 0x84),in_stack_ffffffa4);
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_48);
    local_8 = 0xffffffff;
    FUN_004014d0(local_44);
  }
  CWnd::UpdateData(param_1,1);
  REG::Put((REG *)(param_1 + 0x60),s_EnableSounds_00434868,*(ulong *)(param_1 + 0x108));
  pcVar2 = (char *)FUN_00401470((undefined4 *)(param_1 + 0x84));
  REG::Put((REG *)(param_1 + 0x60),s_CurrentPlayerFile_00434878,pcVar2);
  REG::Put((REG *)(param_1 + 0x60),s_EnableMusic_0043488c,*(ulong *)(param_1 + 0x10c));
  REG::Put((REG *)(param_1 + 0x60),s_MusicVolume_00434898,*(ulong *)(param_1 + 0x110));
  REG::Put((REG *)(param_1 + 0x60),s_GammaLevel_004348a4,*(ulong *)(param_1 + 0x118));
  FUN_004016a0(local_14,s_Gkernel_004348c4,s_Software_Twilight__004348b0);
  local_8 = 2;
  REG::Put(local_14,s_Windowed_004348cc,*(int *)(param_1 + 0x114) != 0);
  local_3c = FUN_004088b0((int)(param_1 + 0x88));
  CTypeLibCacheMap::CTypeLibCacheMap(local_30);
  local_8._0_1_ = 3;
  for (local_34 = 0; local_34 < local_3c; local_34 = local_34 + 1) {
    FUN_00405660(local_40);
    local_8 = CONCAT31(local_8._1_3_,4);
    CListBox::GetText((CListBox *)(param_1 + 0x88),local_34,local_40);
    iVar3 = FUN_00408910(param_1 + 0x88,local_34);
    if (iVar3 == 0) {
      pCVar4 = (CString *)STRING::toupper((int)in_stack_ffffffa4);
      FUN_00407e10(local_30,pCVar4);
    }
    local_8._0_1_ = 3;
    FUN_004014d0(local_40);
  }
  REG::PutStrList((REG *)(param_1 + 0x60),s_DisabledSounds_004348d8,(LIST<> *)local_30);
  CDialog::OnOK((CDialog *)param_1);
  local_8 = CONCAT31(local_8._1_3_,2);
  FUN_00407d50((undefined4 *)local_30);
  local_8 = 0xffffffff;
  FUN_00401750((undefined4 *)local_14);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00407ade(int param_1)

{
  undefined4 *puVar1;
  CString *pCVar2;
  int iVar3;
  char *pcVar4;
  CString local_84 [4];
  CString local_80 [4];
  CString local_7c [4];
  TwDirectXDialog local_78 [96];
  CString local_18 [4];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00428ba9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_14 = FUN_004089f0(param_1 + 200);
  if (local_14 != 0xffffffff) {
    MessageBeep(0);
    FUN_00409fb0(local_78,(CWnd *)0x0);
    local_8 = 0;
    pcVar4 = s_Params_004348fc;
    pCVar2 = local_7c;
    puVar1 = (undefined4 *)FUN_00407f60((void *)(param_1 + 100),local_14);
    INIFILE::GetValue((INIFILE *)*puVar1,(char *)pCVar2,pcVar4);
    local_8._0_1_ = 1;
    pcVar4 = (char *)operator+((char *)local_80,
                               (CString *)s_Are_you_sure_you_want_to_delete_00434904);
    local_8._0_1_ = 2;
    pCVar2 = (CString *)operator+(local_84,pcVar4);
    local_8._0_1_ = 3;
    CString::operator=(local_18,pCVar2);
    local_8._0_1_ = 2;
    CString::~CString(local_84);
    local_8._0_1_ = 1;
    CString::~CString(local_80);
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_004014d0(local_7c);
    iVar3 = TwDirectXDialog::DoModal(local_78);
    if (iVar3 == 1) {
      pcVar4 = s_Solved_00434928;
      puVar1 = (undefined4 *)FUN_00407f60((void *)(param_1 + 100),local_14);
      INIFILE::DeleteSection((INIFILE *)*puVar1,pcVar4);
    }
    local_8 = 0xffffffff;
    FUN_004048f0((CDialog *)local_78);
  }
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00407c4a(CWnd *param_1)

{
  HWND hWnd;
  
  CWnd::UpdateData(param_1,1);
  hWnd = *(HWND *)(param_1 + 0x108);
  CWnd::GetDlgItem((HWND)&param_2_00000419,(int)hWnd);
  CWnd::EnableWindow(hWnd,(BOOL)param_1);
  return;
}



void __fastcall FUN_00407c7d(CWnd *param_1)

{
  HWND hWnd;
  
  CWnd::UpdateData(param_1,1);
  hWnd = *(HWND *)(param_1 + 0x10c);
  CWnd::GetDlgItem((HWND)&hDlg_00000417,(int)hWnd);
  CWnd::EnableWindow(hWnd,(BOOL)param_1);
  return;
}



void __thiscall FUN_00407cb0(void *this,undefined4 param_1,undefined4 *param_2)

{
  CWnd::UpdateData((CWnd *)this,1);
  if (*(int *)((int)this + 0x80) != 0) {
    CMidi::SetVolume(*(CMidi **)((int)this + 0x80),*(ulong *)((int)this + 0x110));
  }
  *param_2 = 0;
  return;
}



void * __thiscall FUN_00407d00(void *this,uint param_1)

{
  FUN_00405f84((CDialog *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_00407d30(undefined4 *param_1)

{
  FUN_004084d0(param_1);
  return;
}



void __fastcall FUN_00407d50(undefined4 *param_1)

{
  FUN_00408230(param_1);
  return;
}



void * __thiscall FUN_00407d70(void *this,CString *param_1)

{
  CString::CString((CString *)this,param_1);
  return this;
}



void __fastcall FUN_00407d90(int param_1)

{
  CString::~CString((CString *)(param_1 + 4));
  return;
}



void * __thiscall FUN_00407db0(void *this,uint param_1)

{
  INIFILE::~INIFILE((INIFILE *)this);
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
  FUN_00408110(this,10);
  *(undefined ***)this = &PTR_LAB_0042d1c8;
  return this;
}



void * __thiscall FUN_00407e10(void *this,CString *param_1)

{
  FUN_00408170(this,param_1);
  return this;
}



bool __thiscall FUN_00407e30(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_004081d0(this,param_1,(undefined4 *)0x0);
  return puVar1 != (undefined4 *)0x0;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_00408370(this,10);
  *(undefined ***)this = &PTR_LAB_0042d1dc;
  return this;
}



void * __thiscall FUN_00407e90(void *this,void *param_1)

{
  if (this != param_1) {
    FUN_0041be10((int)this);
    FUN_004083f0(this,(int)param_1);
  }
  return this;
}



undefined4 __thiscall FUN_00407ed0(void *this,uint param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 uVar2;
  uint uVar3;
  int local_c;
  uint local_8;
  
  bVar1 = IsEmpty((int)this);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    uVar3 = FUN_00423620((int)this);
    if (param_1 < uVar3) {
      local_c = FUN_00423770((int)this);
      local_8 = 0;
      while ((local_8 < param_1 && (uVar3 = FUN_00423620((int)this), local_8 < uVar3))) {
        FUN_00408430(&local_c);
        local_8 = local_8 + 1;
      }
      uVar2 = FUN_00408430(&local_c);
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



void * __thiscall FUN_00407f60(void *this,uint param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  void *pvVar2;
  uint uVar3;
  int local_c;
  uint local_8;
  
  bVar1 = IsEmpty((int)this);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    uVar3 = FUN_00423620((int)this);
    if (param_1 < uVar3) {
      local_c = FUN_00423770((int)this);
      local_8 = 0;
      while ((local_8 < param_1 && (uVar3 = FUN_00423620((int)this), local_8 < uVar3))) {
        FUN_0041be90(&local_c);
        local_8 = local_8 + 1;
      }
      pvVar2 = (void *)FUN_0041be90(&local_c);
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



void __thiscall FUN_00408010(void *this,uint param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  uint uVar2;
  int *local_c;
  uint local_8;
  
  bVar1 = IsEmpty((int)this);
  if ((CONCAT31(extraout_var,bVar1) == 0) && (uVar2 = FUN_00423620((int)this), param_1 < uVar2)) {
    local_c = (int *)FUN_00423770((int)this);
    local_8 = 0;
    while ((local_8 < param_1 && (uVar2 = FUN_00423620((int)this), local_8 < uVar2))) {
      FUN_0041be90((int *)&local_c);
      local_8 = local_8 + 1;
    }
    FUN_00408460(this,local_c);
  }
  return;
}



void * __thiscall FUN_00408090(void *this,uint param_1)

{
  FUN_00407d50((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void * __thiscall FUN_004080c0(void *this,uint param_1)

{
  FUN_00407d30((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_004080f0(int *param_1)

{
  (**(code **)(*param_1 + 0x40))(0x10);
  return;
}



void * __thiscall FUN_00408110(void *this,undefined4 param_1)

{
  FUN_00404b20((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_0042d1f0;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



undefined4 * __thiscall FUN_00408170(void *this,CString *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_004086b0(this,*(undefined4 *)((int)this + 8),0);
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



undefined4 * __thiscall FUN_004081d0(void *this,undefined4 *param_1,undefined4 *param_2)

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
    bVar1 = FUN_00408790(local_8 + 2,param_1);
    if (CONCAT31(extraout_var,bVar1) != 0) break;
    local_8 = (undefined4 *)*local_8;
  }
  return local_8;
}



void __fastcall FUN_00408230(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00428bc9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_0042d1f0;
  local_8 = 0;
  FUN_00408630((int)param_1);
  local_8 = 0xffffffff;
  FUN_00404b70(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_00408290(void *this,CArchive *param_1)

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
  puStack_c = &LAB_00428be9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00401400();
  bVar1 = FUN_00404cf0((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_18 = CArchive::ReadCount(param_1);
    while (local_18 != 0) {
      local_18 = local_18 - 1;
      CString::CString(local_1c);
      local_8 = 0;
      SerializeElements(param_1,local_1c,1);
      FUN_00408170(this,local_1c);
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



void * __thiscall FUN_00408370(void *this,undefined4 param_1)

{
  FUN_00404b20((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_0042d204;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
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



void __thiscall FUN_004083f0(void *this,int param_1)

{
  undefined4 *puVar1;
  int local_8;
  
  local_8 = FUN_00423770(param_1);
  while (local_8 != 0) {
    puVar1 = (undefined4 *)FUN_0041be90(&local_8);
    FUN_0041bdb0(this,puVar1);
  }
  return;
}



int FUN_00408430(int *param_1)

{
  int *piVar1;
  
  piVar1 = (int *)*param_1;
  *param_1 = *piVar1;
  return piVar1[2];
}



void __thiscall FUN_00408460(void *this,int *param_1)

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
  FUN_004087d0(this,param_1);
  return;
}



void __fastcall FUN_004084d0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00428c09;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_0042d204;
  local_8 = 0;
  FUN_0041be10((int)param_1);
  local_8 = 0xffffffff;
  FUN_00404b70(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_00408530(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_10;
  ulong local_c;
  undefined4 *local_8;
  
  FUN_00401400();
  bVar1 = FUN_00404cf0((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      FUN_00408820(param_1,&local_10,1);
      FUN_0041bdb0(this,&local_10);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_00408820(param_1,local_8 + 2,1);
    }
  }
  return;
}



void * __thiscall FUN_004085d0(void *this,uint param_1)

{
  FUN_00408230((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void * __thiscall FUN_00408600(void *this,uint param_1)

{
  FUN_004084d0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_00408630(int param_1)

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



undefined4 * __thiscall FUN_004086b0(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0xc);
    iVar3 = FUN_00428190((int)pCVar2);
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



bool FUN_00408790(void *param_1,undefined4 *param_2)

{
  bool bVar1;
  
  bVar1 = FUN_004087b0(param_1,param_2);
  return bVar1;
}



bool FUN_004087b0(void *param_1,undefined4 *param_2)

{
  char *pcVar1;
  int iVar2;
  
  pcVar1 = (char *)FUN_00401470(param_2);
  iVar2 = FUN_004049b0(param_1,pcVar1);
  return (bool)('\x01' - (iVar2 != 0));
}



void __thiscall FUN_004087d0(void *this,undefined4 *param_1)

{
  FUN_0041bf80(param_1 + 2,1);
  *param_1 = *(undefined4 *)((int)this + 0x10);
  *(undefined4 **)((int)this + 0x10) = param_1;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + -1;
  if (*(int *)((int)this + 0xc) == 0) {
    FUN_0041be10((int)this);
  }
  return;
}



void FUN_00408820(CArchive *param_1,void *param_2,int param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_00404cf0((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    CArchive::Read(param_1,param_2,param_3 << 2);
  }
  else {
    CArchive::Write(param_1,param_2,param_3 << 2);
  }
  return;
}



CWnd * __fastcall FUN_00408860(CWnd *param_1)

{
  CWnd::CWnd(param_1);
  *(undefined ***)param_1 = &PTR_LAB_0042d218;
  return param_1;
}



void * __thiscall FUN_00408880(void *this,uint param_1)

{
  CListBox::~CListBox((CListBox *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_004088b0(int param_1)

{
  SendMessageA(*(HWND *)(param_1 + 0x20),0x18b,0,0);
  return;
}



void __thiscall FUN_004088e0(void *this,WPARAM param_1)

{
  SendMessageA(*(HWND *)((int)this + 0x20),0x197,param_1,0);
  return;
}



void __thiscall FUN_00408910(void *this,WPARAM param_1)

{
  SendMessageA(*(HWND *)((int)this + 0x20),0x187,param_1,0);
  return;
}



void __thiscall FUN_00408940(void *this,LPARAM param_1,WPARAM param_2)

{
  SendMessageA(*(HWND *)((int)this + 0x20),0x185,param_2,param_1);
  return;
}



void __thiscall FUN_00408970(void *this,LPARAM param_1)

{
  SendMessageA(*(HWND *)((int)this + 0x20),0x180,0,param_1);
  return;
}



CWnd * __fastcall FUN_004089a0(CWnd *param_1)

{
  CWnd::CWnd(param_1);
  *(undefined ***)param_1 = &PTR_LAB_0042d2f0;
  return param_1;
}



void * __thiscall FUN_004089c0(void *this,uint param_1)

{
  CComboBox::~CComboBox((CComboBox *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_004089f0(int param_1)

{
  SendMessageA(*(HWND *)(param_1 + 0x20),0x147,0,0);
  return;
}



void __thiscall FUN_00408a20(void *this,WPARAM param_1)

{
  SendMessageA(*(HWND *)((int)this + 0x20),0x14e,param_1,0);
  return;
}



void __thiscall FUN_00408a50(void *this,LPARAM param_1)

{
  SendMessageA(*(HWND *)((int)this + 0x20),0x143,0,param_1);
  return;
}



void __thiscall FUN_00408a80(void *this,WPARAM param_1)

{
  SendMessageA(*(HWND *)((int)this + 0x20),0x144,param_1,0);
  return;
}



void __thiscall FUN_00408ab0(void *this,WPARAM param_1,LPARAM param_2)

{
  SendMessageA(*(HWND *)((int)this + 0x20),0x14a,param_1,param_2);
  return;
}



void __thiscall FUN_00408ae0(void *this,LPARAM param_1)

{
  SendMessageA(*(HWND *)((int)this + 0x20),0x405,1,param_1);
  return;
}



void __thiscall FUN_00408b10(void *this,WPARAM param_1)

{
  SendMessageA(*(HWND *)((int)this + 0x20),0x414,param_1,0);
  return;
}



void * __thiscall FUN_00408b40(void *this,undefined4 *param_1,LPCSTR param_2)

{
  DWORD dwErrCode;
  
  dwErrCode = RegCreateKeyExA((HKEY)*param_1,param_2,0,(LPSTR)0x0,0,0xf003f,
                              (LPSECURITY_ATTRIBUTES)0x0,(PHKEY)this,(LPDWORD)0x0);
  SetLastError(dwErrCode);
  return this;
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
  FUN_00405680(param_1,(CString *)this);
  return param_1;
}



void * __thiscall FUN_00408bc0(void *this,undefined4 param_1,char *param_2)

{
  *(undefined4 *)this = param_1;
  CString::CString((CString *)((int)this + 4),param_2);
  return this;
}



void * __thiscall FUN_00408bf0(void *this,CWnd *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_00428c35;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CDialog::CDialog((CDialog *)this,0x8c,param_1);
  local_8 = 0;
  CString::CString((CString *)((int)this + 0x60));
  local_8 = CONCAT31(local_8._1_3_,1);
  *(undefined ***)this = &PTR_LAB_0042d3e0;
  CString::operator=((CString *)((int)this + 0x60),(char *)&this_00435ed0);
  ExceptionList = local_10;
  return this;
}



void __thiscall FUN_00408c66(void *this,CDataExchange *param_1)

{
  FUN_00401480();
  DDX_Text(param_1,0x41c,(CString *)((int)this + 0x60));
  return;
}



undefined * FUN_00408c94(void)

{
  return messageMap_exref;
}



undefined ** FUN_00408c9e(void)

{
  return &PTR_FUN_0042d3c0;
}



undefined4 __fastcall FUN_00408cae(CDialog *param_1)

{
  CDialog::OnInitDialog(param_1);
  FUN_00408e40((int)param_1);
  return 1;
}



void FUN_00408cce(char *param_1)

{
  HWND__ *hWnd;
  int iVar1;
  CString *pCVar2;
  int *piVar3;
  UINT Msg;
  WPARAM wParam;
  LPARAM lParam;
  CString local_7c [4];
  CString local_78 [4];
  CDialog local_74 [96];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_00428c5a;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00408bf0(local_74,(CWnd *)0x0);
  local_8 = 0;
  CString::operator=(local_14,param_1);
  lParam = 0;
  wParam = 0xf020;
  Msg = 0x112;
  hWnd = GKERNEL::GetHwnd();
  SendMessageA(hWnd,Msg,wParam,lParam);
  iVar1 = CDialog::DoModal(local_74);
  if (iVar1 == 1) {
    pCVar2 = FUN_004014f0(local_78);
    local_8._0_1_ = 1;
    piVar3 = (int *)operator+(local_7c,(char *)pCVar2);
    local_8._0_1_ = 2;
    FUN_0040a219(piVar3);
    local_8._0_1_ = 1;
    CString::~CString(local_7c);
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_78);
  }
  local_8 = 0xffffffff;
  FUN_00408df0(local_74);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_00408dc0(void *this,uint param_1)

{
  FUN_00408df0((CDialog *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_00408df0(CDialog *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00428c79;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  CString::~CString((CString *)(param_1 + 0x60));
  local_8 = 0xffffffff;
  CDialog::~CDialog(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00408e40(int param_1)

{
  SetForegroundWindow(*(HWND *)(param_1 + 0x20));
  return;
}



void * __thiscall FUN_00408e60(void *this,CWnd *param_1)

{
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_00428cc6;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00401770(this,0x86,param_1);
  local_8 = 0;
  CString::CString((CString *)((int)this + 0x60));
  local_8._0_1_ = 1;
  FUN_00405660((CString *)((int)this + 100));
  local_8._0_1_ = 2;
  CString::CString((CString *)((int)this + 0x68));
  local_8._0_1_ = 3;
  *(undefined ***)this = &PTR_LAB_0042d4d8;
  FUN_004056a0(local_14,&DAT_00435ed4);
  local_8._0_1_ = 4;
  FUN_004048d0((void *)((int)this + 100),local_14);
  local_8 = CONCAT31(local_8._1_3_,3);
  FUN_004014d0(local_14);
  CString::operator=((CString *)((int)this + 0x68),&DAT_00435ed8);
  ExceptionList = local_10;
  return this;
}



void __thiscall FUN_00408f22(void *this,CDataExchange *param_1)

{
  FUN_00401480();
  DDX_Text(param_1,0x3f4,(CString *)((int)this + 100));
  DDV_MaxChars(param_1,(CString *)((int)this + 100),0x28);
  DDX_Text(param_1,0x3f5,(CString *)((int)this + 0x68));
  return;
}



undefined * FUN_00408f77(void)

{
  return messageMap_exref;
}



undefined ** FUN_00408f81(void)

{
  return &PTR_FUN_0042d4b8;
}



void __thiscall FUN_00408f91(void *this,HWND param_1,UINT param_2,WPARAM param_3)

{
  ShowMouse(true);
  CWnd::DefWindowProcA(param_1,param_2,param_3,(LPARAM)this);
  return;
}



undefined4 __fastcall FUN_00408fbd(TwDirectXDialog *param_1)

{
  bool bVar1;
  HWND__ *pHVar2;
  CWnd *pCVar3;
  undefined3 extraout_var;
  HWND hWnd;
  
  TwDirectXDialog::OnInitDialog(param_1);
  pHVar2 = GKERNEL::GetHwnd();
  pCVar3 = CWnd::FromHandle(pHVar2);
  CWnd::CenterWindow((CWnd *)param_1,pCVar3);
  bVar1 = FUN_00401430((int *)((CWnd *)param_1 + 0x60));
  if (CONCAT31(extraout_var,bVar1) == 0) {
    hWnd = (HWND)FUN_00401470((undefined4 *)((CWnd *)param_1 + 0x60));
    CWnd::SetWindowTextA(hWnd,(LPCSTR)param_1);
  }
  return 1;
}



void * __thiscall FUN_00409010(void *this,uint param_1)

{
  FUN_00404860((CDialog *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void * __thiscall FUN_00409040(void *this,undefined4 *param_1,CWnd *param_2)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_00428d2f;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00401770(this,0x8a,param_2);
  local_8 = 0;
  FUN_00408b40((void *)((int)this + 0x60),param_1,&DAT_00435edc);
  local_8._0_1_ = 1;
  CDIBStatic::CDIBStatic((CDIBStatic *)((int)this + 100));
  local_8._0_1_ = 2;
  INIFILE::INIFILE((INIFILE *)((int)this + 0xb4));
  local_8._0_1_ = 3;
  CString::CString((CString *)((int)this + 0xdc));
  local_8._0_1_ = 4;
  CString::CString((CString *)((int)this + 0xe0));
  local_8._0_1_ = 5;
  CString::CString((CString *)((int)this + 0xe4));
  local_8 = CONCAT31(local_8._1_3_,6);
  *(undefined ***)this = &PTR_LAB_0042d648;
  CString::operator=((CString *)((int)this + 0xe4),s_Registered_Version_0043494c);
  ExceptionList = local_10;
  return this;
}



void __thiscall FUN_0040911b(void *this,CDataExchange *param_1)

{
  FUN_00401480();
  DDX_Control(param_1,0x3f2,(CWnd *)((int)this + 100));
  DDX_Text(param_1,0x421,(CString *)((int)this + 0xe4));
  return;
}



undefined * FUN_00409160(void)

{
  return messageMap_exref;
}



undefined ** FUN_0040916a(void)

{
  return &PTR_FUN_0042d5b0;
}



void __fastcall FUN_0040917a(int param_1)

{
  bool bVar1;
  char *pcVar2;
  CString *pCVar3;
  undefined4 *puVar4;
  CString *pCVar5;
  undefined3 extraout_var;
  SECTION *this;
  HWND hWnd;
  char *pcVar6;
  CString local_54 [4];
  undefined1 local_50 [8];
  CString local_48 [4];
  CString local_44 [4];
  CString local_40 [4];
  INIFILE local_3c [36];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00428d82;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(local_14,s_Default_Player_plr_00434960);
  local_8 = 0;
  pcVar2 = (char *)FUN_00401470((undefined4 *)local_14);
  REG::GetPut((REG *)(param_1 + 0x60),s_CurrentPlayerFile_00434974,local_14,pcVar2);
  pCVar5 = local_14;
  pCVar3 = (CString *)REG::AppData();
  local_8._0_1_ = 1;
  puVar4 = (undefined4 *)operator+(local_44,pCVar3);
  local_8._0_1_ = 2;
  pcVar2 = (char *)FUN_00401470(puVar4);
  pCVar5 = (CString *)INIFILE::INIFILE(local_3c,pcVar2,(int)pCVar5);
  local_8._0_1_ = 3;
  FUN_00409a80((void *)(param_1 + 0xb4),pCVar5);
  local_8._0_1_ = 2;
  INIFILE::~INIFILE(local_3c);
  local_8._0_1_ = 1;
  CString::~CString(local_44);
  local_8._0_1_ = 0;
  CString::~CString(local_40);
  pCVar5 = (CString *)
           INIFILE::GetValue((INIFILE *)(param_1 + 0xb4),(char *)local_48,s_Params_00434990);
  local_8._0_1_ = 4;
  CString::CString(local_18,pCVar5);
  local_8._0_1_ = 6;
  FUN_004014d0(local_48);
  bVar1 = FUN_00401430((int *)local_18);
  if (CONCAT31(extraout_var,bVar1) != 0) {
    CString::operator=(local_18,s_Default_Player_00434998);
    pcVar2 = (char *)FUN_00401470((undefined4 *)local_18);
    pcVar6 = &DAT_004349b0;
    this = (SECTION *)FUN_00408bc0(local_50,param_1 + 0xb4,s_Params_004349a8);
    local_8._0_1_ = 7;
    INIFILE::SECTION::Put(this,pcVar6,pcVar2);
    local_8._0_1_ = 6;
    FUN_00407d90((int)local_50);
  }
  pCVar5 = local_18;
  puVar4 = (undefined4 *)operator+((char *)local_54,(CString *)s_Current_Player__004349b8);
  local_8._0_1_ = 8;
  hWnd = (HWND)FUN_00401470(puVar4);
  CWnd::GetDlgItem((HWND)&hDlg_00000411,(int)hWnd);
  CWnd::SetWindowTextA(hWnd,(LPCSTR)pCVar5);
  local_8._0_1_ = 6;
  CString::~CString(local_54);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(local_18);
  local_8 = 0xffffffff;
  CString::~CString(local_14);
  ExceptionList = local_10;
  return;
}



undefined4 __fastcall FUN_00409372(TwDirectXDialog *param_1)

{
  bool bVar1;
  CString *pCVar2;
  undefined4 *puVar3;
  char *pcVar4;
  LPCSTR pCVar5;
  int iVar6;
  STRING *this;
  HWND hWnd;
  char *pcVar7;
  CString local_40 [4];
  CString local_3c [4];
  CString local_38 [4];
  CString local_34 [4];
  CString local_30 [4];
  CString local_2c [4];
  CString local_28 [4];
  CString local_24 [4];
  STRING local_20 [4];
  int local_1c [2];
  HWND local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00428de6;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  TwDirectXDialog::OnInitDialog(param_1);
  FUN_004017f0((CDIBStatic *)(param_1 + 100));
  pCVar2 = FUN_004014f0(local_24);
  local_8 = 0;
  puVar3 = (undefined4 *)operator+(local_28,(char *)pCVar2);
  local_8._0_1_ = 1;
  pcVar4 = (char *)FUN_00401470(puVar3);
  CDIBStatic::LoadDib((CDIBStatic *)(param_1 + 100),pcVar4);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(local_28);
  local_8 = 0xffffffff;
  CString::~CString(local_24);
  CDIBStatic::UpdateDib((CDIBStatic *)(param_1 + 100));
  pcVar4 = (char *)REG::RootDir();
  local_8 = 2;
  pcVar7 = (char *)0x40944a;
  puVar3 = (undefined4 *)operator+(local_30,pcVar4);
  local_8._0_1_ = 3;
  pCVar5 = (LPCSTR)FUN_00401470(puVar3);
  FUN_004056e0(local_1c,pCVar5);
  local_8._0_1_ = 6;
  CString::~CString(local_30);
  local_8._0_1_ = 5;
  CString::~CString(local_2c);
  bVar1 = FUN_004057e0(local_1c);
  if (bVar1) {
    STRING::STRING(local_20,*(HWND__ **)(param_1 + 0x20));
    local_8._0_1_ = 7;
    pcVar7 = &DAT_004349e8;
    iVar6 = FUN_00423770((int)local_1c);
    pcVar4 = (char *)FUN_00401470(local_1c);
    this = (STRING *)FUN_00409e80(local_34,pcVar4,iVar6);
    local_8._0_1_ = 8;
    STRING::trim(this,pcVar7);
    pcVar7 = s__Version__004349f0;
    pCVar2 = (CString *)operator+(local_38,(char *)local_20);
    local_8._0_1_ = 9;
    pcVar4 = (char *)operator+(local_3c,pCVar2);
    local_8._0_1_ = 10;
    puVar3 = (undefined4 *)operator+(local_40,pcVar4);
    local_8._0_1_ = 0xb;
    pCVar5 = (LPCSTR)FUN_00401470(puVar3);
    SetWindowTextA(*(HWND *)(param_1 + 0x20),pCVar5);
    local_8._0_1_ = 10;
    CString::~CString(local_40);
    local_8._0_1_ = 9;
    CString::~CString(local_3c);
    local_8._0_1_ = 8;
    CString::~CString(local_38);
    local_8._0_1_ = 7;
    FUN_004014d0(local_34);
    local_8._0_1_ = 5;
    FUN_004014d0((CString *)local_20);
  }
  FUN_0040917a((int)param_1);
  local_14 = CWnd::GetDlgItem((HWND)&DAT_00000414,(int)pcVar7);
  hWnd = (HWND)FUN_00401470((undefined4 *)(param_1 + 0xdc));
  CWnd::SetWindowTextA(hWnd,pcVar7);
  local_8 = 0xffffffff;
  FUN_004057c0(local_1c);
  ExceptionList = local_10;
  return 1;
}



void __fastcall FUN_004095e5(int param_1)

{
  (**(code **)(**(int **)(param_1 + 0xd8) + 0x5c))();
  return;
}



void __fastcall FUN_00409607(void)

{
  HWND hWnd;
  LPSTR extraout_var;
  LPSTR lpString;
  HWND__ in_stack_ffffffec;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &hWnd_00428df9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString((CString *)&stack0xffffffec);
  local_8 = 0;
  hWnd = (HWND)&stack0xffffffec;
  lpString = extraout_var;
  CWnd::GetDlgItem((HWND)&hDlg_000003e9,(int)hWnd);
  CWnd::GetWindowTextA(hWnd,lpString,in_stack_ffffffec.unused);
  CDialog::EndDialog((HWND)0x0,(INT_PTR)lpString);
  local_8 = 0xffffffff;
  CString::~CString((CString *)&stack0xffffffec);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00409673(int param_1)

{
  HWND hWnd;
  int iVar1;
  TwDirectXDialog local_130 [284];
  undefined4 local_14;
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00428e18;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_004016a0(&local_14,s_Gkernel_00434a10,s_Software_Twilight__004349fc);
  local_8 = 0;
  if (param_1 == 0) {
    hWnd = (HWND)0x0;
  }
  else {
    hWnd = (HWND)(param_1 + 0x60);
  }
  FUN_00405d50(local_130,hWnd,0,(CWnd *)0x0);
  local_8 = CONCAT31(local_8._1_3_,1);
  iVar1 = TwDirectXDialog::DoModal(local_130);
  if (iVar1 == 1) {
    FUN_0040917a(param_1);
  }
  CWnd::GetDlgItem((HWND)&hDlg_000003e9,(int)hWnd);
  CWnd::SetFocus(hWnd);
  local_8 = local_8 & 0xffffff00;
  FUN_00405f84((CDialog *)local_130);
  local_8 = 0xffffffff;
  FUN_00401750(&local_14);
  ExceptionList = local_10;
  return;
}



void FUN_0040974d(void)

{
  CString *pCVar1;
  undefined4 *puVar2;
  char *pcVar3;
  LPCSTR lpFile;
  LPCSTR lpParameters;
  LPCSTR lpDirectory;
  INT nShowCmd;
  char *pcVar4;
  CString local_54 [4];
  CString local_50 [4];
  CString local_4c [4];
  CString local_48 [4];
  CString local_44 [4];
  SECTION local_40 [8];
  INIFILE local_38 [36];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_00428e6b;
  local_10 = ExceptionList;
  pcVar4 = s_GAME_INI_00434a18;
  ExceptionList = &local_10;
  pCVar1 = FUN_004014f0(local_44);
  local_8 = 0;
  puVar2 = (undefined4 *)operator+(local_48,(char *)pCVar1);
  local_8._0_1_ = 1;
  pcVar3 = (char *)FUN_00401470(puVar2);
  INIFILE::INIFILE(local_38,pcVar3,(int)pcVar4);
  local_8._0_1_ = 4;
  CString::~CString(local_48);
  local_8._0_1_ = 3;
  CString::~CString(local_44);
  FUN_00408bc0(local_40,local_38,s_TellAFriend_00434a24);
  local_8._0_1_ = 5;
  FUN_004056a0(local_14,s_mailto__Subject__00434a30);
  local_8._0_1_ = 6;
  pcVar3 = (char *)INIFILE::SECTION::Get(local_40,(char *)local_4c);
  local_8._0_1_ = 7;
  pCVar1 = (CString *)operator+(local_50,pcVar3);
  local_8._0_1_ = 8;
  CString::operator+=(local_14,pCVar1);
  local_8._0_1_ = 7;
  CString::~CString(local_50);
  local_8._0_1_ = 6;
  FUN_004014d0(local_4c);
  pCVar1 = (CString *)INIFILE::SECTION::Get(local_40,(char *)local_54);
  local_8._0_1_ = 9;
  CString::operator+=(local_14,pCVar1);
  local_8._0_1_ = 6;
  FUN_004014d0(local_54);
  nShowCmd = 1;
  lpDirectory = (LPCSTR)0x0;
  lpParameters = (LPCSTR)0x0;
  lpFile = (LPCSTR)FUN_00401470((undefined4 *)local_14);
  ShellExecuteA((HWND)0x0,&DAT_00434a5c,lpFile,lpParameters,lpDirectory,nShowCmd);
  local_8._0_1_ = 5;
  FUN_004014d0(local_14);
  local_8 = CONCAT31(local_8._1_3_,3);
  FUN_00407d90((int)local_40);
  local_8 = 0xffffffff;
  INIFILE::~INIFILE(local_38);
  ExceptionList = local_10;
  return;
}



void FUN_004098e3(void)

{
  CString *pCVar1;
  undefined4 *puVar2;
  char *pcVar3;
  CHyperLink *this;
  char *pcVar4;
  int iVar5;
  CString local_110 [4];
  CHyperLink local_10c [200];
  CString local_44 [4];
  CString local_40 [4];
  SECTION local_3c [8];
  INIFILE local_34 [36];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_00428eb3;
  local_10 = ExceptionList;
  pcVar4 = s_GAME_INI_00434a64;
  ExceptionList = &local_10;
  pCVar1 = FUN_004014f0(local_40);
  local_8 = 0;
  puVar2 = (undefined4 *)operator+(local_44,(char *)pCVar1);
  local_8._0_1_ = 1;
  pcVar3 = (char *)FUN_00401470(puVar2);
  INIFILE::INIFILE(local_34,pcVar3,(int)pcVar4);
  local_8._0_1_ = 4;
  CString::~CString(local_44);
  local_8._0_1_ = 3;
  CString::~CString(local_40);
  FUN_00408bc0(local_3c,local_34,s_OtherGames_00434a70);
  local_8._0_1_ = 5;
  iVar5 = 5;
  puVar2 = (undefined4 *)INIFILE::SECTION::Get(local_3c,(char *)local_110);
  local_8._0_1_ = 6;
  pcVar3 = (char *)FUN_00401470(puVar2);
  this = (CHyperLink *)CHyperLink::CHyperLink(local_10c);
  local_8._0_1_ = 7;
  CHyperLink::GotoURL(this,pcVar3,iVar5);
  local_8._0_1_ = 6;
  CHyperLink::~CHyperLink(local_10c);
  local_8._0_1_ = 5;
  FUN_004014d0(local_110);
  local_8 = CONCAT31(local_8._1_3_,3);
  FUN_00407d90((int)local_3c);
  local_8 = 0xffffffff;
  INIFILE::~INIFILE(local_34);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_00409a50(void *this,uint param_1)

{
  FUN_00409ef0((CDialog *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void * __thiscall FUN_00409a80(void *this,CString *param_1)

{
  CString::operator=((CString *)this,param_1);
  FUN_00409ac0((void *)((int)this + 4),param_1 + 4);
  *(undefined4 *)((int)this + 0x20) = *(undefined4 *)(param_1 + 0x20);
  return this;
}



void * __thiscall FUN_00409ac0(void *this,void *param_1)

{
  if (this != param_1) {
    FUN_00409b40((int)this);
    FUN_00409b00(this,(int)param_1);
  }
  return this;
}



void __thiscall FUN_00409b00(void *this,int param_1)

{
  CString *pCVar1;
  int local_8;
  
  local_8 = FUN_00423770(param_1);
  while (local_8 != 0) {
    pCVar1 = (CString *)FUN_0041be90(&local_8);
    FUN_00409bc0(this,pCVar1);
  }
  return;
}



void __fastcall FUN_00409b40(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_00409c20(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



undefined4 * __thiscall FUN_00409bc0(void *this,CString *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_00409d00(this,*(undefined4 *)((int)this + 8),0);
  FUN_00409c50(puVar1 + 2,param_1);
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



void FUN_00409c20(void *param_1,int param_2)

{
  while (param_2 != 0) {
    FUN_00409c80(param_1,0);
    param_1 = (void *)((int)param_1 + 8);
    param_2 = param_2 + -1;
  }
  return;
}



void * __thiscall FUN_00409c50(void *this,CString *param_1)

{
  CString::operator=((CString *)this,param_1);
  CString::operator=((CString *)((int)this + 4),param_1 + 4);
  return this;
}



void * __thiscall FUN_00409c80(void *this,uint param_1)

{
  FUN_00409cb0((CString *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_00409cb0(CString *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00428ec9;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  CString::~CString(param_1 + 4);
  local_8 = 0xffffffff;
  CString::~CString(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __thiscall FUN_00409d00(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0x10);
    iVar3 = FUN_00428190((int)pCVar2);
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
  FUN_00409de0(puVar1 + 2,1);
  return puVar1;
}



void FUN_00409de0(void *param_1,int param_2)

{
  CString *pCVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00428ef1;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  memset(param_1,0,param_2 << 3);
  while (param_2 != 0) {
    pCVar1 = (CString *)FUN_00405640(8,param_1);
    local_8 = 0;
    if (pCVar1 != (CString *)0x0) {
      FUN_00409ea0(pCVar1);
    }
    local_8 = 0xffffffff;
    param_1 = (void *)((int)param_1 + 8);
    param_2 = param_2 + -1;
  }
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_00409e80(void *this,char *param_1,int param_2)

{
  CString::CString((CString *)this,param_1,param_2);
  return this;
}



CString * __fastcall FUN_00409ea0(CString *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00428f09;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(param_1);
  local_8 = 0;
  CString::CString(param_1 + 4);
  ExceptionList = local_10;
  return param_1;
}



void __fastcall FUN_00409ef0(CDialog *param_1)

{
  CDialog *local_18;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &this_00428f8c;
  local_10 = ExceptionList;
  local_8 = 5;
  ExceptionList = &local_10;
  CString::~CString((CString *)(param_1 + 0xe4));
  local_8._0_1_ = 4;
  CString::~CString((CString *)(param_1 + 0xe0));
  local_8._0_1_ = 3;
  CString::~CString((CString *)(param_1 + 0xdc));
  local_8._0_1_ = 2;
  INIFILE::~INIFILE((INIFILE *)(param_1 + 0xb4));
  local_8._0_1_ = 1;
  CDIBStatic::~CDIBStatic((CDIBStatic *)(param_1 + 100));
  local_8 = (uint)local_8._1_3_ << 8;
  if (param_1 == (CDialog *)0x0) {
    local_18 = (CDialog *)0x0;
  }
  else {
    local_18 = param_1 + 0x60;
  }
  FUN_00401750((undefined4 *)local_18);
  local_8 = 0xffffffff;
  FUN_004017d0(param_1);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_00409fb0(void *this,CWnd *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_00428fb5;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00401770(this,0x89,param_1);
  local_8 = 0;
  CString::CString((CString *)((int)this + 0x60));
  local_8 = CONCAT31(local_8._1_3_,1);
  *(undefined ***)this = &PTR_LAB_0042d740;
  CString::operator=((CString *)((int)this + 0x60),(char *)&this_00435ee0);
  ExceptionList = local_10;
  return this;
}



void __thiscall FUN_0040a026(void *this,CDataExchange *param_1)

{
  FUN_00401480();
  DDX_Text(param_1,0x40c,(CString *)((int)this + 0x60));
  return;
}



undefined * FUN_0040a054(void)

{
  return messageMap_exref;
}



undefined ** FUN_0040a05e(void)

{
  return &PTR_FUN_0042d720;
}



void __thiscall FUN_0040a06e(void *this,HWND param_1,UINT param_2,WPARAM param_3)

{
  ShowMouse(true);
  CWnd::DefWindowProcA(param_1,param_2,param_3,(LPARAM)this);
  return;
}



void __fastcall FUN_0040a09a(INT_PTR param_1)

{
  CDialog::EndDialog((HWND)0x2,param_1);
  return;
}



void __fastcall FUN_0040a0af(INT_PTR param_1)

{
  CDialog::EndDialog((HWND)0x1,param_1);
  return;
}



undefined4 __fastcall FUN_0040a0c4(TwDirectXDialog *param_1)

{
  HWND__ *pHVar1;
  CWnd *pCVar2;
  
  TwDirectXDialog::OnInitDialog(param_1);
  pHVar1 = GKERNEL::GetHwnd();
  pCVar2 = CWnd::FromHandle(pHVar1);
  CWnd::CenterWindow((CWnd *)param_1,pCVar2);
  return 1;
}



void * __thiscall FUN_0040a100(void *this,uint param_1)

{
  FUN_004048f0((CDialog *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void FUN_0040a130(void)

{
  FUN_0040a13f();
  FUN_0040a14e();
  return;
}



void FUN_0040a13f(void)

{
  FUN_0040b7b0((undefined4 *)&DAT_00435fb0);
  return;
}



void FUN_0040a14e(void)

{
  FUN_00427dae(FUN_0040a160);
  return;
}



void FUN_0040a160(void)

{
  FUN_0040c9e0((undefined4 *)&DAT_00435fb0);
  return;
}



undefined * FUN_0040a16f(void)

{
  return messageMap_exref;
}



undefined ** FUN_0040a179(void)

{
  return &PTR_FUN_0042d818;
}



CWinApp * __fastcall FUN_0040a189(CWinApp *param_1)

{
  CWinApp::CWinApp(param_1,(char *)0x0);
  *(undefined ***)param_1 = &PTR_LAB_0042d838;
  return param_1;
}



void FUN_0040a1aa(void)

{
  FUN_0040a1b9();
  FUN_0040a1c8();
  return;
}



void FUN_0040a1b9(void)

{
  FUN_0040a189((CWinApp *)&DAT_00435ee8);
  return;
}



void FUN_0040a1c8(void)

{
  FUN_00427dae(FUN_0040a1da);
  return;
}



void FUN_0040a1da(void)

{
  FUN_0040b5b0((CWinApp *)&DAT_00435ee8);
  return;
}



undefined4 FUN_0040a1e9(void)

{
  CString aCStack_14 [4];
  undefined4 local_10;
  undefined1 *local_8;
  
  local_8 = aCStack_14;
  local_10 = CString::CString(aCStack_14,(char *)&this_0044896c);
  GAME::StartGame((GAME *)&DAT_00435fb0);
  return 1;
}



int FUN_0040a219(int *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  HWND__ *hWnd;
  char *pcVar2;
  CHyperLink *this;
  UINT Msg;
  WPARAM wParam;
  LPARAM lParam;
  int iVar3;
  CHyperLink local_dc [200];
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00428fcd;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  bVar1 = FUN_00401430(param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    bVar1 = GKERNEL::Initialized();
    if ((bVar1) && (bVar1 = GKERNEL::Windowed(), !bVar1)) {
      lParam = 0;
      wParam = 0xf020;
      Msg = 0x112;
      hWnd = GKERNEL::GetHwnd();
      SendMessageA(hWnd,Msg,wParam,lParam);
    }
    iVar3 = 5;
    pcVar2 = (char *)FUN_00401470(param_1);
    this = (CHyperLink *)CHyperLink::CHyperLink(local_dc);
    local_8 = 0;
    local_14 = CHyperLink::GotoURL(this,pcVar2,iVar3);
    local_8 = 0xffffffff;
    CHyperLink::~CHyperLink(local_dc);
  }
  else {
    local_14 = 0;
  }
  ExceptionList = local_10;
  return local_14;
}



void __fastcall FUN_0040a2f2(int param_1)

{
  undefined1 uVar1;
  undefined3 extraout_var;
  CString *pCVar2;
  int *piVar3;
  CString local_20 [4];
  CString local_1c [4];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_00428ffb;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  uVar1 = FUN_00414141(param_1);
  if (CONCAT31(extraout_var,uVar1) == 0) {
    pCVar2 = FUN_004014f0(local_1c);
    local_8 = 2;
    piVar3 = (int *)operator+(local_20,(char *)pCVar2);
    local_8._0_1_ = 3;
    FUN_0040a219(piVar3);
    local_8 = CONCAT31(local_8._1_3_,2);
    CString::~CString(local_20);
    local_8 = 0xffffffff;
    CString::~CString(local_1c);
  }
  else {
    pCVar2 = FUN_004014f0(local_14);
    local_8 = 0;
    piVar3 = (int *)operator+(local_18,(char *)pCVar2);
    local_8._0_1_ = 1;
    FUN_0040a219(piVar3);
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_18);
    local_8 = 0xffffffff;
    CString::~CString(local_14);
  }
  ExceptionList = local_10;
  return;
}



undefined1 FUN_0040a3f0(void)

{
  return 1;
}



void __thiscall FUN_0040a3fd(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  CString *pCVar1;
  CString local_1c [4];
  CString local_18 [4];
  int *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_00429020;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  pCVar1 = (CString *)operator+((char *)local_1c,(CString *)s_RELEASE__00434aa8);
  local_8._0_1_ = 1;
  FUN_00405680(local_18,pCVar1);
  local_8._0_1_ = 2;
  FUN_004048d0(&param_1,local_18);
  local_8._0_1_ = 1;
  FUN_004014d0(local_18);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(local_1c);
  local_14 = (int *)FUN_0041c4f0(this,(CString *)&param_1);
  (**(code **)(*local_14 + 0x1c))(param_2,param_3);
  if (local_14 != (int *)0x0) {
    (**(code **)*local_14)(1);
  }
  local_8 = 0xffffffff;
  FUN_004014d0((CString *)&param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_0040a4e4(void *param_1)

{
  bool bVar1;
  CString *pCVar2;
  undefined4 *puVar3;
  char *pcVar4;
  BOOL BVar5;
  int iVar6;
  undefined3 extraout_var;
  undefined4 *puVar7;
  undefined4 *puVar8;
  uint *puVar9;
  char *pcVar10;
  uint *puVar11;
  uint uVar12;
  HANDLE hFindFile;
  LPWIN32_FIND_DATAA *pp_Var13;
  LPWIN32_FIND_DATAA lpFindFileData;
  CString local_a4 [4];
  CString local_a0 [4];
  undefined1 *local_9c;
  CString local_98 [4];
  CString local_94 [4];
  CString local_90 [4];
  CString local_8c [4];
  CString local_88 [4];
  CString local_84 [4];
  uint local_80;
  CString local_7c [4];
  CString local_78 [4];
  CString local_74 [4];
  CString local_70 [4];
  undefined1 *local_6c;
  undefined4 local_68;
  undefined4 local_64;
  STRING local_60 [4];
  INIFILE local_5c [36];
  uint local_38;
  LPWIN32_FIND_DATAA local_34;
  CFileFind local_30 [28];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004290c7;
  local_10 = ExceptionList;
  local_14 = 0;
  local_34 = (LPWIN32_FIND_DATAA)0x0;
  pp_Var13 = &local_34;
  puVar9 = &local_14;
  local_6c = &stack0xfffffee4;
  ExceptionList = &local_10;
  puVar11 = puVar9;
  FUN_004056a0(&stack0xfffffee4,&DAT_00434ab4);
  FUN_0040a3fd(param_1,puVar9,puVar11,pp_Var13);
  pcVar10 = s_Levels__00434ab8;
  uVar12 = local_14;
  lpFindFileData = local_34;
  pCVar2 = FUN_004014f0(local_70);
  local_8 = 0;
  puVar3 = (undefined4 *)operator+(local_74,(char *)pCVar2);
  local_8._0_1_ = 1;
  pcVar4 = (char *)FUN_00401470(puVar3);
  MAP::LoadOptimzationTable(pcVar4,(uint)pcVar10,uVar12);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(local_74);
  local_8 = 0xffffffff;
  CString::~CString(local_70);
  CFileFind::CFileFind(local_30);
  local_8 = 2;
  hFindFile = (HANDLE)0x0;
  pcVar10 = s_Level_Packs_____00434ac0;
  pCVar2 = FUN_004014f0(local_78);
  local_8._0_1_ = 3;
  puVar3 = (undefined4 *)operator+(local_7c,(char *)pCVar2);
  local_8._0_1_ = 4;
  pcVar4 = (char *)FUN_00401470(puVar3);
  CFileFind::FindFile(local_30,pcVar4,(ulong)pcVar10);
  local_8._0_1_ = 3;
  CString::~CString(local_7c);
  local_8._0_1_ = 2;
  CString::~CString(local_78);
  local_38 = CONCAT31(local_38._1_3_,1);
  while ((local_38 & 0xff) != 0) {
    BVar5 = CFileFind::FindNextFileA(hFindFile,lpFindFileData);
    local_38 = CONCAT31(local_38._1_3_,BVar5 != 0);
    iVar6 = FUN_004080f0((int *)local_30);
    if ((iVar6 != 0) && (iVar6 = CFileFind::IsDots(local_30), iVar6 == 0)) {
      pcVar4 = (char *)CFileFind::GetFilePath(local_30);
      local_8._0_1_ = 5;
      puVar3 = (undefined4 *)operator+(local_88,pcVar4);
      local_8._0_1_ = 6;
      pcVar4 = (char *)FUN_00401470(puVar3);
      bVar1 = exists(pcVar4);
      local_80 = CONCAT31(local_80._1_3_,bVar1);
      local_8._0_1_ = 5;
      CString::~CString(local_88);
      local_8._0_1_ = 2;
      CString::~CString(local_84);
      if ((local_80 & 0xff) != 0) {
        pCVar2 = local_8c;
        pcVar4 = (char *)CFileFind::GetFilePath(local_30);
        local_8._0_1_ = 7;
        puVar3 = (undefined4 *)operator+(local_90,pcVar4);
        local_8._0_1_ = 8;
        pcVar4 = (char *)FUN_00401470(puVar3);
        INIFILE::INIFILE(local_5c,pcVar4,(int)pCVar2);
        local_8._0_1_ = 0xb;
        CString::~CString(local_90);
        local_8._0_1_ = 10;
        CString::~CString(local_8c);
        INIFILE::GetValue(local_5c,(char *)local_60,s_Params_00434af8);
        local_8._0_1_ = 0xc;
        bVar1 = FUN_00401430((int *)local_60);
        if ((CONCAT31(extraout_var,bVar1) != 0) ||
           (bVar1 = STRING::equi(local_60,s_Tutorial_00434b00), bVar1)) {
          pcVar10 = s__Levels__00434b0c;
          pCVar2 = local_94;
          pcVar4 = (char *)CFileFind::GetFilePath(local_30);
          local_8._0_1_ = 0xd;
          puVar3 = (undefined4 *)operator+(local_98,pcVar4);
          local_8._0_1_ = 0xe;
          pcVar4 = (char *)FUN_00401470(puVar3);
          MAP::LoadOptimzationTable(pcVar4,(uint)pCVar2,(uint)pcVar10);
          local_8._0_1_ = 0xd;
          CString::~CString(local_98);
          local_8 = CONCAT31(local_8._1_3_,0xc);
          CString::~CString(local_94);
        }
        else {
          local_64 = 0;
          local_68 = 0;
          puVar3 = &local_68;
          puVar7 = &local_64;
          local_9c = &stack0xfffffecc;
          puVar8 = puVar3;
          FUN_00407d70(&stack0xfffffecc,(CString *)local_60);
          FUN_0040a3fd(param_1,puVar3,puVar7,puVar8);
          pcVar10 = s__Levels__00434b18;
          pCVar2 = local_a0;
          pcVar4 = (char *)CFileFind::GetFilePath(local_30);
          local_8._0_1_ = 0xf;
          puVar3 = (undefined4 *)operator+(local_a4,pcVar4);
          local_8._0_1_ = 0x10;
          pcVar4 = (char *)FUN_00401470(puVar3);
          MAP::LoadOptimzationTable(pcVar4,(uint)pCVar2,(uint)pcVar10);
          local_8._0_1_ = 0xf;
          CString::~CString(local_a4);
          local_8 = CONCAT31(local_8._1_3_,0xc);
          CString::~CString(local_a0);
        }
        local_8._0_1_ = 10;
        FUN_004014d0((CString *)local_60);
        local_8._0_1_ = 2;
        INIFILE::~INIFILE(local_5c);
      }
    }
  }
  local_8 = 0xffffffff;
  CFileFind::~CFileFind(local_30);
  ExceptionList = local_10;
  return;
}



undefined4 __fastcall FUN_0040a98a(GAME *param_1)

{
  bool bVar1;
  int iVar2;
  CString *pCVar3;
  undefined4 *puVar4;
  char *pcVar5;
  undefined4 uVar6;
  char *pcVar7;
  uint uVar8;
  HINSTANCE__ *pHVar9;
  undefined1 uVar10;
  CString local_2c [4];
  CString local_28 [4];
  CString local_24 [4];
  CString local_20 [4];
  CString local_1c [4];
  int local_18;
  ulong local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004290fe;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  iVar2 = AlreadyRunning(s_AargonDeluxeRunning123_00434b24);
  if (iVar2 != 0) {
    AfxMessageBox(s_Aargon_Deluxe_Already_Running_00434b3c,0,0);
                    // WARNING: Subroutine does not return
    exit(0);
  }
  *(undefined4 *)(param_1 + 0x134) = 0;
  *(undefined4 *)(param_1 + 0xe1a0) = 0xffffffff;
  param_1[0x1281c] = (GAME)0x0;
  *(GAME **)(param_1 + 0x118) = param_1;
  local_14 = TwDXVersion::GetDXVersion();
  pCVar3 = (CString *)GKTOOLS::GetDXVersionString((ulong)local_1c);
  local_8 = 0;
  CString::operator=((CString *)(param_1 + 0x11c),pCVar3);
  local_8 = 0xffffffff;
  CString::~CString(local_1c);
  if (local_14 < 0x601) {
    DisplayWarning(s_Can_t_Initialize_Direct_X_Music_00434c0c,
                   s_Cannot_play_music_with_current_v_00434b6c,s_DirectX_Music_00434b5c);
  }
  local_18 = (**(code **)(*(int *)(param_1 + 0x40) + 0xc0))();
  if (local_18 == 2) {
                    // WARNING: Subroutine does not return
    exit(0);
  }
  GKERNEL::Init(true);
  CoInitialize((LPVOID)0x0);
  bVar1 = FindDriver(s_Some_random_bullshit_00434c2c);
  if (bVar1) {
    FUN_0040a4e4(param_1);
  }
  FUN_0040af39((int)param_1);
  FUN_0040b6d0(param_1,0);
  param_1[0xe014] = (GAME)0x0;
  *(undefined4 *)(param_1 + 0xe018) = 0;
  *(undefined4 *)(param_1 + 0xe010) = 0;
  REG::GetPut((REG *)(param_1 + 0x34),s_AllowFullScreenEdit_00434c44,(bool *)(param_1 + 0xe015),
              false);
  GAME::ChangeState(param_1,0);
  uVar10 = 0;
  pHVar9 = (HINSTANCE__ *)0x0;
  iVar2 = 0;
  uVar8 = 0;
  pcVar7 = s_Pictures_TITLE16M_BMP_00434c58;
  pCVar3 = FUN_004014f0(local_20);
  local_8 = 1;
  puVar4 = (undefined4 *)operator+(local_24,(char *)pCVar3);
  local_8._0_1_ = 2;
  pcVar5 = (char *)FUN_00401470(puVar4);
  GKTOOLS::CopyDIBToBack(pcVar5,(uint)pcVar7,uVar8,iVar2,pHVar9,(bool)uVar10);
  local_8 = CONCAT31(local_8._1_3_,1);
  CString::~CString(local_24);
  local_8 = 0xffffffff;
  CString::~CString(local_20);
  GKERNEL::Flip();
  bVar1 = GKERNEL::Windowed();
  if (bVar1) {
    uVar10 = 0;
    pHVar9 = (HINSTANCE__ *)0x0;
    iVar2 = 0;
    uVar8 = 0;
    pcVar7 = s_Pictures_TITLE16M_BMP_00434c70;
    pCVar3 = FUN_004014f0(local_28);
    local_8 = 3;
    puVar4 = (undefined4 *)operator+(local_2c,(char *)pCVar3);
    local_8._0_1_ = 4;
    pcVar5 = (char *)FUN_00401470(puVar4);
    GKTOOLS::CopyDIBToBack(pcVar5,(uint)pcVar7,uVar8,iVar2,pHVar9,(bool)uVar10);
    local_8 = CONCAT31(local_8._1_3_,3);
    CString::~CString(local_2c);
    local_8 = 0xffffffff;
    CString::~CString(local_28);
    GKERNEL::Flip();
  }
  FUN_0040cf5c((int)param_1);
  FUN_00418773((int *)param_1);
  GAME::ChangeState(param_1,5);
  uVar6 = FUN_0040b6b0((DWORD *)(param_1 + 0x1282c));
  ExceptionList = local_10;
  return CONCAT31((int3)((uint)uVar6 >> 8),1);
}



void __fastcall FUN_0040ac56(int param_1)

{
  undefined1 uVar1;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  CString *pCVar2;
  undefined4 *puVar3;
  char *pcVar4;
  CHyperLink *this;
  char *pcVar5;
  int iVar6;
  CString local_120 [4];
  CHyperLink local_11c [200];
  CString local_54 [4];
  CString local_50 [4];
  undefined4 *local_4c;
  undefined4 *local_48;
  undefined4 *local_44;
  undefined4 *local_40;
  SECTION local_3c [8];
  INIFILE local_34 [36];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429146;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  uVar1 = FUN_00414141(param_1);
  if (CONCAT31(extraout_var,uVar1) != 0) {
    FUN_00414176(param_1);
  }
  FUN_0040b5d0(param_1 + 0x138);
  ShowCursor(1);
  if (*(int *)(param_1 + 0x129b4) != 0) {
    local_44 = *(undefined4 **)(param_1 + 0x129b4);
    local_40 = local_44;
    if (local_44 != (undefined4 *)0x0) {
      (**(code **)*local_44)(1);
    }
    *(undefined4 *)(param_1 + 0x129b4) = 0;
  }
  MAP::Cleanup();
  FUN_0041a33a();
  FUN_0041da1f();
  if (*(int *)(param_1 + 0xe00c) != 0) {
    local_4c = *(undefined4 **)(param_1 + 0xe00c);
    local_48 = local_4c;
    if (local_4c != (undefined4 *)0x0) {
      (**(code **)*local_4c)(1);
    }
    *(undefined4 *)(param_1 + 0xe00c) = 0;
  }
  CMidi::UnInit((CMidi *)(param_1 + 0x5f48));
  CMidi::UnInit((CMidi *)(param_1 + 0x609c));
  CMidi::UnInit((CMidi *)(param_1 + 0x61f0));
  CMidi::UnInit((CMidi *)(param_1 + 0x6344));
  uVar1 = FUN_00414141(param_1);
  if ((CONCAT31(extraout_var_00,uVar1) != 0) && (*(char *)(param_1 + 0x1281c) == '\0')) {
    ShowMouse(true);
    pcVar5 = s_GAME_INI_00434c88;
    pCVar2 = FUN_004014f0(local_50);
    local_8 = 0;
    puVar3 = (undefined4 *)operator+(local_54,(char *)pCVar2);
    local_8._0_1_ = 1;
    pcVar4 = (char *)FUN_00401470(puVar3);
    INIFILE::INIFILE(local_34,pcVar4,(int)pcVar5);
    local_8._0_1_ = 4;
    CString::~CString(local_54);
    local_8._0_1_ = 3;
    CString::~CString(local_50);
    FUN_00408bc0(local_3c,local_34,s_OtherGames_00434c94);
    local_8._0_1_ = 5;
    iVar6 = 5;
    puVar3 = (undefined4 *)INIFILE::SECTION::Get(local_3c,(char *)local_120);
    local_8._0_1_ = 6;
    pcVar4 = (char *)FUN_00401470(puVar3);
    this = (CHyperLink *)CHyperLink::CHyperLink(local_11c);
    local_8._0_1_ = 7;
    CHyperLink::GotoURL(this,pcVar4,iVar6);
    local_8._0_1_ = 6;
    CHyperLink::~CHyperLink(local_11c);
    local_8._0_1_ = 5;
    FUN_004014d0(local_120);
    local_8 = CONCAT31(local_8._1_3_,3);
    FUN_00407d90((int)local_3c);
    local_8 = 0xffffffff;
    INIFILE::~INIFILE(local_34);
  }
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_0040af39(int param_1)

{
  HWND__ *pHVar1;
  ulong uVar2;
  CString *pCVar3;
  undefined4 *puVar4;
  char *pcVar5;
  CString *pCVar6;
  CString local_70 [4];
  CString local_6c [4];
  INIFILE local_68 [36];
  CString local_44 [4];
  CString local_40 [4];
  uint local_3c;
  bool local_38 [4];
  ulong local_34;
  CString local_30 [4];
  CTypeLibCacheMap local_2c [28];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_3_00429190;
  local_10 = ExceptionList;
  local_38[0] = true;
  local_3c = CONCAT31(local_3c._1_3_,1);
  local_34 = 0x28;
  ExceptionList = &local_10;
  REG::GetPut((REG *)(param_1 + 0x34),s_EnableSounds_00434ca4,local_38,true);
  REG::GetPut((REG *)(param_1 + 0x34),s_EnableMusic_00434cb4,(bool *)&local_3c,true);
  REG::GetPut((REG *)(param_1 + 0x34),s_MusicVolume_00434cc0,&local_34,0x32);
  REG::GetPut((REG *)(param_1 + 0x34),s_GammaLevel_00434ccc,(ulong *)(param_1 + 0x3c),0);
  CWave::Enable(local_38[0]);
  pHVar1 = GKERNEL::GetHwnd();
  CWave::RegisterWindow(pHVar1);
  if ((local_3c & 0xff) != 0) {
    uVar2 = TwDXVersion::GetDXVersion();
    if (0x600 < uVar2) {
      CMidi::Enable();
      CMidi::SetDefaultVolume(local_34);
      CMidi::Init((CMidi *)(param_1 + 0x5f48));
      CMidi::Init((CMidi *)(param_1 + 0x61f0));
      CMidi::Init((CMidi *)(param_1 + 0x6344));
      CMidi::SetVolume((CMidi *)(param_1 + 0x5f48),local_34);
      CMidi::SetVolume((CMidi *)(param_1 + 0x61f0),local_34);
      CMidi::SetVolume((CMidi *)(param_1 + 0x6344),local_34);
      pCVar3 = FUN_004014f0(local_40);
      local_8 = 0;
      puVar4 = (undefined4 *)operator+(local_44,(char *)pCVar3);
      local_8._0_1_ = 1;
      pcVar5 = (char *)FUN_00401470(puVar4);
      CMidi::LoadSong((CMidi *)(param_1 + 0x61f0),pcVar5);
      local_8 = (uint)local_8._1_3_ << 8;
      CString::~CString(local_44);
      local_8 = 0xffffffff;
      CString::~CString(local_40);
      goto LAB_0040b132;
    }
  }
  CMidi::UnInit((CMidi *)(param_1 + 0x5f48));
  CMidi::UnInit((CMidi *)(param_1 + 0x61f0));
  CMidi::UnInit((CMidi *)(param_1 + 0x6344));
  CMidi::UnInit((CMidi *)(param_1 + 0x609c));
  CMidi::Disable();
LAB_0040b132:
  CString::CString(local_30,s_Default_Player_plr_00434cf0);
  local_8 = 2;
  pcVar5 = (char *)FUN_00401470((undefined4 *)local_30);
  REG::GetPut((REG *)(param_1 + 0x34),s_CurrentPlayerFile_00434d04,local_30,pcVar5);
  pCVar3 = local_30;
  pCVar6 = (CString *)REG::AppData();
  local_8._0_1_ = 3;
  puVar4 = (undefined4 *)operator+(local_70,pCVar6);
  local_8._0_1_ = 4;
  pcVar5 = (char *)FUN_00401470(puVar4);
  pCVar3 = (CString *)INIFILE::INIFILE(local_68,pcVar5,(int)pCVar3);
  local_8._0_1_ = 5;
  FUN_00409a80((void *)(param_1 + 0xf4),pCVar3);
  local_8._0_1_ = 4;
  INIFILE::~INIFILE(local_68);
  local_8._0_1_ = 3;
  CString::~CString(local_70);
  local_8._0_1_ = 2;
  CString::~CString(local_6c);
  CTypeLibCacheMap::CTypeLibCacheMap(local_2c);
  local_8._0_1_ = 6;
  REG::GetStrList((REG *)(param_1 + 0x34),s_DisabledSounds_00434d18,(LIST<> *)local_2c);
  CWave::SetIgnoreList((LIST<> *)local_2c);
  local_8 = CONCAT31(local_8._1_3_,2);
  FUN_00407d50((undefined4 *)local_2c);
  local_8 = 0xffffffff;
  CString::~CString(local_30);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_0040b26f(void *this,bool param_1)

{
  bool bVar1;
  HWND__ *pHVar2;
  int iVar3;
  undefined4 uVar4;
  CString *pCVar5;
  char *pcVar6;
  char cVar7;
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004291ac;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  bVar1 = FUN_0040e0e0((int)this);
  if (bVar1) {
    FUN_0040e488(this,param_1);
  }
  MAP::OnRestore((MAP *)((int)this + 0xe23c),param_1);
  if (param_1) {
    pHVar2 = GKERNEL::GetHwnd();
    CWave::RegisterWindow(pHVar2);
  }
  iVar3 = FUN_004056c0((int)this);
  FUN_004132e0(this,iVar3);
  uVar4 = FUN_004056c0((int)this);
  switch(uVar4) {
  case 1:
    pCVar5 = FUN_004014f0(local_18);
    local_8 = 0;
    operator+(local_14,(char *)pCVar5);
    local_8 = CONCAT31(local_8._1_3_,2);
    CString::~CString(local_18);
    bVar1 = false;
    pcVar6 = (char *)FUN_00401470((undefined4 *)local_14);
    GKTOOLS::TileDIBToSurface((DD_SURFACE *)ddsBack_exref,pcVar6,bVar1);
    GKERNEL::Flip();
    bVar1 = false;
    pcVar6 = (char *)FUN_00401470((undefined4 *)local_14);
    GKTOOLS::TileDIBToSurface((DD_SURFACE *)ddsBack_exref,pcVar6,bVar1);
    FUN_0041c930((int)this);
    local_8 = 0xffffffff;
    CString::~CString(local_14);
    break;
  case 2:
  case 0xd:
    (**(code **)(*(int *)((int)this + 0x228) + 0x20))();
    FUN_0040b710((int)this + 0x2a7c);
    cVar7 = '\0';
    iVar3 = FUN_004056c0((int)this);
    FUN_0041db21(this,iVar3 == 0xd,cVar7);
    break;
  case 3:
    FUN_0041a7ba();
    break;
  case 4:
    FUN_0040d19b((int)this);
    break;
  case 6:
    MAP::RefreshBothLevelmapBuffers((MAP *)((int)this + 0xe23c));
    FUN_00417f6e((int *)this);
    FUN_0040b6f0((int)this + 0x307c);
    FUN_0040b6f0((int)this + 0x31f8);
    FUN_0040b740((int *)((int)this + 0x277c));
    FUN_0040b740((int *)((int)this + 0x28fc));
    FUN_0040b740((int *)((int)this + 0x25fc));
    FUN_0040b740((int *)((int)this + 0x2d7c));
    FUN_0040b740((int *)((int)this + 0x2efc));
    break;
  case 9:
    (**(code **)(**(int **)((int)this + 0x129b4) + 0x10))(param_1);
    break;
  case 10:
    MAP::RefreshBothLevelmapBuffers((MAP *)((int)this + 0xe23c));
    FUN_00417f6e((int *)this);
    break;
  case 0xb:
    MAP::RefreshBothLevelmapBuffers((MAP *)((int)this + 0xe23c));
    FUN_00413ccf();
    if (*(int *)((int)this + 0x130) != 0) {
      (**(code **)(*(int *)((int)this + 0xbdb4) + 0x1c))();
      (**(code **)(*(int *)((int)this + 0xcee0) + 0x1c))();
      *(undefined4 *)((int)this + 0x130) = 0;
    }
    break;
  case 0xc:
    MAP::RefreshBothLevelmapBuffers((MAP *)((int)this + 0xe23c));
    FUN_0041809c((int *)this);
  }
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_0040b580(void *this,uint param_1)

{
  FUN_0040b5b0((CWinApp *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_0040b5b0(CWinApp *param_1)

{
  CWinApp::~CWinApp(param_1);
  return;
}



void __fastcall FUN_0040b5d0(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_0040b650(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



void FUN_0040b650(void *param_1,int param_2)

{
  while (param_2 != 0) {
    FUN_0040b680(param_1,0);
    param_1 = (void *)((int)param_1 + 0x2c);
    param_2 = param_2 + -1;
  }
  return;
}



void * __thiscall FUN_0040b680(void *this,uint param_1)

{
  FUN_00404750((int)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_0040b6b0(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
  return;
}



void __thiscall FUN_0040b6d0(void *this,undefined1 param_1)

{
  *(undefined1 *)((int)this + 0x10) = param_1;
  return;
}



void __fastcall FUN_0040b6f0(int param_1)

{
  *(undefined4 *)(param_1 + 0xd4) = 0;
  FUN_0040b710(param_1);
  return;
}



void __fastcall FUN_0040b710(int param_1)

{
  *(undefined4 *)(param_1 + 0x178) = 1;
  *(undefined4 *)(param_1 + 0x174) = 0;
  return;
}



void __fastcall FUN_0040b740(int *param_1)

{
  char cVar1;
  int iVar2;
  
  iVar2 = FUN_0040b790((int)param_1);
  if (iVar2 == 1) {
    cVar1 = (**(code **)(*param_1 + 0x44))();
    if (cVar1 != '\0') {
      CWave::Play((CWave *)param_1[0x5f],0,0,0);
    }
  }
  FUN_0040b6f0((int)param_1);
  return;
}



undefined4 __fastcall FUN_0040b790(int param_1)

{
  return *(undefined4 *)(param_1 + 0xd4);
}



undefined4 * __fastcall FUN_0040b7b0(undefined4 *param_1)

{
  undefined4 local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004294e3;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_0040c1b0(param_1);
  local_8 = 0;
  FUN_004016a0(param_1 + 0xd,s_Aargon_Deluxe_00434d48,s_Software_Twilight__0043410c);
  local_8._0_1_ = 1;
  param_1[0xe] = 0;
  param_1[0xf] = 0;
  FUN_004016a0(&local_14,s_Aargon_Deluxe_00434d48,s_Software_Twilight__0043410c);
  local_8._0_1_ = 2;
  FUN_00409040(param_1 + 0x10,&local_14,(CWnd *)0x0);
  local_8._0_1_ = 4;
  FUN_00401750(&local_14);
  *(undefined1 *)(param_1 + 0x4a) = 0;
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)(param_1 + 0x4e));
  local_8._0_1_ = 5;
  OVERLAY::OVERLAY((OVERLAY *)(param_1 + 0x55));
  local_8._0_1_ = 6;
  SPRITE::SPRITE((SPRITE *)(param_1 + 0x8a));
  local_8._0_1_ = 7;
  SPRITE::SPRITE((SPRITE *)(param_1 + 0x4d5));
  local_8._0_1_ = 8;
  FUN_0040c640((OVERLAY *)(param_1 + 0x920));
  local_8._0_1_ = 9;
  FUN_0040c8c0(param_1 + 0x97f,param_1 + 0x1792);
  local_8._0_1_ = 10;
  FUN_0040c8c0(param_1 + 0x9df,param_1 + 0x1792);
  local_8._0_1_ = 0xb;
  FUN_0040c8c0(param_1 + 0xa3f,param_1 + 0x1792);
  local_8._0_1_ = 0xc;
  FUN_0040c8c0(param_1 + 0xa9f,param_1 + 0x1792);
  local_8._0_1_ = 0xd;
  FUN_0040c8c0(param_1 + 0xaff,param_1 + 0x1792);
  local_8._0_1_ = 0xe;
  FUN_0040c8c0(param_1 + 0xb5f,param_1 + 0x1792);
  local_8._0_1_ = 0xf;
  FUN_0040c8c0(param_1 + 0xbbf,param_1 + 0x1792);
  local_8._0_1_ = 0x10;
  FUN_0040c640((OVERLAY *)(param_1 + 0xc1f));
  local_8._0_1_ = 0x11;
  FUN_0040c640((OVERLAY *)(param_1 + 0xc7e));
  local_8._0_1_ = 0x12;
  OVERLAY::OVERLAY((OVERLAY *)(param_1 + 0xcdd));
  local_8._0_1_ = 0x13;
  FUN_0040c640((OVERLAY *)(param_1 + 0xd11));
  local_8._0_1_ = 0x14;
  FUN_0040c640((OVERLAY *)(param_1 + 0xd70));
  local_8._0_1_ = 0x15;
  FUN_0040c640((OVERLAY *)(param_1 + 0xdcf));
  local_8._0_1_ = 0x16;
  FUN_0040c640((OVERLAY *)(param_1 + 0xe2e));
  local_8._0_1_ = 0x17;
  FUN_0040c640((OVERLAY *)(param_1 + 0xe8d));
  local_8._0_1_ = 0x18;
  FONT::FONT((FONT *)(param_1 + 0xeec));
  local_8._0_1_ = 0x19;
  FONT::FONT((FONT *)(param_1 + 0x1317));
  local_8._0_1_ = 0x1a;
  CWave::CWave((CWave *)(param_1 + 0x1742));
  local_8._0_1_ = 0x1b;
  CWave::CWave((CWave *)(param_1 + 0x1752));
  local_8._0_1_ = 0x1c;
  CWave::CWave((CWave *)(param_1 + 0x1762));
  local_8._0_1_ = 0x1d;
  CWave::CWave((CWave *)(param_1 + 0x1772));
  local_8._0_1_ = 0x1e;
  CWave::CWave((CWave *)(param_1 + 0x1782));
  local_8._0_1_ = 0x1f;
  CWave::CWave((CWave *)(param_1 + 0x1792));
  local_8._0_1_ = 0x20;
  CWave::CWave((CWave *)(param_1 + 0x17a2));
  local_8._0_1_ = 0x21;
  CWave::CWave((CWave *)(param_1 + 0x17b2));
  local_8._0_1_ = 0x22;
  CWave::CWave((CWave *)(param_1 + 0x17c2));
  local_8._0_1_ = 0x23;
  CMidi::CMidi((CMidi *)(param_1 + 0x17d2));
  local_8._0_1_ = 0x24;
  CMidi::CMidi((CMidi *)(param_1 + 0x1827));
  local_8._0_1_ = 0x25;
  CMidi::CMidi((CMidi *)(param_1 + 0x187c));
  local_8._0_1_ = 0x26;
  CMidi::CMidi((CMidi *)(param_1 + 0x18d1));
  local_8._0_1_ = 0x27;
  OVERLAY::OVERLAY((OVERLAY *)(param_1 + 0x1926));
  local_8._0_1_ = 0x28;
  OVERLAY::OVERLAY((OVERLAY *)(param_1 + 0x195a));
  local_8._0_1_ = 0x29;
  OVERLAY::OVERLAY((OVERLAY *)(param_1 + 0x198e));
  local_8._0_1_ = 0x2a;
  OVERLAY::OVERLAY((OVERLAY *)(param_1 + 0x19c2));
  local_8._0_1_ = 0x2b;
  FUN_00427eb4(param_1 + 0x19f6,0x112c,5,SPRITE_exref);
  local_8._0_1_ = 0x2c;
  SPRITE::SPRITE((SPRITE *)(param_1 + 0x2f6d));
  local_8._0_1_ = 0x2d;
  SPRITE::SPRITE((SPRITE *)(param_1 + 0x33b8));
  local_8._0_1_ = 0x2e;
  param_1[0x3803] = 0;
  FUN_00405850(param_1 + 0x3807);
  FUN_0040c640((OVERLAY *)(param_1 + 0x3809));
  local_8._0_1_ = 0x2f;
  DD_SURFACE::DD_SURFACE((DD_SURFACE *)(param_1 + 0x3869));
  local_8._0_1_ = 0x30;
  MAP::MAP((MAP *)(param_1 + 0x388f));
  local_8._0_1_ = 0x31;
  FUN_00427eb4(param_1 + 0x399f,0x440,0xf,MAP_exref);
  local_8._0_1_ = 0x32;
  FUN_00427eb4(param_1 + 0x498f,4,0x78,CString::CString);
  local_8 = CONCAT31(local_8._1_3_,0x33);
  FUN_0040c180(param_1 + 0x4a08);
  *(undefined1 *)(param_1 + 0x4a0a) = 0;
  FUN_0040c180(param_1 + 0x4a0b);
  TwProgressBar::TwProgressBar((TwProgressBar *)(param_1 + 0x4a0c));
  *param_1 = &PTR_FUN_0042d8dc;
  ExceptionList = local_10;
  return param_1;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_0040bd00(this,10);
  *(undefined ***)this = &PTR_LAB_0042d93c;
  return this;
}



void * __thiscall FUN_0040bcd0(void *this,uint param_1)

{
  FUN_0040c9a0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void * __thiscall FUN_0040bd00(void *this,undefined4 param_1)

{
  FUN_00404b20((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_0042d950;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



void __thiscall FUN_0040bd60(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_44 [11];
  ulong local_18;
  undefined4 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004294f9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00401400();
  bVar1 = FUN_00404cf0((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_18 = CArchive::ReadCount(param_1);
    while (local_18 != 0) {
      local_18 = local_18 - 1;
      FUN_004046f0(local_44);
      local_8 = 0;
      FUN_0040bf30(param_1,local_44,1);
      FUN_0040bed0(this,local_44);
      local_8 = 0xffffffff;
      FUN_00404750((int)local_44);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_14 = *(undefined4 **)((int)this + 4); local_14 != (undefined4 *)0x0;
        local_14 = (undefined4 *)*local_14) {
      FUN_0040bf30(param_1,local_14 + 2,1);
    }
  }
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_0040be40(void *this,uint param_1)

{
  FUN_0040be70((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_0040be70(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00429519;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_0042d950;
  local_8 = 0;
  FUN_0040b5d0((int)param_1);
  local_8 = 0xffffffff;
  FUN_00404b70(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __thiscall FUN_0040bed0(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_0040c000(this,*(undefined4 *)((int)this + 8),0);
  FUN_0040bf70(puVar1 + 2,param_1);
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



void FUN_0040bf30(CArchive *param_1,void *param_2,int param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_00404cf0((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    CArchive::Read(param_1,param_2,param_3 * 0x2c);
  }
  else {
    CArchive::Write(param_1,param_2,param_3 * 0x2c);
  }
  return;
}



void * __thiscall FUN_0040bf70(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  
  uVar1 = param_1[1];
  *(undefined4 *)this = *param_1;
  *(undefined4 *)((int)this + 4) = uVar1;
  *(undefined4 *)((int)this + 8) = param_1[2];
  FUN_0040bfc0((void *)((int)this + 0xc),param_1 + 3);
  CString::operator=((CString *)((int)this + 0x28),(CString *)(param_1 + 10));
  return this;
}



void * __thiscall FUN_0040bfc0(void *this,void *param_1)

{
  if (this != param_1) {
    FUN_00405150((int)this);
    FUN_00404d70(this,(int)param_1);
  }
  return this;
}



undefined4 * __thiscall FUN_0040c000(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0x34);
    iVar3 = FUN_00428190((int)pCVar2);
    local_c = (undefined4 *)(iVar3 + (*(int *)((int)this + 0x18) + -1) * 0x34);
    local_10 = *(int *)((int)this + 0x18);
    while (local_10 = local_10 + -1, -1 < local_10) {
      *local_c = *(undefined4 *)((int)this + 0x10);
      *(undefined4 **)((int)this + 0x10) = local_c;
      local_c = local_c + -0xd;
    }
  }
  puVar1 = *(undefined4 **)((int)this + 0x10);
  *(undefined4 *)((int)this + 0x10) = **(undefined4 **)((int)this + 0x10);
  puVar1[1] = param_1;
  *puVar1 = param_2;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  FUN_0040c0e0(puVar1 + 2,1);
  return puVar1;
}



void FUN_0040c0e0(void *param_1,int param_2)

{
  void *pvVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429541;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  memset(param_1,0,param_2 * 0x2c);
  while (param_2 != 0) {
    pvVar1 = (void *)FUN_00405640(0x2c,param_1);
    local_8 = 0;
    if (pvVar1 != (void *)0x0) {
      FUN_004046f0(pvVar1);
    }
    local_8 = 0xffffffff;
    param_1 = (void *)((int)param_1 + 0x2c);
    param_2 = param_2 + -1;
  }
  ExceptionList = local_10;
  return;
}



DWORD * __fastcall FUN_0040c180(DWORD *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  *param_1 = DVar1;
  return param_1;
}



void FUN_0040c1a0(void)

{
  return;
}



undefined4 * __fastcall FUN_0040c1b0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042955c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_0040c210(param_1 + 5,10);
  local_8 = 0;
  CString::CString((CString *)(param_1 + 0xc));
  *param_1 = &PTR_FUN_0042d964;
  ExceptionList = local_10;
  return param_1;
}



void * __thiscall FUN_0040c210(void *this,undefined4 param_1)

{
  FUN_00404b20((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_0042d9c4;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



void __fastcall FUN_0040c270(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00429579;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_0042d9c4;
  local_8 = 0;
  FUN_0040c400((int)param_1);
  local_8 = 0xffffffff;
  FUN_00404b70(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_0040c2d0(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_10;
  ulong local_c;
  undefined4 *local_8;
  
  FUN_00401400();
  bVar1 = FUN_00404cf0((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      FUN_00408820(param_1,&local_10,1);
      FUN_0040c3a0(this,local_10);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_00408820(param_1,local_8 + 2,1);
    }
  }
  return;
}



void * __thiscall FUN_0040c370(void *this,uint param_1)

{
  FUN_0040c270((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



undefined4 * __thiscall FUN_0040c3a0(void *this,undefined4 param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_0040c480(this,*(undefined4 *)((int)this + 8),0);
  puVar1[2] = param_1;
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



void __fastcall FUN_0040c400(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_00405210(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



undefined4 * __thiscall FUN_0040c480(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0xc);
    iVar3 = FUN_00428190((int)pCVar2);
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
  FUN_0041bfb0(puVar1 + 2,1);
  return puVar1;
}



undefined4 __fastcall FUN_0040c560(int param_1)

{
  GKERNEL::Init(false);
  *(undefined1 *)(param_1 + 0x10) = 1;
  return CONCAT31((int3)((uint)param_1 >> 8),1);
}



void FUN_0040c580(void)

{
  return;
}



void FUN_0040c590(void)

{
  return;
}



void FUN_0040c5a0(void)

{
  return;
}



void __fastcall FUN_0040c5b0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0042959c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_FUN_0042d964;
  local_8 = 0;
  CString::~CString((CString *)(param_1 + 0xc));
  local_8 = 0xffffffff;
  FUN_0040c270(param_1 + 5);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_0040c610(void *this,uint param_1)

{
  FUN_0040c5b0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



OVERLAY * __fastcall FUN_0040c640(OVERLAY *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_004295c9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  OVERLAY::OVERLAY(param_1);
  local_8 = 0;
  FUN_0040c180((DWORD *)(param_1 + 0xd0));
  DD_SURFACE::DD_SURFACE((DD_SURFACE *)(param_1 + 0xdc));
  local_8 = CONCAT31(local_8._1_3_,1);
  *(undefined ***)param_1 = &PTR_FUN_0042d9dc;
  *(undefined ***)(param_1 + 8) = &PTR_FUN_0042d9d8;
  FUN_0040b6f0((int)param_1);
  ExceptionList = local_10;
  return param_1;
}



void FUN_0040c6c0(void)

{
  return;
}



undefined1 __fastcall FUN_0040c6d0(int param_1)

{
  return *(undefined1 *)(param_1 + 0xcc);
}



void __fastcall FUN_0040c6f0(int param_1)

{
  *(undefined1 *)(param_1 + 0xcc) = 1;
  return;
}



void __fastcall FUN_0040c710(int param_1)

{
  *(undefined1 *)(param_1 + 0xcc) = 0;
  return;
}



void __thiscall FUN_0040c730(void *this,undefined4 *param_1)

{
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x2c))(*param_1,param_1[1]);
  return;
}



undefined1 __fastcall FUN_0040c760(int param_1)

{
  return *(undefined1 *)(param_1 + 0xa0);
}



void * __thiscall FUN_0040c780(void *this,uint param_1)

{
  FUN_0040c870((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_0040c7b0(undefined4 *param_1)

{
  DD_SURFACE *local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004295e9;
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
  FUN_0040c820(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_0040c820(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_0042da2c;
  return;
}



void * __thiscall FUN_0040c840(void *this,uint param_1)

{
  FUN_0040c820((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_0040c870(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00429609;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(param_1 + 0x37));
  local_8 = 0xffffffff;
  FUN_0040c7b0(param_1);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_0040c8c0(void *this,undefined4 param_1)

{
  FUN_0040c640((OVERLAY *)this);
  *(undefined4 *)((int)this + 0x17c) = param_1;
  *(undefined ***)this = &PTR_FUN_0042da58;
  *(undefined ***)((int)this + 8) = &PTR_FUN_0042da54;
  return this;
}



void __fastcall FUN_0040c900(undefined4 *param_1)

{
  FUN_0040c870(param_1);
  return;
}



void __thiscall FUN_0040c920(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 0x129b0) = param_1;
  return;
}



void FUN_0040c940(char param_1)

{
  CMidi::PauseAll(param_1 == '\0');
  return;
}



void * __thiscall FUN_0040c970(void *this,uint param_1)

{
  FUN_0040c9e0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_0040c9a0(undefined4 *param_1)

{
  FUN_0040be70(param_1);
  return;
}



void __fastcall FUN_0040c9c0(DD_SURFACE *param_1)

{
  DD_SURFACE::~DD_SURFACE(param_1);
  return;
}



void __fastcall FUN_0040c9e0(undefined4 *param_1)

{
  undefined4 *local_18;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &this_00429956;
  local_10 = ExceptionList;
  local_8 = 0x31;
  ExceptionList = &local_10;
  FUN_0040cdf0(param_1 + 0x4a0c);
  local_8._0_1_ = 0x30;
  FUN_00427dc0(param_1 + 0x498f,4,0x78,CString::~CString);
  local_8._0_1_ = 0x2f;
  FUN_00427dc0(param_1 + 0x399f,0x440,0xf,~MAP_exref);
  local_8._0_1_ = 0x2e;
  MAP::~MAP((MAP *)(param_1 + 0x388f));
  local_8._0_1_ = 0x2d;
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(param_1 + 0x3869));
  local_8._0_1_ = 0x2c;
  FUN_0040c870(param_1 + 0x3809);
  local_8._0_1_ = 0x2b;
  SPRITE::~SPRITE((SPRITE *)(param_1 + 0x33b8));
  local_8._0_1_ = 0x2a;
  SPRITE::~SPRITE((SPRITE *)(param_1 + 0x2f6d));
  local_8._0_1_ = 0x29;
  FUN_00427dc0(param_1 + 0x19f6,0x112c,5,~SPRITE_exref);
  local_8._0_1_ = 0x28;
  FUN_0040c7b0(param_1 + 0x19c2);
  local_8._0_1_ = 0x27;
  FUN_0040c7b0(param_1 + 0x198e);
  local_8._0_1_ = 0x26;
  FUN_0040c7b0(param_1 + 0x195a);
  local_8._0_1_ = 0x25;
  FUN_0040c7b0(param_1 + 0x1926);
  local_8._0_1_ = 0x24;
  CMidi::~CMidi((CMidi *)(param_1 + 0x18d1));
  local_8._0_1_ = 0x23;
  CMidi::~CMidi((CMidi *)(param_1 + 0x187c));
  local_8._0_1_ = 0x22;
  CMidi::~CMidi((CMidi *)(param_1 + 0x1827));
  local_8._0_1_ = 0x21;
  CMidi::~CMidi((CMidi *)(param_1 + 0x17d2));
  local_8._0_1_ = 0x20;
  CWave::~CWave((CWave *)(param_1 + 0x17c2));
  local_8._0_1_ = 0x1f;
  CWave::~CWave((CWave *)(param_1 + 0x17b2));
  local_8._0_1_ = 0x1e;
  CWave::~CWave((CWave *)(param_1 + 0x17a2));
  local_8._0_1_ = 0x1d;
  CWave::~CWave((CWave *)(param_1 + 0x1792));
  local_8._0_1_ = 0x1c;
  CWave::~CWave((CWave *)(param_1 + 0x1782));
  local_8._0_1_ = 0x1b;
  CWave::~CWave((CWave *)(param_1 + 0x1772));
  local_8._0_1_ = 0x1a;
  CWave::~CWave((CWave *)(param_1 + 0x1762));
  local_8._0_1_ = 0x19;
  CWave::~CWave((CWave *)(param_1 + 0x1752));
  local_8._0_1_ = 0x18;
  CWave::~CWave((CWave *)(param_1 + 0x1742));
  local_8._0_1_ = 0x17;
  FUN_0040c9c0((DD_SURFACE *)(param_1 + 0x1317));
  local_8._0_1_ = 0x16;
  FUN_0040c9c0((DD_SURFACE *)(param_1 + 0xeec));
  local_8._0_1_ = 0x15;
  FUN_0040c870(param_1 + 0xe8d);
  local_8._0_1_ = 0x14;
  FUN_0040c870(param_1 + 0xe2e);
  local_8._0_1_ = 0x13;
  FUN_0040c870(param_1 + 0xdcf);
  local_8._0_1_ = 0x12;
  FUN_0040c870(param_1 + 0xd70);
  local_8._0_1_ = 0x11;
  FUN_0040c870(param_1 + 0xd11);
  local_8._0_1_ = 0x10;
  FUN_0040c7b0(param_1 + 0xcdd);
  local_8._0_1_ = 0xf;
  FUN_0040c870(param_1 + 0xc7e);
  local_8._0_1_ = 0xe;
  FUN_0040c870(param_1 + 0xc1f);
  local_8._0_1_ = 0xd;
  FUN_0040c900(param_1 + 0xbbf);
  local_8._0_1_ = 0xc;
  FUN_0040c900(param_1 + 0xb5f);
  local_8._0_1_ = 0xb;
  FUN_0040c900(param_1 + 0xaff);
  local_8._0_1_ = 10;
  FUN_0040c900(param_1 + 0xa9f);
  local_8._0_1_ = 9;
  FUN_0040c900(param_1 + 0xa3f);
  local_8._0_1_ = 8;
  FUN_0040c900(param_1 + 0x9df);
  local_8._0_1_ = 7;
  FUN_0040c900(param_1 + 0x97f);
  local_8._0_1_ = 6;
  FUN_0040c870(param_1 + 0x920);
  local_8._0_1_ = 5;
  SPRITE::~SPRITE((SPRITE *)(param_1 + 0x4d5));
  local_8._0_1_ = 4;
  SPRITE::~SPRITE((SPRITE *)(param_1 + 0x8a));
  local_8._0_1_ = 3;
  FUN_0040c7b0(param_1 + 0x55);
  local_8._0_1_ = 2;
  FUN_0040c9a0(param_1 + 0x4e);
  local_8._0_1_ = 1;
  FUN_00409ef0((CDialog *)(param_1 + 0x10));
  local_8 = (uint)local_8._1_3_ << 8;
  if (param_1 == (undefined4 *)0x0) {
    local_18 = (undefined4 *)0x0;
  }
  else {
    local_18 = param_1 + 0xd;
  }
  FUN_00401750(local_18);
  local_8 = 0xffffffff;
  FUN_0040c5b0(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_0040cdf0(undefined4 *param_1)

{
  FUN_0040ce10(param_1);
  return;
}



void __fastcall FUN_0040ce10(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00429969;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(param_1 + 0x34));
  local_8 = 0xffffffff;
  FUN_0040c7b0(param_1);
  ExceptionList = local_10;
  return;
}



void FUN_0040ce60(void)

{
  FUN_0040ce6f();
  FUN_0040ce7e();
  return;
}



void FUN_0040ce6f(void)

{
  FUN_0040d6a0((OVERLAY *)&DAT_00448df0);
  return;
}



void FUN_0040ce7e(void)

{
  FUN_00427dae(FUN_0040ce90);
  return;
}



void FUN_0040ce90(void)

{
  FUN_0040c900((undefined4 *)&DAT_00448df0);
  return;
}



void FUN_0040ce9f(void)

{
  FUN_0040ceae();
  FUN_0040cebd();
  return;
}



void FUN_0040ceae(void)

{
  FUN_0040d6a0((OVERLAY *)&DAT_00448970);
  return;
}



void FUN_0040cebd(void)

{
  FUN_00427dae(FUN_0040cecf);
  return;
}



void FUN_0040cecf(void)

{
  FUN_0040c900((undefined4 *)&DAT_00448970);
  return;
}



void FUN_0040cede(void)

{
  FUN_0040ceed();
  FUN_0040cefc();
  return;
}



void FUN_0040ceed(void)

{
  FUN_0040d6a0((OVERLAY *)&DAT_00448c70);
  return;
}



void FUN_0040cefc(void)

{
  FUN_00427dae(FUN_0040cf0e);
  return;
}



void FUN_0040cf0e(void)

{
  FUN_0040c900((undefined4 *)&DAT_00448c70);
  return;
}



void FUN_0040cf1d(void)

{
  FUN_0040cf2c();
  FUN_0040cf3b();
  return;
}



void FUN_0040cf2c(void)

{
  FUN_0040d6a0((OVERLAY *)&DAT_00448af0);
  return;
}



void FUN_0040cf3b(void)

{
  FUN_00427dae(FUN_0040cf4d);
  return;
}



void FUN_0040cf4d(void)

{
  FUN_0040c900((undefined4 *)&DAT_00448af0);
  return;
}



void __fastcall FUN_0040cf5c(int param_1)

{
  undefined1 uVar1;
  CString *pCVar2;
  char *pcVar3;
  undefined3 extraout_var;
  bool bVar4;
  CString local_30 [4];
  CString local_2c [4];
  CString local_28 [4];
  CString local_24 [4];
  CString local_20 [4];
  CString local_1c [4];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_2_004299c8;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pCVar2 = FUN_004014f0(local_18);
  local_8 = 0;
  operator+(local_14,(char *)pCVar2);
  local_8._0_1_ = 2;
  CString::~CString(local_18);
  bVar4 = false;
  pcVar3 = (char *)FUN_00401470((undefined4 *)local_14);
  TwAutoButton::Init((TwAutoButton *)&DAT_00448df0,pcVar3,bVar4);
  OVERLAY::SetPosition((OVERLAY *)&DAT_00448df0,0x1e,0x19a);
  uVar1 = FUN_00414141(param_1);
  if (CONCAT31(extraout_var,uVar1) == 0) {
    pCVar2 = FUN_004014f0(local_1c);
    local_8._0_1_ = 3;
    pCVar2 = (CString *)operator+(local_20,(char *)pCVar2);
    local_8._0_1_ = 4;
    CString::operator=(local_14,pCVar2);
    local_8._0_1_ = 3;
    CString::~CString(local_20);
    local_8._0_1_ = 2;
    CString::~CString(local_1c);
    bVar4 = false;
    pcVar3 = (char *)FUN_00401470((undefined4 *)local_14);
    TwAutoButton::Init((TwAutoButton *)&DAT_00448af0,pcVar3,bVar4);
    OVERLAY::SetPosition((OVERLAY *)&DAT_00448af0,0x1e,0x19a);
  }
  pCVar2 = FUN_004014f0(local_24);
  local_8._0_1_ = 5;
  pCVar2 = (CString *)operator+(local_28,(char *)pCVar2);
  local_8._0_1_ = 6;
  CString::operator=(local_14,pCVar2);
  local_8._0_1_ = 5;
  CString::~CString(local_28);
  local_8._0_1_ = 2;
  CString::~CString(local_24);
  bVar4 = false;
  pcVar3 = (char *)FUN_00401470((undefined4 *)local_14);
  TwAutoButton::Init((TwAutoButton *)&DAT_00448970,pcVar3,bVar4);
  OVERLAY::SetPosition((OVERLAY *)&DAT_00448970,400,0x19a);
  pCVar2 = FUN_004014f0(local_2c);
  local_8._0_1_ = 7;
  pCVar2 = (CString *)operator+(local_30,(char *)pCVar2);
  local_8._0_1_ = 8;
  CString::operator=(local_14,pCVar2);
  local_8._0_1_ = 7;
  CString::~CString(local_30);
  local_8 = CONCAT31(local_8._1_3_,2);
  CString::~CString(local_2c);
  bVar4 = false;
  pcVar3 = (char *)FUN_00401470((undefined4 *)local_14);
  TwAutoButton::Init((TwAutoButton *)&DAT_00448c70,pcVar3,bVar4);
  OVERLAY::SetPosition((OVERLAY *)&DAT_00448c70,400,0x19a);
  local_8 = 0xffffffff;
  CString::~CString(local_14);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_0040d19b(int param_1)

{
  undefined1 uVar1;
  bool bVar2;
  undefined3 extraout_var;
  int iVar3;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  CString *pCVar4;
  char *pcVar5;
  uint uVar6;
  uint uVar7;
  CString local_28 [4];
  CString local_24 [4];
  CString local_20 [4];
  CString local_1c [4];
  CString local_18 [4];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004299ff;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  uVar1 = FUN_00414141(param_1);
  if (CONCAT31(extraout_var,uVar1) == 0) {
    FUN_0040c6f0(0x448af0);
  }
  else {
    FUN_0040c6f0(0x448df0);
  }
  FUN_0040c6f0(0x448970);
  FUN_0040c6f0(0x448c70);
  iVar3 = FUN_0040e0c0(param_1);
  if ((iVar3 != 1) && (*(char *)(param_1 + 0x12828) == '\0')) {
    bVar2 = FUN_00414159(param_1);
    if (CONCAT31(extraout_var_00,bVar2) == 0) {
      FUN_0040c710(0x448c70);
      goto LAB_0040d22d;
    }
  }
  FUN_0040c710(0x448970);
LAB_0040d22d:
  FUN_0040b710(0x448df0);
  FUN_0040b710(0x448970);
  FUN_0040b710(0x448af0);
  FUN_0040b710(0x448c70);
  GKERNEL::NewSpriteBackground();
  CString::CString(local_18);
  local_8 = 0;
  uVar1 = FUN_00414141(param_1);
  if (CONCAT31(extraout_var_01,uVar1) == 0) {
    pCVar4 = FUN_004014f0(local_1c);
    local_8._0_1_ = 1;
    pCVar4 = (CString *)operator+(local_20,(char *)pCVar4);
    local_8._0_1_ = 2;
    CString::operator=(local_18,pCVar4);
    local_8._0_1_ = 1;
    CString::~CString(local_20);
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_1c);
  }
  else {
    pCVar4 = FUN_004014f0(local_24);
    local_8._0_1_ = 3;
    pCVar4 = (CString *)operator+(local_28,(char *)pCVar4);
    local_8._0_1_ = 4;
    CString::operator=(local_18,pCVar4);
    local_8._0_1_ = 3;
    CString::~CString(local_28);
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_24);
  }
  for (local_14 = 0; local_14 < 2; local_14 = local_14 + 1) {
    bVar2 = false;
    uVar7 = 0;
    uVar6 = 0;
    pcVar5 = (char *)FUN_00401470((undefined4 *)local_18);
    GKTOOLS::CopyDIBToSurface((DD_SURFACE *)ddsBack_exref,pcVar5,uVar6,uVar7,bVar2);
    GKERNEL::Flip();
  }
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_0040d38b(int param_1)

{
  undefined1 uVar1;
  undefined3 extraout_var;
  
  uVar1 = FUN_00414141(param_1);
  if (CONCAT31(extraout_var,uVar1) == 0) {
    BUTTON::DrawToBack((BUTTON *)&DAT_00448af0);
  }
  else {
    BUTTON::DrawToBack((BUTTON *)&DAT_00448df0);
  }
  BUTTON::DrawToBack((BUTTON *)&DAT_00448970);
  BUTTON::DrawToBack((BUTTON *)&DAT_00448c70);
  return;
}



void FUN_0040d3d0(char param_1)

{
  bool bVar1;
  
  TwAutoButton::Up((TwAutoButton *)&DAT_00448df0);
  TwAutoButton::Up((TwAutoButton *)&DAT_00448af0);
  TwAutoButton::Up((TwAutoButton *)&DAT_00448970);
  TwAutoButton::Up((TwAutoButton *)&DAT_00448c70);
  if (param_1 != '\0') {
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_00448df0);
    if (bVar1) {
      TwAutoButton::Down((TwAutoButton *)&DAT_00448df0);
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_00448af0);
    if (bVar1) {
      TwAutoButton::Down((TwAutoButton *)&DAT_00448af0);
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_00448970);
    if (bVar1) {
      TwAutoButton::Down((TwAutoButton *)&DAT_00448970);
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_00448c70);
    if (bVar1) {
      TwAutoButton::Down((TwAutoButton *)&DAT_00448c70);
    }
  }
  return;
}



void __fastcall FUN_0040d491(GAME *param_1)

{
  bool bVar1;
  undefined1 uVar2;
  undefined3 extraout_var;
  CString *pCVar3;
  undefined4 *puVar4;
  char *pcVar5;
  CHyperLink *this;
  char *pcVar6;
  int iVar7;
  CString local_110 [4];
  CHyperLink local_10c [200];
  CString local_44 [4];
  CString local_40 [4];
  SECTION local_3c [8];
  INIFILE local_34 [36];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_00429a47;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_00448970);
  if (bVar1) {
    GAME::StateReturn(param_1);
  }
  bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_00448c70);
  if (bVar1) {
    GKERNEL::Stop();
  }
  else {
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_00448df0);
    if ((!bVar1) && (bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_00448af0), !bVar1)) {
      ExceptionList = local_10;
      return;
    }
    uVar2 = FUN_00414141((int)param_1);
    if (CONCAT31(extraout_var,uVar2) == 0) {
      ShowMouse(true);
      FUN_0040a219((int *)(*(int *)(param_1 + 0x38) + 0x194));
    }
    else {
      pcVar6 = s_GAME_INI_00434df8;
      pCVar3 = FUN_004014f0(local_40);
      local_8 = 0;
      puVar4 = (undefined4 *)operator+(local_44,(char *)pCVar3);
      local_8._0_1_ = 1;
      pcVar5 = (char *)FUN_00401470(puVar4);
      INIFILE::INIFILE(local_34,pcVar5,(int)pcVar6);
      local_8._0_1_ = 4;
      CString::~CString(local_44);
      local_8._0_1_ = 3;
      CString::~CString(local_40);
      FUN_00408bc0(local_3c,local_34,s_Purchase_00434e04);
      local_8._0_1_ = 5;
      iVar7 = 5;
      puVar4 = (undefined4 *)INIFILE::SECTION::Get(local_3c,(char *)local_110);
      local_8._0_1_ = 6;
      pcVar5 = (char *)FUN_00401470(puVar4);
      this = (CHyperLink *)CHyperLink::CHyperLink(local_10c);
      local_8._0_1_ = 7;
      CHyperLink::GotoURL(this,pcVar5,iVar7);
      local_8._0_1_ = 6;
      CHyperLink::~CHyperLink(local_10c);
      local_8._0_1_ = 5;
      FUN_004014d0(local_110);
      local_8 = CONCAT31(local_8._1_3_,3);
      FUN_00407d90((int)local_3c);
      local_8 = 0xffffffff;
      INIFILE::~INIFILE(local_34);
    }
  }
  ExceptionList = local_10;
  return;
}



OVERLAY * __fastcall FUN_0040d6a0(OVERLAY *param_1)

{
  FUN_0040c640(param_1);
  *(undefined ***)param_1 = &PTR_FUN_0042daac;
  *(undefined ***)(param_1 + 8) = &PTR_FUN_0042daa8;
  return param_1;
}



void * __thiscall FUN_0040d6d0(void *this,uint param_1)

{
  FUN_0040c900((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_0040d700(GAME *param_1)

{
  bool bVar1;
  char cVar2;
  HWND__ *pHVar3;
  CWnd *pCVar4;
  int iVar5;
  undefined4 *puVar6;
  CString *pCVar7;
  CString local_80 [4];
  undefined4 local_7c [2];
  TwDirectXDialog local_74 [96];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429a72;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  if (((param_1[0xe014] == (GAME)0x0) &&
      (ExceptionList = &local_10, bVar1 = FUN_0040e0e0((int)param_1), bVar1)) &&
     (cVar2 = FUN_0040f42e(), cVar2 != '\0')) {
    pHVar3 = GKERNEL::GetHwnd();
    pCVar4 = CWnd::FromHandle(pHVar3);
    FUN_00409fb0(local_74,pCVar4);
    local_8 = 0;
    CString::operator=(local_14,s_Reset_and_lose_changes__00434e14);
    iVar5 = TwDirectXDialog::DoModal(local_74);
    if (iVar5 == 2) {
      local_8 = 0xffffffff;
      FUN_004048f0((CDialog *)local_74);
      ExceptionList = local_10;
      return;
    }
    local_8 = 0xffffffff;
    FUN_004048f0((CDialog *)local_74);
  }
  GAME::ChangeState(param_1,8);
  MAP::DestroyMovingObjects((MAP *)(param_1 + 0xe23c));
  if (param_1[0xe014] == (GAME)0x0) {
    puVar6 = FUN_00405910(param_1 + 0xe23c,local_7c);
    MAP::Load((MAP *)(param_1 + 0xe23c),*puVar6,puVar6[1]);
  }
  else {
    pCVar7 = FUN_0040fcfb(local_80);
    local_8 = 1;
    MAP::Set((MAP *)(param_1 + 0xe23c),pCVar7);
    local_8 = 0xffffffff;
    CString::~CString(local_80);
  }
  MAP::WipeErase((MAP *)(param_1 + 0xe23c));
  MAP::WipeReset((MAP *)(param_1 + 0xe23c));
  FUN_00417f6e((int *)param_1);
  GAME::ChangeState(param_1,6);
  ExceptionList = local_10;
  return;
}



// WARNING: Heritage AFTER dead removal. Example location: s0xffffffd4 : 0x0040dade
// WARNING: Restarted to delay deadcode elimination for space: stack

void __fastcall FUN_0040d885(int param_1)

{
  ITEM *pIVar1;
  int *piVar2;
  undefined4 *puVar3;
  int iVar4;
  double dVar5;
  undefined1 local_108 [8];
  undefined1 local_100 [8];
  undefined1 local_f8 [8];
  undefined1 local_f0 [8];
  undefined1 local_e8 [8];
  undefined1 local_e0 [8];
  undefined1 local_d8 [8];
  undefined1 local_d0 [8];
  undefined1 local_c8 [8];
  undefined1 local_c0 [8];
  undefined1 local_b8 [8];
  undefined1 local_b0 [8];
  undefined1 local_a8 [8];
  undefined1 local_a0 [8];
  undefined1 local_98 [8];
  undefined1 local_90 [8];
  undefined1 local_88 [8];
  undefined1 local_80 [8];
  ITEM *local_78;
  int local_74 [9];
  uint local_50;
  undefined4 local_4c [18];
  
  local_74[0] = 0;
  piVar2 = local_74;
  for (iVar4 = 8; piVar2 = piVar2 + 1, iVar4 != 0; iVar4 = iVar4 + -1) {
    *piVar2 = 0;
  }
  FUN_0040df80(local_4c,8,9,FUN_00405850);
  for (local_50 = 0; local_50 < 9; local_50 = local_50 + 1) {
    pIVar1 = MAP::FindItem(s_EXPLOSION_00434e2c);
    iVar4 = (**(code **)(*(int *)pIVar1 + 4))();
    local_74[local_50] = iVar4;
    (**(code **)(*(int *)local_74[local_50] + 0xc))();
  }
  piVar2 = (int *)default_error_condition(local_80,0xffffffff,0xffffffff);
  puVar3 = (undefined4 *)FUN_0040dff0(&stack0x00000004,local_88,piVar2);
  local_4c[0] = *puVar3;
  local_4c[1] = puVar3[1];
  piVar2 = (int *)default_error_condition(local_90,0,0xffffffff);
  puVar3 = (undefined4 *)FUN_0040dff0(&stack0x00000004,local_98,piVar2);
  local_4c[2] = *puVar3;
  local_4c[3] = puVar3[1];
  piVar2 = (int *)default_error_condition(local_a0,1,0xffffffff);
  puVar3 = (undefined4 *)FUN_0040dff0(&stack0x00000004,local_a8,piVar2);
  local_4c[4] = *puVar3;
  local_4c[5] = puVar3[1];
  piVar2 = (int *)default_error_condition(local_b0,0xffffffff,0);
  puVar3 = (undefined4 *)FUN_0040dff0(&stack0x00000004,local_b8,piVar2);
  local_4c[6] = *puVar3;
  local_4c[7] = puVar3[1];
  piVar2 = (int *)default_error_condition(local_c0,0,0);
  puVar3 = (undefined4 *)FUN_0040dff0(&stack0x00000004,local_c8,piVar2);
  local_4c[8] = *puVar3;
  local_4c[9] = puVar3[1];
  piVar2 = (int *)default_error_condition(local_d0,1,0);
  puVar3 = (undefined4 *)FUN_0040dff0(&stack0x00000004,local_d8,piVar2);
  local_4c[10] = *puVar3;
  local_4c[0xb] = puVar3[1];
  piVar2 = (int *)default_error_condition(local_e0,0xffffffff,1);
  puVar3 = (undefined4 *)FUN_0040dff0(&stack0x00000004,local_e8,piVar2);
  local_4c[0xc] = *puVar3;
  local_4c[0xd] = puVar3[1];
  piVar2 = (int *)default_error_condition(local_f0,0,1);
  puVar3 = (undefined4 *)FUN_0040dff0(&stack0x00000004,local_f8,piVar2);
  local_4c[0xe] = *puVar3;
  local_4c[0xf] = puVar3[1];
  piVar2 = (int *)default_error_condition(local_100,1,1);
  puVar3 = (undefined4 *)FUN_0040dff0(&stack0x00000004,local_108,piVar2);
  local_4c[0x10] = *puVar3;
  local_4c[0x11] = puVar3[1];
  for (local_50 = 0; local_50 < 9; local_50 = local_50 + 1) {
    local_78 = MAP::GetItem((MAP *)(param_1 + 0xe23c),local_4c[local_50 * 2],
                            local_4c[local_50 * 2 + 1]);
    if (local_50 == 4) {
      pIVar1 = MAP::SetItem((MAP *)(param_1 + 0xe23c),local_4c[8],local_4c[9],local_74[4]);
      if (pIVar1 != (ITEM *)0x0) {
        (*(code *)**(undefined4 **)pIVar1)(1);
      }
    }
    else {
      iVar4 = FUN_00423770((int)local_78);
      if (iVar4 == 1) {
        if ((undefined4 *)local_74[local_50] != (undefined4 *)0x0) {
          (*(code *)**(undefined4 **)local_74[local_50])(1);
        }
      }
      else {
        MAP::SetItem((MAP *)(param_1 + 0xe23c),local_4c[local_50 * 2],local_4c[local_50 * 2 + 1],
                     local_74[local_50]);
        iVar4 = (**(code **)(*(int *)local_78 + 0x4c))();
        if (iVar4 != 0) {
          FUN_0040e080((void *)local_74[local_50],1);
          FUN_0040e0a0((void *)local_74[local_50],3);
        }
        if (local_78 != (ITEM *)0x0) {
          (*(code *)**(undefined4 **)local_78)(1);
        }
      }
    }
  }
  dVar5 = RandomProb();
  if (0.5 <= dVar5) {
    CWave::Play((CWave *)(param_1 + 0x5d48),0,0,0);
  }
  else {
    CWave::Play((CWave *)(param_1 + 0x5d08),0,0,0);
  }
  return;
}



void __fastcall FUN_0040dc77(GAME *param_1)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  undefined3 extraout_var;
  undefined4 *puVar4;
  undefined3 extraout_var_00;
  undefined1 local_54;
  undefined1 local_44 [8];
  undefined1 local_3c [8];
  undefined1 local_34 [8];
  undefined1 local_2c [8];
  uint local_24;
  char local_20;
  undefined3 uStack_1f;
  uint local_1c;
  uint local_18;
  ITEM *local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  bVar2 = FUN_0040e0e0((int)param_1);
  if (!bVar2) {
    if ((DAT_00448f74 & 1) == 0) {
      DAT_00448f74 = DAT_00448f74 | 1;
      FUN_0040c180((DWORD *)&DAT_00448f6c);
      FUN_00427dae(FUN_0040df74);
    }
    if ((DAT_00448f74 & 2) == 0) {
      DAT_00448f74 = DAT_00448f74 | 2;
      FUN_0040c180((DWORD *)&DAT_00448f70);
      FUN_00427dae(FUN_0040df6f);
    }
    local_10 = local_10 & 0xffffff00;
    local_18 = local_18 & 0xffffff00;
    iVar3 = FUN_004056c0((int)param_1);
    if ((iVar3 == 7) &&
       (bVar2 = FUN_0040dfb0(&DAT_00448f70,0x28), CONCAT31(extraout_var,bVar2) != 0)) {
      local_10 = CONCAT31(local_10._1_3_,1);
    }
    local_8 = local_8 & 0xffffff00;
    puVar4 = (undefined4 *)default_error_condition(local_2c,0,0);
    local_14 = MAP::GetItem((MAP *)(param_1 + 0xe23c),*puVar4,puVar4[1]);
    local_c = 0;
    while ((local_c < 0x14 && ((local_8 & 0xff) == 0))) {
      local_1c = 0;
      while ((local_1c < 0xd && ((local_8 & 0xff) == 0))) {
        iVar3 = (**(code **)(*(int *)local_14 + 0x48))();
        if ((iVar3 == 1) && (iVar3 = (**(code **)(*(int *)local_14 + 0x4c))(), iVar3 != 0)) {
          local_54 = 1;
        }
        else {
          local_54 = 0;
        }
        local_24 = CONCAT31(local_24._1_3_,local_54);
        iVar3 = FUN_00423770((int)local_14);
        if ((iVar3 == 1) && (iVar3 = FUN_0040e0c0((int)local_14), iVar3 == 0)) {
          cVar1 = '\x01';
        }
        else {
          cVar1 = '\0';
        }
        _local_20 = CONCAT31(uStack_1f,cVar1);
        if (((local_24 & 0xff) == 0) && (cVar1 == '\0')) {
          iVar3 = FUN_00423770((int)local_14);
          if ((iVar3 == 1) && ((local_10 & 0xff) != 0)) {
            iVar3 = FUN_0040e0c0((int)local_14);
            FUN_0040e0a0(local_14,iVar3 + -1);
          }
        }
        else {
          (**(code **)(*(int *)local_14 + 0x74))(local_44);
          FUN_0040d885((int)param_1);
          iVar3 = FUN_004056c0((int)param_1);
          if (iVar3 != 7) {
            FUN_0040b6b0((DWORD *)&DAT_00448f70);
          }
          GAME::ChangeState(param_1,7);
          local_18 = CONCAT31(local_18._1_3_,1);
          FUN_0040b6b0((DWORD *)&DAT_00448f6c);
        }
        local_1c = local_1c + 1;
        if (local_1c < 0xd) {
          puVar4 = (undefined4 *)default_error_condition(local_34,local_c,local_1c);
          local_14 = MAP::GetItem((MAP *)(param_1 + 0xe23c),*puVar4,puVar4[1]);
        }
        else if (local_c < 0x13) {
          puVar4 = (undefined4 *)default_error_condition(local_3c,local_c + 1,0);
          local_14 = MAP::GetItem((MAP *)(param_1 + 0xe23c),*puVar4,puVar4[1]);
        }
      }
      local_c = local_c + 1;
    }
    iVar3 = FUN_004056c0((int)param_1);
    if (((iVar3 == 7) && ((local_18 & 0xff) == 0)) &&
       (bVar2 = FUN_0040dfb0(&DAT_00448f6c,0x5dc), CONCAT31(extraout_var_00,bVar2) != 0)) {
      GAME::ChangeState(param_1,10);
    }
  }
  return;
}



void FUN_0040df6f(void)

{
  return;
}



void FUN_0040df74(void)

{
  return;
}



void FUN_0040df80(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  while (param_3 = param_3 + -1, -1 < param_3) {
    (*(code *)param_4)();
  }
  return;
}



bool __thiscall FUN_0040dfb0(void *this,uint param_1)

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



void * __thiscall FUN_0040dff0(void *this,void *param_1,int *param_2)

{
  undefined4 *puVar1;
  undefined1 local_14 [8];
  int local_c;
  int local_8;
  
  local_c = *param_2;
  local_8 = param_2[1];
  puVar1 = (undefined4 *)FID_conflict_operator_(this,local_14,local_c,local_8);
  FUN_0040e060(param_1,puVar1);
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
  FUN_004163a0(param_1,*this + param_2,*(int *)((int)this + 4) + param_3);
  return param_1;
}



void * __thiscall FUN_0040e060(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  
  uVar1 = param_1[1];
  *(undefined4 *)this = *param_1;
  *(undefined4 *)((int)this + 4) = uVar1;
  return this;
}



void __thiscall FUN_0040e080(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 4) = param_1;
  return;
}



void __thiscall FUN_0040e0a0(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 8) = param_1;
  return;
}



undefined4 __fastcall FUN_0040e0c0(int param_1)

{
  return *(undefined4 *)(param_1 + 8);
}



bool __fastcall FUN_0040e0e0(int param_1)

{
  return *(int *)(param_1 + 0xe010) != 0;
}



void __thiscall FUN_0040e0fc(void *this,int param_1)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  TwDirectXDialog local_74 [96];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429a89;
  local_10 = ExceptionList;
  if (param_1 != 1) {
    return;
  }
  ExceptionList = &local_10;
  bVar1 = FUN_0040e0e0((int)this);
  if (bVar1) {
    FUN_00409fb0(local_74,(CWnd *)((HWND)((int)this + 0xe010))->unused);
    local_8 = 0;
    CString::operator=(local_14,s_Exit_and_lose_changes__00434e38);
    if ((((char)((HWND)((int)this + 0xe014))->unused == '\0') &&
        (cVar2 = FUN_0040f42e(), cVar2 != '\0')) &&
       (iVar3 = TwDirectXDialog::DoModal(local_74), iVar3 != 1)) {
      CWnd::SetFocus((HWND)this);
    }
    else {
      FUN_0040e1ce(this,'\0');
    }
    local_8 = 0xffffffff;
    FUN_004048f0((CDialog *)local_74);
    ExceptionList = local_10;
    return;
  }
  FUN_0040e1ce(this,'\x01');
  ExceptionList = local_10;
  return;
}



undefined4 __thiscall FUN_0040e1ce(void *this,char param_1)

{
  bool bVar1;
  void *pvVar2;
  HWND__ *pHVar3;
  CWnd *pCVar4;
  int iVar5;
  char cVar6;
  int in_stack_ffffffd4;
  void *local_28;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429a9d;
  local_10 = ExceptionList;
  if (param_1 == '\0') {
    ExceptionList = &local_10;
    if ((*(int *)((int)this + 0xe010) != 0) &&
       (ExceptionList = &local_10, *(int *)(*(int *)((int)this + 0xe010) + 0x20) != 0)) {
      ExceptionList = &local_10;
      (**(code **)(*(int *)((int)this + 0x1354) + 0x20))();
      GKERNEL::EnableAltEnter(true);
      (**(code **)(**(int **)((int)this + 0xe010) + 0x60))();
      if (*(int **)((int)this + 0xe010) != (int *)0x0) {
        (**(code **)(**(int **)((int)this + 0xe010) + 4))(1);
      }
      *(undefined4 *)((int)this + 0xe010) = 0;
    }
  }
  else {
    if (*(char *)((int)this + 0xe015) == '\0') {
      ExceptionList = &local_10;
      bVar1 = GKERNEL::Windowed();
      if ((!bVar1) && (bVar1 = GKERNEL::SetWindowedMode(true), !bVar1)) {
        ExceptionList = local_10;
        return 0;
      }
      GKERNEL::EnableAltEnter(false);
    }
    else {
      ExceptionList = &local_10;
      (**(code **)(*(int *)((int)this + 0x1354) + 0x1c))();
    }
    pvVar2 = (void *)FUN_0040fd70(0xcc);
    local_8 = 0;
    if (pvVar2 == (void *)0x0) {
      local_28 = (void *)0x0;
    }
    else {
      local_28 = FUN_00401830(pvVar2,(CWnd *)0x0);
    }
    local_8 = 0xffffffff;
    *(void **)((int)this + 0xe010) = local_28;
    *(void **)(*(int *)((int)this + 0xe010) + 0x88) = this;
    pHVar3 = GKERNEL::GetHwnd();
    pCVar4 = CWnd::FromHandle(pHVar3);
    FUN_0040fe50(*(void **)((int)this + 0xe010),0x87,pCVar4);
    bVar1 = GKERNEL::Windowed();
    if (bVar1) {
      CWnd::ShowWindow((HWND)0x1,in_stack_ffffffd4);
    }
    iVar5 = FUN_004056c0((int)this);
    if (iVar5 == 6) {
      FUN_0040f49d(this);
    }
  }
  iVar5 = FUN_004056c0((int)this);
  if ((iVar5 == 2) || (iVar5 = FUN_004056c0((int)this), iVar5 == 0xd)) {
    cVar6 = '\x01';
    iVar5 = FUN_004056c0((int)this);
    pvVar2 = (void *)FUN_0041db21(this,iVar5 == 0xd,cVar6);
  }
  else {
    iVar5 = FUN_004056c0((int)this);
    if ((((iVar5 == 6) || (iVar5 = FUN_004056c0((int)this), iVar5 == 7)) ||
        (iVar5 = FUN_004056c0((int)this), iVar5 == 0xb)) ||
       (pvVar2 = (void *)FUN_004056c0((int)this), pvVar2 == (void *)0xa)) {
      pvVar2 = (void *)FUN_0040d700((GAME *)this);
    }
  }
  if ((param_1 != '\0') && (pvVar2 = this, *(char *)((int)this + 0xe014) != '\0')) {
    pvVar2 = (void *)FUN_0040fbb9((int)this);
  }
  ExceptionList = local_10;
  return CONCAT31((int3)((uint)pvVar2 >> 8),1);
}



void __fastcall FUN_0040e44a(int param_1)

{
  if ((*(int *)(param_1 + 0xe010) != 0) && (*(char *)(*(int *)(param_1 + 0xe010) + 0x80) != '\0')) {
    FUN_0040195f(*(void **)(param_1 + 0xe010),1);
  }
  return;
}



void __thiscall FUN_0040e488(void *this,char param_1)

{
  bool bVar1;
  HWND__ *pHVar2;
  CWnd *pCVar3;
  int iVar4;
  
  if (param_1 != '\0') {
    pHVar2 = GKERNEL::GetHwnd();
    pCVar3 = CWnd::FromHandle(pHVar2);
    FUN_0040fe50(*(void **)((int)this + 0xe010),0x87,pCVar3);
    bVar1 = GKERNEL::Windowed();
    if (bVar1) {
      ShowWindow(*(HWND *)(*(int *)((int)this + 0xe010) + 0x20),1);
    }
    else if (*(char *)((int)this + 0xe015) == '\0') {
                    // WARNING: Load size is inaccurate
      (**(code **)(*this + 0x20))(1,0,0);
    }
    iVar4 = FUN_004056c0((int)this);
    if (iVar4 == 6) {
      FUN_0040f6ea(this,(undefined4 *)((int)this + 0xe01c));
    }
  }
  return;
}



undefined1 __thiscall FUN_0040e529(void *this,uint param_1)

{
  char cVar1;
  bool bVar2;
  uint uVar3;
  int iVar4;
  CString *pCVar5;
  undefined4 uVar6;
  undefined3 extraout_var;
  undefined4 *puVar7;
  int *piVar8;
  void *pvVar9;
  UINT UVar10;
  ITEM *pIVar11;
  LPARAM unaff_ESI;
  char *pcVar12;
  int iVar13;
  WPARAM WVar14;
  undefined1 local_114 [8];
  ITEM *local_10c;
  ITEM *local_108;
  undefined1 local_104 [8];
  undefined1 local_fc [8];
  int local_f4;
  int local_f0;
  undefined1 local_ec [8];
  undefined1 local_e4 [8];
  undefined1 local_dc [8];
  int local_d4;
  int local_d0;
  undefined1 local_cc [8];
  undefined1 local_c4 [8];
  undefined1 local_bc;
  undefined1 *local_b8;
  undefined1 *local_b4;
  undefined1 *local_b0;
  CString local_ac [4];
  CString local_a8 [4];
  CString local_a4 [4];
  undefined1 *local_a0;
  undefined1 *local_9c;
  CString local_98 [4];
  uint local_94;
  CString local_90 [4];
  ITEM *local_8c;
  ITEM *local_88;
  TwDirectXDialog local_84 [96];
  CString local_24 [4];
  CString local_20 [4];
  uint local_1c;
  tagPOINT local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429af5;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  if ((DAT_00448f80 & 1) == 0) {
    DAT_00448f80 = DAT_00448f80 | 1;
    ExceptionList = &local_10;
    CString::CString((CString *)&this_00448f78);
    FUN_00427dae(FUN_0040f0f5);
  }
  FUN_00405850(&local_18);
  uVar3 = GKERNEL::GetCursorPos(&local_18);
  if ((uVar3 & 0xff) == 0) {
    ExceptionList = local_10;
    return 0;
  }
  FUN_0040feb0(&local_18,0x20);
  iVar4 = FUN_004056c0((int)this);
  if (iVar4 == 6) {
    bVar2 = GAME::IsKeyDown((GAME *)this,0x11);
    if ((bVar2) && (param_1 == 10)) {
      bVar2 = GKERNEL::Windowed();
      if (bVar2) {
        FUN_00402838(*(CWnd **)((int)this + 0xe010));
      }
      else {
        pCVar5 = (CString *)MAP::Name((MAP *)((int)this + 0xe23c));
        local_8 = 0;
        CString::operator=((CString *)&this_00448f78,pCVar5);
        local_8 = 0xffffffff;
        FUN_004014d0(local_90);
        DAT_00448fac = '\x01';
      }
      ExceptionList = local_10;
      return 1;
    }
    if (DAT_00448fac != '\0') {
      local_1c = toupper(param_1);
      if (((local_1c & 0xffff0000) == 0) && (iVar4 = isprint(local_1c), iVar4 != 0)) {
        pcVar12 = s_static_map_00434e50;
        pvVar9 = (void *)MAP::Name((MAP *)((int)this + 0xe23c));
        local_8 = 1;
        bVar2 = FUN_00404990(pvVar9,pcVar12);
        local_94 = CONCAT31(local_94._1_3_,bVar2);
        local_8 = 0xffffffff;
        FUN_004014d0(local_98);
        if ((local_94 & 0xff) != 0) {
          local_9c = &stack0xfffffe90;
          CString::CString((CString *)&stack0xfffffe90,(char *)&this_00448fb0);
          MAP::Rename((MAP *)((int)this + 0xe23c));
        }
        uVar6 = CString::CString(local_a4,(char)local_1c,1);
        local_8 = 2;
        local_a0 = &stack0xfffffe90;
        pCVar5 = (CString *)MAP::Name((MAP *)((int)this + 0xe23c));
        local_8._0_1_ = 3;
        operator+((CString *)&stack0xfffffe90,pCVar5);
        MAP::Rename((MAP *)((int)this + 0xe23c),uVar6);
        local_8 = CONCAT31(local_8._1_3_,2);
        FUN_004014d0(local_a8);
        local_8 = 0xffffffff;
        CString::~CString(local_a4);
      }
      else if (param_1 == 8) {
        pCVar5 = (CString *)MAP::Name((MAP *)((int)this + 0xe23c));
        local_8 = 4;
        CString::CString(local_20,pCVar5);
        local_8 = CONCAT31(local_8._1_3_,6);
        FUN_004014d0(local_ac);
        bVar2 = FUN_00401430((int *)local_20);
        if (CONCAT31(extraout_var,bVar2) == 0) {
          iVar13 = 1;
          iVar4 = FUN_0040fd90((int *)local_20);
          CString::Delete(local_20,iVar4 + -1,iVar13);
        }
        local_b0 = &stack0xfffffe90;
        CString::CString((CString *)&stack0xfffffe90,local_20);
        MAP::Rename((MAP *)((int)this + 0xe23c));
        local_8 = 0xffffffff;
        CString::~CString(local_20);
      }
      else if (param_1 == 0x2e0000) {
        local_b4 = &stack0xfffffe90;
        CString::CString((CString *)&stack0xfffffe90,(char *)&this_00448fb4);
        MAP::Rename((MAP *)((int)this + 0xe23c));
      }
      else if (param_1 == 0x1b) {
        local_b8 = &stack0xfffffe90;
        CString::CString((CString *)&stack0xfffffe90,(CString *)&this_00448f78);
        MAP::Rename((MAP *)((int)this + 0xe23c));
        DAT_00448fac = '\0';
      }
      else if (param_1 == 0xd) {
        DAT_00448fac = '\0';
      }
      ExceptionList = local_10;
      return 1;
    }
    if ((param_1 == 0x1b) && (bVar2 = FUN_00405940(*(int *)((int)this + 0xe010)), bVar2)) {
      FUN_004040c5(*(int *)((int)this + 0xe010));
      ExceptionList = local_10;
      return 1;
    }
    if ((((param_1 == 0x1b) && (iVar4 = FUN_004056c0((int)this), iVar4 == 6)) &&
        (cVar1 = FUN_0040f42e(), cVar1 != '\0')) &&
       (bVar2 = FUN_00405940(*(int *)((int)this + 0xe010)), !bVar2)) {
      FUN_00409fb0(local_84,*(CWnd **)((int)this + 0xe010));
      local_8 = 7;
      CString::operator=(local_24,s_Exit_and_lose_changes__00434e5c);
      iVar4 = TwDirectXDialog::DoModal(local_84);
      local_bc = iVar4 == 2;
      local_8 = 0xffffffff;
      FUN_004048f0((CDialog *)local_84);
      ExceptionList = local_10;
      return local_bc;
    }
    bVar2 = GAME::IsKeyDown((GAME *)this,0x11);
    if ((bVar2) && (param_1 == 3)) {
      FUN_00403467(*(void **)((int)this + 0xe010));
      ExceptionList = local_10;
      return 1;
    }
    bVar2 = GAME::IsKeyDown((GAME *)this,0x11);
    if ((bVar2) && (param_1 == 0x16)) {
      FUN_00403534(*(void **)((int)this + 0xe010));
      ExceptionList = local_10;
      return 1;
    }
    bVar2 = GAME::IsKeyDown((GAME *)this,0x11);
    if ((bVar2) && (param_1 == 0x13)) {
      FUN_00402981(*(void **)((int)this + 0xe010));
      ExceptionList = local_10;
      return 1;
    }
    bVar2 = GAME::IsKeyDown((GAME *)this,0x11);
    if ((bVar2) && (param_1 == 6)) {
      FUN_00402fa2(*(CWnd **)((int)this + 0xe010));
      ExceptionList = local_10;
      return 1;
    }
    bVar2 = GAME::IsKeyDown((GAME *)this,0x11);
    if ((bVar2) && (param_1 == 0xf)) {
      FUN_00402aa0(*(void **)((int)this + 0xe010));
      ExceptionList = local_10;
      return 1;
    }
    bVar2 = GAME::IsKeyDown((GAME *)this,0x11);
    if ((bVar2) && (param_1 == 0x17)) {
      FUN_004035c0(*(CWnd **)((int)this + 0xe010));
      ExceptionList = local_10;
      return 1;
    }
    bVar2 = GAME::IsKeyDown((GAME *)this,0x11);
    if ((bVar2) && (param_1 == 0x14)) {
      FUN_00403b82(*(int *)((int)this + 0xe010));
      ExceptionList = local_10;
      return 1;
    }
    bVar2 = GAME::IsKeyDown((GAME *)this,0x11);
    if ((bVar2) && (param_1 == 4)) {
      FUN_004033d5(*(int *)((int)this + 0xe010));
      ExceptionList = local_10;
      return 1;
    }
  }
  if (local_18.y < 0xd) {
    iVar4 = FUN_004056c0((int)this);
    if ((iVar4 == 2) || (iVar4 = FUN_004056c0((int)this), iVar4 == 0xd)) {
      FUN_0041e3d0(this,param_1);
      ExceptionList = local_10;
      return 0;
    }
    iVar4 = FUN_004056c0((int)this);
    if (iVar4 == 6) {
      local_88 = (ITEM *)0x0;
      bVar2 = GAME::IsKeyDown((GAME *)this,0x11);
      if (((bVar2) && (param_1 == 0xd)) ||
         ((bVar2 = GAME::IsKeyDown((GAME *)this,0x11), bVar2 && (param_1 == 0x18)))) {
        if (local_88 == (ITEM *)0x0) {
          FUN_00401b53(*(int *)((int)this + 0xe010));
          FUN_0040f3a1();
        }
        puVar7 = (undefined4 *)default_error_condition(local_c4,local_18.x,local_18.y);
        local_88 = MAP::GetItem((MAP *)((int)this + 0xe23c),*puVar7);
        (**(code **)(*(int *)local_88 + 0x34))();
        (**(code **)(*(int *)local_88 + 0x3c))();
        FUN_004145b0(this,local_18.x << 5,local_18.y << 5);
        piVar8 = (int *)default_error_condition(local_dc,local_18.x,local_18.y);
        iVar4 = *piVar8;
        iVar13 = piVar8[1];
        local_d4 = iVar4;
        local_d0 = iVar13;
        pvVar9 = FUN_00405800((void *)((int)this + 0xe01c),local_cc,0x20);
        iVar4 = FUN_0040fe10(pvVar9,iVar4,iVar13);
        if (iVar4 != 0) {
          WVar14 = 0;
          UVar10 = (**(code **)(*(int *)local_88 + 0x34))();
          CWnd::SendDlgItemMessageA((HWND)&DAT_000003fe,0xf1,UVar10,WVar14,unaff_ESI);
        }
      }
      bVar2 = GAME::IsKeyDown((GAME *)this,0x11);
      if (((bVar2) && (param_1 == 0x12)) ||
         ((bVar2 = GAME::IsKeyDown((GAME *)this,0x11), bVar2 && (param_1 == 0x18)))) {
        if (local_88 == (ITEM *)0x0) {
          FUN_00401b53(*(int *)((int)this + 0xe010));
          FUN_0040f3a1();
        }
        puVar7 = (undefined4 *)default_error_condition(local_e4,local_18.x,local_18.y);
        local_88 = MAP::GetItem((MAP *)((int)this + 0xe23c),*puVar7);
        (**(code **)(*(int *)local_88 + 0x38))();
        (**(code **)(*(int *)local_88 + 0x40))();
        FUN_004145b0(this,local_18.x << 5,local_18.y << 5);
        piVar8 = (int *)default_error_condition(local_fc,local_18.x,local_18.y);
        iVar4 = *piVar8;
        iVar13 = piVar8[1];
        local_f4 = iVar4;
        local_f0 = iVar13;
        pvVar9 = FUN_00405800((void *)((int)this + 0xe01c),local_ec,0x20);
        iVar4 = FUN_0040fe10(pvVar9,iVar4,iVar13);
        if (iVar4 != 0) {
          WVar14 = 0;
          UVar10 = (**(code **)(*(int *)local_88 + 0x34))();
          CWnd::SendDlgItemMessageA((HWND)&DAT_000003ff,0xf1,UVar10,WVar14,unaff_ESI);
        }
      }
      if (local_88 != (ITEM *)0x0) {
        ExceptionList = local_10;
        return 1;
      }
      if (param_1 == 0x2e0000) {
        pIVar11 = MAP::FindItem(s_BLANK_00434e74);
        local_88 = (ITEM *)(**(code **)(*(int *)pIVar11 + 4))();
      }
      else if (param_1 == 0xd) {
        puVar7 = (undefined4 *)FUN_00405800((void *)((int)this + 0xe01c),local_104,0x20);
        local_88 = MAP::GetItem((MAP *)((int)this + 0xe23c),*puVar7);
        local_88 = (ITEM *)(**(code **)(*(int *)local_88 + 4))();
      }
      else if ((param_1 & 0xffff) != 0) {
        local_88 = MAP::FindItem((char)param_1);
        if (local_88 != (ITEM *)0x0) {
          local_88 = (ITEM *)(**(code **)(*(int *)local_88 + 4))();
        }
      }
      if (local_88 != (ITEM *)0x0) {
        local_8c = MAP::GetItem((MAP *)((int)this + 0xe23c),local_18.x);
        iVar4 = FUN_0040ff10(local_88,(int *)local_8c);
        if (iVar4 == 0) {
          FUN_00401b53(*(int *)((int)this + 0xe010));
          FUN_0040f3a1();
          puVar7 = (undefined4 *)default_error_condition(local_114,local_18.x,local_18.y);
          local_10c = MAP::SetItem((MAP *)((int)this + 0xe23c),*puVar7,puVar7[1]);
          if (local_10c != (ITEM *)0x0) {
            local_108 = local_10c;
            (*(code *)**(undefined4 **)local_10c)();
          }
        }
        else if (local_88 != (ITEM *)0x0) {
          (*(code *)**(undefined4 **)local_88)();
        }
        ExceptionList = local_10;
        return 1;
      }
      ExceptionList = local_10;
      return 0;
    }
  }
  ExceptionList = local_10;
  return 0;
}



void FUN_0040f0f5(void)

{
  CString::~CString((CString *)&this_00448f78);
  return;
}



void __fastcall FUN_0040f104(int param_1)

{
  char cVar1;
  int iVar2;
  
  iVar2 = FUN_004056c0(param_1);
  if (iVar2 == 6) {
    cVar1 = (**(code **)(*(int *)(param_1 + 0x3444) + 0x44))();
    if (cVar1 == '\0') {
      cVar1 = (**(code **)(*(int *)(param_1 + 0x35c0) + 0x44))();
      if (cVar1 == '\0') {
        cVar1 = (**(code **)(*(int *)(param_1 + 0x373c) + 0x44))();
        if (cVar1 != '\0') {
          FUN_004039c7(*(int *)(param_1 + 0xe010));
        }
      }
      else {
        FUN_00403938(*(int *)(param_1 + 0xe010));
      }
    }
    else {
      FUN_004038a9(*(int *)(param_1 + 0xe010));
    }
  }
  return;
}



void __thiscall FUN_0040f1ab(void *this,void *param_1)

{
  bool bVar1;
  int *piVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 uVar5;
  undefined1 local_34 [8];
  ITEM *local_2c;
  ITEM *local_28;
  undefined1 local_24 [8];
  undefined1 local_1c [8];
  undefined1 local_14 [8];
  ITEM *local_c;
  int *local_8;
  
  bVar1 = FUN_00405940(*(int *)((int)this + 0xe010));
  if (bVar1) {
    piVar2 = (int *)default_error_condition(local_1c,0x10,0x10);
    FUN_0040dff0(param_1,local_14,piVar2);
    puVar3 = (undefined4 *)FUN_00405800(local_14,local_24,0x20);
    local_c = MAP::GetItem((MAP *)((int)this + 0xe23c),*puVar3,puVar3[1]);
    if (local_c != (ITEM *)0x0) {
      local_8 = *(int **)(*(int *)((int)this + 0xe010) + 0x84);
      iVar4 = FUN_0040ff10(local_c,local_8);
      if (iVar4 == 0) {
        FUN_00401b53(*(int *)((int)this + 0xe010));
        FUN_0040f3a1();
        uVar5 = (**(code **)(*local_8 + 4))();
        puVar3 = (undefined4 *)FUN_00405800(local_14,local_34,0x20);
        local_2c = MAP::SetItem((MAP *)((int)this + 0xe23c),*puVar3,puVar3[1],uVar5);
        if (local_2c != (ITEM *)0x0) {
          local_28 = local_2c;
          (*(code *)**(undefined4 **)local_2c)(1);
        }
      }
    }
  }
  return;
}



void __thiscall FUN_0040f2b0(void *this,int param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  CString *pCVar2;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429b08;
  local_10 = ExceptionList;
  if (param_1 == 6) {
    ExceptionList = &local_10;
    FUN_00401a89(*(void **)((int)this + 0xe010),1);
    FUN_00401a5b(*(void **)((int)this + 0xe010),0x406,
                 (uint)(*(int *)(*(int *)((int)this + 0xe010) + 0x74) != -1));
    bVar1 = FUN_00401430((int *)(*(int *)((int)this + 0xe010) + 0x78));
    FUN_00401a5b(*(void **)((int)this + 0xe010),0x405,(uint)(CONCAT31(extraout_var,bVar1) == 0));
    pCVar2 = (CString *)MAP::Data((MAP *)((int)this + 0xe23c));
    local_8 = 0;
    CString::operator=((CString *)(*(int *)((int)this + 0xe010) + 0x7c),pCVar2);
    local_8 = 0xffffffff;
    FUN_004014d0(local_14);
  }
  else {
    ExceptionList = &local_10;
    FUN_00401a89(*(void **)((int)this + 0xe010),0);
  }
  ExceptionList = local_10;
  return;
}



void FUN_0040f3a1(void)

{
  char cVar1;
  HWND__ *pHVar2;
  STRING local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429b1b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  cVar1 = FUN_0040f42e();
  if (cVar1 != '\0') {
    ExceptionList = local_10;
    return;
  }
  pHVar2 = GKERNEL::GetHwnd();
  STRING::STRING(local_14,pHVar2);
  local_8 = 0;
                    // WARNING: Subroutine does not return
  STRING::terminate(local_14,(char *)&this_00434e7c);
}



undefined1 FUN_0040f42e(void)

{
  HWND__ *pHVar1;
  STRING *this;
  HWND__ **ppHVar2;
  STRING local_18 [4];
  undefined1 local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_00429b2e;
  local_10 = ExceptionList;
  ppHVar2 = &param_1_00434e80;
  ExceptionList = &local_10;
  pHVar1 = GKERNEL::GetHwnd();
  this = (STRING *)STRING::STRING(local_18,pHVar1);
  local_8 = 0;
  local_14 = STRING::tailequ(this,(char *)ppHVar2);
  local_8 = 0xffffffff;
  FUN_004014d0((CString *)local_18);
  ExceptionList = local_10;
  return local_14;
}



void __fastcall FUN_0040f49d(void *param_1)

{
  bool bVar1;
  undefined4 *puVar2;
  ITEM *pIVar3;
  void *pvVar4;
  undefined1 *puVar5;
  undefined1 *puVar6;
  CString *pCVar7;
  char *pcVar8;
  undefined1 local_68 [8];
  undefined1 local_60 [8];
  CString local_58 [4];
  uint local_54;
  undefined1 local_50 [8];
  undefined1 local_48 [8];
  undefined1 local_40 [8];
  CString local_38 [4];
  undefined1 local_34 [8];
  uint local_2c;
  uint local_28;
  ITEM *local_24;
  uint local_20;
  uint local_1c;
  undefined1 local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_00429b4a;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  default_error_condition(local_18,0,0);
  pcVar8 = s_BLANK_00434e84;
  pCVar7 = local_38;
  puVar2 = (undefined4 *)FUN_00405800((void *)((int)param_1 + 0xe01c),local_34,0x20);
  pIVar3 = MAP::GetItem((MAP *)((int)param_1 + 0xe23c),*puVar2,puVar2[1]);
  pvVar4 = (void *)(**(code **)(*(int *)pIVar3 + 0x60))(pCVar7,pcVar8);
  local_8 = 0;
  bVar1 = FUN_00404990(pvVar4,(char *)pCVar7);
  local_2c = CONCAT31(local_2c._1_3_,bVar1);
  local_8 = 0xffffffff;
  CString::~CString(local_38);
  if ((local_2c & 0xff) == 0) {
    local_1c = local_1c & 0xffffff00;
    puVar2 = (undefined4 *)default_error_condition(local_40,0,0);
    local_24 = MAP::GetItem((MAP *)((int)param_1 + 0xe23c),*puVar2,puVar2[1]);
    local_20 = 0;
    while ((local_20 < 0x14 && ((local_1c & 0xff) == 0))) {
      local_28 = 0;
      while ((local_28 < 0xd && ((local_1c & 0xff) == 0))) {
        pcVar8 = s_BLANK_00434e8c;
        pvVar4 = (void *)(**(code **)(*(int *)local_24 + 0x60))(local_58);
        local_8 = 1;
        bVar1 = FUN_00404990(pvVar4,pcVar8);
        local_54 = CONCAT31(local_54._1_3_,bVar1);
        local_8 = 0xffffffff;
        CString::~CString(local_58);
        if ((local_54 & 0xff) != 0) {
          puVar6 = local_68;
          puVar5 = local_60;
          pvVar4 = (void *)(**(code **)(*(int *)local_24 + 0x74))(puVar5,puVar6,0x20);
          puVar2 = (undefined4 *)FUN_0040fe80(pvVar4,puVar5,(int)puVar6);
          FUN_0040f6ea(param_1,puVar2);
          ExceptionList = local_10;
          return;
        }
        local_28 = local_28 + 1;
        if (local_28 < 0xd) {
          puVar2 = (undefined4 *)default_error_condition(local_48,local_20,local_28);
          local_24 = MAP::GetItem((MAP *)((int)param_1 + 0xe23c),*puVar2,puVar2[1]);
        }
        else if (local_20 < 0x13) {
          puVar2 = (undefined4 *)default_error_condition(local_50,local_20 + 1,0);
          local_24 = MAP::GetItem((MAP *)((int)param_1 + 0xe23c),*puVar2,puVar2[1]);
        }
      }
      local_20 = local_20 + 1;
    }
  }
  else {
    FUN_0040f6ea(param_1,(undefined4 *)((int)param_1 + 0xe01c));
  }
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_0040f6ea(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  bool bVar2;
  void *pvVar3;
  UINT UVar4;
  uint wParam;
  WPARAM extraout_ECX;
  WPARAM extraout_ECX_00;
  undefined1 *puVar5;
  WPARAM WVar6;
  CString *pCVar7;
  CString **ppCVar8;
  LPARAM LVar9;
  char *lParam;
  undefined1 local_64;
  undefined1 local_48 [4];
  undefined1 *local_44;
  undefined1 local_40 [4];
  undefined1 *local_3c;
  undefined1 local_38 [4];
  CString local_34 [4];
  uint local_30;
  CString local_2c [4];
  uint local_28;
  undefined1 local_24 [8];
  undefined1 local_1c [8];
  ITEM *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429b66;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  (**(code **)(*(int *)((int)this + 0x228) + 0x28))();
  uVar1 = param_1[1];
  *(undefined4 *)((int)this + 0xe01c) = *param_1;
  *(undefined4 *)((int)this + 0xe020) = uVar1;
  (**(code **)(*(int *)((int)this + 0x228) + 0x1c))();
  FUN_00405800((void *)((int)this + 0xe01c),local_1c,0x20);
  MAP::SelectTile((MAP *)((int)this + 0xe23c));
  bVar2 = FUN_0040e0e0((int)this);
  if (!bVar2) {
    ExceptionList = local_10;
    return;
  }
  FUN_00405800((void *)((int)this + 0xe01c),local_24,0x20);
  local_14 = MAP::GetItem((MAP *)((int)this + 0xe23c));
  lParam = s_BLANK_00434e94;
  pCVar7 = local_2c;
  pvVar3 = (void *)(**(code **)(*(int *)local_14 + 0x60))();
  local_8 = 0;
  bVar2 = FUN_00404990(pvVar3,(char *)pCVar7);
  if (!bVar2) {
    ppCVar8 = &this_00434e9c;
    pvVar3 = (void *)(**(code **)(*(int *)local_14 + 0x60))();
    local_8._0_1_ = 1;
    bVar2 = FUN_00404990(pvVar3,(char *)ppCVar8);
    local_30 = CONCAT31(local_30._1_3_,bVar2);
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_34);
    if ((local_30 & 0xff) == 0) {
      local_64 = 0;
      goto LAB_0040f845;
    }
  }
  local_64 = 1;
LAB_0040f845:
  local_28 = CONCAT31(local_28._1_3_,local_64);
  local_8 = 0xffffffff;
  CString::~CString(local_2c);
  wParam = local_28 & 0xff;
  if (wParam == 0) {
    LVar9 = 0;
    local_3c = &stack0xffffff8c;
    FUN_00405890(&stack0xffffff8c,4);
    puVar5 = local_38;
    pvVar3 = (void *)(**(code **)(*(int *)local_14 + 0x7c))();
    bVar2 = FUN_0040fef0(pvVar3,(uint)puVar5);
    CWnd::SendDlgItemMessageA((HWND)&hDlg_00000408,0xf1,(uint)bVar2,wParam,LVar9);
    LVar9 = 0;
    WVar6 = extraout_ECX;
    local_44 = &stack0xffffff88;
    FUN_00405890(&stack0xffffff88,2);
    puVar5 = local_40;
    pvVar3 = (void *)(**(code **)(*(int *)local_14 + 0x7c))();
    bVar2 = FUN_0040fef0(pvVar3,(uint)puVar5);
    CWnd::SendDlgItemMessageA((HWND)&hDlg_00000409,0xf1,(uint)bVar2,WVar6,LVar9);
    LVar9 = 0;
    WVar6 = extraout_ECX_00;
    FUN_00405890(&stack0xffffff84,1);
    puVar5 = local_48;
    pvVar3 = (void *)(**(code **)(*(int *)local_14 + 0x7c))();
    bVar2 = FUN_0040fef0(pvVar3,(uint)puVar5);
    CWnd::SendDlgItemMessageA((HWND)&DAT_0000040a,0xf1,(uint)bVar2,WVar6,LVar9);
    WVar6 = 0;
    UVar4 = (**(code **)(*(int *)local_14 + 0x34))();
    CWnd::SendDlgItemMessageA((HWND)&DAT_000003fe,0xf1,UVar4,WVar6,LVar9);
    WVar6 = 0;
    UVar4 = (**(code **)(*(int *)local_14 + 0x38))();
    CWnd::SendDlgItemMessageA((HWND)&DAT_000003ff,0xf1,UVar4,WVar6,LVar9);
  }
  else {
    CWnd::SendDlgItemMessageA((HWND)&hDlg_00000408,0xf1,0,0,(LPARAM)lParam);
    CWnd::SendDlgItemMessageA((HWND)&hDlg_00000409,0xf1,0,0,(LPARAM)lParam);
    CWnd::SendDlgItemMessageA((HWND)&DAT_0000040a,0xf1,0,0,(LPARAM)lParam);
    CWnd::SendDlgItemMessageA((HWND)&DAT_000003fe,0xf1,0,0,(LPARAM)lParam);
    CWnd::SendDlgItemMessageA((HWND)&DAT_000003ff,0xf1,0,0,(LPARAM)lParam);
  }
  ExceptionList = local_10;
  return;
}



void FUN_0040fa21(void)

{
  FUN_0040fa30();
  FUN_0040fa3f();
  return;
}



void FUN_0040fa30(void)

{
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)&DAT_00448f90);
  return;
}



void FUN_0040fa3f(void)

{
  FUN_00427dae(FUN_0040fa51);
  return;
}



void FUN_0040fa51(void)

{
  FUN_0040c9a0((undefined4 *)&DAT_00448f90);
  return;
}



void FUN_0040fa60(void)

{
  FUN_0040fa6f();
  FUN_0040fa7e();
  return;
}



void FUN_0040fa6f(void)

{
  CString::CString((CString *)&this_00448f7c);
  return;
}



void FUN_0040fa7e(void)

{
  FUN_00427dae(FUN_0040fa90);
  return;
}



void FUN_0040fa90(void)

{
  CString::~CString((CString *)&this_00448f7c);
  return;
}



void FUN_0040fa9f(void)

{
  FUN_0040faae();
  FUN_0040fabd();
  return;
}



void FUN_0040faae(void)

{
  CString::CString((CString *)&this_00448f84);
  return;
}



void FUN_0040fabd(void)

{
  FUN_00427dae(FUN_0040facf);
  return;
}



void FUN_0040facf(void)

{
  CString::~CString((CString *)&this_00448f84);
  return;
}



void __fastcall FUN_0040fade(int param_1)

{
  CString *pCVar1;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429b79;
  local_10 = ExceptionList;
  if (*(int *)(param_1 + 0xe010) != 0) {
    ExceptionList = &local_10;
    pCVar1 = (CString *)MAP::Data((MAP *)(param_1 + 0xe23c));
    local_8 = 0;
    CString::operator=((CString *)&this_00448f7c,pCVar1);
    local_8 = 0xffffffff;
    FUN_004014d0(local_14);
    FUN_0040fd30(&DAT_00448f90,(void *)(param_1 + 0x138));
    CString::operator=((CString *)&this_00448f84,(CString *)(*(int *)(param_1 + 0xe010) + 0x7c));
    DAT_00448f88 = *(undefined4 *)(param_1 + 0x134);
    *(undefined4 *)(param_1 + 0x134) = 0;
    FUN_00426d40(param_1);
    *(undefined1 *)(param_1 + 0xe014) = 1;
  }
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_0040fbb9(int param_1)

{
  bool bVar1;
  CString *pCVar2;
  undefined4 *puVar3;
  void *pvVar4;
  CString local_1c [4];
  uint local_18;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429b95;
  local_10 = ExceptionList;
  if (*(int *)(param_1 + 0xe010) != 0) {
    ExceptionList = &local_10;
    MAP::Set((MAP *)(param_1 + 0xe23c),(CString *)&this_00448f7c);
    FUN_0040fd30((void *)(param_1 + 0x138),&DAT_00448f90);
    CString::operator=((CString *)(*(int *)(param_1 + 0xe010) + 0x7c),(CString *)&this_00448f84);
    *(undefined4 *)(param_1 + 0x134) = DAT_00448f88;
    DAT_00448f88 = 0;
    pCVar2 = (CString *)CString::CString(local_14);
    local_8 = 0;
    CString::operator=((CString *)&this_00448f7c,pCVar2);
    local_8 = 0xffffffff;
    CString::~CString(local_14);
    FUN_0040b5d0(0x448f90);
    *(undefined1 *)(param_1 + 0xe014) = 0;
    puVar3 = (undefined4 *)(*(int *)(param_1 + 0xe010) + 0x7c);
    pvVar4 = (void *)MAP::Data((MAP *)(param_1 + 0xe23c));
    local_8 = 1;
    bVar1 = FUN_0040fdf0(pvVar4,puVar3);
    local_18 = CONCAT31(local_18._1_3_,bVar1);
    local_8 = 0xffffffff;
    FUN_004014d0(local_1c);
    if ((local_18 & 0xff) != 0) {
      FUN_0040f3a1();
    }
  }
  ExceptionList = local_10;
  return;
}



CString * FUN_0040fcfb(CString *param_1)

{
  CString::CString(param_1,(CString *)&this_00448f7c);
  return param_1;
}



void * __thiscall FUN_0040fd30(void *this,void *param_1)

{
  if (this != param_1) {
    FUN_0040b5d0((int)this);
    FUN_0040fdb0(this,(int)param_1);
  }
  return this;
}



void FUN_0040fd70(uint param_1)

{
  operator_new(param_1);
  return;
}



undefined4 __fastcall FUN_0040fd90(int *param_1)

{
  int iVar1;
  
  iVar1 = FUN_00401450(param_1);
  return *(undefined4 *)(iVar1 + 4);
}



void __thiscall FUN_0040fdb0(void *this,int param_1)

{
  undefined4 *puVar1;
  int local_8;
  
  local_8 = FUN_00423770(param_1);
  while (local_8 != 0) {
    puVar1 = (undefined4 *)FUN_0041be90(&local_8);
    FUN_0040bed0(this,puVar1);
  }
  return;
}



bool FUN_0040fdf0(void *param_1,undefined4 *param_2)

{
  char *pcVar1;
  int iVar2;
  
  pcVar1 = (char *)FUN_00401470(param_2);
  iVar2 = FUN_004049b0(param_1,pcVar1);
  return iVar2 != 0;
}



undefined4 __thiscall FUN_0040fe10(void *this,int param_1,int param_2)

{
  undefined4 local_c;
  
                    // WARNING: Load size is inaccurate
  if ((*this == param_1) && (*(int *)((int)this + 4) == param_2)) {
    local_c = 1;
  }
  else {
    local_c = 0;
  }
  return local_c;
}



void __thiscall FUN_0040fe50(void *this,uint param_1,CWnd *param_2)

{
  CDialog::Create((CDialog *)this,(char *)(param_1 & 0xffff),param_2);
  return;
}



void * __thiscall FUN_0040fe80(void *this,void *param_1,int param_2)

{
                    // WARNING: Load size is inaccurate
  default_error_condition(param_1,*this * param_2,*(int *)((int)this + 4) * param_2);
  return param_1;
}



void * __thiscall FUN_0040feb0(void *this,int param_1)

{
  if (param_1 != 0) {
                    // WARNING: Load size is inaccurate
    *(int *)this = *this / param_1;
    *(int *)((int)this + 4) = *(int *)((int)this + 4) / param_1;
  }
  return this;
}



bool __thiscall FUN_0040fef0(void *this,uint param_1)

{
                    // WARNING: Load size is inaccurate
  return (*this & param_1) == param_1;
}



undefined4 __thiscall FUN_0040ff10(void *this,int *param_1)

{
  bool bVar1;
  undefined4 uVar2;
  void *pvVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  int *piVar7;
  CString *pCVar8;
  undefined1 *puVar9;
  undefined4 local_70;
  int local_48;
  undefined1 local_44 [4];
  bool local_40;
  undefined3 uStack_3f;
  undefined1 local_3c [4];
  undefined1 local_38 [4];
  bool local_34;
  undefined3 uStack_33;
  bool local_30;
  undefined3 uStack_2f;
  bool local_2c;
  undefined3 uStack_2b;
  CString local_28 [4];
  CString local_24 [4];
  uint local_20;
  CString local_1c [4];
  CString local_18 [4];
  undefined4 local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429bc4;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  uVar2 = (**(code **)(*param_1 + 0x50))(local_18);
  local_8 = 0;
  pCVar8 = local_1c;
                    // WARNING: Load size is inaccurate
  pvVar3 = (void *)(**(code **)(*this + 0x50))(pCVar8,uVar2);
  local_8._0_1_ = 1;
  bVar1 = FUN_004087b0(pvVar3,(undefined4 *)pCVar8);
  if (bVar1) {
    pCVar8 = local_24;
    uVar2 = (**(code **)(*param_1 + 0x60))();
    local_8._0_1_ = 2;
                    // WARNING: Load size is inaccurate
    pvVar3 = (void *)(**(code **)(*this + 0x60))(local_28,uVar2);
    local_8._0_1_ = 3;
    bVar1 = FUN_004087b0(pvVar3,(undefined4 *)pCVar8);
    local_20 = CONCAT31(local_20._1_3_,bVar1);
    local_8._0_1_ = 2;
    CString::~CString(local_28);
    local_8._0_1_ = 1;
    CString::~CString(local_24);
    if ((local_20 & 0xff) != 0) {
                    // WARNING: Load size is inaccurate
      iVar4 = (**(code **)(*this + 0x38))();
      iVar5 = (**(code **)(*param_1 + 0x38))();
      _local_2c = CONCAT31(uStack_2b,iVar4 == iVar5);
      if (iVar4 == iVar5) {
                    // WARNING: Load size is inaccurate
        iVar4 = (**(code **)(*this + 0x34))();
        iVar5 = (**(code **)(*param_1 + 0x34))();
        _local_30 = CONCAT31(uStack_2f,iVar4 == iVar5);
        if (iVar4 == iVar5) {
          puVar9 = local_38;
          puVar6 = (undefined4 *)(**(code **)(*param_1 + 0x7c))();
                    // WARNING: Load size is inaccurate
          piVar7 = (int *)(**(code **)(*this + 0x7c))(local_3c,*puVar6);
          bVar1 = FUN_00410130(*piVar7,(int)puVar9);
          _local_34 = CONCAT31(uStack_33,bVar1);
          if (bVar1) {
            piVar7 = &local_48;
            uVar2 = (**(code **)(*param_1 + 0x78))();
                    // WARNING: Load size is inaccurate
            pvVar3 = (void *)(**(code **)(*this + 0x78))(local_44,uVar2);
            bVar1 = FUN_00410110(pvVar3,piVar7);
            _local_40 = CONCAT31(uStack_3f,bVar1);
            if (bVar1) {
              local_70 = 1;
              goto LAB_004100d8;
            }
          }
        }
      }
    }
  }
  local_70 = 0;
LAB_004100d8:
  local_14 = local_70;
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(local_1c);
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  ExceptionList = local_10;
  return local_14;
}



bool __thiscall FUN_00410110(void *this,int *param_1)

{
                    // WARNING: Load size is inaccurate
  return *this == *param_1;
}



bool __cdecl FUN_00410130(int param_1,int param_2)

{
  return param_1 == param_2;
}



void __fastcall FUN_00410150(GAME *param_1)

{
  char cVar1;
  undefined1 uVar2;
  bool bVar3;
  undefined4 uVar4;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  undefined3 extraout_var_03;
  undefined3 extraout_var_04;
  undefined3 extraout_var_05;
  undefined3 extraout_var_06;
  int iVar5;
  int local_11c;
  uint local_118 [68];
  int local_8;
  
  FUN_00410a40(local_118);
  FUN_00410a70(local_118);
  for (local_8 = 0; local_8 < 0x20; local_8 = local_8 + 1) {
    FUN_00410a40((undefined4 *)(g_Timer_exref + local_8 * 0x110));
  }
  uVar4 = FUN_004056c0((int)param_1);
  switch(uVar4) {
  case 1:
    (**(code **)(*(int *)(param_1 + 0x38b8) + 0x14))();
    (**(code **)(*(int *)(param_1 + 0x3a34) + 0x14))();
    break;
  case 2:
  case 0xd:
    uVar2 = FUN_00414141((int)param_1);
    if (CONCAT31(extraout_var_04,uVar2) != 0) {
      if ((DAT_00448fbc & 2) == 0) {
        DAT_00448fbc = DAT_00448fbc | 2;
        FUN_0040c180((DWORD *)&DAT_00448fc0);
        FUN_00427dae(FUN_00410a32);
      }
      bVar3 = FUN_0040dfb0(&DAT_00448fc0,1000);
      if (CONCAT31(extraout_var_05,bVar3) != 0) {
        *(int *)(param_1 + 300) = *(int *)(param_1 + 300) + 1;
        bVar3 = FUN_00414159((int)param_1);
        if (CONCAT31(extraout_var_06,bVar3) != 0) {
          GAME::ChangeState(param_1,4);
          return;
        }
      }
    }
    if (*(int *)(param_1 + 0x129b8) != 0) {
      FUN_0041d5a3((int)param_1);
      FUN_0040b710((int)(param_1 + 0x2480));
      (**(code **)(*(int *)(param_1 + 0x2480) + 0x14))();
    }
    (**(code **)(*(int *)(param_1 + 0x2a7c) + 0x14))();
    break;
  case 3:
    FUN_0041a469();
    break;
  case 4:
    FUN_0040d38b((int)param_1);
    break;
  case 5:
    bVar3 = FUN_0040dfb0(param_1 + 0x1282c,2000);
    if (CONCAT31(extraout_var,bVar3) == 0) {
      return;
    }
    uVar2 = FUN_00414141((int)param_1);
    if (CONCAT31(extraout_var_00,uVar2) != 0) {
      GAME::ChangeState(param_1,4);
      return;
    }
    GAME::ChangeState(param_1,3);
    return;
  case 6:
    uVar2 = FUN_00414141((int)param_1);
    if (CONCAT31(extraout_var_01,uVar2) != 0) {
      if ((DAT_00448fbc & 1) == 0) {
        DAT_00448fbc = DAT_00448fbc | 1;
        FUN_0040c180((DWORD *)&DAT_00448fb8);
        FUN_00427dae(FUN_00410a37);
      }
      bVar3 = FUN_0040dfb0(&DAT_00448fb8,1000);
      if (CONCAT31(extraout_var_02,bVar3) != 0) {
        *(int *)(param_1 + 300) = *(int *)(param_1 + 300) + 1;
        bVar3 = FUN_00414159((int)param_1);
        if (CONCAT31(extraout_var_03,bVar3) != 0) {
          GAME::ChangeState(param_1,4);
          return;
        }
      }
    }
    FUN_00410a70((uint *)g_Timer_exref);
    FUN_00410b70((MAP *)(param_1 + 0xe23c));
    FUN_00410ad0((uint *)g_Timer_exref);
    FUN_00413ac5((int)param_1);
    FUN_00410a70((uint *)(g_Timer_exref + 0x110));
    iVar5 = FUN_0042167f((int)param_1);
    if (iVar5 == 0) {
      (**(code **)(*(int *)(param_1 + 0x277c) + 0x14))();
      (**(code **)(*(int *)(param_1 + 0x28fc) + 0x14))();
      (**(code **)(*(int *)(param_1 + 0x25fc) + 0x14))();
      (**(code **)(*(int *)(param_1 + 0x2d7c) + 0x14))();
      (**(code **)(*(int *)(param_1 + 0x2efc) + 0x14))();
      (**(code **)(*(int *)(param_1 + 0x307c) + 0x14))();
      (**(code **)(*(int *)(param_1 + 0x31f8) + 0x14))();
    }
    FUN_00410ad0((uint *)(g_Timer_exref + 0x110));
    (**(code **)(*(int *)(param_1 + 0x3444) + 0x14))();
    (**(code **)(*(int *)(param_1 + 0x35c0) + 0x14))();
    (**(code **)(*(int *)(param_1 + 0x373c) + 0x14))();
    FUN_00410a70((uint *)(g_Timer_exref + 0x220));
    FUN_0040dc77(param_1);
    FUN_00410ad0((uint *)(g_Timer_exref + 0x220));
    iVar5 = FUN_004213b1((int)param_1);
    if (iVar5 != 0) {
      FUN_0042259d(param_1);
    }
    iVar5 = FUN_004056c0((int)param_1);
    if (iVar5 != 7) {
      (**(code **)(*(int *)(param_1 + 0x2a7c) + 0x14))();
      FUN_00411c36(param_1);
      FUN_00410ad0((uint *)(g_Timer_exref + 0x110));
    }
    break;
  case 7:
    FUN_00410b70((MAP *)(param_1 + 0xe23c));
    FUN_0040dc77(param_1);
    break;
  case 9:
    (**(code **)(**(int **)(param_1 + 0x129b4) + 0x14))();
    break;
  case 10:
    FUN_00410b70((MAP *)(param_1 + 0xe23c));
    iVar5 = FUN_0042167f((int)param_1);
    if (iVar5 == 0) {
      (**(code **)(*(int *)(param_1 + 0x277c) + 0x14))();
    }
    iVar5 = FUN_004213b1((int)param_1);
    if (iVar5 != 0) {
      FUN_0042259d(param_1);
    }
    break;
  case 0xb:
    FUN_00410b70((MAP *)(param_1 + 0xe23c));
    if (*(int *)(param_1 + 0x130) != 0) {
      (**(code **)(*(int *)(param_1 + 0x2bfc) + 0x14))();
      (**(code **)(*(int *)(param_1 + 0xe024) + 0x14))();
    }
    FUN_00413ac5((int)param_1);
    bVar3 = SPRITE::InMotion((SPRITE *)(param_1 + 0xbdb4));
    if (((bVar3) || (bVar3 = SPRITE::InMotion((SPRITE *)(param_1 + 0xcee0)), bVar3)) ||
       (*(int *)(param_1 + 0x130) != 0)) {
      if (((*(int *)(param_1 + 0x130) != 0) &&
          (cVar1 = (**(code **)(*(int *)(param_1 + 0xcee0) + 0x18))(), cVar1 != '\0')) &&
         (cVar1 = (**(code **)(*(int *)(param_1 + 0xbdb4) + 0x18))(), cVar1 != '\0')) {
        (**(code **)(*(int *)(param_1 + 0xbdb4) + 0x14))();
        (**(code **)(*(int *)(param_1 + 0xcee0) + 0x14))();
        (**(code **)(*(int *)(param_1 + 0xbdb4) + 0x20))();
        (**(code **)(*(int *)(param_1 + 0xcee0) + 0x20))();
      }
    }
    else {
      for (local_11c = 0; local_11c < 5; local_11c = local_11c + 1) {
        (**(code **)(*(int *)(param_1 + local_11c * 0x112c + 0x67d8) + 0x20))();
      }
      (**(code **)(*(int *)(param_1 + 0xbdb4) + 0x14))();
      (**(code **)(*(int *)(param_1 + 0xcee0) + 0x14))();
      *(undefined4 *)(param_1 + 0x130) = 1;
    }
    iVar5 = FUN_004213b1((int)param_1);
    if (iVar5 != 0) {
      FUN_0042259d(param_1);
    }
    break;
  case 0xc:
    FUN_00410b70((MAP *)(param_1 + 0xe23c));
    FUN_00418177(param_1);
    FUN_0040dc77(param_1);
    FUN_00413ac5((int)param_1);
  }
  iVar5 = FUN_004213b1((int)param_1);
  if (iVar5 != 0) {
    (**(code **)(*(int *)(param_1 + 0x154) + 0x1c))();
    (**(code **)(*(int *)(param_1 + 0x154) + 0x14))();
  }
  FUN_00410a70((uint *)(g_Timer_exref + 0x330));
  GKERNEL::SaveSprites();
  GKERNEL::DrawSprites();
  FUN_00410ad0((uint *)(g_Timer_exref + 0x330));
  FUN_00410a70((uint *)(g_Timer_exref + 0x440));
  GKERNEL::Flip();
  GKERNEL::FlipSprites();
  FUN_00410ad0((uint *)(g_Timer_exref + 0x440));
  FUN_00410a70((uint *)(g_Timer_exref + 0x550));
  GKERNEL::RestoreSprites();
  FUN_00410ad0((uint *)(g_Timer_exref + 0x550));
  FUN_00410ad0(local_118);
  return;
}



void FUN_00410a32(void)

{
  return;
}



void FUN_00410a37(void)

{
  return;
}



void __fastcall FUN_00410a40(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  return;
}



void __fastcall FUN_00410a70(uint *param_1)

{
  uint uVar1;
  undefined8 uVar2;
  
  uVar1 = FUN_00410b30(param_1);
  if ((uVar1 & 0xff) == 0) {
    uVar2 = FUN_00410aa0();
    *(undefined8 *)param_1 = uVar2;
  }
  return;
}



undefined8 FUN_00410aa0(void)

{
  return 0;
}



void __fastcall FUN_00410ad0(uint *param_1)

{
  uint uVar1;
  uint uVar2;
  undefined8 uVar3;
  
  uVar1 = FUN_00410b30(param_1);
  if ((uVar1 & 0xff) != 0) {
    uVar3 = FUN_00410aa0();
    uVar2 = (uint)uVar3 - *param_1;
    uVar1 = param_1[2];
    param_1[2] = uVar1 + uVar2;
    param_1[3] = param_1[3] +
                 (((int)((ulonglong)uVar3 >> 0x20) - param_1[1]) - (uint)((uint)uVar3 < *param_1)) +
                 (uint)CARRY4(uVar1,uVar2);
  }
  *param_1 = 0;
  param_1[1] = 0;
  return;
}



undefined4 __fastcall FUN_00410b30(uint *param_1)

{
  return CONCAT31((int3)((*param_1 | param_1[1]) >> 8),(*param_1 | param_1[1]) != 0);
}



void __fastcall FUN_00410b70(MAP *param_1)

{
  MAP::NewFrame(param_1,0);
  return;
}



void __thiscall FUN_00410b90(void *this,uint param_1,char param_2)

{
  bool bVar1;
  undefined1 uVar2;
  char cVar3;
  undefined3 extraout_var;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  int *piVar7;
  undefined4 local_c [2];
  
  if (param_2 == '\x01') {
    bVar1 = GAME::IsKeyDown((GAME *)this,0x11);
    if ((bVar1) && (param_1 == 0x11)) {
      uVar2 = FUN_00414141((int)this);
      if (CONCAT31(extraout_var,uVar2) == 0) {
        GKERNEL::Stop();
      }
      else {
        *(undefined1 *)((int)this + 0x12828) = 1;
        GAME::ChangeState((GAME *)this,4);
      }
    }
    else if ((*(char *)((int)this + 0x1281c) != '\0') &&
            ((bVar1 = GAME::IsKeyDown((GAME *)this,0x11), bVar1 && (param_1 == 5)))) {
                    // WARNING: Load size is inaccurate
      (**(code **)(*this + 0x20))(1,0,0);
    }
    bVar1 = FUN_0040e0e0((int)this);
    if (bVar1) {
      cVar3 = FUN_0040e529(this,param_1);
      if (cVar3 != '\0') {
        return;
      }
    }
    else {
      iVar4 = FUN_004213b1((int)this);
      if ((iVar4 != 0) && (uVar5 = FUN_00422c65(this,param_1,'\x01'), (uVar5 & 0xff) != 0)) {
        return;
      }
    }
  }
  uVar6 = FUN_004056c0((int)this);
  switch(uVar6) {
  case 1:
    if ((param_1 & 0xffff0000) == 0) {
      iVar4 = toupper(param_1);
      if ((iVar4 == 0x59) && (param_2 == '\x01')) {
        uVar2 = FUN_00414141((int)this);
        if (CONCAT31(extraout_var_01,uVar2) == 0) {
          GKERNEL::Stop();
        }
        else {
          GAME::ChangeState((GAME *)this,4);
        }
      }
      else {
        iVar4 = toupper(param_1);
        if ((iVar4 == 0x4e) && (param_2 == '\x01')) {
          uVar5 = FUN_0040e0c0((int)this);
          GAME::ChangeState((GAME *)this,uVar5);
        }
      }
    }
    break;
  case 2:
  case 0xd:
    if ((param_1 == 0x1b) && (param_2 == '\x01')) {
      GAME::ChangeState((GAME *)this,9);
    }
    break;
  case 3:
    FUN_0041b6e8(this,param_1);
    break;
  case 5:
    if (param_2 == '\x01') {
      uVar2 = FUN_00414141((int)this);
      if (CONCAT31(extraout_var_00,uVar2) == 0) {
        GAME::ChangeState((GAME *)this,3);
      }
      else {
        GAME::ChangeState((GAME *)this,4);
      }
    }
    break;
  case 6:
    FUN_00417066(this,param_1,param_2);
    break;
  case 9:
    if ((param_1 == 0x1b) && (param_2 == '\x01')) {
      GAME::ChangeState((GAME *)this,3);
    }
    break;
  case 10:
    if ((param_1 == 0x1b) && (param_2 == '\x01')) {
      if (*(char *)((int)this + 0xe014) == '\0') {
        GAME::ChangeState((GAME *)this,2);
      }
      else {
        FUN_0040e1ce(this,'\x01');
      }
    }
    break;
  case 0xb:
    if ((param_1 == 0x1b) && (param_2 == '\x01')) {
      if (*(char *)((int)this + 0xe014) == '\0') {
        piVar7 = FUN_00405910((void *)((int)this + 0xe23c),local_c);
        uVar5 = FUN_004058f0(piVar7);
        if (uVar5 % 100 < 0x10) {
          GAME::ChangeState((GAME *)this,2);
        }
        else {
          GAME::ChangeState((GAME *)this,0xd);
        }
      }
      else {
        FUN_0040e1ce(this,'\x01');
      }
    }
  }
  return;
}



void __fastcall FUN_00410eb0(GAME *param_1)

{
  uint local_454;
  MAP local_450 [1088];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_00429bdd;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  MAP::Cleanup();
  (**(code **)(**(int **)(param_1 + 0x129b4) + 0x1c))();
  MAP::Init(param_1,0,0);
  FUN_00413a8e(param_1,(CString *)&stack0xfffffb8c);
  MAP::SetLevelDir();
  DAT_00448fc4 = 1;
  FUN_00411cca(param_1);
  DAT_00448fc4 = 0;
  MAP::MAP(local_450);
  local_8 = 0;
  MAP::UseSmallTiles(local_450,true);
  for (local_454 = 0; local_454 < 0xf; local_454 = local_454 + 1) {
    MAP::operator=((MAP *)(param_1 + local_454 * 0x440 + 0xe67c),local_450);
  }
  local_8 = 0xffffffff;
  MAP::~MAP(local_450);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00411002(GAME *param_1)

{
  char cVar1;
  bool bVar2;
  undefined1 uVar3;
  int iVar4;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  uint uStack_20;
  uint local_10;
  uint local_c;
  int local_8;
  
  iVar4 = FUN_004213b1((int)param_1);
  if (iVar4 == 0) {
    local_10 = FUN_00411301(param_1);
    if (local_10 == 0xffffffff) {
      local_10 = FUN_00411273(param_1);
    }
    if (local_10 == 0xffffffff) {
      uStack_20 = 0x1b;
      (**(code **)(*(int *)param_1 + 0x24))();
      return;
    }
    FUN_004058b0(&uStack_20,local_10);
    MAP::Load((MAP *)(param_1 + 0xe23c));
    FUN_00417f6e((int *)param_1);
    uStack_20 = 0x4111e1;
    GAME::ChangeState(param_1,6);
    return;
  }
  uStack_20 = 0x41102d;
  FUN_00405910(param_1 + 0xe23c,&local_c);
  cVar1 = FUN_00411e50(&local_c);
  if (cVar1 == '\0') {
    return;
  }
  local_8 = local_8 + 1;
  cVar1 = FUN_00411e50(&local_c);
  if (cVar1 != '\0') {
    uStack_20 = local_c;
    bVar2 = MAP::Exists();
    if (bVar2) {
      uVar3 = FUN_00414141((int)param_1);
      if ((CONCAT31(extraout_var,uVar3) == 0) &&
         (cVar1 = (**(code **)(**(int **)(param_1 + 0x129b4) + 0x20))(), cVar1 == '\0')) {
LAB_00411141:
        uStack_20 = local_c;
        MAP::Load((MAP *)(param_1 + 0xe23c));
        FUN_00417f6e((int *)param_1);
        uStack_20 = 0x41116b;
        GAME::ChangeState(param_1,6);
        return;
      }
      uVar3 = FUN_00414141((int)param_1);
      if ((CONCAT31(extraout_var_00,uVar3) != 0) &&
         (cVar1 = (**(code **)(**(int **)(param_1 + 0x129b4) + 0x20))(), cVar1 == '\0')) {
        uStack_20 = local_c;
        bVar2 = MAP::RefreshItemMap();
        if (bVar2) goto LAB_00411141;
      }
      uVar3 = FUN_00414141((int)param_1);
      if ((CONCAT31(extraout_var_01,uVar3) == 0) &&
         (cVar1 = (**(code **)(**(int **)(param_1 + 0x129b4) + 0x20))(), cVar1 != '\0')) {
        uStack_20 = local_c;
        bVar2 = MAP::RefreshItemMap();
        if (bVar2) goto LAB_00411141;
      }
    }
  }
  uStack_20 = 0x1b;
  (**(code **)(*(int *)param_1 + 0x24))();
  return;
}



void __thiscall FUN_004111e5(void *this,uint param_1)

{
  bool bVar1;
  undefined1 auStack_18 [4];
  undefined4 uStack_14;
  void *local_10;
  
  local_10 = this;
  FUN_004058b0(auStack_18,param_1);
  bVar1 = MAP::Exists();
  if (!bVar1) {
    uStack_14 = 0x411216;
    bVar1 = FUN_0040e0e0((int)local_10);
    if (!bVar1) goto LAB_0041123c;
  }
  FUN_004058b0(auStack_18,param_1);
  MAP::Load((MAP *)((int)local_10 + 0xe23c));
LAB_0041123c:
  uStack_14 = 0x41124b;
  MAP::DestroyMovingObjects((MAP *)((int)local_10 + 0xe23c));
  uStack_14 = 0x411259;
  FUN_00411ee0((MAP *)((int)local_10 + 0xe23c));
  uStack_14 = 0x41125f;
  GKERNEL::SpriteFlip();
  uStack_14 = 0x41126d;
  FUN_00411ee0((MAP *)((int)local_10 + 0xe23c));
  return;
}



int __fastcall FUN_00411273(void *param_1)

{
  bool bVar1;
  int *piVar2;
  int iVar3;
  undefined3 extraout_var;
  undefined4 local_10 [2];
  int local_8;
  
  piVar2 = FUN_00405910((void *)((int)param_1 + 0xe23c),local_10);
  for (local_8 = FUN_004058f0(piVar2);
      (((local_8 != 1 && (local_8 != 0x65)) && (local_8 != 0xc9)) && (local_8 != 0x12d));
      local_8 = local_8 + -1) {
    iVar3 = FUN_00411719(param_1,local_8 - 1);
    if ((iVar3 != 0) && (bVar1 = FUN_00411392(param_1), CONCAT31(extraout_var,bVar1) == 0)) {
      return local_8 + -1;
    }
  }
  return -1;
}



int __fastcall FUN_00411301(void *param_1)

{
  bool bVar1;
  int *piVar2;
  int iVar3;
  undefined3 extraout_var;
  undefined4 local_10 [2];
  int local_8;
  
  piVar2 = FUN_00405910((void *)((int)param_1 + 0xe23c),local_10);
  for (local_8 = FUN_004058f0(piVar2);
      (((local_8 != 0x1e && (local_8 != 0x82)) && (local_8 != 0xe6)) && (local_8 != 0x14a));
      local_8 = local_8 + 1) {
    iVar3 = FUN_00411719(param_1,local_8 + 1);
    if ((iVar3 != 0) && (bVar1 = FUN_00411392(param_1), CONCAT31(extraout_var,bVar1) == 0)) {
      return local_8 + 1;
    }
  }
  return -1;
}



bool __fastcall FUN_00411392(void *param_1)

{
  CString *pCVar1;
  char *pcVar2;
  undefined4 *puVar3;
  int iVar4;
  bool bVar5;
  CString local_34 [4];
  CString local_30 [4];
  CString local_2c [4];
  uint local_28;
  CString local_24 [4];
  CString local_20 [4];
  CString local_1c [4];
  SECTION local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429c26;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00408bc0(local_18,(int)param_1 + 0xf4,s_Solved_00434ea0);
  local_8 = 0;
  pCVar1 = FUN_00413a8e(param_1,local_20);
  local_8._0_1_ = 1;
  FUN_00401470((undefined4 *)pCVar1);
  pCVar1 = (CString *)INIFILE::SECTION::Get(local_18,(char *)local_24);
  local_8._0_1_ = 2;
  CString::CString(local_1c,pCVar1);
  local_8._0_1_ = 5;
  FUN_004014d0(local_24);
  local_8._0_1_ = 4;
  CString::~CString(local_20);
  FUN_00411dd0(local_2c);
  local_8._0_1_ = 6;
  pcVar2 = (char *)operator+((char *)local_30,(CString *)&param_2_00434eac);
  local_8._0_1_ = 7;
  puVar3 = (undefined4 *)operator+(local_34,pcVar2);
  local_8._0_1_ = 8;
  pcVar2 = (char *)FUN_00401470(puVar3);
  iVar4 = CString::Find(local_1c,pcVar2);
  local_28 = CONCAT31(local_28._1_3_,iVar4 != -1);
  local_8._0_1_ = 7;
  CString::~CString(local_34);
  local_8._0_1_ = 6;
  CString::~CString(local_30);
  local_8._0_1_ = 4;
  CString::~CString(local_2c);
  bVar5 = (local_28 & 0xff) == 0;
  if (bVar5) {
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_1c);
    local_8 = 0xffffffff;
    FUN_00407d90((int)local_18);
  }
  else {
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_1c);
    local_8 = 0xffffffff;
    FUN_00407d90((int)local_18);
  }
  ExceptionList = local_10;
  return !bVar5;
}



void __thiscall FUN_00411531(void *this,undefined4 param_1,char param_2)

{
  bool bVar1;
  undefined3 extraout_var;
  CString *pCVar2;
  char *pcVar3;
  char *pcVar4;
  CString local_34 [4];
  CString local_30 [4];
  CString local_2c [4];
  CString local_28 [4];
  CString local_24 [4];
  CString local_20 [4];
  SECTION local_1c [8];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429c78;
  local_10 = ExceptionList;
  if ((*(char *)((int)this + 0xe014) == '\0') &&
     (ExceptionList = &local_10, bVar1 = FUN_00411392(this),
     (bool)param_2 != (CONCAT31(extraout_var,bVar1) != 0))) {
    FUN_00408bc0(local_1c,(int)this + 0xf4,s_Solved_00434eb0);
    local_8 = 0;
    pCVar2 = FUN_00413a8e(this,local_24);
    local_8._0_1_ = 1;
    FUN_00401470((undefined4 *)pCVar2);
    pCVar2 = (CString *)INIFILE::SECTION::Get(local_1c,(char *)local_28);
    local_8._0_1_ = 2;
    CString::CString(local_20,pCVar2);
    local_8._0_1_ = 5;
    FUN_004014d0(local_28);
    local_8._0_1_ = 4;
    CString::~CString(local_24);
    FUN_00411dd0(local_2c);
    local_8._0_1_ = 6;
    pcVar3 = (char *)operator+((char *)local_30,(CString *)&param_2_00434ebc);
    local_8._0_1_ = 7;
    operator+(local_14,pcVar3);
    local_8._0_1_ = 10;
    CString::~CString(local_30);
    local_8 = CONCAT31(local_8._1_3_,9);
    CString::~CString(local_2c);
    if (param_2 == '\0') {
      pcVar4 = &DAT_00448fc8;
      pcVar3 = (char *)FUN_00401470((undefined4 *)local_14);
      CString::Replace(local_20,pcVar3,pcVar4);
    }
    else {
      CString::operator+=(local_20,local_14);
    }
    pcVar3 = (char *)FUN_00401470((undefined4 *)local_20);
    pCVar2 = FUN_00413a8e(this,local_34);
    local_8._0_1_ = 0xb;
    pcVar4 = (char *)FUN_00401470((undefined4 *)pCVar2);
    INIFILE::SECTION::Put(local_1c,pcVar4,pcVar3);
    local_8._0_1_ = 9;
    CString::~CString(local_34);
    local_8._0_1_ = 4;
    CString::~CString(local_14);
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_20);
    local_8 = 0xffffffff;
    FUN_00407d90((int)local_1c);
  }
  ExceptionList = local_10;
  return;
}



undefined4 __thiscall FUN_00411719(void *this,uint param_1)

{
  bool bVar1;
  undefined4 uVar2;
  undefined3 extraout_var;
  undefined4 uStack_28;
  uint uStack_24;
  void *local_20;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  uStack_24 = 0x41172a;
  local_20 = this;
  bVar1 = FUN_0040e0e0((int)this);
  if (bVar1) {
    uVar2 = 1;
  }
  else {
    FUN_004058b0(&uStack_28,param_1);
    bVar1 = MAP::Exists();
    if (bVar1) {
      if (*(char *)(*(int *)((int)local_20 + 0x38) + 0x1a1) == '\0') {
        if (*(char *)(*(int *)((int)local_20 + 0x38) + 0x1a3) == '\0') {
          local_14 = 0;
          if ((((param_1 < 4) || ((99 < param_1 && (param_1 < 0x69)))) ||
              ((199 < param_1 && (param_1 < 0xcd)))) || ((299 < param_1 && (param_1 < 0x131)))) {
            uVar2 = 1;
          }
          else {
            local_18 = 0;
            local_8 = 0;
            local_10 = 0;
            if ((4 < param_1) && (param_1 < 9)) {
              local_18 = 1;
              local_8 = 4;
              local_10 = 3;
            }
            if ((8 < param_1) && (param_1 < 0xd)) {
              local_18 = 5;
              local_8 = 8;
              local_10 = 3;
            }
            if ((0xc < param_1) && (param_1 < 0x10)) {
              local_18 = 9;
              local_8 = 0xc;
              local_10 = 3;
            }
            if ((0xf < param_1) && (param_1 < 0x13)) {
              local_18 = 0xd;
              local_8 = 0xf;
              local_10 = 2;
            }
            if ((0x12 < param_1) && (param_1 < 0x17)) {
              local_18 = 0x10;
              local_8 = 0x12;
              local_10 = 2;
            }
            if ((0x16 < param_1) && (param_1 < 0x1b)) {
              local_18 = 0x13;
              local_8 = 0x16;
              local_10 = 3;
            }
            if ((0x1a < param_1) && (param_1 < 0x1f)) {
              local_18 = 0x17;
              local_8 = 0x1a;
              local_10 = 3;
            }
            if ((0x68 < param_1) && (param_1 < 0x6d)) {
              local_18 = 0x65;
              local_8 = 0x68;
              local_10 = 3;
            }
            if ((0x6c < param_1) && (param_1 < 0x71)) {
              local_18 = 0x69;
              local_8 = 0x6c;
              local_10 = 3;
            }
            if ((0x70 < param_1) && (param_1 < 0x74)) {
              local_18 = 0x6d;
              local_8 = 0x70;
              local_10 = 3;
            }
            if ((0x73 < param_1) && (param_1 < 0x77)) {
              local_18 = 0x71;
              local_8 = 0x73;
              local_10 = 2;
            }
            if ((0x76 < param_1) && (param_1 < 0x7b)) {
              local_18 = 0x74;
              local_8 = 0x76;
              local_10 = 2;
            }
            if ((0x7a < param_1) && (param_1 < 0x7f)) {
              local_18 = 0x77;
              local_8 = 0x7a;
              local_10 = 3;
            }
            if ((0x7e < param_1) && (param_1 < 0x83)) {
              local_18 = 0x7b;
              local_8 = 0x7e;
              local_10 = 3;
            }
            if ((0xcc < param_1) && (param_1 < 0xd1)) {
              local_18 = 0xc9;
              local_8 = 0xcc;
              local_10 = 3;
            }
            if ((0xd0 < param_1) && (param_1 < 0xd5)) {
              local_18 = 0xcd;
              local_8 = 0xd0;
              local_10 = 3;
            }
            if ((0xd4 < param_1) && (param_1 < 0xd8)) {
              local_18 = 0xd1;
              local_8 = 0xd4;
              local_10 = 3;
            }
            if ((0xd7 < param_1) && (param_1 < 0xdb)) {
              local_18 = 0xd5;
              local_8 = 0xd7;
              local_10 = 2;
            }
            if ((0xda < param_1) && (param_1 < 0xdf)) {
              local_18 = 0xd8;
              local_8 = 0xda;
              local_10 = 2;
            }
            if ((0xde < param_1) && (param_1 < 0xe3)) {
              local_18 = 0xdb;
              local_8 = 0xde;
              local_10 = 3;
            }
            if ((0xe2 < param_1) && (param_1 < 0xe7)) {
              local_18 = 0xdf;
              local_8 = 0xe2;
              local_10 = 3;
            }
            if ((0x130 < param_1) && (param_1 < 0x135)) {
              local_18 = 0x12d;
              local_8 = 0x130;
              local_10 = 3;
            }
            if ((0x134 < param_1) && (param_1 < 0x139)) {
              local_18 = 0x131;
              local_8 = 0x134;
              local_10 = 3;
            }
            if ((0x138 < param_1) && (param_1 < 0x13c)) {
              local_18 = 0x135;
              local_8 = 0x138;
              local_10 = 3;
            }
            if ((0x13b < param_1) && (param_1 < 0x13f)) {
              local_18 = 0x139;
              local_8 = 0x13b;
              local_10 = 2;
            }
            if ((0x13e < param_1) && (param_1 < 0x143)) {
              local_18 = 0x13c;
              local_8 = 0x13e;
              local_10 = 2;
            }
            if ((0x142 < param_1) && (param_1 < 0x147)) {
              local_18 = 0x13f;
              local_8 = 0x142;
              local_10 = 3;
            }
            if ((0x146 < param_1) && (param_1 < 0x14b)) {
              local_18 = 0x143;
              local_8 = 0x146;
              local_10 = 3;
            }
            for (local_c = local_18; local_c <= local_8; local_c = local_c + 1) {
              uStack_24 = local_c;
              uStack_28 = 0x411c10;
              bVar1 = FUN_00411392(local_20);
              if (CONCAT31(extraout_var,bVar1) != 0) {
                local_14 = local_14 + 1;
              }
            }
            if (local_14 < local_10) {
              uVar2 = 0;
            }
            else {
              uVar2 = 1;
            }
          }
        }
        else {
          uVar2 = 1;
        }
      }
      else {
        uVar2 = 1;
      }
    }
    else {
      uVar2 = 0;
    }
  }
  return uVar2;
}



void __fastcall FUN_00411c36(GAME *param_1)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  
  cVar1 = FUN_00411ea0((int)(param_1 + 0xe23c));
  if (cVar1 != '\0') {
    iVar3 = FUN_004213b1((int)param_1);
    if ((iVar3 != 0) && (iVar3 = FUN_00421436((int)param_1), iVar3 == 0)) {
      return;
    }
    bVar2 = FUN_0040e0e0((int)param_1);
    if ((!bVar2) && (*(int *)(param_1 + 0xe018) == 0)) {
      cVar1 = FUN_00411ec0((int)(param_1 + 0xe23c));
      if (cVar1 == '\0') {
        GAME::ChangeState(param_1,0xb);
      }
      else {
        GAME::ChangeState(param_1,0xc);
        FUN_0040b6b0((DWORD *)(param_1 + 0x12820));
      }
    }
  }
  return;
}



void __fastcall FUN_00411cca(void *param_1)

{
  CString *pCVar1;
  int iVar2;
  undefined4 uStack_38;
  CString local_24 [4];
  undefined1 *local_20;
  uint local_1c;
  int local_18;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429c8b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  for (local_14 = 0; local_14 < 4; local_14 = local_14 + 1) {
    if (DAT_00448fc4 != '\0') {
      uStack_38 = 0x411d22;
      FUN_0041213f(param_1,local_14 * 10 + 0x14);
    }
    for (local_18 = 0; local_18 < 0x1e; local_18 = local_18 + 1) {
      local_1c = local_14 * 100 + 1 + local_18;
      local_20 = (undefined1 *)&uStack_38;
      FUN_004058b0(&uStack_38,local_1c);
      pCVar1 = (CString *)MAP::GetLevelData(local_24);
      local_8 = 0;
      uStack_38 = 0x411d94;
      CString::operator=((CString *)((int)param_1 + (local_14 * 0x1e + local_18) * 4 + 0x1263c),
                         pCVar1);
      local_8 = 0xffffffff;
      CString::~CString(local_24);
    }
  }
  iVar2 = FUN_004056c0((int)param_1);
  uStack_38 = 0x411dbb;
  FUN_004132e0(param_1,iVar2);
  ExceptionList = local_10;
  return;
}



CString * __cdecl FUN_00411dd0(CString *param_1)

{
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_00429cc0;
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



undefined1 __fastcall FUN_00411e50(uint *param_1)

{
  undefined1 local_c;
  
  if ((((*param_1 == 0) || (4 < *param_1)) || (param_1[1] == 0)) || (0x1e < param_1[1])) {
    local_c = 0;
  }
  else {
    local_c = 1;
  }
  return local_c;
}



undefined1 __fastcall FUN_00411ea0(int param_1)

{
  return *(undefined1 *)(param_1 + 0x438);
}



undefined1 __fastcall FUN_00411ec0(int param_1)

{
  return *(undefined1 *)(param_1 + 0x43a);
}



void __fastcall FUN_00411ee0(MAP *param_1)

{
  MAP::NewFrame(param_1,1);
  return;
}



void __fastcall FUN_00411f00(int *param_1)

{
  CString *pCVar1;
  char *pcVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  undefined1 uVar6;
  undefined4 uVar7;
  CString CVar8;
  CString local_f4 [4];
  undefined1 *local_f0;
  CString local_ec [4];
  CString local_e8 [4];
  OVERLAY local_e4 [208];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429d00;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  for (local_14 = 0; local_14 < 2; local_14 = local_14 + 1) {
    pCVar1 = FUN_004014f0(local_ec);
    local_8 = 0;
    operator+(local_e8,(char *)pCVar1);
    local_8 = CONCAT31(local_8._1_3_,2);
    CString::~CString(local_ec);
    CVar8 = (CString)0x0;
    pcVar2 = (char *)FUN_00401470((undefined4 *)local_e8);
    GKTOOLS::TileDIBToSurface((DD_SURFACE *)ddsBack_exref,pcVar2,(bool)CVar8);
    GKERNEL::Flip();
    local_8 = 0xffffffff;
    CString::~CString(local_e8);
  }
  OVERLAY::OVERLAY(local_e4);
  local_8 = 3;
  local_f0 = &stack0xfffffedc;
  CString::CString((CString *)&stack0xfffffedc,s_Loading_bmp_00434ee4);
  uVar6 = SUB41(local_f4,0);
  puVar3 = (undefined4 *)(**(code **)(*param_1 + 0x54))();
  local_8._0_1_ = 4;
  pcVar2 = (char *)FUN_00401470(puVar3);
  OVERLAY::Init(local_e4,pcVar2,(bool)uVar6);
  local_8 = CONCAT31(local_8._1_3_,3);
  CString::~CString(local_f4);
  OVERLAY::SetPosition(local_e4,0x114,0x188);
  OVERLAY::DrawToBack(local_e4);
  iVar4 = FUN_004132c0((int)local_e4);
  iVar5 = FUN_004132a0((int)local_e4);
  TwTransparentOverlay::Init((TwTransparentOverlay *)(param_1 + 0x4a0c),iVar5,iVar4);
  iVar4 = OVERLAY::Position(local_e4);
  uVar7 = *(undefined4 *)(iVar4 + 4);
  puVar3 = (undefined4 *)OVERLAY::Position(local_e4);
  (**(code **)(param_1[0x4a0c] + 0x2c))(*puVar3,uVar7);
  TwProgressBar::SetParams((TwProgressBar *)(param_1 + 0x4a0c),0x1f,0xffffff,0);
  GKERNEL::NewSpriteBackground();
  (**(code **)(*(int *)param_1[0x3803] + 0x20))();
  local_8 = 0xffffffff;
  FUN_0040c7b0((undefined4 *)local_e4);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_0041213f(void *this,uint param_1)

{
  TwProgressBar::SetPercentage((TwProgressBar *)((int)this + 0x12830),param_1);
  (**(code **)(*(int *)((int)this + 0x12830) + 0x14))();
  GKERNEL::Flip();
  (**(code **)(*(int *)((int)this + 0x12830) + 0x14))();
  GKERNEL::Flip();
  return;
}



void __fastcall FUN_00412195(GAME *param_1)

{
  char *pcVar1;
  void *pvVar2;
  DD_SURFACE *pDVar3;
  uint uVar4;
  undefined4 uVar5;
  int extraout_ECX;
  int extraout_ECX_00;
  int extraout_ECX_01;
  int extraout_ECX_02;
  int extraout_ECX_03;
  int extraout_ECX_04;
  int extraout_ECX_05;
  int extraout_ECX_06;
  int extraout_ECX_07;
  uint uVar6;
  uint uVar7;
  CString aCStack_3cc [4];
  undefined4 uStack_3c8;
  CString aCStack_3c0 [4];
  undefined4 uStack_3bc;
  undefined4 uStack_3b8;
  undefined4 uStack_3b4;
  undefined4 uStack_3b0;
  CString aCStack_3a8 [4];
  undefined4 uStack_3a4;
  CString aCStack_39c [4];
  undefined4 uStack_398;
  undefined4 uStack_394;
  undefined4 uStack_390;
  undefined4 uStack_38c;
  undefined4 uStack_384;
  bool bVar8;
  undefined1 *puVar9;
  int iVar10;
  undefined1 uVar11;
  int iVar12;
  int iVar13;
  undefined4 uStack_2c0;
  undefined4 *local_2bc;
  undefined4 *local_2b8;
  undefined4 local_2b4;
  undefined4 *local_2b0;
  undefined4 *local_2ac;
  undefined4 local_2a8;
  undefined4 *local_2a4;
  undefined4 *local_2a0;
  undefined4 local_29c;
  undefined4 *local_298;
  undefined4 *local_294;
  undefined4 local_290;
  undefined4 *local_28c;
  undefined4 *local_288;
  undefined4 local_284;
  undefined4 *local_280;
  undefined4 *local_27c;
  undefined4 local_278;
  int local_274;
  undefined4 local_270;
  undefined4 *local_26c;
  undefined4 *local_268;
  undefined4 local_264;
  undefined4 *local_260;
  undefined4 *local_25c;
  undefined4 local_258;
  undefined4 *local_254;
  undefined4 *local_250;
  undefined4 local_24c;
  undefined4 *local_248;
  undefined4 *local_244;
  undefined4 local_240;
  undefined4 *local_23c;
  undefined4 *local_238;
  undefined4 local_234;
  undefined4 *local_230;
  undefined4 *local_22c;
  undefined4 local_228;
  undefined4 *local_224;
  undefined4 *local_220;
  undefined4 local_21c;
  undefined4 *local_218;
  undefined4 *local_214;
  undefined4 local_210;
  undefined4 *local_20c;
  undefined4 *local_208;
  undefined4 local_204;
  undefined4 *local_200;
  undefined4 *local_1fc;
  undefined4 local_1f8;
  undefined4 *local_1f4;
  undefined4 *local_1f0;
  undefined4 local_1ec;
  undefined4 *local_1e8;
  undefined4 *local_1e4;
  undefined4 local_1e0;
  CString *local_1dc;
  CString *local_1d8;
  undefined4 local_1d4;
  CString *local_1d0;
  CString *local_1cc;
  undefined4 local_1c8;
  CString *local_1c4;
  CString *local_1c0;
  undefined4 local_1bc;
  CString *local_1b8;
  CString *local_1b4;
  undefined4 local_1b0;
  CString *local_1ac;
  CString *local_1a8;
  undefined4 local_1a4;
  CString *local_1a0;
  CString *local_19c;
  undefined4 local_198;
  CString *local_194;
  CString *local_190;
  undefined4 local_18c;
  CString *local_188;
  CString *local_184;
  undefined4 local_180;
  CString *local_17c;
  CString *local_178;
  undefined4 local_174;
  GAME *local_170;
  CString local_16c [4];
  undefined1 *local_168;
  CString local_164 [4];
  undefined1 *local_160;
  CString local_15c [4];
  undefined1 *local_158;
  CString local_154 [4];
  undefined1 *local_150;
  CString local_14c [4];
  undefined1 *local_148;
  CString local_144 [4];
  undefined1 *local_140;
  SPRITE *local_13c;
  int local_138;
  undefined4 *local_134;
  undefined4 *local_130;
  CString local_12c [4];
  undefined1 *local_128;
  CString local_124 [4];
  undefined1 *local_120;
  CString local_11c [4];
  undefined1 *local_118;
  CString local_114 [4];
  undefined1 *local_110;
  CString local_10c [4];
  undefined1 *local_108;
  CString local_104 [4];
  undefined1 *local_100;
  CString local_fc [4];
  undefined1 *local_f8;
  CString local_f4 [4];
  undefined1 *local_f0;
  CString local_ec [4];
  undefined1 *local_e8;
  CString local_e4 [4];
  undefined1 *local_e0;
  CString local_dc [4];
  undefined1 *local_d8;
  CString local_d4 [4];
  undefined1 *local_d0;
  CString local_cc [4];
  undefined1 *local_c8;
  CString local_c4 [4];
  undefined1 *local_c0;
  CString local_bc [4];
  undefined1 *local_b8;
  CString local_b4 [4];
  undefined1 *local_b0;
  CString local_ac [4];
  undefined1 *local_a8;
  CString local_a4 [4];
  undefined1 *local_a0;
  CString local_9c [4];
  undefined1 *local_98;
  CString local_94 [4];
  undefined1 *local_90;
  CString local_8c [4];
  undefined1 *local_88;
  tagPOINT local_84;
  undefined1 local_7c [8];
  uint local_74;
  uint local_70;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_00429e5c;
  local_10 = ExceptionList;
  uStack_2c0 = 0x4121c4;
  ExceptionList = &local_10;
  local_170 = param_1;
  FUN_00411f00((int *)param_1);
  uStack_2c0 = 0x4121d6;
  CMidi::Stop((CMidi *)(local_170 + 0x5f48));
  local_88 = (undefined1 *)&uStack_2c0;
  local_174 = CString::CString((CString *)&uStack_2c0,s_Barrel_Explosion_00434ef0);
  local_17c = (CString *)(**(code **)(*(int *)local_170 + 0x58))();
  local_8 = 0;
  local_178 = local_17c;
  CWave::Create((CWave *)(local_170 + 0x5d08),local_17c);
  local_8 = 0xffffffff;
  CString::~CString(local_8c);
  local_90 = &stack0xfffffd38;
  local_180 = CString::CString((CString *)&stack0xfffffd38,s_Barrel_Explosion_00434f04);
  local_188 = (CString *)(**(code **)(*(int *)local_170 + 0x58))();
  local_8 = 1;
  local_184 = local_188;
  CWave::Create((CWave *)(local_170 + 0x5d48),local_188);
  local_8 = 0xffffffff;
  CString::~CString(local_94);
  local_98 = &stack0xfffffd30;
  local_18c = CString::CString((CString *)&stack0xfffffd30,s_Piece_Move_00434f18);
  local_194 = (CString *)(**(code **)(*(int *)local_170 + 0x58))();
  local_8 = 2;
  local_190 = local_194;
  CWave::Create((CWave *)(local_170 + 0x5d88),local_194);
  local_8 = 0xffffffff;
  CString::~CString(local_9c);
  local_a0 = &stack0xfffffd28;
  local_198 = CString::CString((CString *)&stack0xfffffd28,s_Buffer_Stuffer_00434f24);
  local_1a0 = (CString *)(**(code **)(*(int *)local_170 + 0x58))();
  local_8 = 3;
  local_19c = local_1a0;
  CWave::Create((CWave *)(local_170 + 0x5dc8),local_1a0);
  local_8 = 0xffffffff;
  CString::~CString(local_a4);
  local_a8 = &stack0xfffffd20;
  local_1a4 = CString::CString((CString *)&stack0xfffffd20,s_Piece_Drop_00434f34);
  local_1ac = (CString *)(**(code **)(*(int *)local_170 + 0x58))();
  local_8 = 4;
  local_1a8 = local_1ac;
  CWave::Create((CWave *)(local_170 + 0x5e08),local_1ac);
  local_8 = 0xffffffff;
  CString::~CString(local_ac);
  local_b0 = &stack0xfffffd18;
  local_1b0 = CString::CString((CString *)&stack0xfffffd18,s_Button_Click_00434f40);
  local_1b8 = (CString *)(**(code **)(*(int *)local_170 + 0x58))();
  local_8 = 5;
  local_1b4 = local_1b8;
  CWave::Create((CWave *)(local_170 + 0x5e48),local_1b8);
  local_8 = 0xffffffff;
  CString::~CString(local_b4);
  local_b8 = &stack0xfffffd10;
  local_1bc = CString::CString((CString *)&stack0xfffffd10,s_Error_00434f50);
  local_1c4 = (CString *)(**(code **)(*(int *)local_170 + 0x58))();
  local_8 = 6;
  local_1c0 = local_1c4;
  CWave::Create((CWave *)(local_170 + 0x5e88),local_1c4);
  local_8 = 0xffffffff;
  CString::~CString(local_bc);
  local_c0 = &stack0xfffffd08;
  local_1c8 = CString::CString((CString *)&stack0xfffffd08,s_System_Complete_00434f58);
  local_1d0 = (CString *)(**(code **)(*(int *)local_170 + 0x58))();
  local_8 = 7;
  local_1cc = local_1d0;
  CWave::Create((CWave *)(local_170 + 0x5ec8),local_1d0);
  local_8 = 0xffffffff;
  CString::~CString(local_c4);
  local_c8 = &stack0xfffffd00;
  local_1d4 = CString::CString((CString *)&stack0xfffffd00,s_Piece_Rotate_00434f68);
  local_1dc = (CString *)(**(code **)(*(int *)local_170 + 0x58))();
  local_8 = 8;
  local_1d8 = local_1dc;
  CWave::Create((CWave *)(local_170 + 0x5f08),local_1dc);
  local_8 = 0xffffffff;
  CString::~CString(local_cc);
  local_d0 = &stack0xfffffcf8;
  local_1e0 = CString::CString((CString *)&stack0xfffffcf8,s_ticktock_rmi_00434f78);
  local_1e8 = (undefined4 *)(**(code **)(*(int *)local_170 + 0x58))();
  local_8 = 9;
  local_1e4 = local_1e8;
  pcVar1 = (char *)FUN_00401470(local_1e8);
  CMidi::LoadSong((CMidi *)(local_170 + 0x6344),pcVar1);
  local_8 = 0xffffffff;
  CString::~CString(local_d4);
  CWave::Play((CWave *)(local_170 + 0x5dc8),0,0,1);
  CWave::Stop((CWave *)(local_170 + 0x5dc8));
  FUN_0041213f(local_170,10);
  pvVar2 = FUN_0041c4f0(local_170,(CString *)(*(int *)(local_170 + 0x38) + 400));
  *(void **)(local_170 + 0x129b4) = pvVar2;
  (**(code **)(**(int **)(local_170 + 0x129b4) + 4))();
  FUN_0041213f(local_170,0x14);
  FUN_00410eb0(local_170);
  MAP::SetGammaLevel(*(uint *)(local_170 + 0x3c));
  FUN_0041213f(local_170,0x3c);
  iVar13 = 1;
  iVar12 = 1;
  local_d8 = &stack0xfffffce0;
  iVar10 = extraout_ECX;
  local_1ec = CString::CString((CString *)&stack0xfffffce0,s_HIGHL16M_BMP_00434f88);
  uVar11 = SUB41(local_dc,0);
  local_1f4 = (undefined4 *)(**(code **)(*(int *)local_170 + 0x54))();
  local_8 = 10;
  local_1f0 = local_1f4;
  pcVar1 = (char *)FUN_00401470(local_1f4);
  SPRITE::Init((SPRITE *)(local_170 + 0x228),pcVar1,(bool)uVar11,iVar10,iVar12,iVar13);
  local_8 = 0xffffffff;
  CString::~CString(local_dc);
  (**(code **)(*(int *)(local_170 + 0x228) + 0x20))();
  iVar13 = 1;
  iVar12 = 1;
  local_e0 = &stack0xfffffcd8;
  iVar10 = extraout_ECX_00;
  local_1f8 = CString::CString((CString *)&stack0xfffffcd8,s_sprEDITING_BMP_00434f98);
  uVar11 = SUB41(local_e4,0);
  local_200 = (undefined4 *)(**(code **)(*(int *)local_170 + 0x54))();
  local_8 = 0xb;
  local_1fc = local_200;
  pcVar1 = (char *)FUN_00401470(local_200);
  SPRITE::Init((SPRITE *)(local_170 + 0x1354),pcVar1,(bool)uVar11,iVar10,iVar12,iVar13);
  local_8 = 0xffffffff;
  CString::~CString(local_e4);
  FUN_004132c0((int)(local_170 + 0x1354));
  (**(code **)(*(int *)(local_170 + 0x1354) + 0x2c))();
  (**(code **)(*(int *)(local_170 + 0x1354) + 0x20))();
  iVar13 = 1;
  iVar12 = 1;
  local_e8 = &stack0xfffffcc8;
  iVar10 = extraout_ECX_01;
  local_204 = CString::CString((CString *)&stack0xfffffcc8,s_completeright_bmp_00434fa8);
  uVar11 = SUB41(local_ec,0);
  local_20c = (undefined4 *)(**(code **)(*(int *)local_170 + 0x54))();
  local_8 = 0xc;
  local_208 = local_20c;
  pcVar1 = (char *)FUN_00401470(local_20c);
  SPRITE::Init((SPRITE *)(local_170 + 0xbdb4),pcVar1,(bool)uVar11,iVar10,iVar12,iVar13);
  local_8 = 0xffffffff;
  CString::~CString(local_ec);
  iVar13 = 1;
  iVar12 = 1;
  local_f0 = &stack0xfffffcc0;
  iVar10 = extraout_ECX_02;
  local_210 = CString::CString((CString *)&stack0xfffffcc0,s_completeleft_bmp_00434fbc);
  uVar11 = SUB41(local_f4,0);
  local_218 = (undefined4 *)(**(code **)(*(int *)local_170 + 0x54))();
  local_8 = 0xd;
  local_214 = local_218;
  pcVar1 = (char *)FUN_00401470(local_218);
  SPRITE::Init((SPRITE *)(local_170 + 0xcee0),pcVar1,(bool)uVar11,iVar10,iVar12,iVar13);
  local_8 = 0xffffffff;
  CString::~CString(local_f4);
  (**(code **)(*(int *)(local_170 + 0xbdb4) + 0x20))();
  (**(code **)(*(int *)(local_170 + 0xcee0) + 0x20))();
  iVar13 = 1;
  iVar12 = 1;
  local_f8 = &stack0xfffffcb8;
  iVar10 = extraout_ECX_03;
  local_21c = CString::CString((CString *)&stack0xfffffcb8,s_pipe1_bmp_00434fd0);
  uVar11 = SUB41(local_fc,0);
  local_224 = (undefined4 *)(**(code **)(*(int *)local_170 + 0x54))();
  local_8 = 0xe;
  local_220 = local_224;
  pcVar1 = (char *)FUN_00401470(local_224);
  SPRITE::Init((SPRITE *)(local_170 + 0x67d8),pcVar1,(bool)uVar11,iVar10,iVar12,iVar13);
  local_8 = 0xffffffff;
  CString::~CString(local_fc);
  (**(code **)(*(int *)(local_170 + 0x67d8) + 0x20))();
  iVar13 = 1;
  iVar12 = 1;
  local_100 = &stack0xfffffcb0;
  iVar10 = extraout_ECX_04;
  local_228 = CString::CString((CString *)&stack0xfffffcb0,s_pipe2_bmp_00434fdc);
  uVar11 = SUB41(local_104,0);
  local_230 = (undefined4 *)(**(code **)(*(int *)local_170 + 0x54))();
  local_8 = 0xf;
  local_22c = local_230;
  pcVar1 = (char *)FUN_00401470(local_230);
  SPRITE::Init((SPRITE *)(local_170 + 0x7904),pcVar1,(bool)uVar11,iVar10,iVar12,iVar13);
  local_8 = 0xffffffff;
  CString::~CString(local_104);
  (**(code **)(*(int *)(local_170 + 0x7904) + 0x20))();
  iVar13 = 1;
  iVar12 = 1;
  local_108 = &stack0xfffffca8;
  iVar10 = extraout_ECX_05;
  local_234 = CString::CString((CString *)&stack0xfffffca8,s_pipe2_bmp_00434fe8);
  uVar11 = SUB41(local_10c,0);
  local_23c = (undefined4 *)(**(code **)(*(int *)local_170 + 0x54))();
  local_8 = 0x10;
  local_238 = local_23c;
  pcVar1 = (char *)FUN_00401470(local_23c);
  SPRITE::Init((SPRITE *)(local_170 + 0x8a30),pcVar1,(bool)uVar11,iVar10,iVar12,iVar13);
  local_8 = 0xffffffff;
  CString::~CString(local_10c);
  (**(code **)(*(int *)(local_170 + 0x8a30) + 0x20))();
  iVar13 = 1;
  iVar12 = 1;
  local_110 = &stack0xfffffca0;
  iVar10 = extraout_ECX_06;
  local_240 = CString::CString((CString *)&stack0xfffffca0,s_pipe1_bmp_00434ff4);
  uVar11 = SUB41(local_114,0);
  local_248 = (undefined4 *)(**(code **)(*(int *)local_170 + 0x54))();
  local_8 = 0x11;
  local_244 = local_248;
  pcVar1 = (char *)FUN_00401470(local_248);
  SPRITE::Init((SPRITE *)(local_170 + 0x9b5c),pcVar1,(bool)uVar11,iVar10,iVar12,iVar13);
  local_8 = 0xffffffff;
  CString::~CString(local_114);
  (**(code **)(*(int *)(local_170 + 0x9b5c) + 0x20))();
  iVar13 = 1;
  iVar12 = 1;
  local_118 = &stack0xfffffc98;
  iVar10 = extraout_ECX_07;
  local_24c = CString::CString((CString *)&stack0xfffffc98,s_pipe1_bmp_00435000);
  uVar11 = SUB41(local_11c,0);
  local_254 = (undefined4 *)(**(code **)(*(int *)local_170 + 0x54))();
  local_8 = 0x12;
  local_250 = local_254;
  pcVar1 = (char *)FUN_00401470(local_254);
  SPRITE::Init((SPRITE *)(local_170 + 0xac88),pcVar1,(bool)uVar11,iVar10,iVar12,iVar13);
  local_8 = 0xffffffff;
  CString::~CString(local_11c);
  (**(code **)(*(int *)(local_170 + 0xac88) + 0x20))();
  local_120 = &stack0xfffffca0;
  local_258 = CString::CString((CString *)&stack0xfffffca0,s_small_font_bmp_0043500c);
  local_260 = (undefined4 *)(**(code **)(*(int *)local_170 + 0x54))();
  local_8 = 0x13;
  local_25c = local_260;
  pcVar1 = (char *)FUN_00401470(local_260);
  FONT::InitFont((FONT *)(local_170 + 0x4c5c),pcVar1);
  local_8 = 0xffffffff;
  CString::~CString(local_124);
  local_128 = &stack0xfffffc98;
  local_264 = CString::CString((CString *)&stack0xfffffc98,s_tiny_font_bmp_0043501c);
  local_26c = (undefined4 *)(**(code **)(*(int *)local_170 + 0x54))();
  local_8 = 0x14;
  local_268 = local_26c;
  pcVar1 = (char *)FUN_00401470(local_26c);
  FONT::InitFont((FONT *)(local_170 + 0x3bb0),pcVar1);
  local_8 = 0xffffffff;
  CString::~CString(local_12c);
  FUN_0041eb38();
  FUN_0041213f(local_170,0x46);
  FUN_00416490();
  FUN_0041213f(local_170,0x50);
  FUN_0041d717();
  FUN_0041213f(local_170,0x5a);
  puVar9 = local_7c;
  pDVar3 = MAP::DefaultTiles((MAP *)(local_170 + 0xe23c));
  DD_SURFACE::Desc(pDVar3,(ulong)puVar9);
  if (*(int *)(local_170 + 0xe00c) != 0) {
    local_134 = *(undefined4 **)(local_170 + 0xe00c);
    local_130 = local_134;
    if (local_134 == (undefined4 *)0x0) {
      local_270 = 0;
    }
    else {
      local_270 = (**(code **)*local_134)();
    }
  }
  local_13c = (SPRITE *)operator_new(0x112c);
  local_8 = 0x15;
  if (local_13c == (SPRITE *)0x0) {
    local_274 = 0;
  }
  else {
    local_274 = SPRITE::SPRITE(local_13c);
  }
  local_138 = local_274;
  local_8 = 0xffffffff;
  *(int *)(local_170 + 0xe00c) = local_274;
  uVar4 = local_70 * local_74 >> 10;
  uVar6 = local_74 >> 5;
  uVar7 = local_70 >> 5;
  bVar8 = true;
  pDVar3 = MAP::DefaultTiles((MAP *)(local_170 + 0xe23c));
  uStack_384 = 0x412f3b;
  SPRITE::Init(*(SPRITE **)(local_170 + 0xe00c),pDVar3,bVar8,uVar7,uVar6,uVar4);
  FUN_00405850(&local_84);
  GKERNEL::GetCursorPos(&local_84);
  (**(code **)(**(int **)(local_170 + 0xe00c) + 0x28))();
  FUN_00414038(local_170,0xcc,(int *)0x0);
  FUN_0041213f(local_170,100);
  local_140 = &stack0xfffffc88;
  local_278 = CString::CString((CString *)&stack0xfffffc88,s_continuedn_bmp_0043502c);
  local_280 = (undefined4 *)(**(code **)(*(int *)local_170 + 0x54))();
  local_8 = 0x16;
  local_27c = local_280;
  FUN_00401470(local_280);
  local_148 = (undefined1 *)&uStack_384;
  uStack_38c = 0x412ffb;
  local_284 = CString::CString((CString *)&uStack_384,s_continueup_bmp_0043503c);
  uStack_38c = 0x413019;
  local_28c = (undefined4 *)(**(code **)(*(int *)local_170 + 0x54))();
  local_8._0_1_ = 0x17;
  uStack_38c = 0x41303a;
  local_288 = local_28c;
  uStack_38c = FUN_00401470(local_28c);
  uStack_390 = 0x413056;
  (**(code **)(*(int *)(local_170 + 0x2bfc) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,0x16);
  uStack_390 = 0x413065;
  CString::~CString(local_14c);
  local_8 = 0xffffffff;
  uStack_390 = 0x413077;
  CString::~CString(local_144);
  uStack_390 = 0x1ac;
  uStack_394 = 0x235;
  uStack_398 = 0x41309c;
  (**(code **)(*(int *)(local_170 + 0x2bfc) + 0x2c))();
  uStack_398 = 0;
  local_150 = aCStack_39c;
  uStack_3a4 = 0x4130b1;
  local_290 = CString::CString(aCStack_39c,s_btnthumbdn_bmp_0043504c);
  uStack_3a4 = 0x4130cf;
  local_298 = (undefined4 *)(**(code **)(*(int *)local_170 + 0x54))();
  local_8 = 0x18;
  uStack_3a4 = 0x4130f3;
  local_294 = local_298;
  uStack_3a4 = FUN_00401470(local_298);
  local_158 = aCStack_3a8;
  uStack_3b0 = 0x413107;
  local_29c = CString::CString(aCStack_3a8,s_btnthumbup_bmp_0043505c);
  uStack_3b0 = 0x413125;
  local_2a4 = (undefined4 *)(**(code **)(*(int *)local_170 + 0x54))();
  local_8._0_1_ = 0x19;
  uStack_3b0 = 0x413146;
  local_2a0 = local_2a4;
  uStack_3b0 = FUN_00401470(local_2a4);
  uStack_3b4 = 0x413162;
  (**(code **)(*(int *)(local_170 + 0xe024) + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,0x18);
  uStack_3b4 = 0x413171;
  CString::~CString(local_15c);
  local_8 = 0xffffffff;
  uStack_3b4 = 0x413183;
  CString::~CString(local_154);
  uStack_3b4 = 0x1ac;
  uStack_3b8 = 0x15;
  uStack_3bc = 0x4131a5;
  (**(code **)(*(int *)(local_170 + 0xe024) + 0x2c))();
  uStack_3bc = 0;
  local_160 = aCStack_3c0;
  uStack_3c8 = 0x4131ba;
  local_2a8 = CString::CString(aCStack_3c0,s_ok_down_bmp_0043506c);
  uStack_3c8 = 0x4131d8;
  local_2b0 = (undefined4 *)(**(code **)(*(int *)local_170 + 0x54))();
  local_8 = 0x1a;
  uStack_3c8 = 0x4131fc;
  local_2ac = local_2b0;
  uStack_3c8 = FUN_00401470(local_2b0);
  local_168 = aCStack_3cc;
  local_2b4 = CString::CString(aCStack_3cc,s_ok_bmp_00435078);
  local_2bc = (undefined4 *)(**(code **)(*(int *)local_170 + 0x54))(local_16c);
  local_8._0_1_ = 0x1b;
  local_2b8 = local_2bc;
  uVar5 = FUN_00401470(local_2bc);
  (**(code **)(*(int *)(local_170 + 0x2480) + 0x4c))(uVar5);
  local_8 = CONCAT31(local_8._1_3_,0x1a);
  CString::~CString(local_16c);
  local_8 = 0xffffffff;
  CString::~CString(local_164);
  ExceptionList = local_10;
  return;
}



undefined4 __fastcall FUN_004132a0(int param_1)

{
  return *(undefined4 *)(param_1 + 0xac);
}



undefined4 __fastcall FUN_004132c0(int param_1)

{
  return *(undefined4 *)(param_1 + 0xb0);
}



void __thiscall FUN_004132e0(void *this,int param_1)

{
  bool bVar1;
  CString *pCVar2;
  undefined3 extraout_var;
  int *piVar3;
  undefined3 extraout_var_00;
  LPCSTR lpString;
  HWND__ *hWnd;
  char *pcVar4;
  undefined4 local_2c [2];
  CString local_24 [4];
  CString local_20 [4];
  CString local_1c [4];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_00429e9d;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(local_18);
  local_8 = 0;
  pCVar2 = (CString *)
           INIFILE::GetValue((INIFILE *)((int)this + 0xf4),(char *)local_1c,s_Params_0043508c);
  local_8._0_1_ = 1;
  CString::CString(local_14,pCVar2);
  local_8._0_1_ = 3;
  FUN_004014d0(local_1c);
  CString::Format(local_18,(char *)local_18);
  if ((param_1 == 6) || (param_1 == 0xb)) {
    CString::operator+=(local_18,(char *)&this_004350a8);
    bVar1 = FUN_00401430((int *)(*(int *)((int)this + 0x38) + 0x18c));
    if (CONCAT31(extraout_var,bVar1) == 0) {
      pCVar2 = (CString *)operator+(local_20,(char *)(*(int *)((int)this + 0x38) + 0x18c));
      local_8._0_1_ = 4;
      CString::operator+=(local_18,pCVar2);
      local_8._0_1_ = 3;
      CString::~CString(local_20);
    }
    pCVar2 = (CString *)MAP::Name((MAP *)((int)this + 0xe23c));
    local_8._0_1_ = 5;
    CString::operator+=(local_18,pCVar2);
    local_8._0_1_ = 3;
    FUN_004014d0(local_24);
    piVar3 = FUN_00405910((void *)((int)this + 0xe23c),local_2c);
    FUN_004058f0(piVar3);
    bVar1 = FUN_00411392(this);
    if (CONCAT31(extraout_var_00,bVar1) == 0) {
      pcVar4 = s__Unsolved__004350bc;
    }
    else {
      pcVar4 = s__Solved__004350b0;
    }
    CString::operator+=(local_18,pcVar4);
  }
  lpString = (LPCSTR)FUN_00401470((undefined4 *)local_18);
  hWnd = GKERNEL::GetHwnd();
  SetWindowTextA(hWnd,lpString);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(local_14);
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  ExceptionList = local_10;
  return;
}



CString * __thiscall FUN_00413491(void *this,CString *param_1)

{
  bool bVar1;
  char *pcVar2;
  CString *pCVar3;
  CString local_1c [4];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
  puStack_c = &this_00429ee2;
  local_10 = ExceptionList;
  local_8 = 1;
  ExceptionList = &local_10;
  bVar1 = IsRelativePath((CString *)&stack0x00000008);
  if (bVar1) {
    operator+(local_14,(CString *)(*(int *)((int)this + 0x38) + 0x184));
    local_8._0_1_ = 2;
    pcVar2 = (char *)FUN_00401470((undefined4 *)local_14);
    bVar1 = exists(pcVar2);
    if (bVar1) {
      CString::CString(param_1,local_14);
      local_8._0_1_ = 1;
      CString::~CString(local_14);
      local_8 = (uint)local_8._1_3_ << 8;
      CString::~CString((CString *)&stack0x00000008);
    }
    else {
      pCVar3 = FUN_004014f0(local_18);
      local_8._0_1_ = 3;
      pCVar3 = (CString *)operator+(local_1c,(char *)pCVar3);
      local_8._0_1_ = 4;
      operator+(param_1,pCVar3);
      local_8._0_1_ = 3;
      CString::~CString(local_1c);
      local_8._0_1_ = 2;
      CString::~CString(local_18);
      local_8._0_1_ = 1;
      CString::~CString(local_14);
      local_8 = (uint)local_8._1_3_ << 8;
      CString::~CString((CString *)&stack0x00000008);
    }
  }
  else {
    CString::CString(param_1,(CString *)&stack0x00000008);
    local_8 = local_8 & 0xffffff00;
    CString::~CString((CString *)&stack0x00000008);
  }
  ExceptionList = local_10;
  return param_1;
}



CString * __thiscall FUN_004135ff(void *this,CString *param_1)

{
  bool bVar1;
  CString *pCVar2;
  undefined3 extraout_var;
  undefined4 *puVar3;
  char *pcVar4;
  CString local_50 [4];
  CString local_4c [4];
  CString local_48 [4];
  uint local_44;
  CString local_40 [4];
  CString local_3c [4];
  CString local_38 [4];
  CString local_34 [4];
  CString local_30 [4];
  uint local_2c;
  CString local_28 [4];
  uint local_24;
  CString local_20 [4];
  CString local_1c [4];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_00429f81;
  local_10 = ExceptionList;
  local_8 = 1;
  ExceptionList = &local_10;
  pCVar2 = (CString *)operator+(local_1c,(CString *)(*(int *)((int)this + 0x38) + 0x188));
  local_8._0_1_ = 2;
  FUN_00405680(local_14,pCVar2);
  local_8._0_1_ = 4;
  CString::~CString(local_1c);
  FUN_00401470((undefined4 *)local_14);
  pCVar2 = (CString *)ExtractFileExt((char *)local_20);
  local_8._0_1_ = 5;
  FUN_00405680(local_18,pCVar2);
  local_8._0_1_ = 7;
  CString::~CString(local_20);
  bVar1 = FUN_00401430((int *)local_18);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    pcVar4 = (char *)FUN_00401470((undefined4 *)local_14);
    bVar1 = exists(pcVar4);
    if (bVar1) {
      CString::CString(param_1,local_14);
      local_8._0_1_ = 4;
      FUN_004014d0(local_18);
      local_8._0_1_ = 1;
      FUN_004014d0(local_14);
      local_8 = (uint)local_8._1_3_ << 8;
      CString::~CString((CString *)&stack0x00000008);
    }
    else {
      pCVar2 = FUN_004014f0(local_4c);
      local_8._0_1_ = 0xf;
      pCVar2 = (CString *)operator+(local_50,(char *)pCVar2);
      local_8._0_1_ = 0x10;
      operator+(param_1,pCVar2);
      local_8._0_1_ = 0xf;
      CString::~CString(local_50);
      local_8._0_1_ = 7;
      CString::~CString(local_4c);
      local_8._0_1_ = 4;
      FUN_004014d0(local_18);
      local_8._0_1_ = 1;
      FUN_004014d0(local_14);
      local_8 = (uint)local_8._1_3_ << 8;
      CString::~CString((CString *)&stack0x00000008);
    }
  }
  else {
    puVar3 = (undefined4 *)operator+(local_28,(char *)local_14);
    local_8._0_1_ = 8;
    pcVar4 = (char *)FUN_00401470(puVar3);
    bVar1 = exists(pcVar4);
    local_24 = CONCAT31(local_24._1_3_,bVar1);
    local_8._0_1_ = 7;
    CString::~CString(local_28);
    if ((local_24 & 0xff) == 0) {
      puVar3 = (undefined4 *)operator+(local_30,(char *)local_14);
      local_8._0_1_ = 9;
      pcVar4 = (char *)FUN_00401470(puVar3);
      bVar1 = exists(pcVar4);
      local_2c = CONCAT31(local_2c._1_3_,bVar1);
      local_8._0_1_ = 7;
      CString::~CString(local_30);
      if ((local_2c & 0xff) == 0) {
        pCVar2 = FUN_004014f0(local_38);
        local_8._0_1_ = 10;
        pCVar2 = (CString *)operator+(local_3c,(char *)pCVar2);
        local_8._0_1_ = 0xb;
        pCVar2 = (CString *)operator+(local_40,pCVar2);
        local_8._0_1_ = 0xc;
        FUN_00405680(local_34,pCVar2);
        local_8._0_1_ = 0xd;
        FUN_004048d0(local_14,local_34);
        local_8._0_1_ = 0xc;
        FUN_004014d0(local_34);
        local_8._0_1_ = 0xb;
        CString::~CString(local_40);
        local_8._0_1_ = 10;
        CString::~CString(local_3c);
        local_8._0_1_ = 7;
        CString::~CString(local_38);
        puVar3 = (undefined4 *)operator+(local_48,(char *)local_14);
        local_8._0_1_ = 0xe;
        pcVar4 = (char *)FUN_00401470(puVar3);
        bVar1 = exists(pcVar4);
        local_44 = CONCAT31(local_44._1_3_,bVar1);
        local_8._0_1_ = 7;
        CString::~CString(local_48);
        if ((local_44 & 0xff) == 0) {
          operator+(param_1,(char *)local_14);
          local_8._0_1_ = 4;
          FUN_004014d0(local_18);
          local_8._0_1_ = 1;
          FUN_004014d0(local_14);
          local_8 = (uint)local_8._1_3_ << 8;
          CString::~CString((CString *)&stack0x00000008);
        }
        else {
          operator+(param_1,(char *)local_14);
          local_8._0_1_ = 4;
          FUN_004014d0(local_18);
          local_8._0_1_ = 1;
          FUN_004014d0(local_14);
          local_8 = (uint)local_8._1_3_ << 8;
          CString::~CString((CString *)&stack0x00000008);
        }
      }
      else {
        operator+(param_1,(char *)local_14);
        local_8._0_1_ = 4;
        FUN_004014d0(local_18);
        local_8._0_1_ = 1;
        FUN_004014d0(local_14);
        local_8 = (uint)local_8._1_3_ << 8;
        CString::~CString((CString *)&stack0x00000008);
      }
    }
    else {
      operator+(param_1,(char *)local_14);
      local_8._0_1_ = 4;
      FUN_004014d0(local_18);
      local_8._0_1_ = 1;
      FUN_004014d0(local_14);
      local_8 = (uint)local_8._1_3_ << 8;
      CString::~CString((CString *)&stack0x00000008);
    }
  }
  ExceptionList = local_10;
  return param_1;
}



CString * __thiscall FUN_00413a8e(void *this,CString *param_1)

{
  CString::CString(param_1,(CString *)(*(int *)((int)this + 0x38) + 0x17c));
  return param_1;
}



void __fastcall FUN_00413ac5(int param_1)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  HDC pHVar4;
  HGDIOBJ h;
  undefined4 *puVar5;
  undefined4 uVar6;
  HDC in_stack_ffffffa8;
  CString local_44 [4];
  undefined1 *local_40;
  CBrush local_3c [8];
  HGDIOBJ local_34;
  HWND__ local_30;
  BOOL local_2c;
  uint local_28;
  int local_24;
  int local_20;
  int local_1c;
  int local_18;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429f9d;
  local_10 = ExceptionList;
  local_24 = 10;
  ExceptionList = &local_10;
  iVar2 = FUN_004213b1(param_1);
  if (iVar2 != 0) {
    local_24 = 0x2a;
  }
  uVar3 = FONT::GetHeight((FONT *)(param_1 + 0x4c5c));
  FUN_00414240(&local_20,0x118,local_24,0x244,local_24 + 2 + uVar3);
  if ((DAT_00448fd0 & 1) == 0) {
    DAT_00448fd0 = DAT_00448fd0 | 1;
    FUN_00405660((CString *)&DAT_00448fcc);
    FUN_00427dae(FUN_00413cc0);
  }
  local_40 = &stack0xffffffa4;
  MAP::Name((MAP *)(param_1 + 0xe23c));
  bVar1 = FUN_004141a0(&DAT_00448fcc);
  if (bVar1) {
    for (local_28 = 0; local_28 < 2; local_28 = local_28 + 1) {
      pHVar4 = DD_SURFACE::GetDC(&local_30);
      if (pHVar4 == (HDC)0x0) {
        ExceptionList = local_10;
        return;
      }
      CBrush::CBrush(local_3c,0);
      local_8 = 0;
      h = (HGDIOBJ)FUN_00414300((int)local_3c);
      local_34 = SelectObject((HDC)local_30.unused,h);
      local_2c = Rectangle((HDC)local_30.unused,local_20,local_1c,local_18,local_14);
      SelectObject((HDC)local_30.unused,local_34);
      DD_SURFACE::ReleaseDC((HWND)local_30.unused,in_stack_ffffffa8);
      GKERNEL::Flip();
      local_8 = 0xffffffff;
      FUN_00414330((undefined4 *)local_3c);
    }
  }
  puVar5 = (undefined4 *)MAP::Name((MAP *)(param_1 + 0xe23c));
  local_8 = 1;
  uVar6 = FUN_00401470(puVar5);
  FONT::CenterText((FONT *)(param_1 + 0x4c5c),uVar6,local_20,local_1c,local_18,local_14);
  local_8 = 0xffffffff;
  FUN_004014d0(local_44);
  ExceptionList = local_10;
  return;
}



void FUN_00413cc0(void)

{
  FUN_004014d0((CString *)&DAT_00448fcc);
  return;
}



void FUN_00413ccf(void)

{
  HDC pHVar1;
  HGDIOBJ h;
  HDC extraout_var;
  CBrush local_28 [8];
  HGDIOBJ local_20;
  HWND__ local_1c;
  BOOL local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429fb0;
  local_10 = ExceptionList;
  local_14 = 0;
  ExceptionList = &local_10;
  while ((local_14 < 2 && (pHVar1 = DD_SURFACE::GetDC(&local_1c), pHVar1 != (HDC)0x0))) {
    pHVar1 = extraout_var;
    CBrush::CBrush(local_28,0);
    local_8 = 0;
    h = (HGDIOBJ)FUN_00414300((int)local_28);
    local_20 = SelectObject((HDC)local_1c.unused,h);
    local_18 = Rectangle((HDC)local_1c.unused,0,0x1a0,0x280,0x1e0);
    SelectObject((HDC)local_1c.unused,local_20);
    DD_SURFACE::ReleaseDC((HWND)local_1c.unused,pHVar1);
    GKERNEL::Flip();
    local_8 = 0xffffffff;
    FUN_00414330((undefined4 *)local_28);
    local_14 = local_14 + 1;
  }
  ExceptionList = local_10;
  return;
}



void FUN_00413daa(int param_1,int param_2,int param_3,int param_4,ulong param_5)

{
  HDC pHVar1;
  HGDIOBJ pvVar2;
  HDC extraout_var;
  CBrush local_34 [8];
  HGDIOBJ local_2c;
  HWND__ local_28;
  HGDIOBJ local_24;
  CPen local_20 [8];
  CPen local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00429fd5;
  local_10 = ExceptionList;
  local_28.unused = 0;
  ExceptionList = &local_10;
  pHVar1 = DD_SURFACE::GetDC(&local_28);
  if (pHVar1 != (HDC)0x0) {
    pHVar1 = extraout_var;
    CBrush::CBrush(local_34,0);
    local_8 = 0;
    pvVar2 = (HGDIOBJ)FUN_00414300((int)local_34);
    local_2c = SelectObject((HDC)local_28.unused,pvVar2);
    CPen::CPen(local_18,0,1,param_5);
    local_8._0_1_ = 1;
    CPen::CPen(local_20,0,1,0);
    local_8._0_1_ = 2;
    pvVar2 = (HGDIOBJ)FUN_00414280((int)local_18);
    local_24 = SelectObject((HDC)local_28.unused,pvVar2);
    Rectangle((HDC)local_28.unused,param_1,param_2,param_3,param_4);
    Rectangle((HDC)local_28.unused,param_1 + 2,param_2 + 2,param_3 + -2,param_4 + -2);
    SelectObject((HDC)local_28.unused,local_24);
    SelectObject((HDC)local_28.unused,local_2c);
    DD_SURFACE::ReleaseDC((HWND)local_28.unused,pHVar1);
    local_8._0_1_ = 1;
    FUN_004142b0((undefined4 *)local_20);
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_004142b0((undefined4 *)local_18);
    local_8 = 0xffffffff;
    FUN_00414330((undefined4 *)local_34);
  }
  ExceptionList = local_10;
  return;
}



// WARNING: Variable defined which should be unmapped: param_2

void * __thiscall FUN_00413eee(void *this,void *param_2)

{
  undefined4 *puVar1;
  int iVar2;
  undefined1 local_2c [8];
  undefined1 local_24 [8];
  undefined1 local_1c [8];
  uint local_14;
  ITEM *local_10;
  uint local_c;
  uint local_8;
  
  local_8 = local_8 & 0xffffff00;
  puVar1 = (undefined4 *)default_error_condition(local_1c,0,0);
  local_10 = MAP::GetItem((MAP *)((int)this + 0xe23c),*puVar1,puVar1[1]);
  local_c = 0;
  while ((local_c < 0x14 && ((local_8 & 0xff) == 0))) {
    local_14 = 0;
    while ((local_14 < 0xd && ((local_8 & 0xff) == 0))) {
      iVar2 = (**(code **)(*(int *)local_10 + 0x34))();
      if (iVar2 != 0) {
        (**(code **)(*(int *)local_10 + 0x74))(param_2);
        return param_2;
      }
      local_14 = local_14 + 1;
      if (local_14 < 0xd) {
        puVar1 = (undefined4 *)default_error_condition(local_24,local_c,local_14);
        local_10 = MAP::GetItem((MAP *)((int)this + 0xe23c),*puVar1,puVar1[1]);
      }
      else if (local_c < 0x13) {
        puVar1 = (undefined4 *)default_error_condition(local_2c,local_c + 1,0);
        local_10 = MAP::GetItem((MAP *)((int)this + 0xe23c),*puVar1,puVar1[1]);
      }
    }
    local_c = local_c + 1;
  }
  default_error_condition(param_2,1,1);
  return param_2;
}



void __thiscall FUN_00414038(void *this,int param_1,int *param_2)

{
  bool bVar1;
  undefined1 local_74 [8];
  uint local_6c;
  uint local_68;
  DD_SURFACE *local_8;
  
  if (*(int *)((int)this + 0xe00c) != 0) {
    if ((param_1 != DAT_00435080) || (param_2 != DAT_00448fd4)) {
      DAT_00448fd4 = param_2;
      DAT_00435080 = param_1;
      local_8 = (DD_SURFACE *)0x0;
      if (param_2 == (int *)0x0) {
        local_8 = MAP::DefaultTiles((MAP *)((int)this + 0xe23c));
      }
      else {
        local_8 = (DD_SURFACE *)(**(code **)(*param_2 + 100))();
      }
      bVar1 = FUN_00414210((int *)&DAT_00448fd8,(int)local_8);
      if (bVar1) {
        DD_SURFACE::Desc(local_8,(ulong)local_74);
        SPRITE::ResetSurfaceInfo
                  (*(SPRITE **)((int)this + 0xe00c),local_8,true,local_68 >> 5,local_6c >> 5,
                   local_68 * local_6c >> 10);
        (**(code **)(**(int **)((int)this + 0xe00c) + 0x70))(param_1);
        return;
      }
    }
    (**(code **)(**(int **)((int)this + 0xe00c) + 0x70))(param_1);
  }
  return;
}



undefined1 __fastcall FUN_00414141(int param_1)

{
  return *(undefined1 *)(param_1 + 0x128);
}



bool __fastcall FUN_00414159(int param_1)

{
  return 0xe10 < *(uint *)(param_1 + 300);
}



void __fastcall FUN_00414176(int param_1)

{
  GetDriverVersion_UAP(s_TimePlayed_0043511c,*(ulong *)(param_1 + 300));
  return;
}



bool __cdecl FUN_004141a0(void *param_1)

{
  bool bVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00429fe9;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  bVar1 = FUN_0040fdf0(param_1,(undefined4 *)&stack0x00000008);
  FUN_004048d0(param_1,(CString *)&stack0x00000008);
  local_8 = 0xffffffff;
  FUN_004014d0((CString *)&stack0x00000008);
  ExceptionList = local_10;
  return bVar1;
}



bool __cdecl FUN_00414210(int *param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *param_1;
  *param_1 = param_2;
  return iVar1 != param_2;
}



void * __thiscall
FUN_00414240(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  *(undefined4 *)this = param_1;
  *(undefined4 *)((int)this + 4) = param_2;
  *(undefined4 *)((int)this + 8) = param_3;
  *(undefined4 *)((int)this + 0xc) = param_4;
  return this;
}



undefined4 __fastcall FUN_00414280(int param_1)

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



void __fastcall FUN_004142b0(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_0042db08;
  FUN_00405a40(param_1);
  return;
}



void * __thiscall FUN_004142d0(void *this,uint param_1)

{
  FUN_004142b0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



undefined4 __fastcall FUN_00414300(int param_1)

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



void __fastcall FUN_00414330(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_0042db1c;
  FUN_00405a40(param_1);
  return;
}



void * __thiscall FUN_00414350(void *this,uint param_1)

{
  FUN_00414330((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



undefined1 __fastcall FUN_00414380(void *param_1)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined4 *puVar5;
  void *pvVar6;
  CString *pCVar7;
  undefined1 local_48 [8];
  CString local_40 [4];
  uint local_3c;
  undefined1 local_38 [8];
  HICON__ local_30 [2];
  ITEM *local_28;
  int local_24;
  undefined1 local_20;
  int local_1c;
  tagPOINT local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a009;
  local_10 = ExceptionList;
  local_20 = 0;
  ExceptionList = &local_10;
  uVar2 = GKERNEL::GetCursorPos(&local_18);
  if (((uVar2 & 0xff) != 0) && (local_18.y < 0x1a0)) {
    if (*(int *)((int)param_1 + 0xe018) == 0) {
      iVar3 = local_18.x + (local_18.x >> 0x1f & 0x1fU);
      iVar4 = local_18.y + (local_18.y >> 0x1f & 0x1fU);
    }
    else {
      iVar3 = local_18.x + 0x10 + (local_18.x + 0x10 >> 0x1f & 0x1fU);
      iVar4 = local_18.y + 0x10 + (local_18.y + 0x10 >> 0x1f & 0x1fU);
    }
    local_1c = (iVar4 >> 5) * 0x20;
    local_24 = (iVar3 >> 5) * 0x20;
    puVar5 = (undefined4 *)
             default_error_condition
                       (local_38,(int)(local_24 + (local_24 >> 0x1f & 0x1fU)) >> 5,
                        (int)(local_1c + (local_1c >> 0x1f & 0x1fU)) >> 5);
    local_28 = MAP::GetItem((MAP *)((int)param_1 + 0xe23c),*puVar5,puVar5[1]);
    if ((((local_28 != (ITEM *)0x0) && (*(int *)((int)param_1 + 0xe01c) == local_24)) &&
        (*(int *)((int)param_1 + 0xe020) == local_1c)) && (*(int *)((int)param_1 + 0xe018) == 0)) {
      pCVar7 = local_40;
      pvVar6 = (void *)(**(code **)(*(int *)local_28 + 0x60))(pCVar7,s_BLANK_00435128);
      local_8 = 0;
      bVar1 = FUN_004162f0(pvVar6,(char *)pCVar7);
      local_3c = CONCAT31(local_3c._1_3_,bVar1);
      local_8 = 0xffffffff;
      CString::~CString(local_40);
      if (((local_3c & 0xff) != 0) &&
         ((iVar3 = (**(code **)(*(int *)local_28 + 0x38))(), iVar3 != 0 ||
          (bVar1 = FUN_0040e0e0((int)param_1), bVar1)))) {
        bVar1 = FUN_0040e0e0((int)param_1);
        if (bVar1) {
          FUN_0040f3a1();
        }
        (**(code **)(*(int *)local_28 + 0x74))(local_30);
        local_20 = 1;
        (**(code **)(*(int *)local_28 + 0x20))();
        CWave::Play((CWave *)((int)param_1 + 0x5f08),0,0,0);
        puVar5 = (undefined4 *)
                 default_error_condition
                           (local_48,(int)(local_24 + (local_24 >> 0x1f & 0x1fU)) >> 5,
                            (int)(local_1c + (local_1c >> 0x1f & 0x1fU)) >> 5);
        FUN_0042746d(param_1,*puVar5,puVar5[1]);
        FUN_004152e0(param_1,local_30);
      }
    }
  }
  ExceptionList = local_10;
  return local_20;
}



void __thiscall FUN_004145b0(void *this,undefined4 param_1,undefined4 param_2)

{
  bool bVar1;
  void *pvVar2;
  undefined4 *puVar3;
  undefined1 *puVar4;
  CString *pCVar5;
  int iVar6;
  CString local_2c [4];
  uint local_28;
  undefined1 local_24 [8];
  undefined1 local_1c [8];
  ITEM *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a01c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  bVar1 = FUN_0040e0e0((int)this);
  if ((!bVar1) || (bVar1 = FUN_00405940(*(int *)((int)this + 0xe010)), !bVar1)) {
    iVar6 = 0x20;
    puVar4 = local_24;
    pvVar2 = default_error_condition(local_1c,param_1,param_2);
    puVar3 = (undefined4 *)FUN_00405800(pvVar2,puVar4,iVar6);
    local_14 = MAP::GetItem((MAP *)((int)this + 0xe23c),*puVar3,puVar3[1]);
    iVar6 = FUN_004056c0((int)this);
    if ((iVar6 == 6) && ((*(int *)((int)this + 0xe018) == 0 && (local_14 != (ITEM *)0x0)))) {
      iVar6 = (**(code **)(*(int *)local_14 + 0x34))();
      if ((iVar6 == 0) || (iVar6 = (**(code **)(*(int *)local_14 + 0x38))(), iVar6 == 0)) {
        iVar6 = (**(code **)(*(int *)local_14 + 0x34))();
        if (iVar6 == 0) {
          iVar6 = (**(code **)(*(int *)local_14 + 0x38))();
          if (iVar6 == 0) {
            FUN_00414038(this,0xcc,(int *)0x0);
          }
          else {
            FUN_00414038(this,0xce,(int *)0x0);
          }
        }
        else {
          FUN_00414038(this,0xcf,(int *)0x0);
        }
      }
      else {
        pCVar5 = local_2c;
        pvVar2 = (void *)(**(code **)(*(int *)local_14 + 0x50))(pCVar5,&this_00435130);
        local_8 = 0;
        bVar1 = FUN_00404990(pvVar2,(char *)pCVar5);
        local_28 = CONCAT31(local_28._1_3_,bVar1);
        local_8 = 0xffffffff;
        CString::~CString(local_2c);
        if ((local_28 & 0xff) == 0) {
          FUN_00414038(this,0xcd,(int *)0x0);
        }
        else {
          FUN_00414038(this,0xcc,(int *)0x0);
        }
      }
    }
    else if (*(int *)((int)this + 0xe018) == 0) {
      FUN_00414038(this,0xcc,(int *)0x0);
    }
  }
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00414764(GAME *param_1)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  undefined4 *puVar4;
  void *pvVar5;
  CString *pCVar6;
  undefined1 local_4c [8];
  undefined1 local_44 [8];
  CString local_3c [4];
  uint local_38;
  undefined1 local_34 [8];
  LONG local_2c [2];
  HICON__ local_24 [2];
  ITEM *local_1c;
  tagPOINT local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a02f;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  iVar2 = FUN_004056c0((int)param_1);
  if ((iVar2 == 6) && (uVar3 = GKERNEL::GetCursorPos(&local_18), (uVar3 & 0xff) != 0)) {
    iVar2 = FUN_004213b1((int)param_1);
    if (iVar2 != 0) {
      FUN_00416310(local_2c,local_18.x,local_18.y);
      bVar1 = FUN_00422951(param_1,local_2c);
      if (bVar1) {
        ExceptionList = local_10;
        return;
      }
    }
    puVar4 = (undefined4 *)
             default_error_condition
                       (local_34,(int)(local_18.x + (local_18.x >> 0x1f & 0x1fU)) >> 5,
                        (int)(local_18.y + (local_18.y >> 0x1f & 0x1fU)) >> 5);
    local_1c = MAP::GetItem((MAP *)(param_1 + 0xe23c),*puVar4,puVar4[1]);
    if (local_1c != (ITEM *)0x0) {
      pCVar6 = local_3c;
      pvVar5 = (void *)(**(code **)(*(int *)local_1c + 0x60))(pCVar6,s_BLANK_00435134);
      local_8 = 0;
      bVar1 = FUN_004162f0(pvVar5,(char *)pCVar6);
      local_38 = CONCAT31(local_38._1_3_,bVar1);
      local_8 = 0xffffffff;
      CString::~CString(local_3c);
      if ((((local_38 & 0xff) != 0) && (iVar2 = FUN_0042167f((int)param_1), iVar2 == 0)) &&
         ((iVar2 = (**(code **)(*(int *)local_1c + 0x38))(), iVar2 != 0 ||
          (bVar1 = FUN_0040e0e0((int)param_1), bVar1)))) {
        (**(code **)(*(int *)local_1c + 0x74))(local_24);
        bVar1 = GAME::IsKeyDown(param_1,0x10);
        if (bVar1) {
          bVar1 = FUN_0040e0e0((int)param_1);
          if (bVar1) {
            FUN_0040f3a1();
          }
          (**(code **)(*(int *)local_1c + 0x20))();
          puVar4 = (undefined4 *)
                   default_error_condition
                             (local_4c,(int)(local_18.x + (local_18.x >> 0x1f & 0x1fU)) >> 5,
                              (int)(local_18.y + (local_18.y >> 0x1f & 0x1fU)) >> 5);
          FUN_0042746d(param_1,*puVar4,puVar4[1]);
        }
        else {
          bVar1 = FUN_0040e0e0((int)param_1);
          if (bVar1) {
            FUN_0040f3a1();
          }
          (**(code **)(*(int *)local_1c + 0x1c))();
          CWave::Play((CWave *)(param_1 + 0x5f08),0,0,0);
          puVar4 = (undefined4 *)
                   default_error_condition
                             (local_44,(int)(local_18.x + (local_18.x >> 0x1f & 0x1fU)) >> 5,
                              (int)(local_18.y + (local_18.y >> 0x1f & 0x1fU)) >> 5);
          FUN_004273c9(param_1,*puVar4,puVar4[1]);
        }
        FUN_004152e0(param_1,local_24);
      }
    }
  }
  ExceptionList = local_10;
  return;
}



void FUN_004149ae(void)

{
  return;
}



void __thiscall FUN_004149bb(void *this,LONG *param_1)

{
  bool bVar1;
  int iVar2;
  void *pvVar3;
  ITEM *pIVar4;
  undefined4 uVar5;
  CString *pCVar6;
  int *piVar7;
  CString local_24 [4];
  uint local_20;
  ITEM *local_1c;
  undefined4 local_18;
  undefined4 local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a042;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_0040e060(&local_18,param_1);
  FUN_0040feb0(&local_18,0x20);
  local_1c = MAP::GetItem((MAP *)((int)this + 0xe23c),local_18,local_14);
  bVar1 = FUN_0040e0e0((int)this);
  if ((((!bVar1) || (bVar1 = FUN_00405940(*(int *)((int)this + 0xe010)), !bVar1)) &&
      ((iVar2 = FUN_004213b1((int)this), iVar2 == 0 || (bVar1 = FUN_0042289f(this,param_1), !bVar1))
      )) && ((*(int *)((int)this + 0xe018) == 0 && (local_1c != (ITEM *)0x0)))) {
    pCVar6 = local_24;
    pvVar3 = (void *)(**(code **)(*(int *)local_1c + 0x60))(pCVar6,s_BLANK_0043513c);
    local_8 = 0;
    bVar1 = FUN_004162f0(pvVar3,(char *)pCVar6);
    local_20 = CONCAT31(local_20._1_3_,bVar1);
    local_8 = 0xffffffff;
    CString::~CString(local_24);
    if (((local_20 & 0xff) != 0) &&
       ((iVar2 = FUN_004056c0((int)this), iVar2 == 6 &&
        ((iVar2 = (**(code **)(*(int *)local_1c + 0x34))(), iVar2 != 0 ||
         (bVar1 = FUN_0040e0e0((int)this), bVar1)))))) {
      CWave::Play((CWave *)((int)this + 0x5d88),0,0,0);
      pIVar4 = MAP::FindItem(s_BLANK_00435144);
      uVar5 = (**(code **)(*(int *)pIVar4 + 4))();
      pIVar4 = MAP::SetItem((MAP *)((int)this + 0xe23c),local_18,local_14,uVar5);
      *(ITEM **)((int)this + 0xe018) = pIVar4;
      piVar7 = *(int **)((int)this + 0xe018);
      iVar2 = (**(code **)(**(int **)((int)this + 0xe018) + 0x70))();
      FUN_00414038(this,iVar2,piVar7);
    }
  }
  ExceptionList = local_10;
  return;
}



undefined4 __thiscall FUN_00414b83(void *this,undefined4 *param_1)

{
  bool bVar1;
  void *pvVar2;
  int iVar3;
  CString *pCVar4;
  undefined1 local_38;
  CString local_1c [4];
  uint local_18;
  ITEM *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a055;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_14 = MAP::GetItem((MAP *)((int)this + 0xe23c),*param_1,param_1[1]);
  if (local_14 == (ITEM *)0x0) {
    ExceptionList = local_10;
    return 0;
  }
  bVar1 = FUN_0040e0e0((int)this);
  if (bVar1) {
    ExceptionList = local_10;
    return 1;
  }
  pCVar4 = local_1c;
  pvVar2 = (void *)(**(code **)(*(int *)local_14 + 0x60))(pCVar4,s_BLANK_0043514c);
  local_8 = 0;
  bVar1 = FUN_004162f0(pvVar2,(char *)pCVar4);
  if (bVar1) {
    iVar3 = (**(code **)(*(int *)local_14 + 0x38))();
    if ((iVar3 == 0) && (iVar3 = (**(code **)(*(int *)local_14 + 0x34))(), iVar3 == 0)) {
      bVar1 = false;
    }
    else {
      bVar1 = true;
    }
    if (bVar1) {
      local_38 = 1;
      goto LAB_00414c6b;
    }
  }
  local_38 = 0;
LAB_00414c6b:
  local_18 = CONCAT31(local_18._1_3_,local_38);
  local_8 = 0xffffffff;
  CString::~CString(local_1c);
  if ((local_18 & 0xff) != 0) {
    ExceptionList = local_10;
    return 1;
  }
  ExceptionList = local_10;
  return 0;
}



undefined1 __thiscall FUN_00414caf(void *this,undefined4 *param_1)

{
  bool bVar1;
  int iVar2;
  void *pvVar3;
  CString *pCVar4;
  undefined1 local_2c;
  CString local_1c [4];
  uint local_18;
  ITEM *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a068;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_14 = MAP::GetItem((MAP *)((int)this + 0xe23c),*param_1,param_1[1]);
  if (local_14 == (ITEM *)0x0) {
    local_2c = 0;
  }
  else {
    iVar2 = (**(code **)(*(int *)local_14 + 0x34))();
    if (iVar2 == 0) {
      pCVar4 = local_1c;
      pvVar3 = (void *)(**(code **)(*(int *)local_14 + 0x60))(pCVar4,s_BLANK_00435154);
      local_8 = 0;
      bVar1 = FUN_00404990(pvVar3,(char *)pCVar4);
      local_18 = CONCAT31(local_18._1_3_,bVar1);
      local_8 = 0xffffffff;
      CString::~CString(local_1c);
      if (((local_18 & 0xff) == 0) && (bVar1 = FUN_0040e0e0((int)this), !bVar1)) {
        ExceptionList = local_10;
        return 0;
      }
    }
    local_2c = 1;
  }
  ExceptionList = local_10;
  return local_2c;
}



void __fastcall FUN_00414d82(GAME *param_1)

{
  char cVar1;
  bool bVar2;
  void *pvVar3;
  undefined4 *puVar4;
  int iVar5;
  uint uVar6;
  HCURSOR pHVar7;
  undefined1 auStack_14c [4];
  undefined4 uStack_148;
  undefined1 *puVar8;
  int *piVar9;
  undefined1 local_124 [8];
  undefined1 local_11c [8];
  int local_114;
  int local_110;
  undefined1 local_10c [8];
  undefined1 local_104 [8];
  undefined1 local_fc [8];
  int local_f4;
  int local_f0;
  undefined1 local_ec [8];
  undefined1 local_e4 [8];
  undefined1 local_dc [8];
  undefined1 *local_d4;
  undefined1 local_d0 [16];
  undefined1 local_c0 [16];
  int local_b0;
  int local_ac;
  undefined1 local_a8 [8];
  ITEM *local_a0;
  ITEM *local_9c;
  undefined1 local_98 [8];
  undefined4 local_90 [2];
  undefined4 local_88 [2];
  uint local_80;
  undefined4 local_7c [2];
  undefined4 local_74 [2];
  uint local_6c;
  int local_68;
  int local_64;
  CTypeLibCacheMap local_60 [28];
  int local_44;
  int local_40;
  int local_3c;
  int local_38;
  int local_34;
  int local_30;
  undefined1 local_2c [8];
  tagPOINT local_24;
  uint local_1c;
  int local_18;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a07b;
  local_10 = ExceptionList;
  local_24.x = 0;
  local_24.y = 0;
  ExceptionList = &local_10;
  local_1c = GKERNEL::GetCursorPos(&local_24);
  local_1c = local_1c & 0xff;
  if (local_1c != 0) {
    default_error_condition(&local_18,0x10,0x10);
    piVar9 = &local_18;
    puVar8 = local_2c;
    pvVar3 = default_error_condition(local_98,local_24.x,local_24.y);
    FUN_0040dff0(pvVar3,puVar8,piVar9);
    if (*(int *)(param_1 + 0xe018) == 0) {
      iVar5 = 0x20;
      puVar8 = local_104;
      local_f4 = local_18;
      local_f0 = local_14;
      uStack_148 = 0x415240;
      puVar4 = (undefined4 *)FID_conflict_operator_(local_2c,local_fc,local_18,local_14);
      pvVar3 = FUN_004163d0(local_ec,puVar4);
      puVar4 = (undefined4 *)FUN_00405800(pvVar3,puVar8,iVar5);
      uVar6 = FUN_00414b83(param_1,puVar4);
      if ((uVar6 & 0xff) != 0) {
        iVar5 = 0x20;
        puVar8 = local_124;
        local_114 = local_18;
        local_110 = local_14;
        uStack_148 = 0x4152a0;
        puVar4 = (undefined4 *)FID_conflict_operator_(local_2c,local_11c,local_18,local_14);
        pvVar3 = FUN_004163d0(local_10c,puVar4);
        pHVar7 = (HCURSOR)FUN_00405800(pvVar3,puVar8,iVar5);
        FUN_004152e0(param_1,pHVar7);
      }
    }
    else {
      (**(code **)(**(int **)(param_1 + 0xe018) + 0x74))();
      local_a0 = MAP::SetItem((MAP *)(param_1 + 0xe23c));
      local_9c = local_a0;
      if (local_a0 != (ITEM *)0x0) {
        (*(code *)**(undefined4 **)local_a0)();
      }
      *(undefined4 *)(param_1 + 0xe018) = 0;
      puVar4 = (undefined4 *)FUN_00405800(local_2c,local_a8,0x20);
      cVar1 = FUN_00414caf(param_1,puVar4);
      if (cVar1 == '\0') {
        CWave::Play((CWave *)(param_1 + 0x5e88),0,0,0);
      }
      else {
        FUN_00405800(local_2c,&local_3c,0x20);
        bVar2 = FUN_0040e0e0((int)param_1);
        if (bVar2) {
          FUN_0040f3a1();
        }
        CWave::Play((CWave *)(param_1 + 0x5e08),0,0,0);
        local_b0 = local_3c;
        local_ac = local_38;
        iVar5 = FUN_00416330(&local_34,local_3c,local_38);
        if (iVar5 != 0) {
          bVar2 = FUN_0040e0e0((int)param_1);
          if ((bVar2) && (bVar2 = GAME::IsKeyDown(param_1,0x11), bVar2)) {
            CTypeLibCacheMap::CTypeLibCacheMap(local_60);
            local_8 = 0;
            local_40 = local_3c;
            local_44 = local_34;
            if (local_3c != local_34) {
              local_6c = 0;
              while (uVar6 = FUN_00416420(), local_6c < uVar6) {
                default_error_condition(local_74,local_40,local_6c);
                default_error_condition(local_7c,local_44,local_6c);
                MAP::SelectTile((MAP *)(param_1 + 0xe23c));
                MAP::SwapTile((MAP *)(param_1 + 0xe23c));
                puVar4 = (undefined4 *)FUN_00416440(local_c0,local_7c,local_74);
                FUN_004162d0(local_60,puVar4);
                local_6c = local_6c + 1;
              }
            }
            local_64 = local_38;
            local_68 = local_30;
            if (local_38 != local_30) {
              local_80 = 0;
              while (uVar6 = FUN_00416430(), local_80 < uVar6) {
                default_error_condition(local_88,local_80,local_64);
                default_error_condition(local_90,local_80,local_68);
                MAP::SelectTile((MAP *)(param_1 + 0xe23c));
                MAP::SwapTile((MAP *)(param_1 + 0xe23c));
                puVar4 = (undefined4 *)FUN_00416440(local_d0,local_90,local_88);
                FUN_004162d0(local_60,puVar4);
                local_80 = local_80 + 1;
              }
            }
            local_d4 = auStack_14c;
            FUN_00404a00(auStack_14c,(int)local_60);
            FUN_004275c1(param_1);
            local_8 = 0xffffffff;
            FUN_00404820((undefined4 *)local_60);
          }
          else {
            MAP::SelectTile((MAP *)(param_1 + 0xe23c));
            MAP::SwapTile((MAP *)(param_1 + 0xe23c));
            FUN_00427511(param_1,local_34,local_30,local_3c,local_38);
          }
        }
        pHVar7 = (HCURSOR)FUN_00405800(local_2c,local_dc,0x20);
        FUN_004152e0(param_1,pHVar7);
        FUN_00405800(param_1 + 0xe01c,local_e4,0x20);
        MAP::SelectTile((MAP *)(param_1 + 0xe23c));
      }
    }
    FUN_004145b0(param_1,local_24.x,local_24.y);
  }
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_004152e0(void *this,HCURSOR param_1)

{
  bool bVar1;
  undefined4 *puVar2;
  undefined1 local_c [8];
  
  bVar1 = FUN_0040e0e0((int)this);
  if (bVar1) {
    bVar1 = FUN_0040e0e0((int)this);
    if (!bVar1) {
      return;
    }
    bVar1 = FUN_00405940(*(int *)((int)this + 0xe010));
    if (bVar1) {
      return;
    }
  }
  puVar2 = (undefined4 *)FUN_0040fe80(param_1,local_c,0x20);
  FUN_0040f6ea(this,puVar2);
  MAP::SetCursor(param_1);
  return;
}



void __fastcall FUN_00415352(int param_1)

{
  char cVar1;
  
  cVar1 = (**(code **)(*(int *)(param_1 + 0x38b8) + 0x44))();
  if (cVar1 == '\0') {
    FUN_0040b6f0(param_1 + 0x38b8);
  }
  else {
    FUN_00416400(param_1 + 0x38b8);
  }
  cVar1 = (**(code **)(*(int *)(param_1 + 0x3a34) + 0x44))();
  if (cVar1 == '\0') {
    FUN_0040b6f0(param_1 + 0x3a34);
  }
  else {
    FUN_00416400(param_1 + 0x3a34);
  }
  return;
}



void __fastcall FUN_004153d5(int param_1)

{
  char cVar1;
  
  cVar1 = (**(code **)(*(int *)(param_1 + 0x2efc) + 0x44))();
  if (cVar1 == '\0') {
    FUN_0040b740((int *)(param_1 + 0x2efc));
  }
  else {
    FUN_00416400(param_1 + 0x2efc);
  }
  cVar1 = (**(code **)(*(int *)(param_1 + 0x2d7c) + 0x44))();
  if (cVar1 == '\0') {
    FUN_0040b740((int *)(param_1 + 0x2d7c));
  }
  else {
    FUN_00416400(param_1 + 0x2d7c);
  }
  cVar1 = (**(code **)(*(int *)(param_1 + 0x25fc) + 0x44))();
  if (cVar1 == '\0') {
    FUN_0040b740((int *)(param_1 + 0x25fc));
  }
  else {
    FUN_00416400(param_1 + 0x25fc);
  }
  cVar1 = (**(code **)(*(int *)(param_1 + 0x277c) + 0x44))();
  if (cVar1 == '\0') {
    FUN_0040b740((int *)(param_1 + 0x277c));
  }
  else {
    FUN_00416400(param_1 + 0x277c);
  }
  cVar1 = (**(code **)(*(int *)(param_1 + 0x28fc) + 0x44))();
  if (cVar1 == '\0') {
    FUN_0040b740((int *)(param_1 + 0x28fc));
  }
  else {
    FUN_00416400(param_1 + 0x28fc);
  }
  cVar1 = (**(code **)(*(int *)(param_1 + 0x307c) + 0x44))();
  if (cVar1 == '\0') {
    FUN_0040b6f0(param_1 + 0x307c);
  }
  else {
    FUN_00416400(param_1 + 0x307c);
  }
  cVar1 = (**(code **)(*(int *)(param_1 + 0x31f8) + 0x44))();
  if (cVar1 == '\0') {
    FUN_0040b6f0(param_1 + 0x31f8);
  }
  else {
    FUN_00416400(param_1 + 0x31f8);
  }
  return;
}



void __thiscall FUN_00415584(void *this,LONG *param_1)

{
  bool bVar1;
  undefined1 uVar2;
  char cVar3;
  undefined4 uVar4;
  undefined3 extraout_var;
  int iVar5;
  undefined3 extraout_var_00;
  uint uVar6;
  
  bVar1 = FUN_0040e0e0((int)this);
  if (bVar1) {
    FUN_0040f104((int)this);
  }
  uVar4 = FUN_004056c0((int)this);
  switch(uVar4) {
  case 1:
    FUN_0040b6f0((int)this + 0x38b8);
    FUN_0040b6f0((int)this + 0x3a34);
    cVar3 = (**(code **)(*(int *)((int)this + 0x38b8) + 0x44))();
    if (cVar3 != '\0') {
      uVar2 = FUN_00414141((int)this);
      if (CONCAT31(extraout_var_00,uVar2) == 0) {
        GKERNEL::Stop();
      }
      else {
        GAME::ChangeState((GAME *)this,4);
      }
    }
    cVar3 = (**(code **)(*(int *)((int)this + 0x3a34) + 0x44))();
    if (cVar3 != '\0') {
      uVar6 = FUN_0040e0c0((int)this);
      GAME::ChangeState((GAME *)this,uVar6);
    }
    break;
  case 2:
    if (*(int *)((int)this + 0x129b8) == 0) {
      cVar3 = (**(code **)(*(int *)((int)this + 0x6568) + 0x44))();
      if (cVar3 == '\0') {
        FUN_00416157((GAME *)this);
      }
      else {
        GAME::ChangeState((GAME *)this,0xd);
      }
    }
    else {
      cVar3 = (**(code **)(*(int *)((int)this + 0x2480) + 0x44))();
      if (cVar3 != '\0') {
        FUN_0041d570(this);
      }
    }
    cVar3 = (**(code **)(*(int *)((int)this + 0x2a7c) + 0x44))();
    if (cVar3 != '\0') {
                    // WARNING: Load size is inaccurate
      (**(code **)(*this + 0x24))(0x1b,1);
    }
    break;
  case 3:
    FUN_0041adeb((GAME *)this);
    break;
  case 4:
    FUN_0040d491((GAME *)this);
    break;
  case 5:
    uVar2 = FUN_00414141((int)this);
    if (CONCAT31(extraout_var,uVar2) == 0) {
      GAME::ChangeState((GAME *)this,3);
    }
    else {
      GAME::ChangeState((GAME *)this,4);
    }
    break;
  case 6:
    FUN_0040b740((int *)((int)this + 0x277c));
    FUN_0040b740((int *)((int)this + 0x28fc));
    FUN_0040b740((int *)((int)this + 0x25fc));
    FUN_0040b740((int *)((int)this + 0x2d7c));
    FUN_0040b740((int *)((int)this + 0x2efc));
    cVar3 = (**(code **)(*(int *)((int)this + 0x2a7c) + 0x44))();
    if (cVar3 == '\0') {
      iVar5 = FUN_004213b1((int)this);
      if ((iVar5 == 0) || (bVar1 = FUN_00422a03(this,param_1), !bVar1)) {
        cVar3 = (**(code **)(*(int *)((int)this + 0x28fc) + 0x44))();
        if (cVar3 == '\0') {
          cVar3 = (**(code **)(*(int *)((int)this + 0x277c) + 0x44))();
          if (cVar3 == '\0') {
            cVar3 = (**(code **)(*(int *)((int)this + 0x2d7c) + 0x44))();
            if (cVar3 == '\0') {
              cVar3 = (**(code **)(*(int *)((int)this + 0x2efc) + 0x44))();
              if (cVar3 == '\0') {
                cVar3 = (**(code **)(*(int *)((int)this + 0x25fc) + 0x44))();
                if (cVar3 == '\0') {
                  FUN_00417425(this);
                  cVar3 = FUN_00414380(this);
                  if (cVar3 == '\0') {
                    FUN_00414d82((GAME *)this);
                  }
                }
                else {
                  FUN_0041763f();
                }
              }
              else {
                FUN_0042735b(this);
              }
            }
            else {
              FUN_004272f7(this);
            }
          }
          else {
            FUN_0040d700((GAME *)this);
          }
        }
        else {
                    // WARNING: Load size is inaccurate
          (**(code **)(*this + 0x5c))();
        }
      }
    }
    else {
                    // WARNING: Load size is inaccurate
      (**(code **)(*this + 0x24))(0x1b,1);
    }
    break;
  case 9:
    (**(code **)(**(int **)((int)this + 0x129b4) + 0x18))();
    break;
  case 10:
    iVar5 = FUN_004213b1((int)this);
    if ((((iVar5 == 0) || (bVar1 = FUN_00422a03(this,param_1), !bVar1)) &&
        (iVar5 = FUN_0042167f((int)this), iVar5 == 0)) &&
       (cVar3 = (**(code **)(*(int *)((int)this + 0x277c) + 0x44))(), cVar3 != '\0')) {
      FUN_0040d700((GAME *)this);
    }
    break;
  case 0xb:
    FUN_0040b740((int *)((int)this + 0x2bfc));
    FUN_0040b6f0((int)this + 0xe024);
    cVar3 = (**(code **)(*(int *)((int)this + 0x2bfc) + 0x44))();
    if (cVar3 == '\0') {
      cVar3 = (**(code **)(*(int *)((int)this + 0xe024) + 0x44))();
      if (cVar3 == '\0') {
        iVar5 = FUN_004213b1((int)this);
        if (iVar5 != 0) {
          FUN_00422a03(this,param_1);
        }
      }
      else {
                    // WARNING: Load size is inaccurate
        (**(code **)(*this + 0x24))(0x1b,1);
      }
    }
    else if (*(char *)((int)this + 0xe014) == '\0') {
      FUN_00411002((GAME *)this);
    }
    else {
                    // WARNING: Load size is inaccurate
      (**(code **)(*this + 0x24))(0x1b,1);
    }
    break;
  case 0xd:
    if (*(int *)((int)this + 0x129b8) == 0) {
      cVar3 = (**(code **)(*(int *)((int)this + 0x6638) + 0x44))();
      if (cVar3 == '\0') {
        FUN_00416157((GAME *)this);
      }
      else {
        GAME::ChangeState((GAME *)this,2);
      }
    }
    else {
      cVar3 = (**(code **)(*(int *)((int)this + 0x2480) + 0x44))();
      if (cVar3 != '\0') {
        FUN_0041d570(this);
      }
    }
    cVar3 = (**(code **)(*(int *)((int)this + 0x2a7c) + 0x44))();
    if (cVar3 != '\0') {
                    // WARNING: Load size is inaccurate
      (**(code **)(*this + 0x24))(0x1b,1);
    }
  }
  return;
}



void __thiscall FUN_00415aca(void *this,uint param_1,uint param_2,char param_3)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  undefined4 uVar4;
  void *pvVar5;
  uint extraout_ECX;
  uint uVar6;
  undefined1 *puVar7;
  char *pcVar8;
  CString **ppCVar9;
  undefined1 local_94;
  undefined1 local_60 [4];
  undefined1 *local_5c;
  undefined1 local_58 [4];
  undefined1 *local_54;
  undefined1 local_50 [4];
  CString local_4c [4];
  uint local_48;
  CString local_44 [4];
  uint local_40;
  CString local_3c [4];
  uint local_38;
  CString local_34 [4];
  uint local_30;
  undefined1 local_2c [8];
  undefined1 local_24 [8];
  undefined1 local_1c [8];
  ITEM *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a0a9;
  local_10 = ExceptionList;
  local_14 = (ITEM *)0x0;
  ExceptionList = &local_10;
  if ((*(int *)((int)this + 0xe00c) != 0) &&
     (ExceptionList = &local_10, cVar1 = (**(code **)(**(int **)((int)this + 0xe00c) + 0x24))(),
     cVar1 != '\0')) {
    (**(code **)(**(int **)((int)this + 0xe00c) + 0x1c))();
  }
  iVar3 = FUN_004056c0((int)this);
  if (iVar3 == 3) {
    FUN_0041ac35(param_3);
    goto LAB_0041608b;
  }
  iVar3 = FUN_004056c0((int)this);
  if (iVar3 == 4) {
    FUN_0040d3d0(param_3);
    goto LAB_0041608b;
  }
  if (param_3 != '\0') {
    uVar4 = FUN_004056c0((int)this);
    switch(uVar4) {
    case 1:
      FUN_00415352((int)this);
      break;
    case 2:
    case 0xd:
      cVar1 = (**(code **)(*(int *)((int)this + 0x2480) + 0x44))();
      if (cVar1 == '\0') {
        FUN_0040b6f0((int)this + 0x2480);
      }
      else {
        FUN_00416400((int)this + 0x2480);
      }
      break;
    case 6:
      FUN_00422cca((int)this);
      bVar2 = FUN_0040e0e0((int)this);
      if (bVar2) {
        pvVar5 = default_error_condition(local_1c,param_1,param_2);
        FUN_0040f1ab(this,pvVar5);
        FUN_004153d5((int)this);
      }
      else {
        iVar3 = FUN_0042167f((int)this);
        if (iVar3 == 0) {
          FUN_004153d5((int)this);
        }
      }
      break;
    case 10:
      FUN_00422cca((int)this);
      iVar3 = FUN_0042167f((int)this);
      if (iVar3 == 0) {
        cVar1 = (**(code **)(*(int *)((int)this + 0x277c) + 0x44))();
        if (cVar1 == '\0') {
          FUN_0040b740((int *)((int)this + 0x277c));
        }
        else {
          FUN_00416400((int)this + 0x277c);
        }
      }
      break;
    case 0xb:
      FUN_00422cca((int)this);
      cVar1 = (**(code **)(*(int *)((int)this + 0x2bfc) + 0x44))();
      if (cVar1 == '\0') {
        FUN_0040b740((int *)((int)this + 0x2bfc));
      }
      else {
        FUN_00416400((int)this + 0x2bfc);
      }
      cVar1 = (**(code **)(*(int *)((int)this + 0xe024) + 0x44))();
      if (cVar1 == '\0') {
        FUN_0040b6f0((int)this + 0xe024);
      }
      else {
        FUN_00416400((int)this + 0xe024);
      }
    }
    goto LAB_0041608b;
  }
  iVar3 = FUN_004056c0((int)this);
  if (iVar3 != 6) {
    if (iVar3 == 0xb) {
      FUN_0040b740((int *)((int)this + 0x2bfc));
      FUN_0040b6f0((int)this + 0xe024);
    }
    goto LAB_0041608b;
  }
  bVar2 = FUN_0040e0e0((int)this);
  if (bVar2) {
    FUN_00405800((void *)((int)this + 0xe01c),local_24,0x20);
    local_14 = MAP::GetItem((MAP *)((int)this + 0xe23c));
  }
  else {
    default_error_condition(local_2c,param_1 >> 5,param_2 >> 5);
    local_14 = MAP::GetItem((MAP *)((int)this + 0xe23c));
  }
  if (local_14 == (ITEM *)0x0) goto LAB_0041608b;
  bVar2 = FUN_0040e0e0((int)this);
  uVar6 = extraout_ECX;
  if (!bVar2) {
    pcVar8 = s_BLANK_0043515c;
    pvVar5 = (void *)(**(code **)(*(int *)local_14 + 0x60))();
    local_8 = 0;
    bVar2 = FUN_00404990(pvVar5,pcVar8);
    if (bVar2) {
LAB_00415f0d:
      local_94 = 1;
    }
    else {
      pcVar8 = s_BRICK_00435164;
      pvVar5 = (void *)(**(code **)(*(int *)local_14 + 0x60))();
      local_8._0_1_ = 1;
      bVar2 = FUN_00404990(pvVar5,pcVar8);
      local_38 = CONCAT31(local_38._1_3_,bVar2);
      local_8._0_1_ = 0;
      CString::~CString(local_3c);
      if ((local_38 & 0xff) != 0) goto LAB_00415f0d;
      ppCVar9 = &this_0043516c;
      pvVar5 = (void *)(**(code **)(*(int *)local_14 + 0x60))();
      local_8._0_1_ = 2;
      bVar2 = FUN_00404990(pvVar5,(char *)ppCVar9);
      local_40 = CONCAT31(local_40._1_3_,bVar2);
      local_8._0_1_ = 0;
      CString::~CString(local_44);
      if ((local_40 & 0xff) != 0) goto LAB_00415f0d;
      ppCVar9 = &this_00435170;
      pvVar5 = (void *)(**(code **)(*(int *)local_14 + 0x60))();
      local_8._0_1_ = 3;
      bVar2 = FUN_00404990(pvVar5,(char *)ppCVar9);
      local_48 = CONCAT31(local_48._1_3_,bVar2);
      local_8 = (uint)local_8._1_3_ << 8;
      CString::~CString(local_4c);
      if ((local_48 & 0xff) != 0) goto LAB_00415f0d;
      local_94 = 0;
    }
    local_30 = CONCAT31(local_30._1_3_,local_94);
    local_8 = 0xffffffff;
    CString::~CString(local_34);
    uVar6 = local_30 & 0xff;
    if (uVar6 != 0) {
      FUN_0040b6f0((int)this + 0x3444);
      FUN_0040b6f0((int)this + 0x35c0);
      FUN_0040b6f0((int)this + 0x373c);
      goto LAB_0041608b;
    }
  }
  local_54 = &stack0xffffff5c;
  FUN_00405890(&stack0xffffff5c,4);
  puVar7 = local_50;
  pvVar5 = (void *)(**(code **)(*(int *)local_14 + 0x7c))();
  bVar2 = FUN_0040fef0(pvVar5,(uint)puVar7);
  if (bVar2) {
    FUN_00416400((int)this + 0x3444);
  }
  else {
    FUN_0040b6f0((int)this + 0x3444);
  }
  local_5c = &stack0xffffff58;
  FUN_00405890(&stack0xffffff58,2);
  puVar7 = local_58;
  pvVar5 = (void *)(**(code **)(*(int *)local_14 + 0x7c))();
  bVar2 = FUN_0040fef0(pvVar5,(uint)puVar7);
  if (bVar2) {
    FUN_00416400((int)this + 0x35c0);
  }
  else {
    FUN_0040b6f0((int)this + 0x35c0);
  }
  FUN_00405890(&stack0xffffff54,1);
  pvVar5 = (void *)(**(code **)(*(int *)local_14 + 0x7c))(local_60);
  bVar2 = FUN_0040fef0(pvVar5,uVar6);
  if (bVar2) {
    FUN_00416400((int)this + 0x373c);
  }
  else {
    FUN_0040b6f0((int)this + 0x373c);
  }
LAB_0041608b:
  cVar1 = (**(code **)(*(int *)((int)this + 0x2a7c) + 0x44))();
  if (cVar1 == '\0') {
    FUN_0040b740((int *)((int)this + 0x2a7c));
  }
  else {
    FUN_00416400((int)this + 0x2a7c);
  }
  if ((*(int *)((int)this + 0xe00c) != 0) &&
     (cVar1 = (**(code **)(**(int **)((int)this + 0xe00c) + 0x24))(), cVar1 != '\0')) {
    (**(code **)(**(int **)((int)this + 0xe00c) + 0x2c))();
    FUN_004145b0(this,param_1,param_2);
  }
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00416157(GAME *param_1)

{
  char cVar1;
  bool bVar2;
  undefined1 uVar3;
  int *piVar4;
  undefined3 extraout_var;
  uint uVar5;
  int iVar6;
  int local_24 [2];
  int local_1c [2];
  int local_14 [2];
  uint local_c [2];
  
  FUN_0041e2e6(param_1,(int *)local_c);
  cVar1 = FUN_00411e50(local_c);
  if (cVar1 != '\0') {
    bVar2 = FUN_0040e0e0((int)param_1);
    if (!bVar2) {
      piVar4 = FUN_0041e2e6(param_1,local_14);
      bVar2 = MAP::Exists(*piVar4,piVar4[1]);
      if (!bVar2) {
        CWave::Play((CWave *)(param_1 + 0x5e88),0,0,0);
        return;
      }
    }
    uVar3 = FUN_00414141((int)param_1);
    if ((((CONCAT31(extraout_var,uVar3) == 0) &&
         (cVar1 = (**(code **)(**(int **)(param_1 + 0x129b4) + 0x20))(), cVar1 == '\0')) ||
        (param_1[0x1281c] != (GAME)0x0)) || (bVar2 = FUN_0040e0e0((int)param_1), !bVar2)) {
      if (param_1[0x1281c] == (GAME)0x0) {
        piVar4 = FUN_0041e2e6(param_1,local_1c);
        uVar5 = FUN_004058f0(piVar4);
        iVar6 = FUN_00411719(param_1,uVar5);
        if (iVar6 == 0) {
          FUN_0041d6ad(param_1,s_SORRY__THAT_LEVEL_IS_LOCKED__YOU_004351a8);
          CWave::Play((CWave *)(param_1 + 0x5e88),0,0,0);
          return;
        }
      }
      piVar4 = FUN_0041e2e6(param_1,local_24);
      MAP::Load((MAP *)(param_1 + 0xe23c),*piVar4,piVar4[1]);
      GAME::ChangeState(param_1,6);
    }
    else {
      FUN_0041d6ad(param_1,s_SORRY__EDITING_IS_DISABLED_IN_TH_00435178);
      CWave::Play((CWave *)(param_1 + 0x5e88),0,0,0);
    }
  }
  return;
}



void * __thiscall FUN_004162d0(void *this,undefined4 *param_1)

{
  FUN_004050e0(this,param_1);
  return this;
}



bool FUN_004162f0(void *param_1,char *param_2)

{
  int iVar1;
  
  iVar1 = FUN_004049b0(param_1,param_2);
  return iVar1 != 0;
}



void * __thiscall FUN_00416310(void *this,undefined4 param_1,undefined4 param_2)

{
  *(undefined4 *)this = param_1;
  *(undefined4 *)((int)this + 4) = param_2;
  return this;
}



undefined4 __thiscall FUN_00416330(void *this,int param_1,int param_2)

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



// Library Function - Multiple Matches With Different Base Names
//  public: class CPoint __thiscall CPoint::operator-(struct tagSIZE)const 
//  public: class CPoint __thiscall CSize::operator-(struct tagPOINT)const 
// 
// Library: Visual Studio

void * __thiscall FID_conflict_operator_(void *this,void *param_1,int param_2,int param_3)

{
                    // WARNING: Load size is inaccurate
  FUN_004163a0(param_1,*this - param_2,*(int *)((int)this + 4) - param_3);
  return param_1;
}



void * __thiscall FUN_004163a0(void *this,undefined4 param_1,undefined4 param_2)

{
  *(undefined4 *)this = param_1;
  *(undefined4 *)((int)this + 4) = param_2;
  return this;
}



void * __thiscall FUN_004163d0(void *this,undefined4 *param_1)

{
  FUN_004163a0(this,*param_1,param_1[1]);
  return this;
}



void __fastcall FUN_00416400(int param_1)

{
  *(undefined4 *)(param_1 + 0xd4) = 1;
  FUN_0040b710(param_1);
  return;
}



undefined4 FUN_00416420(void)

{
  return 0xd;
}



undefined4 FUN_00416430(void)

{
  return 0x14;
}



void * __thiscall FUN_00416440(void *this,undefined4 *param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  
  FUN_00405850(this);
  FUN_00405850((void *)((int)this + 8));
  uVar1 = param_1[1];
  *(undefined4 *)this = *param_1;
  *(undefined4 *)((int)this + 4) = uVar1;
  uVar1 = param_2[1];
  *(undefined4 *)((int)this + 8) = *param_2;
  *(undefined4 *)((int)this + 0xc) = uVar1;
  return this;
}



void FUN_00416490(void)

{
  undefined4 uVar1;
  CString aCStack_374 [4];
  undefined4 uStack_370;
  undefined4 uStack_36c;
  undefined4 uStack_368;
  undefined4 uStack_364;
  CString aCStack_35c [4];
  undefined4 uStack_358;
  CString aCStack_350 [4];
  undefined4 uStack_34c;
  undefined4 uStack_348;
  undefined4 uStack_344;
  undefined4 uStack_340;
  CString aCStack_338 [4];
  undefined4 uStack_334;
  CString aCStack_32c [4];
  undefined4 uStack_328;
  undefined4 uStack_324;
  undefined4 uStack_320;
  undefined4 uStack_31c;
  undefined4 uStack_318;
  undefined4 uStack_314;
  undefined4 uStack_310;
  undefined4 uStack_30c;
  undefined4 uStack_308;
  undefined4 uStack_304;
  undefined4 uStack_300;
  undefined4 uStack_2fc;
  CString aCStack_2f4 [4];
  undefined4 uStack_2f0;
  CString aCStack_2e8 [4];
  undefined4 uStack_2e4;
  undefined4 uStack_2e0;
  CString aCStack_2d8 [4];
  undefined4 uStack_2d4;
  CString aCStack_2cc [4];
  undefined4 uStack_2c8;
  undefined4 uStack_2c4;
  CString aCStack_2bc [4];
  undefined4 uStack_2b8;
  CString aCStack_2b0 [4];
  undefined4 uStack_2ac;
  undefined4 uStack_2a8;
  CString aCStack_2a0 [4];
  undefined4 uStack_29c;
  CString aCStack_294 [4];
  undefined4 uStack_290;
  undefined4 uStack_28c;
  CString aCStack_284 [4];
  undefined4 uStack_280;
  CString aCStack_278 [4];
  undefined4 uStack_274;
  undefined4 uStack_270;
  undefined4 uStack_26c;
  undefined4 uStack_268;
  CString aCStack_260 [4];
  undefined4 uStack_25c;
  CString aCStack_254 [4];
  undefined4 uStack_250;
  undefined4 uStack_24c;
  undefined4 uStack_248;
  undefined4 uStack_244;
  CString aCStack_23c [4];
  undefined4 uStack_238;
  CString aCStack_230 [4];
  undefined4 uStack_22c;
  undefined4 uStack_228;
  undefined4 uStack_224;
  undefined4 uStack_220;
  CString aCStack_218 [4];
  undefined4 uStack_214;
  CString aCStack_20c [4];
  undefined4 uStack_208;
  undefined4 uStack_204;
  undefined4 uStack_200;
  undefined4 uStack_1fc;
  CString aCStack_1f4 [4];
  undefined4 uStack_1f0;
  CString aCStack_1e8 [4];
  undefined4 uStack_1e4;
  undefined4 *local_1e0;
  undefined4 *local_1dc;
  undefined4 local_1d8;
  undefined4 *local_1d4;
  undefined4 *local_1d0;
  undefined4 local_1cc;
  undefined4 *local_1c8;
  undefined4 *local_1c4;
  undefined4 local_1c0;
  undefined4 *local_1bc;
  undefined4 *local_1b8;
  undefined4 local_1b4;
  undefined4 *local_1b0;
  undefined4 *local_1ac;
  undefined4 local_1a8;
  undefined4 *local_1a4;
  undefined4 *local_1a0;
  undefined4 local_19c;
  undefined4 *local_198;
  undefined4 *local_194;
  undefined4 local_190;
  undefined4 *local_18c;
  undefined4 *local_188;
  undefined4 local_184;
  undefined4 *local_180;
  undefined4 *local_17c;
  undefined4 local_178;
  undefined4 *local_174;
  undefined4 *local_170;
  undefined4 local_16c;
  undefined4 *local_168;
  undefined4 *local_164;
  undefined4 local_160;
  undefined4 *local_15c;
  undefined4 *local_158;
  undefined4 local_154;
  undefined4 *local_150;
  undefined4 *local_14c;
  undefined4 local_148;
  undefined4 *local_144;
  undefined4 *local_140;
  undefined4 local_13c;
  undefined4 *local_138;
  undefined4 *local_134;
  undefined4 local_130;
  undefined4 *local_12c;
  undefined4 *local_128;
  undefined4 local_124;
  undefined4 *local_120;
  undefined4 *local_11c;
  undefined4 local_118;
  undefined4 *local_114;
  undefined4 *local_110;
  undefined4 local_10c;
  undefined4 *local_108;
  undefined4 *local_104;
  undefined4 local_100;
  undefined4 *local_fc;
  undefined4 *local_f8;
  undefined4 local_f4;
  undefined4 *local_f0;
  undefined4 *local_ec;
  undefined4 local_e8;
  undefined4 *local_e4;
  undefined4 *local_e0;
  undefined4 local_dc;
  undefined4 *local_d8;
  undefined4 *local_d4;
  undefined4 local_d0;
  int *local_cc;
  CString local_c8 [4];
  undefined1 *local_c4;
  CString local_c0 [4];
  undefined1 *local_bc;
  CString local_b8 [4];
  undefined1 *local_b4;
  CString local_b0 [4];
  undefined1 *local_ac;
  CString local_a8 [4];
  undefined1 *local_a4;
  CString local_a0 [4];
  undefined1 *local_9c;
  CString local_98 [4];
  undefined1 *local_94;
  CString local_90 [4];
  undefined1 *local_8c;
  CString local_88 [4];
  undefined1 *local_84;
  CString local_80 [4];
  undefined1 *local_7c;
  CString local_78 [4];
  undefined1 *local_74;
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
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a1aa;
  local_10 = ExceptionList;
  uStack_1e4 = 0;
  local_14 = aCStack_1e8;
  uStack_1f0 = 0x4164c6;
  ExceptionList = &local_10;
  local_d0 = CString::CString(aCStack_1e8,s_btnresetdn_bmp_00435214);
  uStack_1f0 = 0x4164e1;
  local_d8 = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8 = 0;
  uStack_1f0 = 0x416505;
  local_d4 = local_d8;
  uStack_1f0 = FUN_00401470(local_d8);
  local_1c = aCStack_1f4;
  uStack_1fc = 0x416516;
  local_dc = CString::CString(aCStack_1f4,s_btnresetup_bmp_00435224);
  uStack_1fc = 0x416531;
  local_e4 = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8._0_1_ = 1;
  uStack_1fc = 0x416552;
  local_e0 = local_e4;
  uStack_1fc = FUN_00401470(local_e4);
  uStack_200 = 0x41656e;
  (**(code **)(local_cc[0x9df] + 0x4c))();
  local_8 = (uint)local_8._1_3_ << 8;
  uStack_200 = 0x41657a;
  CString::~CString(local_20);
  local_8 = 0xffffffff;
  uStack_200 = 0x416589;
  CString::~CString(local_18);
  uStack_200 = 0x1ab;
  uStack_204 = 0x27;
  uStack_208 = 0x4165ab;
  (**(code **)(local_cc[0x9df] + 0x2c))();
  uStack_208 = 0;
  local_24 = aCStack_20c;
  uStack_214 = 0x4165bd;
  local_e8 = CString::CString(aCStack_20c,s_btnhelpdn_bmp_00435234);
  uStack_214 = 0x4165d8;
  local_f0 = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8 = 2;
  uStack_214 = 0x4165fc;
  local_ec = local_f0;
  uStack_214 = FUN_00401470(local_f0);
  local_2c = aCStack_218;
  uStack_220 = 0x41660d;
  local_f4 = CString::CString(aCStack_218,s_btnhelpup_bmp_00435244);
  uStack_220 = 0x416628;
  local_fc = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8._0_1_ = 3;
  uStack_220 = 0x416649;
  local_f8 = local_fc;
  uStack_220 = FUN_00401470(local_fc);
  uStack_224 = 0x416665;
  (**(code **)(local_cc[0x97f] + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,2);
  uStack_224 = 0x416671;
  CString::~CString(local_30);
  local_8 = 0xffffffff;
  uStack_224 = 0x416680;
  CString::~CString(local_28);
  uStack_224 = 0x1ab;
  uStack_228 = 0x5e;
  uStack_22c = 0x4166a2;
  (**(code **)(local_cc[0x97f] + 0x2c))();
  uStack_22c = 0;
  local_34 = aCStack_230;
  uStack_238 = 0x4166b4;
  local_100 = CString::CString(aCStack_230,s_Undo_Pressed_bmp_00435254);
  uStack_238 = 0x4166cf;
  local_108 = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8 = 4;
  uStack_238 = 0x4166f3;
  local_104 = local_108;
  uStack_238 = FUN_00401470(local_108);
  local_3c = aCStack_23c;
  uStack_244 = 0x416704;
  local_10c = CString::CString(aCStack_23c,s_Undo_Raised_bmp_00435268);
  uStack_244 = 0x41671f;
  local_114 = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8._0_1_ = 5;
  uStack_244 = 0x416740;
  local_110 = local_114;
  uStack_244 = FUN_00401470(local_114);
  uStack_248 = 0x41675c;
  (**(code **)(local_cc[0xb5f] + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,4);
  uStack_248 = 0x416768;
  CString::~CString(local_40);
  local_8 = 0xffffffff;
  uStack_248 = 0x416777;
  CString::~CString(local_38);
  uStack_248 = 0x1ae;
  uStack_24c = 0xd1;
  uStack_250 = 0x41679c;
  (**(code **)(local_cc[0xb5f] + 0x2c))();
  uStack_250 = 0;
  local_44 = aCStack_254;
  uStack_25c = 0x4167ae;
  local_118 = CString::CString(aCStack_254,s_Redo_Pressed_bmp_00435278);
  uStack_25c = 0x4167c9;
  local_120 = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8 = 6;
  uStack_25c = 0x4167ed;
  local_11c = local_120;
  uStack_25c = FUN_00401470(local_120);
  local_4c = aCStack_260;
  uStack_268 = 0x4167fe;
  local_124 = CString::CString(aCStack_260,s_Redo_Raised_bmp_0043528c);
  uStack_268 = 0x416819;
  local_12c = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8._0_1_ = 7;
  uStack_268 = 0x41683a;
  local_128 = local_12c;
  uStack_268 = FUN_00401470(local_12c);
  uStack_26c = 0x416856;
  (**(code **)(local_cc[0xbbf] + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,6);
  uStack_26c = 0x416862;
  CString::~CString(local_50);
  local_8 = 0xffffffff;
  uStack_26c = 0x416871;
  CString::~CString(local_48);
  uStack_26c = 0x1ae;
  uStack_270 = 0x104;
  uStack_274 = 0x416896;
  (**(code **)(local_cc[0xbbf] + 0x2c))();
  uStack_274 = 0;
  local_54 = aCStack_278;
  uStack_280 = 0x4168a8;
  local_130 = CString::CString(aCStack_278,s_rrdown_bmp_0043529c);
  uStack_280 = 0x4168c3;
  local_138 = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8 = 8;
  uStack_280 = 0x4168e7;
  local_134 = local_138;
  uStack_280 = FUN_00401470(local_138);
  local_5c = aCStack_284;
  uStack_28c = 0x4168f8;
  local_13c = CString::CString(aCStack_284,s_rrup_bmp_004352a8);
  uStack_28c = 0x416913;
  local_144 = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8._0_1_ = 9;
  uStack_28c = 0x416934;
  local_140 = local_144;
  uStack_28c = FUN_00401470(local_144);
  uStack_290 = 0x416950;
  (**(code **)(local_cc[0xc1f] + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,8);
  uStack_290 = 0x41695c;
  CString::~CString(local_60);
  local_8 = 0xffffffff;
  uStack_290 = 0x41696b;
  CString::~CString(local_58);
  uStack_290 = 0;
  local_64 = aCStack_294;
  uStack_29c = 0x41697d;
  local_148 = CString::CString(aCStack_294,s_rldown_bmp_004352b4);
  uStack_29c = 0x416998;
  local_150 = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8 = 10;
  uStack_29c = 0x4169bc;
  local_14c = local_150;
  uStack_29c = FUN_00401470(local_150);
  local_6c = aCStack_2a0;
  uStack_2a8 = 0x4169cd;
  local_154 = CString::CString(aCStack_2a0,s_rlup_bmp_004352c0);
  uStack_2a8 = 0x4169e8;
  local_15c = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8._0_1_ = 0xb;
  uStack_2a8 = 0x416a09;
  local_158 = local_15c;
  uStack_2a8 = FUN_00401470(local_15c);
  uStack_2ac = 0x416a25;
  (**(code **)(local_cc[0xc7e] + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,10);
  uStack_2ac = 0x416a31;
  CString::~CString(local_70);
  local_8 = 0xffffffff;
  uStack_2ac = 0x416a40;
  CString::~CString(local_68);
  uStack_2ac = 0;
  local_74 = aCStack_2b0;
  uStack_2b8 = 0x416a52;
  local_160 = CString::CString(aCStack_2b0,s_red_light_bmp_004352cc);
  uStack_2b8 = 0x416a6d;
  local_168 = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8 = 0xc;
  uStack_2b8 = 0x416a91;
  local_164 = local_168;
  uStack_2b8 = FUN_00401470(local_168);
  local_7c = aCStack_2bc;
  uStack_2c4 = 0x416aa2;
  local_16c = CString::CString(aCStack_2bc,s_red_light_off_bmp_004352dc);
  uStack_2c4 = 0x416abd;
  local_174 = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8._0_1_ = 0xd;
  uStack_2c4 = 0x416ade;
  local_170 = local_174;
  uStack_2c4 = FUN_00401470(local_174);
  uStack_2c8 = 0x416afa;
  (**(code **)(local_cc[0xd11] + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,0xc);
  uStack_2c8 = 0x416b06;
  CString::~CString(local_80);
  local_8 = 0xffffffff;
  uStack_2c8 = 0x416b15;
  CString::~CString(local_78);
  uStack_2c8 = 0;
  local_84 = aCStack_2cc;
  uStack_2d4 = 0x416b27;
  local_178 = CString::CString(aCStack_2cc,s_green_light_bmp_004352f0);
  uStack_2d4 = 0x416b45;
  local_180 = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8 = 0xe;
  uStack_2d4 = 0x416b69;
  local_17c = local_180;
  uStack_2d4 = FUN_00401470(local_180);
  local_8c = aCStack_2d8;
  uStack_2e0 = 0x416b7d;
  local_184 = CString::CString(aCStack_2d8,s_green_light_off_bmp_00435300);
  uStack_2e0 = 0x416b9b;
  local_18c = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8._0_1_ = 0xf;
  uStack_2e0 = 0x416bbc;
  local_188 = local_18c;
  uStack_2e0 = FUN_00401470(local_18c);
  uStack_2e4 = 0x416bd8;
  (**(code **)(local_cc[0xd70] + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,0xe);
  uStack_2e4 = 0x416be7;
  CString::~CString(local_90);
  local_8 = 0xffffffff;
  uStack_2e4 = 0x416bf9;
  CString::~CString(local_88);
  uStack_2e4 = 0;
  local_94 = aCStack_2e8;
  uStack_2f0 = 0x416c0e;
  local_190 = CString::CString(aCStack_2e8,s_blue_light_bmp_00435314);
  uStack_2f0 = 0x416c2c;
  local_198 = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8 = 0x10;
  uStack_2f0 = 0x416c50;
  local_194 = local_198;
  uStack_2f0 = FUN_00401470(local_198);
  local_9c = aCStack_2f4;
  uStack_2fc = 0x416c64;
  local_19c = CString::CString(aCStack_2f4,s_blue_light_off_bmp_00435324);
  uStack_2fc = 0x416c82;
  local_1a4 = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8._0_1_ = 0x11;
  uStack_2fc = 0x416ca3;
  local_1a0 = local_1a4;
  uStack_2fc = FUN_00401470(local_1a4);
  uStack_300 = 0x416cbf;
  (**(code **)(local_cc[0xdcf] + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,0x10);
  uStack_300 = 0x416cce;
  CString::~CString(local_a0);
  local_8 = 0xffffffff;
  uStack_300 = 0x416ce0;
  CString::~CString(local_98);
  uStack_300 = 0x1a9;
  uStack_304 = 0x175;
  uStack_308 = 0x416d05;
  (**(code **)(local_cc[0xc1f] + 0x2c))();
  uStack_308 = 0x1a9;
  uStack_30c = 0x13d;
  uStack_310 = 0x416d2a;
  (**(code **)(local_cc[0xc7e] + 0x2c))();
  uStack_310 = 0x1ab;
  uStack_314 = 0x211;
  uStack_318 = 0x416d4f;
  (**(code **)(local_cc[0xd11] + 0x2c))();
  uStack_318 = 0x1ab;
  uStack_31c = 0x232;
  uStack_320 = 0x416d74;
  (**(code **)(local_cc[0xd70] + 0x2c))();
  uStack_320 = 0x1ab;
  uStack_324 = 0x253;
  uStack_328 = 0x416d99;
  (**(code **)(local_cc[0xdcf] + 0x2c))();
  uStack_328 = 0;
  local_a4 = aCStack_32c;
  uStack_334 = 0x416dae;
  local_1a8 = CString::CString(aCStack_32c,s_btninstdn_bmp_00435338);
  uStack_334 = 0x416dcc;
  local_1b0 = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8 = 0x12;
  uStack_334 = 0x416df0;
  local_1ac = local_1b0;
  uStack_334 = FUN_00401470(local_1b0);
  local_ac = aCStack_338;
  uStack_340 = 0x416e04;
  local_1b4 = CString::CString(aCStack_338,s_btninstup_bmp_00435348);
  uStack_340 = 0x416e22;
  local_1bc = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8._0_1_ = 0x13;
  uStack_340 = 0x416e43;
  local_1b8 = local_1bc;
  uStack_340 = FUN_00401470(local_1bc);
  uStack_344 = 0x416e5f;
  (**(code **)(local_cc[0xa3f] + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,0x12);
  uStack_344 = 0x416e6e;
  CString::~CString(local_b0);
  local_8 = 0xffffffff;
  uStack_344 = 0x416e80;
  CString::~CString(local_a8);
  uStack_344 = 0x1ab;
  uStack_348 = 0x95;
  uStack_34c = 0x416ea5;
  (**(code **)(local_cc[0xa3f] + 0x2c))();
  uStack_34c = 0;
  local_b4 = aCStack_350;
  uStack_358 = 0x416eba;
  local_1c0 = CString::CString(aCStack_350,s_exit_bmp_00435358);
  uStack_358 = 0x416ed8;
  local_1c8 = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8 = 0x14;
  uStack_358 = 0x416efc;
  local_1c4 = local_1c8;
  uStack_358 = FUN_00401470(local_1c8);
  local_bc = aCStack_35c;
  uStack_364 = 0x416f10;
  local_1cc = CString::CString(aCStack_35c,s_exitoff_bmp_00435364);
  uStack_364 = 0x416f2e;
  local_1d4 = (undefined4 *)(**(code **)(*local_cc + 0x54))();
  local_8._0_1_ = 0x15;
  uStack_364 = 0x416f4f;
  local_1d0 = local_1d4;
  uStack_364 = FUN_00401470(local_1d4);
  uStack_368 = 0x416f6b;
  (**(code **)(local_cc[0xa9f] + 0x4c))();
  local_8 = CONCAT31(local_8._1_3_,0x14);
  uStack_368 = 0x416f7a;
  CString::~CString(local_c0);
  local_8 = 0xffffffff;
  uStack_368 = 0x416f8c;
  CString::~CString(local_b8);
  uStack_368 = 0x1ad;
  uStack_36c = 0xc;
  uStack_370 = 0x416fae;
  (**(code **)(local_cc[0xa9f] + 0x2c))();
  uStack_370 = 1;
  local_c4 = aCStack_374;
  local_1d8 = CString::CString(aCStack_374,s_PROGRESS_BMP_00435370);
  local_1e0 = (undefined4 *)(**(code **)(*local_cc + 0x54))(local_c8);
  local_8 = 0x16;
  local_1dc = local_1e0;
  uVar1 = FUN_00401470(local_1e0);
  (**(code **)(local_cc[0xcdd] + 0x3c))(uVar1);
  local_8 = 0xffffffff;
  CString::~CString(local_c8);
  (**(code **)(local_cc[0xcdd] + 0x2c))(0x192,0x1b5);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_00417066(void *this,int param_1,char param_2)

{
  bool bVar1;
  char cVar2;
  int *piVar3;
  uint uVar4;
  undefined4 *puVar5;
  undefined1 local_74 [8];
  undefined1 local_6c [8];
  undefined1 local_64 [8];
  undefined1 local_5c [8];
  undefined1 local_54 [8];
  int local_4c;
  int local_48;
  undefined4 local_44 [2];
  undefined1 local_3c [8];
  undefined1 local_34 [8];
  undefined1 local_2c [8];
  undefined1 local_24 [8];
  int local_1c;
  int local_18;
  undefined4 local_14 [2];
  undefined4 local_c [2];
  
  if (param_2 == '\x01') {
    bVar1 = GAME::IsKeyDown((GAME *)this,0x11);
    if ((bVar1) && (param_1 == 0x1a)) {
      FUN_004272f7(this);
    }
    else {
      bVar1 = GAME::IsKeyDown((GAME *)this,0x11);
      if (((bVar1) && (param_1 == 0x19)) ||
         ((bVar1 = GAME::IsKeyDown((GAME *)this,0x11), bVar1 && (param_1 == 1)))) {
        FUN_0042735b(this);
      }
      else {
        bVar1 = GAME::IsKeyDown((GAME *)this,0x11);
        if ((bVar1) && (param_1 == 7)) {
          *(int *)((int)this + 0x3c) = *(int *)((int)this + 0x3c) + 1;
          *(uint *)((int)this + 0x3c) = *(uint *)((int)this + 0x3c) % 3;
          MAP::SetGammaLevel(*(uint *)((int)this + 0x3c));
          MAP::RefreshBothLevelmapBuffers((MAP *)((int)this + 0xe23c));
          REG::Put((REG *)((int)this + 0x34),s_GammaLevel_00435380,*(ulong *)((int)this + 0x3c));
        }
        else if (param_1 == 0x1b) {
          if (*(int *)((int)this + 0xe018) == 0) {
            if (*(GAME *)((int)this + 0xe014) == (GAME)0x0) {
              piVar3 = FUN_00405910((GAME *)((int)this + 0xe23c),local_c);
              uVar4 = FUN_004058f0(piVar3);
              if (uVar4 % 100 < 0x10) {
                GAME::ChangeState((GAME *)this,2);
              }
              else {
                GAME::ChangeState((GAME *)this,0xd);
              }
            }
            else {
              FUN_0040e1ce(this,'\x01');
            }
          }
          else {
            FUN_00414d82((GAME *)this);
          }
        }
        else if ((param_1 == 0x250000) && (0 < *(int *)((int)this + 0xe01c))) {
          piVar3 = (int *)default_error_condition(local_24,0x20,0);
          local_1c = *piVar3;
          local_18 = piVar3[1];
          puVar5 = (undefined4 *)
                   FID_conflict_operator_((GAME *)((int)this + 0xe01c),local_2c,local_1c,local_18);
          FUN_004163d0(local_14,puVar5);
          FUN_0041821d(this,local_14);
        }
        else if ((param_1 == 0x270000) && (*(int *)((int)this + 0xe01c) < 0x260)) {
          piVar3 = (int *)default_error_condition(local_34,0x20,0);
          puVar5 = (undefined4 *)FUN_0040dff0((GAME *)((int)this + 0xe01c),local_3c,piVar3);
          FUN_0041821d(this,puVar5);
        }
        else if ((param_1 == 0x260000) && (0 < *(int *)((int)this + 0xe020))) {
          piVar3 = (int *)default_error_condition(local_54,0,0x20);
          local_4c = *piVar3;
          local_48 = piVar3[1];
          puVar5 = (undefined4 *)
                   FID_conflict_operator_((GAME *)((int)this + 0xe01c),local_5c,local_4c,local_48);
          FUN_004163d0(local_44,puVar5);
          FUN_0041821d(this,local_44);
        }
        else if ((param_1 == 0x280000) && (*(int *)((int)this + 0xe020) < 0x180)) {
          piVar3 = (int *)default_error_condition(local_64,0,0x20);
          puVar5 = (undefined4 *)FUN_0040dff0((GAME *)((int)this + 0xe01c),local_6c,piVar3);
          FUN_0041821d(this,puVar5);
        }
        else if (param_1 == 0x210000) {
          GKERNEL::SetCursorPos((int)((int)this + 0xe01c),(int)this);
          FUN_00414380(this);
        }
        else if (param_1 == 0x220000) {
          GKERNEL::SetCursorPos((int)((int)this + 0xe01c),(int)this);
                    // WARNING: Load size is inaccurate
          (**(code **)(*this + 0x30))((GAME *)((int)this + 0xe01c));
        }
        else if (param_1 == 0xd) {
          if (*(int *)((int)this + 0xe018) == 0) {
                    // WARNING: Load size is inaccurate
            (**(code **)(*this + 0x38))((GAME *)((int)this + 0xe01c));
            if (*(int *)((int)this + 0xe018) == 0) {
              MessageBeep(0);
            }
            (**(code **)(**(int **)((int)this + 0xe00c) + 0x28))((GAME *)((int)this + 0xe01c));
          }
          else {
            puVar5 = (undefined4 *)FUN_00405800((GAME *)((int)this + 0xe01c),local_74,0x20);
            cVar2 = FUN_00414caf(this,puVar5);
            if (cVar2 == '\0') {
              MessageBeep(0);
            }
            else {
              FUN_00414d82((GAME *)this);
            }
          }
        }
      }
    }
  }
  return;
}



void __fastcall FUN_00417425(void *param_1)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  void *pvVar4;
  HCURSOR pHVar5;
  CString *pCVar6;
  undefined1 local_34 [8];
  undefined1 local_2c [8];
  CString local_24 [4];
  uint local_20;
  int local_1c;
  int local_18;
  ITEM *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a1bd;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_0040b6f0((int)param_1 + 0x307c);
  FUN_0040b6f0((int)param_1 + 0x31f8);
  FUN_00405800((void *)((int)param_1 + 0xe01c),&local_1c,0x20);
  if ((((-1 < local_1c) && (iVar3 = FUN_00416430(), local_1c < iVar3)) && (-1 < local_18)) &&
     ((iVar3 = FUN_00416420(), local_18 < iVar3 &&
      (local_14 = MAP::GetItem((MAP *)((int)param_1 + 0xe23c),local_1c,local_18),
      local_14 != (ITEM *)0x0)))) {
    pCVar6 = local_24;
    pvVar4 = (void *)(**(code **)(*(int *)local_14 + 0x60))(pCVar6,s_BLANK_0043538c);
    local_8 = 0;
    bVar1 = FUN_00404990(pvVar4,(char *)pCVar6);
    local_20 = CONCAT31(local_20._1_3_,bVar1);
    local_8 = 0xffffffff;
    CString::~CString(local_24);
    if ((local_20 & 0xff) == 0) {
      cVar2 = (**(code **)(*(int *)((int)param_1 + 0x307c) + 0x44))();
      if ((cVar2 != '\0') &&
         ((iVar3 = (**(code **)(*(int *)local_14 + 0x38))(), iVar3 != 0 ||
          (bVar1 = FUN_0040e0e0((int)param_1), bVar1)))) {
        pHVar5 = (HCURSOR)(**(code **)(*(int *)local_14 + 0x74))(local_2c);
        FUN_004152e0(param_1,pHVar5);
        (**(code **)(*(int *)local_14 + 0x1c))();
        CWave::Play((CWave *)((int)param_1 + 0x5f08),0,0,0);
        FUN_004273c9(param_1,local_1c,local_18);
      }
      cVar2 = (**(code **)(*(int *)((int)param_1 + 0x31f8) + 0x44))();
      if ((cVar2 != '\0') &&
         ((iVar3 = (**(code **)(*(int *)local_14 + 0x38))(), iVar3 != 0 ||
          (bVar1 = FUN_0040e0e0((int)param_1), bVar1)))) {
        pHVar5 = (HCURSOR)(**(code **)(*(int *)local_14 + 0x74))(local_34);
        FUN_004152e0(param_1,pHVar5);
        (**(code **)(*(int *)local_14 + 0x20))();
        CWave::Play((CWave *)((int)param_1 + 0x5f08),0,0,0);
        FUN_0042746d(param_1,local_1c,local_18);
      }
    }
  }
  ExceptionList = local_10;
  return;
}



void FUN_0041763f(void)

{
  undefined4 uVar1;
  bool bVar2;
  char cVar3;
  int iVar4;
  void *pvVar5;
  int *piVar6;
  undefined4 *puVar7;
  GAME *this;
  undefined1 local_1194;
  undefined1 local_1160 [16];
  undefined1 local_1150 [8];
  undefined1 local_1148 [8];
  undefined1 local_1140 [8];
  undefined1 local_1138 [8];
  char local_1130;
  undefined3 uStackY_112f;
  CString local_112c [4];
  uint local_1128;
  undefined1 local_1124 [8];
  undefined1 local_111c [8];
  undefined1 local_1114 [16];
  undefined1 local_1104 [16];
  int local_10f4;
  uint local_10f0;
  undefined1 local_10ec [16];
  CString local_10dc [4];
  uint local_10d8;
  undefined1 local_10d4 [8];
  undefined1 local_10cc [8];
  undefined1 local_10c4 [8];
  uint local_10bc;
  ITEM *local_10b8;
  uint local_10b4;
  uint local_10b0;
  undefined4 local_10ac;
  undefined4 local_10a8;
  undefined4 local_10a4;
  undefined4 local_10a0;
  uint local_109c;
  ITEM *local_1098;
  undefined1 *local_1094;
  uint local_1090;
  uint local_108c;
  uint local_1088;
  ITEM *local_1084;
  uint local_1080;
  uint local_107c;
  CTypeLibCacheMap local_1078 [28];
  undefined4 local_105c [520];
  undefined4 local_83c [514];
  undefined4 uStackY_34;
  undefined1 auStack_2c [8];
  undefined4 uStack_24;
  undefined1 *puVar8;
  undefined4 *puVar9;
  CString **ppCVar10;
  uint uVar11;
  char *pcVar12;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a1eb;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00427f40();
  uStack_24 = 0x41767f;
  FUN_0040df80(local_83c,8,0x104,FUN_00405850);
  uStack_24 = 0x417697;
  FUN_0040df80(local_105c,8,0x104,FUN_00405850);
  local_107c = local_107c & 0xffffff00;
  default_error_condition(local_10c4,0,0);
  local_1084 = MAP::GetItem((MAP *)(this + 0xe23c));
  local_1080 = 0;
  while ((local_1080 < 0x14 && ((local_107c & 0xff) == 0))) {
    local_1088 = 0;
    while ((local_1088 < 0xd && ((local_107c & 0xff) == 0))) {
      iVar4 = (**(code **)(*(int *)local_1084 + 0x34))();
      if (iVar4 != 0) {
        ppCVar10 = &this_00435394;
        pvVar5 = (void *)(**(code **)(*(int *)local_1084 + 0x50))();
        local_8 = 0;
        bVar2 = FUN_004162f0(pvVar5,(char *)ppCVar10);
        local_10d8 = CONCAT31(local_10d8._1_3_,bVar2);
        local_8 = 0xffffffff;
        CString::~CString(local_10dc);
        if ((((local_10d8 & 0xff) != 0) &&
            (cVar3 = (**(code **)(*(int *)local_1084 + 0x80))(), cVar3 == '\0')) &&
           (piVar6 = (int *)(**(code **)(*(int *)local_1084 + 0x74))(), 2 < *piVar6)) {
          iVar4 = 0x20;
          puVar8 = local_1104;
          pvVar5 = (void *)OVERLAY::Position((OVERLAY *)(this + 0x228));
          piVar6 = (int *)FUN_00405800(pvVar5,puVar8,iVar4);
          local_10f4 = *piVar6;
          local_10f0 = piVar6[1];
          puVar8 = local_10ec;
          iVar4 = local_10f4;
          uVar11 = local_10f0;
          pvVar5 = (void *)(**(code **)(*(int *)local_1084 + 0x74))();
          iVar4 = FUN_0040fe10(pvVar5,(int)puVar8,iVar4);
          if (iVar4 != 0) {
            FUN_0040e080(local_1084,3);
          }
          if (0x103 < uVar11) {
            ExceptionList = local_10;
            return;
          }
          puVar7 = (undefined4 *)(**(code **)(*(int *)local_1084 + 0x74))();
          uVar1 = puVar7[1];
          local_83c[uVar11 * 2] = *puVar7;
          local_83c[uVar11 * 2 + 1] = uVar1;
        }
      }
      local_1088 = local_1088 + 1;
      if (local_1088 < 0xd) {
        default_error_condition(local_10cc,local_1080,local_1088);
        local_1084 = MAP::GetItem((MAP *)(this + 0xe23c));
      }
      else if (local_1080 < 0x13) {
        default_error_condition(local_10d4,local_1080 + 1,0);
        local_1084 = MAP::GetItem((MAP *)(this + 0xe23c));
      }
    }
    local_1080 = local_1080 + 1;
  }
  local_1094 = (undefined1 *)0x0;
  local_108c = local_108c & 0xffffff00;
  puVar7 = (undefined4 *)default_error_condition(local_1114,0,0);
  pvVar5 = (void *)*puVar7;
  local_1098 = MAP::GetItem((MAP *)(this + 0xe23c));
  local_1090 = 0;
  do {
    if ((0x13 < local_1090) || ((local_108c & 0xff) != 0)) {
      puVar7 = (undefined4 *)0x417c4e;
      CTypeLibCacheMap::CTypeLibCacheMap(local_1078);
      local_8 = 2;
      puVar9 = (undefined4 *)0x0;
      while (puVar9 < puVar7) {
        MAP::SelectTile((MAP *)(this + 0xe23c));
        iVar4 = 0x417cbd;
        MAP::SwapTile((MAP *)(this + 0xe23c));
        FUN_00405960(&local_10ac);
        local_10ac = local_83c[iVar4 * 2];
        local_10a8 = local_83c[iVar4 * 2 + 1];
        local_10a4 = local_105c[iVar4 * 2];
        local_10a0 = local_105c[iVar4 * 2 + 1];
        puVar7 = &local_10ac;
        pvVar5 = (void *)0x417d14;
        FUN_004050e0(local_1078,puVar7);
        puVar9 = (undefined4 *)(iVar4 + 1);
      }
      if (puVar7 != (undefined4 *)0x0) {
        if (((uint)pvVar5 & 0xff) == 0) {
          puVar7 = (undefined4 *)OVERLAY::Position((OVERLAY *)(this + 0x228));
          FUN_0040f6ea(this,puVar7);
        }
        else {
          local_10b0 = local_10b0 & 0xffffff00;
          default_error_condition(local_1140,0,0);
          local_10b8 = MAP::GetItem((MAP *)(this + 0xe23c));
          local_10b4 = 0;
          while ((local_10b4 < 0x14 && ((local_10b0 & 0xff) == 0))) {
            local_10bc = 0;
            while( true ) {
              if ((0xc < local_10bc) || ((local_10b0 & 0xff) != 0)) goto LAB_00417d80;
              iVar4 = FUN_00423770((int)local_10b8);
              if (iVar4 == 3) break;
              local_10bc = local_10bc + 1;
              if (local_10bc < 0xd) {
                default_error_condition(local_1148,local_10b4,local_10bc);
                local_10b8 = MAP::GetItem((MAP *)(this + 0xe23c));
              }
              else if (local_10b4 < 0x13) {
                default_error_condition(local_1150,local_10b4 + 1,0);
                local_10b8 = MAP::GetItem((MAP *)(this + 0xe23c));
              }
            }
            FUN_0040e080(local_10b8,0);
            iVar4 = 0x20;
            puVar8 = local_1160;
            pvVar5 = (void *)(**(code **)(*(int *)local_10b8 + 0x74))();
            puVar7 = (undefined4 *)FUN_0040fe80(pvVar5,puVar8,iVar4);
            FUN_0040f6ea(this,puVar7);
            local_10b0 = CONCAT31(local_10b0._1_3_,1);
LAB_00417d80:
            local_10b4 = local_10b4 + 1;
          }
        }
        uStackY_34 = 0x417f3d;
        FUN_00404a00(auStack_2c,(int)local_1078);
        FUN_004275c1(this);
      }
      local_8 = 0xffffffff;
      FUN_00404820((undefined4 *)local_1078);
      ExceptionList = local_10;
      return;
    }
    local_109c = 0;
LAB_00417b02:
    if ((0xc < local_109c) || ((local_108c & 0xff) != 0)) goto LAB_00417a01;
    pcVar12 = &DAT_00435398;
    pvVar5 = (void *)(**(code **)(*(int *)local_1098 + 0x50))();
    local_8 = 1;
    bVar2 = FUN_00404990(pvVar5,pcVar12);
    if (bVar2) {
      cVar3 = (**(code **)(*(int *)local_1098 + 0x80))();
      cVar3 = '\x01' - (cVar3 != '\0');
      _local_1130 = CONCAT31(uStackY_112f,cVar3);
      if (cVar3 == '\0') goto LAB_00417bae;
      local_1194 = 1;
    }
    else {
LAB_00417bae:
      local_1194 = 0;
    }
    local_1128 = CONCAT31(local_1128._1_3_,local_1194);
    local_8 = 0xffffffff;
    CString::~CString(local_112c);
    if ((local_1128 & 0xff) == 0) {
LAB_00417a3f:
      local_109c = local_109c + 1;
      if (local_109c < 0xd) {
        puVar7 = (undefined4 *)default_error_condition(local_111c,local_1090,local_109c);
        pvVar5 = (void *)*puVar7;
        local_1098 = MAP::GetItem((MAP *)(this + 0xe23c));
      }
      else if (local_1090 < 0x13) {
        puVar7 = (undefined4 *)default_error_condition(local_1124,local_1090 + 1,0);
        pvVar5 = (void *)*puVar7;
        local_1098 = MAP::GetItem((MAP *)(this + 0xe23c));
      }
      goto LAB_00417b02;
    }
    puVar8 = local_1138;
    pvVar5 = (void *)0x417bfd;
    puVar7 = (undefined4 *)(**(code **)(*(int *)local_1098 + 0x74))();
    uVar1 = puVar7[1];
    local_105c[(int)local_1094 * 2] = *puVar7;
    local_105c[(int)local_1094 * 2 + 1] = uVar1;
    local_1094 = local_1094 + 1;
    if (local_1094 != puVar8) goto LAB_00417a3f;
    local_108c = CONCAT31(local_108c._1_3_,1);
LAB_00417a01:
    local_1090 = local_1090 + 1;
  } while( true );
}



void __fastcall FUN_00417f6e(int *param_1)

{
  undefined4 *puVar1;
  char *pcVar2;
  CString *pCVar3;
  int *piVar4;
  int iVar5;
  HINSTANCE__ *pHVar6;
  undefined1 uVar7;
  CString local_28 [4];
  undefined1 *local_24;
  tagRECT local_20;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_4_0042a1fe;
  local_10 = ExceptionList;
  uVar7 = 0;
  pHVar6 = (HINSTANCE__ *)0x1a0;
  iVar5 = 0;
  local_24 = &stack0xffffffb0;
  ExceptionList = &local_10;
  piVar4 = param_1;
  CString::CString((CString *)&stack0xffffffb0,s_BUTTONS16M_BMP_0043539c);
  pCVar3 = local_28;
  puVar1 = (undefined4 *)(**(code **)(*param_1 + 0x54))();
  local_8 = 0;
  pcVar2 = (char *)FUN_00401470(puVar1);
  GKTOOLS::CopyDIBToBack(pcVar2,(uint)pCVar3,(uint)piVar4,iVar5,pHVar6,(bool)uVar7);
  local_8 = 0xffffffff;
  CString::~CString(local_28);
  local_20.left = 0;
  local_20.top = 0x1a0;
  local_20.right = 0x280;
  local_20.bottom = 0x1e0;
  DD_SURFACE::BltFast((DD_SURFACE *)ddsPrimary_exref,(DD_SURFACE *)ddsBack_exref,0,0x1a0,&local_20);
  GKERNEL::NewSpriteBackground();
  FUN_0040b710((int)(param_1 + 0x9df));
  FUN_0040b710((int)(param_1 + 0xa3f));
  FUN_0040b710((int)(param_1 + 0x97f));
  FUN_0040b710((int)(param_1 + 0xb5f));
  FUN_0040b710((int)(param_1 + 0xbbf));
  FUN_0040b710((int)(param_1 + 0xc1f));
  FUN_0040b710((int)(param_1 + 0xc7e));
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_0041809c(int *param_1)

{
  undefined4 *puVar1;
  char *pcVar2;
  uint extraout_ECX;
  CString *pCVar3;
  uint uVar4;
  int iVar5;
  HINSTANCE__ *pHVar6;
  undefined1 uVar7;
  CString local_28 [4];
  undefined1 *local_24;
  tagRECT local_20;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_0042a211;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  MAP::RefreshBothLevelmapBuffers((MAP *)(param_1 + 0x388f));
  uVar7 = 0;
  pHVar6 = (HINSTANCE__ *)0x1a0;
  iVar5 = 0;
  local_24 = &stack0xffffffb0;
  uVar4 = extraout_ECX;
  CString::CString((CString *)&stack0xffffffb0,s_STABLE_BMP_004353ac);
  pCVar3 = local_28;
  puVar1 = (undefined4 *)(**(code **)(*param_1 + 0x54))();
  local_8 = 0;
  pcVar2 = (char *)FUN_00401470(puVar1);
  GKTOOLS::CopyDIBToBack(pcVar2,(uint)pCVar3,uVar4,iVar5,pHVar6,(bool)uVar7);
  local_8 = 0xffffffff;
  CString::~CString(local_28);
  local_20.left = 0;
  local_20.top = 0x1a0;
  local_20.right = 0x280;
  local_20.bottom = 0x1e0;
  DD_SURFACE::BltFast((DD_SURFACE *)ddsPrimary_exref,(DD_SURFACE *)ddsBack_exref,0,0x1a0,&local_20);
  GKERNEL::NewSpriteBackground();
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00418177(GAME *param_1)

{
  uint local_2c [10];
  
  local_2c[0] = FUN_00418250((int *)(param_1 + 0x12820));
  local_2c[0] = local_2c[0] / 500;
  local_2c[1] = 8;
  local_2c[2] = 0x13;
  local_2c[3] = 0x1f;
  local_2c[4] = 0x30;
  local_2c[5] = 0x42;
  local_2c[6] = 0x57;
  local_2c[7] = 0x74;
  local_2c[8] = 0x98;
  local_2c[9] = 0xda;
  if ((local_2c[0] != 0) && (local_2c[0] < 10)) {
    (**(code **)(*(int *)(param_1 + 0x3374) + 0x34))(0,0,local_2c[local_2c[0]],0xe);
  }
  if (0xb < local_2c[0]) {
    GAME::ChangeState(param_1,0xb);
  }
  return;
}



void __thiscall FUN_0041821d(void *this,undefined4 *param_1)

{
  GKERNEL::SetCursorPos((int)param_1,(int)this);
  FUN_0040f6ea(this,param_1);
  return;
}



int __fastcall FUN_00418250(int *param_1)

{
  DWORD DVar1;
  
  DVar1 = GetTickCount();
  return DVar1 - *param_1;
}



void FUN_00418270(void)

{
  FUN_0041827f();
  FUN_0041828f();
  return;
}



void FUN_0041827f(void)

{
  CWave::CWave((CWave *)&DAT_0044b718);
  return;
}



void FUN_0041828f(void)

{
  FUN_00427dae(FUN_004182a1);
  return;
}



void FUN_004182a1(void)

{
  CWave::~CWave((CWave *)&DAT_0044b718);
  return;
}



void FUN_004182b1(void)

{
  FUN_004182c0();
  FUN_004182d0();
  return;
}



void FUN_004182c0(void)

{
  SPRITE::SPRITE((SPRITE *)&DAT_0044c980);
  return;
}



void FUN_004182d0(void)

{
  FUN_00427dae(FUN_004182e2);
  return;
}



void FUN_004182e2(void)

{
  SPRITE::~SPRITE((SPRITE *)&DAT_0044c980);
  return;
}



void FUN_004182f2(void)

{
  FUN_00418301();
  FUN_00418311();
  return;
}



void FUN_00418301(void)

{
  SPRITE::SPRITE((SPRITE *)&DAT_0044a090);
  return;
}



void FUN_00418311(void)

{
  FUN_00427dae(FUN_00418323);
  return;
}



void FUN_00418323(void)

{
  SPRITE::~SPRITE((SPRITE *)&DAT_0044a090);
  return;
}



void FUN_00418333(void)

{
  FUN_00418342();
  FUN_00418351();
  return;
}



void FUN_00418342(void)

{
  FUN_0041bb80((TwLightning *)&DAT_0044b798);
  return;
}



void FUN_00418351(void)

{
  FUN_00427dae(FUN_00418363);
  return;
}



void FUN_00418363(void)

{
  FUN_0041bb60((TwLightning *)&DAT_0044b798);
  return;
}



void FUN_00418372(void)

{
  FUN_00418381();
  FUN_00418391();
  return;
}



void FUN_00418381(void)

{
  OVERLAY::OVERLAY((OVERLAY *)&DAT_0044c730);
  return;
}



void FUN_00418391(void)

{
  FUN_00427dae(FUN_004183a3);
  return;
}



void FUN_004183a3(void)

{
  FUN_0040c7b0((undefined4 *)&DAT_0044c730);
  return;
}



void FUN_004183b2(void)

{
  FUN_004183c1();
  FUN_004183d0();
  return;
}



void FUN_004183c1(void)

{
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)&DAT_0044dab0);
  return;
}



void FUN_004183d0(void)

{
  FUN_00427dae(FUN_004183e2);
  return;
}



void FUN_004183e2(void)

{
  FUN_0041bc00((undefined4 *)&DAT_0044dab0);
  return;
}



void FUN_004183f1(void)

{
  FUN_00418400();
  FUN_00418410();
  return;
}



void FUN_00418400(void)

{
  FONT::FONT((FONT *)&DAT_00448fe0);
  return;
}



void FUN_00418410(void)

{
  FUN_00427dae(FUN_00418422);
  return;
}



void FUN_00418422(void)

{
  FUN_0040c9c0((DD_SURFACE *)&DAT_00448fe0);
  return;
}



void FUN_00418431(void)

{
  FUN_00418440();
  FUN_0041844f();
  return;
}



void FUN_00418440(void)

{
  CString::CString((CString *)&DAT_0044c728);
  return;
}



void FUN_0041844f(void)

{
  FUN_00427dae(FUN_00418461);
  return;
}



void FUN_00418461(void)

{
  CString::~CString((CString *)&DAT_0044c728);
  return;
}



void FUN_00418470(void)

{
  FUN_0041847f();
  FUN_0041848f();
  return;
}



void FUN_0041847f(void)

{
  CWave::CWave((CWave *)&DAT_0044b1c0);
  return;
}



void FUN_0041848f(void)

{
  FUN_00427dae(FUN_004184a1);
  return;
}



void FUN_004184a1(void)

{
  CWave::~CWave((CWave *)&DAT_0044b1c0);
  return;
}



void FUN_004184b1(void)

{
  FUN_004184c0();
  FUN_004184cf();
  return;
}



void FUN_004184c0(void)

{
  FUN_0040c640((OVERLAY *)&DAT_0044b418);
  return;
}



void FUN_004184cf(void)

{
  FUN_00427dae(FUN_004184e1);
  return;
}



void FUN_004184e1(void)

{
  FUN_0040c870((undefined4 *)&DAT_0044b418);
  return;
}



void FUN_004184f0(void)

{
  FUN_004184ff();
  FUN_0041850e();
  return;
}



void FUN_004184ff(void)

{
  FUN_0040c640((OVERLAY *)&DAT_0044c800);
  return;
}



void FUN_0041850e(void)

{
  FUN_00427dae(FUN_00418520);
  return;
}



void FUN_00418520(void)

{
  FUN_0040c870((undefined4 *)&DAT_0044c800);
  return;
}



void FUN_0041852f(void)

{
  FUN_0041853e();
  FUN_00418552();
  return;
}



void FUN_0041853e(void)

{
  FUN_0040c8c0(&DAT_0044b200,&DAT_0044b1c0);
  return;
}



void FUN_00418552(void)

{
  FUN_00427dae(FUN_00418564);
  return;
}



void FUN_00418564(void)

{
  FUN_0040c900((undefined4 *)&DAT_0044b200);
  return;
}



void FUN_00418573(void)

{
  FUN_00418582();
  FUN_00418596();
  return;
}



void FUN_00418582(void)

{
  FUN_0040c8c0(&DAT_0044c5a8,&DAT_0044b1c0);
  return;
}



void FUN_00418596(void)

{
  FUN_00427dae(FUN_004185a8);
  return;
}



void FUN_004185a8(void)

{
  FUN_0040c900((undefined4 *)&DAT_0044c5a8);
  return;
}



void FUN_004185b7(void)

{
  FUN_004185c6();
  FUN_004185da();
  return;
}



void FUN_004185c6(void)

{
  FUN_0040c8c0(&DAT_0044b598,&DAT_0044b1c0);
  return;
}



void FUN_004185da(void)

{
  FUN_00427dae(FUN_004185ec);
  return;
}



void FUN_004185ec(void)

{
  FUN_0040c900((undefined4 *)&DAT_0044b598);
  return;
}



void FUN_004185fb(void)

{
  FUN_0041860a();
  FUN_0041861a();
  return;
}



void FUN_0041860a(void)

{
  DD_SURFACE::DD_SURFACE((DD_SURFACE *)&this_0044b380);
  return;
}



void FUN_0041861a(void)

{
  FUN_00427dae(FUN_0041862c);
  return;
}



void FUN_0041862c(void)

{
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)&this_0044b380);
  return;
}



void FUN_0041863c(void)

{
  FUN_0041864b();
  FUN_0041865b();
  return;
}



void FUN_0041864b(void)

{
  CWave::CWave((CWave *)&DAT_0044b758);
  return;
}



void FUN_0041865b(void)

{
  FUN_00427dae(FUN_0041866d);
  return;
}



void FUN_0041866d(void)

{
  CWave::~CWave((CWave *)&DAT_0044b758);
  return;
}



void FUN_0041867d(void)

{
  HDC pHVar1;
  HGDIOBJ pvVar2;
  HDC extraout_var;
  CBrush local_30 [8];
  HGDIOBJ local_28;
  HWND__ local_24;
  HGDIOBJ local_20;
  BOOL local_1c;
  CPen local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a232;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pHVar1 = DD_SURFACE::GetDC(&local_24);
  if (pHVar1 != (HDC)0x0) {
    pHVar1 = extraout_var;
    CBrush::CBrush(local_30,0);
    local_8 = 0;
    pvVar2 = (HGDIOBJ)FUN_00414300((int)local_30);
    local_28 = SelectObject((HDC)local_24.unused,pvVar2);
    CPen::CPen(local_18,0,1,0);
    local_8._0_1_ = 1;
    pvVar2 = (HGDIOBJ)FUN_00414280((int)local_18);
    local_20 = SelectObject((HDC)local_24.unused,pvVar2);
    local_1c = Rectangle((HDC)local_24.unused,0x58,0x56,0x22c,0x141);
    SelectObject((HDC)local_24.unused,local_20);
    SelectObject((HDC)local_24.unused,local_28);
    DD_SURFACE::ReleaseDC((HWND)local_24.unused,pHVar1);
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_004142b0((undefined4 *)local_18);
    local_8 = 0xffffffff;
    FUN_00414330((undefined4 *)local_30);
  }
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00418773(int *param_1)

{
  bool bVar1;
  undefined1 uVar2;
  CString *pCVar3;
  undefined4 *puVar4;
  char *pcVar5;
  BOOL BVar6;
  int iVar7;
  undefined3 extraout_var;
  STRING *pSVar8;
  undefined3 extraout_var_00;
  undefined4 uVar9;
  undefined3 extraout_var_01;
  uint uVar10;
  int *piVar11;
  int3 extraout_var_02;
  undefined3 extraout_var_03;
  undefined3 extraout_var_04;
  undefined4 uVar12;
  int extraout_ECX;
  int extraout_ECX_00;
  undefined4 extraout_EDX;
  uint *puVar13;
  int iVar14;
  int iVar15;
  uint *puVar16;
  uint uVar17;
  uint uVar18;
  char **_Delim;
  CString CVar19;
  char *pcVar20;
  undefined *puVar21;
  HANDLE hFindFile;
  char *pcVar22;
  int *local_33c;
  int *local_2cc;
  CString local_27c [4];
  CString local_278 [4];
  CString local_274 [4];
  CString local_270 [4];
  CString local_26c [4];
  CString local_268 [4];
  CString local_264 [4];
  CString local_260 [4];
  CString local_25c [4];
  CString local_258 [4];
  CString local_254 [4];
  CString local_250 [4];
  CString local_24c [4];
  CString local_248 [4];
  CString local_244 [4];
  CString local_240 [4];
  CString local_23c [4];
  undefined1 *local_238;
  CString local_234 [4];
  undefined1 *local_230;
  CString local_22c [4];
  CString local_228 [4];
  CString local_224 [4];
  CString local_220 [4];
  CString local_21c [4];
  CString local_218 [4];
  CString local_214 [4];
  CString local_210 [4];
  CString local_20c [4];
  CString local_208 [4];
  CString local_204 [4];
  CString local_200 [4];
  CString local_1fc [4];
  CString local_1f8 [4];
  CString local_1f4 [4];
  CString local_1f0 [4];
  CString local_1ec [4];
  CString local_1e8 [4];
  CString local_1e4 [4];
  CString local_1e0 [4];
  CString local_1dc [4];
  undefined1 *local_1d8;
  undefined1 *local_1d4;
  undefined1 *local_1d0;
  undefined1 *local_1cc;
  undefined1 *local_1c8;
  void *local_1c4;
  int *local_1c0;
  CString local_1bc [4];
  CString local_1b8 [4];
  CString local_1b4 [4];
  CString local_1b0 [4];
  CString local_1ac [4];
  CString local_1a8 [4];
  uint local_1a4;
  CString local_1a0 [4];
  CString local_19c [4];
  int local_198;
  CString local_194 [4];
  undefined1 *local_190;
  undefined1 *local_18c;
  undefined1 *local_188;
  undefined1 *local_184;
  undefined1 *local_180;
  void *local_17c;
  int *local_178;
  CString local_174 [4];
  CString local_170 [4];
  CString local_16c [4];
  CString local_168 [4];
  CString local_164 [4];
  char local_160;
  STRING local_15c [4];
  undefined1 local_158;
  CString local_154 [4];
  STRING local_150 [4];
  INIFILE local_14c [36];
  CString local_128 [4];
  bool local_124;
  undefined3 uStack_123;
  int *local_120;
  CString local_11c [4];
  CString local_118 [4];
  undefined1 local_114;
  CString local_110 [4];
  SECTION local_10c [8];
  STRING local_104 [4];
  STRING local_100 [4];
  CString local_fc [4];
  CString local_f8 [4];
  STRING local_f4 [4];
  undefined1 local_f0;
  uint local_ec;
  int local_e8;
  int *local_e4;
  uint local_e0;
  CString local_dc [4];
  uint local_d8;
  void *local_d4;
  CString local_d0 [4];
  CString local_cc [4];
  CString local_c8 [4];
  int local_c4;
  uint local_c0;
  CString local_bc [4];
  uint local_b8;
  uint local_b4;
  CFileFind local_b0 [28];
  CString local_94 [4];
  CString local_90 [4];
  uint local_8c;
  int local_88;
  undefined4 local_84;
  uint local_80 [25];
  undefined4 local_1c;
  int local_18;
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_0042a646;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pCVar3 = FUN_004014f0(local_168);
  local_8 = 0;
  pCVar3 = (CString *)operator+(local_16c,(char *)pCVar3);
  local_8._0_1_ = 1;
  CWave::Create((CWave *)&DAT_0044b1c0,pCVar3);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(local_16c);
  local_8 = 0xffffffff;
  CString::~CString(local_168);
  pCVar3 = FUN_004014f0(local_170);
  local_8 = 2;
  pCVar3 = (CString *)operator+(local_174,(char *)pCVar3);
  local_8._0_1_ = 3;
  CWave::Create((CWave *)&DAT_0044b718,pCVar3);
  local_8 = CONCAT31(local_8._1_3_,2);
  CString::~CString(local_174);
  local_8 = 0xffffffff;
  CString::~CString(local_170);
  local_d8 = local_d8 & 0xffffff00;
  local_17c = operator_new(0x1a4);
  local_8 = 4;
  if (local_17c == (void *)0x0) {
    local_2cc = (int *)0x0;
  }
  else {
    local_180 = &stack0xfffffb54;
    CString::CString((CString *)&stack0xfffffb54,(char *)&this_0044dad4);
    local_8._0_1_ = 5;
    local_184 = &stack0xfffffb50;
    CString::CString((CString *)&stack0xfffffb50,(char *)&this_004353dc);
    local_8._0_1_ = 6;
    local_188 = &stack0xfffffb4c;
    CString::CString((CString *)&stack0xfffffb4c,(char *)&this_0044dad8);
    local_8._0_1_ = 7;
    local_18c = &stack0xfffffb48;
    CString::CString((CString *)&stack0xfffffb48,(char *)&this_0044dadc);
    local_8._0_1_ = 8;
    local_190 = &stack0xfffffb44;
    FUN_004014f0((CString *)&stack0xfffffb44);
    local_8 = CONCAT31(local_8._1_3_,4);
    local_2cc = (int *)FUN_0041c000(local_17c);
  }
  local_178 = local_2cc;
  local_8 = 0xffffffff;
  local_e4 = local_2cc;
  FUN_0041c2e0(local_2cc);
  FUN_0041bc70(&DAT_0044dab0,&local_e4);
  CFileFind::CFileFind(local_b0);
  local_8 = 9;
  pcVar22 = s_Level_Packs__004353e0;
  pCVar3 = FUN_004014f0(local_194);
  local_8._0_1_ = 10;
  operator+(local_90,(char *)pCVar3);
  local_8._0_1_ = 0xc;
  CString::~CString(local_194);
  hFindFile = (HANDLE)0x0;
  puVar21 = &DAT_004353f0;
  puVar4 = (undefined4 *)operator+(local_19c,(char *)local_90);
  local_8._0_1_ = 0xd;
  pcVar5 = (char *)FUN_00401470(puVar4);
  local_198 = CFileFind::FindFile(local_b0,pcVar5,(ulong)puVar21);
  local_8 = CONCAT31(local_8._1_3_,0xc);
  CString::~CString(local_19c);
  if (local_198 != 0) {
    local_ec = CONCAT31(local_ec._1_3_,1);
    while ((local_ec & 0xff) != 0) {
      BVar6 = CFileFind::FindNextFileA(hFindFile,(LPWIN32_FIND_DATAA)pcVar22);
      local_ec = CONCAT31(local_ec._1_3_,BVar6 != 0);
      iVar7 = FUN_004080f0((int *)local_b0);
      if ((iVar7 != 0) && (iVar7 = CFileFind::IsDots(local_b0), iVar7 == 0)) {
        pcVar5 = (char *)CFileFind::GetFilePath(local_b0);
        local_8._0_1_ = 0xe;
        operator+(local_164,pcVar5);
        local_8._0_1_ = 0x10;
        CString::~CString(local_1a0);
        puVar4 = (undefined4 *)operator+(local_1a8,(char *)local_164);
        local_8._0_1_ = 0x11;
        pcVar5 = (char *)FUN_00401470(puVar4);
        bVar1 = exists(pcVar5);
        local_1a4 = CONCAT31(local_1a4._1_3_,'\x01' - bVar1);
        local_8._0_1_ = 0x10;
        CString::~CString(local_1a8);
        if ((local_1a4 & 0xff) == 0) {
          pcVar20 = s_PACK_INI_00435404;
          puVar4 = (undefined4 *)operator+(local_1ac,(char *)local_164);
          local_8._0_1_ = 0x12;
          pcVar5 = (char *)FUN_00401470(puVar4);
          INIFILE::INIFILE(local_14c,pcVar5,(int)pcVar20);
          local_8._0_1_ = 0x14;
          CString::~CString(local_1ac);
          FUN_00408bc0(local_10c,local_14c,s_Params_00435410);
          local_8._0_1_ = 0x15;
          INIFILE::SECTION::Get(local_10c,(char *)local_104);
          local_8._0_1_ = 0x16;
          uVar2 = FUN_00414141((int)param_1);
          if ((CONCAT31(extraout_var,uVar2) == 0) ||
             (bVar1 = STRING::equi(local_104,s_false_00435424), !bVar1)) {
            pCVar3 = (CString *)INIFILE::SECTION::Get(local_10c,(char *)local_1b0);
            local_8._0_1_ = 0x17;
            CString::CString(local_128,pCVar3);
            local_8._0_1_ = 0x19;
            FUN_004014d0(local_1b0);
            iVar7 = FUN_0041bc20(local_128,s_false_00435434);
            _local_124 = CONCAT31(uStack_123,iVar7 != 0);
            pCVar3 = (CString *)INIFILE::SECTION::Get(local_10c,(char *)local_1b4);
            local_8._0_1_ = 0x1a;
            CString::CString(local_11c,pCVar3);
            local_8._0_1_ = 0x1c;
            FUN_004014d0(local_1b4);
            INIFILE::SECTION::Get(local_10c,(char *)local_f8);
            local_8._0_1_ = 0x1d;
            INIFILE::SECTION::Get(local_10c,(char *)local_f4);
            local_8._0_1_ = 0x1e;
            bVar1 = STRING::equi(local_f4,s_false_0043545c);
            local_160 = '\x01' - bVar1;
            INIFILE::SECTION::Get(local_10c,(char *)local_100);
            local_8._0_1_ = 0x1f;
            local_158 = STRING::equi(local_100,&DAT_00435470);
            pcVar5 = &DAT_00435484;
            pSVar8 = (STRING *)INIFILE::SECTION::Get(local_10c,(char *)local_1b8);
            local_8._0_1_ = 0x20;
            pSVar8 = STRING::trim(pSVar8,pcVar5);
            FUN_00407d70(local_118,(CString *)pSVar8);
            local_8._0_1_ = 0x22;
            FUN_004014d0(local_1b8);
            INIFILE::SECTION::Get(local_10c,(char *)local_fc);
            local_8._0_1_ = 0x23;
            INIFILE::SECTION::Get(local_10c,(char *)local_110);
            local_8._0_1_ = 0x24;
            INIFILE::SECTION::Get(local_10c,(char *)local_154);
            local_8._0_1_ = 0x25;
            bVar1 = FUN_00401430((int *)local_154);
            if (CONCAT31(extraout_var_00,bVar1) != 0) {
              FUN_004056a0(local_1bc,&DAT_004354b0);
              local_8._0_1_ = 0x26;
              FUN_004048d0(local_154,local_1bc);
              local_8._0_1_ = 0x25;
              FUN_004014d0(local_1bc);
            }
            INIFILE::SECTION::Get(local_10c,(char *)local_150);
            local_8._0_1_ = 0x27;
            local_f0 = STRING::equi(local_150,&DAT_004354bc);
            INIFILE::SECTION::Get(local_10c,(char *)local_15c);
            local_8._0_1_ = 0x28;
            local_114 = STRING::equi(local_15c,&DAT_004354d0);
            local_1c4 = operator_new(0x1a4);
            local_8._0_1_ = 0x29;
            if (local_1c4 == (void *)0x0) {
              local_33c = (int *)0x0;
            }
            else {
              STRING::atol((char *)CONCAT31((int3)((uint)extraout_EDX >> 8),local_160));
              local_1c8 = &stack0xfffffb3c;
              CString::CString((CString *)&stack0xfffffb3c,local_118);
              local_8._0_1_ = 0x2a;
              local_1cc = &stack0xfffffb38;
              CString::CString((CString *)&stack0xfffffb38,local_154);
              local_8._0_1_ = 0x2b;
              local_1d0 = &stack0xfffffb34;
              CString::CString((CString *)&stack0xfffffb34,local_110);
              local_8._0_1_ = 0x2c;
              local_1d4 = &stack0xfffffb30;
              CString::CString((CString *)&stack0xfffffb30,local_fc);
              local_8._0_1_ = 0x2d;
              local_1d8 = &stack0xfffffb2c;
              CString::CString((CString *)&stack0xfffffb2c,local_164);
              local_8._0_1_ = 0x29;
              local_33c = (int *)FUN_0041c000(local_1c4);
            }
            local_1c0 = local_33c;
            local_8._0_1_ = 0x28;
            local_120 = local_33c;
            FUN_0041c2e0(local_33c);
            CString::TrimRight(local_164,(char *)&this_004354d8);
            _Delim = &_Str_004354dc;
            pCVar3 = local_1e0;
            FUN_00405680(local_1dc,local_164);
            local_8._0_1_ = 0x2e;
            pCVar3 = (CString *)STRING::strtok((char *)pCVar3,(char *)_Delim);
            local_8._0_1_ = 0x2f;
            CString::operator=((CString *)(local_120 + 99),pCVar3);
            local_8._0_1_ = 0x2e;
            FUN_004014d0(local_1e0);
            local_8._0_1_ = 0x28;
            FUN_004014d0(local_1dc);
            FUN_0041bc70(&DAT_0044dab0,&local_120);
            local_8._0_1_ = 0x27;
            FUN_004014d0((CString *)local_15c);
            local_8._0_1_ = 0x25;
            FUN_004014d0((CString *)local_150);
            local_8._0_1_ = 0x24;
            FUN_004014d0(local_154);
            local_8._0_1_ = 0x23;
            FUN_004014d0(local_110);
            local_8._0_1_ = 0x22;
            FUN_004014d0(local_fc);
            local_8._0_1_ = 0x1f;
            FUN_004014d0(local_118);
            local_8._0_1_ = 0x1e;
            FUN_004014d0((CString *)local_100);
            local_8._0_1_ = 0x1d;
            FUN_004014d0((CString *)local_f4);
            local_8._0_1_ = 0x1c;
            FUN_004014d0(local_f8);
            local_8._0_1_ = 0x19;
            CString::~CString(local_11c);
            local_8._0_1_ = 0x16;
            CString::~CString(local_128);
            local_8._0_1_ = 0x15;
            FUN_004014d0((CString *)local_104);
            local_8._0_1_ = 0x14;
            FUN_00407d90((int)local_10c);
            local_8._0_1_ = 0x10;
            INIFILE::~INIFILE(local_14c);
            local_8 = CONCAT31(local_8._1_3_,0xc);
            CString::~CString(local_164);
          }
          else {
            local_8._0_1_ = 0x15;
            FUN_004014d0((CString *)local_104);
            local_8._0_1_ = 0x14;
            FUN_00407d90((int)local_10c);
            local_8._0_1_ = 0x10;
            INIFILE::~INIFILE(local_14c);
            local_8 = CONCAT31(local_8._1_3_,0xc);
            CString::~CString(local_164);
          }
        }
        else {
          local_8 = CONCAT31(local_8._1_3_,0xc);
          CString::~CString(local_164);
        }
      }
    }
  }
  pCVar3 = FUN_004014f0(local_1e4);
  local_8._0_1_ = 0x30;
  puVar4 = (undefined4 *)operator+(local_1e8,(char *)pCVar3);
  local_8._0_1_ = 0x31;
  uVar9 = FUN_00401470(puVar4);
  uVar2 = (undefined1)uVar9;
  pcVar22 = s_Pictures_btnbluequitup_bmp_00435500;
  pCVar3 = FUN_004014f0(local_1ec);
  local_8._0_1_ = 0x32;
  puVar4 = (undefined4 *)operator+(local_1f0,(char *)pCVar3);
  local_8._0_1_ = 0x33;
  pcVar5 = (char *)FUN_00401470(puVar4);
  BUTTON::Init((BUTTON *)&DAT_0044b200,pcVar5,pcVar22,(bool)uVar2);
  local_8._0_1_ = 0x32;
  CString::~CString(local_1f0);
  local_8._0_1_ = 0x31;
  CString::~CString(local_1ec);
  local_8._0_1_ = 0x30;
  CString::~CString(local_1e8);
  local_8._0_1_ = 0xc;
  CString::~CString(local_1e4);
  OVERLAY::SetPosition((OVERLAY *)&DAT_0044b200,0xd1,0x1b9);
  pCVar3 = FUN_004014f0(local_1f4);
  local_8._0_1_ = 0x34;
  puVar4 = (undefined4 *)operator+(local_1f8,(char *)pCVar3);
  local_8._0_1_ = 0x35;
  uVar9 = FUN_00401470(puVar4);
  CVar19 = SUB41(uVar9,0);
  pcVar22 = s_Pictures_btnbuy_bmp_00435534;
  pCVar3 = FUN_004014f0(local_1fc);
  local_8._0_1_ = 0x36;
  puVar4 = (undefined4 *)operator+(local_200,(char *)pCVar3);
  local_8._0_1_ = 0x37;
  pcVar5 = (char *)FUN_00401470(puVar4);
  BUTTON::Init((BUTTON *)&DAT_0044c5a8,pcVar5,pcVar22,(bool)CVar19);
  local_8._0_1_ = 0x36;
  CString::~CString(local_200);
  local_8._0_1_ = 0x35;
  CString::~CString(local_1fc);
  local_8._0_1_ = 0x34;
  CString::~CString(local_1f8);
  local_8 = CONCAT31(local_8._1_3_,0xc);
  CString::~CString(local_1f4);
  OVERLAY::SetPosition((OVERLAY *)&DAT_0044c5a8,0x13e,400);
  uVar2 = FUN_00414141((int)param_1);
  if (CONCAT31(extraout_var_01,uVar2) == 0) {
    FUN_0040c710(0x44c5a8);
  }
  pCVar3 = FUN_004014f0(local_204);
  local_8._0_1_ = 0x38;
  puVar4 = (undefined4 *)operator+(local_208,(char *)pCVar3);
  local_8._0_1_ = 0x39;
  uVar9 = FUN_00401470(puVar4);
  CVar19 = SUB41(uVar9,0);
  pcVar22 = s_Pictures_btnoptionsup_bmp_00435564;
  pCVar3 = FUN_004014f0(local_20c);
  local_8._0_1_ = 0x3a;
  puVar4 = (undefined4 *)operator+(local_210,(char *)pCVar3);
  local_8._0_1_ = 0x3b;
  pcVar5 = (char *)FUN_00401470(puVar4);
  BUTTON::Init((BUTTON *)&DAT_0044b598,pcVar5,pcVar22,(bool)CVar19);
  local_8._0_1_ = 0x3a;
  CString::~CString(local_210);
  local_8._0_1_ = 0x39;
  CString::~CString(local_20c);
  local_8._0_1_ = 0x38;
  CString::~CString(local_208);
  local_8._0_1_ = 0xc;
  CString::~CString(local_204);
  OVERLAY::SetPosition((OVERLAY *)&DAT_0044b598,0x144,0x1b9);
  pCVar3 = FUN_004014f0(local_214);
  local_8._0_1_ = 0x3c;
  operator+(local_dc,(char *)pCVar3);
  local_8._0_1_ = 0x3e;
  CString::~CString(local_214);
  pCVar3 = FUN_004014f0(local_218);
  local_8._0_1_ = 0x3f;
  operator+(local_14,(char *)pCVar3);
  local_8._0_1_ = 0x41;
  CString::~CString(local_218);
  CVar19 = (CString)0x0;
  pcVar5 = (char *)FUN_00401470((undefined4 *)local_14);
  pcVar22 = (char *)FUN_00401470((undefined4 *)local_dc);
  BUTTON::Init((BUTTON *)&DAT_0044b418,pcVar22,pcVar5,(bool)CVar19);
  uVar18 = 3;
  uVar10 = FUN_00423620(0x44dab0);
  uVar10 = FUN_0041bf20(uVar10,uVar18);
  OVERLAY::SetPosition((OVERLAY *)&DAT_0044b418,0x5e,(3 - uVar10) * 0x32 + 0x5a);
  FUN_0040c710(0x44b418);
  pCVar3 = FUN_004014f0(local_21c);
  local_8._0_1_ = 0x42;
  operator+(local_c8,(char *)pCVar3);
  local_8._0_1_ = 0x44;
  CString::~CString(local_21c);
  pCVar3 = FUN_004014f0(local_220);
  local_8._0_1_ = 0x45;
  operator+(local_bc,(char *)pCVar3);
  local_8._0_1_ = 0x47;
  CString::~CString(local_220);
  CVar19 = (CString)0x0;
  pcVar5 = (char *)FUN_00401470((undefined4 *)local_bc);
  pcVar22 = (char *)FUN_00401470((undefined4 *)local_c8);
  BUTTON::Init((BUTTON *)&DAT_0044c800,pcVar22,pcVar5,(bool)CVar19);
  uVar18 = 3;
  uVar10 = FUN_00423620(0x44dab0);
  uVar10 = FUN_0041bf20(uVar10,uVar18);
  uVar17 = 3;
  uVar18 = FUN_00423620(0x44dab0);
  uVar18 = FUN_0041bf20(uVar18,uVar17);
  OVERLAY::SetPosition((OVERLAY *)&DAT_0044c800,0x5e,uVar10 * 0x37 + 0x7e + (3 - uVar18) * 0x32);
  FUN_0040c710(0x44c800);
  pCVar3 = FUN_004014f0(local_224);
  local_8._0_1_ = 0x48;
  operator+(local_94,(char *)pCVar3);
  local_8 = CONCAT31(local_8._1_3_,0x4a);
  CString::~CString(local_224);
  CVar19 = (CString)0x0;
  pcVar5 = (char *)FUN_00401470((undefined4 *)local_94);
  OVERLAY::Init((OVERLAY *)&DAT_0044c730,pcVar5,(bool)CVar19);
  local_8c = 0;
  local_d4 = (void *)0x0;
  local_88 = 0;
  local_18 = 0;
  while (iVar7 = FUN_00423620(0x44dab0), local_18 < iVar7 + -1) {
    local_8c = 0;
    while (iVar7 = FUN_00423620(0x44dab0), (int)local_8c < iVar7 + -1) {
      puVar4 = (undefined4 *)FUN_00407f60(&DAT_0044dab0,local_8c);
      local_d4 = (void *)*puVar4;
      piVar11 = (int *)FUN_00407f60(&DAT_0044dab0,local_8c + 1);
      local_88 = *piVar11;
      bVar1 = FUN_0041c3d0(local_d4,local_88);
      if (CONCAT31(extraout_var_02,bVar1) != 0 && -1 < extraout_var_02) {
        FUN_0041bc90(&DAT_0044dab0,local_8c,local_8c + 1);
      }
      local_8c = local_8c + 1;
    }
    local_18 = local_18 + 1;
  }
  pCVar3 = (CString *)
           INIFILE::GetValue((INIFILE *)(param_1 + 0x3d),(char *)local_228,s_Params_00435618);
  local_8._0_1_ = 0x4b;
  CString::CString(local_d0,pCVar3);
  local_8 = CONCAT31(local_8._1_3_,0x4d);
  FUN_004014d0(local_228);
  local_e0 = 0;
  local_e8 = FUN_00423770(0x44dab0);
  local_c4 = 0;
  local_b4 = 0;
  bVar1 = IsEmpty(0x44dab0);
  if (CONCAT31(extraout_var_03,bVar1) == 0) {
    piVar11 = (int *)FUN_0041be90(&local_e8);
    local_c4 = *piVar11;
  }
  local_b4 = 0;
  while( true ) {
    uVar10 = FUN_00423620(0x44dab0);
    if ((uVar10 <= local_b4) || (bVar1 = IsEmpty(0x44dab0), CONCAT31(extraout_var_04,bVar1) != 0))
    goto LAB_00419b11;
    bVar1 = FUN_004087b0((void *)(local_c4 + 0x180),(undefined4 *)local_d0);
    if (bVar1) break;
    local_e0 = local_e0 + 1;
    local_b4 = local_b4 + 1;
    uVar10 = FUN_00423620(0x44dab0);
    if (local_b4 < uVar10) {
      piVar11 = (int *)FUN_0041be90(&local_e8);
      local_c4 = *piVar11;
    }
  }
  FUN_0041a41b(param_1,local_c4);
LAB_00419b11:
  if (param_1[0xe] == 0) {
    local_e0 = 0;
    piVar11 = (int *)FUN_00407f60(&DAT_0044dab0,0);
    FUN_0041a41b(param_1,*piVar11);
  }
  uVar18 = 3;
  uVar10 = FUN_00423620(0x44dab0);
  uVar10 = FUN_0041bf20(uVar10,uVar18);
  if (uVar10 <= local_e0) {
    uVar18 = 3;
    uVar10 = FUN_00423620(0x44dab0);
    uVar10 = FUN_0041bf20(uVar10,uVar18);
    DAT_0044dacc = (local_e0 - uVar10) + 1;
  }
  local_b8 = 0;
  local_c0 = 0;
  pCVar3 = FUN_004014f0(local_22c);
  local_8._0_1_ = 0x4e;
  operator+(local_cc,(char *)pCVar3);
  local_8 = CONCAT31(local_8._1_3_,0x50);
  CString::~CString(local_22c);
  puVar13 = &local_c0;
  puVar16 = &local_b8;
  pcVar5 = (char *)FUN_00401470((undefined4 *)local_cc);
  GKTOOLS::GetDIBSize(pcVar5,puVar16,puVar13);
  puVar13 = local_80;
  for (iVar7 = 0x1a; iVar7 != 0; iVar7 = iVar7 + -1) {
    *puVar13 = 0;
    puVar13 = puVar13 + 1;
  }
  local_84 = 0x6c;
  local_80[0] = 7;
  local_80[2] = local_b8;
  local_80[1] = local_c0;
  local_1c = 0x840;
  DD_SURFACE::Create((DD_SURFACE *)&this_0044b380,(_DDSURFACEDESC *)&local_84,(HWND__ *)0x0);
  CVar19 = (CString)0x0;
  uVar18 = 0;
  uVar10 = 0;
  pcVar5 = (char *)FUN_00401470((undefined4 *)local_cc);
  GKTOOLS::CopyDIBToSurface((DD_SURFACE *)&this_0044b380,pcVar5,uVar10,uVar18,(bool)CVar19);
  iVar15 = 5;
  iVar14 = 0;
  local_230 = &stack0xfffffb24;
  iVar7 = extraout_ECX;
  CString::CString((CString *)&stack0xfffffb24,s_right_lights_bmp_0043563c);
  uVar2 = SUB41(local_234,0);
  puVar4 = (undefined4 *)(**(code **)(*param_1 + 0x54))();
  local_8._0_1_ = 0x51;
  pcVar5 = (char *)FUN_00401470(puVar4);
  SPRITE::Init((SPRITE *)&DAT_0044c980,pcVar5,(bool)uVar2,iVar7,iVar14,iVar15);
  local_8._0_1_ = 0x50;
  CString::~CString(local_234);
  SPRITE::SetPosition((SPRITE *)&DAT_0044c980,0x1b4,0x199);
  SPRITE::SetAnimationDelay((SPRITE *)&DAT_0044c980,200);
  SPRITE::StartAnimation((SPRITE *)&DAT_0044c980);
  SPRITE::Hide((SPRITE *)&DAT_0044c980);
  iVar15 = 5;
  iVar14 = 0;
  local_238 = &stack0xfffffb1c;
  iVar7 = extraout_ECX_00;
  CString::CString((CString *)&stack0xfffffb1c,s_left_lights_bmp_00435650);
  uVar2 = SUB41(local_23c,0);
  puVar4 = (undefined4 *)(**(code **)(*param_1 + 0x54))();
  local_8._0_1_ = 0x52;
  pcVar5 = (char *)FUN_00401470(puVar4);
  SPRITE::Init((SPRITE *)&DAT_0044a090,pcVar5,(bool)uVar2,iVar7,iVar14,iVar15);
  local_8._0_1_ = 0x50;
  CString::~CString(local_23c);
  SPRITE::SetPosition((SPRITE *)&DAT_0044a090,0x77,0x1a0);
  SPRITE::SetAnimationDelay((SPRITE *)&DAT_0044a090,200);
  SPRITE::StartAnimation((SPRITE *)&DAT_0044a090);
  SPRITE::Hide((SPRITE *)&DAT_0044a090);
  pCVar3 = FUN_004014f0(local_240);
  local_8._0_1_ = 0x53;
  puVar4 = (undefined4 *)operator+(local_244,(char *)pCVar3);
  local_8._0_1_ = 0x54;
  FUN_00401470(puVar4);
  (**(code **)(param_1[0x1926] + 0x3c))();
  local_8._0_1_ = 0x53;
  CString::~CString(local_244);
  local_8._0_1_ = 0x50;
  CString::~CString(local_240);
  pCVar3 = FUN_004014f0(local_248);
  local_8._0_1_ = 0x55;
  puVar4 = (undefined4 *)operator+(local_24c,(char *)pCVar3);
  local_8._0_1_ = 0x56;
  uVar9 = FUN_00401470(puVar4);
  pcVar5 = s_Pictures_yesup_bmp_0043568c;
  pCVar3 = FUN_004014f0(local_250);
  local_8._0_1_ = 0x57;
  puVar4 = (undefined4 *)operator+(local_254,(char *)pCVar3);
  local_8._0_1_ = 0x58;
  uVar12 = FUN_00401470(puVar4);
  (**(code **)(param_1[0xe2e] + 0x4c))(uVar12,pcVar5,uVar9);
  local_8._0_1_ = 0x57;
  CString::~CString(local_254);
  local_8._0_1_ = 0x56;
  CString::~CString(local_250);
  local_8._0_1_ = 0x55;
  CString::~CString(local_24c);
  local_8._0_1_ = 0x50;
  CString::~CString(local_248);
  pCVar3 = FUN_004014f0(local_258);
  local_8._0_1_ = 0x59;
  puVar4 = (undefined4 *)operator+(local_25c,(char *)pCVar3);
  local_8._0_1_ = 0x5a;
  uVar9 = FUN_00401470(puVar4);
  pcVar5 = s_Pictures_noup_bmp_004356b4;
  pCVar3 = FUN_004014f0(local_260);
  local_8._0_1_ = 0x5b;
  puVar4 = (undefined4 *)operator+(local_264,(char *)pCVar3);
  local_8._0_1_ = 0x5c;
  uVar12 = FUN_00401470(puVar4);
  (**(code **)(param_1[0xe8d] + 0x4c))(uVar12,pcVar5,uVar9);
  local_8._0_1_ = 0x5b;
  CString::~CString(local_264);
  local_8._0_1_ = 0x5a;
  CString::~CString(local_260);
  local_8._0_1_ = 0x59;
  CString::~CString(local_25c);
  local_8._0_1_ = 0x50;
  CString::~CString(local_258);
  (**(code **)(param_1[0x1926] + 0x2c))(0xce,100);
  (**(code **)(param_1[0xe2e] + 0x2c))(0xf0,0xb8);
  (**(code **)(param_1[0xe8d] + 0x2c))(0x142,0xb8);
  pCVar3 = FUN_004014f0(local_268);
  local_8._0_1_ = 0x5d;
  puVar4 = (undefined4 *)operator+(local_26c,(char *)pCVar3);
  local_8._0_1_ = 0x5e;
  pcVar5 = (char *)FUN_00401470(puVar4);
  FONT::InitFont((FONT *)&DAT_00448fe0,pcVar5);
  local_8._0_1_ = 0x5d;
  CString::~CString(local_26c);
  local_8._0_1_ = 0x50;
  CString::~CString(local_268);
  pCVar3 = FUN_004014f0(local_270);
  local_8._0_1_ = 0x5f;
  pCVar3 = (CString *)operator+(local_274,(char *)pCVar3);
  local_8._0_1_ = 0x60;
  CWave::Create((CWave *)&DAT_0044b758,pCVar3);
  local_8._0_1_ = 0x5f;
  CString::~CString(local_274);
  local_8._0_1_ = 0x50;
  CString::~CString(local_270);
  GKERNEL::ResetFrameCounter();
  pCVar3 = FUN_004014f0(local_278);
  local_8._0_1_ = 0x61;
  puVar4 = (undefined4 *)operator+(local_27c,(char *)pCVar3);
  local_8._0_1_ = 0x62;
  pcVar5 = (char *)FUN_00401470(puVar4);
  CMidi::LoadSong((CMidi *)(param_1 + 0x17d2),pcVar5);
  local_8._0_1_ = 0x61;
  CString::~CString(local_27c);
  local_8._0_1_ = 0x50;
  CString::~CString(local_278);
  local_8._0_1_ = 0x4d;
  CString::~CString(local_cc);
  local_8._0_1_ = 0x4a;
  CString::~CString(local_d0);
  local_8._0_1_ = 0x47;
  CString::~CString(local_94);
  local_8._0_1_ = 0x44;
  CString::~CString(local_bc);
  local_8._0_1_ = 0x41;
  CString::~CString(local_c8);
  local_8._0_1_ = 0x3e;
  CString::~CString(local_14);
  local_8._0_1_ = 0xc;
  CString::~CString(local_dc);
  local_8 = CONCAT31(local_8._1_3_,9);
  CString::~CString(local_90);
  local_8 = 0xffffffff;
  CFileFind::~CFileFind(local_b0);
  ExceptionList = local_10;
  return;
}



void FUN_0041a33a(void)

{
  bool bVar1;
  undefined3 extraout_var;
  uint uVar2;
  undefined3 extraout_var_00;
  int local_10;
  undefined4 *local_c;
  uint local_8;
  
  local_10 = FUN_00423770(0x44dab0);
  local_c = (undefined4 *)0x0;
  local_8 = 0;
  bVar1 = IsEmpty(0x44dab0);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = (undefined4 *)FUN_0041be90(&local_10);
    local_c = (undefined4 *)*local_c;
  }
  local_8 = 0;
  while ((uVar2 = FUN_00423620(0x44dab0), local_8 < uVar2 &&
         (bVar1 = IsEmpty(0x44dab0), CONCAT31(extraout_var_00,bVar1) == 0))) {
    if (local_c != (undefined4 *)0x0) {
      (**(code **)*local_c)(1);
    }
    local_8 = local_8 + 1;
    uVar2 = FUN_00423620(0x44dab0);
    if (local_8 < uVar2) {
      local_c = (undefined4 *)FUN_0041be90(&local_10);
      local_c = (undefined4 *)*local_c;
    }
  }
  FUN_0041be10(0x44dab0);
  return;
}



void __thiscall FUN_0041a41b(void *this,int param_1)

{
  if ((param_1 != 0) && (param_1 != *(int *)((int)this + 0x38))) {
    if (*(int *)((int)this + 0x38) != 0) {
      FUN_0040b710(*(int *)((int)this + 0x38));
    }
    *(int *)((int)this + 0x38) = param_1;
    FUN_0040b710(*(int *)((int)this + 0x38));
  }
  return;
}



void FUN_0041a469(void)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  int iVar5;
  uint uVar6;
  uint uVar7;
  int local_18;
  int *local_14;
  uint local_10;
  int *local_c;
  uint local_8;
  
  TwLightning::DrawToBack((TwLightning *)&DAT_0044b798);
  if (DAT_0044dacc == 0) {
    FUN_0040c710(0x44b418);
    uVar6 = 3;
    uVar2 = FUN_00423620(0x44dab0);
    uVar2 = FUN_0041bf20(uVar2,uVar6);
    OVERLAY::SetPosition((OVERLAY *)&DAT_0044c730,0x5e,(3 - uVar2) * 0x32 + 0x67);
    OVERLAY::DrawToBack((OVERLAY *)&DAT_0044c730);
  }
  else {
    FUN_0040c6f0(0x44b418);
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044b418);
    if (bVar1) {
      FUN_00416400(0x44b418);
    }
    else {
      FUN_0040b6f0(0x44b418);
    }
  }
  uVar6 = 3;
  uVar2 = FUN_00423620(0x44dab0);
  uVar2 = FUN_0041bf20(uVar2,uVar6);
  iVar5 = DAT_0044dacc + uVar2;
  iVar3 = FUN_00423620(0x44dab0);
  if (iVar5 == iVar3) {
    FUN_0040c710(0x44c800);
    uVar6 = 3;
    uVar2 = FUN_00423620(0x44dab0);
    uVar2 = FUN_0041bf20(uVar2,uVar6);
    uVar7 = 3;
    uVar6 = FUN_00423620(0x44dab0);
    uVar6 = FUN_0041bf20(uVar6,uVar7);
    OVERLAY::SetPosition((OVERLAY *)&DAT_0044c730,0x5e,uVar2 * 0x37 + 0x7d + (3 - uVar6) * 0x32);
    OVERLAY::DrawToBack((OVERLAY *)&DAT_0044c730);
  }
  else {
    FUN_0040c6f0(0x44c800);
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044c800);
    if (bVar1) {
      FUN_00416400(0x44c800);
    }
    else {
      FUN_0040b6f0(0x44c800);
    }
  }
  local_8 = 0;
  do {
    uVar2 = FUN_00423620(0x44dab0);
    if (uVar2 <= local_8) {
      BUTTON::DrawToBack((BUTTON *)&DAT_0044b200);
      BUTTON::DrawToBack((BUTTON *)&DAT_0044c5a8);
      BUTTON::DrawToBack((BUTTON *)&DAT_0044b598);
      BUTTON::DrawToBack((BUTTON *)&DAT_0044b418);
      BUTTON::DrawToBack((BUTTON *)&DAT_0044c800);
      local_18 = FUN_00423770(0x44dab0);
      local_14 = (int *)0x0;
      local_10 = 0;
      bVar1 = IsEmpty(0x44dab0);
      if (CONCAT31(extraout_var,bVar1) == 0) {
        puVar4 = (undefined4 *)FUN_0041be90(&local_18);
        local_14 = (int *)*puVar4;
      }
      local_10 = 0;
      while ((uVar2 = FUN_00423620(0x44dab0), local_10 < uVar2 &&
             (bVar1 = IsEmpty(0x44dab0), CONCAT31(extraout_var_00,bVar1) == 0))) {
        (**(code **)(*local_14 + 0x14))();
        local_10 = local_10 + 1;
        uVar2 = FUN_00423620(0x44dab0);
        if (local_10 < uVar2) {
          puVar4 = (undefined4 *)FUN_0041be90(&local_18);
          local_14 = (int *)*puVar4;
        }
      }
      return;
    }
    puVar4 = (undefined4 *)FUN_00407f60(&DAT_0044dab0,local_8);
    local_c = (int *)*puVar4;
    if (local_8 < DAT_0044dacc) {
LAB_0041a6c6:
      (**(code **)(*local_c + 0x20))();
    }
    else {
      uVar6 = local_8 - DAT_0044dacc;
      uVar7 = 3;
      uVar2 = FUN_00423620(0x44dab0);
      uVar2 = FUN_0041bf20(uVar2,uVar7);
      if (uVar2 <= uVar6) goto LAB_0041a6c6;
      iVar3 = FUN_0040b790((int)local_c);
      if (iVar3 == 1) {
        iVar3 = local_8 - DAT_0044dacc;
        uVar6 = 3;
        uVar2 = FUN_00423620(0x44dab0);
        uVar2 = FUN_0041bf20(uVar2,uVar6);
        (**(code **)(*local_c + 0x2c))(0x6a,iVar3 * 0x37 + 0x7e + (3 - uVar2) * 0x32);
      }
      else {
        iVar3 = local_8 - DAT_0044dacc;
        uVar6 = 3;
        uVar2 = FUN_00423620(0x44dab0);
        uVar2 = FUN_0041bf20(uVar2,uVar6);
        (**(code **)(*local_c + 0x2c))(0x69,iVar3 * 0x37 + 0x7d + (3 - uVar2) * 0x32);
      }
      (**(code **)(*local_c + 0x1c))();
    }
    local_8 = local_8 + 1;
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0041a7ba(void)

{
  bool bVar1;
  undefined3 extraout_var;
  int *piVar2;
  uint uVar3;
  undefined3 extraout_var_00;
  CString *pCVar4;
  char *pcVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  HINSTANCE__ *pHVar9;
  CString local_38 [4];
  CString local_34 [4];
  CString local_30 [4];
  CString local_2c [4];
  CString local_28 [4];
  CString local_24 [4];
  int local_20;
  int local_1c;
  uint local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a686;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_0040b710(0x44b200);
  FUN_0040b710(0x44c5a8);
  FUN_0040b710(0x44b598);
  FUN_0040b710(0x44b418);
  FUN_0040b710(0x44c800);
  local_20 = FUN_00423770(0x44dab0);
  local_1c = 0;
  local_18 = 0;
  bVar1 = IsEmpty(0x44dab0);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    piVar2 = (int *)FUN_0041be90(&local_20);
    local_1c = *piVar2;
  }
  local_18 = 0;
  while ((uVar3 = FUN_00423620(0x44dab0), local_18 < uVar3 &&
         (bVar1 = IsEmpty(0x44dab0), CONCAT31(extraout_var_00,bVar1) == 0))) {
    FUN_0040b710(local_1c);
    local_18 = local_18 + 1;
    uVar3 = FUN_00423620(0x44dab0);
    if (local_18 < uVar3) {
      piVar2 = (int *)FUN_0041be90(&local_20);
      local_1c = *piVar2;
    }
  }
  CString::operator=((CString *)&DAT_0044c728,&DAT_0044dae0);
  _DAT_0044dad0 = 0;
  GKERNEL::NewSpriteBackground();
  for (local_14 = 0; local_14 < 2; local_14 = local_14 + 1) {
    FUN_0041ab42();
    pCVar4 = FUN_004014f0(local_28);
    local_8 = 0;
    operator+(local_24,(char *)pCVar4);
    local_8._0_1_ = 2;
    CString::~CString(local_28);
    bVar1 = false;
    pHVar9 = (HINSTANCE__ *)0x0;
    iVar7 = 0;
    uVar6 = 0;
    uVar3 = 0;
    pcVar5 = (char *)FUN_00401470((undefined4 *)local_24);
    GKTOOLS::CopyDIBToBack(pcVar5,uVar3,uVar6,iVar7,pHVar9,bVar1);
    pCVar4 = FUN_004014f0(local_2c);
    local_8._0_1_ = 3;
    pCVar4 = (CString *)operator+(local_30,(char *)pCVar4);
    local_8._0_1_ = 4;
    CString::operator=(local_24,pCVar4);
    local_8._0_1_ = 3;
    CString::~CString(local_30);
    local_8._0_1_ = 2;
    CString::~CString(local_2c);
    bVar1 = false;
    pHVar9 = (HINSTANCE__ *)0x0;
    iVar7 = 0;
    uVar6 = 0;
    uVar3 = 0x21c;
    pcVar5 = (char *)FUN_00401470((undefined4 *)local_24);
    GKTOOLS::CopyDIBToBack(pcVar5,uVar3,uVar6,iVar7,pHVar9,bVar1);
    pCVar4 = FUN_004014f0(local_34);
    local_8._0_1_ = 5;
    pCVar4 = (CString *)operator+(local_38,(char *)pCVar4);
    local_8._0_1_ = 6;
    CString::operator=(local_24,pCVar4);
    local_8._0_1_ = 5;
    CString::~CString(local_38);
    local_8 = CONCAT31(local_8._1_3_,2);
    CString::~CString(local_34);
    bVar1 = true;
    pHVar9 = (HINSTANCE__ *)0x0;
    iVar7 = 0;
    uVar6 = 0x132;
    uVar3 = 100;
    pcVar5 = (char *)FUN_00401470((undefined4 *)local_24);
    GKTOOLS::CopyDIBToBack(pcVar5,uVar3,uVar6,iVar7,pHVar9,bVar1);
    uVar6 = 3;
    uVar3 = FUN_00423620(0x44dab0);
    uVar3 = FUN_0041bf20(uVar3,uVar6);
    uVar8 = 3;
    uVar6 = FUN_00423620(0x44dab0);
    uVar6 = FUN_0041bf20(uVar6,uVar8);
    OVERLAY::SetPosition((OVERLAY *)&DAT_0044c730,0x5e,uVar3 * 0x37 + 0x7d + (3 - uVar6) * 0x32);
    OVERLAY::DrawToBack((OVERLAY *)&DAT_0044c730);
    uVar6 = 3;
    uVar3 = FUN_00423620(0x44dab0);
    uVar3 = FUN_0041bf20(uVar3,uVar6);
    OVERLAY::SetPosition((OVERLAY *)&DAT_0044c730,0x5e,(3 - uVar3) * 0x32 + 0x67);
    OVERLAY::DrawToBack((OVERLAY *)&DAT_0044c730);
    GKERNEL::Flip();
    local_8 = 0xffffffff;
    CString::~CString(local_24);
  }
  TwLightning::Init((TwLightning *)&DAT_0044b798,0x1e6,0x4f,0xffffff,0x641e1e);
  TwLightning::SetFramesPerSecond((TwLightning *)&DAT_0044b798,0x3c);
  TwTransparentOverlay::SetPosition((TwTransparentOverlay *)&DAT_0044b798,0x4d,0x11);
  _DAT_0044b918 = 4000;
  _DAT_0044b908 = 0x420c0000;
  ExceptionList = local_10;
  return;
}



void FUN_0041ab42(void)

{
  HDC pHVar1;
  HGDIOBJ pvVar2;
  HGDIOBJ h;
  HDC in_stack_ffffffd0;
  HWND__ local_24;
  HGDIOBJ local_20;
  BOOL local_1c;
  CPen local_18 [8];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a6a2;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pHVar1 = DD_SURFACE::GetDC(&local_24);
  if (pHVar1 != (HDC)0x0) {
    CBrush::CBrush((CBrush *)&stack0xffffffd0,0);
    local_8 = 0;
    pvVar2 = (HGDIOBJ)FUN_00414300((int)&stack0xffffffd0);
    pvVar2 = SelectObject((HDC)local_24.unused,pvVar2);
    CPen::CPen(local_18,0,1,0);
    local_8._0_1_ = 1;
    h = (HGDIOBJ)FUN_00414280((int)local_18);
    local_20 = SelectObject((HDC)local_24.unused,h);
    local_1c = Rectangle((HDC)local_24.unused,0,0,0x280,0x1e0);
    SelectObject((HDC)local_24.unused,local_20);
    SelectObject((HDC)local_24.unused,pvVar2);
    DD_SURFACE::ReleaseDC((HWND)local_24.unused,in_stack_ffffffd0);
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_004142b0((undefined4 *)local_18);
    local_8 = 0xffffffff;
    FUN_00414330((undefined4 *)&stack0xffffffd0);
  }
  ExceptionList = local_10;
  return;
}



void FUN_0041ac35(char param_1)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  undefined4 *puVar3;
  uint uVar4;
  undefined3 extraout_var_00;
  int local_10;
  TwAutoButton *local_c;
  uint local_8;
  
  if (param_1 != '\0') {
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044b200);
    if (bVar1) {
      FUN_00416400(0x44b200);
    }
    else {
      FUN_0040b740((int *)&DAT_0044b200);
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044c5a8);
    if (bVar1) {
      FUN_00416400(0x44c5a8);
    }
    else {
      FUN_0040b740((int *)&DAT_0044c5a8);
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044b598);
    if (bVar1) {
      FUN_00416400(0x44b598);
    }
    else {
      FUN_0040b740((int *)&DAT_0044b598);
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044b418);
    if (bVar1) {
      FUN_00416400(0x44b418);
    }
    else {
      FUN_0040b6f0(0x44b418);
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044c800);
    if (bVar1) {
      FUN_00416400(0x44c800);
    }
    else {
      FUN_0040b6f0(0x44c800);
    }
    local_10 = FUN_00423770(0x44dab0);
    local_c = (TwAutoButton *)0x0;
    local_8 = 0;
    bVar1 = IsEmpty(0x44dab0);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      puVar3 = (undefined4 *)FUN_0041be90(&local_10);
      local_c = (TwAutoButton *)*puVar3;
    }
    local_8 = 0;
    while ((uVar4 = FUN_00423620(0x44dab0), local_8 < uVar4 &&
           (bVar1 = IsEmpty(0x44dab0), CONCAT31(extraout_var_00,bVar1) == 0))) {
      cVar2 = (**(code **)(*(int *)local_c + 0x44))();
      if (cVar2 == '\0') {
        TwAutoButton::Up(local_c);
      }
      else {
        TwAutoButton::Down(local_c);
      }
      local_8 = local_8 + 1;
      uVar4 = FUN_00423620(0x44dab0);
      if (local_8 < uVar4) {
        puVar3 = (undefined4 *)FUN_0041be90(&local_10);
        local_c = (TwAutoButton *)*puVar3;
      }
    }
  }
  return;
}



void __fastcall FUN_0041adeb(GAME *param_1)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  undefined4 *puVar3;
  uint uVar4;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  int *piVar5;
  char *pcVar6;
  SECTION *pSVar7;
  char *pcVar8;
  GAME *local_1cc;
  undefined1 local_1c0 [8];
  undefined1 local_1b8 [8];
  CDialog local_1b0 [96];
  int local_150;
  int local_14c;
  int *local_148;
  uint local_144;
  int local_140;
  int local_13c;
  TwDirectXDialog local_138 [284];
  int local_1c;
  TwAutoButton *local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a6dc;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_0040b740((int *)&DAT_0044b200);
  FUN_0040b740((int *)&DAT_0044c5a8);
  FUN_0040b740((int *)&DAT_0044b598);
  FUN_0040b6f0(0x44b418);
  FUN_0040b6f0(0x44c800);
  local_1c = FUN_00423770(0x44dab0);
  local_18 = (TwAutoButton *)0x0;
  local_14 = 0;
  bVar1 = IsEmpty(0x44dab0);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar3 = (undefined4 *)FUN_0041be90(&local_1c);
    local_18 = (TwAutoButton *)*puVar3;
  }
  local_14 = 0;
  while ((uVar4 = FUN_00423620(0x44dab0), local_14 < uVar4 &&
         (bVar1 = IsEmpty(0x44dab0), CONCAT31(extraout_var_00,bVar1) == 0))) {
    TwAutoButton::Up(local_18);
    local_14 = local_14 + 1;
    uVar4 = FUN_00423620(0x44dab0);
    if (local_14 < uVar4) {
      puVar3 = (undefined4 *)FUN_0041be90(&local_1c);
      local_18 = (TwAutoButton *)*puVar3;
    }
  }
  bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044b200);
  if (bVar1) {
    BUTTON::DrawToBack((BUTTON *)&DAT_0044b200);
    GKERNEL::SpriteFlip();
    BUTTON::DrawToBack((BUTTON *)&DAT_0044b200);
    GKERNEL::SpriteFlip();
    GAME::ChangeState(param_1,1);
  }
  else {
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044c5a8);
    if (bVar1) {
      GAME::SetReturnState(param_1,3);
      GAME::ChangeState(param_1,4);
    }
    else {
      bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044b598);
      if (bVar1) {
        BUTTON::DrawToBack((BUTTON *)&DAT_0044b598);
        GKERNEL::SpriteFlip();
        BUTTON::DrawToBack((BUTTON *)&DAT_0044b598);
        GKERNEL::SpriteFlip();
        TwDirectXDialog::EnableFullScreenSupport(true);
        if (param_1 == (GAME *)0x0) {
          local_1cc = (GAME *)0x0;
        }
        else {
          local_1cc = param_1 + 0x34;
        }
        FUN_00405d50(local_138,(undefined4 *)local_1cc,param_1 + 0x5f48,(CWnd *)0x0);
        local_8 = 0;
        TwDirectXDialog::DoModal(local_138);
        TwDirectXDialog::EnableFullScreenSupport(false);
        FUN_0040af39((int)param_1);
        local_8 = 0xffffffff;
        FUN_00405f84((CDialog *)local_138);
      }
      else {
        bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044b418);
        if (bVar1) {
          FUN_0041b4df();
          FUN_0040c710(0x44b418);
          for (local_13c = 0; local_13c < 2; local_13c = local_13c + 1) {
            FUN_0041867d();
            FUN_0041a469();
            GKERNEL::SpriteFlip();
          }
        }
        else {
          bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044c800);
          if (!bVar1) {
            local_14c = FUN_00423770(0x44dab0);
            local_148 = (int *)0x0;
            local_144 = 0;
            bVar1 = IsEmpty(0x44dab0);
            if (CONCAT31(extraout_var_01,bVar1) == 0) {
              puVar3 = (undefined4 *)FUN_0041be90(&local_14c);
              local_148 = (int *)*puVar3;
            }
            local_144 = 0;
            while( true ) {
              uVar4 = FUN_00423620(0x44dab0);
              if (uVar4 <= local_144) {
                ExceptionList = local_10;
                return;
              }
              bVar1 = IsEmpty(0x44dab0);
              if (CONCAT31(extraout_var_02,bVar1) != 0) break;
              cVar2 = (**(code **)(*local_148 + 0x44))();
              if (cVar2 != '\0') {
                FUN_0041a41b(param_1,(int)local_148);
                if (*(char *)(*(int *)(param_1 + 0x38) + 0x1a2) == '\0') {
                  local_150 = 2;
                  if (*(char *)(*(int *)(param_1 + 0x38) + 0x198) != '\0') {
                    TwDirectXDialog::EnableFullScreenSupport(true);
                    piVar5 = (int *)FUN_00405b40(local_1b0,(CWnd *)0x0);
                    local_8 = 1;
                    local_150 = (**(code **)(*piVar5 + 0xc0))();
                    local_8 = 0xffffffff;
                    FUN_00405bd0(local_1b0);
                    TwDirectXDialog::EnableFullScreenSupport(false);
                  }
                  if (local_150 == 1) {
                    if ((param_1[0xe015] == (GAME)0x0) &&
                       (bVar1 = GKERNEL::SupportsWindowedMode(), !bVar1)) {
                      GKERNEL::ErrorMessage(s_Cannot_switch_to_EDIT_MODE__Edit_00435750);
                      ExceptionList = local_10;
                      return;
                    }
                    CMidi::StopAll();
                    CMidi::Disable();
                    CWave::Play((CWave *)&DAT_0044b1c0,0,0,0);
                    pcVar6 = (char *)FUN_00401470((undefined4 *)(*(int *)(param_1 + 0x38) + 0x180));
                    pcVar8 = s_LastPackPlayed_00435814;
                    pSVar7 = (SECTION *)FUN_00408bc0(local_1b8,param_1 + 0xf4,s_Params_0043580c);
                    local_8 = 2;
                    INIFILE::SECTION::Put(pSVar7,pcVar8,pcVar6);
                    local_8 = 0xffffffff;
                    FUN_00407d90((int)local_1b8);
                    FUN_00412195(param_1);
                    GAME::ChangeState(param_1,9);
                    (**(code **)(*(int *)param_1 + 0x20))(1,0,0);
                    ExceptionList = local_10;
                    return;
                  }
                  if (*(char *)(*(int *)(param_1 + 0x38) + 0x1a2) != '\0') {
                    GAME::SetReturnState(param_1,3);
                    GAME::ChangeState(param_1,4);
                    ExceptionList = local_10;
                    return;
                  }
                  pcVar6 = (char *)FUN_00401470((undefined4 *)(*(int *)(param_1 + 0x38) + 0x180));
                  pcVar8 = s_LastPackPlayed_0043582c;
                  pSVar7 = (SECTION *)FUN_00408bc0(local_1c0,param_1 + 0xf4,s_Params_00435824);
                  local_8 = 3;
                  INIFILE::SECTION::Put(pSVar7,pcVar8,pcVar6);
                  local_8 = 0xffffffff;
                  FUN_00407d90((int)local_1c0);
                  if ((*(char *)(*(int *)(param_1 + 0x38) + 0x1a1) != '\0') ||
                     (*(char *)(*(int *)(param_1 + 0x38) + 0x1a3) != '\0')) {
                    CMidi::StopAll();
                    CMidi::Disable();
                  }
                  FUN_00412195(param_1);
                  GAME::ChangeState(param_1,9);
                  ExceptionList = local_10;
                  return;
                }
                GAME::SetReturnState(param_1,3);
                GAME::ChangeState(param_1,4);
              }
              local_144 = local_144 + 1;
              uVar4 = FUN_00423620(0x44dab0);
              if (local_144 < uVar4) {
                puVar3 = (undefined4 *)FUN_0041be90(&local_14c);
                local_148 = (int *)*puVar3;
              }
            }
            ExceptionList = local_10;
            return;
          }
          FUN_0041b5bf();
          FUN_0040c710(0x44c800);
          for (local_140 = 0; local_140 < 2; local_140 = local_140 + 1) {
            FUN_0041867d();
            FUN_0041a469();
            GKERNEL::SpriteFlip();
          }
        }
      }
    }
  }
  ExceptionList = local_10;
  return;
}



void FUN_0041b4df(void)

{
  bool bVar1;
  undefined3 extraout_var;
  int *piVar2;
  uint uVar3;
  undefined3 extraout_var_00;
  int local_10;
  int local_c;
  uint local_8;
  
  if (DAT_0044dacc != 0) {
    if (DAT_0044dacc != 0) {
      DAT_0044dacc = DAT_0044dacc + -1;
      local_10 = FUN_00423770(0x44dab0);
      local_c = 0;
      local_8 = 0;
      bVar1 = IsEmpty(0x44dab0);
      if (CONCAT31(extraout_var,bVar1) == 0) {
        piVar2 = (int *)FUN_0041be90(&local_10);
        local_c = *piVar2;
      }
      local_8 = 0;
      while ((uVar3 = FUN_00423620(0x44dab0), local_8 < uVar3 &&
             (bVar1 = IsEmpty(0x44dab0), CONCAT31(extraout_var_00,bVar1) == 0))) {
        FUN_0040b710(local_c);
        local_8 = local_8 + 1;
        uVar3 = FUN_00423620(0x44dab0);
        if (local_8 < uVar3) {
          piVar2 = (int *)FUN_0041be90(&local_10);
          local_c = *piVar2;
        }
      }
    }
    FUN_0040b710(0x44c800);
  }
  return;
}



void FUN_0041b5bf(void)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  undefined3 extraout_var;
  int *piVar4;
  undefined3 extraout_var_00;
  int iVar5;
  uint uVar6;
  int local_10;
  int local_c;
  uint local_8;
  
  uVar6 = 3;
  uVar2 = FUN_00423620(0x44dab0);
  uVar2 = FUN_0041bf20(uVar2,uVar6);
  iVar5 = DAT_0044dacc + uVar2;
  iVar3 = FUN_00423620(0x44dab0);
  if (iVar5 != iVar3) {
    uVar6 = 3;
    uVar2 = FUN_00423620(0x44dab0);
    uVar2 = FUN_0041bf20(uVar2,uVar6);
    uVar2 = DAT_0044dacc + uVar2;
    iVar3 = FUN_00423620(0x44dab0);
    if (uVar2 < iVar3 + 1U) {
      DAT_0044dacc = DAT_0044dacc + 1;
      local_10 = FUN_00423770(0x44dab0);
      local_c = 0;
      local_8 = 0;
      bVar1 = IsEmpty(0x44dab0);
      if (CONCAT31(extraout_var,bVar1) == 0) {
        piVar4 = (int *)FUN_0041be90(&local_10);
        local_c = *piVar4;
      }
      local_8 = 0;
      while ((uVar2 = FUN_00423620(0x44dab0), local_8 < uVar2 &&
             (bVar1 = IsEmpty(0x44dab0), CONCAT31(extraout_var_00,bVar1) == 0))) {
        FUN_0040b710(local_c);
        local_8 = local_8 + 1;
        uVar2 = FUN_00423620(0x44dab0);
        if (local_8 < uVar2) {
          piVar4 = (int *)FUN_0041be90(&local_10);
          local_c = *piVar4;
        }
      }
    }
    FUN_0040b710(0x44b418);
  }
  return;
}



void __thiscall FUN_0041b6e8(void *this,int param_1)

{
  if (param_1 == 0x1b) {
    GAME::ChangeState((GAME *)this,1);
  }
  return;
}



void __fastcall FUN_0041b706(GAME *param_1)

{
  undefined1 uVar1;
  bool bVar2;
  CString *pCVar3;
  undefined4 *puVar4;
  char *pcVar5;
  SPRITE *this;
  uint uVar6;
  int iVar7;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  HWND__ *hWnd;
  UINT Msg;
  WPARAM wParam;
  LPARAM lParam;
  undefined4 local_b4;
  CString local_8c [4];
  CString local_88 [4];
  tagPOINT local_84;
  undefined1 local_7c [8];
  uint local_74;
  uint local_70;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_0042a70c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_0040af39((int)param_1);
  pCVar3 = FUN_004014f0(local_88);
  local_8 = 0;
  puVar4 = (undefined4 *)operator+(local_8c,(char *)pCVar3);
  local_8._0_1_ = 1;
  pcVar5 = (char *)FUN_00401470(puVar4);
  CMidi::LoadSong((CMidi *)(param_1 + 0x5f48),pcVar5);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(local_8c);
  local_8 = 0xffffffff;
  CString::~CString(local_88);
  DD_SURFACE::Desc((DD_SURFACE *)&this_0044b380,(ulong)local_7c);
  if (*(int *)(param_1 + 0xe00c) == 0) {
    this = (SPRITE *)operator_new(0x112c);
    local_8 = 2;
    if (this == (SPRITE *)0x0) {
      local_b4 = 0;
    }
    else {
      local_b4 = SPRITE::SPRITE(this);
    }
    local_8 = 0xffffffff;
    *(undefined4 *)(param_1 + 0xe00c) = local_b4;
    SPRITE::Init(*(SPRITE **)(param_1 + 0xe00c),(DD_SURFACE *)&this_0044b380,true,local_70 >> 5,
                 local_74 >> 5,local_70 * local_74 >> 10);
    FUN_00405850(&local_84);
    uVar6 = GKERNEL::GetCursorPos(&local_84);
    if ((uVar6 & 0xff) != 0) {
      (**(code **)(**(int **)(param_1 + 0xe00c) + 0x28))(&local_84);
    }
  }
  else {
    SPRITE::ResetSurfaceInfo
              (*(SPRITE **)(param_1 + 0xe00c),(DD_SURFACE *)&this_0044b380,true,local_70 >> 5,
               local_74 >> 5,local_70 * local_74 >> 10);
  }
  (**(code **)(**(int **)(param_1 + 0xe00c) + 0x70))(0xcc);
  if (*(undefined4 **)(param_1 + 0x129b4) != (undefined4 *)0x0) {
    (**(code **)**(undefined4 **)(param_1 + 0x129b4))(1);
  }
  *(undefined4 *)(param_1 + 0x129b4) = 0;
  *(undefined4 *)(param_1 + 0xe1a0) = 0xffffffff;
  iVar7 = FUN_004056c0((int)param_1);
  if (((iVar7 == 9) && (uVar1 = FUN_00414141((int)param_1), CONCAT31(extraout_var,uVar1) == 0)) &&
     (bVar2 = FUN_00401430((int *)(*(int *)(param_1 + 0x38) + 0x194)),
     CONCAT31(extraout_var_00,bVar2) == 0)) {
    GAME::SetReturnState(param_1,3);
    GAME::ChangeState(param_1,4);
  }
  else {
    FUN_0041a7ba();
    bVar2 = FUN_0040e0e0((int)param_1);
    if (bVar2) {
      lParam = 0;
      wParam = 0;
      Msg = 0x401;
      hWnd = GKERNEL::GetHwnd();
      PostMessageA(hWnd,Msg,wParam,lParam);
    }
    iVar7 = FUN_004056c0((int)param_1);
    if (iVar7 != 1) {
      CMidi::Play((CMidi *)(param_1 + 0x5f48),1,0,0,0);
    }
    SPRITE::Show((SPRITE *)&DAT_0044c980);
    SPRITE::SetCurrentImage((SPRITE *)&DAT_0044c980,0);
    SPRITE::Show((SPRITE *)&DAT_0044a090);
    SPRITE::SetCurrentImage((SPRITE *)&DAT_0044a090,0);
  }
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_0041ba7b(void *this,int param_1)

{
  uint uVar1;
  uint uVar2;
  void *this_00;
  undefined1 *puVar3;
  int *piVar4;
  undefined1 local_14 [8];
  int local_c [2];
  
  SPRITE::Hide((SPRITE *)&DAT_0044c980);
  SPRITE::Hide((SPRITE *)&DAT_0044a090);
  if (param_1 == 1) {
    uVar1 = FUN_004132c0((int)this + 0x38b8);
    uVar1 = uVar1 >> 1;
    uVar2 = FUN_004132a0((int)this + 0x38b8);
    default_error_condition(local_c,uVar2 >> 1,uVar1);
    piVar4 = local_c;
    puVar3 = local_14;
    this_00 = (void *)OVERLAY::Position((OVERLAY *)((int)this + 0x38b8));
    FUN_0040dff0(this_00,puVar3,piVar4);
    puVar3 = local_14;
    (**(code **)(**(int **)((int)this + 0xe00c) + 0x28))();
    GKERNEL::SetCursorPos((int)local_14,(int)puVar3);
    FUN_0041867d();
    GKERNEL::SpriteFlip();
    FUN_0041867d();
    GKERNEL::SpriteFlip();
    GKERNEL::NewSpriteBackground();
  }
  else {
    CMidi::Stop((CMidi *)((int)this + 0x5f48));
  }
  return;
}



void __fastcall FUN_0041bb60(TwLightning *param_1)

{
  TwLightning::~TwLightning(param_1);
  return;
}



TwLightning * __fastcall FUN_0041bb80(TwLightning *param_1)

{
  TwLightning::TwLightning(param_1);
  *(undefined ***)param_1 = &PTR_FUN_0042db34;
  *(undefined ***)(param_1 + 8) = &PTR_FUN_0042db30;
  return param_1;
}



void FUN_0041bbb0(void)

{
  CWave::Play((CWave *)&DAT_0044b718,0,0,0);
  return;
}



void * __thiscall FUN_0041bbd0(void *this,uint param_1)

{
  FUN_0041bb60((TwLightning *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_0041bc00(undefined4 *param_1)

{
  FUN_0041bec0(param_1);
  return;
}



void __thiscall FUN_0041bc20(void *this,char *param_1)

{
                    // WARNING: Load size is inaccurate
  _stricmp(*this,param_1);
  return;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_0041bd50(this,10);
  *(undefined ***)this = &PTR_LAB_0042db84;
  return this;
}



void * __thiscall FUN_0041bc70(void *this,undefined4 *param_1)

{
  FUN_0041bdb0(this,param_1);
  return this;
}



void __thiscall FUN_0041bc90(void *this,uint param_1,uint param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  bool bVar3;
  undefined3 extraout_var;
  uint uVar4;
  undefined4 *puVar5;
  
  bVar3 = IsEmpty((int)this);
  if (((CONCAT31(extraout_var,bVar3) == 0) && (uVar4 = FUN_00423620((int)this), param_1 < uVar4)) &&
     (uVar4 = FUN_00423620((int)this), param_2 < uVar4)) {
    puVar5 = (undefined4 *)FUN_00407f60(this,param_1);
    uVar1 = *puVar5;
    puVar5 = (undefined4 *)FUN_00407f60(this,param_2);
    uVar2 = *puVar5;
    puVar5 = (undefined4 *)FUN_00407f60(this,param_1);
    *puVar5 = uVar2;
    puVar5 = (undefined4 *)FUN_00407f60(this,param_2);
    *puVar5 = uVar1;
  }
  return;
}



void * __thiscall FUN_0041bd20(void *this,uint param_1)

{
  FUN_0041bc00((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void * __thiscall FUN_0041bd50(void *this,undefined4 param_1)

{
  FUN_00404b20((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_0042db98;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



undefined4 * __thiscall FUN_0041bdb0(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_0040c480(this,*(undefined4 *)((int)this + 8),0);
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



void __fastcall FUN_0041be10(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_0041bf80(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



int FUN_0041be90(int *param_1)

{
  int *piVar1;
  
  piVar1 = (int *)*param_1;
  *param_1 = *piVar1;
  return (int)(piVar1 + 2);
}



void __fastcall FUN_0041bec0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0042a729;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_0042db98;
  local_8 = 0;
  FUN_0041be10((int)param_1);
  local_8 = 0xffffffff;
  FUN_00404b70(param_1);
  ExceptionList = local_10;
  return;
}



uint __cdecl FUN_0041bf20(uint param_1,uint param_2)

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



void * __thiscall FUN_0041bf50(void *this,uint param_1)

{
  FUN_0041bec0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void FUN_0041bf80(undefined4 param_1,int param_2)

{
  bool bVar1;
  
  do {
    bVar1 = param_2 != 0;
    param_2 = param_2 + -1;
  } while (bVar1);
  return;
}



void FUN_0041bfb0(void *param_1,int param_2)

{
  memset(param_1,0,param_2 << 2);
  while (param_2 != 0) {
    FUN_00405640(4,param_1);
    param_1 = (void *)((int)param_1 + 4);
    param_2 = param_2 + -1;
  }
  return;
}



void * __thiscall FUN_0041c000(void *this)

{
  char *pcVar1;
  CString *pCVar2;
  undefined1 in_stack_00000018;
  undefined4 in_stack_0000001c;
  undefined1 in_stack_00000020;
  undefined1 in_stack_00000024;
  undefined1 in_stack_00000028;
  undefined1 in_stack_0000002c;
  CString local_28 [4];
  CString local_24 [4];
  CString local_20 [4];
  CString local_1c [4];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &this_0042a815;
  local_10 = ExceptionList;
  local_8 = 4;
  ExceptionList = &local_10;
  FUN_0040d6a0((OVERLAY *)this);
  local_8._0_1_ = 5;
  CString::CString((CString *)((int)this + 0x17c));
  local_8._0_1_ = 6;
  CString::CString((CString *)((int)this + 0x180));
  local_8._0_1_ = 7;
  CString::CString((CString *)((int)this + 0x184));
  local_8._0_1_ = 8;
  CString::CString((CString *)((int)this + 0x188));
  local_8._0_1_ = 9;
  CString::CString((CString *)((int)this + 0x18c));
  local_8._0_1_ = 10;
  CString::CString((CString *)((int)this + 400));
  local_8._0_1_ = 0xb;
  CString::CString((CString *)((int)this + 0x194));
  local_8._0_1_ = 0xc;
  *(undefined ***)this = &PTR_FUN_0042dbb0;
  *(undefined ***)((int)this + 8) = &PTR_FUN_0042dbac;
  CString::operator=((CString *)((int)this + 0x180),(CString *)&stack0x00000004);
  pcVar1 = (char *)operator+(local_14,(CString *)&stack0x00000004);
  local_8._0_1_ = 0xd;
  pCVar2 = (CString *)operator+(local_18,pcVar1);
  local_8._0_1_ = 0xe;
  CString::operator=((CString *)((int)this + 0x184),pCVar2);
  local_8._0_1_ = 0xd;
  CString::~CString(local_18);
  local_8._0_1_ = 0xc;
  CString::~CString(local_14);
  pcVar1 = (char *)operator+(local_1c,(CString *)&stack0x00000004);
  local_8._0_1_ = 0xf;
  pCVar2 = (CString *)operator+(local_20,pcVar1);
  local_8._0_1_ = 0x10;
  CString::operator=((CString *)((int)this + 0x188),pCVar2);
  local_8._0_1_ = 0xf;
  CString::~CString(local_20);
  local_8._0_1_ = 0xc;
  CString::~CString(local_1c);
  CString::operator=((CString *)((int)this + 400),(CString *)&stack0x00000010);
  pCVar2 = (CString *)operator+(local_24,&stack0x00000004);
  local_8._0_1_ = 0x11;
  CString::operator=((CString *)((int)this + 0x17c),pCVar2);
  local_8._0_1_ = 0xc;
  CString::~CString(local_24);
  CString::operator=((CString *)((int)this + 0x194),(CString *)&stack0x00000014);
  *(undefined1 *)((int)this + 0x1a3) = in_stack_0000002c;
  pCVar2 = (CString *)operator+((char *)local_28,(CString *)s_RELEASE__00435854);
  local_8._0_1_ = 0x12;
  CString::operator=((CString *)((int)this + 400),pCVar2);
  local_8._0_1_ = 0xc;
  CString::~CString(local_28);
  *(undefined4 *)((int)this + 0x19c) = in_stack_0000001c;
  *(undefined1 *)((int)this + 0x198) = in_stack_00000018;
  *(undefined1 *)((int)this + 0x1a2) = in_stack_00000028;
  *(undefined1 *)((int)this + 0x1a0) = in_stack_00000020;
  *(undefined1 *)((int)this + 0x1a1) = in_stack_00000024;
  local_8._0_1_ = 3;
  CString::~CString((CString *)&stack0x00000004);
  local_8._0_1_ = 2;
  CString::~CString((CString *)&stack0x00000008);
  local_8._0_1_ = 1;
  CString::~CString((CString *)&stack0x0000000c);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString((CString *)&stack0x00000010);
  local_8 = 0xffffffff;
  CString::~CString((CString *)&stack0x00000014);
  ExceptionList = local_10;
  return this;
}



void __fastcall FUN_0041c2e0(int *param_1)

{
  bool bVar1;
  char *pcVar2;
  CString *pCVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  CString local_1c [4];
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_0042a83b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  operator+(local_14,(char *)(param_1 + 0x60));
  local_8 = 0;
  pcVar2 = (char *)FUN_00401470((undefined4 *)local_14);
  bVar1 = exists(pcVar2);
  if (!bVar1) {
    pCVar3 = FUN_004014f0(local_18);
    local_8._0_1_ = 1;
    pCVar3 = (CString *)operator+(local_1c,(char *)pCVar3);
    local_8._0_1_ = 2;
    CString::operator=(local_14,pCVar3);
    local_8._0_1_ = 1;
    CString::~CString(local_1c);
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_18);
  }
  uVar5 = 0;
  uVar4 = FUN_00401470((undefined4 *)local_14);
  (**(code **)(*param_1 + 0x3c))(uVar4,uVar5);
  local_8 = 0xffffffff;
  CString::~CString(local_14);
  ExceptionList = local_10;
  return;
}



bool __thiscall FUN_0041c3d0(void *this,int param_1)

{
  return *(uint *)(param_1 + 0x19c) < *(uint *)((int)this + 0x19c);
}



void * __thiscall FUN_0041c400(void *this,uint param_1)

{
  FUN_0041c430((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_0041c430(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &this_0042a8b3;
  local_10 = ExceptionList;
  local_8 = 6;
  ExceptionList = &local_10;
  CString::~CString((CString *)(param_1 + 0x65));
  local_8._0_1_ = 5;
  CString::~CString((CString *)(param_1 + 100));
  local_8._0_1_ = 4;
  CString::~CString((CString *)(param_1 + 99));
  local_8._0_1_ = 3;
  CString::~CString((CString *)(param_1 + 0x62));
  local_8._0_1_ = 2;
  CString::~CString((CString *)(param_1 + 0x61));
  local_8._0_1_ = 1;
  CString::~CString((CString *)(param_1 + 0x60));
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString((CString *)(param_1 + 0x5f));
  local_8 = 0xffffffff;
  FUN_0040c900(param_1);
  ExceptionList = local_10;
  return;
}



void * __cdecl FUN_0041c4f0(undefined4 param_1,CString *param_2)

{
  bool bVar1;
  CString *pCVar2;
  LPCSTR lpLibFileName;
  void *this;
  void *local_54;
  CString local_30 [4];
  CString local_2c [4];
  int local_28;
  void *local_24;
  FARPROC local_20;
  CString local_1c [4];
  HMODULE local_18;
  FARPROC local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_0042a8e6;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(local_1c,param_2);
  local_8 = 0;
  bVar1 = IsRelativePath(local_1c);
  if (bVar1) {
    pCVar2 = (CString *)REG::RootDir();
    local_8._0_1_ = 1;
    pCVar2 = (CString *)operator+(local_30,pCVar2);
    local_8._0_1_ = 2;
    CString::operator=(local_1c,pCVar2);
    local_8._0_1_ = 1;
    CString::~CString(local_30);
    local_8 = (uint)local_8._1_3_ << 8;
    CString::~CString(local_2c);
  }
  lpLibFileName = (LPCSTR)FUN_00401470((undefined4 *)local_1c);
  local_18 = LoadLibraryA(lpLibFileName);
  local_14 = GetProcAddress(local_18,s__Create__YAPAVSELECT_SKILL1__PAV_004358e0);
  if (local_14 == (FARPROC)0x0) {
    local_20 = GetProcAddress(local_18,s__Create__YAPAVSELECT_SKILL__PAVG_004358b8);
    local_28 = (*local_20)(param_1);
    this = operator_new(8);
    local_8 = CONCAT31(local_8._1_3_,3);
    if (this == (void *)0x0) {
      local_54 = (void *)0x0;
    }
    else {
      local_54 = FUN_0041c670(this,local_28);
    }
    local_24 = local_54;
    local_8 = 0xffffffff;
    CString::~CString(local_1c);
  }
  else {
    local_54 = (void *)(*local_14)(param_1);
    local_8 = 0xffffffff;
    CString::~CString(local_1c);
  }
  ExceptionList = local_10;
  return local_54;
}



void * __thiscall FUN_0041c670(void *this,undefined4 param_1)

{
  FUN_0041c850((undefined4 *)this);
  *(undefined4 *)((int)this + 4) = param_1;
  *(undefined ***)this = &PTR_FUN_0042dc08;
  return this;
}



void __fastcall FUN_0041c6a0(int param_1)

{
  (**(code **)(**(int **)(param_1 + 4) + 4))();
  return;
}



void __fastcall FUN_0041c6c0(int param_1)

{
  (**(code **)(**(int **)(param_1 + 4) + 8))();
  return;
}



void __fastcall FUN_0041c6e0(int param_1)

{
  (**(code **)(**(int **)(param_1 + 4) + 0xc))();
  return;
}



void __thiscall FUN_0041c700(void *this,undefined1 param_1)

{
  (**(code **)(**(int **)((int)this + 4) + 0x10))(param_1);
  return;
}



void __fastcall FUN_0041c730(int param_1)

{
  (**(code **)(**(int **)(param_1 + 4) + 0x14))();
  return;
}



void __fastcall FUN_0041c750(int param_1)

{
  (**(code **)(**(int **)(param_1 + 4) + 0x18))();
  return;
}



void FUN_0041c770(undefined4 *param_1,undefined4 *param_2)

{
  *param_1 = 0xa7;
  *param_2 = 7;
  return;
}



undefined1 FUN_0041c790(void)

{
  return 0;
}



void * __thiscall FUN_0041c7a0(void *this,uint param_1)

{
  FUN_0041c7d0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_0041c7d0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0042a8f9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_FUN_0042dc08;
  local_8 = 0;
  if ((undefined4 *)param_1[1] != (undefined4 *)0x0) {
    (*(code *)**(undefined4 **)param_1[1])(1);
  }
  local_8 = 0xffffffff;
  FUN_0041c8e0(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_0041c850(undefined4 *param_1)

{
  FUN_0041c870(param_1);
  *param_1 = &PTR_FUN_0042dc2c;
  return param_1;
}



undefined4 * __fastcall FUN_0041c870(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_0042dc50;
  return param_1;
}



void * __thiscall FUN_0041c890(void *this,uint param_1)

{
  FUN_0041c8c0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_0041c8c0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_0042dc50;
  return;
}



void __fastcall FUN_0041c8e0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_0042dc2c;
  FUN_0041c8c0(param_1);
  return;
}



void * __thiscall FUN_0041c900(void *this,uint param_1)

{
  FUN_0041c8e0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_0041c930(int param_1)

{
  FUN_0040b6f0(param_1 + 0x38b8);
  FUN_0040b6f0(param_1 + 0x3a34);
  (**(code **)(*(int *)(param_1 + 0x6498) + 0x14))();
  GKERNEL::SpriteFlip();
  (**(code **)(*(int *)(param_1 + 0x6498) + 0x14))();
  GKERNEL::SpriteFlip();
  return;
}



void __thiscall FUN_0041c98d(void *this,undefined4 param_1,int param_2)

{
  int iVar1;
  
  iVar1 = FUN_004213b1((int)this);
  if (iVar1 != 0) {
    FUN_004212be((int)this);
  }
  switch(param_1) {
  case 2:
  case 0xd:
    if ((param_2 != 0xd) && (param_2 != 2)) {
      if (param_2 != 4) {
        CMidi::Stop((CMidi *)((int)this + 0x61f0));
      }
      FUN_0041d6d7(this);
    }
    break;
  case 3:
    FUN_0041ba7b(this,param_2);
    break;
  case 4:
    if ((param_2 != 2) && (param_2 != 0xd)) {
      CMidi::StopAll();
    }
    break;
  case 5:
    CMidi::ReadyThisObjectForPlay((CMidi *)((int)this + 0x5f48));
    break;
  case 6:
    FUN_00414038(this,0xcc,(int *)0x0);
    if (param_2 != 0xc) {
      MAP::DestroyMovingObjects((MAP *)((int)this + 0xe23c));
    }
    if (*(int *)((int)this + 0xe018) != 0) {
      if (*(undefined4 **)((int)this + 0xe018) != (undefined4 *)0x0) {
        (**(code **)**(undefined4 **)((int)this + 0xe018))(1);
      }
      *(undefined4 *)((int)this + 0xe018) = 0;
    }
    FUN_0040b6f0((int)this + 0x3444);
    FUN_0040b6f0((int)this + 0x35c0);
    FUN_0040b6f0((int)this + 0x373c);
    CMidi::Stop((CMidi *)((int)this + 0x609c));
    break;
  case 9:
    if (*(int *)((int)this + 0x129b4) != 0) {
      (**(code **)(**(int **)((int)this + 0x129b4) + 8))();
    }
    if (param_2 == 3) {
      CMidi::ReadyThisObjectForPlay((CMidi *)((int)this + 0x5f48));
    }
    break;
  case 0xb:
    (**(code **)(*(int *)((int)this + 0xbdb4) + 0x20))();
    (**(code **)(*(int *)((int)this + 0xcee0) + 0x20))();
    (**(code **)(*(int *)((int)this + 0x67d8) + 0x20))();
    (**(code **)(*(int *)((int)this + 0x7904) + 0x20))();
    (**(code **)(*(int *)((int)this + 0x8a30) + 0x20))();
    (**(code **)(*(int *)((int)this + 0x9b5c) + 0x20))();
    (**(code **)(*(int *)((int)this + 0xac88) + 0x20))();
    if ((param_2 != 2) && (param_2 != 0xd)) {
      CMidi::Stop((CMidi *)((int)this + 0x61f0));
    }
    break;
  case 0xc:
    CMidi::Stop((CMidi *)((int)this + 0x6344));
    MAP::DestroyMovingObjects((MAP *)((int)this + 0xe23c));
  }
  return;
}



void __thiscall FUN_0041cc20(void *this,int param_1)

{
  undefined1 uVar1;
  bool bVar2;
  undefined3 extraout_var;
  int iVar3;
  int *piVar4;
  undefined1 *this_00;
  undefined4 *puVar5;
  uint uVar6;
  char *pcVar7;
  char cVar8;
  undefined1 *puVar9;
  CString local_38 [4];
  undefined4 local_34 [2];
  undefined1 *local_2c;
  undefined1 local_28 [8];
  undefined1 local_20 [8];
  undefined4 local_18 [2];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a919;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  uVar1 = FUN_00414141((int)this);
  if (CONCAT31(extraout_var,uVar1) != 0) {
    FUN_00414176((int)this);
  }
  FUN_004132e0(this,param_1);
  bVar2 = FUN_0040e0e0((int)this);
  if (bVar2) {
    FUN_0040f2b0(this,param_1);
  }
  iVar3 = FUN_004213b1((int)this);
  if (iVar3 != 0) {
    FUN_00421303(this,param_1);
  }
  switch(param_1) {
  case 1:
    FUN_0041c930((int)this);
    break;
  case 2:
  case 0xd:
    (**(code **)(*(int *)((int)this + 0x228) + 0x20))();
    FUN_0040b710((int)this + 0x2a7c);
    FUN_0041db21(this,param_1 == 0xd,'\x01');
    *(undefined4 *)((int)this + 0x129b8) = 0;
    iVar3 = FUN_004056c0((int)this);
    if ((((iVar3 != 2) && (iVar3 = FUN_004056c0((int)this), iVar3 != 0xd)) &&
        (iVar3 = FUN_004056c0((int)this), iVar3 != 4)) &&
       ((iVar3 = FUN_004056c0((int)this), iVar3 != 0xb || (*(int *)((int)this + 0x130) == 0)))) {
      CMidi::Play((CMidi *)((int)this + 0x61f0),1,0,0xc,0x10);
    }
    break;
  case 3:
    FUN_0041b706((GAME *)this);
    break;
  case 4:
    iVar3 = FUN_004056c0((int)this);
    if ((iVar3 != 2) && (iVar3 = FUN_004056c0((int)this), iVar3 != 0xd)) {
      CMidi::StopAll();
      CMidi::Play((CMidi *)((int)this + 0x61f0),1,1000,0,0x10);
    }
    FUN_0040d19b((int)this);
    break;
  case 5:
    GAME::SetReturnState((GAME *)this,3);
    break;
  case 6:
    FUN_00426d40((int)this);
    bVar2 = FUN_0040e0e0((int)this);
    if (!bVar2) {
      GKERNEL::ResetFrameCounter();
      MAP::CreateMovingObjects((MAP *)((int)this + 0xe23c));
    }
    MAP::RefreshBothLevelmapBuffers((MAP *)((int)this + 0xe23c));
    iVar3 = 0x20;
    this_00 = local_28;
    puVar9 = this_00;
    FUN_00413eee(this,local_20);
    puVar5 = (undefined4 *)FUN_0040fe80(this_00,puVar9,iVar3);
    FUN_0040f6ea(this,puVar5);
    iVar3 = MAP::HasScript((MAP *)((int)this + 0xe23c));
    if ((iVar3 != 0) && (bVar2 = FUN_0040e0e0((int)this), !bVar2)) {
      FUN_0041f49d((int)this);
    }
    FUN_0040b6f0((int)this + 0x307c);
    FUN_0040b6f0((int)this + 0x31f8);
    FUN_0040b740((int *)((int)this + 0x277c));
    FUN_0040b740((int *)((int)this + 0x28fc));
    FUN_0040b740((int *)((int)this + 0x25fc));
    FUN_0040b740((int *)((int)this + 0x2d7c));
    FUN_0040b740((int *)((int)this + 0x2efc));
    CMidi::UnInit((CMidi *)((int)this + 0x609c));
    CMidi::Init((CMidi *)((int)this + 0x609c));
    CMidi::ReadyThisObjectForPlay((CMidi *)((int)this + 0x61f0));
    piVar4 = FUN_00405910((void *)((int)this + 0xe23c),local_34);
    uVar6 = FUN_004058f0(piVar4);
    local_2c = &stack0xffffffb0;
    FUN_0041d419((CString *)&stack0xffffffb0,uVar6);
                    // WARNING: Load size is inaccurate
    puVar5 = (undefined4 *)(**(code **)(*this + 0x58))(local_38);
    local_8 = 0;
    pcVar7 = (char *)FUN_00401470(puVar5);
    CMidi::LoadSong((CMidi *)((int)this + 0x609c),pcVar7);
    local_8 = 0xffffffff;
    CString::~CString(local_38);
    CMidi::Play((CMidi *)((int)this + 0x609c),1,0,0,0);
    break;
  case 7:
    iVar3 = FUN_004056c0((int)this);
    if (iVar3 != 7) {
      FUN_00417f6e((int *)this);
      FUN_00414038(this,0xcc,(int *)0x0);
    }
    break;
  case 9:
    if (*(char *)(*(int *)((int)this + 0x38) + 0x1a0) == '\0') {
      iVar3 = FUN_004056c0((int)this);
      if ((iVar3 == 2) || (iVar3 = FUN_004056c0((int)this), iVar3 == 0xd)) {
        GAME::ChangeState((GAME *)this,3);
      }
      else {
                    // WARNING: Load size is inaccurate
        (**(code **)(*this + 0x50))();
        GAME::ChangeState((GAME *)this,2);
      }
    }
    else {
      (**(code **)(**(int **)((int)this + 0x129b4) + 0xc))();
    }
    break;
  case 10:
    FUN_00417f6e((int *)this);
    FUN_0040b710((int)this + 0x277c);
    MAP::RefreshBothLevelmapBuffers((MAP *)((int)this + 0xe23c));
    break;
  case 0xb:
    (**(code **)(*(int *)((int)this + 0x228) + 0x20))();
    *(undefined4 *)((int)this + 0x130) = 0;
    CWave::Play((CWave *)((int)this + 0x5ec8),0,0,0);
    CMidi::Play((CMidi *)((int)this + 0x61f0),1,0x4e2,0,0x10);
    (**(code **)(*(int *)((int)this + 0xbdb4) + 0x1c))();
    (**(code **)(*(int *)((int)this + 0xbdb4) + 0x10))();
    (**(code **)(*(int *)((int)this + 0xbdb4) + 0x2c))(0x280);
    (**(code **)(*(int *)((int)this + 0xbdb4) + 0x6c))(0x133,0x1a0,0x4e2);
    (**(code **)(*(int *)((int)this + 0xcee0) + 0x1c))();
    (**(code **)(*(int *)((int)this + 0xcee0) + 0x10))();
    (**(code **)(*(int *)((int)this + 0xcee0) + 0x2c))(0xfffffeb5,0x1a0);
    (**(code **)(*(int *)((int)this + 0xcee0) + 0x6c))(2,0x1a0,0x4e2);
    (**(code **)(*(int *)((int)this + 0x67d8) + 0x1c))();
    (**(code **)(*(int *)((int)this + 0x67d8) + 0x10))();
    (**(code **)(*(int *)((int)this + 0x67d8) + 0x2c))(0xfffffec0,0x1af);
    (**(code **)(*(int *)((int)this + 0x67d8) + 0x6c))(200,0x1af,800);
    (**(code **)(*(int *)((int)this + 0x7904) + 0x1c))();
    (**(code **)(*(int *)((int)this + 0x7904) + 0x10))();
    (**(code **)(*(int *)((int)this + 0x7904) + 0x2c))(0xfffffec0,0x1c3);
    (**(code **)(*(int *)((int)this + 0x7904) + 0x6c))(100,0x1c3,500);
    (**(code **)(*(int *)((int)this + 0x8a30) + 0x1c))();
    (**(code **)(*(int *)((int)this + 0x8a30) + 0x10))();
    (**(code **)(*(int *)((int)this + 0x8a30) + 0x2c))(0xfffffec0,0x1d1);
    (**(code **)(*(int *)((int)this + 0x8a30) + 0x6c))(0x96,0x1d1,600);
    (**(code **)(*(int *)((int)this + 0x9b5c) + 0x1c))();
    (**(code **)(*(int *)((int)this + 0x9b5c) + 0x10))();
    (**(code **)(*(int *)((int)this + 0x9b5c) + 0x2c))(0x280,0x1b9);
    (**(code **)(*(int *)((int)this + 0x9b5c) + 0x6c))(300,0x1b9,800);
    (**(code **)(*(int *)((int)this + 0xac88) + 0x1c))();
    (**(code **)(*(int *)((int)this + 0xac88) + 0x10))();
    (**(code **)(*(int *)((int)this + 0xac88) + 0x2c))(0x280,0x1cd);
    (**(code **)(*(int *)((int)this + 0xac88) + 0x6c))(0x163,0x1cd,400);
    FUN_0040b710((int)this + 0x2bfc);
    FUN_0040b710((int)this + 0xe024);
    cVar8 = '\x01';
    piVar4 = FUN_00405910((void *)((int)this + 0xe23c),local_18);
    iVar3 = FUN_004058f0(piVar4);
    FUN_00411531(this,iVar3,cVar8);
    break;
  case 0xc:
    CMidi::Play((CMidi *)((int)this + 0x6344),1,0,0,0);
    FUN_0041809c((int *)this);
  }
  ExceptionList = local_10;
  return;
}



CString * __cdecl FUN_0041d419(CString *param_1,uint param_2)

{
  switch(param_2 % 6) {
  case 0:
    CString::CString(param_1,s_oceanwaves_rmi_0043590c);
    break;
  case 1:
    CString::CString(param_1,s_electricangels_rmi_0043591c);
    break;
  case 2:
    CString::CString(param_1,s_duetta_rmi_00435930);
    break;
  case 3:
    CString::CString(param_1,s_lowncool_rmi_0043593c);
    break;
  case 4:
    CString::CString(param_1,s_guitaria_rmi_0043594c);
    break;
  case 5:
    CString::CString(param_1,s_foreigner_rmi_0043595c);
    break;
  default:
    CString::CString(param_1,s_invalidsong_rmi_0043596c);
  }
  return param_1;
}



void FUN_0041d530(void)

{
  FUN_0041d53f();
  FUN_0041d54f();
  return;
}



void FUN_0041d53f(void)

{
  OVERLAY::OVERLAY((OVERLAY *)&DAT_0044db28);
  return;
}



void FUN_0041d54f(void)

{
  FUN_00427dae(FUN_0041d561);
  return;
}



void FUN_0041d561(void)

{
  FUN_0040c7b0((undefined4 *)&DAT_0044db28);
  return;
}



void __fastcall FUN_0041d570(void *param_1)

{
  int iVar1;
  char cVar2;
  
  cVar2 = '\x01';
  iVar1 = FUN_004056c0((int)param_1);
  FUN_0041db21(param_1,iVar1 == 0xd,cVar2);
  *(undefined4 *)((int)param_1 + 0x129b8) = 0;
  return;
}



void __fastcall FUN_0041d5a3(int param_1)

{
  int iVar1;
  int local_1c;
  int local_18;
  int local_14;
  int local_10;
  int local_c;
  int local_8;
  
  if (DAT_0044dbf8 != 0) {
    FUN_00414240(&local_1c,0xa0,0x60,0x220,0x120);
    FUN_00413daa(local_1c,local_18,local_14,local_10,0xffff00);
    iVar1 = FUN_004132a0(param_1 + 0x2480);
    local_8 = (local_14 - iVar1) + -10;
    iVar1 = FUN_004132c0(param_1 + 0x2480);
    local_c = (local_10 - iVar1) + -10;
    (**(code **)(*(int *)(param_1 + 0x2480) + 0x2c))(local_8,local_c);
    local_1c = local_1c + 10;
    local_18 = local_18 + 10;
    local_10 = local_10 + -10;
    local_14 = local_14 + -10;
    FONT::WrapText((FONT *)(param_1 + 0x4c5c),DAT_0044dbf8,local_1c,local_18,local_14,local_10,0);
  }
  return;
}



void __thiscall FUN_0041d6ad(void *this,undefined4 param_1)

{
  DAT_0044dbf8 = param_1;
  FUN_0041d6d7(this);
  *(undefined4 *)((int)this + 0x129b8) = 1;
  return;
}



void __fastcall FUN_0041d6d7(undefined4 param_1)

{
  uint local_8;
  
  for (local_8 = 0; local_8 < 0xf; local_8 = local_8 + 1) {
    (**(code **)(**(int **)(&DAT_0044dae8 + local_8 * 4) + 0x20))(param_1);
  }
  return;
}



void FUN_0041d717(void)

{
  char *pcVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined1 uVar5;
  CString aCStack_d0 [4];
  undefined4 uStack_cc;
  undefined4 uStack_c8;
  CString aCStack_c0 [4];
  undefined4 uStack_bc;
  undefined4 uStack_b8;
  undefined4 uStack_b4;
  undefined4 uStack_b0;
  CString aCStack_a8 [4];
  undefined4 uStack_a4;
  undefined4 uStack_a0;
  undefined4 uStack_9c;
  undefined4 uStack_98;
  CString aCStack_90 [4];
  undefined4 uStack_8c;
  undefined4 *local_88;
  undefined4 *local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 *local_78;
  undefined4 *local_74;
  undefined4 local_70;
  undefined4 *local_6c;
  undefined4 *local_68;
  undefined4 local_64;
  undefined4 *local_60;
  undefined4 *local_5c;
  undefined4 local_58;
  undefined4 *local_54;
  undefined4 *local_50;
  undefined4 local_4c;
  int *local_48;
  CString local_44 [4];
  undefined1 *local_40;
  SPRITE *local_3c;
  undefined4 local_38;
  CString local_34 [4];
  undefined1 *local_30;
  CString local_2c [4];
  undefined1 *local_28;
  CString local_24 [4];
  undefined1 *local_20;
  CString local_1c [4];
  undefined1 *local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a968;
  local_10 = ExceptionList;
  uStack_8c = 0x41d73d;
  ExceptionList = &local_10;
  FUN_0041da1f();
  uStack_8c = 0;
  local_18 = aCStack_90;
  uStack_98 = 0x41d74f;
  local_4c = CString::CString(aCStack_90,s_more_bmp_0043597c);
  uStack_98 = 0x41d761;
  local_54 = (undefined4 *)(**(code **)(*local_48 + 0x54))();
  local_8 = 0;
  uStack_98 = 0x41d779;
  local_50 = local_54;
  uStack_98 = FUN_00401470(local_54);
  uStack_9c = 0x41d78f;
  (**(code **)(local_48[0x195a] + 0x3c))();
  local_8 = 0xffffffff;
  uStack_9c = 0x41d79e;
  CString::~CString(local_1c);
  uStack_9c = 0x138;
  uStack_a0 = 0x1e0;
  uStack_a4 = 0x41d7bd;
  (**(code **)(local_48[0x195a] + 0x2c))();
  uStack_a4 = 0;
  local_20 = aCStack_a8;
  uStack_b0 = 0x41d7cf;
  local_58 = CString::CString(aCStack_a8,s_less_bmp_00435988);
  uStack_b0 = 0x41d7e1;
  local_60 = (undefined4 *)(**(code **)(*local_48 + 0x54))();
  local_8 = 1;
  uStack_b0 = 0x41d7f9;
  local_5c = local_60;
  uStack_b0 = FUN_00401470(local_60);
  uStack_b4 = 0x41d80f;
  (**(code **)(local_48[0x198e] + 0x3c))();
  local_8 = 0xffffffff;
  uStack_b4 = 0x41d81e;
  CString::~CString(local_24);
  uStack_b4 = 0;
  uStack_b8 = 0;
  uStack_bc = 0x41d837;
  (**(code **)(local_48[0x198e] + 0x2c))();
  uStack_bc = 0;
  local_28 = aCStack_c0;
  uStack_c8 = 0x41d849;
  local_64 = CString::CString(aCStack_c0,s_solved_bmp_00435994);
  uStack_c8 = 0x41d85b;
  local_6c = (undefined4 *)(**(code **)(*local_48 + 0x54))();
  local_8 = 2;
  uStack_c8 = 0x41d873;
  local_68 = local_6c;
  uStack_c8 = FUN_00401470(local_6c);
  uStack_cc = 0x41d889;
  (**(code **)(local_48[0x19c2] + 0x3c))();
  local_8 = 0xffffffff;
  uStack_cc = 0x41d898;
  CString::~CString(local_2c);
  uStack_cc = 0;
  local_30 = aCStack_d0;
  local_70 = CString::CString(aCStack_d0,s_thumbsolved_bmp_004359a0);
  uVar5 = SUB41(local_34,0);
  local_78 = (undefined4 *)(**(code **)(*local_48 + 0x54))();
  local_8 = 3;
  local_74 = local_78;
  pcVar1 = (char *)FUN_00401470(local_78);
  OVERLAY::Init((OVERLAY *)&DAT_0044db28,pcVar1,(bool)uVar5);
  local_8 = 0xffffffff;
  CString::~CString(local_34);
  for (local_14 = 0; local_14 < 0xf; local_14 = local_14 + 1) {
    local_3c = (SPRITE *)operator_new(0x112c);
    local_8 = 4;
    if (local_3c == (SPRITE *)0x0) {
      local_7c = 0;
    }
    else {
      local_7c = SPRITE::SPRITE(local_3c);
    }
    local_38 = local_7c;
    local_8 = 0xffffffff;
    *(undefined4 *)(&DAT_0044dae8 + local_14 * 4) = local_7c;
    iVar4 = 6;
    iVar3 = 1;
    local_40 = &stack0xffffff1c;
    uVar2 = local_14;
    local_80 = CString::CString((CString *)&stack0xffffff1c,s_locksprite_bmp_004359b0);
    uVar5 = SUB41(local_44,0);
    local_88 = (undefined4 *)(**(code **)(*local_48 + 0x54))();
    local_8 = 5;
    local_84 = local_88;
    pcVar1 = (char *)FUN_00401470(local_88);
    SPRITE::Init(*(SPRITE **)(&DAT_0044dae8 + local_14 * 4),pcVar1,(bool)uVar5,uVar2,iVar3,iVar4);
    local_8 = 0xffffffff;
    CString::~CString(local_44);
    (**(code **)(**(int **)(&DAT_0044dae8 + local_14 * 4) + 0x20))();
    (**(code **)(**(int **)(&DAT_0044dae8 + local_14 * 4) + 0x4c))();
    (**(code **)(**(int **)(&DAT_0044dae8 + local_14 * 4) + 0x50))();
  }
  ExceptionList = local_10;
  return;
}



void FUN_0041da1f(void)

{
  uint local_8;
  
  for (local_8 = 0; local_8 < 0xf; local_8 = local_8 + 1) {
    if (*(undefined4 **)(&DAT_0044dae8 + local_8 * 4) != (undefined4 *)0x0) {
      (**(code **)**(undefined4 **)(&DAT_0044dae8 + local_8 * 4))(1);
    }
    *(undefined4 *)(&DAT_0044dae8 + local_8 * 4) = 0;
  }
  return;
}



void FUN_0041da85(int param_1,int param_2)

{
  HDC pHVar1;
  HDC extraout_var;
  int local_20;
  HWND__ local_1c;
  int local_18;
  tagRECT local_14;
  
  pHVar1 = DD_SURFACE::GetDC(&local_1c);
  if (pHVar1 != (HDC)0x0) {
    pHVar1 = extraout_var;
    for (local_18 = 0; local_18 < 4; local_18 = local_18 + 1) {
      for (local_20 = 0; local_20 < 4; local_20 = local_20 + 1) {
        local_14.left = param_1;
        local_14.top = param_2;
        local_14.right = param_1 + 0xa0;
        local_14.bottom = param_2 + 0x68;
        DrawEdge((HDC)local_1c.unused,&local_14,9,0xf);
      }
    }
    DD_SURFACE::ReleaseDC((HWND)local_1c.unused,pHVar1);
  }
  return;
}



void __thiscall FUN_0041db21(void *this,char param_1,char param_2)

{
  bool bVar1;
  CString *pCVar2;
  char *pcVar3;
  undefined3 extraout_var;
  CPosition *pCVar4;
  int iVar5;
  undefined3 extraout_var_00;
  undefined4 *puVar6;
  uint uVar7;
  char **ppcVar8;
  int local_90;
  CString local_80 [4];
  CString local_7c [4];
  CString local_78 [4];
  CString local_74 [4];
  CString local_70 [4];
  CString local_6c [4];
  undefined1 local_68 [8];
  undefined1 *local_60;
  undefined1 *local_5c;
  CString local_58 [4];
  int local_54;
  undefined4 local_50;
  int local_4c;
  undefined4 local_48;
  uint local_44;
  tagRECT local_40;
  uint local_30;
  int local_2c;
  int local_28;
  uint local_24;
  int local_20;
  CString local_1c [4];
  int local_18;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a9ba;
  local_10 = ExceptionList;
  local_20 = 0;
  local_28 = 0;
  local_30 = 0;
  local_14 = (-(uint)(param_1 != '\0') & 0xf) + 1;
  local_2c = 0;
  ExceptionList = &local_10;
  GKERNEL::NewSpriteBackground();
  pCVar2 = FUN_004014f0(local_58);
  local_8 = 0;
  operator+(local_1c,(char *)pCVar2);
  local_8 = CONCAT31(local_8._1_3_,2);
  CString::~CString(local_58);
  bVar1 = false;
  pcVar3 = (char *)FUN_00401470((undefined4 *)local_1c);
  GKTOOLS::TileDIBToSurface((DD_SURFACE *)ddsBack_exref,pcVar3,bVar1);
  if (param_2 != '\0') {
    FUN_0041d6d7(this);
  }
  local_18 = 0;
  for (local_24 = 0; (int)local_24 < 0x10; local_24 = local_24 + 1) {
    uVar7 = local_24 & 0x80000003;
    if ((int)uVar7 < 0) {
      uVar7 = (uVar7 - 1 | 0xfffffffc) + 1;
    }
    local_20 = uVar7 * 0xa0;
    local_28 = ((int)(local_24 + ((int)local_24 >> 0x1f & 3U)) >> 2) * 0x68;
    if ((param_1 == '\0') || (local_24 != 0)) {
      if ((param_1 == '\0') && (local_24 == 0xf)) break;
      local_30 = local_24;
      if (param_1 == '\0') {
        bVar1 = FUN_0040e0e0((int)this);
        if ((bVar1) || (local_18 != 0)) {
          local_90 = 1;
        }
        else {
          local_90 = 0;
        }
        local_18 = local_90;
        if (local_90 == 0) {
          local_5c = &stack0xffffff1c;
          FUN_004058b0(&stack0xffffff1c,*(int *)((int)this + 0x129b0) * 100 + 0xf + local_14);
          bVar1 = MAP::Exists();
          if (bVar1) {
            local_18 = 1;
          }
        }
      }
      else {
        local_30 = local_24 - 1;
      }
      local_44 = local_44 & 0xffffff00;
      bVar1 = FUN_0040e0e0((int)this);
      if (bVar1) {
        local_44 = CONCAT31(local_44._1_3_,1);
      }
      else {
        local_60 = &stack0xffffff1c;
        FUN_004058b0(&stack0xffffff1c,*(int *)((int)this + 0x129b0) * 100 + local_14);
        bVar1 = MAP::Exists();
        if (bVar1) {
          local_44 = CONCAT31(local_44._1_3_,
                              '\x01' - (*(char *)(*(int *)((int)this + 0x38) + 0x1a3) != '\0'));
          bVar1 = FUN_00411392(this);
          if (CONCAT31(extraout_var,bVar1) != 0) {
            local_44 = CONCAT31(local_44._1_3_,1);
          }
        }
      }
      if (((local_44 & 0xff) != 0) || (*(char *)(*(int *)((int)this + 0x38) + 0x1a3) != '\0')) {
        MAP::Set((MAP *)((int)this + local_30 * 0x440 + 0xe67c),
                 (CString *)
                 ((int)this + (*(int *)((int)this + 0x129b0) * 0x1e + -1 + local_14) * 4 + 0x1263c))
        ;
      }
      if ((local_44 & 0xff) == 0) {
        if (*(char *)(*(int *)((int)this + 0x38) + 0x1a3) != '\0') {
          OVERLAY::SetPosition((OVERLAY *)&DAT_0044db28,local_20,local_28);
          OVERLAY::DrawToBack((OVERLAY *)&DAT_0044db28);
          iVar5 = local_20 + 0x1b;
          ppcVar8 = &param_1_004359e8;
          uVar7 = MAP::Name((MAP *)((int)this + local_30 * 0x440 + 0xe67c));
          local_8._0_1_ = 6;
          pcVar3 = (char *)operator+((char *)local_7c,(CString *)&param_2_004359ec);
          local_8._0_1_ = 7;
          puVar6 = (undefined4 *)operator+(local_80,pcVar3);
          local_8._0_1_ = 8;
          pcVar3 = (char *)FUN_00401470(puVar6);
          FONT::OutText((FONT *)((int)this + 0x3bb0),pcVar3,uVar7,(uint)ppcVar8,iVar5);
          local_8._0_1_ = 7;
          CString::~CString(local_80);
          local_8._0_1_ = 6;
          CString::~CString(local_7c);
          local_8 = CONCAT31(local_8._1_3_,2);
          FUN_004014d0(local_78);
          FUN_0041da85(local_20,local_28);
        }
      }
      else {
        pCVar4 = (CPosition *)default_error_condition(local_68,local_20,local_28);
        MAP::SetPosition((MAP *)((int)this + local_30 * 0x440 + 0xe67c),pCVar4);
        FUN_00410b70((MAP *)((int)this + local_30 * 0x440 + 0xe67c));
        iVar5 = FUN_00411719(this,*(int *)((int)this + 0x129b0) * 100 + local_14);
        if ((iVar5 == 0) && (param_2 != '\0')) {
          RandomProb();
          RandomProb();
          local_48 = ftol();
          RandomProb();
          RandomProb();
          local_50 = ftol();
          local_54 = local_20 + 0x36;
          local_4c = local_28 + 0x18;
          (**(code **)(**(int **)(&DAT_0044dae8 + local_2c * 4) + 0x2c))();
          (**(code **)(**(int **)(&DAT_0044dae8 + local_2c * 4) + 0x1c))();
          (**(code **)(**(int **)(&DAT_0044dae8 + local_2c * 4) + 0x6c))(local_54,local_4c,0x5dc);
          local_2c = local_2c + 1;
        }
        bVar1 = FUN_00411392(this);
        if (CONCAT31(extraout_var_00,bVar1) != 0) {
          (**(code **)(*(int *)((int)this + 0x6708) + 0x2c))();
          (**(code **)(*(int *)((int)this + 0x6708) + 0x14))();
        }
        iVar5 = local_20 + 0x1b;
        ppcVar8 = &param_1_004359e0;
        uVar7 = MAP::Name((MAP *)((int)this + local_30 * 0x440 + 0xe67c));
        local_8._0_1_ = 3;
        pcVar3 = (char *)operator+((char *)local_70,(CString *)&param_2_004359e4);
        local_8._0_1_ = 4;
        puVar6 = (undefined4 *)operator+(local_74,pcVar3);
        local_8._0_1_ = 5;
        pcVar3 = (char *)FUN_00401470(puVar6);
        FONT::OutText((FONT *)((int)this + 0x3bb0),pcVar3,uVar7,(uint)ppcVar8,iVar5);
        local_8._0_1_ = 4;
        CString::~CString(local_74);
        local_8._0_1_ = 3;
        CString::~CString(local_70);
        local_8 = CONCAT31(local_8._1_3_,2);
        FUN_004014d0(local_6c);
        FUN_0041da85(local_20,local_28);
      }
      local_14 = local_14 + 1;
    }
  }
  (**(code **)(*(int *)((int)this + 0x6568) + 0x20))();
  (**(code **)(*(int *)((int)this + 0x6638) + 0x20))();
  if ((param_1 == '\0') && (local_18 != 0)) {
    (**(code **)(*(int *)((int)this + 0x6568) + 0x1c))();
    (**(code **)(*(int *)((int)this + 0x6568) + 0x14))();
  }
  else if (param_1 != '\0') {
    (**(code **)(*(int *)((int)this + 0x6638) + 0x1c))();
    (**(code **)(*(int *)((int)this + 0x6638) + 0x14))();
  }
  FUN_00417f6e((int *)this);
  local_40.left = 0;
  local_40.top = 0;
  local_40.right = 0x280;
  local_40.bottom = 0x1e0;
  DD_SURFACE::BltFast((DD_SURFACE *)ddsPrimary_exref,(DD_SURFACE *)ddsBack_exref,0,0,&local_40);
  local_8 = 0xffffffff;
  CString::~CString(local_1c);
  ExceptionList = local_10;
  return;
}



int * __thiscall FUN_0041e2e6(void *this,int *param_1)

{
  uint uVar1;
  int iVar2;
  tagPOINT local_14;
  int local_c;
  int local_8;
  
  uVar1 = GKERNEL::GetCursorPos(&local_14);
  if ((uVar1 & 0xff) == 0) {
    FUN_0041e760(param_1);
  }
  else if (local_14.y / 0x68 < 4) {
    FUN_0041e760(&local_c);
    local_c = *(int *)((int)this + 0x129b0) + 1;
    iVar2 = FUN_004056c0((int)this);
    if (iVar2 == 0xd) {
      local_8 = 0x10;
    }
    else {
      local_8 = 1;
    }
    local_8 = local_8 + local_14.x / 0xa0 + (local_14.y / 0x68) * 4;
    if (local_8 == 0x10) {
      FUN_0041e760(param_1);
    }
    else {
      iVar2 = FUN_004056c0((int)this);
      if (iVar2 == 0xd) {
        local_8 = local_8 + -1;
      }
      *param_1 = local_c;
      param_1[1] = local_8;
    }
  }
  else {
    FUN_0041e760(param_1);
  }
  return param_1;
}



void __thiscall FUN_0041e3d0(void *this,int param_1)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  MAP local_ce0 [1088];
  MAP local_8a0 [1088];
  MAP local_460 [1088];
  char local_20;
  char local_1c;
  uint local_18 [2];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042a9eb;
  local_10 = ExceptionList;
  if (*(int *)((int)this + 0xe010) != 0) {
    ExceptionList = &local_10;
    FUN_0041e2e6(this,(int *)local_18);
    cVar1 = FUN_00411e50(local_18);
    if ((cVar1 != '\0') && (*(char *)((int)this + 0x1281c) != '\0')) {
      if (param_1 == 0x24) {
        MAP::RefreshItemMap();
        MAP::SetDemoLevel(local_18[0]);
        cVar1 = '\x01';
        iVar3 = FUN_004056c0((int)this);
        FUN_0041db21(this,iVar3 == 0xd,cVar1);
      }
      else {
        bVar2 = GAME::IsKeyDown((GAME *)this,0x11);
        if ((bVar2) && (param_1 == 3)) {
          iVar3 = FUN_004058f0((int *)local_18);
          *(int *)((int)this + 0xe1a0) = iVar3;
        }
        else {
          bVar2 = GAME::IsKeyDown((GAME *)this,0x11);
          if ((bVar2) &&
             (((param_1 == 0x17 && (*(int *)((int)this + 0xe1a0) != -1)) &&
              (iVar3 = FUN_004058f0((int *)local_18), *(int *)((int)this + 0xe1a0) != iVar3)))) {
            FUN_004058f0((int *)local_18);
            bVar2 = FUN_00411392(this);
            local_20 = CONCAT31(extraout_var,bVar2) != 0;
            bVar2 = FUN_00411392(this);
            local_1c = CONCAT31(extraout_var_00,bVar2) != 0;
            MAP::MAP(local_8a0);
            local_8 = 0;
            MAP::MAP(local_460);
            local_8._0_1_ = 1;
            FUN_004058b0(&stack0xfffff30c,*(uint *)((int)this + 0xe1a0));
            MAP::Load(local_8a0);
            MAP::Load(local_460);
            MAP::Save(local_8a0);
            FUN_004058b0(&stack0xfffff30c,*(uint *)((int)this + 0xe1a0));
            MAP::Save(local_460);
            cVar1 = local_1c;
            iVar3 = FUN_004058f0((int *)local_18);
            FUN_00411531(this,iVar3,cVar1);
            FUN_00411531(this,*(undefined4 *)((int)this + 0xe1a0),local_20);
            FUN_00411cca(this);
            cVar1 = '\x01';
            iVar3 = FUN_004056c0((int)this);
            FUN_0041db21(this,iVar3 == 0xd,cVar1);
            *(undefined4 *)((int)this + 0xe1a0) = 0xffffffff;
            local_8 = (uint)local_8._1_3_ << 8;
            MAP::~MAP(local_460);
            local_8 = 0xffffffff;
            MAP::~MAP(local_8a0);
          }
          else {
            bVar2 = GAME::IsKeyDown((GAME *)this,0x11);
            if ((bVar2) && (param_1 == 4)) {
              MAP::MAP(local_ce0);
              local_8 = 2;
              MAP::Clear(local_ce0);
              MAP::Save(local_ce0);
              cVar1 = '\0';
              iVar3 = FUN_004058f0((int *)local_18);
              FUN_00411531(this,iVar3,cVar1);
              FUN_00411cca(this);
              cVar1 = '\x01';
              iVar3 = FUN_004056c0((int)this);
              FUN_0041db21(this,iVar3 == 0xd,cVar1);
              local_8 = 0xffffffff;
              MAP::~MAP(local_ce0);
            }
          }
        }
      }
    }
  }
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_0041e760(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  return param_1;
}



void FUN_0041e790(void)

{
  FUN_0041e79f();
  FUN_0041e7af();
  return;
}



void FUN_0041e79f(void)

{
  SPRITE::SPRITE((SPRITE *)&DAT_0044f820);
  return;
}



void FUN_0041e7af(void)

{
  FUN_00427dae(FUN_0041e7c1);
  return;
}



void FUN_0041e7c1(void)

{
  SPRITE::~SPRITE((SPRITE *)&DAT_0044f820);
  return;
}



void FUN_0041e7d1(void)

{
  FUN_0041e7e0();
  FUN_0041e7f0();
  return;
}



void FUN_0041e7e0(void)

{
  SPRITE::SPRITE((SPRITE *)&DAT_0044e3c8);
  return;
}



void FUN_0041e7f0(void)

{
  FUN_00427dae(FUN_0041e802);
  return;
}



void FUN_0041e802(void)

{
  SPRITE::~SPRITE((SPRITE *)&DAT_0044e3c8);
  return;
}



void FUN_0041e812(void)

{
  FUN_0041e821();
  FUN_0041e830();
  return;
}



void FUN_0041e821(void)

{
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)&DAT_0044dd88);
  return;
}



void FUN_0041e830(void)

{
  FUN_00427dae(FUN_0041e842);
  return;
}



void FUN_0041e842(void)

{
  FUN_00422e50((undefined4 *)&DAT_0044dd88);
  return;
}



void FUN_0041e851(void)

{
  FUN_0041e860();
  FUN_0041e86f();
  return;
}



void FUN_0041e860(void)

{
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)&DAT_0044f4f8);
  return;
}



void FUN_0041e86f(void)

{
  FUN_00427dae(FUN_0041e881);
  return;
}



void FUN_0041e881(void)

{
  FUN_00422e50((undefined4 *)&DAT_0044f4f8);
  return;
}



void FUN_0041e890(void)

{
  FUN_0041e89f();
  FUN_0041e8ae();
  return;
}



void FUN_0041e89f(void)

{
  FUN_0040c640((OVERLAY *)&DAT_00450950);
  return;
}



void FUN_0041e8ae(void)

{
  FUN_00427dae(FUN_0041e8c0);
  return;
}



void FUN_0041e8c0(void)

{
  FUN_0040c870((undefined4 *)&DAT_00450950);
  return;
}



void FUN_0041e8cf(void)

{
  FUN_0041e8de();
  FUN_0041e8ed();
  return;
}



void FUN_0041e8de(void)

{
  FUN_0040c640((OVERLAY *)&DAT_0044dda8);
  return;
}



void FUN_0041e8ed(void)

{
  FUN_00427dae(FUN_0041e8ff);
  return;
}



void FUN_0041e8ff(void)

{
  FUN_0040c870((undefined4 *)&DAT_0044dda8);
  return;
}



void FUN_0041e90e(void)

{
  FUN_0041e91d();
  FUN_0041e92c();
  return;
}



void FUN_0041e91d(void)

{
  FUN_0040c640((OVERLAY *)&DAT_0044df48);
  return;
}



void FUN_0041e92c(void)

{
  FUN_00427dae(FUN_0041e93e);
  return;
}



void FUN_0041e93e(void)

{
  FUN_0040c870((undefined4 *)&DAT_0044df48);
  return;
}



void FUN_0041e94d(void)

{
  FUN_0041e95c();
  FUN_0041e96b();
  return;
}



void FUN_0041e95c(void)

{
  FUN_0040c640((OVERLAY *)&DAT_0044f518);
  return;
}



void FUN_0041e96b(void)

{
  FUN_00427dae(FUN_0041e97d);
  return;
}



void FUN_0041e97d(void)

{
  FUN_0040c870((undefined4 *)&DAT_0044f518);
  return;
}



void FUN_0041e98c(void)

{
  FUN_0041e99b();
  FUN_0041e9aa();
  return;
}



void FUN_0041e99b(void)

{
  FUN_0040c640((OVERLAY *)&DAT_0044e248);
  return;
}



void FUN_0041e9aa(void)

{
  FUN_00427dae(FUN_0041e9bc);
  return;
}



void FUN_0041e9bc(void)

{
  FUN_0040c870((undefined4 *)&DAT_0044e248);
  return;
}



void FUN_0041e9cb(void)

{
  FUN_0041e9da();
  FUN_0041e9e9();
  return;
}



void FUN_0041e9da(void)

{
  FUN_0040c640((OVERLAY *)&DAT_0044e0c8);
  return;
}



void FUN_0041e9e9(void)

{
  FUN_00427dae(FUN_0041e9fb);
  return;
}



void FUN_0041e9fb(void)

{
  FUN_0040c870((undefined4 *)&DAT_0044e0c8);
  return;
}



void FUN_0041ea0a(void)

{
  FUN_0041ea19();
  FUN_0041ea28();
  return;
}



void FUN_0041ea19(void)

{
  FUN_0040c640((OVERLAY *)&DAT_0044f6a0);
  return;
}



void FUN_0041ea28(void)

{
  FUN_00427dae(FUN_0041ea3a);
  return;
}



void FUN_0041ea3a(void)

{
  FUN_0040c870((undefined4 *)&DAT_0044f6a0);
  return;
}



void FUN_0041ea49(void)

{
  FUN_0041ea58();
  FUN_0041ea67();
  return;
}



void FUN_0041ea58(void)

{
  FUN_0040c640((OVERLAY *)&DAT_0044dc00);
  return;
}



void FUN_0041ea67(void)

{
  FUN_00427dae(FUN_0041ea79);
  return;
}



void FUN_0041ea79(void)

{
  FUN_0040c870((undefined4 *)&DAT_0044dc00);
  return;
}



void FUN_0041ea88(void)

{
  FUN_0041ea97();
  FUN_0041eaa6();
  return;
}



void FUN_0041ea97(void)

{
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)&DAT_0044df28);
  return;
}



void FUN_0041eaa6(void)

{
  FUN_00427dae(FUN_0041eab8);
  return;
}



void FUN_0041eab8(void)

{
  FUN_00426d00((undefined4 *)&DAT_0044df28);
  return;
}



void FUN_0041eac7(void)

{
  FUN_0041ead1();
  return;
}



void FUN_0041ead1(void)

{
  FUN_00405850(&DAT_0044f698);
  return;
}



void FUN_0041eae0(void)

{
  FUN_0041eaef();
  FUN_0041eafe();
  return;
}



void FUN_0041eaef(void)

{
  CString::CString((CString *)&DAT_0044dda4);
  return;
}



void FUN_0041eafe(void)

{
  FUN_00427dae(FUN_0041eb10);
  return;
}



void FUN_0041eb10(void)

{
  CString::~CString((CString *)&DAT_0044dda4);
  return;
}



void FUN_0041eb1f(void)

{
  FUN_0041eb29();
  return;
}



void FUN_0041eb29(void)

{
  FUN_00405850(&DAT_0044dd80);
  return;
}



void FUN_0041eb38(void)

{
  char *pcVar1;
  CString extraout_CL;
  CString extraout_CL_00;
  CString extraout_CL_01;
  CString extraout_CL_02;
  CString extraout_CL_03;
  CString extraout_CL_04;
  CString extraout_CL_05;
  CString extraout_CL_06;
  CString extraout_CL_07;
  int extraout_ECX;
  int extraout_ECX_00;
  CString *pCVar2;
  undefined1 uVar3;
  int iVar4;
  CString CVar5;
  int iVar6;
  int iVar7;
  CString aCStack_1c0 [4];
  undefined4 uStack_1bc;
  undefined4 *local_1b8;
  undefined4 *local_1b4;
  undefined4 local_1b0;
  undefined4 *local_1ac;
  undefined4 *local_1a8;
  undefined4 local_1a4;
  undefined4 *local_1a0;
  undefined4 *local_19c;
  undefined4 local_198;
  undefined4 *local_194;
  undefined4 *local_190;
  undefined4 local_18c;
  undefined4 *local_188;
  undefined4 *local_184;
  undefined4 local_180;
  undefined4 *local_17c;
  undefined4 *local_178;
  undefined4 local_174;
  undefined4 *local_170;
  undefined4 *local_16c;
  undefined4 local_168;
  undefined4 *local_164;
  undefined4 *local_160;
  undefined4 local_15c;
  undefined4 *local_158;
  undefined4 *local_154;
  undefined4 local_150;
  undefined4 *local_14c;
  undefined4 *local_148;
  undefined4 local_144;
  undefined4 *local_140;
  undefined4 *local_13c;
  undefined4 local_138;
  undefined4 *local_134;
  undefined4 *local_130;
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
  int *local_bc;
  CString local_b8 [4];
  undefined1 *local_b4;
  CString local_b0 [4];
  undefined1 *local_ac;
  CString local_a8 [4];
  undefined1 *local_a4;
  CString local_a0 [4];
  undefined1 *local_9c;
  CString local_98 [4];
  undefined1 *local_94;
  CString local_90 [4];
  undefined1 *local_8c;
  CString local_88 [4];
  undefined1 *local_84;
  CString local_80 [4];
  undefined1 *local_7c;
  CString local_78 [4];
  undefined1 *local_74;
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
  puStack_c = &this_0042aad2;
  local_10 = ExceptionList;
  uStack_1bc = 0;
  local_14 = aCStack_1c0;
  ExceptionList = &local_10;
  local_c0 = CString::CString(aCStack_1c0,s_tutorial_panel_bmp_004359f0);
  local_c8 = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8 = 0;
  local_c4 = local_c8;
  FUN_00401470(local_c8);
  (**(code **)(local_bc[0x55] + 0x3c))();
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  (**(code **)(local_bc[0x55] + 0x2c))();
  (**(code **)(local_bc[0x55] + 0x20))();
  iVar7 = 4;
  iVar6 = 1;
  local_1c = &stack0xfffffe1c;
  iVar4 = extraout_ECX;
  local_cc = CString::CString((CString *)&stack0xfffffe1c,s_pointer_bmp_00435a04);
  CVar5 = SUB41(local_20,0);
  local_d4 = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8 = 1;
  local_d0 = local_d4;
  pcVar1 = (char *)FUN_00401470(local_d4);
  SPRITE::Init((SPRITE *)&DAT_0044e3c8,pcVar1,(bool)CVar5,iVar4,iVar6,iVar7);
  local_8 = 0xffffffff;
  CString::~CString(local_20);
  SPRITE::Hide((SPRITE *)&DAT_0044e3c8);
  iVar7 = 1;
  iVar6 = 1;
  local_24 = &stack0xfffffe14;
  iVar4 = extraout_ECX_00;
  local_d8 = CString::CString((CString *)&stack0xfffffe14,s_HIGHL16M_tutorial_BMP_00435a10);
  uVar3 = SUB41(local_28,0);
  local_e0 = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8 = 2;
  local_dc = local_e0;
  pcVar1 = (char *)FUN_00401470(local_e0);
  SPRITE::Init((SPRITE *)&DAT_0044f820,pcVar1,(bool)uVar3,iVar4,iVar6,iVar7);
  local_8 = 0xffffffff;
  CString::~CString(local_28);
  SPRITE::Hide((SPRITE *)&DAT_0044f820);
  local_2c = &stack0xfffffe18;
  local_e4 = CString::CString((CString *)&stack0xfffffe18,s_tutNext_Down_bmp_00435a28);
  local_ec = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8 = 3;
  local_e8 = local_ec;
  FUN_00401470(local_ec);
  local_34 = &stack0xfffffe0c;
  CVar5 = extraout_CL;
  local_f0 = CString::CString((CString *)&stack0xfffffe0c,s_tutNext_bmp_00435a3c);
  pCVar2 = local_38;
  local_f8 = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8._0_1_ = 4;
  local_f4 = local_f8;
  pcVar1 = (char *)FUN_00401470(local_f8);
  BUTTON::Init((BUTTON *)&DAT_00450950,pcVar1,(char *)pCVar2,(bool)CVar5);
  local_8 = CONCAT31(local_8._1_3_,3);
  CString::~CString(local_38);
  local_8 = 0xffffffff;
  CString::~CString(local_30);
  FUN_0040c710(0x450950);
  local_3c = &stack0xfffffe08;
  local_fc = CString::CString((CString *)&stack0xfffffe08,s_tutPrevStep_Down_bmp_00435a48);
  local_104 = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8 = 5;
  local_100 = local_104;
  FUN_00401470(local_104);
  local_44 = &stack0xfffffdfc;
  CVar5 = extraout_CL_00;
  local_108 = CString::CString((CString *)&stack0xfffffdfc,s_tutPrevStep_bmp_00435a60);
  pCVar2 = local_48;
  local_110 = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8._0_1_ = 6;
  local_10c = local_110;
  pcVar1 = (char *)FUN_00401470(local_110);
  BUTTON::Init((BUTTON *)&DAT_0044dda8,pcVar1,(char *)pCVar2,(bool)CVar5);
  local_8 = CONCAT31(local_8._1_3_,5);
  CString::~CString(local_48);
  local_8 = 0xffffffff;
  CString::~CString(local_40);
  FUN_0040c710(0x44dda8);
  local_4c = &stack0xfffffdf8;
  local_114 = CString::CString((CString *)&stack0xfffffdf8,s_tutShowMe_Down_bmp_00435a70);
  local_11c = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8 = 7;
  local_118 = local_11c;
  FUN_00401470(local_11c);
  local_54 = &stack0xfffffdec;
  CVar5 = extraout_CL_01;
  local_120 = CString::CString((CString *)&stack0xfffffdec,s_tutShowMe_bmp_00435a84);
  pCVar2 = local_58;
  local_128 = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8._0_1_ = 8;
  local_124 = local_128;
  pcVar1 = (char *)FUN_00401470(local_128);
  BUTTON::Init((BUTTON *)&DAT_0044df48,pcVar1,(char *)pCVar2,(bool)CVar5);
  local_8 = CONCAT31(local_8._1_3_,7);
  CString::~CString(local_58);
  local_8 = 0xffffffff;
  CString::~CString(local_50);
  FUN_0040c710(0x44df48);
  local_5c = &stack0xfffffde8;
  local_12c = CString::CString((CString *)&stack0xfffffde8,s_tutLetMeTry_Down_bmp_00435a94);
  local_134 = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8 = 9;
  local_130 = local_134;
  FUN_00401470(local_134);
  local_64 = &stack0xfffffddc;
  CVar5 = extraout_CL_02;
  local_138 = CString::CString((CString *)&stack0xfffffddc,s_tutLetMeTry_bmp_00435aac);
  pCVar2 = local_68;
  local_140 = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8._0_1_ = 10;
  local_13c = local_140;
  pcVar1 = (char *)FUN_00401470(local_140);
  BUTTON::Init((BUTTON *)&DAT_0044f518,pcVar1,(char *)pCVar2,(bool)CVar5);
  local_8 = CONCAT31(local_8._1_3_,9);
  CString::~CString(local_68);
  local_8 = 0xffffffff;
  CString::~CString(local_60);
  FUN_0040c710(0x44f518);
  local_6c = &stack0xfffffdd8;
  local_144 = CString::CString((CString *)&stack0xfffffdd8,s_tutNeedHint_Down_bmp_00435abc);
  local_14c = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8 = 0xb;
  local_148 = local_14c;
  FUN_00401470(local_14c);
  local_74 = &stack0xfffffdcc;
  CVar5 = extraout_CL_03;
  local_150 = CString::CString((CString *)&stack0xfffffdcc,s_tutNeedHint_bmp_00435ad4);
  pCVar2 = local_78;
  local_158 = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8._0_1_ = 0xc;
  local_154 = local_158;
  pcVar1 = (char *)FUN_00401470(local_158);
  BUTTON::Init((BUTTON *)&DAT_0044e248,pcVar1,(char *)pCVar2,(bool)CVar5);
  local_8 = CONCAT31(local_8._1_3_,0xb);
  CString::~CString(local_78);
  local_8 = 0xffffffff;
  CString::~CString(local_70);
  FUN_0040c710(0x44e248);
  local_7c = &stack0xfffffdc8;
  local_15c = CString::CString((CString *)&stack0xfffffdc8,s_tut_NextTutorial_Down_bmp_00435ae4);
  local_164 = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8 = 0xd;
  local_160 = local_164;
  FUN_00401470(local_164);
  local_84 = &stack0xfffffdbc;
  CVar5 = extraout_CL_04;
  local_168 = CString::CString((CString *)&stack0xfffffdbc,s_tut_NextTutorial_bmp_00435b00);
  pCVar2 = local_88;
  local_170 = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8._0_1_ = 0xe;
  local_16c = local_170;
  pcVar1 = (char *)FUN_00401470(local_170);
  BUTTON::Init((BUTTON *)&DAT_0044dc00,pcVar1,(char *)pCVar2,(bool)CVar5);
  local_8 = CONCAT31(local_8._1_3_,0xd);
  CString::~CString(local_88);
  local_8 = 0xffffffff;
  CString::~CString(local_80);
  FUN_0040c710(0x44dc00);
  local_8c = &stack0xfffffdb8;
  local_174 = CString::CString((CString *)&stack0xfffffdb8,s_tut_StartOver_Down_bmp_00435b18);
  local_17c = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8 = 0xf;
  local_178 = local_17c;
  FUN_00401470(local_17c);
  local_94 = &stack0xfffffdac;
  CVar5 = extraout_CL_05;
  local_180 = CString::CString((CString *)&stack0xfffffdac,s_tut_StartOver_bmp_00435b30);
  pCVar2 = local_98;
  local_188 = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8._0_1_ = 0x10;
  local_184 = local_188;
  pcVar1 = (char *)FUN_00401470(local_188);
  BUTTON::Init((BUTTON *)&DAT_0044f6a0,pcVar1,(char *)pCVar2,(bool)CVar5);
  local_8 = CONCAT31(local_8._1_3_,0xf);
  CString::~CString(local_98);
  local_8 = 0xffffffff;
  CString::~CString(local_90);
  FUN_0040c710(0x44f6a0);
  local_9c = &stack0xfffffda8;
  local_18c = CString::CString((CString *)&stack0xfffffda8,s_tutNeedHint_down_bmp_00435b44);
  local_194 = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8 = 0x11;
  local_190 = local_194;
  FUN_00401470(local_194);
  local_a4 = &stack0xfffffd9c;
  CVar5 = extraout_CL_06;
  local_198 = CString::CString((CString *)&stack0xfffffd9c,s_tutNeedHint_bmp_00435b5c);
  pCVar2 = local_a8;
  local_1a0 = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8._0_1_ = 0x12;
  local_19c = local_1a0;
  pcVar1 = (char *)FUN_00401470(local_1a0);
  BUTTON::Init((BUTTON *)&DAT_0044e248,pcVar1,(char *)pCVar2,(bool)CVar5);
  local_8 = CONCAT31(local_8._1_3_,0x11);
  CString::~CString(local_a8);
  local_8 = 0xffffffff;
  CString::~CString(local_a0);
  FUN_0040c710(0x44e248);
  local_ac = &stack0xfffffd98;
  local_1a4 = CString::CString((CString *)&stack0xfffffd98,s_tutPrevHint_down_bmp_00435b6c);
  local_1ac = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8 = 0x13;
  local_1a8 = local_1ac;
  FUN_00401470(local_1ac);
  local_b4 = &stack0xfffffd8c;
  CVar5 = extraout_CL_07;
  local_1b0 = CString::CString((CString *)&stack0xfffffd8c,s_tutPrevHint_bmp_00435b84);
  pCVar2 = local_b8;
  local_1b8 = (undefined4 *)(**(code **)(*local_bc + 0x54))();
  local_8._0_1_ = 0x14;
  local_1b4 = local_1b8;
  pcVar1 = (char *)FUN_00401470(local_1b8);
  BUTTON::Init((BUTTON *)&DAT_0044e0c8,pcVar1,(char *)pCVar2,(bool)CVar5);
  local_8 = CONCAT31(local_8._1_3_,0x13);
  CString::~CString(local_b8);
  local_8 = 0xffffffff;
  CString::~CString(local_b0);
  FUN_0040c710(0x44e0c8);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_0041f49d(int param_1)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  CString *pCVar4;
  char *pcVar5;
  SECTION *this;
  undefined3 extraout_var;
  STRING *pSVar6;
  long lVar7;
  int *piVar8;
  undefined3 extraout_var_00;
  undefined4 *puVar9;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  undefined3 extraout_var_03;
  undefined3 extraout_var_04;
  uint uVar10;
  undefined3 extraout_var_05;
  undefined3 extraout_var_06;
  undefined3 extraout_var_07;
  undefined3 extraout_var_08;
  void *this_00;
  char *unaff_ESI;
  ulong *puVar11;
  char **ppcVar12;
  void *local_52c;
  void *local_518;
  void *local_50c;
  void *local_500;
  void *local_4f4;
  void *local_4e8;
  CDHtmlElementEventSink local_378 [12];
  CString local_36c [4];
  void *local_368;
  void *local_364;
  CDHtmlElementEventSink local_360 [12];
  void *local_354;
  void *local_350;
  CDHtmlElementEventSink local_34c [12];
  void *local_340;
  void *local_33c;
  CDHtmlElementEventSink local_338 [12];
  undefined4 local_32c;
  undefined4 local_328;
  void *local_324;
  void *local_320;
  CDHtmlElementEventSink local_31c [12];
  undefined4 local_310;
  void *local_30c;
  void *local_308;
  CDHtmlElementEventSink local_304 [12];
  CString local_2f8 [4];
  CString local_2f4 [4];
  CString local_2f0 [4];
  CString local_2ec [4];
  CString local_2e8 [4];
  CString local_2e4 [4];
  CString local_2e0 [4];
  CString local_2dc [4];
  CString local_2d8 [4];
  CString local_2d4 [4];
  CString local_2d0 [4];
  CString local_2cc [4];
  CString local_2c8 [4];
  CString local_2c4 [4];
  CString local_2c0 [4];
  CString local_2bc [4];
  CString local_2b8 [4];
  CString local_2b4 [4];
  CString local_2b0 [4];
  uint local_2ac;
  undefined1 local_2a8 [8];
  CString local_2a0 [4];
  CString local_29c [4];
  CString local_298 [4];
  undefined1 local_294 [12];
  CString local_288 [4];
  CString local_284 [4];
  CString local_280 [4];
  CString local_27c [4];
  undefined1 local_278 [16];
  CString local_268 [4];
  CString local_264 [4];
  CString local_260 [4];
  CString local_25c [4];
  CString local_258 [4];
  CString local_254 [4];
  undefined1 local_250 [12];
  CString local_244 [4];
  CString local_240 [4];
  CString local_23c [4];
  CString local_238 [4];
  undefined1 local_234 [16];
  CString local_224 [4];
  CString local_220 [4];
  CString local_21c [4];
  CString local_218 [4];
  CString local_214 [4];
  CString local_210 [4];
  CString local_20c [4];
  undefined1 local_208 [8];
  CString local_200 [4];
  ITEM *local_1fc;
  long local_1f8;
  long local_1f4;
  int local_1f0;
  int local_1ec;
  uint local_1e8;
  uint local_1e4;
  CString local_1e0 [4];
  long local_1dc;
  long local_1d8;
  long local_1d4;
  long local_1d0;
  long local_1cc;
  STRING local_1c8 [4];
  STRING local_1c4 [4];
  CString local_1c0 [4];
  CString local_1bc [4];
  int local_1b8;
  int local_1b4;
  char local_1b0;
  undefined1 local_1af;
  long local_1ac;
  STRING local_1a8 [4];
  int local_1a4;
  int local_1a0;
  undefined *local_19c;
  CString local_198 [4];
  STRING local_194 [4];
  long local_190;
  long local_18c;
  uint local_188;
  STRING local_184 [4];
  long local_180;
  long local_17c;
  long local_178;
  long local_174;
  long local_170;
  long local_16c;
  CString local_168 [4];
  STRING local_164 [4];
  long local_160;
  long local_15c;
  long local_158;
  int local_154;
  int local_150;
  int local_14c;
  int local_148;
  SECTION local_144 [8];
  int local_13c;
  CString local_138 [4];
  CString local_134 [8];
  int local_12c;
  int local_128;
  int local_124;
  int local_120;
  undefined4 local_11c;
  undefined4 local_118;
  undefined1 local_108 [28];
  undefined1 local_ec [28];
  undefined1 local_d0 [28];
  undefined1 local_b4 [28];
  undefined4 local_98;
  undefined4 local_90;
  ulong local_8c;
  ulong local_88;
  ulong local_84;
  ulong local_80;
  ulong local_7c;
  undefined1 local_78 [28];
  undefined1 local_5c [28];
  INIFILE local_40 [36];
  __POSITION *local_1c;
  CString local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042ae4c;
  local_10 = ExceptionList;
  if (DAT_00450ad0 == 0) {
    ExceptionList = &local_10;
    CString::CString(local_14);
    local_8 = 0;
    iVar3 = MAP::GetScript((MAP *)(param_1 + 0xe23c),local_14);
    if (iVar3 == 0) {
      local_8 = 0xffffffff;
      CString::~CString(local_14);
    }
    else {
      DAT_00450ad4 = 0;
      DAT_00450acc = 0;
      DAT_00450ad5 = 0;
      DAT_00450ad8 = 0;
      pCVar4 = (CString *)MAP::Data((MAP *)(param_1 + 0xe23c));
      local_8._0_1_ = 1;
      CString::operator=((CString *)&DAT_0044dda4,pCVar4);
      local_8._0_1_ = 0;
      FUN_004014d0(local_200);
      iVar3 = 1;
      pcVar5 = (char *)FUN_00401470((undefined4 *)local_14);
      INIFILE::INIFILE(local_40,pcVar5,iVar3);
      local_8._0_1_ = 2;
      FUN_00423c80(0x44dd88);
      puVar11 = &DAT_00450ad8;
      pcVar5 = s_DoItYourself_00435b94;
      this = (SECTION *)INIFILE::NullSection(local_40);
      local_8._0_1_ = 3;
      INIFILE::SECTION::Get(this,pcVar5,puVar11);
      local_8._0_1_ = 2;
      FUN_00407d90((int)local_208);
      local_1c = INIFILE::GetFirstSection(local_40);
      FUN_00405660(local_18);
      local_8._0_1_ = 4;
      while (local_1c != (__POSITION *)0x0) {
        FUN_00425fd0(local_138);
        local_8._0_1_ = 5;
        INIFILE::GetNextSection(local_40,(__POSITION **)local_144);
        local_8._0_1_ = 6;
        INIFILE::SECTION::Get(local_144,(char *)local_20c);
        local_8._0_1_ = 7;
        pCVar4 = (CString *)STRING::toupper((int)unaff_ESI);
        CString::operator=(local_138,pCVar4);
        local_8._0_1_ = 6;
        FUN_004014d0(local_20c);
        INIFILE::SECTION::Get(local_144,(char *)local_210);
        local_8._0_1_ = 8;
        pCVar4 = (CString *)STRING::toupper((int)unaff_ESI);
        CString::operator=(local_134,pCVar4);
        local_8._0_1_ = 6;
        FUN_004014d0(local_210);
        pCVar4 = (CString *)INIFILE::SECTION::Get(local_144,(char *)local_214);
        local_8._0_1_ = 9;
        FUN_004048d0(local_18,pCVar4);
        local_8._0_1_ = 6;
        FUN_004014d0(local_214);
        bVar1 = FUN_00401430((int *)local_18);
        if (CONCAT31(extraout_var,bVar1) == 0) {
          ppcVar12 = &param_1_00435bc4;
          pSVar6 = (STRING *)STRING::strtok((char *)local_218,(char *)&_Delim_00435bc0);
          local_8._0_1_ = 10;
          STRING::trim(pSVar6,(char *)ppcVar12);
          lVar7 = STRING::atol(unaff_ESI);
          local_148 = lVar7 * 0x20 + 5;
          local_8._0_1_ = 6;
          FUN_004014d0(local_218);
          ppcVar12 = &param_1_00435bd0;
          pSVar6 = (STRING *)STRING::strtok((char *)local_21c,(char *)&_Delim_00435bcc);
          local_8._0_1_ = 0xb;
          STRING::trim(pSVar6,(char *)ppcVar12);
          lVar7 = STRING::atol(unaff_ESI);
          local_150 = lVar7 * 0x20 + 5;
          local_8._0_1_ = 6;
          FUN_004014d0(local_21c);
          ppcVar12 = &param_1_00435bdc;
          pSVar6 = (STRING *)STRING::strtok((char *)local_220,(char *)&_Delim_00435bd8);
          local_8._0_1_ = 0xc;
          STRING::trim(pSVar6,(char *)ppcVar12);
          lVar7 = STRING::atol(unaff_ESI);
          local_14c = lVar7 * 0x20 + -5;
          local_8._0_1_ = 6;
          FUN_004014d0(local_220);
          ppcVar12 = &param_1_00435be8;
          pSVar6 = (STRING *)STRING::strtok((char *)local_224,(char *)&_Delim_00435be4);
          local_8._0_1_ = 0xd;
          STRING::trim(pSVar6,(char *)ppcVar12);
          lVar7 = STRING::atol(unaff_ESI);
          local_154 = lVar7 * 0x20 + -5;
          local_8._0_1_ = 6;
          FUN_004014d0(local_224);
          piVar8 = (int *)FUN_00414240(local_234,local_148,local_150,local_14c,local_154);
          local_12c = *piVar8;
          local_128 = piVar8[1];
          local_124 = piVar8[2];
          local_120 = piVar8[3];
        }
        pCVar4 = (CString *)INIFILE::SECTION::Get(local_144,(char *)local_238);
        local_8._0_1_ = 0xe;
        FUN_004048d0(local_18,pCVar4);
        local_8 = CONCAT31(local_8._1_3_,6);
        FUN_004014d0(local_238);
        while (bVar1 = FUN_00401430((int *)local_18), CONCAT31(extraout_var_00,bVar1) == 0) {
          ppcVar12 = &param_1_00435c00;
          pSVar6 = (STRING *)STRING::strtok((char *)local_23c,(char *)&_Delim_00435bfc);
          local_8._0_1_ = 0xf;
          pSVar6 = STRING::trim(pSVar6,(char *)ppcVar12);
          FUN_00407d70(local_164,(CString *)pSVar6);
          local_8._0_1_ = 0x11;
          FUN_004014d0(local_23c);
          ppcVar12 = &param_1_00435c0c;
          pSVar6 = (STRING *)STRING::strtok((char *)local_240,(char *)&_Delim_00435c08);
          local_8._0_1_ = 0x12;
          STRING::trim(pSVar6,(char *)ppcVar12);
          local_15c = STRING::atol(unaff_ESI);
          local_8._0_1_ = 0x11;
          FUN_004014d0(local_240);
          ppcVar12 = &param_1_00435c18;
          pSVar6 = (STRING *)STRING::strtok((char *)local_244,(char *)&_Delim_00435c14);
          local_8._0_1_ = 0x13;
          STRING::trim(pSVar6,(char *)ppcVar12);
          local_160 = STRING::atol(unaff_ESI);
          local_8._0_1_ = 0x11;
          FUN_004014d0(local_244);
          STRING::trim(local_164,&DAT_00435c20);
          local_158 = STRING::atol(unaff_ESI);
          puVar9 = (undefined4 *)FUN_00425ec0(local_250,local_15c,local_160,local_158 << 1);
          FUN_00423020(local_ec,puVar9);
          local_8 = CONCAT31(local_8._1_3_,6);
          FUN_004014d0((CString *)local_164);
        }
        pCVar4 = (CString *)INIFILE::SECTION::Get(local_144,(char *)local_254);
        local_8._0_1_ = 0x14;
        FUN_004048d0(local_18,pCVar4);
        local_8 = CONCAT31(local_8._1_3_,6);
        FUN_004014d0(local_254);
        while (bVar1 = FUN_00401430((int *)local_18), CONCAT31(extraout_var_01,bVar1) == 0) {
          ppcVar12 = &param_1_00435c34;
          pSVar6 = (STRING *)STRING::strtok((char *)local_258,(char *)&_Delim_00435c30);
          local_8._0_1_ = 0x15;
          pSVar6 = STRING::trim(pSVar6,(char *)ppcVar12);
          FUN_00407d70(local_168,(CString *)pSVar6);
          local_8._0_1_ = 0x17;
          FUN_004014d0(local_258);
          ppcVar12 = &param_1_00435c40;
          pSVar6 = (STRING *)STRING::strtok((char *)local_25c,(char *)&_Delim_00435c3c);
          local_8._0_1_ = 0x18;
          STRING::trim(pSVar6,(char *)ppcVar12);
          local_16c = STRING::atol(unaff_ESI);
          local_8._0_1_ = 0x17;
          FUN_004014d0(local_25c);
          ppcVar12 = &param_1_00435c4c;
          pSVar6 = (STRING *)STRING::strtok((char *)local_260,(char *)&_Delim_00435c48);
          local_8._0_1_ = 0x19;
          STRING::trim(pSVar6,(char *)ppcVar12);
          local_174 = STRING::atol(unaff_ESI);
          local_8._0_1_ = 0x17;
          FUN_004014d0(local_260);
          ppcVar12 = &param_1_00435c58;
          pSVar6 = (STRING *)STRING::strtok((char *)local_264,(char *)&_Delim_00435c54);
          local_8._0_1_ = 0x1a;
          STRING::trim(pSVar6,(char *)ppcVar12);
          local_170 = STRING::atol(unaff_ESI);
          local_8._0_1_ = 0x17;
          FUN_004014d0(local_264);
          ppcVar12 = &param_1_00435c64;
          pSVar6 = (STRING *)STRING::strtok((char *)local_268,(char *)&_Delim_00435c60);
          local_8._0_1_ = 0x1b;
          STRING::trim(pSVar6,(char *)ppcVar12);
          local_178 = STRING::atol(unaff_ESI);
          local_8._0_1_ = 0x17;
          FUN_004014d0(local_268);
          puVar9 = (undefined4 *)FUN_00425f20(local_278,local_16c,local_174,local_170,local_178);
          FUN_00423040(local_d0,puVar9);
          local_8 = CONCAT31(local_8._1_3_,6);
          FUN_004014d0(local_168);
        }
        pCVar4 = (CString *)INIFILE::SECTION::Get(local_144,(char *)local_27c);
        local_8._0_1_ = 0x1c;
        FUN_004048d0(local_18,pCVar4);
        local_8 = CONCAT31(local_8._1_3_,6);
        FUN_004014d0(local_27c);
        while (bVar1 = FUN_00401430((int *)local_18), CONCAT31(extraout_var_02,bVar1) == 0) {
          ppcVar12 = &param_1_00435c78;
          pSVar6 = (STRING *)STRING::strtok((char *)local_280,(char *)&_Delim_00435c74);
          local_8._0_1_ = 0x1d;
          pSVar6 = STRING::trim(pSVar6,(char *)ppcVar12);
          FUN_00407d70(local_184,(CString *)pSVar6);
          local_8._0_1_ = 0x1f;
          FUN_004014d0(local_280);
          ppcVar12 = &param_1_00435c84;
          pSVar6 = (STRING *)STRING::strtok((char *)local_284,(char *)&_Delim_00435c80);
          local_8._0_1_ = 0x20;
          STRING::trim(pSVar6,(char *)ppcVar12);
          local_17c = STRING::atol(unaff_ESI);
          local_8._0_1_ = 0x1f;
          FUN_004014d0(local_284);
          ppcVar12 = &param_1_00435c90;
          pSVar6 = (STRING *)STRING::strtok((char *)local_288,(char *)&_Delim_00435c8c);
          local_8._0_1_ = 0x21;
          STRING::trim(pSVar6,(char *)ppcVar12);
          local_180 = STRING::atol(unaff_ESI);
          local_8._0_1_ = 0x1f;
          FUN_004014d0(local_288);
          STRING::trim(local_184,&DAT_00435c98);
          local_188 = STRING::atol(unaff_ESI);
          puVar9 = (undefined4 *)
                   FUN_00425f90(local_294,local_17c,local_180,local_188 / 10 != 0,
                                local_188 % 10 != 0);
          FUN_00423060(local_b4,puVar9);
          local_8 = CONCAT31(local_8._1_3_,6);
          FUN_004014d0((CString *)local_184);
        }
        pCVar4 = (CString *)INIFILE::SECTION::Get(local_144,(char *)local_298);
        local_8._0_1_ = 0x22;
        FUN_004048d0(local_18,pCVar4);
        local_8._0_1_ = 6;
        FUN_004014d0(local_298);
        bVar1 = FUN_00401430((int *)local_18);
        if (CONCAT31(extraout_var_03,bVar1) == 0) {
          ppcVar12 = &param_1_00435cac;
          pSVar6 = (STRING *)STRING::strtok((char *)local_29c,(char *)&_Delim_00435ca8);
          local_8._0_1_ = 0x23;
          STRING::trim(pSVar6,(char *)ppcVar12);
          local_18c = STRING::atol(unaff_ESI);
          local_8._0_1_ = 6;
          FUN_004014d0(local_29c);
          ppcVar12 = &param_1_00435cb8;
          pSVar6 = (STRING *)STRING::strtok((char *)local_2a0,(char *)&_Delim_00435cb4);
          local_8._0_1_ = 0x24;
          STRING::trim(pSVar6,(char *)ppcVar12);
          local_190 = STRING::atol(unaff_ESI);
          local_8._0_1_ = 6;
          FUN_004014d0(local_2a0);
          pSVar6 = STRING::trim((STRING *)local_18,&DAT_00435cc0);
          FUN_00407d70(local_194,(CString *)pSVar6);
          local_8._0_1_ = 0x25;
          local_98 = 0;
          bVar1 = STRING::equi(local_194,s_UPPER_RIGHT_00435cc8);
          if (bVar1) {
            local_98 = 1;
          }
          bVar1 = STRING::equi(local_194,s_UPPER_LEFT_00435cd4);
          if (bVar1) {
            local_98 = 0;
          }
          bVar1 = STRING::equi(local_194,s_LOWER_RIGHT_00435ce0);
          if (bVar1) {
            local_98 = 3;
          }
          bVar1 = STRING::equi(local_194,s_LOWER_LEFT_00435cec);
          if (bVar1) {
            local_98 = 2;
          }
          puVar9 = (undefined4 *)default_error_condition(local_2a8,local_18c,local_190);
          local_11c = *puVar9;
          local_118 = puVar9[1];
          local_90 = 1;
          local_8._0_1_ = 6;
          FUN_004014d0((CString *)local_194);
        }
        local_13c = 0;
        while( true ) {
          pCVar4 = FUN_004251c0(local_2b0,s_BUTTON_d_00435cf8);
          local_8._0_1_ = 0x26;
          FUN_00401470((undefined4 *)pCVar4);
          pCVar4 = (CString *)INIFILE::SECTION::Get(local_144,(char *)local_2b4);
          local_8._0_1_ = 0x27;
          piVar8 = (int *)FUN_004048d0(local_18,pCVar4);
          bVar1 = FUN_00401430(piVar8);
          local_2ac = CONCAT31(local_2ac._1_3_,'\x01' - (CONCAT31(extraout_var_04,bVar1) != 0));
          local_8._0_1_ = 0x26;
          FUN_004014d0(local_2b4);
          local_8._0_1_ = 6;
          FUN_00422f30(local_2b0);
          if ((local_2ac & 0xff) == 0) break;
          FUN_00425df0(&local_1a4);
          ppcVar12 = &param_1_00435d08;
          pSVar6 = (STRING *)STRING::strtok((char *)local_2b8,(char *)&_Delim_00435d04);
          local_8._0_1_ = 0x28;
          pSVar6 = STRING::trim(pSVar6,(char *)ppcVar12);
          FUN_00407d70(local_1a8,(CString *)pSVar6);
          local_8._0_1_ = 0x2a;
          FUN_004014d0(local_2b8);
          bVar1 = STRING::equi(local_1a8,&DAT_00435d10);
          if (bVar1) {
            local_19c = &DAT_00450950;
          }
          bVar1 = STRING::equi(local_1a8,&DAT_00435d18);
          if (bVar1) {
            local_19c = &DAT_0044dda8;
          }
          bVar1 = STRING::equi(local_1a8,&DAT_00435d20);
          if (bVar1) {
            local_19c = &DAT_0044df48;
          }
          bVar1 = STRING::equi(local_1a8,&DAT_00435d28);
          if (bVar1) {
            local_19c = &DAT_0044f518;
          }
          bVar1 = STRING::equi(local_1a8,s_RESTART_00435d2c);
          if (bVar1) {
            local_19c = &DAT_0044f6a0;
          }
          bVar1 = STRING::equi(local_1a8,s_FINISH_00435d34);
          if (bVar1) {
            local_19c = &DAT_0044dc00;
          }
          bVar1 = STRING::equi(local_1a8,&DAT_00435d3c);
          if (bVar1) {
            local_19c = &DAT_0044e248;
          }
          bVar1 = STRING::equi(local_1a8,s_PREVHINT_00435d44);
          if (bVar1) {
            local_19c = &DAT_0044e0c8;
          }
          if (local_19c == (undefined *)0x0) {
            local_8._0_1_ = 6;
            FUN_004014d0((CString *)local_1a8);
          }
          else {
            ppcVar12 = &param_1_00435d54;
            pSVar6 = (STRING *)STRING::strtok((char *)local_2bc,(char *)&_Delim_00435d50);
            local_8._0_1_ = 0x2b;
            pSVar6 = STRING::trim(pSVar6,(char *)ppcVar12);
            FUN_00407d70(local_198,(CString *)pSVar6);
            local_8 = CONCAT31(local_8._1_3_,0x2d);
            FUN_004014d0(local_2bc);
            bVar1 = FUN_00404990(local_198,&DAT_00435d5c);
            if (bVar1) {
              iVar3 = FUN_004132a0((int)local_19c);
              local_1a4 = (local_124 - iVar3) + -5;
              iVar3 = FUN_004132c0((int)local_19c);
              local_1a0 = (local_120 - iVar3) + -5;
            }
            else {
              bVar1 = FUN_00404990(local_198,&DAT_00435d60);
              if (bVar1) {
                local_1a4 = local_12c + 5;
                iVar3 = FUN_004132c0((int)local_19c);
                local_1a0 = (local_120 - iVar3) + -5;
              }
              else {
                bVar1 = FUN_00404990(local_198,&DAT_00435d64);
                if (bVar1) {
                  iVar3 = local_124 + local_12c;
                  uVar10 = FUN_004132a0((int)local_19c);
                  local_1a4 = iVar3 / 2 - (uVar10 >> 1);
                  iVar3 = FUN_004132c0((int)local_19c);
                  local_1a0 = (local_120 - iVar3) + -5;
                }
              }
            }
            if (local_19c != (undefined *)0x0) {
              FUN_00422fd0(local_108,&local_1a4);
            }
            local_8._0_1_ = 0x2a;
            FUN_004014d0(local_198);
            local_8._0_1_ = 6;
            FUN_004014d0((CString *)local_1a8);
          }
          local_13c = local_13c + 1;
        }
        pCVar4 = (CString *)INIFILE::SECTION::Get(local_144,(char *)local_2c0);
        local_8._0_1_ = 0x2e;
        FUN_004048d0(local_18,pCVar4);
        local_8 = CONCAT31(local_8._1_3_,6);
        FUN_004014d0(local_2c0);
        while (bVar1 = FUN_00401430((int *)local_18), CONCAT31(extraout_var_05,bVar1) == 0) {
          ppcVar12 = &param_1_00435d74;
          pSVar6 = (STRING *)STRING::strtok((char *)local_2c4,(char *)&_Delim_00435d70);
          local_8._0_1_ = 0x2f;
          pSVar6 = STRING::trim(pSVar6,(char *)ppcVar12);
          FUN_00407d70(local_1c0,(CString *)pSVar6);
          local_8._0_1_ = 0x31;
          FUN_004014d0(local_2c4);
          FUN_00425380(&local_1b8);
          ppcVar12 = &param_1_00435d80;
          pSVar6 = (STRING *)STRING::strtok((char *)local_2c8,(char *)&_Delim_00435d7c);
          local_8._0_1_ = 0x32;
          STRING::trim(pSVar6,(char *)ppcVar12);
          lVar7 = STRING::atol(unaff_ESI);
          local_1b8 = lVar7 * 0x20 + 8;
          local_8._0_1_ = 0x31;
          FUN_004014d0(local_2c8);
          ppcVar12 = &param_1_00435d8c;
          pSVar6 = (STRING *)STRING::strtok((char *)local_2cc,(char *)&_Delim_00435d88);
          local_8._0_1_ = 0x33;
          STRING::trim(pSVar6,(char *)ppcVar12);
          lVar7 = STRING::atol(unaff_ESI);
          local_1b4 = lVar7 * 0x20 + 8;
          local_8._0_1_ = 0x31;
          FUN_004014d0(local_2cc);
          ppcVar12 = &param_1_00435d98;
          pSVar6 = (STRING *)STRING::strtok((char *)local_2d0,(char *)&_Delim_00435d94);
          local_8._0_1_ = 0x34;
          pSVar6 = STRING::trim(pSVar6,(char *)ppcVar12);
          FUN_00407d70(local_1bc,(CString *)pSVar6);
          local_8._0_1_ = 0x36;
          FUN_004014d0(local_2d0);
          lVar7 = STRING::atol(unaff_ESI);
          local_1b0 = '\x01' - (lVar7 != 1);
          lVar7 = STRING::atol(unaff_ESI);
          local_1af = lVar7 == 2;
          ppcVar12 = &param_1_00435da4;
          pSVar6 = (STRING *)STRING::strtok((char *)local_2d4,(char *)&_Delim_00435da0);
          local_8._0_1_ = 0x37;
          STRING::trim(pSVar6,(char *)ppcVar12);
          local_1ac = STRING::atol(unaff_ESI);
          local_8._0_1_ = 0x36;
          FUN_004014d0(local_2d4);
          FUN_004230f0(local_78,&local_1b8);
          local_8._0_1_ = 0x31;
          FUN_004014d0(local_1bc);
          local_8 = CONCAT31(local_8._1_3_,6);
          FUN_004014d0(local_1c0);
        }
        pCVar4 = (CString *)INIFILE::SECTION::Get(local_144,(char *)local_2d8);
        local_8._0_1_ = 0x38;
        FUN_004048d0(local_18,pCVar4);
        local_8 = CONCAT31(local_8._1_3_,6);
        FUN_004014d0(local_2d8);
        bVar1 = FUN_00401430((int *)local_18);
        if ((CONCAT31(extraout_var_06,bVar1) == 0) &&
           (bVar1 = FUN_00401430((int *)local_134), CONCAT31(extraout_var_07,bVar1) != 0)) {
          CString::operator=(local_134,s_SORRY__BUT_YOU_DIDN_T_GET_IT__HI_00435db0);
        }
        while (bVar1 = FUN_00401430((int *)local_18), CONCAT31(extraout_var_08,bVar1) == 0) {
          ppcVar12 = &param_1_00435e14;
          pSVar6 = (STRING *)STRING::strtok((char *)local_2dc,(char *)&_Delim_00435e10);
          local_8._0_1_ = 0x39;
          pSVar6 = STRING::trim(pSVar6,(char *)ppcVar12);
          FUN_00407d70(local_1c4,(CString *)pSVar6);
          local_8._0_1_ = 0x3b;
          FUN_004014d0(local_2dc);
          STRING::strtok((char *)local_1c8,(char *)&_Delim_00435e1c);
          local_8._0_1_ = 0x3c;
          bVar1 = STRING::equi(local_1c8,(char *)&this_00435e20);
          if (bVar1) {
            FUN_00405850(&local_1d8);
            ppcVar12 = &param_1_00435e2c;
            pSVar6 = (STRING *)STRING::strtok((char *)local_2e0,(char *)&_Delim_00435e28);
            local_8._0_1_ = 0x3d;
            STRING::trim(pSVar6,(char *)ppcVar12);
            local_1d8 = STRING::atol(unaff_ESI);
            local_8._0_1_ = 0x3c;
            FUN_004014d0(local_2e0);
            ppcVar12 = &param_1_00435e38;
            pSVar6 = (STRING *)STRING::strtok((char *)local_2e4,(char *)&_Delim_00435e34);
            local_8._0_1_ = 0x3e;
            STRING::trim(pSVar6,(char *)ppcVar12);
            local_1d4 = STRING::atol(unaff_ESI);
            local_8._0_1_ = 0x3c;
            FUN_004014d0(local_2e4);
            STRING::strtok((char *)local_2e8,(char *)&_Delim_00435e40);
            FUN_004014d0(local_2e8);
            FUN_00405850(&local_1d0);
            ppcVar12 = &param_1_00435e48;
            pSVar6 = (STRING *)STRING::strtok((char *)local_2ec,(char *)&_Delim_00435e44);
            local_8._0_1_ = 0x3f;
            STRING::trim(pSVar6,(char *)ppcVar12);
            local_1d0 = STRING::atol(unaff_ESI);
            local_8._0_1_ = 0x3c;
            FUN_004014d0(local_2ec);
            ppcVar12 = &param_1_00435e54;
            pSVar6 = (STRING *)STRING::strtok((char *)local_2f0,(char *)&_Delim_00435e50);
            local_8._0_1_ = 0x40;
            STRING::trim(pSVar6,(char *)ppcVar12);
            local_1cc = STRING::atol(unaff_ESI);
            local_8._0_1_ = 0x3c;
            FUN_004014d0(local_2f0);
            pSVar6 = STRING::trim(local_1c4,&DAT_00435e5c);
            iVar3 = FUN_0040fd90((int *)pSVar6);
            if (iVar3 < 3) {
              local_368 = operator_new(0x18);
              local_8._0_1_ = 0x4d;
              if (local_368 == (void *)0x0) {
                local_518 = (void *)0x0;
              }
              else {
                local_518 = FUN_004253a0(local_368,&local_1d0);
              }
              local_364 = local_518;
              local_8._0_1_ = 0x3c;
              puVar9 = (undefined4 *)FUN_00425da0(local_360,&local_1d8,local_518);
              local_8._0_1_ = 0x4e;
              FUN_00423240(local_5c,puVar9);
              local_8._0_1_ = 0x3c;
              CDHtmlElementEventSink::~CDHtmlElementEventSink(local_360);
            }
            else {
              pcVar5 = (char *)0x1;
              pCVar4 = (CString *)CString::Mid((CString *)local_1c4,(int)local_2f4);
              local_8._0_1_ = 0x41;
              FUN_00405680(local_1e0,pCVar4);
              local_8._0_1_ = 0x43;
              CString::~CString(local_2f4);
              ppcVar12 = &param_1_00435e68;
              pSVar6 = (STRING *)STRING::strtok((char *)local_2f8,(char *)&_Delim_00435e64);
              local_8._0_1_ = 0x44;
              STRING::trim(pSVar6,(char *)ppcVar12);
              local_1dc = STRING::atol(pcVar5);
              local_8._0_1_ = 0x43;
              FUN_004014d0(local_2f8);
              cVar2 = STRING::first(local_1c4);
              if ((cVar2 == 'D') && (local_1dc < 9)) {
                local_30c = operator_new(0x20);
                local_8._0_1_ = 0x45;
                if (local_30c == (void *)0x0) {
                  local_4e8 = (void *)0x0;
                }
                else {
                  FUN_00425220(&local_310,local_1dc << 1);
                  local_4e8 = FUN_00425720(local_30c,&local_1d0,&local_310);
                }
                local_308 = local_4e8;
                local_8._0_1_ = 0x43;
                puVar9 = (undefined4 *)FUN_00425da0(local_304,&local_1d8,local_4e8);
                local_8._0_1_ = 0x46;
                FUN_00423240(local_5c,puVar9);
                local_8._0_1_ = 0x43;
                CDHtmlElementEventSink::~CDHtmlElementEventSink(local_304);
              }
              else {
                cVar2 = STRING::first(local_1c4);
                if ((cVar2 == 'D') && (9 < local_1dc)) {
                  local_1e8 = local_1dc / 10;
                  local_1e4 = local_1dc % 10;
                  local_324 = operator_new(0x50);
                  local_8._0_1_ = 0x47;
                  if (local_324 == (void *)0x0) {
                    local_4f4 = (void *)0x0;
                  }
                  else {
                    FUN_00425220(&local_328,local_1e8);
                    FUN_00425220(&local_32c,local_1e4);
                    local_4f4 = FUN_00425880(local_324,&local_1d0,&local_32c,&local_328);
                  }
                  local_320 = local_4f4;
                  local_8._0_1_ = 0x43;
                  puVar9 = (undefined4 *)FUN_00425da0(local_31c,&local_1d8,local_4f4);
                  local_8._0_1_ = 0x48;
                  FUN_00423240(local_5c,puVar9);
                  local_8._0_1_ = 0x43;
                  CDHtmlElementEventSink::~CDHtmlElementEventSink(local_31c);
                }
                else {
                  cVar2 = STRING::first(local_1c4);
                  if ((cVar2 == 'R') && (local_1dc < 9)) {
                    local_340 = operator_new(0x24);
                    local_8._0_1_ = 0x49;
                    if (local_340 == (void *)0x0) {
                      local_500 = (void *)0x0;
                    }
                    else {
                      local_500 = FUN_00425a30(local_340,&local_1d0,local_1dc);
                    }
                    local_33c = local_500;
                    local_8._0_1_ = 0x43;
                    puVar9 = (undefined4 *)FUN_00425da0(local_338,&local_1d8,local_500);
                    local_8._0_1_ = 0x4a;
                    FUN_00423240(local_5c,puVar9);
                    local_8._0_1_ = 0x43;
                    CDHtmlElementEventSink::~CDHtmlElementEventSink(local_338);
                  }
                  else {
                    cVar2 = STRING::first(local_1c4);
                    if ((cVar2 == 'R') && (9 < local_1dc)) {
                      local_1f0 = local_1dc / 10;
                      local_1ec = local_1dc % 10;
                      local_354 = operator_new(0x58);
                      local_8._0_1_ = 0x4b;
                      if (local_354 == (void *)0x0) {
                        local_50c = (void *)0x0;
                      }
                      else {
                        local_50c = FUN_00425b60(local_354,&local_1d0,local_1ec,local_1f0);
                      }
                      local_350 = local_50c;
                      local_8._0_1_ = 0x43;
                      puVar9 = (undefined4 *)FUN_00425da0(local_34c,&local_1d8,local_50c);
                      local_8._0_1_ = 0x4c;
                      FUN_00423240(local_5c,puVar9);
                      local_8._0_1_ = 0x43;
                      CDHtmlElementEventSink::~CDHtmlElementEventSink(local_34c);
                    }
                  }
                }
              }
              local_8._0_1_ = 0x3c;
              FUN_004014d0(local_1e0);
            }
          }
          else {
            bVar1 = FUN_00404990(local_1c8,&DAT_00435e70);
            if (bVar1) {
              FUN_00405850(&local_1f8);
              ppcVar12 = &param_1_00435e7c;
              pSVar6 = (STRING *)STRING::strtok((char *)local_36c,(char *)&_Delim_00435e78);
              local_8._0_1_ = 0x4f;
              STRING::trim(pSVar6,(char *)ppcVar12);
              local_1f8 = STRING::atol(unaff_ESI);
              local_8._0_1_ = 0x3c;
              FUN_004014d0(local_36c);
              STRING::trim(local_1c4,&DAT_00435e84);
              local_1f4 = STRING::atol(unaff_ESI);
              local_1fc = MAP::GetItem((MAP *)(param_1 + 0xe23c),local_1f8,local_1f4);
              this_00 = operator_new(0x10);
              local_8._0_1_ = 0x50;
              if (this_00 == (void *)0x0) {
                local_52c = (void *)0x0;
              }
              else {
                local_52c = FUN_00425c80(this_00,&local_1f8);
              }
              local_8._0_1_ = 0x3c;
              puVar9 = (undefined4 *)FUN_00425da0(local_378,&local_1f8,local_52c);
              local_8._0_1_ = 0x51;
              FUN_00423240(local_5c,puVar9);
              local_8._0_1_ = 0x3c;
              CDHtmlElementEventSink::~CDHtmlElementEventSink(local_378);
            }
          }
          local_8._0_1_ = 0x3b;
          FUN_004014d0((CString *)local_1c8);
          local_8 = CONCAT31(local_8._1_3_,6);
          FUN_004014d0((CString *)local_1c4);
        }
        INIFILE::SECTION::Get(local_144,s_RETRY_00435e8c,&local_8c);
        INIFILE::SECTION::Get(local_144,s_SKIPONBACK_00435e94,&local_88);
        INIFILE::SECTION::Get(local_144,s_SYSCOMPLETE_00435ea0,&local_84);
        INIFILE::SECTION::Get(local_144,s_RESTORE_00435eac,&local_80);
        INIFILE::SECTION::Get(local_144,s_IGNORERESET_00435eb4,&local_7c);
        FUN_004232d0(&DAT_0044dd88,local_138);
        local_8._0_1_ = 5;
        FUN_00407d90((int)local_144);
        local_8._0_1_ = 4;
        FUN_00422e70(local_138);
      }
      local_8._0_1_ = 2;
      FUN_004014d0(local_18);
      local_8 = (uint)local_8._1_3_ << 8;
      INIFILE::~INIFILE(local_40);
      local_8 = 0xffffffff;
      CString::~CString(local_14);
    }
  }
  else {
    ExceptionList = &local_10;
    FUN_0042128c();
  }
  ExceptionList = local_10;
  return;
}



void FUN_0042128c(void)

{
  FUN_00423290(&DAT_0044dd88,&DAT_0044f4f8);
  DAT_00450acc = DAT_00450ad0;
  FUN_00423c80(0x44f4f8);
  DAT_00450ad0 = 0;
  return;
}



void __fastcall FUN_004212be(int param_1)

{
  SPRITE::Hide((SPRITE *)&DAT_0044e3c8);
  SPRITE::Hide((SPRITE *)&DAT_0044f820);
  (**(code **)(*(int *)(param_1 + 0x154) + 0x20))();
  MAP::RefreshBothLevelmapBuffers((MAP *)(param_1 + 0xe23c));
  return;
}



void __thiscall FUN_00421303(void *this,int param_1)

{
  int iVar1;
  
  if (param_1 == 0xb) {
    iVar1 = FUN_00423620(0x44dd88);
    DAT_00450acc = iVar1 + -1;
  }
  if ((param_1 == 2) || (param_1 == 0xd)) {
    DAT_00450ad0 = 0;
    DAT_00450ad4 = '\0';
  }
  if ((param_1 == 10) && (DAT_00450ad4 != '\0')) {
    FUN_00421393();
    GAME::ChangeState((GAME *)this,6);
    DAT_00450ad4 = '\0';
    FUN_00417f6e((int *)this);
    MAP::RefreshBothLevelmapBuffers((MAP *)((int)this + 0xe23c));
    FUN_004217c5((int)this);
    DAT_00450ad5 = 1;
  }
  return;
}



void FUN_00421393(void)

{
  FUN_00423290(&DAT_0044f4f8,&DAT_0044dd88);
  DAT_00450ad0 = DAT_00450acc;
  return;
}



undefined4 __fastcall FUN_004213b1(int param_1)

{
  bool bVar1;
  int iVar2;
  
  iVar2 = MAP::HasScript((MAP *)(param_1 + 0xe23c));
  if (((iVar2 != 0) && (bVar1 = FUN_0040e0e0(param_1), !bVar1)) &&
     (((iVar2 = FUN_004056c0(param_1), iVar2 == 6 ||
       (((iVar2 = FUN_004056c0(param_1), iVar2 == 0xb ||
         (iVar2 = FUN_004056c0(param_1), iVar2 == 0xc)) ||
        (iVar2 = FUN_004056c0(param_1), iVar2 == 7)))) ||
      (iVar2 = FUN_004056c0(param_1), iVar2 == 10)))) {
    return 1;
  }
  return 0;
}



undefined4 __fastcall FUN_00421436(int param_1)

{
  int iVar1;
  undefined4 local_c;
  
  iVar1 = FUN_004213b1(param_1);
  if ((iVar1 == 0) || (DAT_00450ad8 == 0)) {
    local_c = 0;
  }
  else {
    local_c = 1;
  }
  return local_c;
}



void __fastcall FUN_0042146b(int param_1)

{
  bool bVar1;
  bool bVar2;
  undefined3 extraout_var;
  undefined4 *puVar3;
  uint uVar4;
  undefined3 extraout_var_00;
  ITEM *pIVar5;
  int *piVar6;
  CDHtmlElementEventSink local_40 [12];
  CDHtmlElementEventSink local_34 [12];
  int local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  CString *local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042ae7f;
  local_10 = ExceptionList;
  bVar1 = false;
  if ((DAT_00450ad4 == '\0') &&
     ((ExceptionList = &local_10, DAT_00450ad5 == '\0' ||
      (ExceptionList = &local_10, bVar2 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044f518), bVar2
      )))) {
    DAT_00450ad5 = '\0';
    local_18 = FUN_004232f0(&DAT_0044dd88,DAT_00450acc);
    local_28 = FUN_00423770((int)(local_18 + 0xdc));
    FUN_00425d20(&local_24);
    local_8 = 0;
    local_14 = 0;
    bVar2 = IsEmpty((int)(local_18 + 0xdc));
    if (CONCAT31(extraout_var,bVar2) == 0) {
      puVar3 = (undefined4 *)FUN_00423b30(local_34,&local_28);
      local_8._0_1_ = 1;
      FUN_00422f70(&local_24,puVar3);
      local_8 = (uint)local_8._1_3_ << 8;
      CDHtmlElementEventSink::~CDHtmlElementEventSink(local_34);
    }
    local_14 = 0;
    while ((uVar4 = FUN_00423620((int)(local_18 + 0xdc)), local_14 < uVar4 &&
           (bVar2 = IsEmpty((int)(local_18 + 0xdc)), CONCAT31(extraout_var_00,bVar2) == 0))) {
      pIVar5 = MAP::GetItem((MAP *)(param_1 + 0xe23c),local_24,local_20);
      piVar6 = (int *)FUN_00401470(&local_1c);
      (**(code **)(*piVar6 + 4))(pIVar5);
      local_14 = local_14 + 1;
      uVar4 = FUN_00423620((int)(local_18 + 0xdc));
      if (local_14 < uVar4) {
        puVar3 = (undefined4 *)FUN_00423b30(local_40,&local_28);
        bVar1 = true;
        local_8 = CONCAT31(local_8._1_3_,2);
        FUN_00422f70(&local_24,puVar3);
      }
      local_8 = 0;
      if (bVar1) {
        bVar1 = false;
        CDHtmlElementEventSink::~CDHtmlElementEventSink(local_40);
      }
    }
    DAT_00450ad4 = '\x01';
    DAT_00450adc = 0;
    MAP::RefreshBothLevelmapBuffers((MAP *)(param_1 + 0xe23c));
    local_8 = 0xffffffff;
    CDHtmlElementEventSink::~CDHtmlElementEventSink((CDHtmlElementEventSink *)&local_24);
  }
  ExceptionList = local_10;
  return;
}



undefined4 __fastcall FUN_0042167f(int param_1)

{
  bool bVar1;
  int iVar2;
  undefined4 uVar3;
  CString *this;
  uint uVar4;
  
  iVar2 = FUN_004213b1(param_1);
  if (iVar2 == 0) {
    uVar3 = 0;
  }
  else {
    this = FUN_004232f0(&DAT_0044dd88,DAT_00450acc);
    uVar4 = CMFCOutlookBarPane::IsBackgroundTexture((CMFCOutlookBarPane *)this);
    if (((uVar4 & 0xff) == 0) || (DAT_00450ad5 != '\0')) {
      bVar1 = FUN_004216f4();
      if (bVar1) {
        uVar3 = 0;
      }
      else if (DAT_00450ad8 == 0) {
        uVar3 = 1;
      }
      else {
        uVar3 = 0;
      }
    }
    else {
      uVar3 = 0;
    }
  }
  return uVar3;
}



bool FUN_004216f4(void)

{
  int iVar1;
  
  iVar1 = FUN_00423620(0x44df28);
  return iVar1 != 0;
}



void __fastcall FUN_00421709(int param_1)

{
  undefined4 uVar1;
  CString CVar2;
  CString *pCVar3;
  undefined4 *puVar4;
  CString local_18 [4];
  CString *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &param_1_0042ae92;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_14 = FUN_004232f0(&DAT_0044dd88,DAT_00450acc);
  pCVar3 = (CString *)MAP::Data((MAP *)(param_1 + 0xe23c));
  local_8 = 0;
  CString::operator=(local_14 + 8,pCVar3);
  local_8 = 0xffffffff;
  FUN_004014d0(local_18);
  puVar4 = (undefined4 *)OVERLAY::Position((OVERLAY *)(param_1 + 0x228));
  uVar1 = puVar4[1];
  *(undefined4 *)(local_14 + 0x24) = *puVar4;
  *(undefined4 *)(local_14 + 0x28) = uVar1;
  CVar2 = (CString)(**(code **)(*(int *)(param_1 + 0x228) + 0x18))();
  local_14[0x2c] = CVar2;
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_004217c5(int param_1)

{
  undefined4 uVar1;
  CString *pCVar2;
  int iVar3;
  
  pCVar2 = FUN_004232f0(&DAT_0044dd88,DAT_00450acc);
  iVar3 = FUN_0040fd90((int *)(pCVar2 + 8));
  if (iVar3 != 0) {
    MAP::Set((MAP *)(param_1 + 0xe23c),pCVar2 + 8);
  }
  if (*(int *)(pCVar2 + 0xa8) != 0) {
    FUN_00421890();
  }
  if (DAT_00450acc != 0) {
    (**(code **)(*(int *)(param_1 + 0x228) + 0x28))(pCVar2 + 0x24);
    uVar1 = *(undefined4 *)(pCVar2 + 0x28);
    *(undefined4 *)(param_1 + 0xe01c) = *(undefined4 *)(pCVar2 + 0x24);
    *(undefined4 *)(param_1 + 0xe020) = uVar1;
  }
  if (pCVar2[0x2c] == (CString)0x0) {
    (**(code **)(*(int *)(param_1 + 0x228) + 0x20))();
  }
  MAP::RefreshBothLevelmapBuffers((MAP *)(param_1 + 0xe23c));
  FUN_00426d40(param_1);
  return;
}



void FUN_00421890(void)

{
  int iVar1;
  
  SPRITE::Show((SPRITE *)&DAT_0044e3c8);
  iVar1 = OVERLAY::Position((OVERLAY *)&DAT_0044f820);
  if ((int)(*(int *)(iVar1 + 4) + (*(int *)(iVar1 + 4) >> 0x1f & 0x1fU)) >> 5 < 0xd) {
    SPRITE::Show((SPRITE *)&DAT_0044f820);
  }
  return;
}



void __fastcall FUN_004218d0(GAME *param_1)

{
  bool bVar1;
  undefined1 *this;
  undefined4 *puVar2;
  undefined3 extraout_var;
  uint uVar3;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  ITEM *pIVar4;
  undefined3 extraout_var_03;
  undefined3 extraout_var_04;
  undefined1 *puVar5;
  int iVar6;
  undefined4 uVar7;
  undefined4 *local_d4;
  undefined4 local_b4 [3];
  undefined4 local_a8 [3];
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90 [3];
  undefined4 local_84 [3];
  undefined4 local_78 [4];
  undefined4 local_68 [4];
  undefined1 local_58 [8];
  undefined1 local_50 [8];
  uint local_48;
  uint local_44;
  CString *local_40;
  undefined4 local_3c;
  undefined4 local_38;
  int local_34;
  int local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  int local_20;
  uint local_1c;
  int local_18;
  int local_14;
  undefined4 local_10;
  undefined4 local_c;
  uint local_8;
  
  local_40 = FUN_004232f0(&DAT_0044dd88,DAT_00450acc);
  if (*(int *)(local_40 + 0xb8) != 0) {
    MAP::Set((MAP *)(param_1 + 0xe23c),(CString *)&DAT_0044dda4);
    iVar6 = 0x20;
    puVar5 = local_58;
    this = local_50;
    FUN_00413eee(param_1,this);
    puVar2 = (undefined4 *)FUN_0040fe80(this,puVar5,iVar6);
    FUN_0040f6ea(param_1,puVar2);
    FUN_00426d40((int)param_1);
  }
  local_20 = FUN_00423770((int)(local_40 + 0x68));
  FUN_00425ef0(&local_3c);
  local_1c = 0;
  bVar1 = IsEmpty((int)(local_40 + 0x68));
  if (CONCAT31(extraout_var,bVar1) == 0) {
    puVar2 = FUN_004236b0(local_68,&local_20);
    local_3c = *puVar2;
    local_38 = puVar2[1];
    local_34 = puVar2[2];
    local_30 = puVar2[3];
  }
  local_1c = 0;
  while ((uVar3 = FUN_00423620((int)(local_40 + 0x68)), local_1c < uVar3 &&
         (bVar1 = IsEmpty((int)(local_40 + 0x68)), CONCAT31(extraout_var_00,bVar1) == 0))) {
    MAP::SelectTile((MAP *)(param_1 + 0xe23c),local_3c,local_38);
    MAP::SwapTile((MAP *)(param_1 + 0xe23c),local_34,local_30);
    (**(code **)(*(int *)(param_1 + 0x228) + 0x2c))(local_34 << 5,local_30 << 5);
    local_1c = local_1c + 1;
    uVar3 = FUN_00423620((int)(local_40 + 0x68));
    if (local_1c < uVar3) {
      puVar2 = FUN_004236b0(local_78,&local_20);
      local_3c = *puVar2;
      local_38 = puVar2[1];
      local_34 = puVar2[2];
      local_30 = puVar2[3];
    }
  }
  local_14 = FUN_00423770((int)(local_40 + 0x4c));
  Concurrency::details::SafeSQueue<>::SafeSQueue<>((SafeSQueue<> *)&local_2c);
  local_48 = 0;
  bVar1 = IsEmpty((int)(local_40 + 0x4c));
  if (CONCAT31(extraout_var_01,bVar1) == 0) {
    puVar2 = FUN_004235e0(local_84,&local_14);
    local_2c = *puVar2;
    local_28 = puVar2[1];
    local_24 = puVar2[2];
  }
  local_48 = 0;
  while ((uVar3 = FUN_00423620((int)(local_40 + 0x4c)), local_48 < uVar3 &&
         (bVar1 = IsEmpty((int)(local_40 + 0x4c)), CONCAT31(extraout_var_02,bVar1) == 0))) {
    if (&stack0x00000000 == &DAT_0000002c) {
      local_d4 = (undefined4 *)0x0;
    }
    else {
      local_d4 = &local_24;
    }
    uVar7 = *local_d4;
    local_98 = local_2c;
    local_94 = local_28;
    local_9c = uVar7;
    pIVar4 = MAP::GetItem((MAP *)(param_1 + 0xe23c),local_2c,local_28);
    (**(code **)(*(int *)pIVar4 + 0x18))(uVar7);
    local_48 = local_48 + 1;
    uVar3 = FUN_00423620((int)(local_40 + 0x4c));
    if (local_48 < uVar3) {
      puVar2 = FUN_004235e0(local_90,&local_14);
      local_2c = *puVar2;
      local_28 = puVar2[1];
      local_24 = puVar2[2];
    }
  }
  local_18 = FUN_00423770((int)(local_40 + 0x84));
  FUN_00425f60(&local_10);
  local_44 = 0;
  bVar1 = IsEmpty((int)(local_40 + 0x84));
  if (CONCAT31(extraout_var_03,bVar1) == 0) {
    puVar2 = FUN_00423790(local_a8,&local_18);
    local_10 = *puVar2;
    local_c = puVar2[1];
    local_8 = puVar2[2];
  }
  local_44 = 0;
  while ((uVar3 = FUN_00423620((int)(local_40 + 0x84)), local_44 < uVar3 &&
         (bVar1 = IsEmpty((int)(local_40 + 0x84)), CONCAT31(extraout_var_04,bVar1) == 0))) {
    uVar3 = (uint)((local_8 >> 8 & 0xff) == 0);
    pIVar4 = MAP::GetItem((MAP *)(param_1 + 0xe23c),local_10,local_c);
    (**(code **)(*(int *)pIVar4 + 0x3c))(uVar3);
    uVar3 = (uint)((local_8 & 0xff) == 0);
    pIVar4 = MAP::GetItem((MAP *)(param_1 + 0xe23c),local_10,local_c);
    (**(code **)(*(int *)pIVar4 + 0x40))(uVar3);
    local_44 = local_44 + 1;
    uVar3 = FUN_00423620((int)(local_40 + 0x84));
    if (local_44 < uVar3) {
      puVar2 = FUN_00423790(local_b4,&local_18);
      local_10 = *puVar2;
      local_c = puVar2[1];
      local_8 = puVar2[2];
    }
  }
  if ((*(int *)(local_40 + 0xbc) == 0) || (uVar3 = FUN_00423620(0x44dd88), uVar3 <= DAT_00450acc)) {
    DAT_00450ad0 = 0;
  }
  else {
    FUN_00421393();
  }
  if (*(int *)(local_40 + 0xb4) != 0) {
    GAME::ChangeState(param_1,0xb);
  }
  return;
}



void __fastcall FUN_00421dbb(GAME *param_1)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  
  DAT_00450ad5 = 0;
  iVar2 = FUN_00423620(0x44dd88);
  if (iVar2 != 0) {
    iVar2 = FUN_00423620(0x44dd88);
    if (DAT_00450acc < iVar2 - 1U) {
      DAT_00450acc = DAT_00450acc + 1;
      FUN_004218d0(param_1);
      FUN_00421709((int)param_1);
      MAP::RefreshBothLevelmapBuffers((MAP *)(param_1 + 0xe23c));
      FUN_00417f6e((int *)param_1);
    }
    puVar3 = (undefined4 *)OVERLAY::Position((OVERLAY *)(param_1 + 0x228));
    uVar1 = puVar3[1];
    *(undefined4 *)(param_1 + 0xe01c) = *puVar3;
    *(undefined4 *)(param_1 + 0xe020) = uVar1;
    if (DAT_00450ad8 == 0) {
      FUN_00426d40((int)param_1);
    }
  }
  return;
}



void __fastcall FUN_00421e6b(int *param_1)

{
  int iVar1;
  CString *pCVar2;
  int *piVar3;
  
  DAT_00450ad5 = 0;
  if (DAT_00450acc != 0) {
    DAT_00450acc = DAT_00450acc - 1;
    pCVar2 = FUN_004232f0(&DAT_0044dd88,DAT_00450acc);
    if ((*(int *)(pCVar2 + 0xb0) != 0) && (DAT_00450acc != 0)) {
      FUN_00421e6b(param_1);
      return;
    }
    if (DAT_00450ad8 == 0) {
      FUN_004217c5((int)param_1);
    }
    else {
      MAP::RefreshBothLevelmapBuffers((MAP *)(param_1 + 0x388f));
    }
    FUN_00417f6e(param_1);
  }
  piVar3 = (int *)OVERLAY::Position((OVERLAY *)(param_1 + 0x8a));
  iVar1 = piVar3[1];
  param_1[0x3807] = *piVar3;
  param_1[0x3808] = iVar1;
  return;
}



void __fastcall FUN_00421f19(int param_1)

{
  bool bVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  undefined3 extraout_var;
  uint uVar4;
  undefined3 extraout_var_00;
  CPosition *pCVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  CString *local_68;
  undefined1 local_60 [8];
  undefined4 local_58 [3];
  undefined4 local_4c [3];
  undefined4 local_40 [4];
  CString *local_30;
  int local_2c;
  int local_28;
  int local_24;
  uint local_20;
  undefined4 local_1c;
  undefined4 local_18;
  int *local_14;
  CString *local_10;
  CString *local_c;
  ulong local_8;
  
  local_10 = FUN_004232f0(&DAT_0044dd88,DAT_00450acc);
  bVar1 = FUN_004216f4();
  if ((!bVar1) && (DAT_00450ad4 == '\0')) {
    SPRITE::Hide((SPRITE *)&DAT_0044e3c8);
    SPRITE::Hide((SPRITE *)&DAT_0044f820);
    local_8 = (-(uint)(DAT_00450ad5 != '\0') & 0xff0001ff) + 0xffff00;
    if (DAT_00450ad5 == '\0') {
      local_68 = local_10;
    }
    else {
      local_68 = local_10 + 4;
    }
    local_30 = local_68;
    local_c = local_68;
    FUN_00413daa(*(int *)(local_10 + 0xc),*(int *)(local_10 + 0x10),*(int *)(local_10 + 0x14),
                 *(int *)(local_10 + 0x18),local_8);
    uVar10 = 0;
    puVar2 = FUN_00426bd0(local_10,local_40);
    uVar6 = *puVar2;
    uVar7 = puVar2[1];
    uVar8 = puVar2[2];
    uVar9 = puVar2[3];
    uVar3 = FUN_00401470((undefined4 *)local_c);
    FONT::WrapText((FONT *)(param_1 + 0x4c5c),uVar3,uVar6,uVar7,uVar8,uVar9,uVar10);
    FUN_0040b710(0x450950);
    FUN_0040c710(0x450950);
    FUN_0040b710(0x44dda8);
    FUN_0040c710(0x44dda8);
    FUN_0040b710(0x44df48);
    FUN_0040c710(0x44df48);
    FUN_0040b710(0x44dc00);
    FUN_0040c710(0x44dc00);
    FUN_0040b710(0x44f6a0);
    FUN_0040c710(0x44f6a0);
    FUN_0040b710(0x44e248);
    FUN_0040c710(0x44e248);
    FUN_0040b710(0x44e0c8);
    FUN_0040c710(0x44e0c8);
    FUN_0040b710(0x44f518);
    FUN_0040c710(0x44f518);
    local_24 = FUN_00423770((int)(local_10 + 0x30));
    FUN_00425df0(&local_1c);
    local_20 = 0;
    bVar1 = IsEmpty((int)(local_10 + 0x30));
    if (CONCAT31(extraout_var,bVar1) == 0) {
      puVar2 = FUN_004235e0(local_4c,&local_24);
      local_1c = *puVar2;
      local_18 = puVar2[1];
      local_14 = (int *)puVar2[2];
    }
    local_20 = 0;
    while ((uVar4 = FUN_00423620((int)(local_10 + 0x30)), local_20 < uVar4 &&
           (bVar1 = IsEmpty((int)(local_10 + 0x30)), CONCAT31(extraout_var_00,bVar1) == 0))) {
      (**(code **)(*local_14 + 0x28))(&local_1c);
      (**(code **)(*local_14 + 0x1c))();
      (**(code **)(*local_14 + 0x14))();
      local_20 = local_20 + 1;
      uVar4 = FUN_00423620((int)(local_10 + 0x30));
      if (local_20 < uVar4) {
        puVar2 = FUN_004235e0(local_58,&local_24);
        local_1c = *puVar2;
        local_18 = puVar2[1];
        local_14 = (int *)puVar2[2];
      }
    }
    if (*(int *)(local_10 + 0xa8) != 0) {
      local_2c = 0;
      local_28 = 0;
      SPRITE::SetCurrentImage((SPRITE *)&DAT_0044e3c8,*(uint *)(local_10 + 0xa0));
      switch(*(undefined4 *)(local_10 + 0xa0)) {
      case 0:
        local_2c = 1;
        local_28 = 1;
        break;
      case 1:
        local_2c = -2;
        local_28 = 1;
        break;
      case 2:
        local_2c = 1;
        local_28 = -2;
        break;
      case 3:
        local_2c = -2;
        local_28 = -2;
      }
      SPRITE::SetPosition((SPRITE *)&DAT_0044e3c8,(*(int *)(local_10 + 0x1c) + local_2c) * 0x20,
                          (*(int *)(local_10 + 0x20) + local_28) * 0x20);
      pCVar5 = (CPosition *)FUN_0040fe80(local_10 + 0x1c,local_60,0x20);
      SPRITE::SetPosition((SPRITE *)&DAT_0044f820,pCVar5);
      FUN_00421890();
    }
  }
  return;
}



void __fastcall FUN_00422295(GAME *param_1)

{
  bool bVar1;
  int iVar2;
  void *pvVar3;
  undefined4 *puVar4;
  uint uVar5;
  int *piVar6;
  undefined4 uVar7;
  int iVar8;
  undefined4 uVar9;
  undefined1 local_74 [12];
  undefined4 local_68 [12];
  int local_38;
  int local_34;
  CString *local_10;
  uint local_c;
  uint local_8;
  
  if ((DAT_00450ae0 == '\0') && (iVar2 = FUN_00423620(0x44df28), iVar2 != 0)) {
    GKERNEL::IgnoreUserInput(true);
    pvVar3 = FUN_00423110(&DAT_0044df28,0);
    uVar7 = *(undefined4 *)((int)pvVar3 + 0xc);
    pvVar3 = FUN_00423110(&DAT_0044df28,0);
    uVar9 = *(undefined4 *)((int)pvVar3 + 4);
    puVar4 = (undefined4 *)FUN_00423110(&DAT_0044df28,0);
    (**(code **)(**(int **)(param_1 + 0xe00c) + 0x6c))(*puVar4,uVar9,uVar7);
  }
  bVar1 = SPRITE::InMotion(*(SPRITE **)(param_1 + 0xe00c));
  if (bVar1) {
    iVar2 = OVERLAY::Position(*(OVERLAY **)(param_1 + 0xe00c));
    GKERNEL::SetCursorPos(iVar2,(int)param_1);
    uVar9 = 0;
    pvVar3 = FUN_00423110(&DAT_0044df28,0);
    uVar5 = (uint)*(byte *)((int)pvVar3 + 8);
    iVar2 = OVERLAY::Position(*(OVERLAY **)(param_1 + 0xe00c));
    uVar7 = *(undefined4 *)(iVar2 + 4);
    puVar4 = (undefined4 *)OVERLAY::Position(*(OVERLAY **)(param_1 + 0xe00c));
    (**(code **)(*(int *)param_1 + 0x28))(*puVar4,uVar7,uVar5,uVar9);
    bVar1 = FUN_00423e60(&DAT_00450ae0,'\x01');
    if ((bVar1) && (pvVar3 = FUN_00423110(&DAT_0044df28,0), *(char *)((int)pvVar3 + 8) != '\0')) {
      piVar6 = (int *)FUN_00423110(&DAT_0044df28,0);
      iVar2 = *piVar6;
      iVar8 = piVar6[1];
      local_38 = iVar2;
      local_34 = iVar8;
      pvVar3 = (void *)OVERLAY::Position(*(OVERLAY **)(param_1 + 0xe00c));
      iVar2 = FUN_00416330(pvVar3,iVar2,iVar8);
      if (iVar2 != 0) {
        uVar7 = OVERLAY::Position(*(OVERLAY **)(param_1 + 0xe00c));
        (**(code **)(*(int *)param_1 + 0x38))(uVar7);
      }
    }
  }
  else {
    bVar1 = FUN_00423e60(&DAT_00450ae0,'\0');
    if (bVar1) {
      iVar2 = OVERLAY::Position(*(OVERLAY **)(param_1 + 0xe00c));
      GKERNEL::SetCursorPos(iVar2,(int)param_1);
      local_8 = local_8 & 0xffffff00;
      local_c = local_c & 0xffffff00;
      iVar2 = FUN_00423620(0x44df28);
      if (1 < iVar2) {
        pvVar3 = FUN_00423110(&DAT_0044df28,1);
        local_8 = CONCAT31(local_8._1_3_,*(undefined1 *)((int)pvVar3 + 8));
        pvVar3 = FUN_00423110(&DAT_0044df28,1);
        local_c = CONCAT31(local_c._1_3_,*(undefined1 *)((int)pvVar3 + 9));
      }
      pvVar3 = FUN_00423110(&DAT_0044df28,0);
      if ((*(char *)((int)pvVar3 + 8) == '\0') || ((local_8 & 0xff) != 0)) {
        pvVar3 = FUN_00423110(&DAT_0044df28,0);
        if ((*(char *)((int)pvVar3 + 9) != '\0') && ((local_c & 0xff) == 0)) {
          uVar7 = OVERLAY::Position(*(OVERLAY **)(param_1 + 0xe00c));
          (**(code **)(*(int *)param_1 + 0x30))(uVar7);
        }
      }
      else {
        uVar7 = OVERLAY::Position(*(OVERLAY **)(param_1 + 0xe00c));
        (**(code **)(*(int *)param_1 + 0x2c))(uVar7);
      }
      FUN_00423830(&DAT_0044df28,local_68);
      iVar2 = FUN_00423620(0x44df28);
      if (iVar2 == 0) {
        GKERNEL::IgnoreUserInput(false);
        GKERNEL::SetCursorPos(0x44f698,(int)param_1);
        local_10 = FUN_004232f0(&DAT_0044dd88,DAT_00450acc);
        FUN_00425e10(local_74,&DAT_0044f518);
        bVar1 = FUN_00422ff0(local_10 + 0x30,(int)local_74);
        if (bVar1) {
          FUN_004217c5((int)param_1);
        }
        else {
          FUN_00421dbb(param_1);
        }
        FUN_00417f6e((int *)param_1);
      }
    }
  }
  return;
}



void __fastcall FUN_0042259d(GAME *param_1)

{
  int iVar1;
  
  iVar1 = FUN_004056c0((int)param_1);
  if ((iVar1 != 7) && ((iVar1 = FUN_004056c0((int)param_1), iVar1 != 10 || (DAT_00450ad8 == 0)))) {
    FUN_00421f19((int)param_1);
    FUN_00422295(param_1);
  }
  return;
}



void __fastcall FUN_004225df(GAME *param_1)

{
  bool bVar1;
  bool bVar2;
  char cVar3;
  int iVar4;
  undefined3 extraout_var;
  undefined4 *puVar5;
  uint uVar6;
  undefined3 extraout_var_00;
  ITEM *pIVar7;
  int *piVar8;
  undefined4 *local_74;
  CDHtmlElementEventSink local_48 [12];
  CDHtmlElementEventSink local_3c [12];
  ITEM *local_30;
  int local_2c;
  CDHtmlElementEventSink local_28 [8];
  undefined4 local_20;
  uint local_1c;
  CString *local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042aec5;
  local_10 = ExceptionList;
  bVar1 = false;
  ExceptionList = &local_10;
  iVar4 = FUN_004213b1((int)param_1);
  if ((iVar4 != 0) && (DAT_00450ad4 != '\0')) {
    FUN_00410b70((MAP *)(param_1 + 0xe23c));
    GKERNEL::SpriteFlip();
    FUN_00410b70((MAP *)(param_1 + 0xe23c));
    FUN_0040dc77(param_1);
    iVar4 = FUN_004056c0((int)param_1);
    local_1c = CONCAT31(local_1c._1_3_,iVar4 == 6);
    local_18 = FUN_004232f0(&DAT_0044dd88,DAT_00450acc);
    local_2c = FUN_00423770((int)(local_18 + 0xdc));
    FUN_00425d20(local_28);
    local_8 = 0;
    local_14 = 0;
    bVar2 = IsEmpty((int)(local_18 + 0xdc));
    if (CONCAT31(extraout_var,bVar2) == 0) {
      puVar5 = (undefined4 *)FUN_00423b30(local_3c,&local_2c);
      local_8._0_1_ = 1;
      FUN_00422f70(local_28,puVar5);
      local_8 = (uint)local_8._1_3_ << 8;
      CDHtmlElementEventSink::~CDHtmlElementEventSink(local_3c);
    }
    local_14 = 0;
    while( true ) {
      uVar6 = FUN_00423620((int)(local_18 + 0xdc));
      if ((uVar6 <= local_14) ||
         (bVar2 = IsEmpty((int)(local_18 + 0xdc)), CONCAT31(extraout_var_00,bVar2) != 0))
      goto LAB_00422817;
      iVar4 = FUN_00401470(&local_20);
      if (iVar4 == 0) {
        local_74 = (undefined4 *)0x0;
      }
      else {
        local_74 = (undefined4 *)(iVar4 + 8);
      }
      pIVar7 = MAP::GetItem((MAP *)(param_1 + 0xe23c),*local_74,local_74[1]);
      local_30 = pIVar7;
      piVar8 = (int *)FUN_00401470(&local_20);
      cVar3 = (**(code **)(*piVar8 + 8))(pIVar7);
      if (cVar3 == '\0') break;
      local_14 = local_14 + 1;
      uVar6 = FUN_00423620((int)(local_18 + 0xdc));
      if (local_14 < uVar6) {
        puVar5 = (undefined4 *)FUN_00423b30(local_48,&local_2c);
        bVar1 = true;
        local_8 = CONCAT31(local_8._1_3_,2);
        FUN_00422f70(local_28,puVar5);
      }
      local_8 = 0;
      if (bVar1) {
        bVar1 = false;
        CDHtmlElementEventSink::~CDHtmlElementEventSink(local_48);
      }
    }
    local_1c = local_1c & 0xffffff00;
LAB_00422817:
    DAT_00450adc = DAT_00450adc + 1;
    if ((local_1c & 0xff) == 0) {
      if (*(uint *)(local_18 + 0xac) <= DAT_00450adc) {
        DAT_00450ad4 = '\0';
        FUN_00417f6e((int *)param_1);
        MAP::RefreshBothLevelmapBuffers((MAP *)(param_1 + 0xe23c));
        FUN_004217c5((int)param_1);
        DAT_00450ad5 = 1;
      }
    }
    else {
      DAT_00450ad4 = '\0';
      FUN_00421dbb(param_1);
    }
    local_8 = 0xffffffff;
    CDHtmlElementEventSink::~CDHtmlElementEventSink(local_28);
  }
  ExceptionList = local_10;
  return;
}



bool __thiscall FUN_0042289f(void *this,LONG *param_1)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  undefined4 *this_00;
  LONG LVar4;
  LONG LVar5;
  undefined4 local_18 [4];
  CString *local_8;
  
  iVar2 = FUN_004213b1((int)this);
  if (iVar2 == 0) {
    bVar1 = false;
  }
  else {
    bVar1 = FUN_004216f4();
    if (bVar1) {
      bVar1 = false;
    }
    else if (DAT_00450ad4 == '\0') {
      local_8 = FUN_004232f0(&DAT_0044dd88,DAT_00450acc);
      uVar3 = CMFCOutlookBarPane::IsBackgroundTexture((CMFCOutlookBarPane *)local_8);
      if ((uVar3 & 0xff) != 0) {
        LVar4 = *param_1;
        LVar5 = param_1[1];
        this_00 = FUN_00426bd0(local_8,local_18);
        iVar2 = FUN_00423480(this_00,LVar4,LVar5);
        if (iVar2 == 0) {
          FUN_0042146b((int)this);
        }
      }
      iVar2 = FUN_0042167f((int)this);
      bVar1 = iVar2 != 0;
    }
    else {
      bVar1 = false;
    }
  }
  return bVar1;
}



bool __thiscall FUN_00422951(void *this,LONG *param_1)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  undefined4 *this_00;
  LONG LVar4;
  LONG LVar5;
  undefined4 local_18 [4];
  CString *local_8;
  
  iVar2 = FUN_004213b1((int)this);
  if (iVar2 == 0) {
    bVar1 = false;
  }
  else {
    bVar1 = FUN_004216f4();
    if (bVar1) {
      bVar1 = false;
    }
    else if (DAT_00450ad4 == '\0') {
      local_8 = FUN_004232f0(&DAT_0044dd88,DAT_00450acc);
      uVar3 = CMFCOutlookBarPane::IsBackgroundTexture((CMFCOutlookBarPane *)local_8);
      if ((uVar3 & 0xff) != 0) {
        LVar4 = *param_1;
        LVar5 = param_1[1];
        this_00 = FUN_00426bd0(local_8,local_18);
        iVar2 = FUN_00423480(this_00,LVar4,LVar5);
        if (iVar2 == 0) {
          FUN_0042146b((int)this);
        }
      }
      iVar2 = FUN_0042167f((int)this);
      bVar1 = iVar2 != 0;
    }
    else {
      bVar1 = false;
    }
  }
  return bVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool __thiscall FUN_00422a03(void *this,LONG *param_1)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  undefined4 *puVar4;
  int *piVar5;
  LONG LVar6;
  char cVar7;
  LONG LVar8;
  undefined4 local_30 [4];
  LONG local_20;
  LONG local_1c;
  undefined4 local_18 [4];
  CString *local_8;
  
  iVar2 = FUN_004213b1((int)this);
  if (iVar2 == 0) {
    bVar1 = false;
  }
  else if (((*(int *)((int)this + 0xe018) != 0) || (bVar1 = FUN_004216f4(), bVar1)) ||
          (DAT_00450ad4 != '\0')) {
    bVar1 = false;
  }
  else {
    local_8 = FUN_004232f0(&DAT_0044dd88,DAT_00450acc);
    uVar3 = CMFCOutlookBarPane::IsBackgroundTexture((CMFCOutlookBarPane *)local_8);
    if ((uVar3 & 0xff) != 0) {
      LVar6 = *param_1;
      LVar8 = param_1[1];
      local_20 = LVar6;
      local_1c = LVar8;
      puVar4 = FUN_00426bd0(local_8,local_18);
      iVar2 = FUN_00423480(puVar4,LVar6,LVar8);
      if (iVar2 == 0) {
        FUN_0042146b((int)this);
        iVar2 = FUN_0042167f((int)this);
        return iVar2 != 0;
      }
    }
    FUN_0040b6f0(0x450950);
    FUN_0040b6f0(0x44dda8);
    FUN_0040b6f0(0x44df48);
    FUN_0040b6f0(0x44dc00);
    FUN_0040b6f0(0x44f6a0);
    FUN_0040b6f0(0x44e248);
    FUN_0040b6f0(0x44e0c8);
    FUN_0040b6f0(0x44f518);
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_00450950);
    if ((bVar1) || (bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044e248), bVar1)) {
      FUN_00421dbb((GAME *)this);
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044dda8);
    if ((bVar1) || (bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044e0c8), bVar1)) {
      FUN_00421e6b((int *)this);
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044df48);
    if (bVar1) {
      DAT_00450ad5 = 0;
      puVar4 = (undefined4 *)OVERLAY::Position(*(OVERLAY **)((int)this + 0xe00c));
      _DAT_0044f698 = *puVar4;
      _DAT_0044f69c = puVar4[1];
      FUN_004230b0(&DAT_0044df28,local_8 + 0xc0);
      MAP::RefreshBothLevelmapBuffers((MAP *)((int)this + 0xe23c));
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044f518);
    if (bVar1) {
      FUN_0042146b((int)this);
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044dc00);
    if (bVar1) {
      cVar7 = '\x01';
      piVar5 = FUN_00405910((void *)((int)this + 0xe23c),local_30);
      iVar2 = FUN_004058f0(piVar5);
      FUN_00411531(this,iVar2,cVar7);
      FUN_00411002((GAME *)this);
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044f6a0);
    if (bVar1) {
      DAT_00450acc = 0;
      FUN_0040d700((GAME *)this);
    }
    iVar2 = FUN_0042167f((int)this);
    bVar1 = iVar2 != 0;
  }
  return bVar1;
}



undefined4 __thiscall FUN_00422c65(void *this,int param_1,char param_2)

{
  undefined4 uVar1;
  
  if (param_2 == '\0') {
    uVar1 = 0;
  }
  else if ((param_1 == 0x1b) && (DAT_00450ad4 != '\0')) {
    DAT_00450ad4 = '\0';
    FUN_00417f6e((int *)this);
    MAP::RefreshBothLevelmapBuffers((MAP *)((int)this + 0xe23c));
    uVar1 = FUN_004217c5((int)this);
    DAT_00450adc = 0;
    uVar1 = CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



void __fastcall FUN_00422cca(int param_1)

{
  bool bVar1;
  int iVar2;
  
  iVar2 = FUN_004213b1(param_1);
  if ((iVar2 != 0) && (*(int *)(param_1 + 0xe018) == 0)) {
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_00450950);
    if (bVar1) {
      FUN_00416400(0x450950);
    }
    else {
      FUN_0040b6f0(0x450950);
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044dda8);
    if (bVar1) {
      FUN_00416400(0x44dda8);
    }
    else {
      FUN_0040b6f0(0x44dda8);
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044df48);
    if (bVar1) {
      FUN_00416400(0x44df48);
    }
    else {
      FUN_0040b6f0(0x44df48);
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044dc00);
    if (bVar1) {
      FUN_00416400(0x44dc00);
    }
    else {
      FUN_0040b6f0(0x44dc00);
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044f6a0);
    if (bVar1) {
      FUN_00416400(0x44f6a0);
    }
    else {
      FUN_0040b6f0(0x44f6a0);
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044e248);
    if (bVar1) {
      FUN_00416400(0x44e248);
    }
    else {
      FUN_0040b6f0(0x44e248);
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044e0c8);
    if (bVar1) {
      FUN_00416400(0x44e0c8);
    }
    else {
      FUN_0040b6f0(0x44e0c8);
    }
    bVar1 = OVERLAY::IntersectsCursor((OVERLAY *)&DAT_0044f518);
    if (bVar1) {
      FUN_00416400(0x44f518);
    }
    else {
      FUN_0040b6f0(0x44f518);
    }
  }
  return;
}



void __fastcall FUN_00422e50(undefined4 *param_1)

{
  FUN_00423d00(param_1);
  return;
}



void __fastcall FUN_00422e70(CString *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_0042af33;
  local_10 = ExceptionList;
  local_8 = 7;
  ExceptionList = &local_10;
  FUN_00426d20((undefined4 *)(param_1 + 0xdc));
  local_8._0_1_ = 6;
  FUN_00426d00((undefined4 *)(param_1 + 0xc0));
  local_8._0_1_ = 5;
  FUN_00426ce0((undefined4 *)(param_1 + 0x84));
  local_8._0_1_ = 4;
  FUN_00426cc0((undefined4 *)(param_1 + 0x68));
  local_8._0_1_ = 3;
  FUN_00426ca0((undefined4 *)(param_1 + 0x4c));
  local_8._0_1_ = 2;
  FUN_00426c80((undefined4 *)(param_1 + 0x30));
  local_8._0_1_ = 1;
  CString::~CString(param_1 + 8);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString(param_1 + 4);
  local_8 = 0xffffffff;
  CString::~CString(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00422f30(CString *param_1)

{
  FUN_004014d0(param_1);
  return;
}



// Library Function - Single Match
//  public: __thiscall CDHtmlElementEventSink::~CDHtmlElementEventSink(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug

void __thiscall CDHtmlElementEventSink::~CDHtmlElementEventSink(CDHtmlElementEventSink *this)

{
  FUN_00425dd0((int *)(this + 8));
  return;
}



void * __thiscall FUN_00422f70(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  
  uVar1 = param_1[1];
  *(undefined4 *)this = *param_1;
  *(undefined4 *)((int)this + 4) = uVar1;
  FUN_00422fb0((void *)((int)this + 8),(shared_ptr<> *)(param_1 + 2));
  return this;
}



void * __thiscall FUN_00422fb0(void *this,shared_ptr<> *param_1)

{
  std::shared_ptr<>::shared_ptr<>((shared_ptr<> *)this,param_1);
  return this;
}



void * __thiscall FUN_00422fd0(void *this,undefined4 *param_1)

{
  FUN_004234a0(this,param_1);
  return this;
}



bool __thiscall FUN_00422ff0(void *this,int param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_00423510(this,param_1,(undefined4 *)0x0);
  return puVar1 != (undefined4 *)0x0;
}



void * __thiscall FUN_00423020(void *this,undefined4 *param_1)

{
  FUN_00423570(this,param_1);
  return this;
}



void * __thiscall FUN_00423040(void *this,undefined4 *param_1)

{
  FUN_00423640(this,param_1);
  return this;
}



void * __thiscall FUN_00423060(void *this,undefined4 *param_1)

{
  FUN_00423700(this,param_1);
  return this;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_004237d0(this,10);
  *(undefined ***)this = &PTR_LAB_0042dc78;
  return this;
}



void * __thiscall FUN_004230b0(void *this,void *param_1)

{
  if (this != param_1) {
    FUN_00423970((int)this);
    FUN_004238c0(this,(int)param_1);
  }
  return this;
}



void * __thiscall FUN_004230f0(void *this,undefined4 *param_1)

{
  FUN_00423900(this,param_1);
  return this;
}



void * __thiscall FUN_00423110(void *this,uint param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  void *pvVar2;
  uint uVar3;
  void *local_34;
  void *local_30;
  int local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042af56;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  bVar1 = IsEmpty((int)this);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    uVar3 = FUN_00423620((int)this);
    if (param_1 < uVar3) {
      local_18 = FUN_00423770((int)this);
      local_14 = 0;
      while ((local_14 < param_1 && (uVar3 = FUN_00423620((int)this), local_14 < uVar3))) {
        FUN_004239f0(&local_18);
        local_14 = local_14 + 1;
      }
      local_30 = (void *)FUN_004239f0(&local_18);
    }
    else {
      pvVar2 = operator_new(0x10);
      local_8 = 1;
      if (pvVar2 == (void *)0x0) {
        local_34 = (void *)0x0;
        local_30 = local_34;
      }
      else {
        local_30 = FUN_00425380(pvVar2);
      }
    }
  }
  else {
    pvVar2 = operator_new(0x10);
    local_8 = 0;
    if (pvVar2 == (void *)0x0) {
      local_30 = (void *)0x0;
    }
    else {
      local_30 = FUN_00425380(pvVar2);
    }
  }
  ExceptionList = local_10;
  return local_30;
}



void * __thiscall FUN_00423240(void *this,undefined4 *param_1)

{
  FUN_00423ad0(this,param_1);
  return this;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_00423b80(this,10);
  *(undefined ***)this = &PTR_LAB_0042dc8c;
  return this;
}



void * __thiscall FUN_00423290(void *this,void *param_1)

{
  if (this != param_1) {
    FUN_00423c80((int)this);
    FUN_00423be0(this,(int)param_1);
  }
  return this;
}



void * __thiscall FUN_004232d0(void *this,CString *param_1)

{
  FUN_00423c20(this,param_1);
  return this;
}



CString * __thiscall FUN_004232f0(void *this,uint param_1)

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
  puStack_c = &LAB_0042af76;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  bVar1 = IsEmpty((int)this);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    uVar3 = FUN_00423620((int)this);
    if (param_1 < uVar3) {
      local_18 = FUN_00423770((int)this);
      local_14 = 0;
      while ((local_14 < param_1 && (uVar3 = FUN_00423620((int)this), local_14 < uVar3))) {
        FUN_0041be90(&local_18);
        local_14 = local_14 + 1;
      }
      local_30 = (CString *)FUN_0041be90(&local_18);
    }
    else {
      pCVar2 = (CString *)operator_new(0xf8);
      local_8 = 1;
      if (pCVar2 == (CString *)0x0) {
        local_34 = (CString *)0x0;
        local_30 = local_34;
      }
      else {
        local_30 = FUN_00425fd0(pCVar2);
      }
    }
  }
  else {
    pCVar2 = (CString *)operator_new(0xf8);
    local_8 = 0;
    if (pCVar2 == (CString *)0x0) {
      local_30 = (CString *)0x0;
    }
    else {
      local_30 = FUN_00425fd0(pCVar2);
    }
  }
  ExceptionList = local_10;
  return local_30;
}



void * __thiscall FUN_00423420(void *this,uint param_1)

{
  FUN_00426d00((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void * __thiscall FUN_00423450(void *this,uint param_1)

{
  FUN_00422e50((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __thiscall FUN_00423480(void *this,LONG param_1,LONG param_2)

{
  POINT pt;
  
  pt.y = param_2;
  pt.x = param_1;
  PtInRect((RECT *)this,pt);
  return;
}



undefined4 * __thiscall FUN_004234a0(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_00424350(this,*(undefined4 *)((int)this + 8),0);
  puVar1[2] = *param_1;
  puVar1[3] = param_1[1];
  puVar1[4] = param_1[2];
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



undefined4 * __thiscall FUN_00423510(void *this,int param_1,undefined4 *param_2)

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
    bVar1 = FUN_00424430(local_8 + 2,param_1);
    if (CONCAT31(extraout_var,bVar1) != 0) break;
    local_8 = (undefined4 *)*local_8;
  }
  return local_8;
}



undefined4 * __thiscall FUN_00423570(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_00424490(this,*(undefined4 *)((int)this + 8),0);
  puVar1[2] = *param_1;
  puVar1[3] = param_1[1];
  puVar1[4] = param_1[2];
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



undefined4 * FUN_004235e0(undefined4 *param_1,int *param_2)

{
  int *piVar1;
  
  piVar1 = (int *)*param_2;
  *param_2 = *piVar1;
  *param_1 = piVar1[2];
  param_1[1] = piVar1[3];
  param_1[2] = piVar1[4];
  return param_1;
}



undefined4 __fastcall FUN_00423620(int param_1)

{
  return *(undefined4 *)(param_1 + 0xc);
}



undefined4 * __thiscall FUN_00423640(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_004245b0(this,*(undefined4 *)((int)this + 8),0);
  puVar1[2] = *param_1;
  puVar1[3] = param_1[1];
  puVar1[4] = param_1[2];
  puVar1[5] = param_1[3];
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



undefined4 * FUN_004236b0(undefined4 *param_1,int *param_2)

{
  int *piVar1;
  
  piVar1 = (int *)*param_2;
  *param_2 = *piVar1;
  *param_1 = piVar1[2];
  param_1[1] = piVar1[3];
  param_1[2] = piVar1[4];
  param_1[3] = piVar1[5];
  return param_1;
}



undefined4 * __thiscall FUN_00423700(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_00424750(this,*(undefined4 *)((int)this + 8),0);
  puVar1[2] = *param_1;
  puVar1[3] = param_1[1];
  puVar1[4] = param_1[2];
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



undefined4 __fastcall FUN_00423770(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



undefined4 * FUN_00423790(undefined4 *param_1,int *param_2)

{
  int *piVar1;
  
  piVar1 = (int *)*param_2;
  *param_2 = *piVar1;
  *param_1 = piVar1[2];
  param_1[1] = piVar1[3];
  param_1[2] = piVar1[4];
  return param_1;
}



void * __thiscall FUN_004237d0(void *this,undefined4 param_1)

{
  FUN_00404b20((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_0042dca0;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



undefined4 * __thiscall FUN_00423830(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  
  puVar1 = *(undefined4 **)((int)this + 4);
  uVar2 = puVar1[2];
  uVar3 = puVar1[3];
  uVar4 = puVar1[4];
  uVar5 = puVar1[5];
  *(undefined4 *)((int)this + 4) = *puVar1;
  if (*(int *)((int)this + 4) == 0) {
    *(undefined4 *)((int)this + 8) = 0;
  }
  else {
    *(undefined4 *)(*(int *)((int)this + 4) + 4) = 0;
  }
  FUN_00424910(this,puVar1);
  *param_1 = uVar2;
  param_1[1] = uVar3;
  param_1[2] = uVar4;
  param_1[3] = uVar5;
  return param_1;
}



void __thiscall FUN_004238c0(void *this,int param_1)

{
  undefined4 *puVar1;
  int local_8;
  
  local_8 = FUN_00423770(param_1);
  while (local_8 != 0) {
    puVar1 = (undefined4 *)FUN_004239f0(&local_8);
    FUN_00423900(this,puVar1);
  }
  return;
}



undefined4 * __thiscall FUN_00423900(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_00424830(this,*(undefined4 *)((int)this + 8),0);
  puVar1[2] = *param_1;
  puVar1[3] = param_1[1];
  puVar1[4] = param_1[2];
  puVar1[5] = param_1[3];
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



void __fastcall FUN_00423970(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_00424960(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



int FUN_004239f0(int *param_1)

{
  int *piVar1;
  
  piVar1 = (int *)*param_1;
  *param_1 = *piVar1;
  return (int)(piVar1 + 2);
}



void __thiscall FUN_00423a20(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_1c [4];
  ulong local_c;
  undefined4 *local_8;
  
  FUN_00401400();
  bVar1 = FUN_00404cf0((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      FUN_00425380(local_1c);
      FUN_004051d0(param_1,local_1c,1);
      FUN_00423900(this,local_1c);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_004051d0(param_1,local_8 + 2,1);
    }
  }
  return;
}



undefined4 * __thiscall FUN_00423ad0(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_00424a50(this,*(undefined4 *)((int)this + 8),0);
  FUN_00422f70(puVar1 + 2,param_1);
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



void * FUN_00423b30(void *param_1,int *param_2)

{
  int *piVar1;
  
  piVar1 = (int *)*param_2;
  *param_2 = *piVar1;
  FUN_00423f20(param_1,piVar1 + 2);
  return param_1;
}



void * __thiscall FUN_00423b80(void *this,undefined4 param_1)

{
  FUN_00404b20((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_0042dcb4;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



void __thiscall FUN_00423be0(void *this,int param_1)

{
  CString *pCVar1;
  int local_8;
  
  local_8 = FUN_00423770(param_1);
  while (local_8 != 0) {
    pCVar1 = (CString *)FUN_0041be90(&local_8);
    FUN_00423c20(this,pCVar1);
  }
  return;
}



undefined4 * __thiscall FUN_00423c20(void *this,CString *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_00424b30(this,*(undefined4 *)((int)this + 8),0);
  FUN_00423f90(puVar1 + 2,param_1);
  if (*(int *)((int)this + 8) == 0) {
    *(undefined4 **)((int)this + 4) = puVar1;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar1;
  }
  *(undefined4 **)((int)this + 8) = puVar1;
  return puVar1;
}



void __fastcall FUN_00423c80(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_00424c10(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



void __fastcall FUN_00423d00(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0042af89;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_0042dcb4;
  local_8 = 0;
  FUN_00423c80((int)param_1);
  local_8 = 0xffffffff;
  FUN_00404b70(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_00423d60(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  CString local_110 [248];
  ulong local_18;
  undefined4 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042afac;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00401400();
  bVar1 = FUN_00404cf0((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_18 = CArchive::ReadCount(param_1);
    while (local_18 != 0) {
      local_18 = local_18 - 1;
      FUN_00425fd0(local_110);
      local_8 = 0;
      FUN_00424c40(param_1,local_110,1);
      FUN_00423c20(this,local_110);
      local_8 = 0xffffffff;
      FUN_00422e70(local_110);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_14 = *(undefined4 **)((int)this + 4); local_14 != (undefined4 *)0x0;
        local_14 = (undefined4 *)*local_14) {
      FUN_00424c40(param_1,local_14 + 2,1);
    }
  }
  ExceptionList = local_10;
  return;
}



bool __cdecl FUN_00423e60(char *param_1,char param_2)

{
  char cVar1;
  
  cVar1 = *param_1;
  *param_1 = param_2;
  return cVar1 != param_2;
}



void * __thiscall FUN_00423e90(void *this,uint param_1)

{
  FUN_00423ec0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_00423ec0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0042afc9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_0042dca0;
  local_8 = 0;
  FUN_00423970((int)param_1);
  local_8 = 0xffffffff;
  FUN_00404b70(param_1);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_00423f20(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  
  uVar1 = param_1[1];
  *(undefined4 *)this = *param_1;
  *(undefined4 *)((int)this + 4) = uVar1;
  FUN_00424130((void *)((int)this + 8),param_1 + 2);
  return this;
}



void * __thiscall FUN_00423f60(void *this,uint param_1)

{
  FUN_00423d00((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void * __thiscall FUN_00423f90(void *this,CString *param_1)

{
  undefined4 uVar1;
  
  CString::operator=((CString *)this,param_1);
  CString::operator=((CString *)((int)this + 4),param_1 + 4);
  CString::operator=((CString *)((int)this + 8),param_1 + 8);
  *(undefined4 *)((int)this + 0xc) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)((int)this + 0x10) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)((int)this + 0x14) = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)((int)this + 0x18) = *(undefined4 *)(param_1 + 0x18);
  uVar1 = *(undefined4 *)(param_1 + 0x20);
  *(undefined4 *)((int)this + 0x1c) = *(undefined4 *)(param_1 + 0x1c);
  *(undefined4 *)((int)this + 0x20) = uVar1;
  uVar1 = *(undefined4 *)(param_1 + 0x28);
  *(undefined4 *)((int)this + 0x24) = *(undefined4 *)(param_1 + 0x24);
  *(undefined4 *)((int)this + 0x28) = uVar1;
  *(CString *)((int)this + 0x2c) = param_1[0x2c];
  FUN_00424150((void *)((int)this + 0x30),param_1 + 0x30);
  FUN_00424190((void *)((int)this + 0x4c),param_1 + 0x4c);
  FUN_004241d0((void *)((int)this + 0x68),param_1 + 0x68);
  FUN_00424210((void *)((int)this + 0x84),param_1 + 0x84);
  *(undefined4 *)((int)this + 0xa0) = *(undefined4 *)(param_1 + 0xa0);
  *(undefined4 *)((int)this + 0xa4) = *(undefined4 *)(param_1 + 0xa4);
  *(undefined4 *)((int)this + 0xa8) = *(undefined4 *)(param_1 + 0xa8);
  *(undefined4 *)((int)this + 0xac) = *(undefined4 *)(param_1 + 0xac);
  *(undefined4 *)((int)this + 0xb0) = *(undefined4 *)(param_1 + 0xb0);
  *(undefined4 *)((int)this + 0xb4) = *(undefined4 *)(param_1 + 0xb4);
  *(undefined4 *)((int)this + 0xb8) = *(undefined4 *)(param_1 + 0xb8);
  *(undefined4 *)((int)this + 0xbc) = *(undefined4 *)(param_1 + 0xbc);
  FUN_004230b0((void *)((int)this + 0xc0),param_1 + 0xc0);
  FUN_00424250((void *)((int)this + 0xdc),param_1 + 0xdc);
  return this;
}



void * __thiscall FUN_00424130(void *this,undefined4 *param_1)

{
  FUN_00425290(this,param_1);
  return this;
}



void * __thiscall FUN_00424150(void *this,void *param_1)

{
  if (this != param_1) {
    FUN_004242d0((int)this);
    FUN_00424290(this,(int)param_1);
  }
  return this;
}



void * __thiscall FUN_00424190(void *this,void *param_1)

{
  if (this != param_1) {
    FUN_004246d0((int)this);
    FUN_00424450(this,(int)param_1);
  }
  return this;
}



void * __thiscall FUN_004241d0(void *this,void *param_1)

{
  if (this != param_1) {
    FUN_00405150((int)this);
    FUN_00424570(this,(int)param_1);
  }
  return this;
}



void * __thiscall FUN_00424210(void *this,void *param_1)

{
  if (this != param_1) {
    FUN_004246d0((int)this);
    FUN_00424690(this,(int)param_1);
  }
  return this;
}



void * __thiscall FUN_00424250(void *this,void *param_1)

{
  if (this != param_1) {
    FUN_004249d0((int)this);
    FUN_00424990(this,(int)param_1);
  }
  return this;
}



void __thiscall FUN_00424290(void *this,int param_1)

{
  undefined4 *puVar1;
  int local_8;
  
  local_8 = FUN_00423770(param_1);
  while (local_8 != 0) {
    puVar1 = (undefined4 *)FUN_0041be90(&local_8);
    FUN_004234a0(this,puVar1);
  }
  return;
}



void __fastcall FUN_004242d0(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_00424d60(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



undefined4 * __thiscall FUN_00424350(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0x14);
    iVar3 = FUN_00428190((int)pCVar2);
    local_c = (undefined4 *)(iVar3 + (*(int *)((int)this + 0x18) + -1) * 0x14);
    local_10 = *(int *)((int)this + 0x18);
    while (local_10 = local_10 + -1, -1 < local_10) {
      *local_c = *(undefined4 *)((int)this + 0x10);
      *(undefined4 **)((int)this + 0x10) = local_c;
      local_c = local_c + -5;
    }
  }
  puVar1 = *(undefined4 **)((int)this + 0x10);
  *(undefined4 *)((int)this + 0x10) = **(undefined4 **)((int)this + 0x10);
  puVar1[1] = param_1;
  *puVar1 = param_2;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  FUN_00424cc0(puVar1 + 2,1);
  return puVar1;
}



bool FUN_00424430(void *param_1,int param_2)

{
  bool bVar1;
  
  bVar1 = FUN_00425e70(param_1,param_2);
  return bVar1;
}



void __thiscall FUN_00424450(void *this,int param_1)

{
  undefined4 *puVar1;
  int local_8;
  
  local_8 = FUN_00423770(param_1);
  while (local_8 != 0) {
    puVar1 = (undefined4 *)FUN_0041be90(&local_8);
    FUN_00423570(this,puVar1);
  }
  return;
}



undefined4 * __thiscall FUN_00424490(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0x14);
    iVar3 = FUN_00428190((int)pCVar2);
    local_c = (undefined4 *)(iVar3 + (*(int *)((int)this + 0x18) + -1) * 0x14);
    local_10 = *(int *)((int)this + 0x18);
    while (local_10 = local_10 + -1, -1 < local_10) {
      *local_c = *(undefined4 *)((int)this + 0x10);
      *(undefined4 **)((int)this + 0x10) = local_c;
      local_c = local_c + -5;
    }
  }
  puVar1 = *(undefined4 **)((int)this + 0x10);
  *(undefined4 *)((int)this + 0x10) = **(undefined4 **)((int)this + 0x10);
  puVar1[1] = param_1;
  *puVar1 = param_2;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  FUN_00424d90(puVar1 + 2,1);
  return puVar1;
}



void __thiscall FUN_00424570(void *this,int param_1)

{
  undefined4 *puVar1;
  int local_8;
  
  local_8 = FUN_00423770(param_1);
  while (local_8 != 0) {
    puVar1 = (undefined4 *)FUN_0041be90(&local_8);
    FUN_00423640(this,puVar1);
  }
  return;
}



undefined4 * __thiscall FUN_004245b0(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0x18);
    iVar3 = FUN_00428190((int)pCVar2);
    local_c = (undefined4 *)(iVar3 + (*(int *)((int)this + 0x18) + -1) * 0x18);
    local_10 = *(int *)((int)this + 0x18);
    while (local_10 = local_10 + -1, -1 < local_10) {
      *local_c = *(undefined4 *)((int)this + 0x10);
      *(undefined4 **)((int)this + 0x10) = local_c;
      local_c = local_c + -6;
    }
  }
  puVar1 = *(undefined4 **)((int)this + 0x10);
  *(undefined4 *)((int)this + 0x10) = **(undefined4 **)((int)this + 0x10);
  puVar1[1] = param_1;
  *puVar1 = param_2;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  FUN_00424e30(puVar1 + 2,1);
  return puVar1;
}



void __thiscall FUN_00424690(void *this,int param_1)

{
  undefined4 *puVar1;
  int local_8;
  
  local_8 = FUN_00423770(param_1);
  while (local_8 != 0) {
    puVar1 = (undefined4 *)FUN_0041be90(&local_8);
    FUN_00423700(this,puVar1);
  }
  return;
}



void __fastcall FUN_004246d0(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_00424d60(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



undefined4 * __thiscall FUN_00424750(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0x14);
    iVar3 = FUN_00428190((int)pCVar2);
    local_c = (undefined4 *)(iVar3 + (*(int *)((int)this + 0x18) + -1) * 0x14);
    local_10 = *(int *)((int)this + 0x18);
    while (local_10 = local_10 + -1, -1 < local_10) {
      *local_c = *(undefined4 *)((int)this + 0x10);
      *(undefined4 **)((int)this + 0x10) = local_c;
      local_c = local_c + -5;
    }
  }
  puVar1 = *(undefined4 **)((int)this + 0x10);
  *(undefined4 *)((int)this + 0x10) = **(undefined4 **)((int)this + 0x10);
  puVar1[1] = param_1;
  *puVar1 = param_2;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  FUN_00424ed0(puVar1 + 2,1);
  return puVar1;
}



undefined4 * __thiscall FUN_00424830(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0x18);
    iVar3 = FUN_00428190((int)pCVar2);
    local_c = (undefined4 *)(iVar3 + (*(int *)((int)this + 0x18) + -1) * 0x18);
    local_10 = *(int *)((int)this + 0x18);
    while (local_10 = local_10 + -1, -1 < local_10) {
      *local_c = *(undefined4 *)((int)this + 0x10);
      *(undefined4 **)((int)this + 0x10) = local_c;
      local_c = local_c + -6;
    }
  }
  puVar1 = *(undefined4 **)((int)this + 0x10);
  *(undefined4 *)((int)this + 0x10) = **(undefined4 **)((int)this + 0x10);
  puVar1[1] = param_1;
  *puVar1 = param_2;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  FUN_00424f70(puVar1 + 2,1);
  return puVar1;
}



void __thiscall FUN_00424910(void *this,undefined4 *param_1)

{
  FUN_00424960(param_1 + 2,1);
  *param_1 = *(undefined4 *)((int)this + 0x10);
  *(undefined4 **)((int)this + 0x10) = param_1;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + -1;
  if (*(int *)((int)this + 0xc) == 0) {
    FUN_00423970((int)this);
  }
  return;
}



void FUN_00424960(undefined4 param_1,int param_2)

{
  bool bVar1;
  
  do {
    bVar1 = param_2 != 0;
    param_2 = param_2 + -1;
  } while (bVar1);
  return;
}



void __thiscall FUN_00424990(void *this,int param_1)

{
  undefined4 *puVar1;
  int local_8;
  
  local_8 = FUN_00423770(param_1);
  while (local_8 != 0) {
    puVar1 = (undefined4 *)FUN_0041be90(&local_8);
    FUN_00423ad0(this,puVar1);
  }
  return;
}



void __fastcall FUN_004249d0(int param_1)

{
  undefined4 *local_8;
  
  for (local_8 = *(undefined4 **)(param_1 + 4); local_8 != (undefined4 *)0x0;
      local_8 = (undefined4 *)*local_8) {
    FUN_00425010(local_8 + 2,1);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  CPlex::FreeDataChain(*(CPlex **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



undefined4 * __thiscall FUN_00424a50(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0x14);
    iVar3 = FUN_00428190((int)pCVar2);
    local_c = (undefined4 *)(iVar3 + (*(int *)((int)this + 0x18) + -1) * 0x14);
    local_10 = *(int *)((int)this + 0x18);
    while (local_10 = local_10 + -1, -1 < local_10) {
      *local_c = *(undefined4 *)((int)this + 0x10);
      *(undefined4 **)((int)this + 0x10) = local_c;
      local_c = local_c + -5;
    }
  }
  puVar1 = *(undefined4 **)((int)this + 0x10);
  *(undefined4 *)((int)this + 0x10) = **(undefined4 **)((int)this + 0x10);
  puVar1[1] = param_1;
  *puVar1 = param_2;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  FUN_00425040(puVar1 + 2,1);
  return puVar1;
}



undefined4 * __thiscall FUN_00424b30(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  CPlex *pCVar2;
  int iVar3;
  int local_10;
  undefined4 *local_c;
  
  if (*(int *)((int)this + 0x10) == 0) {
    pCVar2 = CPlex::Create((CPlex **)((int)this + 0x14),*(uint *)((int)this + 0x18),0x100);
    iVar3 = FUN_00428190((int)pCVar2);
    local_c = (undefined4 *)(iVar3 + (*(int *)((int)this + 0x18) + -1) * 0x100);
    local_10 = *(int *)((int)this + 0x18);
    while (local_10 = local_10 + -1, -1 < local_10) {
      *local_c = *(undefined4 *)((int)this + 0x10);
      *(undefined4 **)((int)this + 0x10) = local_c;
      local_c = local_c + -0x40;
    }
  }
  puVar1 = *(undefined4 **)((int)this + 0x10);
  *(undefined4 *)((int)this + 0x10) = **(undefined4 **)((int)this + 0x10);
  puVar1[1] = param_1;
  *puVar1 = param_2;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  FUN_004250e0(puVar1 + 2,1);
  return puVar1;
}



void FUN_00424c10(void *param_1,int param_2)

{
  while (param_2 != 0) {
    FUN_00424c90(param_1,0);
    param_1 = (void *)((int)param_1 + 0xf8);
    param_2 = param_2 + -1;
  }
  return;
}



void FUN_00424c40(CArchive *param_1,void *param_2,int param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_00404cf0((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    CArchive::Read(param_1,param_2,param_3 * 0xf8);
  }
  else {
    CArchive::Write(param_1,param_2,param_3 * 0xf8);
  }
  return;
}



void * __thiscall FUN_00424c90(void *this,uint param_1)

{
  FUN_00422e70((CString *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void FUN_00424cc0(void *param_1,int param_2)

{
  void *pvVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042aff1;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  memset(param_1,0,param_2 * 0xc);
  while (param_2 != 0) {
    pvVar1 = (void *)FUN_00405640(0xc,param_1);
    local_8 = 0;
    if (pvVar1 != (void *)0x0) {
      FUN_00425df0(pvVar1);
    }
    local_8 = 0xffffffff;
    param_1 = (void *)((int)param_1 + 0xc);
    param_2 = param_2 + -1;
  }
  ExceptionList = local_10;
  return;
}



void FUN_00424d60(undefined4 param_1,int param_2)

{
  bool bVar1;
  
  do {
    bVar1 = param_2 != 0;
    param_2 = param_2 + -1;
  } while (bVar1);
  return;
}



void FUN_00424d90(void *param_1,int param_2)

{
  SafeSQueue<> *this;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042b011;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  memset(param_1,0,param_2 * 0xc);
  while (param_2 != 0) {
    this = (SafeSQueue<> *)FUN_00405640(0xc,param_1);
    local_8 = 0;
    if (this != (SafeSQueue<> *)0x0) {
      Concurrency::details::SafeSQueue<>::SafeSQueue<>(this);
    }
    local_8 = 0xffffffff;
    param_1 = (void *)((int)param_1 + 0xc);
    param_2 = param_2 + -1;
  }
  ExceptionList = local_10;
  return;
}



void FUN_00424e30(void *param_1,int param_2)

{
  void *pvVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042b031;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  memset(param_1,0,param_2 << 4);
  while (param_2 != 0) {
    pvVar1 = (void *)FUN_00405640(0x10,param_1);
    local_8 = 0;
    if (pvVar1 != (void *)0x0) {
      FUN_00425ef0(pvVar1);
    }
    local_8 = 0xffffffff;
    param_1 = (void *)((int)param_1 + 0x10);
    param_2 = param_2 + -1;
  }
  ExceptionList = local_10;
  return;
}



void FUN_00424ed0(void *param_1,int param_2)

{
  void *pvVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042b051;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  memset(param_1,0,param_2 * 0xc);
  while (param_2 != 0) {
    pvVar1 = (void *)FUN_00405640(0xc,param_1);
    local_8 = 0;
    if (pvVar1 != (void *)0x0) {
      FUN_00425f60(pvVar1);
    }
    local_8 = 0xffffffff;
    param_1 = (void *)((int)param_1 + 0xc);
    param_2 = param_2 + -1;
  }
  ExceptionList = local_10;
  return;
}



void FUN_00424f70(void *param_1,int param_2)

{
  void *pvVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042b071;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  memset(param_1,0,param_2 << 4);
  while (param_2 != 0) {
    pvVar1 = (void *)FUN_00405640(0x10,param_1);
    local_8 = 0;
    if (pvVar1 != (void *)0x0) {
      FUN_00425380(pvVar1);
    }
    local_8 = 0xffffffff;
    param_1 = (void *)((int)param_1 + 0x10);
    param_2 = param_2 + -1;
  }
  ExceptionList = local_10;
  return;
}



void FUN_00425010(void *param_1,int param_2)

{
  while (param_2 != 0) {
    FUN_00425190(param_1,0);
    param_1 = (void *)((int)param_1 + 0xc);
    param_2 = param_2 + -1;
  }
  return;
}



void FUN_00425040(void *param_1,int param_2)

{
  void *pvVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042b091;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  memset(param_1,0,param_2 * 0xc);
  while (param_2 != 0) {
    pvVar1 = (void *)FUN_00405640(0xc,param_1);
    local_8 = 0;
    if (pvVar1 != (void *)0x0) {
      FUN_00425d20(pvVar1);
    }
    local_8 = 0xffffffff;
    param_1 = (void *)((int)param_1 + 0xc);
    param_2 = param_2 + -1;
  }
  ExceptionList = local_10;
  return;
}



void FUN_004250e0(void *param_1,int param_2)

{
  CString *pCVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042b0b1;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  memset(param_1,0,param_2 * 0xf8);
  while (param_2 != 0) {
    pCVar1 = (CString *)FUN_00405640(0xf8,param_1);
    local_8 = 0;
    if (pCVar1 != (CString *)0x0) {
      FUN_00425fd0(pCVar1);
    }
    local_8 = 0xffffffff;
    param_1 = (void *)((int)param_1 + 0xf8);
    param_2 = param_2 + -1;
  }
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_00425190(void *this,uint param_1)

{
  CDHtmlElementEventSink::~CDHtmlElementEventSink((CDHtmlElementEventSink *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



CString * __cdecl FUN_004251c0(CString *param_1,char *param_2)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042b0c9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00405660(param_1);
  local_8 = 0;
  CString::FormatV(param_1,param_2,&stack0x0000000c);
  ExceptionList = local_10;
  return param_1;
}



void * __thiscall FUN_00425220(void *this,uint param_1)

{
  FUN_00425240(this,param_1);
  return this;
}



void __thiscall FUN_00425240(void *this,uint param_1)

{
  uint uVar1;
  
  uVar1 = FUN_00425260(param_1);
  *(uint *)this = uVar1;
  return;
}



uint __cdecl FUN_00425260(uint param_1)

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



void * __thiscall FUN_00425290(void *this,undefined4 *param_1)

{
  *(undefined4 *)this = *param_1;
                    // WARNING: Load size is inaccurate
  if (*this != 0) {
                    // WARNING: Load size is inaccurate
    FUN_004252c0(*this);
  }
  return this;
}



undefined4 __fastcall FUN_004252c0(int param_1)

{
  *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
  return *(undefined4 *)(param_1 + 4);
}



// Library Function - Single Match
//  public: __thiscall std::shared_ptr<struct Concurrency::details::_Task_impl<unsigned char>
// >::shared_ptr<struct Concurrency::details::_Task_impl<unsigned char> >(class
// std::shared_ptr<struct Concurrency::details::_Task_impl<unsigned char> > const &)
// 
// Libraries: Visual Studio 2012 Debug, Visual Studio 2012 Release

shared_ptr<> * __thiscall std::shared_ptr<>::shared_ptr<>(shared_ptr<> *this,shared_ptr<> *param_1)

{
  FUN_00425310((int *)this);
  FUN_00425290(this,(undefined4 *)param_1);
  return this;
}



void __fastcall FUN_00425310(int *param_1)

{
  int iVar1;
  
  if (((*param_1 != 0) && (iVar1 = FUN_00425360(*param_1), iVar1 == 0)) &&
     ((undefined4 *)*param_1 != (undefined4 *)0x0)) {
    (*(code *)**(undefined4 **)*param_1)(1);
  }
  return;
}



undefined4 __fastcall FUN_00425360(int param_1)

{
  *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + -1;
  return *(undefined4 *)(param_1 + 4);
}



void * __fastcall FUN_00425380(void *param_1)

{
  FUN_00405850(param_1);
  return param_1;
}



void * __thiscall FUN_004253a0(void *this,undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042b0f5;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00425430(this,param_1);
  local_8 = 0;
  CString::CString((CString *)((int)this + 0x10));
  local_8 = CONCAT31(local_8._1_3_,1);
  FUN_00425410((undefined4 *)((int)this + 0x14));
  *(undefined ***)this = &PTR_FUN_0042dcc8;
  ExceptionList = local_10;
  return this;
}



undefined4 * __fastcall FUN_00425410(undefined4 *param_1)

{
  *param_1 = 7;
  return param_1;
}



void * __thiscall FUN_00425430(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  
  uVar1 = param_1[1];
  *(undefined4 *)((int)this + 8) = *param_1;
  *(undefined4 *)((int)this + 0xc) = uVar1;
  FUN_00425470((undefined4 *)this);
  *(undefined ***)this = &PTR_FUN_0042dcd4;
  return this;
}



undefined4 * __fastcall FUN_00425470(undefined4 *param_1)

{
  param_1[1] = 0;
  *param_1 = &PTR_FUN_0042dce0;
  return param_1;
}



void * __thiscall FUN_004254a0(void *this,uint param_1)

{
  FUN_004254d0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_004254d0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_0042dce0;
  return;
}



void FUN_004254f0(void)

{
  return;
}



void __fastcall FUN_00425500(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_0042dcd4;
  FUN_004254d0(param_1);
  return;
}



void * __thiscall FUN_00425520(void *this,uint param_1)

{
  FUN_00425500((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __thiscall FUN_00425550(void *this,int *param_1)

{
  CString *pCVar1;
  undefined4 *puVar2;
  undefined1 local_18 [4];
  CString local_14 [4];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042b109;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  pCVar1 = (CString *)(**(code **)(*param_1 + 0x50))(local_14);
  local_8 = 0;
  CString::operator=((CString *)((int)this + 0x10),pCVar1);
  local_8 = 0xffffffff;
  CString::~CString(local_14);
  puVar2 = (undefined4 *)(**(code **)(*param_1 + 0x7c))(local_18);
  *(undefined4 *)((int)this + 0x14) = *puVar2;
  ExceptionList = local_10;
  return;
}



undefined1 __thiscall FUN_004255e0(void *this,int *param_1)

{
  bool bVar1;
  void *pvVar2;
  int *piVar3;
  CString *pCVar4;
  int iVar5;
  undefined1 local_30;
  undefined1 local_20 [4];
  bool local_1c;
  undefined3 uStack_1b;
  CString local_18 [4];
  undefined1 local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042b129;
  local_10 = ExceptionList;
  pCVar4 = local_18;
  ExceptionList = &local_10;
  pvVar2 = (void *)(**(code **)(*param_1 + 0x50))(pCVar4,(int)this + 0x10);
  local_8 = 0;
  bVar1 = FUN_004087b0(pvVar2,(undefined4 *)pCVar4);
  if (bVar1) {
    iVar5 = *(int *)((int)this + 0x14);
    piVar3 = (int *)(**(code **)(*param_1 + 0x7c))(local_20);
    bVar1 = FUN_00410130(*piVar3,iVar5);
    _local_1c = CONCAT31(uStack_1b,bVar1);
    if (bVar1) {
      local_30 = 1;
      goto LAB_00425677;
    }
  }
  local_30 = 0;
LAB_00425677:
  local_14 = local_30;
  local_8 = 0xffffffff;
  CString::~CString(local_18);
  ExceptionList = local_10;
  return local_14;
}



void * __thiscall FUN_004256a0(void *this,uint param_1)

{
  CChevronOwnerDrawMenu::~CChevronOwnerDrawMenu((CChevronOwnerDrawMenu *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



// Library Function - Single Match
//  public: virtual __thiscall CChevronOwnerDrawMenu::~CChevronOwnerDrawMenu(void)
// 
// Library: Visual Studio 2003 Debug

void __thiscall CChevronOwnerDrawMenu::~CChevronOwnerDrawMenu(CChevronOwnerDrawMenu *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0042b149;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  CString::~CString((CString *)(this + 0x10));
  local_8 = 0xffffffff;
  FUN_00425500((undefined4 *)this);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_00425720(void *this,undefined4 *param_1,undefined4 *param_2)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042b169;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_004253a0(this,param_1);
  local_8 = 0;
  *(undefined4 *)((int)this + 0x18) = *param_2;
  FUN_00425790((undefined4 *)((int)this + 0x1c));
  *(undefined ***)this = &PTR_FUN_0042dce4;
  ExceptionList = local_10;
  return this;
}



undefined4 * __fastcall FUN_00425790(undefined4 *param_1)

{
  *param_1 = 0xfffffc00;
  return param_1;
}



undefined1 __thiscall FUN_004257b0(void *this,int *param_1)

{
  char cVar1;
  bool bVar2;
  void *this_00;
  int *piVar3;
  int local_10;
  int local_8;
  
  cVar1 = FUN_004255e0(this,param_1);
  if (cVar1 != '\0') {
    if (this == (void *)0x0) {
      local_10 = 0;
    }
    else {
      local_10 = (int)this + 0x18;
    }
    piVar3 = &local_8;
    this_00 = (void *)(**(code **)(*param_1 + 0x78))(piVar3,local_10);
    bVar2 = FUN_00410110(this_00,piVar3);
    if (bVar2) {
      return 1;
    }
  }
  return 0;
}



void * __thiscall FUN_00425830(void *this,uint param_1)

{
  FUN_00425860((CChevronOwnerDrawMenu *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_00425860(CChevronOwnerDrawMenu *param_1)

{
  CChevronOwnerDrawMenu::~CChevronOwnerDrawMenu(param_1);
  return;
}



void * __thiscall
FUN_00425880(void *this,undefined4 *param_1,undefined4 *param_2,undefined4 *param_3)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042b195;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00425430(this,param_1);
  local_8 = 0;
  FUN_00425720((void *)((int)this + 0x10),param_1,param_2);
  local_8 = CONCAT31(local_8._1_3_,1);
  FUN_00425720((void *)((int)this + 0x30),param_1,param_3);
  *(undefined ***)this = &PTR_FUN_0042dcf0;
  ExceptionList = local_10;
  return this;
}



void __thiscall FUN_00425900(void *this,undefined4 param_1)

{
  (**(code **)(*(int *)((int)this + 0x10) + 4))(param_1);
  (**(code **)(*(int *)((int)this + 0x30) + 4))(param_1);
  return;
}



undefined1 __thiscall FUN_00425940(void *this,undefined4 param_1)

{
  char cVar1;
  
  cVar1 = (**(code **)(*(int *)((int)this + 0x10) + 8))(param_1);
  if ((cVar1 == '\0') &&
     (cVar1 = (**(code **)(*(int *)((int)this + 0x30) + 8))(param_1), cVar1 == '\0')) {
    return 0;
  }
  return 1;
}



void * __thiscall FUN_004259a0(void *this,uint param_1)

{
  FUN_004259d0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_004259d0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
  puStack_c = &LAB_0042b1b5;
  local_10 = ExceptionList;
  local_8 = 1;
  ExceptionList = &local_10;
  FUN_00425860((CChevronOwnerDrawMenu *)(param_1 + 0xc));
  local_8 = local_8 & 0xffffff00;
  FUN_00425860((CChevronOwnerDrawMenu *)(param_1 + 4));
  local_8 = 0xffffffff;
  FUN_00425500(param_1);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_00425a30(void *this,undefined4 *param_1,undefined4 param_2)

{
  undefined4 local_8;
  
  FUN_00425220(&local_8,0xfffffc00);
  FUN_00425720(this,param_1,&local_8);
  *(undefined4 *)((int)this + 0x20) = param_2;
  *(undefined ***)this = &PTR_FUN_0042dcfc;
  return this;
}



void __thiscall FUN_00425a80(void *this,int *param_1)

{
  undefined4 *puVar1;
  undefined1 local_8 [4];
  
  FUN_00425550(this,param_1);
  puVar1 = (undefined4 *)(**(code **)(*param_1 + 0x78))(local_8);
  *(undefined4 *)((int)this + 0x18) = *puVar1;
  FUN_00425ad0((void *)((int)this + 0x18),*(uint *)((int)this + 0x20));
  return;
}



void __thiscall FUN_00425ad0(void *this,uint param_1)

{
  undefined4 local_8;
  
  for (local_8 = 0; local_8 < param_1; local_8 = local_8 + 1) {
                    // WARNING: Load size is inaccurate
    FUN_00425240(this,*this + 2);
  }
  return;
}



void * __thiscall FUN_00425b10(void *this,uint param_1)

{
  FUN_00425b40((CChevronOwnerDrawMenu *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_00425b40(CChevronOwnerDrawMenu *param_1)

{
  FUN_00425860(param_1);
  return;
}



void * __thiscall FUN_00425b60(void *this,undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 local_c;
  undefined4 local_8;
  
  FUN_00425220(&local_8,0xfffffc00);
  FUN_00425220(&local_c,0xfffffc00);
  FUN_00425880(this,param_1,&local_c,&local_8);
  *(undefined4 *)((int)this + 0x50) = param_2;
  *(undefined4 *)((int)this + 0x54) = param_3;
  *(undefined ***)this = &PTR_FUN_0042dd08;
  return this;
}



void __thiscall FUN_00425bc0(void *this,int *param_1)

{
  undefined4 *puVar1;
  undefined1 local_c [4];
  undefined1 local_8 [4];
  
  FUN_00425900(this,param_1);
  puVar1 = (undefined4 *)(**(code **)(*param_1 + 0x78))(local_8);
  *(undefined4 *)((int)this + 0x28) = *puVar1;
  puVar1 = (undefined4 *)(**(code **)(*param_1 + 0x78))(local_c);
  *(undefined4 *)((int)this + 0x48) = *puVar1;
  FUN_00425ad0((void *)((int)this + 0x28),*(uint *)((int)this + 0x50));
  FUN_00425ad0((void *)((int)this + 0x48),*(uint *)((int)this + 0x54));
  return;
}



void * __thiscall FUN_00425c30(void *this,uint param_1)

{
  FUN_00425c60((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_00425c60(undefined4 *param_1)

{
  FUN_004259d0(param_1);
  return;
}



void * __thiscall FUN_00425c80(void *this,undefined4 *param_1)

{
  FUN_00425430(this,param_1);
  *(undefined ***)this = &PTR_FUN_0042dd14;
  return this;
}



void __thiscall FUN_00425cb0(void *this,int *param_1)

{
  (**(code **)(*param_1 + 0x14))(this);
  return;
}



void * __thiscall FUN_00425cd0(void *this,uint param_1)

{
  FUN_00425d00((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void __fastcall FUN_00425d00(undefined4 *param_1)

{
  FUN_00425500(param_1);
  return;
}



void * __fastcall FUN_00425d20(void *param_1)

{
  FUN_00405850(param_1);
  FUN_00425d50((void *)((int)param_1 + 8),0);
  return param_1;
}



void * __thiscall FUN_00425d50(void *this,undefined4 param_1)

{
  FUN_00425d70(this,param_1);
  return this;
}



void * __thiscall FUN_00425d70(void *this,undefined4 param_1)

{
  *(undefined4 *)this = param_1;
                    // WARNING: Load size is inaccurate
  if (*this != 0) {
                    // WARNING: Load size is inaccurate
    FUN_004252c0(*this);
  }
  return this;
}



void * __thiscall FUN_00425da0(void *this,undefined4 *param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  uVar1 = param_1[1];
  *(undefined4 *)this = *param_1;
  *(undefined4 *)((int)this + 4) = uVar1;
  FUN_00425d50((void *)((int)this + 8),param_2);
  return this;
}



void __fastcall FUN_00425dd0(int *param_1)

{
  FUN_00425310(param_1);
  return;
}



void * __fastcall FUN_00425df0(void *param_1)

{
  FUN_00405850(param_1);
  *(undefined4 *)((int)param_1 + 8) = 0;
  return param_1;
}



void * __thiscall FUN_00425e10(void *this,undefined4 param_1)

{
  FUN_00405850(this);
  FUN_00425e40(this,0,0,param_1);
  return this;
}



void * __thiscall FUN_00425e40(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  default_error_condition(this,param_1,param_2);
  *(undefined4 *)((int)this + 8) = param_3;
  return this;
}



bool __thiscall FUN_00425e70(void *this,int param_1)

{
  return *(int *)(param_1 + 8) == *(int *)((int)this + 8);
}



// Library Function - Single Match
//  public: __thiscall Concurrency::details::SafeSQueue<class
// Concurrency::details::UMSThreadProxy,class
// Concurrency::details::_NonReentrantLock>::SafeSQueue<class
// Concurrency::details::UMSThreadProxy,class Concurrency::details::_NonReentrantLock>(void)
// 
// Libraries: Visual Studio 2010, Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

SafeSQueue<> * __thiscall Concurrency::details::SafeSQueue<>::SafeSQueue<>(SafeSQueue<> *this)

{
  FUN_00405850(this);
  FUN_00425790((undefined4 *)(this + 8));
  return this;
}



void * __thiscall FUN_00425ec0(void *this,undefined4 param_1,undefined4 param_2,uint param_3)

{
  default_error_condition(this,param_1,param_2);
  FUN_00425220((void *)((int)this + 8),param_3);
  return this;
}



void * __fastcall FUN_00425ef0(void *param_1)

{
  FUN_00405850(param_1);
  FUN_00405850((void *)((int)param_1 + 8));
  return param_1;
}



void * __thiscall
FUN_00425f20(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  default_error_condition(this,param_1,param_2);
  default_error_condition((void *)((int)this + 8),param_3,param_4);
  return this;
}



void * __fastcall FUN_00425f60(void *param_1)

{
  FUN_00405850(param_1);
  *(undefined1 *)((int)param_1 + 8) = 0;
  *(undefined1 *)((int)param_1 + 9) = 0;
  return param_1;
}



void * __thiscall
FUN_00425f90(void *this,undefined4 param_1,undefined4 param_2,undefined1 param_3,undefined1 param_4)

{
  default_error_condition(this,param_1,param_2);
  *(undefined1 *)((int)this + 8) = param_3;
  *(undefined1 *)((int)this + 9) = param_4;
  return this;
}



CString * __fastcall FUN_00425fd0(CString *param_1)

{
  undefined4 *puVar1;
  undefined1 local_20 [16];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &this_0042b232;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString(param_1);
  local_8 = 0;
  CString::CString(param_1 + 4);
  local_8._0_1_ = 1;
  CString::CString(param_1 + 8);
  local_8._0_1_ = 2;
  FUN_00404f20(param_1 + 0xc);
  FUN_00405850(param_1 + 0x1c);
  FUN_00405850(param_1 + 0x24);
  param_1[0x2c] = (CString)0x1;
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)(param_1 + 0x30));
  local_8._0_1_ = 3;
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)(param_1 + 0x4c));
  local_8._0_1_ = 4;
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)(param_1 + 0x68));
  local_8._0_1_ = 5;
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)(param_1 + 0x84));
  local_8._0_1_ = 6;
  *(undefined4 *)(param_1 + 0xa4) = 0;
  *(undefined4 *)(param_1 + 0xa8) = 0;
  *(undefined4 *)(param_1 + 0xac) = 10;
  *(undefined4 *)(param_1 + 0xb0) = 0;
  *(undefined4 *)(param_1 + 0xb4) = 0;
  *(undefined4 *)(param_1 + 0xb8) = 0;
  *(undefined4 *)(param_1 + 0xbc) = 0;
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)(param_1 + 0xc0));
  local_8._0_1_ = 7;
  CTypeLibCacheMap::CTypeLibCacheMap((CTypeLibCacheMap *)(param_1 + 0xdc));
  local_8 = CONCAT31(local_8._1_3_,8);
  puVar1 = (undefined4 *)FUN_00414240(local_20,0xc0,0x80,0x1c0,0x100);
  *(undefined4 *)(param_1 + 0xc) = *puVar1;
  *(undefined4 *)(param_1 + 0x10) = puVar1[1];
  *(undefined4 *)(param_1 + 0x14) = puVar1[2];
  *(undefined4 *)(param_1 + 0x18) = puVar1[3];
  ExceptionList = local_10;
  return param_1;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_00426340(this,10);
  *(undefined ***)this = &PTR_LAB_0042dd20;
  return this;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_00426450(this,10);
  *(undefined ***)this = &PTR_LAB_0042dd34;
  return this;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_00426560(this,10);
  *(undefined ***)this = &PTR_LAB_0042dd48;
  return this;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_00426670(this,10);
  *(undefined ***)this = &PTR_LAB_0042dd5c;
  return this;
}



// Library Function - Single Match
//  public: __thiscall CTypeLibCacheMap::CTypeLibCacheMap(void)
// 
// Libraries: Visual Studio 2003 Debug, Visual Studio 2005 Debug, Visual Studio 2008 Debug, Visual
// Studio 2010 Debug

CTypeLibCacheMap * __thiscall CTypeLibCacheMap::CTypeLibCacheMap(CTypeLibCacheMap *this)

{
  FUN_00426780(this,10);
  *(undefined ***)this = &PTR_LAB_0042dd70;
  return this;
}



void * __thiscall FUN_00426250(void *this,uint param_1)

{
  FUN_00426c80((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void * __thiscall FUN_00426280(void *this,uint param_1)

{
  FUN_00426ca0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void * __thiscall FUN_004262b0(void *this,uint param_1)

{
  FUN_00426cc0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void * __thiscall FUN_004262e0(void *this,uint param_1)

{
  FUN_00426ce0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void * __thiscall FUN_00426310(void *this,uint param_1)

{
  FUN_00426d20((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void * __thiscall FUN_00426340(void *this,undefined4 param_1)

{
  FUN_00404b20((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_0042dd84;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



void __thiscall FUN_004263a0(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_18 [3];
  ulong local_c;
  undefined4 *local_8;
  
  FUN_00401400();
  bVar1 = FUN_00404cf0((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      FUN_00425df0(local_18);
      FUN_00426b90(param_1,local_18,1);
      FUN_004234a0(this,local_18);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_00426b90(param_1,local_8 + 2,1);
    }
  }
  return;
}



void * __thiscall FUN_00426450(void *this,undefined4 param_1)

{
  FUN_00404b20((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_0042dd98;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



void __thiscall FUN_004264b0(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  SafeSQueue<> local_18 [12];
  ulong local_c;
  undefined4 *local_8;
  
  FUN_00401400();
  bVar1 = FUN_00404cf0((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      Concurrency::details::SafeSQueue<>::SafeSQueue<>(local_18);
      FUN_00426b90(param_1,local_18,1);
      FUN_00423570(this,(undefined4 *)local_18);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_00426b90(param_1,local_8 + 2,1);
    }
  }
  return;
}



void * __thiscall FUN_00426560(void *this,undefined4 param_1)

{
  FUN_00404b20((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_0042ddac;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



void __thiscall FUN_004265c0(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_1c [4];
  ulong local_c;
  undefined4 *local_8;
  
  FUN_00401400();
  bVar1 = FUN_00404cf0((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      FUN_00425ef0(local_1c);
      FUN_004051d0(param_1,local_1c,1);
      FUN_00423640(this,local_1c);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_004051d0(param_1,local_8 + 2,1);
    }
  }
  return;
}



void * __thiscall FUN_00426670(void *this,undefined4 param_1)

{
  FUN_00404b20((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_0042ddc0;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



void __thiscall FUN_004266d0(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 local_18 [3];
  ulong local_c;
  undefined4 *local_8;
  
  FUN_00401400();
  bVar1 = FUN_00404cf0((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_c = CArchive::ReadCount(param_1);
    while (local_c != 0) {
      local_c = local_c - 1;
      FUN_00425f60(local_18);
      FUN_00426b90(param_1,local_18,1);
      FUN_00423700(this,local_18);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_8 = *(undefined4 **)((int)this + 4); local_8 != (undefined4 *)0x0;
        local_8 = (undefined4 *)*local_8) {
      FUN_00426b90(param_1,local_8 + 2,1);
    }
  }
  return;
}



void * __thiscall FUN_00426780(void *this,undefined4 param_1)

{
  FUN_00404b20((undefined4 *)this);
  *(undefined ***)this = &PTR_LAB_0042ddd4;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = param_1;
  return this;
}



void __thiscall FUN_004267e0(void *this,CArchive *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  CDHtmlElementEventSink local_24 [12];
  ulong local_18;
  undefined4 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042b249;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00401400();
  bVar1 = FUN_00404cf0((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_18 = CArchive::ReadCount(param_1);
    while (local_18 != 0) {
      local_18 = local_18 - 1;
      FUN_00425d20(local_24);
      local_8 = 0;
      FUN_00426b90(param_1,local_24,1);
      FUN_00423ad0(this,(undefined4 *)local_24);
      local_8 = 0xffffffff;
      CDHtmlElementEventSink::~CDHtmlElementEventSink(local_24);
    }
  }
  else {
    CArchive::WriteCount(param_1,*(ulong *)((int)this + 0xc));
    for (local_14 = *(undefined4 **)((int)this + 4); local_14 != (undefined4 *)0x0;
        local_14 = (undefined4 *)*local_14) {
      FUN_00426b90(param_1,local_14 + 2,1);
    }
  }
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_004268c0(void *this,uint param_1)

{
  FUN_004268f0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_004268f0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0042b269;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_0042dd84;
  local_8 = 0;
  FUN_004242d0((int)param_1);
  local_8 = 0xffffffff;
  FUN_00404b70(param_1);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_00426950(void *this,uint param_1)

{
  FUN_00426980((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_00426980(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0042b289;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_0042dd98;
  local_8 = 0;
  FUN_004246d0((int)param_1);
  local_8 = 0xffffffff;
  FUN_00404b70(param_1);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_004269e0(void *this,uint param_1)

{
  FUN_00426a10((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_00426a10(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0042b2a9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_0042ddac;
  local_8 = 0;
  FUN_00405150((int)param_1);
  local_8 = 0xffffffff;
  FUN_00404b70(param_1);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_00426a70(void *this,uint param_1)

{
  FUN_00426aa0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_00426aa0(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0042b2c9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_0042ddc0;
  local_8 = 0;
  FUN_004246d0((int)param_1);
  local_8 = 0xffffffff;
  FUN_00404b70(param_1);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_00426b00(void *this,uint param_1)

{
  FUN_00426b30((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401410(this);
  }
  return this;
}



void __fastcall FUN_00426b30(undefined4 *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0042b2e9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_0042ddd4;
  local_8 = 0;
  FUN_004249d0((int)param_1);
  local_8 = 0xffffffff;
  FUN_00404b70(param_1);
  ExceptionList = local_10;
  return;
}



void FUN_00426b90(CArchive *param_1,void *param_2,int param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_00404cf0((int)param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    CArchive::Read(param_1,param_2,param_3 * 0xc);
  }
  else {
    CArchive::Write(param_1,param_2,param_3 * 0xc);
  }
  return;
}



undefined4 * __thiscall FUN_00426bd0(void *this,undefined4 *param_1)

{
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_14 = *(undefined4 *)((int)this + 0xc);
  local_10 = *(undefined4 *)((int)this + 0x10);
  local_c = *(undefined4 *)((int)this + 0x14);
  local_8 = *(undefined4 *)((int)this + 0x18);
  FUN_00426c30(&local_14,5,5);
  *param_1 = local_14;
  param_1[1] = local_10;
  param_1[2] = local_c;
  param_1[3] = local_8;
  return param_1;
}



void __thiscall FUN_00426c30(void *this,int param_1,int param_2)

{
  InflateRect((LPRECT)this,-param_1,-param_2);
  return;
}



// Library Function - Single Match
//  public: int __thiscall CMFCOutlookBarPane::IsBackgroundTexture(void)const 
// 
// Library: Visual Studio 2010 Debug

int __thiscall CMFCOutlookBarPane::IsBackgroundTexture(CMFCOutlookBarPane *this)

{
  int iVar1;
  
  iVar1 = FUN_00423620((int)(this + 0xdc));
  return (uint)(iVar1 != 0);
}



void __fastcall FUN_00426c80(undefined4 *param_1)

{
  FUN_004268f0(param_1);
  return;
}



void __fastcall FUN_00426ca0(undefined4 *param_1)

{
  FUN_00426980(param_1);
  return;
}



void __fastcall FUN_00426cc0(undefined4 *param_1)

{
  FUN_00426a10(param_1);
  return;
}



void __fastcall FUN_00426ce0(undefined4 *param_1)

{
  FUN_00426aa0(param_1);
  return;
}



void __fastcall FUN_00426d00(undefined4 *param_1)

{
  FUN_00423ec0(param_1);
  return;
}



void __fastcall FUN_00426d20(undefined4 *param_1)

{
  FUN_00426b30(param_1);
  return;
}



void __fastcall FUN_00426d40(int param_1)

{
  FUN_0040b5d0(param_1 + 0x138);
  *(undefined4 *)(param_1 + 0x134) = 0;
  return;
}



void __fastcall FUN_00426d66(GAME *param_1)

{
  uint uVar1;
  int iVar2;
  uint local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0042b309;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  *(int *)(param_1 + 0x134) = *(int *)(param_1 + 0x134) + 1;
  uVar1 = FUN_00423620((int)(param_1 + 0x138));
  for (local_18 = *(int *)(param_1 + 0x134) - 1; local_18 < uVar1; local_18 = local_18 + 1) {
    FUN_004277a0(param_1 + 0x138,*(int *)(param_1 + 0x134) - 1);
  }
  FUN_0040bed0(param_1 + 0x138,(undefined4 *)&stack0x00000004);
  iVar2 = FUN_004213b1((int)param_1);
  if (iVar2 != 0) {
    FUN_004225df(param_1);
  }
  local_8 = 0xffffffff;
  FUN_00404750((int)&stack0x00000004);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_00426e35(void *this,undefined4 *param_1,int param_2)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  undefined3 extraout_var_03;
  uint uVar2;
  undefined3 extraout_var_04;
  CString *pCVar3;
  int iVar4;
  void *pvVar5;
  undefined4 *puVar6;
  CString local_74 [4];
  uint local_70;
  CString local_6c [4];
  CString local_68 [4];
  int local_64;
  uint local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  int local_4c;
  uint local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  int local_34;
  uint local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  ITEM *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042b32e;
  local_10 = ExceptionList;
  local_14 = (ITEM *)0x0;
  ExceptionList = &local_10;
  switch(param_1[2]) {
  case 0:
    ExceptionList = &local_10;
    local_4c = FUN_00423770((int)(param_1 + 3));
    FUN_00405960(&local_44);
    local_48 = 0;
    bVar1 = IsEmpty((int)(param_1 + 3));
    if (CONCAT31(extraout_var_01,bVar1) == 0) {
      puVar6 = (undefined4 *)FUN_0041be90(&local_4c);
      local_44 = *puVar6;
      local_40 = puVar6[1];
      local_3c = puVar6[2];
      local_38 = puVar6[3];
    }
    local_48 = 0;
    while ((uVar2 = FUN_00423620((int)(param_1 + 3)), local_48 < uVar2 &&
           (bVar1 = IsEmpty((int)(param_1 + 3)), CONCAT31(extraout_var_02,bVar1) == 0))) {
      local_14 = MAP::GetItem((MAP *)((int)this + 0xe23c),local_44,local_40);
      if (param_2 == 0) {
        (**(code **)(*(int *)local_14 + 0x20))();
      }
      else {
        (**(code **)(*(int *)local_14 + 0x1c))();
      }
      local_48 = local_48 + 1;
      uVar2 = FUN_00423620((int)(param_1 + 3));
      if (local_48 < uVar2) {
        puVar6 = (undefined4 *)FUN_0041be90(&local_4c);
        local_44 = *puVar6;
        local_40 = puVar6[1];
        local_3c = puVar6[2];
        local_38 = puVar6[3];
      }
    }
    break;
  case 1:
    ExceptionList = &local_10;
    local_34 = FUN_00423770((int)(param_1 + 3));
    FUN_00405960(&local_2c);
    local_30 = 0;
    bVar1 = IsEmpty((int)(param_1 + 3));
    if (CONCAT31(extraout_var,bVar1) == 0) {
      puVar6 = (undefined4 *)FUN_0041be90(&local_34);
      local_2c = *puVar6;
      local_28 = puVar6[1];
      local_24 = puVar6[2];
      local_20 = puVar6[3];
    }
    local_30 = 0;
    while ((uVar2 = FUN_00423620((int)(param_1 + 3)), local_30 < uVar2 &&
           (bVar1 = IsEmpty((int)(param_1 + 3)), CONCAT31(extraout_var_00,bVar1) == 0))) {
      local_14 = MAP::GetItem((MAP *)((int)this + 0xe23c),local_2c,local_28);
      if (param_2 == 0) {
        (**(code **)(*(int *)local_14 + 0x1c))();
      }
      else {
        (**(code **)(*(int *)local_14 + 0x20))();
      }
      local_30 = local_30 + 1;
      uVar2 = FUN_00423620((int)(param_1 + 3));
      if (local_30 < uVar2) {
        puVar6 = (undefined4 *)FUN_0041be90(&local_34);
        local_2c = *puVar6;
        local_28 = puVar6[1];
        local_24 = puVar6[2];
        local_20 = puVar6[3];
      }
    }
    break;
  case 2:
    ExceptionList = &local_10;
    local_64 = FUN_00423770((int)(param_1 + 3));
    FUN_00405960(&local_5c);
    local_60 = 0;
    bVar1 = IsEmpty((int)(param_1 + 3));
    if (CONCAT31(extraout_var_03,bVar1) == 0) {
      puVar6 = (undefined4 *)FUN_0041be90(&local_64);
      local_5c = *puVar6;
      local_58 = puVar6[1];
      local_54 = puVar6[2];
      local_50 = puVar6[3];
    }
    local_60 = 0;
    while ((uVar2 = FUN_00423620((int)(param_1 + 3)), local_60 < uVar2 &&
           (bVar1 = IsEmpty((int)(param_1 + 3)), CONCAT31(extraout_var_04,bVar1) == 0))) {
      MAP::SelectTile((MAP *)((int)this + 0xe23c),local_5c,local_58);
      MAP::SwapTile((MAP *)((int)this + 0xe23c),local_54,local_50);
      local_60 = local_60 + 1;
      uVar2 = FUN_00423620((int)(param_1 + 3));
      if (local_60 < uVar2) {
        puVar6 = (undefined4 *)FUN_0041be90(&local_64);
        local_5c = *puVar6;
        local_58 = puVar6[1];
        local_54 = puVar6[2];
        local_50 = puVar6[3];
      }
    }
    break;
  case 3:
    ExceptionList = &local_10;
    pCVar3 = (CString *)MAP::Data((MAP *)((int)this + 0xe23c));
    local_8 = 0;
    CString::CString(local_68,pCVar3);
    local_8 = CONCAT31(local_8._1_3_,2);
    FUN_004014d0(local_6c);
    MAP::Set((MAP *)((int)this + 0xe23c),(CString *)(param_1 + 10));
    CString::operator=((CString *)(param_1 + 10),local_68);
    MAP::RefreshBothLevelmapBuffers((MAP *)((int)this + 0xe23c));
    local_8 = 0xffffffff;
    CString::~CString(local_68);
  }
  local_1c = *(undefined4 *)((int)this + 0xe01c);
  local_18 = *(undefined4 *)((int)this + 0xe020);
  FUN_0040f6ea(this,param_1);
  *param_1 = local_1c;
  param_1[1] = local_18;
  bVar1 = FUN_0040e0e0((int)this);
  if (bVar1) {
    iVar4 = FUN_004056c0((int)this);
    FUN_004132e0(this,iVar4);
    puVar6 = (undefined4 *)(*(int *)((int)this + 0xe010) + 0x7c);
    pvVar5 = (void *)MAP::Data((MAP *)((int)this + 0xe23c));
    local_8 = 3;
    bVar1 = FUN_0040fdf0(pvVar5,puVar6);
    local_70 = CONCAT31(local_70._1_3_,bVar1);
    local_8 = 0xffffffff;
    FUN_004014d0(local_74);
    if ((local_70 & 0xff) != 0) {
      FUN_0040f3a1();
    }
  }
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_004272f7(void *param_1)

{
  undefined4 *puVar1;
  
  if (*(int *)((int)param_1 + 0x134) == 0) {
    MessageBeep(0);
  }
  else {
    puVar1 = (undefined4 *)
             FUN_00427670((void *)((int)param_1 + 0x138),*(int *)((int)param_1 + 0x134) - 1);
    FUN_00426e35(param_1,puVar1,1);
    *(int *)((int)param_1 + 0x134) = *(int *)((int)param_1 + 0x134) + -1;
  }
  return;
}



void __fastcall FUN_0042735b(void *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = FUN_00423620((int)param_1 + 0x138);
  if (*(int *)((int)param_1 + 0x134) < iVar1) {
    puVar2 = (undefined4 *)
             FUN_00427670((void *)((int)param_1 + 0x138),*(uint *)((int)param_1 + 0x134));
    FUN_00426e35(param_1,puVar2,0);
    *(int *)((int)param_1 + 0x134) = *(int *)((int)param_1 + 0x134) + 1;
  }
  else {
    MessageBeep(0);
  }
  return;
}



void __thiscall FUN_004273c9(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined1 auStack_84 [36];
  undefined4 uStack_60;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined1 local_30 [32];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042b341;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_004046f0(&local_3c);
  local_8 = 0;
  local_34 = 1;
  FUN_00405960(&local_4c);
  local_4c = param_1;
  local_48 = param_2;
  uStack_60 = 0x42741d;
  FUN_004050e0(local_30,&local_4c);
  local_3c = *(undefined4 *)((int)this + 0xe01c);
  local_38 = *(undefined4 *)((int)this + 0xe020);
  FUN_004047a0(auStack_84,&local_3c);
  FUN_00426d66((GAME *)this);
  local_8 = 0xffffffff;
  FUN_00404750((int)&local_3c);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_0042746d(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined1 auStack_84 [36];
  undefined4 uStack_60;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined1 local_30 [32];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042b354;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_004046f0(&local_3c);
  local_8 = 0;
  local_34 = 0;
  FUN_00405960(&local_4c);
  local_4c = param_1;
  local_48 = param_2;
  uStack_60 = 0x4274c1;
  FUN_004050e0(local_30,&local_4c);
  local_3c = *(undefined4 *)((int)this + 0xe01c);
  local_38 = *(undefined4 *)((int)this + 0xe020);
  FUN_004047a0(auStack_84,&local_3c);
  FUN_00426d66((GAME *)this);
  local_8 = 0xffffffff;
  FUN_00404750((int)&local_3c);
  ExceptionList = local_10;
  return;
}



void __thiscall
FUN_00427511(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined1 auStack_84 [36];
  undefined4 uStack_60;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined1 local_30 [32];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042b367;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_004046f0(&local_3c);
  local_8 = 0;
  local_34 = 2;
  FUN_00405960(&local_4c);
  local_4c = param_1;
  local_48 = param_2;
  local_44 = param_3;
  local_40 = param_4;
  uStack_60 = 0x427571;
  FUN_004050e0(local_30,&local_4c);
  local_3c = *(undefined4 *)((int)this + 0xe01c);
  local_38 = *(undefined4 *)((int)this + 0xe020);
  FUN_004047a0(auStack_84,&local_3c);
  FUN_00426d66((GAME *)this);
  local_8 = 0xffffffff;
  FUN_00404750((int)&local_3c);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_004275c1(GAME *param_1)

{
  undefined1 auStack_74 [36];
  undefined4 uStack_50;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined1 local_30 [32];
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_0042b383;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  FUN_004046f0(&local_3c);
  local_8._0_1_ = 1;
  local_34 = 2;
  uStack_50 = 0x427605;
  FUN_0040bfc0(local_30,&stack0x00000004);
  local_3c = *(undefined4 *)(param_1 + 0xe01c);
  local_38 = *(undefined4 *)(param_1 + 0xe020);
  FUN_004047a0(auStack_74,&local_3c);
  FUN_00426d66(param_1);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_00404750((int)&local_3c);
  local_8 = 0xffffffff;
  FUN_00404820((undefined4 *)&stack0x00000004);
  ExceptionList = local_10;
  return;
}



void * __thiscall FUN_00427670(void *this,uint param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  void *pvVar2;
  uint uVar3;
  void *local_34;
  void *local_30;
  int local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042b3a6;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  bVar1 = IsEmpty((int)this);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    uVar3 = FUN_00423620((int)this);
    if (param_1 < uVar3) {
      local_18 = FUN_00423770((int)this);
      local_14 = 0;
      while ((local_14 < param_1 && (uVar3 = FUN_00423620((int)this), local_14 < uVar3))) {
        FUN_0041be90(&local_18);
        local_14 = local_14 + 1;
      }
      local_30 = (void *)FUN_0041be90(&local_18);
    }
    else {
      pvVar2 = operator_new(0x2c);
      local_8 = 1;
      if (pvVar2 == (void *)0x0) {
        local_34 = (void *)0x0;
        local_30 = local_34;
      }
      else {
        local_30 = FUN_004046f0(pvVar2);
      }
    }
  }
  else {
    pvVar2 = operator_new(0x2c);
    local_8 = 0;
    if (pvVar2 == (void *)0x0) {
      local_30 = (void *)0x0;
    }
    else {
      local_30 = FUN_004046f0(pvVar2);
    }
  }
  ExceptionList = local_10;
  return local_30;
}



void __thiscall FUN_004277a0(void *this,uint param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  uint uVar2;
  int *local_c;
  uint local_8;
  
  bVar1 = IsEmpty((int)this);
  if ((CONCAT31(extraout_var,bVar1) == 0) && (uVar2 = FUN_00423620((int)this), param_1 < uVar2)) {
    local_c = (int *)FUN_00423770((int)this);
    local_8 = 0;
    while ((local_8 < param_1 && (uVar2 = FUN_00423620((int)this), local_8 < uVar2))) {
      FUN_0041be90((int *)&local_c);
      local_8 = local_8 + 1;
    }
    FUN_00427820(this,local_c);
  }
  return;
}



void __thiscall FUN_00427820(void *this,int *param_1)

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
  FUN_00427890(this,param_1);
  return;
}



void __thiscall FUN_00427890(void *this,undefined4 *param_1)

{
  FUN_0040b650(param_1 + 2,1);
  *param_1 = *(undefined4 *)((int)this + 0x10);
  *(undefined4 **)((int)this + 0x10) = param_1;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + -1;
  if (*(int *)((int)this + 0xc) == 0) {
    FUN_0040b5d0((int)this);
  }
  return;
}



LRESULT CWnd::DefWindowProcA(HWND hWnd,UINT Msg,WPARAM wParam,LPARAM lParam)

{
  LRESULT LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427976. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = DefWindowProcA(hWnd,Msg,wParam,lParam);
  return LVar1;
}



void DDX_Control(CDataExchange *param_1,int param_2,CWnd *param_3)

{
                    // WARNING: Could not recover jumptable at 0x00427a48. Too many branches
                    // WARNING: Treating indirect jump as call
  DDX_Control(param_1,param_2,param_3);
  return;
}



BOOL CWnd::SetWindowTextA(HWND hWnd,LPCSTR lpString)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427a4e. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = SetWindowTextA(hWnd,lpString);
  return BVar1;
}



HWND CWnd::GetDlgItem(HWND hDlg,int nIDDlgItem)

{
  HWND pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427a54. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = GetDlgItem(hDlg,nIDDlgItem);
  return pHVar1;
}



void __thiscall CString::~CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x00427a5a. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CString(this);
  return;
}



void operator+(CString *param_1,char *param_2)

{
                    // WARNING: Could not recover jumptable at 0x00427a60. Too many branches
                    // WARNING: Treating indirect jump as call
  operator+(param_1,param_2);
  return;
}



void __thiscall CDialog::OnOK(CDialog *this)

{
                    // WARNING: Could not recover jumptable at 0x00427a66. Too many branches
                    // WARNING: Treating indirect jump as call
  OnOK(this);
  return;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00427a6c. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void operator+(CString *param_1,CString *param_2)

{
                    // WARNING: Could not recover jumptable at 0x00427a72. Too many branches
                    // WARNING: Treating indirect jump as call
  operator+(param_1,param_2);
  return;
}



void __thiscall CString::CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x00427a78. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this);
  return;
}



void __thiscall CString::CString(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00427a7e. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



void __thiscall CDialog::CDialog(CDialog *this,uint param_1,CWnd *param_2)

{
                    // WARNING: Could not recover jumptable at 0x00427a84. Too many branches
                    // WARNING: Treating indirect jump as call
  CDialog(this,param_1,param_2);
  return;
}



void __thiscall CDialog::~CDialog(CDialog *this)

{
                    // WARNING: Could not recover jumptable at 0x00427a8a. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CDialog(this);
  return;
}



void __thiscall CImageList::~CImageList(CImageList *this)

{
                    // WARNING: Could not recover jumptable at 0x00427a90. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CImageList(this);
  return;
}



void __thiscall CImageList::CImageList(CImageList *this)

{
                    // WARNING: Could not recover jumptable at 0x00427a96. Too many branches
                    // WARNING: Treating indirect jump as call
  CImageList(this);
  return;
}



void __thiscall CListCtrl::~CListCtrl(CListCtrl *this)

{
                    // WARNING: Could not recover jumptable at 0x00427a9c. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CListCtrl(this);
  return;
}



BOOL CWnd::MoveWindow(HWND hWnd,int X,int Y,int nWidth,int nHeight,BOOL bRepaint)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427aa2. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = MoveWindow(hWnd,X,Y,nWidth,nHeight,bRepaint);
  return BVar1;
}



HWND CWnd::SetFocus(HWND hWnd)

{
  HWND pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427aa8. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = SetFocus(hWnd);
  return pHVar1;
}



CString * __thiscall CString::operator=(CString *this,CString *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427aae. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator=(this,param_1);
  return pCVar1;
}



void __thiscall CString::CString(CString *this,CString *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00427ab4. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



void __thiscall CString::SetAt(CString *this,int param_1,char param_2)

{
                    // WARNING: Could not recover jumptable at 0x00427aba. Too many branches
                    // WARNING: Treating indirect jump as call
  SetAt(this,param_1,param_2);
  return;
}



CString * __thiscall CString::operator+=(CString *this,CString *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427ac0. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator+=(this,param_1);
  return pCVar1;
}



void operator+(char *param_1,CString *param_2)

{
                    // WARNING: Could not recover jumptable at 0x00427ac6. Too many branches
                    // WARNING: Treating indirect jump as call
  operator+(param_1,param_2);
  return;
}



void __thiscall CString::MakeLower(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x00427acc. Too many branches
                    // WARNING: Treating indirect jump as call
  MakeLower(this);
  return;
}



int __thiscall
CImageList::Create(CImageList *this,int param_1,int param_2,uint param_3,int param_4,int param_5)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427ad2. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Create(this,param_1,param_2,param_3,param_4,param_5);
  return iVar1;
}



int __thiscall CImageList::DeleteImageList(CImageList *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427ad8. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = DeleteImageList(this);
  return iVar1;
}



LRESULT CWnd::SendDlgItemMessageA(HWND hDlg,int nIDDlgItem,UINT Msg,WPARAM wParam,LPARAM lParam)

{
  LRESULT LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427ade. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = SendDlgItemMessageA(hDlg,nIDDlgItem,Msg,wParam,lParam);
  return LVar1;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427ae4. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



CString * __thiscall CString::operator=(CString *this,char *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427aea. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator=(this,param_1);
  return pCVar1;
}



void __thiscall CString::CString(CString *this,char *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x00427af0. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1,param_2);
  return;
}



void __thiscall CString::MakeUpper(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x00427af6. Too many branches
                    // WARNING: Treating indirect jump as call
  MakeUpper(this);
  return;
}



ulong __thiscall CArchive::ReadCount(CArchive *this)

{
  ulong uVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427b02. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = ReadCount(this);
  return uVar1;
}



void __thiscall CArchive::WriteCount(CArchive *this,ulong param_1)

{
                    // WARNING: Could not recover jumptable at 0x00427b08. Too many branches
                    // WARNING: Treating indirect jump as call
  WriteCount(this,param_1);
  return;
}



void __thiscall CPlex::FreeDataChain(CPlex *this)

{
                    // WARNING: Could not recover jumptable at 0x00427b0e. Too many branches
                    // WARNING: Treating indirect jump as call
  FreeDataChain(this);
  return;
}



CPlex * CPlex::Create(CPlex **param_1,uint param_2,uint param_3)

{
  CPlex *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427b14. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = Create(param_1,param_2,param_3);
  return pCVar1;
}



uint __thiscall CArchive::Read(CArchive *this,void *param_1,uint param_2)

{
  uint uVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427b1a. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = Read(this,param_1,param_2);
  return uVar1;
}



void __thiscall CArchive::Write(CArchive *this,void *param_1,uint param_2)

{
                    // WARNING: Could not recover jumptable at 0x00427b20. Too many branches
                    // WARNING: Treating indirect jump as call
  Write(this,param_1,param_2);
  return;
}



CDC * CDC::FromHandle(HDC__ *param_1)

{
  CDC *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427b26. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = FromHandle(param_1);
  return pCVar1;
}



void __thiscall CWnd::CWnd(CWnd *this)

{
                    // WARNING: Could not recover jumptable at 0x00427b5c. Too many branches
                    // WARNING: Treating indirect jump as call
  CWnd(this);
  return;
}



CImageList * CImageList::FromHandle(_IMAGELIST *param_1)

{
  CImageList *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427b62. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = FromHandle(param_1);
  return pCVar1;
}



BOOL CGdiObject::DeleteObject(HGDIOBJ ho)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427b74. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = DeleteObject(ho);
  return BVar1;
}



void DDX_Text(CDataExchange *param_1,int param_2,CString *param_3)

{
                    // WARNING: Could not recover jumptable at 0x00427b7a. Too many branches
                    // WARNING: Treating indirect jump as call
  DDX_Text(param_1,param_2,param_3);
  return;
}



void __thiscall CWnd::CenterWindow(CWnd *this,CWnd *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00427b80. Too many branches
                    // WARNING: Treating indirect jump as call
  CenterWindow(this,param_1);
  return;
}



CWnd * CWnd::FromHandle(HWND__ *param_1)

{
  CWnd *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427b86. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = FromHandle(param_1);
  return pCVar1;
}



void __thiscall CComboBox::~CComboBox(CComboBox *this)

{
                    // WARNING: Could not recover jumptable at 0x00427b8c. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CComboBox(this);
  return;
}



void __thiscall CListBox::~CListBox(CListBox *this)

{
                    // WARNING: Could not recover jumptable at 0x00427b92. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CListBox(this);
  return;
}



void DDX_Radio(CDataExchange *param_1,int param_2,int *param_3)

{
                    // WARNING: Could not recover jumptable at 0x00427b98. Too many branches
                    // WARNING: Treating indirect jump as call
  DDX_Radio(param_1,param_2,param_3);
  return;
}



void DDX_Slider(CDataExchange *param_1,int param_2,int *param_3)

{
                    // WARNING: Could not recover jumptable at 0x00427b9e. Too many branches
                    // WARNING: Treating indirect jump as call
  DDX_Slider(param_1,param_2,param_3);
  return;
}



void DDX_Check(CDataExchange *param_1,int param_2,int *param_3)

{
                    // WARNING: Could not recover jumptable at 0x00427ba4. Too many branches
                    // WARNING: Treating indirect jump as call
  DDX_Check(param_1,param_2,param_3);
  return;
}



void __thiscall CFileFind::~CFileFind(CFileFind *this)

{
                    // WARNING: Could not recover jumptable at 0x00427baa. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CFileFind(this);
  return;
}



BOOL CWnd::EnableWindow(HWND hWnd,BOOL bEnable)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427bb0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = EnableWindow(hWnd,bEnable);
  return BVar1;
}



void __thiscall CFileFind::GetFilePath(CFileFind *this)

{
                    // WARNING: Could not recover jumptable at 0x00427bb6. Too many branches
                    // WARNING: Treating indirect jump as call
  GetFilePath(this);
  return;
}



BOOL CFileFind::FindNextFileA(HANDLE hFindFile,LPWIN32_FIND_DATAA lpFindFileData)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427bbc. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = FindNextFileA(hFindFile,lpFindFileData);
  return BVar1;
}



int __thiscall CFileFind::FindFile(CFileFind *this,char *param_1,ulong param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427bc2. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = FindFile(this,param_1,param_2);
  return iVar1;
}



void __thiscall CFileFind::CFileFind(CFileFind *this)

{
                    // WARNING: Could not recover jumptable at 0x00427bc8. Too many branches
                    // WARNING: Treating indirect jump as call
  CFileFind(this);
  return;
}



void __thiscall CSliderCtrl::SetRange(CSliderCtrl *this,int param_1,int param_2,int param_3)

{
                    // WARNING: Could not recover jumptable at 0x00427bce. Too many branches
                    // WARNING: Treating indirect jump as call
  SetRange(this,param_1,param_2,param_3);
  return;
}



void __thiscall CString::Format(CString *this,char *param_1,...)

{
                    // WARNING: Could not recover jumptable at 0x00427bd4. Too many branches
                    // WARNING: Treating indirect jump as call
  Format(this,param_1);
  return;
}



char * __thiscall CString::GetBuffer(CString *this,int param_1)

{
  char *pcVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427bda. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = GetBuffer(this,param_1);
  return pcVar1;
}



int __thiscall CString::Delete(CString *this,int param_1,int param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427be0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Delete(this,param_1,param_2);
  return iVar1;
}



void __thiscall CComboBox::GetLBText(CComboBox *this,int param_1,CString *param_2)

{
                    // WARNING: Could not recover jumptable at 0x00427be6. Too many branches
                    // WARNING: Treating indirect jump as call
  GetLBText(this,param_1,param_2);
  return;
}



void __thiscall CListBox::GetText(CListBox *this,int param_1,CString *param_2)

{
                    // WARNING: Could not recover jumptable at 0x00427bec. Too many branches
                    // WARNING: Treating indirect jump as call
  GetText(this,param_1,param_2);
  return;
}



int __thiscall CWnd::UpdateData(CWnd *this,int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427bf2. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = UpdateData(this,param_1);
  return iVar1;
}



void SerializeElements(CArchive *param_1,CString *param_2,int param_3)

{
                    // WARNING: Could not recover jumptable at 0x00427bf8. Too many branches
                    // WARNING: Treating indirect jump as call
  SerializeElements(param_1,param_2,param_3);
  return;
}



void DestructElements(CString *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x00427bfe. Too many branches
                    // WARNING: Treating indirect jump as call
  DestructElements(param_1,param_2);
  return;
}



void ConstructElements(CString *param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x00427c04. Too many branches
                    // WARNING: Treating indirect jump as call
  ConstructElements(param_1,param_2);
  return;
}



int __thiscall CDialog::DoModal(CDialog *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427c64. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = DoModal(this);
  return iVar1;
}



int __thiscall CDialog::OnInitDialog(CDialog *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427c6a. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = OnInitDialog(this);
  return iVar1;
}



void DDV_MaxChars(CDataExchange *param_1,CString *param_2,int param_3)

{
                    // WARNING: Could not recover jumptable at 0x00427c70. Too many branches
                    // WARNING: Treating indirect jump as call
  DDV_MaxChars(param_1,param_2,param_3);
  return;
}



BOOL CDialog::EndDialog(HWND hDlg,INT_PTR nResult)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427c76. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = EndDialog(hDlg,nResult);
  return BVar1;
}



int CWnd::GetWindowTextA(HWND hWnd,LPSTR lpString,int nMaxCount)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427c7c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = GetWindowTextA(hWnd,lpString,nMaxCount);
  return iVar1;
}



void __thiscall CWinApp::CWinApp(CWinApp *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00427cfa. Too many branches
                    // WARNING: Treating indirect jump as call
  CWinApp(this,param_1);
  return;
}



void __thiscall CWinApp::~CWinApp(CWinApp *this)

{
                    // WARNING: Could not recover jumptable at 0x00427d00. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CWinApp(this);
  return;
}



int __thiscall CFileFind::IsDots(CFileFind *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427d06. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = IsDots(this);
  return iVar1;
}



int AfxMessageBox(char *param_1,uint param_2,uint param_3)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427d0c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxMessageBox(param_1,param_2,param_3);
  return iVar1;
}



BOOL CWnd::ShowWindow(HWND hWnd,int nCmdShow)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427d12. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = ShowWindow(hWnd,nCmdShow);
  return BVar1;
}



void __thiscall CString::CString(CString *this,char param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x00427d18. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1,param_2);
  return;
}



int __thiscall CDialog::Create(CDialog *this,char *param_1,CWnd *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427d1e. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Create(this,param_1,param_2);
  return iVar1;
}



int __thiscall CString::Find(CString *this,char *param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427d24. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Find(this,param_1);
  return iVar1;
}



int __thiscall CString::Replace(CString *this,char *param_1,char *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427d2a. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Replace(this,param_1,param_2);
  return iVar1;
}



CString * __thiscall CString::operator+=(CString *this,char *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427d30. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator+=(this,param_1);
  return pCVar1;
}



void __thiscall CBrush::CBrush(CBrush *this,ulong param_1)

{
                    // WARNING: Could not recover jumptable at 0x00427d36. Too many branches
                    // WARNING: Treating indirect jump as call
  CBrush(this,param_1);
  return;
}



void __thiscall CPen::CPen(CPen *this,int param_1,int param_2,ulong param_3)

{
                    // WARNING: Could not recover jumptable at 0x00427d3c. Too many branches
                    // WARNING: Treating indirect jump as call
  CPen(this,param_1,param_2,param_3);
  return;
}



void __thiscall CString::TrimRight(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00427d4e. Too many branches
                    // WARNING: Treating indirect jump as call
  TrimRight(this,param_1);
  return;
}



void __thiscall CString::Mid(CString *this,int param_1)

{
                    // WARNING: Could not recover jumptable at 0x00427d54. Too many branches
                    // WARNING: Treating indirect jump as call
  Mid(this,param_1);
  return;
}



void __thiscall CString::FormatV(CString *this,char *param_1,char *param_2)

{
                    // WARNING: Could not recover jumptable at 0x00427d5a. Too many branches
                    // WARNING: Treating indirect jump as call
  FormatV(this,param_1,param_2);
  return;
}



void __CxxFrameHandler(void)

{
                    // WARNING: Could not recover jumptable at 0x00427d60. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler();
  return;
}



char * __cdecl strcpy(char *_Dest,char *_Source)

{
  char *pcVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427d70. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = strcpy(_Dest,_Source);
  return pcVar1;
}



int __cdecl strcmp(char *_Str1,char *_Str2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427d76. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = strcmp(_Str1,_Str2);
  return iVar1;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00427d7c. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



void __cdecl FUN_00427d82(_onexit_t param_1)

{
  if (DAT_00450b08 == -1) {
    _onexit(param_1);
    return;
  }
  __dllonexit(param_1,&DAT_00450b08,&DAT_00450b04);
  return;
}



int __cdecl FUN_00427dae(_onexit_t param_1)

{
  int iVar1;
  
  iVar1 = FUN_00427d82(param_1);
  return (iVar1 != 0) - 1;
}



void FUN_00427dc0(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_0042dde8;
  puStack_10 = &DAT_004280da;
  local_14 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_14;
  while( true ) {
    param_3 = param_3 + -1;
    if (param_3 < 0) break;
    (*(code *)param_4)();
  }
  local_8 = 0xffffffff;
  FUN_00427e28();
  ExceptionList = local_14;
  return;
}



void FUN_00427e28(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x1c) == 0) {
    FUN_00427e40(*(undefined4 *)(unaff_EBP + 8),*(undefined4 *)(unaff_EBP + 0xc),
                 *(int *)(unaff_EBP + 0x10),*(undefined **)(unaff_EBP + 0x14));
  }
  return;
}



void FUN_00427e40(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_0042ddf8;
  puStack_10 = &DAT_004280da;
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



void FUN_00427eb4(undefined4 param_1,undefined4 param_2,int param_3,undefined *param_4)

{
  int local_20;
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_0042de08;
  puStack_10 = &DAT_004280da;
  local_14 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_14;
  for (local_20 = 0; local_20 < param_3; local_20 = local_20 + 1) {
    (*(code *)param_4)();
  }
  local_8 = 0xffffffff;
  FUN_00427f1e();
  ExceptionList = local_14;
  return;
}



void FUN_00427f1e(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x20) == 0) {
    FUN_00427e40(*(undefined4 *)(unaff_EBP + 8),*(undefined4 *)(unaff_EBP + 0xc),
                 *(int *)(unaff_EBP + -0x1c),*(undefined **)(unaff_EBP + 0x18));
  }
  return;
}



// WARNING: Unable to track spacebase fully for stack

void FUN_00427f40(void)

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



void __cdecl ftol(void)

{
                    // WARNING: Could not recover jumptable at 0x00427f70. Too many branches
                    // WARNING: Treating indirect jump as call
  ftol();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void entry(void)

{
  undefined4 *puVar1;
  uint uVar2;
  HMODULE pHVar3;
  byte *pbVar4;
  HINSTANCE__ *pHVar5;
  char **local_74;
  _startupinfo local_70;
  int local_6c;
  char **local_68;
  int local_64;
  _STARTUPINFOA local_60;
  undefined1 *local_1c;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_0042de18;
  puStack_10 = &DAT_004280da;
  pvStack_14 = ExceptionList;
  local_1c = &stack0xffffff78;
  local_8 = 0;
  ExceptionList = &pvStack_14;
  __set_app_type(2);
  _DAT_00450b04 = 0xffffffff;
  DAT_00450b08 = 0xffffffff;
  puVar1 = (undefined4 *)__p__fmode();
  *puVar1 = DAT_00450af8;
  puVar1 = (undefined4 *)__p__commode();
  *puVar1 = DAT_00450af4;
  _DAT_00450b00 = *(undefined4 *)_adjust_fdiv_exref;
  FUN_00428107();
  if (DAT_00435ec0 == 0) {
    __setusermatherr(&LAB_00428104);
  }
  FUN_004280f2();
  initterm(&DAT_004340b4,&DAT_004340b8);
  local_70.newmode = DAT_00450af0;
  __getmainargs(&local_64,&local_74,&local_68,_DoWildCard_00450aec,&local_70);
  initterm(&DAT_00434000,&DAT_004340b0);
  pbVar4 = *(byte **)_acmdln_exref;
  if (*pbVar4 != 0x22) {
    do {
      if (*pbVar4 < 0x21) goto LAB_00428069;
      pbVar4 = pbVar4 + 1;
    } while( true );
  }
  do {
    pbVar4 = pbVar4 + 1;
    if (*pbVar4 == 0) break;
  } while (*pbVar4 != 0x22);
  if (*pbVar4 != 0x22) goto LAB_00428069;
  do {
    pbVar4 = pbVar4 + 1;
LAB_00428069:
  } while ((*pbVar4 != 0) && (*pbVar4 < 0x21));
  local_60.dwFlags = 0;
  GetStartupInfoA(&local_60);
  if ((local_60.dwFlags & 1) == 0) {
    uVar2 = 10;
  }
  else {
    uVar2 = (uint)local_60.wShowWindow;
  }
  pHVar5 = (HINSTANCE__ *)0x0;
  pHVar3 = GetModuleHandleA((LPCSTR)0x0);
  local_6c = FUN_00428120(pHVar3,pHVar5,(char *)pbVar4,uVar2);
                    // WARNING: Subroutine does not return
  exit(local_6c);
}



void __dllonexit(void)

{
                    // WARNING: Could not recover jumptable at 0x004280d4. Too many branches
                    // WARNING: Treating indirect jump as call
  __dllonexit();
  return;
}



int __cdecl _XcptFilter(ulong _ExceptionNum,_EXCEPTION_POINTERS *_ExceptionPtr)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004280e6. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _XcptFilter(_ExceptionNum,_ExceptionPtr);
  return iVar1;
}



void __cdecl initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x004280ec. Too many branches
                    // WARNING: Treating indirect jump as call
  initterm();
  return;
}



void FUN_004280f2(void)

{
  _controlfp(0x10000,0x30000);
  return;
}



void FUN_00428107(void)

{
  return;
}



uint __cdecl _controlfp(uint _NewValue,uint _Mask)

{
  uint uVar1;
  
                    // WARNING: Could not recover jumptable at 0x00428108. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = _controlfp(_NewValue,_Mask);
  return uVar1;
}



BOOL GetOpenFileNameA(LPOPENFILENAMEA param_1)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0042810e. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetOpenFileNameA(param_1);
  return BVar1;
}



BOOL GetSaveFileNameA(LPOPENFILENAMEA param_1)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00428114. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetSaveFileNameA(param_1);
  return BVar1;
}



void FUN_00428120(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  AfxWinMain(param_1,param_2,param_3,param_4);
  return;
}



undefined4 FUN_00428138(int param_1,undefined4 param_2)

{
  AFX_MODULE_STATE *pAVar1;
  
  pAVar1 = AfxGetModuleState();
  pAVar1[0x14] = SUB41(param_1,0);
  *(undefined4 *)(pAVar1 + 0x1040) = param_2;
  if (param_1 == 0) {
    _setmbcp(-3);
  }
  return 1;
}



int AfxWinMain(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00428178. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinMain(param_1,param_2,param_3,param_4);
  return iVar1;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x0042817e. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



int __fastcall FUN_00428190(int param_1)

{
  return param_1 + 4;
}



void Unwind_004281b0(void)

{
  int unaff_EBP;
  
  FUN_004017d0(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_004281c3(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_004281cc(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x38));
  return;
}



void Unwind_004281d5(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_004281de(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x40));
  return;
}



void Unwind_004281e7(void)

{
  int unaff_EBP;
  
  INIFILE::~INIFILE((INIFILE *)(unaff_EBP + -0x30));
  return;
}



void Unwind_004281f1(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x44));
  return;
}



void Unwind_00428204(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x38));
  return;
}



void Unwind_0042820d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_00428216(void)

{
  int unaff_EBP;
  
  INIFILE::~INIFILE((INIFILE *)(unaff_EBP + -0x34));
  return;
}



void Unwind_00428220(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428229(void)

{
  int unaff_EBP;
  
  CHyperLink::~CHyperLink((CHyperLink *)(unaff_EBP + -0x104));
  return;
}



void Unwind_00428240(void)

{
  int unaff_EBP;
  
  FUN_004017d0(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428260(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428269(void)

{
  int unaff_EBP;
  
  FUN_00401750((undefined4 *)(unaff_EBP + -0x18));
  return;
}



void Unwind_00428272(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x24) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_00428289(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_00428292(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_004282b0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_004282b9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_004282d0(void)

{
  int unaff_EBP;
  
  FUN_004017d0(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_004282d9(void)

{
  int unaff_EBP;
  
  FUN_00401750((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_004282e5(void)

{
  int unaff_EBP;
  
  CImageList::~CImageList((CImageList *)(*(int *)(unaff_EBP + -0x10) + 100));
  return;
}



void Unwind_004282f1(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x78));
  return;
}



void Unwind_004282fd(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x7c));
  return;
}



void Unwind_00428313(void)

{
  int unaff_EBP;
  
  FUN_004046a0((CDialog *)(unaff_EBP + -0x70));
  return;
}



void Unwind_00428326(void)

{
  int unaff_EBP;
  
  FUN_00404750(unaff_EBP + -0x38);
  return;
}



void Unwind_0042832f(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_00428342(void)

{
  int unaff_EBP;
  
  FUN_00404840((undefined4 *)(unaff_EBP + -0x48));
  return;
}



void Unwind_0042834b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x6c));
  return;
}



void Unwind_00428354(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xb4));
  return;
}



void Unwind_00428360(void)

{
  int unaff_EBP;
  
  FUN_00405b20((undefined4 *)(unaff_EBP + -0x7c));
  return;
}



void Unwind_00428369(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xbc));
  return;
}



void Unwind_00428375(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x80));
  return;
}



void Unwind_0042837e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xc0));
  return;
}



void Unwind_0042838a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xc4));
  return;
}



void Unwind_00428396(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -200));
  return;
}



void Unwind_004283ac(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x14c) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_004283c6(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x144));
  return;
}



void Unwind_004283d2(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x148));
  return;
}



void Unwind_004283e8(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_004283fb(void)

{
  int unaff_EBP;
  
  FUN_00404860((CDialog *)(unaff_EBP + -0x78));
  return;
}



void Unwind_00428404(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x7c));
  return;
}



void Unwind_00428417(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_0042842a(void)

{
  int unaff_EBP;
  
  FUN_00401750((undefined4 *)(unaff_EBP + -0x170));
  return;
}



void Unwind_00428436(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x5c));
  return;
}



void Unwind_0042843f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x5c0));
  return;
}



void Unwind_0042844b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x16c));
  return;
}



void Unwind_00428457(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x17c));
  return;
}



void Unwind_00428463(void)

{
  int unaff_EBP;
  
  FUN_004057c0((int *)(unaff_EBP + -0x178));
  return;
}



void Unwind_0042846f(void)

{
  int unaff_EBP;
  
  MAP::~MAP((MAP *)(unaff_EBP + -0x5bc));
  return;
}



void Unwind_0042847c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x5c8));
  return;
}



void Unwind_00428488(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x5cc));
  return;
}



void Unwind_0042849e(void)

{
  int unaff_EBP;
  
  FUN_00401750((undefined4 *)(unaff_EBP + -0x170));
  return;
}



void Unwind_004284aa(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x5c));
  return;
}



void Unwind_004284b3(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1dc));
  return;
}



void Unwind_004284bf(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x16c));
  return;
}



void Unwind_004284cb(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1e0));
  return;
}



void Unwind_004284d7(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x174));
  return;
}



void Unwind_004284e3(void)

{
  int unaff_EBP;
  
  FUN_004048f0((CDialog *)(unaff_EBP + -0x1d8));
  return;
}



void Unwind_004284f9(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042850c(void)

{
  int unaff_EBP;
  
  FUN_004048f0((CDialog *)(unaff_EBP + -0x4bc));
  return;
}



void Unwind_00428518(void)

{
  int unaff_EBP;
  
  MAP::~MAP((MAP *)(unaff_EBP + -0x454));
  return;
}



void Unwind_00428525(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x4d0));
  return;
}



void Unwind_0042853b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_00428544(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_00428557(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_0042856a(void)

{
  int unaff_EBP;
  
  FUN_00404860((CDialog *)(unaff_EBP + -0x78));
  return;
}



void Unwind_0042857d(void)

{
  int unaff_EBP;
  
  FUN_00404860((CDialog *)(unaff_EBP + -0x7c));
  return;
}



void Unwind_00428586(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042858f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xf0));
  return;
}



void Unwind_0042859b(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0xec));
  return;
}



void Unwind_004285a7(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x80));
  return;
}



void Unwind_004285b0(void)

{
  int unaff_EBP;
  
  FUN_004048f0((CDialog *)(unaff_EBP + -0xe8));
  return;
}



void Unwind_004285bc(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xf8));
  return;
}



void Unwind_004285c8(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xfc));
  return;
}



void Unwind_004285de(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_004285e7(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_00428600(void)

{
  int unaff_EBP;
  
  FUN_004017d0(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428609(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x10) == 0) {
    *(undefined4 *)(unaff_EBP + -0x14) = 0;
  }
  else {
    *(int *)(unaff_EBP + -0x14) = *(int *)(unaff_EBP + -0x10) + 0x60;
  }
  FUN_00401750(*(undefined4 **)(unaff_EBP + -0x14));
  return;
}



void Unwind_00428631(void)

{
  int unaff_EBP;
  
  CImageList::~CImageList((CImageList *)(*(int *)(unaff_EBP + -0x10) + 100));
  return;
}



void Unwind_0042863d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x78));
  return;
}



void Unwind_00428649(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x7c));
  return;
}



void Unwind_00428660(void)

{
  int unaff_EBP;
  
  FUN_004017d0(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428680(void)

{
  int unaff_EBP;
  
  FUN_00404820((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xc));
  return;
}



void Unwind_004286a0(void)

{
  int unaff_EBP;
  
  FUN_00404820((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xc));
  return;
}



void Unwind_004286c0(void)

{
  int unaff_EBP;
  
  FUN_00404820((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xc));
  return;
}



void Unwind_004286e0(void)

{
  int unaff_EBP;
  
  FUN_004017d0(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_004286e9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_004286f5(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(*(int *)(unaff_EBP + -0x10) + 100));
  return;
}



void Unwind_00428710(void)

{
  int unaff_EBP;
  
  FUN_004017d0(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428730(void)

{
  int unaff_EBP;
  
  FUN_00404db0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428750(void)

{
  int unaff_EBP;
  
  FUN_00404b70(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428770(void)

{
  int unaff_EBP;
  
  FUN_00404b70(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428790(void)

{
  FUN_00405650();
  return;
}



void Unwind_004287b0(void)

{
  int unaff_EBP;
  
  FUN_00404b70(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_004287d0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 8));
  return;
}



void Unwind_004287d9(void)

{
  int unaff_EBP;
  
  FUN_004017d0(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_004287e2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_00428800(void)

{
  int unaff_EBP;
  
  FUN_004017d0(*(CDialog **)(unaff_EBP + -0x20));
  return;
}



void Unwind_00428809(void)

{
  int unaff_EBP;
  
  FUN_00401750((undefined4 *)(*(int *)(unaff_EBP + -0x20) + 0x60));
  return;
}



void Unwind_00428815(void)

{
  int unaff_EBP;
  
  FUN_00407d30((undefined4 *)(*(int *)(unaff_EBP + -0x20) + 100));
  return;
}



void Unwind_00428821(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x20) + 0x84));
  return;
}



void Unwind_00428830(void)

{
  int unaff_EBP;
  
  CListBox::~CListBox((CListBox *)(*(int *)(unaff_EBP + -0x20) + 0x88));
  return;
}



void Unwind_0042883f(void)

{
  int unaff_EBP;
  
  CComboBox::~CComboBox((CComboBox *)(*(int *)(unaff_EBP + -0x20) + 200));
  return;
}



void Unwind_0042884e(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_00428857(void)

{
  int unaff_EBP;
  
  FUN_00401750((undefined4 *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0042886a(void)

{
  int unaff_EBP;
  
  FUN_004017d0(*(CDialog **)(unaff_EBP + -0x18));
  return;
}



void Unwind_00428873(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x18) == 0) {
    *(undefined4 *)(unaff_EBP + -0x1c) = 0;
  }
  else {
    *(int *)(unaff_EBP + -0x1c) = *(int *)(unaff_EBP + -0x18) + 0x60;
  }
  FUN_00401750(*(undefined4 **)(unaff_EBP + -0x1c));
  return;
}



void Unwind_0042889b(void)

{
  int unaff_EBP;
  
  FUN_00407d30((undefined4 *)(*(int *)(unaff_EBP + -0x18) + 100));
  return;
}



void Unwind_004288a7(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x18) + 0x84));
  return;
}



void Unwind_004288b6(void)

{
  int unaff_EBP;
  
  CListBox::~CListBox((CListBox *)(*(int *)(unaff_EBP + -0x18) + 0x88));
  return;
}



void Unwind_004288c5(void)

{
  int unaff_EBP;
  
  CComboBox::~CComboBox((CComboBox *)(*(int *)(unaff_EBP + -0x18) + 200));
  return;
}



void Unwind_004288d4(void)

{
  int unaff_EBP;
  
  FUN_00401750((undefined4 *)(unaff_EBP + -0x10));
  return;
}



void Unwind_004288e7(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_004288f0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_004288f9(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0042890c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x78));
  return;
}



void Unwind_00428915(void)

{
  int unaff_EBP;
  
  FUN_00407d30((undefined4 *)(unaff_EBP + -0x94));
  return;
}



void Unwind_00428921(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x98));
  return;
}



void Unwind_0042892d(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x9c));
  return;
}



void Unwind_00428939(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xa0));
  return;
}



void Unwind_00428945(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -100));
  return;
}



void Unwind_0042894e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xa4));
  return;
}



void Unwind_0042895a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x54));
  return;
}



void Unwind_00428963(void)

{
  int unaff_EBP;
  
  CFileFind::~CFileFind((CFileFind *)(unaff_EBP + -0x44));
  return;
}



void Unwind_0042896c(void)

{
  int unaff_EBP;
  
  FUN_00407d50((undefined4 *)(unaff_EBP + -0x28));
  return;
}



void Unwind_00428975(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xac));
  return;
}



void Unwind_00428981(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xb0));
  return;
}



void Unwind_0042898d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xb4));
  return;
}



void Unwind_00428999(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x6c));
  return;
}



void Unwind_004289a2(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x70));
  return;
}



void Unwind_004289ab(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0xbc));
  return;
}



void Unwind_004289c1(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 8));
  return;
}



void Unwind_004289ca(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1a8));
  return;
}



void Unwind_004289d6(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1b8));
  return;
}



void Unwind_004289e2(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1b4));
  return;
}



void Unwind_004289ee(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1c8));
  return;
}



void Unwind_004289fa(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1cc));
  return;
}



void Unwind_00428a06(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1d0));
  return;
}



void Unwind_00428a12(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1c4));
  return;
}



void Unwind_00428a1e(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x1d8));
  return;
}



void Unwind_00428a2c(void)

{
  int unaff_EBP;
  
  FUN_00407d90(unaff_EBP + -0x1e0);
  return;
}



void Unwind_00428a42(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 8));
  return;
}



void Unwind_00428a4b(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_00428a5e(void)

{
  int unaff_EBP;
  
  FUN_00404860((CDialog *)(unaff_EBP + -0x78));
  return;
}



void Unwind_00428a67(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x80));
  return;
}



void Unwind_00428a70(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x84));
  return;
}



void Unwind_00428a86(void)

{
  int unaff_EBP;
  
  FUN_004046a0((CDialog *)(unaff_EBP + -0xe8));
  return;
}



void Unwind_00428a92(void)

{
  int unaff_EBP;
  
  FUN_004046a0((CDialog *)(unaff_EBP + -0x150));
  return;
}



void Unwind_00428a9e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_00428aa7(void)

{
  int unaff_EBP;
  
  FUN_00404860((CDialog *)(unaff_EBP + -0x80));
  return;
}



void Unwind_00428ab0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x158));
  return;
}



void Unwind_00428abc(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x15c));
  return;
}



void Unwind_00428ac8(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x164));
  return;
}



void Unwind_00428ad4(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x168));
  return;
}



void Unwind_00428ae0(void)

{
  int unaff_EBP;
  
  FUN_00407d90(unaff_EBP + -0x170);
  return;
}



void Unwind_00428af6(void)

{
  int unaff_EBP;
  
  FUN_004046a0((CDialog *)(unaff_EBP + -0xe0));
  return;
}



void Unwind_00428b02(void)

{
  int unaff_EBP;
  
  FUN_004046a0((CDialog *)(unaff_EBP + -0x148));
  return;
}



void Unwind_00428b0e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_00428b17(void)

{
  int unaff_EBP;
  
  FUN_004048f0((CDialog *)(unaff_EBP + -0x78));
  return;
}



void Unwind_00428b20(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x150));
  return;
}



void Unwind_00428b2c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x154));
  return;
}



void Unwind_00428b38(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x158));
  return;
}



void Unwind_00428b4e(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x40));
  return;
}



void Unwind_00428b57(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x44));
  return;
}



void Unwind_00428b60(void)

{
  int unaff_EBP;
  
  FUN_00401750((undefined4 *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428b69(void)

{
  int unaff_EBP;
  
  FUN_00407d50((undefined4 *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_00428b72(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_00428b85(void)

{
  int unaff_EBP;
  
  FUN_004048f0((CDialog *)(unaff_EBP + -0x74));
  return;
}



void Unwind_00428b8e(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x78));
  return;
}



void Unwind_00428b97(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x7c));
  return;
}



void Unwind_00428ba0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x80));
  return;
}



void Unwind_00428bc0(void)

{
  int unaff_EBP;
  
  FUN_00404b70(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428be0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_00428c00(void)

{
  int unaff_EBP;
  
  FUN_00404b70(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428c20(void)

{
  int unaff_EBP;
  
  CDialog::~CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428c29(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_00428c3f(void)

{
  int unaff_EBP;
  
  FUN_00408df0((CDialog *)(unaff_EBP + -0x70));
  return;
}



void Unwind_00428c48(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x74));
  return;
}



void Unwind_00428c51(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x78));
  return;
}



void Unwind_00428c70(void)

{
  int unaff_EBP;
  
  CDialog::~CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428c90(void)

{
  int unaff_EBP;
  
  FUN_004017d0(*(CDialog **)(unaff_EBP + -0x14));
  return;
}



void Unwind_00428c99(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x14) + 0x60));
  return;
}



void Unwind_00428ca5(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(*(int *)(unaff_EBP + -0x14) + 100));
  return;
}



void Unwind_00428cb1(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x14) + 0x68));
  return;
}



void Unwind_00428cbd(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428cd0(void)

{
  int unaff_EBP;
  
  FUN_004017d0(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428cd9(void)

{
  int unaff_EBP;
  
  FUN_00401750((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_00428ce5(void)

{
  int unaff_EBP;
  
  CDIBStatic::~CDIBStatic((CDIBStatic *)(*(int *)(unaff_EBP + -0x10) + 100));
  return;
}



void Unwind_00428cf2(void)

{
  int unaff_EBP;
  
  INIFILE::~INIFILE((INIFILE *)(*(int *)(unaff_EBP + -0x10) + 0xb4));
  return;
}



void Unwind_00428d02(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0xdc));
  return;
}



void Unwind_00428d11(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0xe0));
  return;
}



void Unwind_00428d20(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0xe4));
  return;
}



void Unwind_00428d39(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428d42(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_00428d4b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x40));
  return;
}



void Unwind_00428d54(void)

{
  int unaff_EBP;
  
  INIFILE::~INIFILE((INIFILE *)(unaff_EBP + -0x38));
  return;
}



void Unwind_00428d5e(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x44));
  return;
}



void Unwind_00428d67(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_00428d70(void)

{
  int unaff_EBP;
  
  FUN_00407d90(unaff_EBP + -0x4c);
  return;
}



void Unwind_00428d79(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x50));
  return;
}



void Unwind_00428d8c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_00428d95(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_00428d9e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_00428da7(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_00428db0(void)

{
  int unaff_EBP;
  
  FUN_004057c0((int *)(unaff_EBP + -0x18));
  return;
}



void Unwind_00428db9(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_00428dc2(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x30));
  return;
}



void Unwind_00428dcb(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_00428dd4(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x38));
  return;
}



void Unwind_00428ddd(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_00428df0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428e03(void)

{
  int unaff_EBP;
  
  FUN_00401750((undefined4 *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428e0c(void)

{
  int unaff_EBP;
  
  FUN_00405f84((CDialog *)(unaff_EBP + -300));
  return;
}



void Unwind_00428e22(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x40));
  return;
}



void Unwind_00428e2b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x44));
  return;
}



void Unwind_00428e34(void)

{
  int unaff_EBP;
  
  INIFILE::~INIFILE((INIFILE *)(unaff_EBP + -0x34));
  return;
}



void Unwind_00428e3e(void)

{
  int unaff_EBP;
  
  FUN_00407d90(unaff_EBP + -0x3c);
  return;
}



void Unwind_00428e47(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428e50(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x48));
  return;
}



void Unwind_00428e59(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x4c));
  return;
}



void Unwind_00428e62(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x50));
  return;
}



void Unwind_00428e75(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_00428e7e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x40));
  return;
}



void Unwind_00428e87(void)

{
  int unaff_EBP;
  
  INIFILE::~INIFILE((INIFILE *)(unaff_EBP + -0x30));
  return;
}



void Unwind_00428e91(void)

{
  int unaff_EBP;
  
  FUN_00407d90(unaff_EBP + -0x38);
  return;
}



void Unwind_00428e9a(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x10c));
  return;
}



void Unwind_00428ea6(void)

{
  int unaff_EBP;
  
  CHyperLink::~CHyperLink((CHyperLink *)(unaff_EBP + -0x108));
  return;
}



void Unwind_00428ec0(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428ee0(void)

{
  FUN_00405650();
  return;
}



void Unwind_00428f00(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428f20(void)

{
  int unaff_EBP;
  
  FUN_004017d0(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428f29(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x10) == 0) {
    *(undefined4 *)(unaff_EBP + -0x14) = 0;
  }
  else {
    *(int *)(unaff_EBP + -0x14) = *(int *)(unaff_EBP + -0x10) + 0x60;
  }
  FUN_00401750(*(undefined4 **)(unaff_EBP + -0x14));
  return;
}



void Unwind_00428f51(void)

{
  int unaff_EBP;
  
  CDIBStatic::~CDIBStatic((CDIBStatic *)(*(int *)(unaff_EBP + -0x10) + 100));
  return;
}



void Unwind_00428f5e(void)

{
  int unaff_EBP;
  
  INIFILE::~INIFILE((INIFILE *)(*(int *)(unaff_EBP + -0x10) + 0xb4));
  return;
}



void Unwind_00428f6e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0xdc));
  return;
}



void Unwind_00428f7d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0xe0));
  return;
}



void Unwind_00428fa0(void)

{
  int unaff_EBP;
  
  FUN_004017d0(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428fa9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_00428fc0(void)

{
  int unaff_EBP;
  
  CHyperLink::~CHyperLink((CHyperLink *)(unaff_EBP + -0xd8));
  return;
}



void Unwind_00428fd7(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00428fe0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_00428fe9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_00428ff2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_00429005(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + 8));
  return;
}



void Unwind_0042900e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_00429017(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0042902a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x6c));
  return;
}



void Unwind_00429033(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x70));
  return;
}



void Unwind_0042903c(void)

{
  int unaff_EBP;
  
  CFileFind::~CFileFind((CFileFind *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_00429045(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x74));
  return;
}



void Unwind_0042904e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x78));
  return;
}



void Unwind_00429057(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x80));
  return;
}



void Unwind_00429060(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x84));
  return;
}



void Unwind_0042906c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x88));
  return;
}



void Unwind_00429078(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x8c));
  return;
}



void Unwind_00429084(void)

{
  int unaff_EBP;
  
  INIFILE::~INIFILE((INIFILE *)(unaff_EBP + -0x58));
  return;
}



void Unwind_0042908e(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x5c));
  return;
}



void Unwind_00429097(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x90));
  return;
}



void Unwind_004290a3(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x94));
  return;
}



void Unwind_004290af(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x9c));
  return;
}



void Unwind_004290bb(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xa0));
  return;
}



void Unwind_004290d1(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_004290da(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_004290e3(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_004290ec(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_004290f5(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_00429108(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x4c));
  return;
}



void Unwind_00429111(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x50));
  return;
}



void Unwind_0042911a(void)

{
  int unaff_EBP;
  
  INIFILE::~INIFILE((INIFILE *)(unaff_EBP + -0x30));
  return;
}



void Unwind_00429124(void)

{
  int unaff_EBP;
  
  FUN_00407d90(unaff_EBP + -0x38);
  return;
}



void Unwind_0042912d(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x11c));
  return;
}



void Unwind_00429139(void)

{
  int unaff_EBP;
  
  CHyperLink::~CHyperLink((CHyperLink *)(unaff_EBP + -0x118));
  return;
}



void Unwind_00429150(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_00429159(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x40));
  return;
}



void Unwind_00429162(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_0042916b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x68));
  return;
}



void Unwind_00429174(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x6c));
  return;
}



void Unwind_0042917d(void)

{
  int unaff_EBP;
  
  INIFILE::~INIFILE((INIFILE *)(unaff_EBP + -100));
  return;
}



void Unwind_00429187(void)

{
  int unaff_EBP;
  
  FUN_00407d50((undefined4 *)(unaff_EBP + -0x28));
  return;
}



void Unwind_0042919a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_004291a3(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_004291c0(void)

{
  int unaff_EBP;
  
  FUN_0040c5b0(*(undefined4 **)(unaff_EBP + -0x14));
  return;
}



void Unwind_004291c9(void)

{
  int unaff_EBP;
  
  FUN_00401750((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x34));
  return;
}



void Unwind_004291d5(void)

{
  int unaff_EBP;
  
  FUN_00401750((undefined4 *)(unaff_EBP + -0x10));
  return;
}



void Unwind_004291de(void)

{
  int unaff_EBP;
  
  FUN_00409ef0((CDialog *)(*(int *)(unaff_EBP + -0x14) + 0x40));
  return;
}



void Unwind_004291ea(void)

{
  int unaff_EBP;
  
  FUN_0040c9a0((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x138));
  return;
}



void Unwind_004291f9(void)

{
  int unaff_EBP;
  
  FUN_0040c7b0((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x154));
  return;
}



void Unwind_00429208(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x14) + 0x228));
  return;
}



void Unwind_00429218(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x14) + 0x1354));
  return;
}



void Unwind_00429228(void)

{
  int unaff_EBP;
  
  FUN_0040c870((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x2480));
  return;
}



void Unwind_00429237(void)

{
  int unaff_EBP;
  
  FUN_0040c900((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x25fc));
  return;
}



void Unwind_00429246(void)

{
  int unaff_EBP;
  
  FUN_0040c900((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x277c));
  return;
}



void Unwind_00429255(void)

{
  int unaff_EBP;
  
  FUN_0040c900((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x28fc));
  return;
}



void Unwind_00429264(void)

{
  int unaff_EBP;
  
  FUN_0040c900((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x2a7c));
  return;
}



void Unwind_00429273(void)

{
  int unaff_EBP;
  
  FUN_0040c900((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x2bfc));
  return;
}



void Unwind_00429282(void)

{
  int unaff_EBP;
  
  FUN_0040c900((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x2d7c));
  return;
}



void Unwind_00429291(void)

{
  int unaff_EBP;
  
  FUN_0040c900((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x2efc));
  return;
}



void Unwind_004292a0(void)

{
  int unaff_EBP;
  
  FUN_0040c870((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x307c));
  return;
}



void Unwind_004292af(void)

{
  int unaff_EBP;
  
  FUN_0040c870((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x31f8));
  return;
}



void Unwind_004292be(void)

{
  int unaff_EBP;
  
  FUN_0040c7b0((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x3374));
  return;
}



void Unwind_004292cd(void)

{
  int unaff_EBP;
  
  FUN_0040c870((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x3444));
  return;
}



void Unwind_004292dc(void)

{
  int unaff_EBP;
  
  FUN_0040c870((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x35c0));
  return;
}



void Unwind_004292eb(void)

{
  int unaff_EBP;
  
  FUN_0040c870((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x373c));
  return;
}



void Unwind_004292fa(void)

{
  int unaff_EBP;
  
  FUN_0040c870((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x38b8));
  return;
}



void Unwind_00429309(void)

{
  int unaff_EBP;
  
  FUN_0040c870((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x3a34));
  return;
}



void Unwind_00429318(void)

{
  int unaff_EBP;
  
  FUN_0040c9c0((DD_SURFACE *)(*(int *)(unaff_EBP + -0x14) + 0x3bb0));
  return;
}



void Unwind_00429327(void)

{
  int unaff_EBP;
  
  FUN_0040c9c0((DD_SURFACE *)(*(int *)(unaff_EBP + -0x14) + 0x4c5c));
  return;
}



void Unwind_00429336(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x14) + 0x5d08));
  return;
}



void Unwind_00429346(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x14) + 0x5d48));
  return;
}



void Unwind_00429356(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x14) + 0x5d88));
  return;
}



void Unwind_00429366(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x14) + 0x5dc8));
  return;
}



void Unwind_00429376(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x14) + 0x5e08));
  return;
}



void Unwind_00429386(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x14) + 0x5e48));
  return;
}



void Unwind_00429396(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x14) + 0x5e88));
  return;
}



void Unwind_004293a6(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x14) + 0x5ec8));
  return;
}



void Unwind_004293b6(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x14) + 0x5f08));
  return;
}



void Unwind_004293c6(void)

{
  int unaff_EBP;
  
  CMidi::~CMidi((CMidi *)(*(int *)(unaff_EBP + -0x14) + 0x5f48));
  return;
}



void Unwind_004293d6(void)

{
  int unaff_EBP;
  
  CMidi::~CMidi((CMidi *)(*(int *)(unaff_EBP + -0x14) + 0x609c));
  return;
}



void Unwind_004293e6(void)

{
  int unaff_EBP;
  
  CMidi::~CMidi((CMidi *)(*(int *)(unaff_EBP + -0x14) + 0x61f0));
  return;
}



void Unwind_004293f6(void)

{
  int unaff_EBP;
  
  CMidi::~CMidi((CMidi *)(*(int *)(unaff_EBP + -0x14) + 0x6344));
  return;
}



void Unwind_00429406(void)

{
  int unaff_EBP;
  
  FUN_0040c7b0((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x6498));
  return;
}



void Unwind_00429415(void)

{
  int unaff_EBP;
  
  FUN_0040c7b0((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x6568));
  return;
}



void Unwind_00429424(void)

{
  int unaff_EBP;
  
  FUN_0040c7b0((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x6638));
  return;
}



void Unwind_00429433(void)

{
  int unaff_EBP;
  
  FUN_0040c7b0((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x6708));
  return;
}



void Unwind_00429442(void)

{
  int unaff_EBP;
  
  FUN_00427dc0(*(int *)(unaff_EBP + -0x14) + 0x67d8,0x112c,5,~SPRITE_exref);
  return;
}



void Unwind_0042945f(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x14) + 0xbdb4));
  return;
}



void Unwind_0042946f(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x14) + 0xcee0));
  return;
}



void Unwind_0042947f(void)

{
  int unaff_EBP;
  
  FUN_0040c870((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0xe024));
  return;
}



void Unwind_0042948e(void)

{
  int unaff_EBP;
  
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(*(int *)(unaff_EBP + -0x14) + 0xe1a4));
  return;
}



void Unwind_0042949e(void)

{
  int unaff_EBP;
  
  MAP::~MAP((MAP *)(*(int *)(unaff_EBP + -0x14) + 0xe23c));
  return;
}



void Unwind_004294ae(void)

{
  int unaff_EBP;
  
  FUN_00427dc0(*(int *)(unaff_EBP + -0x14) + 0xe67c,0x440,0xf,~MAP_exref);
  return;
}



void Unwind_004294cb(void)

{
  int unaff_EBP;
  
  FUN_00427dc0(*(int *)(unaff_EBP + -0x14) + 0x1263c,4,0x78,CString::~CString);
  return;
}



void Unwind_004294f0(void)

{
  int unaff_EBP;
  
  FUN_00404750(unaff_EBP + -0x40);
  return;
}



void Unwind_00429510(void)

{
  int unaff_EBP;
  
  FUN_00404b70(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00429530(void)

{
  FUN_00405650();
  return;
}



void Unwind_00429550(void)

{
  int unaff_EBP;
  
  FUN_0040c270((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x14));
  return;
}



void Unwind_00429570(void)

{
  int unaff_EBP;
  
  FUN_00404b70(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00429590(void)

{
  int unaff_EBP;
  
  FUN_0040c270((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x14));
  return;
}



void Unwind_004295b0(void)

{
  int unaff_EBP;
  
  FUN_0040c7b0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_004295b9(void)

{
  int unaff_EBP;
  
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(*(int *)(unaff_EBP + -0x10) + 0xdc));
  return;
}



void Unwind_004295e0(void)

{
  int unaff_EBP;
  
  FUN_0040c820(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00429600(void)

{
  int unaff_EBP;
  
  FUN_0040c7b0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00429620(void)

{
  int unaff_EBP;
  
  FUN_0040c5b0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00429629(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x10) == 0) {
    *(undefined4 *)(unaff_EBP + -0x14) = 0;
  }
  else {
    *(int *)(unaff_EBP + -0x14) = *(int *)(unaff_EBP + -0x10) + 0x34;
  }
  FUN_00401750(*(undefined4 **)(unaff_EBP + -0x14));
  return;
}



void Unwind_00429651(void)

{
  int unaff_EBP;
  
  FUN_00409ef0((CDialog *)(*(int *)(unaff_EBP + -0x10) + 0x40));
  return;
}



void Unwind_0042965d(void)

{
  int unaff_EBP;
  
  FUN_0040c9a0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x138));
  return;
}



void Unwind_0042966c(void)

{
  int unaff_EBP;
  
  FUN_0040c7b0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x154));
  return;
}



void Unwind_0042967b(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x228));
  return;
}



void Unwind_0042968b(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0x1354));
  return;
}



void Unwind_0042969b(void)

{
  int unaff_EBP;
  
  FUN_0040c870((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x2480));
  return;
}



void Unwind_004296aa(void)

{
  int unaff_EBP;
  
  FUN_0040c900((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x25fc));
  return;
}



void Unwind_004296b9(void)

{
  int unaff_EBP;
  
  FUN_0040c900((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x277c));
  return;
}



void Unwind_004296c8(void)

{
  int unaff_EBP;
  
  FUN_0040c900((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x28fc));
  return;
}



void Unwind_004296d7(void)

{
  int unaff_EBP;
  
  FUN_0040c900((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x2a7c));
  return;
}



void Unwind_004296e6(void)

{
  int unaff_EBP;
  
  FUN_0040c900((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x2bfc));
  return;
}



void Unwind_004296f5(void)

{
  int unaff_EBP;
  
  FUN_0040c900((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x2d7c));
  return;
}



void Unwind_00429704(void)

{
  int unaff_EBP;
  
  FUN_0040c900((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x2efc));
  return;
}



void Unwind_00429713(void)

{
  int unaff_EBP;
  
  FUN_0040c870((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x307c));
  return;
}



void Unwind_00429722(void)

{
  int unaff_EBP;
  
  FUN_0040c870((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x31f8));
  return;
}



void Unwind_00429731(void)

{
  int unaff_EBP;
  
  FUN_0040c7b0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x3374));
  return;
}



void Unwind_00429740(void)

{
  int unaff_EBP;
  
  FUN_0040c870((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x3444));
  return;
}



void Unwind_0042974f(void)

{
  int unaff_EBP;
  
  FUN_0040c870((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x35c0));
  return;
}



void Unwind_0042975e(void)

{
  int unaff_EBP;
  
  FUN_0040c870((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x373c));
  return;
}



void Unwind_0042976d(void)

{
  int unaff_EBP;
  
  FUN_0040c870((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x38b8));
  return;
}



void Unwind_0042977c(void)

{
  int unaff_EBP;
  
  FUN_0040c870((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x3a34));
  return;
}



void Unwind_0042978b(void)

{
  int unaff_EBP;
  
  FUN_0040c9c0((DD_SURFACE *)(*(int *)(unaff_EBP + -0x10) + 0x3bb0));
  return;
}



void Unwind_0042979a(void)

{
  int unaff_EBP;
  
  FUN_0040c9c0((DD_SURFACE *)(*(int *)(unaff_EBP + -0x10) + 0x4c5c));
  return;
}



void Unwind_004297a9(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x5d08));
  return;
}



void Unwind_004297b9(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x5d48));
  return;
}



void Unwind_004297c9(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x5d88));
  return;
}



void Unwind_004297d9(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x5dc8));
  return;
}



void Unwind_004297e9(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x5e08));
  return;
}



void Unwind_004297f9(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x5e48));
  return;
}



void Unwind_00429809(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x5e88));
  return;
}



void Unwind_00429819(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x5ec8));
  return;
}



void Unwind_00429829(void)

{
  int unaff_EBP;
  
  CWave::~CWave((CWave *)(*(int *)(unaff_EBP + -0x10) + 0x5f08));
  return;
}



void Unwind_00429839(void)

{
  int unaff_EBP;
  
  CMidi::~CMidi((CMidi *)(*(int *)(unaff_EBP + -0x10) + 0x5f48));
  return;
}



void Unwind_00429849(void)

{
  int unaff_EBP;
  
  CMidi::~CMidi((CMidi *)(*(int *)(unaff_EBP + -0x10) + 0x609c));
  return;
}



void Unwind_00429859(void)

{
  int unaff_EBP;
  
  CMidi::~CMidi((CMidi *)(*(int *)(unaff_EBP + -0x10) + 0x61f0));
  return;
}



void Unwind_00429869(void)

{
  int unaff_EBP;
  
  CMidi::~CMidi((CMidi *)(*(int *)(unaff_EBP + -0x10) + 0x6344));
  return;
}



void Unwind_00429879(void)

{
  int unaff_EBP;
  
  FUN_0040c7b0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x6498));
  return;
}



void Unwind_00429888(void)

{
  int unaff_EBP;
  
  FUN_0040c7b0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x6568));
  return;
}



void Unwind_00429897(void)

{
  int unaff_EBP;
  
  FUN_0040c7b0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x6638));
  return;
}



void Unwind_004298a6(void)

{
  int unaff_EBP;
  
  FUN_0040c7b0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x6708));
  return;
}



void Unwind_004298b5(void)

{
  int unaff_EBP;
  
  FUN_00427dc0(*(int *)(unaff_EBP + -0x10) + 0x67d8,0x112c,5,~SPRITE_exref);
  return;
}



void Unwind_004298d2(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0xbdb4));
  return;
}



void Unwind_004298e2(void)

{
  int unaff_EBP;
  
  SPRITE::~SPRITE((SPRITE *)(*(int *)(unaff_EBP + -0x10) + 0xcee0));
  return;
}



void Unwind_004298f2(void)

{
  int unaff_EBP;
  
  FUN_0040c870((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xe024));
  return;
}



void Unwind_00429901(void)

{
  int unaff_EBP;
  
  DD_SURFACE::~DD_SURFACE((DD_SURFACE *)(*(int *)(unaff_EBP + -0x10) + 0xe1a4));
  return;
}



void Unwind_00429911(void)

{
  int unaff_EBP;
  
  MAP::~MAP((MAP *)(*(int *)(unaff_EBP + -0x10) + 0xe23c));
  return;
}



void Unwind_00429921(void)

{
  int unaff_EBP;
  
  FUN_00427dc0(*(int *)(unaff_EBP + -0x10) + 0xe67c,0x440,0xf,~MAP_exref);
  return;
}



void Unwind_0042993e(void)

{
  int unaff_EBP;
  
  FUN_00427dc0(*(int *)(unaff_EBP + -0x10) + 0x1263c,4,0x78,CString::~CString);
  return;
}



void Unwind_00429960(void)

{
  int unaff_EBP;
  
  FUN_0040c7b0(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00429980(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_00429989(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00429992(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_0042999b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_004299a4(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_004299ad(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_004299b6(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_004299bf(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_004299d2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_004299db(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_004299e4(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_004299ed(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_004299f6(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_00429a09(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_00429a12(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x40));
  return;
}



void Unwind_00429a1b(void)

{
  int unaff_EBP;
  
  INIFILE::~INIFILE((INIFILE *)(unaff_EBP + -0x30));
  return;
}



void Unwind_00429a25(void)

{
  int unaff_EBP;
  
  FUN_00407d90(unaff_EBP + -0x38);
  return;
}



void Unwind_00429a2e(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x10c));
  return;
}



void Unwind_00429a3a(void)

{
  int unaff_EBP;
  
  CHyperLink::~CHyperLink((CHyperLink *)(unaff_EBP + -0x108));
  return;
}



void Unwind_00429a60(void)

{
  int unaff_EBP;
  
  FUN_004048f0((CDialog *)(unaff_EBP + -0x70));
  return;
}



void Unwind_00429a69(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x7c));
  return;
}



void Unwind_00429a80(void)

{
  int unaff_EBP;
  
  FUN_004048f0((CDialog *)(unaff_EBP + -0x70));
  return;
}



void Unwind_00429a93(void)

{
  int unaff_EBP;
  
  FUN_00401410(*(void **)(unaff_EBP + -0x14));
  return;
}



void Unwind_00429aa7(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x8c));
  return;
}



void Unwind_00429ab3(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x94));
  return;
}



void Unwind_00429abf(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xa0));
  return;
}



void Unwind_00429acb(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0xa4));
  return;
}



void Unwind_00429ad7(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0xa8));
  return;
}



void Unwind_00429ae3(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_00429aec(void)

{
  int unaff_EBP;
  
  FUN_004048f0((CDialog *)(unaff_EBP + -0x80));
  return;
}



void Unwind_00429aff(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00429b12(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00429b25(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_00429b38(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_00429b41(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x54));
  return;
}



void Unwind_00429b54(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_00429b5d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x30));
  return;
}



void Unwind_00429b70(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00429b83(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00429b8c(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_00429ba0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_00429ba9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_00429bb2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_00429bbb(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_00429bd0(void)

{
  int unaff_EBP;
  
  MAP::~MAP((MAP *)(unaff_EBP + -0x44c));
  return;
}



void Unwind_00429be7(void)

{
  int unaff_EBP;
  
  FUN_00407d90(unaff_EBP + -0x14);
  return;
}



void Unwind_00429bf0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_00429bf9(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_00429c02(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_00429c0b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_00429c14(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_00429c1d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x30));
  return;
}



void Unwind_00429c30(void)

{
  int unaff_EBP;
  
  FUN_00407d90(unaff_EBP + -0x18);
  return;
}



void Unwind_00429c39(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_00429c42(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_00429c4b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_00429c54(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_00429c5d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_00429c66(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00429c6f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x30));
  return;
}



void Unwind_00429c82(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_00429ca0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00429ca9(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x14) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_00429cd0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xe8));
  return;
}



void Unwind_00429cdc(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xe4));
  return;
}



void Unwind_00429ce8(void)

{
  int unaff_EBP;
  
  FUN_0040c7b0((undefined4 *)(unaff_EBP + -0xe0));
  return;
}



void Unwind_00429cf4(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xf0));
  return;
}



void Unwind_00429d0a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x88));
  return;
}



void Unwind_00429d16(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x90));
  return;
}



void Unwind_00429d22(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x98));
  return;
}



void Unwind_00429d2e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xa0));
  return;
}



void Unwind_00429d3a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xa8));
  return;
}



void Unwind_00429d46(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xb0));
  return;
}



void Unwind_00429d52(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xb8));
  return;
}



void Unwind_00429d5e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xc0));
  return;
}



void Unwind_00429d6a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -200));
  return;
}



void Unwind_00429d76(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xd0));
  return;
}



void Unwind_00429d82(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xd8));
  return;
}



void Unwind_00429d8e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xe0));
  return;
}



void Unwind_00429d9a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xe8));
  return;
}



void Unwind_00429da6(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xf0));
  return;
}



void Unwind_00429db2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xf8));
  return;
}



void Unwind_00429dbe(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x100));
  return;
}



void Unwind_00429dca(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x108));
  return;
}



void Unwind_00429dd6(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x110));
  return;
}



void Unwind_00429de2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x118));
  return;
}



void Unwind_00429dee(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x120));
  return;
}



void Unwind_00429dfa(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x128));
  return;
}



void Unwind_00429e06(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x138));
  return;
}



void Unwind_00429e14(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x140));
  return;
}



void Unwind_00429e20(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x148));
  return;
}



void Unwind_00429e2c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x150));
  return;
}



void Unwind_00429e38(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x158));
  return;
}



void Unwind_00429e44(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x160));
  return;
}



void Unwind_00429e50(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x168));
  return;
}



void Unwind_00429e70(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_00429e79(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_00429e82(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00429e8b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_00429e94(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_00429ea7(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 0xc));
  return;
}



void Unwind_00429eb0(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x1c) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_00429ec7(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00429ed0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_00429ed9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_00429eec(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 0xc));
  return;
}



void Unwind_00429ef5(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_00429efe(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_00429f07(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_00429f10(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_00429f19(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_00429f22(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x50) & 1) != 0) {
    CString::~CString(*(CString **)(unaff_EBP + 8));
  }
  return;
}



void Unwind_00429f39(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_00429f42(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_00429f4b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x38));
  return;
}



void Unwind_00429f54(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_00429f5d(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x30));
  return;
}



void Unwind_00429f66(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x44));
  return;
}



void Unwind_00429f6f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x48));
  return;
}



void Unwind_00429f78(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x4c));
  return;
}



void Unwind_00429f8b(void)

{
  int unaff_EBP;
  
  FUN_00414330((undefined4 *)(unaff_EBP + -0x38));
  return;
}



void Unwind_00429f94(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x40));
  return;
}



void Unwind_00429fa7(void)

{
  int unaff_EBP;
  
  FUN_00414330((undefined4 *)(unaff_EBP + -0x24));
  return;
}



void Unwind_00429fba(void)

{
  int unaff_EBP;
  
  FUN_00414330((undefined4 *)(unaff_EBP + -0x30));
  return;
}



void Unwind_00429fc3(void)

{
  int unaff_EBP;
  
  FUN_004142b0((undefined4 *)(unaff_EBP + -0x14));
  return;
}



void Unwind_00429fcc(void)

{
  int unaff_EBP;
  
  FUN_004142b0((undefined4 *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_00429fe0(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + 0xc));
  return;
}



void Unwind_0042a000(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_0042a013(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_0042a026(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x38));
  return;
}



void Unwind_0042a039(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_0042a04c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_0042a05f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_0042a072(void)

{
  int unaff_EBP;
  
  FUN_00404820((undefined4 *)(unaff_EBP + -0x5c));
  return;
}



void Unwind_0042a085(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x30));
  return;
}



void Unwind_0042a08e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x38));
  return;
}



void Unwind_0042a097(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x40));
  return;
}



void Unwind_0042a0a0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x48));
  return;
}



void Unwind_0042a0c0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0042a0c9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_0042a0d2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_0042a0db(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_0042a0e4(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_0042a0ed(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_0042a0f6(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x44));
  return;
}



void Unwind_0042a0ff(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x4c));
  return;
}



void Unwind_0042a108(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x54));
  return;
}



void Unwind_0042a111(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x5c));
  return;
}



void Unwind_0042a11a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -100));
  return;
}



void Unwind_0042a123(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x6c));
  return;
}



void Unwind_0042a12c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x74));
  return;
}



void Unwind_0042a135(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x7c));
  return;
}



void Unwind_0042a13e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x84));
  return;
}



void Unwind_0042a14a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x8c));
  return;
}



void Unwind_0042a156(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x94));
  return;
}



void Unwind_0042a162(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x9c));
  return;
}



void Unwind_0042a16e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xa4));
  return;
}



void Unwind_0042a17a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xac));
  return;
}



void Unwind_0042a186(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xb4));
  return;
}



void Unwind_0042a192(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xbc));
  return;
}



void Unwind_0042a19e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xc4));
  return;
}



void Unwind_0042a1b4(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_0042a1c7(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10d8));
  return;
}



void Unwind_0042a1d3(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1128));
  return;
}



void Unwind_0042a1df(void)

{
  int unaff_EBP;
  
  FUN_00404820((undefined4 *)(unaff_EBP + -0x1074));
  return;
}



void Unwind_0042a1f5(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_0042a208(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_0042a220(void)

{
  int unaff_EBP;
  
  FUN_00414330((undefined4 *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_0042a229(void)

{
  int unaff_EBP;
  
  FUN_004142b0((undefined4 *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0042a23c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x164));
  return;
}



void Unwind_0042a248(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x168));
  return;
}



void Unwind_0042a254(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x16c));
  return;
}



void Unwind_0042a260(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x170));
  return;
}



void Unwind_0042a26c(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x178));
  return;
}



void Unwind_0042a27a(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x17c));
  return;
}



void Unwind_0042a286(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x180));
  return;
}



void Unwind_0042a292(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x184));
  return;
}



void Unwind_0042a29e(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x188));
  return;
}



void Unwind_0042a2aa(void)

{
  int unaff_EBP;
  
  CFileFind::~CFileFind((CFileFind *)(unaff_EBP + -0xac));
  return;
}



void Unwind_0042a2b6(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -400));
  return;
}



void Unwind_0042a2c2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x8c));
  return;
}



void Unwind_0042a2ce(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x198));
  return;
}



void Unwind_0042a2da(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x19c));
  return;
}



void Unwind_0042a2e6(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x160));
  return;
}



void Unwind_0042a2f2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1a4));
  return;
}



void Unwind_0042a2fe(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1a8));
  return;
}



void Unwind_0042a30a(void)

{
  int unaff_EBP;
  
  INIFILE::~INIFILE((INIFILE *)(unaff_EBP + -0x148));
  return;
}



void Unwind_0042a317(void)

{
  int unaff_EBP;
  
  FUN_00407d90(unaff_EBP + -0x108);
  return;
}



void Unwind_0042a323(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x100));
  return;
}



void Unwind_0042a32f(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1ac));
  return;
}



void Unwind_0042a33b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x124));
  return;
}



void Unwind_0042a347(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1b0));
  return;
}



void Unwind_0042a353(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x118));
  return;
}



void Unwind_0042a35f(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0xf4));
  return;
}



void Unwind_0042a36b(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0xf0));
  return;
}



void Unwind_0042a377(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0xfc));
  return;
}



void Unwind_0042a383(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1b4));
  return;
}



void Unwind_0042a38f(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x114));
  return;
}



void Unwind_0042a39b(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0xf8));
  return;
}



void Unwind_0042a3a7(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x10c));
  return;
}



void Unwind_0042a3b3(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x150));
  return;
}



void Unwind_0042a3bf(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1b8));
  return;
}



void Unwind_0042a3cb(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x14c));
  return;
}



void Unwind_0042a3d7(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x158));
  return;
}



void Unwind_0042a3e3(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x1c0));
  return;
}



void Unwind_0042a3f1(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x1c4));
  return;
}



void Unwind_0042a3fd(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x1c8));
  return;
}



void Unwind_0042a409(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x1cc));
  return;
}



void Unwind_0042a415(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x1d0));
  return;
}



void Unwind_0042a421(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1d8));
  return;
}



void Unwind_0042a42d(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1dc));
  return;
}



void Unwind_0042a439(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1e0));
  return;
}



void Unwind_0042a445(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1e4));
  return;
}



void Unwind_0042a451(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1e8));
  return;
}



void Unwind_0042a45d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1ec));
  return;
}



void Unwind_0042a469(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1f0));
  return;
}



void Unwind_0042a475(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -500));
  return;
}



void Unwind_0042a481(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1f8));
  return;
}



void Unwind_0042a48d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1fc));
  return;
}



void Unwind_0042a499(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x200));
  return;
}



void Unwind_0042a4a5(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x204));
  return;
}



void Unwind_0042a4b1(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x208));
  return;
}



void Unwind_0042a4bd(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20c));
  return;
}



void Unwind_0042a4c9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x210));
  return;
}



void Unwind_0042a4d5(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xd8));
  return;
}



void Unwind_0042a4e1(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x214));
  return;
}



void Unwind_0042a4ed(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042a4f6(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x218));
  return;
}



void Unwind_0042a502(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xc4));
  return;
}



void Unwind_0042a50e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x21c));
  return;
}



void Unwind_0042a51a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xb8));
  return;
}



void Unwind_0042a526(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x220));
  return;
}



void Unwind_0042a532(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x90));
  return;
}



void Unwind_0042a53e(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x224));
  return;
}



void Unwind_0042a54a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xcc));
  return;
}



void Unwind_0042a556(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x228));
  return;
}



void Unwind_0042a562(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -200));
  return;
}



void Unwind_0042a56e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x230));
  return;
}



void Unwind_0042a57a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x238));
  return;
}



void Unwind_0042a586(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x23c));
  return;
}



void Unwind_0042a592(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x240));
  return;
}



void Unwind_0042a59e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x244));
  return;
}



void Unwind_0042a5aa(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x248));
  return;
}



void Unwind_0042a5b6(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24c));
  return;
}



void Unwind_0042a5c2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x250));
  return;
}



void Unwind_0042a5ce(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x254));
  return;
}



void Unwind_0042a5da(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -600));
  return;
}



void Unwind_0042a5e6(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x25c));
  return;
}



void Unwind_0042a5f2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x260));
  return;
}



void Unwind_0042a5fe(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x264));
  return;
}



void Unwind_0042a60a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x268));
  return;
}



void Unwind_0042a616(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x26c));
  return;
}



void Unwind_0042a622(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x270));
  return;
}



void Unwind_0042a62e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x274));
  return;
}



void Unwind_0042a63a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x278));
  return;
}



void Unwind_0042a650(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_0042a659(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_0042a662(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_0042a66b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_0042a674(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x30));
  return;
}



void Unwind_0042a67d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_0042a690(void)

{
  int unaff_EBP;
  
  FUN_00414330((undefined4 *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_0042a699(void)

{
  int unaff_EBP;
  
  FUN_004142b0((undefined4 *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0042a6ac(void)

{
  int unaff_EBP;
  
  FUN_00405f84((CDialog *)(unaff_EBP + -0x134));
  return;
}



void Unwind_0042a6b8(void)

{
  int unaff_EBP;
  
  FUN_00405bd0((CDialog *)(unaff_EBP + -0x1ac));
  return;
}



void Unwind_0042a6c4(void)

{
  int unaff_EBP;
  
  FUN_00407d90(unaff_EBP + -0x1b4);
  return;
}



void Unwind_0042a6d0(void)

{
  int unaff_EBP;
  
  FUN_00407d90(unaff_EBP + -0x1bc);
  return;
}



void Unwind_0042a6e6(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x84));
  return;
}



void Unwind_0042a6f2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x88));
  return;
}



void Unwind_0042a6fe(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x90));
  return;
}



void Unwind_0042a720(void)

{
  int unaff_EBP;
  
  FUN_00404b70(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042a740(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 0x18));
  return;
}



void Unwind_0042a749(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 0x14));
  return;
}



void Unwind_0042a752(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 0x10));
  return;
}



void Unwind_0042a75b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 0xc));
  return;
}



void Unwind_0042a764(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 8));
  return;
}



void Unwind_0042a76d(void)

{
  int unaff_EBP;
  
  FUN_0040c900(*(undefined4 **)(unaff_EBP + -0x28));
  return;
}



void Unwind_0042a776(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x28) + 0x17c));
  return;
}



void Unwind_0042a785(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x28) + 0x180));
  return;
}



void Unwind_0042a794(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x28) + 0x184));
  return;
}



void Unwind_0042a7a3(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x28) + 0x188));
  return;
}



void Unwind_0042a7b2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x28) + 0x18c));
  return;
}



void Unwind_0042a7c1(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x28) + 400));
  return;
}



void Unwind_0042a7d0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x28) + 0x194));
  return;
}



void Unwind_0042a7df(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042a7e8(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0042a7f1(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_0042a7fa(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_0042a803(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_0042a80c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_0042a820(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042a829(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0042a832(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_0042a850(void)

{
  int unaff_EBP;
  
  FUN_0040c900(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042a859(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x17c));
  return;
}



void Unwind_0042a868(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x180));
  return;
}



void Unwind_0042a877(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x184));
  return;
}



void Unwind_0042a886(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x188));
  return;
}



void Unwind_0042a895(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x18c));
  return;
}



void Unwind_0042a8a4(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 400));
  return;
}



void Unwind_0042a8c0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_0042a8c9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_0042a8d2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_0042a8db(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x34));
  return;
}



void Unwind_0042a8f0(void)

{
  int unaff_EBP;
  
  FUN_0041c8e0(*(undefined4 **)(unaff_EBP + -0x18));
  return;
}



void Unwind_0042a910(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_0042a930(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_0042a939(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_0042a942(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_0042a94b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x30));
  return;
}



void Unwind_0042a954(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x38));
  return;
}



void Unwind_0042a95f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x40));
  return;
}



void Unwind_0042a972(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x54));
  return;
}



void Unwind_0042a97b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_0042a984(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x68));
  return;
}



void Unwind_0042a98d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x6c));
  return;
}



void Unwind_0042a996(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x70));
  return;
}



void Unwind_0042a99f(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x74));
  return;
}



void Unwind_0042a9a8(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x78));
  return;
}



void Unwind_0042a9b1(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x7c));
  return;
}



void Unwind_0042a9c4(void)

{
  int unaff_EBP;
  
  MAP::~MAP((MAP *)(unaff_EBP + -0x89c));
  return;
}



void Unwind_0042a9d1(void)

{
  int unaff_EBP;
  
  MAP::~MAP((MAP *)(unaff_EBP + -0x45c));
  return;
}



void Unwind_0042a9de(void)

{
  int unaff_EBP;
  
  MAP::~MAP((MAP *)(unaff_EBP + -0xcdc));
  return;
}



void Unwind_0042aa00(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0042aa09(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_0042aa12(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_0042aa1b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2c));
  return;
}



void Unwind_0042aa24(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_0042aa2d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_0042aa36(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x44));
  return;
}



void Unwind_0042aa3f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x4c));
  return;
}



void Unwind_0042aa48(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x54));
  return;
}



void Unwind_0042aa51(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x5c));
  return;
}



void Unwind_0042aa5a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -100));
  return;
}



void Unwind_0042aa63(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x6c));
  return;
}



void Unwind_0042aa6c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x74));
  return;
}



void Unwind_0042aa75(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x7c));
  return;
}



void Unwind_0042aa7e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x84));
  return;
}



void Unwind_0042aa8a(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x8c));
  return;
}



void Unwind_0042aa96(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x94));
  return;
}



void Unwind_0042aaa2(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x9c));
  return;
}



void Unwind_0042aaae(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xa4));
  return;
}



void Unwind_0042aaba(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xac));
  return;
}



void Unwind_0042aac6(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0xb4));
  return;
}



void Unwind_0042aadc(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042aae5(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1fc));
  return;
}



void Unwind_0042aaf1(void)

{
  int unaff_EBP;
  
  INIFILE::~INIFILE((INIFILE *)(unaff_EBP + -0x3c));
  return;
}



void Unwind_0042aafb(void)

{
  int unaff_EBP;
  
  FUN_00407d90(unaff_EBP + -0x204);
  return;
}



void Unwind_0042ab07(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0042ab10(void)

{
  int unaff_EBP;
  
  FUN_00422e70((CString *)(unaff_EBP + -0x134));
  return;
}



void Unwind_0042ab1c(void)

{
  int unaff_EBP;
  
  FUN_00407d90(unaff_EBP + -0x140);
  return;
}



void Unwind_0042ab28(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x208));
  return;
}



void Unwind_0042ab34(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x20c));
  return;
}



void Unwind_0042ab40(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x210));
  return;
}



void Unwind_0042ab4c(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x214));
  return;
}



void Unwind_0042ab58(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x218));
  return;
}



void Unwind_0042ab64(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x21c));
  return;
}



void Unwind_0042ab70(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x220));
  return;
}



void Unwind_0042ab7c(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x234));
  return;
}



void Unwind_0042ab88(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x238));
  return;
}



void Unwind_0042ab94(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x160));
  return;
}



void Unwind_0042aba0(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x23c));
  return;
}



void Unwind_0042abac(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x240));
  return;
}



void Unwind_0042abb8(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x250));
  return;
}



void Unwind_0042abc4(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x254));
  return;
}



void Unwind_0042abd0(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x164));
  return;
}



void Unwind_0042abdc(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -600));
  return;
}



void Unwind_0042abe8(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x25c));
  return;
}



void Unwind_0042abf4(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x260));
  return;
}



void Unwind_0042ac00(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x264));
  return;
}



void Unwind_0042ac0c(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x278));
  return;
}



void Unwind_0042ac18(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x27c));
  return;
}



void Unwind_0042ac24(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x180));
  return;
}



void Unwind_0042ac30(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x280));
  return;
}



void Unwind_0042ac3c(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x284));
  return;
}



void Unwind_0042ac48(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x294));
  return;
}



void Unwind_0042ac54(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x298));
  return;
}



void Unwind_0042ac60(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x29c));
  return;
}



void Unwind_0042ac6c(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -400));
  return;
}



void Unwind_0042ac78(void)

{
  int unaff_EBP;
  
  FUN_00422f30((CString *)(unaff_EBP + -0x2ac));
  return;
}



void Unwind_0042ac84(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x2b0));
  return;
}



void Unwind_0042ac90(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x2b4));
  return;
}



void Unwind_0042ac9c(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1a4));
  return;
}



void Unwind_0042aca8(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x2b8));
  return;
}



void Unwind_0042acb4(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x194));
  return;
}



void Unwind_0042acc0(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -700));
  return;
}



void Unwind_0042accc(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x2c0));
  return;
}



void Unwind_0042acd8(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1bc));
  return;
}



void Unwind_0042ace4(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x2c4));
  return;
}



void Unwind_0042acf0(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x2c8));
  return;
}



void Unwind_0042acfc(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x2cc));
  return;
}



void Unwind_0042ad08(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1b8));
  return;
}



void Unwind_0042ad14(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x2d0));
  return;
}



void Unwind_0042ad20(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x2d4));
  return;
}



void Unwind_0042ad2c(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x2d8));
  return;
}



void Unwind_0042ad38(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1c0));
  return;
}



void Unwind_0042ad44(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1c4));
  return;
}



void Unwind_0042ad50(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x2dc));
  return;
}



void Unwind_0042ad5c(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x2e0));
  return;
}



void Unwind_0042ad68(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x2e8));
  return;
}



void Unwind_0042ad74(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x2ec));
  return;
}



void Unwind_0042ad80(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x2f0));
  return;
}



void Unwind_0042ad8c(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x1dc));
  return;
}



void Unwind_0042ad98(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x2f4));
  return;
}



void Unwind_0042ada4(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x308));
  return;
}



void Unwind_0042adb2(void)

{
  int unaff_EBP;
  
  CDHtmlElementEventSink::~CDHtmlElementEventSink((CDHtmlElementEventSink *)(unaff_EBP + -0x300));
  return;
}



void Unwind_0042adbe(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -800));
  return;
}



void Unwind_0042adcc(void)

{
  int unaff_EBP;
  
  CDHtmlElementEventSink::~CDHtmlElementEventSink((CDHtmlElementEventSink *)(unaff_EBP + -0x318));
  return;
}



void Unwind_0042add8(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x33c));
  return;
}



void Unwind_0042ade6(void)

{
  int unaff_EBP;
  
  CDHtmlElementEventSink::~CDHtmlElementEventSink((CDHtmlElementEventSink *)(unaff_EBP + -0x334));
  return;
}



void Unwind_0042adf2(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x350));
  return;
}



void Unwind_0042ae00(void)

{
  int unaff_EBP;
  
  CDHtmlElementEventSink::~CDHtmlElementEventSink((CDHtmlElementEventSink *)(unaff_EBP + -0x348));
  return;
}



void Unwind_0042ae0c(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x364));
  return;
}



void Unwind_0042ae1a(void)

{
  int unaff_EBP;
  
  CDHtmlElementEventSink::~CDHtmlElementEventSink((CDHtmlElementEventSink *)(unaff_EBP + -0x35c));
  return;
}



void Unwind_0042ae26(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x368));
  return;
}



void Unwind_0042ae32(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x37c));
  return;
}



void Unwind_0042ae40(void)

{
  int unaff_EBP;
  
  CDHtmlElementEventSink::~CDHtmlElementEventSink((CDHtmlElementEventSink *)(unaff_EBP + -0x374));
  return;
}



void Unwind_0042ae56(void)

{
  int unaff_EBP;
  
  CDHtmlElementEventSink::~CDHtmlElementEventSink((CDHtmlElementEventSink *)(unaff_EBP + -0x20));
  return;
}



void Unwind_0042ae5f(void)

{
  int unaff_EBP;
  
  CDHtmlElementEventSink::~CDHtmlElementEventSink((CDHtmlElementEventSink *)(unaff_EBP + -0x30));
  return;
}



void Unwind_0042ae68(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x48) & 1) != 0) {
    CDHtmlElementEventSink::~CDHtmlElementEventSink((CDHtmlElementEventSink *)(unaff_EBP + -0x3c));
  }
  return;
}



void Unwind_0042ae89(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0042ae9c(void)

{
  int unaff_EBP;
  
  CDHtmlElementEventSink::~CDHtmlElementEventSink((CDHtmlElementEventSink *)(unaff_EBP + -0x24));
  return;
}



void Unwind_0042aea5(void)

{
  int unaff_EBP;
  
  CDHtmlElementEventSink::~CDHtmlElementEventSink((CDHtmlElementEventSink *)(unaff_EBP + -0x38));
  return;
}



void Unwind_0042aeae(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x50) & 1) != 0) {
    CDHtmlElementEventSink::~CDHtmlElementEventSink((CDHtmlElementEventSink *)(unaff_EBP + -0x44));
  }
  return;
}



void Unwind_0042aed0(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042aed9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_0042aee5(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 8));
  return;
}



void Unwind_0042aef1(void)

{
  int unaff_EBP;
  
  FUN_00426c80((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x30));
  return;
}



void Unwind_0042aefd(void)

{
  int unaff_EBP;
  
  FUN_00426ca0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x4c));
  return;
}



void Unwind_0042af09(void)

{
  int unaff_EBP;
  
  FUN_00426cc0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x68));
  return;
}



void Unwind_0042af15(void)

{
  int unaff_EBP;
  
  FUN_00426ce0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x84));
  return;
}



void Unwind_0042af24(void)

{
  int unaff_EBP;
  
  FUN_00426d00((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xc0));
  return;
}



void Unwind_0042af40(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x1c));
  return;
}



void Unwind_0042af4b(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_0042af60(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x1c));
  return;
}



void Unwind_0042af6b(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_0042af80(void)

{
  int unaff_EBP;
  
  FUN_00404b70(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042afa0(void)

{
  int unaff_EBP;
  
  FUN_00422e70((CString *)(unaff_EBP + -0x10c));
  return;
}



void Unwind_0042afc0(void)

{
  int unaff_EBP;
  
  FUN_00404b70(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042afe0(void)

{
  FUN_00405650();
  return;
}



void Unwind_0042b000(void)

{
  FUN_00405650();
  return;
}



void Unwind_0042b020(void)

{
  FUN_00405650();
  return;
}



void Unwind_0042b040(void)

{
  FUN_00405650();
  return;
}



void Unwind_0042b060(void)

{
  FUN_00405650();
  return;
}



void Unwind_0042b080(void)

{
  FUN_00405650();
  return;
}



void Unwind_0042b0a0(void)

{
  FUN_00405650();
  return;
}



void Unwind_0042b0c0(void)

{
  int unaff_EBP;
  
  FUN_004014d0(*(CString **)(unaff_EBP + 8));
  return;
}



void Unwind_0042b0e0(void)

{
  int unaff_EBP;
  
  FUN_00425500(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042b0e9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x10));
  return;
}



void Unwind_0042b100(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042b120(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0042b140(void)

{
  int unaff_EBP;
  
  FUN_00425500(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042b160(void)

{
  int unaff_EBP;
  
  CChevronOwnerDrawMenu::~CChevronOwnerDrawMenu(*(CChevronOwnerDrawMenu **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042b180(void)

{
  int unaff_EBP;
  
  FUN_00425500(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042b189(void)

{
  int unaff_EBP;
  
  FUN_00425860((CChevronOwnerDrawMenu *)(*(int *)(unaff_EBP + -0x10) + 0x10));
  return;
}



void Unwind_0042b1a0(void)

{
  int unaff_EBP;
  
  FUN_00425500(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042b1a9(void)

{
  int unaff_EBP;
  
  FUN_00425860((CChevronOwnerDrawMenu *)(*(int *)(unaff_EBP + -0x10) + 0x10));
  return;
}



void Unwind_0042b1c0(void)

{
  int unaff_EBP;
  
  CString::~CString(*(CString **)(unaff_EBP + -0x20));
  return;
}



void Unwind_0042b1c9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x20) + 4));
  return;
}



void Unwind_0042b1d5(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x20) + 8));
  return;
}



void Unwind_0042b1e1(void)

{
  int unaff_EBP;
  
  FUN_00426c80((undefined4 *)(*(int *)(unaff_EBP + -0x20) + 0x30));
  return;
}



void Unwind_0042b1ed(void)

{
  int unaff_EBP;
  
  FUN_00426ca0((undefined4 *)(*(int *)(unaff_EBP + -0x20) + 0x4c));
  return;
}



void Unwind_0042b1f9(void)

{
  int unaff_EBP;
  
  FUN_00426cc0((undefined4 *)(*(int *)(unaff_EBP + -0x20) + 0x68));
  return;
}



void Unwind_0042b205(void)

{
  int unaff_EBP;
  
  FUN_00426ce0((undefined4 *)(*(int *)(unaff_EBP + -0x20) + 0x84));
  return;
}



void Unwind_0042b214(void)

{
  int unaff_EBP;
  
  FUN_00426d00((undefined4 *)(*(int *)(unaff_EBP + -0x20) + 0xc0));
  return;
}



void Unwind_0042b223(void)

{
  int unaff_EBP;
  
  FUN_00426d20((undefined4 *)(*(int *)(unaff_EBP + -0x20) + 0xdc));
  return;
}



void Unwind_0042b240(void)

{
  int unaff_EBP;
  
  CDHtmlElementEventSink::~CDHtmlElementEventSink((CDHtmlElementEventSink *)(unaff_EBP + -0x20));
  return;
}



void Unwind_0042b260(void)

{
  int unaff_EBP;
  
  FUN_00404b70(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042b280(void)

{
  int unaff_EBP;
  
  FUN_00404b70(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042b2a0(void)

{
  int unaff_EBP;
  
  FUN_00404b70(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042b2c0(void)

{
  int unaff_EBP;
  
  FUN_00404b70(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042b2e0(void)

{
  int unaff_EBP;
  
  FUN_00404b70(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0042b300(void)

{
  int unaff_EBP;
  
  FUN_00404750(unaff_EBP + 8);
  return;
}



void Unwind_0042b313(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x68));
  return;
}



void Unwind_0042b31c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -100));
  return;
}



void Unwind_0042b325(void)

{
  int unaff_EBP;
  
  FUN_004014d0((CString *)(unaff_EBP + -0x70));
  return;
}



void Unwind_0042b338(void)

{
  int unaff_EBP;
  
  FUN_00404750(unaff_EBP + -0x38);
  return;
}



void Unwind_0042b34b(void)

{
  int unaff_EBP;
  
  FUN_00404750(unaff_EBP + -0x38);
  return;
}



void Unwind_0042b35e(void)

{
  int unaff_EBP;
  
  FUN_00404750(unaff_EBP + -0x38);
  return;
}



void Unwind_0042b371(void)

{
  int unaff_EBP;
  
  FUN_00404820((undefined4 *)(unaff_EBP + 8));
  return;
}



void Unwind_0042b37a(void)

{
  int unaff_EBP;
  
  FUN_00404750(unaff_EBP + -0x38);
  return;
}



void Unwind_0042b390(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x1c));
  return;
}



void Unwind_0042b39b(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x24));
  return;
}


