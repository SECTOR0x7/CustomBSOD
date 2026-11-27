#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>
#include <ntintsafe.h>
#include <ntstrsafe.h>
#pragma intrinsic(_disable)
typedef struct _HOOK_INFO {
    PVOID TargetAddress;
    PUCHAR OriginalCode;
    SIZE_T PatchSize;
    PVOID Trampoline;
    BOOLEAN Installed;
    PVOID Variable;
} HOOK_INFO, * PHOOK_INFO;
typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    ULONG Padding;
    PWSTR Buffer;
} NTUNICODE_STRING, * PNTUNICODE_STRING;
typedef struct {
    ULONG H;
    ULONG W;
    ULONG BitsPerPixel;
    ULONG Stride;
    ULONG Flags;
    ULONG Padding;
    ULONG* PixelData;
} GP_RECT_DESC, * PGP_RECT_DESC;
typedef struct {
    UINT32  DstX;
    UINT32  DstY;
} GP_DST_INFO, * PGP_DST_INFO;
typedef struct _KAFFINITY_EX {
    USHORT Count;
    USHORT Size;
    ULONG Reserved;
    ULONGLONG Bitmap[20];
} KAFFINITY_EX;
typedef struct _RC_CMD_NODE {
    LIST_ENTRY ListEntry;
    ULONG Length;
    CHAR Buffer[1];
} RC_CMD_NODE;
static LIST_ENTRY g_RCCmdList;
typedef enum _WINDOWS_VERSION {
    WIN_UNKNOWN = 0,
    WIN_7,
    WIN_8,
    WIN_10,
    WIN_11_24H2,
    WIN_11_24H2_NEW,
    WIN_11_25H2,
    WIN_11_26H1,
    WIN_11_27H2,
    WIN_11_UNKNOWN
} WINDOWS_VERSION;
ULONG WindowsUBR = 0;
WINDOWS_VERSION winver = {};
static KBUGCHECK_REASON_CALLBACK_RECORD CallbackRecord = { 0 };
BOOLEAN CallbackRegistered = FALSE;
ULONG* g_tbcolor = NULL;
ULONG* g_tfcolor = NULL;
PUCHAR g_color = NULL;
static PVOID InstalledBlock = NULL;
PVOID g_BgpClearScreen = NULL;
PVOID g_BgpTxtDisplayCharacter = NULL;
PVOID g_BcpDisplayCriticalString = NULL;
PVOID g_BcpDisplayCriticalStringCentered = NULL;
PVOID g_BgpGxDrawRectangle = NULL;
PVOID g_BcpDisplayErrorInformationModernized = NULL;
PVOID BgInternal_0xF8 = NULL;
static HOOK_INFO g_KeGetBugMessageTextHookInfo = { NULL, NULL, 0, NULL, FALSE, NULL };
static HOOK_INFO g_BgpClearScreenHookInfo = { NULL, NULL, 0, NULL, FALSE, NULL };
static HOOK_INFO g_BgpTxtDisplayCharacterHookInfo = { NULL, NULL, 0, NULL, FALSE, NULL };
static HOOK_INFO g_BcpDisplayCriticalStringHookInfo = { NULL, NULL, 0, NULL, FALSE, NULL };
static HOOK_INFO g_BgpFwDisplayBugCheckScreenHookInfo = { NULL, NULL, 0, NULL, FALSE, NULL };
static HOOK_INFO g_BcpDisplayErrorInformationModernizedHookInfo = { NULL, NULL, 0, NULL, FALSE, NULL };
static PVOID  g_Win7StopCodeHookTarget = NULL;
static PUCHAR g_Win7StopCodeOrigCode = NULL;
static SIZE_T g_Win7StopCodeOrigSize = 0;
static BOOLEAN g_Win7StopCodeHooked = FALSE;
static PWCHAR g_WhatFailedString = 0;
static PVOID g_WhatFailedUnicodeString = NULL;
static UCHAR g_WhatFailedCallInstruction[5] = { 0 };
static PVOID g_WhatFailedCallAddress = NULL;
BOOLEAN g_UninstallAllHooksDuringDriverUnload = TRUE;
PUCHAR pVGABuffer = NULL;
UCHAR* VGAString = NULL;
ULONG VGABackColor = NULL;
ULONG VGAForeColor = NULL;
BOOLEAN VGABlink = FALSE;
BOOLEAN VGA80x25 = FALSE;
BOOLEAN VGARainbow = FALSE;
BOOLEAN Paused = FALSE;
GP_RECT_DESC OriginalSrc = { 0, 0, 0, 0, 0, 0, NULL };
static BOOLEAN g_RCListInit = FALSE;
static KBUGCHECK_REASON_CALLBACK_RECORD g_RCRecord;
static BOOLEAN g_RCRegistered = FALSE;
static PDEVICE_OBJECT g_RCDevice = NULL;
typedef NTSTATUS(*_BcpDisplayCriticalString)(PNTUNICODE_STRING String, ULONG TextSize, ULONG64 Reserved, ULONG DisplayType);
typedef NTSTATUS(*_BgpGxDrawRectangle)(PGP_RECT_DESC pSrcInfo, PGP_DST_INFO pDstInfo);
extern "C" NTKERNELAPI NTSTATUS InbvAcquireDisplayOwnership();
extern "C" NTKERNELAPI PVOID NTAPI RtlPcToFileHeader(PVOID PcValue, PVOID* BaseOfImage);
extern "C" NTKERNELAPI USHORT NTAPI KeCopyAffinityEx(VOID* Destination, const USHORT* Source);
extern "C" NTKERNELAPI ULONG NTAPI KeRemoveProcessorAffinityEx(VOID* Affinity, ULONG ProcessorNumber);
NTSTATUS _Write(PDEVICE_OBJECT DeviceObject, PVOID buffer, ULONG bufLen);
#define IOCTL_CUSTOMBSOD_GET_LOG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
static KSPIN_LOCK g_LogLock;
static CHAR* g_LogBuf = NULL;
static SIZE_T g_LogBufSize = 16777216;
static ULONG g_LogLen;
static VOID LogPrintf(ULONG Component, ULONG Level, const CHAR* Format, ...) {
    CHAR text[1024];
    CHAR* pText = text;
    ULONG textCch = RTL_NUMBER_OF(text);
    BOOLEAN freeText = FALSE;
    va_list args;
    va_start(args, Format);
    NTSTATUS status = RtlStringCchVPrintfA(text, RTL_NUMBER_OF(text), Format, args);
    va_end(args);
    if (status == STATUS_BUFFER_OVERFLOW) {
        ULONG size = 4096;
        while (TRUE) {
            CHAR* buf = (CHAR*)ExAllocatePoolWithTag(NonPagedPool, size, 'BgoL');
            if (buf == NULL) break;
            va_start(args, Format);
            status = RtlStringCchVPrintfA(buf, size, Format, args);
            va_end(args);
            if (status != STATUS_BUFFER_OVERFLOW || size >= 16777216) {
                pText = buf;
                textCch = size;
                freeText = TRUE;
                break;
            }
            ExFreePool(buf);
            size = (size > 16777216 / 2) ? 16777216 : size * 2;
        }
    }
    DbgPrintEx(Component, Level, "%s", pText);
    size_t length = 0;
    RtlStringCchLengthA(pText, textCch, &length);
    if (length == 0) {
        if (freeText) ExFreePool(pText);
        return;
    }
    if (length > g_LogBufSize) length = g_LogBufSize;
    KIRQL irql;
    KeAcquireSpinLock(&g_LogLock, &irql);
    if (g_LogLen + length > g_LogBufSize) {
        ULONG drop = (ULONG)(g_LogLen + length - g_LogBufSize);
        if (drop > g_LogLen) drop = g_LogLen;
        RtlMoveMemory(g_LogBuf, g_LogBuf + drop, g_LogLen - drop);
        g_LogLen -= drop;
    }
    RtlCopyMemory(g_LogBuf + g_LogLen, pText, length);
    g_LogLen += (ULONG)length;
    KeReleaseSpinLock(&g_LogLock, irql);
    if (freeText) ExFreePool(pText);
}
ULONG GetWindowsUBR()
{
    UNICODE_STRING KeyName;
    UNICODE_STRING ValueName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE KeyHandle;
    ULONG ResultLength;
    ULONG UBR = 0;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    RtlInitUnicodeString(&KeyName, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    RtlInitUnicodeString(&ValueName, L"UBR");
    InitializeObjectAttributes(&ObjectAttributes, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes))) return 0;
    NTSTATUS Status = ZwQueryValueKey(KeyHandle, &ValueName, KeyValuePartialInformation, Buffer, sizeof(Buffer), &ResultLength);
    ZwClose(KeyHandle);
    if (!NT_SUCCESS(Status)) return 0;
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    if (Info->Type != REG_DWORD || Info->DataLength < sizeof(ULONG)) return 0;
    RtlCopyMemory(&UBR, Info->Data, sizeof(ULONG));
    return UBR;
}
WINDOWS_VERSION DetectWindowsVersion() {
    RTL_OSVERSIONINFOW ver = { 0 };
    ver.dwOSVersionInfoSize = sizeof(ver);
    RtlGetVersion(&ver);
    if (ver.dwMajorVersion == 6 && ver.dwMinorVersion == 1) return WIN_7;
    if (ver.dwMajorVersion == 6 && (ver.dwMinorVersion == 2 || ver.dwMinorVersion == 3)) return WIN_8;
    if (ver.dwMajorVersion >= 10)
    {
        ULONG build = ver.dwBuildNumber;
        if (build > 29639) return WIN_11_UNKNOWN;
        if (build == 29639) return WIN_11_27H2;
        if (build >= 28000) return WIN_11_26H1;
        if (build >= 26200) return WIN_11_25H2;
        if (build == 26100 && WindowsUBR >= 4770) return WIN_11_24H2_NEW;
        if (build == 26100) return WIN_11_24H2;
        if (build >= 10240) return WIN_10;
    }
    return WIN_UNKNOWN;
}
ULONG_PTR FindAddress(PVOID Address, unsigned char* Bin, ULONG_PTR ScopeSize, ULONG_PTR BinSize) {
    unsigned char* BytesAddress = (unsigned char*)Address;
    ULONG_PTR i;
    for (ULONG_PTR find = 0; find <= ScopeSize - BinSize; find++) {
        for (i = 0; i < BinSize; i++) {
            if ((BytesAddress[find + i] != Bin[i]) && (Bin[i] != 0x00)) {
                break;
            }
        }
        if (i == BinSize) {
            return (ULONG_PTR)(BytesAddress + find);
        }
    }
    return NULL;
}
NTSTATUS WriteMemory(PVOID Address, PVOID Buffer, ULONG Size) {
    if (!Address || !Buffer || Size == 0) return STATUS_INVALID_PARAMETER;
    PMDL mdl = IoAllocateMdl(Address, Size, FALSE, FALSE, NULL);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;
    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogPrintf(77, 0, "WriteMemory Failed! Status:0x%08X\n", GetExceptionCode());
        IoFreeMdl(mdl);
        return GetExceptionCode();
    }
    PVOID mapped = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if (!mapped) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(mapped, Buffer, Size);
    LogPrintf(77, 0, "WriteMemory Succeeded! Wrote %lu bytes to address 0x%p\n", Size, Address);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return STATUS_SUCCESS;
}
NTSTATUS ReadMemory(PVOID Address, PVOID Buffer, ULONG Size) {
    PMDL Mdl = NULL;
    PVOID MappedAddress = NULL;
    BOOLEAN Locked = FALSE;
    if (!Address || !Buffer || Size == 0) return STATUS_INVALID_PARAMETER;
    Mdl = IoAllocateMdl(Address, Size, FALSE, FALSE, NULL);
    if (!Mdl) return STATUS_INSUFFICIENT_RESOURCES;
    __try {
        MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
        Locked = TRUE;
        MappedAddress = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
        if (!MappedAddress) {
            LogPrintf(77, 0, "MmGetSystemAddressForMdlSafe (in ReadMemory) Failed!\n");
            if (Locked) MmUnlockPages(Mdl);
            IoFreeMdl(Mdl);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(Buffer, MappedAddress, Size);
        LogPrintf(77, 0, "ReadMemory Succeeded! Read %lu bytes from address 0x%p\n", Size, Address);
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogPrintf(77, 0, "ReadMemory Failed! Status:0x%08X\n", GetExceptionCode());
        if (Locked) MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return GetExceptionCode();
    }
}
NTSTATUS ConvertCharToPwchar(__in PCHAR AnsiStr, __deref_out PWCHAR* UnicodeBuffer) {
    ANSI_STRING ansiStr;
    UNICODE_STRING uniStr;
    NTSTATUS status;
    RtlInitAnsiString(&ansiStr, AnsiStr);
    status = RtlAnsiStringToUnicodeString(&uniStr, &ansiStr, TRUE);
    if (!NT_SUCCESS(status)) return status;
    *UnicodeBuffer = uniStr.Buffer;
    return STATUS_SUCCESS;
}
VOID FreePwchar(PWCHAR UnicodeBuffer)
{
    if (UnicodeBuffer) {
        UNICODE_STRING str = {};
        str.Buffer = UnicodeBuffer;
        RtlFreeUnicodeString(&str);
    }
}
typedef struct _NT_TEXT_RANGE {
    PUCHAR Base;
    SIZE_T Size;
} NT_TEXT_RANGE, * PNT_TEXT_RANGE;
NT_TEXT_RANGE NtTextRangeCache = { 0 };
BOOLEAN GetNtTextRange(PNT_TEXT_RANGE TextRange)
{
    if (NtTextRangeCache.Base) { *TextRange = NtTextRangeCache; return TRUE; }
    PVOID ntBase = NULL;
    if (!TextRange) return FALSE;
    RtlZeroMemory(TextRange, sizeof(NT_TEXT_RANGE));
    if (!RtlPcToFileHeader((PVOID)KeBugCheckEx, &ntBase)) return FALSE;
    if (!ntBase) return FALSE;
    IMAGE_DOS_HEADER dosHeader = { 0 };
    if (!NT_SUCCESS(ReadMemory(ntBase, &dosHeader, sizeof(dosHeader)))) return FALSE;
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    IMAGE_NT_HEADERS64 ntHeaders = { 0 };
    PVOID ntHeaderAddress = (PUCHAR)ntBase + dosHeader.e_lfanew;
    if (!NT_SUCCESS(ReadMemory(ntHeaderAddress, &ntHeaders, sizeof(ntHeaders)))) return FALSE;
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) return FALSE;
    if (ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return FALSE;
    PIMAGE_SECTION_HEADER sectionHeaderAddress = (PIMAGE_SECTION_HEADER)((PUCHAR)ntHeaderAddress + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + ntHeaders.FileHeader.SizeOfOptionalHeader);
    for (USHORT i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
    {
        IMAGE_SECTION_HEADER section = { 0 };
        if (!NT_SUCCESS(ReadMemory((PUCHAR)sectionHeaderAddress + i * sizeof(IMAGE_SECTION_HEADER), &section, sizeof(section)))) continue;
        if (section.Name[0] == '.' && section.Name[1] == 't' && section.Name[2] == 'e' && section.Name[3] == 'x' && section.Name[4] == 't') {
            TextRange->Base = (PUCHAR)ntBase + section.VirtualAddress;
            TextRange->Size = section.Misc.VirtualSize;
            if (TextRange->Size == 0) TextRange->Size = section.SizeOfRawData;
            NtTextRangeCache = *TextRange;
            return TRUE;
        }
    }
    return FALSE;
}
PVOID FindFunction(UCHAR* pattern, ULONG patternSize, UCHAR* pattern2 = NULL, ULONG patternSize2 = NULL, UCHAR* pattern3 = NULL, ULONG patternSize3 = NULL, UCHAR* pattern4 = NULL, ULONG patternSize4 = NULL, UCHAR* pattern5 = NULL, ULONG patternSize5 = NULL, UCHAR* pattern6 = NULL, ULONG patternSize6 = NULL) {
    NT_TEXT_RANGE textRange = { 0 };
    if (!GetNtTextRange(&textRange)) return NULL;
    if (!textRange.Base) return NULL;
    if (textRange.Size < patternSize) return NULL;
    if (pattern2 && textRange.Size < patternSize2) return NULL;
    if (pattern3 && textRange.Size < patternSize3) return NULL;
    if (pattern4 && textRange.Size < patternSize4) return NULL;
    if (pattern5 && textRange.Size < patternSize5) return NULL;
    if (pattern6 && textRange.Size < patternSize6) return NULL;
    ULONG_PTR address = FindAddress(textRange.Base, pattern, textRange.Size, patternSize);
    ULONG_PTR address2 = NULL, address3 = NULL, address4 = NULL, address5 = NULL, address6 = NULL;
    if (pattern2) address2 = FindAddress(textRange.Base, pattern2, textRange.Size, patternSize2);
    if (pattern3) address3 = FindAddress(textRange.Base, pattern3, textRange.Size, patternSize3);
    if (pattern4) address4 = FindAddress(textRange.Base, pattern4, textRange.Size, patternSize4);
    if (pattern5) address5 = FindAddress(textRange.Base, pattern5, textRange.Size, patternSize5);
    if (pattern6) address6 = FindAddress(textRange.Base, pattern6, textRange.Size, patternSize6);
    if (address) return (PVOID)address;
    if (address2) return (PVOID)address2;
    if (address3) return (PVOID)address3;
    if (address4) return (PVOID)address4;
    if (address5) return (PVOID)address5;
    if (address6) return (PVOID)address6;
    return NULL;
}
PVOID FindKeBugCheck2() {
    UCHAR pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x00, 0x00, 0x00, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x9D, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xAD, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xF6, 0x44, 0x88, 0xB5, 0x00, 0x00, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x44, 0x39, 0x35, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0x80, 0x0F, 0xB6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x95, 0x44, 0x24, 0x00, 0x89, 0x4C, 0x24, 0x00, 0x41, 0x8D, 0x4E, 0x01, 0xC1, 0xE8, 0x02, 0x23, 0xC1, 0x4D, 0x8B, 0xF9, 0x49, 0x8B, 0xF8, 0x48, 0x8B, 0xF2, 0x44, 0x88, 0x74, 0x24, 0x00, 0x44, 0x88, 0x74, 0x24, 0x00, 0x89, 0x44, 0x24, 0x00, 0x4C, 0x89, 0x74, 0x24, 0x00, 0x4C, 0x89, 0x74, 0x24, 0x00, 0x88, 0x4C, 0x24, 0x00, 0x88, 0x4C, 0x24, 0x00, 0x45, 0x8B, 0xE6, 0x44, 0x0F, 0x20, 0xC0, 0x8D, 0x51, 0x01, 0x3A, 0xC2, 0x73, 0x00 };
    UCHAR pattern2[] = { 0x48, 0x89, 0x5C, 0x24, 0x00, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x00, 0x00, 0x00, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xB5, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0xF8, 0x4C, 0x8B, 0xB5, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xEA, 0x89, 0x4C, 0x24, 0x00, 0x33, 0xD2, 0x41, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x4D, 0x00, 0x49, 0x8B, 0xF9, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x33, 0xDB, 0xC6, 0x44, 0x24, 0x00, 0x01, 0x88, 0x9D, 0x00, 0x00, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0x39, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x00, 0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0x00, 0x0F, 0x95, 0x44, 0x24, 0x00, 0x48, 0x89, 0x5D, 0x00, 0x88, 0x5C, 0x24, 0x00, 0x88, 0x5C, 0x24, 0x00, 0x88, 0x5C, 0x24, 0x00, 0x48, 0x89, 0x5C, 0x24, 0x00, 0x48, 0x89, 0x5D, 0x00, 0xC6, 0x44, 0x24, 0x00, 0x01, 0x89, 0x5D, 0x00, 0x48, 0x89, 0x5D, 0x00, 0x48, 0x89, 0x5D, 0x00, 0x89, 0x5D, 0x00, 0x44, 0x0F, 0x20, 0xC0, 0x8D, 0x53, 0x00, 0x44, 0x8D, 0x43, 0x00, 0x3A, 0xC2, 0x73, 0x00 };
    UCHAR pattern3[] = { 0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x00, 0x00, 0x00, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x85, 0x00, 0x00, 0x00, 0x00, 0x49, 0x8B, 0xF8, 0x4C, 0x8B, 0xAD, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xFA, 0x4C, 0x89, 0x45, 0x00, 0x33, 0xD2, 0x89, 0x4D, 0x00, 0x41, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x4D, 0x00, 0x48, 0x89, 0x44, 0x24, 0x00, 0x4D, 0x8B, 0xE1, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xF6, 0xC6, 0x44, 0x24, 0x00, 0x01, 0x44, 0x88, 0xB5, 0x00, 0x00, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x44, 0x39, 0x35, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0x00, 0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0x00, 0x0F, 0x95, 0x44, 0x24, 0x00, 0x41, 0x8D, 0x46, 0x01, 0x4C, 0x89, 0x75, 0x00, 0x44, 0x88, 0x74, 0x24, 0x00, 0x4C, 0x89, 0x75, 0x00, 0x87, 0x05, 0x00, 0x00, 0x00, 0x00, 0x44, 0x88, 0x74, 0x24, 0x00, 0x44, 0x88, 0x74, 0x24, 0x00, 0x44, 0x88, 0x74, 0x24, 0x00, 0x4C, 0x89, 0x75, 0x00, 0x4C, 0x89, 0x74, 0x24, 0x00, 0xC6, 0x44, 0x24, 0x00, 0x01, 0x44, 0x88, 0x74, 0x24, 0x00, 0x44, 0x89, 0x75, 0x00, 0x85, 0xC0, 0x75, 0x00 };
    UCHAR pattern4[] = { 0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0xB8, 0xF9, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0x48, 0x07, 0x00, 0x00, 0x48, 0x8B, 0x85, 0xB8, 0x06, 0x00, 0x00, 0x49, 0x8B, 0xF0, 0x4C, 0x8B, 0xAD, 0xB0, 0x06, 0x00, 0x00, 0x4C, 0x8B, 0xFA, 0x4C, 0x89, 0x45, 0xD0, 0x33, 0xD2, 0x89, 0x4D, 0x80, 0x41, 0xB8, 0x08, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x4D, 0xE0, 0x48, 0x89, 0x44, 0x24, 0x70, 0x4D, 0x8B, 0xE1, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x33, 0xDB, 0x88, 0x9D, 0xC0, 0x05, 0x00, 0x00, 0x8B, 0xFB, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x39, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0xB0, 0x44, 0x8D, 0x73, 0x01, 0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x5D, 0xA8, 0x48, 0x89, 0x45, 0xB8, 0x0F, 0x95, 0x44, 0x24, 0x5D, 0x41, 0x8B, 0xC6, 0x88, 0x5C, 0x24, 0x5B, 0x87, 0x05, 0x00, 0x00, 0x00, 0x00, 0x88, 0x5C, 0x24, 0x54, 0x88, 0x5C, 0x24, 0x78, 0x88, 0x5C, 0x24, 0x7A, 0x48, 0x89, 0x5C, 0x24, 0x60, 0x48, 0x89, 0x5D, 0xC0, 0x48, 0x89, 0x5D, 0x90, 0x44, 0x88, 0x74, 0x24, 0x5A, 0x44, 0x88, 0x74, 0x24, 0x50, 0x88, 0x5C, 0x24, 0x79, 0x89, 0x5D, 0x98, 0x85, 0xC0, 0x75, 0x64 };
    UCHAR pattern5[] = { 0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x00, 0x00, 0x00, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x85, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0xF0, 0x4C, 0x8B, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xEA, 0x4C, 0x89, 0x45, 0x00, 0x49, 0x8B, 0xF9, 0x48, 0x89, 0x55, 0x00, 0x41, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x89, 0x4D, 0x00, 0x33, 0xD2, 0x48, 0x8D, 0x4D, 0x00, 0x48, 0x89, 0x44, 0x24, 0x00, 0x4C, 0x89, 0x4D, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x33, 0xDB, 0x88, 0x9D, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xF3, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0x39, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0x00, 0x44, 0x8D, 0x7B, 0x00, 0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x5D, 0x00, 0x48, 0x89, 0x45, 0x00, 0x0F, 0x95, 0x44, 0x24, 0x00, 0x41, 0x8B, 0xC7, 0x88, 0x5C, 0x24, 0x00, 0x87, 0x05, 0x00, 0x00, 0x00, 0x00, 0x88, 0x5C, 0x24, 0x00, 0x88, 0x5C, 0x24, 0x00, 0x48, 0x89, 0x5D, 0x00, 0x48, 0x89, 0x5D, 0x00, 0x44, 0x88, 0x7C, 0x24, 0x00, 0x44, 0x88, 0x7C, 0x24, 0x00, 0x89, 0x5D, 0x00, 0x85, 0xC0, 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00 };
    return FindFunction(pattern, sizeof(pattern), pattern2, sizeof(pattern2), pattern3, sizeof(pattern3), pattern4, sizeof(pattern4), pattern5, sizeof(pattern5));
}
PVOID FindKiDisplayBlueScreen()
{
    UCHAR pattern[] = { 0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x54, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x84, 0x24, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xB4, 0x24, 0x00, 0x00, 0x00, 0x00, 0x49, 0x8B, 0xD9, 0x49, 0x8B, 0xF8, 0x40, 0x8A, 0xEA, 0x44, 0x8B, 0xE1, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x84, 0xC0, 0x74, 0x00 };
    UCHAR pattern2[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x00, 0x48, 0x89, 0x70, 0x00, 0x48, 0x89, 0x78, 0x00, 0x4C, 0x89, 0x60, 0x00, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xA8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x85, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x33, 0xD2, 0x44, 0x8B, 0xF1, 0x8D, 0x4A, 0x00, 0x45, 0x33, 0xFF, 0x45, 0x33, 0xC9, 0x45, 0x33, 0xC0, 0x89, 0x44, 0x24, 0x00, 0xC6, 0x44, 0x24, 0x00, 0x01, 0x4C, 0x89, 0x7C, 0x24, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x8D, 0x47, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x00, 0x41, 0x8B, 0xC8, 0x45, 0x33, 0xC9, 0x4C, 0x89, 0x7C, 0x24, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x41, 0x8D, 0x77, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x00, 0x8D, 0x4E, 0x00, 0x45, 0x33, 0xC9, 0x44, 0x8B, 0xC6, 0x4C, 0x89, 0x7C, 0x24, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xDB, 0x75, 0x00 };
    UCHAR pattern3[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x00, 0x48, 0x89, 0x70, 0x00, 0x48, 0x89, 0x78, 0x00, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xA8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x85, 0x00, 0x00, 0x00, 0x00, 0x33, 0xD2, 0x44, 0x8B, 0xE1, 0x48, 0x8D, 0x4C, 0x24, 0x00, 0x44, 0x8D, 0x42, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xED, 0x33, 0xD2, 0x4C, 0x89, 0x6C, 0x24, 0x00, 0x0F, 0x57, 0xC0, 0x89, 0x44, 0x24, 0x00, 0x45, 0x33, 0xC9, 0x4C, 0x89, 0x6C, 0x24, 0x00, 0x45, 0x8D, 0x7D, 0x00, 0x45, 0x33, 0xC0, 0x8D, 0x4A, 0x00, 0x44, 0x88, 0x7C, 0x24, 0x00, 0x0F, 0x11, 0x44, 0x24, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC9, 0x4C, 0x89, 0x6C, 0x24, 0x00, 0x45, 0x8B, 0xC7, 0x48, 0x8D, 0x54, 0x24, 0x00, 0x41, 0x8B, 0xCF, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x8D, 0x75, 0x00, 0x4C, 0x89, 0x6C, 0x24, 0x00, 0x45, 0x8B, 0xC6, 0x48, 0x8D, 0x54, 0x24, 0x00, 0x45, 0x33, 0xC9, 0x41, 0x8D, 0x4D, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x41, 0x8D, 0x4E, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xDB, 0x75, 0x00 };
    UCHAR pattern4[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x00, 0x48, 0x89, 0x70, 0x00, 0x48, 0x89, 0x78, 0x00, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xA8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x85, 0x00, 0x00, 0x00, 0x00, 0x33, 0xD2, 0x44, 0x8B, 0xF9, 0x48, 0x8D, 0x4C, 0x24, 0x00, 0x44, 0x8D, 0x42, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xE4, 0x0F, 0x57, 0xC0, 0x4C, 0x89, 0x64, 0x24, 0x00, 0x45, 0x33, 0xC9, 0x89, 0x44, 0x24, 0x00, 0x45, 0x33, 0xC0, 0x4C, 0x89, 0x64, 0x24, 0x00, 0x41, 0x8D, 0x74, 0x24, 0x00, 0x33, 0xD2, 0x8D, 0x4E, 0x00, 0x40, 0x88, 0x74, 0x24, 0x00, 0x0F, 0x11, 0x44, 0x24, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC9, 0x4C, 0x89, 0x64, 0x24, 0x00, 0x44, 0x8B, 0xC6, 0x48, 0x8D, 0x54, 0x24, 0x00, 0x8B, 0xCE, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x8D, 0x74, 0x24, 0x00, 0x4C, 0x89, 0x64, 0x24, 0x00, 0x45, 0x8B, 0xC6, 0x48, 0x8D, 0x54, 0x24, 0x00, 0x45, 0x33, 0xC9, 0x8D, 0x4E, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x41, 0x8D, 0x4E, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xDB, 0x75, 0x00 };
    UCHAR pattern5[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x00, 0x48, 0x89, 0x70, 0x00, 0x48, 0x89, 0x78, 0x00, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xA8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x85, 0x00, 0x00, 0x00, 0x00, 0x33, 0xD2, 0x44, 0x8B, 0xF1, 0x48, 0x8D, 0x4C, 0x24, 0x00, 0x44, 0x8D, 0x42, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xFF, 0x0F, 0x57, 0xC0, 0x4C, 0x89, 0x7C, 0x24, 0x00, 0x45, 0x33, 0xC9, 0x89, 0x44, 0x24, 0x00, 0x45, 0x33, 0xC0, 0x4C, 0x89, 0x7C, 0x24, 0x00, 0x41, 0x8D, 0x7F, 0x00, 0x33, 0xD2, 0x8D, 0x4F, 0x00, 0x40, 0x88, 0x7C, 0x24, 0x00, 0x0F, 0x11, 0x44, 0x24, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC9, 0x4C, 0x89, 0x7C, 0x24, 0x00, 0x44, 0x8B, 0xC7, 0x48, 0x8D, 0x54, 0x24, 0x00, 0x8B, 0xCF, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8D, 0x77, 0x00, 0x4C, 0x89, 0x7C, 0x24, 0x00, 0x44, 0x8B, 0xC6, 0x48, 0x8D, 0x54, 0x24, 0x00, 0x45, 0x33, 0xC9, 0x8D, 0x4F, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8D, 0x4E, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x25, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xDB, 0x75, 0x00 };
    UCHAR pattern6[] = { 0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x55, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x00, 0x00, 0x00, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x85, 0x00, 0x00, 0x00, 0x00, 0x33, 0xD2, 0x8B, 0xF1, 0x48, 0x8D, 0x4C, 0x24, 0x00, 0x44, 0x8D, 0x42, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x33, 0xD2, 0x0F, 0x57, 0xC0, 0x48, 0xC7, 0x44, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xBD, 0x00, 0x00, 0x00, 0x00, 0x89, 0x44, 0x24, 0x00, 0x45, 0x33, 0xC9, 0x44, 0x88, 0x6C, 0x24, 0x00, 0x8D, 0x4A, 0x00, 0x48, 0xC7, 0x44, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC0, 0x0F, 0x11, 0x44, 0x24, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC9, 0x48, 0xC7, 0x44, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x45, 0x8B, 0xC5, 0x48, 0x8D, 0x54, 0x24, 0x00, 0x41, 0x8B, 0xCD, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC9, 0x48, 0xC7, 0x44, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x45, 0x8D, 0x45, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x00, 0x41, 0x8D, 0x4D, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xDB, 0x75, 0x00 };
    return FindFunction(pattern, sizeof(pattern), pattern2, sizeof(pattern2), pattern3, sizeof(pattern3), pattern4, sizeof(pattern4), pattern5, sizeof(pattern5), pattern6, sizeof(pattern6));
}
PVOID FindKeGetBugMessageText()
{
    UCHAR pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x8B, 0xF9, 0x33, 0xDB, 0x88, 0x5C, 0x24, 0x20, 0x48, 0x39, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 };
    UCHAR pattern2[] = { 0x48, 0x83, 0xEC, 0x28, 0x44, 0x8B, 0xD1, 0x45, 0x33, 0xC9, 0x44, 0x88, 0x0C, 0x24, 0x4C, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x85, 0xC0, 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 };
    UCHAR pattern3[] = { 0x48, 0x83, 0xEC, 0x28, 0x4C, 0x8B, 0xDA, 0x44, 0x8B, 0xD1, 0x45, 0x33, 0xC0, 0x44, 0x88, 0x04, 0x24, 0x4C, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x85, 0xC9, 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 };
    UCHAR pattern4[] = { 0x48, 0x83, 0xEC, 0x00, 0x4C, 0x8B, 0xDA, 0x44, 0x8B, 0xD1, 0x45, 0x32, 0xC0, 0x44, 0x88, 0x04, 0x24, 0x4C, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x85, 0xC9, 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 };
    return FindFunction(pattern, sizeof(pattern), pattern2, sizeof(pattern2), pattern3, sizeof(pattern3), pattern4, sizeof(pattern4));
}
PVOID FindBgpFwDisplayBugCheckScreen() {
    UCHAR pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x00, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x44, 0x8B, 0xF9, 0x4D, 0x8B, 0xF1, 0x4D, 0x8B, 0xE8, 0x48, 0x8B, 0xEA, 0xB9, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x00, 0x74, 0x00 };
    UCHAR pattern2[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x00, 0x48, 0x89, 0x68, 0x00, 0x48, 0x89, 0x70, 0x00, 0x4C, 0x89, 0x40, 0x00, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x00, 0x48, 0x83, 0x60, 0x00, 0x00, 0x8B, 0xE9, 0x48, 0x83, 0x60, 0x00, 0x00, 0x4D, 0x8B, 0xE1, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xEA, 0xB9, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x00, 0x74, 0x00 };
    UCHAR pattern3[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x00, 0x48, 0x89, 0x68, 0x00, 0x48, 0x89, 0x70, 0x00, 0x4C, 0x89, 0x40, 0x00, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x00, 0x48, 0x83, 0x60, 0x00, 0x00, 0x4D, 0x8B, 0xE1, 0x48, 0x83, 0x60, 0x00, 0x00, 0x4C, 0x8B, 0xEA, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xE9, 0xA8, 0x00, 0x74, 0x00 };
    UCHAR pattern4[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x00, 0x48, 0x89, 0x68, 0x00, 0x48, 0x89, 0x70, 0x00, 0x4C, 0x89, 0x40, 0x00, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x00, 0x48, 0xC7, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0xE1, 0x48, 0xC7, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xEA, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xE9, 0xA8, 0x00, 0x74, 0x00 };
    UCHAR pattern5[] = { 0x4C, 0x89, 0x44, 0x24, 0x00, 0x53, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x00, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0xE1, 0x48, 0xC7, 0x44, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xEA, 0x48, 0xC7, 0x44, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xE9, 0xA8, 0x00, 0x74, 0x00 };
    return FindFunction(pattern, sizeof(pattern), pattern2, sizeof(pattern2), pattern3, sizeof(pattern3), pattern4, sizeof(pattern4), pattern5, sizeof(pattern5));
}
PVOID FindBgpClearScreen()
{
    UCHAR pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x7C, 0x24, 0x20, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x30, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xF1, 0xA8, 0x01, 0x75, 0x00 };
    UCHAR pattern2[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x7C, 0x24, 0x20, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x40, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x44, 0x8B, 0xF1, 0xA8, 0x01, 0x75, 0x00 };
    UCHAR pattern3[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x7C, 0x24, 0x20, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x30, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x44, 0x8B, 0xF9, 0xA8, 0x01, 0x75, 0x00 };
    UCHAR pattern4[] = { 0x48, 0x89, 0x5C, 0x24, 0x00, 0x48, 0x89, 0x6C, 0x24, 0x00, 0x56, 0x57, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x00, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x44, 0x8B, 0xF1, 0x48, 0xC7, 0x44, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x00, 0x75, 0x00 };
    return FindFunction(pattern, sizeof(pattern), pattern2, sizeof(pattern2), pattern3, sizeof(pattern3), pattern4, sizeof(pattern4));
}
PVOID FindBgpTxtDisplayCharacter()
{
    UCHAR pattern[] = { 0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x00, 0x44, 0x89, 0x40, 0x00, 0x66, 0x89, 0x50, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x68, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x41, 0x00, 0x4C, 0x8B, 0xE1, 0x49, 0x8B, 0x74, 0x24, 0x00, 0x4D, 0x8D, 0x5C, 0x24, 0x00, 0x48, 0x89, 0x45, 0x00, 0x45, 0x8A, 0x73, 0x00, 0x33, 0xC0, 0x41, 0x80, 0xE6, 0x01, 0x8B, 0xC8, 0x48, 0x89, 0x45, 0x00, 0x44, 0x8B, 0xC0, 0x89, 0x45, 0x00, 0x48, 0x89, 0x45, 0x00, 0x89, 0x45, 0x00, 0x89, 0x45, 0x00, 0x8B, 0xD8, 0x48, 0x89, 0x45, 0x00, 0x44, 0x8B, 0xF8, 0x48, 0x89, 0x45, 0x00, 0x88, 0x45, 0x00, 0x8B, 0xF8, 0x44, 0x8B, 0xE8, 0x89, 0x45, 0x00, 0x66, 0x83, 0xFA, 0x00, 0x72, 0x00 };
    UCHAR pattern2[] = { 0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x00, 0x44, 0x89, 0x40, 0x00, 0x66, 0x89, 0x50, 0x00, 0x48, 0x89, 0x48, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x68, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0x65, 0x00, 0x00, 0x48, 0x8B, 0xC1, 0x48, 0x8B, 0x49, 0x00, 0x45, 0x33, 0xC9, 0x33, 0xDB, 0x48, 0x89, 0x4D, 0x00, 0x33, 0xC9, 0x44, 0x89, 0x4D, 0x00, 0x21, 0x4D, 0x00, 0x4C, 0x8D, 0x40, 0x00, 0x45, 0x8A, 0x78, 0x00, 0x45, 0x33, 0xE4, 0x21, 0x4D, 0x00, 0x41, 0x80, 0xE7, 0x00, 0x21, 0x4D, 0x00, 0x45, 0x33, 0xED, 0x21, 0x4D, 0x00, 0x33, 0xFF, 0x48, 0x8B, 0x70, 0x00, 0x45, 0x8A, 0xF7, 0x48, 0x89, 0x4D, 0x00, 0x48, 0x89, 0x5D, 0x00, 0x4C, 0x89, 0x65, 0x00, 0x88, 0x4D, 0x00, 0x4C, 0x89, 0x45, 0x00, 0x44, 0x89, 0x6D, 0x00, 0x66, 0x83, 0xFA, 0x00, 0x72, 0x00 };
    UCHAR pattern3[] = { 0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x00, 0x44, 0x89, 0x40, 0x00, 0x66, 0x89, 0x50, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x68, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x41, 0x00, 0x45, 0x33, 0xF6, 0x4C, 0x8B, 0xE9, 0x48, 0x89, 0x45, 0x00, 0x41, 0x8B, 0xCE, 0x4C, 0x89, 0x75, 0x00, 0x41, 0x8B, 0xDE, 0x44, 0x89, 0x75, 0x00, 0x41, 0x8B, 0xC6, 0x4C, 0x89, 0x75, 0x00, 0x49, 0x8B, 0x7D, 0x00, 0x4D, 0x8D, 0x45, 0x00, 0x45, 0x8A, 0x78, 0x00, 0x45, 0x8B, 0xCE, 0x41, 0x80, 0xE7, 0x00, 0x44, 0x89, 0x75, 0x00, 0x44, 0x89, 0x75, 0x00, 0x45, 0x8B, 0xE6, 0x4C, 0x89, 0x75, 0x00, 0x41, 0x8B, 0xF6, 0x44, 0x88, 0x75, 0x00, 0x45, 0x8A, 0xF7, 0x48, 0x89, 0x4D, 0x00, 0x48, 0x89, 0x5D, 0x00, 0x89, 0x45, 0x00, 0x66, 0x83, 0xFA, 0x00, 0x0F, 0x82, 0x00, 0x00, 0x00, 0x00 };
    UCHAR pattern4[] = { 0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x00, 0x44, 0x89, 0x40, 0x00, 0x66, 0x89, 0x50, 0x00, 0x48, 0x89, 0x48, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x68, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xC1, 0x48, 0xC7, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x49, 0x00, 0x45, 0x33, 0xC0, 0x33, 0xDB, 0x48, 0x89, 0x4D, 0x00, 0x33, 0xC9, 0x44, 0x89, 0x45, 0x00, 0x4C, 0x8B, 0x70, 0x00, 0x4C, 0x8D, 0x68, 0x00, 0x45, 0x8A, 0x7D, 0x00, 0x45, 0x33, 0xE4, 0x41, 0x80, 0xE7, 0x01, 0x48, 0x89, 0x4D, 0x00, 0x33, 0xC0, 0x48, 0x89, 0x4D, 0x00, 0x33, 0xF6, 0x89, 0x4D, 0x00, 0x89, 0x4D, 0x00, 0x41, 0x8A, 0xFF, 0x48, 0x89, 0x5D, 0x00, 0x4C, 0x89, 0x65, 0x00, 0x88, 0x4D, 0x00, 0x89, 0x45, 0x00, 0x66, 0x83, 0xFA, 0x00, 0x0F, 0x82, 0x00, 0x00, 0x00, 0x00 };
    UCHAR pattern5[] = { 0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x00, 0x44, 0x89, 0x40, 0x00, 0x66, 0x89, 0x50, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x68, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xF9, 0x48, 0xC7, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0xC9, 0x45, 0x33, 0xC0, 0x33, 0xFF, 0x48, 0x89, 0x4D, 0x00, 0x45, 0x33, 0xE4, 0x44, 0x89, 0x45, 0x00, 0x41, 0x8B, 0x5F, 0x00, 0x45, 0x32, 0xED, 0x4D, 0x8B, 0x77, 0x00, 0x33, 0xC0, 0x83, 0xE3, 0x01, 0x48, 0x89, 0x4D, 0x00, 0x33, 0xF6, 0x89, 0x4D, 0x00, 0x89, 0x4D, 0x00, 0x48, 0x89, 0x7D, 0x00, 0x4C, 0x89, 0x65, 0x00, 0x44, 0x88, 0x6D, 0x00, 0x89, 0x45, 0x00, 0x66, 0x83, 0xFA, 0x00, 0x0F, 0x82, 0x00, 0x00, 0x00, 0x00 };
    return FindFunction(pattern, sizeof(pattern), pattern2, sizeof(pattern2), pattern3, sizeof(pattern3), pattern4, sizeof(pattern4), pattern5, sizeof(pattern5));
}
PVOID FindBgpFwAcquireLock() {
    UCHAR pattern[] = { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x00, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x23, 0xC1, 0x3B, 0xC1, 0x74, 0x00 };
    UCHAR pattern2[] = { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x00, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x23, 0xC1, 0x3B, 0xC1, 0x74, 0x00 };
    return FindFunction(pattern, sizeof(pattern), pattern2, sizeof(pattern2));
}
PVOID FindBcpDisplayCriticalString() {
    UCHAR pattern[] = { 0x44, 0x89, 0x44, 0x24, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x00, 0x8B, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x35, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xE9, 0x44, 0x8B, 0xC2, 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x49, 0x63, 0xC1, 0x45, 0x32, 0xE4, 0x44, 0x89, 0x65, 0x00, 0x48, 0x6B, 0xC0, 0x00, 0x48, 0x03, 0xC1, 0x48, 0x89, 0x45, 0x00, 0x8B, 0x48, 0x00, 0x44, 0x8B, 0x78, 0x00, 0x03, 0x48, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x50, 0x00, 0x89, 0x4D, 0x00, 0x44, 0x03, 0xF9, 0x44, 0x89, 0x42, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x72, 0x00, 0x44, 0x89, 0x40, 0x00, 0x4C, 0x8D, 0x45, 0x00, 0x49, 0x8B, 0xD5, 0x49, 0x8B, 0xCE, 0x4C, 0x89, 0x75, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xD2, 0x44, 0x8B, 0xC8, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x85, 0xC9, 0x78, 0x00 };
    UCHAR pattern2[] = { 0x44, 0x89, 0x44, 0x24, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x00, 0x45, 0x33, 0xC0, 0x49, 0x63, 0xC1, 0x4C, 0x8B, 0xD1, 0x44, 0x89, 0x45, 0x00, 0x44, 0x89, 0x45, 0x00, 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x44, 0x89, 0x45, 0x00, 0x4C, 0x8D, 0x3C, 0xC0, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x00 };
    UCHAR pattern3[] = { 0x44, 0x89, 0x44, 0x24, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x00, 0x45, 0x33, 0xFF, 0x49, 0x63, 0xC1, 0x4C, 0x8D, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x44, 0x89, 0x7D, 0x00, 0x44, 0x8B, 0xC2, 0x44, 0x89, 0x7D, 0x00, 0x48, 0x8B, 0x15, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xD1, 0x44, 0x89, 0x7D, 0x00, 0x4C, 0x8D, 0x0C, 0xC0, 0x4C, 0x89, 0x4D, 0x00, 0x4B, 0x8D, 0x04, 0xCB, 0x4B, 0x8D, 0x0C, 0xCB, 0x48, 0x85, 0xD2, 0x74, 0x00 };
    UCHAR pattern4[] = { 0x44, 0x89, 0x44, 0x24, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x00, 0x45, 0x33, 0xFF, 0x49, 0x63, 0xC1, 0x4C, 0x6B, 0xC8, 0x00, 0x4C, 0x8D, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x44, 0x89, 0x7D, 0x00, 0x44, 0x8B, 0xC2, 0x44, 0x89, 0x7D, 0x00, 0x48, 0x8B, 0x15, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xD1, 0x44, 0x89, 0x7D, 0x00, 0x4C, 0x89, 0x4D, 0x00, 0x4B, 0x8D, 0x04, 0x19, 0x4B, 0x8D, 0x0C, 0x19, 0x48, 0x85, 0xD2, 0x74, 0x00 };
    UCHAR pattern5[] = { 0x44, 0x89, 0x44, 0x24, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x00, 0x45, 0x33, 0xC0, 0x49, 0x63, 0xC1, 0x4C, 0x6B, 0xF8, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xE9, 0x44, 0x89, 0x45, 0x00, 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x44, 0x89, 0x45, 0x00, 0x44, 0x89, 0x45, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x00 };
    return FindFunction(pattern, sizeof(pattern), pattern2, sizeof(pattern2), pattern3, sizeof(pattern3), pattern4, sizeof(pattern4), pattern5, sizeof(pattern5));
}
PVOID FindBcpDisplayCriticalStringCentered() {
    UCHAR pattern[] = { 0x44, 0x89, 0x44, 0x24, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xDB, 0x49, 0x63, 0xC1, 0x4C, 0x6B, 0xF8, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x44, 0x89, 0x5D, 0x00, 0x4C, 0x8B, 0xD1, 0x44, 0x89, 0x5D, 0x00, 0x44, 0x89, 0x5D, 0x00, 0x41, 0x8B, 0x4C, 0x3F, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x00 };
    UCHAR pattern2[] = { 0x44, 0x89, 0x44, 0x24, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x33, 0xF6, 0x49, 0x63, 0xC1, 0x4C, 0x6B, 0xF8, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00, 0x89, 0x75, 0x00, 0x4C, 0x8B, 0xE1, 0x89, 0x75, 0x00, 0x89, 0x75, 0x00, 0x43, 0x8B, 0x4C, 0x17, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x00 };
    UCHAR pattern3[] = { 0x44, 0x89, 0x44, 0x24, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x00, 0x49, 0x63, 0xC1, 0x4C, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x6B, 0xF8, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xD1, 0x33, 0xC9, 0x89, 0x4D, 0x00, 0x89, 0x4D, 0x00, 0x89, 0x4D, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x00 };
    return FindFunction(pattern, sizeof(pattern), pattern2, sizeof(pattern2), pattern3, sizeof(pattern3));
}
PVOID FindBgpGxDrawRectangle() {
    UCHAR pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x00, 0x57, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x84, 0x24, 0x00, 0x00, 0x00, 0x00, 0x33, 0xDB, 0x48, 0x8B, 0xFA, 0x4C, 0x8B, 0xD1, 0x48, 0x89, 0x5C, 0x24, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x41, 0x39, 0x42, 0x00, 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00 };
    UCHAR pattern2[] = { 0x48, 0x89, 0x5C, 0x24, 0x00, 0x55, 0x56, 0x57, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x84, 0x24, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xEA, 0x48, 0x8B, 0xD9, 0x33, 0xD2, 0x48, 0x8D, 0x4C, 0x24, 0x00, 0x44, 0x8D, 0x42, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x33, 0xFF, 0x48, 0x89, 0x7C, 0x24, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x33, 0xF6, 0x39, 0x43, 0x00, 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00 };
    UCHAR pattern3[] = { 0x48, 0x89, 0x5C, 0x24, 0x00, 0x55, 0x56, 0x57, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x84, 0x24, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xEA, 0x48, 0x8B, 0xF9, 0x33, 0xD2, 0x48, 0x8D, 0x4C, 0x24, 0x00, 0x44, 0x8D, 0x42, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x33, 0xDB, 0x48, 0x89, 0x5C, 0x24, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x33, 0xF6, 0x39, 0x47, 0x00, 0x74, 0x00 };
    UCHAR pattern4[] = { 0x48, 0x89, 0x5C, 0x24, 0x00, 0x55, 0x56, 0x57, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x84, 0x24, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xEA, 0x48, 0x8B, 0xD9, 0x33, 0xD2, 0x48, 0x8D, 0x4C, 0x24, 0x00, 0x44, 0x8D, 0x42, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x33, 0xFF, 0x48, 0x89, 0x7C, 0x24, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x33, 0xF6, 0x39, 0x43, 0x00, 0x75, 0x00 };
    return FindFunction(pattern, sizeof(pattern), pattern2, sizeof(pattern2), pattern3, sizeof(pattern3), pattern4, sizeof(pattern4));
}
PVOID FindKiSendFreeze() {
    UCHAR pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x00, 0x48, 0x89, 0x6C, 0x24, 0x00, 0x48, 0x89, 0x74, 0x24, 0x00, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x00, 0x4C, 0x8B, 0x51, 0x00, 0x33, 0xFF, 0x8A, 0xDA, 0x4C, 0x8B, 0xC1, 0x4C, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00, 0x41, 0x83, 0xCF, 0x00, 0x8D, 0x77, 0x00, 0x8D, 0x6F, 0x00, 0x44, 0x8B, 0xDF, 0x44, 0x0F, 0xB7, 0xCF };
    UCHAR pattern2[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x00, 0x48, 0x89, 0x68, 0x00, 0x56, 0x57, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x00, 0x33, 0xED, 0x40, 0x8A, 0xF2, 0x89, 0x68, 0x00, 0x48, 0x8B, 0xF9, 0x66, 0x89, 0x68, 0x00, 0x8B, 0xDD, 0x66, 0x89, 0x68, 0x00, 0x89, 0x68, 0x00, 0x44, 0x8D, 0x75, 0x00, 0x48, 0x8B, 0x41, 0x00, 0x48, 0x89, 0x44, 0x24, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x00 };
    UCHAR pattern3[] = { 0x48, 0x89, 0x5C, 0x24, 0x00, 0x48, 0x89, 0x74, 0x24, 0x00, 0x48, 0x89, 0x7C, 0x24, 0x00, 0x55, 0x41, 0x54, 0x41, 0x56, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x00, 0x45, 0x33, 0xF6, 0x40, 0x8A, 0xF2, 0x48, 0x8B, 0xD9, 0x44, 0x89, 0x75, 0x00, 0x66, 0x44, 0x89, 0x75, 0x00, 0x44, 0x89, 0x75, 0x00, 0x41, 0x8D, 0x46, 0x00, 0xF0, 0x0F, 0xC1, 0x05, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xC0, 0x83, 0xF8, 0x00, 0x0F, 0x8F, 0x00, 0x00, 0x00, 0x00 };
    UCHAR pattern4[] = { 0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x08, 0x49, 0x89, 0x6B, 0x10, 0x56, 0x57, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x33, 0xED, 0x40, 0x8A, 0xF2, 0x48, 0x8B, 0xD9 };
    UCHAR pattern5[] = { 0x4C, 0x8B, 0xDC, 0x53, 0x56, 0x57, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x00, 0x33, 0xC0, 0xC7, 0x44, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x00, 0x40, 0x8A, 0xF2, 0x41, 0x89, 0x43, 0x00, 0x48, 0x8B, 0xD9, 0xB8, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x0F, 0xC1, 0x05, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xC0, 0x83, 0xF8, 0x00, 0x0F, 0x8F, 0x00, 0x00, 0x00, 0x00 };
    return FindFunction(pattern, sizeof(pattern), pattern2, sizeof(pattern2), pattern3, sizeof(pattern3), pattern4, sizeof(pattern4), pattern5, sizeof(pattern5));
}
PVOID FindKiSetDebuggerOwner() {
    UCHAR pattern[] = { 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x75, 0x00, 0x48, 0x85, 0xC9, 0x74, 0x00, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x83, 0xF8, 0x01, 0x74, 0x00, 0x48, 0xB8, 0xC6, 0x03, 0x00, 0x00, 0x80, 0xF7, 0xFF, 0xFF, 0x8A, 0x00, 0x84, 0xC0, 0x75, 0x00 };
    return FindFunction(pattern, sizeof(pattern));
}
PVOID FindBcpDisplayErrorInformationModernized() {
    UCHAR pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0xC0, 0x48, 0x81, 0xEC, 0x40, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x45, 0x30, 0x4C, 0x8B, 0xB5, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0x33, 0xFF, 0x4C, 0x63, 0xF9, 0x0F, 0x57, 0xC0, 0x4C, 0x89, 0x75, 0x88, 0x0F, 0x11, 0x44, 0x24, 0x40, 0x48, 0x8D, 0x4C, 0x24, 0x30, 0x44, 0x8B, 0xEA, 0xF2, 0x0F, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00, 0xF2, 0x0F, 0x11, 0x44, 0x24, 0x20, 0x49, 0x8B, 0xF1, 0x0F, 0x57, 0xC0, 0x48, 0x89, 0x7C, 0x24, 0x5C, 0x0F, 0x11, 0x44, 0x24, 0x30, 0x4D, 0x8B, 0xE0, 0x89, 0x7C, 0x24, 0x6C, 0x49, 0x6B, 0xDF, 0x54, 0x89, 0x7C, 0x24, 0x7C, 0x48, 0x03, 0xD8, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x89, 0x44, 0x24, 0x50, 0x89, 0x44, 0x24, 0x28, 0x8D, 0x47, 0x12, 0x66, 0x89, 0x44, 0x24, 0x7A, 0x48, 0x8D, 0x45, 0x90, 0x48, 0x89, 0x45, 0x80, 0xB8, 0x00, 0x04, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x32, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x38, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x0F, 0x88, 0x00, 0x00, 0x00, 0x00 };
    UCHAR pattern2[] = { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0xC0, 0x48, 0x81, 0xEC, 0x40, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x45, 0x30, 0x4C, 0x8B, 0xB5, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0x33, 0xFF, 0x4C, 0x63, 0xF9, 0x0F, 0x57, 0xC0, 0x4C, 0x89, 0x75, 0x88, 0x0F, 0x11, 0x44, 0x24, 0x48, 0x48, 0x8D, 0x4C, 0x24, 0x30, 0x44, 0x8B, 0xEA, 0xF2, 0x0F, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00, 0xF2, 0x0F, 0x11, 0x44, 0x24, 0x20, 0x49, 0x8B, 0xF1, 0x0F, 0x57, 0xC0, 0x48, 0x89, 0x7C, 0x24, 0x5C, 0x0F, 0x11, 0x44, 0x24, 0x30, 0x4D, 0x8B, 0xE0, 0x89, 0x7C, 0x24, 0x6C, 0x49, 0x6B, 0xDF, 0x54, 0x89, 0x7C, 0x24, 0x7C, 0x48, 0x03, 0xD8, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x89, 0x44, 0x24, 0x40, 0x89, 0x44, 0x24, 0x28, 0x8D, 0x47, 0x12, 0x66, 0x89, 0x44, 0x24, 0x7A, 0x48, 0x8D, 0x45, 0x90, 0x48, 0x89, 0x45, 0x80, 0xB8, 0x00, 0x04, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x32, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x38, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x0F, 0x88, 0x00, 0x00, 0x00, 0x00 };
    UCHAR pattern3[] = { 0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0xC8, 0x48, 0x81, 0xEC, 0x38, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x45, 0x20, 0x44, 0x8B, 0x25, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x45, 0x88, 0x4C, 0x8B, 0xAD, 0xA0, 0x00, 0x00, 0x00, 0x0F, 0x57, 0xC0, 0x33, 0xDB, 0x48, 0x89, 0x44, 0x24, 0x78, 0x0F, 0x11, 0x44, 0x24, 0x40, 0xB8, 0x00, 0x04, 0x00, 0x00, 0x44, 0x8B, 0xFA, 0xF2, 0x0F, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00, 0xF2, 0x0F, 0x11, 0x44, 0x24, 0x20, 0x8D, 0x7B, 0x12, 0x0F, 0x57, 0xC0, 0x4C, 0x63, 0xF1, 0x0F, 0x11, 0x44, 0x24, 0x30, 0x66, 0x89, 0x44, 0x24, 0x32, 0x48, 0x8D, 0x4C, 0x24, 0x30, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x49, 0x8B, 0xF1, 0x48, 0x89, 0x44, 0x24, 0x38, 0x4C, 0x89, 0x45, 0x80, 0x48, 0x89, 0x5C, 0x24, 0x54, 0x89, 0x5C, 0x24, 0x64, 0x44, 0x89, 0x64, 0x24, 0x28, 0x89, 0x5C, 0x24, 0x74, 0x66, 0x89, 0x7C, 0x24, 0x72, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x0F, 0x88, 0x00, 0x00, 0x00, 0x00 };
    return FindFunction(pattern, sizeof(pattern), pattern2, sizeof(pattern2), pattern3, sizeof(pattern3));
}
PVOID FindFeatureEnabledBsodRejuvenation() {
    PVOID CmpInstructionAddress = FindKiDisplayBlueScreen();
    if (CmpInstructionAddress == NULL) return NULL;
    ULONG CmpOffset = 0;
    if (winver < WIN_11_24H2_NEW) return NULL;
    if (winver == WIN_11_25H2 || winver == WIN_11_24H2_NEW) CmpOffset = 0x22D;
    else if (winver == WIN_11_26H1) CmpOffset = 0x229;
    else if (winver > WIN_11_26H1) CmpOffset = 0x22E;
    CmpInstructionAddress = (PVOID)((ULONG_PTR)CmpInstructionAddress + CmpOffset);
    PUCHAR code = (PUCHAR)CmpInstructionAddress;
    ULONG_PTR rip = (ULONG_PTR)CmpInstructionAddress;
    UCHAR rex = 0;
    SIZE_T offset = 0;
    UCHAR byte0 = 0;
    __try {
        byte0 = code[0];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    if (byte0 >= 0x40 && byte0 <= 0x4F) {
        rex = byte0;
        offset = 1;
    }
    UCHAR opcode = 0;
    __try {
        opcode = code[offset];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    if (opcode == 0x80) {
        UCHAR modrm = 0;
        UCHAR imm8 = 0;
        __try {
            modrm = code[offset + 1];
            imm8 = code[offset + 6];
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return NULL;
        }
        UCHAR mod = (modrm >> 6) & 0x3;
        UCHAR reg = (modrm >> 3) & 0x7;
        UCHAR rm = modrm & 0x7;
        if (mod != 0 || reg != 7 || rm != 5) return NULL;
        if ((rex & 0x04) != 0) return NULL;
        if (imm8 != 0) return NULL;
        LONG disp32 = 0;
        __try {
            disp32 = *(PLONG)(code + offset + 2);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return NULL;
        }
        return (PVOID)(rip + offset + 7 + disp32);
    }
    if (opcode != 0x38) return NULL;
    UCHAR modrm = 0;
    __try {
        modrm = code[offset + 1];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    UCHAR mod = (modrm >> 6) & 0x3;
    UCHAR reg = (modrm >> 3) & 0x7;
    UCHAR rm = modrm & 0x7;
    UCHAR rexR = (rex >> 2) & 1;
    UCHAR actualReg = (rexR << 3) | reg;
    if (actualReg != 12 && actualReg != 15) return NULL;
    if (mod != 0 || rm != 5) return NULL;
    LONG disp32 = 0;
    __try {
        disp32 = *(PLONG)(code + offset + 2);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    return (PVOID)(rip + offset + 6 + disp32);
}
PVOID FindBcpCursor() {
    PVOID AddInstructionAddress = FindBgpFwDisplayBugCheckScreen();
    if (AddInstructionAddress == NULL) return NULL;
    ULONG AddOffset = 0;
    if (winver == WIN_8) AddOffset = 0xEB;
    else if (winver == WIN_10) AddOffset = 0x139;
    else if (winver == WIN_11_24H2) AddOffset = 0x12B;
    else if (winver == WIN_11_25H2 || winver == WIN_11_24H2_NEW) AddOffset = 0x12A;
    else if (winver == WIN_11_26H1) AddOffset = 0x130;
    else if (winver > WIN_11_26H1) AddOffset = 0x120;
    AddInstructionAddress = (PVOID)((ULONG_PTR)AddInstructionAddress + AddOffset);
    PUCHAR code = (PUCHAR)AddInstructionAddress;
    ULONG_PTR rip = (ULONG_PTR)AddInstructionAddress;
    UCHAR opcode = 0;
    UCHAR modrm = 0;
    LONG  disp32 = 0;
    __try {
        opcode = code[0];
        modrm = code[1];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    if (opcode != 0x03) return NULL;
    UCHAR mod = (modrm >> 6) & 0x3;
    UCHAR reg = (modrm >> 3) & 0x7;
    UCHAR rm = modrm & 0x7;
    if (reg != 1 && reg != 2) return NULL;
    if (mod != 0 || rm != 5) return NULL;
    __try {
        disp32 = *(PLONG)(code + 2);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    SIZE_T instructionLength = 6;
    ULONG_PTR targetAddress = rip + instructionLength + disp32;
    ULONG_PTR bcpCursorBase = targetAddress - 0x8;
    return (PVOID)bcpCursorBase;
}
PVOID FindBgInternal_0xF8()
{
    PVOID InstructionAddress = FindBgpFwDisplayBugCheckScreen();
    if (InstructionAddress == NULL) return NULL;
    ULONG Offset;
    if (winver == WIN_10) Offset = 0x2A7;
    else if (winver == WIN_11_24H2 || winver == WIN_11_26H1) Offset = 0x279;
    else if (winver == WIN_11_25H2 || winver == WIN_11_24H2_NEW) Offset = 0x273;
    else Offset = 0x26D;
    InstructionAddress = (PVOID)((ULONG_PTR)InstructionAddress + Offset);
    PUCHAR code = (PUCHAR)InstructionAddress;
    ULONG_PTR rip = (ULONG_PTR)InstructionAddress;
    UCHAR rex = 0;
    SIZE_T prefixLength = 0;
    UCHAR firstByte = 0;
    __try {
        firstByte = code[0];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    if (firstByte >= 0x40 && firstByte <= 0x4F) {
        rex = firstByte;
        prefixLength = 1;
    }
    UCHAR opcode = 0;
    __try {
        opcode = code[prefixLength];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    if (opcode != 0x8B) return NULL;
    UCHAR modrm = 0;
    __try {
        modrm = code[prefixLength + 1];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    UCHAR mod = (modrm >> 6) & 0x3;
    UCHAR reg = (modrm >> 3) & 0x7;
    UCHAR rm = modrm & 0x7;
    UCHAR rexR = (rex >> 2) & 1;
    UCHAR actualReg = (rexR << 3) | reg;
    if (actualReg != 1) return NULL;
    if (mod != 0 || rm != 5) return NULL;
    if (((rex >> 3) & 1) != 1) return NULL;
    LONG disp32 = 0;
    __try {
        disp32 = *(PLONG)(code + prefixLength + 2);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return NULL;
    }
    SIZE_T instructionLength = prefixLength + 6;
    ULONG_PTR targetAddress = rip + instructionLength + disp32;
    return (PVOID)targetAddress;
}
PVOID FindKeActiveProcessors()
{
    PVOID InstructionAddress = FindKeBugCheck2();
    if (InstructionAddress == NULL) return NULL;
    ULONG InstructionOffset = 0;
    if (winver == WIN_8) InstructionOffset = 0x8E6;
    else if (winver == WIN_10) InstructionOffset = 0x9D4;
    else if (winver >= WIN_11_24H2 && winver <= WIN_11_25H2) InstructionOffset = 0xD1F;
    else if (winver == WIN_11_26H1) InstructionOffset = 0xCA8;
    else if (winver == WIN_11_27H2) InstructionOffset = 0xC7D;
    InstructionAddress = (PVOID)((ULONG_PTR)InstructionAddress + InstructionOffset);
    PUCHAR code = (PUCHAR)InstructionAddress;
    ULONG_PTR rip = (ULONG_PTR)InstructionAddress;
    UCHAR first = 0;
    __try {
        first = code[0];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    SIZE_T prefix = 0;
    UCHAR rex = 0;
    if (first >= 0x40 && first <= 0x4F) {
        rex = first;
        prefix = 1;
    }
    UCHAR op1 = 0;
    UCHAR op2 = 0;
    UCHAR modrm = 0;
    SIZE_T dispOffset = 0;
    SIZE_T instrLen = 0;
    int isMovzx = 0;
    __try {
        op1 = code[prefix];
        if (op1 == 0x8D) {
            modrm = code[prefix + 1];
            dispOffset = prefix + 2;
            instrLen = prefix + 6;
            isMovzx = 0;
        }
        else if (op1 == 0x0F) {
            op2 = code[prefix + 1];
            if (op2 != 0xB7) return NULL;
            modrm = code[prefix + 2];
            dispOffset = prefix + 3;
            instrLen = prefix + 7;
            isMovzx = 1;
        }
        else {
            return NULL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    UCHAR mod = (modrm >> 6) & 0x3;
    UCHAR reg = (modrm >> 3) & 0x7;
    UCHAR rm = modrm & 0x7;
    UCHAR rexR = (rex >> 2) & 1;
    UCHAR actualReg = (rexR << 3) | reg;
    if (mod != 0 || rm != 5) return NULL;
    if (isMovzx) {
        if (actualReg != 1) return NULL;
    }
    else {
        if (actualReg != 2 && actualReg != 8) return NULL;
    }
    LONG disp32 = 0;
    __try {
        disp32 = *(PLONG)(code + dispOffset);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    ULONG_PTR targetAddress = rip + instrLen + disp32;
    return (PVOID)targetAddress;
}
PVOID FindKiBugCheckDriver() {
    PVOID InstructionAddress = FindKiDisplayBlueScreen();
    if (InstructionAddress == NULL) return NULL;
    ULONG Offset = 0;
    if (winver == WIN_7) Offset = 0xC6;
    else if (winver == WIN_8) Offset = 0x96;
    else if (winver == WIN_10) Offset = 0xE3;
    else if (winver >= WIN_11_24H2 && winver <= WIN_11_25H2) Offset = 0xC0;
    else if (winver == WIN_11_26H1) Offset = 0xBC;
    else if (winver == WIN_11_27H2) Offset = 0xBE;
    else return NULL;
    InstructionAddress = (PVOID)((ULONG_PTR)InstructionAddress + Offset);
    PUCHAR code = (PUCHAR)InstructionAddress;
    ULONG_PTR rip = (ULONG_PTR)InstructionAddress;
    UCHAR first = 0;
    __try {
        first = code[0];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    SIZE_T prefix = 0;
    UCHAR rex = 0;
    if (first >= 0x40 && first <= 0x4F) { rex = first; prefix = 1; }
    UCHAR opcode = 0;
    UCHAR modrm = 0;
    __try {
        opcode = code[prefix]; modrm = code[prefix + 1];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    UCHAR mod = (modrm >> 6) & 0x3;
    UCHAR reg = (modrm >> 3) & 0x7;
    UCHAR rm = modrm & 0x7;
    UCHAR rexR = (rex >> 2) & 1;
    UCHAR actualReg = (rexR << 3) | reg;
    if (mod != 0 || rm != 5) return NULL;
    LONG disp32 = 0;
    SIZE_T dispOffset = 0;
    SIZE_T instructionLength = 0;
    if (opcode == 0x83) {
        if (actualReg != 7) return NULL;
        dispOffset = prefix + 2;
        instructionLength = prefix + 7;
    }
    else if (opcode == 0x8B) {
        if (actualReg != 3) return NULL;
        dispOffset = prefix + 2;
        instructionLength = prefix + 6;
    }
    else return NULL;
    __try { disp32 = *(PLONG)(code + dispOffset); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return NULL; }
    ULONG_PTR targetAddress = rip + instructionLength + disp32;
    return (PVOID)targetAddress;
}
ULONG_PTR Freeze(ULONG_PTR) {
    UCHAR freeze[] = { 0xFA, 0xEB, 0xFE, 0xEB, 0xFB };
    PVOID execMem = ExAllocatePool(NonPagedPoolExecute, 5);
    RtlCopyMemory(execMem, freeze, 5);
    ((void(*)())execMem)();
    return 0;
}
ULONG_PTR Disable(ULONG_PTR) {
    _disable();
    __writecr8(HIGH_LEVEL);
    UCHAR hlt[] = { 0xFA, 0xF4, 0xEB, 0xFA, 0xC3 };
    WriteMemory(KeBugCheckEx, hlt, 7);
    return 0;
}
VOID PauseCPU() {
    if (Paused) return;
    _disable();
    __writecr8(HIGH_LEVEL);
    ((VOID(*)(LONGLONG))FindKiSetDebuggerOwner())((LONGLONG)KeGetPcr()->CurrentPrcb);
    UCHAR affinity[sizeof(KAFFINITY_EX) + 8];
    RtlZeroMemory(affinity, sizeof(KAFFINITY_EX));
    PVOID KeActiveProcessors = FindKeActiveProcessors();
    KeCopyAffinityEx(affinity, (USHORT*)KeActiveProcessors);
    KeRemoveProcessorAffinityEx(affinity, KeGetCurrentProcessorNumberEx(NULL));
    KeIpiGenericCall(Disable, 0);
    ((VOID(*)(UCHAR*, CHAR))FindKiSendFreeze())(affinity, 0);
    KeStallExecutionProcessor(1000000);
    InbvAcquireDisplayOwnership();
    Paused = TRUE;
}
PVOID AllocateExecutableMemory(SIZE_T Size) {
    PVOID buffer = ExAllocatePoolWithTag(NonPagedPoolExecute, Size, 'pmrT');
    return buffer;
}
VOID UninstallKeGetBugMessageTextHook()
{
    if (!g_KeGetBugMessageTextHookInfo.Installed) return;
    KIRQL oldIrql;
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    if (!NT_SUCCESS(WriteMemory(g_KeGetBugMessageTextHookInfo.TargetAddress, g_KeGetBugMessageTextHookInfo.OriginalCode, g_KeGetBugMessageTextHookInfo.PatchSize))) { LogPrintf(77, 0, "UninstallKeGetBugMessageTextHook Failed!\n"); return; }
    KeLowerIrql(oldIrql);
    ExFreePoolWithTag(g_KeGetBugMessageTextHookInfo.Trampoline, 'pmrT');
    ExFreePoolWithTag(g_KeGetBugMessageTextHookInfo.OriginalCode, 'OgnS');
    if (g_KeGetBugMessageTextHookInfo.Variable) {
        UNICODE_STRING str = {};
        str.Buffer = (PWCHAR)g_KeGetBugMessageTextHookInfo.Variable;
        RtlFreeUnicodeString(&str);
    }
    RtlZeroMemory(&g_KeGetBugMessageTextHookInfo, sizeof(g_KeGetBugMessageTextHookInfo));
    g_KeGetBugMessageTextHookInfo.Installed = FALSE;
    LogPrintf(77, 0, "UninstallKeGetBugMessageTextHook Succeeded!\n");
}
NTSTATUS InstallKeGetBugMessageTextHook(PVOID TargetFunction, PWCHAR NewString, SIZE_T CharCount)
{
    if (!TargetFunction || !NewString || CharCount < 1) return STATUS_INVALID_PARAMETER;
    if (CharCount * sizeof(WCHAR) > 0xFFFF) return STATUS_INVALID_PARAMETER;
    if (g_KeGetBugMessageTextHookInfo.Installed) { UninstallKeGetBugMessageTextHook(); if (g_KeGetBugMessageTextHookInfo.Installed) return STATUS_UNSUCCESSFUL; return InstallKeGetBugMessageTextHook(TargetFunction, NewString, CharCount); }
    g_KeGetBugMessageTextHookInfo.Variable = NewString;
    BOOLEAN isWin11_27H2 = winver > WIN_11_26H1;
    WORD byteLen = (WORD)(CharCount * sizeof(WCHAR));
    WORD byteMaxLen = byteLen + sizeof(WCHAR);
    ULONG hookOffset = isWin11_27H2 ? 0x8C : ((winver == WIN_8) ? 0x84 : 0x90);
    ULONG returnOffset = isWin11_27H2 ? 0x9C : ((winver == WIN_8) ? 0x94 : 0xA2);
    ULONG patchSize = isWin11_27H2 ? 16 : ((winver == WIN_8) ? 16 : 18);
    ULONG origSize = patchSize;
    ULONG segD_len = 4;
    ULONG segH_off = (winver == WIN_8) ? 9 : 9;
    ULONG segH_len = (winver == WIN_8) ? 3 : 4;
    ULONG segI_off = (winver == WIN_8) ? 12 : 13;
    ULONG segI_len = (winver == WIN_8) ? 4 : 5;
    PUCHAR hookPoint = (PUCHAR)TargetFunction + hookOffset;
    PUCHAR returnPoint = (PUCHAR)TargetFunction + returnOffset;
    UCHAR original[18];
    RtlZeroMemory(original, sizeof(original));
    NTSTATUS status = ReadMemory(hookPoint, original, origSize);
    if (!NT_SUCCESS(status)) return status;
    SIZE_T strBytes = CharCount * sizeof(WCHAR);
    SIZE_T alignedBytes = (strBytes + 7) & ~7ull;
    PWCHAR strBuf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPoolExecute, alignedBytes, 'grtS');
    if (!strBuf) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(strBuf, alignedBytes);
    RtlCopyMemory(strBuf, NewString, strBytes);
    const SIZE_T fixedSize = isWin11_27H2 ? 52 : 54;
    SIZE_T trampSize = fixedSize + alignedBytes;
    PUCHAR tramp = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolExecute, trampSize, 'pmrT');
    if (!tramp) {
        LogPrintf(77, 0, "ExAllocatePoolWithTag_1 (in InstallKeGetBugMessageTextHook) Failed!\n");
        ExFreePoolWithTag(strBuf, 'grtS');
        FreePwchar(NewString);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(tramp, trampSize);
    PUCHAR origCopy = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, origSize, 'OgnS');
    if (!origCopy) {
        LogPrintf(77, 0, "ExAllocatePoolWithTag_2 (in InstallKeGetBugMessageTextHook) Failed!\n");
        ExFreePoolWithTag(tramp, 'pmrT');
        ExFreePoolWithTag(strBuf, 'grtS');
        FreePwchar(NewString);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(origCopy, original, origSize);
    PUCHAR p = tramp;
    ULONG64 strDataAddr = (ULONG64)(tramp + fixedSize);
    if (isWin11_27H2) {
        p[0] = 0x51;
        p += 1;
        p[0] = 0x48;
        p[1] = 0xB9;
        *(ULONG64*)(p + 2) = strDataAddr;
        p += 10;
        RtlCopyMemory(p, original, 4);
        p += 4;
        p[0] = 0x59;
        p += 1;
        *p = 0x50;
        p += 1;
        p[0] = 0x66; p[1] = 0xB8;
        *(WORD*)(p + 2) = byteLen;
        p += 4;
        RtlCopyMemory(p, original + 4, 4);
        p += 4;
        p[0] = 0x66; p[1] = 0xB8;
        *(WORD*)(p + 2) = byteMaxLen;
        p += 4;
        RtlCopyMemory(p, original + 8, 5);
        p += 5;
        *p = 0x58;
        p += 1;
        RtlCopyMemory(p, original + 13, 3);
        p += 3;
    }
    else {
        RtlCopyMemory(p, original + 0, 5);
        p += 5;
        if (winver == WIN_8) {
            p[0] = 0x41;
            p[1] = 0x50;
            p += 2;
        }
        else {
            p[0] = 0x51;
            p += 1;
        }
        if (winver == WIN_8) {
            p[0] = 0x49;
            p[1] = 0xB8;
        }
        else {
            p[0] = 0x48;
            p[1] = 0xB9;
        }
        *(ULONG64*)(p + 2) = strDataAddr;
        p += 10;
        RtlCopyMemory(p, original + 5, segD_len);
        p += segD_len;
        if (winver == WIN_8) {
            p[0] = 0x41; p[1] = 0x58;
            p += 2;
        }
        else {
            p[0] = 0x59;
            p += 1;
        }
        *p = 0x50;
        p += 1;
        p[0] = 0x66; p[1] = 0xB8;
        *(WORD*)(p + 2) = byteLen;
        p += 4;
        RtlCopyMemory(p, original + segH_off, segH_len);
        p += segH_len;
        p[0] = 0x66; p[1] = 0xB8;
        *(WORD*)(p + 2) = byteMaxLen;
        p += 4;
        RtlCopyMemory(p, original + segI_off, segI_len);
        p += segI_len;
        *p = 0x58;
        p += 1;
    }
    ULONG64 retAddr = (ULONG64)returnPoint;
    p[0] = 0x68;
    *(ULONG*)(p + 1) = (ULONG)(retAddr & 0xFFFFFFFF);
    p[5] = 0xC7;
    p[6] = 0x44;
    p[7] = 0x24;
    p[8] = 0x04;
    *(ULONG*)(p + 9) = (ULONG)(retAddr >> 32);
    p[13] = 0xC3;
    p += 14;
    RtlCopyMemory(p, strBuf, alignedBytes);
    UCHAR patch[18];
    RtlZeroMemory(patch, 18);
    ULONG64 trampAddr = (ULONG64)tramp;
    patch[0] = 0x68;
    *(ULONG*)(patch + 1) = (ULONG)(trampAddr & 0xFFFFFFFF);
    patch[5] = 0xC7;
    patch[6] = 0x44;
    patch[7] = 0x24;
    patch[8] = 0x04;
    *(ULONG*)(patch + 9) = (ULONG)(trampAddr >> 32);
    patch[13] = 0xC3;
    patch[14] = 0x90;
    patch[15] = 0x90;
    patch[16] = 0x90;
    patch[17] = 0x90;
    status = WriteMemory(hookPoint, patch, patchSize);
    if (!NT_SUCCESS(status)) {
        LogPrintf(77, 0, "WriteMemory (in InstallKeGetBugMessageTextHook) Failed!\n");
        ExFreePoolWithTag(tramp, 'pmrT');
        ExFreePoolWithTag(strBuf, 'grtS');
        ExFreePoolWithTag(origCopy, 'OgnS');
        FreePwchar(NewString);
        return status;
    }
    g_KeGetBugMessageTextHookInfo.TargetAddress = hookPoint;
    g_KeGetBugMessageTextHookInfo.OriginalCode = origCopy;
    g_KeGetBugMessageTextHookInfo.PatchSize = origSize;
    g_KeGetBugMessageTextHookInfo.Trampoline = tramp;
    g_KeGetBugMessageTextHookInfo.Installed = TRUE;
    KeMemoryBarrier();
    ExFreePoolWithTag(strBuf, 'grtS');
    LogPrintf(77, 0, "InstallKeGetBugMessageTextHook Succeeded!\n");
    return STATUS_SUCCESS;
}
VOID UninstallBgpClearScreenHook()
{
    if (!g_BgpClearScreenHookInfo.Installed) return;
    KIRQL oldIrql;
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    if (!NT_SUCCESS(WriteMemory(g_BgpClearScreenHookInfo.TargetAddress, g_BgpClearScreenHookInfo.OriginalCode, g_BgpClearScreenHookInfo.PatchSize))) { LogPrintf(77, 0, "UninstallBgpClearScreenHook Failed!\n"); return; }
    KeLowerIrql(oldIrql);
    ExFreePoolWithTag(g_BgpClearScreenHookInfo.Trampoline, 'pCgB');
    ExFreePoolWithTag(g_BgpClearScreenHookInfo.OriginalCode, 'OgnC');
    RtlZeroMemory(&g_BgpClearScreenHookInfo, sizeof(g_BgpClearScreenHookInfo));
    g_BgpClearScreenHookInfo.Installed = FALSE;
    g_color = NULL;
    LogPrintf(77, 0, "UninstallBgpClearScreenHook Succeeded!\n");
}
NTSTATUS InstallBgpClearScreenHook(PVOID BgpClearScreenAddr, ULONG64 color)
{
    if (!BgpClearScreenAddr) return STATUS_INVALID_PARAMETER;
    if (g_BgpClearScreenHookInfo.Installed) { UninstallBgpClearScreenHook(); if (g_BgpClearScreenHookInfo.Installed) return STATUS_UNSUCCESSFUL; return InstallBgpClearScreenHook(BgpClearScreenAddr, color); }
    ULONG patchSize = winver > WIN_11_26H1 ? 18u : 15u;
    PUCHAR tramp = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolExecute, 64u, 'pCgB');
    if (!tramp) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(tramp, 64u);
    PUCHAR origCopy = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, patchSize, 'OgnC');
    if (!origCopy) {
        LogPrintf(77, 0, "ExAllocatePoolWithTag (in InstallBgpClearScreenHook) Failed!\n");
        ExFreePoolWithTag(tramp, 'pCgB');
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ReadMemory(BgpClearScreenAddr, origCopy, patchSize);
    PUCHAR p = tramp;
    RtlCopyMemory(p, BgpClearScreenAddr, patchSize);
    p += patchSize;
    p[0] = 0x48;
    p[1] = 0xB9;
    g_color = p + 2;
    *(ULONG64*)(p + 2) = color;
    p += 10;
    ULONG64 retAddr = (ULONG64)((PUCHAR)BgpClearScreenAddr + patchSize);
    p[0] = 0x48;
    p[1] = 0xB8;
    *(ULONG64*)(p + 2) = retAddr;
    p += 10;
    p[0] = 0xFF;
    p[1] = 0xE0;
    p += 2;
    UCHAR patch[18];
    RtlFillMemory(patch, sizeof(patch), 0x90);
    ULONG64 trampAddr = (ULONG64)tramp;
    patch[0] = 0x48;
    patch[1] = 0xB8;
    *(ULONG64*)(patch + 2) = trampAddr;
    patch[10] = 0xFF;
    patch[11] = 0xE0;
    NTSTATUS status = WriteMemory(BgpClearScreenAddr, patch, patchSize);
    if (!NT_SUCCESS(status)) {
        LogPrintf(77, 0, "WriteMemory (in InstallBgpClearScreenHook) Failed!\n");
        ExFreePoolWithTag(tramp, 'pCgB');
        ExFreePoolWithTag(origCopy, 'OgnC');
        return status;
    }
    g_BgpClearScreenHookInfo.TargetAddress = BgpClearScreenAddr;
    g_BgpClearScreenHookInfo.OriginalCode = origCopy;
    g_BgpClearScreenHookInfo.PatchSize = patchSize;
    g_BgpClearScreenHookInfo.Trampoline = tramp;
    g_BgpClearScreenHookInfo.Installed = TRUE;
    KeMemoryBarrier();
    LogPrintf(77, 0, "InstallBgpClearScreenHook Succeeded!\n");
    return STATUS_SUCCESS;
}
VOID UninstallBgpTxtDisplayCharacterHook()
{
    if (!g_BgpTxtDisplayCharacterHookInfo.Installed) return;
    KIRQL oldIrql;
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    if (!NT_SUCCESS(WriteMemory(g_BgpTxtDisplayCharacterHookInfo.TargetAddress, g_BgpTxtDisplayCharacterHookInfo.OriginalCode, g_BgpTxtDisplayCharacterHookInfo.PatchSize))) { LogPrintf(77, 0, "UninstallBgpTxtDisplayCharacterHook Failed!\n"); return; }
    KeLowerIrql(oldIrql);
    ExFreePoolWithTag(g_BgpTxtDisplayCharacterHookInfo.Trampoline, 'cDgB');
    ExFreePoolWithTag(g_BgpTxtDisplayCharacterHookInfo.OriginalCode, 'OgnT');
    RtlZeroMemory(&g_BgpTxtDisplayCharacterHookInfo, sizeof(g_BgpTxtDisplayCharacterHookInfo));
    g_BgpTxtDisplayCharacterHookInfo.Installed = FALSE;
    g_tbcolor = NULL;
    g_tfcolor = NULL;
    LogPrintf(77, 0, "UninstallBgpTxtDisplayCharacterHook Succeeded!\n");
}
NTSTATUS InstallBgpTxtDisplayCharacterHook(PVOID BgpTxtDisplayCharacterAddr, ULONG backColor, ULONG foreColor)
{
    if (!BgpTxtDisplayCharacterAddr) return STATUS_INVALID_PARAMETER;
    if (g_BgpTxtDisplayCharacterHookInfo.Installed) { UninstallBgpTxtDisplayCharacterHook(); if (g_BgpTxtDisplayCharacterHookInfo.Installed) return STATUS_UNSUCCESSFUL; return InstallBgpTxtDisplayCharacterHook(BgpTxtDisplayCharacterAddr, backColor, foreColor); }
    BOOLEAN isWin11_27H2 = winver > WIN_11_26H1;
    BOOLEAN is4cmd = winver == WIN_8 || (winver > WIN_10 && winver <= WIN_11_26H1);
    ULONG patchSize;
    ULONG originalInstrSize;
    PUCHAR tramp = NULL;
    if (is4cmd) {
        patchSize = 15;
        originalInstrSize = 15;
    }
    else {
        patchSize = 19;
        originalInstrSize = 19;
    }
    tramp = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolExecute, 64u, 'cDgB');
    if (!tramp) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(tramp, 64u);
    PUCHAR origCopy = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, patchSize, 'OgnT');
    if (!origCopy) {
        LogPrintf(77, 0, "ExAllocatePoolWithTag (in InstallBgpTxtDisplayCharacterHook) Failed!\n");
        ExFreePoolWithTag(tramp, 'cDgB');
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ReadMemory(BgpTxtDisplayCharacterAddr, origCopy, patchSize);
    PUCHAR p = tramp;
    p[0] = 0x41; p[1] = 0xBA;
    g_tbcolor = (ULONG*)((PUCHAR)tramp + 2);
    *(ULONG*)(p + 2) = backColor;
    p += 6;
    p[0] = 0x44; p[1] = 0x89; p[2] = 0x51; p[3] = 0x28;
    p += 4;
    p[0] = 0x41; p[1] = 0xBA;
    g_tfcolor = (ULONG*)((PUCHAR)tramp + 12);
    *(ULONG*)(p + 2) = foreColor;
    p += 6;
    p[0] = 0x44; p[1] = 0x89; p[2] = 0x51; p[3] = 0x2C;
    p += 4;
    if (isWin11_27H2) {
        RtlCopyMemory(p, origCopy, originalInstrSize);
        p += originalInstrSize;
    }
    else if (is4cmd) {
        p[0] = 0x48; p[1] = 0x8B; p[2] = 0xC4;
        p += 3;
        p[0] = 0x4C; p[1] = 0x89; p[2] = 0x48; p[3] = 0x20;
        p += 4;
        p[0] = 0x44; p[1] = 0x89; p[2] = 0x40; p[3] = 0x18;
        p += 4;
        p[0] = 0x66; p[1] = 0x89; p[2] = 0x50; p[3] = 0x10;
        p += 4;
    }
    else {
        p[0] = 0x48; p[1] = 0x8B; p[2] = 0xC4;
        p += 3;
        p[0] = 0x4C; p[1] = 0x89; p[2] = 0x48; p[3] = 0x20;
        p += 4;
        p[0] = 0x44; p[1] = 0x89; p[2] = 0x40; p[3] = 0x18;
        p += 4;
        p[0] = 0x66; p[1] = 0x89; p[2] = 0x50; p[3] = 0x10;
        p += 4;
        p[0] = 0x48; p[1] = 0x89; p[2] = 0x48; p[3] = 0x08;
        p += 4;
    }
    ULONG64 retAddr = (ULONG64)((PUCHAR)BgpTxtDisplayCharacterAddr + originalInstrSize);
    p[0] = 0x49; p[1] = 0xBA;
    *(ULONG64*)(p + 2) = retAddr;
    p += 10;
    p[0] = 0x41; p[1] = 0xFF; p[2] = 0xE2;
    p += 3;
    UCHAR patch[19];
    RtlZeroMemory(patch, sizeof(patch));
    ULONG64 trampAddr = (ULONG64)tramp;
    patch[0] = 0x49; patch[1] = 0xBA;
    *(ULONG64*)(patch + 2) = trampAddr;
    patch[10] = 0x41; patch[11] = 0xFF; patch[12] = 0xE2;
    for (ULONG i = 13; i < patchSize; i++) patch[i] = 0x90;
    NTSTATUS status = WriteMemory(BgpTxtDisplayCharacterAddr, patch, patchSize);
    if (!NT_SUCCESS(status))
    {
        LogPrintf(77, 0, "WriteMemory (in InstallBgpTxtDisplayCharacterHook) Failed!\n");
        ExFreePoolWithTag(tramp, 'cDgB');
        ExFreePoolWithTag(origCopy, 'OgnT');
        return status;
    }
    g_BgpTxtDisplayCharacterHookInfo.TargetAddress = BgpTxtDisplayCharacterAddr;
    g_BgpTxtDisplayCharacterHookInfo.OriginalCode = origCopy;
    g_BgpTxtDisplayCharacterHookInfo.PatchSize = patchSize;
    g_BgpTxtDisplayCharacterHookInfo.Trampoline = tramp;
    g_BgpTxtDisplayCharacterHookInfo.Installed = TRUE;
    KeMemoryBarrier();
    LogPrintf(77, 0, "InstallBgpTxtDisplayCharacterHook Succeeded!\n");
    return STATUS_SUCCESS;
}
VOID UninstallBcpDisplayCriticalStringHook()
{
    if (!g_BcpDisplayCriticalStringHookInfo.Installed) return;
    if (!g_BcpDisplayCriticalStringHookInfo.TargetAddress || !g_BcpDisplayCriticalStringHookInfo.OriginalCode || !g_BcpDisplayCriticalStringHookInfo.Trampoline) { LogPrintf(77, 0, "UninstallBcpDisplayCriticalStringHook Failed!\n"); return; }
    if (!NT_SUCCESS(WriteMemory(g_BcpDisplayCriticalStringHookInfo.TargetAddress, g_BcpDisplayCriticalStringHookInfo.OriginalCode, g_BcpDisplayCriticalStringHookInfo.PatchSize))) { LogPrintf(77, 0, "UninstallBcpDisplayCriticalStringHook Failed!\n"); return; }
    KeMemoryBarrier();
    if (g_BcpDisplayCriticalStringHookInfo.Variable) ExFreePoolWithTag(g_BcpDisplayCriticalStringHookInfo.Variable, 'cTxB');
    ExFreePoolWithTag(g_BcpDisplayCriticalStringHookInfo.Trampoline, 0);
    ExFreePoolWithTag(g_BcpDisplayCriticalStringHookInfo.OriginalCode, 'OgnB');
    RtlZeroMemory(&g_BcpDisplayCriticalStringHookInfo, sizeof(g_BcpDisplayCriticalStringHookInfo));
    InstalledBlock = NULL;
    LogPrintf(77, 0, "UninstallBcpDisplayCriticalStringHook Succeeded!\n");
}
NTSTATUS InstallBcpDisplayCriticalStringHook(PVOID BcpDisplayCriticalStringAddr, ULONG Mode, PWSTR Buffer, PWSTR* Buffers) {
    UCHAR ExpectedBytesWin8[20] = { 0x44, 0x89, 0x44, 0x24, 0x18, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC };
    UCHAR ExpectedBytesWin10[16] = { 0x44, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54 };
    UCHAR ExpectedBytesWin11[25] = { 0x44, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC };
    UCHAR ExpectedBytesWin11_New[27] = { 0x44, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0xE1 };
    const ULONG MaxBuffers = 1024;
    const SIZE_T CodeCapacity = (Mode & 6) == 6 ? 1536 : 1024;
    ULONG FillMode;
    BOOLEAN SkipPercent;
    ULONG SkipAfter = 0;
    ULONG SkipCount = 0;
    PWSTR Metadata;
    PWSTR OriginalBuffer = Buffer;
    PWSTR* OriginalBuffers = Buffers;
    ULONG New = 0;
    ULONG PatchSize;
    PUCHAR ExpectedBytes;
    SIZE_T ExpectedBytesSize;
    ULONG BufferCount;
    ULONG StringCount = 0;
    ULONG Index;
    PWSTR CurrentBuffer;
    SIZE_T CounterOffset;
    SIZE_T TableOffset;
    SIZE_T AllocationSize;
    SIZE_T totalStringBytes;
    PUCHAR Block;
    PUCHAR Cursor;
    PUCHAR CodeEnd;
    PUCHAR stringDataPtr;
    volatile ULONG64* Counter;
    PUCHAR FixedCache = NULL;
    PNTUNICODE_STRING StringTable;
    PUCHAR origCopy;
    UCHAR Patch[27];
    ULONG64 Value64;
    NTSTATUS Status;
    LONG_PTR Offset;
    LONG Relative32;
    PUCHAR JumpNullString = NULL;
    PUCHAR JumpEmptyString = NULL;
    PUCHAR JumpNullBuffer = NULL;
    PUCHAR JumpPercent = NULL;
    PUCHAR JumpBeforeSkip = NULL;
    PUCHAR JumpSkipOriginal = NULL;
    PUCHAR JumpHaveReplacement = NULL;
    PUCHAR JumpNoReplacement = NULL;
    PUCHAR JumpModuloDone = NULL;
    PUCHAR JumpExhausted = NULL;
    PUCHAR ReplacementIndex = NULL;
    PUCHAR ModuloDone = NULL;
    PUCHAR HaveReplacement = NULL;
    PUCHAR LastReplacement = NULL;
    PUCHAR UseReplacement = NULL;
    PUCHAR ContinueOriginal = NULL;
    PUCHAR OriginalCode = NULL;
    ULONG HashCount = 0;
    ULONG HashMask = 0;
    ULONG SlotDisp = 0;
    SIZE_T SpaceOffset;
    PNTUNICODE_STRING SpaceText;
    PUCHAR ChunkTop = NULL;
    PUCHAR TailTop = NULL;
    PUCHAR HashDoneTop = NULL;
    PUCHAR ProbeTop = NULL;
    PUCHAR EmptyTop = NULL;
    PUCHAR HitTop = NULL;
    PUCHAR RetTop = NULL;
    PUCHAR SpaceTop = NULL;
    PUCHAR JumpNullText = NULL;
    PUCHAR JumpOddText = NULL;
    PUCHAR JumpLongText = NULL;
    PUCHAR JumpBlankText = NULL;
    PUCHAR JumpPercentHead = NULL;
    PUCHAR JumpPercentTail = NULL;
    PUCHAR JumpTail = NULL;
    PUCHAR JumpHashDone = NULL;
    PUCHAR JumpTailStep = NULL;
    PUCHAR JumpEmptySlot = NULL;
    PUCHAR JumpHitSlot = NULL;
    PUCHAR JumpProbe = NULL;
    PUCHAR JumpChunk = NULL;
    PUCHAR JumpSlotFull = NULL;
    PUCHAR JumpRetOrig = NULL;
    PUCHAR JumpSpaceOrig = NULL;
    FillMode = Mode & 6;
    if ((Mode & ~7) != 0) return STATUS_INVALID_PARAMETER;
    if (!BcpDisplayCriticalStringAddr || !Buffer) return STATUS_INVALID_PARAMETER;
    if (Buffer[0] == 0x1F && Buffer[1] == L'C' && Buffer[2] == L'T' && Buffer[3] == L':') {
        if (!Buffers || !Buffers[0]) return STATUS_INVALID_PARAMETER;
        Metadata = Buffer + 4;
        if (*Metadata < L'0' || *Metadata > L'9') return STATUS_INVALID_PARAMETER;
        while (*Metadata >= L'0' && *Metadata <= L'9') {
            SkipAfter = SkipAfter * 10 + (ULONG)(*Metadata++ - L'0');
            if (SkipAfter > MaxBuffers) return STATUS_INVALID_PARAMETER;
        }
        if (*Metadata != L':') return STATUS_INVALID_PARAMETER;
        ++Metadata;
        if (*Metadata < L'0' || *Metadata > L'9') return STATUS_INVALID_PARAMETER;
        while (*Metadata >= L'0' && *Metadata <= L'9') {
            SkipCount = SkipCount * 10 + (ULONG)(*Metadata++ - L'0');
            if (SkipCount > MaxBuffers) return STATUS_INVALID_PARAMETER;
        }
        if (*Metadata || !SkipAfter || !SkipCount) return STATUS_INVALID_PARAMETER;
        Buffer = Buffers[0];
        ++Buffers;
    }
    SkipPercent = (BOOLEAN)((Mode & 1) != 0);
    ReadMemory(FindFeatureEnabledBsodRejuvenation(), &New, sizeof(New));
    if (New == 1 && BcpDisplayCriticalStringAddr == g_BcpDisplayCriticalString) return STATUS_INVALID_PARAMETER_1;
    if (winver == WIN_8) {
        ExpectedBytes = ExpectedBytesWin8;
        ExpectedBytesSize = sizeof(ExpectedBytesWin8);
        PatchSize = 20;
    }
    else if (winver > WIN_10 && winver <= WIN_11_24H2) {
        ExpectedBytes = ExpectedBytesWin11;
        ExpectedBytesSize = sizeof(ExpectedBytesWin11);
        PatchSize = 25;
    }
    else if (winver >= WIN_11_25H2 && winver <= WIN_11_26H1) {
        ExpectedBytes = ExpectedBytesWin11_New;
        ExpectedBytesSize = sizeof(ExpectedBytesWin11_New);
        PatchSize = 27;
    }
    else if (winver > WIN_11_26H1) {
        ExpectedBytes = ExpectedBytesWin11;
        ExpectedBytesSize = sizeof(ExpectedBytesWin11);
        PatchSize = 25;
    }
    else {
        ExpectedBytes = ExpectedBytesWin10;
        ExpectedBytesSize = sizeof(ExpectedBytesWin10);
        PatchSize = 16;
    }
    if (InstalledBlock) {
        UninstallBcpDisplayCriticalStringHook();
        if (InstallBcpDisplayCriticalStringHook(g_BcpDisplayCriticalString, Mode, OriginalBuffer, OriginalBuffers) == STATUS_INVALID_PARAMETER_1) Status = InstallBcpDisplayCriticalStringHook(g_BcpDisplayCriticalStringCentered, Mode, OriginalBuffer, OriginalBuffers);
        return Status;
    }
    if (RtlCompareMemory(BcpDisplayCriticalStringAddr, ExpectedBytes, ExpectedBytesSize) != ExpectedBytesSize) return STATUS_NOT_SUPPORTED;
    BufferCount = 1;
    for (Index = 0; Buffers && Buffers[Index]; ++Index) {
        if (BufferCount == MaxBuffers) return STATUS_BUFFER_OVERFLOW;
        ++BufferCount;
    }
    totalStringBytes = 0;
    for (Index = 0; Index < BufferCount; ++Index) {
        SIZE_T charCount = 0;
        CurrentBuffer = (Index == 0) ? Buffer : Buffers[Index - 1];
        if (!CurrentBuffer) return STATUS_INVALID_PARAMETER;
        while (charCount <= 0x7FFF && CurrentBuffer[charCount] != L'\0') ++charCount;
        if (charCount > 0x7FFF) return STATUS_NAME_TOO_LONG;
        totalStringBytes += charCount * sizeof(WCHAR) + sizeof(WCHAR);
    }
    CounterOffset = (CodeCapacity + sizeof(ULONG64) - 1) & ~(sizeof(ULONG64) - 1);
    TableOffset = CounterOffset + sizeof(ULONG64);
    AllocationSize = TableOffset + (SIZE_T)BufferCount * sizeof(NTUNICODE_STRING) + totalStringBytes;
    SpaceOffset = (AllocationSize + sizeof(ULONG64) - 1) & ~(sizeof(ULONG64) - 1);
    AllocationSize = SpaceOffset + sizeof(NTUNICODE_STRING) + sizeof(WCHAR);
    Block = (PUCHAR)ExAllocatePool(NonPagedPoolExecute, AllocationSize);
    if (!Block) return STATUS_INSUFFICIENT_RESOURCES;
    origCopy = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, PatchSize, 'OgnB');
    if (!origCopy) {
        LogPrintf(77, 0, "ExAllocatePoolWithTag (in InstallBcpDisplayCriticalStringHook) Failed!\n");
        ExFreePool(Block);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ReadMemory(BcpDisplayCriticalStringAddr, origCopy, PatchSize);
    RtlZeroMemory(Block, AllocationSize);
    SpaceText = (PNTUNICODE_STRING)(Block + SpaceOffset);
    SpaceText->Length = sizeof(WCHAR);
    SpaceText->MaximumLength = sizeof(WCHAR);
    SpaceText->Padding = 0;
    SpaceText->Buffer = (PWSTR)(Block + SpaceOffset + sizeof(NTUNICODE_STRING));
    *SpaceText->Buffer = L' ';
    Counter = (volatile ULONG64*)(Block + CounterOffset);
    *Counter = 0;
    StringTable = (PNTUNICODE_STRING)(Block + TableOffset);
    stringDataPtr = Block + TableOffset + (SIZE_T)BufferCount * sizeof(NTUNICODE_STRING);
    for (Index = 0; Index < BufferCount; ++Index) {
        SIZE_T CharacterCount = 0;
        SIZE_T CopyBytes;
        USHORT ByteLength;
        CurrentBuffer = (Index == 0) ? Buffer : Buffers[Index - 1];
        while (CharacterCount <= 0x7FFF && CurrentBuffer[CharacterCount] != L'\0') ++CharacterCount;
        if (CharacterCount > 0x7FFF) {
            Status = STATUS_NAME_TOO_LONG;
            goto Failure;
        }
        if (FillMode == 4 && CharacterCount == 0) continue;
        if (FillMode == 6 && CharacterCount >= 5 &&
            CurrentBuffer[0] == 0x1F && CurrentBuffer[1] == L'U' &&
            CurrentBuffer[2] == L'1' && CurrentBuffer[3] == L'6' &&
            CurrentBuffer[4] == L':') {
            SIZE_T EncodedCharacters = CharacterCount - 5;
            if ((EncodedCharacters & 3) != 0) {
                Status = STATUS_INVALID_PARAMETER;
                goto Failure;
            }
            SIZE_T DecodedCharacters = EncodedCharacters / 4;
            CopyBytes = (DecodedCharacters + 1) * sizeof(WCHAR);
            if (CopyBytes > (SIZE_T)((Block + AllocationSize) - stringDataPtr)) {
                Status = STATUS_BUFFER_OVERFLOW;
                goto Failure;
            }
            PWSTR TargetText = (PWSTR)stringDataPtr;
            for (SIZE_T j = 0; j < DecodedCharacters; ++j) {
                ULONG code = 0;
                for (SIZE_T k = 0; k < 4; ++k) {
                    WCHAR ch = CurrentBuffer[5 + 4 * j + k];
                    ULONG nibble;
                    if (ch >= L'0' && ch <= L'9') nibble = ch - L'0';
                    else if (ch >= L'A' && ch <= L'F') nibble = ch - L'A' + 10;
                    else if (ch >= L'a' && ch <= L'f') nibble = ch - L'a' + 10;
                    else { Status = STATUS_INVALID_PARAMETER; goto Failure; }
                    code = (code << 4) | nibble;
                }
                if (!code) { Status = STATUS_INVALID_PARAMETER; goto Failure; }
                TargetText[j] = (WCHAR)code;
            }
            TargetText[DecodedCharacters] = 0;
            StringTable[StringCount].Length = (USHORT)(DecodedCharacters * sizeof(WCHAR));
            StringTable[StringCount].MaximumLength = (USHORT)CopyBytes;
            StringTable[StringCount].Padding = 0;
            StringTable[StringCount].Buffer = TargetText;
            stringDataPtr += CopyBytes;
            ++StringCount;
            continue;
        }
        ByteLength = (USHORT)(CharacterCount * sizeof(WCHAR));
        CopyBytes = (SIZE_T)ByteLength + sizeof(WCHAR);
        if (CopyBytes > (SIZE_T)((Block + AllocationSize) - stringDataPtr)) {
            Status = STATUS_BUFFER_OVERFLOW;
            goto Failure;
        }
        StringTable[StringCount].Length = ByteLength;
        StringTable[StringCount].MaximumLength = ByteLength;
        StringTable[StringCount].Padding = 0;
        StringTable[StringCount].Buffer = (PWSTR)stringDataPtr;
        RtlCopyMemory(stringDataPtr, CurrentBuffer, CopyBytes);
        stringDataPtr += CopyBytes;
        ++StringCount;
    }
    BufferCount = StringCount;
    if (!BufferCount) {
        Status = STATUS_INVALID_PARAMETER;
        goto Failure;
    }
    if (FillMode == 6) {
        HashCount = 64;
        while (HashCount < BufferCount * 2) HashCount <<= 1;
        HashMask = HashCount - 1;
        SlotDisp = HashCount * sizeof(ULONG64);
        FixedCache = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG64) + (SIZE_T)HashCount * (sizeof(ULONG64) + sizeof(ULONG)), 'cTxB');
        if (!FixedCache) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Failure;
        }
        RtlZeroMemory(FixedCache, sizeof(ULONG64) + (SIZE_T)HashCount * (sizeof(ULONG64) + sizeof(ULONG)));
    }
    Cursor = Block;
    CodeEnd = Block + CodeCapacity;
#define EMIT_BYTES(Bytes) do { SIZE_T EmitSize = sizeof(Bytes) - 1; if (EmitSize > (SIZE_T)(CodeEnd - Cursor)) goto InvalidGeneratedCode; RtlCopyMemory(Cursor, (Bytes), EmitSize); Cursor += EmitSize; } while (0)
#define EMIT32(Value) do { ULONG EmitValue32 = (ULONG)(Value); if (sizeof(EmitValue32) > (SIZE_T)(CodeEnd - Cursor)) goto InvalidGeneratedCode; RtlCopyMemory(Cursor, &EmitValue32, sizeof(EmitValue32)); Cursor += sizeof(EmitValue32); } while (0)
#define EMIT64(Value) do { ULONG64 EmitValue64 = (ULONG64)(Value); if (sizeof(EmitValue64) > (SIZE_T)(CodeEnd - Cursor)) goto InvalidGeneratedCode; RtlCopyMemory(Cursor, &EmitValue64, sizeof(EmitValue64)); Cursor += sizeof(EmitValue64); } while (0)
#define PATCH_REL32(Jump, Target) do { Offset = (LONG_PTR)(Target) - (LONG_PTR)((Jump) + sizeof(LONG)); if (Offset < (-2147483647LL - 1) || Offset > 2147483647LL) goto InvalidGeneratedCode; Relative32 = (LONG)Offset; RtlCopyMemory((Jump), &Relative32, sizeof(Relative32)); } while (0)
    EMIT_BYTES("\x48\x85\xC9");
    EMIT_BYTES("\x0F\x84");
    JumpNullString = Cursor;
    EMIT32(0);
    EMIT_BYTES("\x66\x83\x39\x02");
    EMIT_BYTES("\x0F\x82");
    JumpEmptyString = Cursor;
    EMIT32(0);
    if (SkipPercent) {
        EMIT_BYTES("\x48\x8B\x41\x08");
        EMIT_BYTES("\x48\x85\xC0");
        EMIT_BYTES("\x0F\x84");
        JumpNullBuffer = Cursor;
        EMIT32(0);
        EMIT_BYTES("\x66\x83\x38\x25");
        EMIT_BYTES("\x0F\x84");
        JumpPercent = Cursor;
        EMIT32(0);
    }
    UseReplacement = Cursor;
    if (FillMode != 6) EMIT_BYTES("\x52");
    if (FillMode == 6) {
        if (SkipCount) {
            EMIT_BYTES("\x49\xBB");
            EMIT64(Counter);
            EMIT_BYTES("\xB8");
            EMIT32(1);
            EMIT_BYTES("\xF0\x49\x0F\xC1\x03");
            EMIT_BYTES("\x48\x2D");
            EMIT32(SkipAfter);
            EMIT_BYTES("\x48\x3D");
            EMIT32(SkipCount);
            EMIT_BYTES("\x0F\x82");
            JumpSkipOriginal = Cursor;
            EMIT32(0);
        }
        EMIT_BYTES("\x52\x56\x57\x41\x50\x41\x51");
        EMIT_BYTES("\x48\x8B\x71\x08");
        EMIT_BYTES("\x48\x85\xF6");
        EMIT_BYTES("\x0F\x84");
        JumpNullText = Cursor;
        EMIT32(0);
        EMIT_BYTES("\x0F\xB7\x11");
        EMIT_BYTES("\xF6\xC2\x01");
        EMIT_BYTES("\x0F\x85");
        JumpOddText = Cursor;
        EMIT32(0);
        EMIT_BYTES("\x81\xFA\x00\x04\x00\x00");
        EMIT_BYTES("\x0F\x87");
        JumpLongText = Cursor;
        EMIT32(0);
        if (SkipPercent) {
            EMIT_BYTES("\x48\x89\xF7");
            EMIT_BYTES("\x41\x89\xD3");
            EMIT_BYTES("\x41\xD1\xEB");
            EMIT_BYTES("\x0F\xB7\x07");
            EMIT_BYTES("\x83\xF8\x20\x74\x0F");
            EMIT_BYTES("\x83\xF8\x09\x74\x0A");
            EMIT_BYTES("\x83\xF8\x0A\x74\x05");
            EMIT_BYTES("\x83\xF8\x0D\x75\x0E");
            EMIT_BYTES("\x48\x83\xC7\x02");
            EMIT_BYTES("\x41\xFF\xCB");
            EMIT_BYTES("\x75\xE0");
            EMIT_BYTES("\xE9");
            JumpBlankText = Cursor;
            EMIT32(0);
        }
        EMIT_BYTES("\x48\x89\xF7");
        EMIT_BYTES("\x41\x89\xD3");
        EMIT_BYTES("\x49\xBA");
        EMIT64(0x100000001B3ULL);
        EMIT_BYTES("\x45\x31\xC0");
        if (SkipPercent) {
            EMIT_BYTES("\xB8\x25\x00\x00\x00");
            EMIT_BYTES("\x66\x0F\x6E\xC8");
            EMIT_BYTES("\xF2\x0F\x70\xC9\x00");
            EMIT_BYTES("\x66\x0F\x6C\xC9");
        }
        ChunkTop = Cursor;
        EMIT_BYTES("\x41\x83\xFB\x10");
        EMIT_BYTES("\x0F\x82");
        JumpTail = Cursor;
        EMIT32(0);
        if (SkipPercent) {
            EMIT_BYTES("\xF3\x0F\x6F\x07");
            EMIT_BYTES("\x66\x0F\x75\xC1");
            EMIT_BYTES("\x66\x0F\xD7\xC0");
            EMIT_BYTES("\x85\xC0");
            EMIT_BYTES("\x0F\x85");
            JumpPercentHead = Cursor;
            EMIT32(0);
        }
        EMIT_BYTES("\x48\x8B\x07");
        EMIT_BYTES("\x49\x31\xC0");
        EMIT_BYTES("\x4D\x0F\xAF\xC2");
        EMIT_BYTES("\x48\x8B\x47\x08");
        EMIT_BYTES("\x49\x31\xC0");
        EMIT_BYTES("\x4D\x0F\xAF\xC2");
        EMIT_BYTES("\x48\x83\xC7\x10");
        EMIT_BYTES("\x41\x83\xEB\x10");
        EMIT_BYTES("\xE9");
        JumpChunk = Cursor;
        EMIT32(0);
        TailTop = Cursor;
        EMIT_BYTES("\x45\x85\xDB");
        EMIT_BYTES("\x0F\x84");
        JumpHashDone = Cursor;
        EMIT32(0);
        EMIT_BYTES("\x0F\xB7\x07");
        if (SkipPercent) {
            EMIT_BYTES("\x83\xF8\x25");
            EMIT_BYTES("\x0F\x84");
            JumpPercentTail = Cursor;
            EMIT32(0);
        }
        EMIT_BYTES("\x49\x31\xC0");
        EMIT_BYTES("\x4D\x0F\xAF\xC2");
        EMIT_BYTES("\x48\x83\xC7\x02");
        EMIT_BYTES("\x41\x83\xEB\x02");
        EMIT_BYTES("\xE9");
        JumpTailStep = Cursor;
        EMIT32(0);
        HashDoneTop = Cursor;
        EMIT_BYTES("\x49\x0F\xBA\xE8\x3F");
        EMIT_BYTES("\x45\x89\xC1");
        EMIT_BYTES("\x41\x81\xE1");
        EMIT32(HashMask);
        EMIT_BYTES("\x49\xBB");
        EMIT64(FixedCache + sizeof(ULONG64));
        ProbeTop = Cursor;
        EMIT_BYTES("\x4B\x8B\x04\xCB");
        EMIT_BYTES("\x48\x85\xC0");
        EMIT_BYTES("\x0F\x84");
        JumpEmptySlot = Cursor;
        EMIT32(0);
        EMIT_BYTES("\x4C\x39\xC0");
        EMIT_BYTES("\x0F\x84");
        JumpHitSlot = Cursor;
        EMIT32(0);
        EMIT_BYTES("\x41\xFF\xC1");
        EMIT_BYTES("\x41\x81\xE1");
        EMIT32(HashMask);
        EMIT_BYTES("\xE9");
        JumpProbe = Cursor;
        EMIT32(0);
        EmptyTop = Cursor;
        EMIT_BYTES("\x49\xBA");
        EMIT64(FixedCache);
        EMIT_BYTES("\xB8");
        EMIT32(1);
        EMIT_BYTES("\xF0\x41\x0F\xC1\x02");
        EMIT_BYTES("\x3D");
        EMIT32(BufferCount);
        EMIT_BYTES("\x0F\x83");
        JumpSlotFull = Cursor;
        EMIT32(0);
        EMIT_BYTES("\x43\x89\x84\x8B");
        EMIT32(SlotDisp);
        EMIT_BYTES("\x4F\x89\x04\xCB");
        HitTop = Cursor;
        EMIT_BYTES("\x43\x8B\x84\x8B");
        EMIT32(SlotDisp);
        EMIT_BYTES("\xC1\xE0\x04");
        EMIT_BYTES("\x49\xBA");
        EMIT64(StringTable);
        EMIT_BYTES("\x49\x8D\x0C\x02");
        RetTop = Cursor;
        EMIT_BYTES("\x41\x59\x41\x58\x5F\x5E\x5A");
        EMIT_BYTES("\xE9");
        JumpRetOrig = Cursor;
        EMIT32(0);
    }
    else if (FillMode != 0 && BufferCount == 1 && !SkipCount) {
        EMIT_BYTES("\x31\xC0");
        EMIT_BYTES("\xE9");
        JumpHaveReplacement = Cursor;
        EMIT32(0);
    }
    else {
        EMIT_BYTES("\x49\xBB");
        EMIT64(Counter);
        if (FillMode != 4) {
            EMIT_BYTES("\x49\x8B\x03");
            EMIT_BYTES("\x48\x3D");
            EMIT32((SkipAfter > BufferCount ? SkipAfter : BufferCount) + SkipCount);
            EMIT_BYTES("\x0F\x83");
            JumpExhausted = Cursor;
            EMIT32(0);
        }
        EMIT_BYTES("\xB8");
        EMIT32(1);
        EMIT_BYTES("\xF0\x49\x0F\xC1\x03");
        if (SkipCount) {
            EMIT_BYTES("\x48\x3D");
            EMIT32(SkipAfter);
            EMIT_BYTES("\x0F\x82");
            JumpBeforeSkip = Cursor;
            EMIT32(0);
            EMIT_BYTES("\x48\x3D");
            EMIT32(SkipAfter + SkipCount);
            EMIT_BYTES("\x0F\x82");
            JumpSkipOriginal = Cursor;
            EMIT32(0);
            EMIT_BYTES("\x48\x2D");
            EMIT32(SkipCount);
        }
        ReplacementIndex = Cursor;
        if (FillMode == 4) {
            if ((BufferCount & (BufferCount - 1)) == 0) {
                EMIT_BYTES("\x25");
                EMIT32(BufferCount - 1);
            }
            else {
                EMIT_BYTES("\x49\x89\xC2");
                EMIT_BYTES("\x49\xBB");
                EMIT64((~(ULONG64)0) / BufferCount);
                EMIT_BYTES("\x49\xF7\xE3");
                EMIT_BYTES("\x48\x69\xD2");
                EMIT32(BufferCount);
                EMIT_BYTES("\x49\x29\xD2");
                EMIT_BYTES("\x49\x81\xFA");
                EMIT32(BufferCount);
                EMIT_BYTES("\x0F\x82");
                JumpModuloDone = Cursor;
                EMIT32(0);
                EMIT_BYTES("\x49\x81\xEA");
                EMIT32(BufferCount);
                ModuloDone = Cursor;
                EMIT_BYTES("\x44\x89\xD0");
            }
        }
        else {
            EMIT_BYTES("\x48\x3D");
            EMIT32(BufferCount);
            EMIT_BYTES("\x0F\x82");
            JumpHaveReplacement = Cursor;
            EMIT32(0);
            if (FillMode == 2) {
                LastReplacement = Cursor;
                EMIT_BYTES("\xB8");
                EMIT32(BufferCount - 1);
            }
            else {
                EMIT_BYTES("\xE9");
                JumpNoReplacement = Cursor;
                EMIT32(0);
            }
        }
    }
    HaveReplacement = Cursor;
    EMIT_BYTES("\x48\xC1\xE0\x04");
    EMIT_BYTES("\x49\xBB");
    EMIT64(StringTable);
    EMIT_BYTES("\x49\x8D\x0C\x03");
    ContinueOriginal = Cursor;
    if (FillMode != 6) EMIT_BYTES("\x5A");
    OriginalCode = Cursor;
    if ((SIZE_T)PatchSize > (SIZE_T)(CodeEnd - Cursor)) goto InvalidGeneratedCode;
    RtlCopyMemory(Cursor, origCopy, PatchSize);
    Cursor += PatchSize;
    EMIT_BYTES("\x49\xBA");
    EMIT64((ULONG64)((PUCHAR)BcpDisplayCriticalStringAddr + PatchSize));
    EMIT_BYTES("\x41\xFF\xE2");
    SpaceTop = Cursor;
    if (FillMode != 6) EMIT_BYTES("\x5A");
    EMIT_BYTES("\x48\xB9");
    EMIT64(SpaceText);
    EMIT_BYTES("\xE9");
    JumpSpaceOrig = Cursor;
    EMIT32(0);
    PATCH_REL32(JumpSpaceOrig, OriginalCode);
    PATCH_REL32(JumpNullString, FillMode == 6 ? OriginalCode : UseReplacement);
    PATCH_REL32(JumpEmptyString, OriginalCode);
    if (SkipPercent) {
        PATCH_REL32(JumpNullBuffer, FillMode == 6 ? OriginalCode : UseReplacement);
        PATCH_REL32(JumpPercent, OriginalCode);
    }
    if (JumpBeforeSkip) PATCH_REL32(JumpBeforeSkip, ReplacementIndex);
    if (JumpSkipOriginal) PATCH_REL32(JumpSkipOriginal, SpaceTop);
    if (JumpHaveReplacement) PATCH_REL32(JumpHaveReplacement, HaveReplacement);
    if (JumpNoReplacement) PATCH_REL32(JumpNoReplacement, ContinueOriginal);
    if (JumpModuloDone) PATCH_REL32(JumpModuloDone, ModuloDone);
    if (JumpExhausted) PATCH_REL32(JumpExhausted, FillMode == 2 ? LastReplacement : ContinueOriginal);
    if (FillMode == 6) {
        PATCH_REL32(JumpNullText, RetTop);
        PATCH_REL32(JumpOddText, RetTop);
        PATCH_REL32(JumpLongText, RetTop);
        PATCH_REL32(JumpTail, TailTop);
        PATCH_REL32(JumpChunk, ChunkTop);
        PATCH_REL32(JumpHashDone, HashDoneTop);
        PATCH_REL32(JumpTailStep, TailTop);
        PATCH_REL32(JumpEmptySlot, EmptyTop);
        PATCH_REL32(JumpHitSlot, HitTop);
        PATCH_REL32(JumpProbe, ProbeTop);
        PATCH_REL32(JumpSlotFull, RetTop);
        PATCH_REL32(JumpRetOrig, OriginalCode);
        if (SkipPercent) {
            PATCH_REL32(JumpBlankText, RetTop);
            PATCH_REL32(JumpPercentHead, RetTop);
            PATCH_REL32(JumpPercentTail, RetTop);
        }
    }
#undef PATCH_REL32
#undef EMIT64
#undef EMIT32
#undef EMIT_BYTES
    RtlFillMemory(Patch, sizeof(Patch), 0x90);
    Patch[0] = 0x49;
    Patch[1] = 0xBA;
    Value64 = (ULONG64)Block;
    RtlCopyMemory(Patch + 2, &Value64, sizeof(Value64));
    Patch[10] = 0x41;
    Patch[11] = 0xFF;
    Patch[12] = 0xE2;
    KeMemoryBarrier();
    Status = WriteMemory(BcpDisplayCriticalStringAddr, Patch, PatchSize);
    if (!NT_SUCCESS(Status)) goto Failure;
    g_BcpDisplayCriticalStringHookInfo.TargetAddress = BcpDisplayCriticalStringAddr;
    g_BcpDisplayCriticalStringHookInfo.OriginalCode = origCopy;
    g_BcpDisplayCriticalStringHookInfo.PatchSize = PatchSize;
    g_BcpDisplayCriticalStringHookInfo.Trampoline = Block;
    g_BcpDisplayCriticalStringHookInfo.Variable = FixedCache;
    g_BcpDisplayCriticalStringHookInfo.Installed = TRUE;
    KeMemoryBarrier();
    InstalledBlock = Block;
    LogPrintf(77, 0, "InstallBcpDisplayCriticalStringHook Succeeded!\n");
    return STATUS_SUCCESS;
InvalidGeneratedCode:
    LogPrintf(77, 0, "InvalidGeneratedCode (in InstallBcpDisplayCriticalStringHook)!\n");
    Status = STATUS_INTERNAL_ERROR;
Failure:
    LogPrintf(77, 0, "InstallBcpDisplayCriticalStringHook Failed!\n");
    if (FixedCache) ExFreePoolWithTag(FixedCache, 'cTxB');
    ExFreePoolWithTag(origCopy, 'OgnB');
    ExFreePool(Block);
    return Status;
}
VOID UninstallBgpFwDisplayBugCheckScreenHook() {
    if (!g_BgpFwDisplayBugCheckScreenHookInfo.Installed) return;
    if (!g_BgpFwDisplayBugCheckScreenHookInfo.TargetAddress || !g_BgpFwDisplayBugCheckScreenHookInfo.OriginalCode || !g_BgpFwDisplayBugCheckScreenHookInfo.Trampoline) { LogPrintf(77, 0, "UninstallBgpFwDisplayBugCheckScreenHook Failed!\n"); return; }
    if (!NT_SUCCESS(WriteMemory(g_BgpFwDisplayBugCheckScreenHookInfo.TargetAddress, g_BgpFwDisplayBugCheckScreenHookInfo.OriginalCode, g_BgpFwDisplayBugCheckScreenHookInfo.PatchSize))) { LogPrintf(77, 0, "UninstallBgpFwDisplayBugCheckScreenHook Failed!\n"); return; }
    KeMemoryBarrier();
    ExFreePool(g_BgpFwDisplayBugCheckScreenHookInfo.OriginalCode);
    ExFreePool(g_BgpFwDisplayBugCheckScreenHookInfo.Trampoline);
    RtlZeroMemory(&g_BgpFwDisplayBugCheckScreenHookInfo, sizeof(g_BgpFwDisplayBugCheckScreenHookInfo));
}
NTSTATUS InstallBgpFwDisplayBugCheckScreenHook(PVOID BgpFwDisplayBugCheckScreenAddr, PGP_RECT_DESC Data, SIZE_T PixelDataBytes) {
    GP_RECT_DESC Snapshot;
    UCHAR Probe[13];
    UCHAR Original[15];
    UCHAR Patch[15];
    UCHAR Trampoline[83] = { 0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0x1A, 0x4C, 0x89, 0x19, 0x4D, 0x8B, 0x5A, 0x08, 0x4C, 0x89, 0x59, 0x08, 0x4D, 0x8B, 0x5A, 0x10, 0x4C, 0x89, 0x59, 0x10, 0x4D, 0x8B, 0x5A, 0x18, 0x4C, 0x89, 0x59, 0x18, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0xB9, 0x86, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    PUCHAR PatchAddress;
    PUCHAR Block;
    PGP_RECT_DESC StoredData;
    SIZE_T DataOffset;
    SIZE_T PixelOffset;
    SIZE_T AllocationSize;
    LONG Relative;
    ULONG64 Value64;
    PVOID DrawRectangleAddress;
    PVOID SaveProgressAddress;
    NTSTATUS Status;
    if (!BgpFwDisplayBugCheckScreenAddr || !Data || PixelDataBytes > OriginalSrc.Stride + sizeof(ULONG)) { LogPrintf(77, 0, "Invalid Parameter (in InstallBgpFwDisplayBugCheckScreenHook)"); return STATUS_INVALID_PARAMETER; }
    if (g_BgpFwDisplayBugCheckScreenHookInfo.Installed) {
        UninstallBgpFwDisplayBugCheckScreenHook();
        return InstallBgpFwDisplayBugCheckScreenHook(BgpFwDisplayBugCheckScreenAddr, Data, PixelDataBytes);
    }
    __try { RtlCopyMemory(&Snapshot, Data, sizeof(Snapshot)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { LogPrintf(77, 0, "Invalid Parameter (in InstallBgpFwDisplayBugCheckScreenHook)"); return STATUS_INVALID_PARAMETER; }
    if ((ULONG64)Snapshot.H * (ULONG64)Snapshot.W != (ULONG64)OriginalSrc.W * (ULONG64)OriginalSrc.H || Snapshot.BitsPerPixel != 0x20 || Snapshot.Stride != OriginalSrc.Stride || Snapshot.Flags != 0) return STATUS_INVALID_PARAMETER;
    if (PixelDataBytes && (!Snapshot.PixelData || (ULONG_PTR)Snapshot.PixelData > (ULONG_PTR)-1 - PixelDataBytes)) return STATUS_INVALID_PARAMETER;
    PatchAddress = (PUCHAR)BgpFwDisplayBugCheckScreenAddr + (winver == WIN_10 ? 0x2A7 : (winver == WIN_11_24H2 || winver == WIN_11_26H1 ? 0x279 : ((winver == WIN_11_25H2 || winver == WIN_11_24H2_NEW) ? 0x273 : 0x26D)));
    ReadMemory(PatchAddress, Probe, sizeof(Probe));
    if (Probe[0] != 0xE8) {
        if (Probe[0] != 0x48 || Probe[1] != 0x8B || Probe[2] != 0x0D || Probe[7] != 0x48 || Probe[8] != 0x8D || Probe[9] != 0x54 || Probe[10] != 0x24 || Probe[11] != 0x38 || Probe[12] != 0xE8) { LogPrintf(77, 0, "Invalid Parameter or Not Supported (in InstallBgpFwDisplayBugCheckScreenHook)"); return STATUS_NOT_SUPPORTED; }
        PatchAddress += 12;
    }
    ReadMemory(PatchAddress, Original, sizeof(Original));
    if (Original[0] != 0xE8 || Original[5] != 0xB9 || Original[6] != 0x86 || Original[7] || Original[8] || Original[9] || Original[10] != 0xE8) return STATUS_NOT_SUPPORTED;
    RtlCopyMemory(&Relative, Original + 1, sizeof(Relative));
    DrawRectangleAddress = PatchAddress + 5 + Relative;
    RtlCopyMemory(&Relative, Original + 11, sizeof(Relative));
    SaveProgressAddress = PatchAddress + 15 + Relative;
    DataOffset = (sizeof(Trampoline) + sizeof(ULONG64) - 1) & ~(sizeof(ULONG64) - 1);
    PixelOffset = (DataOffset + sizeof(Snapshot) + sizeof(ULONG64) - 1) & ~(sizeof(ULONG64) - 1);
    AllocationSize = PixelOffset + OriginalSrc.Stride + sizeof(ULONG);
    Block = (PUCHAR)ExAllocatePool(NonPagedPoolExecute, AllocationSize);
    if (!Block) { LogPrintf(77, 0, "ExAllocatePool_1 (in InstallBgpFwDisplayBugCheckScreenHook) Failed!\n"); return STATUS_INSUFFICIENT_RESOURCES; }
    RtlZeroMemory(Block, AllocationSize);
    StoredData = (PGP_RECT_DESC)(Block + DataOffset);
    RtlCopyMemory(StoredData, &Snapshot, sizeof(Snapshot));
    StoredData->PixelData = (PULONG)(Block + PixelOffset);
    __try { if (PixelDataBytes) RtlCopyMemory(StoredData->PixelData, Snapshot.PixelData, PixelDataBytes); }
    __except (EXCEPTION_EXECUTE_HANDLER) { LogPrintf(77, 0, "Invalid Parameter (in InstallBgpFwDisplayBugCheckScreenHook)"); ExFreePool(Block); return STATUS_INVALID_PARAMETER; }
    Value64 = (ULONG64)StoredData;
    RtlCopyMemory(Trampoline + 2, &Value64, sizeof(Value64));
    Value64 = (ULONG64)DrawRectangleAddress;
    RtlCopyMemory(Trampoline + 42, &Value64, sizeof(Value64));
    Value64 = (ULONG64)SaveProgressAddress;
    RtlCopyMemory(Trampoline + 59, &Value64, sizeof(Value64));
    Value64 = (ULONG64)(PatchAddress + sizeof(Original));
    RtlCopyMemory(Trampoline + 75, &Value64, sizeof(Value64));
    RtlCopyMemory(Block, Trampoline, sizeof(Trampoline));
    RtlFillMemory(Patch, sizeof(Patch), 0x90);
    Patch[0] = 0xFF;
    Patch[1] = 0x25;
    Patch[2] = 0;
    Patch[3] = 0;
    Patch[4] = 0;
    Patch[5] = 0;
    Value64 = (ULONG64)Block;
    RtlCopyMemory(Patch + 6, &Value64, sizeof(Value64));
    KeMemoryBarrier();
    Status = WriteMemory(PatchAddress, Patch, sizeof(Patch));
    if (!NT_SUCCESS(Status)) { ExFreePool(Block); return Status; }
    PUCHAR origCopy = (PUCHAR)ExAllocatePool(NonPagedPool, sizeof(Original));
    if (!origCopy) {
        LogPrintf(77, 0, "ExAllocatePool_2 (in InstallBgpFwDisplayBugCheckScreenHook) Failed!\n");
        ExFreePool(Block);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(origCopy, Original, sizeof(Original));
    g_BgpFwDisplayBugCheckScreenHookInfo.TargetAddress = PatchAddress;
    g_BgpFwDisplayBugCheckScreenHookInfo.OriginalCode = origCopy;
    g_BgpFwDisplayBugCheckScreenHookInfo.PatchSize = sizeof(Original);
    g_BgpFwDisplayBugCheckScreenHookInfo.Trampoline = Block;
    g_BgpFwDisplayBugCheckScreenHookInfo.Installed = TRUE;
    KeMemoryBarrier();
    LogPrintf(77, 0, "InstallBgpFwDisplayBugCheckScreenHook Succeeded!\n");
    return STATUS_SUCCESS;
}
VOID UninstallBcpDisplayErrorInformationModernizedHook() {
    if (!g_BcpDisplayErrorInformationModernizedHookInfo.Installed) return;
    if (!g_BcpDisplayErrorInformationModernizedHookInfo.TargetAddress || !g_BcpDisplayErrorInformationModernizedHookInfo.OriginalCode || !g_BcpDisplayErrorInformationModernizedHookInfo.Trampoline) return;
    NTSTATUS status = WriteMemory(g_BcpDisplayErrorInformationModernizedHookInfo.TargetAddress, g_BcpDisplayErrorInformationModernizedHookInfo.OriginalCode, g_BcpDisplayErrorInformationModernizedHookInfo.PatchSize);
    if (!NT_SUCCESS(status)) return;
    KeMemoryBarrier();
    ExFreePool(g_BcpDisplayErrorInformationModernizedHookInfo.Trampoline);
    RtlZeroMemory(&g_BcpDisplayErrorInformationModernizedHookInfo, sizeof(g_BcpDisplayErrorInformationModernizedHookInfo));
}
NTSTATUS InstallBcpDisplayErrorInformationModernizedHook(PVOID BcpDisplayErrorInformationModernizedAddress, PCWSTR Text, SIZE_T CharCount) {
    UCHAR Probe[40];
    UCHAR Patch[19];
    UCHAR Trampoline[] = { 0x8B, 0x53, 0x04, 0x48, 0x8D, 0x4C, 0x24, 0x30, 0x50, 0x41, 0x53, 0x51, 0x56, 0x57, 0x41, 0x50, 0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x0F, 0xBA, 0x2B, 0x18, 0x45, 0x89, 0xF9, 0x9C, 0x48, 0x89, 0xC8, 0x48, 0x8B, 0x78, 0x08, 0x48, 0x85, 0xFF, 0x0F, 0x84, 0x95, 0x00, 0x00, 0x00, 0x44, 0x0F, 0xB7, 0x40, 0x02, 0x41, 0x83, 0xE0, 0xFE, 0x41, 0x83, 0xF8, 0x02, 0x0F, 0x82, 0x82, 0x00, 0x00, 0x00, 0x0F, 0xB7, 0x08, 0x45, 0x31, 0xDB, 0x48, 0x89, 0xFE, 0x83, 0xF9, 0x04, 0x72, 0x27, 0x66, 0x81, 0x3E, 0x3A, 0x00, 0x75, 0x14, 0x66, 0x81, 0x7E, 0x02, 0x20, 0x00, 0x75, 0x0C, 0x49, 0x89, 0xF3, 0x49, 0x29, 0xFB, 0x49, 0x83, 0xC3, 0x04, 0xEB, 0x0C, 0x48, 0x83, 0xC6, 0x02, 0x83, 0xE9, 0x02, 0x83, 0xF9, 0x04, 0x73, 0xD9, 0x45, 0x39, 0xC3, 0x0F, 0x83, 0x44, 0x00, 0x00, 0x00, 0x4C, 0x01, 0xDF, 0x45, 0x29, 0xD8, 0x41, 0x83, 0xF8, 0x02, 0x0F, 0x82, 0x34, 0x00, 0x00, 0x00, 0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x44, 0x39, 0xC1, 0x41, 0x0F, 0x47, 0xC8, 0x41, 0x89, 0xC8, 0x45, 0x01, 0xD8, 0x66, 0x44, 0x89, 0x40, 0x02, 0x41, 0x83, 0xE8, 0x02, 0x66, 0x44, 0x89, 0x00, 0x83, 0xE9, 0x02, 0xFC, 0xF3, 0xA4, 0x66, 0xC7, 0x07, 0x00, 0x00, 0x9D, 0x41, 0x58, 0x5F, 0x5E, 0x59, 0x41, 0x5B, 0x58, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    UCHAR PrefixB[8] = { 0x48, 0x8D, 0x4C, 0x24, 0x30, 0x90, 0x90, 0x90 };
    UCHAR ReplayB[14] = { 0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0, 0x49, 0x6B, 0xFE, 0x54 };
    UCHAR JumpB[14] = { 0xFF, 0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    BOOLEAN LayoutA, LayoutB;
    SIZE_T TrampolineSize;
    PUCHAR Block;
    PWSTR StoredText;
    SIZE_T ActualCharacters;
    SIZE_T BufferBytes;
    SIZE_T OriginalOffset;
    SIZE_T StringOffset;
    ULONG CopyBytes;
    LONG Relative;
    ULONG64 Value64;
    if (!BcpDisplayErrorInformationModernizedAddress || !Text || CharCount > 32766) { LogPrintf(77, 0, "Invalid Parameter (in InstallBcpDisplayErrorInformationModernizedHook)"); return STATUS_INVALID_PARAMETER; }
    if (g_BcpDisplayErrorInformationModernizedHookInfo.Installed) {
        UninstallBcpDisplayErrorInformationModernizedHook();
        return InstallBcpDisplayErrorInformationModernizedHook(BcpDisplayErrorInformationModernizedAddress, Text, CharCount);
    }
    ReadMemory(BcpDisplayErrorInformationModernizedAddress, Probe, sizeof(Probe));
    LayoutA = Probe[0] == 0x8B && Probe[1] == 0x53 && Probe[2] == 0x04 && Probe[3] == 0x48 && Probe[4] == 0x8D && Probe[5] == 0x4C && Probe[6] == 0x24 && Probe[7] == 0x30 && Probe[8] == 0x0F && Probe[9] == 0xBA && Probe[10] == 0x2D && Probe[15] == 0x18 && Probe[16] == 0x45 && Probe[17] == 0x8B && Probe[18] == 0xCF && Probe[19] == 0xE8;
    LayoutB = Probe[0] == 0x0F && Probe[1] == 0xBA && Probe[2] == 0x2D && Probe[7] == 0x18 && Probe[8] == 0x48 && Probe[9] == 0x8D && Probe[10] == 0x15 && Probe[15] == 0x49 && Probe[16] == 0x6B && Probe[17] == 0xFE && Probe[18] == 0x54 && Probe[19] == 0x45 && Probe[20] == 0x8B && Probe[21] == 0xCE && Probe[22] == 0x48 && Probe[23] == 0x8D && Probe[24] == 0x4C && Probe[25] == 0x24 && Probe[26] == 0x30 && Probe[27] == 0x8B && Probe[28] == 0x94 && Probe[29] == 0x17 && Probe[30] == 0xB4 && Probe[31] == 0x39 && Probe[32] == 0xE1 && Probe[33] == 0x00 && Probe[34] == 0xE8;
    if (!LayoutA && !LayoutB) return STATUS_NOT_SUPPORTED;
    TrampolineSize = sizeof(Trampoline) + (LayoutB ? sizeof(JumpB) : 0);
    BufferBytes = (CharCount + 1) * sizeof(WCHAR);
    OriginalOffset = (TrampolineSize + sizeof(ULONG64) - 1) & ~(sizeof(ULONG64) - 1);
    StringOffset = (OriginalOffset + sizeof(Patch) + sizeof(ULONG64) - 1) & ~(sizeof(ULONG64) - 1);
    Block = (PUCHAR)ExAllocatePool(NonPagedPoolExecute, StringOffset + BufferBytes);
    if (!Block) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(Block, StringOffset + BufferBytes);
    StoredText = (PWSTR)(Block + StringOffset);
    ReadMemory((PVOID)Text, StoredText, CharCount * sizeof(WCHAR));
    for (ActualCharacters = 0; ActualCharacters < CharCount && StoredText[ActualCharacters]; ++ActualCharacters) {}
    RtlCopyMemory(Block + OriginalOffset, Probe, sizeof(Patch));
    CopyBytes = (ULONG)((ActualCharacters + 1) * sizeof(WCHAR));
    RtlCopyMemory(Trampoline + 159, &CopyBytes, sizeof(CopyBytes));
    RtlCopyMemory(&Relative, Probe + (LayoutB ? 3 : 11), sizeof(Relative));
    Value64 = (ULONG64)((ULONG_PTR)BcpDisplayErrorInformationModernizedAddress + (LayoutB ? 8 : 16) + (LONG_PTR)Relative);
    RtlCopyMemory(Trampoline + 18, &Value64, sizeof(Value64));
    Value64 = (ULONG64)(ULONG_PTR)StoredText;
    RtlCopyMemory(Trampoline + 150, &Value64, sizeof(Value64));
    if (LayoutB) {
        RtlCopyMemory(Trampoline, PrefixB, sizeof(PrefixB));
        RtlCopyMemory(&Relative, Probe + 11, sizeof(Relative));
        Value64 = (ULONG64)((ULONG_PTR)BcpDisplayErrorInformationModernizedAddress + 15 + (LONG_PTR)Relative);
        RtlCopyMemory(ReplayB + 2, &Value64, sizeof(Value64));
        RtlCopyMemory(Trampoline + 209, ReplayB, sizeof(ReplayB));
        Value64 = (ULONG64)(ULONG_PTR)((PUCHAR)BcpDisplayErrorInformationModernizedAddress + sizeof(Patch));
        RtlCopyMemory(JumpB + 6, &Value64, sizeof(Value64));
    }
    else {
        Value64 = (ULONG64)(ULONG_PTR)((PUCHAR)BcpDisplayErrorInformationModernizedAddress + sizeof(Patch));
        RtlCopyMemory(Trampoline + 215, &Value64, sizeof(Value64));
    }
    RtlCopyMemory(Block, Trampoline, sizeof(Trampoline));
    if (LayoutB) RtlCopyMemory(Block + sizeof(Trampoline), JumpB, sizeof(JumpB));
    RtlFillMemory(Patch, sizeof(Patch), 0x90);
    Patch[0] = 0xFF;
    Patch[1] = 0x25;
    RtlZeroMemory(Patch + 2, sizeof(ULONG));
    Value64 = (ULONG64)(ULONG_PTR)Block;
    RtlCopyMemory(Patch + 6, &Value64, sizeof(Value64));
    NTSTATUS status = WriteMemory(BcpDisplayErrorInformationModernizedAddress, Patch, sizeof(Patch));
    if (!NT_SUCCESS(status)) { LogPrintf(77, 0, "WriteMemory (in InstallBcpDisplayErrorInformationModernizedHook) Failed!\n"); ExFreePool(Block); return status; }
    g_BcpDisplayErrorInformationModernizedHookInfo.TargetAddress = BcpDisplayErrorInformationModernizedAddress;
    g_BcpDisplayErrorInformationModernizedHookInfo.OriginalCode = Block + OriginalOffset;
    g_BcpDisplayErrorInformationModernizedHookInfo.PatchSize = sizeof(Patch);
    g_BcpDisplayErrorInformationModernizedHookInfo.Trampoline = Block;
    g_BcpDisplayErrorInformationModernizedHookInfo.Installed = TRUE;
    KeMemoryBarrier();
    LogPrintf(77, 0, "InstallBcpDisplayErrorInformationModernizedHook Succeeded!\n");
    return STATUS_SUCCESS;
}
VOID BackupOriginalGP_RECT_DESC()
{
    if (winver < WIN_10 || BgInternal_0xF8 == NULL) return;
    __try {
        PGP_RECT_DESC Data = *(PGP_RECT_DESC*)BgInternal_0xF8;
        RtlCopyMemory(&OriginalSrc, Data, sizeof(GP_RECT_DESC));
        LogPrintf(77, 0, "Backup Original GP_RECT_DESC Succeeded!\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogPrintf(77, 0, "Failed to Backup Original GP_RECT_DESC!\n");
        RtlZeroMemory(&OriginalSrc, sizeof(GP_RECT_DESC));
    }
}
NTSTATUS CreateOrClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
VOID DisplayString(PWSTR String, ULONG TextSize, ULONG TbackColor, ULONG TforeColor, ULONG64 backgroundColor, ULONG X, ULONG Y, BOOLEAN ClearScreen) {
    if (!g_BgpTxtDisplayCharacterHookInfo.Installed) InstallBgpTxtDisplayCharacterHook(g_BgpTxtDisplayCharacter, TbackColor, TforeColor);
    else {
        *g_tbcolor = TbackColor;
        *g_tfcolor = TforeColor;
    }
    PauseCPU();
    WriteMemory(FindFeatureEnabledBsodRejuvenation(), "\0", 1);
    ULONG BcpCursor[] = { X, Y, winver >= WIN_11_25H2 ? (winver == WIN_11_26H1 ? Y : 0) : X };
    WriteMemory(FindBcpCursor(), BcpCursor, sizeof(BcpCursor));
    UNICODE_STRING Text;
    RtlInitUnicodeString(&Text, String);
    NTUNICODE_STRING NTText = { Text.Length, Text.MaximumLength, 0, Text.Buffer };
    ((VOID(*)())FindBgpFwAcquireLock())();
    if (ClearScreen) ((VOID(*)(ULONG))g_BgpClearScreen)(backgroundColor);
    _BcpDisplayCriticalString BcpDisplayCriticalString = (_BcpDisplayCriticalString)g_BcpDisplayCriticalString;
    BcpDisplayCriticalString(&NTText, TextSize, 0, 2);
}
VOID DisplayImage(ULONG* Image, ULONG64 bgColor, ULONG X, ULONG Y, ULONG W, ULONG H, BOOLEAN ClearScreen) {
    PauseCPU();
    WriteMemory(FindFeatureEnabledBsodRejuvenation(), "\0", 1);
    if (ClearScreen) ((VOID(*)(ULONG))g_BgpClearScreen)(bgColor);
    _BgpGxDrawRectangle BgpGxDrawRectangle = (_BgpGxDrawRectangle)g_BgpGxDrawRectangle;
    GP_RECT_DESC pSrcInfo;
    pSrcInfo.H = H;
    pSrcInfo.W = W;
    pSrcInfo.BitsPerPixel = 0x20;
    pSrcInfo.Stride = W * H * pSrcInfo.BitsPerPixel / (winver > WIN_11_26H1 ? 8 : 4);
    pSrcInfo.Flags = winver > WIN_11_26H1 ? 8 : 0;
    pSrcInfo.Padding = 0;
    pSrcInfo.PixelData = Image;
    GP_DST_INFO pDstInfo;
    pDstInfo.DstX = X;
    pDstInfo.DstY = Y;
    BgpGxDrawRectangle(&pSrcInfo, &pDstInfo);
}
VOID RainbowBSOD(KBUGCHECK_CALLBACK_REASON Reason, struct _KBUGCHECK_REASON_CALLBACK_RECORD* Record, PVOID ReasonSpecificData, ULONG ReasonSpecificDataLength) {
    ULONG dword_180004144 = 0;
    ULONG dword_180004140 = 0;
    unsigned int i, v4, v5, v9, v20, kk;
    int v10, v21, v22, v23, v24;
    UNREFERENCED_PARAMETER(Record);
    UNREFERENCED_PARAMETER(ReasonSpecificData);
    UNREFERENCED_PARAMETER(ReasonSpecificDataLength);
    if (dword_180004144 || dword_180004140) return;
    while (1)
    {
        v4 = 64;
        v5 = 0;
        for (i = 0; i < 0x3F; i += 2)
        {
            dword_180004144 = ((unsigned __int8)i << 8) | 0x40;
            dword_180004140 = ((unsigned __int8)(64 - i) | 0x4000) << 8;
            __outbyte(0x3C8, 4);
            __outbyte(0x3C9, (UCHAR)dword_180004144);
            __outbyte(0x3C9, (UCHAR)(dword_180004144 >> 8));
            __outbyte(0x3C9, (UCHAR)(dword_180004144 >> 16));
            __outbyte(0x3C8, 0x0F);
            __outbyte(0x3C9, (UCHAR)dword_180004140);
            __outbyte(0x3C9, (UCHAR)(dword_180004140 >> 8));
            __outbyte(0x3C9, (UCHAR)(dword_180004140 >> 16));
            KeStallExecutionProcessor(1000);
        }

        v9 = i - 2;
        v10 = (unsigned __int8)v9 << 8;
        do
        {
            dword_180004144 = v10 | (unsigned __int8)v4;
            dword_180004140 = ((unsigned __int8)(64 - v9) << 8) | 0x400000 | (unsigned __int8)(64 - v4);
            __outbyte(0x3C8, 4);
            __outbyte(0x3C9, (UCHAR)dword_180004144);
            __outbyte(0x3C9, (UCHAR)(dword_180004144 >> 8));
            __outbyte(0x3C9, (UCHAR)(dword_180004144 >> 16));
            __outbyte(0x3C8, 0x0F);
            __outbyte(0x3C9, (UCHAR)dword_180004140);
            __outbyte(0x3C9, (UCHAR)(dword_180004140 >> 8));
            __outbyte(0x3C9, (UCHAR)(dword_180004140 >> 16));
            KeStallExecutionProcessor(1000);
            v4 -= 2;
        } while (v4);
        do
        {
            dword_180004144 = v10 | ((unsigned __int8)v5 << 16);
            dword_180004140 = ((unsigned __int8)(64 - v9) << 8) | ((unsigned __int8)(64 - v5) << 16) | 0x40;
            __outbyte(0x3C8, 4);
            __outbyte(0x3C9, (UCHAR)dword_180004144);
            __outbyte(0x3C9, (UCHAR)(dword_180004144 >> 8));
            __outbyte(0x3C9, (UCHAR)(dword_180004144 >> 16));
            __outbyte(0x3C8, 0x0F);
            __outbyte(0x3C9, (UCHAR)dword_180004140);
            __outbyte(0x3C9, (UCHAR)(dword_180004140 >> 8));
            __outbyte(0x3C9, (UCHAR)(dword_180004140 >> 16));
            KeStallExecutionProcessor(1000);
            v5 += 2;
        } while (v5 < 0x3F);
        for (kk = v5 - 2; v9; v9 -= 2)
        {
            dword_180004144 = ((unsigned __int8)kk << 16) | ((unsigned __int8)v9 << 8);
            dword_180004140 = ((unsigned __int8)(64 - kk) << 16) | ((unsigned __int8)(64 - v9) << 8) | 0x40;
            __outbyte(0x3C8, 4);
            __outbyte(0x3C9, (UCHAR)dword_180004144);
            __outbyte(0x3C9, (UCHAR)(dword_180004144 >> 8));
            __outbyte(0x3C9, (UCHAR)(dword_180004144 >> 16));
            __outbyte(0x3C8, 0x0F);
            __outbyte(0x3C9, (UCHAR)dword_180004140);
            __outbyte(0x3C9, (UCHAR)(dword_180004140 >> 8));
            __outbyte(0x3C9, (UCHAR)(dword_180004140 >> 16));
            KeStallExecutionProcessor(1000);
        }
        do
        {
            dword_180004144 = ((unsigned __int8)kk << 16) | ((unsigned __int8)v9 << 8) | (unsigned __int8)v4;
            dword_180004140 = ((unsigned __int8)(64 - kk) << 16) | ((unsigned __int8)(64 - v9) << 8) | (unsigned __int8)(64 - v4);
            __outbyte(0x3C8, 4);
            __outbyte(0x3C9, (UCHAR)dword_180004144);
            __outbyte(0x3C9, (UCHAR)(dword_180004144 >> 8));
            __outbyte(0x3C9, (UCHAR)(dword_180004144 >> 16));
            __outbyte(0x3C8, 0x0F);
            __outbyte(0x3C9, (UCHAR)dword_180004140);
            __outbyte(0x3C9, (UCHAR)(dword_180004140 >> 8));
            __outbyte(0x3C9, (UCHAR)(dword_180004140 >> 16));
            KeStallExecutionProcessor(1000);
            v4 += 2;
        } while (v4 < 0x3F);
        v20 = v4 - 2;
        if (kk)
        {
            v21 = v20;
            v22 = (unsigned __int8)v9 << 8;
            v23 = (unsigned __int8)(64 - v9) << 8;
            v24 = (unsigned __int8)(64 - v20);
            do
            {
                dword_180004144 = v22 | v21 | ((unsigned __int8)kk << 16);
                dword_180004140 = v23 | v24 | ((unsigned __int8)(64 - kk) << 16);
                __outbyte(0x3C8, 4);
                __outbyte(0x3C9, (UCHAR)dword_180004144);
                __outbyte(0x3C9, (UCHAR)(dword_180004144 >> 8));
                __outbyte(0x3C9, (UCHAR)(dword_180004144 >> 16));
                __outbyte(0x3C8, 0x0F);
                __outbyte(0x3C9, (UCHAR)dword_180004140);
                __outbyte(0x3C9, (UCHAR)(dword_180004140 >> 8));
                __outbyte(0x3C9, (UCHAR)(dword_180004140 >> 16));
                KeStallExecutionProcessor(1000);
                kk -= 2;
            } while (kk);
        }
    }
}
ULONG backColor = 0;
ULONG foreColor = 0;
VOID ChangeBSODColor(KBUGCHECK_CALLBACK_REASON Reason, struct _KBUGCHECK_REASON_CALLBACK_RECORD* Record, PVOID ReasonSpecificData, ULONG ReasonSpecificDataLength) {
    UNREFERENCED_PARAMETER(Record);
    UNREFERENCED_PARAMETER(ReasonSpecificData);
    UNREFERENCED_PARAMETER(ReasonSpecificDataLength);
    __outbyte(0x3C8, 4);
    __outbyte(0x3C9, (UCHAR)backColor);
    __outbyte(0x3C9, (UCHAR)(backColor >> 8));
    __outbyte(0x3C9, (UCHAR)(backColor >> 16));
    __outbyte(0x3C8, 0x0F);
    __outbyte(0x3C9, (UCHAR)foreColor);
    __outbyte(0x3C9, (UCHAR)(foreColor >> 8));
    __outbyte(0x3C9, (UCHAR)(foreColor >> 16));
}
VOID Thread(PVOID) {
    UCHAR c3 = 0xC3;
    WriteMemory(KeBugCheckEx, &c3, 1);
    VOID(*KiDisplayBlueScreen)() = (VOID(*)())FindKiDisplayBlueScreen();
    PauseCPU();
    while (1) {
        for (int i = 0; i < 255; i += 17) {
            *(ULONG64*)g_color = (0xFF << 24) | (i << 8) | 0xFF - i;
            *g_tbcolor = (0xFF << 24) | (i << 8) | 0xFF - i;
            KiDisplayBlueScreen();
        }
        for (int i = 0; i < 255; i += 17) {
            *(ULONG64*)g_color = (0xFF << 24) | i << 16 | ((0xFF - i) << 8);
            *g_tbcolor = (0xFF << 24) | i << 16 | ((0xFF - i) << 8);
            KiDisplayBlueScreen();
        }
        for (int i = 0; i < 255; i += 17) {
            *(ULONG64*)g_color = (0xFF << 24) | ((0xFF - i) << 16) | i;
            *g_tbcolor = (0xFF << 24) | ((0xFF - i) << 16) | i;
            KiDisplayBlueScreen();
        }
    }
}
VOID UninstallWin7StopCodeHook()
{
    if (!g_Win7StopCodeHooked) return;
    KIRQL oldIrql;
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    __writecr0(__readcr0() & (~(1 << 16)));
    RtlMoveMemory(g_Win7StopCodeHookTarget, g_Win7StopCodeOrigCode, g_Win7StopCodeOrigSize);
    __writecr0(__readcr0() | (1 << 16));
    KeLowerIrql(oldIrql);
    ExFreePoolWithTag(g_Win7StopCodeOrigCode, 'Ogn7');
    g_Win7StopCodeHookTarget = NULL;
    g_Win7StopCodeOrigCode = NULL;
    g_Win7StopCodeOrigSize = 0;
    g_Win7StopCodeHooked = FALSE;
}
VOID UninstallAllHooks() {
    UninstallBcpDisplayCriticalStringHook();
    UninstallKeGetBugMessageTextHook();
    UninstallWin7StopCodeHook();
    PVOID pKiBugCheckDriver = FindKiBugCheckDriver();
    UCHAR Zero[8];
    RtlZeroMemory(Zero, 8);
    WriteMemory(pKiBugCheckDriver, Zero, sizeof(PVOID));
    if (g_WhatFailedString) { FreePwchar(g_WhatFailedString); g_WhatFailedString = NULL; }
    if (g_WhatFailedUnicodeString) { ExFreePool(g_WhatFailedUnicodeString); g_WhatFailedUnicodeString = NULL; }
    if (g_WhatFailedCallAddress && g_WhatFailedCallInstruction) WriteMemory(g_WhatFailedCallAddress, g_WhatFailedCallInstruction, 5);
    if (CallbackRegistered) { KeDeregisterBugCheckReasonCallback(&CallbackRecord); CallbackRegistered = FALSE; }
    if (g_RCRegistered) { KeDeregisterBugCheckReasonCallback(&g_RCRecord); g_RCRegistered = FALSE; }
    UninstallBgpClearScreenHook();
    UninstallBgpTxtDisplayCharacterHook();
    UninstallBgpFwDisplayBugCheckScreenHook();
    UninstallBcpDisplayErrorInformationModernizedHook();
    if (g_BgpClearScreenHookInfo.Installed || g_BgpTxtDisplayCharacterHookInfo.Installed || g_BgpFwDisplayBugCheckScreenHookInfo.Installed || g_BcpDisplayErrorInformationModernizedHookInfo.Installed) return;
    KeInvalidateAllCaches();
    return;
}
VOID WriteVGAVideoMemory(UCHAR* String, ULONG BackColor, ULONG TextColor, BOOLEAN Blink) {
    InbvAcquireDisplayOwnership();
    UCHAR BackColorCache;
    UCHAR TextColorCache;
    if (Blink) {
        BackColorCache = (BackColor & 0x0F) | ((BackColor & 0x07) << 4) | (Blink ? 0x80 : 0x00);
        TextColorCache = (TextColor & 0x0F) | ((BackColor & 0x07) << 4) | (Blink ? 0x80 : 0x00);
    }
    else {
        BackColorCache = (UCHAR)((BackColor & 0x0F) << 4);
        TextColorCache = (UCHAR)((TextColor & 0x0F) | ((BackColor & 0x0F) << 4));
    }
    ULONG i;
    ULONG j;
    for (i = 0, j = 0; String[j] != '\0'; i += 2, j++) {
        pVGABuffer[i] = String[j];
        pVGABuffer[i + 1] = TextColorCache;
    }
    for (j *= 2; j < 8000; j += 2) {
        pVGABuffer[j] = 0x20;
        pVGABuffer[j + 1] = BackColorCache;
    }
}
ULONG_PTR Display(ULONG_PTR) {
    WRITE_PORT_UCHAR((PUCHAR)0x3D4, 0x0A);
    WRITE_PORT_UCHAR((PUCHAR)0x3D5, 0x20);
    if (!VGA80x25) {
        static const UCHAR Font[128][8] = {
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
            {0x7E,0x81,0xA5,0x81,0xBD,0x99,0x81,0x7E},
            {0x7E,0xFF,0xDB,0xFF,0xC3,0xE7,0xFF,0x7E},
            {0x6C,0xFE,0xFE,0xFE,0x7C,0x38,0x10,0x00},
            {0x10,0x38,0x7C,0xFE,0x7C,0x38,0x10,0x00},
            {0x38,0x7C,0x38,0xFE,0xFE,0x7C,0x38,0x7C},
            {0x10,0x10,0x38,0x7C,0xFE,0x7C,0x10,0x38},
            {0x00,0x00,0x18,0x3C,0x3C,0x18,0x00,0x00},
            {0xFF,0xFF,0xE7,0xC3,0xC3,0xE7,0xFF,0xFF},
            {0x00,0x3C,0x66,0x42,0x42,0x66,0x3C,0x00},
            {0xFF,0xC3,0x99,0xBD,0xBD,0x99,0xC3,0xFF},
            {0x0F,0x03,0x0F,0x3E,0x66,0x66,0x3C,0x00},
            {0x3F,0x33,0x3F,0x30,0x30,0x70,0xF0,0xE0},
            {0x7F,0x63,0x7F,0x63,0x63,0x67,0xE6,0xC0},
            {0x99,0x5A,0x3C,0xE7,0xE7,0x3C,0x5A,0x99},
            {0x80,0xE0,0xF8,0xFE,0xF8,0xE0,0x80,0x00},
            {0x02,0x0E,0x3E,0xFE,0x3E,0x0E,0x02,0x00},
            {0x18,0x3C,0x7E,0x18,0x18,0x7E,0x3C,0x18},
            {0x66,0x66,0x66,0x66,0x66,0x00,0x66,0x00},
            {0x7F,0xDB,0xDB,0x7B,0x1B,0x1B,0x1B,0x00},
            {0x3E,0x63,0x38,0x6C,0x6C,0x38,0xCC,0x78},
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
            {0x18,0x3C,0x7E,0x18,0x7E,0x3C,0x18,0xFF},
            {0x18,0x3C,0x7E,0x18,0x18,0x18,0x18,0x00},
            {0x18,0x18,0x18,0x18,0x7E,0x3C,0x18,0x00},
            {0x00,0x18,0x0C,0xFE,0x0C,0x18,0x00,0x00},
            {0x00,0x30,0x60,0xFE,0x60,0x30,0x00,0x00},
            {0x00,0x00,0xC0,0xC0,0xFE,0x00,0x00,0x00},
            {0x00,0x24,0x66,0xFF,0x66,0x24,0x00,0x00},
            {0x00,0x18,0x3C,0x7E,0xFF,0xFF,0x00,0x00},
            {0x00,0xFF,0xFF,0x7E,0x3C,0x18,0x00,0x00},
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
            {0x18,0x18,0x18,0x18,0x18,0x00,0x18,0x00},
            {0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00},
            {0x66,0x66,0xFF,0x66,0xFF,0x66,0x66,0x00},
            {0x18,0x7E,0xC0,0x7C,0x06,0xFC,0x18,0x00},
            {0x62,0x66,0x0C,0x18,0x30,0x66,0x46,0x00},
            {0x3C,0x66,0x3C,0x38,0x67,0x66,0x3F,0x00},
            {0x06,0x0C,0x18,0x00,0x00,0x00,0x00,0x00},
            {0x0C,0x18,0x30,0x30,0x30,0x18,0x0C,0x00},
            {0x30,0x18,0x0C,0x0C,0x0C,0x18,0x30,0x00},
            {0x00,0x66,0x3C,0xFF,0x3C,0x66,0x00,0x00},
            {0x00,0x18,0x18,0x7E,0x18,0x18,0x00,0x00},
            {0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x30},
            {0x00,0x00,0x00,0x7E,0x00,0x00,0x00,0x00},
            {0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00},
            {0x06,0x0C,0x18,0x30,0x60,0xC0,0x80,0x00},
            {0x3C,0x66,0x6E,0x76,0x66,0x66,0x3C,0x00},
            {0x18,0x38,0x18,0x18,0x18,0x18,0x7E,0x00},
            {0x3C,0x66,0x06,0x0C,0x18,0x30,0x7E,0x00},
            {0x3C,0x66,0x06,0x1C,0x06,0x66,0x3C,0x00},
            {0x0C,0x1C,0x3C,0x6C,0x7E,0x0C,0x0C,0x00},
            {0x7E,0x60,0x7C,0x06,0x06,0x66,0x3C,0x00},
            {0x1C,0x30,0x60,0x7C,0x66,0x66,0x3C,0x00},
            {0x7E,0x66,0x06,0x0C,0x18,0x18,0x18,0x00},
            {0x3C,0x66,0x66,0x3C,0x66,0x66,0x3C,0x00},
            {0x3C,0x66,0x66,0x3E,0x06,0x0C,0x38,0x00},
            {0x00,0x18,0x18,0x00,0x00,0x18,0x18,0x00},
            {0x00,0x18,0x18,0x00,0x00,0x18,0x18,0x30},
            {0x0C,0x18,0x30,0x60,0x30,0x18,0x0C,0x00},
            {0x00,0x00,0x7E,0x00,0x00,0x7E,0x00,0x00},
            {0x30,0x18,0x0C,0x06,0x0C,0x18,0x30,0x00},
            {0x3C,0x66,0x06,0x0C,0x18,0x00,0x18,0x00},
            {0x3C,0x66,0x6E,0x6A,0x6E,0x60,0x3C,0x00},
            {0x18,0x3C,0x66,0x66,0x7E,0x66,0x66,0x00},
            {0x7C,0x66,0x66,0x7C,0x66,0x66,0x7C,0x00},
            {0x3C,0x66,0x60,0x60,0x60,0x66,0x3C,0x00},
            {0x78,0x6C,0x66,0x66,0x66,0x6C,0x78,0x00},
            {0x7E,0x60,0x60,0x7C,0x60,0x60,0x7E,0x00},
            {0x7E,0x60,0x60,0x7C,0x60,0x60,0x60,0x00},
            {0x3C,0x66,0x60,0x6E,0x66,0x66,0x3C,0x00},
            {0x66,0x66,0x66,0x7E,0x66,0x66,0x66,0x00},
            {0x3C,0x18,0x18,0x18,0x18,0x18,0x3C,0x00},
            {0x1E,0x0C,0x0C,0x0C,0x0C,0x6C,0x38,0x00},
            {0x66,0x6C,0x78,0x70,0x78,0x6C,0x66,0x00},
            {0x60,0x60,0x60,0x60,0x60,0x60,0x7E,0x00},
            {0x63,0x77,0x7F,0x6B,0x63,0x63,0x63,0x00},
            {0x66,0x76,0x7E,0x7E,0x6E,0x66,0x66,0x00},
            {0x3C,0x66,0x66,0x66,0x66,0x66,0x3C,0x00},
            {0x7C,0x66,0x66,0x7C,0x60,0x60,0x60,0x00},
            {0x3C,0x66,0x66,0x66,0x6E,0x3C,0x0E,0x00},
            {0x7C,0x66,0x66,0x7C,0x78,0x6C,0x66,0x00},
            {0x3C,0x66,0x60,0x3C,0x06,0x66,0x3C,0x00},
            {0x7E,0x5A,0x18,0x18,0x18,0x18,0x3C,0x00},
            {0x66,0x66,0x66,0x66,0x66,0x66,0x3C,0x00},
            {0x66,0x66,0x66,0x66,0x66,0x3C,0x18,0x00},
            {0x63,0x63,0x63,0x6B,0x7F,0x77,0x63,0x00},
            {0x66,0x66,0x3C,0x18,0x3C,0x66,0x66,0x00},
            {0x66,0x66,0x66,0x3C,0x18,0x18,0x3C,0x00},
            {0x7E,0x06,0x0C,0x18,0x30,0x60,0x7E,0x00},
            {0x3C,0x30,0x30,0x30,0x30,0x30,0x3C,0x00},
            {0xC0,0x60,0x30,0x18,0x0C,0x06,0x03,0x00},
            {0x3C,0x0C,0x0C,0x0C,0x0C,0x0C,0x3C,0x00},
            {0x10,0x38,0x6C,0xC6,0x00,0x00,0x00,0x00},
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF},
            {0x30,0x18,0x0C,0x00,0x00,0x00,0x00,0x00},
            {0x00,0x00,0x3C,0x06,0x3E,0x66,0x3E,0x00},
            {0x60,0x60,0x7C,0x66,0x66,0x66,0x7C,0x00},
            {0x00,0x00,0x3C,0x66,0x60,0x66,0x3C,0x00},
            {0x06,0x06,0x3E,0x66,0x66,0x66,0x3E,0x00},
            {0x00,0x00,0x3C,0x66,0x7E,0x60,0x3C,0x00},
            {0x1C,0x36,0x30,0x7C,0x30,0x30,0x30,0x00},
            {0x00,0x00,0x3E,0x66,0x66,0x3E,0x06,0x7C},
            {0x60,0x60,0x7C,0x66,0x66,0x66,0x66,0x00},
            {0x18,0x00,0x38,0x18,0x18,0x18,0x3C,0x00},
            {0x06,0x00,0x0E,0x06,0x06,0x66,0x66,0x3C},
            {0x60,0x60,0x66,0x6C,0x78,0x6C,0x66,0x00},
            {0x38,0x18,0x18,0x18,0x18,0x18,0x3C,0x00},
            {0x00,0x00,0x66,0x7F,0x7F,0x6B,0x63,0x00},
            {0x00,0x00,0x7C,0x66,0x66,0x66,0x66,0x00},
            {0x00,0x00,0x3C,0x66,0x66,0x66,0x3C,0x00},
            {0x00,0x00,0x7C,0x66,0x66,0x7C,0x60,0x60},
            {0x00,0x00,0x3E,0x66,0x66,0x3E,0x06,0x06},
            {0x00,0x00,0x6C,0x76,0x60,0x60,0x60,0x00},
            {0x00,0x00,0x3E,0x60,0x3C,0x06,0x7C,0x00},
            {0x30,0x30,0x7C,0x30,0x30,0x36,0x1C,0x00},
            {0x00,0x00,0x66,0x66,0x66,0x66,0x3E,0x00},
            {0x00,0x00,0x66,0x66,0x66,0x3C,0x18,0x00},
            {0x00,0x00,0x63,0x6B,0x7F,0x7F,0x36,0x00},
            {0x00,0x00,0x66,0x3C,0x18,0x3C,0x66,0x00},
            {0x00,0x00,0x66,0x66,0x66,0x3E,0x06,0x7C},
            {0x00,0x00,0x7E,0x0C,0x18,0x30,0x7E,0x00},
            {0x0E,0x18,0x18,0x70,0x18,0x18,0x0E,0x00},
            {0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00},
            {0x70,0x18,0x18,0x0E,0x18,0x18,0x70,0x00},
            {0x32,0x4C,0x00,0x00,0x00,0x00,0x00,0x00},
            {0x00,0x10,0x38,0x6C,0xC6,0xC6,0xFE,0x00}
        };
        PHYSICAL_ADDRESS Phys;
        PUCHAR p;
        UCHAR c;
        UCHAR b;
        Phys.QuadPart = 0xA0000;
        p = (PUCHAR)MmMapIoSpace(Phys, 0x10000, MmNonCached);
        READ_PORT_UCHAR((PUCHAR)0x3DA);
        WRITE_PORT_UCHAR((PUCHAR)0x3C4, 0x00);
        WRITE_PORT_UCHAR((PUCHAR)0x3C5, 0x01);
        WRITE_PORT_UCHAR((PUCHAR)0x3C4, 0x02);
        WRITE_PORT_UCHAR((PUCHAR)0x3C5, 0x04);
        WRITE_PORT_UCHAR((PUCHAR)0x3C4, 0x04);
        WRITE_PORT_UCHAR((PUCHAR)0x3C5, 0x07);
        WRITE_PORT_UCHAR((PUCHAR)0x3C4, 0x03);
        WRITE_PORT_UCHAR((PUCHAR)0x3C5, 0x00);
        WRITE_PORT_UCHAR((PUCHAR)0x3CE, 0x04);
        WRITE_PORT_UCHAR((PUCHAR)0x3CF, 0x02);
        WRITE_PORT_UCHAR((PUCHAR)0x3CE, 0x05);
        WRITE_PORT_UCHAR((PUCHAR)0x3CF, 0x00);
        WRITE_PORT_UCHAR((PUCHAR)0x3CE, 0x06);
        WRITE_PORT_UCHAR((PUCHAR)0x3CF, 0x00);
        for (c = 1; c < 128; c++) for (b = 0; b < 8; b++) p[((ULONG)(c + 1) * 32) + b] = Font[c][b];
        WRITE_PORT_UCHAR((PUCHAR)0x3C4, 0x00);
        WRITE_PORT_UCHAR((PUCHAR)0x3C5, 0x03);
        WRITE_PORT_UCHAR((PUCHAR)0x3C4, 0x02);
        WRITE_PORT_UCHAR((PUCHAR)0x3C5, 0x03);
        WRITE_PORT_UCHAR((PUCHAR)0x3C4, 0x04);
        WRITE_PORT_UCHAR((PUCHAR)0x3C5, 0x03);
        WRITE_PORT_UCHAR((PUCHAR)0x3C4, 0x03);
        WRITE_PORT_UCHAR((PUCHAR)0x3C5, 0x00);
        WRITE_PORT_UCHAR((PUCHAR)0x3CE, 0x04);
        WRITE_PORT_UCHAR((PUCHAR)0x3CF, 0x00);
        WRITE_PORT_UCHAR((PUCHAR)0x3CE, 0x05);
        WRITE_PORT_UCHAR((PUCHAR)0x3CF, 0x10);
        WRITE_PORT_UCHAR((PUCHAR)0x3CE, 0x06);
        WRITE_PORT_UCHAR((PUCHAR)0x3CF, 0x0E);
        WRITE_PORT_UCHAR((PUCHAR)0x3D4, 0x11);
        WRITE_PORT_UCHAR((PUCHAR)0x3D5, 0x8E);
        WRITE_PORT_UCHAR((PUCHAR)0x3D4, 0x06);
        WRITE_PORT_UCHAR((PUCHAR)0x3D5, 0xBF);
        WRITE_PORT_UCHAR((PUCHAR)0x3D4, 0x07);
        WRITE_PORT_UCHAR((PUCHAR)0x3D5, 0x1F);
        WRITE_PORT_UCHAR((PUCHAR)0x3D4, 0x09);
        WRITE_PORT_UCHAR((PUCHAR)0x3D5, 0x07);
        WRITE_PORT_UCHAR((PUCHAR)0x3D4, 0x0A);
        WRITE_PORT_UCHAR((PUCHAR)0x3D5, 0x20);
        WRITE_PORT_UCHAR((PUCHAR)0x3D4, 0x0B);
        WRITE_PORT_UCHAR((PUCHAR)0x3D5, 0x20);
        WRITE_PORT_UCHAR((PUCHAR)0x3D4, 0x10);
        WRITE_PORT_UCHAR((PUCHAR)0x3D5, 0x9C);
        WRITE_PORT_UCHAR((PUCHAR)0x3D4, 0x12);
        WRITE_PORT_UCHAR((PUCHAR)0x3D5, 0x8F);
        WRITE_PORT_UCHAR((PUCHAR)0x3D4, 0x15);
        WRITE_PORT_UCHAR((PUCHAR)0x3D5, 0x96);
        WRITE_PORT_UCHAR((PUCHAR)0x3D4, 0x16);
        WRITE_PORT_UCHAR((PUCHAR)0x3D5, 0xB9);
        READ_PORT_UCHAR((PUCHAR)0x3DA);
        if (!VGABlink) {
            WRITE_PORT_UCHAR((PUCHAR)0x3C0, 0x10);
            WRITE_PORT_UCHAR((PUCHAR)0x3C0, 0x00);
            WRITE_PORT_UCHAR((PUCHAR)0x3C0, 0x20);
        }
        MmUnmapIoSpace(p, 0x10000);
    }
    else if (!VGABlink) {
        UCHAR v;
        READ_PORT_UCHAR((PUCHAR)0x3DA);
        WRITE_PORT_UCHAR((PUCHAR)0x3C0, 0x10);
        v = READ_PORT_UCHAR((PUCHAR)0x3C1);
        v &= (UCHAR)~0x08;
        READ_PORT_UCHAR((PUCHAR)0x3DA);
        WRITE_PORT_UCHAR((PUCHAR)0x3C0, 0x10);
        WRITE_PORT_UCHAR((PUCHAR)0x3C0, v);
    }
    if (VGARainbow) for (UCHAR i = 0; ; i = i == 0xF ? i = 0 : ++i) WriteVGAVideoMemory(VGAString, i, 0xF - i, VGABlink);
    else WriteVGAVideoMemory(VGAString, VGABackColor, VGAForeColor, VGABlink);
    return 0;
}
VOID RCFreeCommands()
{
    if (!g_RCListInit) return;
    while (!IsListEmpty(&g_RCCmdList)) {
        PLIST_ENTRY e = RemoveHeadList(&g_RCCmdList);
        RC_CMD_NODE* n = CONTAINING_RECORD(e, RC_CMD_NODE, ListEntry);
        ExFreePool(n);
    }
}
VOID Callback(KBUGCHECK_CALLBACK_REASON Reason, struct _KBUGCHECK_REASON_CALLBACK_RECORD* Record, PVOID Data, ULONG Length) {
    Paused = TRUE;
    if (g_RCListInit) {
        for (PLIST_ENTRY e = g_RCCmdList.Flink; e != &g_RCCmdList; e = e->Flink) {
            RC_CMD_NODE* n = CONTAINING_RECORD(e, RC_CMD_NODE, ListEntry);
            _Write(g_RCDevice, n->Buffer, n->Length);
        }
        ((VOID(*)())FindKiDisplayBlueScreen())();
    }
}
static ULONG DecodeEscapedAnsi(CHAR* text, ULONG length) {
    ULONG out = 0, i = 0;
    while (i < length) {
        if (text[i] == '\\' && i + 1 < length) {
            CHAR c = text[i + 1];
            if (c == '"') { text[out++] = '"'; i += 2; continue; }
            if (c == '\'') { text[out++] = '\''; i += 2; continue; }
            if (c == '\\') { text[out++] = '\\'; i += 2; continue; }
            if (c == 'r') { text[out++] = '\r'; i += 2; continue; }
            if (c == 'n') { text[out++] = '\n'; i += 2; continue; }
            if (c == 't') { text[out++] = '\t'; i += 2; continue; }
        }
        text[out++] = text[i++];
    }
    return out;
}
static ULONG UTF8ToUTF16(const CHAR* src, ULONG srcLen, WCHAR* dst, ULONG dstMaxChars)
{
    ULONG i = 0, j = 0;
    while (i < srcLen) {
        UCHAR c = (UCHAR)src[i];
        ULONG need;
        WCHAR wc1, wc2 = 0;
        if (c < 0x80) {
            wc1 = (WCHAR)c;
            need = 1;
            i += 1;
        }
        else if ((c & 0xE0) == 0xC0) {
            if (i + 1 >= srcLen) return (ULONG)-1;
            UCHAR c1 = (UCHAR)src[i + 1];
            if ((c1 & 0xC0) != 0x80) return (ULONG)-1;
            wc1 = (WCHAR)(((c & 0x1F) << 6) | (c1 & 0x3F));
            if (wc1 < 0x80) return (ULONG)-1;
            need = 1;
            i += 2;
        }
        else if ((c & 0xF0) == 0xE0) {
            if (i + 2 >= srcLen) return (ULONG)-1;
            UCHAR c1 = (UCHAR)src[i + 1];
            UCHAR c2 = (UCHAR)src[i + 2];
            if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80) return (ULONG)-1;
            if (c == 0xE0 && c1 < 0xA0) return (ULONG)-1;
            if (c == 0xED && c1 >= 0xA0) return (ULONG)-1;
            wc1 = (WCHAR)(((c & 0x0F) << 12) | ((c1 & 0x3F) << 6) | (c2 & 0x3F));
            if (wc1 < 0x800) return (ULONG)-1;
            need = 1;
            i += 3;
        }
        else if ((c & 0xF8) == 0xF0) {
            if (i + 3 >= srcLen) return (ULONG)-1;
            UCHAR c1 = (UCHAR)src[i + 1];
            UCHAR c2 = (UCHAR)src[i + 2];
            UCHAR c3 = (UCHAR)src[i + 3];
            if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80 || (c3 & 0xC0) != 0x80) return (ULONG)-1;
            if (c == 0xF0 && c1 < 0x90) return (ULONG)-1;
            if (c == 0xF4 && c1 >= 0x90) return (ULONG)-1;
            if (c > 0xF4) return (ULONG)-1;
            ULONG cp = ((ULONG)(c & 0x07) << 18) | ((ULONG)(c1 & 0x3F) << 12) |
                ((ULONG)(c2 & 0x3F) << 6) | (ULONG)(c3 & 0x3F);
            if (cp < 0x10000 || cp > 0x10FFFF) return (ULONG)-1;
            cp -= 0x10000;
            wc1 = (WCHAR)(0xD800 | (cp >> 10));
            wc2 = (WCHAR)(0xDC00 | (cp & 0x3FF));
            need = 2;
            i += 4;
        }
        else {
            return (ULONG)-1;
        }
        if (j + need >= dstMaxChars) return (ULONG)-1;
        dst[j++] = wc1;
        if (need == 2) dst[j++] = wc2;
    }
    if (j >= dstMaxChars) return (ULONG)-1;
    dst[j] = L'\0';
    return j;
}
NTSTATUS _Write(PDEVICE_OBJECT DeviceObject, PVOID buffer, ULONG bufLen) {
    if (!buffer || bufLen < 3 || ((CHAR*)buffer)[bufLen - 1] != '\0') { LogPrintf(77, 0, "Invalid Parameter (in _Write)"); return STATUS_INVALID_PARAMETER; }
    else {
        CHAR* p = (CHAR*)buffer;
        LogPrintf(77, 0, "\nReceived Command!\nCommand Address: %p\nCommand:\n\n%s\n\n", p, p);
        if (p[0] == 'S' && p[1] == 'P' && p[2] == ' ') { //Stop Code String
            p = (CHAR*)buffer + 3;
            ULONG decodedSpLen = DecodeEscapedAnsi(p, (ULONG)strlen(p));
            p[decodedSpLen] = '\0';
            PWCHAR pUni = NULL;
            if (NT_SUCCESS(ConvertCharToPwchar(p, &pUni))) {
                PVOID pKiDisplayBlueScreen = FindKiDisplayBlueScreen();
                if (pKiDisplayBlueScreen && winver == WIN_7) {
                    unsigned char pattern[] = { 0x48, 0x8B, 0x05, 0x0E, 0x7A, 0x11, 0x00, 0x4C, 0x8B, 0x1D, 0x0F, 0x7A, 0x11, 0x00, 0x44, 0x8B, 0x0D, 0xE8, 0x79, 0x11, 0x00, 0x4C, 0x89, 0x5C, 0x24, 0x38, 0x48, 0x89, 0x44, 0x24, 0x30, 0x48, 0x8B, 0x05, 0xE7, 0x79, 0x11, 0x00, 0x4C, 0x8D, 0x05, 0x70, 0x44, 0xF5, 0xFF, 0x48, 0x8D, 0x4C, 0x24, 0x40, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0x8B, 0x05, 0xC7, 0x79, 0x11, 0x00, 0x48, 0x8B, 0xD7, 0x48, 0x89, 0x44, 0x24, 0x20, 0xE8, 0x02, 0xF4, 0xF8, 0xFF, 0x48, 0x8D, 0x4C, 0x24, 0x40 };
                    unsigned char mov[10] = { 0x48, 0xB9 };
                    unsigned char stopcode[sizeof(pattern) / sizeof(unsigned char)] = { 0 };
                    for (ULONG i = 0; i < (sizeof(pattern) / sizeof(unsigned char) - sizeof(mov) / sizeof(unsigned char)); i++) stopcode[i] = 0x90;
                    char* stopcodetext = (char*)ExAllocatePoolWithTag(NonPagedPool, decodedSpLen + 1, 'StcA');
                    if (!stopcodetext) return STATUS_INSUFFICIENT_RESOURCES;
                    RtlCopyMemory(stopcodetext, p, decodedSpLen + 1);
                    *(ULONG_PTR*)&mov[2] = (ULONG_PTR)stopcodetext;
                    RtlMoveMemory(stopcode + (sizeof(pattern) / sizeof(unsigned char) - sizeof(mov) / sizeof(unsigned char)), mov, sizeof(mov) / sizeof(unsigned char));
                    ULONG_PTR StopcodeAddress = FindAddress(pKiDisplayBlueScreen, pattern, 0x10000, sizeof(pattern) / sizeof(unsigned char));
                    ULONG patternLen = sizeof(pattern) / sizeof(unsigned char);
                    SIZE_T origSize = patternLen;
                    PUCHAR origWin7 = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, origSize, 'Ogn7');
                    if (origWin7) ReadMemory((PVOID)StopcodeAddress, origWin7, origSize);
                    __writecr0(__readcr0() & (~(1 << 16)));
                    RtlMoveMemory((void*)StopcodeAddress, stopcode, sizeof(pattern) / sizeof(unsigned char));
                    __writecr0(__readcr0() | (1 << 16));
                    if (origWin7) {
                        g_Win7StopCodeHookTarget = (PVOID)StopcodeAddress;
                        g_Win7StopCodeOrigCode = origWin7;
                        g_Win7StopCodeOrigSize = origSize;
                        g_Win7StopCodeHooked = TRUE;
                    }
                }
                else {
                    if (winver > WIN_7 && winver < WIN_11_24H2_NEW) InstallKeGetBugMessageTextHook(FindKeGetBugMessageText(), pUni, wcslen(pUni) + 1);
                    else {
                        ULONG Offset = 0;
                        if (winver == WIN_11_24H2_NEW || winver == WIN_11_25H2) Offset = 0x22E;
                        else if (winver == WIN_11_26H1) Offset = 0x222;
                        else if (winver == WIN_11_27H2) Offset = 0x211;
                        if (!NT_SUCCESS(InstallBcpDisplayErrorInformationModernizedHook((PVOID)((ULONG64)g_BcpDisplayErrorInformationModernized + Offset), pUni, wcslen(pUni) + 1))) InstallKeGetBugMessageTextHook(FindKeGetBugMessageText(), pUni, wcslen(pUni) + 1);
                    }
                }
            }
        }
        else if (p[0] == 'W' && p[1] == 'F' && p[2] == ' ') { //What Failed String
            p = (CHAR*)buffer + 3;
            ULONG decodedWfLen = DecodeEscapedAnsi(p, (ULONG)strlen(p));
            p[decodedWfLen] = '\0';
            PWCHAR pUni = NULL;
            if (NT_SUCCESS(ConvertCharToPwchar(p, &pUni))) {
                g_WhatFailedUnicodeString = ExAllocatePool(NonPagedPool, sizeof(UNICODE_STRING));
                PUNICODE_STRING pString = (PUNICODE_STRING)g_WhatFailedUnicodeString;
                if (pString) {
                    RtlInitUnicodeString(pString, pUni);
                    g_WhatFailedString = pUni;
                    PVOID pKiBugCheckDriver = FindKiBugCheckDriver();
                    WriteMemory(pKiBugCheckDriver, &pString, sizeof(PVOID));
                    ULONG Offset = 0;
                    UCHAR nop[5];
                    RtlFillMemory(nop, 5, 0x90);
                    if (winver == WIN_7) Offset = 0x1EB;
                    else if (winver == WIN_8) Offset = 0xB1;
                    else if (winver >= WIN_10 && winver <= WIN_11_25H2) Offset = 0xDE;
                    else if (winver == WIN_11_26H1) Offset = 0xDA;
                    else if (winver == WIN_11_27H2) Offset = 0xDD;
                    PVOID Address = (PVOID)((ULONG64)FindKiDisplayBlueScreen() + Offset);
                    g_WhatFailedCallAddress = Address;
                    ReadMemory(Address, g_WhatFailedCallInstruction, 5);
                    WriteMemory(Address, nop, 5);
                }
            }
        }
        else if (p[0] == 'C' && p[1] == 'R' && p[2] == ' ') { //ChangeBackColor
            p = (CHAR*)buffer + 3;
            ULONG64 color;
            sscanf_s(p, "%llu", &color);
            InstallBgpClearScreenHook(g_BgpClearScreen, color);
        }
        else if (p[0] == 'C' && p[1] == 'C' && p[2] == ' ') { //ChangeTextColor
            p = (CHAR*)buffer + 3;
            ULONG backColor, foreColor;
            sscanf_s(p, "%lu %lu", &backColor, &foreColor);
            InstallBgpTxtDisplayCharacterHook(g_BgpTxtDisplayCharacter, backColor, foreColor);
        }
        else if (p[0] == 'C' && p[1] == 'T' && p[2] == ' ') {
            CHAR* cur = p + 3;
            CHAR* end = (CHAR*)buffer + bufLen;
            while (cur < end && (*cur == ' ' || *cur == '\t')) ++cur;
            ULONG mode = 0;
            if (cur < end && *cur >= '0' && *cur <= '7') {
                mode = (ULONG)(*cur - '0');
                ++cur;
            }
            const ULONG maxArgs = 1024;
            PWSTR* args = (PWSTR*)ExAllocatePoolWithTag(NonPagedPool, (maxArgs + 1) * sizeof(PWSTR), 'StcA');
            if (!args) return STATUS_INSUFFICIENT_RESOURCES;
            RtlZeroMemory(args, (maxArgs + 1) * sizeof(PWSTR));
            ULONG argc = 0;
            NTSTATUS textStatus = STATUS_SUCCESS;
            while (cur < end && *cur) {
                while (cur < end && (*cur == ' ' || *cur == '\t')) ++cur;
                if (cur >= end || !*cur) break;
                if (*cur != '"') { textStatus = STATUS_INVALID_PARAMETER; break; }
                ++cur;
                CHAR* token = cur;
                while (cur < end && *cur && *cur != '"') {
                    if (*cur == '\\' && cur + 1 < end) cur += 2;
                    else ++cur;
                }
                if (cur >= end || *cur != '"') {
                    textStatus = STATUS_INVALID_PARAMETER;
                    break;
                }
                SIZE_T length = (SIZE_T)DecodeEscapedAnsi(token, (ULONG)(cur - token));
                if (argc >= maxArgs || length > 32760) {
                    textStatus = STATUS_BUFFER_OVERFLOW;
                    break;
                }
                PWSTR value = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, (length + 1) * sizeof(WCHAR), 'StcA');
                if (!value) { textStatus = STATUS_INSUFFICIENT_RESOURCES; break; }
                ULONG out = UTF8ToUTF16(token, (ULONG)length, value, (ULONG)length + 1);
                if (out == (ULONG)-1) {
                    ExFreePoolWithTag(value, 'StcA');
                    textStatus = STATUS_INVALID_PARAMETER;
                    break;
                }
                args[argc++] = value;
                ++cur;
            }
            if (NT_SUCCESS(textStatus)) {
                if (!argc) textStatus = STATUS_INVALID_PARAMETER;
                else {
                    textStatus = InstallBcpDisplayCriticalStringHook(g_BcpDisplayCriticalString, mode, args[0], argc > 1 ? args + 1 : NULL);
                    if (textStatus == STATUS_INVALID_PARAMETER_1) textStatus = InstallBcpDisplayCriticalStringHook(g_BcpDisplayCriticalStringCentered, mode, args[0], argc > 1 ? args + 1 : NULL);
                }
            }
            for (ULONG i = 0; i < argc; ++i) if (args[i]) ExFreePoolWithTag(args[i], 'StcA');
            ExFreePoolWithTag(args, 'StcA');
            return textStatus;
        }
        else if (p[0] == 'D' && p[1] == 'S' && p[2] == ' ') { //DisplayString & DisplayImage
            CHAR* cmd = p + 3;
            BOOLEAN loop = FALSE;
            while (*cmd == ' ' || *cmd == '\t') cmd++;
            if (*cmd == 'L') { loop = TRUE; cmd++; }
            if (*cmd == '{') cmd++;
            if (winver == WIN_7) loop = FALSE;
            struct _OP_NODE {
                LIST_ENTRY ListEntry;
                UCHAR Type;
                union {
                    struct {
                        CHAR* Str;
                        ULONG TextSize;
                        ULONG TbackColor;
                        ULONG TforeColor;
                        ULONG64 BgColor;
                        ULONG X, Y;
                        BOOLEAN ClearScreen;
                        BOOLEAN IsWin7;
                        ULONG Win7BackColor;
                        ULONG Win7ForeColor;
                        BOOLEAN Win7Blink;
                        BOOLEAN Win7Vga80x25;
                        BOOLEAN Win7Rainbow;
                    } StringOp;
                    struct {
                        ULONG* ImageData;
                        ULONG Count;
                        ULONG64 BgColor;
                        ULONG X, Y, W, H;
                        BOOLEAN ClearScreen;
                    } ImageOp;
                    struct {
                        ULONGLONG Milliseconds;
                    } SleepOp;
                };
            };
            LIST_ENTRY opListHead;
            InitializeListHead(&opListHead);
            BOOLEAN parseError = FALSE;
            while (*cmd && *cmd != '}') {
                while (*cmd == ' ' || *cmd == '\t') cmd++;
                if (*cmd == '\0' || *cmd == '}') break;
                struct _OP_NODE* node = (struct _OP_NODE*)ExAllocatePoolWithTag(NonPagedPool, sizeof(struct _OP_NODE), 'OpNd');
                if (!node) return STATUS_INSUFFICIENT_RESOURCES;
                RtlZeroMemory(node, sizeof(struct _OP_NODE));
                InsertTailList(&opListHead, &node->ListEntry);
                if (cmd[0] == 'S' && cmd[1] == 'L') {
                    node->Type = 3;
                    cmd += 2;
                    while (*cmd == ' ' || *cmd == '\t') cmd++;
                    ULONGLONG ms = 0;
                    BOOLEAN hasDigit = FALSE;
                    while (*cmd >= '0' && *cmd <= '9') {
                        hasDigit = TRUE;
                        ms = ms * 10 + (ULONGLONG)(*cmd - '0');
                        if (ms > 4294967) ms = 4294967;
                        cmd++;
                    }
                    if (!hasDigit) { parseError = TRUE; break; }
                    node->SleepOp.Milliseconds = ms;
                    while (*cmd && *cmd != ',' && *cmd != '}') cmd++;
                    if (*cmd == ',') cmd++;
                    continue;
                }
                if (*cmd == '"') {
                    node->Type = 1;
                    CHAR* strStart = cmd + 1;
                    CHAR* strEnd = strStart;
                    while (*strEnd && *strEnd != '"') {
                        if (*strEnd == '\\' && strEnd[1]) strEnd++;
                        strEnd++;
                    }
                    if (*strEnd != '"') { parseError = TRUE; break; }
                    ULONG strLen = (ULONG)DecodeEscapedAnsi(strStart, (ULONG)(strEnd - strStart));
                    CHAR* ansiStr = (CHAR*)ExAllocatePoolWithTag(NonPagedPool, strLen + 1, 'DSpA');
                    if (!ansiStr) return STATUS_INSUFFICIENT_RESOURCES;
                    RtlCopyMemory(ansiStr, strStart, strLen);
                    ansiStr[strLen] = '\0';
                    node->StringOp.Str = ansiStr;
                    CHAR* numStart = strEnd + 1;
                    while (*numStart == ' ' || *numStart == '\t') numStart++;
                    if (winver == WIN_7) {
                        node->StringOp.IsWin7 = TRUE;
                        ULONG backColor, foreColor, blink, vga80x25, rainbow;
                        int converted = sscanf_s(numStart, "%x %x %x %x %x", &backColor, &foreColor, &blink, &vga80x25, &rainbow);
                        if (converted != 5) {
                            parseError = TRUE;
                            break;
                        }
                        node->StringOp.Win7BackColor = backColor;
                        node->StringOp.Win7ForeColor = foreColor;
                        node->StringOp.Win7Blink = (BOOLEAN)blink;
                        node->StringOp.Win7Vga80x25 = (BOOLEAN)vga80x25;
                        node->StringOp.Win7Rainbow = (BOOLEAN)rainbow;
                    }
                    else {
                        node->StringOp.IsWin7 = FALSE;
                        ULONG TextSize, TbackColor, TforeColor, X, Y;
                        ULONG64 backgroundColor;
                        BOOLEAN ClearScreen;
                        int converted = sscanf_s(numStart, "%x %x %x %llx %x %x %u", &TextSize, &TbackColor, &TforeColor, &backgroundColor, &X, &Y, &ClearScreen);
                        if (converted != 7) {
                            parseError = TRUE;
                            break;
                        }
                        node->StringOp.TextSize = TextSize;
                        node->StringOp.TbackColor = TbackColor;
                        node->StringOp.TforeColor = TforeColor;
                        node->StringOp.BgColor = backgroundColor;
                        node->StringOp.X = X;
                        node->StringOp.Y = Y;
                        node->StringOp.ClearScreen = (BOOLEAN)ClearScreen;
                    }
                    cmd = numStart;
                    while (*cmd && *cmd != ',' && *cmd != '}') cmd++;
                    if (*cmd == ',') cmd++;
                    continue;
                }
                if (*cmd == '[') {
                    node->Type = 2;
                    CHAR* bracketStart = cmd + 1;
                    CHAR* bracketEnd = bracketStart;
                    while (*bracketEnd && *bracketEnd != ']') bracketEnd++;
                    if (*bracketEnd != ']') {
                        parseError = TRUE;
                        break;
                    }
                    ULONG count = 1;
                    for (CHAR* tmp = bracketStart; tmp < bracketEnd; tmp++) if (*tmp == ',') count++;
                    ULONG* image = (ULONG*)ExAllocatePoolWithTag(NonPagedPool, count * sizeof(ULONG), 'DImg');
                    if (!image) return STATUS_INSUFFICIENT_RESOURCES;
                    BOOLEAN arrayOk = TRUE;
                    ULONG index = 0;
                    CHAR* pNum = bracketStart;
                    while (pNum < bracketEnd) {
                        while (pNum < bracketEnd && (*pNum == ' ' || *pNum == '\t')) pNum++;
                        if (pNum >= bracketEnd) break;
                        if (!((*pNum >= '0' && *pNum <= '9') || (*pNum >= 'a' && *pNum <= 'f') || (*pNum >= 'A' && *pNum <= 'F'))) {
                            arrayOk = FALSE;
                            break;
                        }
                        ULONG value = 0;
                        while (pNum < bracketEnd) {
                            if (*pNum >= '0' && *pNum <= '9') value = (value << 4) | (ULONG)(*pNum - '0');
                            else if (*pNum >= 'a' && *pNum <= 'f') value = (value << 4) | (ULONG)(*pNum - 'a' + 10);
                            else if (*pNum >= 'A' && *pNum <= 'F') value = (value << 4) | (ULONG)(*pNum - 'A' + 10);
                            else break;
                            pNum++;
                        }
                        if (index >= count) {
                            arrayOk = FALSE;
                            break;
                        }
                        image[index++] = value;
                        while (pNum < bracketEnd && (*pNum == ' ' || *pNum == '\t')) pNum++;
                        if (index < count) {
                            if (pNum >= bracketEnd || *pNum != ',') {
                                arrayOk = FALSE;
                                break;
                            }
                            pNum++;
                        }
                        else {
                            if (pNum != bracketEnd) {
                                arrayOk = FALSE;
                                break;
                            }
                        }
                    }
                    if (!arrayOk || index != count) {
                        ExFreePoolWithTag(image, 'DImg');
                        parseError = TRUE;
                        break;
                    }
                    CHAR* paramStart = bracketEnd + 1;
                    while (*paramStart == ' ' || *paramStart == '\t') paramStart++;
                    ULONG64 imgBgColor = 0;
                    ULONG imgX = 0, imgY = 0, imgW = 0, imgH = 0;
                    ULONG imgClearScreen = 0;
                    int converted = sscanf_s(paramStart, "%llx %x %x %x %x %u", &imgBgColor, &imgX, &imgY, &imgW, &imgH, &imgClearScreen);
                    if (converted != 6) {
                        ExFreePoolWithTag(image, 'DImg');
                        parseError = TRUE;
                        break;
                    }
                    ULONG* imgCopy = (ULONG*)ExAllocatePoolWithTag(NonPagedPool, count * sizeof(ULONG), 'ImgC');
                    if (!imgCopy) {
                        ExFreePoolWithTag(image, 'DImg');
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                    RtlCopyMemory(imgCopy, image, count * sizeof(ULONG));
                    ExFreePoolWithTag(image, 'DImg');
                    node->ImageOp.ImageData = imgCopy;
                    node->ImageOp.Count = count;
                    node->ImageOp.BgColor = imgBgColor;
                    node->ImageOp.X = imgX;
                    node->ImageOp.Y = imgY;
                    node->ImageOp.W = imgW;
                    node->ImageOp.H = imgH;
                    node->ImageOp.ClearScreen = (BOOLEAN)imgClearScreen;
                    cmd = paramStart;
                    while (*cmd && *cmd != ',' && *cmd != '}') cmd++;
                    if (*cmd == ',') cmd++;
                    continue;
                }
                parseError = TRUE;
                break;
            }
            if (parseError || !cmd || *cmd != '}') {
                while (!IsListEmpty(&opListHead)) {
                    PLIST_ENTRY entry = RemoveHeadList(&opListHead);
                    struct _OP_NODE* node = CONTAINING_RECORD(entry, struct _OP_NODE, ListEntry);
                    if (node->Type == 1) if (node->StringOp.Str) ExFreePoolWithTag(node->StringOp.Str, 'DSpA');
                    else if (node->Type == 2) if (node->ImageOp.ImageData) ExFreePoolWithTag(node->ImageOp.ImageData, 'ImgC');
                    ExFreePoolWithTag(node, 'OpNd');
                }
                return STATUS_INVALID_PARAMETER;
            }
            if (!loop) {
                PLIST_ENTRY entry;
                for (entry = opListHead.Flink; entry != &opListHead; entry = entry->Flink) {
                    struct _OP_NODE* node = CONTAINING_RECORD(entry, struct _OP_NODE, ListEntry);
                    if (node->Type == 1) {
                        if (node->StringOp.IsWin7) {
                            CHAR* ansi = (CHAR*)ExAllocatePoolWithTag(NonPagedPool, strlen(node->StringOp.Str) + 1, 'DSpA');
                            if (ansi) {
                                RtlCopyMemory(ansi, node->StringOp.Str, strlen(node->StringOp.Str) + 1);
                                VGAString = (UCHAR*)ansi;
                                VGABackColor = node->StringOp.Win7BackColor;
                                VGAForeColor = node->StringOp.Win7ForeColor;
                                VGABlink = node->StringOp.Win7Blink;
                                VGA80x25 = node->StringOp.Win7Vga80x25;
                                VGARainbow = node->StringOp.Win7Rainbow;
                                KeIpiGenericCall(Disable, 0);
                                InbvAcquireDisplayOwnership();
                                KeIpiGenericCall(Display, 0);
                                ExFreePoolWithTag(VGAString, 'DSpA');
                                VGAString = NULL;
                            }
                        }
                        else {
                            CHAR* ansi = (CHAR*)ExAllocatePoolWithTag(NonPagedPool, strlen(node->StringOp.Str) + 1, 'DSpA');
                            if (ansi) {
                                RtlCopyMemory(ansi, node->StringOp.Str, strlen(node->StringOp.Str) + 1);
                                ULONG srcLen = (ULONG)strlen(ansi);
                                PWCHAR wstr = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, (srcLen + 1) * sizeof(WCHAR), 'DSpW');
                                if (wstr) {
                                    ULONG wlen = UTF8ToUTF16(ansi, srcLen, wstr, srcLen + 1);
                                    if (wlen != (ULONG)-1) DisplayString(wstr, node->StringOp.TextSize, node->StringOp.TbackColor, node->StringOp.TforeColor, node->StringOp.BgColor, node->StringOp.X, node->StringOp.Y, node->StringOp.ClearScreen);
                                    ExFreePoolWithTag(wstr, 'DSpW');
                                }
                                ExFreePoolWithTag(ansi, 'DSpA');
                            }
                        }
                    }
                    else if (node->Type == 2) {
                        ULONG* imgCopy = (ULONG*)ExAllocatePoolWithTag(NonPagedPool, node->ImageOp.Count * sizeof(ULONG), 'ImgD');
                        if (imgCopy) {
                            RtlCopyMemory(imgCopy, node->ImageOp.ImageData, node->ImageOp.Count * sizeof(ULONG));
                            DisplayImage(imgCopy, node->ImageOp.BgColor, node->ImageOp.X, node->ImageOp.Y, node->ImageOp.W, node->ImageOp.H, node->ImageOp.ClearScreen);
                            ExFreePoolWithTag(imgCopy, 'ImgD');
                        }
                    }
                    else if (node->Type == 3) {
                        ULONGLONG stallUs = node->SleepOp.Milliseconds * 1000;
                        if (stallUs > 0xFFFFFFFFULL) stallUs = 0xFFFFFFFFULL;
                        KeStallExecutionProcessor((ULONG)stallUs);
                    }
                }
                while (!IsListEmpty(&opListHead)) {
                    PLIST_ENTRY entry = RemoveHeadList(&opListHead);
                    struct _OP_NODE* node = CONTAINING_RECORD(entry, struct _OP_NODE, ListEntry);
                    if (node->Type == 1) {
                        if (node->StringOp.Str) ExFreePoolWithTag(node->StringOp.Str, 'DSpA');
                    }
                    else if (node->Type == 2) {
                        if (node->ImageOp.ImageData) ExFreePoolWithTag(node->ImageOp.ImageData, 'ImgC');
                    }
                    ExFreePoolWithTag(node, 'OpNd');
                }
                KeIpiGenericCall(Disable, 0);
                KeIpiGenericCall(Freeze, 0);
            }
            else {
                while (TRUE) {
                    PLIST_ENTRY entry;
                    for (entry = opListHead.Flink; entry != &opListHead; entry = entry->Flink) {
                        struct _OP_NODE* node = CONTAINING_RECORD(entry, struct _OP_NODE, ListEntry);
                        if (node->Type == 1) {
                            if (node->StringOp.IsWin7) {
                                CHAR* ansi = (CHAR*)ExAllocatePoolWithTag(NonPagedPool, strlen(node->StringOp.Str) + 1, 'DSpA');
                                if (ansi) {
                                    RtlCopyMemory(ansi, node->StringOp.Str, strlen(node->StringOp.Str) + 1);
                                    VGAString = (UCHAR*)ansi;
                                    VGABackColor = node->StringOp.Win7BackColor;
                                    VGAForeColor = node->StringOp.Win7ForeColor;
                                    VGABlink = node->StringOp.Win7Blink;
                                    VGA80x25 = node->StringOp.Win7Vga80x25;
                                    VGARainbow = node->StringOp.Win7Rainbow;
                                    KeIpiGenericCall(Disable, 0);
                                    KeIpiGenericCall(Display, 0);
                                    ExFreePoolWithTag(VGAString, 'DSpA');
                                    VGAString = NULL;
                                }
                            }
                            else {
                                CHAR* ansi = (CHAR*)ExAllocatePoolWithTag(NonPagedPool, strlen(node->StringOp.Str) + 1, 'DSpA');
                                if (ansi) {
                                    RtlCopyMemory(ansi, node->StringOp.Str, strlen(node->StringOp.Str) + 1);
                                    ULONG srcLen = (ULONG)strlen(ansi);
                                    PWCHAR wstr = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, (srcLen + 1) * sizeof(WCHAR), 'DSpW');
                                    if (wstr) {
                                        ULONG wlen = UTF8ToUTF16(ansi, srcLen, wstr, srcLen + 1);
                                        if (wlen != (ULONG)-1) DisplayString(wstr, node->StringOp.TextSize, node->StringOp.TbackColor, node->StringOp.TforeColor, node->StringOp.BgColor, node->StringOp.X, node->StringOp.Y, node->StringOp.ClearScreen);
                                        ExFreePoolWithTag(wstr, 'DSpW');
                                    }
                                    ExFreePoolWithTag(ansi, 'DSpA');
                                }
                            }
                        }
                        else if (node->Type == 2) {
                            ULONG* imgCopy = (ULONG*)ExAllocatePoolWithTag(NonPagedPool, node->ImageOp.Count * sizeof(ULONG), 'ImgD');
                            if (imgCopy) {
                                RtlCopyMemory(imgCopy, node->ImageOp.ImageData, node->ImageOp.Count * sizeof(ULONG));
                                DisplayImage(imgCopy, node->ImageOp.BgColor, node->ImageOp.X, node->ImageOp.Y, node->ImageOp.W, node->ImageOp.H, node->ImageOp.ClearScreen);
                                ExFreePoolWithTag(imgCopy, 'ImgD');
                            }
                        }
                        else if (node->Type == 3) {
                            ULONGLONG stallUs = node->SleepOp.Milliseconds * 1000;
                            if (stallUs > 0xFFFFFFFFULL) stallUs = 0xFFFFFFFFULL;
                            KeStallExecutionProcessor((ULONG)stallUs);
                        }
                    }
                }
            }
        }
        else if (p[0] == 'C' && p[1] == '7' && p[2] == ' ') { //ChangeColor For Windows7
            p = (CHAR*)buffer + 3;
            sscanf_s(p, "%lu %lu", &foreColor, &backColor);
            if (CallbackRegistered) KeDeregisterBugCheckReasonCallback(&CallbackRecord);
            CallbackRecord.State = 0;
            KeRegisterBugCheckReasonCallback(&CallbackRecord, (PKBUGCHECK_REASON_CALLBACK_ROUTINE)ChangeBSODColor, KbCallbackReserved1, (PUCHAR)"BSOD");
            CallbackRegistered = TRUE;
        }
        else if (p[0] == 'R' && p[1] == '7') { //RainbowBSOD For Windows7
            if (CallbackRegistered) KeDeregisterBugCheckReasonCallback(&CallbackRecord);
            CallbackRecord.State = 0;
            KeRegisterBugCheckReasonCallback(&CallbackRecord, (PKBUGCHECK_REASON_CALLBACK_ROUTINE)RainbowBSOD, KbCallbackReserved1, (PUCHAR)"BSOD");
            CallbackRegistered = TRUE;
        }
        else if (p[0] == 'R' && p[1] == 'D') { //RainbowBSOD
            InstallBgpTxtDisplayCharacterHook(g_BgpTxtDisplayCharacter, 0x00000000, 0xFFFFFFFF);
            InstallBgpClearScreenHook(g_BgpClearScreen, 0x0000000000000000);
            if (g_WhatFailedCallAddress && g_WhatFailedCallInstruction) WriteMemory(g_WhatFailedCallAddress, g_WhatFailedCallInstruction, 5);
            if (Paused) Thread(0);
            HANDLE hThread = NULL;
            PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr, Thread, nullptr);
        }
        else if (p[0] == 'Q' && p[1] == 'R' && p[2] == ' ') { //QrCode
            NTSTATUS status = STATUS_SUCCESS;
            CHAR* cur = p + 3;
            CHAR* end = (CHAR*)buffer + bufLen;
            ULONG x = 0, y = 0;
            ULONG maxCount = OriginalSrc.W * OriginalSrc.H;
            ULONG count = 0;
            ULONG index = 0;
            PULONG pixeldata = NULL;
            while (cur < end && (*cur == ' ' || *cur == '\t' || *cur == '\r' || *cur == '\n')) ++cur;
            if (cur >= end) return STATUS_INVALID_PARAMETER;
            if (cur[0] == '0' && (cur[1] == 'x' || cur[1] == 'X')) cur += 2;
            if (cur >= end || !((*cur >= '0' && *cur <= '9') || (*cur >= 'a' && *cur <= 'f') || (*cur >= 'A' && *cur <= 'F'))) return STATUS_INVALID_PARAMETER;
            ULONG64 vx = 0;
            while (cur < end && ((*cur >= '0' && *cur <= '9') || (*cur >= 'a' && *cur <= 'f') || (*cur >= 'A' && *cur <= 'F'))) {
                CHAR c = *cur;
                ULONG digit;
                if (c >= '0' && c <= '9') digit = (ULONG)(c - '0');
                else if (c >= 'a' && c <= 'f') digit = (ULONG)(c - 'a' + 10);
                else digit = (ULONG)(c - 'A' + 10);
                if (vx > (0xFFFFFFFFULL - digit) / 16) return STATUS_INVALID_PARAMETER;
                vx = (vx << 4) | digit;
                ++cur;
            }
            x = (ULONG)vx;
            while (cur < end && (*cur == ' ' || *cur == '\t' || *cur == '\r' || *cur == '\n')) ++cur;
            if (cur >= end) return STATUS_INVALID_PARAMETER;
            if (cur[0] == '0' && (cur[1] == 'x' || cur[1] == 'X')) cur += 2;
            if (cur >= end || !((*cur >= '0' && *cur <= '9') || (*cur >= 'a' && *cur <= 'f') || (*cur >= 'A' && *cur <= 'F'))) return STATUS_INVALID_PARAMETER;
            ULONG64 vy = 0;
            while (cur < end && ((*cur >= '0' && *cur <= '9') || (*cur >= 'a' && *cur <= 'f') || (*cur >= 'A' && *cur <= 'F'))) {
                CHAR c = *cur;
                ULONG digit;
                if (c >= '0' && c <= '9') digit = (ULONG)(c - '0');
                else if (c >= 'a' && c <= 'f') digit = (ULONG)(c - 'a' + 10);
                else digit = (ULONG)(c - 'A' + 10);
                if (vy > (0xFFFFFFFFULL - digit) / 16) return STATUS_INVALID_PARAMETER;
                vy = (vy << 4) | digit;
                ++cur;
            }
            y = (ULONG)vy;
            if ((ULONG64)x * (ULONG64)y != maxCount) return STATUS_SUCCESS;
            while (cur < end && (*cur == ' ' || *cur == '\t' || *cur == '\r' || *cur == '\n')) ++cur;
            if (cur >= end || *cur != '{') return STATUS_INVALID_PARAMETER;
            ++cur;
            CHAR* scan = cur;
            while (scan < end && *scan != '}') {
                while (scan < end && (*scan == ' ' || *scan == '\t' || *scan == '\r' || *scan == '\n' || *scan == ',')) {
                    ++scan;
                }
                if (scan >= end || *scan == '}') break;
                CHAR* tokenStart = scan;
                while (scan < end && *scan != ',' && *scan != '}' &&
                    *scan != ' ' && *scan != '\t' && *scan != '\r' && *scan != '\n') {
                    ++scan;
                }
                if (scan == tokenStart) return STATUS_INVALID_PARAMETER;
                ++count;
            }
            if (count > maxCount) return STATUS_INVALID_PARAMETER;
            pixeldata = (PULONG)ExAllocatePoolWithTag(NonPagedPool, maxCount * sizeof(ULONG), 'QrPt');
            if (!pixeldata) return STATUS_INSUFFICIENT_RESOURCES;
            RtlZeroMemory(pixeldata, maxCount * sizeof(ULONG));
            scan = cur;
            while (scan < end && *scan != '}' && index < count) {
                while (scan < end && (*scan == ' ' || *scan == '\t' || *scan == '\r' || *scan == '\n' || *scan == ',')) {
                    ++scan;
                }
                if (scan >= end || *scan == '}') break;
                CHAR* tokenStart = scan;
                while (scan < end && *scan != ',' && *scan != '}' &&
                    *scan != ' ' && *scan != '\t' && *scan != '\r' && *scan != '\n') {
                    ++scan;
                }
                if (scan == tokenStart) {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                if ((scan - tokenStart) >= 2 &&
                    tokenStart[0] == '0' &&
                    (tokenStart[1] == 'x' || tokenStart[1] == 'X')) {
                    tokenStart += 2;
                }
                if (tokenStart >= scan) {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                ULONG64 value = 0;
                BOOLEAN valid = TRUE;
                for (CHAR* s = tokenStart; s < scan; ++s) {
                    CHAR c = *s;
                    ULONG digit;
                    if (c >= '0' && c <= '9') digit = (ULONG)(c - '0');
                    else if (c >= 'a' && c <= 'f') digit = (ULONG)(c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') digit = (ULONG)(c - 'A' + 10);
                    else {
                        valid = FALSE;
                        break;
                    }
                    if (value > (0xFFFFFFFFULL - digit) / 16) {
                        valid = FALSE;
                        break;
                    }
                    value = (value << 4) | digit;
                }
                if (!valid) {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                pixeldata[index++] = (ULONG)value;
            }
            if (NT_SUCCESS(status) && index != count) status = STATUS_INVALID_PARAMETER;
            if (!NT_SUCCESS(status)) {
                if (pixeldata) {
                    ExFreePoolWithTag(pixeldata, 'QrPt');
                }
                return status;
            }
            GP_RECT_DESC data;
            data.H = x;
            data.W = y;
            data.BitsPerPixel = 0x20;
            data.Stride = OriginalSrc.Stride;
            data.Flags = 0;
            data.Padding = 0;
            data.PixelData = pixeldata;
            InstallBgpFwDisplayBugCheckScreenHook(FindBgpFwDisplayBugCheckScreen(), &data, maxCount * sizeof(ULONG));
        }
        else if (p[0] == 'F' && p[1] == 'R' && p[2] == ' ') { //FeatureEnabledBsodRejuvenation
            p = (CHAR*)buffer + 3;
            UCHAR BSOD = 0;
            sscanf_s(p, "%hhx", &BSOD);
            WriteMemory(FindFeatureEnabledBsodRejuvenation(), &BSOD, 1);
        }
        else if (p[0] == 'U' && p[1] == 'U' && p[2] == ' ') { //Uninstall all hooks during DriverUnload
            p = (CHAR*)buffer + 3;
            UCHAR Uninstall = 0;
            sscanf_s(p, "%hhx", &Uninstall);
            g_UninstallAllHooksDuringDriverUnload = Uninstall;
        }
        else if (p[0] == 'R' && p[1] == 'C' && p[2] == ' ') { //Register BugCheck Callback
            CHAR* cur = (CHAR*)buffer + 3;
            CHAR* end = (CHAR*)buffer + bufLen;
            NTSTATUS st = STATUS_SUCCESS;
            if (g_RCRegistered) {
                KeDeregisterBugCheckReasonCallback(&g_RCRecord);
                g_RCRegistered = FALSE;
            }
            if (!g_RCListInit) {
                InitializeListHead(&g_RCCmdList);
                g_RCListInit = TRUE;
            }
            else RCFreeCommands();
            while (cur < end && *cur != '\0') {
                while (cur < end && (*cur == ' ' || *cur == '\t' || *cur == '\r' || *cur == '\n')) ++cur;
                if (cur >= end || *cur == '\0') break;
                if (*cur != '"') { st = STATUS_INVALID_PARAMETER; break; }
                ++cur;
                CHAR* start = cur;
                while (cur < end && *cur != '\0') {
                    if (*cur == '\\' && cur + 1 < end && (cur[1] == '"' || cur[1] == '\'' || cur[1] == '\\' || cur[1] == 'r' || cur[1] == 'n' || cur[1] == 't')) { cur += 2; continue; }
                    if (*cur == '"') break;
                    ++cur;
                }
                if (cur >= end || *cur != '"') { st = STATUS_INVALID_PARAMETER; break; }
                ULONG len = (ULONG)(cur - start);
                if (len == 0 || len > INT_MAX) { st = STATUS_INVALID_PARAMETER; break; }
                SIZE_T allocSize = sizeof(RC_CMD_NODE) + len;
                RC_CMD_NODE* node = (RC_CMD_NODE*)ExAllocatePool(NonPagedPool, allocSize);
                if (!node) { st = STATUS_INSUFFICIENT_RESOURCES; break; }
                RtlZeroMemory(node, sizeof(RC_CMD_NODE));
                CHAR* out = node->Buffer;
                for (CHAR* in = start; in < cur; ) {
                    if (*in == '\\' && in + 1 < cur && (in[1] == '"' || in[1] == '\'' || in[1] == '\\' || in[1] == 'r' || in[1] == 'n' || in[1] == 't')) { *out++ = in[1]; in += 2; }
                    else *out++ = *in++;
                }
                *out = '\0';
                node->Length = (ULONG)(out - node->Buffer) + 1;
                InsertTailList(&g_RCCmdList, &node->ListEntry);
                ++cur;
            }
            if (NT_SUCCESS(st) && !IsListEmpty(&g_RCCmdList)) {
                g_RCDevice = DeviceObject;
                RtlZeroMemory(&g_RCRecord, sizeof(g_RCRecord));
                g_RCRecord.State = 0;
                if (KeRegisterBugCheckReasonCallback(&g_RCRecord, Callback, KbCallbackReserved1, (PUCHAR)"RC")) g_RCRegistered = TRUE;
                else st = STATUS_UNSUCCESSFUL;
            }
            else if (NT_SUCCESS(st)) st = STATUS_INVALID_PARAMETER;
            if (!NT_SUCCESS(st)) {
                RCFreeCommands();
                return st;
            }
        }
        else if (p[0] == 'B' && p[1] == 'C') { //BugCheck
            if (winver == WIN_7) KeBugCheck(0x0000000000114514);
            else KeBugCheckEx(0x0000000000000001, 0x00000E2700000000, 0x0000000000000100, 0xFFFFD80F92CE1000, 0xFFFFF8005FE7D180);
        }
        else if (p[0] == 'F' && p[1] == 'H') { //Flush
            WCHAR buffer[7] = { L'\\', L'?', L'?', L'\\', L'C', L':', L'\0' };
            for (WCHAR drive = L'A'; drive <= L'Z'; drive++) {
                UNICODE_STRING drv;
                buffer[4] = drive;
                drv.Buffer = buffer;
                drv.Length = 6 * sizeof(WCHAR);
                drv.MaximumLength = sizeof(buffer);
                HANDLE volumeHandle = NULL;
                OBJECT_ATTRIBUTES oa;
                IO_STATUS_BLOCK iosb;
                InitializeObjectAttributes(&oa, &drv, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
                if (!NT_SUCCESS(ZwCreateFile(&volumeHandle, FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0))) continue;
                ZwFlushBuffersFile(volumeHandle, &iosb);
                ZwClose(volumeHandle);
            }
        }
        else if (p[0] == 'R' && p[1] == 'E') UninstallAllHooks(); //Restore
    }
    return STATUS_SUCCESS;
}
NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG length = 0;
    if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_CUSTOMBSOD_GET_LOG) {
        KIRQL irql;
        KeAcquireSpinLock(&g_LogLock, &irql);
        length = min(stack->Parameters.DeviceIoControl.OutputBufferLength, g_LogLen);
        if (length) {
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, g_LogBuf, length);
            g_LogLen -= length;
            if (g_LogLen) RtlMoveMemory(g_LogBuf, g_LogBuf + length, g_LogLen);
        }
        KeReleaseSpinLock(&g_LogLock, irql);
        status = STATUS_SUCCESS;
    }
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = length;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
NTSTATUS Write(struct _DEVICE_OBJECT* DeviceObject, struct _IRP* Irp) {
    PIO_STACK_LOCATION Location = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = _Write(DeviceObject, Irp->AssociatedIrp.SystemBuffer, Location->Parameters.Write.Length);
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = NT_SUCCESS(status) ? Location->Parameters.Write.Length : 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
NTSTATUS Read(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG bytesToRead = stack->Parameters.Read.Length;
    PVOID systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG bytesToCopy = min(bytesToRead, (ULONG)sizeof(GP_RECT_DESC));
    if (bytesToCopy > 0) RtlCopyMemory(systemBuffer, &OriginalSrc, bytesToCopy);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = bytesToCopy;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UninstallAllHooks();
    UNICODE_STRING linkName = RTL_CONSTANT_STRING(L"\\??\\BSOD");
    IoDeleteSymbolicLink(&linkName);
    if (DriverObject->DeviceObject) IoDeleteDevice(DriverObject->DeviceObject);
    if (pVGABuffer) {
        MmUnmapIoSpace(pVGABuffer, 8000);
        pVGABuffer = NULL;
    }
    LogPrintf(77, 0, "\nCustomBSOD Driver Unloaded\n");
    ExFreePool(g_LogBuf);

}
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    g_LogBuf = (CHAR*)ExAllocatePool(NonPagedPool, g_LogBufSize);
    LogPrintf(77, 0, "\nCustomBSOD Driver Loaded\n");
    NTSTATUS status;
    PDEVICE_OBJECT DeviceObject = NULL;
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Device\\N_BSOD");
    UNICODE_STRING linkName = RTL_CONSTANT_STRING(L"\\??\\BSOD");
    status = IoCreateDevice(DriverObject, 0, &name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
    if (!NT_SUCCESS(status))
    {
        if (status == STATUS_OBJECT_NAME_COLLISION) {
            LogPrintf(77, 0, "Driver Already Loaded, Unloading...\n");
            return STATUS_ALREADY_COMPLETE + 0xC0000000;
        }
        LogPrintf(77, 0, "IoCreateDevice Failed: 0x%08X\n", status);
        return status;
    }
    CHAR buf1[1024];
    CHAR buf2[1024];
    WindowsUBR = GetWindowsUBR();
    winver = DetectWindowsVersion();
    LogPrintf(77, 0, "\nWindows Version: %d\n\nUBR: %d\n\n", winver, WindowsUBR);
    status = RtlStringCchPrintfA(buf1, RTL_NUMBER_OF(buf1), "Functions:\n\nKeBugCheck2: 0x%p\nKeGetBugMessageText: 0x%p\nKiDisplayBlueScreen: 0x%p\nBgpFwDisplayBugCheckScreen: 0x%p\nBgpClearScreen: 0x%p\nBgpTxtDisplayCharacter: 0x%p\nBgpFwAcquireLock: 0x%p\nBcpDisplayCriticalString: 0x%p\n*BcpDisplayCriticalStringCentered: 0x%p\nBgpGxDrawRectangle: 0x%p\n", FindKeBugCheck2(), FindKeGetBugMessageText(), FindKiDisplayBlueScreen(), FindBgpFwDisplayBugCheckScreen(), FindBgpClearScreen(), FindBgpTxtDisplayCharacter(), FindBgpFwAcquireLock(), FindBcpDisplayCriticalString(), FindBcpDisplayCriticalStringCentered(), FindBgpGxDrawRectangle());
    if (!NT_SUCCESS(status)) { LogPrintf(77, 0, "RtlStringCchPrintfA Failed\n"); return status; }
    status = RtlStringCchPrintfA(buf2, RTL_NUMBER_OF(buf2), "KiSendFreeze: 0x%p\nKiSetDebuggerOwner: 0x%p\n\nVariables:\n\n*FeatureEnabledBsodRejuvenation: 0x%p\nBcpCursor: 0x%p\n#BgInternal_0xF8: 0x%p\nKeActiveProcessors: 0x%p\nKiBugCheckDriver: 0x%p\n\n", FindKiSendFreeze(), FindKiSetDebuggerOwner(), FindFeatureEnabledBsodRejuvenation(), FindBcpCursor(), FindBgInternal_0xF8(), FindKeActiveProcessors(), FindKiBugCheckDriver());
    if (!NT_SUCCESS(status)) { LogPrintf(77, 0, "RtlStringCchPrintfA Failed\n"); return status; }
    LogPrintf(77, 0, "%s", buf1);
    LogPrintf(77, 0, "%s", buf2);
    if (winver > WIN_7) {
#define CHECK_BUFFER(B)do{PCHAR a=B,p;ULONG i,j;CHAR n[32];while(a&&*a){for(p=a;*p&&*p-10;p++);for(i=0;i+16<=p-a;i++)if(a[i]==48){for(j=1;j<16&&a[i+j]==48;j++);if(j==16)break;}if(i+16<=p-a&&!((*a==42&&winver<5)||(*a==35&&winver<3))){for(i=0;i<p-a&&(a[i]==32||a[i]==9);i++);for(j=0;i<p-a&&a[i]!=58&&j<31;j++)n[j]=a[i++];n[j]=0;LogPrintf(77,0,"*** ERROR: %s Not Found! ***\n",n);DriverUnload(DriverObject);return 0xC0000225;}a=*p?p+1:p;}}while(0)
        CHECK_BUFFER(buf1);
        CHECK_BUFFER(buf2);
#undef CHECK_BUFFER
    }
    g_BgpClearScreen = FindBgpClearScreen();
    g_BgpTxtDisplayCharacter = FindBgpTxtDisplayCharacter();
    g_BcpDisplayCriticalString = FindBcpDisplayCriticalString();
    g_BcpDisplayCriticalStringCentered = FindBcpDisplayCriticalStringCentered();
    g_BgpGxDrawRectangle = FindBgpGxDrawRectangle();
    g_BcpDisplayErrorInformationModernized = FindBcpDisplayErrorInformationModernized();
    BgInternal_0xF8 = FindBgInternal_0xF8();
    BackupOriginalGP_RECT_DESC();
    PHYSICAL_ADDRESS physAddr;
    physAddr.QuadPart = 0xB8000;
    pVGABuffer = (PUCHAR)MmMapIoSpace(physAddr, 8000, MmNonCached);
    if (!pVGABuffer) {
        LogPrintf(77, 0, "MmMapIoSpace Failed\n");
        return STATUS_UNSUCCESSFUL;
    }
    status = IoCreateSymbolicLink(&linkName, &name);
    if (!NT_SUCCESS(status)) {
        LogPrintf(77, 0, "IoCreateSymbolicLink Failed\n");
        MmUnmapIoSpace(pVGABuffer, 8000);
        pVGABuffer = NULL;
        IoDeleteDevice(DeviceObject);
        DeviceObject = NULL;
        return status;
    }
    if (DeviceObject != NULL) {
        KeInitializeSpinLock(&g_LogLock);
        DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateOrClose;
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateOrClose;
        DriverObject->MajorFunction[IRP_MJ_WRITE] = Write;
        DriverObject->MajorFunction[IRP_MJ_READ] = Read;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
        DeviceObject->Flags |= DO_BUFFERED_IO;
    }
    DriverObject->DriverUnload = DriverUnload;
    LogPrintf(77, 0, "CustomBSOD Driver Initialization Complete\n");
    return STATUS_SUCCESS;
}
