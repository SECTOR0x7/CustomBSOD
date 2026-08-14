#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>
#include <ntintsafe.h>
#include <ntstrsafe.h>
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
typedef struct _HOOK_INFO {
    PVOID TargetAddress;
    PUCHAR OriginalCode;
    SIZE_T PatchSize;
    PVOID Trampoline;
    BOOLEAN Installed;
} HOOK_INFO, * PHOOK_INFO;
static HOOK_INFO g_StopCodeHookInfo = { NULL, NULL, 0, NULL, FALSE };
static HOOK_INFO g_BgpClearScreenHookInfo = { NULL, NULL, 0, NULL, FALSE };
static HOOK_INFO g_BgpTxtDisplayCharHookInfo = { NULL, NULL, 0, NULL, FALSE };
static HOOK_INFO g_BcpDisplayCriticalHookInfo = { NULL, NULL, 0, NULL, FALSE };
static PVOID  g_Win7StopCodeHookTarget = NULL;
static PUCHAR g_Win7StopCodeOrigCode = NULL;
static SIZE_T g_Win7StopCodeOrigSize = 0;
static BOOLEAN g_Win7StopCodeHooked = FALSE;
PUCHAR pVGABuffer = NULL;
UCHAR* VGAString = NULL;
ULONG VGABackColor = NULL;
ULONG VGAForeColor = NULL;
BOOLEAN VGABlink = NULL;
BOOLEAN VGA80x25 = NULL;
BOOLEAN VGARainbow = NULL;
typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    ULONG Padding;
    PWSTR Buffer;
} NTUNICODE_STRING, * PNTUNICODE_STRING;
typedef NTSTATUS(*_BcpDisplayCriticalString)(PNTUNICODE_STRING String, ULONG TextSize, ULONG64 Reserved, ULONG DisplayType);
extern "C" NTKERNELAPI NTSTATUS InbvAcquireDisplayOwnership();
BOOLEAN SafeReadMemory(PVOID Address, PVOID Buffer, SIZE_T Size)
{
    PMDL Mdl = NULL;
    PVOID MappedAddress = NULL;
    BOOLEAN Locked = FALSE;
    if (!Address || !Buffer || Size == 0) return FALSE;
    Mdl = IoAllocateMdl(Address, (ULONG)Size, FALSE, FALSE, NULL);
    if (!Mdl) return FALSE;
    __try
    {
        MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
        Locked = TRUE;
        MappedAddress = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
        if (!MappedAddress)
        {
            if (Locked) MmUnlockPages(Mdl);
            IoFreeMdl(Mdl);
            return FALSE;
        }
        RtlCopyMemory(Buffer, MappedAddress, Size);
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        if (Locked) MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return FALSE;
    }
}
typedef enum _WINDOWS_VERSION {
    WIN_UNKNOWN = 0,
    WIN_7,
    WIN_8,
    WIN_10,
    WIN_11_21H2,
    WIN_11_22H2,
    WIN_11_23H2,
    WIN_11_24H2,
    WIN_11_25H2,
    WIN_11_26H1
} WINDOWS_VERSION;
WINDOWS_VERSION DetectWindowsVersion() {
    RTL_OSVERSIONINFOW ver = { 0 };
    ver.dwOSVersionInfoSize = sizeof(ver);
    RtlGetVersion(&ver);
    if (ver.dwMajorVersion == 6 && ver.dwMinorVersion == 1) return WIN_7;
    if (ver.dwMajorVersion == 6 && (ver.dwMinorVersion == 2 || ver.dwMinorVersion == 3)) return WIN_8;
    if (ver.dwMajorVersion >= 10)
    {
        ULONG build = ver.dwBuildNumber;
        if (build >= 28000) return WIN_11_26H1;
        if (build >= 26200) return WIN_11_25H2;
        if (build >= 26100) return WIN_11_24H2;
        if (build >= 22631) return WIN_11_23H2;
        if (build >= 22621) return WIN_11_22H2;
        if (build >= 22000) return WIN_11_21H2;
        if (build >= 10240) return WIN_10;
    }
    return WIN_UNKNOWN;
}
PVOID SearchPattern(PVOID BaseAddress, SIZE_T SearchSize, const UCHAR* Pattern, SIZE_T PatternSize, UCHAR Wildcard) {
    for (SIZE_T i = 0; i <= SearchSize - PatternSize; i++) {
        BOOLEAN Found = TRUE;
        PVOID CurrentAddress = (PUCHAR)BaseAddress + i;
        UCHAR* CurrentPattern = (UCHAR*)Pattern;
        for (SIZE_T j = 0; j < PatternSize; j++) {
            UCHAR MemoryByte;
            if (!SafeReadMemory((PUCHAR)CurrentAddress + j, &MemoryByte, sizeof(UCHAR))) {
                Found = FALSE;
                break;
            }
            if (CurrentPattern[j] != Wildcard && MemoryByte != CurrentPattern[j]) {
                Found = FALSE;
                break;
            }
        }
        if (Found) return CurrentAddress;
    }
    return NULL;
}
ULONG_PTR FindAddress(PVOID Address, unsigned char* Bin, SIZE_T size) {
    unsigned char* BytesAddress = (unsigned char*)Address;
    ULONG i;
    for (ULONG find = 0; ; find++) {
        for (i = 0; i < size; i++) {
            if (BytesAddress[find + i] != Bin[i]) {
                break;
            }
        }
        if (i == size) {
            return (ULONG_PTR)(BytesAddress + find);
        }
    }
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
extern "C" NTSYSAPI PVOID NTAPI RtlPcToFileHeader(PVOID PcValue, PVOID* BaseOfImage);
typedef struct _NT_TEXT_RANGE {
    PUCHAR Base;
    SIZE_T Size;
} NT_TEXT_RANGE, * PNT_TEXT_RANGE;
BOOLEAN IsRangeInside(PVOID Address, SIZE_T Size, PVOID Base, SIZE_T RangeSize)
{
    ULONG_PTR addr = (ULONG_PTR)Address;
    ULONG_PTR base = (ULONG_PTR)Base;
    ULONG_PTR end = base + RangeSize;
    if (!Address || !Base || Size == 0 || RangeSize == 0) return FALSE;
    if (addr < base) return FALSE;
    if (addr >= end) return FALSE;
    if (Size > end - addr) return FALSE;
    return TRUE;
}
BOOLEAN GetNtTextRange(PNT_TEXT_RANGE TextRange)
{
    PVOID ntBase = NULL;
    if (!TextRange) return FALSE;
    RtlZeroMemory(TextRange, sizeof(NT_TEXT_RANGE));
    if (!RtlPcToFileHeader((PVOID)KeBugCheckEx, &ntBase)) return FALSE;
    if (!ntBase) return FALSE;
    IMAGE_DOS_HEADER dosHeader = { 0 };
    if (!SafeReadMemory(ntBase, &dosHeader, sizeof(dosHeader))) return FALSE;
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    IMAGE_NT_HEADERS64 ntHeaders = { 0 };
    PVOID ntHeaderAddress = (PUCHAR)ntBase + dosHeader.e_lfanew;
    if (!SafeReadMemory(ntHeaderAddress, &ntHeaders, sizeof(ntHeaders))) return FALSE;
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) return FALSE;
    if (ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return FALSE;
    PIMAGE_SECTION_HEADER sectionHeaderAddress = (PIMAGE_SECTION_HEADER)((PUCHAR)ntHeaderAddress + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + ntHeaders.FileHeader.SizeOfOptionalHeader);
    for (USHORT i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
    {
        IMAGE_SECTION_HEADER section = { 0 };
        if (!SafeReadMemory((PUCHAR)sectionHeaderAddress + i * sizeof(IMAGE_SECTION_HEADER), &section, sizeof(section))) continue;
        if (section.Name[0] == '.' &&
            section.Name[1] == 't' &&
            section.Name[2] == 'e' &&
            section.Name[3] == 'x' &&
            section.Name[4] == 't')
        {
            TextRange->Base = (PUCHAR)ntBase + section.VirtualAddress;
            TextRange->Size = section.Misc.VirtualSize;
            if (TextRange->Size == 0) TextRange->Size = section.SizeOfRawData;
            return TRUE;
        }
    }
    return FALSE;
}
PVOID FindFunction(UCHAR* pattern, ULONG patternSize, UCHAR* pattern2 = NULL, ULONG patternSize2 = NULL, UCHAR* pattern3 = NULL, ULONG patternSize3 = NULL, UCHAR* pattern4 = NULL, ULONG patternSize4 = NULL) {
    NT_TEXT_RANGE textRange = { 0 };
    if (!GetNtTextRange(&textRange)) return NULL;
    if (!textRange.Base) return NULL;
    if (textRange.Size < patternSize) return NULL;
    if (pattern2 && textRange.Size < patternSize2) return NULL;
    if (pattern3 && textRange.Size < patternSize3) return NULL;
    if (pattern4 && textRange.Size < patternSize4) return NULL;
    ULONG_PTR address = FindAddress(textRange.Base, pattern, textRange.Size, patternSize);
    ULONG_PTR address2 = NULL, address3 = NULL, address4 = NULL;
    if (pattern2) address2 = FindAddress(textRange.Base, pattern2, textRange.Size, patternSize2);
    if (pattern3) address3 = FindAddress(textRange.Base, pattern3, textRange.Size, patternSize3);
    if (pattern4) address4 = FindAddress(textRange.Base, pattern4, textRange.Size, patternSize4);
    if (address) return (PVOID)address;
    if (address2) return (PVOID)address2;
    if (address3) return (PVOID)address3;
    if (address4) return (PVOID)address4;
    return NULL;
}
PVOID ResolveRelativeCallTarget(PVOID CallInstr)
{
    UCHAR op = 0;
    LONG offset = 0;
    if (!CallInstr) return NULL;
    if (!SafeReadMemory(CallInstr, &op, sizeof(op))) return NULL;
    if (op != 0xE8) return NULL;
    if (!SafeReadMemory((PUCHAR)CallInstr + 1, &offset, sizeof(offset))) return NULL;
    return (PVOID)((PUCHAR)CallInstr + 5 + offset);
}
BOOLEAN IsKiDisplayBlueScreenEntryInText(PVOID Address, PNT_TEXT_RANGE TextRange)
{
    UCHAR wildcard = 0xCC;
    UCHAR pattern[] = { 0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x54, 0x48, 0x81, 0xEC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x84, 0x24, 0xCC, 0xCC, 0xCC, 0xCC };
    UCHAR pattern2[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x48, 0x89, 0x78, 0x18, 0x4C, 0x89, 0x60, 0x20, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xA8, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x81, 0xEC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x85, 0xCC, 0xCC, 0xCC, 0xCC };
    UCHAR pattern3[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x48, 0x89, 0x78, 0x18, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xA8, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x81, 0xEC, 0xCC, 0xCC, 0xCC, 0xCC };
    UCHAR pattern4[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x48, 0x89, 0x78, 0x18, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xA8, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x81, 0xEC, 0xCC, 0xCC, 0x00, 0x00 };
    if (!Address || !TextRange) return FALSE;
    if (!IsRangeInside(Address, sizeof(pattern), TextRange->Base, TextRange->Size) && !IsRangeInside(Address, sizeof(pattern2), TextRange->Base, TextRange->Size) && !IsRangeInside(Address, sizeof(pattern3), TextRange->Base, TextRange->Size) && !IsRangeInside(Address, sizeof(pattern4), TextRange->Base, TextRange->Size)) return FALSE;
    return SearchPattern(Address, sizeof(pattern), pattern, sizeof(pattern), wildcard) == Address || SearchPattern(Address, sizeof(pattern2), pattern2, sizeof(pattern2), wildcard) == Address || SearchPattern(Address, sizeof(pattern3), pattern3, sizeof(pattern3), wildcard) == Address || SearchPattern(Address, sizeof(pattern4), pattern4, sizeof(pattern4), wildcard) == Address;
}

PVOID FindKiDisplayBlueScreenFromKeBugCheck2(PVOID pKeBugCheck2, PNT_TEXT_RANGE TextRange)
{
    PUCHAR pBuffer = (PUCHAR)pKeBugCheck2;
    if (!pKeBugCheck2 || !TextRange) return NULL;
    if (!IsRangeInside(pKeBugCheck2, 1, TextRange->Base, TextRange->Size)) return NULL;
    for (SIZE_T i = 0; i < 0x6000; i++)
    {
        UCHAR op = 0;
        PVOID current = pBuffer + i;
        if (!IsRangeInside(current, 5, TextRange->Base, TextRange->Size)) break;
        if (!SafeReadMemory(current, &op, sizeof(op))) continue;
        if (op != 0xE8) continue;
        PVOID target = ResolveRelativeCallTarget(current);
        if (!target)continue;
        if (!IsRangeInside(target, 1, TextRange->Base, TextRange->Size))continue;
        if (IsKiDisplayBlueScreenEntryInText(target, TextRange))return target;
    }

    return NULL;
}
PVOID FindKiDisplayBlueScreen()
{
    NT_TEXT_RANGE textRange = { 0 };
    if (!GetNtTextRange(&textRange)) return NULL;
    if (!textRange.Base || textRange.Size == 0) return NULL;
    PVOID pKeBugCheckEx = (PVOID)KeBugCheckEx;
    if (!IsRangeInside(pKeBugCheckEx, 1, textRange.Base, textRange.Size)) return NULL;
    PUCHAR pBuffer = (PUCHAR)pKeBugCheckEx;
    for (SIZE_T i = 0; i < 0x300; i++)
    {
        UCHAR op = 0;
        PVOID current = pBuffer + i;
        if (!IsRangeInside(current, 5, textRange.Base, textRange.Size)) break;
        if (!SafeReadMemory(current, &op, sizeof(op))) continue;
        if (op != 0xE8) continue;
        PVOID pKeBugCheck2 = ResolveRelativeCallTarget(current);
        if (!pKeBugCheck2) continue;
        if (!IsRangeInside(pKeBugCheck2, 1, textRange.Base, textRange.Size)) continue;
        PVOID pKiDisplayBlueScreen = FindKiDisplayBlueScreenFromKeBugCheck2(pKeBugCheck2, &textRange);
        if (pKiDisplayBlueScreen) return pKiDisplayBlueScreen;
    }
    return NULL;
}
PVOID FindKeGetBugMessageText()
{
    UCHAR pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x8B, 0xF9, 0x33, 0xDB, 0x88, 0x5C, 0x24, 0x20, 0x48, 0x39, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 };
    UCHAR pattern2[] = { 0x48, 0x83, 0xEC, 0x28, 0x44, 0x8B, 0xD1, 0x45, 0x33, 0xC9, 0x44, 0x88, 0x0C, 0x24, 0x4C, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x85, 0xC0, 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 };
    UCHAR pattern3[] = { 0x48, 0x83, 0xEC, 0x28, 0x4C, 0x8B, 0xDA, 0x44, 0x8B, 0xD1, 0x45, 0x33, 0xC0, 0x44, 0x88, 0x04, 0x24, 0x4C, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x85, 0xC9, 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 };
    return FindFunction(pattern, sizeof(pattern), pattern2, sizeof(pattern2), pattern3, sizeof(pattern3));
}
PVOID FindBgpFwDisplayBugCheckScreen() {
    UCHAR pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x00, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x44, 0x8B, 0xF9, 0x4D, 0x8B, 0xF1, 0x4D, 0x8B, 0xE8, 0x48, 0x8B, 0xEA, 0xB9, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x00, 0x74, 0x00 };
    UCHAR pattern2[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x00, 0x48, 0x89, 0x68, 0x00, 0x48, 0x89, 0x70, 0x00, 0x4C, 0x89, 0x40, 0x00, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x00, 0x48, 0x83, 0x60, 0x00, 0x00, 0x8B, 0xE9, 0x48, 0x83, 0x60, 0x00, 0x00, 0x4D, 0x8B, 0xE1, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xEA, 0xB9, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x00, 0x74, 0x00 };
    UCHAR pattern3[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x00, 0x48, 0x89, 0x68, 0x00, 0x48, 0x89, 0x70, 0x00, 0x4C, 0x89, 0x40, 0x00, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x00, 0x48, 0x83, 0x60, 0x00, 0x00, 0x4D, 0x8B, 0xE1, 0x48, 0x83, 0x60, 0x00, 0x00, 0x4C, 0x8B, 0xEA, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xE9, 0xA8, 0x00, 0x74, 0x00 };
    UCHAR pattern4[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x00, 0x48, 0x89, 0x68, 0x00, 0x48, 0x89, 0x70, 0x00, 0x4C, 0x89, 0x40, 0x00, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x00, 0x48, 0xC7, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0xE1, 0x48, 0xC7, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xEA, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xE9, 0xA8, 0x00, 0x74, 0x00 };
    return FindFunction(pattern, sizeof(pattern), pattern2, sizeof(pattern2), pattern3, sizeof(pattern3), pattern4, sizeof(pattern4));
}
PVOID FindBgpClearScreen()
{
    UCHAR pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x7C, 0x24, 0x20, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x30, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xF1, 0xA8, 0x01, 0x75, 0x00 };
    UCHAR pattern2[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x7C, 0x24, 0x20, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x40, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x44, 0x8B, 0xF1, 0xA8, 0x01, 0x75, 0x00 };
    UCHAR pattern3[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x7C, 0x24, 0x20, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x30, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x44, 0x8B, 0xF9, 0xA8, 0x01, 0x75, 0x00 };
    return FindFunction(pattern, sizeof(pattern), pattern2, sizeof(pattern2), pattern3, sizeof(pattern3));
}
PVOID FindBgpTxtDisplayCharacter()
{
    UCHAR pattern[] = { 0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x00, 0x44, 0x89, 0x40, 0x00, 0x66, 0x89, 0x50, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x68, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x41, 0x00, 0x4C, 0x8B, 0xE1, 0x49, 0x8B, 0x74, 0x24, 0x00, 0x4D, 0x8D, 0x5C, 0x24, 0x00, 0x48, 0x89, 0x45, 0x00, 0x45, 0x8A, 0x73, 0x00, 0x33, 0xC0, 0x41, 0x80, 0xE6, 0x01, 0x8B, 0xC8, 0x48, 0x89, 0x45, 0x00, 0x44, 0x8B, 0xC0, 0x89, 0x45, 0x00, 0x48, 0x89, 0x45, 0x00, 0x89, 0x45, 0x00, 0x89, 0x45, 0x00, 0x8B, 0xD8, 0x48, 0x89, 0x45, 0x00, 0x44, 0x8B, 0xF8, 0x48, 0x89, 0x45, 0x00, 0x88, 0x45, 0x00, 0x8B, 0xF8, 0x44, 0x8B, 0xE8, 0x89, 0x45, 0x00, 0x66, 0x83, 0xFA, 0x00, 0x72, 0x00 };
    UCHAR pattern2[] = { 0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x00, 0x44, 0x89, 0x40, 0x00, 0x66, 0x89, 0x50, 0x00, 0x48, 0x89, 0x48, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x68, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0x65, 0x00, 0x00, 0x48, 0x8B, 0xC1, 0x48, 0x8B, 0x49, 0x00, 0x45, 0x33, 0xC9, 0x33, 0xDB, 0x48, 0x89, 0x4D, 0x00, 0x33, 0xC9, 0x44, 0x89, 0x4D, 0x00, 0x21, 0x4D, 0x00, 0x4C, 0x8D, 0x40, 0x00, 0x45, 0x8A, 0x78, 0x00, 0x45, 0x33, 0xE4, 0x21, 0x4D, 0x00, 0x41, 0x80, 0xE7, 0x00, 0x21, 0x4D, 0x00, 0x45, 0x33, 0xED, 0x21, 0x4D, 0x00, 0x33, 0xFF, 0x48, 0x8B, 0x70, 0x00, 0x45, 0x8A, 0xF7, 0x48, 0x89, 0x4D, 0x00, 0x48, 0x89, 0x5D, 0x00, 0x4C, 0x89, 0x65, 0x00, 0x88, 0x4D, 0x00, 0x4C, 0x89, 0x45, 0x00, 0x44, 0x89, 0x6D, 0x00, 0x66, 0x83, 0xFA, 0x00, 0x72, 0x00 };
    UCHAR pattern3[] = { 0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x00, 0x44, 0x89, 0x40, 0x00, 0x66, 0x89, 0x50, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x68, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x41, 0x00, 0x45, 0x33, 0xF6, 0x4C, 0x8B, 0xE9, 0x48, 0x89, 0x45, 0x00, 0x41, 0x8B, 0xCE, 0x4C, 0x89, 0x75, 0x00, 0x41, 0x8B, 0xDE, 0x44, 0x89, 0x75, 0x00, 0x41, 0x8B, 0xC6, 0x4C, 0x89, 0x75, 0x00, 0x49, 0x8B, 0x7D, 0x00, 0x4D, 0x8D, 0x45, 0x00, 0x45, 0x8A, 0x78, 0x00, 0x45, 0x8B, 0xCE, 0x41, 0x80, 0xE7, 0x00, 0x44, 0x89, 0x75, 0x00, 0x44, 0x89, 0x75, 0x00, 0x45, 0x8B, 0xE6, 0x4C, 0x89, 0x75, 0x00, 0x41, 0x8B, 0xF6, 0x44, 0x88, 0x75, 0x00, 0x45, 0x8A, 0xF7, 0x48, 0x89, 0x4D, 0x00, 0x48, 0x89, 0x5D, 0x00, 0x89, 0x45, 0x00, 0x66, 0x83, 0xFA, 0x00, 0x0F, 0x82, 0x00, 0x00, 0x00, 0x00 };
    UCHAR pattern4[] = { 0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x00, 0x44, 0x89, 0x40, 0x00, 0x66, 0x89, 0x50, 0x00, 0x48, 0x89, 0x48, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x68, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xC1, 0x48, 0xC7, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x49, 0x00, 0x45, 0x33, 0xC0, 0x33, 0xDB, 0x48, 0x89, 0x4D, 0x00, 0x33, 0xC9, 0x44, 0x89, 0x45, 0x00, 0x4C, 0x8B, 0x70, 0x00, 0x4C, 0x8D, 0x68, 0x00, 0x45, 0x8A, 0x7D, 0x00, 0x45, 0x33, 0xE4, 0x41, 0x80, 0xE7, 0x01, 0x48, 0x89, 0x4D, 0x00, 0x33, 0xC0, 0x48, 0x89, 0x4D, 0x00, 0x33, 0xF6, 0x89, 0x4D, 0x00, 0x89, 0x4D, 0x00, 0x41, 0x8A, 0xFF, 0x48, 0x89, 0x5D, 0x00, 0x4C, 0x89, 0x65, 0x00, 0x88, 0x4D, 0x00, 0x89, 0x45, 0x00, 0x66, 0x83, 0xFA, 0x00, 0x0F, 0x82, 0x00, 0x00, 0x00, 0x00 };
    return FindFunction(pattern, sizeof(pattern), pattern2, sizeof(pattern2), pattern3, sizeof(pattern3), pattern4, sizeof(pattern4));
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
    return FindFunction(pattern, sizeof(pattern), pattern2, sizeof(pattern2), pattern3, sizeof(pattern3), pattern4, sizeof(pattern4));
}
PVOID FindBcpDisplayCriticalStringCentered() {
    UCHAR pattern[] = { 0x44, 0x89, 0x44, 0x24, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xDB, 0x49, 0x63, 0xC1, 0x4C, 0x6B, 0xF8, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x44, 0x89, 0x5D, 0x00, 0x4C, 0x8B, 0xD1, 0x44, 0x89, 0x5D, 0x00, 0x44, 0x89, 0x5D, 0x00, 0x41, 0x8B, 0x4C, 0x3F, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x00 };
    UCHAR pattern2[] = { 0x44, 0x89, 0x44, 0x24, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x33, 0xF6, 0x49, 0x63, 0xC1, 0x4C, 0x6B, 0xF8, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00, 0x89, 0x75, 0x00, 0x4C, 0x8B, 0xE1, 0x89, 0x75, 0x00, 0x89, 0x75, 0x00, 0x43, 0x8B, 0x4C, 0x17, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x00 };
    return FindFunction(pattern, sizeof(pattern), pattern2, sizeof(pattern2));
}
PVOID FindFeatureEnabledBsodRejuvenation() {
    PVOID CmpInstructionAddress = FindKiDisplayBlueScreen();
    if (CmpInstructionAddress == NULL) return NULL;
    ULONG CmpOffset = 0;
    WINDOWS_VERSION winver = DetectWindowsVersion();
    if (winver < WIN_11_25H2) return NULL;
    if (winver == WIN_11_25H2) CmpOffset = 0x22D;
    else if (winver == WIN_11_26H1) CmpOffset = 0x229;
    CmpInstructionAddress = (PVOID)((ULONG_PTR)CmpInstructionAddress + CmpOffset);
    PUCHAR code = (PUCHAR)CmpInstructionAddress;
    ULONG_PTR rip = (ULONG_PTR)CmpInstructionAddress;
    UCHAR rex = 0;
    BOOLEAN rexPrefixFound = FALSE;
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
        rexPrefixFound = TRUE;
        offset = 1;
    }
    UCHAR opcode = 0;
    __try {
        opcode = code[offset];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
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
    SIZE_T instructionLength = offset + 1 + 1 + 4;
    LONG disp32 = 0;
    __try {
        disp32 = *(PLONG)(code + offset + 2);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    ULONG_PTR targetAddress = rip + instructionLength + disp32;
    return (PVOID)targetAddress;
}
PVOID FindBcpCursor() {
    PVOID AddInstructionAddress = FindBgpFwDisplayBugCheckScreen();
    if (AddInstructionAddress == NULL) return NULL;
    ULONG AddOffset = 0;
    WINDOWS_VERSION winver = DetectWindowsVersion();
    if (winver == WIN_8) AddOffset = 0xEB;
    else if (winver == WIN_10) AddOffset = 0x139;
    else if (winver == WIN_11_24H2) AddOffset = 0x12B;
    else if (winver == WIN_11_25H2) AddOffset = 0x12A;
    else if (winver == WIN_11_26H1) AddOffset = 0x130;
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
PVOID AllocateExecutableMemory(SIZE_T Size) {
    PVOID buffer = ExAllocatePoolWithTag(NonPagedPoolExecute, Size, 'pmrT');
    return buffer;
}
NTSTATUS ReadMemory(PVOID Address, PVOID Buffer, SIZE_T Size) {
    if (!Address || !Buffer || Size == 0) return STATUS_INVALID_PARAMETER;
    __try {
        RtlCopyMemory(Buffer, Address, Size);
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}
NTSTATUS WriteMemory(PVOID Address, PVOID Buffer, SIZE_T Size) {
    if (!Address || !Buffer || Size == 0) return STATUS_INVALID_PARAMETER;
    PMDL mdl = IoAllocateMdl(Address, (ULONG)Size, FALSE, FALSE, NULL);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;
    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
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
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return STATUS_SUCCESS;
}
VOID UninstallStopCodeHook()
{
    if (!g_StopCodeHookInfo.Installed) return;
    KIRQL oldIrql;
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    WriteMemory(g_StopCodeHookInfo.TargetAddress, g_StopCodeHookInfo.OriginalCode, g_StopCodeHookInfo.PatchSize);
    KeLowerIrql(oldIrql);
    ExFreePoolWithTag(g_StopCodeHookInfo.Trampoline, 'pmrT');
    ExFreePoolWithTag(g_StopCodeHookInfo.OriginalCode, 'OgnS');
    RtlZeroMemory(&g_StopCodeHookInfo, sizeof(g_StopCodeHookInfo));
    g_StopCodeHookInfo.Installed = FALSE;
}
NTSTATUS InstallStopCodeHook(PVOID TargetFunction, PWCHAR NewString, SIZE_T CharCount)
{
    if (!TargetFunction || !NewString || CharCount < 1) return STATUS_INVALID_PARAMETER;
    if (CharCount * sizeof(WCHAR) > 0xFFFF) return STATUS_INVALID_PARAMETER;
    if (g_StopCodeHookInfo.Installed) { UninstallStopCodeHook(); return InstallStopCodeHook(TargetFunction, NewString, CharCount); }
    WINDOWS_VERSION WinVer = DetectWindowsVersion();
    WORD byteLen = (WORD)(CharCount * sizeof(WCHAR));
    WORD byteMaxLen = byteLen + sizeof(WCHAR);
    ULONG hookOffset = (WinVer == WIN_8) ? 0x84 : 0x90;
    ULONG returnOffset = (WinVer == WIN_8) ? 0x94 : 0xA2;
    ULONG patchSize = (WinVer == WIN_8) ? 16 : 18;
    ULONG origSize = patchSize;
    ULONG segD_len = 4;
    ULONG segH_off = (WinVer == WIN_8) ? 9 : 9;
    ULONG segH_len = (WinVer == WIN_8) ? 3 : 4;
    ULONG segI_off = (WinVer == WIN_8) ? 12 : 13;
    ULONG segI_len = (WinVer == WIN_8) ? 4 : 5;
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
    const SIZE_T fixedSize = 54;
    SIZE_T trampSize = fixedSize + alignedBytes;
    PUCHAR tramp = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolExecute, trampSize, 'pmrT');
    if (!tramp) {
        ExFreePoolWithTag(strBuf, 'grtS');
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(tramp, trampSize);
    PUCHAR origCopy = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, origSize, 'OgnS');
    if (!origCopy) {
        ExFreePoolWithTag(tramp, 'pmrT');
        ExFreePoolWithTag(strBuf, 'grtS');
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(origCopy, original, origSize);
    PUCHAR p = tramp;
    RtlCopyMemory(p, original + 0, 5);
    p += 5;
    if (WinVer == WIN_8) {
        p[0] = 0x41;
        p[1] = 0x50;
        p += 2;
    }
    else {
        p[0] = 0x51;
        p += 1;
    }
    ULONG64 strDataAddr = (ULONG64)(tramp + fixedSize);
    if (WinVer == WIN_8) {
        p[0] = 0x49;
        p[1] = 0xB8;
    }
    else {
        p[0] = 0x48;
        p[1] = 0xB9;
    }
    *(ULONG64*)(p + 2) = strDataAddr;
    p += 10;
    RtlCopyMemory(p, original + 5, 4);
    p += 4;
    if (WinVer == WIN_8) {
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
        ExFreePoolWithTag(tramp, 'pmrT');
        ExFreePoolWithTag(strBuf, 'grtS');
        ExFreePoolWithTag(origCopy, 'OgnS');
        return status;
    }
    g_StopCodeHookInfo.TargetAddress = hookPoint;
    g_StopCodeHookInfo.OriginalCode = origCopy;
    g_StopCodeHookInfo.PatchSize = origSize;
    g_StopCodeHookInfo.Trampoline = tramp;
    g_StopCodeHookInfo.Installed = TRUE;
    KeMemoryBarrier();
    ExFreePoolWithTag(strBuf, 'grtS');
    return STATUS_SUCCESS;
}
VOID UninstallBgpClearScreenHook()
{
    if (!g_BgpClearScreenHookInfo.Installed) return;
    KIRQL oldIrql;
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    WriteMemory(g_BgpClearScreenHookInfo.TargetAddress, g_BgpClearScreenHookInfo.OriginalCode, g_BgpClearScreenHookInfo.PatchSize);
    KeLowerIrql(oldIrql);
    ExFreePoolWithTag(g_BgpClearScreenHookInfo.Trampoline, 'pCgB');
    ExFreePoolWithTag(g_BgpClearScreenHookInfo.OriginalCode, 'OgnC');
    RtlZeroMemory(&g_BgpClearScreenHookInfo, sizeof(g_BgpClearScreenHookInfo));
    g_BgpClearScreenHookInfo.Installed = FALSE;
    g_color = NULL;
}
NTSTATUS InstallBgpClearScreenHook(PVOID BgpClearScreenAddr, ULONG64 color)
{
    if (!BgpClearScreenAddr) return STATUS_INVALID_PARAMETER;
    if (g_BgpClearScreenHookInfo.Installed) { UninstallBgpClearScreenHook(); return InstallBgpClearScreenHook(BgpClearScreenAddr, color); }
    PUCHAR tramp = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolExecute, 64u, 'pCgB');
    if (!tramp) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(tramp, 64u);
    PUCHAR origCopy = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 15u, 'OgnC');
    if (!origCopy) {
        ExFreePoolWithTag(tramp, 'pCgB');
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ReadMemory(BgpClearScreenAddr, origCopy, 15u);
    PUCHAR p = tramp;
    RtlCopyMemory(p, BgpClearScreenAddr, 15u);
    p += 15u;
    p[0] = 0x48;
    p[1] = 0xB9;
    g_color = p + 2;
    *(ULONG64*)(p + 2) = color;
    p += 10;
    ULONG64 retAddr = (ULONG64)((PUCHAR)BgpClearScreenAddr + 15u);
    p[0] = 0x48;
    p[1] = 0xB8;
    *(ULONG64*)(p + 2) = retAddr;
    p += 10;
    p[0] = 0xFF;
    p[1] = 0xE0;
    p += 2;
    UCHAR patch[15u];
    RtlZeroMemory(patch, 15u);
    ULONG64 trampAddr = (ULONG64)tramp;
    patch[0] = 0x48;
    patch[1] = 0xB8;
    *(ULONG64*)(patch + 2) = trampAddr;
    patch[10] = 0xFF;
    patch[11] = 0xE0;
    patch[12] = 0x90;
    patch[13] = 0x90;
    patch[14] = 0x90;
    NTSTATUS status = WriteMemory(BgpClearScreenAddr, patch, 15u);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(tramp, 'pCgB');
        ExFreePoolWithTag(origCopy, 'OgnC');
        return status;
    }
    g_BgpClearScreenHookInfo.TargetAddress = BgpClearScreenAddr;
    g_BgpClearScreenHookInfo.OriginalCode = origCopy;
    g_BgpClearScreenHookInfo.PatchSize = 15u;
    g_BgpClearScreenHookInfo.Trampoline = tramp;
    g_BgpClearScreenHookInfo.Installed = TRUE;
    KeMemoryBarrier();
    return STATUS_SUCCESS;
}
VOID UninstallBgpTxtDisplayCharacterHook()
{
    if (!g_BgpTxtDisplayCharHookInfo.Installed) return;
    KIRQL oldIrql;
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    WriteMemory(g_BgpTxtDisplayCharHookInfo.TargetAddress, g_BgpTxtDisplayCharHookInfo.OriginalCode, g_BgpTxtDisplayCharHookInfo.PatchSize);
    KeLowerIrql(oldIrql);
    ExFreePoolWithTag(g_BgpTxtDisplayCharHookInfo.Trampoline, 'cDgB');
    ExFreePoolWithTag(g_BgpTxtDisplayCharHookInfo.OriginalCode, 'OgnT');
    RtlZeroMemory(&g_BgpTxtDisplayCharHookInfo, sizeof(g_BgpTxtDisplayCharHookInfo));
    g_BgpTxtDisplayCharHookInfo.Installed = FALSE;
    g_tbcolor = NULL;
    g_tfcolor = NULL;
}
NTSTATUS InstallBgpTxtDisplayCharacterHook(PVOID BgpTxtDisplayCharacterAddr, ULONG backColor, ULONG foreColor)
{
    if (!BgpTxtDisplayCharacterAddr) return STATUS_INVALID_PARAMETER;
    if (g_BgpTxtDisplayCharHookInfo.Installed) { UninstallBgpTxtDisplayCharacterHook(); return InstallBgpTxtDisplayCharacterHook(BgpTxtDisplayCharacterAddr, backColor, foreColor); }
    UCHAR* funcBytes = (UCHAR*)BgpTxtDisplayCharacterAddr;
    BOOLEAN is4cmd = DetectWindowsVersion() == WIN_8 || (DetectWindowsVersion() > WIN_10 && DetectWindowsVersion() <= WIN_11_26H1);
    ULONG patchSize;
    ULONG originalInstrSize;
    PUCHAR tramp = NULL;
    if (is4cmd)
    {
        patchSize = 15;
        originalInstrSize = 15;
    }
    else
    {
        patchSize = 19;
        originalInstrSize = 19;
    }
    tramp = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolExecute, 64u, 'cDgB');
    if (!tramp) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(tramp, 64u);
    PUCHAR origCopy = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, patchSize, 'OgnT');
    if (!origCopy) {
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
    if (is4cmd)
    {
        p[0] = 0x48; p[1] = 0x8B; p[2] = 0xC4;
        p += 3;
        p[0] = 0x4C; p[1] = 0x89; p[2] = 0x48; p[3] = 0x20;
        p += 4;
        p[0] = 0x44; p[1] = 0x89; p[2] = 0x40; p[3] = 0x18;
        p += 4;
        p[0] = 0x66; p[1] = 0x89; p[2] = 0x50; p[3] = 0x10;
        p += 4;
    }
    else
    {
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
        ExFreePoolWithTag(tramp, 'cDgB');
        ExFreePoolWithTag(origCopy, 'OgnT');
        return status;
    }
    g_BgpTxtDisplayCharHookInfo.TargetAddress = BgpTxtDisplayCharacterAddr;
    g_BgpTxtDisplayCharHookInfo.OriginalCode = origCopy;
    g_BgpTxtDisplayCharHookInfo.PatchSize = patchSize;
    g_BgpTxtDisplayCharHookInfo.Trampoline = tramp;
    g_BgpTxtDisplayCharHookInfo.Installed = TRUE;
    KeMemoryBarrier();
    return STATUS_SUCCESS;
}
VOID UninstallBcpDisplayCriticalStringHook()
{
    if (!g_BcpDisplayCriticalHookInfo.Installed) return;
    KIRQL oldIrql;
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    WriteMemory(g_BcpDisplayCriticalHookInfo.TargetAddress, g_BcpDisplayCriticalHookInfo.OriginalCode, g_BcpDisplayCriticalHookInfo.PatchSize);
    KeLowerIrql(oldIrql);
    ExFreePoolWithTag(g_BcpDisplayCriticalHookInfo.Trampoline, 0);
    ExFreePoolWithTag(g_BcpDisplayCriticalHookInfo.OriginalCode, 'OgnB');
    RtlZeroMemory(&g_BcpDisplayCriticalHookInfo, sizeof(g_BcpDisplayCriticalHookInfo));
    g_BcpDisplayCriticalHookInfo.Installed = FALSE;
    InstalledBlock = NULL;
}
NTSTATUS InstallBcpDisplayCriticalStringHook(PVOID BcpDisplayCriticalStringAddr, BOOLEAN SkipPercentStrings, PWSTR Buffer, PWSTR* Buffers) {
    UCHAR ExpectedBytesWin8[20] = { 0x44, 0x89, 0x44, 0x24, 0x18, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC };
    UCHAR ExpectedBytesWin10[16] = { 0x44, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54 };
    UCHAR ExpectedBytesWin11[25] = { 0x44, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC };
    UCHAR ExpectedBytesWin11_New[27] = { 0x44, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0xE1 };
    ULONG MaxBuffers = 1024;
    ULONG PatchSize;
    SIZE_T CodeSize;
    PUCHAR ExpectedBytes;
    SIZE_T ExpectedBytesSize;
    ULONG winVer;
    ULONG BufferCount;
    ULONG Index;
    PWSTR CurrentBuffer;
    SIZE_T CounterOffset;
    SIZE_T TableOffset;
    SIZE_T AllocationSize;
    PUCHAR Block;
    PUCHAR Cursor;
    volatile ULONG64* Counter;
    PNTUNICODE_STRING StringTable;
    PUCHAR origCopy;
    UCHAR Patch[27];
    ULONG64 Value64;
    NTSTATUS Status;
    PUCHAR JumpNullString;
    PUCHAR JumpEmptyString;
    PUCHAR JumpNullBuffer;
    PUCHAR JumpPercent;
    PUCHAR JumpScanLoop;
    PUCHAR ScanLoop;
    PUCHAR UseReplacement;
    PUCHAR ContinueOriginal;
    SIZE_T totalStringBytes;
    PUCHAR stringDataPtr;
    if (!BcpDisplayCriticalStringAddr || !Buffer) return STATUS_INVALID_PARAMETER;
    winVer = DetectWindowsVersion();
    if (winVer > WIN_11_24H2 && BcpDisplayCriticalStringAddr == g_BcpDisplayCriticalString) return STATUS_INVALID_PARAMETER;
    if (winVer == WIN_8)
    {
        ExpectedBytes = ExpectedBytesWin8;
        ExpectedBytesSize = sizeof(ExpectedBytesWin8);
        PatchSize = 20;
    }
    else if (winVer > WIN_10 && winVer <= WIN_11_24H2)
    {
        ExpectedBytes = ExpectedBytesWin11;
        ExpectedBytesSize = sizeof(ExpectedBytesWin11);
        PatchSize = 25;
    }
    else if (winVer >= WIN_11_25H2 && winVer <= WIN_11_26H1)
    {
        ExpectedBytes = ExpectedBytesWin11_New;
        ExpectedBytesSize = sizeof(ExpectedBytesWin11_New);
        PatchSize = 27;
    }
    else
    {
        ExpectedBytes = ExpectedBytesWin10;
        ExpectedBytesSize = sizeof(ExpectedBytesWin10);
        PatchSize = 16;
    }
    CodeSize = 109 + PatchSize + 12 + (SkipPercentStrings ? 23 : 0);
    if (InstalledBlock)
    {
        UninstallBcpDisplayCriticalStringHook();
        Status = InstallBcpDisplayCriticalStringHook(g_BcpDisplayCriticalString, SkipPercentStrings, Buffer, Buffers);
        if (Status == STATUS_INVALID_PARAMETER) Status = InstallBcpDisplayCriticalStringHook(g_BcpDisplayCriticalStringCentered, SkipPercentStrings, Buffer, Buffers);
        return Status;
    }
    if (RtlCompareMemory(BcpDisplayCriticalStringAddr, ExpectedBytes, ExpectedBytesSize) != ExpectedBytesSize) return STATUS_NOT_SUPPORTED;
    BufferCount = 1;
    for (Index = 0; Buffers && Buffers[Index]; ++Index)
    {
        if (BufferCount == MaxBuffers) return STATUS_BUFFER_OVERFLOW;
        ++BufferCount;
    }
    totalStringBytes = 0;
    for (Index = 0; Index < BufferCount; ++Index)
    {
        CurrentBuffer = (Index == 0) ? Buffer : Buffers[Index - 1];
        if (!CurrentBuffer) return STATUS_INVALID_PARAMETER;
        SIZE_T charCount = 0;
        while (charCount <= 0x7FFF && CurrentBuffer[charCount] != L'\0') ++charCount;
        if (charCount > 0x7FFF) return STATUS_NAME_TOO_LONG;
        totalStringBytes += (charCount * sizeof(WCHAR)) + sizeof(WCHAR);
    }
    CounterOffset = (CodeSize + sizeof(ULONG64) - 1) & ~(sizeof(ULONG64) - 1);
    TableOffset = (CounterOffset + sizeof(ULONG64) + sizeof(ULONG64) - 1) & ~(sizeof(ULONG64) - 1);
    AllocationSize = TableOffset + ((SIZE_T)BufferCount * sizeof(NTUNICODE_STRING)) + totalStringBytes;
    Block = (PUCHAR)ExAllocatePool(NonPagedPoolExecute, AllocationSize);
    if (!Block) return STATUS_INSUFFICIENT_RESOURCES;
    origCopy = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, PatchSize, 'OgnB');
    if (!origCopy)
    {
        ExFreePool(Block);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ReadMemory(BcpDisplayCriticalStringAddr, origCopy, PatchSize);
    RtlZeroMemory(Block, AllocationSize);
    Counter = (volatile ULONG64*)(Block + CounterOffset);
    StringTable = (PNTUNICODE_STRING)(Block + TableOffset);
    stringDataPtr = Block + TableOffset + (BufferCount * sizeof(NTUNICODE_STRING));
    for (Index = 0; Index < BufferCount; ++Index)
    {
        SIZE_T CharacterCount;
        USHORT ByteLength;
        CurrentBuffer = Index == 0 ? Buffer : Buffers[Index - 1];
        CharacterCount = 0;
        while (CharacterCount <= 0x7FFF && CurrentBuffer[CharacterCount] != L'\0')
        {
            ++CharacterCount;
        }
        if (CharacterCount > 0x7FFF)
        {
            ExFreePoolWithTag(origCopy, 'OgnB');
            ExFreePool(Block);
            return STATUS_NAME_TOO_LONG;
        }
        ByteLength = (USHORT)(CharacterCount * sizeof(WCHAR));
        StringTable[Index].Length = ByteLength;
        StringTable[Index].MaximumLength = ByteLength;
        StringTable[Index].Padding = 0;
        StringTable[Index].Buffer = (PWSTR)stringDataPtr;
        RtlCopyMemory(stringDataPtr, CurrentBuffer, ByteLength + sizeof(WCHAR));
        stringDataPtr += ByteLength + sizeof(WCHAR);
    }
    JumpNullString = NULL;
    JumpEmptyString = NULL;
    JumpNullBuffer = NULL;
    JumpPercent = NULL;
    JumpScanLoop = NULL;
    ScanLoop = NULL;
    UseReplacement = NULL;
    ContinueOriginal = NULL;
    Cursor = Block;
#define EMIT8(Value) do { *Cursor++ = (UCHAR)(Value); } while (0)
#define EMIT32(Value) do { ULONG EmitValue32 = (ULONG)(Value); RtlCopyMemory(Cursor, &EmitValue32, sizeof(EmitValue32)); Cursor += sizeof(EmitValue32); } while (0)
#define EMIT64(Value) do { ULONG64 EmitValue64 = (ULONG64)(Value); RtlCopyMemory(Cursor, &EmitValue64, sizeof(EmitValue64)); Cursor += sizeof(EmitValue64); } while (0)
    EMIT8(0x52);
    EMIT8(0x48);
    EMIT8(0x85);
    EMIT8(0xC9);
    EMIT8(0x74);
    JumpNullString = Cursor;
    EMIT8(0x00);
    EMIT8(0x0F);
    EMIT8(0xB7);
    EMIT8(0x11);
    EMIT8(0xD1);
    EMIT8(0xEA);
    EMIT8(0x74);
    JumpEmptyString = Cursor;
    EMIT8(0x00);
    if (SkipPercentStrings)
    {
        EMIT8(0x48);
        EMIT8(0x8B);
        EMIT8(0x41);
        EMIT8(0x08);
        EMIT8(0x48);
        EMIT8(0x85);
        EMIT8(0xC0);
        EMIT8(0x74);
        JumpNullBuffer = Cursor;
        EMIT8(0x00);
        ScanLoop = Cursor;
        EMIT8(0x66);
        EMIT8(0x83);
        EMIT8(0x38);
        EMIT8(0x25);
        EMIT8(0x74);
        JumpPercent = Cursor;
        EMIT8(0x00);
        EMIT8(0x48);
        EMIT8(0x83);
        EMIT8(0xC0);
        EMIT8(0x02);
        EMIT8(0xFF);
        EMIT8(0xCA);
        EMIT8(0x75);
        JumpScanLoop = Cursor;
        EMIT8(0x00);
    }
    UseReplacement = Cursor;
    EMIT8(0x49);
    EMIT8(0xBB);
    EMIT64(Counter);
    EMIT8(0xF0);
    EMIT8(0x49);
    EMIT8(0x0F);
    EMIT8(0xBA);
    EMIT8(0x2B);
    EMIT8(0x3F);
    EMIT8(0x73);
    EMIT8(0x04);
    EMIT8(0xF3);
    EMIT8(0x90);
    EMIT8(0xEB);
    EMIT8(0xF4);
    EMIT8(0x4D);
    EMIT8(0x8B);
    EMIT8(0x13);
    EMIT8(0x49);
    EMIT8(0x0F);
    EMIT8(0xBA);
    EMIT8(0xF2);
    EMIT8(0x3F);
    EMIT8(0x48);
    EMIT8(0xC7);
    EMIT8(0xC2);
    EMIT32(BufferCount - 1);
    EMIT8(0x4C);
    EMIT8(0x39);
    EMIT8(0xD2);
    EMIT8(0x4C);
    EMIT8(0x0F);
    EMIT8(0x42);
    EMIT8(0xD2);
    EMIT8(0x49);
    EMIT8(0xC1);
    EMIT8(0xE2);
    EMIT8(0x04);
    EMIT8(0x49);
    EMIT8(0xBB);
    EMIT64(StringTable);
    EMIT8(0x4D);
    EMIT8(0x01);
    EMIT8(0xD3);
    EMIT8(0x4C);
    EMIT8(0x89);
    EMIT8(0xD9);
    EMIT8(0x49);
    EMIT8(0xBB);
    EMIT64(Counter);
    EMIT8(0x49);
    EMIT8(0x8B);
    EMIT8(0x03);
    EMIT8(0x48);
    EMIT8(0xFF);
    EMIT8(0xC0);
    EMIT8(0x48);
    EMIT8(0x0F);
    EMIT8(0xBA);
    EMIT8(0xE8);
    EMIT8(0x3F);
    EMIT8(0x49);
    EMIT8(0x89);
    EMIT8(0x03);
    EMIT8(0xF0);
    EMIT8(0x49);
    EMIT8(0x0F);
    EMIT8(0xBA);
    EMIT8(0x33);
    EMIT8(0x3F);
    ContinueOriginal = Cursor;
    EMIT8(0x5A);
    RtlCopyMemory(Cursor, ExpectedBytes, PatchSize);
    Cursor += PatchSize;
    EMIT8(0x49);
    EMIT8(0xBA);
    EMIT64((ULONG64)((PUCHAR)BcpDisplayCriticalStringAddr + PatchSize));
    EMIT8(0x41);
    EMIT8(0xFF);
    EMIT8(0xE2);
#undef EMIT64
#undef EMIT32
#undef EMIT8
    {
        LONG_PTR Offset;
        Offset = (LONG_PTR)UseReplacement - (LONG_PTR)(JumpNullString + 1);
        if (Offset < -128 || Offset > 127) goto InvalidGeneratedCode;
        *JumpNullString = (UCHAR)(CHAR)Offset;
        Offset = (LONG_PTR)ContinueOriginal - (LONG_PTR)(JumpEmptyString + 1);
        if (Offset < -128 || Offset > 127) goto InvalidGeneratedCode;
        *JumpEmptyString = (UCHAR)(CHAR)Offset;
        if (SkipPercentStrings)
        {
            Offset = (LONG_PTR)UseReplacement - (LONG_PTR)(JumpNullBuffer + 1);
            if (Offset < -128 || Offset > 127) goto InvalidGeneratedCode;
            *JumpNullBuffer = (UCHAR)(CHAR)Offset;
            Offset = (LONG_PTR)ContinueOriginal - (LONG_PTR)(JumpPercent + 1);
            if (Offset < -128 || Offset > 127) goto InvalidGeneratedCode;
            *JumpPercent = (UCHAR)(CHAR)Offset;
            Offset = (LONG_PTR)ScanLoop - (LONG_PTR)(JumpScanLoop + 1);
            if (Offset < -128 || Offset > 127) goto InvalidGeneratedCode;
            *JumpScanLoop = (UCHAR)(CHAR)Offset;
        }
    }
    if ((SIZE_T)(Cursor - Block) != CodeSize) goto InvalidGeneratedCode;
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
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(origCopy, 'OgnB');
        ExFreePool(Block);
        return Status;
    }
    g_BcpDisplayCriticalHookInfo.TargetAddress = BcpDisplayCriticalStringAddr;
    g_BcpDisplayCriticalHookInfo.OriginalCode = origCopy;
    g_BcpDisplayCriticalHookInfo.PatchSize = PatchSize;
    g_BcpDisplayCriticalHookInfo.Trampoline = Block;
    g_BcpDisplayCriticalHookInfo.Installed = TRUE;
    KeMemoryBarrier();
    InstalledBlock = Block;
    return STATUS_SUCCESS;
InvalidGeneratedCode:
    ExFreePoolWithTag(origCopy, 'OgnB');
    ExFreePool(Block);
    return STATUS_INTERNAL_ERROR;
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
    if (!g_BgpTxtDisplayCharHookInfo.Installed) InstallBgpTxtDisplayCharacterHook(g_BgpTxtDisplayCharacter, TbackColor, TforeColor);
    else {
        *g_tbcolor = TbackColor;
        *g_tfcolor = TforeColor;
    }
    KIRQL irql;
    KeRaiseIrql(HIGH_LEVEL, &irql);
    UCHAR hlt[] = { 0xCC, 0xEB, 0xFE, 0xC3 };
    WriteMemory(KeBugCheckEx, hlt, 4);
    InbvAcquireDisplayOwnership();
    UCHAR OldBSOD = 0x00;
    WriteMemory(FindFeatureEnabledBsodRejuvenation(), &OldBSOD, 1);
    WINDOWS_VERSION winver = DetectWindowsVersion();
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
    KIRQL irql;
    KeRaiseIrql(HIGH_LEVEL, &irql);
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
void WriteVGAVideoMemory(UCHAR* String, ULONG BackColor, ULONG TextColor, BOOLEAN Blink) {
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
#pragma intrinsic(_disable)
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
ULONG_PTR FuckYouVM3DMP(ULONG_PTR) {
    _disable();
    KIRQL irql;
    KeRaiseIrql(HIGH_LEVEL, &irql);
    UCHAR hlt[] = { 0xEB, 0xFE, 0xC3 };
    WriteMemory(KeBugCheckEx, hlt, 3);
    return 0;
}
NTSTATUS Write(struct _DEVICE_OBJECT* DeviceObject, struct _IRP* Irp) {
    PIO_STACK_LOCATION Location = IoGetCurrentIrpStackLocation(Irp);
    ULONG bufLen = Location->Parameters.Write.Length;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    if (buffer) {
        CHAR* p = (CHAR*)buffer;
        if (p[0] == 'S' && p[1] == 'P' && p[2] == ' ') { //StopCode
            p = (CHAR*)buffer + 3;
            PWCHAR pUni = NULL;
            if (NT_SUCCESS(ConvertCharToPwchar(p, &pUni))) {
                PVOID pKiDisplayBlueScreen = FindKiDisplayBlueScreen();
                if (pKiDisplayBlueScreen) {
                    PVOID pKeGetBugMessageText = FindKeGetBugMessageText();
                    if (DetectWindowsVersion() != WIN_7) InstallStopCodeHook(pKeGetBugMessageText, pUni, wcslen(pUni) + 1);
                    else {
                        unsigned char pattern[] = { 0x48, 0x8B, 0x05, 0x0E, 0x7A, 0x11, 0x00, 0x4C, 0x8B, 0x1D, 0x0F, 0x7A, 0x11, 0x00, 0x44, 0x8B, 0x0D, 0xE8, 0x79, 0x11, 0x00, 0x4C, 0x89, 0x5C, 0x24, 0x38, 0x48, 0x89, 0x44, 0x24, 0x30, 0x48, 0x8B, 0x05, 0xE7, 0x79, 0x11, 0x00, 0x4C, 0x8D, 0x05, 0x70, 0x44, 0xF5, 0xFF, 0x48, 0x8D, 0x4C, 0x24, 0x40, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0x8B, 0x05, 0xC7, 0x79, 0x11, 0x00, 0x48, 0x8B, 0xD7, 0x48, 0x89, 0x44, 0x24, 0x20, 0xE8, 0x02, 0xF4, 0xF8, 0xFF, 0x48, 0x8D, 0x4C, 0x24, 0x40 };
                        unsigned char mov[10] = { 0x48, 0xB9 };
                        unsigned char stopcode[sizeof(pattern) / sizeof(unsigned char)] = { 0 };
                        for (ULONG i = 0; i < (sizeof(pattern) / sizeof(unsigned char) - sizeof(mov) / sizeof(unsigned char)); i++) {
                            stopcode[i] = 0x90;
                        }
                        char* stopcodetext = (char*)ExAllocatePoolWithTag(NonPagedPool, bufLen + 1, 'StcA');
                        if (!stopcodetext) {
                            Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                            Irp->IoStatus.Information = 0;
                            IoCompleteRequest(Irp, IO_NO_INCREMENT);
                            return STATUS_INSUFFICIENT_RESOURCES;
                        }
                        RtlCopyMemory(stopcodetext, p, bufLen);
                        stopcodetext[bufLen] = '\0';
                        *(ULONG_PTR*)&mov[2] = (ULONG_PTR)stopcodetext;
                        RtlMoveMemory(stopcode + (sizeof(pattern) / sizeof(unsigned char) - sizeof(mov) / sizeof(unsigned char)), mov, sizeof(mov) / sizeof(unsigned char));
                        ULONG_PTR StopcodeAddress = FindAddress(pKiDisplayBlueScreen, pattern, sizeof(pattern) / sizeof(unsigned char));
                        ULONG patternLen = sizeof(pattern) / sizeof(unsigned char);
                        SIZE_T origSize = patternLen;
                        PUCHAR origWin7 = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, origSize, 'Ogn7');
                        if (origWin7) {
                            ReadMemory((PVOID)StopcodeAddress, origWin7, origSize);
                        }
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
        else if (p[0] == 'C' && p[1] == 'T' && p[2] == ' ') { // ChangeText
            p = (CHAR*)buffer + 3;
            CHAR* cur = p;
            while (*cur == ' ' || *cur == '\t') ++cur;
            BOOLEAN skipPercent = FALSE;
            if (*cur == '0' || *cur == '1') {
                skipPercent = (*cur == '1') ? TRUE : FALSE;
                ++cur;
            }
            PWSTR* args = NULL;
            ULONG capacity = 4;
            ULONG argc = 0;
            args = (PWSTR*)ExAllocatePoolWithTag(NonPagedPool, capacity * sizeof(PWSTR), 'StcA');
            while (*cur) {
                while (*cur == ' ' || *cur == '\t') ++cur;
                if (*cur != '"') break;
                ++cur;
                CHAR* start = cur;
                while (*cur && *cur != '"') ++cur;
                if (*cur != '"') break;
                ULONG len = (ULONG)(cur - start);
                PWSTR wstr = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, (len + 1) * sizeof(WCHAR), 'StcA');
                if (!wstr) {
                    for (ULONG i = 0; i < argc; ++i) {
                        ExFreePoolWithTag(args[i], 'StcA');
                    }
                    if (args) ExFreePoolWithTag(args, 'StcA');
                    break;
                }
                ANSI_STRING ansi;
                UNICODE_STRING uni;
                ansi.Buffer = start;
                ansi.Length = (USHORT)len;
                ansi.MaximumLength = (USHORT)len;
                uni.Buffer = wstr;
                uni.MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));
                RtlAnsiStringToUnicodeString(&uni, &ansi, FALSE);
                wstr[len] = L'\0';
                if (argc >= capacity) {
                    capacity *= 2;
                    PWSTR* newArgs = (PWSTR*)ExAllocatePoolWithTag(NonPagedPool, capacity * sizeof(PWSTR), 'StcA');
                    if (!newArgs) {
                        ExFreePoolWithTag(wstr, 'StcA');
                        for (ULONG i = 0; i < argc; ++i) {
                            ExFreePoolWithTag(args[i], 'StcA');
                        }
                        if (args) ExFreePoolWithTag(args, 'StcA');
                        args = NULL;
                        argc = 0;
                        break;
                    }
                    if (args) {
                        RtlCopyMemory(newArgs, args, argc * sizeof(PWSTR));
                        ExFreePoolWithTag(args, 'StcA');
                    }
                    args = newArgs;
                }
                args[argc++] = wstr;
                ++cur;
            }
            if (argc > 0 || (argc == 0 && *cur == '\0')) {
                PWSTR Buffer = NULL;
                PWSTR* Buffers = NULL;
                PWSTR* bufferArray = NULL;
                if (argc >= 1) Buffer = args[0];
                if (argc > 1) {
                    bufferArray = (PWSTR*)ExAllocatePoolWithTag(NonPagedPool, argc * sizeof(PWSTR), 'StcA');
                    if (bufferArray) {
                        for (ULONG i = 1; i < argc; ++i) {
                            bufferArray[i - 1] = args[i];
                        }
                        bufferArray[argc - 1] = NULL;
                        Buffers = bufferArray;
                    }
                    else {
                        Buffer = args[0];
                        Buffers = NULL;
                    }
                }
                else Buffer = NULL;
                if (InstallBcpDisplayCriticalStringHook(g_BcpDisplayCriticalString, skipPercent, Buffer, Buffers) == STATUS_INVALID_PARAMETER) InstallBcpDisplayCriticalStringHook(g_BcpDisplayCriticalStringCentered, skipPercent, Buffer, Buffers);
                if (bufferArray) ExFreePoolWithTag(bufferArray, 'StcA');
            }
            if (args) {
                for (ULONG i = 0; i < argc; ++i) {
                    if (args[i]) ExFreePoolWithTag(args[i], 'StcA');
                }
                ExFreePoolWithTag(args, 'StcA');
            }
        }
        else if (p[0] == 'D' && p[1] == 'S' && p[2] == ' ') { //DisplayString
            CHAR* cmd = p + 3;
            while (*cmd == ' ' || *cmd == '\t') cmd++;
            if (*cmd == '{') cmd++;
            while (*cmd && *cmd != '}') {
                while (*cmd == ' ' || *cmd == '\t') cmd++;
                if (*cmd == '\0' || *cmd == '}') break;
                if (*cmd != '"') break;
                CHAR* strStart = cmd + 1;
                CHAR* strEnd = strStart;
                while (*strEnd && *strEnd != '"') strEnd++;
                if (*strEnd != '"') break;
                ULONG strLen = (ULONG)(strEnd - strStart);
                CHAR* ansiStr = (CHAR*)ExAllocatePoolWithTag(NonPagedPool, strLen + 1, 'DSpA');
                if (!ansiStr) {
                    Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                    Irp->IoStatus.Information = 0;
                    IoCompleteRequest(Irp, IO_NO_INCREMENT);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                RtlCopyMemory(ansiStr, strStart, strLen);
                ansiStr[strLen] = '\0';
                if (DetectWindowsVersion() == WIN_7) {
                    CHAR* numStart = strEnd + 1;
                    while (*numStart == ' ' || *numStart == '\t') numStart++;
                    ULONG backColor, foreColor, blink, vga80x25, rainbow;
                    int converted = sscanf_s(numStart, "%x %x %x %x %x", &backColor, &foreColor, &blink, &vga80x25, &rainbow);
                    if (converted != 5) {
                        ExFreePoolWithTag(ansiStr, 'DSpA');
                        break;
                    }
                    VGAString = (UCHAR*)ansiStr;
                    VGABackColor = backColor;
                    VGAForeColor = foreColor;
                    VGABlink = (BOOLEAN)blink;
                    VGA80x25 = (BOOLEAN)vga80x25;
                    VGARainbow = (BOOLEAN)rainbow;
                    KeIpiGenericCall(FuckYouVM3DMP, 0);
                    KeIpiGenericCall(Display, 0);
                    ExFreePoolWithTag(VGAString, 'DSpA');
                    VGAString = NULL;
                    cmd = numStart;
                    while (*cmd && *cmd != ',' && *cmd != '}') cmd++;
                    if (*cmd == ',') cmd++;
                }
                else {
                    PWCHAR wstr = NULL;
                    ANSI_STRING ansi;
                    UNICODE_STRING uni;
                    RtlInitAnsiString(&ansi, ansiStr);
                    ULONG wlen = RtlAnsiStringToUnicodeSize(&ansi) / sizeof(WCHAR);
                    wstr = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, (wlen + 1) * sizeof(WCHAR), 'DSpW');
                    if (!wstr) {
                        ExFreePoolWithTag(ansiStr, 'DSpA');
                        Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                        Irp->IoStatus.Information = 0;
                        IoCompleteRequest(Irp, IO_NO_INCREMENT);
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                    uni.Buffer = wstr;
                    uni.MaximumLength = (USHORT)((wlen + 1) * sizeof(WCHAR));
                    if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&uni, &ansi, FALSE))) {
                        ExFreePoolWithTag(wstr, 'DSpW');
                        ExFreePoolWithTag(ansiStr, 'DSpA');
                        break;
                    }
                    ExFreePoolWithTag(ansiStr, 'DSpA');
                    CHAR* numStart = strEnd + 1;
                    while (*numStart == ' ' || *numStart == '\t') numStart++;
                    ULONG TextSize, TbackColor, TforeColor, X, Y;
                    ULONG64 backgroundColor;
                    BOOLEAN ClearScreen;
                    int converted = sscanf_s(numStart, "%x %x %x %llx %x %x %u", &TextSize, &TbackColor, &TforeColor, &backgroundColor, &X, &Y, &ClearScreen);
                    if (converted != 7) {
                        ExFreePoolWithTag(wstr, 'DSpW');
                        break;
                    }
                    DisplayString(wstr, TextSize, TbackColor, TforeColor, backgroundColor, X, Y, ClearScreen);
                    ExFreePoolWithTag(wstr, 'DSpW');
                    cmd = numStart;
                    while (*cmd && *cmd != ',' && *cmd != '}') cmd++;
                    if (*cmd == ',') cmd++;
                }
            }
        }
        else if (p[0] == 'C' && p[1] == '7' && p[2] == ' ') { //ChangeColorForWindows7
            p = (CHAR*)buffer + 3;
            sscanf_s(p, "%lu %lu", &foreColor, &backColor);
            if (CallbackRegistered) KeDeregisterBugCheckReasonCallback(&CallbackRecord);
            CallbackRecord.State = 0;
            KeRegisterBugCheckReasonCallback(&CallbackRecord, (PKBUGCHECK_REASON_CALLBACK_ROUTINE)ChangeBSODColor, KbCallbackReserved1, (PUCHAR)"BSOD");
            CallbackRegistered = TRUE;
        }
        else if (p[0] == 'R' && p[1] == '7') { //RainbowBSODForWindows7
            if (CallbackRegistered) KeDeregisterBugCheckReasonCallback(&CallbackRecord);
            CallbackRecord.State = 0;
            KeRegisterBugCheckReasonCallback(&CallbackRecord, (PKBUGCHECK_REASON_CALLBACK_ROUTINE)RainbowBSOD, KbCallbackReserved1, (PUCHAR)"BSOD");
            CallbackRegistered = TRUE;
        }
        else if (p[0] == 'R' && p[1] == 'D') { //(Fake)RainbowBSOD
            InstallBgpTxtDisplayCharacterHook(g_BgpTxtDisplayCharacter, 0x00000000, 0xFFFFFFFF);
            InstallBgpClearScreenHook(g_BgpClearScreen, 0x0000000000000000);
            HANDLE hThread = NULL;
            PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr, Thread, nullptr);
        }
        else if (p[0] == 'B' && p[1] == 'C') { //BugCheck
            if (DetectWindowsVersion() == WIN_7) KeBugCheck(0x0000000000114514);
            else KeBugCheckEx(0x0000000000000001, 0x00000E2700000000, 0x0000000000000100, 0xFFFFD80F92CE1000, 0xFFFFF8005FE7D180);
        }
    }
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    g_BgpClearScreen = FindBgpClearScreen();
    g_BgpTxtDisplayCharacter = FindBgpTxtDisplayCharacter();
    g_BcpDisplayCriticalString = FindBcpDisplayCriticalString();
    g_BcpDisplayCriticalStringCentered = FindBcpDisplayCriticalStringCentered();
    PHYSICAL_ADDRESS physAddr;
    physAddr.QuadPart = 0xB8000;
    pVGABuffer = (PUCHAR)MmMapIoSpace(physAddr, 8000, MmNonCached);
    PDEVICE_OBJECT pDev = NULL;
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Device\\N_BSOD");
    UNICODE_STRING linkName = RTL_CONSTANT_STRING(L"\\??\\BSOD");
    IoCreateDevice(DriverObject, 0, &name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDev);
    IoCreateSymbolicLink(&linkName, &name);
    if (pDev != NULL) {
        DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateOrClose;
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateOrClose;
        DriverObject->MajorFunction[IRP_MJ_WRITE] = Write;
        pDev->Flags |= DO_BUFFERED_IO;
    }
    return STATUS_SUCCESS;
}
