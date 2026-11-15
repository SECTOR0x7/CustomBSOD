# CustomBSOD_v2

A Windows kernel driver and companion user-mode application that allow you to fully customize the Blue Screen of Death (BSOD) display — change colors, modify text strings, and tailor the crash screen appearance across Windows 7 through Windows 11.

# ⚠This program may be detected by **`PatchGuard`**!
This program uses inline hook technology, which modifies the .text segment of ntoskrnl.
`PatchGuard` will periodically scan the .text segment of ntoskrnl.
Once any abnormalities are detected, it will trigger a **blue screen**, even if you didn't manually trigger the blue screen.

## Architecture Overview

```
┌──────────────────────────────────────────────────┐
│                  User Mode (R3)                  │
│  ┌────────────────────────────────────────────┐  │
│  │         CustomBSOD_v2.exe                  │  │
│  │  • Configuration GUI (WinForms)            │  │
│  │  • Driver registry creation & loading      │  │
│  │  • Embedded driver binary                  │  │
│  │  • Manual BugCheck trigger                 │  │
│  └──────────────┬─────────────────────────────┘  │
│                 │ NtLoadDriver                   │
├─────────────────┼────────────────────────────────┤
│                 │     Kernel Mode (R0)           │
│  ┌──────────────▼─────────────────────────────┐  │
│  │              BSOD.sys                      │  │
│  │  • Pattern-based kernel function discovery │  │
│  │  • Inline hooking of BSOD display routines │  │
│  │  • Multi-version Windows support           │  │
│  │  • VGA text-mode manipulation              │  │
│  │  • Background / foreground color control   │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```
![](/../main/assets/1.png)
## Features

| Feature | Description |
|---------|-------------|
| **Custom Stop Code Text** | Replace the default bugcheck stop code string with your own message ![](/../main/assets/sp.png) |
| **Background Color** | Change the BSOD background to any color ![](/../main/assets/bgc.png) |
| **Foreground/Text Color** | Set a custom text color for the crash screen ![](/../main/assets/ftc.png) |
| **Change BSOD Texts** | Change the BSOD text ![](/../main/assets/cbt.png) |
| **Modify QR code** | Modify the QR code to make it display your own image ![](/../main/assets/mqc.png) |
| **Display strings** | Display your own strings on the screen ![](/../main/assets/ds.png) |
| **Display images**| Display your own images on the screen ![](/../main/assets/di.png) |
| **Rainbow BSOD** | Use hooks or callback functions to implement a blue screen that constantly changes colors ![](/../main/assets/rb.gif) |
| **VGA Mode Support** | Supports 80x25 and 80x50 modes in VGA text mode and supports blinking and rainbow mode (Windows 7 only) ![](/../main/assets/vga.gif) |
| **Manual BugCheck** | Trigger a controlled system crash for testing purposes |

## Supported Windows Versions

| OS Version | Build Range | Status |
|-----------|-------------|--------|
| Windows 7 | 6.1 | Supported |
| Windows 8 / 8.1 | 6.2 – 6.3 | Supported |
| Windows 10 | 19045+ | Supported |
| Windows 11 | 26100+ | Supported |

## How It Works

### 1. Function Discovery (Kernel)

The driver uses byte-pattern scanning to locate undocumented internal Windows kernel functions at runtime. This avoids hardcoded offsets that would break across Windows versions.

Key functions discovered:
- `KeBugCheckEx` - The export function
- `KeBugCheck2` - The function called internally by `KeBugCheckEx`
- `KeGetBugMessageText` - The function retrieves the hexadecimal stop code and converts it to its string representation
- `KiDisplayBlueScreen` - The function for rendering the BSOD
- `BgpFwDisplayBugCheckScreen`- The functions called internally by `KiDisplayBlueScreen`, which is actually used for rendering the blue screen
- `BcpDisplayCriticalString` - This function is used to render text, such as ":("
- `BcpDisplayCriticalStringCentered` - Just like `BcpDisplayCriticalString`, but it appeared after the Windows 11 25H2 version
- `BgpClearScreen` - This function renders the background of the BSOD.
- `BgpTxtDisplayCharacter` - This function is used to render **one** character on the BSOD.
- `BgpGxDrawRectangle` - This function is used for writing to the `video memory`, it will eventually use `DpiSystemDisplayWrite`
- `KiSendFreeze` - This function is used to freeze other CPUs that are not currently experiencing BSOD
- `KiSetDebuggerOwner` - This function sets the current processor as the debugger owner.
- `DpiSystemDisplayWrite` - **(Not used)** DpiSystemDisplayWrite is at a more fundamental level and is used for directly writing to the video memory. It's in `dxgkrnl.sys`, information related to `DpiSystemDisplayWrite`, visit https://github.com/WindowsKin/Bcp-Rendering-Engine-Usage-in-Windows-NT-Kernel-BSOD

Function Call Graph:
![](/../main/assets/CallGraph.png)
                                
### 2. Variable Discovery (Kernel)

The driver selects instructions by Windows version and decodes their RIP-relative addressing to resolve BSOD-related global variable addresses.

Key variables discovered:

- `FeatureEnabledBsodRejuvenation` - Used by `KiDisplayBlueScreen`; `1` enables the centered Windows 11 layout, while `0` restores the Windows 10-style layout with `:(`.
- `BcpCursor` - Used by `BgpFwDisplayBugCheckScreen`; points to the cursor state `{ ULONG X, Y, Unknown; }` for text positioning. The third field remains unconfirmed; the following code guesses the layout of `BcpCursor`:

  ```c
  ULONG BcpCursor[] = { X, Y, winver >= WIN_11_25H2 ? (winver == WIN_11_26H1 ? Y : 0) : X };
  ```

- `BgInternal+0xF8` - Used by `BgpFwDisplayBugCheckScreen`; stores the QR image descriptor pointer. Access it as a pointer-to-pointer using `*(PGP_RECT_DESC*)BgInternal_0xF8` to obtain a pointer to this structure:

  ```c
  typedef struct {
      ULONG H;
      ULONG W;
      ULONG BitsPerPixel;
      ULONG Stride;
      ULONG Flags;
      ULONG Padding;
      ULONG* PixelData;
  } GP_RECT_DESC, * PGP_RECT_DESC;
  ```

- `KeActiveProcessors` - Used by `KeBugCheck2`; records active logical processors to identify which processors to freeze, excluding the processor handling the BugCheck.
- `KiBugCheckDriver` - Used by `KiDisplayBlueScreen`; stores a `UNICODE_STRING` pointer containing the faulting driver name for the "What Failed:" field.

### 3. Inline Hooking

The driver installs trampoline-based inline hooks on the discovered functions:

```
Original Function        Hooked Function
─────────────────        ───────────────
[prologue bytes]    →    [JMP trampoline]
[ body ...     ]         [trampoline]
[ ...          ]         [original prologue]
                         [JMP back to body]
```

Hooks are installed for:
- **Stop code text** — the `KeGetBugMessageText` call is patched to replaced with user-defined text
- **Background color** — the `BgpClearScreen` call is patched to use a custom background color
- **Foreground color** — the `BgpTxtDisplayCharacter` call is patched with custom foreground/background colors (texts)
- **Change Text** — the `BcpDisplayCriticalString` or `BcpDisplayCriticalStringCentered` call is patched with custom texts
- **QR Code** — the `BgpFwDisplayBugCheckScreen` call is patched to use a custom picture

### 4. User-Mode GUI

The `CustomBSOD_v2` application provides a WinForms-based interface.

Startup sequence:
1. Checks if **testsigning** mode is enabled (required for loading unsigned drivers)
2. Extracts the embedded driver binary to disk
3. Creates the driver service registry and load the driver
4. Show the main window

## Have Fun!
![](/../main/assets/3.gif)
