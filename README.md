# CustomBSOD_v2

A Windows kernel driver and companion user-mode application that allow you to fully customize the Blue Screen of Death (BSOD) display — change colors, modify text strings, and tailor the crash screen appearance across Windows 7 through Windows 11.

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
| **Modify QR code** | Modify the QR code to make it display your own image ![](/../main/assets/mqc.png) |
| **Display strings** | Display your own strings on the screen ![](/../main/assets/ds.png) |
| **Display images**| Display your own images on the screen ![](/../main/assets/di.png) |
| **Rainbow BSOD** | Use hooks or callback functions to implement a blue screen that constantly changes colors ![](/../main/assets/rb.png) |
| **VGA Mode Support** | Supports 80x25 and 80x50 modes in VGA text mode and supports blinking and rainbow mode (Windows 7 only) ![](/../main/assets/vga.png) |
| **Manual BugCheck** | Trigger a controlled system crash for testing purposes |

![](/../main/assets/2.png)

## Supported Windows Versions

| OS Version | Build Range | Status |
|-----------|-------------|--------|
| Windows 7 | 6.1 | Supported |
| Windows 8 / 8.1 | 6.2 – 6.3 | Supported |
| Windows 10 | 10240+ | Supported |
| Windows 11 24H2 | 26100 | Supported |
| Windows 11 25H2 | 26200 | Supported |
| Windows 11 26H1 | 28000 | Supported |

## How It Works

### 1. Function Discovery (Kernel)

The driver uses byte-pattern scanning to locate undocumented internal Windows kernel functions at runtime. This avoids hardcoded offsets that would break across Windows versions.

Key functions discovered:
- `KeBugCheckEx` - The export function
- `KeBugCheck2` - The functions called internally by `KeBugCheckEx`
- `KiDisplayBlueScreen` - The function for rendering the BSOD
- `BgpFwDisplayBugCheckScreen`- The functions called internally by `KiDisplayBlueScreen`, which is actually used for rendering the blue screen
- `BcpDisplayCriticalString` - The function is used to render text, such as ":("
- `BcpDisplayCriticalStringCentered` - Just like `BcpDisplayCriticalString`, but it appeared after the Windows 11 25H2 version
- `BgpClearScreen` - The function renders the background of the BSOD.
- `BgpTxtDisplayCharacter` - The function is used to render **one** character on the BSOD.

### 2. Inline Hooking

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
- **Stop code text** — the bugcheck error code string is replaced with user-defined text
- **Background color** — the `BgpClearScreen` call is patched to use a custom background color
- **Foreground color** — the `BgpTxtDisplayCharacter` call is patched with custom foreground/background colors (texts)
- **Display strings** — use `BcpDisplayCriticalString` and `BcpDisplayCriticalStringCentered`

### 3. User-Mode GUI

The `CustomBSOD_v2` application provides a WinForms-based interface.

Startup sequence:
1. Checks if **testsigning** mode is enabled (required for loading unsigned drivers)
2. Extracts the embedded driver binary to disk
3. Creates the driver service registry and load the driver
4. Show the main window

### Have Fun!
![](/../main/assets/3.gif)
