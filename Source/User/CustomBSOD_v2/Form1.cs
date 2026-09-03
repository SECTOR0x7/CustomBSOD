using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
using System.IO;
using System.Diagnostics;

namespace BsodController
{
    internal static class Program
    {
        [DllImport("user32.dll")]
        private static extern bool SetProcessDPIAware();

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        private static extern void RtlInitUnicodeString(out UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        [DllImport("ntdll.dll")]
        private static extern uint NtCreateKey(out IntPtr KeyHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, uint TitleIndex, IntPtr Class, uint CreateOptions, out uint Disposition);

        [DllImport("ntdll.dll")]
        private static extern uint NtSetValueKey(IntPtr KeyHandle, ref UNICODE_STRING ValueName, uint TitleIndex, uint Type, IntPtr Data, uint DataSize);

        [DllImport("ntdll.dll")]
        private static extern uint NtLoadDriver(ref UNICODE_STRING DriverServiceName);

        [DllImport("ntdll.dll")]
        private static extern uint RtlAdjustPrivilege(uint Privilege, bool Enable, bool CurrentThread, out bool Enabled);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandleW(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int RtlGetVersion(ref OSVERSIONINFOW lpVersionInformation);
        public static int[] GetSystemVersion()
        {
            var osvi = new OSVERSIONINFOW();
            osvi.dwOSVersionInfoSize = (uint)Marshal.SizeOf(osvi);
            int status = RtlGetVersion(ref osvi);
            if (status == 0)
            {
                return new int[]
                {
                    (int)osvi.dwMajorVersion,
                    (int)osvi.dwMinorVersion,
                    (int)osvi.dwBuildNumber
                };
            }
            return new int[] { 0, 0, 0 };
        }

        public static bool IsWindows7()
        {
            int[] version = GetSystemVersion();
            return version.Length >= 2 && version[0] == 6 && version[1] == 1;
        }

        public static bool IsWindows8()
        {
            int[] version = GetSystemVersion();
            return version[0] == 6 && (version[1] == 2 || version[1] == 3);
        }

        public static bool IsWindows11NewBlueScreen()
        {
            int[] version = GetSystemVersion();
            return version.Length >= 3 && version[0] >= 10 && (version[2] > 26100 || (version[2] == 26100 && GetSystemUbr() >= 4770));
        }

        private static int GetSystemUbr()
        {
            try
            {
                using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    object value = key == null ? null : key.GetValue("UBR");
                    return value == null ? 0 : Convert.ToInt32(value, CultureInfo.InvariantCulture);
                }
            }
            catch
            {
                return 0;
            }
        }

        public static bool ForceWindows10BlueScreenEffect { get; set; }

        public static bool IsQrCustomizationSupported()
        {
            int[] version = GetSystemVersion();
            return version.Length >= 3 && version[0] == 10 && version[2] >= 10240 && version[2] <= 26100 && GetSystemUbr() < 4770;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct OBJECT_ATTRIBUTES
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct OSVERSIONINFOW
        {
            public uint dwOSVersionInfoSize;
            public uint dwMajorVersion;
            public uint dwMinorVersion;
            public uint dwBuildNumber;
            public uint dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
        }

        private static OBJECT_ATTRIBUTES InitializeObjectAttributes(IntPtr ObjectName, uint Attributes, IntPtr RootDirectory, IntPtr SecurityDescriptor)
        {
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES
            {
                Length = (uint)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
                RootDirectory = RootDirectory,
                ObjectName = ObjectName,
                Attributes = Attributes,
                SecurityDescriptor = SecurityDescriptor,
                SecurityQualityOfService = IntPtr.Zero
            };
            return oa;
        }

        private const uint KEY_ALL_ACCESS = 0xF003F;
        private const uint REG_OPTION_NON_VOLATILE = 0x00000000;
        private const uint REG_DWORD = 4;
        private const uint REG_EXPAND_SZ = 2;
        private const uint OBJ_CASE_INSENSITIVE = 0x00000040;
        private const uint SE_LOAD_DRIVER_PRIVILEGE = 10;
        private static bool CreateDriverRegistry(string serviceName, string sysPath)
        {
            string ntRegPath = $@"\Registry\Machine\SYSTEM\CurrentControlSet\Services\{serviceName}";
            RtlInitUnicodeString(out UNICODE_STRING keyName, ntRegPath);
            IntPtr pKeyName = Marshal.AllocHGlobal(Marshal.SizeOf<UNICODE_STRING>());
            Marshal.StructureToPtr(keyName, pKeyName, false);
            OBJECT_ATTRIBUTES objAttr = InitializeObjectAttributes(pKeyName, OBJ_CASE_INSENSITIVE, IntPtr.Zero, IntPtr.Zero);
            uint status = NtCreateKey(out IntPtr hKey, KEY_ALL_ACCESS, ref objAttr, 0, IntPtr.Zero, REG_OPTION_NON_VOLATILE, out uint disposition);
            Marshal.FreeHGlobal(pKeyName);
            if (status != 0) return false;
            Tuple<string, uint, uint>[] vals = new Tuple<string, uint, uint>[]
            {
                Tuple.Create("Type", REG_DWORD, 1u),
                Tuple.Create("Start", REG_DWORD, 3u),
                Tuple.Create("ErrorControl", REG_DWORD, 1u)
            };
            foreach (var v in vals)
            {
                RtlInitUnicodeString(out UNICODE_STRING valName, v.Item1);
                IntPtr pData = Marshal.AllocHGlobal(sizeof(uint));
                Marshal.WriteInt32(pData, (int)v.Item3);
                status = NtSetValueKey(hKey, ref valName, 0, v.Item2, pData, sizeof(uint));
                Marshal.FreeHGlobal(pData);
                if (status != 0)
                {
                    CloseHandle(hKey);
                    return false;
                }
            }
            string currentDir = Directory.GetCurrentDirectory();
            string imagePath = $@"\??\{currentDir}\{sysPath}";
            RtlInitUnicodeString(out UNICODE_STRING valImagePath, "ImagePath");
            byte[] imagePathBytes = Encoding.Unicode.GetBytes(imagePath + "\0");
            IntPtr pImagePath = Marshal.AllocHGlobal(imagePathBytes.Length);
            Marshal.Copy(imagePathBytes, 0, pImagePath, imagePathBytes.Length);
            status = NtSetValueKey(hKey, ref valImagePath, 0, REG_EXPAND_SZ, pImagePath, (uint)imagePathBytes.Length);
            Marshal.FreeHGlobal(pImagePath);
            if (status != 0)
            {
                CloseHandle(hKey);
                return false;
            }
            CloseHandle(hKey);
            return true;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_CODEINTEGRITY_INFORMATION
        {
            public uint Length;
            public uint CodeIntegrityOptions;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        public static bool IsTestSigningEnabled()
        {
            int size = Marshal.SizeOf(typeof(SYSTEM_CODEINTEGRITY_INFORMATION));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                SYSTEM_CODEINTEGRITY_INFORMATION info = new SYSTEM_CODEINTEGRITY_INFORMATION { Length = (uint)size };
                Marshal.StructureToPtr(info, buffer, false);
                if (NtQuerySystemInformation(103, buffer, (uint)size, out _) != 0) return false;
                info = (SYSTEM_CODEINTEGRITY_INFORMATION)Marshal.PtrToStructure(buffer, typeof(SYSTEM_CODEINTEGRITY_INFORMATION));
                return (info.CodeIntegrityOptions & 2) != 0;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        [STAThread]
        private static void Main()
        {
            SetProcessDPIAware();
            if (!IsTestSigningEnabled())
            {
                MessageBox.Show("当前系统未打开testsigning，无法正常加载驱动！\n请打开管理员cmd并输入以下命令后重启系统:\nbcdedit /set testsigning on", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Process.Start("cmd.exe", $"/c @echo 是否执行bcdedit /set testsigning on？&@echo 按下任意键执行此命令并重启系统...&@pause>nul 2>&1&%windir%\\{(Environment.Is64BitProcess ? "System32" : "Sysnative")}\\bcdedit.exe /set testsigning on&&shutdown -r -t 0 -f||echo 设置失败！请尝试手动设置&pause>nul 2>&1");
                Environment.Exit(1);
            }
            byte[] sysFileContent = new byte[] {
	            //BSOD.sys的驱动数据
            };
            try
            {
                File.WriteAllBytes("BSOD.sys", sysFileContent);
            }
            catch { }
            string drvName = "CustomBSOD";
            CreateDriverRegistry(drvName, "BSOD.sys");
            RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, true, false, out _);
            string regPath = $@"\Registry\Machine\System\CurrentControlSet\Services\{drvName}";
            RtlInitUnicodeString(out UNICODE_STRING us, regPath);
            NtLoadDriver(ref us);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }

    internal static class Ui
    {
        public static readonly Color Window = Color.FromArgb(244, 247, 251);
        public static readonly Color Sidebar = Color.White;
        public static readonly Color Card = Color.White;
        public static readonly Color CardAlt = Color.FromArgb(239, 244, 250);
        public static readonly Color Input = Color.FromArgb(250, 252, 255);
        public static readonly Color Border = Color.FromArgb(215, 224, 236);
        public static readonly Color Accent = Color.FromArgb(37, 99, 235);
        public static readonly Color AccentHover = Color.FromArgb(29, 78, 216);
        public static readonly Color Text = Color.FromArgb(24, 34, 52);
        public static readonly Color Muted = Color.FromArgb(91, 107, 132);
        public static readonly Color Green = Color.FromArgb(22, 163, 116);
        public static readonly Color Red = Color.FromArgb(214, 54, 74);
        public static readonly Color Amber = Color.FromArgb(194, 120, 3);
        public static readonly Color SoftWarning = Color.FromArgb(255, 248, 229);
        public static readonly Color SoftPurple = Color.FromArgb(249, 244, 255);
        public static readonly Color SoftRed = Color.FromArgb(255, 242, 244);

        public static Label Label(string text, float size, FontStyle style, Color color)
        {
            return new Label
            {
                AutoSize = true,
                Text = text,
                ForeColor = color,
                Font = new Font("Segoe UI", size, style),
                BackColor = Color.Transparent
            };
        }

        public static TextBox TextBox(string text, bool multiline)
        {
            return new TextBox
            {
                Text = text,
                Multiline = multiline,
                BorderStyle = BorderStyle.FixedSingle,
                BackColor = Input,
                ForeColor = Text,
                Font = new Font("Segoe UI", 10F),
                ScrollBars = multiline ? ScrollBars.Vertical : ScrollBars.None
            };
        }

        public static CheckBox CheckBox(string text, bool value)
        {
            return new CheckBox
            {
                Text = text,
                Checked = value,
                AutoSize = true,
                ForeColor = Text,
                BackColor = Color.Transparent,
                Font = new Font("Segoe UI", 9.5F),
                FlatStyle = FlatStyle.Flat
            };
        }

        public static void RoundRegion(Control control, int radius)
        {
            if (control.Width <= 0 || control.Height <= 0) return;
            using (GraphicsPath path = RoundedPath(new Rectangle(0, 0, control.Width, control.Height), radius)) control.Region = new Region(path);
        }

        public static GraphicsPath RoundedPath(Rectangle bounds, int radius)
        {
            int diameter = radius * 2;
            GraphicsPath path = new GraphicsPath();
            path.AddArc(bounds.Left, bounds.Top, diameter, diameter, 180, 90);
            path.AddArc(bounds.Right - diameter, bounds.Top, diameter, diameter, 270, 90);
            path.AddArc(bounds.Right - diameter, bounds.Bottom - diameter, diameter, diameter, 0, 90);
            path.AddArc(bounds.Left, bounds.Bottom - diameter, diameter, diameter, 90, 90);
            path.CloseFigure();
            return path;
        }
    }

    internal sealed class DeviceClient
    {
        public const string DevicePath = @"\\.\BSOD";
        private const uint GenericRead = 0x80000000;
        private const uint GenericWrite = 0x40000000;
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint OpenExisting = 3;
        private const uint FileAttributeNormal = 0x00000080;
        private static readonly IntPtr InvalidHandleValue = new IntPtr(-1);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ReadFile(IntPtr hFile, out GP_RECT_DESC lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
        public struct GP_RECT_DESC
        {
            public uint H;
            public uint W;
            public uint BitsPerPixel;
            public uint Stride;
            public uint Flags;
            public uint Padding;
            public IntPtr PixelData;
        }

        public void Probe()
        {
            IntPtr handle = OpenDevice(GenericWrite);
            CloseHandle(handle);
        }

        public void Send(string command)
        {
            if (string.IsNullOrWhiteSpace(command)) throw new ArgumentException("命令不能为空", "command");
            byte[] data = Encoding.Default.GetBytes(command + "\0");
            IntPtr handle = OpenDevice(GenericRead | GenericWrite);
            try
            {
                uint bytesWritten;
                bool success = WriteFile(handle, data, checked((uint)data.Length), out bytesWritten, IntPtr.Zero);
                if (!success)
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error, "WriteFile 写入设备失败");
                }
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        public GP_RECT_DESC ReadRectangleDescription()
        {
            IntPtr handle = OpenDevice(GenericWrite | GenericRead);
            try
            {
                GP_RECT_DESC description;
                uint expectedSize = checked((uint)Marshal.SizeOf(typeof(GP_RECT_DESC)));
                uint bytesRead;
                bool success = ReadFile(handle, out description, expectedSize, out bytesRead, IntPtr.Zero);
                if (!success)
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error, "ReadFile 读取 GP_RECT_DESC 失败");
                }
                if (bytesRead < expectedSize) throw new InvalidOperationException("ReadFile 返回的 GP_RECT_DESC 数据不完整");
                return description;
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        private static IntPtr OpenDevice(uint desiredAccess)
        {
            IntPtr handle = CreateFileW(DevicePath, desiredAccess, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, FileAttributeNormal, IntPtr.Zero);
            if (handle == InvalidHandleValue)
            {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error, "CreateFileW 无法打开设备 " + DevicePath + "");
            }
            return handle;
        }
    }

    internal delegate bool CommandRequestHandler(string command, string successMessage);
    internal delegate bool LargeCommandRequestHandler(string command, string confirmationMessage, string successMessage);
    internal delegate void PreviewRequestHandler(PreviewSnapshot snapshot, string title);
    internal delegate DeviceClient.GP_RECT_DESC RectDescriptionRequestHandler();

    internal sealed class ModernButton : Button
    {
        private bool _hover;
        private bool _selected;
        private bool _adjustingSize;
        private Color _baseColor = Ui.Accent;

        public ModernButton()
        {
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            ForeColor = Color.White;
            Font = new Font("Segoe UI Semibold", 9.5F, FontStyle.Bold);
            Cursor = Cursors.Hand;
            Height = 40;
            BackColor = _baseColor;
            AutoEllipsis = false;
            UseVisualStyleBackColor = false;
            Padding = new Padding(12, 0, 12, 0);
        }

        public Color BaseColor
        {
            get { return _baseColor; }
            set { _baseColor = value; RefreshColor(); }
        }

        public bool SelectedState
        {
            get { return _selected; }
            set { _selected = value; RefreshColor(); }
        }

        protected override void OnMouseEnter(EventArgs e)
        {
            _hover = true;
            RefreshColor();
            base.OnMouseEnter(e);
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            _hover = false;
            RefreshColor();
            base.OnMouseLeave(e);
        }

        protected override void OnTextChanged(EventArgs e)
        {
            base.OnTextChanged(e);
            EnsureTextFits();
        }

        protected override void OnFontChanged(EventArgs e)
        {
            base.OnFontChanged(e);
            EnsureTextFits();
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            EnsureTextFits();
            Ui.RoundRegion(this, 7);
        }

        private void EnsureTextFits()
        {
            if (_adjustingSize || string.IsNullOrEmpty(Text) || Font == null) return;
            Size measured = TextRenderer.MeasureText(Text, Font, new Size(int.MaxValue, int.MaxValue), TextFormatFlags.SingleLine | TextFormatFlags.NoPadding);
            int minimumWidth = measured.Width + Padding.Horizontal + 22;
            int minimumHeight = measured.Height + 16;
            if (Width >= minimumWidth && Height >= minimumHeight) return;
            _adjustingSize = true;
            Size = new Size(Math.Max(Width, minimumWidth), Math.Max(Height, minimumHeight));
            _adjustingSize = false;
        }

        private void RefreshColor()
        {
            Color actual;
            if (_selected) actual = Ui.Accent;
            else if (_hover) actual = _baseColor == Ui.Accent ? Ui.AccentHover : (IsDark(_baseColor) ? ControlPaint.Light(_baseColor, 0.08F) : Color.FromArgb(226, 234, 246));
            else actual = _baseColor;
            BackColor = actual;
            ForeColor = IsDark(actual) ? Color.White : Ui.Text;
            FlatAppearance.MouseOverBackColor = actual;
            FlatAppearance.MouseDownBackColor = IsDark(actual) ? ControlPaint.Dark(actual, 0.06F) : Color.FromArgb(214, 225, 241);
        }

        private static bool IsDark(Color color)
        {
            double luminance = (0.299 * color.R) + (0.587 * color.G) + (0.114 * color.B);
            return luminance < 155.0;
        }
    }

    internal sealed class CardPanel : Panel
    {
        public CardPanel()
        {
            BackColor = Ui.Card;
            Padding = new Padding(22);
            DoubleBuffered = true;
            Resize += delegate { Ui.RoundRegion(this, 12); Invalidate(); };
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            if (Width < 3 || Height < 3) return;
            using (Pen pen = new Pen(Ui.Border))
            using (GraphicsPath path = Ui.RoundedPath(new Rectangle(0, 0, Width - 1, Height - 1), 12))
            {
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                e.Graphics.DrawPath(pen, path);
            }
        }
    }

    internal class PageView : Panel
    {
        private readonly FlowLayoutPanel _stack;

        public PageView(string title, string subtitle)
        {
            Dock = DockStyle.Fill;
            BackColor = Ui.Window;
            _stack = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                Padding = new Padding(30, 24, 30, 30),
                BackColor = Ui.Window
            };
            Controls.Add(_stack);
            Panel heading = new Panel { Height = 78, BackColor = Ui.Window, Margin = new Padding(0, 0, 0, 12) };
            Label titleLabel = Ui.Label(title, 20F, FontStyle.Bold, Ui.Text);
            titleLabel.Location = new Point(0, 0);
            Label subLabel = Ui.Label(subtitle, 9.5F, FontStyle.Regular, Ui.Muted);
            subLabel.Location = new Point(1, 53);
            heading.Controls.Add(titleLabel);
            heading.Controls.Add(subLabel);
            _stack.Controls.Add(heading);
            _stack.ClientSizeChanged += delegate { ResizeChildren(); };
        }

        public void AddCard(Control control)
        {
            control.Margin = new Padding(0, 0, 0, 16);
            _stack.Controls.Add(control);
            ResizeChildren();
        }

        private void ResizeChildren()
        {
            int width = Math.Max(700, _stack.ClientSize.Width - _stack.Padding.Horizontal - 22);
            foreach (Control control in _stack.Controls) control.Width = width;
        }
    }

    internal sealed class ColorPickerBox : UserControl
    {
        private readonly Label _label;
        private readonly Panel _preview;
        private readonly TextBox _hex;
        private uint _value;

        public ColorPickerBox(string label, uint value)
        {
            Height = 60;
            Width = 265;
            BackColor = Color.Transparent;
            _label = Ui.Label(label, 8.5F, FontStyle.Regular, Ui.Muted);
            _label.Location = new Point(0, 0);
            Controls.Add(_label);
            _preview = new Panel
            {
                Location = new Point(0, 25),
                Size = new Size(34, 29),
                Cursor = Cursors.Hand,
                BorderStyle = BorderStyle.FixedSingle
            };
            _preview.Click += PickColor;
            Controls.Add(_preview);
            _hex = Ui.TextBox(string.Empty, false);
            _hex.CharacterCasing = CharacterCasing.Upper;
            _hex.Location = new Point(42, 25);
            _hex.Size = new Size(118, 29);
            _hex.MaxLength = 10;
            _hex.Leave += delegate { ParseHex(); };
            _hex.KeyDown += delegate (object sender, KeyEventArgs e)
            {
                if (e.KeyCode == Keys.Enter) { ParseHex(); e.SuppressKeyPress = true; }
            };
            Controls.Add(_hex);
            ModernButton pick = new ModernButton
            {
                Text = "调色",
                Location = new Point(168, 24),
                Size = new Size(88, 31),
                BaseColor = Ui.CardAlt
            };
            pick.Click += PickColor;
            Controls.Add(pick);
            Value = value;
        }

        public uint Value
        {
            get { ParseHex(); return _value; }
            set
            {
                _value = value;
                _hex.Text = value.ToString("X8", CultureInfo.InvariantCulture);
                _preview.BackColor = Color.FromArgb(unchecked((int)value));
            }
        }

        public uint VgaDacValue
        {
            get
            {
                ParseHex();
                Color color = Color.FromArgb(unchecked((int)_value));
                uint r = (uint)Math.Round(color.R * 63.0 / 255.0);
                uint g = (uint)Math.Round(color.G * 63.0 / 255.0);
                uint b = (uint)Math.Round(color.B * 63.0 / 255.0);
                return r | (g << 8) | (b << 16);
            }
        }

        private void PickColor(object sender, EventArgs e)
        {
            using (ColorDialog dialog = new ColorDialog())
            {
                dialog.FullOpen = true;
                dialog.AnyColor = true;
                dialog.Color = Color.FromArgb(unchecked((int)_value));
                if (dialog.ShowDialog(FindForm()) == DialogResult.OK) Value = 0xFF000000u | ((uint)dialog.Color.R << 16) | ((uint)dialog.Color.G << 8) | dialog.Color.B;
            }
        }

        private void ParseHex()
        {
            string text = (_hex.Text ?? string.Empty).Trim();
            if (text.StartsWith("#", StringComparison.Ordinal)) text = text.Substring(1);
            if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) text = text.Substring(2);
            uint parsed;
            if (uint.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out parsed))
            {
                _value = parsed;
                _hex.Text = parsed.ToString("X8", CultureInfo.InvariantCulture);
                _preview.BackColor = Color.FromArgb(unchecked((int)parsed));
            }
            else _hex.Text = _value.ToString("X8", CultureInfo.InvariantCulture);
        }
    }

    internal sealed class NumericField : UserControl
    {
        private readonly NumericUpDown _number;

        public NumericField(string label, uint value, uint maximum)
        {
            Width = 140;
            Height = 58;
            BackColor = Color.Transparent;
            Label caption = Ui.Label(label, 8.5F, FontStyle.Regular, Ui.Muted);
            caption.Location = new Point(0, 0);
            Controls.Add(caption);
            _number = new NumericUpDown
            {
                Location = new Point(0, 25),
                Size = new Size(128, 29),
                Minimum = 0,
                Maximum = maximum,
                Value = Math.Min(value, maximum),
                BackColor = Ui.Input,
                ForeColor = Ui.Text,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 10F),
                ThousandsSeparator = false
            };
            Controls.Add(_number);
        }

        public uint Value { get { return decimal.ToUInt32(_number.Value); } }
    }

    internal sealed class MainForm : Form
    {
        private readonly DeviceClient _client = new DeviceClient();
        private readonly Dictionary<string, PageView> _pages = new Dictionary<string, PageView>();
        private readonly Dictionary<string, ModernButton> _navButtons = new Dictionary<string, ModernButton>();
        private readonly List<ModernButton> _navButtonOrder = new List<ModernButton>();
        private readonly bool _windows7 = Program.IsWindows7();
        private readonly bool _qrSupported = Program.IsQrCustomizationSupported();
        private readonly bool _blueScreenStyleSwitchSupported = Program.IsWindows11NewBlueScreen();
        private Panel _content;
        private Label _statusLabel;
        private Panel _statusDot;
        private TextBox _stopCodeText;
        private ColorPickerBox _backgroundColor;
        private ColorPickerBox _textBackColor;
        private ColorPickerBox _textForeColor;
        private ColorPickerBox _windows7ForeColor;
        private ColorPickerBox _windows7BackColor;
        private ChangeTextPage _changeTextPage;
        private QrEditorPage _qrEditorPage;
        private DisplayStringsPage _displayStringsPage;
        private bool _rainbowPreviewEnabled;
        private bool _stopCodeApplied;
        private string _appliedStopCode;
        private bool _backgroundColorApplied;
        private Color _appliedBackgroundColor;
        private bool _textColorsApplied;
        private Color _appliedTextBackgroundColor;
        private Color _appliedTextForegroundColor;
        private bool _windows7ColorsApplied;
        private Color _appliedWindows7ForegroundColor;
        private Color _appliedWindows7BackgroundColor;
        private ModernButton _blueScreenStyleButton;

        public MainForm()
        {
            Text = "自定义蓝屏";
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(1160, 760);
            Size = new Size(1320, 860);
            BackColor = Ui.Window;
            ForeColor = Ui.Text;
            Font = new Font("Segoe UI", 9F);
            ShowIcon = false;
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            BuildShell();
            BuildPages();
            ShowPage("home");
            Shown += delegate { ProbeDevice(false); };
        }

        private void BuildShell()
        {
            TableLayoutPanel shell = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1,
                Margin = Padding.Empty,
                Padding = Padding.Empty,
                BackColor = Ui.Window
            };
            shell.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 230F));
            shell.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            shell.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            Controls.Add(shell);

            Panel sidebar = new Panel { Dock = DockStyle.Fill, Margin = Padding.Empty, BackColor = Ui.Sidebar };
            shell.Controls.Add(sidebar, 0, 0);

            Label logo = Ui.Label("CustomBSOD", 13F, FontStyle.Bold, Ui.Text);
            logo.Location = new Point(24, 24);
            sidebar.Controls.Add(logo);

            string[,] nav =
            {
                { "home", "首页" },
                { "stop", "终止代码" },
                { "colors", "颜色" },
                { "change", "替换文本" },
                { "qr", "修改二维码" },
                { "display", "显示字符串/图片" },
                { "effects", "特效与触发" },
                { "manual", "手动发送命令" }
            };
            int y = 102;
            for (int i = 0; i < nav.GetLength(0); i++)
            {
                string key = nav[i, 0];
                if (_windows7 && key == "change") continue;
                if (!_qrSupported && !_blueScreenStyleSwitchSupported && key == "qr") continue;
                bool initiallyVisible = key != "qr" || _qrSupported;
                ModernButton button = new ModernButton
                {
                    Text = nav[i, 1],
                    TextAlign = ContentAlignment.MiddleLeft,
                    Padding = new Padding(18, 0, 0, 0),
                    Location = new Point(14, y),
                    Size = new Size(202, 43),
                    BaseColor = Ui.Sidebar,
                    Tag = key,
                    Visible = initiallyVisible
                };
                button.Click += delegate (object sender, EventArgs e)
                {
                    ShowPage((string)((Control)sender).Tag);
                };
                sidebar.Controls.Add(button);
                _navButtons.Add(key, button);
                _navButtonOrder.Add(button);
                if (initiallyVisible) y += 50;
            }

            Panel statusArea = new Panel { Dock = DockStyle.Bottom, Height = 78, BackColor = Ui.Sidebar };
            sidebar.Controls.Add(statusArea);
            _statusDot = new Panel { Location = new Point(24, 19), Size = new Size(10, 10), BackColor = Ui.Amber };
            _statusDot.Resize += delegate { Ui.RoundRegion(_statusDot, 5); };
            statusArea.Controls.Add(_statusDot);
            _statusLabel = Ui.Label("尚未检测", 9F, FontStyle.Bold, Ui.Muted);
            _statusLabel.Location = new Point(42, 14);
            statusArea.Controls.Add(_statusLabel);
            Label device = Ui.Label(DeviceClient.DevicePath, 8F, FontStyle.Regular, Ui.Muted);
            device.Location = new Point(24, 42);
            statusArea.Controls.Add(device);

            TableLayoutPanel right = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                Margin = Padding.Empty,
                Padding = Padding.Empty,
                BackColor = Ui.Window,
                ColumnCount = 1,
                RowCount = 2
            };
            right.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            right.RowStyles.Add(new RowStyle(SizeType.Absolute, 66F));
            right.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            shell.Controls.Add(right, 1, 0);

            Panel top = new Panel { Dock = DockStyle.Fill, Margin = Padding.Empty, BackColor = Ui.Sidebar };
            right.Controls.Add(top, 0, 0);
            Label appTitle = Ui.Label("CustomBSOD —— 让你自定义你的蓝屏！", 11F, FontStyle.Bold, Ui.Text);
            appTitle.Location = new Point(30, 23);
            top.Controls.Add(appTitle);
            ModernButton reconnect = new ModernButton
            {
                Text = "重新检测设备",
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
                Size = new Size(150, 38),
                Location = new Point(right.Width - 180, 14),
                BaseColor = Ui.CardAlt
            };
            reconnect.Click += delegate { ProbeDevice(true); };
            top.Controls.Add(reconnect);
            top.Resize += delegate { reconnect.Left = top.ClientSize.Width - reconnect.Width - 30; };

            _content = new Panel { Dock = DockStyle.Fill, Margin = Padding.Empty, BackColor = Ui.Window };
            right.Controls.Add(_content, 0, 1);
        }

        private void BuildPages()
        {
            AddPage("home", BuildHomePage());
            AddPage("stop", BuildStopCodePage());
            AddPage("colors", BuildColorsPage());
            if (!_windows7)
            {
                _changeTextPage = new ChangeTextPage(TrySendCommand, ShowPreview);
                AddPage("change", _changeTextPage);
            }
            if (_qrSupported || _blueScreenStyleSwitchSupported)
            {
                _qrEditorPage = new QrEditorPage(TrySendLargeCommand, _client.ReadRectangleDescription);
                AddPage("qr", _qrEditorPage);
            }
            _displayStringsPage = new DisplayStringsPage(TrySendCommand, TrySendLargeCommand, ShowPreview);
            AddPage("display", _displayStringsPage);
            AddPage("effects", BuildEffectsPage());
            AddPage("manual", BuildManualPage());
        }

        private void AddPage(string key, PageView page)
        {
            _pages.Add(key, page);
            _content.Controls.Add(page);
        }

        private PageView BuildHomePage()
        {
            PageView page = new PageView("首页", "连接内核驱动并选择需要发送的控制命令");
            CardPanel connection = new CardPanel { Height = 174 };
            Label title = Ui.Label("驱动连接", 13F, FontStyle.Bold, Ui.Text);
            title.Location = new Point(22, 19);
            connection.Controls.Add(title);
            Label desc = Ui.Label("控制程序通过 \\\\.\\BSOD 发送命令，需要管理员权限", 9.5F, FontStyle.Regular, Ui.Muted);
            desc.Location = new Point(22, 52);
            connection.Controls.Add(desc);
            ModernButton check = new ModernButton { Text = "检测设备", Location = new Point(22, 101), Size = new Size(118, 38) };
            check.Click += delegate { ProbeDevice(true); };
            connection.Controls.Add(check);
            page.AddCard(connection);
            return page;
        }

        private PageView BuildStopCodePage()
        {
            PageView page = new PageView("终止代码", "自定义蓝屏中显示的 Stop Code 文本");
            CardPanel card = new CardPanel { Height = 240 };
            Label title = Ui.Label("Stop Code", 13F, FontStyle.Bold, Ui.Text);
            title.Location = new Point(22, 19);
            card.Controls.Add(title);
            _stopCodeText = Ui.TextBox("CUSTOM_STOP_CODE", false);
            _stopCodeText.Location = new Point(22, 91);
            _stopCodeText.Size = new Size(610, 31);
            card.Controls.Add(_stopCodeText);
            ModernButton send = new ModernButton { Text = "应用终止代码", Location = new Point(22, 154), Size = new Size(142, 40) };
            send.Click += delegate
            {
                string value = ValidateProtocolText(_stopCodeText.Text, false);
                if (TrySendCommand("SP " + value, "终止代码已设置"))
                {
                    _appliedStopCode = value;
                    _stopCodeApplied = true;
                }
            };
            card.Controls.Add(send);
            ModernButton preview = CreatePreviewButton(new Point(send.Right + 20, send.Top));
            preview.Click += delegate
            {
                try
                {
                    PreviewSnapshot snapshot = CreateDefaultPreview();
                    snapshot.StopCode = ValidateProtocolText(_stopCodeText.Text, false);
                    snapshot.Kind = _windows7 ? PreviewKind.Windows7StopCode : PreviewKind.ModernStopCode;
                    ShowPreview(snapshot, "终止代码预览");
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, ex.Message, "无法生成预览", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            };
            card.Controls.Add(preview);
            page.AddCard(card);
            return page;
        }

        private PageView BuildColorsPage()
        {
            PageView page = new PageView("颜色", _windows7 ? "Windows 7 VGA 蓝屏配色" : "使用调色板或直接输入 8 位 ARGB 十六进制值");
            if (!_windows7)
            {
                CardPanel background = new CardPanel { Height = 184 };
                Label bTitle = Ui.Label("背景颜色", 13F, FontStyle.Bold, Ui.Text);
                bTitle.Location = new Point(22, 18);
                background.Controls.Add(bTitle);
                _backgroundColor = new ColorPickerBox("屏幕背景 ARGB", 0xFF0078D4u) { Location = new Point(22, 57) };
                background.Controls.Add(_backgroundColor);
                ModernButton bgSend = new ModernButton { Text = "应用背景色", Location = new Point(320, 81), Size = new Size(128, 38) };
                bgSend.Click += delegate
                {
                    uint value = _backgroundColor.Value;
                    if (TrySendCommand("CR " + ((ulong)value).ToString(CultureInfo.InvariantCulture), "背景色已设置"))
                    {
                        _appliedBackgroundColor = Color.FromArgb(unchecked((int)value));
                        _backgroundColorApplied = true;
                    }
                };
                background.Controls.Add(bgSend);
                ModernButton bgPreview = CreatePreviewButton(new Point(bgSend.Right + 20, bgSend.Top));
                bgPreview.Click += delegate
                {
                    PreviewSnapshot snapshot = CreateDefaultPreview();
                    snapshot.Background = Color.FromArgb(unchecked((int)_backgroundColor.Value));
                    snapshot.Kind = PreviewKind.ModernBackground;
                    ShowPreview(snapshot, "背景颜色预览");
                };
                background.Controls.Add(bgPreview);
                page.AddCard(background);
                CardPanel textColors = new CardPanel { Height = 200 };
                Label tTitle = Ui.Label("文字颜色", 13F, FontStyle.Bold, Ui.Text);
                tTitle.Location = new Point(22, 18);
                textColors.Controls.Add(tTitle);
                _textBackColor = new ColorPickerBox("文字背景 ARGB", 0x00000000u) { Location = new Point(22, 58) };
                _textForeColor = new ColorPickerBox("文字前景 ARGB", 0xFFFFFFFFu) { Location = new Point(306, 58) };
                textColors.Controls.Add(_textBackColor);
                textColors.Controls.Add(_textForeColor);
                ModernButton textSend = new ModernButton { Text = "应用文字颜色", Location = new Point(610, 82), Size = new Size(142, 38) };
                textSend.Click += delegate
                {
                    uint backgroundValue = _textBackColor.Value;
                    uint foregroundValue = _textForeColor.Value;
                    if (TrySendCommand("CC " + backgroundValue.ToString(CultureInfo.InvariantCulture) + " " + foregroundValue.ToString(CultureInfo.InvariantCulture), "文字颜色已设置"))
                    {
                        _appliedTextBackgroundColor = Color.FromArgb(unchecked((int)backgroundValue));
                        _appliedTextForegroundColor = Color.FromArgb(unchecked((int)foregroundValue));
                        _textColorsApplied = true;
                    }
                };
                textColors.Controls.Add(textSend);
                ModernButton textPreview = CreatePreviewButton(new Point(textSend.Right + 20, textSend.Top));
                textPreview.Click += delegate
                {
                    PreviewSnapshot snapshot = CreateDefaultPreview();
                    snapshot.TextBackground = Color.FromArgb(unchecked((int)_textBackColor.Value));
                    snapshot.Foreground = Color.FromArgb(unchecked((int)_textForeColor.Value));
                    snapshot.Kind = PreviewKind.ModernTextColors;
                    ShowPreview(snapshot, "文字颜色预览");
                };
                textColors.Controls.Add(textPreview);
                page.AddCard(textColors);
            }
            else
            {
                CardPanel win7 = new CardPanel { Height = 224 };
                Label wTitle = Ui.Label("Windows 7 修改颜色", 13F, FontStyle.Bold, Ui.Text);
                wTitle.Location = new Point(22, 18);
                win7.Controls.Add(wTitle);
                _windows7ForeColor = new ColorPickerBox("前景色", 0xFFFFFFFFu) { Location = new Point(22, 53) };
                _windows7BackColor = new ColorPickerBox("背景色", 0xFF000082u) { Location = new Point(306, 53) };
                win7.Controls.Add(_windows7ForeColor);
                win7.Controls.Add(_windows7BackColor);
                ModernButton wSend = new ModernButton { Text = "引用 Win7 配色", Location = new Point(610, 78), Size = new Size(150, 38) };
                wSend.Click += delegate
                {
                    if (TrySendCommand("C7 " + _windows7ForeColor.VgaDacValue.ToString(CultureInfo.InvariantCulture) + " " + _windows7BackColor.VgaDacValue.ToString(CultureInfo.InvariantCulture), "Windows 7 配色回调已注册"))
                    {
                        _appliedWindows7ForegroundColor = Color.FromArgb(unchecked((int)_windows7ForeColor.Value));
                        _appliedWindows7BackgroundColor = Color.FromArgb(unchecked((int)_windows7BackColor.Value));
                        _windows7ColorsApplied = true;
                        _rainbowPreviewEnabled = false;
                    }
                };
                win7.Controls.Add(wSend);
                ModernButton wPreview = CreatePreviewButton(new Point(wSend.Right + 20, wSend.Top));
                wPreview.Click += delegate
                {
                    PreviewSnapshot snapshot = CreateDefaultPreview();
                    snapshot.Foreground = Color.FromArgb(unchecked((int)_windows7ForeColor.Value));
                    snapshot.Background = Color.FromArgb(unchecked((int)_windows7BackColor.Value));
                    snapshot.Kind = PreviewKind.Windows7Colors;
                    ShowPreview(snapshot, "Windows 7 配色预览");
                };
                win7.Controls.Add(wPreview);
                page.AddCard(win7);
            }
            return page;
        }

        private PageView BuildEffectsPage()
        {
            PageView page = new PageView("特效与触发", "彩色蓝屏和手动触发蓝屏");
            if (_windows7)
            {
                CardPanel win7 = new CardPanel { Height = 176 };
                Label title = Ui.Label("Windows 7 彩色蓝屏", 13F, FontStyle.Bold, Ui.Text);
                title.Location = new Point(22, 18);
                win7.Controls.Add(title);
                Label desc = Ui.Label("R7 注册蓝屏回调，让 Windows 7 实现彩色蓝屏", 9F, FontStyle.Regular, Ui.Muted);
                desc.Location = new Point(22, 52);
                win7.Controls.Add(desc);
                ModernButton r7 = new ModernButton { Text = "注册", Location = new Point(22, 102), Size = new Size(118, 38) };
                r7.Click += delegate
                {
                    if (TrySendCommand("R7", "Windows 7 蓝屏回调已注册")) { _rainbowPreviewEnabled = true; _windows7ColorsApplied = false; }
                };
                win7.Controls.Add(r7);
                ModernButton r7Preview = CreatePreviewButton(new Point(r7.Right + 20, r7.Top));
                r7Preview.Click += delegate
                {
                    PreviewSnapshot snapshot = CreateDefaultPreview();
                    snapshot.Rainbow = true;
                    snapshot.Kind = PreviewKind.Windows7Rainbow;
                    ShowPreview(snapshot, "Windows 7 彩色蓝屏预览");
                };
                win7.Controls.Add(r7Preview);
                page.AddCard(win7);
            }
            else
            {
                CardPanel rainbow = new CardPanel { Height = 188, BackColor = Ui.SoftPurple };
                Label rTitle = Ui.Label("彩色蓝屏", 13F, FontStyle.Bold, Ui.Text);
                rTitle.Location = new Point(22, 18);
                rainbow.Controls.Add(rTitle);
                Label rDesc = Ui.Label("驱动将反复调用蓝屏绘制函数来达到彩色蓝屏", 9F, FontStyle.Regular, Ui.Muted);
                rDesc.Location = new Point(22, 52);
                rDesc.MaximumSize = new Size(900, 0);
                rainbow.Controls.Add(rDesc);
                ModernButton rd = new ModernButton { Text = "启动动态彩虹", Location = new Point(22, 119), Size = new Size(148, 40), BaseColor = Color.FromArgb(126, 79, 160) };
                rd.Click += delegate
                {
                    if (TrySendCommand("RD", "如果你看到了这条消息，说明驱动运行失败了")) _rainbowPreviewEnabled = true;
                };
                rainbow.Controls.Add(rd);
                ModernButton rdPreview = CreatePreviewButton(new Point(rd.Right + 20, rd.Top));
                rdPreview.Click += delegate
                {
                    PreviewSnapshot snapshot = CreateDefaultPreview();
                    snapshot.Rainbow = true;
                    snapshot.Kind = PreviewKind.ModernRainbow;
                    ShowPreview(snapshot, "彩色蓝屏预览");
                };
                rainbow.Controls.Add(rdPreview);
                page.AddCard(rainbow);
            }

            CardPanel crash = new CardPanel { Height = 210, BackColor = Ui.SoftRed };
            Label cTitle = Ui.Label("主动 BugCheck", 13F, FontStyle.Bold, Ui.Red);
            cTitle.Location = new Point(22, 18);
            crash.Controls.Add(cTitle);
            Label cDesc = Ui.Label("立即触发蓝屏", 9F, FontStyle.Regular, Ui.Text);
            cDesc.Location = new Point(22, 52);
            crash.Controls.Add(cDesc);
            Label warning = Ui.Label("预览效果可能与实际效果不同", 8.8F, FontStyle.Bold, Ui.Amber);
            warning.Location = new Point(22, 82);
            crash.Controls.Add(warning);
            ModernButton bc = new ModernButton { Text = "触发蓝屏", Location = new Point(22, 137), Size = new Size(126, 40), BaseColor = Color.FromArgb(181, 61, 78) };
            bc.Click += delegate { SendCommand("BC", "如果你看到了这条消息，说明驱动运行失败了"); };
            crash.Controls.Add(bc);
            ModernButton allPreview = CreatePreviewButton(new Point(bc.Right + 20, bc.Top));
            allPreview.Text = "预览已修改的所有配置";
            allPreview.Size = new Size(236, 40);
            allPreview.Click += delegate
            {
                try { ShowPreview(CreateFullPreview(), "全部设置预览"); }
                catch (Exception ex) { MessageBox.Show(this, ex.Message, "无法生成预览", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            };
            crash.Controls.Add(allPreview);
            page.AddCard(crash);

            if (_blueScreenStyleSwitchSupported)
            {
                CardPanel styleSwitch = new CardPanel { Height = 176 };
                Label switchTitle = Ui.Label("蓝屏版本效果", 13F, FontStyle.Bold, Ui.Text);
                switchTitle.Location = new Point(22, 18);
                styleSwitch.Controls.Add(switchTitle);
                Label switchDesc = Ui.Label("在当前新版蓝屏和 Windows 10 旧版蓝屏效果之间切换", 9F, FontStyle.Regular, Ui.Muted);
                switchDesc.Location = new Point(22, 52);
                styleSwitch.Controls.Add(switchDesc);
                _blueScreenStyleButton = new ModernButton { Text = "切换为老版本蓝屏效果", Location = new Point(22, 102), Size = new Size(210, 40) };
                _blueScreenStyleButton.Click += delegate { ToggleBlueScreenStyle(); };
                styleSwitch.Controls.Add(_blueScreenStyleButton);
                page.AddCard(styleSwitch);
            }
            return page;
        }

        private void ToggleBlueScreenStyle()
        {
            bool useWindows10Effect = !Program.ForceWindows10BlueScreenEffect;
            string command = useWindows10Effect ? "FR 0" : "FR 1";
            string successMessage = useWindows10Effect ? "已切换为老版本蓝屏效果" : "已切换为新版本蓝屏效果";
            if (!TrySendCommand(command, successMessage)) return;

            Program.ForceWindows10BlueScreenEffect = useWindows10Effect;
            _blueScreenStyleButton.Text = useWindows10Effect ? "切换为新版本蓝屏效果" : "切换为老版本蓝屏效果";
            SetQrNavigationVisible(_qrSupported || useWindows10Effect);

            if (useWindows10Effect && _changeTextPage != null && _changeTextPage.HasPreviewConfiguration)
            {
                TrySendCommandWithoutPrompt(_changeTextPage.BuildAppliedProtocolCommand(true));
            }
        }

        private void SetQrNavigationVisible(bool visible)
        {
            ModernButton qrButton;
            if (!_navButtons.TryGetValue("qr", out qrButton)) return;
            qrButton.Visible = visible;
            int y = 102;
            foreach (ModernButton button in _navButtonOrder)
            {
                bool buttonVisible = button != qrButton || visible;
                button.Visible = buttonVisible;
                if (!buttonVisible) continue;
                button.Top = y;
                y += 50;
            }
        }

        private static ModernButton CreatePreviewButton(Point location)
        {
            return new ModernButton
            {
                Text = "预览",
                Location = location,
                Size = new Size(100, 38),
                BaseColor = Ui.CardAlt
            };
        }

        private PreviewSnapshot CreateDefaultPreview()
        {
            return PreviewSnapshot.CreateDefault(_windows7);
        }

        private PreviewSnapshot CreateFullPreview()
        {
            PreviewSnapshot snapshot = CreateDefaultPreview();
            if (_stopCodeApplied) snapshot.StopCode = _appliedStopCode;
            if (_windows7)
            {
                if (_windows7ColorsApplied)
                {
                    snapshot.Foreground = _appliedWindows7ForegroundColor;
                    snapshot.Background = _appliedWindows7BackgroundColor;
                }
            }
            else
            {
                if (_backgroundColorApplied) snapshot.Background = _appliedBackgroundColor;
                if (_textColorsApplied)
                {
                    snapshot.TextBackground = _appliedTextBackgroundColor;
                    snapshot.Foreground = _appliedTextForegroundColor;
                }
                if (_changeTextPage != null && _changeTextPage.HasPreviewConfiguration)
                {
                    snapshot.ReplacementTexts.AddRange(_changeTextPage.GetAppliedPreviewTexts());
                    snapshot.SkipPercent = _changeTextPage.SkipPercent;
                }
            }
            snapshot.Rainbow = _rainbowPreviewEnabled;
            return snapshot;
        }

        private void ShowPreview(PreviewSnapshot snapshot, string title)
        {
            try
            {
                if (_qrEditorPage != null) _qrEditorPage.ApplyToPreview(snapshot);
                using (PreviewForm preview = new PreviewForm(snapshot, title)) preview.ShowDialog(this);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "无法生成预览", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private PageView BuildManualPage()
        {
            PageView page = new PageView("手动发送命令", "输入原始命令字符串并发送");
            CardPanel card = new CardPanel { Height = 350 };
            TextBox cmdBox = new TextBox
            {
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                Location = new Point(22, 22),
                BackColor = Ui.Input,
                ForeColor = Ui.Text,
                Font = new Font("Consolas", 10F),
                BorderStyle = BorderStyle.FixedSingle,
                Text = "SP TEST"
            };
            cmdBox.Size = new Size(card.Width - 44, 220);
            card.Controls.Add(cmdBox);
            ModernButton sendBtn = new ModernButton
            {
                Text = "发送命令",
                Location = new Point(22, 260),
                Size = new Size(140, 40)
            };
            sendBtn.Click += (s, e) =>
            {
                string command = cmdBox.Text;
                if (string.IsNullOrWhiteSpace(command))
                {
                    MessageBox.Show(page.FindForm(), "请输入命令", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                string[] commands = command.Split('\n');
                if (MessageBox.Show($"是否发送命令？\n{command}", "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.No) return;
                foreach (string cmd in commands)
                {
                    if (!string.IsNullOrWhiteSpace(cmd)) _client.Send(cmd.Trim());
                }
            };
            card.Controls.Add(sendBtn);
            card.Resize += (s, e) =>
            {
                int width = card.ClientSize.Width - 44;
                cmdBox.Width = Math.Max(200, width);
            };

            page.AddCard(card);
            return page;
        }

        private void ShowPage(string key)
        {
            PageView page;
            if (!_pages.TryGetValue(key, out page)) return;
            page.BringToFront();
            foreach (KeyValuePair<string, ModernButton> item in _navButtons) item.Value.SelectedState = item.Key == key;
        }

        private void ProbeDevice(bool showMessage)
        {
            try
            {
                if (_qrEditorPage != null) _qrEditorPage.LoadRectangleDescription();
                else _client.Probe();
                SetDeviceStatus(true, "驱动已连接");
                if (showMessage) MessageBox.Show(this, "已成功打开 " + DeviceClient.DevicePath, "设备检测", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                SetDeviceStatus(false, "设备不可用");
                if (showMessage) MessageBox.Show(this, BuildDeviceError(ex), "无法连接驱动", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void SetDeviceStatus(bool connected, string text)
        {
            _statusDot.BackColor = connected ? Ui.Green : Ui.Red;
            _statusLabel.Text = text;
            _statusLabel.ForeColor = connected ? Ui.Green : Ui.Red;
        }

        private void SendCommand(string command, string successMessage)
        {
            TrySendCommand(command, successMessage);
        }

        private bool TrySendCommand(string command, string successMessage)
        {
            try
            {
                if (MessageBox.Show($"是否发送此条命令？\n{command}", "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.No) return false;
                _client.Send(command);
                SetDeviceStatus(true, "驱动已连接");
                MessageBox.Show(this, successMessage, "命令已发送", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return true;
            }
            catch (Exception ex)
            {
                SetDeviceStatus(false, "发送失败");
                MessageBox.Show(this, BuildDeviceError(ex), "命令发送失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }

        private bool TrySendCommandWithoutPrompt(string command)
        {
            try
            {
                _client.Send(command);
                SetDeviceStatus(true, "驱动已连接");
                return true;
            }
            catch
            {
                SetDeviceStatus(false, "发送失败");
                return false;
            }
        }

        private bool TrySendLargeCommand(string command, string confirmationMessage, string successMessage)
        {
            try
            {
                if (MessageBox.Show(this, confirmationMessage, "确认应用", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return false;
                _client.Send(command);
                SetDeviceStatus(true, "驱动已连接");
                MessageBox.Show(this, successMessage, "应用成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return true;
            }
            catch (Exception ex)
            {
                SetDeviceStatus(false, "发送失败");
                MessageBox.Show(this, BuildDeviceError(ex), "二维码应用失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }

        internal static string ValidateProtocolText(string value, bool rejectQuote)
        {
            if (value == null) value = string.Empty;
            if (value.IndexOf('\0') >= 0) throw new InvalidOperationException("文本不能包含 NUL 字符");
            if (rejectQuote && value.IndexOf('"') >= 0) throw new InvalidOperationException("驱动协议不支持字符串中的双引号");
            return value.Replace("\r", " ").Replace("\n", " ");
        }

        private static string BuildDeviceError(Exception ex)
        {
            return "无法访问 " + DeviceClient.DevicePath + "\n\n" + ex;
        }
    }

    internal enum PreviewKind
    {
        Full,
        Windows7StopCode,
        Windows7Colors,
        Windows7DisplayString,
        Windows7Rainbow,
        ModernStopCode,
        ModernBackground,
        ModernTextColors,
        ModernChangeText,
        ModernDisplayStrings,
        ModernRainbow
    }

    internal static class BsodQrPattern
    {
        private static readonly string[] Rows =
        {
            "#######.##.#.#.##.#######",
            "#.....#.###.....#.#.....#",
            "#.###.#.##....#...#.###.#",
            "#.###.#.#..#.##.#.#.###.#",
            "#.###.#....#.#.##.#.###.#",
            "#.....#.#.#.#.#...#.....#",
            "#######.#.#.#.#.#.#######",
            ".........###..##.........",
            "##..###..##...#....#.####",
            "...#.#..#..#..####..##.#.",
            "#.########.######..####..",
            "##...#.###..#.....##..##.",
            "#.#..##....##..#.##..####",
            "##.#...##..#.#####..#..#.",
            "......#.####.#.#...####..",
            "..###...#.###.###.###.##.",
            "##...####.#....########..",
            "........##.#..#.#...#....",
            "#######..#.####.#.#.#....",
            "#.....#.###...#.#...####.",
            "#.###.#.##......#######.#",
            "#.###.#...##..###.##..#..",
            "#.###.#...###.#.###..#.#.",
            "#.....#.#...#.#...######.",
            "#######.##.##.##......###"
        };

        public static readonly Color CodeColor = Color.FromArgb(0, 120, 215);

        public static void Draw(Graphics graphics, RectangleF bounds)
        {
            Draw(graphics, bounds, CodeColor);
        }

        public static void Draw(Graphics graphics, RectangleF bounds, Color codeColor)
        {
            float side = Math.Min(bounds.Width, bounds.Height);
            float left = bounds.Left + (bounds.Width - side) / 2F;
            float top = bounds.Top + (bounds.Height - side) / 2F;
            using (Brush white = new SolidBrush(Color.White)) graphics.FillRectangle(white, left, top, side, side);
            float quiet = side * (24F / 284F);
            float codeSize = side - (quiet * 2F);
            float module = codeSize / 25F;
            using (Brush code = new SolidBrush(Color.FromArgb(255, codeColor.R, codeColor.G, codeColor.B)))
            {
                for (int row = 0; row < Rows.Length; row++)
                {
                    for (int column = 0; column < Rows[row].Length; column++)
                    {
                        if (Rows[row][column] != '#') continue;
                        float x0 = left + quiet + (column * module);
                        float y0 = top + quiet + (row * module);
                        float x1 = left + quiet + ((column + 1) * module);
                        float y1 = top + quiet + ((row + 1) * module);
                        graphics.FillRectangle(code, x0, y0, Math.Max(1F, x1 - x0), Math.Max(1F, y1 - y0));
                    }
                }
            }
        }
    }

    internal sealed class PreviewSnapshot
    {
        public PreviewKind Kind;
        public bool Windows7;
        public bool Windows8;
        public bool Windows11New;
        public bool SkipPercent;
        public Color Background;
        public Color Foreground;
        public Color TextBackground;
        public string StopCode;
        public bool Rainbow;
        public int QrWidth;
        public int QrLength;
        public uint[] QrPixels;
        public readonly List<string> ReplacementTexts = new List<string>();
        public readonly List<PreviewTextItem> DisplayItems = new List<PreviewTextItem>();
        public readonly List<PreviewImageItem> DisplayImages = new List<PreviewImageItem>();

        public static PreviewSnapshot CreateDefault(bool windows7)
        {
            bool windows8 = !windows7 && Program.IsWindows8();
            Color modernBlue = windows8 ? Color.FromArgb(32, 103, 178) : Color.FromArgb(0, 120, 212);
            bool windows11New = !windows7 && Program.IsWindows11NewBlueScreen() && !Program.ForceWindows10BlueScreenEffect;
            return new PreviewSnapshot
            {
                Kind = PreviewKind.Full,
                Windows7 = windows7,
                Windows8 = windows8,
                Windows11New = windows11New,
                Background = windows7 ? Color.FromArgb(0, 0, 128) : (windows11New ? Color.Black : modernBlue),
                Foreground = Color.White,
                TextBackground = windows7 ? Color.Transparent : (windows11New ? Color.Black : modernBlue),
                StopCode = null
            };
        }
    }

    internal sealed class PreviewTextItem
    {
        public string Text;
        public uint TextSize;
        public Color TextBackground;
        public Color TextForeground;
        public Color ScreenBackground;
        public uint X;
        public uint Y;
        public bool ClearScreen;
        public bool VgaText;
        public bool Vga80x25;
        public int VgaBackground;
        public int VgaForeground;
        public bool Blink;
        public bool Rainbow;
    }

    internal sealed class PreviewImageItem
    {
        public uint[] Pixels;
        public int Width;
        public int Height;
        public uint X;
        public uint Y;
        public Color ScreenBackground;
        public bool ClearScreen;
    }

    internal sealed class PreviewForm : Form
    {
        public PreviewForm(PreviewSnapshot snapshot, string title)
        {
            Text = title + " — 预览效果可能与实际效果不同 (按下Esc 退出)";
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedSingle;
            WindowState = FormWindowState.Maximized;
            BackColor = Color.Black;
            ShowIcon = false;
            MaximizeBox = false;
            MinimizeBox = false;
            KeyPreview = true;
            KeyDown += delegate (object sender, KeyEventArgs e)
            {
                if (e.KeyCode == Keys.Escape) Close();
            };
            Controls.Add(new PreviewCanvas(snapshot) { Dock = DockStyle.Fill });
        }
    }

    internal sealed class PreviewCanvas : Control
    {
        private static readonly Color ModernBlue = Color.FromArgb(0, 120, 212);
        private static readonly Color Windows8Blue = Color.FromArgb(32, 103, 178);
        private readonly PreviewSnapshot _snapshot;
        private readonly Bitmap _qrBitmap;
        private readonly Timer _timer;
        private readonly Stopwatch _animationClock;
        private double _hue;
        private int _frame;

        public PreviewCanvas(PreviewSnapshot snapshot)
        {
            _snapshot = snapshot;
            _qrBitmap = BuildQrBitmap(snapshot);
            DoubleBuffered = true;
            BackColor = snapshot.Background;
            if (snapshot.Rainbow || IsRainbowKind(snapshot.Kind) || HasAnimatedText(snapshot.DisplayItems))
            {
                _animationClock = Stopwatch.StartNew();
                _timer = new Timer { Interval = 16 };
                _timer.Tick += delegate
                {
                    double elapsedSeconds = _animationClock.Elapsed.TotalSeconds;
                    _hue = (elapsedSeconds * 100.0) % 360.0;
                    _frame = (int)(elapsedSeconds * (1000.0 / 120.0));
                    Invalidate();
                };
                _timer.Start();
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_timer != null) _timer.Dispose();
                if (_qrBitmap != null) _qrBitmap.Dispose();
            }
            base.Dispose(disposing);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            e.Graphics.SmoothingMode = SmoothingMode.None;
            e.Graphics.TextRenderingHint = System.Drawing.Text.TextRenderingHint.SingleBitPerPixelGridFit;
            if (_snapshot.Windows7) DrawWindows7(e.Graphics);
            else DrawModern(e.Graphics);
        }

        private void DrawWindows7(Graphics graphics)
        {
            bool displayOnly = _snapshot.Kind == PreviewKind.Windows7DisplayString || (_snapshot.Kind == PreviewKind.Full && _snapshot.DisplayItems.Count > 0);
            if (displayOnly)
            {
                DrawWindows7DisplayString(graphics);
                return;
            }
            bool rainbow = _snapshot.Kind == PreviewKind.Windows7Rainbow || _snapshot.Rainbow;
            Color background = rainbow ? FromHsv(_hue, 1.0, 1.0) : Opaque(_snapshot.Background);
            Color foreground = rainbow ? FromHsv((_hue + 180.0) % 360.0, 1.0, 0.15) : Opaque(_snapshot.Foreground);
            Fill(graphics, background);
            DrawWindows7CrashText(graphics, foreground);
        }

        private void DrawWindows7CrashText(Graphics graphics, Color foreground)
        {
            float sx = ClientSize.Width / 800F;
            float sy = ClientSize.Height / 600F;
            GraphicsState state = graphics.Save();
            graphics.ScaleTransform(sx, sy);
            using (Font font = new Font("Lucida Console", 13F, FontStyle.Regular, GraphicsUnit.Pixel))
            using (Brush brush = new SolidBrush(foreground))
            {
                DrawClassicLine(graphics, font, brush, "A problem has been detected and Windows has been shut down to prevent damage", 18);
                DrawClassicLine(graphics, font, brush, "to your computer.", 34);
                DrawClassicLine(graphics, font, brush, "If this is the first time you've seen this Stop error screen,", 96);
                DrawClassicLine(graphics, font, brush, "restart your computer. If this screen appears again, follow", 112);
                DrawClassicLine(graphics, font, brush, "these steps:", 128);
                DrawClassicLine(graphics, font, brush, "Check to make sure any new hardware or software is properly installed.", 160);
                DrawClassicLine(graphics, font, brush, "If this is a new installation, ask your hardware or software manufacturer", 176);
                DrawClassicLine(graphics, font, brush, "for any Windows updates you might need.", 192);
                DrawClassicLine(graphics, font, brush, "If problems continue, disable or remove any newly installed hardware", 224);
                DrawClassicLine(graphics, font, brush, "or software. Disable BIOS memory options such as caching or shadowing.", 240);
                DrawClassicLine(graphics, font, brush, "If you need to use Safe Mode to remove or disable components, restart", 256);
                DrawClassicLine(graphics, font, brush, "your computer, press F8 to select Advanced Startup Options, and then", 272);
                DrawClassicLine(graphics, font, brush, "select Safe Mode.", 288);
                bool customStop = _snapshot.Kind == PreviewKind.Windows7StopCode || (_snapshot.Kind == PreviewKind.Full && !string.IsNullOrEmpty(_snapshot.StopCode));
                if (customStop)
                {
                    DrawClassicLine(graphics, font, brush, _snapshot.StopCode ?? "CUSTOM_STOP_CODE", 320);
                    DrawClassicLine(graphics, font, brush, "Collecting data for crash dump ...", 352);
                    DrawClassicLine(graphics, font, brush, "Initializing disk for crash dump ...", 368);
                }
                else
                {
                    DrawClassicLine(graphics, font, brush, "Technical information:", 320);
                    DrawClassicLine(graphics, font, brush, "*** STOP: 0x00114514 (0x0000000000000000,0x0000000000000000,", 352);
                    DrawClassicLine(graphics, font, brush, "0x0000000000000000,0x0000000000000000)", 368);
                    DrawClassicLine(graphics, font, brush, "Collecting data for crash dump ...", 432);
                    DrawClassicLine(graphics, font, brush, "Initializing disk for crash dump ...", 448);
                }
            }
            graphics.Restore(state);
        }

        private static void DrawClassicLine(Graphics graphics, Font font, Brush brush, string text, float y)
        {
            graphics.DrawString(text, font, brush, 0F, y, StringFormat.GenericTypographic);
        }

        private void DrawWindows7DisplayString(Graphics graphics)
        {
            PreviewTextItem item = _snapshot.DisplayItems.Count > 0 ? _snapshot.DisplayItems[0] : new PreviewTextItem
            {
                Text = "Your costom text",
                Vga80x25 = true,
                VgaBackground = 0x7,
                VgaForeground = 0x0
            };
            int backgroundIndex = item.Blink ? item.VgaBackground & 0x07 : item.VgaBackground;
            Color background = item.Rainbow ? VgaColor((_frame / 2) & 0x0F) : VgaColor(backgroundIndex);
            Color foreground = item.Rainbow ? VgaColor(0x0F - ((_frame / 2) & 0x0F)) : VgaColor(item.VgaForeground);
            Fill(graphics, background);
            if (item.Blink && ((_frame / 4) & 1) != 0) return;
            int rows = item.Vga80x25 ? 25 : 50;
            float cellHeight = Math.Max(8F, ClientSize.Height / (float)rows);
            using (Font font = new Font("Terminal", cellHeight, FontStyle.Bold, GraphicsUnit.Pixel))
            using (Brush brush = new SolidBrush(foreground))
            {
                graphics.DrawString(item.Text ?? string.Empty, font, brush, 0F, 0F, StringFormat.GenericTypographic);
            }
        }

        private void DrawModern(Graphics graphics)
        {
            if (_snapshot.Kind == PreviewKind.ModernDisplayStrings)
            {
                Fill(graphics, Color.Black);
                DrawModernDisplayStrings(graphics);
                return;
            }
            if (_snapshot.Windows8)
            {
                DrawWindows8(graphics);
                return;
            }
            if (_snapshot.Windows11New)
            {
                DrawWindows11(graphics);
                return;
            }
            if (_snapshot.Kind == PreviewKind.ModernChangeText)
            {
                Fill(graphics, ModernBlue);
                DrawModernChangeText(graphics);
                return;
            }
            bool rainbow = _snapshot.Kind == PreviewKind.ModernRainbow || _snapshot.Rainbow;
            Color background = rainbow ? FromHsv(_hue, 1.0, 1.0) : Opaque(_snapshot.Background);
            Color foreground = rainbow ? Color.White : Opaque(_snapshot.Foreground);
            Color glyphBackground;
            if (_snapshot.Kind == PreviewKind.ModernBackground || _snapshot.Kind == PreviewKind.ModernStopCode) glyphBackground = ModernBlue;
            else if (rainbow) glyphBackground = background;
            else glyphBackground = Opaque(_snapshot.TextBackground);
            Fill(graphics, background);
            if (_snapshot.Kind == PreviewKind.Full && _snapshot.ReplacementTexts.Count > 0) DrawModernChangeText(graphics, foreground, glyphBackground);
            else DrawModernCrashText(graphics, foreground, glyphBackground, rainbow);
        }

        private void DrawWindows8(Graphics graphics)
        {
            bool rainbow = _snapshot.Kind == PreviewKind.ModernRainbow || _snapshot.Rainbow;
            Color background = rainbow ? FromHsv(_hue, 1.0, 1.0) : Opaque(_snapshot.Background);
            Color foreground = rainbow ? Color.White : Opaque(_snapshot.Foreground);
            Color glyphBackground;
            if (_snapshot.Kind == PreviewKind.ModernBackground || _snapshot.Kind == PreviewKind.ModernStopCode) glyphBackground = Windows8Blue;
            else if (rainbow) glyphBackground = background;
            else glyphBackground = Opaque(_snapshot.TextBackground);
            Fill(graphics, background);
            if ((_snapshot.Kind == PreviewKind.ModernChangeText || _snapshot.Kind == PreviewKind.Full) && _snapshot.ReplacementTexts.Count > 0) DrawWindows8ChangeText(graphics, foreground, glyphBackground);
            else DrawWindows8CrashText(graphics, foreground, glyphBackground, rainbow);
        }

        private void DrawWindows8CrashText(Graphics graphics, Color foreground, Color glyphBackground, bool rainbow)
        {
            float sx = ClientSize.Width / 2048F;
            float sy = ClientSize.Height / 1249F;
            float faceX = 347F * sx;
            float textX = 366F * sx;
            using (Font face = new Font("Segoe UI Light", Math.Max(72F, 238F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            using (Font body = new Font("Microsoft YaHei UI", Math.Max(25F, 52F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            using (Font small = new Font("Microsoft YaHei UI", Math.Max(14F, 27F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            {
                DrawWideFaceText(graphics, ":(", face, foreground, glyphBackground, faceX, 198F * sy);
                DrawTextBlock(graphics, "你的电脑遇到问题，需要重新启动", body, foreground, glyphBackground, textX, 533F * sy);
                DrawTextBlock(graphics, "我们只收集某些错误信息，然后为你重新启动" + (rainbow ? "" : "（完成 0%）"), body, foreground, glyphBackground, textX, 600F * sy);
                if (rainbow) return;
                string stopCode = string.IsNullOrEmpty(_snapshot.StopCode) ? "APC_INDEX_MISMATCH" : _snapshot.StopCode;
                DrawTextBlock(graphics, "如果你想了解更多信息，则可以稍后在线搜索此错误: " + stopCode, small, foreground, glyphBackground, textX, 755F * sy);
            }
        }

        private void DrawWindows8ChangeText(Graphics graphics, Color foreground, Color glyphBackground)
        {
            List<string> values = PadPreviewValues(_snapshot.ReplacementTexts, 10);
            string faceText = ValueAtOrRepeatLast(values, 0, ":(");
            string bodyText = ValueAtOrRepeatLast(values, 1, "你的设备遇到问题，需要重启。") + " " + ValueAtOrRepeatLast(values, 2, "我们只收集某些错误信息，然后为你重新启动。");
            bodyText += _snapshot.SkipPercent ? " " + ValueAtOrRepeatLast(values, 5, "(完成 ") + ValueAtOrRepeatLast(values, 6, "0") + "%)" : " " + ValueAtOrRepeatLast(values, 5, "(完成 ") + ValueAtOrRepeatLast(values, 6, "0") + ValueAtOrRepeatLast(values, 7, "%)");
            string smallText = ValueAtOrRepeatLast(values, 3, "4") + " " + ValueAtOrRepeatLast(values, 4, "5");
            float sx = ClientSize.Width / 2048F;
            float sy = ClientSize.Height / 1249F;
            using (Font face = new Font("Segoe UI Light", Math.Max(72F, 238F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            using (Font body = new Font("Microsoft YaHei UI", Math.Max(25F, 52F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            using (Font small = new Font("Microsoft YaHei UI", Math.Max(14F, 27F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            {
                DrawWideFaceText(graphics, faceText, face, foreground, glyphBackground, 347F * sx, 198F * sy);
                DrawTextBlock(graphics, bodyText, body, foreground, glyphBackground, 366F * sx, 533F * sy);
                DrawTextBlock(graphics, smallText, small, foreground, glyphBackground, 366F * sx, 675F * sy);
            }
        }

        private void DrawModernCrashText(Graphics graphics, Color foreground, Color glyphBackground, bool rainbow)
        {
            float sx = ClientSize.Width / 2048F;
            float sy = ClientSize.Height / 1536F;
            float x = 260F * sx;
            using (Font face = new Font("Segoe UI Light", Math.Max(72F, 238F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            using (Font body = new Font("Microsoft YaHei UI", Math.Max(25F, 52F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            using (Font progress = new Font("Microsoft YaHei UI", Math.Max(24F, 48F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            using (Font small = new Font("Microsoft YaHei UI", Math.Max(14F, 27F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            {
                DrawWideFaceText(graphics, ":(", face, foreground, glyphBackground, x, 210F * sy);
                DrawTextBlock(graphics, "你的设备遇到问题，需要重启。", body, foreground, glyphBackground, x, 505F * sy);
                DrawTextBlock(graphics, rainbow ? "我们只收集某些错误信息，然后你可以重新启动。" : "我们只收集某些错误信息，然后为你重新启动。", body, foreground, glyphBackground, x, 580F * sy);
                if (rainbow) return;
                DrawTextBlock(graphics, "0% 完成", progress, foreground, glyphBackground, x, 705F * sy);
                float qrX = x;
                float qrY = 820F * sy;
                float qrSize = Math.Max(120F, 205F * sy);
                DrawQrCode(graphics, qrX, qrY, qrSize);
                float infoX = qrX + qrSize + 30F * sx;
                DrawTextBlock(graphics, "有关此问题的详细信息和可能的解决方法，请访问 https://www.windows.com/stopcode", small, foreground, glyphBackground, infoX, 820F * sy);
                DrawTextBlock(graphics, "如果致电支持人员，请向他们提供以下信息:", small, foreground, glyphBackground, infoX, 910F * sy);
                DrawTextBlock(graphics, "终止代码: " + (string.IsNullOrEmpty(_snapshot.StopCode) ? "APC_INDEX_MISMATCH" : _snapshot.StopCode), small, foreground, glyphBackground, infoX, 955F * sy);
            }
        }

        private void DrawModernChangeText(Graphics graphics)
        {
            DrawModernChangeText(graphics, Color.White, ModernBlue);
        }

        private void DrawModernChangeText(Graphics graphics, Color foreground, Color glyphBackground)
        {
            List<string> values = PadPreviewValues(_snapshot.ReplacementTexts, 9);
            string faceText = ValueAtOrRepeatLast(values, 0, ":(");
            string firstBodyText = ValueAtOrRepeatLast(values, 1, "你的设备遇到问题，需要重启。");
            string secondBodyText = ValueAtOrRepeatLast(values, 2, "我们只收集某些错误信息，然后为你重新启动。");
            string progressText = ValueAtOrRepeatLast(values, 7, "0") + (_snapshot.SkipPercent ? "% 完成" : ValueAtOrRepeatLast(values, 8, "% 完成"));
            float sx = ClientSize.Width / 2048F;
            float sy = ClientSize.Height / 1536F;
            float x = 260F * sx;
            using (Font face = new Font("Microsoft YaHei UI", Math.Max(72F, 238F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            using (Font body = new Font("Microsoft YaHei UI", Math.Max(25F, 52F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            using (Font progress = new Font("Microsoft YaHei UI", Math.Max(24F, 48F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            using (Font small = new Font("Microsoft YaHei UI", Math.Max(14F, 27F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            {
                DrawWideFaceText(graphics, faceText, face, foreground, glyphBackground, x, 210F * sy);
                DrawTextBlock(graphics, firstBodyText, body, foreground, glyphBackground, x, 505F * sy);
                DrawTextBlock(graphics, secondBodyText, body, foreground, glyphBackground, x, 580F * sy);
                DrawTextBlock(graphics, progressText, progress, foreground, glyphBackground, x, 705F * sy);
                float qrX = x;
                float qrY = 820F * sy;
                float qrSize = Math.Max(120F, 205F * sy);
                DrawQrCode(graphics, qrX, qrY, qrSize);
                float infoX = qrX + qrSize + 30F * sx;
                DrawTextBlock(graphics, ValueAtOrRepeatLast(values, 3, "有关此问题的详细信息和可能的解决方法，请访问 https://www.windows.com/stopcode"), small, foreground, glyphBackground, infoX, 820F * sy);
                DrawTextBlock(graphics, ValueAtOrRepeatLast(values, 4, "如果致电支持人员，请向他们提供以下信息:"), small, foreground, glyphBackground, infoX, 910F * sy);
                DrawTextBlock(graphics, ValueAtOrRepeatLast(values, 5, "终止代码: ") + " " + ValueAtOrRepeatLast(values, 6, "APC_INDEX_MISMATCH"), small, foreground, glyphBackground, infoX, 955F * sy);
            }
        }

        private void DrawWindows11(Graphics graphics)
        {
            bool rainbow = _snapshot.Kind == PreviewKind.ModernRainbow || _snapshot.Rainbow;
            Color background = rainbow ? FromHsv(_hue, 1.0, 0.92) : Opaque(_snapshot.Background);
            Fill(graphics, background);
            float sx = ClientSize.Width / 2048F;
            float sy = ClientSize.Height / 1536F;
            using (Font body = new Font("Microsoft YaHei UI", Math.Max(25F, 52F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            using (Font progress = new Font("Microsoft YaHei UI", Math.Max(24F, 48F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            using (Font small = new Font("Microsoft YaHei UI", Math.Max(14F, 27F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            {
                if (rainbow)
                {
                    DrawCenteredTextBlock(graphics, "你的设备遇到问题，需要重启。", body, Color.White, background, ClientSize.Width / 2F, 635F * sy);
                    DrawCenteredTextBlock(graphics, "我们只收集某些错误信息，然后你可以重新启动。", body, Color.White, background, ClientSize.Width / 2F, 705F * sy);
                    return;
                }
                Color foreground = Opaque(_snapshot.Foreground);
                Color glyphBackground = (_snapshot.Kind == PreviewKind.ModernBackground || _snapshot.Kind == PreviewKind.ModernStopCode) ? Color.Black : Opaque(_snapshot.TextBackground);
                if ((_snapshot.Kind == PreviewKind.ModernChangeText || _snapshot.Kind == PreviewKind.Full) && _snapshot.ReplacementTexts.Count > 0)
                {
                    DrawWindows11ChangeText(graphics, body, progress, small, foreground, glyphBackground, sy);
                    return;
                }
                DrawCenteredTextBlock(graphics, "你的设备遇到问题，需要重启。", body, foreground, glyphBackground, ClientSize.Width / 2F, 635F * sy);
                using (Brush band = new SolidBrush(glyphBackground)) graphics.FillRectangle(band, 22F * sx, 733F * sy, 1446F * sx, Math.Max(40F * sy, 1F));
                DrawCenteredTextBlock(graphics, "0% 完成", progress, foreground, glyphBackground, ClientSize.Width / 2F, 755F * sy);
                string stopCode = string.IsNullOrEmpty(_snapshot.StopCode) ? "APC_INDEX_MISMATCH" : _snapshot.StopCode;
                DrawCenteredTextBlock(graphics, "终止代码: " + stopCode + " (0x1)", small, foreground, glyphBackground, ClientSize.Width / 2F, 1460F * sy);
            }
        }

        private void DrawWindows11ChangeText(Graphics graphics, Font body, Font progress, Font small, Color foreground, Color glyphBackground, float sy)
        {
            List<string> values = PadPreviewValues(_snapshot.ReplacementTexts, 10);
            string mainText = ValueAtOrRepeatLast(values, 0, "你的设备遇到问题，需要重启。");
            string progressText = _snapshot.SkipPercent ? "0% 完成" : ValueAtOrRepeatLast(values, 2, "0% 完成");
            string bottomText = ValueAtOrRepeatLast(values, 1, "终止代码: " + (string.IsNullOrEmpty(_snapshot.StopCode) ? "APC_INDEX_MISMATCH" : _snapshot.StopCode) + " (0x1)");
            DrawCenteredTextBlock(graphics, mainText, body, foreground, glyphBackground, ClientSize.Width / 2F, 635F * sy);
            DrawCenteredTextBlock(graphics, progressText, progress, foreground, glyphBackground, ClientSize.Width / 2F, 755F * sy);
            DrawCenteredTextBlock(graphics, bottomText, small, foreground, glyphBackground, ClientSize.Width / 2F, 1460F * sy);
        }

        private void DrawModernDisplayStrings(Graphics graphics)
        {
            float scaleX = ClientSize.Width / 1152F;
            float scaleY = ClientSize.Height / 864F;
            float fontScale = Math.Min(scaleX, scaleY);
            foreach (PreviewTextItem item in _snapshot.DisplayItems)
            {
                if (item.ClearScreen) Fill(graphics, Opaque(item.ScreenBackground));
                float fontSize = Math.Max(8F, item.TextSize * fontScale);
                float x = item.X * scaleX;
                float y = item.Y * scaleY;
                Color foreground = item.Rainbow ? Color.White : Opaque(item.TextForeground);
                Color background = item.Rainbow ? FromHsv(_hue, 1.0, 1.0) : Opaque(item.TextBackground);
                using (Font font = new Font("Segoe UI", fontSize, FontStyle.Regular, GraphicsUnit.Pixel))
                {
                    DrawTextBlock(graphics, item.Text ?? string.Empty, font, foreground, background, x, y);
                }
            }
            foreach (PreviewImageItem item in _snapshot.DisplayImages)
            {
                if (item.ClearScreen) Fill(graphics, Opaque(item.ScreenBackground));
                if (item.Pixels == null || item.Width <= 0 || item.Height <= 0 || (long)item.Width * item.Height != item.Pixels.Length) continue;
                using (Bitmap bitmap = new Bitmap(item.Width, item.Height))
                {
                    int pixelIndex = 0;
                    for (int y = 0; y < item.Height; y++)
                    {
                        for (int x = 0; x < item.Width; x++) bitmap.SetPixel(x, y, Color.FromArgb(unchecked((int)item.Pixels[pixelIndex++])));
                    }
                    InterpolationMode previous = graphics.InterpolationMode;
                    PixelOffsetMode previousOffset = graphics.PixelOffsetMode;
                    graphics.InterpolationMode = InterpolationMode.NearestNeighbor;
                    graphics.PixelOffsetMode = PixelOffsetMode.Half;
                    graphics.DrawImage(bitmap, new RectangleF(item.X * scaleX, item.Y * scaleY, Math.Max(1F, item.Width * scaleX), Math.Max(1F, item.Height * scaleY)), new RectangleF(0, 0, item.Width, item.Height), GraphicsUnit.Pixel);
                    graphics.InterpolationMode = previous;
                    graphics.PixelOffsetMode = previousOffset;
                }
            }
        }

        private void DrawQrCode(Graphics graphics, float x, float y, float size)
        {
            RectangleF area = new RectangleF(x, y, size, size);
            if (_qrBitmap == null)
            {
                BsodQrPattern.Draw(graphics, area);
                return;
            }
            using (Brush white = new SolidBrush(Color.White)) graphics.FillRectangle(white, area);
            float scale = Math.Min(size / _qrBitmap.Width, size / _qrBitmap.Height);
            float width = Math.Max(1F, _qrBitmap.Width * scale);
            float height = Math.Max(1F, _qrBitmap.Height * scale);
            RectangleF destination = new RectangleF(x + (size - width) / 2F, y + (size - height) / 2F, width, height);
            InterpolationMode previous = graphics.InterpolationMode;
            PixelOffsetMode previousOffset = graphics.PixelOffsetMode;
            graphics.InterpolationMode = InterpolationMode.NearestNeighbor;
            graphics.PixelOffsetMode = PixelOffsetMode.Half;
            graphics.DrawImage(_qrBitmap, destination, new RectangleF(0, 0, _qrBitmap.Width, _qrBitmap.Height), GraphicsUnit.Pixel);
            graphics.InterpolationMode = previous;
            graphics.PixelOffsetMode = previousOffset;
        }

        private static Bitmap BuildQrBitmap(PreviewSnapshot snapshot)
        {
            if (snapshot == null || snapshot.QrPixels == null || snapshot.QrWidth <= 0 || snapshot.QrLength <= 0) return null;
            if ((long)snapshot.QrWidth * snapshot.QrLength != snapshot.QrPixels.Length) return null;
            Bitmap bitmap = new Bitmap(snapshot.QrLength, snapshot.QrWidth);
            int index = 0;
            for (int row = 0; row < snapshot.QrWidth; row++)
            {
                for (int column = 0; column < snapshot.QrLength; column++) bitmap.SetPixel(column, row, Color.FromArgb(unchecked((int)snapshot.QrPixels[index++])));
            }
            return bitmap;
        }

        private static void DrawTextBlock(Graphics graphics, string text, Font font, Color foreground, Color background, float x, float y)
        {
            SizeF measured = graphics.MeasureString(text ?? string.Empty, font, PointF.Empty, StringFormat.GenericTypographic);
            if (background.A != 0)
            {
                using (Brush backBrush = new SolidBrush(Opaque(background))) graphics.FillRectangle(backBrush, x, y, Math.Max(1F, measured.Width), Math.Max(1F, measured.Height));
            }
            using (Brush textBrush = new SolidBrush(Opaque(foreground))) graphics.DrawString(text ?? string.Empty, font, textBrush, x, y, StringFormat.GenericTypographic);
        }

        private static void DrawWideFaceText(Graphics graphics, string text, Font font, Color foreground, Color background, float x, float y)
        {
            if (text != ":(" && text != ":)")
            {
                DrawTextBlock(graphics, text, font, foreground, background, x, y);
                return;
            }
            const float parenthesisScale = 1.35F;
            string parenthesis = text.Substring(1, 1);
            SizeF colonSize = graphics.MeasureString(":", font, PointF.Empty, StringFormat.GenericTypographic);
            SizeF parenthesisSize = graphics.MeasureString(parenthesis, font, PointF.Empty, StringFormat.GenericTypographic);
            float width = colonSize.Width + parenthesisSize.Width * parenthesisScale;
            float height = Math.Max(colonSize.Height, parenthesisSize.Height);
            if (background.A != 0)
            {
                using (Brush backBrush = new SolidBrush(Opaque(background))) graphics.FillRectangle(backBrush, x, y, Math.Max(1F, width), Math.Max(1F, height));
            }
            using (Brush textBrush = new SolidBrush(Opaque(foreground)))
            {
                graphics.DrawString(":", font, textBrush, x, y, StringFormat.GenericTypographic);
                GraphicsState state = graphics.Save();
                graphics.ScaleTransform(parenthesisScale, 1F);
                graphics.DrawString(parenthesis, font, textBrush, (x + colonSize.Width) / parenthesisScale, y, StringFormat.GenericTypographic);
                graphics.Restore(state);
            }
        }

        private static void DrawCenteredTextBlock(Graphics graphics, string text, Font font, Color foreground, Color background, float centerX, float y)
        {
            SizeF measured = graphics.MeasureString(text ?? string.Empty, font, PointF.Empty, StringFormat.GenericTypographic);
            DrawTextBlock(graphics, text, font, foreground, background, centerX - measured.Width / 2F, y);
        }

        private void Fill(Graphics graphics, Color color)
        {
            using (Brush brush = new SolidBrush(Opaque(color))) graphics.FillRectangle(brush, ClientRectangle);
        }

        private static string ValueAtOrRepeatLast(List<string> values, int index, string fallback)
        {
            if (values == null || values.Count == 0 || index < 0) return fallback;
            return index < values.Count ? values[index] : fallback;
        }

        private static List<string> PadPreviewValues(List<string> values, int minimumCount)
        {
            List<string> padded = values == null ? new List<string>() : new List<string>(values);
            return padded;
        }

        private static bool HasAnimatedText(List<PreviewTextItem> items)
        {
            foreach (PreviewTextItem item in items) if (item.Rainbow || item.Blink) return true;
            return false;
        }

        private static bool IsRainbowKind(PreviewKind kind)
        {
            return kind == PreviewKind.Windows7Rainbow || kind == PreviewKind.ModernRainbow;
        }

        private static Color VgaColor(int value)
        {
            Color[] colors =
            {
                Color.FromArgb(0, 0, 0), Color.FromArgb(0, 0, 170), Color.FromArgb(0, 170, 0), Color.FromArgb(0, 170, 170),
                Color.FromArgb(170, 0, 0), Color.FromArgb(170, 0, 170), Color.FromArgb(170, 85, 0), Color.FromArgb(192, 192, 192),
                Color.FromArgb(128, 128, 128), Color.FromArgb(85, 85, 255), Color.FromArgb(85, 255, 85), Color.FromArgb(85, 255, 255),
                Color.FromArgb(255, 85, 85), Color.FromArgb(255, 85, 255), Color.FromArgb(255, 255, 85), Color.FromArgb(255, 255, 255)
            };
            return colors[value & 0x0F];
        }

        private static Color Opaque(Color color)
        {
            return Color.FromArgb(255, color.R, color.G, color.B);
        }

        private static Color FromHsv(double hue, double saturation, double value)
        {
            double chroma = value * saturation;
            double h = hue / 60.0;
            double x = chroma * (1.0 - Math.Abs((h % 2.0) - 1.0));
            double r = 0, g = 0, b = 0;
            if (h < 1) { r = chroma; g = x; }
            else if (h < 2) { r = x; g = chroma; }
            else if (h < 3) { g = chroma; b = x; }
            else if (h < 4) { g = x; b = chroma; }
            else if (h < 5) { r = x; b = chroma; }
            else { r = chroma; b = x; }
            double m = value - chroma;
            return Color.FromArgb(255, (int)Math.Round((r + m) * 255), (int)Math.Round((g + m) * 255), (int)Math.Round((b + m) * 255));
        }
    }

    internal sealed class ChangeTextPage : PageView
    {
        private readonly FlowLayoutPanel _rows;
        private readonly Label _count;
        private readonly CheckBox _skipPercent;
        private readonly CommandRequestHandler _send;
        private readonly PreviewRequestHandler _preview;
        private readonly List<ChangeTextRow> _items = new List<ChangeTextRow>();
        private readonly List<string> _appliedPreviewTexts = new List<string>();
        private bool _appliedSkipPercent;
        public bool HasPreviewConfiguration { get; private set; }
        public bool SkipPercent { get { return _appliedSkipPercent; } }

        public ChangeTextPage(CommandRequestHandler send, PreviewRequestHandler preview) : base("替换文本", "按调用顺序替换蓝屏关键字符串；可配置 1–100 条")
        {
            _send = send;
            _preview = preview;
            CardPanel card = new CardPanel { Height = 615 };
            Label title = Ui.Label("ChangeText 替换蓝屏文本", 13F, FontStyle.Bold, Ui.Text);
            title.Location = new Point(22, 18);
            card.Controls.Add(title);
            _skipPercent = Ui.CheckBox("跳过包含 % 的原始字符串", true);
            _skipPercent.Location = new Point(22, 83);
            card.Controls.Add(_skipPercent);
            _rows = new FlowLayoutPanel
            {
                Location = new Point(22, 119),
                Height = 382,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                AutoScroll = true,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                BackColor = Ui.Window,
                Padding = new Padding(8)
            };
            card.Controls.Add(_rows);
            card.Resize += delegate
            {
                _rows.Width = card.ClientSize.Width - 44;
                ResizeRows();
            };
            ModernButton minus = new ModernButton { Text = "−", Location = new Point(22, 526), Size = new Size(42, 38), BaseColor = Ui.CardAlt };
            minus.Click += delegate { RemoveLast(); };
            card.Controls.Add(minus);
            ModernButton plus = new ModernButton { Text = "+", Location = new Point(72, 526), Size = new Size(42, 38), BaseColor = Ui.CardAlt };
            plus.Click += delegate { AddRow(null); };
            card.Controls.Add(plus);
            _count = Ui.Label("0 / 100", 9F, FontStyle.Bold, Ui.Muted);
            _count.Location = new Point(160, 536);
            card.Controls.Add(_count);
            ModernButton apply = new ModernButton { Text = "应用全部替换文本", Location = new Point(260, 524), Size = new Size(168, 42) };
            apply.Click += delegate { Apply(); };
            card.Controls.Add(apply);
            ModernButton previewButton = new ModernButton { Text = "预览", Location = new Point(apply.Right + 20, apply.Top), Size = new Size(100, 42), BaseColor = Ui.CardAlt };
            previewButton.Click += delegate
            {
                try
                {
                    PreviewSnapshot snapshot = PreviewSnapshot.CreateDefault(false);
                    snapshot.ReplacementTexts.AddRange(GetPreviewTexts());
                    snapshot.SkipPercent = _skipPercent.Checked;
                    snapshot.Kind = PreviewKind.ModernChangeText;
                    _preview(snapshot, "替换文本预览");
                }
                catch (Exception ex)
                {
                    MessageBox.Show(FindForm(), ex.Message, "无法生成预览", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            };
            card.Controls.Add(previewButton);
            AddCard(card);
            for (int i = 0; i < 5; i++) AddRow("自定义文本 " + (i + 1).ToString(CultureInfo.InvariantCulture));
        }

        private void AddRow(string text)
        {
            if (_items.Count >= 100) return;
            ChangeTextRow row = new ChangeTextRow(text ?? string.Empty);
            row.RemoveRequested += delegate { RemoveRow(row); };
            _items.Add(row);
            _rows.Controls.Add(row);
            RefreshRows();
        }

        private void RemoveLast()
        {
            if (_items.Count > 1) RemoveRow(_items[_items.Count - 1]);
        }

        private void RemoveRow(ChangeTextRow row)
        {
            if (_items.Count <= 1) return;
            _items.Remove(row);
            _rows.Controls.Remove(row);
            row.Dispose();
            RefreshRows();
        }

        private void RefreshRows()
        {
            for (int i = 0; i < _items.Count; i++) _items[i].Index = i + 1;
            _count.Text = _items.Count.ToString(CultureInfo.InvariantCulture) + " / 100";
            ResizeRows();
        }

        private void ResizeRows()
        {
            int width = Math.Max(500, _rows.ClientSize.Width - _rows.Padding.Horizontal - 22);
            foreach (ChangeTextRow row in _items) row.Width = width;
        }

        public List<string> GetPreviewTexts()
        {
            List<string> values = new List<string>();
            foreach (ChangeTextRow row in _items) values.Add(MainForm.ValidateProtocolText(row.Value, true));
            return values;
        }

        public List<string> GetAppliedPreviewTexts()
        {
            return new List<string>(_appliedPreviewTexts);
        }

        public string BuildAppliedProtocolCommand(bool forceWindows10Layout)
        {
            if (!HasPreviewConfiguration) return null;
            return BuildProtocolCommand(_appliedPreviewTexts, _appliedSkipPercent, forceWindows10Layout);
        }

        private static string BuildProtocolCommand(IList<string> values, bool skipPercent, bool forceWindows10Layout)
        {
            int[] version = Program.GetSystemVersion();
            bool windows10Layout = forceWindows10Layout || (version[2] < 26100 && version[0] <= 10);
            StringBuilder command = new StringBuilder();
            command.Append("CT ");
            command.Append(skipPercent ? '1' : '0');
            for (int i = 0; i < values.Count; i++)
            {
                command.Append(" \"");
                command.Append(values[i]);
                command.Append('"');
                if (i == 2 && windows10Layout)
                {
                    int placeholderCount = skipPercent ? (Program.IsWindows8() ? 202 : 101) : (Program.IsWindows8() ? 303 : 202);
                    for (int j = 0; j < placeholderCount; j++) command.Append(" \"1\"");
                }
                else if (i == 0 && !windows10Layout && version[2] >= 26100 && version[0] == 10) command.Append(" \"1\"");
            }
            return command.ToString();
        }

        private void Apply()
        {
            try
            {
                List<string> values = new List<string>();
                foreach (ChangeTextRow row in _items) values.Add(MainForm.ValidateProtocolText(row.Value, true));
                List<string> previewValues = new List<string>(values);
                if (values.Count == 1) values.Add(values[0]);
                string command = BuildProtocolCommand(values, _skipPercent.Checked, Program.ForceWindows10BlueScreenEffect);
                if (_send(command, "替换文本配置已设置\n"))
                {
                    _appliedPreviewTexts.Clear();
                    _appliedPreviewTexts.AddRange(previewValues);
                    _appliedSkipPercent = _skipPercent.Checked;
                    HasPreviewConfiguration = true;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(FindForm(), ex.Message, "文本格式无效", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
    }

    internal sealed class ChangeTextRow : UserControl
    {
        private readonly Label _index;
        private readonly TextBox _text;
        public event EventHandler RemoveRequested;

        public ChangeTextRow(string value)
        {
            Height = 58;
            BackColor = Ui.CardAlt;
            Margin = new Padding(0, 0, 0, 8);
            Resize += delegate { Ui.RoundRegion(this, 7); LayoutRow(); };
            _index = Ui.Label("01", 9F, FontStyle.Bold, Ui.Accent);
            _index.Location = new Point(13, 20);
            Controls.Add(_index);
            _text = Ui.TextBox(value, false);
            _text.Location = new Point(50, 14);
            _text.Height = 30;
            Controls.Add(_text);
            ModernButton remove = new ModernButton { Text = "×", Size = new Size(38, 32), BaseColor = Ui.SoftRed };
            remove.Click += delegate { if (RemoveRequested != null) RemoveRequested(this, EventArgs.Empty); };
            Controls.Add(remove);
            remove.Tag = "remove";
            LayoutRow();
        }
        public int Index { set { _index.Text = value.ToString("00", CultureInfo.InvariantCulture); } }
        public string Value { get { return _text.Text; } }
        private void LayoutRow()
        {
            Control remove = null;
            foreach (Control control in Controls) if ((string)control.Tag == "remove") remove = control;
            if (remove == null) return;
            remove.Location = new Point(Width - 46, 14);
            _text.Width = Math.Max(200, Width - 108);
        }
    }

    internal enum QrPaintTool
    {
        Select,
        Brush,
        Eraser,
        Fill,
        Line,
        Rectangle,
        Ellipse,
        Text
    }

    internal sealed class QrEditorPage : PageView
    {
        private readonly LargeCommandRequestHandler _send;
        private readonly RectDescriptionRequestHandler _readRectDescription;
        private readonly NumericUpDown _width;
        private readonly NumericUpDown _length;
        private readonly NumericUpDown _thickness;
        private readonly NumericUpDown _fontSize;
        private readonly NumericUpDown _zoom;
        private readonly Label _dimensionStatus;
        private readonly Label _toolStatus;
        private readonly Panel _colorPreview;
        private readonly QrCanvasControl _canvas;
        private readonly Dictionary<QrPaintTool, ModernButton> _toolButtons = new Dictionary<QrPaintTool, ModernButton>();
        private uint[] _appliedPixels;
        private int _appliedWidth;
        private int _appliedLength;
        private long _requiredPixelCount;
        private uint _driverHeight;
        private uint _driverWidth;
        private bool _dimensionsLoaded;
        public bool HasAppliedConfiguration { get; private set; }

        public QrEditorPage(LargeCommandRequestHandler send, RectDescriptionRequestHandler readRectDescription) : base("修改二维码", "将二维码改成自定义的图像")
        {
            _send = send;
            _readRectDescription = readRectDescription;
            CardPanel card = new CardPanel { Height = 920 };
            TableLayoutPanel layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                Margin = Padding.Empty,
                Padding = Padding.Empty,
                ColumnCount = 1,
                RowCount = 5,
                BackColor = Color.Transparent
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 36F));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 112F));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 92F));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 154F));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            card.Controls.Add(layout);

            Label title = Ui.Label("二维码画板", 13F, FontStyle.Bold, Ui.Text);
            title.Dock = DockStyle.Fill;
            title.TextAlign = ContentAlignment.MiddleLeft;
            layout.Controls.Add(title, 0, 0);

            FlowLayoutPanel statusBar = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 2, 0, 6),
                Padding = new Padding(8, 5, 8, 5),
                WrapContents = true,
                AutoScroll = true,
                FlowDirection = FlowDirection.LeftToRight,
                BackColor = Ui.CardAlt
            };
            layout.Controls.Add(statusBar, 0, 1);
            _width = CreateDimensionField(1);
            statusBar.Controls.Add(CreateFieldPanel("宽（行数）", _width, 104));
            Label multiply = Ui.Label("×", 12F, FontStyle.Bold, Ui.Muted);
            multiply.Margin = new Padding(2, 29, 2, 0);
            statusBar.Controls.Add(multiply);
            _length = CreateDimensionField(1);
            statusBar.Controls.Add(CreateFieldPanel("长（列数）", _length, 104));
            _dimensionStatus = Ui.Label(string.Empty, 9F, FontStyle.Bold, Ui.Green);
            _dimensionStatus.Margin = new Padding(10, 27, 8, 0);
            statusBar.Controls.Add(_dimensionStatus);
            ModernButton rebuild = CreateToolbarButton("重建画布", 112);
            rebuild.Margin = new Padding(8, 17, 2, 0);
            rebuild.Click += delegate { RebuildCanvas(); };
            statusBar.Controls.Add(rebuild);
            ModernButton apply = CreateToolbarButton("应用二维码", 124);
            apply.Margin = new Padding(8, 17, 2, 0);
            apply.BaseColor = Ui.Accent;
            apply.Click += delegate { Apply(); };
            statusBar.Controls.Add(apply);
            _toolStatus = Ui.Label("当前工具：画笔", 8.8F, FontStyle.Regular, Ui.Muted);
            _toolStatus.Margin = new Padding(12, 27, 8, 0);
            statusBar.Controls.Add(_toolStatus);

            FlowLayoutPanel tools = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 0, 0, 6),
                Padding = new Padding(6, 5, 6, 5),
                WrapContents = true,
                AutoScroll = true,
                FlowDirection = FlowDirection.LeftToRight,
                BackColor = Ui.CardAlt
            };
            layout.Controls.Add(tools, 0, 2);
            AddToolButton(tools, QrPaintTool.Select, "选择");
            AddToolButton(tools, QrPaintTool.Brush, "画笔");
            AddToolButton(tools, QrPaintTool.Eraser, "橡皮");
            AddToolButton(tools, QrPaintTool.Fill, "填充");
            AddToolButton(tools, QrPaintTool.Line, "直线");
            AddToolButton(tools, QrPaintTool.Rectangle, "矩形");
            AddToolButton(tools, QrPaintTool.Ellipse, "椭圆");
            AddToolButton(tools, QrPaintTool.Text, "文字");
            ModernButton import = CreateToolbarButton("导入图像", 92);
            import.Click += delegate { ImportImage(); };
            tools.Controls.Add(import);
            ModernButton undo = CreateToolbarButton("撤销", 66);
            undo.Click += delegate { _canvas.Undo(); };
            tools.Controls.Add(undo);
            ModernButton redo = CreateToolbarButton("重做", 66);
            redo.Click += delegate { _canvas.Redo(); };
            tools.Controls.Add(redo);
            ModernButton clear = CreateToolbarButton("清空", 66);
            clear.Click += delegate { _canvas.Clear(Color.White); };
            tools.Controls.Add(clear);
            ModernButton copy = CreateToolbarButton("复制", 66);
            copy.Click += delegate { _canvas.CopySelection(); };
            tools.Controls.Add(copy);
            ModernButton paste = CreateToolbarButton("粘贴", 66);
            paste.Click += delegate { _canvas.PasteClipboard(); };
            tools.Controls.Add(paste);

            FlowLayoutPanel options = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 0, 0, 6),
                Padding = new Padding(4, 3, 4, 3),
                WrapContents = true,
                AutoScroll = true,
                FlowDirection = FlowDirection.LeftToRight,
                BackColor = Color.Transparent
            };
            layout.Controls.Add(options, 0, 3);
            _thickness = CreateNumberField(2, 1, 64, 72);
            options.Controls.Add(CreateFieldPanel("粗细", _thickness, 78));
            _fontSize = CreateNumberField(18, 4, 128, 72);
            options.Controls.Add(CreateFieldPanel("字号", _fontSize, 78));
            _zoom = CreateNumberField(3, 1, 16, 72);
            options.Controls.Add(CreateFieldPanel("缩放倍数", _zoom, 86));
            _colorPreview = new Panel
            {
                Size = new Size(42, 29),
                BackColor = Color.Black,
                BorderStyle = BorderStyle.FixedSingle,
                Cursor = Cursors.Hand
            };
            _colorPreview.Click += delegate { PickCustomColor(); };
            options.Controls.Add(CreateFieldPanel("颜色", _colorPreview, 50));
            FlowLayoutPanel palette = new FlowLayoutPanel
            {
                Width = 600,
                Height = 70,
                Margin = new Padding(4, 1, 4, 1),
                Padding = new Padding(0),
                WrapContents = true,
                FlowDirection = FlowDirection.LeftToRight,
                BackColor = Color.Transparent
            };
            options.Controls.Add(palette);
            Color[] colors =
            {
                Color.Black, Color.White, Color.Gray, Color.Silver,
                Color.Red, Color.Maroon, Color.Orange, Color.Yellow,
                Color.Lime, Color.Green, Color.Cyan, Color.Teal,
                Color.Blue, Color.Navy, Color.Magenta, Color.Purple
            };
            foreach (Color color in colors) AddPaletteColor(palette, color);
            Button customColor = new Button
            {
                Text = "+",
                Size = new Size(30, 30),
                Margin = new Padding(2),
                FlatStyle = FlatStyle.Flat,
                BackColor = Ui.CardAlt,
                ForeColor = Ui.Text,
                Cursor = Cursors.Hand
            };
            customColor.Click += delegate { PickCustomColor(); };
            palette.Controls.Add(customColor);

            TableLayoutPanel canvasLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                Margin = Padding.Empty,
                Padding = Padding.Empty,
                ColumnCount = 1,
                RowCount = 2,
                BackColor = Color.Transparent
            };
            canvasLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            canvasLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 27F));
            canvasLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            layout.Controls.Add(canvasLayout, 0, 4);
            Panel canvasHost = new Panel
            {
                Dock = DockStyle.Fill,
                Margin = Padding.Empty,
                AutoScroll = true,
                BackColor = Color.FromArgb(222, 229, 239),
                BorderStyle = BorderStyle.FixedSingle
            };
            canvasLayout.Controls.Add(canvasHost, 0, 1);
            _canvas = new QrCanvasControl(1, 1)
            {
                Location = new Point(8, 8),
                PrimaryColor = Color.Black,
                BrushSize = 2,
                TextSize = 18,
                Zoom = 3
            };
            canvasHost.Controls.Add(_canvas);
            _canvas.SizeChanged += delegate { canvasHost.AutoScrollMinSize = new Size(_canvas.Width + 16, _canvas.Height + 16); };
            canvasHost.AutoScrollMinSize = new Size(_canvas.Width + 16, _canvas.Height + 16);
            _width.ValueChanged += delegate { UpdateDimensionStatus(); };
            _length.ValueChanged += delegate { UpdateDimensionStatus(); };
            _thickness.ValueChanged += delegate { _canvas.BrushSize = decimal.ToInt32(_thickness.Value); };
            _fontSize.ValueChanged += delegate { _canvas.TextSize = decimal.ToInt32(_fontSize.Value); };
            _zoom.ValueChanged += delegate
            {
                _canvas.Zoom = decimal.ToInt32(_zoom.Value);
                if (_zoom.Value != _canvas.Zoom) _zoom.Value = _canvas.Zoom;
            };
            _canvas.ZoomChanged += delegate { if (_zoom.Value != _canvas.Zoom) _zoom.Value = _canvas.Zoom; };
            AddCard(card);
            SelectTool(QrPaintTool.Brush, "画笔");
            UpdateDimensionStatus();
        }

        public void LoadRectangleDescription()
        {
            try
            {
                DeviceClient.GP_RECT_DESC description = _readRectDescription();
                if (description.H == 0 || description.W == 0) throw new InvalidOperationException("驱动返回的 H 和 W 必须大于 0");
                if (description.H > int.MaxValue || description.W > int.MaxValue) throw new InvalidOperationException($"驱动返回的 H({description.H}) 或 W({description.W}) 超出画布支持范围");
                long requiredPixelCount = checked((long)description.H * description.W);
                if (requiredPixelCount > int.MaxValue) throw new InvalidOperationException("驱动返回的 H × W 超出画布支持范围");

                if (_dimensionsLoaded && _requiredPixelCount != requiredPixelCount)
                {
                    _appliedPixels = null;
                    HasAppliedConfiguration = false;
                }
                _driverHeight = description.H;
                _driverWidth = description.W;
                _requiredPixelCount = requiredPixelCount;
                int maximumDimension = checked((int)requiredPixelCount);
                _width.Maximum = maximumDimension;
                _length.Maximum = maximumDimension;
                _width.Value = description.H;
                _length.Value = description.W;
                _canvas.ResizeCanvas(checked((int)description.H), checked((int)description.W));
                if (_zoom.Value != _canvas.Zoom) _zoom.Value = _canvas.Zoom;
                _dimensionsLoaded = true;
                UpdateDimensionStatus();
            }
            catch
            {
                _dimensionsLoaded = false;
                _appliedPixels = null;
                HasAppliedConfiguration = false;
                _dimensionStatus.Text = "未能从驱动读取画布尺寸";
                _dimensionStatus.ForeColor = Ui.Red;
                throw;
            }
        }

        private static NumericUpDown CreateDimensionField(int value)
        {
            return CreateNumberField(value, 1, int.MaxValue, 96);
        }

        private static NumericUpDown CreateNumberField(int value, int minimum, int maximum, int width)
        {
            return new NumericUpDown
            {
                Size = new Size(width, 29),
                Minimum = minimum,
                Maximum = maximum,
                Value = value,
                BackColor = Ui.Input,
                ForeColor = Ui.Text,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 9.5F),
                ThousandsSeparator = false
            };
        }

        private static Panel CreateFieldPanel(string label, Control input, int width)
        {
            Panel panel = new Panel
            {
                Width = width,
                Height = Math.Max(60, input.Height + 28),
                Margin = new Padding(4, 1, 4, 1),
                BackColor = Color.Transparent
            };
            Label caption = Ui.Label(label, 8.3F, FontStyle.Regular, Ui.Muted);
            caption.Location = new Point(0, 0);
            input.Location = new Point(0, 24);
            panel.Controls.Add(caption);
            panel.Controls.Add(input);
            return panel;
        }

        private static ModernButton CreateToolbarButton(string text, int width)
        {
            return new ModernButton
            {
                Text = text,
                Size = new Size(width, 34),
                Margin = new Padding(3),
                BaseColor = Ui.CardAlt
            };
        }

        private void AddToolButton(FlowLayoutPanel tools, QrPaintTool tool, string text)
        {
            ModernButton button = CreateToolbarButton(text, 66);
            button.Click += delegate { SelectTool(tool, text); };
            _toolButtons.Add(tool, button);
            tools.Controls.Add(button);
        }

        private void SelectTool(QrPaintTool tool, string text)
        {
            _canvas.Tool = tool;
            foreach (KeyValuePair<QrPaintTool, ModernButton> item in _toolButtons) item.Value.SelectedState = item.Key == tool;
            _toolStatus.Text = "当前工具：" + text;
        }

        private void AddPaletteColor(FlowLayoutPanel palette, Color color)
        {
            Button swatch = new Button
            {
                Size = new Size(30, 30),
                Margin = new Padding(2),
                BackColor = color,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Tag = color
            };
            swatch.FlatAppearance.BorderColor = color == Color.Black ? Color.DimGray : Ui.Border;
            swatch.Click += delegate (object sender, EventArgs e) { SetColor((Color)((Control)sender).Tag); };
            palette.Controls.Add(swatch);
        }

        private void PickCustomColor()
        {
            using (ColorDialog dialog = new ColorDialog())
            {
                dialog.FullOpen = true;
                dialog.AnyColor = true;
                dialog.Color = _canvas.PrimaryColor;
                if (dialog.ShowDialog(FindForm()) == DialogResult.OK) SetColor(Color.FromArgb(255, dialog.Color.R, dialog.Color.G, dialog.Color.B));
            }
        }

        private void SetColor(Color color)
        {
            _canvas.PrimaryColor = color;
            _colorPreview.BackColor = color;
        }

        private void UpdateDimensionStatus()
        {
            if (!_dimensionsLoaded)
            {
                _dimensionStatus.Text = "等待从驱动读取 H × W";
                _dimensionStatus.ForeColor = Ui.Amber;
                return;
            }
            long width = decimal.ToInt64(_width.Value);
            long length = decimal.ToInt64(_length.Value);
            long product = width * length;
            bool valid = product == _requiredPixelCount;
            _dimensionStatus.Text = valid ? "有效：" + product.ToString(CultureInfo.InvariantCulture) + "(0x" + width.ToString("X", CultureInfo.InvariantCulture) + " × 0x" + length.ToString("X", CultureInfo.InvariantCulture) + ")" : "无效：" + product.ToString(CultureInfo.InvariantCulture) + " / " + _requiredPixelCount.ToString(CultureInfo.InvariantCulture);
            _dimensionStatus.ForeColor = valid ? Ui.Green : Ui.Red;
        }

        private bool TryGetValidDimensions(out int width, out int length)
        {
            width = decimal.ToInt32(_width.Value);
            length = decimal.ToInt32(_length.Value);
            if (!_dimensionsLoaded)
            {
                MessageBox.Show(FindForm(), "尚未从驱动读取 GP_RECT_DESC，无法确定二维码画布像素数", "尺寸不可用", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
            if ((long)width * length == _requiredPixelCount) return true;
            MessageBox.Show(FindForm(), "宽 × 长必须等于驱动返回的 H × W\n\nH × W：" + _driverHeight.ToString(CultureInfo.InvariantCulture) + " × " + _driverWidth.ToString(CultureInfo.InvariantCulture) + "\n要求像素数：" + _requiredPixelCount.ToString(CultureInfo.InvariantCulture), "尺寸无效", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return false;
        }

        private void RebuildCanvas()
        {
            int width, length;
            if (!TryGetValidDimensions(out width, out length)) return;
            _canvas.ResizeCanvas(width, length);
            if (_zoom.Value != _canvas.Zoom) _zoom.Value = _canvas.Zoom;
            UpdateDimensionStatus();
        }

        private void ImportImage()
        {
            using (OpenFileDialog dialog = new OpenFileDialog())
            {
                dialog.Title = "导入图像到二维码画板";
                dialog.Filter = "图像文件|*.png;*.jpg;*.jpeg;*.bmp;*.gif|所有文件|*.*";
                if (dialog.ShowDialog(FindForm()) != DialogResult.OK) return;
                try { _canvas.ImportImage(dialog.FileName); }
                catch (Exception ex) { MessageBox.Show(FindForm(), ex.Message, "无法导入图像", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            }
        }

        private void Apply()
        {
            try
            {
                int width, length;
                if (!TryGetValidDimensions(out width, out length)) return;
                if (_canvas.ProtocolWidth != width || _canvas.ProtocolLength != length) _canvas.ResizeCanvas(width, length);
                if (_zoom.Value != _canvas.Zoom) _zoom.Value = _canvas.Zoom;
                uint[] pixels = _canvas.GetArgbPixels();
                if (pixels.LongLength != _requiredPixelCount) throw new InvalidOperationException("画布数据项数量不等于驱动返回的 H × W");
                StringBuilder command = new StringBuilder(32 + (pixels.Length * 9));
                command.Append("QR ");
                command.Append(width.ToString("X", CultureInfo.InvariantCulture));
                command.Append(' ');
                command.Append(length.ToString("X", CultureInfo.InvariantCulture));
                command.Append(" {");
                for (int i = 0; i < pixels.Length; i++)
                {
                    if (i > 0) command.Append(',');
                    command.Append(pixels[i].ToString("X8", CultureInfo.InvariantCulture));
                }
                command.Append('}');
                string confirmation = "是否应用当前二维码图像？\n\n宽 × 长：" + width.ToString(CultureInfo.InvariantCulture) + " × " + length.ToString(CultureInfo.InvariantCulture) + "(发送为 0x" + width.ToString("X", CultureInfo.InvariantCulture) + " 0x" + length.ToString("X", CultureInfo.InvariantCulture) + ")\n数据: " + pixels.Length.ToString(CultureInfo.InvariantCulture) + " 项 ARGB";
                if (_send(command.ToString(), confirmation, "二维码图像已应用"))
                {
                    _appliedWidth = width;
                    _appliedLength = length;
                    _appliedPixels = (uint[])pixels.Clone();
                    HasAppliedConfiguration = true;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(FindForm(), ex.Message, "无法应用二维码", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        public void ApplyToPreview(PreviewSnapshot snapshot)
        {
            if (!HasAppliedConfiguration || snapshot == null || _appliedPixels == null) return;
            snapshot.QrWidth = _appliedWidth;
            snapshot.QrLength = _appliedLength;
            snapshot.QrPixels = (uint[])_appliedPixels.Clone();
        }
    }

    internal sealed class QrCanvasControl : Control
    {
        private enum SelectionHandle
        {
            None,
            TopLeft,
            Top,
            TopRight,
            Right,
            BottomRight,
            Bottom,
            BottomLeft,
            Left
        }

        private struct InlineTextHistoryState
        {
            public readonly string Text;
            public readonly int Caret;
            public readonly int Anchor;

            public InlineTextHistoryState(string text, int caret, int anchor)
            {
                Text = text;
                Caret = caret;
                Anchor = anchor;
            }
        }

        private const TextFormatFlags NaturalTextFlags = TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine | TextFormatFlags.Left | TextFormatFlags.Top | TextFormatFlags.PreserveGraphicsClipping;
        private const int CanvasMargin = 12;
        private Bitmap _image;
        private Rectangle _imageBounds;
        private bool _drawing;
        private Point _startPoint;
        private Point _lastPoint;
        private Point _currentPoint;
        private int _zoom = 3;
        private QrPaintTool _tool;
        private Color _primaryColor = Color.Black;
        private int _brushSize = 2;
        private string _textValue = string.Empty;
        private int _textSize = 18;
        private Point _textOrigin;
        private bool _isEditingText;
        private string _editingTextValue = string.Empty;
        private int _textCaretIndex;
        private int _textSelectionAnchor;
        private bool _selectingText;
        private bool _caretVisible;
        private readonly Timer _caretTimer;
        private readonly List<InlineTextHistoryState> _textUndo = new List<InlineTextHistoryState>();
        private readonly List<InlineTextHistoryState> _textRedo = new List<InlineTextHistoryState>();
        private Rectangle _selection = Rectangle.Empty;
        private bool _selecting;
        private bool _movingSelection;
        private bool _resizingSelection;
        private Bitmap _floatingSelection;
        private Rectangle _floatingSourceSelection;
        private Point _selectionOffset;
        private Rectangle _resizeStartSelection;
        private SelectionHandle _activeSelectionHandle;
        private bool _selectionIsText;
        private int _selectionTextSize = 18;
        private readonly List<Bitmap> _undo = new List<Bitmap>();
        private readonly List<Bitmap> _redo = new List<Bitmap>();
        public event EventHandler ZoomChanged;
        public event EventHandler TextValueChanged;

        public QrCanvasControl(int protocolWidth, int protocolLength)
        {
            DoubleBuffered = true;
            BackColor = Color.White;
            Cursor = Cursors.Cross;
            TabStop = true;
            ImeMode = ImeMode.On;
            SetStyle(ControlStyles.Selectable, true);
            _caretTimer = new Timer { Interval = 500 };
            _caretTimer.Tick += delegate
            {
                _caretVisible = _isEditingText && ContainsFocus && !_caretVisible;
                if (_isEditingText) Invalidate();
            };
            _image = CreateBlankBitmap(protocolLength, protocolWidth, Color.White);
            using (Graphics graphics = Graphics.FromImage(_image)) BsodQrPattern.Draw(graphics, new RectangleF(0, 0, _image.Width, _image.Height));
            Tool = QrPaintTool.Brush;
            PrimaryColor = Color.Black;
            BrushSize = 2;
            TextValue = string.Empty;
            TextSize = 18;
            UpdateCanvasSize();
        }

        public QrPaintTool Tool
        {
            get { return _tool; }
            set
            {
                if (_tool == value) return;
                if (_tool == QrPaintTool.Text) CommitTextEditor();
                _tool = value;
                Cursor = value == QrPaintTool.Text ? Cursors.IBeam : Cursors.Cross;
                Invalidate();
            }
        }
        public Color PrimaryColor
        {
            get { return _primaryColor; }
            set
            {
                Color next = Color.FromArgb(255, value.R, value.G, value.B);
                if (_primaryColor.ToArgb() == next.ToArgb()) return;
                _primaryColor = next;
                if (!_isEditingText && _selectionIsText && !_selection.IsEmpty && !_drawing) RecolorSelection(next);
                Invalidate();
            }
        }
        public int BrushSize
        {
            get { return _brushSize; }
            set { _brushSize = Math.Max(1, value); }
        }
        public string TextValue
        {
            get { return _textValue ?? string.Empty; }
            set
            {
                _textValue = value ?? string.Empty;
                if (_isEditingText)
                {
                    _editingTextValue = _textValue;
                    _textCaretIndex = _editingTextValue.Length;
                    _textSelectionAnchor = _textCaretIndex;
                    ResetCaretBlink();
                }
            }
        }
        public int TextSize
        {
            get { return _textSize; }
            set
            {
                int next = Math.Max(4, value);
                if (_textSize == next) return;
                _textSize = next;
                if (!_isEditingText && _selectionIsText && !_selection.IsEmpty && !_drawing && _selectionTextSize > 0)
                {
                    ScaleSelection((float)next / _selectionTextSize);
                    _selectionTextSize = next;
                }
                Invalidate();
            }
        }
        public int ProtocolWidth { get { return _image.Height; } }
        public int ProtocolLength { get { return _image.Width; } }
        public int Zoom
        {
            get { return _zoom; }
            set
            {
                int next = Math.Max(1, Math.Min(16, value));
                int largest = Math.Max(_image.Width, _image.Height);
                while (next > 1 && ((long)largest * next) > 30000L) next--;
                if (_zoom == next) return;
                _zoom = next;
                UpdateCanvasSize();
                Invalidate();
                if (ZoomChanged != null) ZoomChanged(this, EventArgs.Empty);
            }
        }

        public void ResizeCanvas(int protocolWidth, int protocolLength)
        {
            CommitTextEditor();
            CommitFloatingSelection();
            if (protocolWidth <= 0 || protocolLength <= 0) throw new ArgumentOutOfRangeException("protocolWidth", "画布尺寸必须大于 0");
            if (_image.Height == protocolWidth && _image.Width == protocolLength) return;
            Bitmap resized = CreateBlankBitmap(protocolLength, protocolWidth, Color.White);
            using (Graphics graphics = Graphics.FromImage(resized))
            {
                graphics.InterpolationMode = InterpolationMode.NearestNeighbor;
                graphics.PixelOffsetMode = PixelOffsetMode.Half;
                graphics.DrawImage(_image, new Rectangle(0, 0, protocolLength, protocolWidth), new Rectangle(0, 0, _image.Width, _image.Height), GraphicsUnit.Pixel);
            }
            _image.Dispose();
            _image = resized;
            _selection = Rectangle.Empty;
            _selectionIsText = false;
            ClearHistory();
            Zoom = _zoom;
            UpdateCanvasSize();
            Invalidate();
        }

        public void ImportImage(string path)
        {
            CommitTextEditor();
            CommitFloatingSelection();
            using (Image source = Image.FromFile(path))
            {
                PushUndo();
                using (Graphics graphics = Graphics.FromImage(_image))
                {
                    graphics.Clear(Color.White);
                    graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
                    graphics.PixelOffsetMode = PixelOffsetMode.HighQuality;
                    graphics.DrawImage(source, new Rectangle(0, 0, _image.Width, _image.Height));
                }
            }
            _selection = Rectangle.Empty;
            _selectionIsText = false;
            Invalidate();
        }

        public void Clear(Color color)
        {
            CommitTextEditor();
            CommitFloatingSelection();
            PushUndo();
            using (Graphics graphics = Graphics.FromImage(_image)) graphics.Clear(color);
            _selection = Rectangle.Empty;
            _selectionIsText = false;
            Invalidate();
        }

        public void Undo()
        {
            if (_isEditingText)
            {
                UndoInlineText();
                return;
            }
            CommitTextEditor();
            CommitFloatingSelection();
            if (_undo.Count == 0) return;
            _redo.Add(CloneBitmap(_image));
            int index = _undo.Count - 1;
            Bitmap previous = _undo[index];
            _undo.RemoveAt(index);
            _image.Dispose();
            _image = previous;
            _selection = Rectangle.Empty;
            _selectionIsText = false;
            Invalidate();
        }

        public void Redo()
        {
            if (_isEditingText)
            {
                RedoInlineText();
                return;
            }
            CommitTextEditor();
            CommitFloatingSelection();
            if (_redo.Count == 0) return;
            _undo.Add(CloneBitmap(_image));
            int index = _redo.Count - 1;
            Bitmap next = _redo[index];
            _redo.RemoveAt(index);
            _image.Dispose();
            _image = next;
            _selection = Rectangle.Empty;
            _selectionIsText = false;
            Invalidate();
        }

        public void SelectAllPixels()
        {
            CommitTextEditor();
            CommitFloatingSelection();
            _selection = new Rectangle(0, 0, _image.Width, _image.Height);
            _selectionIsText = false;
            Invalidate();
        }

        public void CopySelection()
        {
            CommitTextEditor();
            CommitFloatingSelection();
            Rectangle source = _selection.IsEmpty ? new Rectangle(0, 0, _image.Width, _image.Height) : _selection;
            try
            {
                using (Bitmap copy = ExtractBitmap(source)) Clipboard.SetDataObject(copy, true);
            }
            catch (ExternalException ex)
            {
                MessageBox.Show(FindForm(), ex.Message, "无法复制图像", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        public void CutSelection()
        {
            if (_selection.IsEmpty) return;
            CopySelection();
            DeleteSelection();
        }

        public void PasteClipboard()
        {
            CommitTextEditor();
            CommitFloatingSelection();
            try
            {
                if (!Clipboard.ContainsImage()) return;
                using (Image pasted = Clipboard.GetImage())
                {
                    if (pasted == null) return;
                    int width = Math.Max(1, Math.Min(_image.Width, pasted.Width));
                    int height = Math.Max(1, Math.Min(_image.Height, pasted.Height));
                    int left = _selection.IsEmpty ? 0 : Math.Min(_image.Width - width, _selection.Left + 1);
                    int top = _selection.IsEmpty ? 0 : Math.Min(_image.Height - height, _selection.Top + 1);
                    Rectangle target = new Rectangle(Math.Max(0, left), Math.Max(0, top), width, height);
                    PushUndo();
                    using (Graphics graphics = Graphics.FromImage(_image))
                    {
                        graphics.InterpolationMode = InterpolationMode.NearestNeighbor;
                        graphics.PixelOffsetMode = PixelOffsetMode.Half;
                        graphics.DrawImage(pasted, target);
                    }
                    _selection = target;
                    _selectionIsText = false;
                }
                Invalidate();
            }
            catch (ExternalException ex)
            {
                MessageBox.Show(FindForm(), ex.Message, "无法粘贴图像", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        public void DeleteSelection()
        {
            CommitTextEditor();
            CommitFloatingSelection();
            if (_selection.IsEmpty) return;
            PushUndo();
            ClearImageRectangle(_selection);
            _selection = Rectangle.Empty;
            _selectionIsText = false;
            Invalidate();
        }

        public void DuplicateSelection()
        {
            CommitTextEditor();
            CommitFloatingSelection();
            if (_selection.IsEmpty) return;
            using (Bitmap copy = ExtractBitmap(_selection))
            {
                int left = Math.Min(_image.Width - _selection.Width, _selection.Left + 1);
                int top = Math.Min(_image.Height - _selection.Height, _selection.Top + 1);
                Rectangle target = new Rectangle(Math.Max(0, left), Math.Max(0, top), _selection.Width, _selection.Height);
                PushUndo();
                DrawBitmap(copy, target);
                _selection = target;
            }
            Invalidate();
        }

        public void ScaleSelection(float factor)
        {
            CommitTextEditor();
            CommitFloatingSelection();
            if (_selection.IsEmpty || factor <= 0F) return;
            int width = Math.Max(1, Math.Min(_image.Width - _selection.Left, (int)Math.Round(_selection.Width * factor)));
            int height = Math.Max(1, Math.Min(_image.Height - _selection.Top, (int)Math.Round(_selection.Height * factor)));
            Rectangle target = new Rectangle(_selection.Left, _selection.Top, width, height);
            if (target == _selection) return;
            using (Bitmap source = ExtractBitmap(_selection))
            {
                PushUndo();
                ClearImageRectangle(_selection);
                DrawBitmap(source, target);
            }
            _selection = target;
            Invalidate();
        }

        public void MoveSelection(int dx, int dy)
        {
            CommitTextEditor();
            CommitFloatingSelection();
            if (_selection.IsEmpty) return;
            int left = Math.Max(0, Math.Min(_image.Width - _selection.Width, _selection.Left + dx));
            int top = Math.Max(0, Math.Min(_image.Height - _selection.Height, _selection.Top + dy));
            if (left == _selection.Left && top == _selection.Top) return;
            using (Bitmap source = ExtractBitmap(_selection))
            {
                PushUndo();
                ClearImageRectangle(_selection);
                _selection = new Rectangle(left, top, _selection.Width, _selection.Height);
                DrawBitmap(source, _selection);
            }
            Invalidate();
        }

        public uint[] GetArgbPixels()
        {
            CommitTextEditor();
            CommitFloatingSelection();
            uint[] pixels = new uint[_image.Width * _image.Height];
            int index = 0;
            for (int y = 0; y < _image.Height; y++)
            {
                for (int x = 0; x < _image.Width; x++) pixels[index++] = unchecked((uint)_image.GetPixel(x, y).ToArgb());
            }
            return pixels;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            _imageBounds = new Rectangle(CanvasMargin, CanvasMargin, _image.Width * _zoom, _image.Height * _zoom);
            using (HatchBrush checker = new HatchBrush(HatchStyle.LargeCheckerBoard, Color.FromArgb(238, 242, 247), Color.White)) e.Graphics.FillRectangle(checker, _imageBounds);
            e.Graphics.InterpolationMode = InterpolationMode.NearestNeighbor;
            e.Graphics.PixelOffsetMode = PixelOffsetMode.Half;
            e.Graphics.DrawImage(_image, _imageBounds, new Rectangle(0, 0, _image.Width, _image.Height), GraphicsUnit.Pixel);
            using (Pen border = new Pen(Color.FromArgb(110, 124, 145))) e.Graphics.DrawRectangle(border, _imageBounds);
            if (_zoom >= 6) DrawPixelGrid(e.Graphics);
            if (_drawing && IsPreviewTool(Tool)) DrawPreview(e.Graphics, _currentPoint);
            if (_floatingSelection != null && !_selection.IsEmpty) DrawFloatingSelection(e.Graphics);
            if (!_selection.IsEmpty) DrawSelectionFrame(e.Graphics);
            if (_isEditingText) DrawInlineTextEditor(e.Graphics);
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            if (e.Button != MouseButtons.Left) return;
            Focus();
            Point point;
            if (Tool == QrPaintTool.Select)
            {
                SelectionHandle handle = HitTestSelectionHandle(e.Location);
                if (!TryMapPoint(e.Location, out point) && handle == SelectionHandle.None) return;
                if (handle != SelectionHandle.None) point = MapPointClamped(e.Location);
                BeginSelection(point, handle);
                return;
            }
            if (Tool == QrPaintTool.Text)
            {
                if (_isEditingText && HitTestInlineText(e.Location))
                {
                    BeginInlineTextSelection(e.Location, (ModifierKeys & Keys.Shift) == Keys.Shift);
                    return;
                }
                if (!TryMapPoint(e.Location, out point)) return;
                BeginTextEditor(point);
                return;
            }
            if (!TryMapPoint(e.Location, out point)) return;
            PushUndo();
            _startPoint = point;
            _lastPoint = point;
            _currentPoint = point;
            _drawing = true;
            Capture = true;
            if (Tool == QrPaintTool.Fill)
            {
                FloodFill(point, PrimaryColor);
                _drawing = false;
                Capture = false;
                Invalidate();
            }
            else if (Tool == QrPaintTool.Brush || Tool == QrPaintTool.Eraser)
            {
                DrawStroke(point, point, Tool == QrPaintTool.Eraser ? Color.White : PrimaryColor);
                Invalidate();
            }
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            if (_selectingText)
            {
                UpdateInlineTextSelection(e.Location);
                return;
            }
            if (!_drawing)
            {
                UpdatePointerCursor(e.Location);
                return;
            }
            Point point;
            if (Tool == QrPaintTool.Select)
            {
                point = MapPointClamped(e.Location);
                UpdateSelection(point);
            }
            else
            {
                if (!TryMapPoint(e.Location, out point)) return;
                if (Tool == QrPaintTool.Brush || Tool == QrPaintTool.Eraser)
                {
                    DrawStroke(_lastPoint, point, Tool == QrPaintTool.Eraser ? Color.White : PrimaryColor);
                    _lastPoint = point;
                }
                else if (IsPreviewTool(Tool)) _currentPoint = ApplyShiftConstraint(_startPoint, point, Tool);
            }
            Invalidate();
        }

        protected override void OnMouseUp(MouseEventArgs e)
        {
            base.OnMouseUp(e);
            if (_selectingText && e.Button == MouseButtons.Left)
            {
                _selectingText = false;
                Capture = false;
                ResetCaretBlink();
                return;
            }
            if (!_drawing || e.Button != MouseButtons.Left) return;
            Point point;
            if (Tool == QrPaintTool.Select)
            {
                point = MapPointClamped(e.Location);
                UpdateSelection(point);
                FinishSelectionInteraction();
                UpdatePointerCursor(e.Location);
                return;
            }
            if (!TryMapPoint(e.Location, out point)) point = _currentPoint;
            point = ApplyShiftConstraint(_startPoint, point, Tool);
            if (Tool == QrPaintTool.Line) DrawStroke(_startPoint, point, PrimaryColor);
            else if (Tool == QrPaintTool.Rectangle) DrawShape(_startPoint, point, false);
            else if (Tool == QrPaintTool.Ellipse) DrawShape(_startPoint, point, true);
            _drawing = false;
            Capture = false;
            Invalidate();
        }

        protected override void OnMouseCaptureChanged(EventArgs e)
        {
            base.OnMouseCaptureChanged(e);
            if (!Capture && _selectingText) _selectingText = false;
            if (!Capture && _drawing && MouseButtons == MouseButtons.None)
            {
                if (Tool == QrPaintTool.Select) FinishSelectionInteraction();
                else
                {
                    _drawing = false;
                    Invalidate();
                }
            }
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            if (!_drawing) Cursor = Tool == QrPaintTool.Text ? Cursors.IBeam : Cursors.Cross;
        }

        protected override void OnMouseWheel(MouseEventArgs e)
        {
            if ((ModifierKeys & Keys.Control) == Keys.Control)
            {
                Zoom += e.Delta > 0 ? 1 : -1;
                return;
            }
            base.OnMouseWheel(e);
        }

        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            Keys key = keyData & Keys.KeyCode;
            bool control = (keyData & Keys.Control) == Keys.Control;
            bool shift = (keyData & Keys.Shift) == Keys.Shift;
            if (_isEditingText && ProcessInlineTextKey(key, control, shift)) return true;
            if (control && shift && key == Keys.Z) { Redo(); return true; }
            if (control && key == Keys.Z) { Undo(); return true; }
            if (control && key == Keys.Y) { Redo(); return true; }
            if (control && key == Keys.C) { CopySelection(); return true; }
            if (control && key == Keys.X) { CutSelection(); return true; }
            if (control && key == Keys.V) { PasteClipboard(); return true; }
            if (control && key == Keys.A) { SelectAllPixels(); return true; }
            if (control && key == Keys.D) { DuplicateSelection(); return true; }
            if (control && (key == Keys.Add || key == Keys.Oemplus))
            {
                if (_selection.IsEmpty) Zoom++;
                else ScaleSelection(1.25F);
                return true;
            }
            if (control && (key == Keys.Subtract || key == Keys.OemMinus))
            {
                if (_selection.IsEmpty) Zoom--;
                else ScaleSelection(0.8F);
                return true;
            }
            if (control && key == Keys.D0) { Zoom = 3; return true; }
            if (control && key == Keys.Insert) { CopySelection(); return true; }
            if (shift && key == Keys.Insert) { PasteClipboard(); return true; }
            if (shift && key == Keys.Delete) { CutSelection(); return true; }
            if (key == Keys.Delete) { DeleteSelection(); return true; }
            if (key == Keys.Escape)
            {
                if (_isEditingText) CancelTextEditor();
                else { CommitFloatingSelection(); _selection = Rectangle.Empty; _selectionIsText = false; Invalidate(); }
                return true;
            }
            int step = shift ? 10 : 1;
            if (key == Keys.Left) { MoveSelection(-step, 0); return true; }
            if (key == Keys.Right) { MoveSelection(step, 0); return true; }
            if (key == Keys.Up) { MoveSelection(0, -step); return true; }
            if (key == Keys.Down) { MoveSelection(0, step); return true; }
            return base.ProcessCmdKey(ref msg, keyData);
        }

        protected override void OnKeyPress(KeyPressEventArgs e)
        {
            if (_isEditingText && !char.IsControl(e.KeyChar))
            {
                InsertInlineText(e.KeyChar.ToString());
                e.Handled = true;
                return;
            }
            base.OnKeyPress(e);
        }

        private void DrawStroke(Point start, Point end, Color color)
        {
            using (Graphics graphics = Graphics.FromImage(_image))
            using (Pen pen = new Pen(color, Math.Max(1, BrushSize)))
            {
                graphics.SmoothingMode = SmoothingMode.None;
                pen.StartCap = LineCap.Round;
                pen.EndCap = LineCap.Round;
                graphics.DrawLine(pen, start, end);
            }
        }

        private void DrawShape(Point start, Point end, bool ellipse)
        {
            int left = Math.Min(start.X, end.X);
            int top = Math.Min(start.Y, end.Y);
            int width = Math.Max(1, Math.Abs(end.X - start.X));
            int height = Math.Max(1, Math.Abs(end.Y - start.Y));
            using (Graphics graphics = Graphics.FromImage(_image))
            using (Pen pen = new Pen(PrimaryColor, Math.Max(1, BrushSize)))
            {
                graphics.SmoothingMode = SmoothingMode.None;
                if (ellipse) graphics.DrawEllipse(pen, left, top, width, height);
                else graphics.DrawRectangle(pen, left, top, width, height);
            }
        }

        private void DrawText(Point point)
        {
            using (Graphics graphics = Graphics.FromImage(_image))
            using (Font font = CreateNaturalTextFont(Math.Max(4, TextSize)))
            {
                DrawNaturalTextLines(graphics, TextValue, font, point, PrimaryColor);
            }
        }

        private Rectangle MeasureTextBounds(Point point, string text)
        {
            using (Graphics graphics = Graphics.FromImage(_image))
            using (Font font = CreateNaturalTextFont(Math.Max(4, TextSize)))
            {
                string[] lines = text.Split(new[] { '\n' }, StringSplitOptions.None);
                int width = 0;
                foreach (string line in lines) width = Math.Max(width, MeasureNaturalTextWidth(graphics, font, line));
                int height = Math.Max(1, lines.Length * GetNaturalTextLineHeight(graphics, font));
                Rectangle bounds = new Rectangle(point.X, point.Y, Math.Max(1, width), height);
                return Rectangle.Intersect(new Rectangle(0, 0, _image.Width, _image.Height), bounds);
            }
        }

        private static Font CreateNaturalTextFont(int pixelSize)
        {
            return new Font(SystemFonts.MessageBoxFont.FontFamily, Math.Max(1, pixelSize), FontStyle.Regular, GraphicsUnit.Pixel);
        }

        private static int MeasureNaturalTextWidth(IDeviceContext context, Font font, string text)
        {
            if (string.IsNullOrEmpty(text)) return 0;
            return TextRenderer.MeasureText(context, text, font, new Size(32767, 32767), NaturalTextFlags).Width;
        }

        private static int GetNaturalTextLineHeight(IDeviceContext context, Font font)
        {
            return Math.Max(1, TextRenderer.MeasureText(context, "Ag", font, new Size(32767, 32767), NaturalTextFlags).Height);
        }

        private static void DrawNaturalTextLines(Graphics graphics, string text, Font font, Point origin, Color color)
        {
            string[] lines = (text ?? string.Empty).Split(new[] { '\n' }, StringSplitOptions.None);
            int lineHeight = GetNaturalTextLineHeight(graphics, font);
            for (int i = 0; i < lines.Length; i++)
            {
                if (lines[i].Length == 0) continue;
                TextRenderer.DrawText(graphics, lines[i], font, new Point(origin.X, origin.Y + (i * lineHeight)), color, NaturalTextFlags);
            }
        }

        private void BeginTextEditor(Point point)
        {
            CommitTextEditor();
            CommitFloatingSelection();
            _selection = Rectangle.Empty;
            _selectionIsText = false;
            _textOrigin = point;
            _textValue = string.Empty;
            _editingTextValue = string.Empty;
            _textCaretIndex = 0;
            _textSelectionAnchor = 0;
            _textUndo.Clear();
            _textRedo.Clear();
            _isEditingText = true;
            _caretTimer.Start();
            ResetCaretBlink();
            Focus();
            Invalidate();
        }

        private void CommitTextEditor()
        {
            if (!_isEditingText) return;
            string text = _editingTextValue;
            _textValue = text;
            StopInlineTextEditor();
            if (!string.IsNullOrEmpty(text))
            {
                PushUndo();
                DrawText(_textOrigin);
                _selection = MeasureTextBounds(_textOrigin, text);
                _selectionIsText = !_selection.IsEmpty;
                _selectionTextSize = TextSize;
            }
            else
            {
                _selection = Rectangle.Empty;
                _selectionIsText = false;
            }
            Invalidate();
            if (TextValueChanged != null) TextValueChanged(this, EventArgs.Empty);
        }

        private void CancelTextEditor()
        {
            if (!_isEditingText) return;
            StopInlineTextEditor();
            _editingTextValue = string.Empty;
            Invalidate();
        }

        private void StopInlineTextEditor()
        {
            _isEditingText = false;
            _selectingText = false;
            _caretVisible = false;
            _caretTimer.Stop();
            _textUndo.Clear();
            _textRedo.Clear();
            if (Capture) Capture = false;
        }

        private void ResetCaretBlink()
        {
            _caretVisible = true;
            _caretTimer.Stop();
            if (_isEditingText) _caretTimer.Start();
            Invalidate();
        }

        private InlineTextHistoryState CaptureInlineTextState()
        {
            return new InlineTextHistoryState(_editingTextValue, _textCaretIndex, _textSelectionAnchor);
        }

        private void RestoreInlineTextState(InlineTextHistoryState state)
        {
            _editingTextValue = state.Text ?? string.Empty;
            _textCaretIndex = Math.Max(0, Math.Min(_editingTextValue.Length, state.Caret));
            _textSelectionAnchor = Math.Max(0, Math.Min(_editingTextValue.Length, state.Anchor));
            ResetCaretBlink();
        }

        private void PushInlineTextUndo()
        {
            _textUndo.Add(CaptureInlineTextState());
            _textRedo.Clear();
        }

        private void UndoInlineText()
        {
            if (_textUndo.Count == 0) return;
            _textRedo.Add(CaptureInlineTextState());
            int index = _textUndo.Count - 1;
            InlineTextHistoryState state = _textUndo[index];
            _textUndo.RemoveAt(index);
            RestoreInlineTextState(state);
        }

        private void RedoInlineText()
        {
            if (_textRedo.Count == 0) return;
            _textUndo.Add(CaptureInlineTextState());
            int index = _textRedo.Count - 1;
            InlineTextHistoryState state = _textRedo[index];
            _textRedo.RemoveAt(index);
            RestoreInlineTextState(state);
        }

        private bool ProcessInlineTextKey(Keys key, bool control, bool shift)
        {
            if (control && key == Keys.Enter)
            {
                CommitTextEditor();
                Focus();
                return true;
            }
            if (key == Keys.Escape)
            {
                CancelTextEditor();
                return true;
            }
            if (control && key == Keys.A)
            {
                _textSelectionAnchor = 0;
                _textCaretIndex = _editingTextValue.Length;
                ResetCaretBlink();
                return true;
            }
            if ((control && key == Keys.C) || (control && key == Keys.Insert))
            {
                CopyInlineTextSelection();
                return true;
            }
            if ((control && key == Keys.X) || (shift && key == Keys.Delete))
            {
                if (InlineTextSelectionLength > 0)
                {
                    CopyInlineTextSelection();
                    PushInlineTextUndo();
                    DeleteInlineTextSelection();
                }
                return true;
            }
            if ((control && key == Keys.V) || (shift && key == Keys.Insert))
            {
                PasteInlineText();
                return true;
            }
            if (control && key == Keys.Z)
            {
                if (shift) RedoInlineText();
                else UndoInlineText();
                return true;
            }
            if (control && key == Keys.Y)
            {
                RedoInlineText();
                return true;
            }
            if (key == Keys.Back)
            {
                if (InlineTextSelectionLength > 0 || _textCaretIndex > 0)
                {
                    PushInlineTextUndo();
                    if (!DeleteInlineTextSelection())
                    {
                        _editingTextValue = _editingTextValue.Remove(_textCaretIndex - 1, 1);
                        MoveInlineTextCaret(_textCaretIndex - 1, false);
                    }
                }
                ResetCaretBlink();
                return true;
            }
            if (key == Keys.Delete)
            {
                if (InlineTextSelectionLength > 0 || _textCaretIndex < _editingTextValue.Length)
                {
                    PushInlineTextUndo();
                    if (!DeleteInlineTextSelection()) _editingTextValue = _editingTextValue.Remove(_textCaretIndex, 1);
                }
                ResetCaretBlink();
                return true;
            }
            if (key == Keys.Left)
            {
                int target = !shift && InlineTextSelectionLength > 0 ? InlineTextSelectionStart : Math.Max(0, _textCaretIndex - 1);
                MoveInlineTextCaret(target, shift);
                return true;
            }
            if (key == Keys.Right)
            {
                int target = !shift && InlineTextSelectionLength > 0 ? InlineTextSelectionStart + InlineTextSelectionLength : Math.Min(_editingTextValue.Length, _textCaretIndex + 1);
                MoveInlineTextCaret(target, shift);
                return true;
            }
            if (key == Keys.Home)
            {
                MoveInlineTextCaret(GetInlineLineStart(_textCaretIndex), shift);
                return true;
            }
            if (key == Keys.End)
            {
                MoveInlineTextCaret(GetInlineLineEnd(GetInlineLineStart(_textCaretIndex)), shift);
                return true;
            }
            if (key == Keys.Up)
            {
                MoveInlineTextCaret(GetVerticalInlineCaretIndex(-1), shift);
                return true;
            }
            if (key == Keys.Down)
            {
                MoveInlineTextCaret(GetVerticalInlineCaretIndex(1), shift);
                return true;
            }
            if (key == Keys.Enter)
            {
                InsertInlineText("\n");
                return true;
            }
            if (key == Keys.Tab)
            {
                InsertInlineText("\t");
                return true;
            }
            return false;
        }

        private int InlineTextSelectionStart
        {
            get { return Math.Min(_textSelectionAnchor, _textCaretIndex); }
        }

        private int InlineTextSelectionLength
        {
            get { return Math.Abs(_textSelectionAnchor - _textCaretIndex); }
        }

        private void MoveInlineTextCaret(int index, bool extendSelection)
        {
            int next = Math.Max(0, Math.Min(_editingTextValue.Length, index));
            if (!extendSelection) _textSelectionAnchor = next;
            _textCaretIndex = next;
            ResetCaretBlink();
        }

        private void InsertInlineText(string value)
        {
            if (string.IsNullOrEmpty(value)) return;
            PushInlineTextUndo();
            DeleteInlineTextSelection();
            string normalized = value.Replace("\r\n", "\n").Replace('\r', '\n');
            _editingTextValue = _editingTextValue.Insert(_textCaretIndex, normalized);
            _textCaretIndex += normalized.Length;
            _textSelectionAnchor = _textCaretIndex;
            ResetCaretBlink();
        }

        private bool DeleteInlineTextSelection()
        {
            int length = InlineTextSelectionLength;
            if (length <= 0) return false;
            int start = InlineTextSelectionStart;
            _editingTextValue = _editingTextValue.Remove(start, length);
            _textCaretIndex = start;
            _textSelectionAnchor = start;
            ResetCaretBlink();
            return true;
        }

        private void CopyInlineTextSelection()
        {
            if (InlineTextSelectionLength <= 0) return;
            try { Clipboard.SetText(_editingTextValue.Substring(InlineTextSelectionStart, InlineTextSelectionLength)); }
            catch (ExternalException) { }
        }

        private void PasteInlineText()
        {
            try
            {
                if (Clipboard.ContainsText()) InsertInlineText(Clipboard.GetText());
            }
            catch (ExternalException) { }
        }

        private int GetInlineLineStart(int index)
        {
            int safe = Math.Max(0, Math.Min(_editingTextValue.Length, index));
            int newline = safe > 0 ? _editingTextValue.LastIndexOf('\n', safe - 1) : -1;
            return newline + 1;
        }

        private int GetInlineLineEnd(int lineStart)
        {
            int newline = _editingTextValue.IndexOf('\n', Math.Max(0, lineStart));
            return newline < 0 ? _editingTextValue.Length : newline;
        }

        private int GetVerticalInlineCaretIndex(int direction)
        {
            int currentStart = GetInlineLineStart(_textCaretIndex);
            int column = _textCaretIndex - currentStart;
            if (direction < 0)
            {
                if (currentStart == 0) return _textCaretIndex;
                int previousEnd = currentStart - 1;
                int previousStart = GetInlineLineStart(previousEnd);
                return Math.Min(previousStart + column, previousEnd);
            }
            int currentEnd = GetInlineLineEnd(currentStart);
            if (currentEnd >= _editingTextValue.Length) return _textCaretIndex;
            int nextStart = currentEnd + 1;
            return Math.Min(nextStart + column, GetInlineLineEnd(nextStart));
        }

        private void BeginInlineTextSelection(Point location, bool extendSelection)
        {
            int index = HitTestInlineTextIndex(location);
            if (!extendSelection) _textSelectionAnchor = index;
            _textCaretIndex = index;
            _selectingText = true;
            Capture = true;
            ResetCaretBlink();
        }

        private void UpdateInlineTextSelection(Point location)
        {
            _textCaretIndex = HitTestInlineTextIndex(location);
            ResetCaretBlink();
        }

        private bool HitTestInlineText(Point location)
        {
            if (!_isEditingText) return false;
            using (Graphics graphics = CreateGraphics())
            using (Font font = CreateInlineTextFont())
                return GetInlineTextBounds(graphics, font).Contains(location);
        }

        private int HitTestInlineTextIndex(Point location)
        {
            using (Graphics graphics = CreateGraphics())
            using (Font font = CreateInlineTextFont())
            {
                PointF origin = GetInlineTextOrigin();
                float lineHeight = GetNaturalTextLineHeight(graphics, font);
                string[] lines = _editingTextValue.Split(new[] { '\n' }, StringSplitOptions.None);
                int line = Math.Max(0, Math.Min(lines.Length - 1, (int)Math.Floor((location.Y - origin.Y) / lineHeight)));
                int lineStart = 0;
                for (int i = 0; i < line; i++) lineStart += lines[i].Length + 1;
                string lineText = lines[line];
                float relativeX = location.X - origin.X;
                if (relativeX <= 0F) return lineStart;
                float previous = 0F;
                for (int i = 0; i < lineText.Length; i++)
                {
                    float next = MeasureInlineTextWidth(graphics, font, lineText.Substring(0, i + 1));
                    if (relativeX < (previous + next) / 2F) return lineStart + i;
                    previous = next;
                }
                return lineStart + lineText.Length;
            }
        }

        private void DrawInlineTextEditor(Graphics graphics)
        {
            GraphicsState state = graphics.Save();
            try
            {
                graphics.SetClip(_imageBounds);
                graphics.SmoothingMode = SmoothingMode.AntiAlias;
                graphics.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAliasGridFit;
                using (Font font = CreateInlineTextFont())
                {
                    PointF origin = GetInlineTextOrigin();
                    DrawInlineTextSelection(graphics, font, origin);
                    if (_editingTextValue.Length > 0)
                        DrawNaturalTextLines(graphics, _editingTextValue, font, Point.Round(origin), PrimaryColor);
                    if (_caretVisible && ContainsFocus)
                    {
                        PointF caret = GetInlineCaretPoint(graphics, font, origin, _textCaretIndex);
                        int brightness = ((PrimaryColor.R * 299) + (PrimaryColor.G * 587) + (PrimaryColor.B * 114)) / 1000;
                        Color caretColor = brightness > 220 ? Color.Black : PrimaryColor;
                        using (Pen pen = new Pen(caretColor, 1.4F))
                            graphics.DrawLine(pen, caret.X, caret.Y, caret.X, caret.Y + GetNaturalTextLineHeight(graphics, font));
                    }
                }
            }
            finally { graphics.Restore(state); }
        }

        private void DrawInlineTextSelection(Graphics graphics, Font font, PointF origin)
        {
            int selectionLength = InlineTextSelectionLength;
            if (selectionLength <= 0) return;
            int selectionStart = InlineTextSelectionStart;
            int selectionEnd = selectionStart + selectionLength;
            float lineHeight = GetNaturalTextLineHeight(graphics, font);
            int lineStart = 0;
            int lineNumber = 0;
            using (Brush highlight = new SolidBrush(Color.FromArgb(120, SystemColors.Highlight)))
            {
                while (lineStart <= _editingTextValue.Length)
                {
                    int newline = _editingTextValue.IndexOf('\n', lineStart);
                    int lineEnd = newline < 0 ? _editingTextValue.Length : newline;
                    int partStart = Math.Max(selectionStart, lineStart);
                    int partEnd = Math.Min(selectionEnd, lineEnd);
                    if (partStart < partEnd)
                    {
                        string prefix = _editingTextValue.Substring(lineStart, partStart - lineStart);
                        string selected = _editingTextValue.Substring(partStart, partEnd - partStart);
                        float x = origin.X + MeasureInlineTextWidth(graphics, font, prefix);
                        float width = Math.Max(2F, MeasureInlineTextWidth(graphics, font, selected));
                        graphics.FillRectangle(highlight, x, origin.Y + (lineNumber * lineHeight), width, lineHeight);
                    }
                    if (newline >= 0 && selectionStart <= newline && selectionEnd > newline)
                    {
                        string lineText = _editingTextValue.Substring(lineStart, lineEnd - lineStart);
                        float x = origin.X + MeasureInlineTextWidth(graphics, font, lineText);
                        graphics.FillRectangle(highlight, x, origin.Y + (lineNumber * lineHeight), 4F, lineHeight);
                    }
                    if (newline < 0) break;
                    lineStart = newline + 1;
                    lineNumber++;
                }
            }
        }

        private Font CreateInlineTextFont()
        {
            return CreateNaturalTextFont(Math.Max(8, TextSize * _zoom));
        }

        private PointF GetInlineTextOrigin()
        {
            return new PointF(_imageBounds.Left + (_textOrigin.X * _zoom), _imageBounds.Top + (_textOrigin.Y * _zoom));
        }

        private RectangleF GetInlineTextBounds(Graphics graphics, Font font)
        {
            string[] lines = _editingTextValue.Split(new[] { '\n' }, StringSplitOptions.None);
            float width = 0F;
            foreach (string line in lines) width = Math.Max(width, MeasureInlineTextWidth(graphics, font, line));
            PointF origin = GetInlineTextOrigin();
            float height = Math.Max(1F, lines.Length * GetNaturalTextLineHeight(graphics, font));
            return new RectangleF(origin.X - 4F, origin.Y - 3F, Math.Max(12F, width + 8F), height + 6F);
        }

        private PointF GetInlineCaretPoint(Graphics graphics, Font font, PointF origin, int index)
        {
            int safe = Math.Max(0, Math.Min(_editingTextValue.Length, index));
            int lineStart = GetInlineLineStart(safe);
            int lineNumber = 0;
            for (int i = 0; i < lineStart; i++) if (_editingTextValue[i] == '\n') lineNumber++;
            string prefix = _editingTextValue.Substring(lineStart, safe - lineStart);
            return new PointF(origin.X + MeasureInlineTextWidth(graphics, font, prefix), origin.Y + (lineNumber * GetNaturalTextLineHeight(graphics, font)));
        }

        private static float MeasureInlineTextWidth(Graphics graphics, Font font, string text)
        {
            if (string.IsNullOrEmpty(text)) return 0F;
            return MeasureNaturalTextWidth(graphics, font, text);
        }

        private void BeginSelection(Point point, SelectionHandle handle)
        {
            CommitTextEditor();
            CommitFloatingSelection();
            _startPoint = point;
            _currentPoint = point;
            _lastPoint = point;
            _drawing = true;
            Capture = true;
            if (!_selection.IsEmpty && handle != SelectionHandle.None)
            {
                PushUndo();
                _floatingSelection = ExtractBitmap(_selection);
                _floatingSourceSelection = _selection;
                _resizeStartSelection = _selection;
                _activeSelectionHandle = handle;
                _resizingSelection = true;
                return;
            }
            if (!_selection.IsEmpty && _selection.Contains(point))
            {
                PushUndo();
                _floatingSelection = ExtractBitmap(_selection);
                _floatingSourceSelection = _selection;
                _selectionOffset = new Point(point.X - _selection.Left, point.Y - _selection.Top);
                _movingSelection = true;
                return;
            }
            _selection = new Rectangle(point.X, point.Y, 1, 1);
            _selectionIsText = false;
            _floatingSourceSelection = Rectangle.Empty;
            _selecting = true;
            Invalidate();
        }

        private void UpdateSelection(Point point)
        {
            _currentPoint = point;
            if (_selecting)
            {
                _selection = NormalizeSelectionRectangle(_startPoint, point);
            }
            else if (_movingSelection)
            {
                int left = Math.Max(0, Math.Min(_image.Width - _selection.Width, point.X - _selectionOffset.X));
                int top = Math.Max(0, Math.Min(_image.Height - _selection.Height, point.Y - _selectionOffset.Y));
                _selection = new Rectangle(left, top, _selection.Width, _selection.Height);
            }
            else if (_resizingSelection)
            {
                _selection = ResizeSelection(point);
            }
            Invalidate();
        }

        private void FinishSelectionInteraction()
        {
            if (!_drawing) return;
            if (_movingSelection || _resizingSelection) CommitFloatingSelection();
            _drawing = false;
            _selecting = false;
            _movingSelection = false;
            _resizingSelection = false;
            _activeSelectionHandle = SelectionHandle.None;
            Capture = false;
            Invalidate();
        }

        private void CommitFloatingSelection()
        {
            if (_floatingSelection == null) return;
            if (!_floatingSourceSelection.IsEmpty) ClearImageRectangle(_floatingSourceSelection);
            DrawBitmap(_floatingSelection, _selection);
            _floatingSelection.Dispose();
            _floatingSelection = null;
            _floatingSourceSelection = Rectangle.Empty;
            _movingSelection = false;
            _resizingSelection = false;
            _activeSelectionHandle = SelectionHandle.None;
            Invalidate();
        }

        private void DrawFloatingSelection(Graphics graphics)
        {
            Rectangle display = SelectionToDisplay(_selection);
            if (!_floatingSourceSelection.IsEmpty)
            {
                Rectangle sourceDisplay = SelectionToDisplay(_floatingSourceSelection);
                using (Brush background = new SolidBrush(Color.White)) graphics.FillRectangle(background, sourceDisplay);
            }
            InterpolationMode previous = graphics.InterpolationMode;
            PixelOffsetMode previousOffset = graphics.PixelOffsetMode;
            graphics.InterpolationMode = InterpolationMode.NearestNeighbor;
            graphics.PixelOffsetMode = PixelOffsetMode.Half;
            graphics.DrawImage(_floatingSelection, display);
            graphics.InterpolationMode = previous;
            graphics.PixelOffsetMode = previousOffset;
        }

        private void DrawSelectionFrame(Graphics graphics)
        {
            Rectangle display = SelectionToDisplay(_selection);
            using (Pen pen = new Pen(Color.FromArgb(37, 99, 235), 1F))
            {
                pen.DashStyle = DashStyle.Dash;
                graphics.DrawRectangle(pen, display);
            }
            int handle = 7;
            Point[] grips = GetSelectionHandlePoints(display);
            using (Brush white = new SolidBrush(Color.White))
            using (Pen blue = new Pen(Ui.Accent))
            {
                foreach (Point point in grips)
                {
                    Rectangle grip = new Rectangle(point.X - (handle / 2), point.Y - (handle / 2), handle, handle);
                    graphics.FillRectangle(white, grip);
                    graphics.DrawRectangle(blue, grip);
                }
            }
        }

        private static Point[] GetSelectionHandlePoints(Rectangle display)
        {
            int middleX = display.Left + (display.Width / 2);
            int middleY = display.Top + (display.Height / 2);
            return new[]
            {
                new Point(display.Left, display.Top),
                new Point(middleX, display.Top),
                new Point(display.Right, display.Top),
                new Point(display.Right, middleY),
                new Point(display.Right, display.Bottom),
                new Point(middleX, display.Bottom),
                new Point(display.Left, display.Bottom),
                new Point(display.Left, middleY)
            };
        }

        private SelectionHandle HitTestSelectionHandle(Point location)
        {
            if (_selection.IsEmpty) return SelectionHandle.None;
            Rectangle display = SelectionToDisplay(_selection);
            int tolerance = 5;
            bool nearLeft = Math.Abs(location.X - display.Left) <= tolerance;
            bool nearRight = Math.Abs(location.X - display.Right) <= tolerance;
            bool nearTop = Math.Abs(location.Y - display.Top) <= tolerance;
            bool nearBottom = Math.Abs(location.Y - display.Bottom) <= tolerance;
            bool insideX = location.X >= display.Left - tolerance && location.X <= display.Right + tolerance;
            bool insideY = location.Y >= display.Top - tolerance && location.Y <= display.Bottom + tolerance;
            if (nearLeft && nearTop) return SelectionHandle.TopLeft;
            if (nearRight && nearTop) return SelectionHandle.TopRight;
            if (nearRight && nearBottom) return SelectionHandle.BottomRight;
            if (nearLeft && nearBottom) return SelectionHandle.BottomLeft;
            if (nearTop && insideX) return SelectionHandle.Top;
            if (nearRight && insideY) return SelectionHandle.Right;
            if (nearBottom && insideX) return SelectionHandle.Bottom;
            if (nearLeft && insideY) return SelectionHandle.Left;
            return SelectionHandle.None;
        }

        private void UpdatePointerCursor(Point location)
        {
            if (Tool == QrPaintTool.Text)
            {
                Cursor = Cursors.IBeam;
                return;
            }
            if (Tool != QrPaintTool.Select)
            {
                Cursor = Cursors.Cross;
                return;
            }
            SelectionHandle handle = HitTestSelectionHandle(location);
            switch (handle)
            {
                case SelectionHandle.TopLeft:
                case SelectionHandle.BottomRight:
                    Cursor = Cursors.SizeNWSE;
                    return;
                case SelectionHandle.TopRight:
                case SelectionHandle.BottomLeft:
                    Cursor = Cursors.SizeNESW;
                    return;
                case SelectionHandle.Top:
                case SelectionHandle.Bottom:
                    Cursor = Cursors.SizeNS;
                    return;
                case SelectionHandle.Left:
                case SelectionHandle.Right:
                    Cursor = Cursors.SizeWE;
                    return;
            }
            Cursor = !_selection.IsEmpty && SelectionToDisplay(_selection).Contains(location) ? Cursors.SizeAll : Cursors.Cross;
        }

        private Point MapPointClamped(Point location)
        {
            int x = (location.X - _imageBounds.Left) / Math.Max(1, _zoom);
            int y = (location.Y - _imageBounds.Top) / Math.Max(1, _zoom);
            return new Point(Math.Max(0, Math.Min(_image.Width - 1, x)), Math.Max(0, Math.Min(_image.Height - 1, y)));
        }

        private Rectangle ResizeSelection(Point point)
        {
            int left = _resizeStartSelection.Left;
            int top = _resizeStartSelection.Top;
            int right = _resizeStartSelection.Right;
            int bottom = _resizeStartSelection.Bottom;
            if (_activeSelectionHandle == SelectionHandle.TopLeft || _activeSelectionHandle == SelectionHandle.Left || _activeSelectionHandle == SelectionHandle.BottomLeft) left = Math.Max(0, Math.Min(right - 1, point.X));
            if (_activeSelectionHandle == SelectionHandle.TopRight || _activeSelectionHandle == SelectionHandle.Right || _activeSelectionHandle == SelectionHandle.BottomRight) right = Math.Min(_image.Width, Math.Max(left + 1, point.X + 1));
            if (_activeSelectionHandle == SelectionHandle.TopLeft || _activeSelectionHandle == SelectionHandle.Top || _activeSelectionHandle == SelectionHandle.TopRight) top = Math.Max(0, Math.Min(bottom - 1, point.Y));
            if (_activeSelectionHandle == SelectionHandle.BottomLeft || _activeSelectionHandle == SelectionHandle.Bottom || _activeSelectionHandle == SelectionHandle.BottomRight) bottom = Math.Min(_image.Height, Math.Max(top + 1, point.Y + 1));
            return Rectangle.FromLTRB(left, top, right, bottom);
        }

        private Rectangle SelectionToDisplay(Rectangle selection)
        {
            return new Rectangle(_imageBounds.Left + (selection.Left * _zoom), _imageBounds.Top + (selection.Top * _zoom), Math.Max(1, selection.Width * _zoom), Math.Max(1, selection.Height * _zoom));
        }

        private static Rectangle NormalizeSelectionRectangle(Point start, Point end)
        {
            return new Rectangle(Math.Min(start.X, end.X), Math.Min(start.Y, end.Y), Math.Abs(end.X - start.X) + 1, Math.Abs(end.Y - start.Y) + 1);
        }

        private Bitmap ExtractBitmap(Rectangle source)
        {
            Rectangle safe = Rectangle.Intersect(new Rectangle(0, 0, _image.Width, _image.Height), source);
            Bitmap result = new Bitmap(Math.Max(1, safe.Width), Math.Max(1, safe.Height));
            using (Graphics graphics = Graphics.FromImage(result)) graphics.DrawImage(_image, new Rectangle(0, 0, result.Width, result.Height), safe, GraphicsUnit.Pixel);
            return result;
        }

        private void ClearImageRectangle(Rectangle rectangle)
        {
            using (Graphics graphics = Graphics.FromImage(_image))
            using (Brush white = new SolidBrush(Color.White)) graphics.FillRectangle(white, rectangle);
        }

        private void DrawBitmap(Image source, Rectangle target)
        {
            using (Graphics graphics = Graphics.FromImage(_image))
            {
                graphics.InterpolationMode = InterpolationMode.NearestNeighbor;
                graphics.PixelOffsetMode = PixelOffsetMode.Half;
                graphics.DrawImage(source, target);
            }
        }

        private void RecolorSelection(Color color)
        {
            if (_selection.IsEmpty) return;
            PushUndo();
            Rectangle safe = Rectangle.Intersect(new Rectangle(0, 0, _image.Width, _image.Height), _selection);
            for (int y = safe.Top; y < safe.Bottom; y++)
            {
                for (int x = safe.Left; x < safe.Right; x++)
                {
                    Color pixel = _image.GetPixel(x, y);
                    int coverage = Math.Max(255 - pixel.R, Math.Max(255 - pixel.G, 255 - pixel.B));
                    if (coverage <= 0) continue;
                    int red = 255 - (((255 - color.R) * coverage) / 255);
                    int green = 255 - (((255 - color.G) * coverage) / 255);
                    int blue = 255 - (((255 - color.B) * coverage) / 255);
                    _image.SetPixel(x, y, Color.FromArgb(pixel.A, red, green, blue));
                }
            }
            Invalidate();
        }

        private void FloodFill(Point start, Color replacement)
        {
            Color target = _image.GetPixel(start.X, start.Y);
            if (target.ToArgb() == replacement.ToArgb()) return;
            bool[] visited = new bool[_image.Width * _image.Height];
            Stack<Point> pending = new Stack<Point>();
            pending.Push(start);
            while (pending.Count > 0)
            {
                Point point = pending.Pop();
                if (point.X < 0 || point.Y < 0 || point.X >= _image.Width || point.Y >= _image.Height) continue;
                int index = (point.Y * _image.Width) + point.X;
                if (visited[index]) continue;
                visited[index] = true;
                if (_image.GetPixel(point.X, point.Y).ToArgb() != target.ToArgb()) continue;
                _image.SetPixel(point.X, point.Y, replacement);
                pending.Push(new Point(point.X - 1, point.Y));
                pending.Push(new Point(point.X + 1, point.Y));
                pending.Push(new Point(point.X, point.Y - 1));
                pending.Push(new Point(point.X, point.Y + 1));
            }
        }

        private bool TryMapPoint(Point location, out Point point)
        {
            point = Point.Empty;
            if (_imageBounds.Width <= 0 || _imageBounds.Height <= 0 || !_imageBounds.Contains(location)) return false;
            int x = (location.X - _imageBounds.Left) / _zoom;
            int y = (location.Y - _imageBounds.Top) / _zoom;
            point = new Point(Math.Max(0, Math.Min(_image.Width - 1, x)), Math.Max(0, Math.Min(_image.Height - 1, y)));
            return true;
        }

        private static bool IsPreviewTool(QrPaintTool tool)
        {
            return tool == QrPaintTool.Line || tool == QrPaintTool.Rectangle || tool == QrPaintTool.Ellipse;
        }

        private Point ApplyShiftConstraint(Point start, Point current, QrPaintTool tool)
        {
            if ((ModifierKeys & Keys.Shift) != Keys.Shift || !IsPreviewTool(tool)) return current;
            int dx = current.X - start.X;
            int dy = current.Y - start.Y;
            int sx = dx < 0 ? -1 : 1;
            int sy = dy < 0 ? -1 : 1;
            int ax = Math.Abs(dx);
            int ay = Math.Abs(dy);
            if (tool == QrPaintTool.Line)
            {
                if (ax > ay * 2) return new Point(current.X, start.Y);
                if (ay > ax * 2) return new Point(start.X, current.Y);
            }
            int size = Math.Max(ax, ay);
            int availableX = sx < 0 ? start.X : (_image.Width - 1 - start.X);
            int availableY = sy < 0 ? start.Y : (_image.Height - 1 - start.Y);
            size = Math.Min(size, Math.Min(availableX, availableY));
            return new Point(start.X + (sx * size), start.Y + (sy * size));
        }

        private void DrawPreview(Graphics graphics, Point end)
        {
            graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using (Pen pen = new Pen(PrimaryColor, Math.Max(1, BrushSize * _zoom)))
            {
                pen.DashStyle = DashStyle.Dash;
                pen.StartCap = LineCap.Round;
                pen.EndCap = LineCap.Round;
                if (Tool == QrPaintTool.Line)
                {
                    graphics.DrawLine(pen, ToDisplayPoint(_startPoint), ToDisplayPoint(end));
                    return;
                }
                Rectangle pixels = NormalizeRectangle(_startPoint, end);
                Rectangle display = new Rectangle(_imageBounds.Left + (pixels.Left * _zoom), _imageBounds.Top + (pixels.Top * _zoom), Math.Max(_zoom, pixels.Width * _zoom), Math.Max(_zoom, pixels.Height * _zoom));
                if (Tool == QrPaintTool.Ellipse) graphics.DrawEllipse(pen, display);
                else graphics.DrawRectangle(pen, display);
            }
        }

        private Point ToDisplayPoint(Point point)
        {
            return new Point(_imageBounds.Left + (point.X * _zoom) + (_zoom / 2), _imageBounds.Top + (point.Y * _zoom) + (_zoom / 2));
        }

        private static Rectangle NormalizeRectangle(Point start, Point end)
        {
            return new Rectangle(Math.Min(start.X, end.X), Math.Min(start.Y, end.Y), Math.Max(1, Math.Abs(end.X - start.X)), Math.Max(1, Math.Abs(end.Y - start.Y)));
        }

        private void DrawPixelGrid(Graphics graphics)
        {
            using (Pen grid = new Pen(Color.FromArgb(48, 70, 82, 98)))
            {
                for (int x = 1; x < _image.Width; x++)
                {
                    int displayX = _imageBounds.Left + (x * _zoom);
                    graphics.DrawLine(grid, displayX, _imageBounds.Top, displayX, _imageBounds.Bottom);
                }
                for (int y = 1; y < _image.Height; y++)
                {
                    int displayY = _imageBounds.Top + (y * _zoom);
                    graphics.DrawLine(grid, _imageBounds.Left, displayY, _imageBounds.Right, displayY);
                }
            }
        }

        private void UpdateCanvasSize()
        {
            int largest = Math.Max(_image.Width, _image.Height);
            while (_zoom > 1 && ((long)largest * _zoom) > 30000L) _zoom--;
            _imageBounds = new Rectangle(CanvasMargin, CanvasMargin, _image.Width * _zoom, _image.Height * _zoom);
            Size = new Size((_image.Width * _zoom) + (CanvasMargin * 2) + 1, (_image.Height * _zoom) + (CanvasMargin * 2) + 1);
        }

        private void PushUndo()
        {
            _undo.Add(CloneBitmap(_image));
            DisposeBitmaps(_redo);
            _redo.Clear();
        }

        private void ClearHistory()
        {
            DisposeBitmaps(_undo);
            DisposeBitmaps(_redo);
            _undo.Clear();
            _redo.Clear();
        }

        private static Bitmap CreateBlankBitmap(int width, int height, Color color)
        {
            Bitmap bitmap = new Bitmap(width, height);
            using (Graphics graphics = Graphics.FromImage(bitmap)) graphics.Clear(color);
            return bitmap;
        }

        private static Bitmap CloneBitmap(Bitmap source)
        {
            return new Bitmap(source);
        }

        private static void DisposeBitmaps(List<Bitmap> bitmaps)
        {
            foreach (Bitmap bitmap in bitmaps) bitmap.Dispose();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_caretTimer != null) _caretTimer.Dispose();
                if (_floatingSelection != null) _floatingSelection.Dispose();
                if (_image != null) _image.Dispose();
                DisposeBitmaps(_undo);
                DisposeBitmaps(_redo);
            }
            base.Dispose(disposing);
        }
    }

    internal sealed class Windows7DisplayStringRow : UserControl
    {
        private readonly TextBox _text;
        private readonly NumericUpDown _background;
        private readonly NumericUpDown _foreground;
        private readonly CheckBox _blink;
        private readonly ComboBox _mode;
        private readonly CheckBox _color;
        private readonly Label _compatibility;

        public Windows7DisplayStringRow()
        {
            Height = 188;
            BackColor = Ui.CardAlt;
            Margin = new Padding(0, 0, 0, 10);
            Resize += delegate { Ui.RoundRegion(this, 9); LayoutRow(); };
            Label index = Ui.Label("01", 10F, FontStyle.Bold, Ui.Accent);
            index.Location = new Point(15, 15);
            Controls.Add(index);
            Label textLabel = Ui.Label("文本（不能包含双引号）", 8.5F, FontStyle.Regular, Ui.Muted);
            textLabel.Location = new Point(55, 10);
            Controls.Add(textLabel);
            _text = Ui.TextBox("TEST", false);
            _text.Location = new Point(55, 33);
            _text.Height = 29;
            Controls.Add(_text);
            Label backgroundLabel = Ui.Label("背景色（0–F）", 8.5F, FontStyle.Regular, Ui.Muted);
            backgroundLabel.Location = new Point(55, 78);
            Controls.Add(backgroundLabel);
            _background = CreateHexField(0xF);
            _background.Location = new Point(55, 103);
            _background.ValueChanged += delegate { UpdateCompatibility(); };
            Controls.Add(_background);
            Label foregroundLabel = Ui.Label("前景色（0–F）", 8.5F, FontStyle.Regular, Ui.Muted);
            foregroundLabel.Location = new Point(205, 78);
            Controls.Add(foregroundLabel);
            _foreground = CreateHexField(0x0);
            _foreground.Location = new Point(205, 103);
            Controls.Add(_foreground);
            Label modeLabel = Ui.Label("屏幕模式", 8.5F, FontStyle.Regular, Ui.Muted);
            modeLabel.Location = new Point(355, 78);
            Controls.Add(modeLabel);
            _mode = new ComboBox
            {
                Location = new Point(355, 103),
                Size = new Size(130, 30),
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = Ui.Input,
                ForeColor = Ui.Text,
                Font = new Font("Segoe UI", 9.5F)
            };
            _mode.Items.Add("80 × 25");
            _mode.Items.Add("80 × 50");
            _mode.SelectedIndex = 1;
            Controls.Add(_mode);
            _blink = Ui.CheckBox("启用闪烁", true);
            _blink.Location = new Point(515, 106);
            _blink.CheckedChanged += delegate { UpdateCompatibility(); };
            Controls.Add(_blink);
            _color = Ui.CheckBox("彩色", false);
            _color.Location = new Point(635, 106);
            Controls.Add(_color);
            _compatibility = Ui.Label(string.Empty, 8.5F, FontStyle.Bold, Ui.Amber);
            _compatibility.Location = new Point(55, 151);
            Controls.Add(_compatibility);
            UpdateCompatibility();
            LayoutRow();
        }

        public bool HasBlinkBrightBackgroundConflict
        {
            get { return _blink.Checked && _background.Value >= 8; }
        }

        public string BuildProtocolCommand()
        {
            string text = MainForm.ValidateProtocolText(_text.Text, true);
            return "DS \"" + text + "\" " + decimal.ToUInt32(_background.Value).ToString("X", CultureInfo.InvariantCulture) + " " + decimal.ToUInt32(_foreground.Value).ToString("X", CultureInfo.InvariantCulture) + " " + (_blink.Checked ? "1" : "0") + " " + (_mode.Text.Contains("25") ? "1" : "0") + " " + (_color.Checked ? "1" : "0");
        }

        public PreviewTextItem BuildPreviewItem()
        {
            return new PreviewTextItem
            {
                Text = MainForm.ValidateProtocolText(_text.Text, true),
                TextSize = 16,
                TextBackground = VgaColor(decimal.ToUInt32(_background.Value)),
                TextForeground = VgaColor(decimal.ToUInt32(_foreground.Value)),
                ScreenBackground = VgaColor(decimal.ToUInt32(_background.Value)),
                ClearScreen = false,
                VgaText = true,
                Vga80x25 = _mode.Text.Contains("25"),
                VgaBackground = decimal.ToInt32(_background.Value),
                VgaForeground = decimal.ToInt32(_foreground.Value),
                Blink = _blink.Checked,
                Rainbow = _color.Checked
            };
        }

        private static Color VgaColor(uint value)
        {
            Color[] colors =
            {
                Color.FromArgb(0, 0, 0), Color.FromArgb(0, 0, 170), Color.FromArgb(0, 170, 0), Color.FromArgb(0, 170, 170),
                Color.FromArgb(170, 0, 0), Color.FromArgb(170, 0, 170), Color.FromArgb(170, 85, 0), Color.FromArgb(170, 170, 170),
                Color.FromArgb(85, 85, 85), Color.FromArgb(85, 85, 255), Color.FromArgb(85, 255, 85), Color.FromArgb(85, 255, 255),
                Color.FromArgb(255, 85, 85), Color.FromArgb(255, 85, 255), Color.FromArgb(255, 255, 85), Color.FromArgb(255, 255, 255)
            };
            return colors[(int)(value & 0x0F)];
        }

        private static NumericUpDown CreateHexField(uint value)
        {
            return new NumericUpDown
            {
                Size = new Size(128, 29),
                Minimum = 0,
                Maximum = 0xF,
                Value = value,
                Hexadecimal = true,
                TextAlign = HorizontalAlignment.Center,
                BackColor = Ui.Input,
                ForeColor = Ui.Text,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 10F),
                ThousandsSeparator = false
            };
        }

        private void UpdateCompatibility()
        {
            if (HasBlinkBrightBackgroundConflict)
            {
                _compatibility.Text = "警告: 闪烁和 8–F 的 16 色亮背景互不兼容!";
                _compatibility.ForeColor = Ui.Red;
            }
            else
            {
                _compatibility.Text = "";
                _compatibility.ForeColor = Ui.Amber;
            }
        }

        private void LayoutRow()
        {
            _text.Width = Math.Max(250, Width - 75);
        }
    }

    internal sealed class DisplayStringsPage : PageView
    {
        private readonly FlowLayoutPanel _rows;
        private readonly Label _count;
        private readonly List<DisplayStringRow> _items = new List<DisplayStringRow>();
        private readonly CommandRequestHandler _send;
        private readonly LargeCommandRequestHandler _sendLarge;
        private readonly PreviewRequestHandler _preview;
        private readonly bool _windows7 = Program.IsWindows7();
        private FlowLayoutPanel _windows7Rows;
        private Windows7DisplayStringRow _windows7Row;
        private CheckBox _clearBeforeAll;
        private CheckBox _loopAll;
        private ColorPickerBox _clearBeforeAllBackground;
        public bool HasPreviewConfiguration { get; private set; }

        public DisplayStringsPage(CommandRequestHandler send, LargeCommandRequestHandler sendLarge, PreviewRequestHandler preview) : base("显示字符串/图片", "每一条都可以保留为文字，或转换成自定义图片画布")
        {
            _send = send;
            _sendLarge = sendLarge;
            _preview = preview;
            if (_windows7)
            {
                BuildWindows7Page();
                return;
            }
            CardPanel card = new CardPanel { Height = 730 };
            Label title = Ui.Label("DisplayString / DisplayImage", 13F, FontStyle.Bold, Ui.Text);
            title.Location = new Point(22, 5);
            card.Controls.Add(title);
            Label hint = Ui.Label("默认 5 条，最多 100 条，可将任意一条转换为图片", 8.8F, FontStyle.Regular, Ui.Muted);
            hint.Location = new Point(22, 42);
            card.Controls.Add(hint);
            _clearBeforeAll = Ui.CheckBox("绘制所有东西前清屏", false);
            _clearBeforeAll.Location = new Point(22, 94);
            card.Controls.Add(_clearBeforeAll);
            _loopAll = Ui.CheckBox("循环显示所有配置", false);
            _loopAll.Location = new Point(540, 94);
            card.Controls.Add(_loopAll);
            _clearBeforeAllBackground = new ColorPickerBox("背景色 ARGB", 0xFF0078D4u) { Location = new Point(255, 69) };
            _clearBeforeAllBackground.Enabled = false;
            card.Controls.Add(_clearBeforeAllBackground);
            _clearBeforeAll.CheckedChanged += delegate { _clearBeforeAllBackground.Enabled = _clearBeforeAll.Checked; };
            _rows = new FlowLayoutPanel
            {
                Location = new Point(22, 136),
                Height = 477,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                AutoScroll = true,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                BackColor = Ui.Window,
                Padding = new Padding(8)
            };
            card.Controls.Add(_rows);
            card.Resize += delegate
            {
                _rows.Width = card.ClientSize.Width - 44;
                ResizeRows();
            };
            ModernButton minus = new ModernButton { Text = "−", Location = new Point(22, 638), Size = new Size(42, 38), BaseColor = Ui.CardAlt };
            minus.Click += delegate { RemoveLast(); };
            card.Controls.Add(minus);
            ModernButton plus = new ModernButton { Text = "+", Location = new Point(72, 638), Size = new Size(42, 38), BaseColor = Ui.CardAlt };
            plus.Click += delegate { AddRow(); };
            card.Controls.Add(plus);
            _count = Ui.Label("0 / 100", 9F, FontStyle.Bold, Ui.Muted);
            _count.Location = new Point(168, 648);
            card.Controls.Add(_count);
            ModernButton apply = new ModernButton { Text = "发送全部内容", Location = new Point(260, 636), Size = new Size(164, 42) };
            apply.Click += delegate { Apply(); };
            card.Controls.Add(apply);
            ModernButton previewButton = new ModernButton { Text = "预览", Location = new Point(apply.Right + 20, apply.Top), Size = new Size(100, 42), BaseColor = Ui.CardAlt };
            previewButton.Click += delegate { PreviewCurrent(); };
            card.Controls.Add(previewButton);
            AddCard(card);
            for (int i = 0; i < 5; i++) AddRow();
        }

        private void BuildWindows7Page()
        {
            CardPanel card = new CardPanel { Height = 430 };
            Label title = Ui.Label("DisplayString", 13F, FontStyle.Bold, Ui.Text);
            title.Location = new Point(22, 18);
            card.Controls.Add(title);
            _windows7Rows = new FlowLayoutPanel
            {
                Location = new Point(22, 83),
                Height = 224,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                AutoScroll = true,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                BackColor = Ui.Window,
                Padding = new Padding(8)
            };
            card.Controls.Add(_windows7Rows);
            _windows7Row = new Windows7DisplayStringRow();
            _windows7Rows.Controls.Add(_windows7Row);
            card.Resize += delegate
            {
                _windows7Rows.Width = card.ClientSize.Width - 44;
                _windows7Row.Width = Math.Max(780, _windows7Rows.ClientSize.Width - _windows7Rows.Padding.Horizontal - 22);
            };
            ModernButton apply = new ModernButton
            {
                Text = "显示字符串/图片",
                Location = new Point(22, 332),
                Size = new Size(142, 42)
            };
            apply.Click += delegate { Apply(); };
            card.Controls.Add(apply);
            ModernButton previewButton = new ModernButton
            {
                Text = "预览",
                Location = new Point(apply.Right + 20, apply.Top),
                Size = new Size(100, 42),
                BaseColor = Ui.CardAlt
            };
            previewButton.Click += delegate { PreviewCurrent(); };
            card.Controls.Add(previewButton);
            AddCard(card);
        }

        private void AddRow()
        {
            if (_items.Count >= 100) return;
            DisplayStringRow row = new DisplayStringRow();
            row.RemoveRequested += delegate { RemoveRow(row); };
            _items.Add(row);
            _rows.Controls.Add(row);
            RefreshRows();
        }

        private void RemoveLast()
        {
            if (_items.Count > 1) RemoveRow(_items[_items.Count - 1]);
        }

        private void RemoveRow(DisplayStringRow row)
        {
            if (_items.Count <= 1) return;
            _items.Remove(row);
            _rows.Controls.Remove(row);
            row.Dispose();
            RefreshRows();
        }

        private void RefreshRows()
        {
            for (int i = 0; i < _items.Count; i++) _items[i].Index = i + 1;
            _count.Text = _items.Count.ToString(CultureInfo.InvariantCulture) + " / 100";
            ResizeRows();
        }

        private void ResizeRows()
        {
            int width = Math.Max(850, _rows.ClientSize.Width - _rows.Padding.Horizontal - 22);
            foreach (DisplayStringRow row in _items) row.Width = width;
        }

        public List<PreviewTextItem> GetPreviewItems()
        {
            List<PreviewTextItem> items = new List<PreviewTextItem>();
            if (_windows7)
            {
                if (_windows7Row != null) items.Add(_windows7Row.BuildPreviewItem());
                return items;
            }
            foreach (DisplayStringRow row in _items) if (!row.IsImage) items.Add(row.BuildPreviewItem());
            return items;
        }

        public List<PreviewImageItem> GetPreviewImages()
        {
            List<PreviewImageItem> items = new List<PreviewImageItem>();
            if (_windows7) return items;
            foreach (DisplayStringRow row in _items) if (row.IsImage) items.Add(row.BuildPreviewImageItem());
            return items;
        }

        private void PreviewCurrent()
        {
            try
            {
                PreviewSnapshot snapshot = PreviewSnapshot.CreateDefault(_windows7);
                if (!_windows7 && _clearBeforeAll != null && _clearBeforeAll.Checked)
                {
                    Color background = Color.FromArgb(unchecked((int)_clearBeforeAllBackground.Value));
                    snapshot.DisplayItems.Add(new PreviewTextItem
                    {
                        Text = " ",
                        TextSize = 0,
                        TextBackground = background,
                        TextForeground = background,
                        ScreenBackground = background,
                        X = 0,
                        Y = 0,
                        ClearScreen = true,
                        VgaText = false
                    });
                }
                snapshot.DisplayItems.AddRange(GetPreviewItems());
                snapshot.DisplayImages.AddRange(GetPreviewImages());
                foreach (PreviewTextItem item in snapshot.DisplayItems) if (item.ClearScreen) snapshot.Background = item.ScreenBackground;
                foreach (PreviewImageItem item in snapshot.DisplayImages) if (item.ClearScreen) snapshot.Background = item.ScreenBackground;
                snapshot.Kind = _windows7 ? PreviewKind.Windows7DisplayString : PreviewKind.ModernDisplayStrings;
                HasPreviewConfiguration = true;
                _preview(snapshot, "显示字符串/图片预览");
            }
            catch (Exception ex)
            {
                MessageBox.Show(FindForm(), ex.Message, "无法生成预览", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void Apply()
        {
            try
            {
                HasPreviewConfiguration = true;
                if (_windows7)
                {
                    if (_windows7Row.HasBlinkBrightBackgroundConflict)
                    {
                        DialogResult result = MessageBox.Show(FindForm(), "当前同时启用了闪烁和 8–F 亮色背景Windows 7 文本模式中两者不能同时生效\n\n仍要按当前参数发送吗？", "闪烁与亮色背景不兼容", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                        if (result != DialogResult.Yes) return;
                    }
                    _send(_windows7Row.BuildProtocolCommand(), "Windows 7 DisplayString 配置已发送");
                    return;
                }
                StringBuilder command = new StringBuilder(_loopAll.Checked ? "DS L{" : "DS {");
                bool hasText = false;
                bool hasImage = false;
                uint clearBeforeAllBackground = _clearBeforeAllBackground.Value;
                for (int i = 0; i < _items.Count; i++)
                {
                    if (_items[i].IsImage) { hasImage = true; continue; }
                    if (hasText) command.Append(",");
                    command.Append(_items[i].BuildProtocolItem(_clearBeforeAll.Checked && !hasText, clearBeforeAllBackground));
                    hasText = true;
                }
                command.Append("}");
                if (hasImage)
                {
                    command.Append(" DI {");
                    bool hasImagePart = false;
                    foreach (DisplayStringRow row in _items)
                    {
                        if (!row.IsImage) continue;
                        foreach (string part in row.BuildProtocolImageItems())
                        {
                            if (hasImagePart) command.Append(',');
                            command.Append(part);
                            hasImagePart = true;
                        }
                    }
                    command.Append('}');
                    int imageCount = 0;
                    int clearImageCount = 0;
                    foreach (DisplayStringRow row in _items)
                    {
                        if (!row.IsImage) continue;
                        imageCount++;
                        if (row.ImageClearsScreen) clearImageCount++;
                    }
                    _sendLarge(command.ToString(), "是否发送当前配置？\n命令长度:" + command.Length.ToString(CultureInfo.InvariantCulture) + " 字符", "DisplayString / DisplayImage 配置已发送");
                }
                else _send(command.ToString(), "DisplayString 配置已发送");
            }
            catch (Exception ex)
            {
                MessageBox.Show(FindForm(), ex.Message, "字符串配置无效", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
    }

    internal sealed class DisplayImageEditorPanel : Panel
    {
        private readonly NumericUpDown _width;
        private readonly NumericUpDown _height;
        private readonly NumericUpDown _x;
        private readonly NumericUpDown _y;
        private readonly NumericUpDown _thickness;
        private readonly NumericUpDown _fontSize;
        private readonly NumericUpDown _zoom;
        private readonly ColorPickerBox _background;
        private readonly CheckBox _clear;
        private readonly Label _dimensionStatus;
        private readonly Label _toolStatus;
        private readonly Panel _colorPreview;
        private readonly QrCanvasControl _canvas;
        private readonly Panel _canvasHost;
        private readonly Dictionary<QrPaintTool, ModernButton> _toolButtons = new Dictionary<QrPaintTool, ModernButton>();

        public DisplayImageEditorPanel()
        {
            Height = 570;
            BackColor = Color.Transparent;

            FlowLayoutPanel parameters = new FlowLayoutPanel
            {
                Location = new Point(0, 0),
                Height = 72,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                AutoScroll = true,
                WrapContents = false,
                FlowDirection = FlowDirection.LeftToRight,
                BackColor = Color.Transparent
            };
            Controls.Add(parameters);
            _width = CreateNumberField(8, 1, uint.MaxValue, 82);
            _height = CreateNumberField(8, 1, uint.MaxValue, 82);
            _x = CreateNumberField(0, 0, uint.MaxValue, 108);
            _y = CreateNumberField(0, 0, uint.MaxValue, 108);
            parameters.Controls.Add(CreateFieldPanel("宽", _width, 90));
            parameters.Controls.Add(CreateFieldPanel("高", _height, 90));
            parameters.Controls.Add(CreateFieldPanel("X 坐标", _x, 116));
            parameters.Controls.Add(CreateFieldPanel("Y 坐标", _y, 116));
            _background = new ColorPickerBox("清屏背景", 0xFF0078D4u) { Margin = new Padding(4, 0, 4, 0) };
            parameters.Controls.Add(_background);
            _clear = Ui.CheckBox("绘制前清屏", false);
            _clear.Margin = new Padding(8, 29, 4, 0);
            _clear.CheckedChanged += delegate
            {
                if (!_clear.Checked) return;
                DialogResult result = MessageBox.Show(FindForm(), "图片会在文字之后绘制\n\n勾选“绘制前清屏”会先清除屏幕，因此之前绘制的文字也会被清除\n仍要勾选吗？", "确认图片清屏", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (result != DialogResult.Yes) _clear.Checked = false;
            };
            parameters.Controls.Add(_clear);
            ModernButton rebuild = CreateToolbarButton("重建画布", 96);
            rebuild.Margin = new Padding(8, 20, 4, 0);
            rebuild.Click += delegate { RebuildCanvas(); };
            parameters.Controls.Add(rebuild);

            FlowLayoutPanel tools = new FlowLayoutPanel
            {
                Location = new Point(0, 78),
                Height = 78,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                AutoScroll = true,
                WrapContents = true,
                FlowDirection = FlowDirection.LeftToRight,
                BackColor = Color.Transparent
            };
            Controls.Add(tools);
            AddToolButton(tools, QrPaintTool.Select, "选择");
            AddToolButton(tools, QrPaintTool.Brush, "画笔");
            AddToolButton(tools, QrPaintTool.Eraser, "橡皮");
            AddToolButton(tools, QrPaintTool.Fill, "填充");
            AddToolButton(tools, QrPaintTool.Line, "直线");
            AddToolButton(tools, QrPaintTool.Rectangle, "矩形");
            AddToolButton(tools, QrPaintTool.Ellipse, "椭圆");
            AddToolButton(tools, QrPaintTool.Text, "文字");
            ModernButton import = CreateToolbarButton("导入图像", 88);
            import.Click += delegate { ImportImage(); };
            tools.Controls.Add(import);
            ModernButton undo = CreateToolbarButton("撤销", 62);
            undo.Click += delegate { _canvas.Undo(); };
            tools.Controls.Add(undo);
            ModernButton redo = CreateToolbarButton("重做", 62);
            redo.Click += delegate { _canvas.Redo(); };
            tools.Controls.Add(redo);
            ModernButton clear = CreateToolbarButton("清空", 62);
            clear.Click += delegate { _canvas.Clear(Color.White); };
            tools.Controls.Add(clear);

            FlowLayoutPanel options = new FlowLayoutPanel
            {
                Location = new Point(0, 162),
                Height = 74,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                AutoScroll = true,
                WrapContents = false,
                FlowDirection = FlowDirection.LeftToRight,
                BackColor = Color.Transparent
            };
            Controls.Add(options);
            _thickness = CreateNumberField(2, 1, 64, 72);
            _fontSize = CreateNumberField(18, 4, 128, 72);
            _zoom = CreateNumberField(6, 1, 16, 72);
            options.Controls.Add(CreateFieldPanel("粗细", _thickness, 80));
            options.Controls.Add(CreateFieldPanel("字号", _fontSize, 80));
            options.Controls.Add(CreateFieldPanel("缩放", _zoom, 80));
            _colorPreview = new Panel
            {
                Size = new Size(42, 29),
                BackColor = Color.Black,
                BorderStyle = BorderStyle.FixedSingle,
                Cursor = Cursors.Hand
            };
            _colorPreview.Click += delegate { PickCustomColor(); };
            options.Controls.Add(CreateFieldPanel("颜色", _colorPreview, 50));
            Color[] colors = { Color.Black, Color.White, Color.Red, Color.Lime, Color.Blue, Color.Yellow, Color.Cyan, Color.Magenta };
            foreach (Color color in colors) AddPaletteColor(options, color);
            _dimensionStatus = Ui.Label(string.Empty, 8.5F, FontStyle.Bold, Ui.Green);
            _dimensionStatus.Margin = new Padding(10, 28, 4, 0);
            options.Controls.Add(_dimensionStatus);
            _toolStatus = Ui.Label("当前工具：画笔", 8.5F, FontStyle.Regular, Ui.Muted);
            _toolStatus.Margin = new Padding(10, 28, 4, 0);
            options.Controls.Add(_toolStatus);

            _canvasHost = new Panel
            {
                Location = new Point(0, 242),
                Height = 320,
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
                AutoScroll = true,
                BackColor = Color.FromArgb(222, 229, 239),
                BorderStyle = BorderStyle.FixedSingle
            };
            Controls.Add(_canvasHost);
            _canvas = new QrCanvasControl(8, 8)
            {
                Location = new Point(8, 8),
                PrimaryColor = Color.Black,
                BrushSize = 2,
                TextSize = 18,
                Zoom = 6
            };
            _canvas.Clear(Color.White);
            _canvasHost.Controls.Add(_canvas);
            _canvas.SizeChanged += delegate { UpdateCanvasScrollSize(); };
            _width.ValueChanged += delegate { UpdateDimensionStatus(); };
            _height.ValueChanged += delegate { UpdateDimensionStatus(); };
            _thickness.ValueChanged += delegate { _canvas.BrushSize = decimal.ToInt32(_thickness.Value); };
            _fontSize.ValueChanged += delegate { _canvas.TextSize = decimal.ToInt32(_fontSize.Value); };
            _zoom.ValueChanged += delegate
            {
                _canvas.Zoom = decimal.ToInt32(_zoom.Value);
                if (_zoom.Value != _canvas.Zoom) _zoom.Value = _canvas.Zoom;
            };
            _canvas.ZoomChanged += delegate { if (_zoom.Value != _canvas.Zoom) _zoom.Value = _canvas.Zoom; };
            Resize += delegate { LayoutEditor(); };
            SelectTool(QrPaintTool.Brush, "画笔");
            UpdateDimensionStatus();
            LayoutEditor();
        }

        public bool ClearScreen { get { return _clear.Checked; } }

        public List<string> BuildProtocolItems()
        {
            int width, height;
            EnsureCanvasDimensions(out width, out height);
            uint[] pixels = _canvas.GetArgbPixels();
            if ((long)width * height != pixels.Length) throw new InvalidOperationException("图片画布尺寸与像素数据不一致");
            uint baseX = decimal.ToUInt32(_x.Value);
            uint baseY = decimal.ToUInt32(_y.Value);
            ulong background = _background.Value;
            StringBuilder item = new StringBuilder();
            item.Append('[');
            for (int i = 0; i < pixels.Length; i++)
            {
                if (i > 0) item.Append(',');
                item.Append(pixels[i].ToString("X8", CultureInfo.InvariantCulture));
            }
            item.Append("] ");
            item.Append(background.ToString("X", CultureInfo.InvariantCulture));
            item.Append(' ');
            item.Append(baseX.ToString("X", CultureInfo.InvariantCulture));
            item.Append(' ');
            item.Append(baseY.ToString("X", CultureInfo.InvariantCulture));
            item.Append(' ');
            item.Append(width.ToString("X", CultureInfo.InvariantCulture));
            item.Append(' ');
            item.Append(height.ToString("X", CultureInfo.InvariantCulture));
            item.Append(' ');
            item.Append(_clear.Checked ? '1' : '0');
            return new List<string> { item.ToString() };
        }

        public PreviewImageItem BuildPreviewItem()
        {
            int width, height;
            EnsureCanvasDimensions(out width, out height);
            return new PreviewImageItem
            {
                Pixels = _canvas.GetArgbPixels(),
                Width = width,
                Height = height,
                X = decimal.ToUInt32(_x.Value),
                Y = decimal.ToUInt32(_y.Value),
                ScreenBackground = Color.FromArgb(unchecked((int)_background.Value)),
                ClearScreen = _clear.Checked
            };
        }

        private void RebuildCanvas()
        {
            int width, height;
            if (!TryGetDimensions(out width, out height, true)) return;
            _canvas.ResizeCanvas(height, width);
            if (_zoom.Value != _canvas.Zoom) _zoom.Value = _canvas.Zoom;
            UpdateCanvasScrollSize();
        }

        private void EnsureCanvasDimensions(out int width, out int height)
        {
            if (!TryGetDimensions(out width, out height, false)) throw new InvalidOperationException("图片宽和高必须大于 0");
            if (_canvas.ProtocolLength != width || _canvas.ProtocolWidth != height) _canvas.ResizeCanvas(height, width);
        }

        private bool TryGetDimensions(out int width, out int height, bool showMessage)
        {
            width = decimal.ToInt32(_width.Value);
            height = decimal.ToInt32(_height.Value);
            bool valid = width > 0 && height > 0;
            if (!valid && showMessage) MessageBox.Show(FindForm(), "图片宽和高必须大于 0", "尺寸无效", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return valid;
        }

        private void UpdateDimensionStatus()
        {
            long pixels = decimal.ToInt64(_width.Value) * decimal.ToInt64(_height.Value);
            bool valid = pixels > 0;
            _dimensionStatus.Text = valid ? pixels.ToString(CultureInfo.InvariantCulture) + " 像素" : "尺寸无效";
            _dimensionStatus.ForeColor = valid ? Ui.Green : Ui.Red;
        }

        private void ImportImage()
        {
            int width, height;
            if (!TryGetDimensions(out width, out height, true)) return;
            if (_canvas.ProtocolLength != width || _canvas.ProtocolWidth != height) _canvas.ResizeCanvas(height, width);
            using (OpenFileDialog dialog = new OpenFileDialog())
            {
                dialog.Title = "导入图像到 DisplayImage 画布";
                dialog.Filter = "图像文件|*.png;*.jpg;*.jpeg;*.bmp;*.gif|所有文件|*.*";
                if (dialog.ShowDialog(FindForm()) != DialogResult.OK) return;
                try { _canvas.ImportImage(dialog.FileName); }
                catch (Exception ex) { MessageBox.Show(FindForm(), ex.Message, "无法导入图像", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            }
        }

        private void AddToolButton(FlowLayoutPanel tools, QrPaintTool tool, string text)
        {
            ModernButton button = CreateToolbarButton(text, 62);
            button.Click += delegate { SelectTool(tool, text); };
            _toolButtons.Add(tool, button);
            tools.Controls.Add(button);
        }

        private void SelectTool(QrPaintTool tool, string text)
        {
            _canvas.Tool = tool;
            foreach (KeyValuePair<QrPaintTool, ModernButton> item in _toolButtons) item.Value.SelectedState = item.Key == tool;
            _toolStatus.Text = "当前工具：" + text;
        }

        private void AddPaletteColor(FlowLayoutPanel palette, Color color)
        {
            Button swatch = new Button
            {
                Size = new Size(28, 28),
                Margin = new Padding(2, 23, 2, 0),
                BackColor = color,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Tag = color
            };
            swatch.FlatAppearance.BorderColor = color == Color.Black ? Color.DimGray : Ui.Border;
            swatch.Click += delegate (object sender, EventArgs e) { SetColor((Color)((Control)sender).Tag); };
            palette.Controls.Add(swatch);
        }

        private void PickCustomColor()
        {
            using (ColorDialog dialog = new ColorDialog())
            {
                dialog.FullOpen = true;
                dialog.AnyColor = true;
                dialog.Color = _canvas.PrimaryColor;
                if (dialog.ShowDialog(FindForm()) == DialogResult.OK) SetColor(Color.FromArgb(255, dialog.Color.R, dialog.Color.G, dialog.Color.B));
            }
        }

        private void SetColor(Color color)
        {
            _canvas.PrimaryColor = color;
            _colorPreview.BackColor = color;
        }

        private static NumericUpDown CreateNumberField(decimal value, decimal minimum, decimal maximum, int width)
        {
            return new NumericUpDown
            {
                Size = new Size(width, 29),
                Minimum = minimum,
                Maximum = maximum,
                Value = value,
                BackColor = Ui.Input,
                ForeColor = Ui.Text,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 9.5F),
                ThousandsSeparator = false
            };
        }

        private static Panel CreateFieldPanel(string label, Control input, int width)
        {
            Panel panel = new Panel { Width = width, Height = 62, Margin = new Padding(4, 0, 4, 0), BackColor = Color.Transparent };
            Label caption = Ui.Label(label, 8.3F, FontStyle.Regular, Ui.Muted);
            caption.Location = new Point(0, 0);
            input.Location = new Point(0, 24);
            panel.Controls.Add(caption);
            panel.Controls.Add(input);
            return panel;
        }

        private static ModernButton CreateToolbarButton(string text, int width)
        {
            return new ModernButton { Text = text, Size = new Size(width, 32), Margin = new Padding(3), BaseColor = Ui.CardAlt };
        }

        private void LayoutEditor()
        {
            int width = Math.Max(500, ClientSize.Width);
            foreach (Control control in Controls)
            {
                if (control is FlowLayoutPanel) control.Width = width;
            }
            _canvasHost.Width = width;
            UpdateCanvasScrollSize();
        }

        private void UpdateCanvasScrollSize()
        {
            _canvasHost.AutoScrollMinSize = new Size(_canvas.Width + 16, _canvas.Height + 16);
        }
    }

    internal sealed class DisplayStringRow : UserControl
    {
        private readonly Label _index;
        private readonly Label _textLabel;
        private readonly TextBox _text;
        private readonly NumericField _textSize;
        private readonly ColorPickerBox _textBack;
        private readonly ColorPickerBox _textFore;
        private readonly ColorPickerBox _background;
        private readonly NumericField _x;
        private readonly NumericField _y;
        private readonly CheckBox _clear;
        private readonly ModernButton _toggleMode;
        private readonly ModernButton _remove;
        private DisplayImageEditorPanel _imageEditor;
        private bool _imageMode;
        public event EventHandler RemoveRequested;

        public DisplayStringRow()
        {
            Height = 236;
            BackColor = Ui.CardAlt;
            Margin = new Padding(0, 0, 0, 10);
            Resize += delegate { Ui.RoundRegion(this, 9); LayoutRow(); };
            _index = Ui.Label("01", 10F, FontStyle.Bold, Ui.Accent);
            _index.Location = new Point(15, 15);
            Controls.Add(_index);
            _textLabel = Ui.Label("文本（不能包含双引号）", 8.5F, FontStyle.Regular, Ui.Muted);
            _textLabel.Location = new Point(55, 10);
            Controls.Add(_textLabel);
            _text = Ui.TextBox("Your custom text", false);
            _text.Location = new Point(55, 33);
            _text.Height = 29;
            Controls.Add(_text);
            _toggleMode = new ModernButton { Text = "转为图片", Size = new Size(92, 32), BaseColor = Ui.CardAlt };
            _toggleMode.Click += delegate { SetImageMode(!_imageMode); };
            Controls.Add(_toggleMode);
            _remove = new ModernButton { Text = "×", Size = new Size(38, 32), BaseColor = Ui.SoftRed };
            _remove.Click += delegate { if (RemoveRequested != null) RemoveRequested(this, EventArgs.Empty); };
            Controls.Add(_remove);
            _textSize = new NumericField("字号 / TextSize", 24, 512) { Location = new Point(55, 78) };
            _x = new NumericField("X 坐标", 0, uint.MaxValue) { Location = new Point(205, 78) };
            _y = new NumericField("Y 坐标", 0, uint.MaxValue) { Location = new Point(355, 78) };
            _clear = Ui.CheckBox("绘制前清屏", false);
            _clear.Location = new Point(520, 107);
            Controls.Add(_textSize);
            Controls.Add(_x);
            Controls.Add(_y);
            Controls.Add(_clear);
            _textBack = new ColorPickerBox("文字背景 ARGB", 0x00000000u) { Location = new Point(55, 157) };
            _textFore = new ColorPickerBox("文字前景 ARGB", 0xFFFFFFFFu) { Location = new Point(330, 157) };
            _background = new ColorPickerBox("清屏背景 ARGB", 0xFF0078D4u) { Location = new Point(605, 157) };
            Controls.Add(_textBack);
            Controls.Add(_textFore);
            Controls.Add(_background);
            LayoutRow();
        }

        public int Index { set { _index.Text = value.ToString("00", CultureInfo.InvariantCulture); } }
        public bool IsImage { get { return _imageMode; } }
        public bool ImageClearsScreen { get { return _imageMode && _imageEditor != null && _imageEditor.ClearScreen; } }

        public string BuildProtocolItem(bool clearBeforeAll, uint clearBeforeAllBackground)
        {
            string text = MainForm.ValidateProtocolText(_text.Text, true);
            string background = clearBeforeAll ? clearBeforeAllBackground.ToString("X8", CultureInfo.InvariantCulture) : ((ulong)_background.Value).ToString("X", CultureInfo.InvariantCulture);
            return "\"" + text + "\" " + _textSize.Value.ToString("X", CultureInfo.InvariantCulture) + " " + _textBack.Value.ToString("X", CultureInfo.InvariantCulture) + " " + _textFore.Value.ToString("X", CultureInfo.InvariantCulture) + " " + background + " " + _x.Value.ToString("X", CultureInfo.InvariantCulture) + " " + _y.Value.ToString("X", CultureInfo.InvariantCulture) + " " + (clearBeforeAll || _clear.Checked ? "1" : "0");
        }

        public PreviewTextItem BuildPreviewItem()
        {
            return new PreviewTextItem
            {
                Text = MainForm.ValidateProtocolText(_text.Text, true),
                TextSize = _textSize.Value,
                TextBackground = Color.FromArgb(unchecked((int)_textBack.Value)),
                TextForeground = Color.FromArgb(unchecked((int)_textFore.Value)),
                ScreenBackground = Color.FromArgb(unchecked((int)_background.Value)),
                X = _x.Value,
                Y = _y.Value,
                ClearScreen = _clear.Checked,
                VgaText = false
            };
        }

        public List<string> BuildProtocolImageItems()
        {
            if (!_imageMode || _imageEditor == null) return new List<string>();
            return _imageEditor.BuildProtocolItems();
        }

        public PreviewImageItem BuildPreviewImageItem()
        {
            if (!_imageMode || _imageEditor == null) throw new InvalidOperationException("当前条目不是图片模式");
            return _imageEditor.BuildPreviewItem();
        }

        private void SetImageMode(bool imageMode)
        {
            _imageMode = imageMode;
            if (_imageMode && _imageEditor == null)
            {
                _imageEditor = new DisplayImageEditorPanel { Location = new Point(55, 68) };
                Controls.Add(_imageEditor);
            }
            _textLabel.Visible = !_imageMode;
            _text.Visible = !_imageMode;
            _textSize.Visible = !_imageMode;
            _x.Visible = !_imageMode;
            _y.Visible = !_imageMode;
            _clear.Visible = !_imageMode;
            _textBack.Visible = !_imageMode;
            _textFore.Visible = !_imageMode;
            _background.Visible = !_imageMode;
            if (_imageEditor != null) _imageEditor.Visible = _imageMode;
            _toggleMode.Text = _imageMode ? "转为文字" : "转为图片";
            _toggleMode.BaseColor = _imageMode ? Ui.Accent : Ui.CardAlt;
            Height = _imageMode ? 660 : 236;
            LayoutRow();
        }

        private void LayoutRow()
        {
            _remove.Location = new Point(Math.Max(0, Width - _remove.Width - 9), 31);
            _toggleMode.Location = new Point(Math.Max(0, _remove.Left - _toggleMode.Width - 8), 31);
            _text.Width = Math.Max(250, _toggleMode.Left - _text.Left - 8);
            if (_imageEditor != null) _imageEditor.Width = Math.Max(500, Width - 110);
            int available = Width - 110;
            if (available > 850)
            {
                int gap = Math.Max(8, (available - 795) / 2);
                _textBack.Left = 55;
                _textFore.Left = 55 + 265 + gap;
                _background.Left = _textFore.Left + 265 + gap;
            }
            _toggleMode.BringToFront();
            _remove.BringToFront();
        }
    }
}
