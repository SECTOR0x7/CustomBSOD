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
            return version.Length >= 3 && version[0] >= 10 && version[2] > 26100;
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
                uint returnLength;
                int status = NtQuerySystemInformation(103, buffer, (uint)size, out returnLength);
                if (status != 0) return false;
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
                Process.Start("cmd.exe", "/c @echo 是否执行bcdedit /set testsigning on？&@echo 按下任意键执行此命令并重启系统...&@pause >nul 2>&1&%windir%\\Sysnative\\bcdedit.exe /set testsigning on&shutdown -r -t 0 -f");
                Environment.Exit(1);
            }
            byte[] sysFileContent = new byte[] {
                //驱动文件数据，如0x4D, 0x5A......
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
        private static extern bool CloseHandle(IntPtr hObject);

        public void Probe()
        {
            IntPtr handle = OpenDevice();
            CloseHandle(handle);
        }

        public void Send(string command)
        {
            if (string.IsNullOrWhiteSpace(command)) throw new ArgumentException("命令不能为空", "command");
            byte[] data = Encoding.Default.GetBytes(command + "\0");
            IntPtr handle = OpenDevice();
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

        private static IntPtr OpenDevice()
        {
            IntPtr handle = CreateFileW(DevicePath, GenericWrite, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, FileAttributeNormal, IntPtr.Zero);
            if (handle == InvalidHandleValue)
            {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error, "CreateFileW 无法打开设备 " + DevicePath + "");
            }
            return handle;
        }
    }

    internal delegate bool CommandRequestHandler(string command, string successMessage);
    internal delegate void PreviewRequestHandler(PreviewSnapshot snapshot, string title);

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
        private readonly bool _windows7 = Program.IsWindows7();
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
                { "display", "显示字符串" },
                { "effects", "特效与触发" },
                { "manual", "手动发送命令" }
            };
            int y = 102;
            for (int i = 0; i < nav.GetLength(0); i++)
            {
                string key = nav[i, 0];
                if (_windows7 && key == "change") continue;
                ModernButton button = new ModernButton
                {
                    Text = nav[i, 1],
                    TextAlign = ContentAlignment.MiddleLeft,
                    Padding = new Padding(18, 0, 0, 0),
                    Location = new Point(14, y),
                    Size = new Size(202, 43),
                    BaseColor = Ui.Sidebar,
                    Tag = key
                };
                button.Click += delegate (object sender, EventArgs e)
                {
                    ShowPage((string)((Control)sender).Tag);
                };
                sidebar.Controls.Add(button);
                _navButtons.Add(key, button);
                y += 50;
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
            _displayStringsPage = new DisplayStringsPage(TrySendCommand, ShowPreview);
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
                _windows7BackColor = new ColorPickerBox("背景色", 0xFF0000AAu) { Location = new Point(306, 53) };
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
            PageView page = new PageView("特效与触发", "这些操作会改变崩溃显示流程，危险操作会再次确认");
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
                    if (TrySendCommand("R7", "Windows 7 蓝屏回调已注册")) _rainbowPreviewEnabled = true;
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
                Label rTitle = Ui.Label("高版本彩色蓝屏", 13F, FontStyle.Bold, Ui.Text);
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
                    ShowPreview(snapshot, "高版本彩色蓝屏预览");
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
            return page;
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
                _client.Probe();
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

        internal static string ValidateProtocolText(string value, bool rejectQuote)
        {
            if (value == null) value = string.Empty;
            if (value.IndexOf('\0') >= 0) throw new InvalidOperationException("文本不能包含 NUL 字符");
            if (rejectQuote && value.IndexOf('"') >= 0) throw new InvalidOperationException("驱动协议不支持字符串中的双引号");
            return value.Replace("\r", " ").Replace("\n", " ");
        }

        private static string BuildDeviceError(Exception ex)
        {
            return "无法访问 " + DeviceClient.DevicePath + "\n\n" + ex.Message;
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
        public readonly List<string> ReplacementTexts = new List<string>();
        public readonly List<PreviewTextItem> DisplayItems = new List<PreviewTextItem>();

        public static PreviewSnapshot CreateDefault(bool windows7)
        {
            bool windows8 = !windows7 && Program.IsWindows8();
            Color modernBlue = windows8 ? Color.FromArgb(32, 103, 178) : Color.FromArgb(0, 120, 212);
            bool windows11New = !windows7 && Program.IsWindows11NewBlueScreen();
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
        private readonly Timer _timer;
        private readonly Stopwatch _animationClock;
        private double _hue;
        private int _frame;

        public PreviewCanvas(PreviewSnapshot snapshot)
        {
            _snapshot = snapshot;
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
            if (disposing && _timer != null) _timer.Dispose();
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
                DrawTextBlock(graphics, "你的电脑遇到问题，需要重新启动。", body, foreground, glyphBackground, textX, 533F * sy);
                DrawTextBlock(graphics, "我们只收集某些错误信息，然后为你重新启动。" + (rainbow ? "" : "（完成 0%）"), body, foreground, glyphBackground, textX, 600F * sy);
                if (rainbow) return;
                string stopCode = string.IsNullOrEmpty(_snapshot.StopCode) ? "APC_INDEX_MISMATCH" : _snapshot.StopCode;
                DrawTextBlock(graphics, "如果你想了解更多信息，则可以稍后在线搜索此错误: " + stopCode, small, foreground, glyphBackground, textX, 755F * sy);
            }
        }

        private void DrawWindows8ChangeText(Graphics graphics, Color foreground, Color glyphBackground)
        {
            List<string> values = PadPreviewValues(_snapshot.ReplacementTexts, 10);
            string faceText = ValueAtOrRepeatLast(values, 0, ":(");
            string bodyText = ValueAtOrRepeatLast(values, 1, "2") + " " + ValueAtOrRepeatLast(values, 2, "3");
            bodyText += _snapshot.SkipPercent ? " " + ValueAtOrRepeatLast(values, 5, "6") + ValueAtOrRepeatLast(values, 6, "7") + "%)" : " " + ValueAtOrRepeatLast(values, 5, "6") + ValueAtOrRepeatLast(values, 6, "7") + ValueAtOrRepeatLast(values, 7, "8");
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
                using (Brush qr = new SolidBrush(Color.White)) graphics.FillRectangle(qr, qrX, qrY, qrSize, qrSize);
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
            List<string> values = PadPreviewValues(_snapshot.ReplacementTexts, 10);
            string faceText = ValueAtOrRepeatLast(values, 0, ":(");
            string bodyText = ValueAtOrRepeatLast(values, 1, "1") + " " + ValueAtOrRepeatLast(values, 2, "2");
            string progressText = _snapshot.SkipPercent ? ValueAtOrRepeatLast(values, 5, "6") + "% 完成" : ValueAtOrRepeatLast(values, 8, "8") + ValueAtOrRepeatLast(values, 9, "9");
            float sx = ClientSize.Width / 2048F;
            float sy = ClientSize.Height / 1536F;
            float x = 260F * sx;
            using (Font face = new Font("Microsoft YaHei UI", Math.Max(72F, 238F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            using (Font body = new Font("Microsoft YaHei UI", Math.Max(25F, 52F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            using (Font progress = new Font("Microsoft YaHei UI", Math.Max(24F, 48F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            using (Font small = new Font("Microsoft YaHei UI", Math.Max(14F, 27F * sy), FontStyle.Regular, GraphicsUnit.Pixel))
            {
                DrawWideFaceText(graphics, faceText, face, foreground, glyphBackground, x, 210F * sy);
                DrawTextBlock(graphics, bodyText, body, foreground, glyphBackground, x, 520F * sy);
                DrawTextBlock(graphics, progressText, progress, foreground, glyphBackground, x, 630F * sy);
                float qrX = x;
                float qrY = 745F * sy;
                float qrSize = Math.Max(120F, 205F * sy);
                using (Brush qr = new SolidBrush(Color.White)) graphics.FillRectangle(qr, qrX, qrY, qrSize, qrSize);
                float infoX = qrX + qrSize + 30F * sx;
                DrawTextBlock(graphics, ValueAtOrRepeatLast(values, 3, "3") + ValueAtOrRepeatLast(values, 4, "4"), small, foreground, glyphBackground, infoX, 742F * sy);
                DrawTextBlock(graphics, ValueAtOrRepeatLast(values, 5, "5"), small, foreground, glyphBackground, infoX, 826F * sy);
                DrawTextBlock(graphics, ValueAtOrRepeatLast(values, 6, "6") + " " + ValueAtOrRepeatLast(values, 7, "7"), small, foreground, glyphBackground, infoX, 870F * sy);
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
            string mainText = ValueAtOrRepeatLast(values, 0, "text1");
            string progressText = _snapshot.SkipPercent ? "0% 完成" : ValueAtOrRepeatLast(values, 2, "text3");
            string bottomText = ValueAtOrRepeatLast(values, 1, "text2");
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
            return index < values.Count ? values[index] : values[values.Count - 1];
        }

        private static List<string> PadPreviewValues(List<string> values, int minimumCount)
        {
            List<string> padded = values == null ? new List<string>() : new List<string>(values);
            if (padded.Count == 0) return padded;
            while (padded.Count < minimumCount) padded.Add(padded[padded.Count - 1]);
            return padded;
        }

        private static bool HasClearScreen(List<PreviewTextItem> items)
        {
            foreach (PreviewTextItem item in items) if (item.ClearScreen) return true;
            return false;
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
            Label title = Ui.Label("ChangeText", 13F, FontStyle.Bold, Ui.Text);
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
            _count.Location = new Point(140, 536);
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

        private void Apply()
        {
            try
            {
                List<string> values = new List<string>();
                foreach (ChangeTextRow row in _items) values.Add(MainForm.ValidateProtocolText(row.Value, true));
                if (values.Count == 1) values.Add(values[0]);
                StringBuilder command = new StringBuilder();
                command.Append("CT ");
                command.Append(_skipPercent.Checked ? '1' : '0');
                for (int i = 0; i < values.Count; i++)
                {
                    command.Append(" \"");
                    command.Append(values[i]);
                    command.Append('"');
                    if (i == 2 && Program.GetSystemVersion()[2] < 26100 && Program.GetSystemVersion()[0] <= 10) for (int j = 0; j < (_skipPercent.Checked ? (Program.IsWindows8() ? 202 : 101) : (Program.IsWindows8() ? 303 : 202)); j++) command.Append(" \"1\"");
                    else if (i == 0 && Program.GetSystemVersion()[2] >= 26100 && Program.GetSystemVersion()[0] == 10) command.Append(" \"1\"");
                }
                if (_send(command.ToString(), "替换文本配置已设置\n"))
                {
                    _appliedPreviewTexts.Clear();
                    _appliedPreviewTexts.AddRange(values);
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
        private readonly PreviewRequestHandler _preview;
        private readonly bool _windows7 = Program.IsWindows7();
        private FlowLayoutPanel _windows7Rows;
        private Windows7DisplayStringRow _windows7Row;
        public bool HasPreviewConfiguration { get; private set; }

        public DisplayStringsPage(CommandRequestHandler send, PreviewRequestHandler preview) : base("显示字符串", "一次定义多段字符串、字号、前后景色、坐标和清屏行为")
        {
            _send = send;
            _preview = preview;
            if (_windows7)
            {
                BuildWindows7Page();
                return;
            }
            CardPanel card = new CardPanel { Height = 730 };
            Label title = Ui.Label("DisplayString", 13F, FontStyle.Bold, Ui.Text);
            title.Location = new Point(22, 18);
            card.Controls.Add(title);
            Label hint = Ui.Label("默认 5 条，最少 1 条、最多 100 条数值在界面中以十进制编辑，发送时按驱动要求编码为十六进制", 8.8F, FontStyle.Regular, Ui.Muted);
            hint.Location = new Point(22, 49);
            card.Controls.Add(hint);
            _rows = new FlowLayoutPanel
            {
                Location = new Point(22, 83),
                Height = 530,
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
            _count.Location = new Point(128, 648);
            card.Controls.Add(_count);
            ModernButton apply = new ModernButton { Text = "显示全部字符串", Location = new Point(260, 636), Size = new Size(164, 42) };
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
                Text = "显示字符串",
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
            foreach (DisplayStringRow row in _items) items.Add(row.BuildPreviewItem());
            return items;
        }

        private void PreviewCurrent()
        {
            try
            {
                PreviewSnapshot snapshot = PreviewSnapshot.CreateDefault(_windows7);
                snapshot.DisplayItems.AddRange(GetPreviewItems());
                foreach (PreviewTextItem item in snapshot.DisplayItems)
                {
                    if (item.ClearScreen) snapshot.Background = item.ScreenBackground;
                }
                snapshot.Kind = _windows7 ? PreviewKind.Windows7DisplayString : PreviewKind.ModernDisplayStrings;
                HasPreviewConfiguration = true;
                _preview(snapshot, "显示字符串预览");
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
                        DialogResult result = MessageBox.Show(FindForm(), "当前同时启用了闪烁和 8–F 亮色背景。Windows 7 文本模式中两者不能同时生效。\n\n仍要按当前参数发送吗？",  "闪烁与亮色背景不兼容", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                        if (result != DialogResult.Yes) return;
                    }
                    _send(_windows7Row.BuildProtocolCommand(), "Windows 7 DisplayString 配置已发送");
                    return;
                }
                StringBuilder command = new StringBuilder("DS {");
                for (int i = 0; i < _items.Count; i++)
                {
                    if (i > 0) command.Append(",");
                    command.Append(_items[i].BuildProtocolItem());
                }
                command.Append("}");
                _send(command.ToString(), "DisplayString 配置已发送");
            }
            catch (Exception ex)
            {
                MessageBox.Show(FindForm(), ex.Message, "字符串配置无效", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
    }

    internal sealed class DisplayStringRow : UserControl
    {
        private readonly Label _index;
        private readonly TextBox _text;
        private readonly NumericField _textSize;
        private readonly ColorPickerBox _textBack;
        private readonly ColorPickerBox _textFore;
        private readonly ColorPickerBox _background;
        private readonly NumericField _x;
        private readonly NumericField _y;
        private readonly CheckBox _clear;
        private readonly ModernButton _remove;
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
            Label textLabel = Ui.Label("文本（不能包含双引号）", 8.5F, FontStyle.Regular, Ui.Muted);
            textLabel.Location = new Point(55, 10);
            Controls.Add(textLabel);
            _text = Ui.TextBox("Your custom text", false);
            _text.Location = new Point(55, 33);
            _text.Height = 29;
            Controls.Add(_text);
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

        public string BuildProtocolItem()
        {
            string text = MainForm.ValidateProtocolText(_text.Text, true);
            return "\"" + text + "\" " + _textSize.Value.ToString("X", CultureInfo.InvariantCulture) + " " + _textBack.Value.ToString("X", CultureInfo.InvariantCulture) + " " + _textFore.Value.ToString("X", CultureInfo.InvariantCulture) + " " + ((ulong)_background.Value).ToString("X", CultureInfo.InvariantCulture) + " " + _x.Value.ToString("X", CultureInfo.InvariantCulture) + " " + _y.Value.ToString("X", CultureInfo.InvariantCulture) + " " + (_clear.Checked ? "1" : "0");
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

        private void LayoutRow()
        {
            _remove.Location = new Point(Width - 47, 31);
            _text.Width = Math.Max(250, Width - 118);
            int available = Width - 110;
            if (available > 850)
            {
                int gap = Math.Max(8, (available - 795) / 2);
                _textBack.Left = 55;
                _textFore.Left = 55 + 265 + gap;
                _background.Left = _textFore.Left + 265 + gap;
            }
        }
    }
}
