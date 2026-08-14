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
                Environment.Exit(1);
            }
            byte[] sysFileContent = new byte[] {
	            //填入你的驱动文件，如0x4D, 0x5A......
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

    internal delegate void CommandRequestHandler(string command, string successMessage);

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
        private Panel _content;
        private Label _statusLabel;
        private Panel _statusDot;

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

            Label logo = Ui.Label("BSOD", 18F, FontStyle.Bold, Ui.Text);
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
            Label appTitle = Ui.Label("BSOD", 11F, FontStyle.Bold, Ui.Text);
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
            AddPage("change", new ChangeTextPage(SendCommand));
            AddPage("display", new DisplayStringsPage(SendCommand));
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
            TextBox text = Ui.TextBox("CUSTOM_STOP_CODE", false);
            text.Location = new Point(22, 91);
            text.Size = new Size(610, 31);
            card.Controls.Add(text);
            ModernButton send = new ModernButton { Text = "应用终止代码", Location = new Point(22, 154), Size = new Size(142, 40) };
            send.Click += delegate
            {
                string value = ValidateProtocolText(text.Text, false);
                SendCommand("SP " + value, "终止代码已设置");
            };
            card.Controls.Add(send);
            page.AddCard(card);
            return page;
        }

        private PageView BuildColorsPage()
        {
            PageView page = new PageView("颜色", "使用调色板或直接输入 8 位 ARGB 十六进制值");
            CardPanel background = new CardPanel { Height = 184 };
            Label bTitle = Ui.Label("背景颜色", 13F, FontStyle.Bold, Ui.Text);
            bTitle.Location = new Point(22, 18);
            background.Controls.Add(bTitle);
            ColorPickerBox bg = new ColorPickerBox("屏幕背景 ARGB", 0xFF0078D4u) { Location = new Point(22, 57) };
            background.Controls.Add(bg);
            ModernButton bgSend = new ModernButton { Text = "应用背景色", Location = new Point(320, 81), Size = new Size(128, 38) };
            bgSend.Click += delegate { SendCommand("CR " + ((ulong)bg.Value).ToString(CultureInfo.InvariantCulture), "背景色已设置"); };
            background.Controls.Add(bgSend);
            page.AddCard(background);

            CardPanel textColors = new CardPanel { Height = 200 };
            Label tTitle = Ui.Label("文字颜色", 13F, FontStyle.Bold, Ui.Text);
            tTitle.Location = new Point(22, 18);
            textColors.Controls.Add(tTitle);
            ColorPickerBox tb = new ColorPickerBox("文字背景 ARGB", 0x00000000u) { Location = new Point(22, 58) };
            ColorPickerBox tf = new ColorPickerBox("文字前景 ARGB", 0xFFFFFFFFu) { Location = new Point(306, 58) };
            textColors.Controls.Add(tb);
            textColors.Controls.Add(tf);
            ModernButton textSend = new ModernButton { Text = "应用文字颜色", Location = new Point(610, 82), Size = new Size(142, 38) };
            textSend.Click += delegate
            {
                SendCommand("CC " + tb.Value.ToString(CultureInfo.InvariantCulture) + " " + tf.Value.ToString(CultureInfo.InvariantCulture), "文字颜色已设置");
            };
            textColors.Controls.Add(textSend);
            page.AddCard(textColors);

            CardPanel win7 = new CardPanel { Height = 224 };
            Label wTitle = Ui.Label("Windows 7 修改颜色 (与上面不兼容)", 13F, FontStyle.Bold, Ui.Text);
            wTitle.Location = new Point(22, 18);
            win7.Controls.Add(wTitle);
            ColorPickerBox wf = new ColorPickerBox("前景色", 0xFFFFFFFFu) { Location = new Point(22, 53) };
            ColorPickerBox wb = new ColorPickerBox("背景色", 0xFF0000AAu) { Location = new Point(306, 53) };
            win7.Controls.Add(wf);
            win7.Controls.Add(wb);
            ModernButton wSend = new ModernButton { Text = "引用 Win7 配色", Location = new Point(610, 78), Size = new Size(150, 38) };
            wSend.Click += delegate
            {
                SendCommand("C7 " + wf.VgaDacValue.ToString(CultureInfo.InvariantCulture) + " " + wb.VgaDacValue.ToString(CultureInfo.InvariantCulture), "Windows 7 配色回调已注册");
            };
            win7.Controls.Add(wSend);
            page.AddCard(win7);
            return page;
        }

        private PageView BuildEffectsPage()
        {
            PageView page = new PageView("特效与触发", "这些操作会改变崩溃显示流程，危险操作会再次确认");
            CardPanel win7 = new CardPanel { Height = 176 };
            Label title = Ui.Label("Windows 7 彩色蓝屏", 13F, FontStyle.Bold, Ui.Text);
            title.Location = new Point(22, 18);
            win7.Controls.Add(title);
            Label desc = Ui.Label("R7 注册蓝屏回调，让Windows 7实现彩色蓝屏", 9F, FontStyle.Regular, Ui.Muted);
            desc.Location = new Point(22, 52);
            win7.Controls.Add(desc);
            ModernButton r7 = new ModernButton { Text = "注册", Location = new Point(22, 102), Size = new Size(118, 38) };
            r7.Click += delegate { SendCommand("R7", "Windows 7 蓝屏回调已注册"); };
            win7.Controls.Add(r7);
            page.AddCard(win7);

            CardPanel rainbow = new CardPanel { Height = 188, BackColor = Ui.SoftPurple };
            Label rTitle = Ui.Label("高版本彩色蓝屏", 13F, FontStyle.Bold, Ui.Text);
            rTitle.Location = new Point(22, 18);
            rainbow.Controls.Add(rTitle);
            Label rDesc = Ui.Label("驱动将反复调用蓝屏绘制函数来达到彩色蓝屏", 9F, FontStyle.Regular, Ui.Muted);
            rDesc.Location = new Point(22, 52);
            rDesc.MaximumSize = new Size(900, 0);
            rainbow.Controls.Add(rDesc);
            ModernButton rd = new ModernButton { Text = "启动动态彩虹", Location = new Point(22, 119), Size = new Size(148, 40), BaseColor = Color.FromArgb(126, 79, 160) };
            rd.Click += delegate { SendCommand("RD", "如果你看到了这条消息，说明驱动运行失败了"); };
            rainbow.Controls.Add(rd);
            page.AddCard(rainbow);

            CardPanel crash = new CardPanel { Height = 188, BackColor = Ui.SoftRed };
            Label cTitle = Ui.Label("主动 BugCheck", 13F, FontStyle.Bold, Ui.Red);
            cTitle.Location = new Point(22, 18);
            crash.Controls.Add(cTitle);
            Label cDesc = Ui.Label("立即触发蓝屏", 9F, FontStyle.Regular, Ui.Text);
            cDesc.Location = new Point(22, 52);
            crash.Controls.Add(cDesc);
            ModernButton bc = new ModernButton { Text = "触发蓝屏", Location = new Point(22, 119), Size = new Size(126, 40), BaseColor = Color.FromArgb(181, 61, 78) };
            bc.Click += delegate { SendCommand("BC", "如果你看到了这条消息，说明驱动运行失败了"); };
            crash.Controls.Add(bc);
            page.AddCard(crash);
            return page;
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
                    _client.Send(cmd.Trim());
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
            try
            {
                if (MessageBox.Show($"是否发送此条命令？\n{command}", "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.No) return;
                _client.Send(command);
                SetDeviceStatus(true, "驱动已连接");
                MessageBox.Show(this, successMessage, "命令已发送", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                SetDeviceStatus(false, "发送失败");
                MessageBox.Show(this, BuildDeviceError(ex), "命令发送失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
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

    internal sealed class ChangeTextPage : PageView
    {
        private readonly FlowLayoutPanel _rows;
        private readonly Label _count;
        private readonly CheckBox _skipPercent;
        private readonly CommandRequestHandler _send;
        private readonly List<ChangeTextRow> _items = new List<ChangeTextRow>();

        public ChangeTextPage(CommandRequestHandler send) : base("替换文本", "按调用顺序替换蓝屏关键字符串；可配置 1–100 条")
        {
            _send = send;
            CardPanel card = new CardPanel { Height = 615 };
            Label title = Ui.Label("ChangeText · CT", 13F, FontStyle.Bold, Ui.Text);
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
            _count.Location = new Point(128, 536);
            card.Controls.Add(_count);
            ModernButton apply = new ModernButton { Text = "应用全部替换文本", Location = new Point(260, 524), Size = new Size(168, 42) };
            apply.Click += delegate { Apply(); };
            card.Controls.Add(apply);
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
                    if (i == 2 && Program.GetSystemVersion()[2] < 26100 && Program.GetSystemVersion()[0] <= 10) for (int j = 0; j < 101; j++) command.Append(" \"1\"");
                }
                _send(command.ToString(), "替换文本配置已设置\n");
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
            return "DS \"" + text + "\" " +
                   decimal.ToUInt32(_background.Value).ToString("X", CultureInfo.InvariantCulture) + " " +
                   decimal.ToUInt32(_foreground.Value).ToString("X", CultureInfo.InvariantCulture) + " " +
                   (_blink.Checked ? "1" : "0") + " " +
                   (_mode.Text.Contains("25") ? "1" : "0") + " " +
                   (_color.Checked ? "1" : "0");
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
                _compatibility.Text = "警告: 闪烁和 8–F 的 16 色亮背景互不兼容，超过7的会被显示为灰色!";
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
        private readonly bool _windows7 = IsWindows7();
        private FlowLayoutPanel _windows7Rows;
        private Windows7DisplayStringRow _windows7Row;

        public DisplayStringsPage(CommandRequestHandler send) : base("显示字符串", "一次定义多段字符串、字号、前后景色、坐标和清屏行为")
        {
            _send = send;
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
            AddCard(card);
            for (int i = 0; i < 5; i++) AddRow();
        }

        private static bool IsWindows7()
        {
            int[] version = Program.GetSystemVersion();
            return version.Length >= 2 && version[0] == 6 && version[1] == 1;
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

        private void Apply()
        {
            try
            {
                if (_windows7)
                {
                    if (_windows7Row.HasBlinkBrightBackgroundConflict)
                    {
                        DialogResult result = MessageBox.Show(
                            FindForm(),
                            "当前同时启用了闪烁和 8–F 亮色背景。Windows 7 文本模式中两者不能同时生效。\n\n仍要按当前参数发送吗？",
                            "闪烁与亮色背景不兼容",
                            MessageBoxButtons.YesNo,
                            MessageBoxIcon.Warning);
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
            return "\"" + text + "\" " +
                   _textSize.Value.ToString("X", CultureInfo.InvariantCulture) + " " +
                   _textBack.Value.ToString("X", CultureInfo.InvariantCulture) + " " +
                   _textFore.Value.ToString("X", CultureInfo.InvariantCulture) + " " +
                   ((ulong)_background.Value).ToString("X", CultureInfo.InvariantCulture) + " " +
                   _x.Value.ToString("X", CultureInfo.InvariantCulture) + " " +
                   _y.Value.ToString("X", CultureInfo.InvariantCulture) + " " +
                   (_clear.Checked ? "1" : "0");
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
