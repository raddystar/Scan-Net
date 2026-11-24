using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace NetScanner
{
    public partial class ScannerForm : Form
    {
        private TextBox _txtStartIp = new() { Width = 115 };
        private TextBox _txtEndIp = new() { Width = 115 };
        private ComboBox _cmbPortPreset = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 155 }; private CheckBox _chkHostname = new() { Text = "Hostnames", Checked = true, AutoSize = true, Margin = new Padding(4, 6, 2, 0) }; private CheckBox _chkMac = new() { Text = "MAC/Vendor", Checked = true, AutoSize = true, Margin = new Padding(4, 6, 2, 0) }; private CheckBox _chkPorts = new() { Text = "Open Ports", Checked = true, AutoSize = true, Margin = new Padding(4, 6, 2, 0) }; private CheckBox _chkShares = new() { Text = "Shares", Checked = false, AutoSize = true, Margin = new Padding(4, 6, 4, 0) };
        private Button _btnScan = new() { Text = "Start Scan", Width = 100, Height = 30, BackColor = Color.FromArgb(25, 135, 84), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
        private Button _btnStop = new() { Text = "Stop", Width = 65, Height = 30, Enabled = false, BackColor = Color.FromArgb(220, 53, 69), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
        private Button _btnWol = new() { Text = "Wake-on-LAN", Width = 115, Height = 30, BackColor = Color.FromArgb(13, 110, 253), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
        private Button _btnExport = new() { Text = "Export CSV", Width = 95, Height = 30 };
        private ProgressBar _progress = new() { Width = 140, Height = 22 };
        private Label _lblStatus = new() { AutoSize = true, Text = "Ready", Margin = new Padding(8, 7, 0, 0) };

        private DataGridView _gridDevices = new();
        private DataTable _dtDevices = new();

        private ComboBox _cmbAdapters = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 260 };
        private Label _lblDownSpeed = new() { AutoSize = true, Font = new Font("Segoe UI", 9.5F, FontStyle.Bold), ForeColor = Color.FromArgb(13, 110, 253), Text = "PC Down: 0.0 KB/s (0.00 Mbps)" };
        private Label _lblUpSpeed = new() { AutoSize = true, Font = new Font("Segoe UI", 9.5F, FontStyle.Bold), ForeColor = Color.FromArgb(25, 135, 84), Text = "PC Up: 0.0 KB/s (0.00 Mbps)" };
        private Label _lblTotals = new() { AutoSize = true, ForeColor = Color.DimGray, Text = "RX: 0 MB | TX: 0 MB" };

        private CheckBox _chkSnmp = new() { Text = "OPNsense SNMP:", AutoSize = true, Margin = new Padding(0, 5, 4, 0) };
        private TextBox _txtSnmpIp = new() { Width = 110, Text = "192.168.1.1" };
        private TextBox _txtSnmpComm = new() { Width = 80, Text = "public" };
        private NumericUpDown _numSnmpIf = new() { Width = 48, Minimum = 1, Maximum = 64, Value = 1 };
        private Label _lblSnmpSpeed = new() { AutoSize = true, Font = new Font("Segoe UI", 9.5F, FontStyle.Bold), ForeColor = Color.FromArgb(102, 16, 242), Text = "Router WAN: Idle" };

        private System.Windows.Forms.Timer _bwTimer = new() { Interval = 1000 };
        private long _lastBytesRx = 0, _lastBytesTx = 0, _startBytesRx = 0, _startBytesTx = 0;
        private uint _lastSnmpIn = 0, _lastSnmpOut = 0;
        private bool _hasSnmpBaseline = false;
        private CancellationTokenSource? _cts;

        public ScannerForm()
        {
            Text = "Portable LAN Scanner, WoL & OPNsense SNMP Monitor";
            Size = new Size(1380, 810);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Segoe UI", 9.5F);

            InitTable();
            BuildLayout();
            Shown += async (s, e) => { await Task.Run(() => Invoke(DetectDefaultSubnet)); LoadNetworkAdapters(); };

            _bwTimer.Tick += BwTimer_Tick;
            _bwTimer.Start();
        }

        private void InitTable()
        {
            _dtDevices.Columns.Add("IP Address", typeof(string));
            _dtDevices.Columns.Add("Hostname", typeof(string));
            _dtDevices.Columns.Add("MAC Address", typeof(string));
            _dtDevices.Columns.Add("Vendor", typeof(string));
            _dtDevices.Columns.Add("Ping (ms)", typeof(int));
            _dtDevices.Columns.Add("Open Ports", typeof(string));
            _dtDevices.Columns.Add("Network Shares", typeof(string));
        }

        private void BuildLayout()
        {
            var topBar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 88, Padding = new Padding(8), BackColor = Color.FromArgb(245, 247, 250) };
            _cmbPortPreset.Items.AddRange(new object[] { "All Ports (Cam/POS/PC)", "Standard Business", "Cameras & NVR", "POS & Printers" });
            _cmbPortPreset.SelectedIndex = 0;

            topBar.Controls.Add(new Label { Text = "Start:", AutoSize = true, Margin = new Padding(0, 6, 2, 0) });
            topBar.Controls.Add(_txtStartIp);
            topBar.Controls.Add(new Label { Text = "End:", AutoSize = true, Margin = new Padding(6, 6, 2, 0) });
            topBar.Controls.Add(_txtEndIp);
            topBar.Controls.Add(_chkHostname); topBar.Controls.Add(_chkMac); topBar.Controls.Add(_chkPorts); topBar.Controls.Add(_cmbPortPreset); topBar.Controls.Add(_chkShares); topBar.SetFlowBreak(_chkShares, true);
            topBar.Controls.Add(_btnScan);
            topBar.Controls.Add(_btnStop);
            topBar.Controls.Add(_btnWol);
            topBar.Controls.Add(_btnExport);
            topBar.Controls.Add(_progress);
            topBar.Controls.Add(_lblStatus);

            _btnScan.Click += async (s, e) => await StartScanAsync();
            _btnStop.Click += (s, e) => _cts?.Cancel();
            _btnWol.Click += (s, e) => OpenWolDialog();
            _btnExport.Click += (s, e) => ExportCsv();

            var bottomContainer = new Panel { Dock = DockStyle.Bottom, Height = 82, BackColor = Color.FromArgb(240, 244, 248) };

            var pcRow = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 40, Padding = new Padding(8, 6, 8, 2) };
            pcRow.Controls.Add(new Label { Text = "Local Adapter:", AutoSize = true, Margin = new Padding(0, 5, 4, 0) });
            pcRow.Controls.Add(_cmbAdapters);
            pcRow.Controls.Add(new Label { Text = "  |  ", AutoSize = true, Margin = new Padding(0, 5, 0, 0) });
            pcRow.Controls.Add(_lblDownSpeed);
            pcRow.Controls.Add(new Label { Text = "  |  ", AutoSize = true, Margin = new Padding(0, 5, 0, 0) });
            pcRow.Controls.Add(_lblUpSpeed);
            pcRow.Controls.Add(new Label { Text = "  |  ", AutoSize = true, Margin = new Padding(0, 5, 0, 0) });
            pcRow.Controls.Add(_lblTotals);

            var snmpRow = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 40, Padding = new Padding(8, 4, 8, 6) };
            snmpRow.Controls.Add(_chkSnmp);
            snmpRow.Controls.Add(new Label { Text = "Router IP:", AutoSize = true, Margin = new Padding(4, 5, 2, 0) });
            snmpRow.Controls.Add(_txtSnmpIp);
            snmpRow.Controls.Add(new Label { Text = "Community:", AutoSize = true, Margin = new Padding(6, 5, 2, 0) });
            snmpRow.Controls.Add(_txtSnmpComm);
            snmpRow.Controls.Add(new Label { Text = "IfIndex:", AutoSize = true, Margin = new Padding(6, 5, 2, 0) });
            snmpRow.Controls.Add(_numSnmpIf);
            snmpRow.Controls.Add(new Label { Text = "  |  ", AutoSize = true, Margin = new Padding(0, 5, 0, 0) });
            snmpRow.Controls.Add(_lblSnmpSpeed);

            _cmbAdapters.SelectedIndexChanged += (s, e) => ResetAdapterCounters();
            _chkSnmp.CheckedChanged += (s, e) => { _hasSnmpBaseline = false; if (!_chkSnmp.Checked) _lblSnmpSpeed.Text = "Router WAN: Idle"; };
            _numSnmpIf.ValueChanged += (s, e) => _hasSnmpBaseline = false;

            bottomContainer.Controls.Add(pcRow);
            bottomContainer.Controls.Add(snmpRow);

            _gridDevices.Dock = DockStyle.Fill;
            _gridDevices.DataSource = _dtDevices;
            _gridDevices.ReadOnly = true;
            _gridDevices.AllowUserToAddRows = false;
            _gridDevices.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            _gridDevices.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            _gridDevices.BackgroundColor = Color.White;
            _gridDevices.RowHeadersVisible = false;
            _gridDevices.CellDoubleClick += GridDevices_CellDoubleClick;

            var ctx = new ContextMenuStrip();
            ctx.Items.Add("Wake-on-LAN (Save & Wake Device)", null, (s, e) => WakeSelectedRow());
            ctx.Items.Add("Open Network Shares (\\\\IP)", null, (s, e) => OpenSelectedShares());
            ctx.Items.Add("Copy IP & MAC Address", null, (s, e) => CopySelectedRow());
            _gridDevices.ContextMenuStrip = ctx;

            Controls.Add(_gridDevices);
            Controls.Add(topBar);
            Controls.Add(bottomContainer); _gridDevices.BringToFront();
        }

        private void GridDevices_CellDoubleClick(object? sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0) return;
            string shares = _gridDevices.Rows[e.RowIndex].Cells["Network Shares"].Value?.ToString() ?? "";
            if (!string.IsNullOrWhiteSpace(shares) && shares != "None") OpenSelectedShares();
            else CopySelectedRow();
        }

        private void OpenSelectedShares()
        {
            if (_gridDevices.SelectedRows.Count == 0) return;
            string ip = _gridDevices.SelectedRows.Cast<DataGridViewRow>().First().Cells["IP Address"].Value?.ToString() ?? "";
            if (!string.IsNullOrEmpty(ip)) Process.Start("explorer.exe", $"\\\\{ip}");
        }

        private void CopySelectedRow()
        {
            if (_gridDevices.SelectedRows.Count == 0) return;
            var r = _gridDevices.SelectedRows.Cast<DataGridViewRow>().First();
            Clipboard.SetText($"{r.Cells["IP Address"].Value} | {r.Cells["Hostname"].Value} | {r.Cells["MAC Address"].Value}");
        }
    }
}





