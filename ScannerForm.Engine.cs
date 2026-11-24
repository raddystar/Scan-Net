using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
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
    public partial class ScannerForm
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(uint DestIP, uint SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);

        private string WolFile => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "wol_devices.csv");

        private static readonly (int Port, string Name)[] StandardPorts = new[]
        {
            (21, "FTP"), (22, "SSH"), (53, "DNS"), (80, "HTTP"), (135, "RPC"),
            (139, "NetBIOS"), (443, "HTTPS"), (445, "SMB"), (3389, "RDP"), (5900, "VNC"), (8080, "HTTP-Alt"), (8443, "HTTPS-Alt")
        };

        private static readonly (int Port, string Name)[] CameraPorts = new[]
        {
            (80, "WebUI"), (443, "HTTPS"), (554, "RTSP"), (8000, "Hikvision"), (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"), (34567, "XMeye-DVR"), (37777, "Dahua-NVR")
        };

        private static readonly (int Port, string Name)[] PosPorts = new[]
        {
            (80, "HTTP"), (443, "HTTPS"), (445, "SMB-Share"), (1433, "MSSQL"), (3306, "MySQL"), (5173, "AppWeb"), (8080, "POS-Web"), (9100, "ReceiptPrinter")
        };

        private (int Port, string Name)[] GetSelectedPorts() => _cmbPortPreset.SelectedIndex switch
        {
            1 => StandardPorts,
            2 => CameraPorts,
            3 => PosPorts,
            _ => StandardPorts.Concat(CameraPorts).Concat(PosPorts).DistinctBy(p => p.Port).ToArray()
        };

        private static readonly Dictionary<string, string> OuiVendors = new(StringComparer.OrdinalIgnoreCase)
        {
            ["00:50:56"] = "VMware", ["00:0C:29"] = "VMware", ["08:00:27"] = "VirtualBox",
            ["B8:27:EB"] = "Raspberry Pi", ["DC:A6:32"] = "Raspberry Pi", ["E4:5F:01"] = "Raspberry Pi",
            ["24:5A:4C"] = "Ubiquiti / UniFi", ["74:83:C2"] = "Ubiquiti / UniFi",
            ["FC:EC:DA"] = "Ubiquiti / UniFi", ["18:E8:29"] = "Ubiquiti / UniFi",
            ["78:8A:20"] = "Ubiquiti / UniFi", ["68:D7:9A"] = "Ubiquiti / UniFi",
            ["00:1B:63"] = "Apple", ["3C:22:FB"] = "Apple", ["F0:18:98"] = "Apple",
            ["00:14:22"] = "Dell", ["D4:BE:D9"] = "Dell",
            ["3C:D9:2B"] = "HP", ["00:1E:0B"] = "HP", ["98:E7:F4"] = "HP",
            ["28:D2:44"] = "Lenovo", ["54:EE:75"] = "Lenovo", ["00:15:5D"] = "Microsoft Hyper-V",
            ["44:19:B6"] = "Hikvision", ["C0:56:E3"] = "Hikvision", ["BC:AD:28"] = "Hikvision",
            ["3C:EF:8C"] = "Dahua", ["90:02:A9"] = "Dahua",
            ["00:1D:0F"] = "TP-Link", ["50:C7:BF"] = "TP-Link", ["C0:25:E9"] = "TP-Link",
            ["00:E0:4C"] = "Realtek", ["00:1B:21"] = "Intel", ["3C:97:0E"] = "Intel", ["8C:8D:28"] = "Intel"
        };

        private void DetectDefaultSubnet()
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var ipProp = ni.GetIPProperties();
                if (ipProp.GatewayAddresses.Count == 0) continue;

                foreach (var ua in ipProp.UnicastAddresses)
                {
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        byte[] b = ua.Address.GetAddressBytes();
                        _txtStartIp.Text = $"{b.ElementAt(0)}.{b.ElementAt(1)}.{b.ElementAt(2)}.1";
                        _txtEndIp.Text = $"{b.ElementAt(0)}.{b.ElementAt(1)}.{b.ElementAt(2)}.254";
                        _txtSnmpIp.Text = ipProp.GatewayAddresses.First().Address.ToString();
                        return;
                    }
                }
            }
            _txtStartIp.Text = "192.168.1.1";
            _txtEndIp.Text = "192.168.1.254";
        }

        private void LoadNetworkAdapters()
        {
            _cmbAdapters.Items.Clear();
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus == OperationalStatus.Up && ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    _cmbAdapters.Items.Add(new AdapterItem(ni));
            }
            if (_cmbAdapters.Items.Count > 0) _cmbAdapters.SelectedIndex = 0;
        }

        private void ResetAdapterCounters()
        {
            if (_cmbAdapters.SelectedItem is not AdapterItem item) return;
            var stats = item.Interface.GetIPStatistics();
            _startBytesRx = _lastBytesRx = stats.BytesReceived;
            _startBytesTx = _lastBytesTx = stats.BytesSent;
        }

        private bool _snmpBusy = false; private async void BwTimer_Tick(object? sender, EventArgs e)
        {
            if (_cmbAdapters.SelectedItem is AdapterItem item)
            {
                try
                {
                    var stats = item.Interface.GetIPStatistics();
                    long rxDiff = Math.Max(0, stats.BytesReceived - _lastBytesRx);
                    long txDiff = Math.Max(0, stats.BytesSent - _lastBytesTx);
                    _lastBytesRx = stats.BytesReceived;
                    _lastBytesTx = stats.BytesSent;

                    double downKBs = rxDiff / 1024.0;
                    double upKBs = txDiff / 1024.0;
                    double downMbps = (rxDiff * 8.0) / 1_000_000.0;
                    double upMbps = (txDiff * 8.0) / 1_000_000.0;

                    double totalRxMb = (stats.BytesReceived - _startBytesRx) / (1024.0 * 1024.0);
                    double totalTxMb = (stats.BytesSent - _startBytesTx) / (1024.0 * 1024.0);

                    _lblDownSpeed.Text = $"PC Down: {downKBs:F1} KB/s ({downMbps:F2} Mbps)";
                    _lblUpSpeed.Text = $"PC Up: {upKBs:F1} KB/s ({upMbps:F2} Mbps)";
                    _lblTotals.Text = $"RX: {totalRxMb:F1} MB | TX: {totalTxMb:F1} MB";
                }
                catch { }
            }
            if (_chkSnmp.Checked && !_snmpBusy) { _snmpBusy = true; try { await PollSnmpRouterAsync(); } finally { _snmpBusy = false; } }
        }





        private async Task PollSnmpRouterAsync() { try { string ip = _txtSnmpIp.Text.Trim(); string comm = _txtSnmpComm.Text.Trim(); int idx = (int)_numSnmpIf.Value; uint inOct = await Task.Run(() => SnmpGetCounter32(ip, comm, new int[] { 1, 3, 6, 1, 2, 1, 2, 2, 1, 10, idx })); uint outOct = await Task.Run(() => SnmpGetCounter32(ip, comm, new int[] { 1, 3, 6, 1, 2, 1, 2, 2, 1, 16, idx })); if (!_hasSnmpBaseline) { _lastSnmpIn = inOct; _lastSnmpOut = outOct; _hasSnmpBaseline = true; _lblSnmpSpeed.Text = "Router: Syncing..."; return; } uint rx = inOct >= _lastSnmpIn ? inOct - _lastSnmpIn : (uint.MaxValue - _lastSnmpIn + inOct); uint tx = outOct >= _lastSnmpOut ? outOct - _lastSnmpOut : (uint.MaxValue - _lastSnmpOut + outOct); _lastSnmpIn = inOct; _lastSnmpOut = outOct; _lblSnmpSpeed.Text = $"Router If#{idx} Down: {(rx * 8.0) / 1_000_000.0:F2} Mbps | Up: {(tx * 8.0) / 1_000_000.0:F2} Mbps"; } catch { _lblSnmpSpeed.Text = "Router SNMP: No Response"; } }
        private static uint SnmpGetCounter32(string ip, string comm, int[] oid) { var ob = new List<byte> { (byte)(oid.ElementAt(0) * 40 + oid.ElementAt(1)) }; for (int i = 2; i < oid.Length; i++) { int v = oid.ElementAt(i); if (v < 128) ob.Add((byte)v); else { ob.Add((byte)((v >> 7) | 0x80)); ob.Add((byte)(v & 0x7F)); } } var vb = new List<byte> { 0x06, (byte)ob.Count }; vb.AddRange(ob); vb.AddRange(new byte[] { 0x05, 0x00 }); var vbl = WrapTlv(0x30, WrapTlv(0x30, vb)); var pb = new List<byte> { 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00 }; pb.AddRange(vbl); var pdu = WrapTlv(0xA0, pb); byte[] cb = Encoding.ASCII.GetBytes(comm); var mb = new List<byte> { 0x02, 0x01, 0x01, 0x04, (byte)cb.Length }; mb.AddRange(cb); mb.AddRange(pdu); byte[] pkt = WrapTlv(0x30, mb).ToArray(); using var udp = new UdpClient(); udp.Client.ReceiveTimeout = 500; udp.Send(pkt, pkt.Length, ip, 161); IPEndPoint ep = new(IPAddress.Any, 0); byte[] r = udp.Receive(ref ep); for (int i = r.Length - 6; i >= 0; i--) { if ((r.ElementAt(i) == 0x41 || r.ElementAt(i) == 0x02) && r.ElementAt(i + 1) >= 1 && r.ElementAt(i + 1) <= 5) { int len = r.ElementAt(i + 1); uint val = 0; for (int j = 0; j < len; j++) val = (val << 8) | r.ElementAt(i + 2 + j); return val; } } return 0; }
        private static List<byte> WrapTlv(byte tag, List<byte> c) { var r = new List<byte> { tag, (byte)c.Count }; r.AddRange(c); return r; }
        private async Task StartScanAsync() { if (!IPAddress.TryParse(_txtStartIp.Text.Trim(), out var sIp) || !IPAddress.TryParse(_txtEndIp.Text.Trim(), out var eIp)) { MessageBox.Show("Invalid IP range."); return; } uint start = IpToUint(sIp), end = IpToUint(eIp); if (end < start || (end - start) > 2048) { MessageBox.Show("Range must be <= 2048 IPs."); return; } var ports = GetSelectedPorts(); bool doHost = _chkHostname.Checked, doMac = _chkMac.Checked, doPorts = _chkPorts.Checked, doShares = _chkShares.Checked; _dtDevices.Rows.Clear(); _btnScan.Enabled = false; _btnStop.Enabled = true; _cts = new CancellationTokenSource(); var tok = _cts.Token; var sw = Stopwatch.StartNew(); int total = (int)(end - start + 1), done = 0; _progress.Maximum = total; _progress.Value = 0; var ips = Enumerable.Range(0, total).Select(i => UintToIp(start + (uint)i)).ToList(); using var sem = new SemaphoreSlim(64); var tasks = ips.Select(async ip => { await sem.WaitAsync(tok); try { if (tok.IsCancellationRequested) return; var res = await ProbeHostAsync(ip, ports, doHost, doMac, doPorts, doShares, tok); if (res != null) BeginInvoke(() => _dtDevices.Rows.Add(res.Ip, res.Hostname, res.Mac, res.Vendor, res.PingMs, res.OpenPorts, res.Shares)); } catch { } finally { int c = Interlocked.Increment(ref done); if (!IsDisposed) BeginInvoke(() => { _progress.Value = Math.Min(c, _progress.Maximum); _lblStatus.Text = $"Scanning {c}/{total} ({sw.Elapsed.TotalSeconds:F1}s)..."; }); sem.Release(); } }); try { await Task.WhenAll(tasks); } catch { } sw.Stop(); _btnScan.Enabled = true; _btnStop.Enabled = false; _lblStatus.Text = $"Done in {sw.Elapsed.TotalSeconds:F2}s - {_dtDevices.Rows.Count} active devices found."; }
        private static async Task<HostResult?> ProbeHostAsync(IPAddress ip, (int Port, string Name)[] ports, bool doHost, bool doMac, bool doPorts, bool doShares, CancellationToken tok) { string ipStr = ip.ToString(); int pingMs = -1; try { using var p = new Ping(); var rep = await p.SendPingAsync(ip, 220); if (rep.Status == IPStatus.Success) pingMs = (int)rep.RoundtripTime; } catch { } string mac = doMac ? await Task.Run(() => GetMacViaArp(ip)) : ""; if (pingMs < 0 && string.IsNullOrEmpty(mac)) return null; var open = new ConcurrentBag<(int Port, string Name)>(); if (doPorts) { await Task.WhenAll(ports.Select(async p => { if (await IsPortOpenAsync(ipStr, p.Port, 160, tok)) open.Add(p); })); } var sorted = open.OrderBy(x => x.Port).ToList(); string portsStr = !doPorts ? "Skipped" : (sorted.Count > 0 ? string.Join(", ", sorted.Select(p => $"{p.Port}({p.Name})")) : "None"); string host = !doHost ? "Skipped" : "-"; if (doHost) { try { var ent = await Dns.GetHostEntryAsync(ipStr).WaitAsync(TimeSpan.FromMilliseconds(300), tok); if (!string.IsNullOrWhiteSpace(ent.HostName)) host = ent.HostName; } catch { } } string shares = !doShares ? "Skipped" : ((!doPorts || sorted.Any(p => p.Port == 445 || p.Port == 139)) ? await Task.Run(() => GetSmbShares(ipStr)) : "None"); return new HostResult(ipStr, host, !doMac ? "Skipped" : (string.IsNullOrEmpty(mac) ? "Local / Routed" : mac), !doMac ? "-" : LookupVendor(mac), pingMs < 0 ? 0 : pingMs, portsStr, shares); }
        private static async Task<bool> IsPortOpenAsync(string ip, int port, int ms, CancellationToken tok) { try { using var tcp = new TcpClient(); using var cts = CancellationTokenSource.CreateLinkedTokenSource(tok); cts.CancelAfter(ms); await tcp.ConnectAsync(ip, port, cts.Token); return true; } catch { return false; } }
        private static string GetMacViaArp(IPAddress ip) { try { uint dest = BitConverter.ToUInt32(ip.GetAddressBytes(), 0); byte[] mac = (byte[])Array.CreateInstance(typeof(byte), 6); uint len = 6; if (SendARP(dest, 0, mac, ref len) == 0) return string.Join(":", mac.Take((int)len).Select(b => b.ToString("X2"))); } catch { } return ""; }
        private static string LookupVendor(string mac) => (string.IsNullOrEmpty(mac) || mac.Length < 8) ? "-" : (OuiVendors.TryGetValue(mac.Substring(0, 8), out string? v) ? v : "Unknown");
        private static string GetSmbShares(string ip) { try { var psi = new ProcessStartInfo("net", $"view \\\\{ip}") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true }; using var p = Process.Start(psi); if (p == null) return "None"; string outTxt = p.StandardOutput.ReadToEnd(); p.WaitForExit(1000); var list = new List<string>(); foreach (var line in outTxt.Split(new[] { (char)13, (char)10 }, StringSplitOptions.RemoveEmptyEntries)) { if (line.Contains("Disk", StringComparison.OrdinalIgnoreCase)) { string name = Regex.Split(line.Trim(), @"\s{2,}").First(); if (!string.IsNullOrWhiteSpace(name)) list.Add(name); } } return list.Count > 0 ? string.Join(", ", list) : "SMB Active (Auth Required)"; } catch { return "None"; } }
        private void WakeSelectedRow() { if (_gridDevices.SelectedRows.Count == 0) return; var r = _gridDevices.SelectedRows.Cast<DataGridViewRow>().First(); string mac = r.Cells["MAC Address"].Value?.ToString() ?? ""; string name = r.Cells["Hostname"].Value?.ToString() ?? "Office PC"; if (!mac.Contains((char)58)) { MessageBox.Show("No valid MAC on this row."); return; } SaveWolDevice(name, mac); SendMagicPacket(mac); MessageBox.Show($"WoL sent to {name} ({mac})!"); }
        private void OpenWolDialog() { string pMac = "", pName = "Office PC"; if (_gridDevices.SelectedRows.Count > 0) { var r = _gridDevices.SelectedRows.OfType<DataGridViewRow>().First(); pMac = r.Cells["MAC Address"].Value?.ToString() ?? ""; pName = r.Cells["Hostname"].Value?.ToString() ?? "Office PC"; } using var f = new Form { Width = 430, Height = 260, Text = "Wake-on-LAN", StartPosition = FormStartPosition.CenterParent, FormBorderStyle = FormBorderStyle.FixedDialog, MaximizeBox = false }; var cmb = new ComboBox { Left = 14, Top = 32, Width = 385, DropDownStyle = ComboBoxStyle.DropDownList }; var tName = new TextBox { Left = 14, Top = 84, Width = 180, Text = pName }; var tMac = new TextBox { Left = 204, Top = 84, Width = 195, Text = pMac.Contains((char)58) ? pMac : "" }; var bWake = new Button { Text = "Send Magic Packet", Left = 14, Top = 130, Width = 210, Height = 34, BackColor = Color.FromArgb(13, 110, 253), ForeColor = Color.White, FlatStyle = FlatStyle.Flat }; var bSave = new Button { Text = "Save & Wake", Left = 234, Top = 130, Width = 165, Height = 34 }; cmb.Items.Add("-- Saved Office PCs --"); if (File.Exists(WolFile)) foreach (var l in File.ReadAllLines(WolFile).Skip(1)) { var pt = l.Split((char)44); if (pt.Length >= 2) cmb.Items.Add($"{pt.ElementAt(0)} | {pt.ElementAt(1)}"); } cmb.SelectedIndex = 0; cmb.SelectedIndexChanged += (s, e) => { if (cmb.SelectedIndex > 0) { var pt = cmb.Text.Split((char)124); tName.Text = pt.ElementAt(0).Trim(); tMac.Text = pt.ElementAt(1).Trim(); } }; bWake.Click += (s, e) => { if (SendMagicPacket(tMac.Text)) MessageBox.Show($"WoL sent to {tMac.Text}!"); }; bSave.Click += (s, e) => { if (SendMagicPacket(tMac.Text)) { SaveWolDevice(tName.Text, tMac.Text); MessageBox.Show($"Saved & sent WoL to {tName.Text}!"); } }; f.Controls.AddRange(new Control[] { new Label { Left = 14, Top = 12, Width = 380, Text = "Saved PCs or enter MAC:" }, cmb, new Label { Left = 14, Top = 64, Width = 170, Text = "Label:" }, tName, new Label { Left = 204, Top = 64, Width = 180, Text = "MAC:" }, tMac, bWake, bSave }); f.ShowDialog(); }
        private void SaveWolDevice(string name, string mac) { if (!File.Exists(WolFile)) File.WriteAllText(WolFile, "Name,MAC\r\n"); if (!File.ReadAllLines(WolFile).Any(l => l.Contains(mac, StringComparison.OrdinalIgnoreCase))) File.AppendAllText(WolFile, $"{name.Replace(",", " ")},{mac.Trim()}\r\n"); }
        private static bool SendMagicPacket(string macInput) { string clean = Regex.Replace(macInput ?? "", "[^0-9A-Fa-f]", ""); if (clean.Length != 12) { MessageBox.Show("Invalid MAC address."); return false; } byte[] mac = Enumerable.Range(0, 6).Select(i => Convert.ToByte(clean.Substring(i * 2, 2), 16)).ToArray(); byte[] pkt = (byte[])Array.CreateInstance(typeof(byte), 102); for (int i = 0; i < 6; i++) pkt.SetValue((byte)0xFF, i); for (int i = 1; i <= 16; i++) Buffer.BlockCopy(mac, 0, pkt, i * 6, 6); using var udp = new UdpClient { EnableBroadcast = true }; udp.Send(pkt, pkt.Length, new IPEndPoint(IPAddress.Broadcast, 9)); return true; }
        private void ExportCsv() { using var sfd = new SaveFileDialog { Filter = "CSV (.csv)|.csv", FileName = $"NetScan_{DateTime.Now:yyyyMMdd_HHmm}.csv" }; if (sfd.ShowDialog() != DialogResult.OK) return; var sb = new StringBuilder(); string q = ((char)34).ToString(); var cols = _dtDevices.Columns.OfType<DataColumn>().ToList(); sb.AppendLine(string.Join(",", cols.Select(c => q + c.ColumnName + q))); foreach (DataRow r in _dtDevices.Rows) sb.AppendLine(string.Join(",", cols.Select(c => q + (r[c]?.ToString() ?? "").Replace(q, q + q) + q))); File.WriteAllText(sfd.FileName, sb.ToString(), Encoding.UTF8); MessageBox.Show("Exported CSV!"); }
        private static uint IpToUint(IPAddress ip) { byte[] b = ip.GetAddressBytes(); return ((uint)b.ElementAt(0) << 24) | ((uint)b.ElementAt(1) << 16) | ((uint)b.ElementAt(2) << 8) | b.ElementAt(3); } private static IPAddress UintToIp(uint v) => new IPAddress(new byte[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v }); private sealed record HostResult(string Ip, string Hostname, string Mac, string Vendor, int PingMs, string OpenPorts, string Shares); private sealed record AdapterItem(NetworkInterface Interface) { public override string ToString() => $"{Interface.Name} ({Interface.Description})"; } } }

