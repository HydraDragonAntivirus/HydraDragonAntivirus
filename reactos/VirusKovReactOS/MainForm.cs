using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace VirusKov.ReactOS
{
    /// <summary>
    /// Plain WinForms, built in code (no designer, no WPF): works on ReactOS, XP and,
    /// through dotnet9x, Windows 95/98/ME.
    /// </summary>
    public sealed class MainForm : Form
    {
        private readonly Settings settings;
        private readonly RealtimeMonitor realtime;
        private readonly NotifyIcon tray = new NotifyIcon();
        private bool exiting;

        // Scan tab
        private readonly ListBox lstTargets = new ListBox();
        private readonly ComboBox cmbDrives = new ComboBox();
        private readonly TextBox txtExclude = new TextBox();
        private readonly NumericUpDown numMaxMb = new NumericUpDown();
        private readonly CheckBox chkExeOnly = new CheckBox();
        private readonly Button btnAddFolderT = new Button(), btnAddFile = new Button(), btnRemoveT = new Button(), btnClearT = new Button(),
            btnAddDrive = new Button(), btnAllDrives = new Button(), btnQuickFolders = new Button();
        private readonly Button btnScan = new Button(), btnQuick = new Button(), btnFull = new Button(), btnStop = new Button();
        private readonly ProgressBar progress = new ProgressBar();
        private readonly Label lblScan = new Label();
        private readonly ListView lvResults = new ListView();
        private readonly Button btnQuarantineSel = new Button(), btnReport = new Button();
        private Scanner scanner;

        // Real-time tab
        private readonly CheckBox chkRealtime = new CheckBox(), chkAutoQ = new CheckBox();
        private readonly Label lblRealtime = new Label();
        private readonly ListBox lstFolders = new ListBox();
        private readonly Button btnAddFolder = new Button(), btnRemoveFolder = new Button();
        private readonly ListView lvEvents = new ListView();

        // Quarantine tab
        private readonly ListView lvQuarantine = new ListView();
        private readonly Button btnRestore = new Button(), btnDeleteQ = new Button(), btnRefreshQ = new Button();

        // Boot sector tab
        private readonly Label lblBoot = new Label();
        private readonly Button btnBootCheck = new Button(), btnBootBackup = new Button(), btnBootRestore = new Button();
        private readonly CheckBox chkTrack0 = new CheckBox();

        // Settings tab
        private readonly TextBox txtServer = new TextBox(), txtToken = new TextBox(), txtLog = new TextBox();
        private readonly CheckBox chkAutostart = new CheckBox();
        private readonly Button btnSave = new Button(), btnEula = new Button();

        private readonly TabControl tabs = new TabControl();
        private readonly TabPage tabScan = new TabPage("Scan"), tabRealtime = new TabPage("Real-time"),
            tabQuarantine = new TabPage("Quarantine"), tabBoot = new TabPage("Boot sector"), tabSettings = new TabPage("Settings");

        public MainForm(Settings settings, bool startMinimized)
        {
            this.settings = settings;
            realtime = new RealtimeMonitor(settings);
            realtime.ThreatFound += OnRealtimeThreat;

            Text = "VirusKov for ReactOS " + AppInfo.Version;
            ClientSize = new Size(760, 520);
            MinimumSize = new Size(640, 440);
            StartPosition = FormStartPosition.CenterScreen;
            Icon = SystemIcons.Application;

            tabs.Dock = DockStyle.Fill;
            tabs.TabPages.AddRange(new[] { tabScan, tabRealtime, tabQuarantine, tabBoot, tabSettings });
            Controls.Add(tabs);
            BuildScanTab();
            BuildRealtimeTab();
            BuildQuarantineTab();
            BuildBootTab();
            BuildSettingsTab();

            tray.Icon = SystemIcons.Application;
            tray.Text = "VirusKov";
            tray.Visible = true;
            var menu = new ContextMenu();
            menu.MenuItems.Add("Open VirusKov", (s, e) => ShowFromTray());
            menu.MenuItems.Add("-");
            menu.MenuItems.Add("Exit", (s, e) => { exiting = true; Close(); });
            tray.ContextMenu = menu;
            tray.DoubleClick += (s, e) => ShowFromTray();

            Log.Written += line => Ui(() =>
            {
                if (txtLog.TextLength > 60000) txtLog.Text = txtLog.Text.Substring(txtLog.TextLength - 30000);
                txtLog.AppendText(line + "\r\n");
            });

            Load += (s, e) =>
            {
                if (startMinimized) { WindowState = FormWindowState.Minimized; Hide(); }
                StartupChecks();
            };
            FormClosing += OnClosingToTray;
        }

        // ---------------- helpers ----------------

        private void Ui(MethodInvoker a)
        {
            if (IsDisposed || !IsHandleCreated) return;
            try
            {
                if (InvokeRequired) BeginInvoke(a);
                else a();
            }
            catch (Exception) { }
        }

        private static Button Btn(Button b, string text, int x, int y, int w)
        {
            b.Text = text;
            b.SetBounds(x, y, w, 26);
            return b;
        }

        private static ListView Grid(ListView lv, params object[] columns)
        {
            lv.View = View.Details;
            lv.FullRowSelect = true;
            lv.HideSelection = false;
            lv.GridLines = true;
            lv.Scrollable = true;
            for (int i = 0; i + 1 < columns.Length; i += 2)
                lv.Columns.Add((string)columns[i], (int)columns[i + 1]);
            return lv;
        }

        private static Color VerdictColor(string v)
        {
            switch (v)
            {
                case "malicious": return Color.FromArgb(200, 30, 30);
                case "suspicious": return Color.FromArgb(200, 120, 0);
                case "clean": return Color.FromArgb(20, 130, 60);
                case "possible_clean": return Color.FromArgb(60, 150, 90);
                case "error": return Color.Gray;
                default: return SystemColors.WindowText;
            }
        }

        private static string VerdictText(string v)
        {
            switch (v)
            {
                case "malicious": return "Malicious";
                case "suspicious": return "Suspicious";
                case "clean": return "Clean";
                case "possible_clean": return "Possibly clean";
                case "error": return "Error";
                default: return "Unknown";
            }
        }

        // ---------------- Scan ----------------

        private void BuildScanTab()
        {
            var p = tabScan;
            p.AutoScroll = true;
            p.AutoScrollMinSize = new Size(740, 480);
            const AnchorStyles TL = AnchorStyles.Top | AnchorStyles.Left;

            p.Controls.Add(new Label { Text = "Locations to scan (folders, files, drives):", AutoSize = true, Location = new Point(10, 8) });
            lstTargets.SetBounds(10, 26, 380, 110);
            lstTargets.SelectionMode = SelectionMode.MultiExtended;
            lstTargets.HorizontalScrollbar = true;
            foreach (string t in settings.ScanTargetList()) lstTargets.Items.Add(t);
            p.Controls.Add(lstTargets);

            Btn(btnAddFolderT, "Add folder...", 396, 26, 110).Anchor = TL;
            btnAddFolderT.Click += (s, e) =>
            {
                using (var d = new FolderBrowserDialog())
                {
                    d.Description = "Choose a folder to scan";
                    if (d.ShowDialog(this) == DialogResult.OK) AddTarget(d.SelectedPath);
                }
            };
            p.Controls.Add(btnAddFolderT);
            Btn(btnAddFile, "Add file...", 396, 54, 110);
            btnAddFile.Click += (s, e) =>
            {
                using (var d = new OpenFileDialog())
                {
                    d.Multiselect = true;
                    d.Title = "Choose files to scan";
                    if (d.ShowDialog(this) == DialogResult.OK) foreach (string f in d.FileNames) AddTarget(f);
                }
            };
            p.Controls.Add(btnAddFile);
            Btn(btnRemoveT, "Remove", 396, 82, 110);
            btnRemoveT.Click += (s, e) =>
            {
                var sel = new List<object>();
                foreach (object o in lstTargets.SelectedItems) sel.Add(o);
                foreach (object o in sel) lstTargets.Items.Remove(o);
            };
            p.Controls.Add(btnRemoveT);
            Btn(btnClearT, "Clear", 396, 110, 110);
            btnClearT.Click += (s, e) => lstTargets.Items.Clear();
            p.Controls.Add(btnClearT);

            cmbDrives.DropDownStyle = ComboBoxStyle.DropDownList;
            cmbDrives.SetBounds(514, 27, 120, 22);
            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                try
                {
                    string label = d.Name + "  (" + d.DriveType + ")";
                    cmbDrives.Items.Add(label);
                }
                catch (Exception) { }
            }
            if (cmbDrives.Items.Count > 0) cmbDrives.SelectedIndex = 0;
            p.Controls.Add(cmbDrives);
            Btn(btnAddDrive, "Add drive", 640, 26, 100);
            btnAddDrive.Click += (s, e) =>
            {
                if (cmbDrives.SelectedItem == null) return;
                AddTarget(((string)cmbDrives.SelectedItem).Split(' ')[0]);
            };
            p.Controls.Add(btnAddDrive);
            Btn(btnAllDrives, "Add all hard disks", 514, 54, 226);
            btnAllDrives.Click += (s, e) => { foreach (string d in FixedDrives()) AddTarget(d); };
            p.Controls.Add(btnAllDrives);
            Btn(btnQuickFolders, "Add quick scan folders", 514, 82, 226);
            btnQuickFolders.Click += (s, e) => { foreach (string d in realtime.Folders()) AddTarget(d); };
            p.Controls.Add(btnQuickFolders);

            p.Controls.Add(new Label { Text = "Exclude (one per line: a folder such as C:\\Games, a folder name such as \\RECYCLER, or a pattern such as *.iso):", AutoSize = true, Location = new Point(10, 142) });
            txtExclude.Multiline = true;
            txtExclude.ScrollBars = ScrollBars.Vertical;
            txtExclude.SetBounds(10, 160, 380, 62);
            txtExclude.Text = string.Join("\r\n", settings.ExcludeList().ToArray());
            p.Controls.Add(txtExclude);

            chkExeOnly.Text = "Only executables && scripts (recommended)";
            chkExeOnly.Checked = settings.ExecutablesOnly;
            chkExeOnly.SetBounds(396, 160, 344, 22);
            chkExeOnly.CheckedChanged += (s, e) =>
            {
                if (!chkExeOnly.Checked &&
                    MessageBox.Show(this, "Without this filter every file in the scanned locations, including personal files, may be uploaded to viruskov.com. Continue?",
                        "VirusKov", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                {
                    chkExeOnly.Checked = true;
                    return;
                }
                settings.ExecutablesOnly = chkExeOnly.Checked;
                settings.Save();
            };
            p.Controls.Add(chkExeOnly);
            p.Controls.Add(new Label { Text = "Skip files over", AutoSize = true, Location = new Point(396, 192) });
            numMaxMb.Minimum = 0;
            numMaxMb.Maximum = 4096;
            numMaxMb.Value = Math.Min(4096, Math.Max(0, settings.MaxScanMB));
            numMaxMb.SetBounds(486, 188, 64, 22);
            p.Controls.Add(numMaxMb);
            p.Controls.Add(new Label { Text = "MB (0 = server limit)", AutoSize = true, Location = new Point(556, 192) });

            Btn(btnScan, "Scan these locations", 10, 230, 160);
            btnScan.Click += (s, e) =>
            {
                var targets = new List<string>();
                foreach (object o in lstTargets.Items) targets.Add((string)o);
                if (targets.Count == 0) { MessageBox.Show(this, "Add at least one folder, file or drive.", "VirusKov"); return; }
                StartScan(targets);
            };
            p.Controls.Add(btnScan);
            Btn(btnQuick, "Quick scan", 176, 230, 100);
            btnQuick.Click += (s, e) => StartScan(realtime.Folders());
            p.Controls.Add(btnQuick);
            Btn(btnFull, "Full scan (all hard disks)", 282, 230, 180);
            btnFull.Click += (s, e) => StartScan(FixedDrives());
            p.Controls.Add(btnFull);
            Btn(btnStop, "Stop", 468, 230, 70);
            btnStop.Enabled = false;
            btnStop.Click += (s, e) => { if (scanner != null) scanner.Cancel(); };
            p.Controls.Add(btnStop);

            progress.SetBounds(10, 262, 730, 16);
            progress.Maximum = 1000;
            progress.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            p.Controls.Add(progress);
            lblScan.SetBounds(10, 282, 730, 18);
            lblScan.AutoEllipsis = true;
            lblScan.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            lblScan.Text = "Ready.";
            p.Controls.Add(lblScan);

            Grid(lvResults, "File", 300, "Verdict", 100, "Threat / detail", 300);
            lvResults.SetBounds(10, 304, 730, 138);
            lvResults.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            p.Controls.Add(lvResults);

            Btn(btnQuarantineSel, "Quarantine selected threats", 10, 448, 200).Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            btnQuarantineSel.Click += (s, e) => QuarantineSelected();
            p.Controls.Add(btnQuarantineSel);
            Btn(btnReport, "Open report on viruskov.com", 216, 448, 200).Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            btnReport.Click += (s, e) =>
            {
                if (lvResults.SelectedItems.Count == 0) return;
                var r = (ScanResult)lvResults.SelectedItems[0].Tag;
                if (!string.IsNullOrEmpty(r.Sha256))
                    try { System.Diagnostics.Process.Start("https://viruskov.com/file/index.html?sha256=" + r.Sha256); } catch (Exception) { }
            };
            p.Controls.Add(btnReport);
        }

        private void AddTarget(string path)
        {
            foreach (object o in lstTargets.Items)
                if (((string)o).Equals(path, StringComparison.OrdinalIgnoreCase)) return;
            lstTargets.Items.Add(path);
        }

        private static List<string> FixedDrives()
        {
            var drives = new List<string>();
            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                try { if (d.DriveType == DriveType.Fixed && d.IsReady) drives.Add(d.RootDirectory.FullName); }
                catch (Exception) { }
            }
            return drives;
        }

        private void SaveScanOptions()
        {
            var t = new List<string>();
            foreach (object o in lstTargets.Items) t.Add((string)o);
            settings.ScanTargets = string.Join("|", t.ToArray());
            var ex = new List<string>();
            foreach (string l in txtExclude.Lines) if (l.Trim().Length > 0) ex.Add(l.Trim());
            settings.Excludes = string.Join("|", ex.ToArray());
            settings.MaxScanMB = (int)numMaxMb.Value;
            settings.Save();
        }

        private void StartScan(IList<string> targets)
        {
            if (scanner != null) return;
            if (targets.Count == 0) { MessageBox.Show(this, "Nothing to scan.", "VirusKov"); return; }
            SaveScanOptions();
            lvResults.Items.Clear();
            progress.Value = 0;
            SetScanning(true);
            scanner = new Scanner(settings);
            scanner.Status += s => Ui(() => lblScan.Text = s);
            scanner.Progress += v => Ui(() => progress.Value = Math.Max(0, Math.Min(1000, v)));
            var th = new Thread(() =>
            {
                List<ScanResult> results = null;
                string error = null;
                try { results = scanner.Run(targets); }
                catch (Exception e) { error = e.Message; Log.Write("scan failed: " + e); }
                Ui(() =>
                {
                    if (results != null) ShowResults(results);
                    if (error != null)
                    {
                        lblScan.Text = "Scan failed: " + error;
                        MessageBox.Show(this, "Scan failed:\r\n" + error + "\r\n\r\nDetails are in data\\viruskov.log.", "VirusKov", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    SetScanning(false);
                    scanner = null;
                });
            });
            th.IsBackground = true;
            th.Start();
        }

        private void SetScanning(bool on)
        {
            btnScan.Enabled = btnQuick.Enabled = btnFull.Enabled = !on;
            btnAddFolderT.Enabled = btnAddFile.Enabled = btnAddDrive.Enabled = btnAllDrives.Enabled = btnQuickFolders.Enabled = !on;
            btnStop.Enabled = on;
        }

        private void ShowResults(List<ScanResult> results)
        {
            // Threats first, then the rest.
            results.Sort((a, b) => (b.IsThreat ? 1 : 0).CompareTo(a.IsThreat ? 1 : 0));
            lvResults.BeginUpdate();
            foreach (ScanResult r in results)
            {
                var it = new ListViewItem(new[] { r.Path, VerdictText(r.Verdict), r.Threat.Length > 0 ? r.Threat + "  " + r.Detail : r.Detail });
                it.ForeColor = VerdictColor(r.Verdict);
                it.Tag = r;
                lvResults.Items.Add(it);
            }
            lvResults.EndUpdate();
            int threats = results.FindAll(r => r.IsThreat).Count;
            if (threats > 0)
                MessageBox.Show(this, threats + " threat(s) found. Select them and press \"Quarantine selected threats\".", "VirusKov", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        private void QuarantineSelected()
        {
            int n = 0;
            foreach (ListViewItem it in lvResults.SelectedItems)
            {
                var r = (ScanResult)it.Tag;
                if (!r.IsThreat || !File.Exists(r.Path)) continue;
                try
                {
                    Quarantine.Add(r.Path, r.Sha256, r.Threat);
                    it.SubItems[1].Text = "Quarantined";
                    n++;
                }
                catch (Exception e)
                {
                    MessageBox.Show(this, "Could not quarantine " + r.Path + ":\r\n" + e.Message, "VirusKov", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            if (n > 0) RefreshQuarantine();
        }

        // ---------------- Real-time ----------------

        private void BuildRealtimeTab()
        {
            var p = tabRealtime;
            chkRealtime.Text = "Real-time protection (watch the folders below and check new programs)";
            chkRealtime.SetBounds(10, 12, 600, 22);
            chkRealtime.Checked = settings.RealtimeEnabled;
            chkRealtime.CheckedChanged += (s, e) =>
            {
                settings.RealtimeEnabled = chkRealtime.Checked;
                settings.Save();
                if (chkRealtime.Checked) realtime.Start(); else realtime.Stop();
                UpdateRealtimeLabel();
            };
            p.Controls.Add(chkRealtime);
            chkAutoQ.Text = "Quarantine malicious files automatically";
            chkAutoQ.SetBounds(10, 36, 600, 22);
            chkAutoQ.Checked = settings.AutoQuarantine;
            chkAutoQ.CheckedChanged += (s, e) => { settings.AutoQuarantine = chkAutoQ.Checked; settings.Save(); };
            p.Controls.Add(chkAutoQ);
            lblRealtime.SetBounds(10, 62, 730, 32);
            lblRealtime.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            p.Controls.Add(lblRealtime);

            lstFolders.SetBounds(10, 98, 600, 110);
            lstFolders.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            p.Controls.Add(lstFolders);
            Btn(btnAddFolder, "Add folder...", 620, 98, 120).Anchor = AnchorStyles.Top | AnchorStyles.Right;
            btnAddFolder.Click += (s, e) =>
            {
                using (var d = new FolderBrowserDialog())
                {
                    if (d.ShowDialog(this) != DialogResult.OK) return;
                    var l = settings.ExtraFolderList();
                    l.Add(d.SelectedPath);
                    settings.ExtraFolders = string.Join("|", l.ToArray());
                    settings.Save();
                    RestartRealtime();
                }
            };
            p.Controls.Add(btnAddFolder);
            Btn(btnRemoveFolder, "Remove", 620, 128, 120).Anchor = AnchorStyles.Top | AnchorStyles.Right;
            btnRemoveFolder.Click += (s, e) =>
            {
                if (lstFolders.SelectedItem == null) return;
                var l = settings.ExtraFolderList();
                if (l.RemoveAll(x => x.Equals((string)lstFolders.SelectedItem, StringComparison.OrdinalIgnoreCase)) == 0)
                {
                    MessageBox.Show(this, "Only folders you added can be removed.", "VirusKov");
                    return;
                }
                settings.ExtraFolders = string.Join("|", l.ToArray());
                settings.Save();
                RestartRealtime();
            };
            p.Controls.Add(btnRemoveFolder);

            Grid(lvEvents, "Time", 130, "Verdict", 100, "File", 330, "Action", 150);
            lvEvents.SetBounds(10, 216, 730, 260);
            lvEvents.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            p.Controls.Add(lvEvents);
        }

        private void RestartRealtime()
        {
            if (realtime.Running) { realtime.Stop(); realtime.Start(); }
            UpdateRealtimeLabel();
        }

        private void UpdateRealtimeLabel()
        {
            lblRealtime.Text = "Status: " + realtime.Mode + ". Detects and quarantines; without a kernel driver it cannot block a program before it starts.";
            lstFolders.Items.Clear();
            foreach (string f in realtime.Folders()) lstFolders.Items.Add(f);
        }

        private void OnRealtimeThreat(ScanResult r, bool quarantined)
        {
            Ui(() =>
            {
                var it = new ListViewItem(new[] { DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), VerdictText(r.Verdict), r.Path, quarantined ? "Quarantined" : "Reported" });
                it.ForeColor = VerdictColor(r.Verdict);
                it.ToolTipText = r.Threat + "  " + r.Detail;
                lvEvents.Items.Insert(0, it);
                if (lvEvents.Items.Count > 500) lvEvents.Items.RemoveAt(500);
                tray.ShowBalloonTip(8000, "VirusKov: " + VerdictText(r.Verdict),
                    Path.GetFileName(r.Path) + (r.Threat.Length > 0 ? "\r\n" + r.Threat : "") + (quarantined ? "\r\nMoved to quarantine." : ""),
                    ToolTipIcon.Warning);
                if (quarantined) RefreshQuarantine();
            });
        }

        // ---------------- Quarantine ----------------

        private void BuildQuarantineTab()
        {
            var p = tabQuarantine;
            Grid(lvQuarantine, "Date", 130, "Threat", 200, "Original location", 380);
            lvQuarantine.SetBounds(10, 10, 730, 430);
            lvQuarantine.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            p.Controls.Add(lvQuarantine);
            Btn(btnRestore, "Restore", 10, 448, 100).Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            btnRestore.Click += (s, e) =>
            {
                if (lvQuarantine.SelectedItems.Count == 0) return;
                var q = (QuarantineItem)lvQuarantine.SelectedItems[0].Tag;
                if (MessageBox.Show(this, "Restore " + q.OriginalPath + "?\r\nIt was detected as " + q.Threat + ".", "VirusKov",
                        MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
                try { Quarantine.Restore(q, File.Exists(q.OriginalPath) ? q.OriginalPath + ".restored" : null); }
                catch (Exception ex) { MessageBox.Show(this, ex.Message, "VirusKov", MessageBoxButtons.OK, MessageBoxIcon.Error); }
                RefreshQuarantine();
            };
            p.Controls.Add(btnRestore);
            Btn(btnDeleteQ, "Delete permanently", 116, 448, 140).Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            btnDeleteQ.Click += (s, e) =>
            {
                if (lvQuarantine.SelectedItems.Count == 0) return;
                if (MessageBox.Show(this, "Delete the selected file(s) permanently?", "VirusKov", MessageBoxButtons.YesNo) != DialogResult.Yes) return;
                foreach (ListViewItem it in lvQuarantine.SelectedItems)
                    try { Quarantine.Delete((QuarantineItem)it.Tag); } catch (Exception) { }
                RefreshQuarantine();
            };
            p.Controls.Add(btnDeleteQ);
            Btn(btnRefreshQ, "Refresh", 262, 448, 90).Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            btnRefreshQ.Click += (s, e) => RefreshQuarantine();
            p.Controls.Add(btnRefreshQ);
        }

        private void RefreshQuarantine()
        {
            lvQuarantine.BeginUpdate();
            lvQuarantine.Items.Clear();
            foreach (QuarantineItem q in Quarantine.List())
            {
                var it = new ListViewItem(new[] { q.Date.ToString("yyyy-MM-dd HH:mm"), q.Threat, q.OriginalPath });
                it.Tag = q;
                lvQuarantine.Items.Add(it);
            }
            lvQuarantine.EndUpdate();
        }

        // ---------------- Boot sector ----------------

        private void BuildBootTab()
        {
            var p = tabBoot;
            var info = new Label
            {
                Text = "The first 63 sectors of the boot disk (MBR and track 0) are backed up and compared at every start. " +
                       "Bootkits and MBR wipers change them. The backup stays on this computer.",
            };
            info.SetBounds(10, 10, 730, 36);
            info.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            p.Controls.Add(info);
            lblBoot.SetBounds(10, 52, 730, 80);
            lblBoot.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            lblBoot.Font = new Font(Font, FontStyle.Bold);
            p.Controls.Add(lblBoot);
            Btn(btnBootCheck, "Check now", 10, 140, 120);
            btnBootCheck.Click += (s, e) => CheckBoot(true);
            p.Controls.Add(btnBootCheck);
            Btn(btnBootBackup, "Make a new backup", 136, 140, 150);
            btnBootBackup.Click += (s, e) =>
            {
                if (File.Exists(BootSectorGuard.BackupPath) &&
                    MessageBox.Show(this, "Replace the existing backup with the boot sector as it is now? Only do this if the current boot sector is known to be good (for example after installing a boot manager).",
                        "VirusKov", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
                try { BootSectorGuard.Backup(); }
                catch (Exception ex) { MessageBox.Show(this, "Backup failed (run as administrator): " + ex.Message, "VirusKov"); }
                CheckBoot(false);
            };
            p.Controls.Add(btnBootBackup);
            Btn(btnBootRestore, "Restore boot code...", 292, 140, 160);
            btnBootRestore.Click += (s, e) =>
            {
                if (!File.Exists(BootSectorGuard.BackupPath)) return;
                if (MessageBox.Show(this,
                        "This writes the saved boot code back to the start of the disk. The current partition table is kept.\r\n\r\n" +
                        "Only continue if the boot code was changed by malware, not by installing another operating system or boot manager. " +
                        "A wrong restore can stop this computer from starting.\r\n\r\nRestore now?",
                        "VirusKov - restore boot sector", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
                try
                {
                    BootSectorGuard.RestoreBootCode(chkTrack0.Checked);
                    MessageBox.Show(this, "Boot code restored. Restart the computer.", "VirusKov");
                }
                catch (Exception ex) { MessageBox.Show(this, "Restore failed: " + ex.Message, "VirusKov", MessageBoxButtons.OK, MessageBoxIcon.Error); }
                CheckBoot(false);
            };
            p.Controls.Add(btnBootRestore);
            chkTrack0.Text = "Also restore track 0 (sectors 1-62)";
            chkTrack0.SetBounds(460, 142, 280, 22);
            p.Controls.Add(chkTrack0);
        }

        private BootSectorState CheckBoot(bool showOk)
        {
            string detail;
            BootSectorState st = BootSectorGuard.Check(out detail);
            lblBoot.Text = st + ": " + detail;
            lblBoot.ForeColor = st == BootSectorState.Ok ? Color.FromArgb(20, 130, 60)
                : st == BootSectorState.BootCodeChanged || st == BootSectorState.HiddenSectorsChanged ? Color.FromArgb(200, 30, 30)
                : st == BootSectorState.PartitionTableChanged ? Color.FromArgb(200, 120, 0) : SystemColors.ControlText;
            bool nt = st != BootSectorState.Unsupported;
            btnBootBackup.Enabled = nt;
            btnBootRestore.Enabled = nt && File.Exists(BootSectorGuard.BackupPath);
            if (showOk && st == BootSectorState.Ok) MessageBox.Show(this, detail, "VirusKov");
            return st;
        }

        // ---------------- Settings ----------------

        private void BuildSettingsTab()
        {
            var p = tabSettings;
            var l1 = new Label { Text = "Server:", AutoSize = true, Location = new Point(10, 16) };
            p.Controls.Add(l1);
            txtServer.SetBounds(110, 12, 420, 22);
            txtServer.Text = settings.ServerUrl;
            p.Controls.Add(txtServer);
            var l2 = new Label { Text = "Token:", AutoSize = true, Location = new Point(10, 46) };
            p.Controls.Add(l2);
            txtToken.SetBounds(110, 42, 420, 22);
            txtToken.Text = settings.Token;
            txtToken.UseSystemPasswordChar = true;
            p.Controls.Add(txtToken);
            chkAutostart.Text = "Start with Windows (in the tray)";
            chkAutostart.SetBounds(110, 72, 420, 22);
            chkAutostart.Checked = settings.StartWithWindows;
            p.Controls.Add(chkAutostart);
            Btn(btnSave, "Save", 110, 100, 100);
            btnSave.Click += (s, e) =>
            {
                string url = txtServer.Text.Trim();
                if (!url.StartsWith("wss://", StringComparison.OrdinalIgnoreCase) &&
                    !url.StartsWith("ws://localhost", StringComparison.OrdinalIgnoreCase) &&
                    !url.StartsWith("ws://127.0.0.1", StringComparison.OrdinalIgnoreCase))
                {
                    MessageBox.Show(this, "The server address must start with wss:// (encrypted). ws:// is only allowed for localhost.", "VirusKov");
                    return;
                }
                settings.ServerUrl = url;
                settings.Token = txtToken.Text.Trim();
                settings.StartWithWindows = chkAutostart.Checked;
                settings.Save();
                SetAutostart(settings.StartWithWindows);
                MessageBox.Show(this, "Saved.", "VirusKov");
            };
            p.Controls.Add(btnSave);
            Btn(btnEula, "Cloud scanning agreement", 216, 100, 200);
            btnEula.Click += (s, e) => Eula.Ask(true);
            p.Controls.Add(btnEula);
            var l3 = new Label { Text = "Log:", AutoSize = true, Location = new Point(10, 140) };
            p.Controls.Add(l3);
            txtLog.Multiline = true;
            txtLog.ReadOnly = true;
            txtLog.ScrollBars = ScrollBars.Vertical;
            txtLog.SetBounds(10, 160, 730, 316);
            txtLog.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            txtLog.Font = new Font(FontFamily.GenericMonospace, 8.25f);
            p.Controls.Add(txtLog);
        }

        private static void SetAutostart(bool on)
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                {
                    if (k == null) return;
                    if (on) k.SetValue("VirusKov", "\"" + Application.ExecutablePath + "\" /minimized");
                    else if (k.GetValue("VirusKov") != null) k.DeleteValue("VirusKov");
                }
            }
            catch (Exception e)
            {
                Log.Write("autostart: " + e.Message);
            }
        }

        // ---------------- start, tray ----------------

        private void StartupChecks()
        {
            RefreshQuarantine();
            // Boot sector: first start makes the backup; later starts compare.
            if (Platform.IsNT && !File.Exists(BootSectorGuard.BackupPath))
            {
                try { BootSectorGuard.Backup(); }
                catch (Exception e) { Log.Write("boot sector backup failed: " + e.Message); }
            }
            BootSectorState st = CheckBoot(false);
            if (st == BootSectorState.BootCodeChanged || st == BootSectorState.HiddenSectorsChanged || st == BootSectorState.PartitionTableChanged)
            {
                ShowFromTray();
                tabs.SelectedTab = tabBoot;
                MessageBox.Show(this, lblBoot.Text, "VirusKov - boot sector changed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            if (settings.RealtimeEnabled) realtime.Start();
            UpdateRealtimeLabel();
            Log.Write("VirusKov for ReactOS " + AppInfo.Version + " started on " + Environment.OSVersion.VersionString +
                      ", CLR " + Environment.Version);
        }

        private void ShowFromTray()
        {
            Show();
            WindowState = FormWindowState.Normal;
            Activate();
        }

        private void OnClosingToTray(object sender, FormClosingEventArgs e)
        {
            // Closing the window keeps real-time protection running in the tray.
            if (!exiting && realtime.Running && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                Hide();
                tray.ShowBalloonTip(3000, "VirusKov", "Real-time protection keeps running here. Right-click for Exit.", ToolTipIcon.Info);
                return;
            }
            if (scanner != null) scanner.Cancel();
            realtime.Dispose();
            tray.Visible = false;
            tray.Dispose();
        }
    }
}
