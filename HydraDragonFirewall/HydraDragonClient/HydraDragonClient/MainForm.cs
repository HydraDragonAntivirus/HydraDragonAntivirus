using System;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Windows.Forms;
using HydraDragonClient.Client;
using HydraDragonClient.Config;
using HydraDragonClient.Protocol;
using HydraDragonClient.Remote;
using HydraDragonClient.UI;

namespace HydraDragonClient
{
    /// <summary>
    /// Main application form with dual mode (Client/Remote)
    /// </summary>
    public partial class MainForm : Form
    {
        private readonly AppSettings _settings;
        private readonly RemoteServer _server;
        private readonly RemoteClient _client;
        private ScreenViewer _screenViewer = null!;
        private NotifyIcon _trayIcon = null!;
        private Label _statusLabel = null!;
        private Label _passwordLabel = null!;
        private Label _ipLabel = null!;
        private Panel _infoPanel = null!;
        private bool _mouseEnabled = true;
        private bool _isClosing;

        public MainForm()
        {
            _settings = AppSettings.Load();
            _server = new RemoteServer(_settings);
            _client = new RemoteClient();

            InitializeComponents();
            SetupEventHandlers();
            SetupTrayIcon();
            SetupKeyboardShortcuts();

            // Start server safely
            try
            {
                _server.Start();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Could not start server on port {_settings.Port}: {ex.Message}\n\nTry closing other instances or change the port in settings.", "Server Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            UpdateUI();
        }

        private void InitializeComponents()
        {
            // Form setup
            Text = "HydraDragon Remote Desktop";
            Size = new Size(1200, 800);
            MinimumSize = new Size(950, 650);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.FromArgb(25, 25, 25);
            ForeColor = Color.White;
            Font = new Font("Segoe UI", 10);
            KeyPreview = true;

            // Header Panel
            _infoPanel = new Panel
            {
                Dock = DockStyle.Top,
                Height = 130, // Increased height for multiple rows
                BackColor = Color.FromArgb(35, 35, 35),
                Padding = new Padding(20, 10, 20, 10)
            };

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 2,
                BackColor = Color.Transparent
            };
            mainLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 70));
            mainLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 30));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 50));

            // Top Left: Title
            var titleLabel = new Label
            {
                Text = "HYDRADRAGON",
                Font = new Font("Segoe UI Black", 24, FontStyle.Bold),
                ForeColor = Color.FromArgb(255, 50, 50), // Dragon Red
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = true
            };

            // Top Right: Status/Buttons
            var topButtons = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.RightToLeft,
                Padding = new Padding(0, 5, 0, 0)
            };

            var disconnectBtn = new Button
            {
                Text = "DISCONNECT",
                Size = new Size(120, 35),
                BackColor = Color.FromArgb(180, 40, 40),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            disconnectBtn.FlatAppearance.BorderSize = 0;
            disconnectBtn.Click += (s, e) => {
                if (_client.IsConnected) _client.Disconnect();
                _statusLabel.Text = "Disconnected by user.";
            };

            var sendFileBtn = new Button
            {
                Text = "SEND FILE",
                Size = new Size(120, 35),
                BackColor = Color.FromArgb(0, 122, 204),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9, FontStyle.Bold),
                Cursor = Cursors.Hand,
                Margin = new Padding(0, 0, 10, 0)
            };
            sendFileBtn.FlatAppearance.BorderSize = 0;
            sendFileBtn.Click += async (s, e) =>
            {
                if (!_client.IsConnected)
                {
                    MessageBox.Show("Please connect to a remote server first.", "Not Connected", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                using var ofd = new OpenFileDialog();
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    _statusLabel.Text = $"Sending: {ofd.SafeFileName}";
                    await _client.SendFileAsync(ofd.FileName);
                    _statusLabel.Text = "File transfer complete.";
                }
            };

            topButtons.Controls.Add(disconnectBtn);
            topButtons.Controls.Add(sendFileBtn);

            // Bottom Left: Connection Info
            var infoBox = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.LeftToRight,
                Padding = new Padding(0, 5, 0, 0)
            };

            _ipLabel = new Label
            {
                Text = $"IP: {GetLocalIPAddress()}  |  Port: {_settings.Port}",
                ForeColor = Color.DarkGray,
                Font = new Font("Segoe UI Semibold", 10),
                AutoSize = true,
                Margin = new Padding(0, 8, 20, 0)
            };

            _passwordLabel = new Label
            {
                Text = $"PASSWORD: {_server.SessionPassword}",
                ForeColor = Color.FromArgb(0, 255, 120),
                Font = new Font("Consolas", 14, FontStyle.Bold),
                AutoSize = true
            };

            infoBox.Controls.Add(_ipLabel);
            infoBox.Controls.Add(_passwordLabel);

            // Bottom Right: Shortcuts
            var shortcutLabel = new Label
            {
                Text = "F1: Connect  |  F2: New Pass  |  F5: Mouse  |  Esc: Stop",
                ForeColor = Color.DimGray,
                Font = new Font("Segoe UI", 9, FontStyle.Italic),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleRight
            };

            mainLayout.Controls.Add(titleLabel, 0, 0);
            mainLayout.Controls.Add(topButtons, 1, 0);
            mainLayout.Controls.Add(infoBox, 0, 1);
            mainLayout.Controls.Add(shortcutLabel, 1, 1);

            _infoPanel.Controls.Add(mainLayout);
            Controls.Add(_infoPanel);

            // Screen viewer (center)
            _screenViewer = new ScreenViewer
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Black
            };
            Controls.Add(_screenViewer);

            // Status bar (bottom)
            var statusPanel = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 25,
                BackColor = Color.FromArgb(20, 20, 20)
            };

            _statusLabel = new Label
            {
                Text = "SYSTEM READY",
                Location = new Point(10, 4),
                AutoSize = true,
                ForeColor = Color.Gray,
                Font = new Font("Segoe UI", 8, FontStyle.Bold)
            };
            statusPanel.Controls.Add(_statusLabel);

            Controls.Add(statusPanel);

            // Ensure proper Z-order
            _screenViewer.BringToFront();
        }

        private void SetupEventHandlers()
        {
            // Server events
            _server.ConnectionRequested += (s, e) =>
            {
                Invoke(() =>
                {
                    using var dialog = new ConsentDialog(e.RemoteAddress, e.ClientName);
                    dialog.ShowDialog(this);
                    _server.RespondToConnection(dialog.Accepted);
                });
            };

            _server.ClientConnected += (s, ip) =>
            {
                Invoke(() =>
                {
                    _statusLabel.Text = $"Remote client connected: {ip}";
                    _trayIcon.ShowBalloonTip(3000, "Connected", $"Client {ip} connected", ToolTipIcon.Info);
                });
            };

            _server.ClientDisconnected += (s, e) =>
            {
                Invoke(() =>
                {
                    _statusLabel.Text = "Ready - Server running";
                });
            };

            _server.Error += (s, error) =>
            {
                Invoke(() =>
                {
                    _statusLabel.Text = $"Error: {error}";
                });
            };

            // Client events
            _client.Connected += (s, host) =>
            {
                Invoke(() =>
                {
                    _statusLabel.Text = $"Connected to {host}";
                    _screenViewer.Focus();
                });
            };

            _client.Disconnected += (s, e) =>
            {
                Invoke(() =>
                {
                    _statusLabel.Text = "Disconnected - Server running";
                    _screenViewer.Invalidate();
                });
            };

            _client.FrameReceived += (s, frame) =>
            {
                _screenViewer.UpdateFrame(frame);
                frame.Dispose();
            };

            _client.Error += (s, error) =>
            {
                Invoke(() =>
                {
                    _statusLabel.Text = $"Client error: {error}";
                });
            };

            // Screen viewer mouse events
            _screenViewer.MouseMove += OnScreenViewerMouseMove;
            _screenViewer.MouseDown += OnScreenViewerMouseDown;
            _screenViewer.MouseUp += OnScreenViewerMouseUp;
            _screenViewer.MouseWheel += OnScreenViewerMouseWheel;
        }

        private void SetupTrayIcon()
        {
            var contextMenu = new ContextMenuStrip();
            contextMenu.Items.Add("Show", null, (s, e) => { Show(); WindowState = FormWindowState.Normal; });
            contextMenu.Items.Add("New Password", null, (s, e) => RegeneratePassword());
            contextMenu.Items.Add("-");
            contextMenu.Items.Add("Exit", null, (s, e) => { _isClosing = true; Close(); });

            _trayIcon = new NotifyIcon
            {
                Text = "HydraDragon Remote Desktop",
                Visible = true,
                ContextMenuStrip = contextMenu
            };

            // Load icon from assets folder
            var iconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "..", "assets", "app.ico");
            if (File.Exists(iconPath))
            {
                var icon = new Icon(iconPath);
                _trayIcon.Icon = icon;
                this.Icon = icon;
            }
            else
            {
                // Fallback: create a simple icon programmatically
                using var bmp = new Bitmap(32, 32);
                using var g = Graphics.FromImage(bmp);
                g.Clear(Color.FromArgb(0, 122, 204));
                g.FillRectangle(Brushes.White, 8, 8, 16, 16);
                _trayIcon.Icon = Icon.FromHandle(bmp.GetHicon());
            }

            _trayIcon.DoubleClick += (s, e) => { Show(); WindowState = FormWindowState.Normal; };
        }

        private void SetupKeyboardShortcuts()
        {
            KeyDown += async (s, e) =>
            {
                switch (e.KeyCode)
                {
                    case Keys.F1:
                        ShowConnectDialog();
                        e.Handled = true;
                        break;

                    case Keys.F2:
                        RegeneratePassword();
                        e.Handled = true;
                        break;

                    case Keys.F5:
                        _mouseEnabled = !_mouseEnabled;
                        _statusLabel.Text = $"Mouse {(_mouseEnabled ? "enabled" : "disabled")}";
                        e.Handled = true;
                        break;

                    case Keys.Escape:
                        if (_client.IsConnected)
                        {
                            _client.Disconnect();
                        }
                        e.Handled = true;
                        break;

                    default:
                        if (_client.IsConnected && _screenViewer.Focused)
                        {
                            await _client.SendKeyboardAsync(
                                (int)e.KeyCode, 
                                true,
                                e.Shift,
                                e.Control,
                                e.Alt);
                            e.Handled = true;
                            e.SuppressKeyPress = true;
                        }
                        break;
                }
            };

            KeyUp += async (s, e) =>
            {
                if (_client.IsConnected && _screenViewer.Focused)
                {
                    await _client.SendKeyboardAsync(
                        (int)e.KeyCode,
                        false,
                        e.Shift,
                        e.Control,
                        e.Alt);
                    e.Handled = true;
                    e.SuppressKeyPress = true;
                }
            };
        }

        private void ShowConnectDialog()
        {
            using var dialog = new ConnectDialog(_settings.LastConnectedIp ?? "", _settings.Port);
            if (dialog.ShowDialog(this) == DialogResult.OK || dialog.Confirmed)
            {
                _settings.LastConnectedIp = dialog.Host;
                _settings.Save();

                _ = ConnectAsync(dialog.Host, dialog.Port, dialog.Password);
            }
        }

        private async System.Threading.Tasks.Task ConnectAsync(string host, int port, string password)
        {
            _statusLabel.Text = $"Connecting to {host}:{port}...";
            var success = await _client.ConnectAsync(host, port, password);
            if (!success)
            {
                _statusLabel.Text = "Connection failed";
            }
        }

        private void RegeneratePassword()
        {
            _server.RegeneratePassword();
            _passwordLabel.Text = $"Session Password: {_server.SessionPassword}";
            _trayIcon.ShowBalloonTip(2000, "New Password", _server.SessionPassword, ToolTipIcon.Info);
        }

        private void UpdateUI()
        {
            _passwordLabel.Text = $"Session Password: {_server.SessionPassword}";
            _ipLabel.Text = $"Your IP: {GetLocalIPAddress()} | Port: {_settings.Port}";
        }

        #region Mouse Event Handlers

        private async void OnScreenViewerMouseMove(object? sender, MouseEventArgs e)
        {
            if (!_client.IsConnected || !_mouseEnabled) return;

            var remotePoint = _screenViewer.ClientToRemote(e.Location, _client.RemoteWidth, _client.RemoteHeight);
            if (remotePoint.X >= 0)
            {
                await _client.SendMouseAsync(remotePoint.X, remotePoint.Y, MouseAction.Move);
            }
        }

        private async void OnScreenViewerMouseDown(object? sender, MouseEventArgs e)
        {
            if (!_client.IsConnected || !_mouseEnabled) return;

            var remotePoint = _screenViewer.ClientToRemote(e.Location, _client.RemoteWidth, _client.RemoteHeight);
            if (remotePoint.X >= 0)
            {
                var action = e.Button switch
                {
                    MouseButtons.Left => MouseAction.LeftDown,
                    MouseButtons.Right => MouseAction.RightDown,
                    MouseButtons.Middle => MouseAction.MiddleDown,
                    _ => MouseAction.Move
                };
                await _client.SendMouseAsync(remotePoint.X, remotePoint.Y, action);
            }
        }

        private async void OnScreenViewerMouseUp(object? sender, MouseEventArgs e)
        {
            if (!_client.IsConnected || !_mouseEnabled) return;

            var remotePoint = _screenViewer.ClientToRemote(e.Location, _client.RemoteWidth, _client.RemoteHeight);
            if (remotePoint.X >= 0)
            {
                var action = e.Button switch
                {
                    MouseButtons.Left => MouseAction.LeftUp,
                    MouseButtons.Right => MouseAction.RightUp,
                    MouseButtons.Middle => MouseAction.MiddleUp,
                    _ => MouseAction.Move
                };
                await _client.SendMouseAsync(remotePoint.X, remotePoint.Y, action);
            }
        }

        private async void OnScreenViewerMouseWheel(object? sender, MouseEventArgs e)
        {
            if (!_client.IsConnected || !_mouseEnabled) return;

            var remotePoint = _screenViewer.ClientToRemote(e.Location, _client.RemoteWidth, _client.RemoteHeight);
            if (remotePoint.X >= 0)
            {
                await _client.SendMouseAsync(remotePoint.X, remotePoint.Y, MouseAction.Wheel, e.Delta);
            }
        }

        #endregion

        private static string GetLocalIPAddress()
        {
            try
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0);
                socket.Connect("8.8.8.8", 65530);
                var endPoint = socket.LocalEndPoint as IPEndPoint;
                return endPoint?.Address.ToString() ?? "Unknown";
            }
            catch
            {
                return "Unknown";
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (!_isClosing && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                Hide();
                _trayIcon.ShowBalloonTip(2000, "HydraDragon", "Running in background", ToolTipIcon.Info);
                return;
            }

            _client.Dispose();
            _server.Dispose();
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
            _settings.Save();

            base.OnFormClosing(e);
        }
    }
}
