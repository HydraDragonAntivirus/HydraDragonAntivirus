using System;
using System.Drawing;
using System.Windows.Forms;

namespace HydraDragonClient.UI
{
    /// <summary>
    /// Dialog for user consent when someone tries to connect
    /// </summary>
    public class ConsentDialog : Form
    {
        private readonly Label _messageLabel;
        private readonly Button _acceptButton;
        private readonly Button _denyButton;
        private readonly System.Windows.Forms.Timer _timeoutTimer;
        private int _remainingSeconds = 30;

        public bool Accepted { get; private set; }

        public ConsentDialog(string remoteAddress, string clientName)
        {
            // Form setup
            Text = "ACCESS REQUEST";
            Size = new Size(450, 300);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterScreen;
            MaximizeBox = false;
            MinimizeBox = false;
            TopMost = true;
            BackColor = Color.FromArgb(25, 25, 25);
            ForeColor = Color.White;
            Font = new Font("Segoe UI", 10);
            KeyPreview = true;

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                Padding = new Padding(20),
                ColumnCount = 1,
                RowCount = 3
            };
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));  // Title
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // Message
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));  // Buttons

            var titleLabel = new Label
            {
                Text = "INCOMING CONNECTION",
                ForeColor = Color.FromArgb(255, 50, 50),
                Font = new Font("Segoe UI", 12, FontStyle.Bold),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter
            };

            _messageLabel = new Label
            {
                Text = $"Remote device is requesting control:\n\nNAME: {clientName}\nIP: {remoteAddress}\n\nGrant access? ({_remainingSeconds}s)",
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font("Segoe UI", 11)
            };

            var buttonPanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.RightToLeft,
                Padding = new Padding(0, 5, 0, 0)
            };

            _denyButton = new Button
            {
                Text = "DENY (Esc)",
                Size = new Size(120, 40),
                BackColor = Color.FromArgb(180, 40, 40),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            _denyButton.Click += (s, e) => { Accepted = false; Close(); };

            _acceptButton = new Button
            {
                Text = "ALLOW (Enter)",
                Size = new Size(130, 40),
                BackColor = Color.FromArgb(0, 180, 100),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                Cursor = Cursors.Hand,
                Margin = new Padding(10, 0, 0, 0)
            };
            _acceptButton.Click += (s, e) => { Accepted = true; Close(); };

            buttonPanel.Controls.Add(_denyButton);
            buttonPanel.Controls.Add(_acceptButton);

            mainLayout.Controls.Add(titleLabel, 0, 0);
            mainLayout.Controls.Add(_messageLabel, 0, 1);
            mainLayout.Controls.Add(buttonPanel, 0, 2);

            Controls.Add(mainLayout);

            // Timeout timer
            _timeoutTimer = new System.Windows.Forms.Timer { Interval = 1000 };
            _timeoutTimer.Tick += (s, e) =>
            {
                _remainingSeconds--;
                if (_remainingSeconds <= 0)
                {
                    Accepted = false;
                    Close();
                }
                else
                {
                    _messageLabel.Text = $"Remote device is requesting control:\n\nNAME: {clientName}\nIP: {remoteAddress}\n\nGrant access? ({_remainingSeconds}s)";
                }
            };
            _timeoutTimer.Start();

            // Keyboard handling
            KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.Enter) _acceptButton.PerformClick();
                else if (e.KeyCode == Keys.Escape) _denyButton.PerformClick();
            };

            Shown += (s, e) => _acceptButton.Focus();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            _timeoutTimer.Stop();
            _timeoutTimer.Dispose();
            base.OnFormClosing(e);
        }
    }
}
