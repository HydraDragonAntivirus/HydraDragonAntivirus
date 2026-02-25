using System;
using System.Drawing;
using System.Windows.Forms;

namespace HydraDragonClient.UI
{
    /// <summary>
    /// Connection dialog with keyboard-focused design
    /// </summary>
    public class ConnectDialog : Form
    {
        private readonly TextBox _hostTextBox;
        private readonly TextBox _portTextBox;
        private readonly TextBox _passwordTextBox;
        private readonly Button _connectButton;
        private readonly Button _cancelButton;

        public string Host => _hostTextBox.Text.Trim();
        public int Port => int.TryParse(_portTextBox.Text, out var p) ? p : 9876;
        public string Password => _passwordTextBox.Text;
        public bool Confirmed { get; private set; }

        public ConnectDialog(string defaultHost = "", int defaultPort = 9876)
        {
            // Form setup
            Text = "REMOTE CONNECTION";
            Size = new Size(450, 380);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterParent;
            MaximizeBox = false;
            MinimizeBox = false;
            BackColor = Color.FromArgb(30, 30, 30);
            ForeColor = Color.White;
            Font = new Font("Segoe UI", 10);
            KeyPreview = true;

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                Padding = new Padding(30),
                ColumnCount = 1,
                RowCount = 7
            };

            // Add controls with consistent spacing
            mainLayout.Controls.Add(CreateLabel("TARGET IP ADDRESS:"), 0, 0);
            
            _hostTextBox = CreateTextBox(defaultHost, 0);
            mainLayout.Controls.Add(_hostTextBox, 0, 1);

            mainLayout.Controls.Add(CreateLabel("TARGET PORT:"), 0, 2);
            
            _portTextBox = CreateTextBox(defaultPort.ToString(), 1);
            _portTextBox.Width = 120;
            mainLayout.Controls.Add(_portTextBox, 0, 3);

            mainLayout.Controls.Add(CreateLabel("SESSION PASSWORD (6 DIGITS):"), 0, 4);
            
            _passwordTextBox = CreateTextBox("", 2);
            _passwordTextBox.UseSystemPasswordChar = true;
            _passwordTextBox.MaxLength = 6;
            mainLayout.Controls.Add(_passwordTextBox, 0, 5);

            // Button layout
            var buttonPanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.RightToLeft,
                Padding = new Padding(0, 15, 0, 0)
            };

            _cancelButton = CreateButton("CANCEL", Color.FromArgb(80, 80, 80));
            _cancelButton.Height = 50; // Increased height
            _cancelButton.Click += (s, e) => Close();

            _connectButton = CreateButton("CONNECT", Color.FromArgb(0, 122, 204));
            _connectButton.Height = 50; // Increased height
            _connectButton.Click += (s, e) => 
            {
                if (ValidateInput())
                {
                    Confirmed = true;
                    DialogResult = DialogResult.OK;
                    Close();
                }
            };

            buttonPanel.Controls.Add(_cancelButton);
            buttonPanel.Controls.Add(_connectButton);
            mainLayout.Controls.Add(buttonPanel, 0, 6);

            Controls.Add(mainLayout);

            // Handle Enter/Esc
            KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.Escape) Close();
                else if (e.KeyCode == Keys.Enter) _connectButton.PerformClick();
            };
        }

        private Label CreateLabel(string text) => new Label {
            Text = text,
            ForeColor = Color.DarkGray,
            Font = new Font("Segoe UI", 9, FontStyle.Bold),
            AutoSize = true,
            Margin = new Padding(0, 10, 0, 5)
        };

        private TextBox CreateTextBox(string text, int tabIndex) => new TextBox {
            Text = text,
            TabIndex = tabIndex,
            BackColor = Color.FromArgb(45, 45, 50),
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 12),
            Width = 370
        };

        private Button CreateButton(string text, Color backColor) => new Button {
            Text = text,
            Size = new Size(130, 40), // Default width slightly wider
            BackColor = backColor,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 10, FontStyle.Bold),
            Margin = new Padding(10, 0, 0, 0),
            Cursor = Cursors.Hand
        };

        private bool ValidateInput()
        {
            if (string.IsNullOrWhiteSpace(_hostTextBox.Text))
            {
                MessageBox.Show("Please enter an IP address", "Validation Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                _hostTextBox.Focus();
                return false;
            }

            if (!int.TryParse(_portTextBox.Text, out var port) || port < 1 || port > 65535)
            {
                MessageBox.Show("Please enter a valid port (1-65535)", "Validation Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                _portTextBox.Focus();
                return false;
            }

            if (string.IsNullOrWhiteSpace(_passwordTextBox.Text))
            {
                MessageBox.Show("Please enter the session password", "Validation Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                _passwordTextBox.Focus();
                return false;
            }

            return true;
        }
    }
}
