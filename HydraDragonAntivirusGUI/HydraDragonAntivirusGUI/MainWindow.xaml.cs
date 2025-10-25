// MainWindow.xaml.cs
using System.Diagnostics;
using System.Windows;

namespace HydraDragonAntivirusGUI
{
    public partial class MainWindow : Window
    {
        private readonly string _launcherProcessName = "HydraDragonLauncher"; // without .exe

        public MainWindow()
        {
            InitializeComponent();

            UpdateProtectionUI();
        }

        private void UpdateProtectionUI()
        {
            bool running = IsProcessRunning(_launcherProcessName);
            txtStatus.Text = running ? "Protected — launcher is running" : "Unprotected — launcher not found";

            if (running)
                imgProtection.Source = new System.Windows.Media.Imaging.BitmapImage(new Uri("hydradragon_protected.gif", UriKind.Relative));
            else
                imgProtection.Source = new System.Windows.Media.Imaging.BitmapImage(new Uri("hydradragon_unprotected.gif", UriKind.Relative));
        }

        private bool IsProcessRunning(string procNameWithoutExt)
        {
            try
            {
                var procs = Process.GetProcessesByName(procNameWithoutExt);
                return procs != null && procs.Length > 0;
            }
            catch
            {
                return false;
            }
        }
    }
}
