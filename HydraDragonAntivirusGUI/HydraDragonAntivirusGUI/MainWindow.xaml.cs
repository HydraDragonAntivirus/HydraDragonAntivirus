using System.Diagnostics;
using System.Windows;
using System.Windows.Media.Imaging;

namespace HydraDragonAntivirusGUI
{
    public partial class MainWindow : Window
    {
        private readonly string _scheduledTaskName = "HydraDragonAntivirus";

        public MainWindow()
        {
            InitializeComponent();
            UpdateProtectionUI();
        }

        private void UpdateProtectionUI()
        {
            bool running = IsScheduledTaskRunning(_scheduledTaskName);

            if (txtStatus != null)
                txtStatus.Text = running
                    ? "Protected — scheduled task is running"
                    : "Unprotected — task not running";

            if (imgProtection != null)
            {
                string gifPath = running
                    ? "hydradragon_protected.gif"
                    : "hydradragon_unprotected.gif";

                imgProtection.Source = new BitmapImage(new Uri(gifPath, UriKind.Relative));
            }
        }

        private bool IsScheduledTaskRunning(string taskName)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "schtasks",
                    Arguments = $"/Query /TN \"{taskName}\" /FO LIST /V",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using Process proc = Process.Start(psi)!;
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();

                return output.Contains("Running");
            }
            catch
            {
                return false;
            }
        }
    }
}

