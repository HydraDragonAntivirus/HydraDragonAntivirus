using System;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Media.Imaging;
using WpfAnimatedGif;

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

            // Update status text safely
            if (txtStatus != null)
                txtStatus.Text = running
                    ? "Protected — scheduled task is running"
                    : "Unprotected — task not running";

            if (imgProtection != null)
            {
                // Get the folder where the executable is running
                string exeFolder = AppDomain.CurrentDomain.BaseDirectory;

                // Pick correct GIF
                string gifFileName = running
                    ? "hydradragon_protected.gif"
                    : "hydradragon_unprotected.gif";

                string gifFullPath = Path.Combine(exeFolder, gifFileName);

                // Load animated GIF using WpfAnimatedGif
                if (File.Exists(gifFullPath))
                {
                    var image = new BitmapImage(new Uri(gifFullPath, UriKind.Absolute));
                    ImageBehavior.SetAnimatedSource(imgProtection, image);
                }
                else
                {
                    // Optional fallback if file not found
                    imgProtection.Source = null;
                    Console.WriteLine($"GIF not found: {gifFullPath}");
                }
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
