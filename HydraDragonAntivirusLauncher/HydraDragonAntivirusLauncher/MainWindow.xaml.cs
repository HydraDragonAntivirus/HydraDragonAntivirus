using System.Diagnostics;
using System.IO;
using System.Windows;

namespace HydraDragonAntivirusLauncher
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void BtnLaunch_Click(object sender, RoutedEventArgs e)
        {
            // Prevent double‑clicks
            BtnLaunch.IsEnabled = false;
            BtnLaunch.Content = "Launching...";

            try
            {
                LaunchWithConsole();
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Unexpected error: {ex.Message}",
                    "Launcher Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );
            }
            finally
            {
                BtnLaunch.IsEnabled = true;
                BtnLaunch.Content = "Launch Antivirus";
            }
        }

        static private void LaunchWithConsole()
        {
            // base directory of the running EXE
            string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;

            // activation script path
            string activateScript = Path.Combine(
                baseDirectory, "venv", "Scripts", "activate.bat"
            );

            if (!File.Exists(activateScript))
            {
                MessageBox.Show(
                    $"Activation script not found:\n{activateScript}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );
                return;
            }

            // Use /K to keep the console open after the commands run
            string cmdArgs = $"/K \"\"{activateScript}\" && poetry run hydradragon\"";

            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = cmdArgs,
                WorkingDirectory = baseDirectory,
                UseShellExecute = true,   // allow a real console window
                RedirectStandardOutput = false,
                RedirectStandardError = false,
                CreateNoWindow = false
            };

            Process.Start(psi);
        }
    }
}
