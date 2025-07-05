using System;
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
            BtnLaunch.IsEnabled = false;
            StatusText.Text = "Launching Antivirus...";

            try
            {
                LaunchWithConsole("hydradragon");
                StatusText.Text = "Antivirus launched.";
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Unexpected error: {ex.Message}",
                    "Launcher Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );
                StatusText.Text = "Error launching antivirus.";
            }
            finally
            {
                BtnLaunch.IsEnabled = true;
            }
        }

        private void BtnLaunchDiscord_Click(object sender, RoutedEventArgs e)
        {
            string token = TxtDiscordToken.Password;
            if (string.IsNullOrWhiteSpace(token))
            {
                MessageBox.Show(
                    "Please enter a valid Discord token.",
                    "Launcher Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning
                );
                return;
            }

            BtnLaunchDiscord.IsEnabled = false;
            StatusText.Text = "Launching Discord Bot...";

            try
            {
                // Set the DISCORD_TOKEN for the launched process
                Environment.SetEnvironmentVariable(
                    "DISCORD_TOKEN", token, EnvironmentVariableTarget.Process);
                LaunchWithConsole("hydradragon-discord");
                StatusText.Text = "Discord Bot launched.";
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Unexpected error: {ex.Message}",
                    "Launcher Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );
                StatusText.Text = "Error launching Discord Bot.";
            }
            finally
            {
                BtnLaunchDiscord.IsEnabled = true;
            }
        }

        private void LaunchWithConsole(string scriptName)
        {
            string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            string activateScript = Path.Combine(baseDirectory, "venv", "Scripts", "activate.bat");

            if (!File.Exists(activateScript))
            {
                MessageBox.Show(
                    $"Activation script not found:\n{activateScript}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );
                StatusText.Text = "Activation script missing.";
                return;
            }

            // Use /K to keep the console open after running the commands
            string cmdArgs = $"/K \"\"{activateScript}\" && poetry run {scriptName}\"";

            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = cmdArgs,
                WorkingDirectory = baseDirectory,
                UseShellExecute = true,
                CreateNoWindow = false
            };

            Process.Start(psi);
        }
    }
}