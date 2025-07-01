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

        private async void BtnLaunch_Click(object sender, RoutedEventArgs e)
        {
            // Disable the button to prevent multiple launches
            BtnLaunch.IsEnabled = false;
            BtnLaunch.Content = "Launching Antivirus...";

            try
            {
                await Task.Run(() => LaunchApplication());
            }
            catch (Exception ex)
            {
                // Handle any exceptions that bubble up from the background thread
                MessageBox.Show($"An unexpected error occurred while trying to launch the application: {ex.Message}", "Launcher Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                // Re-enable the button and restore original text
                BtnLaunch.IsEnabled = true;
                BtnLaunch.Content = "Launch Antivirus"; 
            }
        }

        private void LaunchApplication()
        {
            try
            {
                // Define the path to the application's base directory.
                string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;

                // Define the full path to the virtual environment's activation script.
                // This assumes a 'venv' folder exists in the same directory as the launcher.
                string activateScript = Path.Combine(baseDirectory, "venv", "Scripts", "activate.bat");

                // Check if the activation script exists before trying to run it.
                if (!File.Exists(activateScript))
                {
                    // Use Dispatcher.Invoke to show MessageBox on UI thread
                    Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show($"Virtual environment activation script not found at the expected location:\n{activateScript}\n\nPlease ensure the 'venv' directory is set up correctly.", "Error: Environment Not Found", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                    return;
                }

                // This is the command to run the Python application using Poetry.
                string poetryCommand = "poetry run hydradragon";

                // Configure the process to start the command prompt.
                var psi = new ProcessStartInfo
                {
                    FileName = "cmd.exe",

                    // Arguments to pass to cmd.exe:
                    // /C -> Carries out the command specified by the string and then terminates.
                    // We chain two commands using '&&':
                    // 1. Activate the virtual environment. The path to the script is wrapped in quotes to handle potential spaces.
                    // 2. Run the python script using 'poetry run'. This command will only run if the activation is successful.
                    Arguments = $"/C \"\"{activateScript}\" && {poetryCommand}\"",

                    // Set the working directory for the process to the application's root.
                    WorkingDirectory = baseDirectory,

                    // We don't use the system shell to execute, which allows us to redirect I/O streams.
                    UseShellExecute = false,

                    // Redirect Standard Error and Output to capture any messages for debugging.
                    RedirectStandardError = true,
                    RedirectStandardOutput = true
                };

                // Start the process and check if it returned a null object.
                // A 'using' declaration ensures the process is disposed of at the end of the scope.
                using Process? process = Process.Start(psi);

                // If the process is null, it failed to start. Show an error and exit.
                if (process == null)
                {
                    Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show("Failed to start the underlying command process.", "Process Start Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                    return;
                }

                // Read the output and error streams. It's important to read both.
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                // Wait for the process to complete.
                process.WaitForExit();

                // If the process did not exit cleanly (exit code is not 0), show an error message with the details.
                if (process.ExitCode != 0)
                {
                    Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show($"Failed to launch the application (Exit Code: {process.ExitCode}).\n\nError Stream:\n{error}\n\nOutput Stream:\n{output}", "Execution Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
            }
            catch (Exception ex)
            {
                // Catch any other exceptions during process startup and show on UI thread
                Dispatcher.Invoke(() =>
                {
                    MessageBox.Show($"An unexpected error occurred while trying to launch the application: {ex.Message}", "Launcher Error", MessageBoxButton.OK, MessageBoxImage.Error);
                });
            }
        }
    }
}
