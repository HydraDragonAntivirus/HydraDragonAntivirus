// MainWindow.xaml.cs
using System.Diagnostics;
using System.Windows;

namespace HydraDragonAntivirusLauncher
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void BtnLaunch_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "py.exe",
                    Arguments = "-3.12 \"antivirus.py\"",
                    WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                var proc = Process.Start(psi);
                if (proc == null)
                {
                    MessageBox.Show("Failed to start antivirus process.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                proc.OutputDataReceived += (s, ea) =>
                {
                    if (!string.IsNullOrEmpty(ea.Data))
                        Dispatcher.Invoke(() => MessageBox.Show(ea.Data, "Output", MessageBoxButton.OK, MessageBoxImage.Information));
                };
                proc.ErrorDataReceived += (s, ea) =>
                {
                    if (!string.IsNullOrEmpty(ea.Data))
                        Dispatcher.Invoke(() => MessageBox.Show(ea.Data, "Error", MessageBoxButton.OK, MessageBoxImage.Error));
                };

                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Exception: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}
