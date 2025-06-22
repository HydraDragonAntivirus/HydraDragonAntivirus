// MainWindow.xaml.cs
using System;
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
                    FileName = "py.exe", // Python executable
                    Arguments = "-3.11 \"antivirus.py\"", // Launch antivirus GUI
                    WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory,
                    UseShellExecute = false, // Optional: could be true if you don't need Redirects
                    CreateNoWindow = false
                };

                Process.Start(psi); // JUST START, no events, no monitoring
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to launch antivirus: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}
