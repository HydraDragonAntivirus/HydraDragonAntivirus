using RestSharp;
using System.IO;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Threading;
using System.Diagnostics;
using System.Xml.Linq; // Required for XDocument

namespace HydraDragonAntivirusGUI
{
    public partial class MainWindow : Window
    {
        // Marking as nullable to satisfy non-nullable rules
        private FileSystemWatcher? logWatcher;
        // Update the path to your actual log file location.
        private readonly string logFilePath = Path.Combine(Environment.CurrentDirectory, "log", "antivirus.log");

        public MainWindow()
        {
            InitializeComponent();
            StartLogWatcher();
        }

        /// <summary>
        /// Helper to append a line into the RTF log viewer with a given color
        /// </summary>
        private void AppendLog(string? line, Brush color)
        {
            if (string.IsNullOrEmpty(line)) return;
            var p = new Paragraph(new Run(line)) { Foreground = color };
            rtbLogs.Document.Blocks.Add(p);
            rtbLogs.ScrollToEnd();
        }

        /// <summary>
        /// Sets up a FileSystemWatcher to monitor the antivirus log file in real time.
        /// </summary>
        private void StartLogWatcher()
        {
            // Ensure the log directory exists; get the directory (using ! to assert non-null)
            string logDir = Path.GetDirectoryName(logFilePath)!;
            if (!File.Exists(logFilePath))
            {
                Directory.CreateDirectory(logDir);
                File.WriteAllText(logFilePath, ""); // Create empty log file if it doesn't exist
            }

            logWatcher = new FileSystemWatcher(logDir)
            {
                Filter = Path.GetFileName(logFilePath),
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size
            };
            logWatcher.Changed += LogWatcher_Changed;
            logWatcher.EnableRaisingEvents = true;

            // Load the initial content
            LoadLogFile();
        }

        /// <summary>
        /// Called when the log file is changed. Reloads the log file content.
        /// </summary>
        private void LogWatcher_Changed(object sender, FileSystemEventArgs e)
        {
            // Use the dispatcher to update UI safely from the watcher thread.
            Dispatcher.Invoke(() => LoadLogFile());
        }

        private void BtnRunBackend_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // assume antivirus.py sits in the same folder as your .exe
                string pythonExe = "python.exe";
                string script = Path.Combine(Environment.CurrentDirectory, "antivirus.py");

                var psi = new ProcessStartInfo
                {
                    FileName = pythonExe,
                    Arguments = $"\"{script}\"",
                    WorkingDirectory = Environment.CurrentDirectory,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                var proc = Process.Start(psi);
                if (proc == null)
                    throw new InvalidOperationException("Could not start python.exe");

                // asynchronously read output and error
                proc.OutputDataReceived += (s, ea) =>
                    Dispatcher.Invoke(() => AppendLog(ea.Data, Brushes.LightGreen));
                proc.ErrorDataReceived += (s, ea) =>
                    Dispatcher.Invoke(() => AppendLog(ea.Data, Brushes.Red));

                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to run backend: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Reads the log file and updates the RichTextBox with color-coded log entries.
        /// </summary>
        private void LoadLogFile()
        {
            try
            {
                string[] lines = File.ReadAllLines(logFilePath);
                rtbLogs.Document.Blocks.Clear();

                foreach (string line in lines)
                {
                    Paragraph para = new Paragraph();
                    Run run = new Run(line);

                    // Colorize based on log level keywords
                    if (line.Contains("ERROR"))
                        run.Foreground = Brushes.Red;
                    else if (line.Contains("WARNING"))
                        run.Foreground = Brushes.Orange;
                    else if (line.Contains("INFO"))
                        run.Foreground = Brushes.LightGreen;
                    else
                        run.Foreground = Brushes.White;

                    para.Inlines.Add(run);
                    rtbLogs.Document.Blocks.Add(para);
                }
                // Scroll to the end so the latest log is visible.
                rtbLogs.ScrollToEnd();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to load log file: " + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // Event handler for Update Definitions using RestSharp
        private async void BtnUpdateDefinitions_Click(object sender, RoutedEventArgs e)
        {
            string url = "http://localhost:8000/update_definitions";
            string xmlPayload = @"<?xml version=""1.0"" encoding=""UTF-8""?>
                                  <request>
                                    <action>update_definitions</action>
                                  </request>";
            string result = await SendXmlRequestAsync(url, xmlPayload);
            MessageBox.Show(result, "Update Definitions");
        }

        // Event handler for Analyze File using RestSharp
        private async void BtnAnalyzeFile_Click(object sender, RoutedEventArgs e)
        {
            string url = "http://localhost:8000/analyze_file";
            string xmlPayload = @"<?xml version=""1.0"" encoding=""UTF-8""?>
                                  <file>
                                    <name>sample.txt</name>
                                    <content>This is sample content.</content>
                                  </file>";
            string result = await SendXmlRequestAsync(url, xmlPayload);
            MessageBox.Show(result, "Analyze File");
        }

        // Event handler for First Analysis (HiJackThis)
        private async void BtnHijackThis_Click(object sender, RoutedEventArgs e)
        {
            // Change button text for final analysis
            BtnHijackThis.Content = "Do Final Analysis";

            // Call the HiJackThis analysis endpoint (simulated as /capture)
            string url = "http://localhost:8000/capture";
            string xmlPayload = @"<?xml version=""1.0"" encoding=""UTF-8""?>
                                  <capture>
                                    <action>start_capture</action>
                                  </capture>";
            string result = await SendXmlRequestAsync(url, xmlPayload);
            MessageBox.Show(result, "First Analysis Complete");
        }

        // Event handler for Compute Diff (final analysis)
        private async void BtnComputeDiff_Click(object sender, RoutedEventArgs e)
        {
            // Wait for 5 minutes (simulate with a task delay)
            BtnComputeDiff.IsEnabled = false; // Disable the button to prevent re-clicking
            MessageBox.Show("Please wait for 5 minutes before proceeding.", "Wait", MessageBoxButton.OK, MessageBoxImage.Information);

            await Task.Delay(TimeSpan.FromMinutes(5)); // Wait 5 minutes before calling the diff computation

            // Call the compute_diff endpoint
            string url = "http://localhost:8000/compute_diff";
            string xmlPayload = @"<?xml version=""1.0"" encoding=""UTF-8""?>
                                  <diff>
                                    <action>compute_diff</action>
                                  </diff>";
            string result = await SendXmlRequestAsync(url, xmlPayload);
            MessageBox.Show(result, "Compute Diff Complete");

            // After 5 minutes, disable the button (since the analysis is done)
            BtnHijackThis.IsEnabled = false; // Disable "Do Final Analysis" button
        }

        private async Task<string> SendXmlRequestAsync(string url, string xmlPayload)
        {
            try
            {
                // Create a RestClient with the base URL (url here contains the full endpoint)
                var client = new RestClient(url);
                // Pass an empty resource string along with the Method.Post value
                var request = new RestRequest("", Method.Post);
                request.AddHeader("Content-Type", "application/xml");
                request.AddParameter("application/xml", xmlPayload, ParameterType.RequestBody);

                RestResponse response = await client.ExecuteAsync(request);
                if (response.IsSuccessful)
                {
                    // Optionally, parse the XML response
                    try
                    {
                        XDocument xmlResponse = XDocument.Parse(response.Content);
                        string status = xmlResponse.Root?.Element("status")?.Value;
                        string message = xmlResponse.Root?.Element("message")?.Value;
                        return $"Status: {status}\nMessage: {message}";
                    }
                    catch
                    {
                        return "Raw Response:\n" + response.Content;
                    }
                }
                else
                {
                    return $"Error: {response.StatusCode} - {response.ErrorMessage}";
                }
            }
            catch (Exception ex)
            {
                return "Exception: " + ex.Message;
            }
        }
    }
}
