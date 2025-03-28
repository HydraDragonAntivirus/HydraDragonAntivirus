using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Documents;
using Newtonsoft.Json;
using RestSharp;
using System.Threading.Tasks;

namespace OpenHydra
{
    public partial class MainWindow : Window
    {
        private readonly string apiUrl = "http://localhost:8000";
        private readonly RestClient client;

        public MainWindow()
        {
            InitializeComponent();
            client = new RestClient(apiUrl);

            // Run async task after UI fully loads
            Dispatcher.InvokeAsync(async () => await LoadSignaturesAsync());

            LoadEditorContent();
        }

        /// <summary>
        /// Loads the editor with default instructions.
        /// </summary>
        private void LoadEditorContent()
        {
            var defaultText = "Enter additional notes, examples, or instructions for the signature here...";
            SignatureRichTextBox.Document.Blocks.Clear();
            SignatureRichTextBox.Document.Blocks.Add(new Paragraph(new Run(defaultText)));
        }

        /// <summary>
        /// Loads existing signatures from the backend, handling errors gracefully.
        /// </summary>
        private async Task LoadSignaturesAsync()
        {
            try
            {
                var request = new RestRequest("signature", Method.Get);
                var response = await client.ExecuteAsync(request);

                if (response.IsSuccessful && !string.IsNullOrWhiteSpace(response.Content))
                {
                    var signatures = JsonConvert.DeserializeObject<List<Signature>>(response.Content);
                    SignatureListBox.Items.Clear();

                    if (signatures.Count > 0)
                    {
                        foreach (var sig in signatures)
                        {
                            SignatureListBox.Items.Add($"{sig.Name} - {sig.Pattern}");
                        }
                    }
                    else
                    {
                        SignatureListBox.Items.Add("No signatures found.");
                    }
                }
                else
                {
                    SignatureListBox.Items.Clear();
                    SignatureListBox.Items.Add("Error: Could not load signatures.");
                }
            }
            catch (Exception ex)
            {
                SignatureListBox.Items.Clear();
                SignatureListBox.Items.Add("Error connecting to backend.");
                MessageBox.Show("Could not connect to backend: " + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        /// <summary>
        /// Submits a new signature to the backend.
        /// </summary>
        private async void SubmitSignature_Click(object sender, RoutedEventArgs e)
        {
            string name = SignatureNameTextBox.Text.Trim();
            string pattern = SignaturePatternTextBox.Text.Trim();
            string description = SignatureDescriptionTextBox.Text.Trim();

            string richText = new TextRange(SignatureRichTextBox.Document.ContentStart, SignatureRichTextBox.Document.ContentEnd).Text.Trim();
            if (!string.IsNullOrEmpty(richText))
            {
                description += "\nAdditional Notes: " + richText;
            }

            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(pattern))
            {
                MessageBox.Show("Please provide both a signature name and pattern.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var signatureData = new Signature { Name = name, Pattern = pattern, Description = description };

            try
            {
                var request = new RestRequest("signature", Method.Post);
                request.AddJsonBody(signatureData);
                var response = await client.ExecuteAsync(request);

                if (response.IsSuccessful)
                {
                    MessageBox.Show("Signature submitted successfully.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                    ClearInputFields();
                    await LoadSignaturesAsync();  // Refresh list
                }
                else
                {
                    MessageBox.Show("Submission failed: " + response.ErrorMessage, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error during submission: " + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Clears all input fields after a successful submission.
        /// </summary>
        private void ClearInputFields()
        {
            SignatureNameTextBox.Text = "";
            SignaturePatternTextBox.Text = "";
            SignatureDescriptionTextBox.Text = "";
            SignatureRichTextBox.Document.Blocks.Clear();
        }
    }

    public class Signature
    {
        public string Name { get; set; }
        public string Pattern { get; set; }
        public string Description { get; set; }
    }
}
