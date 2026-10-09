using System;
using System.Drawing;
using System.Windows.Forms;

namespace VirusKov.ReactOS
{
    /// <summary>
    /// Cloud scanning agreement, the same terms as Multron Win Cleaner (EULA version 2) and
    /// viruskov.com/eula.html. Must be accepted before anything is sent.
    /// </summary>
    public static class Eula
    {
        public const int Version = 2;

        public const string Text =
"VirusKov for ReactOS - Cloud Scanning Agreement (version 2)\r\n\r\n" +
"1. What the cloud scan does\r\n" +
"This program checks files on your computer for malicious software. It sends files to the cloud scanning servers of viruskov.com, where they are examined by the viruskov.com OPEN-EDR engine, and shows you the result for each file.\r\n\r\n" +
"2. Which files are sent\r\n" +
"Files are taken only from the folders and drives you scan and, while real-time protection is on, from the watched folders (Desktop, Downloads, Startup, Temp and the extra folders you add). By default only executable files and scripts are sent, for example .exe, .dll, .sys, .scr, .msi, .bat, .cmd, .ps1, .vbs and .js files. For each file the name, size, SHA-256 hash and the path of the folder it is in are sent first; the content of the file is uploaded only when the server does not already know it. Before the folder path is sent, your user folder and other standard Windows folders are replaced with placeholders such as %USERPROFILE%\\Downloads or %APPDATA%, so your user name is not sent. Files larger than the server limit are skipped.\r\n\r\n" +
"3. Personal files\r\n" +
"While the \"Only executables & scripts\" option is on, which it is by default, personal files such as photos, videos, music and documents are never sent. If you turn it off, every file in the scanned locations may be uploaded and examined in the cloud.\r\n\r\n" +
"4. Transfer, processing and storage\r\n" +
"Files are transferred over an encrypted TLS 1.2 connection. Uploaded files, their hashes, file names, folder paths and the scan results may be stored on the viruskov.com servers and used to detect and analyze malware and to improve detection, for example to learn in which folders malware hides. Folder paths are seen only by viruskov.com analysts and are never published on the website or shared with other users. Files and folder paths are not sold to third parties. The boot sector backup stays on your computer and is never sent.\r\n\r\n" +
"5. Your responsibilities\r\n" +
"You confirm that you own the computer you scan or are authorized to scan it, and that you have the right to send the selected files for analysis.\r\n\r\n" +
"6. Scan results and quarantine\r\n" +
"Scan results are provided for information only. A detection does not prove that a file is harmful, and a clean result does not guarantee that a file is safe. Quarantined files can be restored. Restoring the boot sector overwrites the start of your disk: only do it if you understand the warning shown.\r\n\r\n" +
"7. No warranty\r\n" +
"The program and the cloud scan are provided \"as is\", without warranties of any kind. The service may be interrupted, changed or discontinued at any time.\r\n\r\n" +
"8. Limitation of liability\r\n" +
"To the maximum extent permitted by applicable law, the developers and the operators of viruskov.com are not liable for any indirect, incidental, special or consequential damages, loss of data or damage to your system.\r\n\r\n" +
"9. Withdrawing consent\r\n" +
"You can stop at any time by turning off real-time protection and not starting scans. This agreement continues to apply to files sent before you stopped.\r\n\r\n" +
"10. Changes and your legal rights\r\n" +
"When this agreement changes, you will be asked to accept the new version. Nothing in it limits rights you have under mandatory consumer or data protection law, such as the GDPR or the Turkish Personal Data Protection Law (KVKK).\r\n\r\n" +
"Full text: https://viruskov.com/eula.html";

        /// <summary>Shows the agreement. True when accepted.</summary>
        public static bool Ask(bool readOnly)
        {
            using (var f = new Form())
            {
                f.Text = "VirusKov - Cloud Scanning Agreement";
                f.ClientSize = new Size(620, 460);
                f.StartPosition = FormStartPosition.CenterScreen;
                f.MinimizeBox = false;
                f.MaximizeBox = false;
                f.FormBorderStyle = FormBorderStyle.FixedDialog;

                var box = new TextBox();
                box.Multiline = true;
                box.ReadOnly = true;
                box.ScrollBars = ScrollBars.Vertical;
                box.Text = Text;
                box.SetBounds(10, 10, 600, 400);
                box.BackColor = SystemColors.Window;
                f.Controls.Add(box);

                var ok = new Button();
                ok.Text = readOnly ? "Close" : "I accept";
                ok.SetBounds(readOnly ? 520 : 410, 420, 100, 28);
                ok.DialogResult = DialogResult.OK;
                f.Controls.Add(ok);
                f.AcceptButton = ok;

                if (!readOnly)
                {
                    var no = new Button();
                    no.Text = "Decline";
                    no.SetBounds(520, 420, 100, 28);
                    no.DialogResult = DialogResult.Cancel;
                    f.Controls.Add(no);
                    f.CancelButton = no;
                }
                return f.ShowDialog() == DialogResult.OK;
            }
        }
    }
}
