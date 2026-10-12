using System;
using System.Drawing;
using System.Windows.Forms;

namespace VirusKov.ReactOS
{
    /// <summary>
    /// Cloud scanning agreement, the same terms as Multron Win Cleaner (EULA version 4) and
    /// viruskov.com/eula.html. Must be accepted before anything is sent.
    /// </summary>
    public static class Eula
    {
        public const int Version = 4;

        public const string Text =
"VirusKov for ReactOS - Cloud Scanning Agreement (version 4)\r\n\r\n" +
"1. What the cloud scan does\r\nThis program checks files on your computer for malicious software. It sends files to the cloud scanning servers of viruskov.com, where they are examined by the viruskov.com OPEN-EDR engine, and shows you the result for each file.\r\n\r\n" +
"2. Which files are sent\r\nFiles are taken only from the folders and drives you scan and, while real-time protection is on, from the watched folders (Desktop, Downloads, Startup, Temp and the extra folders you add). By default only executable files and scripts are sent, for example .exe, .dll, .sys, .scr, .msi, .bat, .cmd, .ps1, .vbs and .js files. For each file the name, size, SHA-256 hash and the folder it is in are sent first; the content of the file is uploaded only when the server does not already know it. The folder is sent in two forms: the full path exactly as it is on your computer, including your Windows user name (for example C:\\Users\\<your name>\\Downloads), so that several user profiles on one computer can be told apart; and a short form in which your user folder and other standard Windows folders are replaced with placeholders such as %USERPROFILE%\\Downloads or %APPDATA%. Files larger than the server limit are skipped.\r\n\r\n" +
"3. Personal files\r\nWhile the \"Only executables & scripts\" option is on, which it is by default, personal files such as photos, videos, music and documents are never sent. If you turn it off, every file in the scanned locations may be uploaded and examined in the cloud.\r\n\r\n" +
"4. Transfer, processing and storage\r\nFiles are transferred over an encrypted TLS 1.2 connection. Uploaded files, their hashes, file names, folder paths (including the full paths with your user name), the IP address each file was sent from and the scan results may be stored on the viruskov.com servers. They may be used to detect and analyze malware, to write detection signatures and to train and test machine learning models, including neural networks, for example to learn in which folders malware hides. Trained models and signatures may be shipped with this program or published; they do not contain your files. Folder paths, user names and IP addresses are seen only by viruskov.com analysts; they are never published on the website or in the API and are not shared with other users. Files, folder paths and IP addresses are not sold to third parties. The boot sector backup stays on your computer and is never sent.\r\n\r\n" +
"5. What is published on viruskov.com\r\nFor each scanned file viruskov.com may publish on its file page and in its API: the SHA-256 hash, the verdict and threat name, the file names it was seen with, its size, when it was first and last seen, how often it was seen, the static analysis report and the result of a human analysis with its public note. For binary files such as programs and libraries, the report includes the text strings found in the file. For text files (scripts, configuration files and other non-binary files, UTF-8 text included) the strings are not published, because they are the content of the file itself and may contain important or personal information; only researchers with a viruskov.com API key can see them. The hashes of newly seen malicious and suspicious files are published in a daily list, and overall statistics are published without anything that identifies you.\r\n\r\n" +
"6. Your IP address\r\nThe servers see the IP address you connect from. It is used to limit the number of connections and requests, to block abuse and to keep the service running, and it is recorded in the server's connection log. It is also stored with every file you send, together with the full folder path the file was sent from, how many times it was sent from that address and when it was first and last sent. This shows from how many different sources a file was seen, which helps to tell common clean software from malware and to write better signatures, and it is used to find automated uploads (bots) and other abuse. Addresses that abuse the service may be blocked. IP addresses and the paths stored with them are seen only by viruskov.com analysts and operators; they are never published on the website or in the API, are not shared with other users and are not sold to third parties.\r\n\r\n" +
"7. Analyst review, signatures and sharing with researchers\r\nviruskov.com analysts may open and examine the files you send, give them a verdict and write detection signatures from them, for example YARA, ClamAV and similarity (TLSH) signatures. New signatures are run over the stored files to find related samples, and the verdicts of the matching files may change. Files found to be malicious or suspicious may be shared with security researchers and antivirus vendors who have a viruskov.com API key, for research and detection. Clean files are not shared.\r\n\r\n" +
"8. Your responsibilities\r\nYou confirm that you own the computer you scan or are authorized to scan it, and that you have the right to send the selected files for analysis.\r\n\r\n" +
"9. Scan results and quarantine\r\nScan results are provided for information only. A detection does not prove that a file is harmful, and a clean result does not guarantee that a file is safe. Quarantined files can be restored. Restoring the boot sector overwrites the start of your disk: only do it if you understand the warning shown.\r\n\r\n" +
"10. No warranty\r\nThe program and the cloud scan are provided \"as is\", without warranties of any kind. The service may be interrupted, changed or discontinued at any time.\r\n\r\n" +
"11. Limitation of liability\r\nTo the maximum extent permitted by applicable law, the developers and the operators of viruskov.com are not liable for any indirect, incidental, special or consequential damages, loss of data or damage to your system.\r\n\r\n" +
"12. Withdrawing consent\r\nYou can stop at any time by turning off real-time protection and not starting scans. This agreement continues to apply to files sent before you stopped.\r\n\r\n" +
"13. Changes and your legal rights\r\nWhen this agreement changes, you will be asked to accept the new version. Nothing in it limits rights you have under mandatory consumer or data protection law, such as the GDPR or the Turkish Personal Data Protection Law (KVKK).\r\n\r\n" +
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
