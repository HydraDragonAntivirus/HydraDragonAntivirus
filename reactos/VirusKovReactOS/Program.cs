using System;
using System.Threading;
using System.Windows.Forms;

namespace VirusKov.ReactOS
{
    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            bool created;
            using (var single = new Mutex(true, "VirusKovReactOS.SingleInstance", out created))
            {
                if (!created)
                {
                    MessageBox.Show("VirusKov is already running (look in the tray).", "VirusKov");
                    return;
                }
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.ThreadException += (s, e) => Log.Write("UI error: " + e.Exception);
                AppDomain.CurrentDomain.UnhandledException += (s, e) => Log.Write("fatal: " + e.ExceptionObject);

                Settings settings = Settings.Load();
                if (settings.EulaAccepted < Eula.Version)
                {
                    if (!Eula.Ask(false))
                        return;
                    settings.EulaAccepted = Eula.Version;
                    settings.Save();
                }
                bool minimized = false;
                foreach (string a in args)
                    if (a.Equals("/minimized", StringComparison.OrdinalIgnoreCase)) minimized = true;
                Application.Run(new MainForm(settings, minimized));
            }
        }
    }
}
