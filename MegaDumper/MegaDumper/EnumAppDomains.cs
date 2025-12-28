/*
 * Created by SharpDevelop.
 * User: Bogdan
 * Date: 02.03.2011
 * Time: 19:07
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.Text;
using System.Windows.Forms;

namespace Mega_Dumper
{
    /// <summary>
    /// Description of EnumAssemblies.
    /// </summary>
    public partial class EnumAppDomains : Form
    {
        private readonly int procid = 0;
        public EnumAppDomains(int processid)
        {
            procid = processid;
            //
            // The InitializeComponent() call is required for Windows Forms designer support.
            //
            InitializeComponent();

            //
            // TODO: Add constructor code after the InitializeComponent() call.
            //
        }

        private void EnumAppDomainsShown(object sender, EventArgs e)
        {
            ICorPublish publish = (ICorPublish)new CorpubPublish();

            if (publish != null)
            {
                ICorPublishProcess ppProcess = null;
                try
                {
                    publish.GetProcess((uint)procid, out ppProcess);
                }
                catch
                {
                }

                if (ppProcess != null)
                {
                    ppProcess.IsManaged(out bool IsManaged);
                    if (IsManaged)
                    {
                        // Enumerate the domains within the process.
                        ppProcess.EnumAppDomains(out ICorPublishAppDomainEnum ppEnum);

                        // ICorPublishAppDomain
                        while (ppEnum.Next(1, out ICorPublishAppDomain pappDomain, out uint aFetched) == 0 && aFetched > 0)
                        {
                            StringBuilder szName = null;
                            try
                            {
                                pappDomain.GetName(0, out uint pcchName, null);
                                szName = new StringBuilder((int)pcchName);
                                pappDomain.GetName((uint)szName.Capacity, out pcchName, szName);
                            }
                            catch
                            {
                            }

                            string appdomainname = szName.ToString();
                            pappDomain.GetID(out uint appdomainid);

                            ListViewItem appdomaintoadd = new(new string[] { appdomainid.ToString(), appdomainname });
                            lvdomains.Items.Add(appdomaintoadd);
                        }
                    }
                    else
                    {
                        MessageBox.Show("Selected process is not a managed .NET process!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                }
                else
                {
                    MessageBox.Show("Failed to open slected process \r\n" +
                                                "maybe is not a .NET process!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
        }
    }
}
