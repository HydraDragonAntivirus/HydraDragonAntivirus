/*
 * Created by SharpDevelop.
 * User: Bogdan
 * Date: 27.10.2010
 * Time: 18:02
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.Collections;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace Mega_Dumper
{
    internal enum COR_PUB_ENUMPROCESS
    {
        /// <summary>
        /// Indicates that we need to get managed processes only
        /// </summary>
        COR_PUB_MANAGEDONLY = 0x00000001
    }

    /// <summary>
    /// This is ICorePublish default interface implementation
    /// </summary>
    [Guid("047a9a40-657e-11d3-8d5b-00104b35e7ef")]
    [ClassInterface(ClassInterfaceType.None)]
    [ComImport()]
    internal class CorpubPublish { }

    /// <summary>
    /// CLR core interface for working with managed processes
    /// </summary>
    [ComImport()]
    [Guid("9613A0E7-5A68-11D3-8F84-00A0C9B4D50C")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface ICorPublish
    {
        /// <summary>
        /// Gets a set of managed processes
        /// </summary>
        void EnumProcesses([In] COR_PUB_ENUMPROCESS Type, [Out] out ICorPublishProcessEnum ppIenum);

        /// <summary>
        /// Gets a managed process by ID
        /// </summary>
        void GetProcess([In] uint pid, [Out] out ICorPublishProcess ppProcess);
    }

    [ComImport()]
    [Guid("D6315C8F-5A6A-11d3-8F84-00A0C9B4D50C")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface ICorPublishAppDomain
    {
        /// <summary>
        /// Gets domain ID
        /// </summary>
        void GetID([Out] out uint puId);

        /// <summary>
        /// Gets domain name
        /// </summary>
        void GetName([In, MarshalAs(UnmanagedType.U4)] uint cchName, [Out, MarshalAs(UnmanagedType.U4)] out uint pcchName, [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder szName);
    }

    [ComImport()]
    [Guid("9F0C98F5-5A6A-11d3-8F84-00A0C9B4D50C")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface ICorPublishAppDomainEnum
    {
        /// <summary>
        /// Skips a set of domains
        /// </summary>
        void Skip([In] uint celt);

        /// <summary>
        /// Resets the collection
        /// </summary>
        void Reset();

        /// <summary>
        /// Creates a deep copy of the collection
        /// </summary>
        void Clone([Out] out ICorPublishEnum ppEnum);

        /// <summary>
        /// Gets the collection size
        /// </summary>
        void GetCount([Out] out uint pcelt);

        /// <summary>
        /// Gets next set of managed domains
        /// </summary>
        int Next([In] uint celt, [MarshalAs(UnmanagedType.Interface)][Out] out ICorPublishAppDomain objects, [Out] out uint pceltFetched);
    }

    [ComImport()]
    [Guid("C0B22967-5A69-11D3-8F84-00A0C9B4D50C")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface ICorPublishEnum
    {
        void Skip([In] uint celt);
        void Reset();
        void Clone([Out] out ICorPublishEnum ppEnum);
        void GetCount([Out] out uint pcelt);
    }

    [ComImport()]
    [Guid("18D87AF1-5A6A-11d3-8F84-00A0C9B4D50C")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface ICorPublishProcess
    {
        /// <summary>
        /// Gets if the process is managed
        /// </summary>
        void IsManaged([Out, MarshalAs(UnmanagedType.Bool)] out bool pbManaged);

        /// <summary>
        /// Gets loaded domains set for process
        /// </summary>
        void EnumAppDomains([Out] out ICorPublishAppDomainEnum ppEnum);

        /// <summary>
        /// Gets process ID
        /// </summary>
        void GetProcessID([Out] out uint pid);

        /// <summary>
        /// Gets process name
        /// </summary>
        void GetDisplayName([In] uint cchName, [Out] out uint pcchName, [Out] StringBuilder szName);
    }

    [ComImport()]
    [Guid("A37FBD41-5A69-11d3-8F84-00A0C9B4D50C")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface ICorPublishProcessEnum
    {
        /// <summary>
        /// Skips a set of processes
        /// </summary>
        void Skip([In] uint celt);

        /// <summary>
        /// Resets the collection
        /// </summary>
        void Reset();

        /// <summary>
        /// Creates a deep copy of the collection
        /// </summary>
        void Clone([Out] out ICorPublishEnum ppEnum);

        /// <summary>
        /// Gets the collection size
        /// </summary>
        void GetCount([Out] out uint pcelt);

        /// <summary>
        /// Gets the set of managed processes
        /// </summary>
        int Next([In] uint celt, [Out] out ICorPublishProcess objects, [Out] out uint pceltFetched);
    }

    public class ManagedProcessInfoCollection : IEnumerator, ICollection, IEnumerable, ICloneable
    {
        private ICorPublishProcess CurrentProcess;
        private readonly ICorPublishProcessEnum Processes;

        // Methods
        internal ManagedProcessInfoCollection(ICorPublishProcessEnum AllProcesses)
        {
            Processes = AllProcesses;
            CurrentProcess = null;
        }

        public object Clone()
        {
            ((ICorPublishEnum)Processes).Clone(out ICorPublishEnum ppEnum);
            if (ppEnum != null)
            {
                return new ManagedProcessInfoCollection((ICorPublishProcessEnum)ppEnum);
            }
            return null;
        }

        public void CopyTo(Array Destination, int index)
        {
            if (Destination == null)
            {
                throw new ArgumentNullException("Destination array cannot be null.");
            }
            if (Destination.Rank != 1)
            {
                throw new ArgumentException("Invalid array rank!");
            }
            int num = index;
            ManagedProcessInfo[] infoArray = (ManagedProcessInfo[])Destination;
            foreach (ManagedProcessInfo info in this)
            {
                infoArray[num++] = info;
            }
        }

        public IEnumerator GetEnumerator()
        {
            return this;
        }

        public bool MoveNext()
        {
            Processes.Next(1, out CurrentProcess, out uint pceltFetched);
            if (pceltFetched != 1)
            {
                CurrentProcess = null;
            }
            return (CurrentProcess != null) && (pceltFetched == 1);
        }

        public void Reset()
        {
            Processes.Reset();
            CurrentProcess = null;
        }

        // Properties
        public int Count
        {
            get
            {
                Processes.GetCount(out uint pcelt);
                return (int)pcelt;
            }
        }

        public object Current
        {
            get
            {
                if (CurrentProcess != null)
                {
                    return new ManagedProcessInfo(CurrentProcess);
                }
                return null;
            }
        }

        public bool IsSynchronized => true;
        public object SyncRoot { get; } = new();
    }

    public class ManagedDomainInfo
    {
        // Fields
        private readonly ICorPublishAppDomain Domain;

        // Methods
        internal ManagedDomainInfo(ICorPublishAppDomain SingleDomain)
        {
            Domain = SingleDomain;
        }

        // Properties
        public uint DomainID
        {
            get
            {
                Domain.GetID(out uint puId);
                return puId;
            }
        }

        public string DomainName
        {
            get
            {
                StringBuilder szName = new(0xff);
                Domain.GetName(0xff, out uint pcchName, szName);
                if ((pcchName > 0) && (pcchName > 0xff))
                {
                    szName = new StringBuilder((int)pcchName);
                    Domain.GetName(pcchName, out _, szName);
                }
                return szName.ToString();
            }
        }
    }

    public class ManagedDomainInfoCollection : IEnumerator, ICollection, IEnumerable, ICloneable
    {
        private ICorPublishAppDomain CurrentDomain;
        private readonly ICorPublishAppDomainEnum Domains;

        // Methods
        internal ManagedDomainInfoCollection(ICorPublishAppDomainEnum AllDomains)
        {
            Domains = AllDomains;
            CurrentDomain = null;
        }

        public object Clone()
        {
            ((ICorPublishEnum)Domains).Clone(out ICorPublishEnum ppEnum);
            if (ppEnum != null)
            {
                return new ManagedDomainInfoCollection((ICorPublishAppDomainEnum)ppEnum);
            }
            return null;
        }

        public void CopyTo(Array Destination, int index)
        {
            if (Destination == null)
            {
                throw new ArgumentNullException("Destination array cannot be null.");
            }
            if (Destination.Rank != 1)
            {
                throw new ArgumentException("Invalid array rank!");
            }
            int num = index;
            ManagedDomainInfo[] infoArray = (ManagedDomainInfo[])Destination;
            foreach (ManagedDomainInfo info in this)
            {
                infoArray[num++] = info;
            }
        }

        public IEnumerator GetEnumerator()
        {
            return this;
        }

        public bool MoveNext()
        {
            Domains.Next(1, out CurrentDomain, out uint pceltFetched);
            if (pceltFetched != 1)
            {
                CurrentDomain = null;
            }
            return (CurrentDomain != null) && (pceltFetched == 1);
        }

        public void Reset()
        {
            Domains.Reset();
            CurrentDomain = null;
        }

        // Properties
        public int Count
        {
            get
            {
                Domains.GetCount(out uint pcelt);
                return (int)pcelt;
            }
        }

        public object Current
        {
            get
            {
                if (CurrentDomain != null)
                {
                    return new ManagedDomainInfo(CurrentDomain);
                }
                return null;
            }
        }

        public bool IsSynchronized => true;

        public object SyncRoot { get; } = new();
    }

    public class ManagedProcessInfo
    {
        // Fields
        private readonly ICorPublishProcess Process;

        // Methods
        internal ManagedProcessInfo(ICorPublishProcess SingleProcess)
        {
            Process = SingleProcess;
        }

        public Process ConvertToDiagnosticsProcess()
        {
            return System.Diagnostics.Process.GetProcessById((int)ProcessID);
        }

        public static ManagedProcessInfo GetProcessByID(uint ID)
        {
            ICorPublish publish = (ICorPublish)new CorpubPublish();
            if (publish != null)
            {
                publish.GetProcess(ID, out ICorPublishProcess ppProcess);
                if (ppProcess != null)
                {
                    return new ManagedProcessInfo(ppProcess);
                }
            }
            return null;
        }

        public class ManagedProcessInfoCollection : IEnumerator, ICollection, IEnumerable, ICloneable
        {
            private ICorPublishProcess CurrentProcess;
            private readonly ICorPublishProcessEnum Processes;

            // Methods
            internal ManagedProcessInfoCollection(ICorPublishProcessEnum AllProcesses)
            {
                Processes = AllProcesses;
                CurrentProcess = null;
            }

            public object Clone()
            {
                ((ICorPublishEnum)Processes).Clone(out ICorPublishEnum ppEnum);
                if (ppEnum != null)
                {
                    return new ManagedProcessInfoCollection((ICorPublishProcessEnum)ppEnum);
                }
                return null;
            }

            public void CopyTo(Array Destination, int index)
            {
                if (Destination == null)
                {
                    throw new ArgumentNullException("Destination array cannot be null.");
                }
                if (Destination.Rank != 1)
                {
                    throw new ArgumentException("Invalid array rank!");
                }
                int num = index;
                ManagedProcessInfo[] infoArray = (ManagedProcessInfo[])Destination;
                foreach (ManagedProcessInfo info in this)
                {
                    infoArray[num++] = info;
                }
            }

            public IEnumerator GetEnumerator()
            {
                return this;
            }

            public bool MoveNext()
            {
                Processes.Next(1, out CurrentProcess, out uint pceltFetched);
                if (pceltFetched != 1)
                {
                    CurrentProcess = null;
                }
                return (CurrentProcess != null) && (pceltFetched == 1);
            }

            public void Reset()
            {
                Processes.Reset();
                CurrentProcess = null;
            }

            // Properties
            public int Count
            {
                get
                {
                    Processes.GetCount(out uint pcelt);
                    return (int)pcelt;
                }
            }

            public object Current
            {
                get
                {
                    if (CurrentProcess != null)
                    {
                        return new ManagedProcessInfo(CurrentProcess);
                    }
                    return null;
                }
            }

            public bool IsSynchronized => true;

            public object SyncRoot { get; } = new();
        }

        public static ManagedProcessInfoCollection GetProcesses()
        {
            ICorPublish publish = (ICorPublish)new CorpubPublish();
            if (publish != null)
            {
                publish.EnumProcesses(COR_PUB_ENUMPROCESS.COR_PUB_MANAGEDONLY, out ICorPublishProcessEnum ppIenum);
                if (ppIenum != null)
                {
                    return new ManagedProcessInfoCollection(ppIenum);
                }
            }
            return null;
        }

        // Properties
        public string DisplayName
        {
            get
            {
                StringBuilder szName = new(0xff);
                Process.GetDisplayName(0xff, out uint pcchName, szName);
                if ((pcchName > 0) && (pcchName > 0xff))
                {
                    szName = new StringBuilder((int)pcchName);
                    Process.GetDisplayName(pcchName, out _, szName);
                }
                return szName.ToString();
            }
        }

        public ManagedDomainInfoCollection LoadedDomains
        {
            get
            {
                Process.EnumAppDomains(out ICorPublishAppDomainEnum ppEnum);
                if (ppEnum != null)
                {
                    return new ManagedDomainInfoCollection(ppEnum);
                }
                return null;
            }
        }

        public uint ProcessID
        {
            get
            {
                Process.GetProcessID(out uint pid);
                return pid;
            }
        }
    }

    /// <summary>
    /// Description of Form2.
    /// </summary>
    public partial class NetPerformance : Form
    {
        public string ProcessName;
        public int procid;
        public NetPerformance(string procname, int prid)
        {
            ProcessName = procname;
            procid = prid;
            //
            // The InitializeComponent() call is required for Windows Forms designer support.
            //
            InitializeComponent();

            //
            // TODO: Add constructor code after the InitializeComponent() call.
            //
        }

        private void Form2Load(object sender, EventArgs e)
        {
            Text = ".NET Performance for " + ProcessName + " whit PID=" + procid.ToString();
            comboBox1.Items.Add(".NET CLR Memory");
            comboBox1.Items.Add(".NET CLR Jit");
            comboBox1.Items.Add(".NET CLR Exceptions");
            comboBox1.Items.Add(".NET CLR LocksAndThreads");
            comboBox1.Items.Add(".NET CLR Data");
            comboBox1.Items.Add(".NET CLR Interop");
            comboBox1.Items.Add(".NET CLR Loading");
            comboBox1.Items.Add(".NET CLR Remoting");
            comboBox1.Items.Add(".NET CLR Security");
            comboBox1.SelectedIndex = 0;
        }

        private void ComboBox1SelectedIndexChanged(object sender, EventArgs e)
        {
            perfobject.Items.Clear();
            string[] instanceNames;
            ArrayList counters = new();
            if (comboBox1.SelectedIndex != -1)
            {
                PerformanceCounterCategory mycat = new(comboBox1.SelectedItem.ToString());
                instanceNames = mycat.GetInstanceNames();
                int proccount = 0;
                for (int i = 0; i < instanceNames.Length; i++)
                {
                    string fortest = instanceNames[i].ToLower();
                    int lastdiez = fortest.LastIndexOf("#");
                    if (lastdiez != -1)
                    {
                        fortest = fortest.Remove(lastdiez, fortest.Length - lastdiez);
                    }
                    if (ProcessName.ToLower().Contains(fortest))
                    {
                        proccount++;
                        if (proccount >= 2) break;
                    }
                }

                for (int i = 0; i < instanceNames.Length; i++)
                {
                    bool IsFinded = false;
                    PerformanceCounterCategory mycattest = new(".NET CLR Memory");
                    ArrayList testcounters = new();
                    testcounters.AddRange(mycattest.GetCounters(instanceNames[i]));

                    foreach (PerformanceCounter tcounter in testcounters)
                    {
                        if (tcounter.CounterName == "Process ID")
                        {
                            IsFinded = (int)tcounter.RawValue == procid;
                        }
                    }

                    if (!IsFinded || proccount >= 2)
                    {
                        string fortest = instanceNames[i];
                        int lastdiez = fortest.LastIndexOf("#");
                        if (lastdiez != -1)
                        {
                            fortest = fortest.Remove(lastdiez, fortest.Length - lastdiez);
                        }
                        if (ProcessName.IndexOf(fortest, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            IsFinded = true;
                            string[] prcdet = new string[] { "" };
                            ListViewItem proctadd = new(prcdet);
                            perfobject.Items.Add(proctadd);
                            prcdet = new string[] { instanceNames[i] };
                            proctadd = new ListViewItem(prcdet);
                            perfobject.Items.Add(proctadd);
                        }
                    }

                    if (IsFinded)
                    {
                        counters.AddRange(mycat.GetCounters(instanceNames[i]));
                        // Add the retrieved counters to the list.
                        foreach (PerformanceCounter counter in counters)
                        {
                            string[] prcdetails = new string[] { counter.CounterName, counter.RawValue.ToString() };
                            ListViewItem proc = new(prcdetails);
                            perfobject.Items.Add(proc);
                        }
                    }
                    if (proccount < 2 && IsFinded) break;
                }
            }
        }
    }
}
