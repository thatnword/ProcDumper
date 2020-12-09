using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Process_Dumper {
    class Program {
        static Random r = new Random();

        static Stopwatch sw = new Stopwatch();

        static List<string> svchostList = new List<string>();

        static string[] exclusionList = { "svchost", "cmd", "chrome", "opera", "firefox", "discord" }; // always keep svchost in this list, this prevents duplicated dumps

        static string additionalCommands = ""; // add your own commands

        static string path = AppDomain.CurrentDomain.BaseDirectory;

        static void Main(string[] args) {
            Console.WriteLine("Proc Dumper v0.2");

            // setup all needed directories and files
            if (!Directory.Exists("dumps") || !Directory.Exists("assets")) {
                Directory.CreateDirectory("dumps");
                Directory.CreateDirectory("assets");
                File.WriteAllBytes("assets\\dumper.exe", Properties.Resources.s2);
            }

            runCommand($"cd {path}assets & tasklist /svc | find \"svchost.exe\" > svchost.log");

            Thread.Sleep(500);

            sw.Start();

            // gather service list and dump them
            getSvchost();
            dumpSvchost();

            // dump all normal processes excluding whatever is in the Exclusion List
            dumpProcesses();

            Thread.Sleep(1000);

            // wait for all dumps to be fully finished
            // credits: LevensLes
            Process[] cmdprocs = Process.GetProcessesByName("dumper");
            int procsLeft = cmdprocs.Length;

            foreach (var proc in cmdprocs) {
                while (procsLeft != 0) {
                    int currentproc = proc.Id;
                    if (!getParent(currentproc).Equals(Process.GetCurrentProcess().ProcessName))
                        procsLeft--;
                }
            }

            Console.WriteLine($"\nFinished dumping all system processes & services in {sw.ElapsedMilliseconds}ms.");
            Console.ReadLine();
        }

        /// <summary>
        /// process dumper
        /// </summary>
        static void dumpProcesses() {
            Console.WriteLine("\nDumping processes - Step 2");

            var allProcesses = Process.GetProcesses();
            foreach (Process p in allProcesses) {
                new Thread(() => {
                    try {
                        if (!exclusionList.Contains(p.ProcessName)) {
                            // creat directory for specific process if it doesnt exist
                            if (!Directory.Exists($"dumps\\{p.ProcessName}"))
                                Directory.CreateDirectory($"dumps\\{p.ProcessName}");

                            // dump process
                            runCommand($"\"{path}assets\\\"dumper.exe -pid {p.Id} -l 4 -nh {additionalCommands} > \"{path}dumps\\{p.ProcessName}\\\"{p.ProcessName}_{r.Next(0, 999999999)}.txt");
                        }
                    } catch { Console.WriteLine($"Failed to dump process \"{p.ProcessName}\""); }
                }).Start();
            }
        }

        /// <summary>
        /// svchost/service dumper
        /// </summary>
        static void dumpSvchost() {
            Console.WriteLine("\nDumping services - Step 1");

            // creat special directory for all services to go
            if (!Directory.Exists("dumps\\svchost"))
                Directory.CreateDirectory("dumps\\svchost");

            foreach (string service in svchostList) {
                new Thread(() => {
                    try {
                        // creat directory for specific service if it doesnt exist
                        if (!Directory.Exists($"dumps\\svchost\\{service}"))
                            Directory.CreateDirectory($"dumps\\svchost\\{service}");

                        // dump service 
                        runCommand($"\"{path}assets\\\"dumper.exe -pid {getService(service)} -l 4 -nh {additionalCommands} > \"{path}dumps\\svchost\\{service}\\\"{service}_{r.Next(0, 999999999)}.txt");
                    } catch { Console.WriteLine($"Failed to dump service \"{service}\""); }
                }).Start();
            }
        }

        /// <summary>
        /// parse through svchost list and grab only the service name
        /// </summary>
        static void getSvchost() {
            string reader = File.ReadAllText("assets\\svchost.log");
            foreach (string line in reader.Split('\n')) {
                if (line.Length > 5) {
                    string serviceName = line.Substring(35).Replace(" ", "").Replace(",", ".");
                    svchostList.Add(serviceName.Substring(0, serviceName.Length - 1));
                }
            }
        }

        /// <summary>
        /// run any command input through cmd as admin
        /// </summary>
        static void runCommand(string command) {
            Process CMD = new Process();
            CMD.StartInfo.FileName = "cmd.exe";
            CMD.StartInfo.RedirectStandardInput = true;
            CMD.StartInfo.RedirectStandardOutput = true;
            CMD.StartInfo.CreateNoWindow = true;
            CMD.StartInfo.UseShellExecute = false;
            CMD.Start();

            CMD.StandardInput.WriteLine(command);
            CMD.StandardInput.Flush();
            CMD.StandardInput.Close();
        }

        /// <summary>
        /// get parent process list
        /// taken from Lev's version of proc dump
        /// </summary>
        static string getParent(int pid) {
            try {
                var myId = pid;
                var query = string.Format("SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {0}", myId);
                var search = new ManagementObjectSearcher("root\\CIMV2", query);
                var results = search.Get().GetEnumerator();
                results.MoveNext();
                var queryObj = results.Current;
                var parentId = (uint) queryObj["ParentProcessId"];
                var parent = Process.GetProcessById((int) parentId);

                return parent.ProcessName;
            } catch (Exception e) {
                return "prolly died so is fine";
            }
        }

        /// <summary>
        /// Gets the PID of specifc services
        /// </summary>
        static uint getService(string serviceName) {
            uint processId = 0;
            string qry = "SELECT PROCESSID FROM WIN32_SERVICE WHERE NAME = '" + serviceName + "'";
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(qry);

            foreach (System.Management.ManagementObject mngntObj in searcher.Get())
                processId = (uint) mngntObj["PROCESSID"];

            return processId;
        }
    }
}
