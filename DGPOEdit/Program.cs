using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace DGPOEdit {
    internal class Program {

        static string AddQuotesIfNeeded(string arg) {
            if (arg.StartsWith("/gpobject"))
                return $@"/gpobject:""{arg.Substring(10)}""";
            else
                return arg;
        }

        static void Main(string[] args) {

            string targetDomain = null;
            string channelName = null;
            string commandLine;
            string domainController = "";

            if (args.Length >= 2) {
                commandLine = args.Aggregate(@"""C:\WINDOWS\SYSTEM32\GPME.MSC""",
                    (current, next) => $@"{current} {AddQuotesIfNeeded(next)}");

                if (args[1].ToLower().StartsWith("/gpobject:")) {
                    Uri uri = new Uri(args[1].Substring(10));
                    domainController = uri.Host;
                    targetDomain = domainController.Substring(domainController.IndexOf('.') + 1);
                }

                Console.WriteLine($"[=] Detected GPO edit action - DC={domainController}, TargetDomain={targetDomain}");

            }else if(args.Length == 1){
                commandLine = @"""C:\WINDOWS\SYSTEM32\GPMC.MSC""";
                targetDomain = args[0];
            } else {
                Console.WriteLine("[!] Usage: DGPOEdit target_domain");
                return;
            }

            EasyHook.RemoteHooking.IpcCreateServer<DGPOHook.ServerRpc>(ref channelName, System.Runtime.Remoting.WellKnownObjectMode.Singleton);
            
            string injectionLibrary = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "DGPOHook.dll");

            EasyHook.RemoteHooking.CreateAndInject(@"c:\windows\system32\mmc.exe", commandLine, 0, EasyHook.InjectionOptions.DoNotRequireStrongName,
                injectionLibrary, injectionLibrary, out var targetPID, new object[] { targetDomain, domainController, channelName });

            Console.WriteLine($"[+] Launched MMC with PID {targetPID}, waiting for process to exit...");

            Process.GetProcessById(targetPID).WaitForExit();           
        }
    }
}
