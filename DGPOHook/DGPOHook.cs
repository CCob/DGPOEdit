using System;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.Remoting.Messaging;
using System.Security.Permissions;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using EasyHook;
using Microsoft.Win32.SafeHandles;
using static DGPOHook.DGPOHook;
using static EasyHook.RemoteHooking;

namespace DGPOHook {

    public enum ExtendedNameFormat {
        NameUnknown = 0,
        NameFullyQualifiedDN = 1,
        NameSamCompatible = 2,
        NameDisplay = 3,
        NameUniqueId = 6,
        NameCanonical = 7,
        NameUserPrincipal = 8,
        NameCanonicalEx = 9,
        NameServicePrincipal = 10,
        NameDnsDomain = 12
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct SHELLEXECUTEINFOW {
        public int cbSize;
        public uint fMask;
        public IntPtr hwnd;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpVerb;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpFile;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpParameters;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpDirectory;
        public int nShow;
        public IntPtr hInstApp;
        public IntPtr lpIDList;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpClass;
        public IntPtr hkeyClass;
        public uint dwHotKey;
        public IntPtr hIcon;
        public IntPtr hProcess;
    }

    public class ServerRpc : MarshalByRefObject  {

        public void IsInstalled(int clientPID) {
            Console.WriteLine($"DGPOEdit has injected hooks into process {clientPID}.\r\n");
        }
 
        public void ReportMessage(int clientPID, string message) {
            Console.WriteLine(message);
        }

        public void ReportException(Exception e) {
            Console.WriteLine("The target process has reported an error:\r\n" + e.ToString());
        }

        public void Ping() {
        }
    }

    public class DGPOHook : IEntryPoint {

        string TargetDomain;
        string DomainController;
        ServerRpc Server;
        string LastMessage = null;

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError=true)]
        delegate bool GetUserNameEx_Delegate(ExtendedNameFormat nameFormat, IntPtr userNamePtr, ref int userNameSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError=true)]
        delegate bool ShellExecuteExW_Delegate(ref SHELLEXECUTEINFOW lpExecInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate uint NtCreateFile_Delegate(out IntPtr handle, uint access, ref OBJECT_ATTRIBUTES objectAttributes, IntPtr ioStatus, ref long allocSize,
                                                uint fileAttributes, uint share, uint createDisposition, uint createOptions, IntPtr eaBuffer, uint eaLength);


        [DllImport("sspicli.dll", CharSet = CharSet.Unicode)]
        static extern bool GetUserNameExW(ExtendedNameFormat nameFormat, IntPtr userName, ref int userNameSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern void SetLastError(uint dwErrorCode);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        static extern bool ShellExecuteExW(ref SHELLEXECUTEINFOW lpExecInfo);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = true)]
        public static extern uint NtCreateFile(out IntPtr handle, uint access, ref OBJECT_ATTRIBUTES objectAttributes, IntPtr ioStatus, ref long allocSize,
                                                uint fileAttributes, uint share, uint createDisposition, uint createOptions, IntPtr eaBuffer, uint eaLength);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool RtlCreateUnicodeString(ref UNICODE_STRING DestinationString, string SourceString);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool RtlFreeUnicodeString( ref UNICODE_STRING String);

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IO_STATUS_BLOCK {
            public uint status;
            public IntPtr information;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct OBJECT_ATTRIBUTES {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;

        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct UNICODE_STRING {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;

        }

        public DGPOHook(IContext ctx, string domain, string domainController, string channelName) {
            TargetDomain = domain;
            DomainController = domainController;

            // Connect to server object using provided channel name
            Server = IpcConnectClient<ServerRpc>(channelName);

            Server.Ping();
        }

        bool GetRedirectedFileName(ref string fileName) {
 
            var prefix = $@"\??\unc\{TargetDomain.ToLower()}\";

            if (fileName.ToLower().StartsWith(prefix)) {
                fileName = $@"\??\UNC\{DomainController}\{fileName.Substring(prefix.Length)}";
                LastMessage = $"[=] Redirected GPO file to {fileName}";
                return true;
            }

            return false;
        }

        uint NtCreateFile_Hook(out IntPtr handle, uint access, ref OBJECT_ATTRIBUTES objectAttributes, IntPtr ioStatus, ref long allocSize,
                                                uint fileAttributes, uint share, uint createDisposition, uint createOptions, IntPtr eaBuffer, uint eaLength) {

            
            if (objectAttributes.ObjectName != IntPtr.Zero) {
                var objName = Marshal.PtrToStructure<UNICODE_STRING>(objectAttributes.ObjectName);
                var rawName = new byte[objName.Length];
                Marshal.Copy(objName.Buffer, rawName,0, objName.Length);
                var path = Encoding.Unicode.GetString(rawName);

                if (GetRedirectedFileName(ref path)) {

                    var originalName = objectAttributes.ObjectName;
                    UNICODE_STRING redirectedName = new UNICODE_STRING();                    
                    RtlCreateUnicodeString(ref redirectedName, path);

                    objectAttributes.ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf<UNICODE_STRING>());
                    Marshal.StructureToPtr(redirectedName, objectAttributes.ObjectName, false);

                    var result = NtCreateFile(out handle, access, ref objectAttributes, ioStatus, ref allocSize, fileAttributes, 
                        share, createDisposition, createOptions, eaBuffer, eaLength);

                    RtlFreeUnicodeString(ref redirectedName);
                    Marshal.FreeHGlobal(objectAttributes.ObjectName);
                    objectAttributes.ObjectName = originalName;

                    return result;
                }
            }            

            return NtCreateFile(out handle, access, ref objectAttributes, ioStatus, ref allocSize, fileAttributes, share, createDisposition, createOptions, eaBuffer, eaLength);
        }

        bool ShellExecuteExW_Hook(ref SHELLEXECUTEINFOW lpExecInfo) {

            if(lpExecInfo.lpFile.ToLower() == "gpme.msc") {
                lpExecInfo.lpFile = Path.Combine(Path.GetDirectoryName(Assembly.GetCallingAssembly().Location), "DGPOEdit.exe");
            }
          
            return ShellExecuteExW(ref lpExecInfo);                     
        }

        bool GetUserNameEx_Hook(ExtendedNameFormat nameFormat, IntPtr userNamePtr, ref int userNameSize) {

            if (nameFormat == ExtendedNameFormat.NameDnsDomain) {
                
                var fullName =  $"{TargetDomain}\\User";

                //If the input is not long enough, just pass onto the original function
                if (userNameSize < fullName.Length + 1) {
                    userNameSize = fullName.Length + 1;
                    SetLastError(0xea); //ERROR_MORE_DATA;
                    LastMessage = $"[+] GetUserNameEx_Hook - Faked domain joined error condition";
                    return false;
                } else {
                    var rawName = Encoding.Unicode.GetBytes(fullName + '\0');
                    Marshal.Copy(rawName, 0, userNamePtr, rawName.Length);
                    userNameSize = fullName.Length;
                    LastMessage = $"[+] GetUserNameEx_Hook - Faked domain user format with {fullName}";
                    return true;
                }
                
            } else {
                return GetUserNameExW(nameFormat, userNamePtr, ref userNameSize); 
            }            
        }

        public void Run(IContext ctx, string domain, string domainController, string channelName) {

            LocalHook ntCreateFileHook = null;

            var getUserNameExHook = LocalHook.Create(EasyHook.LocalHook.GetProcAddress("sspicli.dll", "GetUserNameExW"),
                new GetUserNameEx_Delegate(GetUserNameEx_Hook),this);
            getUserNameExHook.ThreadACL.SetExclusiveACL(new int[] { 0 });

            var shellExecuteExWHook = LocalHook.Create(EasyHook.LocalHook.GetProcAddress("shell32.dll", "ShellExecuteExW"),
                new ShellExecuteExW_Delegate(ShellExecuteExW_Hook), this);
            shellExecuteExWHook.ThreadACL.SetExclusiveACL(new int[] { 0 });

            if (domainController != "") {
                ntCreateFileHook = LocalHook.Create(EasyHook.LocalHook.GetProcAddress("ntdll.dll", "NtCreateFile"),
                    new NtCreateFile_Delegate(NtCreateFile_Hook), this);
                ntCreateFileHook.ThreadACL.SetExclusiveACL(new int[] { 0 });
            }
                                    
            Server.ReportMessage(Process.GetCurrentProcess().Id, $"[=] Hooks installed using target domain {TargetDomain}, resuming process");

            WakeUpProcess();

            try {
                while (true) {
                    Thread.Sleep(500);

                    if(LastMessage != null) {
                        Server.ReportMessage(Process.GetCurrentProcess().Id, LastMessage);
                        LastMessage = null;
                    } else {
                        Server.Ping();
                    }                                                               
                }
            } catch {
                // Ping() or ReportMessages() will raise an exception if host is unreachable
            }

            getUserNameExHook.Dispose();
            shellExecuteExWHook.Dispose();
            if (domainController != null) {
                ntCreateFileHook.Dispose();
            }

            LocalHook.Release();
        }
    }
}
