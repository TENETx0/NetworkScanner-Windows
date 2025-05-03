using Microsoft.Win32;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Text.Json;

namespace Tenetx01
{
    public partial class Form1 : Form
    {
        CancellationTokenSource scanCancellationTokenSource = new CancellationTokenSource();

        public Form1()
        {
            InitializeComponent();
            progressBar1.Minimum = 0;
            progressBar1.Maximum = 100;
            button1.Enabled = false;
        }


        private async void button1_Click(object sender, EventArgs e)
        {
            string input = textBox1.Text.Trim();

            if (!IsValidIPRange(input))
            {
                MessageBox.Show("❌ Invalid IP Address or Range.\nTry formats like:\n192.168.1.1\n192.168.1.1-192.168.1.10");
                return;
            }

            if (!IsAnyCheckboxChecked())
            {
                MessageBox.Show("⚠️ Please select at least one scan option to proceed.");
                return;
            }

          ////  richTextBox1.Clear();
            progressBar1.Value = 0;
            scanCancellationTokenSource = new CancellationTokenSource();
            CancellationToken ct = scanCancellationTokenSource.Token;

            var ipList = ParseIPRange(input);

            foreach (var ip in ipList)
            {
                if (ct.IsCancellationRequested) break;

                richTextBox1.AppendText($"======================== SCANNING: {ip} ========================\n\n");

                if (checkBox1.Checked)
                {
                    richTextBox1.AppendText("🔎 [BASIC SCAN INITIATED]\n");
                    await Task.Run(() => PerformScanTasks(ip, ct));
                }

                if (checkBox2.Checked)
                {
                    richTextBox1.AppendText("\n🧠 [NETWORK HEALTH CHECK STARTED]\n");
                    await Task.Run(() => PerformHealthCheck(ip, ct));
                }

                if (checkBox3.Checked)
                {
                    richTextBox1.AppendText("\n🤖 [IOT DEVICE SCAN STARTED]\n");
                    await Task.Run(() => PerformIoTScan(new List<string> { ip }));
                }

                if (checkBox4.Checked)
                {
                    richTextBox1.AppendText("\n🔐 [CRYPTOGRAPHIC METADATA ANALYSIS STARTED]\n");
                    await Task.Run(() => PerformCryptoScan(ip));
                }

                if (checkBox5.Checked)
                {
                    richTextBox1.AppendText("\n📡 [ADVANCED ENUMERATION STARTED]\n");
                    await Task.Run(() => PerformAdvancedEnumeration(ip));
                }

                if (checkBox6.Checked)
                {
                    richTextBox1.AppendText("\n🌐 [PROXY/ VPN / FIREWALL DETECTION STARTED]\n");
                    await Task.Run(() => PerformProxyVpnFirewallCheck(ip, ct));
                }

                if (checkBox7.Checked)
                {
                    richTextBox1.AppendText("\n📂 [FILE SHARING PORT SCAN STARTED]\n");
                    await Task.Run(() => PerformFileSharingScan(ip));
                }

                if (checkBox8.Checked)
                {
                    richTextBox1.AppendText("\n🔀 [PORT TO APP MAPPING STARTED]\n");
                    await Task.Run(() => PerformPortToAppMapping(ip, ct));

                }

                richTextBox1.AppendText($"\n✅ SCAN COMPLETE FOR: {ip}\n");
                richTextBox1.AppendText("================================================================\n\n");
            }

            progressBar1.Value = 100;
            if (!ct.IsCancellationRequested)
                MessageBox.Show("✅ All selected scans completed successfully!");
        }


        private void PerformAdvancedEnumeration(string ip)
        {
            // Create delegate for thread-safe logging to the RichTextBox with colorization support
            void Log(string msg, Color? color = null)
            {
                richTextBox1.Invoke(() =>
                {
                    if (color.HasValue)
                    {
                        richTextBox1.SelectionStart = richTextBox1.TextLength;
                        richTextBox1.SelectionLength = 0;
                        richTextBox1.SelectionColor = color.Value;
                    }
                    richTextBox1.AppendText(msg + Environment.NewLine);
                    richTextBox1.SelectionColor = richTextBox1.ForeColor;
                    richTextBox1.ScrollToCaret();
                });
            }

            // Section divider method
            void LogSection(string title)
            {
                Log($"\n■━━━━━━━━━━━━━━━ {title} ━━━━━━━━━━━━━━━■", Color.DodgerBlue);
            }

            LogSection($"ADVANCED ENUMERATION: {ip}");

            // --- Basic Host Information ---
            try
            {
                IPHostEntry entry = Dns.GetHostEntry(ip);
                Log($"🌐 Hostname: {entry.HostName}", Color.Green);

                if (entry.Aliases.Length > 0)
                    Log($"📥 Aliases: {string.Join(", ", entry.Aliases)}", Color.Green);

                Log($"📦 Address List: {string.Join(", ", entry.AddressList.Select(a => a.ToString()))}", Color.Green);
            }
            catch (Exception ex)
            {
                Log($"❌ Host Resolution: {ex.Message}", Color.Red);
            }

            // --- OS Detection Section ---
            LogSection("OS FINGERPRINTING");

            try
            {
                using (Ping ping = new Ping())
                {
                    PingReply reply = ping.Send(ip, 1500);
                    if (reply.Status == IPStatus.Success)
                    {
                        int ttl = reply.Options?.Ttl ?? 0;
                        string osGuess;
                        Color osColor;

                        if (ttl <= 32)
                        {
                            osGuess = "Likely Network Device (Router/Switch)";
                            osColor = Color.Orange;
                        }
                        else if (ttl <= 64)
                        {
                            osGuess = "Linux/Unix/MacOS (TTL≤64)";
                            osColor = Color.DarkGreen;
                        }
                        else if (ttl <= 128)
                        {
                            osGuess = "Windows (TTL≤128)";
                            osColor = Color.RoyalBlue;
                        }
                        else
                        {
                            osGuess = "Solaris/AIX or Custom TTL";
                            osColor = Color.Purple;
                        }

                        Log($"🧬 OS Detection [TTL={ttl}]: {osGuess}", osColor);
                        Log($"⏱️ Ping Response Time: {reply.RoundtripTime}ms");

                        // Additional Windows verification
                        try
                        {
                            using TcpClient tcp = new TcpClient();
                            if (tcp.ConnectAsync(ip, 135).Wait(700))
                            {
                                Log("📡 Port 135 (DCOM/RPC) open - Windows OS confirmed", Color.RoyalBlue);
                            }

                            using TcpClient tcp2 = new TcpClient();
                            if (tcp2.ConnectAsync(ip, 445).Wait(700))
                            {
                                Log("📡 Port 445 (SMB) open - Windows OS likely", Color.RoyalBlue);
                            }
                        }
                        catch { /* Silent fail for connection attempts */ }

                        // Additional Unix verification
                        try
                        {
                            using TcpClient tcp = new TcpClient();
                            if (tcp.ConnectAsync(ip, 22).Wait(700))
                            {
                                Log("📡 Port 22 (SSH) open - Unix/Linux system likely", Color.DarkGreen);
                            }
                        }
                        catch { /* Silent fail for connection attempts */ }
                    }
                    else
                    {
                        Log($"⚠️ Ping failed with status: {reply.Status}", Color.Orange);
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"❌ OS detection error: {ex.Message}", Color.Red);
            }

            // --- Critical Services Enumeration ---
            LogSection("CRITICAL SERVICES & RISKS");

            // Define ports with categories for better organization
            var serviceEntries = new List<(int Port, string Service, string Category, int Risk, string Description)>
    {
        // Authentication & Remote Access (High Risk)
        (22, "SSH", "Remote Access", 7, "Secure Shell remote access"),
        (23, "Telnet", "Remote Access", 9, "Unencrypted remote access - MAJOR RISK"),
        (3389, "RDP", "Remote Access", 8, "Windows Remote Desktop Protocol"),
        (5900, "VNC", "Remote Access", 8, "Virtual Network Computing remote access"),
        
        // File Sharing (High Risk for Lateral Movement)
        (21, "FTP", "File Transfer", 8, "File Transfer Protocol - often unencrypted"),
        (139, "NetBIOS", "File Sharing", 9, "Legacy Windows file sharing - MAJOR RISK"),
        (445, "SMB", "File Sharing", 8, "Server Message Block file sharing"),
        (2049, "NFS", "File Sharing", 7, "Network File System (Unix/Linux)"),
        
        // Management Protocols (Critical for Network Takeover)
        (161, "SNMP", "Management", 8, "Simple Network Management Protocol"),
        (162, "SNMPTRAP", "Management", 7, "SNMP Trap receiver"),
        (69, "TFTP", "Management", 9, "Trivial FTP - no authentication"),
        (514, "RSH", "Management", 9, "Remote Shell - legacy unencrypted access"),
        
        // Databases (Data Exfiltration Risk)
        (1433, "MSSQL", "Database", 7, "Microsoft SQL Server"),
        (1521, "Oracle", "Database", 7, "Oracle Database Server"),
        (3306, "MySQL", "Database", 6, "MySQL Database Server"),
        (5432, "PostgreSQL", "Database", 6, "PostgreSQL Database Server"),
        (6379, "Redis", "Database", 8, "Redis Database - often unsecured"),
        (27017, "MongoDB", "Database", 7, "MongoDB Database"),
        
        // Web Services
        (80, "HTTP", "Web", 5, "Web server - unencrypted"),
        (443, "HTTPS", "Web", 4, "Secure web server"),
        (8080, "HTTP-Alt", "Web", 5, "Alternative HTTP port"),
        (8443, "HTTPS-Alt", "Web", 4, "Alternative HTTPS port"),
        
        // Email & Communication
        (25, "SMTP", "Email", 5, "Mail transfer"),
        (110, "POP3", "Email", 6, "Mail retrieval - often unencrypted"),
        (143, "IMAP", "Email", 6, "Mail access - often unencrypted"),
        (465, "SMTPS", "Email", 4, "Secure mail transfer"),
        (993, "IMAPS", "Email", 4, "Secure mail access"),
        (995, "POP3S", "Email", 4, "Secure mail retrieval"),
        
        // Directory Services
        (389, "LDAP", "Directory", 7, "Directory services - often unencrypted"),
        (636, "LDAPS", "Directory", 5, "Secure directory services"),
        
        // Other Notable Services
        (53, "DNS", "Network", 6, "Domain Name Service"),
        (123, "NTP", "Network", 5, "Network Time Protocol"),
        (179, "BGP", "Network", 8, "Border Gateway Protocol - core routing"),
        (873, "rsync", "Transfer", 6, "File synchronization service"),
        (5985, "WinRM-HTTP", "Management", 8, "Windows Remote Management (HTTP)"),
        (5986, "WinRM-HTTPS", "Management", 7, "Windows Remote Management (HTTPS)")
    };

            // Group services by category
            var servicesByCategory = serviceEntries.GroupBy(s => s.Category).ToList();
            var openServices = new Dictionary<string, List<string>>();
            var riskyServices = new List<(string Service, int Port, int Risk, string Description)>();

            // Check ports with timeout and track results by category
            foreach (var service in serviceEntries)
            {
                try
                {
                    using TcpClient client = new TcpClient();
                    if (client.ConnectAsync(ip, service.Port).Wait(600)) // Slightly increased timeout
                    {
                        if (!openServices.ContainsKey(service.Category))
                            openServices[service.Category] = new List<string>();

                        openServices[service.Category].Add($"{service.Service}:{service.Port}");

                        if (service.Risk >= 7)
                        {
                            riskyServices.Add((service.Service, service.Port, service.Risk, service.Description));
                        }
                    }
                }
                catch { /* Ignore connection errors */ }
            }

            // Display found services by category
            if (openServices.Count > 0)
            {
                foreach (var category in openServices.Keys)
                {
                    Log($"📌 {category} Services:", Color.Brown);
                    foreach (var service in openServices[category])
                    {
                        Log($"   ├─ {service}");
                    }
                }
            }
            else
            {
                Log("⚠️ No common services detected on standard ports", Color.Orange);
            }

            // Highlight high-risk services
            if (riskyServices.Count > 0)
            {
                Log("\n🚨 HIGH RISK SERVICES DETECTED:", Color.Red);
                foreach (var service in riskyServices.OrderByDescending(s => s.Risk))
                {
                    Log($"   ⛔ {service.Service}:{service.Port} (Risk Level: {service.Risk}/10) - {service.Description}",
                        service.Risk >= 8 ? Color.Red : Color.Orange);
                }
            }

            // --- Lateral Movement Assessment ---
            if (openServices.ContainsKey("File Sharing") || openServices.ContainsKey("Remote Access"))
            {
                LogSection("LATERAL MOVEMENT ANALYSIS");

                bool highRisk = false;

                if (openServices.ContainsKey("File Sharing"))
                {
                    if (openServices["File Sharing"].Any(s => s.Contains("SMB") || s.Contains("445")))
                    {
                        Log("⚠️ SMB File Sharing: Potential credential theft & lateral movement vector", Color.Red);
                        highRisk = true;

                        // Try basic SMB enumeration if SMB is detected
                        try
                        {
                            Log("🔍 Attempting to enumerate SMB shares (anonymous)...");

                            // Simulate SMB enumeration process
                            using (Process process = new Process())
                            {
                                process.StartInfo.FileName = "net";
                                process.StartInfo.Arguments = $"view \\\\{ip}";
                                process.StartInfo.UseShellExecute = false;
                                process.StartInfo.RedirectStandardOutput = true;
                                process.StartInfo.CreateNoWindow = true;

                                try
                                {
                                    process.Start();
                                    string result = process.StandardOutput.ReadToEnd();
                                    process.WaitForExit(3000);

                                    if (!string.IsNullOrEmpty(result) && !result.Contains("error"))
                                    {
                                        Log($"📂 SMB Shares found:\n{result}", Color.Brown);
                                    }
                                    else
                                    {
                                        Log("📂 No anonymously accessible SMB shares detected");
                                    }
                                }
                                catch
                                {
                                    Log("📂 SMB share enumeration failed - requires elevated privileges", Color.Orange);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Log($"📂 SMB enumeration error: {ex.Message}", Color.Red);
                        }
                    }

                    if (openServices["File Sharing"].Any(s => s.Contains("FTP") || s.Contains("21")))
                    {
                        Log("⚠️ FTP Service: Check for anonymous access & unencrypted transfers", Color.Red);
                        highRisk = true;

                        // Try basic FTP banner grab
                        try
                        {
                            using (TcpClient ftpClient = new TcpClient())
                            {
                                if (ftpClient.ConnectAsync(ip, 21).Wait(1000))
                                {
                                    using (NetworkStream stream = ftpClient.GetStream())
                                    {
                                        if (stream.CanRead)
                                        {
                                            stream.ReadTimeout = 2000;
                                            byte[] buffer = new byte[1024];
                                            int bytesRead = stream.Read(buffer, 0, buffer.Length);
                                            if (bytesRead > 0)
                                            {
                                                string banner = Encoding.ASCII.GetString(buffer, 0, bytesRead).Trim();
                                                Log($"📟 FTP Banner: {banner}", Color.Yellow);

                                                // Check for common vulnerable FTP servers
                                                if (banner.Contains("vsFTPd 2.3.4") || banner.Contains("ProFTPD 1.3.3"))
                                                {
                                                    Log("🚨 VULNERABLE FTP VERSION DETECTED!", Color.Red);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        catch { /* Ignore FTP banner grab errors */ }
                    }

                    if (openServices["File Sharing"].Any(s => s.Contains("NFS") || s.Contains("2049")))
                    {
                        Log("⚠️ NFS Service: Check for misconfigurations & world-readable exports", Color.Red);
                        highRisk = true;
                    }
                }

                if (openServices.ContainsKey("Remote Access"))
                {
                    if (openServices["Remote Access"].Any(s => s.Contains("Telnet") || s.Contains("23")))
                    {
                        Log("🚨 CRITICAL: Telnet service - plaintext credentials & commands", Color.Red);
                        highRisk = true;
                    }

                    if (openServices["Remote Access"].Any(s => s.Contains("RDP") || s.Contains("3389")))
                    {
                        Log("⚠️ RDP Service: Check for weak authentication & BlueKeep/similar vulnerabilities", Color.Red);
                        highRisk = true;
                    }

                    if (openServices["Remote Access"].Any(s => s.Contains("SSH") || s.Contains("22")))
                    {
                        Log("🔒 SSH Service: Check for outdated versions & weak authentication methods", Color.Brown);

                        // Try SSH banner grab
                        try
                        {
                            using (TcpClient sshClient = new TcpClient())
                            {
                                if (sshClient.ConnectAsync(ip, 22).Wait(1000))
                                {
                                    using (NetworkStream stream = sshClient.GetStream())
                                    {
                                        stream.ReadTimeout = 2000;
                                        byte[] buffer = new byte[255];
                                        int bytesRead = stream.Read(buffer, 0, buffer.Length);
                                        if (bytesRead > 0)
                                        {
                                            string banner = Encoding.ASCII.GetString(buffer, 0, bytesRead).Trim();
                                            Log($"📟 SSH Banner: {banner}", Color.Brown);

                                            // Check for outdated SSH versions
                                            if (banner.Contains("SSH-1.") || banner.Contains("OpenSSH 4.") ||
                                                banner.Contains("OpenSSH 5.") || banner.Contains("OpenSSH 6.0"))
                                            {
                                                Log("🚨 OUTDATED SSH VERSION - SECURITY RISK!", Color.Red);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        catch { /* Ignore SSH banner grab errors */ }
                    }
                }

                if (highRisk)
                {
                    Log("📊 LATERAL MOVEMENT RISK: HIGH", Color.Red);
                    Log("⚠️ Multiple high-risk services detected for lateral movement", Color.Red);
                }
                else
                {
                    Log("📊 LATERAL MOVEMENT RISK: MODERATE", Color.Orange);
                    Log("⚠️ Some potential lateral movement vectors present", Color.Orange);
                }
            }

            // --- UAC Configuration Check (Local Only) ---
            if (ip == "127.0.0.1" || ip == "localhost" || IsLocalIpAddress(ip))
            {
                LogSection("UAC CONFIGURATION CHECK (LOCAL)");

                try
                {
                    // Check UAC registry settings
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"))
                    {
                        if (key != null)
                        {
                            int enableLUA = (int)key.GetValue("EnableLUA", 1);
                            int consentPromptBehaviorAdmin = (int)key.GetValue("ConsentPromptBehaviorAdmin", 5);
                            int promptOnSecureDesktop = (int)key.GetValue("PromptOnSecureDesktop", 1);

                            Log($"🔐 UAC Enabled: {(enableLUA == 1 ? "Yes" : "No")}",
                                enableLUA == 1 ? Color.Green : Color.Red);

                            string uacLevel = "Unknown";
                            Color uacColor = Color.Gray;

                            if (enableLUA == 0)
                            {
                                uacLevel = "Disabled (High Risk)";
                                uacColor = Color.Red;
                            }
                            else if (consentPromptBehaviorAdmin == 0 && promptOnSecureDesktop == 0)
                            {
                                uacLevel = "Never Notify (High Risk)";
                                uacColor = Color.Red;
                            }
                            else if (consentPromptBehaviorAdmin == 5 && promptOnSecureDesktop == 0)
                            {
                                uacLevel = "Notify without Secure Desktop (Medium Risk)";
                                uacColor = Color.Orange;
                            }
                            else if (consentPromptBehaviorAdmin == 5 && promptOnSecureDesktop == 1)
                            {
                                uacLevel = "Default - Notify with Secure Desktop (Low Risk)";
                                uacColor = Color.Green;
                            }
                            else if (consentPromptBehaviorAdmin == 2 && promptOnSecureDesktop == 1)
                            {
                                uacLevel = "Always Notify (Lowest Risk)";
                                uacColor = Color.Green;
                            }

                            Log($"🔐 UAC Level: {uacLevel}", uacColor);

                            // Check for UAC bypass vulnerabilities based on Windows version
                            if (Environment.OSVersion.Version.Major == 10)
                            {
                                if (Environment.OSVersion.Version.Build < 17763)
                                {
                                    Log("⚠️ Windows 10 build < 1809: Check for UAC bypass via fodhelper.exe", Color.Red);
                                }

                                if (enableLUA == 1 && consentPromptBehaviorAdmin != 2)
                                {
                                    Log("⚠️ UAC settings potentially vulnerable to bypass techniques", Color.Red);
                                }
                            }
                        }
                        else
                        {
                            Log("❌ Cannot access UAC registry settings", Color.Red);
                        }
                    }

                    // Check if running as administrator
                    bool isElevated = IsAdministrator();
                    Log($"👑 Running with Administrator Rights: {(isElevated ? "Yes" : "No")}",
                        isElevated ? Color.Green : Color.Gray);
                }
                catch (Exception ex)
                {
                    Log($"❌ UAC check error: {ex.Message}", Color.Red);
                }
            }

            // --- Outbound Connection Simulation ---
            LogSection("OUTBOUND CONNECTION SIMULATION");

            string[] commonC2Ports = { "80", "443", "53", "8080", "8443", "445", "3389", "4444", "5353" };

            Log("🔄 Testing outbound connection capabilities...");

            try
            {
                // Test outbound DNS resolution
                bool dnsWorks = false;
                try
                {
                    IPHostEntry entry = Dns.GetHostEntry("www.google.com");
                    if (entry != null && entry.AddressList.Length > 0)
                    {
                        Log("✅ DNS Resolution: Working", Color.Green);
                        dnsWorks = true;
                    }
                }
                catch
                {
                    Log("❌ DNS Resolution: Failed or Blocked", Color.Red);
                }

                // Test common outbound ports that malware might use
                if (dnsWorks)
                {
                    Log("🔎 Testing common C2 channels:");

                    bool anyPortOpen = false;
                    foreach (string port in commonC2Ports)
                    {
                        try
                        {
                            string testHost = "www.google.com";
                            int portNum = int.Parse(port);

                            using (TcpClient client = new TcpClient())
                            {
                                // Only test standard web ports to avoid abuse
                                if (portNum == 80 || portNum == 443 || portNum == 8080 || portNum == 8443)
                                {
                                    if (client.ConnectAsync(testHost, portNum).Wait(1500))
                                    {
                                        Log($"   ✅ Port {port}: Outbound connection allowed", Color.Green);
                                        anyPortOpen = true;
                                    }
                                    else
                                    {
                                        Log($"   ❌ Port {port}: Blocked", Color.Red);
                                    }
                                }
                                else
                                {
                                    // For non-standard ports, just report that they should be checked
                                    Log($"   ⚠️ Port {port}: Common C2 channel - should be monitored", Color.Orange);
                                }
                            }
                        }
                        catch
                        {
                            Log($"   ❌ Port {port}: Blocked or Error", Color.Red);
                        }
                    }

                    if (anyPortOpen)
                    {
                        Log("⚠️ Multiple outbound channels available for potential C2 traffic", Color.Orange);
                        Log("🔒 Recommendation: Implement egress filtering on firewalls", Color.Orange);
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"❌ Outbound connection test error: {ex.Message}", Color.Red);
            }

            // --- Running Process/Service enumeration (simplified version) ---
            if (ip == "127.0.0.1" || ip == "localhost" || IsLocalIpAddress(ip))
            {
                LogSection("RUNNING PROCESSES");

                try
                {
                    // Get interesting running processes
                    Log("🔎 Scanning for potentially interesting processes...");

                    Process[] processes = Process.GetProcesses();
                    var interestingProcesses = processes
                        .Where(p =>
                        {
                            try
                            {
                                string name = p.ProcessName.ToLower();
                                return name.Contains("sql") || name.Contains("apache") ||
                                       name.Contains("nginx") || name.Contains("iis") ||
                                       name.Contains("tomcat") || name.Contains("server") ||
                                       name.Contains("java") || name.Contains("python") ||
                                       name.Contains("node") || name.Contains("php") ||
                                       name.StartsWith("ms") || name.Contains("net");
                            }
                            catch { return false; }
                        })
                        .Take(15)
                        .ToList();

                    if (interestingProcesses.Count > 0)
                    {
                        foreach (var proc in interestingProcesses)
                        {
                            try
                            {
                                Log($"   ▶️ {proc.ProcessName} (PID: {proc.Id})",
                                    proc.ProcessName.ToLower().Contains("sql") ? Color.Orange : Color.Gray);
                            }
                            catch { }
                        }
                    }
                    else
                    {
                        Log("   No interesting processes found");
                    }

                    // Check for services using WMI instead of ServiceController
                    try
                    {
                        Log("\n🔌 Scanning for critical services...");

                        using (Process wmiProcess = new Process())
                        {
                            wmiProcess.StartInfo.FileName = "wmic";
                            wmiProcess.StartInfo.Arguments = "service where (displayname like '%sql%' or displayname like '%web%' or displayname like '%ftp%' or displayname like '%remote%') get name,displayname,state /format:list";
                            wmiProcess.StartInfo.UseShellExecute = false;
                            wmiProcess.StartInfo.RedirectStandardOutput = true;
                            wmiProcess.StartInfo.CreateNoWindow = true;

                            wmiProcess.Start();
                            string wmiOutput = wmiProcess.StandardOutput.ReadToEnd();
                            wmiProcess.WaitForExit(5000);

                            if (!string.IsNullOrEmpty(wmiOutput))
                            {
                                string[] services = wmiOutput.Split(new[] { "\r\n\r\n" }, StringSplitOptions.RemoveEmptyEntries);

                                foreach (string service in services)
                                {
                                    if (string.IsNullOrWhiteSpace(service)) continue;

                                    string displayName = ExtractWmiValue(service, "DisplayName");
                                    string state = ExtractWmiValue(service, "State");
                                    string name = ExtractWmiValue(service, "Name");

                                    if (!string.IsNullOrEmpty(displayName))
                                    {
                                        Color svcColor = Color.Gray;
                                        if (displayName.ToLower().Contains("sql") ||
                                            displayName.ToLower().Contains("ftp") ||
                                            displayName.ToLower().Contains("telnet"))
                                            svcColor = Color.Orange;

                                        Log($"   ▶️ {name} - {displayName} ({state})", svcColor);
                                    }
                                }
                            }
                            else
                            {
                                Log("   Service information not available - requires elevated privileges", Color.Orange);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"❌ Service enumeration error: {ex.Message}", Color.Red);
                    }
                }
                catch (Exception ex)
                {
                    Log($"❌ Process enumeration error: {ex.Message}", Color.Red);
                }
            }
            else if (openServices.ContainsKey("File Sharing") &&
                    openServices["File Sharing"].Any(s => s.Contains("SMB") || s.Contains("445")))
            {
                Log("🔒 Remote SMB detected - process enumeration requires credentials", Color.Orange);
                Log("💡 Consider authenticated scan for deeper enumeration", Color.Orange);
            }

            LogSection("SCAN SUMMARY");
            Log($"✅ Advanced Enumeration Completed on {ip}", Color.Green);
            Log($"📊 Scan Timestamp: {DateTime.Now}", Color.Gray);

            // Helper method to extract WMI values
            string ExtractWmiValue(string serviceInfo, string propertyName)
            {
                string searchKey = propertyName + "=";
                int startIndex = serviceInfo.IndexOf(searchKey);
                if (startIndex < 0)
                    return string.Empty;

                startIndex += searchKey.Length;
                int endIndex = serviceInfo.IndexOf("\r\n", startIndex);
                if (endIndex < 0)
                    endIndex = serviceInfo.Length;

                return serviceInfo.Substring(startIndex, endIndex - startIndex).Trim();
            }

            // Helper method to check if an IP is local
            bool IsLocalIpAddress(string host)
            {
                try
                {
                    // get host IP addresses
                    IPAddress[] hostIPs = Dns.GetHostAddresses(host);
                    // get local IP addresses
                    IPAddress[] localIPs = Dns.GetHostAddresses(Dns.GetHostName());

                    // test if any host IP equals to any local IP or to localhost
                    foreach (IPAddress hostIP in hostIPs)
                    {
                        // is localhost
                        if (IPAddress.IsLoopback(hostIP)) return true;
                        // is local address
                        foreach (IPAddress localIP in localIPs)
                        {
                            if (hostIP.Equals(localIP)) return true;
                        }
                    }
                }
                catch { }
                return false;
            }

            // Helper method to check if running as administrator
            bool IsAdministrator()
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        private async Task PerformPortToAppMapping(string ip, CancellationToken cancellationToken)
        {
            void Log(string msg) =>
                richTextBox1.Invoke(() => richTextBox1.AppendText(msg + Environment.NewLine));

            // Clear previous scan results
            richTextBox1.Invoke(() => richTextBox1.Clear());

            // Enhanced port-to-app dictionary with more comprehensive mapping
            Dictionary<int, (string Name, string Category, string Icon)> portToApp = new Dictionary<int, (string, string, string)>
    {
        // Web Services
        { 80, ("HTTP", "Web", "🌐") }, { 443, ("HTTPS", "Web", "🔒") },
        { 8080, ("HTTP Proxy", "Web", "🌐") }, { 8443, ("HTTPS-Alt", "Web", "🔒") },
        { 8000, ("HTTP-Alt", "Web", "🌐") }, { 8081, ("Tomcat Admin", "Web", "🌐") },
        { 8888, ("Jupyter Notebook", "Web", "📊") }, { 3000, ("Grafana", "Web", "📊") },
        { 5601, ("Kibana", "Web", "📊") }, { 9000, ("SonarQube", "Web", "🔍") },
        { 9200, ("Elasticsearch", "Web", "🔍") }, { 10000, ("Webmin", "Web", "⚙️") },
        
        // Development Servers
        { 3001, ("React Dev Server", "Dev", "⚛️") }, { 4200, ("Angular Dev Server", "Dev", "🅰️") },
        { 8082, ("Vue.js Dev Server", "Dev", "🟢") }, { 8083, ("Spring Boot", "Dev", "🍃") },
        { 5000, ("Flask Dev Server", "Dev", "🐍") }, { 3002, ("Svelte Dev Server", "Dev", "🔥") },
        { 1880, ("Node-RED", "Dev", "🔴") }, { 4040, ("Ngrok", "Dev", "🔄") },
        { 4000, ("GraphQL Server", "Dev", "📝") },
        
        // File Transfer
        { 20, ("FTP Data", "File", "📁") }, { 21, ("FTP", "File", "📁") },
        { 22, ("SSH", "File", "🔐") }, { 69, ("TFTP", "File", "📄") },
        { 115, ("SFTP", "File", "🔒") }, { 989, ("FTPS Data", "File", "🔒") },
        { 990, ("FTPS", "File", "🔒") }, { 2022, ("Custom SSH", "File", "🔐") },
        
        // Email
        { 25, ("SMTP", "Email", "📧") }, { 110, ("POP3", "Email", "📨") },
        { 143, ("IMAP", "Email", "📬") }, { 465, ("SMTPS", "Email", "🔒") },
        { 587, ("SMTP TLS", "Email", "🔒") }, { 993, ("IMAPS", "Email", "🔒") },
        { 995, ("POP3S", "Email", "🔒") },
        
        // Database
        { 1433, ("MSSQL", "DB", "🗄️") }, { 1521, ("Oracle", "DB", "🗄️") },
        { 3306, ("MySQL", "DB", "🗄️") }, { 5432, ("PostgreSQL", "DB", "🗄️") },
        { 6379, ("Redis", "DB", "🗄️") }, { 27017, ("MongoDB", "DB", "🗄️") },
        { 27018, ("MongoDB Secondary", "DB", "🗄️") }, { 2480, ("OrientDB", "DB", "🗄️") },
        { 5984, ("CouchDB", "DB", "🗄️") }, { 11211, ("Memcached", "DB", "🗄️") },
        
        // Networking
        { 23, ("Telnet", "Net", "🔌") }, { 53, ("DNS", "Net", "🔍") },
        { 67, ("DHCP Server", "Net", "🔄") }, { 68, ("DHCP Client", "Net", "🔄") },
        { 123, ("NTP", "Net", "🕒") }, { 161, ("SNMP", "Net", "📊") },
        { 162, ("SNMP Trap", "Net", "📊") }, { 179, ("BGP", "Net", "🌐") },
        { 514, ("Syslog", "Net", "📜") }, { 1080, ("SOCKS Proxy", "Net", "🔄") },
        
        // Windows Services
        { 137, ("NetBIOS Name", "Win", "🪟") }, { 138, ("NetBIOS Datagram", "Win", "🪟") },
        { 139, ("NetBIOS Session", "Win", "🪟") }, { 445, ("SMB", "Win", "📂") },
        { 3389, ("RDP", "Win", "🖥️") },
        
        // Messaging and Queues
        { 1883, ("MQTT", "Msg", "📡") }, { 1884, ("MQTT Alt", "Msg", "📡") },
        { 5672, ("AMQP", "Msg", "📨") }, { 7000, ("ActiveMQ", "Msg", "📨") },
        { 61616, ("ActiveMQ TCP", "Msg", "📨") }, { 15672, ("RabbitMQ Admin", "Msg", "🐇") },
        { 25672, ("RabbitMQ Inter-Node", "Msg", "🐇") }, { 6667, ("IRC", "Msg", "💬") },
        
        // Remote Access
        { 5900, ("VNC", "Remote", "🖥️") }, { 5901, ("VNC Alt", "Remote", "🖥️") },
        { 1723, ("PPTP", "Remote", "🔌") }, { 1720, ("H.323", "Remote", "📞") },
        
        // Other Services
        { 119, ("NNTP", "Other", "📰") }, { 515, ("LPD", "Other", "🖨️") },
        { 631, ("IPP", "Other", "🖨️") }, { 636, ("LDAPS", "Other", "🔒") },
        { 873, ("rsync", "Other", "🔄") }, { 3690, ("Subversion", "Other", "📚") },
        { 7070, ("RealServer", "Other", "🎞️") }, { 7071, ("Jenkins", "Other", "🔨") },
        { 8761, ("Eureka", "Other", "🔍") }, { 9090, ("Prometheus", "Other", "📊") },
        { 10050, ("Zabbix Agent", "Other", "📊") }, { 8181, ("OpenAM", "Other", "🔐") },
        { 6001, ("Laravel Echo Server", "Other", "🔊") }, { 54321, ("Custom TCP Service", "Other", "🧩") },
    };

            // Get ports from the dictionary
            List<int> portsToScan = portToApp.Keys.OrderBy(p => p).ToList();
            int totalPorts = portsToScan.Count;
            int scannedPorts = 0;
            int openPorts = 0;
            DateTime startTime = DateTime.Now;

            // Add fancy header
            Log($"╔════════════════════════════════════════════════════════╗");
            Log($"║  🔍 ADVANCED PORT SCANNER - {DateTime.Now}  ║");
            Log($"╠════════════════════════════════════════════════════════╣");
            Log($"║  Target: {ip}                                          ");
            Log($"║  Scanning {totalPorts} ports...                                   ");
            Log($"╚════════════════════════════════════════════════════════╝");
            Log("");

            // Group ports by category for concurrent scanning
            var portsByCategory = portToApp.GroupBy(p => p.Value.Category)
                                          .ToDictionary(g => g.Key, g => g.Select(p => p.Key).ToList());

            // Dictionary to store open ports for sorted display
            Dictionary<int, (string Name, string Category, string Icon)> openPortsInfo =
                new Dictionary<int, (string Name, string Category, string Icon)>();

            // Progress tracking
            progressBar1.Invoke(() =>
            {
                progressBar1.Minimum = 0;
                // Ensure Maximum is at least 100 to prevent Value setting errors
                progressBar1.Maximum = Math.Max(100, totalPorts);
                progressBar1.Value = 0;
                progressBar1.Style = ProgressBarStyle.Continuous;
            });

            // Configure parallel scanning options
            ParallelOptions parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = 50,
                CancellationToken = cancellationToken
            };

            try
            {
                // Scan ports in parallel with categories
                foreach (var category in portsByCategory)
                {
                    string categoryName = category.Key;
                    List<int> categoryPorts = category.Value;

                    await Task.Run(async () =>
                    {
                        await Parallel.ForEachAsync(categoryPorts, parallelOptions, async (port, cancellationToken) =>
                        {
                            if (cancellationToken.IsCancellationRequested)
                                return;

                            try
                            {
                                using TcpClient client = new TcpClient();
                                var connectTask = client.ConnectAsync(ip, port);

                                // Wait for connection with timeout
                                if (await Task.WhenAny(connectTask, Task.Delay(150, cancellationToken)) == connectTask && client.Connected)
                                {
                                    // Port is open - store information for later display
                                    lock (openPortsInfo)
                                    {
                                        openPortsInfo[port] = portToApp[port];
                                        openPorts++;
                                    }
                                }
                            }
                            catch { /* Connection failed or timed out */ }

                            // Update progress
                            lock (progressBar1)
                            {
                                scannedPorts++;
                                progressBar1.Invoke(() =>
                                {
                                    // Calculate percentage instead of direct port count
                                    int percentComplete = (int)((scannedPorts * 100.0) / totalPorts);
                                    progressBar1.Value = Math.Min(percentComplete, progressBar1.Maximum);
                                });
                            }
                        });
                    }, cancellationToken);
                }

                // Calculate scan duration
                TimeSpan scanDuration = DateTime.Now - startTime;

                // Display results in categories
                Log("");
                Log($"╔════════════════════════════════════════════════════════╗");
                Log($"║  🎯 SCAN RESULTS                                       ║");
                Log($"╠════════════════════════════════════════════════════════╣");
                Log($"║  Open ports found: {openPorts}/{totalPorts}                            ");
                Log($"║  Scan duration: {scanDuration.TotalSeconds:F2} seconds                 ");
                Log($"╚════════════════════════════════════════════════════════╝");

                if (openPorts > 0)
                {
                    // Group open ports by category for display
                    var openPortsByCategory = openPortsInfo
                        .GroupBy(p => p.Value.Category)
                        .OrderBy(g => g.Key);

                    foreach (var categoryGroup in openPortsByCategory)
                    {
                        string categoryName = GetCategoryFullName(categoryGroup.Key);
                        Log("");
                        Log($"┌─── {categoryGroup.First().Value.Icon} {categoryName} ─────────────────────────────────────┐");

                        foreach (var portEntry in categoryGroup.OrderBy(p => p.Key))
                        {
                            int port = portEntry.Key;
                            var (serviceName, _, icon) = portEntry.Value;
                            Log($"│  {icon} Port {port,-5} → {serviceName,-25}    │");
                        }

                        Log($"└──────────────────────────────────────────────────────────┘");
                    }
                }
                else
                {
                    Log("");
                    Log("😕 No open ports were found on this target.");
                }

                // Final status
                Log("");
                Log($"✅ Port-to-App Mapping Completed Successfully.");
            }
            catch (OperationCanceledException)
            {
                Log("");
                Log("⚠️ Scan was cancelled by user.");
            }
            catch (Exception ex)
            {
                Log("");
                Log($"❌ Error during port scan: {ex.Message}");
            }
            finally
            {
                // Complete the progress bar and reset
                progressBar1.Invoke(() =>
                {
                    // Safely set to 100% completion
                    try
                    {
                        progressBar1.Value = progressBar1.Maximum;
                    }
                    catch
                    {
                        // Fallback in case of any issues
                        progressBar1.Value = progressBar1.Minimum;
                    }
                    progressBar1.Style = ProgressBarStyle.Continuous;
                });
            }
        }

        // Helper method to get full category name
        private string GetCategoryFullName(string categoryShort)
        {
            return categoryShort switch
            {
                "Web" => "Web Services",
                "Dev" => "Development Servers",
                "File" => "File Transfer",
                "Email" => "Email Services",
                "DB" => "Database Services",
                "Net" => "Network Services",
                "Win" => "Windows Services",
                "Msg" => "Messaging Services",
                "Remote" => "Remote Access",
                "Other" => "Other Services",
                _ => categoryShort
            };
        }



        private async Task PerformFileSharingScan(string ip)
        {
            // Expanded port list with additional file sharing related services
            var fileSharingPorts = new Dictionary<int, (string Service, string Description, int RiskLevel)>
    {
        // Windows File Sharing
        { 135, ("MSRPC", "Microsoft RPC - Used in file/printer sharing, high risk if exposed", 9) },
        { 137, ("NetBIOS-NS", "NetBIOS Name Service - Legacy Windows file sharing discovery", 7) },
        { 138, ("NetBIOS-DGM", "NetBIOS Datagram Service - Broadcast sharing info", 7) },
        { 139, ("NetBIOS-SSN", "NetBIOS Session Service - File and printer sharing", 8) },
        { 445, ("SMB", "Microsoft SMB - Primary file sharing port on modern Windows systems", 10) },
        
        // Unix/Linux File Sharing
        { 111, ("RPCBind", "Remote Procedure Call Bind - Used with NFS", 6) },
        { 2049, ("NFS", "Network File System - Unix/Linux network file sharing", 9) },
        { 873, ("rsync", "Unix/Linux file synchronization service", 6) },
        { 3260, ("iSCSI", "Internet Small Computer Systems Interface - Block-level data transfer", 8) },
        { 8443, ("NX", "NoMachine NX - Remote file access", 5) },
        { 2020, ("FTP-DATA", "FTP Data transfer (alternate)", 7) },
        
        // Apple/macOS File Sharing
        { 548, ("AFP", "Apple Filing Protocol - Used by macOS for file sharing", 8) },
        { 427, ("SLP", "Service Location Protocol - Used by AFP", 5) },
        { 5009, ("Apple Xsan", "Apple Xsan filesystem sharing", 7) },
        
        // Media/General File Sharing
        { 1900, ("SSDP", "Simple Service Discovery Protocol - Media/device discovery", 5) },
        { 2869, ("UPNP", "Universal Plug and Play - HTTP service for device discovery", 6) },
        { 5000, ("UPnP", "Universal Plug and Play - Allows file/media sharing via discovery", 6) },
        { 5357, ("WSDAPI", "Web Services for Devices - Windows device and service discovery", 5) },
        { 3702, ("WS-Discovery", "Web Services Dynamic Discovery - Used for NAS discovery", 5) },
        { 10243, ("WSD-Events", "Web Services Discovery Events - Used for device discovery", 4) },
        
        // Other File-Related Services
        { 20, ("FTP-DATA", "FTP Data Transfer - Standard file transfer protocol data", 8) },
        { 21, ("FTP", "File Transfer Protocol - Standard file transfer protocol control", 8) },
        { 22, ("SFTP/SCP", "SSH File Transfer Protocol - Secure file transfers over SSH", 7) },
        { 69, ("TFTP", "Trivial File Transfer Protocol - Simple file transfers, no authentication", 9) },
        { 989, ("FTPS-DATA", "FTP Secure Data - Encrypted FTP data channel", 6) },
        { 990, ("FTPS", "FTP Secure - Encrypted FTP control channel", 6) },
        { 3128, ("Proxy/Cache", "Proxy/File Caching Service", 5) },
        { 3306, ("MySQL", "MySQL Database - Often used with file sharing applications", 8) },
        { 3389, ("RDP", "Remote Desktop Protocol - Can expose file systems", 9) },
        { 5800, ("VNC-HTTP", "VNC Web Interface - Can expose file systems", 8) },
        { 5900, ("VNC", "Virtual Network Computing - Remote access with file exposure", 8) },
        { 8009, ("AJP", "Apache JServ Protocol - May serve internal file resources", 6) },
        { 8080, ("HTTP-ALT", "Alternate HTTP - Web file serving", 7) },
        { 9000, ("FileIndex", "Sonar/File Index APIs", 5) },
        
        // Cloud Storage Related
        { 443, ("HTTPS", "Secure HTTP - Used by many cloud storage services", 6) },
        { 4443, ("Webdav-Alt", "Alternative WebDAV - Web-based file sharing", 7) },
        { 8181, ("WebDAV", "Web-based Distributed Authoring and Versioning", 7) }
    };

            // Create a CancellationTokenSource with timeout for the entire scan
            using CancellationTokenSource scanTimeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(60));

            int baseRiskScore = 100;
            int totalFoundPorts = 0;
            var foundPorts = new List<(int Port, string Service, string Description, int RiskLevel)>();
            var highRiskPorts = new List<int> { 21, 69, 111, 135, 137, 138, 139, 445, 548, 2049, 3389 };

            // UI notification for start of scan
            await UpdateRichTextBoxAsync(() =>
            {
                richTextBox1.SelectionColor = Color.DarkBlue;
                richTextBox1.AppendText($"🔍 Starting File Sharing Port Scan on {ip}...\n");
                richTextBox1.SelectionColor = richTextBox1.ForeColor;
            });

            // Initialize a list to hold all scan tasks
            List<Task<(bool IsOpen, int Port)>> scanTasks = new List<Task<(bool IsOpen, int Port)>>();

            // Create all scan tasks
            foreach (var portInfo in fileSharingPorts)
            {
                int port = portInfo.Key;
                scanTasks.Add(ScanPortAsync(ip, port, scanTimeoutCts.Token));
            }

            try
            {
                // Wait for all scans to complete or timeout
                while (scanTasks.Count > 0)
                {
                    // Use Task.WhenAny to process results as they complete
                    Task<(bool IsOpen, int Port)> completedTask = await Task.WhenAny(scanTasks);
                    scanTasks.Remove(completedTask);

                    // Process the completed scan result
                    var result = await completedTask;
                    if (result.IsOpen)
                    {
                        int port = result.Port;
                        var (service, description, riskLevel) = fileSharingPorts[port];

                        foundPorts.Add((port, service, description, riskLevel));
                        totalFoundPorts++;

                        // Update UI with the found port
                        await UpdateRichTextBoxAsync(() =>
                        {
                            // Apply color based on risk level
                            Color portColor = riskLevel >= 8 ? Color.Red :
                                             riskLevel >= 6 ? Color.DarkOrange : Color.DarkGreen;

                            richTextBox1.SelectionColor = portColor;
                            richTextBox1.AppendText($"📂 Port {port} ({service}): ");
                            richTextBox1.SelectionColor = richTextBox1.ForeColor;
                            richTextBox1.AppendText($"{description}\n");
                        });

                        // Reduce risk score based on risk level
                        if (highRiskPorts.Contains(port))
                        {
                            baseRiskScore -= riskLevel * 2; // Higher penalty for high-risk ports
                        }
                        else
                        {
                            baseRiskScore -= riskLevel;
                        }
                    }

                    // Update progress bar
                    int progressIncrement = 100 / fileSharingPorts.Count;
                    await UpdateProgressBarAsync(progressIncrement);
                }
            }
            catch (OperationCanceledException)
            {
                await UpdateRichTextBoxAsync(() =>
                {
                    richTextBox1.SelectionColor = Color.Red;
                    richTextBox1.AppendText("⚠️ Scan timed out. Some ports may not have been checked.\n");
                    richTextBox1.SelectionColor = richTextBox1.ForeColor;
                });
            }

            // Ensure risk score stays within bounds
            baseRiskScore = Math.Max(0, Math.Min(100, baseRiskScore));

            // Display scan summary
            await UpdateRichTextBoxAsync(() =>
            {
                richTextBox1.AppendText("\n");
                richTextBox1.SelectionColor = Color.Navy;
                richTextBox1.AppendText("📊 FILE SHARING SCAN SUMMARY\n");
                richTextBox1.SelectionColor = richTextBox1.ForeColor;
                richTextBox1.AppendText("───────────────────────────────────\n");

                // Risk score color coding
                Color scoreColor = baseRiskScore >= 70 ? Color.Green :
                                  baseRiskScore >= 40 ? Color.Orange : Color.Red;

                richTextBox1.SelectionColor = scoreColor;
                richTextBox1.AppendText($"🛡️ Security Score: {baseRiskScore}/100\n");
                richTextBox1.SelectionColor = richTextBox1.ForeColor;

                richTextBox1.AppendText($"🔢 Open Ports: {totalFoundPorts}\n");

                // Add security assessment
                richTextBox1.AppendText("\n📝 ASSESSMENT: ");

                if (baseRiskScore >= 80)
                {
                    richTextBox1.SelectionColor = Color.Green;
                    richTextBox1.AppendText("Low Exposure Risk\n");
                }
                else if (baseRiskScore >= 50)
                {
                    richTextBox1.SelectionColor = Color.Orange;
                    richTextBox1.AppendText("Moderate Exposure Risk\n");
                }
                else
                {
                    richTextBox1.SelectionColor = Color.Red;
                    richTextBox1.AppendText("High Exposure Risk\n");
                }

                richTextBox1.SelectionColor = richTextBox1.ForeColor;

                // Recommendations based on findings
                if (totalFoundPorts > 0)
                {
                    richTextBox1.SelectionColor = Color.DarkBlue;
                    richTextBox1.AppendText("\n🔧 RECOMMENDATIONS:\n");
                    richTextBox1.SelectionColor = richTextBox1.ForeColor;

                    // Group high-risk open ports
                    var highRiskFound = foundPorts.Where(p => p.RiskLevel >= 8).ToList();
                    if (highRiskFound.Any())
                    {
                        richTextBox1.AppendText("• Consider closing high-risk ports: ");
                        richTextBox1.SelectionColor = Color.Red;
                        richTextBox1.AppendText(string.Join(", ", highRiskFound.Select(p => $"{p.Port}({p.Service})")) + "\n");
                        richTextBox1.SelectionColor = richTextBox1.ForeColor;
                    }

                    // Common recommendations
                    if (foundPorts.Any(p => p.Port == 445 || p.Port == 139))
                    {
                        richTextBox1.AppendText("• Set strong SMB security policies and restrict access\n");
                    }

                    if (foundPorts.Any(p => p.Port == 21 || p.Port == 20 || p.Port == 989 || p.Port == 990))
                    {
                        richTextBox1.AppendText("• Use SFTP instead of standard FTP for better security\n");
                    }

                    if (foundPorts.Any(p => p.Port == 2049 || p.Port == 111))
                    {
                        richTextBox1.AppendText("• Configure NFS with proper access restrictions\n");
                    }

                    richTextBox1.AppendText("• Use a firewall to restrict access to file sharing services\n");
                    richTextBox1.AppendText("• Implement strong authentication for all file sharing services\n");
                }

                richTextBox1.AppendText("\n✅ File Sharing Scan Complete\n");
                richTextBox1.AppendText("───────────────────────────────────\n");
            });

            // Ensure progress bar is complete
            await UpdateProgressBarAsync(progressBar1.Maximum, true);
        }

        // Helper method to update the progress bar safely
        private async Task UpdateProgressBarAsync(int increment, bool setToMaximum = false)
        {
            if (progressBar1.InvokeRequired)
            {
                await Task.Run(() => progressBar1.Invoke((MethodInvoker)delegate
                {
                    if (setToMaximum)
                    {
                        progressBar1.Value = progressBar1.Maximum;
                    }
                    else if (progressBar1.Value + increment <= progressBar1.Maximum)
                    {
                        progressBar1.Value += increment;
                    }
                    else
                    {
                        progressBar1.Value = progressBar1.Maximum;
                    }
                }));
            }
            else
            {
                if (setToMaximum)
                {
                    progressBar1.Value = progressBar1.Maximum;
                }
                else if (progressBar1.Value + increment <= progressBar1.Maximum)
                {
                    progressBar1.Value += increment;
                }
                else
                {
                    progressBar1.Value = progressBar1.Maximum;
                }
            }
        }

        // Helper method to scan a single port asynchronously
        private async Task<(bool IsOpen, int Port)> ScanPortAsync(string ip, int port, CancellationToken cancellationToken)
        {
            try
            {
                using var client = new TcpClient();

                // Use a task with timeout for connection attempt
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
                using var combinedCts = CancellationTokenSource.CreateLinkedTokenSource(timeoutCts.Token, cancellationToken);

                await client.ConnectAsync(ip, port, combinedCts.Token);
                return (client.Connected, port);
            }
            catch (Exception)
            {
                // Port is closed or connection timed out
                return (false, port);
            }
        }

        // Helper method to update the RichTextBox safely
        private async Task UpdateRichTextBoxAsync(Action action)
        {
            if (richTextBox1.InvokeRequired)
            {
                await Task.Run(() => richTextBox1.Invoke(action));
            }
            else
            {
                action();
            }
        }




        private async void PerformProxyVpnFirewallCheck(string ip, CancellationToken cancellationToken = default)
        {
            void LogHeader(string title)
            {
                richTextBox1.Invoke(() =>
                {
                    richTextBox1.SelectionColor = System.Drawing.Color.White;
                    richTextBox1.SelectionBackColor = System.Drawing.Color.FromArgb(0, 122, 204);
                    richTextBox1.SelectionFont = new Font(richTextBox1.Font.FontFamily, 10, FontStyle.Bold);
                    richTextBox1.AppendText($" {title} ".PadRight(50) + Environment.NewLine);
                    richTextBox1.SelectionBackColor = richTextBox1.BackColor;
                    richTextBox1.SelectionFont = richTextBox1.Font;
                });
            }

            void Log(string msg, System.Drawing.Color color, string icon = "🌐")
            {
                richTextBox1.Invoke(() =>
                {
                    richTextBox1.SelectionColor = color;
                    richTextBox1.AppendText($"{icon} {msg}{Environment.NewLine}");
                    richTextBox1.ScrollToCaret();
                });
            }

            void UpdateProgress(int increment = 5)
            {
                progressBar1.Invoke(() =>
                {
                    if (progressBar1.Value + increment <= progressBar1.Maximum)
                        progressBar1.Value += increment;
                    else
                        progressBar1.Value = progressBar1.Maximum;
                });
            }

            try
            {
                // Initialize scan
                LogHeader($"SECURITY SCAN FOR {ip}");
                Log($"Starting comprehensive network security scan...", System.Drawing.Color.Cyan, "🔍");
                UpdateProgress();

                // Create scan result variables
                bool vpnDetected = false;
                bool proxyDetected = false;
                bool statefulFirewallDetected = false;
                bool statelessFirewallDetected = false;
                List<int> openPorts = new List<int>();

                // Define port categories for better classification
                Dictionary<int, (string service, string category)> portInfo = new Dictionary<int, (string, string)>
        {
            { 21, ("FTP", "Standard") },
            { 22, ("SSH", "Standard") },
            { 23, ("Telnet", "Standard") },
            { 25, ("SMTP", "Standard") },
            { 53, ("DNS", "Standard") },
            { 80, ("HTTP", "Standard") },
            { 443, ("HTTPS/OpenVPN", "VPN") },
            { 500, ("IPsec/IKE", "VPN") },
            { 1080, ("SOCKS Proxy", "Proxy") },
            { 1194, ("OpenVPN", "VPN") },
            { 3128, ("Squid Proxy", "Proxy") },
            { 4500, ("IPsec NAT-T", "VPN") },
            { 8000, ("Alt HTTP Proxy", "Proxy") },
            { 8080, ("HTTP Proxy", "Proxy") },
            { 8118, ("Privoxy", "Proxy") },
            { 8888, ("HTTP Proxy", "Proxy") },
            { 9050, ("Tor", "Proxy") }
        };

                // Get general IP information
                LogHeader("IP INFORMATION");
                try
                {
                    using (WebClient client = new WebClient())
                    {
                        string ipApiUrl = $"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,mobile,proxy,hosting";

                        Log($"Fetching geolocation and network data...", System.Drawing.Color.Cyan, "🔄");
                        string response = await client.DownloadStringTaskAsync(ipApiUrl);

                        // Parse JSON response
                        var ipInfo = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(response);

                        if (ipInfo.TryGetValue("status", out var status) && status.GetString() == "success")
                        {
                            Log($"Location: {ipInfo["country"].GetString()}, {ipInfo["regionName"].GetString()}, {ipInfo["city"].GetString()}",
                                System.Drawing.Color.White, "🌎");

                            Log($"ISP: {ipInfo["isp"].GetString()}", System.Drawing.Color.Brown, "🏢");

                            if (ipInfo.TryGetValue("org", out var org) && !org.ValueEquals(""))
                                Log($"Organization: {org.GetString()}", System.Drawing.Color.Brown, "🏛️");

                            Log($"AS: {ipInfo["as"].GetString()}", System.Drawing.Color.Brown, "🌐");

                            if (ipInfo.TryGetValue("proxy", out var proxy) && proxy.GetBoolean())
                            {
                                Log($"IP identified as proxy/VPN/tor by IP-API", System.Drawing.Color.Red, "⚠️");
                                proxyDetected = true;
                            }

                            if (ipInfo.TryGetValue("hosting", out var hosting) && hosting.GetBoolean())
                                Log($"IP belongs to a hosting provider", System.Drawing.Color.Orange, "☁️");
                        }
                    }
                }
                catch
                {
                    Log("Could not retrieve IP information from external API", System.Drawing.Color.Gray, "❓");
                }

                // Try reverse DNS lookup
                try
                {
                    var hostEntry = await Dns.GetHostEntryAsync(ip);
                    Log($"Reverse DNS: {hostEntry.HostName}", System.Drawing.Color.Cyan, "🧭");

                    string hostname = hostEntry.HostName.ToLower();
                    if (hostname.Contains("vpn") || hostname.Contains("tunnel") || hostname.Contains("tor"))
                    {
                        vpnDetected = true;
                        Log($"Hostname contains VPN/tunnel indicators", System.Drawing.Color.Red, "🔒");
                    }

                    if (hostname.Contains("proxy") || hostname.Contains("cache"))
                    {
                        proxyDetected = true;
                        Log($"Hostname contains proxy indicators", System.Drawing.Color.Red, "🔍");
                    }
                }
                catch
                {
                    Log("Reverse DNS lookup failed - possibly blocking DNS queries", System.Drawing.Color.Gray, "❌");
                    statefulFirewallDetected = true;  // DNS blocking often indicates firewall
                }

                UpdateProgress();

                // Check ASN ranges associated with VPN providers
                try
                {
                    IPAddress address = IPAddress.Parse(ip);
                    byte[] bytes = address.GetAddressBytes();

                    // Sample common VPN provider ranges
                    Dictionary<(byte, byte), string> vpnRanges = new Dictionary<(byte, byte), string>
            {
                { (185, 0), "NordVPN" },
                { (45, 0), "ProtonVPN" },
                { (198, 0), "ExpressVPN" },
                { (104, 0), "Private Internet Access" },
                { (92, 38), "Mullvad VPN" },
                { (31, 14), "NordVPN" },
                { (37, 120), "PureVPN" },
                { (37, 58), "StrongVPN" },
                { (146, 70), "Surfshark" }
            };

                    foreach (var range in vpnRanges)
                    {
                        if (bytes[0] == range.Key.Item1 && (range.Key.Item2 == 0 || bytes[1] == range.Key.Item2))
                        {
                            vpnDetected = true;
                            Log($"IP falls within known VPN range: {range.Value}", System.Drawing.Color.OrangeRed, "⚠️");
                            break;
                        }
                    }
                }
                catch
                {
                    Log("Unable to analyze ASN range", System.Drawing.Color.Gray, "⚠️");
                }

                UpdateProgress();

                // Port scanning - improved with parallel scanning and timeout
                LogHeader("PORT SCAN RESULTS");

                // First batch: Common ports
                var commonPorts = portInfo.Keys.ToList();
                Log($"Scanning {commonPorts.Count} common ports...", System.Drawing.Color.Cyan, "🔄");

                var portScanTasks = commonPorts.Select(async port =>
                {
                    try
                    {
                        using (TcpClient client = new TcpClient())
                        {
                            var connectTask = client.ConnectAsync(ip, port);
                            var timeoutTask = Task.Delay(200); // 200ms timeout

                            var completedTask = await Task.WhenAny(connectTask, timeoutTask);

                            if (completedTask == connectTask && client.Connected)
                            {
                                string serviceInfo = portInfo.ContainsKey(port) ?
                                    $"{portInfo[port].service}" : "Unknown Service";

                                string category = portInfo.ContainsKey(port) ?
                                    portInfo[port].category : "Unknown";

                                System.Drawing.Color portColor = category switch
                                {
                                    "VPN" => System.Drawing.Color.Red,
                                    "Proxy" => System.Drawing.Color.Orange,
                                    _ => System.Drawing.Color.DarkGreen
                                };

                                Log($"Port {port} OPEN - {serviceInfo}", portColor, "📶");

                                lock (openPorts)
                                {
                                    openPorts.Add(port);

                                    if (category == "VPN")
                                        vpnDetected = true;
                                    else if (category == "Proxy")
                                        proxyDetected = true;
                                }

                                return true;
                            }
                        }
                    }
                    catch { }

                    return false;
                }).ToList();

                // Wait for all port scans to complete
                await Task.WhenAll(portScanTasks);

                if (openPorts.Count == 0)
                    Log("No open ports detected - possible stateless firewall", System.Drawing.Color.AliceBlue, "🧱");

                UpdateProgress();

                // Firewall detection logic
                LogHeader("FIREWALL ANALYSIS");

                // Test for stateful firewall by sending malformed packets
                int statefulTestPort = 12345;

                try
                {
                    using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                    {
                        // Connect with extremely short timeout to trigger RST instead of waiting for timeout
                        IAsyncResult result = socket.BeginConnect(ip, statefulTestPort, null, null);
                        bool connected = result.AsyncWaitHandle.WaitOne(10); // Very short timeout

                        if (connected)
                        {
                            socket.EndConnect(result);
                            Log("No stateful firewall detected - unusual port accepted connection", System.Drawing.Color.Green, "🔓");
                        }
                        else
                        {
                            // Now try to determine if we got an explicit rejection or a timeout
                            try
                            {
                                socket.EndConnect(result);
                            }
                            catch (SocketException ex)
                            {
                                if (ex.SocketErrorCode == SocketError.ConnectionRefused)
                                {
                                    // We got an RST packet, which means no stateful firewall
                                    Log("Host actively refusing connections - typical behavior", System.Drawing.Color.AliceBlue, "🛡️");
                                }
                                else if (ex.SocketErrorCode == SocketError.TimedOut)
                                {
                                    // Timeout suggests packet filtering
                                    statelessFirewallDetected = true;
                                    Log("Connection attempts timing out - possible stateless firewall", System.Drawing.Color.Orange, "🧱");
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    if (ex.Message.Contains("actively refused"))
                    {
                        Log("Host actively refusing connections", System.Drawing.Color.AliceBlue, "🛡️");
                    }
                    else
                    {
                        statefulFirewallDetected = true;
                        Log("Connection terminated abnormally - possible stateful firewall", System.Drawing.Color.Orange, "🧱");
                    }
                }

                // Check for TCP sequence prediction protection (stateful firewall feature)
                try
                {
                    using (Socket socket1 = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                    using (Socket socket2 = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                    {
                        // Connect first socket to port 80 (or a known open port if we found one)
                        int testPort = openPorts.Count > 0 ? openPorts.First() : 80;

                        IAsyncResult result1 = socket1.BeginConnect(ip, testPort, null, null);
                        bool connected1 = result1.AsyncWaitHandle.WaitOne(1000);

                        if (connected1)
                        {
                            socket1.EndConnect(result1);

                            // Try to establish a second connection with the same parameters
                            IAsyncResult result2 = socket2.BeginConnect(ip, testPort, null, null);
                            bool connected2 = result2.AsyncWaitHandle.WaitOne(1000);

                            if (connected2)
                            {
                                socket2.EndConnect(result2);
                                Log("Multiple simultaneous connections allowed - basic firewall", System.Drawing.Color.Green, "🔓");
                            }
                            else
                            {
                                statefulFirewallDetected = true;
                                Log("Multiple simultaneous connections blocked - stateful inspection", System.Drawing.Color.Orange, "🧱");
                            }
                        }
                    }
                }
                catch
                {
                    Log("Could not complete firewall connection test", System.Drawing.Color.Gray, "❓");
                }

                UpdateProgress();

                // Final analysis and summary
                LogHeader("SCAN SUMMARY");

                if (vpnDetected)
                    Log("VPN SERVICE DETECTED", System.Drawing.Color.Red, "🔒");
                else
                    Log("No VPN detected", System.Drawing.Color.Green, "✅");

                if (proxyDetected)
                    Log("PROXY SERVICE DETECTED", System.Drawing.Color.Red, "🔍");
                else
                    Log("No proxy detected", System.Drawing.Color.Green, "✅");

                if (statefulFirewallDetected)
                    Log("STATEFUL FIREWALL DETECTED", System.Drawing.Color.Orange, "🧱");
                else
                    Log("No stateful firewall detected", System.Drawing.Color.Green, "✅");

                if (statelessFirewallDetected || openPorts.Count == 0)
                    Log("STATELESS FIREWALL/FILTERING DETECTED", System.Drawing.Color.Orange, "🛡️");
                else
                    Log("No stateless firewall detected", System.Drawing.Color.Green, "✅");

                // Overall security rating
                int securityScore = 0;
                if (vpnDetected) securityScore += 30;
                if (proxyDetected) securityScore += 20;
                if (statefulFirewallDetected) securityScore += 25;
                if (statelessFirewallDetected) securityScore += 15;
                if (openPorts.Count == 0) securityScore += 10;

                System.Drawing.Color ratingColor = securityScore switch
                {
                    < 30 => System.Drawing.Color.Red,
                    < 60 => System.Drawing.Color.Orange,
                    < 80 => System.Drawing.Color.AliceBlue,
                    _ => System.Drawing.Color.Green
                };

                string rating = securityScore switch
                {
                    < 30 => "LOW",
                    < 60 => "MODERATE",
                    < 80 => "HIGH",
                    _ => "VERY HIGH"
                };

                Log($"SECURITY RATING: {rating} ({securityScore}/100)", ratingColor, "🏆");

                // Finish progress bar
                progressBar1.Invoke(() => progressBar1.Value = progressBar1.Maximum);
            }
            catch (OperationCanceledException)
            {
                Log("Scan canceled by user", System.Drawing.Color.Gray, "❌");
            }
            catch (Exception ex)
            {
                Log($"Error during scan: {ex.Message}", System.Drawing.Color.Red, "⚠️");
            }
        }
        




        private async Task PerformIoTScan(List<string> ipList, CancellationToken cancellationToken = default)
        {
            void Log(string msg, Color? color = null)
            {
                richTextBox1.Invoke(() =>
                {
                    // Store current position and color
                    int startPos = richTextBox1.TextLength;

                    // Append the text
                    richTextBox1.AppendText(msg + Environment.NewLine);

                    // Apply color if specified
                    if (color.HasValue)
                    {
                        richTextBox1.SelectionStart = startPos;
                        richTextBox1.SelectionLength = msg.Length;
                        richTextBox1.SelectionColor = color.Value;
                    }

                    // Auto-scroll to the bottom
                    richTextBox1.ScrollToCaret();
                });
            }

            Dictionary<string, (string device, Color color)> fingerprints = new Dictionary<string, (string, Color)>(StringComparer.OrdinalIgnoreCase)
    {
        { "cisco", ("Cisco Router", Color.DarkOrange) },
        { "hp", ("HP Printer", Color.DodgerBlue) },
        { "xerox", ("Xerox Printer", Color.DarkCyan) },
        { "canon", ("Canon Printer", Color.Red) },
        { "roku", ("Smart TV (Roku)", Color.Purple) },
        { "webos", ("Smart TV (LG WebOS)", Color.LimeGreen) },
        { "samsung", ("Smart TV (Samsung)", Color.Blue) },
        { "printer", ("Generic Printer", Color.Gray) },
        { "tv", ("Smart TV", Color.Indigo) },
        { "cam", ("IP Camera", Color.Tomato) },
        { "router", ("Router/Embedded Device", Color.RoyalBlue) },
        { "microhttpd", ("Embedded Web Server", Color.DarkGreen) },
        { "lighttpd", ("Lightweight Web Server (IoT)", Color.SteelBlue) },
        { "tplink", ("TP-Link Router", Color.Teal) },
        { "dlink", ("D-Link Router", Color.DarkBlue) },
        { "netgear", ("Netgear Router", Color.MediumBlue) },
        { "uhttpd", ("uHTTPd - OpenWRT Router Web UI", Color.DarkOliveGreen) },
        { "dyson", ("Smart Appliance", Color.Chocolate) },
        { "nest", ("Google Nest Device", Color.Orange) },
        { "alexa", ("Amazon Alexa Device", Color.DarkSlateBlue) },
        { "hue", ("Philips Hue", Color.MediumOrchid) },
        { "sonos", ("Sonos Speaker", Color.Black) },
        { "hikvision", ("Hikvision Camera", Color.DarkRed) },
        { "dahua", ("Dahua Camera", Color.Crimson) },
        { "axis", ("Axis Camera", Color.DarkGoldenrod) },
        { "tuya", ("Tuya Smart Device", Color.DarkMagenta) },
        { "esp", ("ESP8266/ESP32 Device", Color.DarkTurquoise) }
    };

            // Port categories for better understanding of services
            var portCategories = new Dictionary<int, string>
    {
        { 21, "FTP" },
        { 22, "SSH" },
        { 23, "Telnet" },
        { 25, "SMTP" },
        { 53, "DNS" },
        { 80, "HTTP" },
        { 81, "HTTP Alternate" },
        { 443, "HTTPS" },
        { 554, "RTSP (Cameras)" },
        { 631, "IPP (Printing)" },
        { 1883, "MQTT (IoT)" },
        { 5683, "CoAP (IoT)" },
        { 8000, "HTTP Alt" },
        { 8080, "HTTP Proxy" },
        { 8081, "HTTP Alt" },
        { 8443, "HTTPS Alt" },
        { 8888, "HTTP Alt" },
        { 9100, "Raw Printing" },
        { 1900, "UPnP" },
        { 5000, "UPnP" },
        { 6000, "HTTP Alt" },
        { 8008, "HTTP Alt" },
        { 8009, "HTTP Alt" },
        { 49152, "UPnP" },
        { 32764, "Router Backdoor" }
    };

            int[] iotPorts = { 21, 22, 23, 25, 53, 80, 81, 443, 554, 631, 1883, 5683, 8000, 8080, 8081, 8443, 8888, 9100, 1900, 5000, 6000, 8008, 8009, 49152, 32764 };

            // Status tracking
            int totalDevices = ipList.Count;
            int scannedDevices = 0;
            int iotDevicesFound = 0;
            Dictionary<string, int> deviceTypeStats = new Dictionary<string, int>();

            Log($"🚀 Starting IoT Device Scan on {totalDevices} IP addresses...", Color.DarkBlue);
            Log($"⏱️ Scan started at: {DateTime.Now.ToString("HH:mm:ss")}", Color.DarkGray);
            Log("──────────────────────────────────────────────", Color.Gray);

            // Semaphore to limit concurrent scans
            using SemaphoreSlim semaphore = new SemaphoreSlim(10); // Limit to 10 concurrent scans
            List<Task> scanTasks = new List<Task>();

            // Create a task for each IP
            foreach (var ip in ipList)
            {
                scanTasks.Add(Task.Run(async () =>
                {
                    await semaphore.WaitAsync(cancellationToken);
                    try
                    {
                        if (cancellationToken.IsCancellationRequested)
                            return;

                        Log($"\n🔍 Scanning {ip} for IoT traits...", Color.RoyalBlue);
                        bool isIoT = false;
                        string guess = "Unknown";
                        string matchedDevice = "None";
                        Color deviceColor = Color.Black;
                        List<string> detectionReasons = new List<string>();
                        List<int> openPorts = new List<int>();

                        try
                        {
                            using (Ping ping = new Ping())
                            {
                                var reply = await ping.SendPingAsync(ip, 1000);
                                if (reply.Status == IPStatus.Success)
                                {
                                    int ttl = reply.Options?.Ttl ?? 0;

                                    // More accurate OS fingerprinting based on TTL
                                    guess = ttl >= 225 ? "Cisco/Network Device" :
                                           ttl >= 200 ? "Router/Embedded Device" :
                                           ttl == 128 ? "Windows-based" :
                                           ttl == 64 ? "Linux-based" :
                                           ttl == 60 ? "MacOS" :
                                           ttl == 255 ? "Cisco/Network Device" : "Unknown";

                                    Log($"📡 TTL: {ttl} → OS Guess: {guess}",
                                        ttl > 200 ? Color.DarkOrange :
                                        ttl == 64 ? Color.Green :
                                        ttl == 128 ? Color.Blue : Color.DarkGray);

                                    if (ttl > 200)
                                    {
                                        isIoT = true;
                                        detectionReasons.Add($"TTL value {ttl} suggests embedded device");
                                    }
                                }
                                else
                                {
                                    Log($"❌ Device at {ip} did not respond to ping ({reply.Status})", Color.Red);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Log($"❌ Ping failed: {ex.Message}", Color.Red);
                        }

                        // Port scanning with improved timeout handling
                        var portScanTasks = new List<Task<(int port, bool isOpen, string banner)>>();

                        foreach (var port in iotPorts)
                        {
                            portScanTasks.Add(CheckPortAsync(ip, port));
                        }

                        var portResults = await Task.WhenAll(portScanTasks);

                        foreach (var result in portResults)
                        {
                            if (result.isOpen)
                            {
                                openPorts.Add(result.port);
                                isIoT = true;
                                string portDescription = portCategories.ContainsKey(result.port)
                                    ? $"{result.port} ({portCategories[result.port]})"
                                    : result.port.ToString();

                                Log($"✅ Open port: {portDescription}", Color.Green);

                                if (!string.IsNullOrEmpty(result.banner))
                                {
                                    foreach (var keyword in fingerprints.Keys)
                                    {
                                        if (result.banner.Contains(keyword))
                                        {
                                            matchedDevice = fingerprints[keyword].device;
                                            deviceColor = fingerprints[keyword].color;
                                            detectionReasons.Add($"Banner match: '{keyword}'");
                                            Log($"🧠 Detected: {matchedDevice} (via banner match: '{keyword}')", deviceColor);
                                            break;
                                        }
                                    }

                                    if (string.IsNullOrEmpty(matchedDevice) || matchedDevice == "None")
                                    {
                                        string preview = result.banner.Split('\n')[0];
                                        if (preview.Length > 50) preview = preview.Substring(0, 50) + "...";
                                        Log($"📝 Banner Preview: {preview}", Color.DarkGray);
                                    }
                                }
                            }
                        }

                        // UPnP Detection
                        if (openPorts.Contains(1900))
                        {
                            try
                            {
                                string upnpInfo = await CheckUPnPAsync(ip);
                                if (!string.IsNullOrEmpty(upnpInfo))
                                {
                                    Log($"📱 UPnP Info: {upnpInfo}", Color.Purple);
                                    detectionReasons.Add("UPnP service detected");

                                    // Try to determine device type from UPnP info
                                    if (matchedDevice == "None")
                                    {
                                        foreach (var keyword in fingerprints.Keys)
                                        {
                                            if (upnpInfo.ToLower().Contains(keyword))
                                            {
                                                matchedDevice = fingerprints[keyword].device;
                                                deviceColor = fingerprints[keyword].color;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            catch { }
                        }

                        // If multiple ports are open, it's more likely to be an IoT device
                        if (openPorts.Count >= 2)
                        {
                            detectionReasons.Add($"Multiple ports open: {openPorts.Count}");
                        }

                        // Final determination and output
                        if (isIoT || matchedDevice != "None")
                        {
                            // If we haven't identified the device but we have open ports, make an educated guess
                            if (matchedDevice == "None")
                            {
                                if (openPorts.Contains(554) || openPorts.Contains(8000) || openPorts.Contains(8554))
                                {
                                    matchedDevice = "IP Camera";
                                    deviceColor = Color.Tomato;
                                }
                                else if (openPorts.Contains(9100) || openPorts.Contains(631))
                                {
                                    matchedDevice = "Printer";
                                    deviceColor = Color.DarkBlue;
                                }
                                else if (openPorts.Contains(8008) || openPorts.Contains(8009))
                                {
                                    matchedDevice = "Smart TV/Media Device";
                                    deviceColor = Color.Purple;
                                }
                                else if (guess.Contains("Router") || guess.Contains("Embedded"))
                                {
                                    matchedDevice = "Router/Network Device";
                                    deviceColor = Color.RoyalBlue;
                                }
                                else
                                {
                                    matchedDevice = "Unknown IoT Device";
                                    deviceColor = Color.DarkOrange;
                                }
                            }

                            string reasons = detectionReasons.Count > 0
                                ? string.Join(", ", detectionReasons)
                                : "Open IoT ports detected";

                            Log($"🤖 {ip} is an IoT Device: {matchedDevice} ✅", deviceColor);
                            Log($"   Detected based on: {reasons}", Color.DarkGray);

                            // Update device stats
                            lock (deviceTypeStats)
                            {
                                if (!deviceTypeStats.ContainsKey(matchedDevice))
                                    deviceTypeStats[matchedDevice] = 0;
                                deviceTypeStats[matchedDevice]++;
                                iotDevicesFound++;
                            }
                        }
                        else
                        {
                            Log($"🚫 {ip} does not appear to be an IoT device.", Color.Gray);
                        }

                        // Update progress
                        Interlocked.Increment(ref scannedDevices);
                        int progressPercentage = (int)((double)scannedDevices / totalDevices * 100);
                        Log($"Progress: {progressPercentage}% ({scannedDevices}/{totalDevices})", Color.DarkGray);
                    }
                    catch (Exception ex)
                    {
                        Log($"❌ Error scanning {ip}: {ex.Message}", Color.Red);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, cancellationToken));
            }

            try
            {
                await Task.WhenAll(scanTasks);
            }
            catch (OperationCanceledException)
            {
                Log("\n🛑 Scan was cancelled by user.", Color.Red);
            }
            catch (Exception ex)
            {
                Log($"\n❌ Error during scan: {ex.Message}", Color.Red);
            }

            // Final summary
            Log("\n──────────────────────────────────────────────", Color.Gray);
            Log($"✅ IoT Device Scan Completed at {DateTime.Now.ToString("HH:mm:ss")}", Color.Green);
            Log($"📊 Summary: Found {iotDevicesFound} IoT devices out of {totalDevices} scanned IPs",
                iotDevicesFound > 0 ? Color.Green : Color.DarkGray);

            if (deviceTypeStats.Count > 0)
            {
                Log("\n📱 Device Type Breakdown:", Color.Blue);
                foreach (var stat in deviceTypeStats.OrderByDescending(s => s.Value))
                {
                    Log($"   • {stat.Key}: {stat.Value}", Color.DarkBlue);
                }
            }

            Log("──────────────────────────────────────────────", Color.Gray);
        }

        // Helper method to check if a port is open and get banner if available
        private async Task<(int port, bool isOpen, string banner)> CheckPortAsync(string ip, int port)
        {
            try
            {
                using TcpClient client = new TcpClient();
                var connectTask = client.ConnectAsync(ip, port);

                // Use Task.WhenAny to implement timeout
                if (await Task.WhenAny(connectTask, Task.Delay(300)) == connectTask && client.Connected)
                {
                    string banner = "";

                    try
                    {
                        // For HTTP(S) ports, send HTTP request
                        if (port == 80 || port == 8080 || port == 8000 || port == 8081 || port == 8888 ||
                            port == 443 || port == 8443)
                        {
                            NetworkStream stream = client.GetStream();

                            // If it's an HTTPS port, wrap in SSL stream
                            Stream dataStream = stream;
                            if (port == 443 || port == 8443)
                            {
                                try
                                {
                                    // Ignore certificate errors
                                    SslStream sslStream = new SslStream(stream, false,
                                        (sender, certificate, chain, sslPolicyErrors) => true);
                                    await sslStream.AuthenticateAsClientAsync(ip);
                                    dataStream = sslStream;
                                }
                                catch
                                {
                                    // If SSL fails, just continue with regular stream
                                    dataStream = stream;
                                }
                            }

                            string httpRequest = $"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: NetworkScanner/1.0\r\nConnection: close\r\n\r\n";
                            byte[] requestData = Encoding.ASCII.GetBytes(httpRequest);

                            await dataStream.WriteAsync(requestData, 0, requestData.Length);
                            await dataStream.FlushAsync();

                            // Read response
                            byte[] buffer = new byte[4096];
                            using MemoryStream ms = new MemoryStream();
                            int bytesRead;

                            var readTask = dataStream.ReadAsync(buffer, 0, buffer.Length);
                            if (await Task.WhenAny(readTask, Task.Delay(500)) == readTask)
                            {
                                bytesRead = readTask.Result;
                                if (bytesRead > 0)
                                {
                                    ms.Write(buffer, 0, bytesRead);
                                    banner = Encoding.ASCII.GetString(ms.ToArray()).ToLower();
                                }
                            }
                        }
                        // For telnet/banner grabbing on other ports
                        else if (port == 21 || port == 22 || port == 23 || port == 25 || port == 554)
                        {
                            NetworkStream stream = client.GetStream();
                            stream.ReadTimeout = 500;

                            // Just try to read the banner
                            byte[] buffer = new byte[1024];
                            var readTask = stream.ReadAsync(buffer, 0, buffer.Length);

                            if (await Task.WhenAny(readTask, Task.Delay(500)) == readTask)
                            {
                                int bytesRead = readTask.Result;
                                if (bytesRead > 0)
                                {
                                    banner = Encoding.ASCII.GetString(buffer, 0, bytesRead).ToLower();
                                }
                            }
                        }
                    }
                    catch { /* Ignore banner grabbing errors */ }

                    return (port, true, banner);
                }
            }
            catch { /* Ignore connection errors */ }

            return (port, false, "");
        }

        // Helper method to check for UPnP information
        private async Task<string> CheckUPnPAsync(string ip)
        {
            try
            {
                using UdpClient udpClient = new UdpClient();
                udpClient.Client.ReceiveTimeout = 1000;

                // UPnP discovery message
                string discoveryMessage =
                    "M-SEARCH * HTTP/1.1\r\n" +
                    "HOST: 239.255.255.250:1900\r\n" +
                    "MAN: \"ssdp:discover\"\r\n" +
                    "MX: 1\r\n" +
                    "ST: ssdp:all\r\n\r\n";

                byte[] requestData = Encoding.ASCII.GetBytes(discoveryMessage);
                await udpClient.SendAsync(requestData, requestData.Length, ip, 1900);

                IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                var receiveTask = udpClient.ReceiveAsync();

                if (await Task.WhenAny(receiveTask, Task.Delay(1000)) == receiveTask)
                {
                    var result = receiveTask.Result;
                    string response = Encoding.ASCII.GetString(result.Buffer);

                    // Extract useful information
                    var match = Regex.Match(response, @"SERVER: (.*?)\r\n");
                    if (match.Success)
                    {
                        return match.Groups[1].Value.Trim();
                    }

                    // If no server header, look for model name
                    match = Regex.Match(response, @"MODEL: (.*?)\r\n");
                    if (match.Success)
                    {
                        return $"Model: {match.Groups[1].Value.Trim()}";
                    }

                    // Return partial response if we got something
                    if (!string.IsNullOrEmpty(response))
                    {
                        var firstLine = response.Split('\n').FirstOrDefault() ?? "";
                        return firstLine.Length > 0 ? firstLine : "UPnP service detected";
                    }
                }
            }
            catch { /* Ignore UPnP errors */ }

            return "";
        }







        private void PerformCryptoScan(string ip)
        {
            // Define enhanced logging function with timestamps and icons
            void Log(string msg, string icon = "🔎", System.Drawing.Color? customColor = null)
            {
                var color = customColor ?? System.Drawing.Color.Cyan;
                richTextBox1.Invoke(() =>
                {
                    richTextBox1.SelectionColor = color;
                    richTextBox1.AppendText($"{icon} [{DateTime.Now:HH:mm:ss}] {msg}{Environment.NewLine}");
                    richTextBox1.ScrollToCaret();
                });
            }

            // Improved status highlighting with more detailed ratings
            void Highlight(string status, string details = "")
            {
                var (color, icon) = status switch
                {
                    "Excellent" => (System.Drawing.Color.DarkGreen, "🔒"),
                    "Secure" => (System.Drawing.Color.Green, "🔒"),
                    "Moderate" => (System.Drawing.Color.Orange, "⚠️"),
                    "Outdated" => (System.Drawing.Color.Red, "❗"),
                    "Vulnerable" => (System.Drawing.Color.DarkRed, "🚨"),
                    _ => (System.Drawing.Color.Gray, "❓")
                };

                richTextBox1.Invoke(() =>
                {
                    richTextBox1.SelectionColor = color;
                    richTextBox1.SelectionFont = new System.Drawing.Font(richTextBox1.Font.FontFamily, richTextBox1.Font.Size, System.Drawing.FontStyle.Bold);
                    richTextBox1.AppendText($"{icon} Security Rating: {status}{Environment.NewLine}");

                    if (!string.IsNullOrEmpty(details))
                    {
                        richTextBox1.SelectionColor = color;
                        richTextBox1.SelectionFont = new System.Drawing.Font(richTextBox1.Font.FontFamily, richTextBox1.Font.Size, System.Drawing.FontStyle.Regular);
                        richTextBox1.AppendText($"   {details}{Environment.NewLine}");
                    }

                    richTextBox1.AppendText(Environment.NewLine);
                    richTextBox1.ScrollToCaret();
                });
            }

            // Show scan initiation message
            Log($"Starting SSL/TLS security scan for {ip}...", "🚀", System.Drawing.Color.DeepSkyBlue);

            try
            {
                using (TcpClient client = new TcpClient())
                {
                    // Connection attempt with better timeout handling
                    var connectionTask = client.ConnectAsync(ip, 443);
                    if (!Task.WaitAll(new[] { connectionTask }, 3000))
                    {
                        Log("Port 443 unreachable or connection timed out.", "❌", System.Drawing.Color.Red);
                        Highlight("Vulnerable", "HTTPS endpoint not accessible");
                        return;
                    }

                    Log("Connected to HTTPS endpoint successfully.", "✅", System.Drawing.Color.LightGreen);
                    UpdateProgress(10);

                    // Create SSL Stream with more options
                    using (SslStream sslStream = new SslStream(
                        client.GetStream(),
                        false,
                        (sender, certificate, chain, errors) =>
                        {
                            // Record certificate validation issues but allow connection to continue
                            if (errors != System.Net.Security.SslPolicyErrors.None)
                            {
                                Log($"Certificate validation issues: {errors}", "⚠️", System.Drawing.Color.Orange);
                            }
                            return true;
                        }))
                    {
                        // Try to authenticate with modern protocols first
                        try
                        {
                            sslStream.AuthenticateAsClient(
                                ip,
                                null,
                                System.Security.Authentication.SslProtocols.Tls12 |
                                System.Security.Authentication.SslProtocols.Tls13,
                                true  // Check certificate revocation
                            );
                        }
                        catch (Exception)
                        {
                            // Fall back to allowing older protocols (for analysis only)
                            Log("Modern TLS handshake failed, falling back to include older protocols.", "⚠️", System.Drawing.Color.Orange);
                            try
                            {
                                sslStream.AuthenticateAsClient(
                                    ip,
                                    null,
                                    System.Security.Authentication.SslProtocols.Tls |
                                    System.Security.Authentication.SslProtocols.Tls11 |
                                    System.Security.Authentication.SslProtocols.Tls12 |
                                    System.Security.Authentication.SslProtocols.Tls13,
                                    false
                                );
                            }
                            catch (Exception ex)
                            {
                                Log($"SSL/TLS handshake failed: {ex.Message}", "❌", System.Drawing.Color.Red);
                                Highlight("Vulnerable", "Unable to establish secure connection");
                                return;
                            }
                        }

                        UpdateProgress(20);

                        // Extract certificate details
                        var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(sslStream.RemoteCertificate);

                        // Display certificate info with improved formatting
                        Log("Certificate Details:", "📜", System.Drawing.Color.LightBlue);
                        Log($"Subject: {cert.Subject}", "📍", System.Drawing.Color.White);

                        // Certificate validity period
                        var now = DateTime.Now;
                        var daysUntilExpiration = (cert.NotAfter - now).TotalDays;
                        var expirationColor = daysUntilExpiration < 30 ? System.Drawing.Color.OrangeRed :
                                             daysUntilExpiration < 90 ? System.Drawing.Color.Orange :
                                             System.Drawing.Color.LightGreen;

                        Log($"Valid From: {cert.NotBefore:yyyy-MM-dd}", "📆", System.Drawing.Color.White);
                        Log($"Valid Until: {cert.NotAfter:yyyy-MM-dd} ({daysUntilExpiration:F0} days)", "📅", expirationColor);

                        UpdateProgress(40);

                        // Security details
                        Log($"Public Key: {cert.PublicKey.Oid.FriendlyName}, {cert.PublicKey.Key.KeySize} bits", "🔑",
                            cert.PublicKey.Key.KeySize >= 2048 ? System.Drawing.Color.LightGreen : System.Drawing.Color.OrangeRed);
                        Log($"Signature Algorithm: {cert.SignatureAlgorithm.FriendlyName}", "✒️",
                            cert.SignatureAlgorithm.FriendlyName.Contains("sha256") ||
                            cert.SignatureAlgorithm.FriendlyName.Contains("sha384") ||
                            cert.SignatureAlgorithm.FriendlyName.Contains("sha512") ?
                            System.Drawing.Color.LightGreen : System.Drawing.Color.OrangeRed);
                        Log($"Issuer: {cert.Issuer}", "⚓", System.Drawing.Color.White);

                        // Check for SAN (Subject Alternative Names)
                        var sanExtension = cert.Extensions.Cast<System.Security.Cryptography.X509Certificates.X509Extension>()
                            .FirstOrDefault(e => e.Oid.Value == "2.5.29.17"); // SAN OID

                        if (sanExtension != null)
                        {
                            var asnData = new System.Security.Cryptography.AsnEncodedData(sanExtension.Oid, sanExtension.RawData);
                            Log($"Subject Alternative Names: {asnData.Format(false)}", "🔗", System.Drawing.Color.White);
                        }

                        UpdateProgress(60);

                        // Check TLS Protocol Version
                        string tlsVersion = sslStream.SslProtocol.ToString();
                        Log($"TLS Protocol: {tlsVersion}", "🔌",
                            tlsVersion.Contains("Tls13") ? System.Drawing.Color.LightGreen :
                            tlsVersion.Contains("Tls12") ? System.Drawing.Color.LightBlue :
                            System.Drawing.Color.OrangeRed);

                        // Check for Cipher Suite if available
                        string cipherSuite = string.Empty;

                        try
                        {
                            // This might not be available in all .NET versions/platforms
                            var cipherSuiteProperty = sslStream.GetType().GetProperty("NegotiatedCipherSuite");
                            if (cipherSuiteProperty != null)
                            {
                                var value = cipherSuiteProperty.GetValue(sslStream);
                                if (value != null)
                                    cipherSuite = value.ToString();
                            }

                            if (!string.IsNullOrEmpty(cipherSuite))
                                Log($"Cipher Suite: {cipherSuite}", "🔐", System.Drawing.Color.White);
                        }
                        catch { /* Ignoring if not supported */ }

                        UpdateProgress(80);

                        // Enhanced comprehensive rating
                        var securityIssues = new List<string>();
                        string rating = "Secure"; // Default

                        // Certificate expiration check
                        if (daysUntilExpiration < 0)
                        {
                            rating = "Vulnerable";
                            securityIssues.Add("Certificate has expired");
                        }
                        else if (daysUntilExpiration < 30)
                        {
                            if (rating != "Vulnerable") rating = "Moderate";
                            securityIssues.Add($"Certificate expires soon ({daysUntilExpiration:F0} days)");
                        }

                        // Key strength check
                        if (cert.PublicKey.Key.KeySize < 2048)
                        {
                            rating = "Vulnerable";
                            securityIssues.Add($"Weak key size ({cert.PublicKey.Key.KeySize} bits)");
                        }

                        // Signature algorithm check
                        if (cert.SignatureAlgorithm.FriendlyName.Contains("md5") ||
                            cert.SignatureAlgorithm.FriendlyName.Contains("sha1"))
                        {
                            rating = "Vulnerable";
                            securityIssues.Add("Weak signature algorithm");
                        }
                        else if (!cert.SignatureAlgorithm.FriendlyName.Contains("sha256") &&
                                 !cert.SignatureAlgorithm.FriendlyName.Contains("sha384") &&
                                 !cert.SignatureAlgorithm.FriendlyName.Contains("sha512"))
                        {
                            if (rating != "Vulnerable") rating = "Moderate";
                            securityIssues.Add("Suboptimal signature algorithm");
                        }

                        // TLS version check
                        if (tlsVersion.Contains("Tls13"))
                        {
                            if (rating == "Secure" && cert.PublicKey.Key.KeySize >= 3072 &&
                                (cert.SignatureAlgorithm.FriendlyName.Contains("sha384") ||
                                 cert.SignatureAlgorithm.FriendlyName.Contains("sha512")))
                            {
                                rating = "Excellent";
                            }
                        }
                        else if (!tlsVersion.Contains("Tls12") && !tlsVersion.Contains("Tls13"))
                        {
                            rating = "Outdated";
                            securityIssues.Add("Outdated TLS protocol version");
                        }
                        else if (!tlsVersion.Contains("Tls13"))
                        {
                            // TLS 1.2 is acceptable but not ideal
                            if (rating == "Secure") rating = "Moderate";
                            securityIssues.Add("Not using latest TLS 1.3");
                        }

                        UpdateProgress(100);

                        // Display final rating with detailed explanation
                        string details = securityIssues.Count > 0 ?
                            "Issues: " + string.Join("; ", securityIssues) :
                            "No significant security issues detected";

                        Highlight(rating, details);
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"Error during scan: {ex.Message}", "❌", System.Drawing.Color.Red);
                if (ex.InnerException != null)
                {
                    Log($"Details: {ex.InnerException.Message}", "  ⮑", System.Drawing.Color.Red);
                }
                Highlight("Error", "Could not complete security analysis");
                UpdateProgress(100); // Ensure progress bar completes
            }

            // Helper method to update progress bar
            void UpdateProgress(int value)
            {
                progressBar1.Invoke(() =>
                {
                    progressBar1.Value = Math.Min(100, Math.Max(0, value));
                });
            }
        }
        private void PerformScanTasks(string ip, CancellationToken ct)
        {
            void Log(string msg) => richTextBox1.Invoke(() => richTextBox1.AppendText(msg + Environment.NewLine));
            void UpdateProgress(int value) => progressBar1.Invoke(() => progressBar1.Value = value);

            // Step 1: Enhanced PING & OS DETECTION
            Log("\n=== STEP 1: ENHANCED PING & OS DETECTION ===");

            int[] ttlValues = new int[5];
            bool pingSuccess = false;

            try
            {
                using (Ping ping = new Ping())
                {
                    for (int i = 0; i < 5; i++)
                    {
                        if (ct.IsCancellationRequested) return;

                        PingOptions options = new PingOptions(i + 1, true);
                        byte[] buffer = Encoding.ASCII.GetBytes(new string('A', 32));

                        var reply = ping.Send(ip, 1000, buffer, options);

                        if (reply.Status == IPStatus.Success)
                        {
                            pingSuccess = true;
                            ttlValues[i] = reply.Options.Ttl;
                            Log($"✅ Ping {i + 1}: Reply from {reply.Address}, Time={reply.RoundtripTime}ms, TTL={ttlValues[i]}, " +
                                $"Size={reply.Buffer.Length}b");
                        }
                        else
                        {
                            Log($"❌ Ping {i + 1}: {reply.Status}");
                        }
                    }

                    // More accurate OS detection based on TTL patterns
                    string osGuess = "Unknown";
                    if (pingSuccess)
                    {
                        int avgTtl = (int)ttlValues.Where(t => t > 0).DefaultIfEmpty(0).Average(t => t);


                        if (avgTtl <= 0)
                        {
                            osGuess = "Firewall/Blocked";
                        }
                        else if (avgTtl <= 32)
                        {
                            osGuess = "Network Device";
                        }
                        else if (avgTtl <= 64)
                        {
                            osGuess = "Linux/Unix/macOS";
                        }
                        else if (avgTtl <= 128)
                        {
                            osGuess = "Windows";
                        }
                        else if (avgTtl <= 255)
                        {
                            osGuess = "Cisco/Network Equipment";
                        }

                        // Try to get additional OS info via HTTP
                        try
                        {
                            using (HttpClient client = new HttpClient())
                            {
                                client.Timeout = TimeSpan.FromSeconds(2);
                                client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0");
                                var response = client.GetAsync($"http://{ip}").Result;

                                if (response.IsSuccessStatusCode)
                                {
                                    var serverHeader = response.Headers.Server.ToString();
                                    if (!string.IsNullOrEmpty(serverHeader))
                                    {
                                        osGuess += $" (Web: {serverHeader})";
                                    }
                                }
                            }
                        }
                        catch { /* Ignore HTTP errors */ }
                    }

                    Log($"🖥️ [OS Detection] Detected OS: {osGuess}");

                    // Additional network info
                    try
                    {
                        IPHostEntry hostEntry = Dns.GetHostEntry(ip);
                        Log($"📛 Hostname: {hostEntry.HostName}");

                        // Get MAC address (works on local network)
                        string macAddress = GetMacAddress(ip);
                        if (!string.IsNullOrEmpty(macAddress))
                        {
                            string vendor = GetVendorFromMac(macAddress);
                            Log($"💻 MAC Address: {macAddress} ({vendor})");
                        }
                    }
                    catch { Log("❌ Could not resolve hostname"); }
                }
            }
            catch (Exception ex) { Log($"❌ Ping failed: {ex.Message}"); }

            UpdateProgress(10);

            // Step 2: BANNER GRABBING (200 COMMON PORTS)
            Log("\n=== STEP 2: EXTENSIVE BANNER GRABBING (200 COMMON PORTS) ===");

            // 200 commonly used ports
            int[] commonPorts = {
        1, 3, 7, 9, 13, 17, 19, 20, 21, 22, 23, 25, 26, 37, 53, 67, 68, 69, 79, 80,
        81, 82, 83, 84, 85, 88, 89, 90, 99, 106, 109, 110, 111, 113, 119, 123, 135, 137, 138, 139,
        143, 144, 161, 162, 177, 179, 192, 199, 201, 264, 311, 389, 427, 443, 444, 445, 464, 465, 497, 500,
        512, 513, 514, 515, 520, 521, 540, 548, 554, 563, 587, 593, 631, 636, 639, 646, 691, 860, 873, 902,
        989, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1080, 1194, 1214, 1241, 1311, 1337, 1433, 1434, 1512, 1589, 1701,
        1723, 1725, 1741, 1755, 1812, 1813, 1863, 1900, 2000, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2100, 2222, 2483, 2484,
        2601, 2604, 2638, 2809, 2947, 2967, 3000, 3128, 3130, 3306, 3389, 3396, 3689, 3690, 4662, 5000, 5001, 5004, 5005, 5060,
        5061, 5190, 5222, 5223, 5228, 5280, 5432, 5554, 5631, 5632, 5800, 5900, 5938, 6000, 6001, 6346, 6347, 6660, 6661, 6662,
        6663, 6664, 6665, 6666, 6667, 6668, 6669, 6697, 7000, 7001, 7002, 7070, 7777, 8000, 8001, 8002, 8008, 8009, 8010, 8080,
        8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8118, 8123, 8443, 8888, 9000, 9001, 9090, 9091, 9102, 9999
    };

            Dictionary<int, string> portServices = new Dictionary<int, string>
    {
        {1, "TCPMUX"}, {3, "COMPRESSNET"}, {7, "ECHO"}, {9, "DISCARD"}, {13, "DAYTIME"},
        {17, "QOTD"}, {19, "CHARGEN"}, {20, "FTP-DATA"}, {21, "FTP"}, {22, "SSH"},
        {23, "TELNET"}, {25, "SMTP"}, {26, "RSFTP"}, {37, "TIME"}, {53, "DNS"},
        {67, "DHCP-SRV"}, {68, "DHCP-CLT"}, {69, "TFTP"}, {79, "FINGER"}, {80, "HTTP"},
        {81, "TORPARK"}, {82, "TORPARK"}, {83, "MIT-ML"}, {84, "CTF"}, {85, "MIT-ML"},
        {88, "KERBEROS"}, {89, "SU-MIT"}, {90, "DNSIX"}, {99, "METAGRAM"}, {106, "POP3PW"},
        {109, "POP2"}, {110, "POP3"}, {111, "RPCBIND"}, {113, "IDENT"}, {119, "NNTP"},
        {123, "NTP"}, {135, "MSRPC"}, {137, "NETBIOS-NS"}, {138, "NETBIOS-DGM"}, {139, "NETBIOS-SSN"},
        {143, "IMAP"}, {144, "NEWS"}, {161, "SNMP"}, {162, "SNMPTRAP"}, {177, "XDMCP"},
        {179, "BGP"}, {192, "OSU-NMS"}, {199, "SMUX"}, {201, "APPSERV"}, {264, "BGMP"},
        {311, "ASIP"}, {389, "LDAP"}, {427, "SLP"}, {443, "HTTPS"}, {444, "SNPP"},
        {445, "SMB"}, {464, "KPASSWD"}, {465, "SMTPS"}, {497, "RETROSPECT"}, {500, "ISAKMP"},
        {512, "EXEC"}, {513, "LOGIN"}, {514, "SHELL"}, {515, "PRINTER"}, {520, "RIP"},
        {521, "RIPNG"}, {540, "UUCP"}, {548, "AFP"}, {554, "RTSP"}, {563, "NNTPS"},
        {587, "SUBMISSION"}, {593, "HTTP-RPC"}, {631, "IPP"}, {636, "LDAPS"}, {639, "MSDP"},
        {646, "LDP"}, {691, "MS-EXCHANGE"}, {860, "ISCSI"}, {873, "RSYNC"}, {902, "VMware"},
        {989, "FTPS-DATA"}, {990, "FTPS"}, {993, "IMAPS"}, {995, "POP3S"}, {1025, "NFS"},
        {1026, "CALENDAR"}, {1027, "NTALK"}, {1028, "RMI"}, {1029, "MS-LSASS"}, {1080, "SOCKS"},
        {1194, "OpenVPN"}, {1214, "KAZAA"}, {1241, "NESSUS"}, {1311, "DELL-WEBADMIN"}, {1337, "WASTE"},
        {1433, "MS-SQL"}, {1434, "MS-SQL-M"}, {1512, "WINS"}, {1589, "CISCO-VQP"}, {1701, "L2TP"},
        {1723, "PPTP"}, {1725, "STEAM"}, {1741, "NETIQ"}, {1755, "MS-MEDIA"}, {1812, "RADIUS"},
        {1813, "RADIUS-ACT"}, {1863, "MSN"}, {1900, "UPNP"}, {2000, "CISCO-SCCP"}, {2049, "NFS"},
        {2082, "CPANEL"}, {2083, "CPANEL-SSL"}, {2086, "WHM"}, {2087, "WHM-SSL"}, {2095, "WEBMAIL"},
        {2096, "WEBMAIL-SSL"}, {2100, "ORACLE-XDB"}, {2222, "DIRECTADMIN"}, {2483, "ORACLE"}, {2484, "ORACLE-SSL"},
        {2601, "ZEBRA"}, {2604, "ZEBRA"}, {2638, "SYBASE"}, {2809, "CORBALOC"}, {2947, "GPSD"},
        {2967, "SYMANTEC"}, {3000, "PEERCAST"}, {3128, "SQUID"}, {3130, "ICPV2"}, {3306, "MYSQL"},
        {3389, "RDP"}, {3396, "PRINTER"}, {3689, "ITUNES"}, {3690, "SVN"}, {4662, "EMULE"},
        {5000, "UPnP"}, {5001, "COMMPLEX"}, {5004, "RTP"}, {5005, "RTCP"}, {5060, "SIP"},
        {5061, "SIP-TLS"}, {5190, "AOL"}, {5222, "XMPP"}, {5223, "XMPP-SSL"}, {5228, "ANDROID"},
        {5280, "XMPP-WEB"}, {5432, "POSTGRESQL"}, {5554, "SGI"}, {5631, "PCANY"}, {5632, "PCANY"},
        {5800, "VNC"}, {5900, "VNC"}, {5938, "TEAMVIEWER"}, {6000, "X11"}, {6001, "X11-1"},
        {6346, "GNUTELLA"}, {6347, "GNUTELLA"}, {6660, "IRC"}, {6661, "IRC"}, {6662, "IRC"},
        {6663, "IRC"}, {6664, "IRC"}, {6665, "IRC"}, {6666, "IRC"}, {6667, "IRC"},
        {6668, "IRC"}, {6669, "IRC"}, {6697, "IRC-SSL"}, {7000, "WEBLOGIC"}, {7001, "WEBLOGIC"},
        {7002, "WEBLOGIC"}, {7070, "RTSP"}, {7777, "CBTLS"}, {8000, "HTTP-ALT"}, {8001, "HTTP-ALT"},
        {8002, "HTTP-ALT"}, {8008, "HTTP-ALT"}, {8009, "AJPV13"}, {8010, "XMPP"}, {8080, "HTTP-PROXY"},
        {8081, "HTTP-ALT"}, {8082, "HTTP-ALT"}, {8083, "HTTP-ALT"}, {8084, "HTTP-ALT"}, {8085, "HTTP-ALT"},
        {8086, "HTTP-ALT"}, {8087, "HTTP-ALT"}, {8088, "HTTP-ALT"}, {8089, "HTTP-ALT"}, {8090, "HTTP-ALT"},
        {8118, "PRIVOXY"}, {8123, "POLIPO"}, {8443, "HTTPS-ALT"}, {8888, "HTTP-ALT"}, {9000, "CSLISTENER"},
        {9001, "TOR-ORPORT"}, {9090, "WEBSM"}, {9091, "XMLTEC"}, {9102, "JETDIRECT"}, {9999, "ABYSS"}
    };

            var openPorts = new ConcurrentBag<Tuple<int, string, string>>();
            int portProgress = 0;

            // Using Parallel for faster scanning with throttling
            ParallelOptions parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = 20,
                CancellationToken = ct
            };

            try
            {
                Parallel.ForEach(commonPorts, parallelOptions, port =>
                {
                    if (ct.IsCancellationRequested) return;

                    string serviceName = portServices.ContainsKey(port) ? portServices[port] : "Unknown";
                    string banner = "";

                    try
                    {
                        using (TcpClient client = new TcpClient())
                        {
                            var connectTask = client.ConnectAsync(ip, port);
                            if (Task.WaitAny(new Task[] { connectTask }, 800) == 0 && client.Connected)
                            {
                                try
                                {
                                    banner = GrabBanner(client, port);
                                    openPorts.Add(new Tuple<int, string, string>(port, serviceName, banner));
                                }
                                catch (Exception ex)
                                {
                                    // Connection successful but couldn't grab banner
                                    openPorts.Add(new Tuple<int, string, string>(port, serviceName, "[Open]"));
                                }
                            }
                        }
                    }
                    catch { }

                    // Update progress
                    Interlocked.Increment(ref portProgress);
                    int progressValue = 10 + (int)(portProgress * 20.0 / commonPorts.Length);
                    UpdateProgress(progressValue);
                });

                // Sort and display results
                var sortedPorts = openPorts.OrderBy(x => x.Item1).ToList();

                Log($"\n🔍 Found {sortedPorts.Count} open ports from common port list:");
                foreach (var portInfo in sortedPorts)
                {
                    string displayBanner = portInfo.Item3.Length > 50 ?
                        portInfo.Item3.Substring(0, 47) + "..." : portInfo.Item3;

                    Log($"✅ Port {portInfo.Item1,5} ({portInfo.Item2,-12}) - {displayBanner}");
                }
            }
            catch (OperationCanceledException) { return; }
            catch (Exception ex) { Log($"❌ Banner grabbing error: {ex.Message}"); }

            UpdateProgress(30);

            // Step 3: FULL PORT SCAN (1-65535)
            Log("\n=== STEP 3: FULL PORT SCAN (1-65535) ===");

            int totalPorts = 65535;
            int scanBatchSize = 4096;
            int openPortsCount = 0;
            int completedRanges = 0;

            try
            {
                for (int startPort = 1; startPort <= totalPorts; startPort += scanBatchSize)
                {
                    if (ct.IsCancellationRequested) return;

                    int endPort = Math.Min(startPort + scanBatchSize - 1, totalPorts);
                    Log($"⏳ Scanning ports {startPort}-{endPort}...");

                    var currentOpenPorts = new ConcurrentBag<int>();

                    Parallel.For(startPort, endPort + 1, parallelOptions, port =>
                    {
                        if (ct.IsCancellationRequested) return;

                        try
                        {
                            using (var client = new TcpClient())
                            {
                                var result = client.BeginConnect(ip, port, null, null);
                                if (result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(2)))
                                {
                                    if (client.Connected)
                                    {
                                        currentOpenPorts.Add(port);
                                        client.Close();
                                    }
                                }
                            }
                        }
                        catch { }
                    });

                    // Sort and display results for this batch
                    var sortedCurrentPorts = currentOpenPorts.OrderBy(p => p).ToList();
                    foreach (int port in sortedCurrentPorts)
                    {
                        string service = portServices.ContainsKey(port) ? portServices[port] : "Unknown";
                        Log($"✅ Port {port,5} open ({service})");
                    }

                    openPortsCount += sortedCurrentPorts.Count;
                    completedRanges++;

                    // Update progress (30% for common ports + 70% for full scan)
                    int progressValue = 30 + (int)(completedRanges * 70.0 / Math.Ceiling((double)totalPorts / scanBatchSize));
                    UpdateProgress(progressValue);
                }

                Log($"\n🧾 [SCAN SUMMARY]");
                Log($"📊 Total Open Ports Found: {openPortsCount}");
                Log($"🕒 Scan Completed: {DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")}");
                Log($"📍 Target: {ip}");
            }
            catch (OperationCanceledException) { return; }
            catch (Exception ex) { Log($"❌ Port scanning error: {ex.Message}"); }

            UpdateProgress(100);
        }

        // Helper method to grab service banners with protocol-specific requests
        private string GrabBanner(TcpClient client, int port)
        {
            using (NetworkStream stream = client.GetStream())
            {
                stream.ReadTimeout = 1000;

                byte[] buffer = new byte[2048];
                byte[] requestData = null;

                // Protocol-specific banner grabbing
                switch (port)
                {
                    case 21: // FTP
                        requestData = Encoding.ASCII.GetBytes("HELP\r\n");
                        break;
                    case 22: // SSH
                             // SSH servers send banner automatically - just read
                        break;
                    case 23: // TELNET
                        requestData = new byte[] { 0xFF, 0xFB, 0x01 }; // IAC WILL ECHO
                        break;
                    case 25: // SMTP
                        requestData = Encoding.ASCII.GetBytes("EHLO scan.local\r\n");
                        break;
                    case 80: // HTTP
                    case 443: // HTTPS
                    case 8080: // HTTP-Proxy
                    case 8443: // HTTPS-Alt
                        requestData = Encoding.ASCII.GetBytes("HEAD / HTTP/1.1\r\nHost: " + client.Client.RemoteEndPoint.ToString().Split(':')[0] + "\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n");
                        break;
                    case 110: // POP3
                              // POP3 servers send banner automatically - just read
                        break;
                    case 143: // IMAP
                              // IMAP servers send banner automatically - just read
                        break;
                    case 3306: // MySQL
                               // MySQL sends banner automatically - just read
                        break;
                    default:
                        requestData = Encoding.ASCII.GetBytes("\r\n");
                        break;
                }

                // Send request if needed
                if (requestData != null)
                {
                    stream.Write(requestData, 0, requestData.Length);
                }

                // Try to read response
                int bytes;
                try
                {
                    stream.ReadTimeout = 1000;
                    bytes = stream.Read(buffer, 0, buffer.Length);

                    if (bytes > 0)
                    {
                        string response = Encoding.ASCII.GetString(buffer, 0, bytes);
                        // Clean up response for display
                        return CleanBannerResponse(response);
                    }
                }
                catch
                {
                    return "[No Banner]";
                }

                return "[No Response]";
            }
        }

        // Clean banner response for display
        private string CleanBannerResponse(string response)
        {
            if (string.IsNullOrEmpty(response))
                return "[Empty Response]";

            // Remove control characters and limit length
            var cleanedResponse = new StringBuilder();
            foreach (char c in response)
            {
                if (c >= 32 && c <= 126 || c == '\r' || c == '\n')
                    cleanedResponse.Append(c);
                else
                    cleanedResponse.Append('.');
            }

            string result = cleanedResponse.ToString()
                .Replace("\r\n", " ")
                .Replace("\n", " ")
                .Trim();

            return string.IsNullOrEmpty(result) ? "[Non-Printable Response]" : result;
        }

        // Get MAC address for IP on local network
        private string GetMacAddress(string ipAddress)
        {
            try
            {
                IPAddress ip = IPAddress.Parse(ipAddress);

                // Check if this is on local network
                if (IsLocalNetwork(ip))
                {
                    Process process = new Process();
                    process.StartInfo.FileName = "arp";
                    process.StartInfo.Arguments = "-a " + ipAddress;
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;

                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    string[] lines = output.Split('\n');
                    foreach (string line in lines)
                    {
                        if (line.Contains(ipAddress))
                        {
                            string pattern = @"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})";
                            Match match = Regex.Match(line, pattern);
                            if (match.Success)
                            {
                                return match.Value.ToUpper();
                            }
                        }
                    }
                }
            }
            catch { /* Ignore errors */ }

            return string.Empty;
        }

        // Check if IP is on local network
        private bool IsLocalNetwork(IPAddress ip)
        {
            try
            {
                // Get all network interfaces
                NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

                foreach (NetworkInterface networkInterface in networkInterfaces)
                {
                    if (networkInterface.OperationalStatus == OperationalStatus.Up)
                    {
                        foreach (UnicastIPAddressInformation ipInfo in networkInterface.GetIPProperties().UnicastAddresses)
                        {
                            if (ipInfo.Address.AddressFamily == AddressFamily.InterNetwork)
                            {
                                // Calculate the network address using the IP and subnet mask
                                byte[] ipBytes = ip.GetAddressBytes();
                                byte[] maskBytes = ipInfo.IPv4Mask.GetAddressBytes();
                                byte[] networkBytes = new byte[4];

                                for (int i = 0; i < 4; i++)
                                {
                                    networkBytes[i] = (byte)(ipBytes[i] & maskBytes[i]);
                                }

                                byte[] interfaceBytes = new byte[4];
                                byte[] interfaceIpBytes = ipInfo.Address.GetAddressBytes();

                                for (int i = 0; i < 4; i++)
                                {
                                    interfaceBytes[i] = (byte)(interfaceIpBytes[i] & maskBytes[i]);
                                }

                                if (networkBytes.SequenceEqual(interfaceBytes))
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            catch { /* Ignore errors */ }

            return false;
        }


        private string GetVendorFromMac(string macAddress)
        {
            try
            {
                // Common vendor prefixes (first 6 characters of MAC)
                Dictionary<string, string> vendorPrefixes = new Dictionary<string, string>
                {
                    { "00:0C:29", "VMware" },
                    { "00:50:56", "VMware" },
                    { "00:1A:11", "Google" },
                    { "00:03:93", "Apple" },
                    { "00:05:02", "Apple" },
                    { "00:0A:27", "Apple" },
                    { "00:0A:95", "Apple" },
                    { "00:0D:93", "Apple" },
                    { "00:11:24", "Apple" },
                    { "00:14:51", "Apple" },
                    { "00:16:CB", "Apple" },
                    { "00:17:F2", "Apple" },
                    { "00:19:E3", "Apple" },
                    { "00:1B:63", "Apple" },
                    { "00:1C:B3", "Apple" },
                    { "00:1D:4F", "Apple" },
                    { "00:1E:52", "Apple" },
                    { "00:1E:C2", "Apple" },
                    { "00:1F:5B", "Apple" },
                    { "00:1F:F3", "Apple" },
                    { "00:21:E9", "Apple" },
                    { "00:22:41", "Apple" },
                    { "00:23:12", "Apple" },
                    { "00:23:32", "Apple" },
                    { "00:23:6C", "Apple" },
                    { "00:23:DF", "Apple" },
                    { "00:24:36", "Apple" },
                    { "00:25:00", "Apple" },
                    { "00:25:BC", "Apple" },
                    { "00:26:4A", "Apple" },
                    { "00:26:B0", "Apple" },
                    { "00:26:BB", "Apple" },
                    { "00:30:65", "Apple" },
                    { "00:3E:E1", "Apple" },
                    { "00:0A:00", "Mediatek" },
                    { "00:1C:23", "Dell" },
                    { "00:21:9B", "Dell" },
                    { "00:21:70", "Dell" },
                    { "00:1E:4F", "Dell" },
                    { "00:12:3F", "Dell" },
                    { "00:23:AE", "Dell" },
                    { "00:13:72", "Dell" },
                    { "00:11:43", "Dell" },
                    { "00:01:44", "Dell" },
                    { "D4:BE:D9", "Dell" },
                    { "F8:DB:88", "Dell" },
                    { "00:14:22", "Dell" },
                    { "BC:30:5B", "Dell" },
                    { "74:46:A0", "HP" },
                    { "00:1B:78", "HP" },
                    { "00:1C:C4", "HP" },
                    { "00:1F:FE", "HP" },
                    { "00:21:5A", "HP" },
                    { "00:23:7D", "HP" },
                    { "00:24:81", "HP" },
                    { "00:25:B3", "HP" },
                    { "00:26:55", "HP" },
                    { "00:0E:7F", "HP" },
                    { "00:10:83", "HP" },
                    { "00:13:21", "HP" },
                    { "00:17:A4", "HP" },
                    { "00:18:FE", "HP" },
                    { "00:1A:4B", "HP" },
                    { "00:1B:78", "HP" },
                    { "00:1C:C4", "HP" },
                    { "00:1E:0B", "HP" },
                    { "00:00:0C", "Cisco" },
                    { "00:01:42", "Cisco" },
                    { "00:01:63", "Cisco" },
                    { "00:01:64", "Cisco" },
                    { "00:01:96", "Cisco" },
                    { "00:01:97", "Cisco" },
                    { "00:01:C7", "Cisco" },
                    { "00:01:C9", "Cisco" },
                    { "00:01:AD", "Cisco" },
                    { "00:02:4A", "Cisco" },
                    { "00:02:4B", "Cisco" },
                    { "00:02:7D", "Cisco" },
                    { "00:02:B9", "Cisco" },
                    { "00:03:9F", "Cisco" },
                    { "00:03:E3", "Cisco" },
                    { "00:04:9A", "Cisco" },
                    { "00:04:DD", "Cisco" },
                    { "00:05:9A", "Cisco" },
                    { "00:05:DC", "Cisco" },
                    { "00:06:C1", "Cisco" },
                    { "00:07:0E", "Cisco" },
                    { "00:07:4F", "Cisco" },
                    { "00:07:EB", "Cisco" },
                    { "00:08:7C", "Cisco" },
                    { "00:09:43", "Cisco" },
                    { "00:0A:8A", "Cisco" },
                    { "00:0A:B7", "Cisco" },
                    { "00:0B:5F", "Cisco" },
                    { "00:0B:BE", "Cisco" },
                    { "00:0C:85", "Cisco" },
                    { "00:0D:65", "Cisco" },
                    { "00:0E:38", "Cisco" },
                    { "00:0E:D7", "Cisco" },
                    { "00:0F:23", "Cisco" },
                    { "00:0F:8F", "Cisco" },
                    { "00:10:FF", "Cisco" },
                    { "00:11:20", "Cisco" },
                    { "00:11:BB", "Cisco" },
                    { "00:12:43", "Cisco" },
                    { "00:12:7F", "Cisco" },
                    { "00:13:10", "Cisco" },
                    { "00:13:7F", "Cisco" },
                    { "00:14:69", "Cisco" },
                    { "AC:CC:8E", "Axis" },
                    { "B8:27:EB", "Raspberry Pi" }

                };
                string normalizedMac = macAddress.ToUpperInvariant().Replace("-", ":");
                string oui = normalizedMac.Length >= 8 ? normalizedMac.Substring(0, 8) : normalizedMac;

                // Find vendor by prefix
                foreach (var prefix in vendorPrefixes.Keys)
                {
                    if (oui.StartsWith(prefix))
                    {
                        return vendorPrefixes[prefix];
                    }
                }

                // If not found in our local dictionary, try to fetch online
                try
                {
                    using (var client = new HttpClient())
                    {
                        client.Timeout = TimeSpan.FromSeconds(2);
                        // Note: This API URL is fictional as most MAC lookup APIs require registration
                        // In a real implementation, you would use a registered API service
                        var response = client.GetStringAsync($"https://api.macvendors.com/{normalizedMac.Replace(":", "")}").Result;
                        if (!string.IsNullOrEmpty(response))
                        {
                            return response.Trim();
                        }
                    }
                }
                catch { /* Ignore online lookup errors */ }

                return "Unknown Vendor";
            }
            catch (Exception)
            {
                return "Unknown Vendor";
            }
        }


        private async Task PerformHealthCheck(string ip, CancellationToken ct)
        {
            // Define a better logging method with color support
            void Log(string msg, Color? color = null)
            {
                richTextBox1.Invoke(() =>
                {
                    int start = richTextBox1.TextLength;
                    richTextBox1.AppendText(msg + Environment.NewLine);
                    int end = richTextBox1.TextLength;

                    if (color.HasValue)
                    {
                        richTextBox1.SelectionStart = start;
                        richTextBox1.SelectionLength = end - start;
                        richTextBox1.SelectionColor = color.Value;
                        richTextBox1.SelectionLength = 0;
                    }
                });
            }

            void UpdateProgress(int value) => progressBar1.Invoke(() => progressBar1.Value = value);

            // Clear previous results
            richTextBox1.Invoke(() => richTextBox1.Clear());

            try
            {
                // Begin scan with stylish header
                Log($"╔══════════════════════════════════════════════════════════╗", Color.DodgerBlue);
                Log($"║       NETWORK HEALTH SCAN - {DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")}  ║", Color.DodgerBlue);
                Log($"╚══════════════════════════════════════════════════════════╝", Color.DodgerBlue);
                Log("");
                Log($"🔬 Starting comprehensive health check on: {ip}", Color.Black);

                // Variables for tracking network health
                int score = 100;
                int openPorts = 0;
                int uncommonPorts = 0;
                int legacyPorts = 0;
                int secureServiceCount = 0;
                int vulnerableServiceCount = 0;
                bool hasFirewall = true;
                int pingTime = 0;

                // Define ports categorization
                Dictionary<int, string> commonPortDescriptions = new Dictionary<int, string>
        {
            { 21, "FTP" },
            { 22, "SSH" },
            { 23, "Telnet" },
            { 25, "SMTP" },
            { 53, "DNS" },
            { 80, "HTTP" },
            { 110, "POP3" },
            { 143, "IMAP" },
            { 443, "HTTPS" },
            { 445, "SMB" },
            { 3306, "MySQL" },
            { 3389, "RDP" },
            { 8080, "HTTP Alt" }
        };

                // Define secure and insecure services
                int[] secureServices = { 22, 443, 993, 995 };
                int[] vulnerableServices = { 21, 23, 110, 139, 445, 3389 };

                // Lists to store scan results
                List<int> discoveredOpenPorts = new List<int>();
                List<string> scanResults = new List<string>();

                // Start with ping test
                UpdateProgress(5);
                Log("🌐 Testing connectivity...", Color.Brown);

                using (Ping ping = new Ping())
                {
                    try
                    {
                        PingReply reply = await ping.SendPingAsync(ip, 3000);
                        if (reply.Status == IPStatus.Success)
                        {
                            pingTime = (int)reply.RoundtripTime;
                            Log($"📶 Ping response: {reply.RoundtripTime}ms",
                                reply.RoundtripTime < 50 ? Color.LightGreen :
                                reply.RoundtripTime < 150 ? Color.Brown : Color.Orange);

                            // Adjust score based on ping response
                            if (reply.RoundtripTime > 200) score -= 5;
                            if (reply.RoundtripTime > 500) score -= 10;
                        }
                        else
                        {
                            Log($"⚠️ Ping failed: {reply.Status}", Color.Red);
                            score -= 15;
                            hasFirewall = true; // Likely blocked by firewall
                        }
                    }
                    catch
                    {
                        Log("⚠️ Ping test failed - host may be down or blocking ICMP", Color.Red);
                        score -= 15;
                    }
                }

                // DNS resolution test
                UpdateProgress(15);
                try
                {
                    var dnsResult = await Dns.GetHostEntryAsync(ip);
                    Log($"🌐 DNS Resolved: {dnsResult.HostName}", Color.LightGreen);
                    scanResults.Add($"Hostname: {dnsResult.HostName}");
                }
                catch
                {
                    Log("❌ DNS Resolution Failed - Hostname not found", Color.Red);
                    score -= 10;
                    scanResults.Add("DNS: Unresolvable");
                }

                // Trace route test (simplified)
                UpdateProgress(25);
                Log("🔄 Checking route to target...", Color.Brown);
                int hopCount = await SimulateTraceRoute(ip, ct);
                if (hopCount > 0)
                {
                    Log($"🛣️ Route hops: {hopCount}", hopCount < 10 ? Color.DarkGreen : Color.Brown);
                    scanResults.Add($"Network distance: {hopCount} hops");
                }
                else
                {
                    Log("❌ Unable to trace route to target", Color.Red);
                }

                // Begin port scanning
                UpdateProgress(30);
                Log("🔎 Scanning common network services...", Color.Brown);

                // First scan common ports (faster check)
                foreach (var portEntry in commonPortDescriptions)
                {
                    if (ct.IsCancellationRequested) return;

                    int port = portEntry.Key;
                    string serviceName = portEntry.Value;

                    bool isOpen = await IsPortOpen(ip, port, 500);
                    if (isOpen)
                    {
                        openPorts++;
                        discoveredOpenPorts.Add(port);

                        Color serviceColor = Color.DarkGreen;
                        string securityStatus = "";

                        if (vulnerableServices.Contains(port))
                        {
                            vulnerableServiceCount++;
                            securityStatus = " ⚠️";
                            serviceColor = Color.Orange;
                            score -= 7; // Penalty for each vulnerable service
                        }
                        else if (secureServices.Contains(port))
                        {
                            secureServiceCount++;
                            securityStatus = " 🔒";
                        }

                        Log($"  ▶ {port}/TCP ({serviceName}) - OPEN{securityStatus}", serviceColor);
                    }
                }

                // Now scan a wider range of ports if time permits (with faster timeout)
                UpdateProgress(50);
                Log("🔍 Probing for additional services...", Color.Black);

                // Scan range more efficiently with fewer common ranges
                int[] portRanges = {
            1, 20,     // Early system ports
            1024, 1124, // Registered ports beginning
            3000, 3100, // Common development services
            5000, 5100, // Common development services
            8000, 8100  // Common HTTP alternatives
        };

                for (int i = 0; i < portRanges.Length; i += 2)
                {
                    for (int port = portRanges[i]; port <= portRanges[i + 1]; port++)
                    {
                        if (ct.IsCancellationRequested) return;
                        if (commonPortDescriptions.ContainsKey(port)) continue; // Already checked

                        bool isOpen = await IsPortOpen(ip, port, 200); // Faster timeout for broader scan
                        if (isOpen)
                        {
                            openPorts++;
                            uncommonPorts++;
                            discoveredOpenPorts.Add(port);
                            Log($"  ▶ {port}/TCP - OPEN (Uncommon)", Color.Black);
                        }
                    }
                    UpdateProgress(50 + (i * 20 / portRanges.Length));
                }

                // Calculate if host likely has firewall
                hasFirewall = (openPorts < 5 && pingTime > 0);

                // Analyze results and update score
                if (openPorts > 15) score -= 15;
                if (uncommonPorts > 5) score -= 10;
                if (vulnerableServiceCount > 2) score -= 15;
                if (secureServiceCount > 0) score += 5;
                if (hasFirewall) score += 10;

                // Ensure score stays in valid range
                score = Math.Max(0, Math.Min(100, score));

                string category = "UNKNOWN";
                Color ratingColor = Color.Gray;

                if (score >= 90) { category = "EXCELLENT"; ratingColor = Color.LightGreen; }
                else if (score >= 80) { category = "STRONG"; ratingColor = Color.Green; }
                else if (score >= 70) { category = "GOOD"; ratingColor = Color.Blue; }
                else if (score >= 60) { category = "MODERATE"; ratingColor = Color.Blue; }
                else if (score >= 40) { category = "WEAK"; ratingColor = Color.Orange; }
                else { category = "VULNERABLE"; ratingColor = Color.Red; }

                // Create summary of security findings
                UpdateProgress(95);

                Log("", Color.White);
                Log("╔══════════════════════════════════════════════════════════╗", Color.LightBlue);
                Log("║                   NETWORK HEALTH SUMMARY                 ║", Color.LightBlue);
                Log("╚══════════════════════════════════════════════════════════╝", Color.LightBlue);
                Log("", Color.White);
                Log($"📊 Total Open Ports: {openPorts}",
                    openPorts > 10 ? Color.Red : openPorts > 5 ? Color.Black : Color.LightGreen);
                Log($"⚠️ Uncommon Services: {uncommonPorts}",
                    uncommonPorts > 3 ? Color.Red : uncommonPorts > 0 ? Color.Black : Color.LightGreen);
                Log($"🧯 Vulnerable Services: {vulnerableServiceCount}",
                    vulnerableServiceCount > 0 ? Color.Red : Color.LightGreen);
                Log($"🔒 Secure Services: {secureServiceCount}",
                    secureServiceCount > 0 ? Color.LightGreen : Color.Black);
                Log($"🔥 Firewall Detected: {(hasFirewall ? "Likely" : "Unlikely")}",
                    hasFirewall ? Color.LightGreen : Color.Black);
                Log("", Color.Brown);

                // Display security rating with visual bar
                Log("╔══════════════════════════════════════════════════════════╗", ratingColor);
                Log($"║  SECURITY RATING: {category} - {score}/100", ratingColor);

                // Create a visual meter
                StringBuilder meter = new StringBuilder("║  [");
                int filledBlocks = (int)Math.Round(score / 5.0);

                for (int i = 0; i < 20; i++)
                {
                    if (i < filledBlocks)
                        meter.Append("█");
                    else
                        meter.Append("░");
                }
                meter.Append("]");
                Log(meter.ToString(), ratingColor);
                Log("╚══════════════════════════════════════════════════════════╝", ratingColor);

                // Add recommendations based on findings
                if (score < 80)
                {
                    Log("", Color.White);
                    Log("🛡️ SECURITY RECOMMENDATIONS:", Color.Orange);

                    if (vulnerableServiceCount > 0)
                        Log("  • Consider disabling or securing vulnerable services like FTP, Telnet, or unencrypted protocols", Color.Orange);

                    if (openPorts > 10)
                        Log("  • Reduce attack surface by closing unnecessary open ports", Color.Orange);

                    if (uncommonPorts > 3)
                        Log("  • Investigate uncommon open ports - they may indicate unauthorized services", Color.Orange);

                    if (!hasFirewall)
                        Log("  • Implement proper firewall rules to restrict access to essential services only", Color.Orange);
                }

                UpdateProgress(100);
            }
            catch (Exception ex)
            {
                Log($"❌ Error during health check: {ex.Message}", Color.Red);
            }
        }

        // Helper method to check if a port is open
        private async Task<bool> IsPortOpen(string host, int port, int timeoutMs)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var connectTask = client.ConnectAsync(host, port);
                    var timeoutTask = Task.Delay(timeoutMs);

                    var completedTask = await Task.WhenAny(connectTask, timeoutTask);
                    return completedTask == connectTask && client.Connected;
                }
            }
            catch
            {
                return false;
            }
        }

        // Helper method to simulate traceroute
        private async Task<int> SimulateTraceRoute(string host, CancellationToken ct)
        {
            int maxHops = 15;
            for (int ttl = 1; ttl <= maxHops; ttl++)
            {
                if (ct.IsCancellationRequested) return 0;

                using (Ping pinger = new Ping())
                {
                    PingOptions options = new PingOptions(ttl, true);
                    byte[] buffer = new byte[32];

                    try
                    {
                        PingReply reply = await pinger.SendPingAsync(host, 1000, buffer, options);

                        if (reply.Status == IPStatus.Success)
                        {
                            return ttl; // Reached destination
                        }
                        else if (reply.Status == IPStatus.TimedOut)
                        {
                            // Continue to next hop
                            continue;
                        }
                    }
                    catch
                    {
                        // Continue even if there's an error
                    }
                }
            }

            return 0; // Could not determine route
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (scanCancellationTokenSource != null && !scanCancellationTokenSource.IsCancellationRequested)
            {
                scanCancellationTokenSource.Cancel();
                richTextBox1.AppendText("\n❌ Scan cancelled by user.\n");
            }
        }

        private List<string> ParseIPRange(string input)
        {
            var result = new List<string>();
            if (IPAddress.TryParse(input, out _)) result.Add(input);
            else if (input.Contains('-'))
            {
                try
                {
                    var parts = input.Split('-');
                    IPAddress startIP = IPAddress.Parse(parts[0]);
                    IPAddress endIP = IPAddress.Parse(parts[1]);
                    uint start = BitConverter.ToUInt32(startIP.GetAddressBytes().Reverse().ToArray(), 0);
                    uint end = BitConverter.ToUInt32(endIP.GetAddressBytes().Reverse().ToArray(), 0);

                    for (uint i = start; i <= end; i++)
                    {
                        byte[] bytes = BitConverter.GetBytes(i).Reverse().ToArray();
                        result.Add(new IPAddress(bytes).ToString());
                    }
                }
                catch { }
            }
            return result;
        }

        private bool IsValidIPRange(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return false;
            if (IPAddress.TryParse(input, out IPAddress single)) return IsValidIPv4(single.ToString());

            if (input.Contains('-'))
            {
                var parts = input.Split('-');
                if (parts.Length != 2) return false;
                if (!IPAddress.TryParse(parts[0], out IPAddress start) ||
                    !IPAddress.TryParse(parts[1], out IPAddress end))
                    return false;

                uint s = BitConverter.ToUInt32(start.GetAddressBytes().Reverse().ToArray(), 0);
                uint e = BitConverter.ToUInt32(end.GetAddressBytes().Reverse().ToArray(), 0);
                return s <= e;
            }

            return false;
        }

        private bool IsValidIPv4(string ip)
        {
            if (IPAddress.TryParse(ip, out IPAddress address))
            {
                var bytes = address.GetAddressBytes();
                return bytes.Length == 4 && bytes[0] >= 1 && bytes[0] <= 254;
            }
            return false;
        }

        private bool IsAnyCheckboxChecked() =>
            checkBox1.Checked || checkBox2.Checked || checkBox3.Checked || checkBox4.Checked || checkBox5.Checked || checkBox6.Checked || checkBox7.Checked || checkBox8.Checked;

        private void textBox1_TextChanged(object sender, EventArgs e) =>
            button1.Enabled = IsValidIPRange(textBox1.Text.Trim()) && IsAnyCheckboxChecked();

        private void checkBox1_CheckedChanged(object sender, EventArgs e) => button1.Enabled = IsValidIPRange(textBox1.Text.Trim()) && IsAnyCheckboxChecked();


        private void checkBox2_CheckedChanged(object sender, EventArgs e) => button1.Enabled = IsValidIPRange(textBox1.Text.Trim()) && IsAnyCheckboxChecked();


        // Unused handlers
        private void Form1_Load(object sender, EventArgs e) { }
        private void richTextBox1_TextChanged(object sender, EventArgs e) { }
        private void progressBar1_Click(object sender, EventArgs e) { }
        private void saveFileDialog1_FileOk(object sender, System.ComponentModel.CancelEventArgs e) { }
        private void linkLabel1_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {


            System.Diagnostics.Process.Start(new ProcessStartInfo
            {
                FileName = "https://github.com/TENETx0/NetworkScanner/wiki",
                UseShellExecute = true
            });

        }
        private async void checkBox3_CheckedChanged(object sender, EventArgs e) => button1.Enabled = IsValidIPRange(textBox1.Text.Trim()) && IsAnyCheckboxChecked();

        private void checkBox4_CheckedChanged(object sender, EventArgs e) => button1.Enabled = IsValidIPRange(textBox1.Text.Trim()) && IsAnyCheckboxChecked();

        private void checkBox5_CheckedChanged(object sender, EventArgs e) =>
             button1.Enabled = IsValidIPRange(textBox1.Text.Trim()) && IsAnyCheckboxChecked();

        private void checkBox6_CheckedChanged(object sender, EventArgs e) => button1.Enabled = IsValidIPRange(textBox1.Text.Trim()) && IsAnyCheckboxChecked();
        private void checkBox7_CheckedChanged(object sender, EventArgs e) => button1.Enabled = IsValidIPRange(textBox1.Text.Trim()) && IsAnyCheckboxChecked();
        private void checkBox8_CheckedChanged(object sender, EventArgs e) =>
             button1.Enabled = IsValidIPRange(textBox1.Text.Trim()) && IsAnyCheckboxChecked();
        private void process1_Exited(object sender, EventArgs e) { }

        private void button3_Click(object sender, EventArgs e)
        {
            richTextBox1.Clear();
            progressBar1.Value = 0;

            checkBox1.Checked = false;
            checkBox2.Checked = false;
            checkBox3.Checked = false;
            checkBox4.Checked = false;
            checkBox5.Checked = false;
            checkBox6.Checked = false;
            checkBox7.Checked = false;
            checkBox8.Checked = false;

            textBox1.Clear();
            button1.Enabled = false;
        }

        private void button4_Click(object sender, EventArgs e)
        {
            SaveFileDialog saveDialog = new SaveFileDialog
            {
                Filter = "HTML Files (*.html)|*.html",
                Title = "Save Report as HTML",
                FileName = $"NetworkScanReport_{DateTime.Now:yyyyMMdd_HHmmss}.html"
            };

            if (saveDialog.ShowDialog() == DialogResult.OK)
            {
                try
                {
                    string encodedText = WebUtility.HtmlEncode(richTextBox1.Text);

                    string html = $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='UTF-8'>
    <title>Network Scan Report</title>
    <style>
        body {{
            font-family: Consolas, monospace;
            background-color: #121212;
            color: #e0e0e0;
            padding: 20px;
        }}
        h1 {{
            color: #00e676;
            border-bottom: 2px solid #00e676;
            padding-bottom: 10px;
        }}
        .metadata {{
            font-size: 14px;
            color: #b0bec5;
        }}
        pre {{
            background-color: #1e1e1e;
            color: #cfd8dc;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            white-space: pre-wrap;
        }}
        .footer {{
            margin-top: 30px;
            font-size: 12px;
            color: #777;
        }}
    </style>
</head>
<body>
    <h1>🔎 Network Scanner Report</h1>
    <div class='metadata'><b>Generated:</b> {DateTime.Now:F}</div>
    <div class='metadata'><b>Host Machine:</b> {Environment.MachineName} ({Environment.UserName})</div>
    <br />
    <pre>{encodedText}</pre>
    <div class='footer'>Report generated by Tenetx01 Advanced Network Scanner</div>
</body>
</html>";

                    File.WriteAllText(saveDialog.FileName, html, Encoding.UTF8);
                    MessageBox.Show("✅ Stylish HTML report saved successfully!", "Export", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"❌ Failed to save report: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }
    }
}