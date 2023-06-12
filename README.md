# AzTokenHunter
Hunts for Azure tokens inside of process memory. Written in C# for use in C2. A fork of SharpDump. Based on the information from the following blog post:

https://mrd0x.com/stealing-tokens-from-office-applications/

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
