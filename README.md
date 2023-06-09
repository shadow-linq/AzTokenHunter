# AzTokenHunter
Hunts for Azure tokens inside of process memory.

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
