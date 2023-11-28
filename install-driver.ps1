$cleanName = "DolboebDriver"

Write-Host "Stopping & deleting driver"
sc.exe stop $cleanName
sc.exe delete $cleanName

sc.exe create $cleanName type= kernel start= demand error= normal binPath="\\vmware-host\Shared Folders\Debug\x64\Debug\KernalDriver.sys" DisplayName= $cleanName
sc.exe start $cleanName