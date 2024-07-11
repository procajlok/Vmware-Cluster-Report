

[![Percentage of issues still open](https://isitmaintained.com/badge/open/procajlok/Vmware-Cluster-Report.svg)](https://isitmaintained.com/project/procajlok/Vmware-Cluster-Report "Percentage of issues still open")

[![Average time to resolve an issue](https://isitmaintained.com/badge/resolution/procajlok/Vmware-Cluster-Report.svg)](https://isitmaintained.com/project/procajlok/Vmware-Cluster-Report "Average time to resolve an issue")

[![GitHub stars](https://img.shields.io/github/stars/procajlok/Vmware-Cluster-Report.svg)](https://github.com/procajlok/Vmware-Cluster-Report/stargazers)

[![GitHub forks](https://img.shields.io/github/forks/procajlok/Vmware-Cluster-Report.svg)](https://github.com/procajlok/Vmware-Cluster-Report/network)

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://paypal.me/procajlok)

  

## O skrypcie
Skrypt generuje raport podsumowania infrastruktury związanej ze środowiskiem wirtualizacji Vmware.

  
## Wymagane moduły Powershell
  

- Power.CLI
- ActiveDirectory
- ImportExcell

## Funkcje skryptu
  

 - Generowanie podsumowania DSR
 - Zbieranie informacji o serwerach wirtualizacji

  
## Parametry skryptu

##### Główne

 - `$ScriptVersion  =  "2.0"`
 - `$ScriptMode  =  "ESX"`  - ESX (dla pojedynczego serwera ESX); Cluster (dla klastra vcenter)
 - `$ReportFolderPath  =  "C:\Scripts\ClusterVmwareReport\Reports"`
 - `$ReportFileNamePrefix  =  "VMCL1_PROD"`

##### Ustawienia wysyłki maila

 - `$enablemail  =  "yes"`
 - `$smtpServer  =  ""`
 - `$mailfrom  =  ""`
 - `$mailto  =  ""`
 - `$SMTPUsername  =  ""`
 - `$SMTPPassword  =  ""`

##### Uprawnienia 

 - `$username1  =  ""`
 - `$password1  =  ""`
 - `$username2  =  ""`
 - `$password2  =  ""`

  
#####  Połączenie do vCenter

 - `$vcserver  =  "" `
 - `$username  =  ""`
 - `$password  =  ""`

##### Info
