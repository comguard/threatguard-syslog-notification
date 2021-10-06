Script načíta XML súbor z ThreatGuard zo zadaného odkazu.
Odkaz sa získa cez aplikáciu ThreatGuard -> "Názov účtu" -> Česky -> skopírovať URL
Script sa spustí z príkazového riadku s týmito parametrami:
./TG-notification-4 -u <URL-TG> -s <IP/DN SIEM serveru> -p <port>

Script sa nachádza v stave vývoja, na jeho spustenie je nutné mať nainštalovaný Python 3.6, alebo novší.
Pri UNIX systémoch je nutné pri spustení zadať cestu k Python balíku