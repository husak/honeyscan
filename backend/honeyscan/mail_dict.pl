# e-mail notofication of massive access from outer network to honeypots
#
# following variables are exported:
# $hostname - ip address and hostname (if known) of attacker
# $timestamp - time when the attack started
# $scale - number of host accesed by attacker (honeypots and other hosts in local network)
# $service - authenticated service attacked by cracking passwords (e.g. SSH, FTP...)

$subject = "Objectionable traffic from $hostname";

$message = 
"Greetings,

we would like to notify you that $hostname
has been classified as a security threat for <name of your network> (<your IP range>).

The IP accessed our honeypots and attempted login to some authenticated services.
Similar behaviour was detected towards hosts in the production network.

Start time:      $timestamp
Hosts accessed:  $scale
Service atacked: $service


Regards,

<your signature>
";
