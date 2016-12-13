# e-mail notofication of massive access from outer network to honeypots
#
# following variables are exported:
# $hostname - ip address and hostname (if known) of attacker
# $timestamp - time when the attack started
# $scale - number of host accesed by attacker (honeypots and other hosts in local network)

$subject = "Objectionable traffic from $hostname";

$message = 
"Greetings,

we would like to notify you that $hostname
has been classified as a security threat for <name of your network> (<your IP range>).

The IP accessed our honeypots and many other hosts in the production network.
This might suggest that the IP performed network scanning attack.

Start time:      $timestamp
Hosts accessed:  $scale


Regards,

<your signature>
";
