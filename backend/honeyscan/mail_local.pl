# e-mail notofication of access from local network to honeypot
#
# following variables are exported:
# $hostname - ip address and hostname (if known) of attacker
# $details - list of network flows with honeypot addresses anonymized

$subject = "Objectionable traffic from $hostname";

$message =
"Greetings,

we would like to notify you that $hostname accessed honeypots (network traps) in our network.
It is possible that this machine is compromised, security check of this machine is recommended.


Regards,

<your signature>


Incident details:
------------------
Date flow start          Duration Proto                             Src IP Addr:Port     Dst Pt  Packets    Bytes Flows
$details
";

