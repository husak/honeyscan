#!/usr/bin/perl
#
#  honeyscan.pm - honeynet monitoring plugin for NfSen
# 
#  Copyright (C) 2011 Masaryk University
#  Author(s): Martin HUSAK <husakm@ics.muni.cz>
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the documentation
#     and/or other materials provided with the distribution.
#   * Neither the name of Masaryk University nor the names of its contributors may be
#     used to endorse or promote products derived from this software without
#     specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.
#
# 1.0.0
#

# Name of the plugin
package honeyscan;

use strict;

use Switch;
use POSIX;
use Socket;
use DBD::Pg;
use DBI;
use MIME::Lite;
use Geo::IPfree;
use Net::CIDR;
use NfConf;

use Sys::Syslog;
Sys::Syslog::setlogsock ('unix');

our %cmd_lookup = (
  'usingPassDB' => \&usingPassDB,
  'getOverview' => \&getOverview,
  'getDBrecord' => \&getDBrecord,
  'getIPinfo'   => \&getIPinfo,
  'getTrend'    => \&getTrend,
  'getPassword' => \&getPassword,
  'whitelist'   => \&whitelist,
);

# This string identifies the plugin as a version 1.3.0 plugin. 
our $VERSION = 130;

# Global variables - values are set in Init function
my ( $NFDUMP, $PROFILEDIR, $BACKEND_PLUGINDIR, $LOGGER, $USEPASSDB );

#
# Connect to the database using settings in nfsen.conf, returns database handler
#
sub connectToDB
{
  my $dbconf     = $NfConf::PluginConf{honeyscan};
  my $dbname     = $$dbconf{'dbname'};
  my $dbhost     = $$dbconf{'dbhost'};
  my $dbport     = $$dbconf{'dbport'};
  my $dbuser     = $$dbconf{'dbuser'};
  my $dbpasswd   = $$dbconf{'dbpasswd'};
  return my $dbh = DBI->connect("DBI:Pg:dbname=$dbname;host=$dbhost;port=$dbport", $dbuser, $dbpasswd);
} # End of connectToDB

#
# This function tells frontend if password database is used or not
#
sub usingPassDB
{
  my $socket = shift;
  my $opts   = shift;
  my %return;
  $return{"use_pass_db"} = $USEPASSDB;
  Nfcomm::socket_send_ok($socket, \%return);
} # End of usingPassDB

#
# The getOverview is called by frontend plugin. It has to tell frontend the basic info about the database,
# f.e. size od DB, latest changes etc.
#
sub getOverview
{
  # get parameters
  my $socket = shift;
  my $opts   = shift;

  # connect to the database
  my $dbh = &connectToDB;
  if ( !$dbh ) {
    syslog("err", "honeyscan: Connection to the database failed");
    Nfcomm::socket_send_error($socket, "Connection to the database failed");
    return;
  }
  syslog("info", "honeyscan: Connected to the database");

  my %overview; # hash of results for frontend
  $overview{"use_pass_db"} = $USEPASSDB;
  my @row;

  # get size of the database
  my $query = $dbh->prepare("SELECT pg_size_pretty(pg_database_size(current_database()));");
  if ( !defined($dbh) ) {
    syslog("err", "honeyscan: Cannot prepare $DBI::errstr");
    Nfcomm::socket_send_error($socket, "Cannot prepare database query");
    return;
  }
  if ( !$query->execute ) {
    syslog("err", "honeyscan: Cannot execute $DBI::errstr");
    Nfcomm::socket_send_error($socket, "Cannot execute database query");
    return;
  }
  @row = $query->fetchrow;
  $overview{"db_size"} = $row[0];
  # get size of the honeyscan table
  $query = $dbh->prepare("SELECT count(*) FROM honeyscan;");
  $query->execute;
  @row = $query->fetchrow;
  $overview{"table_size"} = $row[0];
  # get most active source IPs
  $query = $dbh->prepare("SELECT srcip,sum(flows) FROM honeyscan
    WHERE timeslot > (current_date - interval '1 week')
    GROUP BY srcip ORDER BY sum(flows) DESC LIMIT 10;");
  $query->execute;
  my $index = 0;
  my $geo = Geo::IPfree->new;
  while ( @row = $query->fetchrow ) {
    my ($code, $country) = $geo->LookUp($row[0]);
    $overview{"srcip_$index"} = $row[0]." ".$code." ".$row[1];
    $index++;
  }
  # get port activity overview
  $query = $dbh->prepare("SELECT proto,dstport,sum(flows) FROM honeyscan
    WHERE timeslot > (current_date - interval '1 week')
    GROUP BY proto,dstport ORDER BY sum(flows) DESC LIMIT 10;");
  $query->execute;
  $index = 0;
  while ( @row = $query->fetchrow ) {
    $overview{"port_$index"} = $row[0]." ".$row[1].";".$row[2];
    $index++;
  }
  # get number of saved passwords
  $query = $dbh->prepare("SELECT count(*) FROM passwords;");
  $query->execute;
  @row = $query->fetchrow;
  $overview{"pw_count"} = $row[0];
  # get number of unique passwords
  $query = $dbh->prepare("SELECT count(distinct password) FROM passwords;");
  $query->execute;
  @row = $query->fetchrow;
  $overview{"pw_unique"} = $row[0];
  # get timestamp of last saved password
  $query = $dbh->prepare("SELECT timestamp FROM passwords
    WHERE id = ( SELECT max(id) FROM passwords );");
  $query->execute;
  @row = $query->fetchrow;
  $overview{"last_pw_time"} = $row[0];
  # get mostly used passwords
  $query = $dbh->prepare("SELECT password,count(*) FROM passwords
    WHERE timestamp > ( current_date - interval '1 week' )
    GROUP BY password ORDER BY count(password) DESC LIMIT 10;");
  $query->execute;
  $index = 0;
  while ( @row = $query->fetchrow) {
    $overview{"password_$index"} = $row[1]." ".$row[0];
    $index++;
  }
  # get password collecting service activity overview
  $query = $dbh->prepare("SELECT service,count(*) FROM passwords
    WHERE timestamp > ( current_date - interval '1 week' ) GROUP BY service;");
  $query->execute;
  $index = 0;
  while ( @row = $query->fetchrow) {
    $overview{"service_$index"} = $row[0]." ".$row[1];
    $index++;
  }
  $overview{"service_total"} = $index;
  # close database connection and send data to frontend
  $dbh->disconnect();
  syslog("info", "honeyscan: Closing the database connection");

  Nfcomm::socket_send_ok($socket, \%overview);

} # End of getOverview

#
# The getDBrecord function is called by frontend plugin. It queries the database
# with user-specified parameters and returns matching flows to frontend.
#
sub getDBrecord
{
  # get parameters
  my $socket  = shift;
  my $opts  = shift;

  my $profile      = $$opts{'profile'};
  my $profilegroup = $$opts{'profilegroup'};
  my $time_start   = $$opts{'time_start'};
  my $time_end     = $$opts{'time_end'};
  my $srcip        = $$opts{'srcip'};
  my $dstip        = $$opts{'dstip'};
  my $port         = $$opts{'port'};

  # connect to the database, prepare and execute sql query
  my $dbh = &connectToDB;
  if ( !$dbh ) {
    syslog("err", "honeyscan: Connection to the database failed");
    Nfcomm::socket_send_error($socket, "Connection to the database failed");
    return;
  }
  syslog("info", "honeyscan: Connected to the database");
  my $select = "SELECT timeslot,srcip,dstip,proto,dstport,flows FROM honeyscan
    WHERE timeslot BETWEEN '$time_start' AND '$time_end'";
  if ( $srcip ) {
    if ( $srcip =~ /\// ) { $select .= " AND srcip << '$srcip'"; }
    else { $select .= " AND srcip = '$srcip'"; }
  }
  if ( $dstip ) {
    if ( $dstip =~ /\// ) { $select .= " AND dstip << '$dstip'"; }
    else { $select .= " AND dstip = '$dstip'"; }
  }
  if ( $port ) {
    $select .= " AND dstport = $port";
  }
  $select .= " LIMIT 1000;";
  my $query = $dbh->prepare( $select );
  if ( !defined($dbh) ) {
    syslog("err", "honeyscan: Cannot prepare database query $DBI::errstr");
    Nfcomm::socket_send_error($socket, "Cannot prepare database query");
    return;
  }
  if ( !$query->execute ) {
    syslog("err", "honeyscan: Cannot execute database query $DBI::errstr");
    Nfcomm::socket_send_error($socket, "Cannot execute database query");
    return;
  }

  # format database table before sending to frontend
  my %data;
  my @row;
  my $index = 0;
  while ( @row = $query->fetchrow ) {
    $data{ $index } = $row[1].";".$row[2].";".$row[0].";".$row[3].";".$row[4].";".$row[5];
    $index++;
  }
  syslog("info", "honeyscan: Reading ".keys( %data )." flows from the database");
  $dbh->disconnect();
  syslog("info", "honeyscan: Closing the database connection");

  # send data to frontend
  Nfcomm::socket_send_ok($socket, \%data);

} # End of getDBrecord

#
# The getIPinfo function is called by frontend. It searches for flows from main network colector,
# not just honeynet probe. Task is to find whether some IP accessed any machines other than honeypots.
#
sub getIPinfo
{
  #get parameters
  my $socket    = shift;
  my $opts    = shift;

  my $profile      = $$opts{'profile'};
  my $profilegroup = $$opts{'profilegroup'};
  my $time_start   = $$opts{'time_start'};
  my $time_end     = $$opts{'time_end'};
  my $srcip        = $$opts{'srcip'};

  # nfsen.conf variables
  my $conf           = $NfConf::PluginConf{honeyscan};
  my $global_channel = $$conf{'global_channel'};
  my $localnet       = $$conf{'localnet'};
  my $localnet6      = $$conf{'localnet6'};

  # set profile variables
  my $profilepath     = NfProfile::ProfilePath($profile, $profilegroup);
  my $netflow_sources = "$PROFILEDIR/$profilepath/$global_channel";

  # process timeslot, format file range and time range
  # intput format: YYYY-MM-DD hh:mm
  # time format YYYY/MM/DD.hh:mm
  $time_start =~ s/-/\//g;
  $time_end =~ s/-/\//g;
  $time_start =~ s/ /\./g;
  $time_end =~ s/ /\./g;
  # file format: YYYYMMDDhhm(0|5)
  my $file_start = $time_start;
  my $file_end = $time_end;
  $file_start =~ s/[^0-9]//g;
  $file_start = substr($file_start, 0, 11).'0';
  $file_end =~ s/[^0-9]//g;
  $file_end = substr($file_end, 0, 11).'0';

  # prepare filter
  my $filter;
  if ( $srcip =~ /\// ) {
    $filter = "(dst net $localnet or dst net $localnet6) and src net $srcip";
  }
  else {
    $filter = "(dst net $localnet or dst net $localnet6) and src ip $srcip";
  }

  # call nfdump
  my @output = `$NFDUMP -q -c 1000 -M $netflow_sources -R nfcapd.$file_start:nfcapd.$file_end -t $time_start-$time_end -a -A proto,srcip,dstip,dstport -o "fmt:%sa;%da;%ts;%pr;%dp;%fl" -6 '$filter'`;
  syslog("info", "honeyscan: IP info obtained ".@output." flows");

  my $index = 0;
  my %data;
  foreach ( @output ) {
    $data{ $index } = $_;
    $index++;
  }

  # additional IP info - domain name, geolocation
  # get hostname
  my $ip_number = pack( "C4", split(/\./, $srcip) );
  my ( $hostname ) = ( gethostbyaddr($ip_number, 2) )[0];
  $data{"hostname"} = $hostname;
  # geolocation
  my $geo = Geo::IPfree->new;
  my ($code, $country) = $geo->LookUp($srcip);
  $data{"country"} = $country;

  # send data to frontend
  Nfcomm::socket_send_ok($socket, \%data);

} # End of getIPinfo

#
# This function is called by frontend. It queries the database for specified item
# and creates timeline for this item. Timeline tells how many items were recorded
# in a single day for the long time period (half a year)
#
sub getTrend
{
  # get parameters
  my $socket = shift;
  my $opts   = shift;
  my $item   = $$opts{'item'};
  my $value  = $$opts{'value'};

  my $table  = "honeyscan";
  my $time   = "timeslot";
  my $column = "flows";
  switch ($item) {
    case "dict" { $table = "passwords"; $time = "timestamp"; $column = "1"; }
    case "service"  { $table = "passwords"; $time = "timestamp"; $column = "1"; }
    case "username" { $table = "passwords"; $time = "timestamp"; $column = "1"; }
    case "password" { $table = "passwords"; $time = "timestamp"; $column = "1"; }
  }

  # prepare database connection
  my $dbh = &connectToDB;
  if ( !$dbh ) {
    syslog("err", "honeyscan: Connection to the database failed");
    Nfcomm::socket_send_error($socket, "Connection to the database failed");
    return;
  }
  syslog("info", "honeyscan: Connected to the database");
  # create timeline for the last six months day by day
  my $query = $dbh->prepare("SELECT a::date FROM generate_series((now()-interval '6 month')::date, now(), '1 day') s(a);");
  if ( !defined($dbh) ) {
    syslog("err", "honeyscan: Cannot prepare database query $DBI::errstr");
    Nfcomm::socket_send_error($socket, "Cannot prepare database query");
    return;
  }
  if ( !$query->execute ) {
    syslog("err", "honeyscan: Cannot execute database query $DBI::errstr");
    Nfcomm::socket_send_error($socket, "Cannot execute database query");
    return;
  }
  # save timeline in hash with days as keys
  my %data;
  my @row;
  while ( @row = $query->fetchrow ) {
    $data{ $row[0] } = 0;
  }
  # query for items with given value,
  # value is omitted when item is flows or dict (all flows/passwords are selected then)
  my $select = "SELECT $time,$column FROM $table WHERE $time > now() - interval '6 months'";
  if ( $item ne "flows" and $item ne "dict" ) {
    $select .=" AND $item = '$value'";
  }
  $select .= ";";
  my $query = $dbh->prepare( $select );
  if ( !$query->execute ) {
    syslog("err", "honeyscan: Cannot execute database query $DBI::errstr");
    Nfcomm::socket_send_error($socket, "Cannot execute database query");
    return;
  }
  while ( @row = $query->fetchrow ) {
    $data{ substr($row[0],0,10) } += $row[1];
  }
  $dbh->disconnect();
  syslog("info", "honeyscan: Closing the database connection");

  # send data to frontend
  Nfcomm::socket_send_ok($socket, \%data);

} # End of getTrend

#
# This function is called by frontend. It queries the database for passwords
# specified by user parameters.
#
sub getPassword
{
  # get parameters
  my $socket   = shift;
  my $opts     = shift;
  my $start    = $$opts{'pw_start'};
  my $end      = $$opts{'pw_end'};
  my $service  = $$opts{'pw_service'};
  my $username = $$opts{'pw_username'};
  my $password = $$opts{'pw_password'};

  # connect to the database, prepare and execute sql query
  my $dbh = &connectToDB;
  if ( !$dbh ) {
    syslog("err", "honeyscan: Connection to the database failed");
    Nfcomm::socket_send_error($socket, "Connection to the database failed");
    return;
  }
  syslog("info", "honeyscan: Connected to the database");
  my $select = "SELECT timestamp,rhost,host,service,username,password
    FROM passwords WHERE timestamp BETWEEN '$start' AND '$end'";
  if ( $service ) {
    $select .= " AND service = '$service'";
  }
  if ( $username ) {
    $select .= " AND username = '$username'";
  }
  if ( $password ) {
    $select .= " AND password = '$password'";
  }
  $select .= " LIMIT 1000;";
  my $query = $dbh->prepare( $select );
  if ( !defined($dbh) ) {
    syslog("err", "honeyscan: Cannot prepare database query $DBI::errstr");
    Nfcomm::socket_send_error($socket, "Cannot prepare database query");
    return;
  }
  if ( !$query->execute ) {
    syslog("err", "honeyscan: Cannot execute database query $DBI::errstr");
    Nfcomm::socket_send_error($socket, "Cannot execute database query");
    return;
  }
  my $index = 0;
  my %data;
  my @row;
  while ( @row = $query->fetchrow ) {
    $data{ $index } = $row[0].";".$row[1].";".$row[2].";".$row[3].";".$row[4].";".$row[5];
    $index++;
  }
  syslog("info", "honeyscan: Reading ".keys( %data )." passwords from the database");
  $dbh->disconnect();
  syslog("info", "honeyscan: Closing the database connection");

  # send data to frontend
  Nfcomm::socket_send_ok($socket, \%data);

} # End of getPassword function

#
# This function is used by frontend to process whitelist file by presenting the whitelist content
# and eventually add/remove any IPs in file
#
sub whitelist
{
  # get parameters
  my $socket = shift;
  my $opts   = shift;

  my $list_count  = $$opts{'count'};

  # write new whitelist content if available
  if ( $list_count ) {
    syslog("info", "honeyscan: Whitelist changes submitted");
    # open whitelist file
    if ( ! open WHITELIST, ">$BACKEND_PLUGINDIR/honeyscan/honeyscan.whitelist" ) {
      syslog("err", "honeyscan: Cannot open whitelist file for writing");
    }
    # lock it
    elsif ( ! flock WHITELIST, 2 ) {
      syslog("err", "honeyscan: Cannot lock whitelist file");
    }
    # write new whitelist
    else {
      my $count = 0;
      while ( $count < $list_count ) {
        $count++;
        # validate with Net::CIDR?
        print WHITELIST $$opts{"value_$count"}."\n";
      }
      close(WHITELIST);
    }
  }

  # read whitelist file
  my $counter = 0;
  my %content;
  if ( ! open WHITELIST, "$BACKEND_PLUGINDIR/honeyscan/honeyscan.whitelist" ) {
    syslog("err", "honeyscan: Cannot open whitelist file");
    Nfcomm::socket_send_error($socket, "Cannot open whitelist file");
    return;
  }
  while(<WHITELIST>) {
    chomp;
    $content{ $counter } = $_;
    $counter++;
  }
  close(WHITELIST);

  # send whitelist content to frontend
  Nfcomm::socket_send_ok($socket, \%content);

} # End of whitelist

#
# reportAccess function sends email notification about the suspicious IPs from the local network
# and includes relevant netflow data
# input:  'netflow_sources' string with netflow sources for nfdump
#         'timeslot'        nfdump timeslot of the attack
#         'ip'              captured local IP
sub reportAccess
{
  my ( $netflow_sources, $timeslot, $ip ) = @_;

  syslog("warning", "honeyscan: Access from local IP $ip");

  my $conf  = $NfConf::PluginConf{honeyscan};
  my $mail_from = $$conf{'mail_from'};
  my $mail_to = $$conf{'mail_to'};

  # call nfdump, sort flows
  my @flows = sort `$NFDUMP -q -M $netflow_sources -r nfcapd.$timeslot -o "fmt:%ts %td %pr %sap -> %dp %pkt %byt %fl" -6 'src ip $ip'`;
  # pick time when suspicious activity started
  my ( $date, $time ) = split(  ' ', $flows[0] );
  my $start_time = "$date $time";
  our $details = "";
  foreach ( @flows ) {
    $details .= $_;
  }

  # convert timeslot to ISO 8601
  substr($timeslot, 10, 0) = ':';
  substr($timeslot, 8, 0) = ' ';
  substr($timeslot, 6, 0) = '-';
  substr($timeslot, 4, 0) = '-';

  # get hostname
  # TODO IPv6!
  our $hostname = scalar gethostbyaddr(inet_aton($ip), AF_INET);
  if ( $hostname ) { $hostname = "$ip ($hostname)"; }
  else { $hostname = "$ip"; }

  our $subject = "";
  our $message = "";
  # using hostname, details
  do "$BACKEND_PLUGINDIR/honeyscan/mail_local.pl";

  my $msg = MIME::Lite->new(
    From                 => $mail_from,
    To                   => $mail_to,
    Subject              => $subject,
    Data                 => $message
  );
  my $rc = $msg->send;
  syslog("info", "honeyscan: E-mail sent to $mail_to with result code $rc");

  return 1;
} # End of notify

#
# reportAttack sends email notification of suspicious behaviour of external IPs
# input:  'timestamp' attack start time
#         'ip'        IP of attacker
#         'scale'     number of flows to production network
#         'dict'      number of authentication attempts
sub reportAttack
{
  our ( $timestamp, $ip, $scale, $dict ) = @_;

  syslog("warning", "honeyscan: Malicious IP $ip, hosts accessed: $scale, passwords: $dict");

  my $conf      = $NfConf::PluginConf{honeyscan};
  my $mail_from = $$conf{'mail_from'};
  my $mail_to   = $$conf{'mail_to'};

  # convert timestamp to ISO 8601
  substr($timestamp, 10, 0) = ':';
  substr($timestamp, 8, 0) = ' ';
  substr($timestamp, 6, 0) = '-';
  substr($timestamp, 4, 0) = '-';
  # get timezone
  my $timezone = strftime("%Z", localtime());
  # get timestamp in GMT with timezone
  my $timestamp = `date -d "$timestamp $timezone" -u "+%Y-%m-%d %H:%M %Z"`;
  chomp $timestamp;

  # get hostname
  # TODO IPv6!
  our $hostname = scalar gethostbyaddr(inet_aton($ip), AF_INET);
  if ( $hostname ) { $hostname = "$ip ($hostname)"; }
  else { $hostname = "$ip"; }

  our $subject = "";
  our $message = "";
  if ( $dict ) {
    our ( $service, $count ) = split(/:/, $dict);
    $service = uc $service;
    # using hostname, timestamp, scale, service
    do "$BACKEND_PLUGINDIR/honeyscan/mail_dict.pl";
  } else {
    # using hostname, timestamp, scale
    do "$BACKEND_PLUGINDIR/honeyscan/mail_global.pl";
  }

  my $msg = MIME::Lite->new(
    From                 => $mail_from,
    To                   => $mail_to,
    Subject              => $subject,
    Data                 => $message,
  );
  my $rc = $msg->send;
  syslog("info", "honeyscan: E-mail sent to $mail_to with result code $rc");

  return 1;
} # End of reportScan

#
# This function prepares whitelist-based nfdump filter
#
sub prepareFilter
{
  # nfsen.conf variables
  my $conf      = $NfConf::PluginConf{honeyscan};
  my $localnet  = $$conf{'localnet'};
  my $honeynet  = $$conf{'honeynet'};
  my $localnet6 = $$conf{'localnet6'};
  my $honeynet6 = $$conf{'honeynet6'};

  if ( ! open WHITELIST, "$BACKEND_PLUGINDIR/honeyscan/honeyscan.whitelist" ) {
    syslog("err", "honeyscan: Cannot open whitelist file");
    return 0;
  }
  if ( ! open FILTER, ">$BACKEND_PLUGINDIR/honeyscan/honeyscan.filter" ) {
    syslog("err", "honeyscan: Cannot open nfdump filter file");
    close(WHITELIST);
    return 0;
  }
  if ( ! flock FILTER, 2 ) {
    syslog("err", "honeyscan: Cannot lock filter file");
    close(WHITELIST);
    close(FILTER);
    return 0;
  }
  print FILTER "(dst net $honeynet or dst net $honeynet6) and (not src net $honeynet and not src net $honeynet6)";
  my ( $ip, $net );
  $net = " and not net fe80::/10"; # whitelist local link
  foreach(<WHITELIST>) {
    # validate with Net::CIDR?
    chomp;
    if ( $_ =~ /\// ) { $net .= " and not net $_"; }
    else { $ip .= " $_"; }
  }
  if ( $ip ) { print FILTER " and not ip in [$ip]"; }
  if ( $net ) { print FILTER $net; }
  print FILTER " and not port in [53 123] and ( not proto icmp or icmp-type 8 )";
  close(FILTER);
  close(WHITELIST);
  syslog("info", "honeyscan: Nfdump filter prepared");
  return 1;
} # End of prepareFilter

#
# Periodic data processing function
# input:  hash reference including the items:
#     'profile'   profile name
#     'profilegroup'    profile group
#     'timeslot'    time of slot to process: Format yyyymmddHHMM e.g. 200503031200
sub run
{
  my $argref       = shift;
  my $profile      = $$argref{'profile'};
  my $profilegroup = $$argref{'profilegroup'};
  my $timeslot     = $$argref{'timeslot'};

  # nfsen.conf variables
  my $conf           = $NfConf::PluginConf{honeyscan};
  my $channel        = $$conf{'channel'};
  my $global_channel = $$conf{'global_channel'};
  my $localnet       = $$conf{'localnet'};
  my $localnet6      = $$conf{'localnet6'};
  my $threshold      = $$conf{'threshold'};
  my $exportdir      = $$conf{'exportdir'};

  my %profileinfo     = NfProfile::ReadProfile($profile, $profilegroup);
  my $profilepath     = NfProfile::ProfilePath($profile, $profilegroup);
  my $all_sources     = join ':', keys %{$profileinfo{'channel'}};
  my $netflow_sources = "$PROFILEDIR/$profilepath/$channel";
  my $global_sources  = "$PROFILEDIR/$profilepath/$global_channel";

  # call nfdump
  if ( &prepareFilter == 0 ) {
    syslog("err", "honeyscan: Nfdump filter preparation failed");
    return;
  }
  my @output = `$NFDUMP -q -M $netflow_sources -r nfcapd.$timeslot -a -A proto,srcip,dstip,dstport -o "fmt:%sa %da %ts %pr %dp %fl" -6 -f $BACKEND_PLUGINDIR/honeyscan/honeyscan.filter`;

  # --- netflow data obtained, save them to the database and process them ---

  # sets for data processing (check for suspicious IPs from localnet, check for scans)
  my %ipset;   # set of IPs
  my %dictset; # set of dictionary attackers

  # connect to the database
  my $dbh = &connectToDB;
  if ( !$dbh ) {
    syslog("err", "honeyscan: Connection to the database failed");
    return;
  }
  syslog("info", "honeyscan: Connected to the database");

  # prepare inserting to the database
  my $counter = 0;
  $dbh->do("COPY honeyscan (timeslot, srcip, dstip, proto, dstport, flows) FROM STDIN USING DELIMITERS ';' WITH NULL AS 'null'")
    or die syslog("err", "honeyscan: Cannot initiate inserting to database $DBI::errstr");
  # process the data
  my $lastsrcip = "";
  my $lastdstip = "";
  foreach ( @output ) {
    my ( $srcip, $dstip, $day, $time, $proto, $dstport, $flows ) = split( ' ', $_ );
    # agregation for later data processing - number of honeypots accessed by each IP
    if ( $srcip ne $lastsrcip or $dstip ne $lastdstip ) {
      $ipset{$srcip}++;
      $lastsrcip = $srcip;
      $lastdstip = $dstip;
    }
    # copy the data to the database
    $dbh->pg_putcopydata( "$day $time;$srcip;$dstip;$proto;".int($dstport).";$flows\n" )
      or die syslog("err", "honeyscan: Cannot insert flows to database $DBI::errstr");
    $counter++;
  }
  syslog("info", "honeyscan: $counter records inserted to the database");
  $dbh->pg_putcopyend();

  # query for any dictionary attackers in the last fice minutes, returning IP and service
  my $query = $dbh->prepare("SELECT rhost, service, count(*) FROM passwords WHERE timestamp > now() - INTERVAL '5 minute' GROUP BY rhost, service;"); # HAVING count(*) > 4
  $query->execute;
  while ( my ( $dictip, $dictservice, $dictcount ) = $query->fetchrow ) {
    syslog("info", "honeyscan: $dictcount new passwords from remote host $dictip in the last 5 minutes");
    # considering only attackers with more athentication attempts than 4
    if ( $dictcount > 4 ) {
      $dictset{$dictip} = "$dictservice:$dictcount";
    }
  }
  # close the database connection
  $dbh->disconnect();
  syslog("info", "honeyscan: Closing the database connection");

  # --- data are saved, start processing ---

  # process set of IPs, pick IPs from localnet
  my $iplist = "";
  my $ip;
  foreach $ip ( keys %ipset ) {
    # process IPv6 addresses
    if ( $ip !~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ) {
      # is IP from localnet?
      if ( Net::CIDR::cidrlookup( $ip, $localnet6 ) ) {
        &reportAccess( $netflow_sources, $timeslot, $ip );
      } else {
        $iplist .= "$ip ";
      }
    }
    # process IPv4 addresses
    else {
      # is IP from localnet?
      if ( Net::CIDR::cidrlookup( $ip, $localnet ) ) {
        &reportAccess( $netflow_sources, $timeslot, $ip );
      } else {
        $iplist .= "$ip ";
      }
    }
  }
  # get flows from honeypot visitors in global channel
  my %gipset;
  my @globalflows = `$NFDUMP -q -M $global_sources -r nfcapd.$timeslot -a -A srcip,dstip -o "fmt:%sa %da" -6 'src ip in [$iplist]'`;
  foreach (@globalflows) {
    my ( $srcip, $dstip ) = split( ' ', $_ );
    $gipset{$srcip}++;
  }
  # log visitors accessing IPs outside the honeypot segment, report dangerous ones
  foreach $ip ( keys %gipset ) {
    # scale is the number of flows from attacker to production network but not to honeypots
    my $scale = $gipset{$ip} - $ipset{$ip};
    if ( $scale > 0 ) {
      syslog("info", "honeyscan: IP $ip accessed $scale IPs outside the honeypot segment (".$ipset{$ip}." inside)");
    }
    # report dictionary attackers with more than 4 passwords authentication attempts
    if ( defined $dictset{$ip} and $scale > 0 ) {
      &reportAttack($timeslot, $ip, $gipset{$ip}, $dictset{$ip} );
    }
    # report "scanners" with more than $threshold flows to producton network
    elsif ( $scale > $threshold ) {
      &reportAttack($timeslot, $ip, $gipset{$ip}, 0, 0);
    }
  }

  # --- call additional routines ---

  # run export every hour
  if ( substr($timeslot, 10, 2) eq "00" ) {
    &export( $exportdir, $timeslot );
  }
  # run database cleanup every day
  if( substr($timeslot, 8, 4) eq "0000") {
    &DBCleanup();
  }

  syslog("info", "honeyscan: End of periodic processing");

  return 1;
} # End of run

#
# This function provides integration of Warden client - system for sharing security incident reports.
# Data are once more obtained from nfdump (different aggregaton is used this time)
# and only the flows with IP accessing both honeynet and production net are sent to Warden.
#

#
# DBCleanup function is supposed to check database size
# and delete records older then one year if the database is too big
#
sub DBCleanup
{
  syslog("info", "honeyscan: Database cleanup");
  # connect to the database
  my $dbh = &connectToDB;
  if ( !$dbh ) {
    syslog("err", "honeyscan: Connection to the database failed");
    return;
  }
  syslog("info", "honeyscan: Connected to the database");
  # get size of the 'honeyscan' table
  my $query = $dbh->prepare("SELECT pg_relation_size('honeyscan');");
  $query->execute;
  my @row = $query->fetchrow;
  my $size = $row[0];
  syslog("info", "honeyscan: Database size is $size");
  # delete
  $query = $dbh->prepare("DELETE FROM honeyscan WHERE timeslot < now() - INTERVAL '1 year';");
  $query->execute;
  syslog("info", "honeyscan: Old data deleted");
  # disconnect
  $dbh->disconnect();
  syslog("info", "honeyscan: Closing the database connection");

  return 1;
} # End of DBCleanup

#
# Export function stores captured flows to text files in specified directory.
# Honeypot addresses are anonymized and timestamps are converted to GMT.
# File name format: honeyscan-YYYYMMDDhhmm.txt
#
sub export
{
  my ( $exportdir, $timeslot ) = @_;
  my $exporttime = 86400 * 7; # 1 week - time to store exported data

  syslog("info", "honeyscan: Exporting flows");

  # return if exportdir is not set
  if ( $exportdir eq "" ) {
    syslog("info", "honeyscan: Export directory is not set");
    return 0;
  }

  # check for old files in export directory
  my $today = time;
  if ( ! opendir DIR, $exportdir ) {
    syslog("err", "honeyscan: Failed to open export directory $exportdir");
    return 0;
  }
  while ( my $file = readdir DIR ) {
    next if -d "$exportdir/$file";
    next if $file !~ /honeyscan-\d{12}\.txt/;
    my $filetime = (stat "$exportdir/$file") [9];
    if ($today - $exporttime > $filetime) {
      # delete file
      syslog("info", "honeyscan: $exportdir/$file is older than 1 week - deleting");
      unlink("$exportdir/$file");
    }
  }
  closedir DIR;

  # format timeslot, prepare new file
  substr( $timeslot,10,0 ) = ":";
  substr( $timeslot,8,0 ) = " ";
  substr( $timeslot,6,0 ) = "-";
  substr( $timeslot,4,0 ) = "-";
  # get local timezone
  my $timezone = strftime("%Z", localtime());
  # get timeslot in GMT
  my $filename = `date -d "$timeslot $timezone" -u +%Y%m%d%H%M`;
  chomp $filename;
  syslog("info", "honeyscan: Creating export file honeyscan-$filename.txt");

  if ( ! open FILE, ">$exportdir/honeyscan-$filename.txt" ) {
    syslog("err", "honeyscan: Cannot open export file");
    return 0;
  }
  # connect to database, get lower and upper bounds of timeslot in GMT
  my $dbh = &connectToDB;
  if ( !$dbh ) {
    syslog("err", "honeyscan: Connection to the database failed");
    return;
  }
  syslog("info", "honeyscan: Connected to the database");
  my $query = $dbh->prepare("SELECT
    timezone(current_setting('TIMEZONE'), timestamp '$timeslot' - interval '1 hour')
    at time zone 'GMT';");
  $query->execute;
  my @row = $query->fetchrow;
  my $lower_timeslot = substr( $row[0],0,16 );
  $query = $dbh->prepare("SELECT
    timezone(current_setting('TIMEZONE'), timestamp '$timeslot')
    at time zone 'GMT';");
  $query->execute;
  @row = $query->fetchrow;
  my $upper_timeslot = substr( $row[0],0,16 );
  # print file header
  print FILE "# Honeyscan - honeynet monitoring tool
#
# This file contains records of flows incoming to honeypots
# from $lower_timeslot to $upper_timeslot GMT.
# A new file is created every hour, files older than one week are deleted automatically.
# Comments are preceded with a '#' at the beginning of line.
#
# Timestamp             Timestamp in GMT of when the flow(s) appeared
# source IP             IP of host that is connecting to honeypot
# destination IP        Honeypot IP (the first three bytes anonymized)
# proto                 Protocol of the flow (ICMP, TCP, UDP)
# port                  Destination port of the flow
# flows                 Number of flows
#
#Timestamp              | source IP       | destination IP  | proto | port  | flows
#---------------------- | --------------- | --------------- | ----- | ----- | -----
";
  # prepare and execute query - selecting all flows from 1 hour interval with timestamps converted to GMT
  # timeslot already formatted when resolving filename
  $query = $dbh->prepare("SELECT
    timezone(current_setting('TIMEZONE'), timeslot) at time zone 'GMT', srcip, dstip, proto, dstport, flows
    FROM honeyscan
    WHERE timeslot BETWEEN (timestamp '$timeslot' - interval '1 hour') AND '$timeslot' ORDER BY timeslot;");
  $query->execute;
  # write database content to file
  while ( my @row = $query->fetchrow ) {
    my ( $timestamp, $srcip, $dstip, $proto, $dstport, $flows ) = @row;
    # hide honeypot segment address
    $dstip =~ s/(\d{1,3}\.){3}/aaa\.bbb\.ccc\./;
    printf FILE "%-23s | %-15s | %-15s | %5s | %5s | %5s\n", $timestamp, $srcip, $dstip, $proto, $dstport, $flows;
  }
  close(FILE);
  $dbh->disconnect;
  syslog("info", "honeyscan: Closing the database connection");

  syslog("info", "honeyscan: Export completed");

  return 1;
} # End of export

#
# The Init function is called when the plugin is loaded. It's purpose is to give the plugin 
# the possibility to initialize itself. The plugin should return 1 for success or 0 for 
# failure. If the plugin fails to initialize, it's disabled and not used. Therefore, if
# you want to temporarily disable your plugin return 0 when Init is called.
#
sub Init
{
  use NfConf;
  my $conf        = $NfConf::PluginConf{honeyscan};

  $NFDUMP            = "$NfConf::PREFIX/nfdump";
  $PROFILEDIR        = "$NfConf::PROFILEDATADIR";
  $BACKEND_PLUGINDIR = "$NfConf::BACKEND_PLUGINDIR";


  $USEPASSDB = $$conf{'use_password_db'};
  $USEPASSDB ? syslog("info", "honeyscan: Password database enabled") : syslog("info", "honeyscan: Password database disabled");

  syslog("info", "honeyscan: Initialized");

  return 1;
}

sub Cleanup
{
  return 1;
}

1;
