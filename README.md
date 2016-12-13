# honeyscan

+---------------------------------+
| README - NfSen Honeyscan Plugin |
+---------------------------------+

Honeyscan - honeynet monitoring plugin for NfSen provides information
about activity of honeypot network based on NetFlow data.
IPv4 and IPv6 is supported, legitimate IP addresses can be whitelisted.
Honeyscan detects unauthorized accesses to the honeypot network, stores authentication
attempts to honeypot services and reports accesses from local network.
Honeyscan also reports dictionary attackers and massive accesses to honeypots that threatens local network.
Web interface is provided to present captured flows, passwords and statistics.

2012-09-03 v1.0.0 stable version

Content:
========
1. License
2. Requirements
3. Installation
4. Configuration
        4.1 Setting of PostgreSQL database
        4.2 Setting of nfsen.conf
	4.3 Writing whitelist
	4.4 Editing e-mail messages
        4.5 Reload of NfSen
5. Using the honeyscan plugin
	5.1 Interface
	5.2 Passwords
6. Uninstallation
        6.1 Uninstallation of honeyscan plugin
        6.2 Uninstallation of database


1. License:
===========
* The plugin frontend includes the third party software component JQuery,
  distributed under the MIT License.
* The plugin backend uses the third party software component PostgreSQL database.
* The plugin backend and frontend code is available under the BSD License.


2. Requirements:
================
* Perl 5.8.8 or higher
* PHP 5.5.3 or higher
* PostgreSQL 8.4.9 or higher
* NfSen 1.3.6 or higher
* nfdump 1.6.5 or higher
* DBD::Pg
* DBI
* MIME::Lite
* Geo::IPfree
* Net::CIDR


3. Installation:
================

1. Unpack honeyscan tarball.

$ tar xzvf honeyscan-1.0.0.tar.gz

Copy the content of backend directory to $BACKEND_PLUGINDIR
and the content of frontend directory to $FRONTEND_PLUGINDIR

$BACKEND_PLUGINDIR and $FRONTEND_PLUGINDIR are specified in /data/nfsen/etc/nfsen.conf.

Make sure that honeyscan will be able to create and write to files in $BACKEND_PLUGINDIR/honeyscan/


4. Configuration:
=================

4.1 PostgreSQL database settings
--------------------------------
Assuming the PostgreSQL database is installed and running
log in as database admin

    $ su -
    # su - postgres
    $ psql

Create the database

    =# CREATE DATABASE honeyscandb;

Create new database user with password

    =# CREATE USER honeyscan WITH PASSWORD 'password';

Grant all privileges on honeyscan database to this user

    =# GRANT ALL ON DATABASE honeyscandb TO honeyscan;

Exit PostgreSQL console

    =# \q

Log into PostgreSQL console as the new user

    $ psql honeyscandb -U honeyscan

Create tables in honeyscan database

    honeyscandb=> CREATE TABLE honeyscan (timeslot TIMESTAMP, srcip INET, dstip INET, proto VARCHAR(8), dstport INT, flows INT);
    honeyscandb=> CREATE TABLE passwords (id serial primary key, timestamp TIMESTAMP, host INET, rhost INET, service VARCHAR(8), username VARCHAR(32), password VARCHAR(32));

Create indexes for faster database queries

    honeyscandb=> CREATE INDEX timeslotindex ON honeyscan (timeslot);
    honeyscandb=> CREATE INDEX timestampindex ON passwords (timestamp);

Exit PostreSQL console

    honeyscandb=> \q

4.2 Plugin Configuration
------------------------
Add the following line to the @plugins section of nfsen.conf

  [ 'live', 'honeyscan' ],

Modify %PluginConf hash variable in nfsen.conf:

%PluginConf = (
  ...
  honeyscan => {
    channel         => '<channel>',
    global_channel  => '<global_channel>',
    localnet        => '10.0.0.0/16',
    localnet6       => '2001::/48',
    honeynet        => '10.0.10.0/24',
    honeynet6       => '2001:0:0:1::/64',
    dbname          => '<dbname>',
    dbhost          => '<dbhost>',
    dbport          => '<dbport>',
    dbuser          => '<dbuser>',
    dbpasswd        => '<dbpasswd>',
    use_password_db => 1,
    mail_to         => 'operator@your.domain',
    mail_from       => 'honeyscan@your.domain',
    threshold        => 60000,
    exportdir       => '/path/to/export/dir',
  },
  ...
);

- <channel>         NfSen channel for honeynet monitoring probe
- <global_channel>  NfSen channel for the whole network
- localnet          IPv4 range of your production network
- localnet6         IPv6 range of your production network
- honeynet          IPv4 range of honeypot network
- honeynet6         IPv6 range of honeypot network
- <dbname>          name of the database specified in 4.1 ("honeyscandb")
- <dbhost>          hostname of remote database host or "localhost" if the database runs locally
- <dbport>          database port (usually 5432)
- <dbuser>          database user created in 4.1 ("honeyscan")
- <dbpasswd>        password for the database user created in 4.1 ("password")
- mail_to           e-mail address that will receive all the notifications
- mail_from         sender's address
- use_passwd_db     If you capture and store authentication attempts at honeypots (see 5.2) set use_password_db to 1,
                    otherwise set it to 0, this variable tells honeyscan to (or not to) access and present stored passwords in frontend.
- threshold         This sets the minimal number of IPs in your network accessed by some IP from outer network to be considered
                    as attack (e.g., if someone accesses any honeypot AND at least threshold other IPs in your network, the notification is sent),
                    for example, 60000 is reasonable threshold for /16 production network.
- exportdir         This tells honeyscan where to export data in text files. These files contains flows with anonymized honeypot IPs
                    and timestamps converted to GMT, so it can be used for sharing the data without revealing the honeypots.
                    New file is created every hour and is deleted after 1 week. Export can be disabled by setting empty string ''.

4.3 Whitelist
-------------
Edit file honeyscan.whitelist in $BACKEND_PLUGINDIR/honeyscan directory.
Write down list of whitelisted IP addresses or subnets, one per line, which
should be excluded from honeynet activity monitoring. Whitelist can be changed
anytime using web frontend.

The plugin itself whitelists DNS and NTP communication (ports 53 and 123)
as well as ICMP messages with exception of ICMP type 8 (Echo).

4.4 Editing e-mail messages
---------------------------
Go to $BACKEND_PLUGINDIR/honeyscan/ directory, you can see files named mail_local.pl, mail_global.pl and mail_dict.pl.
These files are templates for e-mail notification, each file represents different reported incident:
  mail_local.pl  - access from local network to honeypot
  mail_global.pl - massive access from outer network to honeypots and local network (e.g., scan)
  mail_dict.pl   - dictionary attack against honeypot that threatens local network (not used when use_password_db is set to 0, see 4.2)
In any of these files you can change the content of $subject and $message strings to whatever you want to be sent as a notification e-mail,
each file includes short description of exported variables you can use in your text (e.g., reported IP, current time, etc.).

4.5 Reload of NfSen
-------------------
$BINDIR/nfsen reload


5. Using honeyscan plugin:
==========================

5.1 Interface
-------------
Honeyscan interface is accesible via NfSen web interface in the 'Plugins' section.
First you see 'Overview' tab containing graphs of most active suspicious addresses, honeynet port activity,
passwords statistics and basic information about the database.
In 'Details' tab and 'Passwords' tab honeyscan presents detailed captured flows and passwords.
Tab 'IP info' will tell you if some IP contacted any other machines in your network apart from honeypots.
'Trends' prints long-term occurrence graphs of key items.
'Whitelist' tab allows user to change whitelist content.

WARNING: Tabs, graphs and items presenting captured passwords could be disabled, see 4.2 (use_password_db) and 5.2 for more info.

5.2 Passwords
-------------
Honeyscan contains database of passwords which were used by attackers, however
honeyscan is not able to capture passwords by itself, this is done by honeypots.
Capturing passwords is not compulsory but it helps honeyscan to convict serious attack.
Suppose you have some service at honeypot that can record username/password typed by attacker,
use this SQL command to insert record into the passwords database:

	INSERT INTO passwords (timestamp, rhost, host, service, username, password)
		VALUES ('<timestamp>', '<attacker_ip>', '<honeypot_ip>', '<service>', '<username>', '<passwords>');

It could be hazardous to give honeypot access to the database, consider sending the credentials
through some proxy or honeypot host machine.
If you are interested in password capturing tools, contact the author.


6. Uninstallation:
==================

6.1 Uninstallation of honeyscan plugin
--------------------------------------
Stop NfSen
Edit file nfsen.conf - delete line

  [ 'live', 'honeyscan' ],

in @plugins section.
Delete hash variable entry

  honeyscan => {
    ...
  }

in section %PluginConf.

Remove file honeyscan.pm and directory honeyscan from $BACKEND_PLUGINDIR,
delete file honeyscan.php and directory honeyscan from $FRONTEND_PLUGINDIR.
$BACKEND_PLUGINDIR and $FRONTEND_PLUGINDIR are specified by nfsen.conf.

6.2 Uninstallation of database
------------------------------
Connect to database as admin, delete honeyscan database in PostgreSQL console:

    $ su -
    # su - postgres
    $ psql

    =# DROP TABLE honeyscan FROM DATABASE honeyscandb;
    =# DROP TABLE passwords FROM DATABASE honeyscandb;
    =# DROP DATABASE honeyscan
    =# \q

