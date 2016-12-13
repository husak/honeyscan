<?php
/*
* Copyright (C) 2011 Masaryk University
* Author(s): Martin HUSAK <husakm@ics.muni.cz>
* 
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*     * Neither the name of the organization nor the
*       names of its contributors may be used to endorse or promote products
*       derived from this software without specific prior written permission.
* 
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COMPANY BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*/

// prevent frontend from refreshing page every 5 minutes
$_SESSION['refresh'] = 0;

/* 
 * honeyscan_ParseInput is called prior to any output to the web browser 
 * and is intended for the plugin to parse possible form data. This 
 * function is called only, if this plugin is selected in the plugins tab. 
 * If required, this function may set any number of messages as a result 
 * of the argument parsing.
 * The return value is ignored.
 */
function honeyscan_ParseInput( $plugin_id ) {

$parse_opts = array (
  "time_start" => array(
    "required"   => 0,
    "default"    => date("Y-m-d H:i", $_SESSION['profileinfo']['updated'] - 300),
    "allow_null" => 0,
    "match"      => "/^\d\d\d\d-\d\d-\d\d \d\d:\d\d$/",
    "validate"   => NULL,
  ),
  "time_end" => array(
    "required"   => 0,
    "default"    => date("Y-m-d H:i", $_SESSION['profileinfo']['updated']),
    "allow_null" => 0,
    "match"      => "/^\d\d\d\d-\d\d-\d\d \d\d:\d\d$/",
    "validate"   => NULL,
  ),
  "srcip" => array(
    "required"   => 0,
    "default"    => NULL,
    "allow_null" => 1,
    "match"      => NULL,//"/^((\d{1,3}\.){3})(\d{1,3})($|(\/(\d{1,2})$))/", //TODO IPv6
    "validate"   => NULL,
  ),
  "dstip" => array(
    "required"   => 0,
    "default"    => NULL,
    "allow_null" => 1,
    "match"      => NULL,//"/^((\d{1,3}\.){3})(\d{1,3})($|(\/(\d{1,2})$))/", //TODO IPv6
    "validate"   => NULL,
  ),
  "port" => array(
    "required"   => 0,
    "default"    => NULL,
    "allow_null" => 1,
    "match"      => "/^\d{1,5}$/",
    "validate"   => NULL,
  ),
  "item" => array(
    "required"   => 0,
    "default"    => "flows",
    "allow_null" => 0,
    "match"      => "/^[a-z]+$/",
    "validate"   => NULL,
  ),
  "value" => array(
    "required"   => 0,
    "default"    => "",
    "allow_null" => 1,
    "match"      => NULL,
    "validate"   => NULL,
  ),
  "pw_start" => array(
    "required"   => 0,
    "default"    => NULL,
    "allow_null" => 1,
    "match"      => "/^\d\d\d\d-\d\d-\d\d \d\d:\d\d$/",
    "validate"   => NULL,
  ),
  "pw_end" => array(
    "required"   => 0,
    "default"    => date("Y-m-d H:i"),
    "allow_null" => 0,
    "match"      => "/^\d\d\d\d-\d\d-\d\d \d\d:\d\d$/",
    "validate"   => NULL,
  ),
  "pw_service" => array(
    "required"   => 0,
    "default"    => NULL,
    "allow_null" => 1,
    "match"      => "/^[a-z]+$/",
    "validate"   => NULL,
  ),
  "pw_username" => array(
    "required"   => 0,
    "default"    => NULL,
    "allow_null" => 1,
    "match"      => NULL,
    "validate"   => NULL,
  ),
  "pw_password" => array(
    "required"   => 0,
    "default"    => NULL,
    "allow_null" => 1,
    "match"      => NULL,
    "validate"   => NULL,
  )
);

list ($process_form, $has_errors) = ParseForm($parse_opts);
$_SESSION['honeyscan']['has_errors']  = $has_errors;

// Details tab parameters
$_SESSION['honeyscan']['time_start'] = $process_form['time_start'];
$_SESSION['honeyscan']['time_end']   = $process_form['time_end'];
$_SESSION['honeyscan']['srcip']      = $process_form['srcip'];
$_SESSION['honeyscan']['dstip']      = $process_form['dstip'];
$_SESSION['honeyscan']['port']       = $process_form['port'];
// Trends tab parameters
$_SESSION['honeyscan']['item']  = $process_form['item'];
$_SESSION['honeyscan']['value'] = $process_form['value'];
// Passwords tab parameters
$_SESSION['honeyscan']['pw_start']    = $process_form['pw_start'];
$_SESSION['honeyscan']['pw_end']      = $process_form['pw_end'];
$_SESSION['honeyscan']['pw_service']  = $process_form['pw_service'];
$_SESSION['honeyscan']['pw_username'] = $process_form['pw_username'];
$_SESSION['honeyscan']['pw_password'] = $process_form['pw_password'];

} // End of honeyscan_ParseInput


/*
 * This function is called after the header and the navigation bar have 
 * are sent to the browser. It's now up to this function what to display.
 * This function is called only, if this plugin is selected in the plugins tab
 * Its return value is ignored.
 */
function honeyscan_Run( $plugin_id ) {

// Include javascript and css
print '
<script type="text/javascript" src="plugins/honeyscan/jquery.min.js"></script>
<script type="text/javascript" src="plugins/honeyscan/jquery-ui.js"></script>
<script type="text/javascript" src="plugins/honeyscan/jquery.easytabs.min.js"></script>

<link rel="stylesheet" href="plugins/honeyscan/jquery.tablesorter.min.css" type="text/css" />
<script type="text/javascript" src="plugins/honeyscan/jquery.tablesorter.min.js"></script>

<link rel="stylesheet" type="text/css" href="plugins/honeyscan/jquery.jqplot.min.css" />
<script type="text/javascript" src="plugins/honeyscan/jquery.jqplot.min.js"></script>
<script type="text/javascript" src="plugins/honeyscan/jqplot.barRenderer.min.js"></script>
<script type="text/javascript" src="plugins/honeyscan/jqplot.categoryAxisRenderer.min.js"></script>
<script type="text/javascript" src="plugins/honeyscan/jqplot.canvasAxisTickRenderer.min.js"></script>
<script type="text/javascript" src="plugins/honeyscan/jqplot.canvasTextRenderer.min.js"></script>
<script type="text/javascript" src="plugins/honeyscan/jqplot.pieRenderer.min.js"></script>
<script type="text/javascript" src="plugins/honeyscan/jqplot.ClickableBars.js"></script>
';

// Call backend plugin
$command  = 'honeyscan::usingPassDB';
$opts     = array();
$return = nfsend_query($command, $opts);
$_SESSION['honeyscan']['use_pass_db'] = $return['use_pass_db'];

// Print tabs container
$active = 'li:first-child';
if( isset($_POST['details'])  || isset($_POST['detailslink']) ) { $active = 'li#details'; }
if( isset($_POST['ipinfo']) || isset($_POST['ipinfolink']) )  { $active = 'li#ipinfo'; }
if( isset($_POST['trends']) || isset($_POST['trendslink']) )  { $active = 'li#trends'; }
if( isset($_POST['passwords'])  || isset($_POST['passwordslink']) ) { $active = 'li#passwords'; }
if( isset($_POST['whitelist']) ) { $active = 'li#whitelist'; }
print '
<div id="tabContainer" class="shadetabs" style="background-image: none; font-family: Verdana, sans-serif;">
<ul class="shadetabs" style="margin-left: 0px; width: 100%;">
  <li id="overview" style="margin-left: 10px;"><a href="#overviewTab">Overview</a></li>
  <li id="details"><a href="#detailsTab">Details</a></li>
  <li id="ipinfo"><a href="#IPinfoTab">IP info</a></li>
  <li id="trends"><a href="#trendsTab">Trends</a></li>
';
if( $_SESSION['honeyscan']['use_pass_db'] ) { print '
  <li id="passwords"><a href="#passwordsTab">Passwords</a></li>
'; }
print '
  <li id="whitelist"><a href="#whitelistTab">Whitelist</a></li>
  <li id="about"><a href="#aboutTab">About</a></li>
</ul>
<script type="text/javascript">
$(document).ready(function(){
  $("#tabContainer").easytabs({
    animate: false,
    updateHash: false,
    defaultTab: "'.$active.'",
    tabActiveClass: "selected",
  });
});
</script>
';

// Tab overview
print '
<div id="overviewTab" style="background-color: #CFDFDE; background-image: url(../nfsen/icons/shade.png);
  background-position: top; background-repeat: repeat-x;">';
honeyscan_tabOverview();
print '</div>
';
// Tab details
print '
<div id="detailsTab" style="background-color: #CFDFDE; background-image: url(../nfsen/icons/shade.png);
  background-position: top; background-repeat: repeat-x;">';
honeyscan_tabDetails();
print '</div>
';
// Tab IPinfo
print '
<div id="IPinfoTab" style="background-color: #CFDFDE; background-image: url(../nfsen/icons/shade.png);
  background-position: top; background-repeat: repeat-x;">';
honeyscan_tabIPinfo();
print '</div>
';
// Tab trends
print '
<div id="trendsTab" style="background-color: #CFDFDE; background-image: url(../nfsen/icons/shade.png);
  background-position: top; background-repeat: repeat-x;">';
honeyscan_tabTrends();
print '</div>
';
// Tab passwords (if enabled)
if( $_SESSION['honeyscan']['use_pass_db'] ) {
print '
<div id="passwordsTab" style="background-color: #CFDFDE; background-image: url(../nfsen/icons/shade.png);
  background-position: top; background-repeat: repeat-x;">';
honeyscan_tabPasswords();
print '</div>
'; }
// Tab whitelist
print '
<div id="whitelistTab" style="background-color: #CFDFDE; background-image: url(../nfsen/icons/shade.png);
  background-position: top; background-repeat: repeat-x;">';
honeyscan_tabWhitelist();
print '</div>
';
// Tab about
print '
<div id="aboutTab" style="background-color: #CFDFDE; background-image: url(../nfsen/icons/shade.png);
  background-position: top; background-repeat: repeat-x;">';
honeyscan_tabAbout();
print '</div>
';
// Close tab container and print footer
print '</div>

<div style="color: #666666; border: 1px solid white; font-size: 9pt; text-align: right;
  padding-bottom: 20px; width: 95%;">
<img src="plugins/honeyscan/logo_mu.gif" width="50" hspace="0"
  style="vertical-align: bottom; opacity: 0.5; float: right;">
<div style="margin-top: 8px; padding-right: 55px;">
&copy; 2010, Masaryk University, Honeyscan Plugin<br>
</div>
</div>
';

} // End of honeyscan_Run


/*
 * This function displays Overview tab, backend is called to provide needed information,
 * then it prints database size and honeypot activity graphs (most active ports etc.).
 */
function honeyscan_tabOverview() {

// Call backend plugin
$command  = 'honeyscan::getOverview';
$opts     = array();
$overview = nfsend_query($command, $opts);

if( !is_array($overview) ) {
  print '<h3>&nbsp;Error while calling backend plugin</h3><br>';
  return;
}

// Set timestamp of the last saved password for the passwords tab
$_SESSION['honeyscan']['last_pw_time'] = $overview["last_pw_time"];

// Get timestamps for calling details from overview
$tend = date("Y-m-d H:i", $_SESSION['profileinfo']['updated']);
$tstart = date("Y-m-d H:i", $_SESSION['profileinfo']['updated'] - 3600*24*7);

// Print source IP activity graph
if( $overview["srcip_0"] ) {
$xaxis = "";
$xlabel = "";
$yaxis = "";
for( $i=0; $i<10; $i++ ) {
  list($x, $y, $z) = explode(" ", $overview["srcip_$i"]);
  $xaxis .= "'$x',";
  $xlabel .= "'$x ($y)',";
  $yaxis .= "$z,";
}
print '
<br>
<div id="ipGraph" style="height:320px; width: 800px; margin-left: 10px;"></div>
<script language="Javascript" type="text/javascript">
ips = ['.$xaxis.'];
$.jqplot(\'ipGraph\', [['.$yaxis.']], {
  legend:{
    show:true,
    location:\'ne\'
  },
  title:{text: \'Most active IPs in the last week\', fontFamily: \'Verdana\'},
  series: [{renderer:$.jqplot.BarRenderer, color:\'#ff0000\', label: \'Number of flows\'}],
  ClickableBars: {
    onClick: function(i, j, data) {
      //alert("ip " + ips[j]);
      details("'.$tstart.'", "'.$tend.'", ips[j], "", "");
    }
  },
  axesDefaults:{tickOptions:{fontFamily: \'Verdana\'}},
  axes:{
    xaxis:{
      renderer:$.jqplot.CategoryAxisRenderer,
      tickRenderer: $.jqplot.CanvasAxisTickRenderer,
      ticks: ['.$xlabel.'],
      tickOptions: { angle: 15, } 
    },
    yaxis:{
      min:0,
      tickOptions:{formatString:\'%d\'},
    }
  }
});
</script>
';
} else {
  print '<h3>&nbsp;Most active IPs in the last week: No data available</h3><br>';
}

// Print port activity graph
if( $overview["port_0"] ) {
$xaxis = "";
$yaxis = "";
$ports = "";
for( $i=0; $i<10; $i++ ) {
  list($x, $y) = explode(";", $overview["port_$i"]);
  $xaxis .= "'$x',";
  $yaxis .= "$y,";
  list($a, $b) = explode(" ", $x);
  $ports .= "$b,";
}
print '
<br>
<div id="portGraph" style="height:300px; width: 800px; margin-left: 10px;"></div>
<script language="Javascript" type="text/javascript">
ports = ['.$ports.'];
$.jqplot(\'portGraph\', [['.$yaxis.']], {
  legend:{
    show:true,
    location:\'ne\'
  },
  title:{text: \'Most active ports in the last week\', fontFamily: \'Verdana\'},
  series: [{renderer:$.jqplot.BarRenderer, label: \'Number of flows\'}],
  ClickableBars: {
    onClick: function(i, j, data) {
      details("'.$tstart.'", "'.$tend.'", "", "", ports[j]);
    }
  },
  axesDefaults:{tickOptions:{fontFamily: \'Verdana\'}},
  axes:{
    xaxis:{
      renderer:$.jqplot.CategoryAxisRenderer,
      ticks: ['.$xaxis.'],
    },
    yaxis:{min:0, tickOptions:{formatString:\'%d\'}}
  }
});
</script>
';
} else {
  print '<h3>&nbsp;Most active ports in the last week: No data available</h3><br>';
}

if( $_SESSION['honeyscan']['use_pass_db'] == 1 ) {
// Print graph of commonest passwords
if( $overview["password_0"] ) {
$xaxis = "";
$yaxis = "";
for( $i=0; $i<10; $i++ ) {
  list($y, $x) = explode(" ", $overview["password_$i"]);
  $xaxis .= "'$x',";
  $yaxis .= "$y,";
}
print '
<br>
<div id="passwordGraph" style="height:300px; width: 800px; margin-left: 10px;"></div>
<script language="Javascript" type="text/javascript">
pswd = ['.$xaxis.'];
$.jqplot(\'passwordGraph\', [['.$yaxis.']], {
  legend:{
    show:true,
    location:\'ne\'
  },
  title:{text: \'Most common passwords in the last week\', fontFamily: \'Verdana\'},
  series: [{renderer:$.jqplot.BarRenderer, color:\'#ff0000\', label: \'Number of passwords\'}],
  ClickableBars: {
    onClick: function(i, j, data) {
      passwords("'.$tstart.'", "'.$tend.'", "", "", pswd[j]);
    }
  },
  axesDefaults:{tickOptions:{fontFamily: \'Verdana\'}},
  axes:{
    xaxis:{
      renderer:$.jqplot.CategoryAxisRenderer,
      ticks: ['.$xaxis.'],
    },
    yaxis:{min:0, tickOptions:{formatString:\'%d\'}}
  }
});
</script>
';
} else {
  print '<h3>&nbsp;Most commmon passwords in the last week: No data available</h3><br>';
}
}

print '
<br>
<table style="margin-left: 10px;">
<tr>';
if( $_SESSION['honeyscan']['use_pass_db'] ) {
// Print shares of passwords by services
if( $overview["password_0"] ) {
$service_total = $overview["service_total"];
$pie_data = "";
for( $i=0; $i<$service_total; $i++ ) {
  list($x, $y) = explode(" ", $overview["service_$i"]);
  $pie_data .= "['$x', $y],";
}
print '<td>
<div id="servicePie" style="height:300px; width: 300px;"></div>
<script language="Javascript" type="text/javascript">
$.jqplot(\'servicePie\', [['.$pie_data.']], {
  legend: {
    show:true,
    location:\'e\'
  },
  title:{text: \'Passwords by service\', fontFamily: \'Verdana\'},
  seriesDefaults: {
    renderer: $.jqplot.PieRenderer,
    rendererOptions: { showDataLabels: true }
  }
});
</script>
</td>
';
} else {
  print '<h3>&nbsp;Passwords by service: No data available</h3><br>';
}
}

// Print other details
print '
<td>

<br>
<table width=500>
<tr>
<td>NfSen profile last update</td><td align=right>'.date("Y-m-d H:i:s", $_SESSION['profileinfo']['updated']).'</td>
</tr><tr>
';
if( $_SESSION['honeyscan']['use_pass_db'] ) {
print '<td>Timestamp of the last password</td><td align=right>'.$overview["last_pw_time"].'</td>
</tr><tr>
<td>Number of saved passwords</td><td align=right>'.$overview["pw_count"].'</td>
</tr><tr>
<td>Number of unique password</td><td align=right>'.$overview["pw_unique"].'</td>
</tr><tr>
'; }
print '<td>Total flow records saved</td><td align=right>'.$overview["table_size"].'</td>
</tr><tr>
<td>Database size</td><td align=right>'.$overview["db_size"].'</td>
</tr>
</table>

</td></tr>
</table>
<br>
';

} // End of honeyscan_tabOverview


/*
 * This function is supposed to prepare and display the captured flows from database.
 * Frontend asks backend for database content and prints the table of entries.
 * User can select database entries by specified timeslot, when the flows were captured.
 */
function honeyscan_tabDetails() {

if( $_SESSION['honeyscan']['time_start'] == NULL ) {
  $_SESSION['honeyscan']['time_start'] = date("Y-m-d H:i", $_SESSION['profileinfo']['updated'] - 300);
}
if( $_SESSION['honeyscan']['time_end'] == NULL ) {
  $_SESSION['honeyscan']['time_end'] = date("Y-m-d H:i", $_SESSION['profileinfo']['updated']);
}

// Print script for calling details from overview
print '
<script language="Javascript" type="text/javascript">
function details (tstart, tend, srcip, dstip, port) {
  detailsform.elements["time_start"].value = tstart;
  detailsform.elements["time_end"].value = tend;
  detailsform.elements["srcip"].value = srcip;
  detailsform.elements["dstip"].value = dstip;
  detailsform.elements["port"].value = port;
  detailsform.elements["detailslink"].value = "1";
  detailsform.submit();
}
</script>
';

// Print forms
print '
<form name="detailsform" id="detailsform" method="post" style="margin-left: 10px;">
<br>
Select timeslot:
<input class="plain" name="time_start" id="time_start" size="16" value="'.$_SESSION['honeyscan']['time_start'].'">
&nbsp;-&nbsp;
<input class="plain" name="time_end" size="16" value="'.$_SESSION['honeyscan']['time_end'].'">
<input type="submit" name="details" value="Submit">
<font size=2>
<br><br>
(Optional arguments)&nbsp;Source IP:
<input class="plain" name="srcip" size="16" value="'.$_SESSION['honeyscan']['srcip'].'">
&nbsp;Destination IP:
<input class="plain" name="dstip" size="16" value="'.$_SESSION['honeyscan']['dstip'].'">
&nbsp;Port:
<input class="plain" name="port" size="4" value="'.$_SESSION['honeyscan']['port'].'">
<input type="hidden" name="detailslink">
</font>
</form>
';
// End of forms

// Selected timeslot info
if( ( isset($_POST['details']) || isset($_POST['detailslink']) ) and ! $_SESSION['honeyscan']['has_errors'] ) {
  // Calling backend plugin
  $command = 'honeyscan::getDBrecord';
  $opts    = array();
  $opts['profile']      = $_SESSION['profile'];
  $opts['profilegroup'] = $_SESSION['profilegroup'];
  $opts['time_start']   = $_SESSION['honeyscan']['time_start'];
  $opts['time_end']     = $_SESSION['honeyscan']['time_end'];
  $opts['srcip']        = $_SESSION['honeyscan']['srcip'];
  $opts['dstip']        = $_SESSION['honeyscan']['dstip'];
  $opts['port']         = $_SESSION['honeyscan']['port'];
  $data = nfsend_query($command, $opts);

  if( !is_array($data) ) {
    print '<h3>&nbsp;Error while calling backend plugin</h3><br>';
    return;
  }
  if( empty($data) ) {
    print '<h3>&nbsp;No matching flows in selected timeslot!</h3><br>';
    return;
  }
  if( count($data) > 999 ) {
    print '<br>Only the first 1000 records are shown!<br>';
  }

  // Print table
  print '
<div id="table">
<table class="tablesorter" style="margin-left: 10px; width: 98%;">
<caption>Selected timeslot: '.$_SESSION['honeyscan']['time_start'].'&nbsp;-&nbsp;'.$_SESSION['honeyscan']['time_end'].'</caption>
<thead><tr>
  <th>Source&nbsp;IP</th>
  <th>Destination&nbsp;IP</th>
  <th>Protocol</th>
  <th>Destination port</th>
  <th>Flows</th>
  <th>Timestamp</th>
</tr></thead>
<tbody>
';

  // Process data
  foreach ( $data as $key=>$val ) {
    list( $srcip,$dstip,$timeslot,$proto,$dstport,$flows ) = explode( ";", $val );
    print "<tr>
      <td><a href=\"javascript:postip('$srcip', '$timeslot')\" title=\"Click for IP info\" style=\"text-decoration:none;color:red;font-weight:bold;\">$srcip</a></td>
      <td>$dstip</td>
      <td>$proto</td>
      <td>$dstport</td>
      <td>$flows</td>
      <td>$timeslot</td>
    </tr>\n";
  }

  // Close table, run tablesorter
  print '</tbody>
</table>
<script language="Javascript" type="text/javascript">
$.tablesorter.addParser({
  id: \'ips\',
  is: function(s) {return false;},
  format: function(s) {
    var a = s.split(".");
    if(a.length != 4) { return 0; }
    r = "";
    for(var i=0; i<4; i++) {
      var item = a[i];
      if(item.length == 2) {
        r += "0";
      }
      if(item.length == 1) {
        r += "00";
      }
      r += item;
    }
    return r;
  },
  type: \'numeric\'
});
$.tablesorter.addParser({
  id: \'timestamp\',
  is: function(s) {return false;},
  format: function(s) {
    var r = s.replace(/-| |:|\./g, "");
    while(r.length != 17) {
      r = r+"0";
    }
    return r;
  },
  type: \'numeric\'
});
$(function() {
  $("table").tablesorter({
    headers: {
      0: {sorter:\'ips\'},
      1: {sorter:\'ips\'},
      5: {sorter:\'timestamp\'}
    },
    sortList: [[5,0]]
  });
});
</script>
</div>
';

} // End of selected timeslot

print '<br>';

} // End of honeyscan_tabDetails function


/*
 * This function prints tab containing info about the specified IP address.
 * Info consists of IP, its domain name and geolocation.
 * Most important is table of flows from given IP to any destination in our network (not just honeypots).
 */
function honeyscan_tabIPinfo() {

if( $_SESSION['honeyscan']['time_start'] > date("Y-m-d H:i", $_SESSION['profileinfo']['updated']) ) {
  $_SESSION['honeyscan']['time_start'] = date("Y-m-d H:i", $_SESSION['profileinfo']['updated'] - 300);
}
if( $_SESSION['honeyscan']['time_end'] > date("Y-m-d H:i", $_SESSION['profileinfo']['updated']) ) {
  $_SESSION['honeyscan']['time_end'] = date("Y-m-d H:i", $_SESSION['profileinfo']['updated']);
}

// Print script for calling IP info from other tabs
print '
<script language="Javascript" type="text/javascript">
function postip (ip, time) {
  ipinfoform.elements["srcip"].value = ip;
  ipinfoform.elements["time_start"].value = time.substr(0,15) + "0";
  //ipinfoform.elements["time_end"].value = time.substr(0,15) + "9";
  ipinfoform.elements["ipinfolink"].value = "1";
  ipinfoform.submit();
}
</script>
';

// Print forms
print '
<form name="ipinfoform" method="post" style="margin-left: 10px;">
<br>
Select timeslot:
<input class="plain" name="time_start" size="16" value="'.$_SESSION['honeyscan']['time_start'].'">
&nbsp;-&nbsp;
<input class="plain" name="time_end" size="16" value="'.$_SESSION['honeyscan']['time_end'].'">
<input type="hidden" name="ipinfolink">
<br><br>
Select IP:
<input class="plain" name="srcip" size="16" value="'.$_SESSION['honeyscan']['srcip'].'">
<input type="submit" name="ipinfo" value="Submit">
</form>
';
// End of forms

// Selected IP and timeslot info
if( ( isset($_POST['ipinfo']) || isset($_POST['ipinfolink']) ) and ! $_SESSION['honeyscan']['has_errors'] ) {
  // Check srcip
  if( ! isset($_SESSION['honeyscan']['srcip']) ) {
    print 'IP address not specified!<br>';
    exit;
  }

  // Calling backend plugin
  $command = 'honeyscan::getIPinfo';
  $opts    = array();
  $opts['profile']      = $_SESSION['profile'];
  $opts['profilegroup'] = $_SESSION['profilegroup'];
  $opts['time_start']   = $_SESSION['honeyscan']['time_start'];
  $opts['time_end']     = $_SESSION['honeyscan']['time_end'];
  $opts['srcip']        = $_SESSION['honeyscan']['srcip'];
  $data = nfsend_query($command, $opts);

  if( !is_array($data) ) {
    print '<h3>&nbsp;Error while calling backend plugin</h3><br>';
    return;
  }

  // Print IP info
  if($data['hostname'] == "") { $data['hostname'] = "-"; }
  if($data['country'] == "") { $data['country'] = "-"; }
  print '
<table class="tablesorter" style="margin-left: 10px; width: 40%">
<tr><td>IP</td><td>'.$_SESSION['honeyscan']['srcip'].'</td></tr>
<tr><td>Hostname</td><td>'.$data['hostname'].'</td></tr>
<tr><td>Country</td><td>'.$data['country'].'</td></tr>
</table>
<br>';
  unset($data['hostname']);
  unset($data['country']);

  if( empty($data) ) {
    print '<h3>&nbsp;No matching flows in selected timeslot!</h3><br>';
    return;
  }

  // Print table, process data, run tablesorter
  if( count($data) > 999 ) {
    print '<br>Only the first 1000 records are shown!<br>';
  }
  print '
<div id="table">
<table class="tablesorter" style="margin-left: 10px; width: 98%;">
<caption>Selected timeslot: '.$_SESSION['honeyscan']['time_start'].'&nbsp;-&nbsp;'.$_SESSION['honeyscan']['time_end'].'</caption>
<thead><tr>
  <th>Source&nbsp;IP</th>
  <th>Destination&nbsp;IP</th>
  <th>Protocol</th>
  <th>Destination port</th>
  <th>Flows</th>
  <th>Timestamp</th>
</tr></thead>
<tbody>';
  foreach ( $data as $key=>$val ) {
    list( $srcip,$dstip,$timeslot,$proto,$dstport,$flows ) = explode( ";", $val );
    print "<tr>
      <td><b style=\"color: red\">$srcip</b></td>
      <td>$dstip</td>
      <td>$proto</td>
      <td>$dstport</td>
      <td>$flows</td>
      <td>$timeslot</td>
    </tr>\n";
  }
  print '</tbody>
</table>
<script language="Javascript" type="text/javascript">
$.tablesorter.addParser({
  id: \'ips\',
  is: function(s) {return false;},
  format: function(s) {
    var a = s.split(".");
    if(a.length != 4) { return 0; }
    r = "";
    for(var i=0; i<4; i++) {
      var item = a[i];
      if(item.length == 2) {
        r += "0";
      }
      if(item.length == 1) {
        r += "00";
      }
      r += item;
    }
    return r;
  },
  type: \'numeric\'
});
$.tablesorter.addParser({
  id: \'timestamp\',
  is: function(s) {return false;},
  format: function(s) {
    var r = s.replace(/-| |:|\./g, "");
    while(r.length != 17) {
      r = r+"0";
    }
    return r;
  },
  type: \'numeric\'
});
$(function() {
  $("table").tablesorter({
    headers: {
      0: {sorter:\'ips\'},
      1: {sorter:\'ips\'},
      5: {sorter:\'timestamp\'}
    },
    sortList: [[5,0]]
  });
});
</script>
</div>';
}

print '<br>';

} // End of honeyscan_tabIPinfo function


/*
 * This is the trend plotting function. It prints tab with trend graph.
 * Trend is number of occurrences of some item by day in the last half year.
 * Item can be source IP, port, password, username...
 */
function honeyscan_tabTrends() {

// Print script for calling trends from the other tabs
print '
<script language="Javascript" type="text/javascript">
function trends (item, value) {
  trendsform.elements["item"].value = item;
  trendsform.elements["value"].value = value;
  trendsform.elements["trendslink"].value = "1";
  trendsform.submit();
}
</script>
';

// Print forms
print '
<form name="trendsform" method="post" style="margin-left: 10px;">
<br>Item:&nbsp;
<select name="item">
<option value="flows">All flows</option>
<option value="srcip"';
if( $_SESSION['honeyscan']['item'] == "srcip" ) print ' selected="selected"';
print '>Source IP</option>
<option value="dstip"';
if( $_SESSION['honeyscan']['item'] == "dstip" ) print ' selected="selected"';
print '>Destination IP</option>
<option value="proto"';
if( $_SESSION['honeyscan']['item'] == "proto" ) print ' selected="selected"';
print '>Protocol</option>
<option value="dstport"';
if( $_SESSION['honeyscan']['item'] == "dstport" ) print ' selected="selected"';
print '>Port</option>
';
if( $_SESSION['honeyscan']['use_pass_db'] ) {
print '<option disabled="disabled">----------</option>
<option value="dict"';
if( $_SESSION['honeyscan']['item'] == "dict" ) print ' selected="selected"';
print '>All paswords</option>
<option value="username"';
if( $_SESSION['honeyscan']['item'] == "username" ) print ' selected="selected"';
print '>Username</option>
<option value="password"';
if( $_SESSION['honeyscan']['item'] == "password" ) print ' selected="selected"';
print '>Password</option>
<option value="service"';
if( $_SESSION['honeyscan']['item'] == "service" ) print ' selected="selected"';
print '>Service</option>
'; }
print '</select>
&nbsp;Value:&nbsp;
<input class="plain" name="value" size="16" value="'.$_SESSION['honeyscan']['value'].'">
&nbsp;<input type="submit" name="trends" value="Submit">
<input type="hidden" name="trendslink">
</form>
';

// Passwords in selected timeslot
if( isset($_POST['trends']) ) {
  // Calling backend plugin
  $command = 'honeyscan::getTrend';
  $opts    = array();
  $opts['item']  = $_SESSION['honeyscan']['item'];
  $opts['value'] = $_SESSION['honeyscan']['value'];
  $data = nfsend_query($command, $opts);

  if( !is_array($data) ) {
    print '<h3>&nbsp;Error while calling backend plugin</h3><br>';
    return;
  }
  if( empty($data) ) {
    print '<h3>&nbsp;No data found!</h3><br>';
    return;
  }

  // Sort data by key, print graph
  ksort($data);
  $counter = 7;
  $xaxis = "";
  $yaxis = "";
  foreach ($data as $key => $val) {
    if ($counter == 7) {
      $counter = 1;
      $xaxis .= "'$key',";
    } else {
      $counter++;
      $xaxis .= "' ',";
    }
    $yaxis .= "$val,";
  }
  print '
<br>
<div id="trendGraph" style="height:300px; width: 1600px; margin-left: 10px;"></div>
<script language="Javascript" type="text/javascript">
$.jqplot(\'trendGraph\', [['.$yaxis.']], {
  legend:{
    show:false,
  },
  series: [{
    color:\'#ff0000\',
    markerOptions: { show: false }
  }],
  axesDefaults:{
    tickOptions:{fontFamily: \'Verdana\'}
  },
  axes:{
    xaxis:{
      renderer:$.jqplot.CategoryAxisRenderer,
      tickRenderer: $.jqplot.CanvasAxisTickRenderer,
      ticks: ['.$xaxis.'],
      tickOptions: { angle: 15, }
    },
    yaxis:{min:0, tickOptions:{formatString:\'%d\'}}
  }
});
</script>
';

}

print '<br>';

} // End of honeyscan_tabtrends function


/*
 * This function presents passwords captured by honeypots
 * and stored in the database. User is allowed to specify
 * which passwords to display by typing timeslot.
 */
function honeyscan_tabPasswords() {

if( $_SESSION['honeyscan']['pw_start'] == NULL ) {
  $_SESSION['honeyscan']['pw_start'] = substr($_SESSION['honeyscan']['last_pw_time'], 0, 15)."0";
}

// Print script for calling passwords from overview
print '
<script language="Javascript" type="text/javascript">
function passwords (tstart, tend, service, username, password) {
  passwordsform.elements["pw_start"].value = tstart;
  passwordsform.elements["pw_end"].value = tend;
  passwordsform.elements["pw_service"].value = service;
  passwordsform.elements["pw_username"].value = username;
  passwordsform.elements["pw_password"].value = password;
  passwordsform.elements["passwordslink"].value = "1";
  passwordsform.submit();
}
</script>
';

// Print forms
print '
<form name="passwordsform" method="post" style="margin-left: 10px;">
<br>
Select timeslot:
<input class="plain" name="pw_start" size="16" value="'.$_SESSION['honeyscan']['pw_start'].'">
&nbsp;-&nbsp;
<input class="plain" name="pw_end" size="16" value="'.$_SESSION['honeyscan']['pw_end'].'">
&nbsp;<input type="submit" name="passwords" value="Submit">
<br><br>(Optional arguments)&nbsp;Service:
<input class="plain" name="pw_service" size="4" value="'.$_SESSION['honeyscan']['pw_service'].'">
&nbsp;Username:
<input class="plain" name="pw_username" size="16" value="'.$_SESSION['honeyscan']['pw_username'].'">
&nbsp;Password:
<input class="plain" name="pw_password" size="16" value="'.$_SESSION['honeyscan']['pw_password'].'">
<input type="hidden" name="passwordslink">
</form>
';

if( isset($_POST['passwords']) || isset($_POST['passwordslink']) ) {
  // Calling backend plugin
  $command = 'honeyscan::getPassword';
  $opts    = array();
  $opts['pw_start']    = $_SESSION['honeyscan']['pw_start'];
  $opts['pw_end']      = $_SESSION['honeyscan']['pw_end'];
  $opts['pw_service']  = $_SESSION['honeyscan']['pw_service'];
  $opts['pw_username'] = $_SESSION['honeyscan']['pw_username'];
  $opts['pw_password'] = $_SESSION['honeyscan']['pw_password'];
  $data     = nfsend_query($command, $opts);

  if( !is_array($data) ) {
    print '<h3>&nbsp;Error while calling backend plugin</h3><br>';
    return;
  }
  if( empty($data) ) {
    print '<h3>&nbsp;No matching password records in selected timeslot!</h3><br>';
    return;
  }
  if( count($data) > 999 ) {
    print '<br>Only the first 1000 records are shown!<br>';
  }

  print '<div id="table">
<table class="tablesorter" style="margin-left: 10px; width: 98%;">
<caption>Selected timeslot: '.$_SESSION['honeyscan']['pw_start'].'&nbsp;-&nbsp;'.$_SESSION['honeyscan']['pw_end'].'</caption>
<thead><tr>
  <th>Remote host</th>
  <th>Honeypot</th>
  <th>Service</th>
  <th>Username</th>
  <th>Password</th>
  <th>Timestamp</th>
</tr></thead>
<tbody>
';
  foreach ( $data as $key=>$val ) {
    list( $timestamp,$rhost,$host,$service,$username,$password ) = explode( ";", $val, 6 );
    print "
    <tr>
    <td><a href=\"javascript:details('".$_SESSION['honeyscan']['pw_start']."', '".$_SESSION['honeyscan']['pw_end']."','$rhost', '', '')\"
      title=\"Click for flows for this IP\"
      style=\"text-decoration:none;color:red;font-weight:bold;\">$rhost</a></td>
    <td>$host</td>
    <td>$service</td>
    <td>$username</td>
    <td>$password</td>
    <td>$timestamp</dt>
    </tr>";
  }
  print '
</tbody>
</table>
<script language="Javascript" type="text/javascript">
$.tablesorter.addParser({
  id: \'ips\',
  is: function(s) {return false;},
  format: function(s) {
    var a = s.split(".");
    if(a.length != 4) { return 0; }
    r = "";
    for(var i=0; i<4; i++) {
      var item = a[i];
      if(item.length == 2) {
        r += "0";
      }
      if(item.length == 1) {
        r += "00";
      }
      r += item;
    }
    return r;
  },
  type: \'numeric\'
});
$(function() {
  $("table").tablesorter({
    headers: {
      0: {sorter:\'ips\'},
      1: {sorter:\'ips\'},
    },
    sortList: [[5,0]]
  });
});
</script>
</div>
';
} // End of table printing

print '<br>';

} // End of honeyscan_tabPasswords function


/*
 * This function is supposed to present actual whitelist
 * and let user to add/remove IPs from it.
 */
function honeyscan_tabWhitelist() {

// Calling backend
$command = "honeyscan::whitelist";
$opts = array();
if( isset($_POST['whitelisttext']) ) {
  $content = preg_split( '/\s+/', $_POST['whitelisttext'] );
  $counter = 0;
  foreach( $content as $value ) {
    $counter++;
    $opts[ "value_$counter" ] = $value;
  }
  $opts['count'] = $counter;
}
$whitelist = nfsend_query($command, $opts);

if( !is_array($whitelist) ) {
  print '<h3>&nbsp;Error while calling backend plugin</h3><br>';
  return;
}

// Print form and whitelist content
print '
<form name="whitelistform" method="post" style="margin-left: 10px;">
<br>
Whitelist content:
<br><br>
<textarea name="whitelisttext" cols=32 rows=32>';
natsort($whitelist);
foreach($whitelist as $key=>$val) {
  print "$val\n";
}
print '</textarea>
<br><br>
<input type="submit" name="whitelist" value="Submit changes">
</form>
<br><br>
';

} // End of honeyscan_tabWhitelist function


/*
 * This function prints tab About.
 */
function honeyscan_tabAbout() {

print '
<br>
<div id="innerAbout" style="background-color: white; border: 2px solid black; font-size: 14;
  width: 780px; padding: 25px 25px 25px 25px; margin: 20px 10px 10px 20px;">
<img src="plugins/honeyscan/logo_mu.gif" alt="Masaryk University" hspace="130" style="vertical-align: middle;">
<img src="plugins/honeyscan/logo_csirt.png" alt="CSIRT-MU" hspace="70" style="vertical-align: middle;">
<br>
<b>Honeyscan - honeynet monitoring plugin for NfSen</b> provides information about activity of honeypot network based on NetFlow data.
IPv4 and IPv6 is supported, legitimate IP addresses can be whitelisted.
Honeyscan detects unauthorized accesses to the honeypot network, stores authentication attempts to honeypot services and reports accesses from local network.
Honeyscan also reports dictionary attackers and massive accesses to honeypots that threatens local network.
Web interface is provided to present captured flows, passwords and statistics.
<br><br>
<b>Version: 1.0.0</b>
<br>
<h3>License</h3>
<ul>
<li type="disc" style="display: list-item;">The plugin frontend includes the third party software components
JQuery, easyTabs and jqPlot distributed under the MIT License.
<li type="disc" style="display: list-item;">The plugin backend uses the third party software component PostgreSQL database.
<li type="disc" style="display: list-item;">The plugin backend and frontend code is available under the BSD License.
</ul>
<h3>BSD License</h3>
Copyright &copy; 2010-2012 Masaryk University<br>
All rights reserved.
<br><br>
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
<br><br>
<ul>
<li type="disc" style="display: list-item;">Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.
<li type="disc" style="display: list-item;">Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or other materials
provided with the distribution.
<li type="disc" style="display: list-item;">Neither the name of the Masaryk University nor the names of its contributors
may be used to endorse or promote products derived from this software without specific prior written permission.
</ul>
<br>
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COMPANY BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
</div>
<br>
';

} // End of honeyscan_tabAbout function


?>
