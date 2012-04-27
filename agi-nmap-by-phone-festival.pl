#!/usr/bin/perl
#
# AGI Script that prompts the user for an ip address, scans the ip, and reports back to the user.
#
# Requires the Asterisk::AGI and Nmap::Parser perl modules
#
# Written by: Black Rathchet (blackratchet@blackratchet.org): http://www.oldskoolphreak.com
# enhanced and modified by: Christoph Eicke (christoph@geisterstunde.org): http://www.geisterstunde.org
# 

use Asterisk::AGI;
use Nmap::Parser;
use File::Basename;
use Digest::MD5 qw(md5_hex);

my $nmap_logfile = "/var/log/asterisk/nmap.log";
my $ttsdir = "/usr/share/asterisk/sounds/tts";

# speaks a string of text
sub speak(){
    $text = $_[0];

    my $hash = md5_hex($text);

    my $wavefile = "$ttsdir/tts-$hash.ulaw";

    unless (-f $wavefile) {
	system("echo $text | /usr/bin/text2wave -F 8000 -otype ulaw -o $wavefile");
    }

    $filename = 'tts/'.basename('tts/'.basename($wavefile,".ulaw"));

    $AGI->exec('Playback', $filename);

    unlink("$wavefile");

}

$AGI = new Asterisk::AGI;

my %input = $AGI->ReadParse();

my ($caller) = $input{callerid} =~ /<(\d+)>/;
if (!defined $caller) {
    ($caller) = $input{callerid} =~ /(\d+)/;
}

my $finished = 0;

&speak("Enter the eye-p address you wish to scan.");

my $ipaddr = '';
my $x = 0;

# While we don't have a complete IP address, have the user enter one
# using '#' for '.'...
while (!$finished) {
	my $input = chr($AGI->wait_for_digit('5000'));
	if ($input =~ /^[0-9\*\#]$/) {
		if ($input =~ /^[\*\#]$/) {
			$x++;
			if ($x > 3) {
				$finished = 1;
			} else {
				$ipaddr .= '.';
			}
		
		} else {
			$ipaddr .= $input;
		}
	} else {
			#must have timed out
			$finished = 1;
	}

	if ( length($ipaddr) > 14) {
		$finished = 1;
	}
}

open(LOG,">>$nmap_logfile");
print LOG localtime(time) . " - $caller - $ipaddr\n";

# Double check the address is valid...
if ($ipaddr !~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {
	&speak("Invalid Address: $ipaddr");
	exit 0;
}

&speak("Please wait, scan is in progress.");

# Set up a new Nmap::Parser object
my $np = new Nmap::Parser;

$nmap_exe = '/usr/local/bin/nmap';

$np->callback(\&host_handler);

# Scan the host given.
$np->parsescan($nmap_exe,'-sT -p1-1023', $ipaddr);

# Do this after every host scanned
sub host_handler {
	my $host_obj = shift; #an instance of Nmap::Parser::Host (for current)

	&speak("Host " . $host_obj->hostname() . " found with " . $host_obj->tcp_port_count() . " ports open");

	# Make and array of all the ports.
	my @ports = $host_obj->tcp_open_ports();

	# For every port, speak the port number and service.
	foreach $port (@ports){
		&speak("Open port found, " . $host_obj->tcp_service($port)->name. " on port " . $port);
	}
	&speak("Scan completed! Good bye.");
	
	exit;
	close(LOG);
}

# If a host was found, we shouldn't get here.
&speak("No host found with eye-p address " . $ipaddr . "! Good bye.");

exit;
close(LOG);


