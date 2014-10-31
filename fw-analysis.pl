#!/usr/bin/perl
#

use strict;
use warnings;
use feature qw( switch );
use Term::ANSIColor;
use Data::Dumper;
use Getopt::Long;

my $_depth = "10";
#my $_config = "fwa.conf";

#if ((defined($config)) && ($config ne "") { $config = $_config; }

#my $cfg = new Config::Simple($config);
#if (!defined($depth)) {	$depth = $cfg->param('Depth'); }
#if (!defined($nodns)) { $nodns = $cfg->param('NoDNS'); }
#if (!defined($nocolor)) { $nocolor = $cfg->param('NoColor'); }


my ($help, $depth, $nodns, $nocolor);
GetOptions(
	'h|help'	=> \$help,
	'd|depth=s'	=> \$depth,
	'n|no-dns'	=> \$nodns,
	'nc|no-color'	=> \$nocolor
);

if ($help) { &Usage(); }

if (&check_perl_mods()) {
	use Net::Nslookup;
	use Geo::IP::PurePerl;
	use Date::Calc qw(:all);
	#use Config::Simple;
}

if (($depth) && ($depth ne "") && ($depth =~ /\d+/)) { $_depth = $depth; }

&check_geoip_db();

my $settings = &get_net_and_dhcp_info();

my @lines;
# get the lines of packets dropped by the FW
open FILE, "</var/log/messages" or die "Couldn't open messages file: $! \n";
while (my $line = <FILE>) {
	chomp($line);
	push(@lines, $line);
}
close FILE or die "Couldn't close messages file: $! \n";

my $gip = Geo::IP::PurePerl->open('/usr/share/GeoIP/GeoIP.dat', GEOIP_MEMORY_CACHE);
my (%iface_pkts, %inbound_pkts, %outbound_pkts, %dports, %dests, %srcs, %protos, %watched, %protoport, %src_countries, %dest_countries, %filters);
foreach my $line (@lines) {
	#Oct 24 18:57:15 swe kernel: [171040.374665] Denied-by-filter:INPUT IN=eth1 OUT= MAC=00:21:9b:fc:95:c4:00:01:5c:64:ae:46:08:00 SRC=184.105.247.254 DST=76.167.67.20 LEN=51 TOS=0x00 PREC=0x00 TTL=54 ID=22438 DF PROTO=UDP SPT=44236 DPT=623 LEN=31
	# We'll start with a rough glossing over.
	my $src; my $dst;
	if ( $line =~ /IN=(.*?) / ) { $iface_pkts{$1}++; }
	if ( $line =~ /SRC=(.*?) / ) { $src = $1; $srcs{$src}++; }
	if ( $line =~ /DST=(.*?) / ) { $dst = $1; $dests{$dst}++; }
	if ( $line =~ /DPT=(.*?) / ) { $dports{$1}++; }
	if ( $line =~ /PROTO=(.*?) / ) { $protos{$1}++; }
	if ( $line =~ /PROTO=TCP SPT=.*? DPT=(?:8[01]|44[13]) / ) { $watched{'http(s)'}++; }
	if ( $line =~ /PROTO=TCP SPT=.*? DPT=22 / ) { $watched{'ssh'}++; }
	if ( $line =~ /PROTO=UDP SPT=.*? DPT=123 / ) { $watched{'ntp'}++; }
	if ( $line =~ /PROTO=UDP SPT=.*? DPT=53 / ) { $watched{'dns'}++; }
	if ( $line =~ /PROTO=TCP SPT=.*? DPT=21 / ) { $watched{'ftp'}++; }
	if ( $line =~ /PROTO=TCP SPT=.*? DPT=23 / ) { $watched{'telnet'}++; }
	if ( $line =~ /PROTO=TCP SPT=.*? DPT=25 / ) { $watched{'smtp'}++; }
	if ( $line =~ /PROTO=(.*?) SPT=.*? DPT=(.*?) / ) { $protoport{"$1/$2"}++; }
	if ( $line =~ /Denied-by-filter:([a-zA-Z]+)/ ) { 
		my $f = $1;
		next if ((!defined($f)) || ($f eq ""));
		$filters{$1}++; 
	}
	my $country = $gip->country_name_by_addr($src);
	if ((!defined($country)) || ($country eq "")) { $country = 'XX'; }
	$src_countries{$country}++;
	$country = $gip->country_name_by_addr($dst);
	if ((!defined($country)) || ($country eq "")) { $country = 'XX'; }
	$dest_countries{$country}++;
}

my $i = 0;

print "=" x 72;
print "\n";
if ($nocolor) {
	print "Number of packets per interface:\n";
	print "================================\n";
} else {
	print colored("Number of packets per interface:\n", "cyan");
	print colored("================================\n", "cyan");
}
foreach my $p ( sort keys %iface_pkts ) {
	#print "$p => ". nslookup($p) . " ==> $iface_pkts{$p}\n";
	if ($nocolor) {
		print "$p";
	} else {
		print colored("$p", "$settings->{$p}");
	}
	print "\t=>\t$iface_pkts{$p}\n";
}
if ($nocolor) {
	print "\nNumber of packets per filter:\n";
	print "=============================\n";
} else {
	print colored("\nNumber of packets per filter:\n", "cyan");
	print colored("=============================\n", "cyan");
}
foreach my $f ( sort { $filters{$b} <=> $filters{$a} } keys %filters ) {
	if (length($f) <= 7) {
		print "$f\t\t$filters{$f}\n";
	} else {
		print "$f:\t$filters{$f}\n";
	}
}

print "\nNumber of unique source IPs: ";
if ($nocolor) {	print scalar(keys(%srcs)) . "\n"; }
else { print colored(scalar(keys(%srcs)) . "\n", "green"); }
if ($nocolor) {
	print "Top $_depth sources:\n";
	print "===============\n";
} else {
	print colored("Top $_depth sources:\n", "cyan");
	print colored("===============\n", "cyan");
}
foreach my $s ( sort { $srcs{$b} <=> $srcs{$a} } keys %srcs ) {
	my $name;
	unless ($nodns) {
		$name = nslookup('host' => $s, 'type' => "PTR");
		if ((!defined($name)) || ($name eq "")) { $name = 'UNRESOLVED'; }
		if (($name eq "UNRESOLVED") && (exists($settings->{'lease_hash'}{$s}))) {
			$name = $settings->{'lease_hash'}{$s};
		}
		if ($name eq "UNRESOLVED") {
			$name = nslookup('host' => $s, 'type' => 'A', 'server' => '127.0.0.1');
		}
		if ((!defined($name)) || ($name eq "")) { $name = 'UNRESOLVED'; }
	}
	my $cc = $gip->country_code_by_addr($s);
	if ((!defined($cc)) || ($cc eq "")) { $cc = 'XX'; }
	if ($nodns) { print "$s => $srcs{$s} ($cc) \n"; }
	else { print "$s => $name => $srcs{$s} ($cc) \n"; }
	$i++;
	last if ( $i >= $_depth );
}

$i = 0;
print "\nNumber of unique destination IPs: ";
if ($nocolor) { print scalar(keys(%dests)) . "\n"; }
else { print colored(scalar(keys(%dests)) . "\n", "green"); }
if ($nocolor) {
	print "Top $_depth Destinations:\n";
	print "====================\n";
} else {
	print colored("Top $_depth Destinations:\n", "cyan");
	print colored("====================\n", "cyan");
}
foreach my $d ( sort { $dests{$b} <=> $dests{$a} } keys %dests ) {
	my $name;
	unless ($nodns) {
		$name = nslookup('host' => $d, 'type' => "PTR");
		if ((!defined($name)) || ($name eq "")) { $name = "UNRESOLVED"; }
		if (($name eq "UNRESOLVED") && (exists($settings->{'lease_hash'}{$d}))) {
			$name = $settings->{'lease_hash'}{$d};
		}
	}
	my $cc = $gip->country_code_by_addr($d);
	if ((!defined($cc)) || ($cc eq "")) { $cc = 'XX'; }
	if ($nodns) { print "$d => $dests{$d} ($cc) \n"; }
	else { print "$d => $name => $dests{$d} ($cc) \n"; }
	$i++;
	last if ( $i >= $_depth );
}

if ($nocolor) {
	print "\nWatched protocols:\n";
	print "====================\n";
} else {
	print colored("\nWatched protocols:\n", "cyan");
	print colored("====================\n", "cyan");
}
foreach my $k ( sort keys %watched ) {
	print "$k\t=>\t$watched{$k}\n";
}

$i = 0;
if ($nocolor) {
	print "\nTop $_depth Proto/Port's:\n";
	print "======================\n";
} else {
	print colored("\nTop $_depth Proto/Port's:\n", "cyan");
	print colored("======================\n", "cyan");
}
foreach my $k ( sort { $protoport{$b} <=> $protoport{$a} } keys %protoport ) {
	my $tabs = "";
	if (length($k) >= 8) {
		$tabs = "\t";
	} else {
		$tabs = "\t\t";
	}
	print "$k$tabs=>\t$protoport{$k}\n";
	$i++;
	last if ( $i >= $_depth );
}

$i = 0;
if ($nocolor) {
	print "\nTop $_depth Source Countries:\n";
	print "==========================\n";
} else {
	print colored("\nTop $_depth Source Countries:\n", "cyan");
	print colored("==========================\n", "cyan");
}
foreach my $sc ( sort { $src_countries{$b} <=> $src_countries{$a} } keys %src_countries ) {
	my $tabs = "";
	if (length($sc) >= 17) {
		$tabs = "\t";
	} elsif ((length($sc) < 17) && (length($sc) > 7)) {
		$tabs = "\t\t";
	} elsif (length($sc) <= 7) {
		$tabs = "\t\t\t";
	}

	print "$sc$tabs=>\t$src_countries{$sc}\n";
	$i++;
	last if ( $i >= $_depth );
}

$i = 0;
if ($nocolor) {
	print "\nTop $_depth Destination Countries:\n";
	print "===============================\n";
} else {
	print colored("\nTop $_depth Destination Countries:\n", "cyan");
	print colored("===============================\n", "cyan");
}
foreach my $dc ( sort { $dest_countries{$b} <=> $dest_countries{$a} } keys %dest_countries ) {
	my $tabs = "";
	if (length($dc) >= 9) {
		$tabs = "\t";
	} else {
		$tabs = "\t\t";
	}
	print "$dc$tabs=>\t$dest_countries{$dc}\n";
	$i++;
	last if ( $i >= $_depth );
}

exit 0;

#######################################################################
sub Usage() {
	print <<EOF;
$0 [-h|--help] [-d|--depth <depth>] [-n|--no-dns] [-nc|--no-color]

-h|--help	Displays this message and exits.
-d|--depth	Sets the "Top X" number.  Default is 10.  Setting a value of 0 displays all.
-n|--no-dns	Turns off any name resolution.
-nc|--no-color	Turns off colorised output.

EOF

	exit 0;
}

sub check_geoip_db() {
	if ( -f "/usr/share/GeoIP/GeoIP.dat" ) {
		use Data::Dumper;
		my @stats = stat("/usr/share/GeoIP/GeoIP.dat");
		#print Dumper(@stats);
		my $time = time();
		if (($time - $stats[10]) >= 2592000) {
			if ($nocolor) { print "GeoIP.dat file is over 30 days old.  Consider updating.\n"; } 
			else { print colored("GeoIP.dat file is over 30 days old.  Consider updating.\n", "yellow"); }
		} else {
			if ($nocolor) { print "GeoIP.dat OK.\n"; }
			else { print colored("GeoIP.dat OK.\n", "green"); }
		}
	} else {
		if ($nocolor) {	print "Couldn't find GeoIP.dat.\n"; }
		else { print colored("Couldn't find GeoIP.dat.\n", "red"); }
	}
}

sub check_perl_mods() {
	my $status = 0;
	my @mods = ("Net::Nslookup", "Geo::IP::PurePerl", "Date::Calc", "Config::Simple");
	foreach my $mod ( @mods ) {
		my $result = `/usr/bin/perl -m$mod -e ";" 2>&1`;
		if ($result =~ /^Can't locate /) {
			if ($nocolor) { print "Couldn't find $mod. Please run the included script: install-mods.sh.\n" }
			else { print colored("Couldn't find $mod. Please run the included script: install-mods.sh.\n", "red"); }
			$status = 1
		} elsif ((! defined($result)) || $result eq "") {
			if ($nocolor) { print "$mod OK.\n" }
			else { print colored("$mod OK.\n", "green"); }
			$status = 1
		} else {
			if ($nocolor) { print "$result\n"; }
			else { print colored("$result\n", "red"); }
			$status = 0
		}
		if ($status == 0) { return $status; }
	}
	#system("sed -i -e 's/#\(use .*\)/\1/g' $0");
	return $status;
}

sub get_net_and_dhcp_info() {
	my %ndsettings;
	my $leases = "/usr/etc/dhcpd.leases";
	if ( -f "/var/smoothwall/dhcp/enable" ) { $ndsettings{'dhcp_enabled'} = 1; }
	open ETH, "</var/smoothwall/ethernet/settings" or die "Couldn't open ethernet settings file: $! \n";
	while (my $line = <ETH>) {
		chomp($line);
		if ($line =~ /GREEN_DEV=(.*)/) { $ndsettings{$1} = "green"; }
		if ($line =~ /RED_DEV=(.*)/) { $ndsettings{$1} = "red"; }
		if ($line =~ /GREEN_NETADDRESS=(.*)/) { $ndsettings{'green net addr'} = $1; }
		if ($line =~ /GREEN_BROADCAST=(.*)/) { $ndsettings{'green net bdcst'} = $1; }
	}
	close ETH or die "Couldn't close ethernet settings file: $! \n";

	open LEAS, "</usr/etc/dhcpd.leases";
	my $lease_data = do { local $/; <LEAS> };
	close LEAS;

	my @records = split(/\}/, $lease_data);

	foreach my $r (@records) {
		$r =~ /lease ([0-9.]+) {.*?starts \d .*?([0-9:\/ ]+).*?ends \d .*?([0-9:\/ ]+).*?binding state (active|free).*?client-hostname "(.*?)";/s;
		my $ip = $1; my $start = $2; my $end = $3; my $state = $4; my $name = $5;
		my ($Sy, $Sm, $Sd, $Sh, $Smm, $Ss) = &parse_datetime($start);
		next if ((!defined($Sy)) || ($Sy eq "")); 
		my $lower = Date_to_Days($Sy,$Sm,$Sd);
		my ($Ey, $Em, $Ed, $Eh, $Emm, $Es) = &parse_datetime($end);
		next if ((!defined($Ey)) || ($Ey eq ""));
		my $upper = Date_to_Days($Ey, $Em, $Ed);
		my $gmt = gmtime();
		my ($tyear, $tmo, $tday, $thour, $tmin, $tsec) = Today_and_Now($gmt);
		my $date = Date_to_Days($tyear, $tmo, $tday);
		#if (($date >= $lower) && ($date <= $upper)) {
			$ndsettings{'lease_hash'}{$ip} = $name;
		#}
	}
	
	return \%ndsettings;
}

sub parse_datetime($) {
	no warnings;
	my $dstr = shift(@_);
	my ($date, $time) = split(/ /, $dstr);
	my ($y, $m, $d) = split(/\//, $date);
	my ($h, $mm, $s) = split(/:/, $time);

	return ($y, $m, $d, $h, $mm, $s);
}
