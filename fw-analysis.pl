#!/usr/bin/perl -w


use strict;
use warnings;
use feature qw( switch );
use Term::ANSIColor;
use Data::Dumper;
use Getopt::Long;
use File::Fetch;
use IO::Uncompress::Gunzip qw( gunzip $GunzipError );

my $_depth = "10";
#my $_config = "fwa.conf";

#if ((defined($config)) && ($config ne "") { $config = $_config; }

#my $cfg = new Config::Simple($config);
#if (!defined($depth)) {	$depth = $cfg->param('Depth'); }
#if (!defined($nodns)) { $nodns = $cfg->param('NoDNS'); }
#if (!defined($nocolor)) { $nocolor = $cfg->param('NoColor'); }


my ($help, $depth, $nodns, $nocolor, $srcip, $dstip, $html);
GetOptions(
	'h|help'		=>	\$help,
	'd|depth=s'		=>	\$depth,
	'n|no-dns'		=>	\$nodns,
	'nc|no-color'	=>	\$nocolor,
	'srcip=s'		=>	\$srcip,
	'html'			=>	\$html,
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

my $settings;

# FIX ME:  This should check for the DHCP "enable" flag, or
# it should check for a valid ethernet settings file.  The sub
# doesn't use the settings from the DHCP config, but it does
# use the ethernet settings.
# Chenging this to check for a valid settings file, for now.
if (-e "/var/smoothwall/dhcp/settings-green" && !-z "/var/smoothwall/dhcp/settings-green") {
	$settings = &get_net_and_dhcp_info();
} else {
	print "DHCP settings file not found.  Is this a smoothwall system?\n";
	my $ans = readline();
	chomp($ans);
	if ($ans =~ /[Yy](?:es)?/) {
		die "Unable to locate valid DHCP settings file.  Verify location and try again.\n";
	} else {
		# get settings from ipconfig??
	}
}

my @lines;
# get the lines of packets dropped by the FW
open FILE, "</var/log/messages" or die "Couldn't open messages file: $! \n";
while (my $line = <FILE>) {
	chomp($line);
	if ($line =~ /kernel:/) { push(@lines, $line); }
}
close FILE or die "Couldn't close messages file: $! \n";

my $gip = Geo::IP::PurePerl->open('/usr/share/GeoIP/GeoIP.dat', GEOIP_MEMORY_CACHE);

if ($srcip) {
	@lines = grep { / SRC=$srcip / } @lines;
	#foreach my $line ( @lines ) {
		#next unless ($line =~ /SRC=$srcip/);
		#print "$line\n";
	#}
	#exit 0;
}
if ($dstip) {
	@lines = grep { / DST=$dstip / } @lines;
}

my (%iface_pkts, %inbound_pkts, %outbound_pkts, %dports, %dests, %srcs, %protos, %watched, %protoport, %src_countries, %dest_countries, %filters, %packets);
foreach my $line (@lines) {
	#Oct 24 18:57:15 swe kernel: [171040.374665] Denied-by-filter:INPUT IN=eth1 OUT= MAC=00:21:9b:fc:95:c4:00:01:5c:64:ae:46:08:00 SRC=184.105.247.254 DST=76.167.67.20 LEN=51 TOS=0x00 PREC=0x00 TTL=54 ID=22438 DF PROTO=UDP SPT=44236 DPT=623 LEN=31
	# We'll start with a rough glossing over.
	my $src; my $dst; my $dport; my $proto; my $country;
	if ( $line =~ /IN=(.*?) / ) { $iface_pkts{$1}++; }
	if ( $line =~ /SRC=(.*?) / ) { $src = $1; $srcs{$src}++; }
	if ( $line =~ /DST=(.*?) / ) { $dst = $1; $dests{$dst}++; }
	if ( $line =~ /DPT=(.*?) / ) { $dport = $1; $dports{$dport}++; }
	if ( $line =~ /PROTO=(.*?) / ) { $proto = $1; $protos{$proto}++; }
	if (((defined($proto)) && ($proto ne "")) &&
	    ((defined($src)) && ($src ne "")) &&
	    ((defined($dst)) && ($dst ne "")) &&
	    ((defined($dport)) && ($dport ne ""))) {
		$packets{"$proto: $src => $dst:$dport"}++;
	}
	if ( $line =~ /PROTO=TCP SPT=.*? DPT=(?:8[01]|44[13]) / ) { $watched{'http(s)'}++; }
	if ( $line =~ /PROTO=TCP SPT=.*? DPT=22 / ) { $watched{'ssh'}++; }
	if ( $line =~ /PROTO=UDP SPT=.*? DPT=123 / ) { $watched{'ntp'}++; }
	if ( $line =~ /PROTO=UDP SPT=.*? DPT=53 / ) { $watched{'dns'}++; }
	if ( $line =~ /PROTO=TCP SPT=.*? DPT=21 / ) { $watched{'ftp'}++; }
	if ( $line =~ /PROTO=TCP SPT=.*? DPT=23 / ) { $watched{'telnet'}++; }
	if ( $line =~ /PROTO=TCP SPT=.*? DPT=25 / ) { $watched{'smtp'}++; }
	if ( $line =~ /PROTO=TCP SPT=.*? DPT=7547 / ) { $watched{'cwmp'}++; }
	if ( $line =~ /PROTO=(.*?) SPT=.*? DPT=(.*?) / ) { $protoport{"$1/$2"}++; }
	if ( $line =~ /(\.\.FFC\.\.not\.GREEN\.subnet\.\.|Denied-by-\w+:.*? )/ ) { 
		my $f = $1;
		next if ((!defined($f)) || ($f eq ""));
		$filters{$1}++; 
	}
	if ((defined($src)) && ($src ne '')) {
		$country = $gip->country_name_by_addr($src);
		if ((!defined($country)) || ($country eq "")) { $country = 'XX'; }
		$src_countries{$country}++;
	} else {
		open UM, ">>/tmp/unmatched-src.$$.txt" or die "Couldn't open unmatched dump file for writing: $! \n";
		print UM "$line\n";
		close UM or die "Couldn't close unmatched dump file: $! \n";
	}
	if ((defined($dst)) && ($dst ne '')) {
		$country = $gip->country_name_by_addr($dst);
		if ((!defined($country)) || ($country eq "")) { $country = 'XX'; }
		$dest_countries{$country}++;
	} else {
		open UM, ">>/tmp/unmatched-dst.$$.txt" or die "Couldn't open unmatched dump file for writing: $! \n";
		print UM "$line\n";
		close UM or die "Couldn't close unmatched dump file: $! \n";
	}
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

$i = 0;
if ($nocolor) {
	print "\nTop $_depth Packets:\n";
	print "======================\n";
} else {
	print colored("\nTop $_depth Packets:\n", "cyan");
	print colored("======================\n", "cyan");
}
foreach my $p ( sort { $packets{$b} <=> $packets{$a} } keys %packets ) {
	print "$p => $packets{$p}\n";
	$i++;
	last if ( $i >= $_depth );
}

#######################################################################
sub Usage() {
	print <<EOF;
$0 [-h|--help] [-d|--depth <depth>] [-n|--no-dns] [-nc|--no-color]

-h|--help			Displays this message and exits.
-d|--depth			Sets the "Top X" number.  Default is 10.  Setting a value of 0 displays all.
-n|--no-dns			Turns off any name resolution.
-nc|--no-color			Turns off colorised output.
--html				Display results with HTML output.

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
			else { print colored("GeoIP.dat file is over 30 days old.  Consider updating.\n", "bright_yellow"); }
			print "Would you like to attempt to update the GeoIP database now?\n";
			my $ans = readline();
			chomp($ans);
			if ($ans =~ /[Yy](es)?/) {
				# update the GeoIP database
				my $ff = File::Fetch->new(uri => 'http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz');
				my $where = $ff->fetch( 'to' => '/tmp' );
				print colored("==> $where\n", "magenta");
				my $input = "/tmp/GeoIP.dat.gz"; 
				my $output = "/usr/share/GeoIP/GeoIP.dat";
				my $status = gunzip $input => $output
					or die "gunzip failed: $GunzipError\n";
			} else {
				if ($nocolor) { print "Good.  Continuing without updating.\n"; }
				else { print colored("Good.  Continuing without updating.\n", "yellow"); }
			}
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
	#my @mods = ("Net::Nslookup", "Geo::IP::PurePerl", "Date::Calc", "Config::Simple");
	my @mods = ("Net::Nslookup", "Geo::IP::PurePerl", "Date::Calc", "MIME::Lite", "DBD::SQLite");
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
		if ($line =~ /PURPLE_DEV=(.*)/) { $ndsettings{$1} = "magenta"; }
		if ($line =~ /ORANGE_DEV=(.*)/) { $ndsettings{$1} = "yellow"; }
		if ($line =~ /GREEN_NETADDRESS=(.*)/) { $ndsettings{'green net addr'} = $1; }
		if ($line =~ /GREEN_BROADCAST=(.*)/) { $ndsettings{'green net bdcst'} = $1; }
		if ($line =~ /PURPLE_BROADCAST=(.*)/) { $ndsettings{'purple net bdcst'} = $1; }
		if ($line =~ /ORANGE_BROADCAST=(.*)/) { $ndsettings{'orange net bdcst'} = $1; }
	}
	close ETH or die "Couldn't close ethernet settings file: $! \n";

	open LEAS, "</usr/etc/dhcpd.leases" or die "Couldn't open DHCP leases file: $! \n";
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

sub array_to_hash() {
	my $ary_ref = shift(@_);
	my (%hash);
	if (scalar(@{$ary_ref}) == 0) {
		return undef;
	} else {
		foreach my $ele ( sort @{$ary_ref} ) {
			if (exists($hash{$ele})) { $hash{$ele}++; }
			else { $hash{$ele} = 1; }
		}
		return %hash;
	}
}
