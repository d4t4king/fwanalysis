#!/usr/bin/perl
#

use strict;
use warnings;
use feature qw( switch );
use Term::ANSIColor;
use Data::Dumper;

if (&check_perl_mods()) {
	use Net::Nslookup;
	use Geo::IP::PurePerl;
	use Date::Calc qw(:all);
}

&check_geoip_db();

my $settings = &get_net_and_dhcp_info();
#print Dumper($settings);

my @lines;
# get the lines of packets dropped by the FW
open FILE, "</var/log/messages" or die "Couldn't open messages file: $! \n";
while (my $line = <FILE>) {
	chomp($line);
	push(@lines, $line);
}
close FILE or die "Couldn't close messages file: $! \n";

my $gip = Geo::IP::PurePerl->open('/usr/share/GeoIP/GeoIP.dat', GEOIP_MEMORY_CACHE);
my (%iface_pkts, %inbound_pkts, %outbound_pkts, %dports, %dests, %srcs, %protos, %watched, %protoport, %src_countries, %dest_countries);
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
print colored("Number of packets per interface:\n", "cyan");
print colored("================================\n", "cyan");
foreach my $p ( sort keys %iface_pkts ) {
	#print "$p => ". nslookup($p) . " ==> $iface_pkts{$p}\n";
	print colored("$p", "$settings->{$p}");
	print "\t=>\t$iface_pkts{$p}\n";
}

print "\nNumber of unique source IPs: ";
print colored(scalar(keys(%srcs)) . "\n", "green");
print colored("Top 10 sources:\n", "cyan");
print colored("===============\n", "cyan");
foreach my $s ( sort { $srcs{$b} <=> $srcs{$a} } keys %srcs ) {
	my $name = nslookup('host' => $s, 'type' => "PTR");
	if ((!defined($name)) || ($name eq "")) { $name = 'UNRESOLVED'; }
	if (($name eq "UNRESOLVED") && (exists($settings->{'lease_hash'}{$s}))) {
		$name = $settings->{'lease_hash'}{$s};
	}
	my $cc = $gip->country_code_by_addr($s);
	if ((!defined($cc)) || ($cc eq "")) { $cc = 'XX'; }
	print "$s => $name => $srcs{$s} ($cc) \n";
	$i++;
	last if ( $i >= 10 );
}

$i = 0;
print "\nNumber of unique destination IPs: ";
print colored(scalar(keys(%dests)) . "\n", "green");
print colored("Top 10 Destinations:\n", "cyan");
print colored("====================\n", "cyan");
foreach my $d ( sort { $dests{$b} <=> $dests{$a} } keys %dests ) {
	my $name = nslookup('host' => $d, 'type' => "PTR");
	if ((!defined($name)) || ($name eq "")) { $name = "UNRESOLVED"; }
	if (($name eq "UNRESOLVED") && (exists($settings->{'lease_hash'}{$d}))) {
		$name = $settings->{'lease_hash'}{$d};
	}
	my $cc = $gip->country_code_by_addr($d);
	if ((!defined($cc)) || ($cc eq "")) { $cc = 'XX'; }
	print "$d => $name => $dests{$d} ($cc) \n";
	$i++;
	last if ( $i >= 10 );
}

print colored("\nWatched protocols:\n", "cyan");
print colored("====================\n", "cyan");
foreach my $k ( sort keys %watched ) {
	print "$k\t=>\t$watched{$k}\n";
}

$i = 0;
print colored("\nTop 10 Proto/Port's:\n", "cyan");
print colored("======================\n", "cyan");
foreach my $k ( sort { $protoport{$b} <=> $protoport{$a} } keys %protoport ) {
	my $tabs = "";
	if (length($k) >= 8) {
		$tabs = "\t";
	} else {
		$tabs = "\t\t";
	}
	print "$k$tabs=>\t$protoport{$k}\n";
	$i++;
	last if ( $i >= 10 );
}

$i = 0;
print colored("\nTop 10 Source Countries:\n", "cyan");
print colored("==========================\n", "cyan");
foreach my $sc ( sort { $src_countries{$b} <=> $src_countries{$a} } keys %src_countries ) {
	my $tabs = "";
	if (length($sc) >= 17) {
		$tabs = "\t";
	} elsif ((length($sc) < 17) && (length($sc) >= 7)) {
		$tabs = "\t\t";
	} elsif (length($sc) < 7) {
		$tabs = "\t\t\t";
	}

	print "$sc$tabs=>\t$src_countries{$sc}\n";
	$i++;
	last if ( $i >= 10 );
}

$i = 0;
print colored("\nTop 10 Destination Countries:\n", "cyan");
print colored("===============================\n", "cyan");
foreach my $dc ( sort { $dest_countries{$b} <=> $dest_countries{$a} } keys %dest_countries ) {
	my $tabs = "";
	if (length($dc) >= 9) {
		$tabs = "\t";
	} else {
		$tabs = "\t\t";
	}
	print "$dc$tabs=>\t$dest_countries{$dc}\n";
	$i++;
	last if ( $i >= 10 );
}
#######################################################################
sub check_geoip_db() {
	if ( -f "/usr/share/GeoIP/GeoIP.dat" ) {
		use Data::Dumper;
		my @stats = stat("/usr/share/GeoIP/GeoIP.dat");
		#print Dumper(@stats);
		my $time = time();
		if (($time - $stats[10]) >= 2592000) {
			print colored("GeoIP.dat file is over 30 days old.  Consider updating.\n", "yellow");
		} else {
			print colored("GeoIP.dat OK.\n", "green");
		}
	} else {
		print color 'red';
		print "Couldn't find GeoIP.dat.\n";
		print color 'reset';
	}
}

sub check_perl_mods() {
	my $status = 0;
	my $result = `/usr/bin/perl -mNet::Nslookup -e ";" 2>&1`;
	if ($result =~ /^Can't locate /) {
		#print colored("Can't find Net::Nslookup.  Installing...", "red");
		#system("cd; wget http://search.cpan.org/CPAN/authors/id/G/GA/GAAS/Digest-HMAC-1.03.tar.gz > /dev/null 2>&1");
		#system("cd; tar xf Digest-HMAC-1.03.tar.gz > /dev/null 2>&1; cd Digest-HMAC-1.03/; perl Makefile.PL /dev/null 2>&1; make >/dev/null 2>&1 && make install > /dev/null 2>&1");
		#system("cd; wget http://search.cpan.org/CPAN/authors/id/N/NL/NLNETLABS/Net-DNS-0.80.tar.gz > /dev/null 2>&1");
		#system("cd; tar xf Net-DNS-0.80.tar.gz > /dev/null 2>&1; cd Net-DNS-0.80/; perl Makefile.PL > /dev/null 2>&1; make >/dev/null 2>&1 && make install > /dev/null 2>&1");
		#system("cd; wget http://search.cpan.org/CPAN/authors/id/D/DA/DARREN/Net-Nslookup-2.01.tar.gz > /dev/null 2>&1");
		#system("cd; tar xf Net-Nslookup-2.01.tar.gz > /dev/null 2>&1; cd Net-Nslookup-2.01/; perl Makefile.PL >/dev/null 2>&1; make >/dev/null 2>&1 && make install > /dev/null 2>&1");
		#system("cd; rm -rf Digest-HMAC-1.03* Net-DNS-0.80* Net-Nslookup-2.01* > /dev/null 2>&1");
		#print colored("done.\n", "red");
		print colored("Couldn't find Net::Nslookup. Please run the included script: install-mods.sh.", "red");
		$status = 1
	} elsif ((! defined($result)) || $result eq "") {
		print colored("Net::Nslookup OK.\n", "green");
		$status = 1
	} else {
		print colored("$result\n", "red");
		$status = 0
	}
	if ($status == 0) { return $status; }
	# Geo::IP wants libgeoip to be newer than v1.5.0, which it apparently isn't.
	# So we'll use the PurePerl version, which works just as well.
	$result = `/usr/bin/perl -mGeo::IP::PurePerl -e ";" 2>&1`;
	if ($result =~ /^Can't locate /) {
		#print colored("Can't find Geo::IP::PurePerl.  Installing...", "red");
		#system("cd; wget http://search.cpan.org/CPAN/authors/id/B/BO/BORISZ/Geo-IP-PurePerl-1.25.tar.gz >/dev/null 2>&1");
		#system("cd; tar xf Geo-IP-PurePerl-1.25.tar.gz > /dev/null 2>&1; cd Geo-IP-PurePerl-1.25/; perl Makefile.PL > /dev/null 2>&1; make >/dev/null 2>&1 && make insstall > /dev/null 2>&1");
		#print colored("done.\n", "red");
		print colored("Couldn't find Geo::IP::PurePerl.  Please run the included script: install-mods.sh.", "red");
		$status = 1;
	} elsif ((!defined($result)) || $result eq "") {
		print colored("Geo::IP::PurePerl OK\n", "green");
		$status = 1;
	} else {
		print colored("$result\n", "red");
		$status = 0;
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
