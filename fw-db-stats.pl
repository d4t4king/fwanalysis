#!/usr/bin/perl

use strict;
use warnings;
require 5.010;
use feature qw( switch );

use Getopt::Long;
use DBI;
use Term::ANSIColor;
use Data::Dumper;
use IO::Uncompress::Gunzip qw( gunzip $GunzipError );

my ($dbfile, $depth, $help, $onetime, $verbose);
our ($crontab);

my $__depth__ = 10;

GetOptions( 
	'onetime'		=>	\$onetime,
	'd|dbfile=s'	=>	\$dbfile,
	'D|depth=s'		=>	\$depth,
	'c|crontab'		=>	\$crontab,
	'h|?|help'		=>	\$help,
	'v|verbose'		=>	\$verbose,
);

my %colors2html = (
	'red'		=>	'#FF0000',
	'blue'		=>	'#0000FF',
	'green'		=>	'#00FF00',
	'purple'	=>	'#800080',
	'orange'	=>	'#FFA500',
);

if ($help) { &Usage(); }

if ($verbose) { print "Checking perl mods....\n"; }
if (&check_perl_mods()) {
	use Net::Nslookup;
	use Geo::IP::PurePerl;
	use Date::Calc qw( :all );
}

if (($depth) && ($depth ne "") && ($depth =~ /\d+/)) { $__depth__ = $depth; }

if ($verbose) { print "Checking GeoIP database....\n"; }

&check_geoip_db();

#
### Initialize Database Tables (if not exist)
#
if ($verbose) { print "Setting up the tables in the database file ($dbfile)....\n"; }
my $db = DBI->connect("dbi:SQLite:$dbfile", "", "") or die "Can't connect to database: $DBI::errstr";
my $sth = $db->prepare("CREATE TABLE IF NOT EXISTS ifaces (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, datetime INTEGER, hitcount INTEGER);") or die "Can't prepare statement: $DBI::errstr";
my $rtv = $sth->execute() or die "Can't execute statement: $DBI::errstr";
print STDERR "RTV: $rtv\n";
$sth = $db->prepare("CREATE TABLE IF NOT EXISTS filters (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, datetime INTEGER, hitcount INTEGER);") or die "Can't prepare statement: $DBI::errstr";
$rtv = $sth->execute() or die "Can't execute statement: $DBI::errstr";
print STDERR "RTV: $rtv\n";
warn $DBI::errstr if $DBI::err;

#
### Grab data from tables (if exist)
#
if ($verbose) { print "Loading existing database data (filters)....\n"; }
my (%db_filters, %db_ifaces);
$sth = $db->prepare("SELECT name,datetime,hitcount FROM ifaces") or die "Can't prepare statement: $DBI::errstr";
$rtv = $sth->execute() or die "Can't execute statement: $DBI::errstr";
while (my @row = $sth->fetchrow_array()) {
	$db_ifaces{$row[0]}{$row[1]} = $row[2];
}
$sth = $db->prepare("SELECT name,datetime,hitcount FROM filters") or die "Can't prepare statement: $DBI::errstr";
$rtv = $sth->execute() or die "Can't execute statement: $DBI::errstr";
print STDERR "RTV: $rtv\n";
while (my @row = $sth->fetchrow_array()) {
	$db_filters{$row[0]}{$row[1]} = $row[2];
}
warn $DBI::errstr if $DBI::err;
$sth->finish() or die "There was a problem cleaning up the statement handle: $DBI::errstr";

#
### Parse the log file(s) for the relevant data to insert
#
if ($verbose) { print "Loading data from logs into database (filters)....\n"; }
my (%filters, %iface_pkts);
if ($onetime) {
	if ($verbose && $onetime) { print "_onetime_ flag set.  Loading historical data...\n"; }
	my @files = `/bin/ls -1 /var/log/messages*`;
	foreach my $file (reverse @files) {
		chomp($file);
		my $ext = (split(/\./, $file))[-1];
		if ($ext eq 'gz') {
			my $z = new IO::Uncompress::Gunzip $file
				or die "gunzip failed $GunzipError\n";
			while (my $line = $z->getline()) {
				chomp($line);
				next unless ($line =~ /swe\s+kernel\:/);
				my ($y, $m, $d, $h, $mm, $s, $mkt) = &extract_log_date($line);
				print STDERR "($y $m $d, $h, $mm, $s, $mkt)\n";
				if ($line =~ /IN=(.*?) /) { $iface_pkts{$1}{$mkt}++; }
				if ($line =~ /(\.\.FFC\.\.not\.GREEN\.subnet\.\.|Denied-by-\w+:.*? )/) {
					my $f = $1;
					next if ((!defined($f)) || ($f eq ''));
					$filters{$f}{$mkt}++;
				}
			}
		} else {
			open LOG, $file or die "Can't open log file ($file) for reading: $! \n";
			while (my $line = <LOG>) {
				chomp($line);
				next unless ($line =~ /swe\s+kernel\:/);
				my ($y, $m, $d, $h, $mm, $s, $mkt) = &extract_log_date($line);
				print STDERR "($y $m $d, $h, $mm, $s, $mkt)\n";
				if ($line =~ /IN=(.*?) /) { $iface_pkts{$1}{$mkt}++; }
				if ($line =~ /(\.\.FFC\.\.not\.GREEN\.subnet\.\.|Denied-by-\w+:.*? )/) {
					my $f = $1;
					next if ((!defined($f)) || ($f eq ''));
					$filters{$f}{$mkt}++;
				}
			}
		}
	}
} else {
	if ($verbose) { print "Just loading the last 24 horus of log data (filters)....\n"; }
	### FIX ME:  Add the code to add the last 24 hours.
}

#
### Add the "new" stuff to the database.
#
foreach my $iface ( sort keys %iface_pkts ) {
	foreach my $if_date ( sort keys %{$iface_pkts{$iface}} ) {
		$sth = $db->prepare("INSERT INTO ifaces (name,datetime,hitcount) VALUES ('$iface', '$if_date', '$iface_pkts{$iface}{$if_date}')") or die "Can't prepare staement: $DBI::errstr";
		$sth->execute() or die "Can't execute statement: $DBI::errstr";
	}
}
foreach my $filter ( sort keys %filters ) {
	foreach my $f_date ( sort keys %{$filters{$filter}} ) {
		$sth = $db->prepare("INSERT INTO filters (name,datetime,hitcount) VALUES ('$filter', '$f_date', '$filters{$filter}{$f_date}');") or die "Can't prepare statement: $DBI::errstr";
		$sth->execute() or die "Can't execute statement: $DBI::errstr";
	}
}
warn $DBI::errstr if $DBI::err;
$sth->finish() or die "There was a problem cleaning up the statement handle: $DBI::errstr";

$db->disconnect() or die "There was a problem disconnecting from the database: $DBI::errstr";

###############################################################################
sub extract_log_date() {
	my $line = shift(@_);
	if ($line =~ /(\w+)\s*(\d+)\s*([0-9:]+)\s*(\w+)\s*/) {
		my $m = $1; my $d = $2; my $time = $3;
		my ($h, $mm, $s) = split(/\:/, $time);
		my $mnum = &mon2num($m);
		my $gmt = gmtime();
		my $y = This_Year($gmt);
		my $mktime = Mktime($y, $mnum, $d, $h, $mm, $s);

		return ($y, $mnum, $d, $h, $mm, $s, $mktime);
	} else {
		warn "extract_log_date(): Received invalid or unrecognizeable log line (with date??)\n";
		return -1;
	}
}

sub mon2num() {
	my $mon = shift(@_);
	given ($mon) {
		when (/[Jj]an(?:uary)?/) { return 1; }
		when (/[Ff]eb(?:ruary)?/) { return 2; }
		when (/[Mm]ar(?:ch)?/) { return 3; }
		when (/[Aa]pr(?:il)?/) { return 4; }
		when (/[Mm]ay/) { return 5; }
		when (/[Jj]un(?:e)?/) { return 6; }
		when (/[Jj]ul(?:y)?/) { return 7; }
		when (/[Aa]ug(?:ust)?/) { return 8; }
		when (/[Ss]ep(?:tember)?/) { return 9; }
		when (/[Oo]ct(?:tober)?/) { return 10; }
		when (/[Nn]ov(?:ember)?/) { return 11; }
		when (/[Dd]ec(?:ember)?/) { return 12; }
		default { die "Unrecognized month string: $mon\n"; }
	}
}

sub check_geoip_db() {
	if ( -f "/usr/share/GeoIP/GeoIP.dat" ) {
		my @stats = stat("/usr/share/GeoIP/GeoIP.dat");
		#print Dumper(@stats);
		my $time = time();
		if (($time - $stats[10]) >= 2592000) {
			print "GeoIP.dat file is over 30 days old.  Consider updating.\n";
			unless ($crontab) {
				print "Would you like to attempt to update the GeoIP database now?\n";
				my $ans = readline();
				chomp($ans);
				if ($ans =~ /[Yy](es)?/) {
					#update the GeoIP database
					my $ff = File::Fetch->new(uri => 'http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz');
					my $where = $ff->fetch( 'to' => '/tmp' );
					print "==> $where\n";
					my $input = "/tmp/GeoIP.dat.gz";
					my $output = "/usr/share/GeoIP/GeoIP.dat";
					my $status = gunzip $input => $output
						or die "gunzip failed: $GunzipError\n";
				} else {
					print "Good.  Continuing without updating.\n";
				}
			}
		} else {
			print "GeoIP.dat OK.\n";
		}
	} else {
		print "Couldn't find GeoIP.dat.\n";
	}
}

sub check_perl_mods() {
	my $status = 0;
	#my @mods = ("Net::Nslookup", "Geo::IP::PurePerl", "Date::Calc", "Config::Simple");
	my @mods = ("Net::Nslookup", "Geo::IP::PurePerl", "Date::Calc", "MIME::Lite", "DBD::SQLite");
	foreach my $mod ( @mods ) {
		my $result = `/usr/bin/perl -m$mod -e ";" 2>&1`;
		if ($result =~ /^Can't locate /) {
			print "Couldn't find $mod. Please run the included script: install-mods.sh.\n"; 
			$status = 1
		} elsif ((! defined($result)) || $result eq "") {
			print "$mod OK.\n";
			$status = 1
		} else {
			print "$result\n";
			$status = 0
		}
		if ($status == 0) { return $status; }
	}
	#system("sed -i -e 's/#\(use .*\)/\1/g' $0");
	return $status;
}


sub parse_datetime($) {
	no warnings;
	my $dstr = shift(@_);
	my ($date, $time) = split(/ /, $dstr);
	my ($y, $m, $d) = split(/\//, $date);
	my ($h, $mm, $s) = split(/:/, $time);

	return ($y, $m, $d, $h, $mm, $s);
}
