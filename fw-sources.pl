#!/usr/bin/perl -w

use strict;
use warnings;
use feature qw( switch );		# on perl 5.18 or later, warnings need to be surpressed here
use Getopt::Long;
use Term::ANSIColor;
use DBI;
use IO::Uncompress::Gunzip qw( gunzip $GunzipError );
use Data::Dumper;
use Date::Calc qw( This_Year );

my ($dbfile, $onetime, $single);
my $csv = 0;		# false

my (%srcs_by_date, %srcs_by_src);

GetOptions(
	'dbfile=s'		=>	\$dbfile,
	'onetime'		=>	\$onetime,
	's|single=s'	=>	\$single,
	'csv'			=>	\$csv,
);

if ($dbfile) {
	my $db = DBI->connect("dbi:SQLite:$dbfile", "", "");
	my $sth = $db->prepare("CREATE TABLE IF NOT EXISTS sources (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_addr TEXT, name TEXT, country_code TEXT, hitcount INTEGER);") or die "Can't prepare statement: $DBI::errstr";
	my $rtv = $sth->execute() or die "Can't execute statement: $DBI::errstr";
	warn $DBI::errstr if $DBI::err;
	$sth->finish();
	#$db->disconnect();
}

# Nov  1 04:23:13 swe kernel: [817038.485625] Denied-by-filter:badtraffic
if ($onetime) {				# get historical data, then stop
	# get the list of files
	my @files = `/bin/ls -1 /var/log/messages*`;
	#print Dumper(@files);
	# loop through the list, extracting each (if compressed)
	foreach my $file (reverse @files) {
		chomp($file);
		my $ext = (split(/\./, $file))[-1];
		if ($ext eq 'gz') {
			my $z = new IO::Uncompress::Gunzip $file 
				or die "gunzip failed: $GunzipError\n";
			# and parse each line, storing by day
			while (my $line = $z->getline()) {
				chomp($line);
				next unless ($line =~ /swe\s+kernel\:/);
				#print Dumper($line);
				if ($line =~ /(\w+)\s*(\d+)\s*([0-9:]+)\s*(\w+)\s*kernel:\s*/) {
					my $mon = $1; my $day = $2; my $time = $3;
					$day = "0$day" if (($day < 10) && (length($day) == 1));
					my $monnum = &mon2num($mon);
					my $gmt = gmtime();
					my $year = This_Year($gmt);
					#my $monstamp = "$year$monnum";
					my $datestamp = "$year-$monnum-$day";
					#my $timestamp = "$datestamp".join("", split(/\:/, $time));
					#print "DEBUG: $timestamp\n";
					if ($line =~ /SRC=(.*?) /) { 
						my $ip = $1;
						next unless ($ip eq $single);
						$srcs_by_date{"$datestamp"."T00:00:00.000"}{$ip}++; 
						#$srcs_by_src{$1}{$monstamp}++;
					}
				}
			}
		} else {
			#print Dumper($ext);
			# assume, for now, it's the current log
			open LOG, $file or die "Can't open file ($file) for reading: $! \n";
			while (my $line = <LOG>) {
				chomp($line);
				next unless ($line =~ /swe\s+kernel\:/);
				#print Dumper($line);
				if ($line =~ /(\w+)\s*(\d+)\s*([0-9:]+)\s*(\w+)\s*kernel:\s*/) {
					my $mon = $1; my $day = $2; my $time = $3;
					$day = "0$day" if (($day < 10) && (length($day) == 1));
					my $monnum = &mon2num($mon);
					my $gmt = gmtime();
					my $year = This_Year($gmt);
					#my $monstamp = "$year$monnum";
					my $datestamp = "$year-$monnum-$day";
					#my $timestamp = "$datestamp".join("", split(/\:/, $time));
					#print "DEBUG: $timestamp\n";
					if ($line =~ /SRC=(.*?) /) { 
						my $ip = $1;
						next unless ($ip eq $single);
						$srcs_by_date{"$datestamp"."T00:00:00.000"}{$1}++; 
						#$srcs_by_src{$1}{$monstamp}++;
					}
				}
			}
		}
	}
} else {
	### FIX ME
	die "You're only working on the hitory stuff, dummy.  Come back to this later.  \nUse the '--onetime' option!\n"
}

#print Dumper(%srcs_by_date);

foreach my $date ( sort keys %srcs_by_date ) {
#	my $count = 0; my $src = '192.168.1.10';
	foreach my $src ( sort { $srcs_by_date{$date}{$b} <=> $srcs_by_date{$date}{$a} } keys %{$srcs_by_date{$date}} ) {
		if ($csv) {
			if ($single) {
				print "$date,$srcs_by_date{$date}{$single}\n";
			} else {
				print "$src,$date,$srcs_by_date{$date}{$src}\n";
			}
		} else {
			print "$date => $src => $srcs_by_date{$date}{$src}\n";
		}
	#	$count++;
	#	last if ($count >= 9);
	}
}

#foreach my $src ( sort keys %srcs_by_src ) {
#	my $count = 0;
#	foreach my $date ( sort { $srcs_by_src{$src}{$b} <=> $srcs_by_src{$src}{$a} } keys %{$srcs_by_src{$src}} ) {
#		print "$src => $date => $srcs_by_src{$src}{$date}\n";
#		$count++;
#		last if ($count >= 9);
#	}
#}

###############################################################################
sub mon2num() {
	my $mon = shift(@_);
	given ($mon) {
		when (/[Jj]an(?:uary)?/) { return '01'; }
		when (/[Ff]eb(?:ruary)?/) {	return '02'; }
		when (/[Mm]ar(?:ch)?/) { return '03'; }
		when (/[Aa]pr(?:il)?/) { return '04'; }
		when (/[Mm]ay/) { return '05'; }
		when (/[Jj]un(?:e)?/) { return '06'; }
		when (/[Jj]ul(?:y)?/) { return '07'; }
		when (/[Aa]ug(?:ust)?/) { return '08'; }
		when (/[Ss]ep(?:tember)?/) { return '09'; }
		when (/[Oo]ct(?:tober)?/) {	return '10'; }
		when (/[Nn]ov(?:ember)?/) { return '11'; }
		when (/[Dd]ec(?:ember)?/) { return '12'; }
		default { die "Unrecognized month string: $mon\n"; }
	}
}
