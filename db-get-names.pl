#!/usr/bin/perl -w

use strict;
use warnings;

use Net::Nslookup;
use Getopt::Long;
use DBI;

my ($db_file);

GetOptions(
	'd|db-file=s'	=>	\$db_file,
);

my (%ip_names);

my $dbh = DBI->connect("dbi:SQLite:dbname=$db_file", "", "") or die "Can't connect to database ($db_file): $DBI::errstr";
my $sth = $dbh->prepare("SELECT ip_addr FROM sources") or die "Can't prepare statement: $DBI::errstr";
my $rtv = $sth->execute() or die "Can't execute statement: $DBI::errstr";
while (my @row = $sth->fetchrow_array()) {
	unless ((defined($row[1])) && ($row[1] ne '')) {
		# do name lookup
		my $name = nslookup(host => $row[0], type => 'PTR');
		$name = 'UNRESOLVED' unless ((defined($name)) && ($name ne ''));
		print "Got name: $name for IP: $row[0].\n";
		$ip_names{$row[0]} = $name;
	}
}
warn $DBI::errstr if $DBI::err;
$sth->finish();

foreach my $ip ( sort keys %ip_names ) {
	print "UPDATE sources SET name='$ip_names{$ip}' WHERE ip_addr='$ip'\n";
	$sth = $dbh->prepare("UPDATE sources SET name='$ip_names{$ip}' WHERE ip_addr='$ip'") or die "Can't prepare statement: $DBI::errstr";
	$rtv = $sth->execute() or die "Can't execute statement: $DBI::errstr";
	warn $DBI::errstr if $DBI::err;
	$sth->finish();
}

$dbh->disconnect();

