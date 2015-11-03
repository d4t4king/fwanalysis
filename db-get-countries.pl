#!/usr/bin/perl -w

use strict;
use warnings;

use Getopt::Long;
use Geo::IP::PurePerl;
use DBI;

my ($db_file, $verbose);
GetOptions(
	'd|db-file=s'	=>	\$db_file,
	'v|verbose'		=>	\$verbose,
);

my (%db_cc, %db_idx_cc, %to_add);

if ($verbose) { print "Setting up database connection....\n"; }
my $dbh = DBI->connect("dbi:SQLite:dbname=$db_file", "", "") or die "Can't connect to database ($db_file): $DBI::errstr";
if ($verbose) { print "Prepareing and executing countries query....\n"; }
my $sth = $dbh->prepare("SELECT id,cc FROM countries") or die "Can't prepare statement: $DBI::errstr";
my $rtv = $sth->execute() or die "Can't execute statement: $DBI::errstr";
if ($verbose) { print "Populating index hash....\n"; }
while (my @row = $sth->fetchrow_array()) {
	$db_cc{$row[1]} = $row[0];
	$db_idx_cc{$row[0]} = $row[1];
}
warn $DBI::errstr if $DBI::err;

my $gip = Geo::IP::PurePerl->open('/usr/share/GeoIP/GeoIP.dat', GEOIP_MEMORY_CACHE);

# check country index in sources
if ($verbose) { print "Querying sources....\n"; }
$sth = $dbh->prepare("SELECT ip_addr,country_index FROM sources") or die "Can't prepare statement: $DBI::errstr";
$rtv = $sth->execute() or die "Can't execute statement: $DBI::errstr";
while (my @row = $sth->fetchrow_array()) {
	# if the country index is empty, update it
	# well....add it to the list to be updated later.
	# We don't want the DB handles stomping o themselves,
	# which they seem to be doing, if we try to do everything
	# in the same loop.
	if ((!defined($row[1])) || ($row[1] eq "")) {
		if ($verbose) { print "Country index for source ($row[0]) not defined....\n"; }
		my $cc = $gip->country_code_by_addr($row[0]);
		my $cn = $gip->country_name_by_addr($row[0]);
		if ($verbose) { print "Got cc: $cc, name: $cn for IP $row[0].\nAdding to update list....\n"; }
		# but if the country isn't in the countries table, add it first
		$to_add{$row[0]} = "$cc|$cn";
	} else {
		if ($verbose) { print "Country index defined for IP ($row[0]): $row[1], $db_idx_cc{$row[1]}.\n"; }
	}
}
$sth->finish();

foreach my $ip ( sort keys %to_add ) {
	print "--> $ip\n" if ($verbose);
	my ($_cc, $_cn) = split(/\|/, $to_add{$ip});
	
	# Is the country in the countries database? If not, add it.
	unless (exists($db_cc{$_cc})) {
		if ($verbose) { print "Adding country code ($_cc) and country name ($_cn) to database....\n"; }
		$sth = $dbh->prepare("INSERT INTO countries (cc,full_name) VALUES ('$_cc', '$_cn')") or die "Can't prepare statement: $DBI::errstr";
		$rtv = $sth->execute() or die "Can't execute statement: $DBI::errstr";
	}
}

# All of the "new" countries should be added to the database now,
# so, reinitialize the reference hashes and requery.
if ($verbose) { print "Prepareing and executing countries query (again)....\n"; }
$sth = $dbh->prepare("SELECT id,cc FROM countries") or die "Can't prepare statement: $DBI::errstr";
$rtv = $sth->execute() or die "Can't execute statement: $DBI::errstr";
if ($verbose) { print "(Re-)Populating index hash....\n"; }
while (my @row = $sth->fetchrow_array()) {
	$db_cc{$row[1]} = $row[0];
	$db_idx_cc{$row[0]} = $row[1];
}
warn $DBI::errstr if $DBI::err;
$sth->finish();

# loop through the %to_add list again.  This time, update the sources (and destinations(???)) table(s).
foreach my $ip ( sort keys %to_add ) {
	my ($_cc, $_cn) = split(/\|/, $to_add{$ip});
	$sth = $dbh->prepare("UPDATE sources SET country_index='$db_cc{$_cc}' WHERE ip_addr='$ip'") or die "Can't prepare statement: $DBI::errstr";
	$rtv = $sth->execute() or die "Can't execute statement: $DBI::errstr";
}
warn $DBI::errstr if $DBI::err;
$sth->finish();

$dbh->disconnect();
