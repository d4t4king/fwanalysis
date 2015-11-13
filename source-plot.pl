#!/usr/bin/perl -w

use warnings;
use strict;

use Geo::IP::PurePerl;
use Data::Dumper;
use Date::Calc;
use IO::Uncompress::Gunzip qw( gunzip $GunzipError );

my (%sources);
open LOG, "</var/log/messages" or die "Can't open log for reading: $!\n";
while (my $line = <LOG>) {
	chomp($line);
	next if ($line !~ /swe\s*kernel\:/);
	if ($line =~ /SRC=(.*?) /) {
		my $src = $1;
		next if ($src =~ /192\.168\.1\.\d+/);		# skip "internal addresses
		$sources{$src}++;
	}
}
close LOG;

print "Found ".scalar(keys(%sources))." unique sources in active log file.\n";

my $kml_header = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<kml xmlns=\"http://www.opengis.net/kml/2.2\">\n\t<Document>\n";
my $kml_footer = "\t</Document>\n</kml>\n";
my $gip = Geo::IP::PurePerl->open('/usr/share/GeoIP/GeoLiteCity.dat', GEOIP_STANDARD);
print "$kml_header\n";
foreach my $src ( sort keys %sources ) {
	my $href = $gip->get_city_record_as_hash($src);
	#print Dumper($href);
	print "\t\t<Placemark>\n\t\t\t<name>$src</name>\n\t\t\t<Point>\n\t\t\t\t<coordinates>$href->{'latitude'},$href->{'longitude'}</coordinates>\n\t\t\t</Point>\n\t\t</Placemark>\n";
}
print "$kml_footer\n";
