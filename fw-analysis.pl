#!/usr/bin/perl
#

use strict;
use warnings;
#use Geo::IP;

my @lines;
# get the lines of packets dropped by the FW
open FILE, "</var/log/messages" or die "Couldn't open messages file: $! \n";
while (my $line = <FILE>) {
	chomp($line);
	push(@lines, $line);
}
close FILE or die "Couldn't close messages file: $! \n";

my (%iface_pkts, %inbound_pkts, %outbound_pkts, %dports, %dests, %srcs, %protos);
foreach my $line (@lines) {
	#Oct 24 18:57:15 swe kernel: [171040.374665] Denied-by-filter:INPUT IN=eth1 OUT= MAC=00:21:9b:fc:95:c4:00:01:5c:64:ae:46:08:00 SRC=184.105.247.254 DST=76.167.67.20 LEN=51 TOS=0x00 PREC=0x00 TTL=54 ID=22438 DF PROTO=UDP SPT=44236 DPT=623 LEN=31
	# We'll start with a rough glossing over.
	if ( $line =~ /IN=(.*?) / ) { $iface_pkts{$1}++; }
	if ( $line =~ /SRC=(.*?) / ) { $srcs{$1}++; }
	if ( $line =~ /DST=(.*?) / ) { $dests{$1}++; }
	if ( $line =~ /DPT=(.*?) / ) { $dports{$1}++; }
	if ( $line =~ /PROTO=(.*?) / ) { $protos{$1}++; }
}

my $i = 0;

foreach my $p ( sort keys %iface_pkts ) {
	print "$p => $iface_pkts{$p}\n";
}

foreach my $s ( sort { $srcs{$b} <=> $srcs{$a} } keys %srcs ) {
	print "$s => $srcs{$s}\n";
	$i++;
	last if ( $i >= 10 );
}
