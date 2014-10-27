#!/bin/bash

echo "Installed perl modules from source, and in the required order."
echo "If you encounter any errors or problems, and don't know what to do, post on the SWE forums, in the thread for this script."

cd
perl -mDigest::HMAC -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/G/GA/GAAS/Digest-HMAC-1.03.tar.gz
	tar xf Digest-HMAC-1.03.tar.gz
	cd Digest-HMAC-1.03/
	perl Makefile.PL
	make && make install
fi
cd
perl -mNet::DNS -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/N/NL/NLNETLABS/Net-DNS-0.80.tar.gz
	tar xf Net-DNS-0.80.tar.gz
	cd Net-DNS-0.80/
	perl Makefile.PL
	make && make install
fi
cd
perl -mNet::Nslookup -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/D/DA/DARREN/Net-Nslookup-2.01.tar.gz
	tar xf Net-Nslookup-2.01.tar.gz
	cd Net-Nslookup-2.01/
	perl Makefile.PL
	make && make install
fi
cd
perl -mGeo::IP::PurePerl -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/B/BO/BORISZ/Geo-IP-PurePerl-1.25.tar.gz
	tar xf Geo-IP-PurePerl-1.25.tar.gz
	cd Geo-IP-PurePerl-1.25/
	perl Makefile.PL
	make && make install
fi
cd
perl -mNet::IPv4Addr -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/F/FR/FRAJULAC/Net-IPv4Addr-0.10.tar.gz
	tar xf Net-IPv4Addr-0.10.tar.gz
	cd Net-IPv4Addr-0.10/
	perl Makefile.PL
	make && make install
fi
cd
rm -rf Digest* Net* Geo-IP*
