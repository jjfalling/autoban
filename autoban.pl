#!/usr/bin/env perl

#****************************************************************************
#*   Autoban                                                                *
#*   Realtime attack and abuse defence and intrusion prevention             *
#*                                                                          *
#*   Copyright (C) 2013 by Jeremy Falling except where noted.               *
#*                                                                          *
#*   This program is free software: you can redistribute it and/or modify   *
#*   it under the terms of the GNU General Public License as published by   *
#*   the Free Software Foundation, either version 3 of the License, or      *
#*   (at your option) any later version.                                    *
#*                                                                          *
#*   This program is distributed in the hope that it will be useful,        *
#*   but WITHOUT ANY WARRANTY; without even the implied warranty of         *
#*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
#*   GNU General Public License for more details.                           *
#*                                                                          *
#*   You should have received a copy of the GNU General Public License      *
#*   along with this program.  If not, see <http://www.gnu.org/licenses/>.  *
#****************************************************************************


use strict;
use warnings;
use Config::Simple;
use Data::Dumper;
use Pod::Usage;
use Getopt::Long;
use Fcntl qw(LOCK_EX LOCK_NB);
use File::NFSLock;


# Try to get an exclusive lock on myself.
my $lock = File::NFSLock->new($0, LOCK_EX|LOCK_NB);
die "$0 is already running!\n" unless $lock;

#Define config file
my $configFile = "autoban.cfg";

#define program version
my $version = "0.1";


my ($help, $man, $foreground, $debug);
my  @plugins;

Getopt::Long::Configure('bundling');
GetOptions
        ('h|help|?' => \$help, man => \$man,
         'f|foreground' => \$foreground,
         "d|debug" => \$debug) or pod2usage(2);
pod2usage(1) if $help;
pod2usage(-exitval => 0, -verbose => 2) if $man;


#TODO: switch to yaml?
#check if config file exists, and if not exit
unless (-e $configFile) {
        print "\nERROR: $configFile was found\n";
		exit 1;
}

our $autobanConfig = new Config::Simple(filename=>"$configFile");

#print Dumper($config->{"_DATA"}->{"autoban"});
#print $autobanConfig->param("autoban.mysqlHost");


print "\n\n";
print "Starting Autoban v.$version, please wait...\n\n";
debugOutput("\n**DEBUG: Debugging enabled");

#check if running as root, if so give warning.
if ( $< == 0 ) {
    print "\n\n*********************************************\n";
	print "* WARNNIG: You are running Autoban as root! *\n";
	print "* This is probally a horrible idea...       *\n";
    print "*********************************************\n\n"; 
}

#define a HoH to shove all of our data in.
# the format will be banData = {ip} => {plugin} => [info about the ip] => [value for each key]
my $banData;


#look through the plugin directories and load the plugins
debugOutput("**DEBUG: searching for plugins");
opendir (DIR, "./plugins") or die $!;


#TODO: put this in a hash, by type. or really just anything more reasonable
while (my $file = readdir(DIR)) {

	# look for plugins
	next unless ($file =~ m/.*\.input|.output|.filter/);
	my $value = $file;
	my $key = $file;
	#$key =~ s/.input|.filter|.output//;	
	push (@plugins, "$value");

}

closedir(DIR);

debugOutput("**DEBUG: found following plugins: @plugins");

#TEMP
require "./plugins/nginx-es.input";
nginx_es_input();










#This function will be used to give the user output, if they so desire
sub debugOutput {
	my $human_status = $_[0];
	if ($debug) {
		print "$human_status \n";
		
	}
}



__END__

=head1 NAME

Autoban - Realtime attack and abuse defence and intrusion prevention

=head1 SYNOPSIS

check_elasticsearch --node hostname [options]

=head1 DESCRIPTION

B<This program> is used to analyze inputs, apply filters and push data to outputs


=head1 OPTIONS

No options are required

=over 8

=item B<-d, --debug> 
Enable debug mode

=item B<-f, --foreground>
Run in foreground

=item B<-h, --help>
Print a brief help message and exits.

=item B<--man>
Print the manual page.

=back

=head1 CHANGELOG

B<1.0> 12-10-2013 Initial release

=cut
