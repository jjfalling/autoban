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


#Define config file
my $configFile = "autoban.cfg";

#define program version
my $autobanVersion = "0.1";


my ($help, $man, $foreground, $debug, $safe, $verbose, $version);
my @plugins;

#TODO: fix whole debug vs verbose thing. 
Getopt::Long::Configure('bundling');
GetOptions
        ('h|help|?' => \$help, man => \$man,
         'f|foreground' => \$foreground,
         "d|debug" => \$debug,
         "V|verbose" => \$verbose,
         "v|version" => \$version,
         "s|safe" => \$safe) or pod2usage(2);

pod2usage(1) if $help;
pod2usage(-exitval => 0, -verbose => 2) if $man;

if ($version) {
	print "autoban $autobanVersion\n";
	exit;
}

# Before we do anything else, try to get an exclusive lock
my $lock = File::NFSLock->new($0, LOCK_EX|LOCK_NB); 

#unless we are running in the foreground, die if there is another copy
unless ($foreground) {
	die "\nERROR: I am already running and I will not run another demonized copy!\nTo run manually while the daemon is running, give the foreground flag\n\n" unless $lock;
}


#TODO: switch to yaml? Maybe modular configs?
#check if config file exists, and if not exit
unless (-e $configFile) {
        print "\nERROR: $configFile was found! Please see the man page!\n";
		exit 1;
}

#this needs to not be a global....
our $autobanConfig = new Config::Simple(filename=>"$configFile");

#print Dumper($config->{"_DATA"}->{"autoban"});
#print $autobanConfig->param("autoban.mysqlHost");


print "\n\n";
print "Starting Autoban v.$autobanVersion, please wait...\n\n";
debugOutput("\n**DEBUG: Debugging enabled");


#check if running as root, if so give warning.
if ( $< == 0 ) {
	print "\n********************************************************\n";
	print "* DANGERZONE: You are running Autoban as root!         *\n";
	print "* This is probably a horrible idea security wise...    *\n";
	print "********************************************************\n\n\n"; 
}

#Define a HoHoHoL(?) to shove all of our data in. 
#I originally did this by ip instead of plugin, but I want to have the ability to specify routing between plugins and separate their data.
# the format will be data = {plugin} => {ipData} => [info about the ip]
#                                       {pluginData} => (varies by plugin)
our $data;


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

#TODO, when enabling outputs, obey safe mode
if ($safe) {
	print "\nAnd remember this: there is no more important safety rule than to wear these — safety glasses (safe mode is enabled)\n\n";
}


#TEMP
require "./plugins/nginx_es.input";
nginx_es_input();
require "./plugins/nginx.filter";
nginx_filter();

#require "./plugins/nginx_ban.output";
#nginx_ban();

#if debuging is enabled, give raw data
#if ($debug) {
#	print Dumper($data);
#}







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

autoban [options]

 Options:
   -d,--debug       enable debugging
   -V,--verbose     enable verbose messages
   -f,--foreground  run in foreground
   -h,-help         brief help message
   -man             full documentation
   -s,--safe        safe mode
   -v,--version     display version

=head1 DESCRIPTION

B<This program> is used to analyze inputs, apply filters and push data to outputs


=head1 OPTIONS

No options are required

=over 8

=item B<-d, --debug> 
Enable debug mode

=item B<-v, --verbose> 
Enable verbose messages

=item B<-f, --foreground>
Run in foreground. This will enable you to run autoban in the foreground, even if the daemon is running.

=item B<-h, --help>
Print a brief help message and exits.

=item B<--man>
Print the manual page.

=item B<-s,--safe>
Run in safe mode. This will not preform any bans, but instead display what would have happened. This is useful if you want to run this in read only mode. 

=item B<-v, --version> 
Display program version 

=back

=head1 CHANGELOG

B<0.1> 12-10-2013 Initial release of sanitized code with some serious changes.

=cut
