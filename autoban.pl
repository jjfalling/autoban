#!/usr/bin/env perl

#****************************************************************************
#*   autoban                                                                *
#*   Realtime attack and abuse defence and intrusion prevention             *
#*                                                                          *
#*   Copyright (C) 2014 by Jeremy Falling except where noted.               *
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
package autoban;

use strict;
use warnings;

use Data::Dumper;
use Config::Simple;
use Pod::Usage;
use Getopt::Long;
use Fcntl qw(LOCK_EX LOCK_NB);
use File::NFSLock;
use Time::HiRes qw(usleep ualarm gettimeofday tv_interval);
use Log::Log4perl;
use FindBin;     

#get offical elasticsearch module @ https://metacpan.org/pod/Search::Elasticsearch
use Search::Elasticsearch;
#A recent version is required for some things we do
die "FATAL: The Search::Elasticsearch module must be >= v1.14! You have v$Search::Elasticsearch::VERSION\n\n"
    unless $Search::Elasticsearch::VERSION >= 1.14;
           
use lib "$FindBin::Bin/lib"; 
use autoban::Logging;
use autoban::EsIndexMgmt;

#if we get an interupt, run function to exit
$SIG{INT} = \&interrupt;
$SIG{TERM} = \&interrupt;
$SIG{HUP} = \&interrupt;


#store the path to autoban as found by FindBin
my $autobanPath = "$FindBin::Bin";

#Define config file
my $configFile = "$autobanPath/conf/autoban.cfg";

#define program version (major, minor, patch)
my $autobanVersion = "0.1.0";

my ($help, $man, $loglevel, $version);
our ($safe, $foreground); #<-- this should probally not be handled as a global....
my @plugins;

#TODO: fix whole debug vs verbose thing and replace with logging system
my ($verbose, $debug);
Getopt::Long::Configure('bundling');
GetOptions
    ('h|help|?' => \$help, 
     'man' => \$man,
     "l|loglevel=s" => \$loglevel,
     'f|foreground' => \$foreground,
     "v|version" => \$version,
     "s|safe" => \$safe) or pod2usage(2);

pod2usage(-verbose => 1) if $help;
pod2usage(-verbose => 3, -exitval => 0) if $man;

if ($version) {
    print "autoban $autobanVersion\n\n";
    exit;
}


our $autobanConfig = new Config::Simple(filename=>"$configFile"); #<-- this should probally not be handled as a global....

#check if config file exists, and if not exit
unless (-e $configFile) {
    print "\nFATAL: $configFile was found! Please see the man page (--man)!\n";
    exit 1;}

#set the log level via the flag or fall back to the config
our $autobanLogLevel;
if ($loglevel){
    #use uc to ensure upper case
    $autobanLogLevel = uc $loglevel;
}
else {
    $autobanLogLevel = $autobanConfig->param('autoban.LogLevel');
}

# Before we do anything else, try to get an exclusive lock
my $lock = File::NFSLock->new($0, LOCK_EX|LOCK_NB); 

#finish setting up logging
Log::Log4perl::init("$autobanPath/conf/logging.cfg");
our $autobanLog = Log::Log4perl->get_logger();

#capture die errors
$SIG{__DIE__} = sub {
        if($^S) {
            # We're in an eval {} and don't want log
            # this message but catch it later
            return;
        }
	#ensure we are not being called by log4perl, as we dont want to send the log back to it
	my($callingPackage) = caller;
        if($callingPackage eq 'Log::Log4perl::Logger') {
            # We're in an eval {} and don't want log
            # this message but catch it later
            return;
	}

        $Log::Log4perl::caller_depth++;
	autoban::Logging::OutputHandler('LOGCONFESS','autoban',"UNHANDLED EXECPTION: @_");
        die @_; # Now terminate really
    };

#capture warn errors
$SIG{__WARN__} = sub {
        if($^S) {
            # We're in an eval {} and don't want log
            # this message but catch it later
            return;
        }
        $Log::Log4perl::caller_depth++;
	autoban::Logging::OutputHandler('LOGCLUCK','autoban',"UNHANDLED WARNING: @_");
    };

unless ($foreground) {

    #we are not running in the foreground check if there is another copy of this program running and die if so
    autoban::Logging::OutputHandler('FATALDIE', 'autoban', 'autoban is already running and I will not run another demonized copy! To run autoban manually while the daemon is running, give the foreground flag. See help or the man page.') unless $lock;
    
}



#Any output past this point should be handled by the logging system
autoban::Logging::OutputHandler('INFO','autoban','');
autoban::Logging::OutputHandler('OFF','autoban',"Starting autoban v.$autobanVersion, please wait...");
autoban::Logging::OutputHandler('INFO','autoban','');


#check if running as root, if so give warning.
if ( $< == 0 ) {
    autoban::Logging::OutputHandler('WARN','autoban','');
    autoban::Logging::OutputHandler('WARN','autoban','********************************************************');
    autoban::Logging::OutputHandler('WARN','autoban','*    DANGERZONE: You are running autoban as root!      *');
    autoban::Logging::OutputHandler('WARN','autoban','*    This is probably a horrible idea security wise... *');
    autoban::Logging::OutputHandler('WARN','autoban','********************************************************');
    autoban::Logging::OutputHandler('WARN','autoban','');
}

#Define a HoHoHoL(?) to shove all of our data in. 
#I originally did this by ip instead of plugin, but I want to have the ability to specify routing between plugins and separate their data.
# the format will be data = {plugin} => {ipData} => [info about the ip]
#                                       {pluginData} => (varies by plugin)
our $data;


#when safemode is enabled, do not preform any actions. only gather data and report to the user. 
if ($safe) {
    autoban::Logging::OutputHandler('INFO','autoban','Safe mode is enabled. No bans will be created');
}


#create the shared es connection
our $es = Search::Elasticsearch->new(
    cxn_pool => $autobanConfig->param('autoban.cnx_pool'),
    nodes => [$autobanConfig->param('autoban.esNodes')],
    #log_to   => 'Stderr',
    #trace_to => 'Stderr',
    ) || $autobanLog->logdie("Cannot create new es instance: $es");


#ensure the autoban template exists and update it 
autoban::Logging::OutputHandler('DEBUG','autoban','Updating autoban index template');
autoban::EsIndexMgmt::UpdateAutobanTemplate();
autoban::Logging::OutputHandler('DEBUG','autoban','autoban template updated');


###MAIN 

#if foreground flag given, run only once
if ($foreground) {
    main();
    exit 0;

}else {
    #run forever (poor mans daemon for now)
    while (1) {
	main();
	sleep $autobanConfig->param('autoban.runInterval');

    }
}

###END MAIN



#handle interrupts
########################################
sub interrupt {
########################################
    autoban::Logging::OutputHandler('OFF','autoban','Received an interupt, shutting down....');
    exit;
}



#this is the main autoban function
########################################
sub main {
########################################
    #setup timer for stats reasons
    my $autobanTime = [gettimeofday];

    #check the cluster health, break out of the main loop if things are not healthy
    unless ( autoban::EsIndexMgmt::CheckClusterHealth() eq 'ok'){
      return;
    }


    #run some sanity checks on the autoban index
    autoban::EsIndexMgmt::CheckAutobanIndex();


    #load and run plugins specified in config
    foreach my $runPlugin ($autobanConfig->param('autoban.runPlugins')) {

	#ensure the request plugin exists
	unless (-e "$autobanPath/plugins/$runPlugin.pm") {
	    autoban::Logging::OutputHandler('FATALDIE','autoban',"Plugin $runPlugin was found! Plugin should be $autobanPath/plugins/$runPlugin.pm!");
	}
	require "$autobanPath/plugins/$runPlugin.pm";

	#work around strict not allowing string as a subroutine ref
	my $subref = \&$runPlugin;

	autoban::Logging::OutputHandler('INFO','autoban','');
	autoban::Logging::OutputHandler('INFO','autoban',"Running plugin $runPlugin");

	#get time just before running module
	my $modPluginTime = [gettimeofday];

	#try to run the function
	&$subref();
	
	#get amt of time the plugin took to run
	my $elapsedPluginTime = tv_interval ($modPluginTime);
	autoban::Logging::OutputHandler('DEBUG','autoban',"Plugin $runPlugin took $elapsedPluginTime seconds to run");
	
    }

    my $elapsedAutobanTime = tv_interval ($autobanTime);
    autoban::Logging::OutputHandler('INFO','autoban','');
    autoban::Logging::OutputHandler('INFO','autoban','Completed this autoban run');
    autoban::Logging::OutputHandler('DEBUG','autoban',"Run took $elapsedAutobanTime seconds");
    autoban::Logging::OutputHandler('INFO','autoban','');
}







__END__

=head1 NAME

autoban - Realtime attack and abuse defence and intrusion prevention

=head1 SYNOPSIS

autoban [options]

     Options:
       -f,--foreground  run in foreground
       -h,-help         brief help message
       -l,--loglevel    logging level
       --man            full documentation
       -s,--safe        safe mode
       -v,--version     display version

=head1 DESCRIPTION

B<autoban> is used to analyze inputs, apply filters and push data to outputs
If using a flag that sets an option that is also set in the config, the flag value will be used. 

=head1 OPTIONS

No options are required

=over 8

=item B<-f, --foreground>
Run in foreground. This will enable you to run autoban in the foreground, even if the daemon is running. This will also cause messages to go to stdout instead of the log file. autoban will exit after running once.

=item B<-h, --help>
Print a brief help message and exits.

=item B<-l, --loglevel [log level]> 
Specify logging level (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)

=item B<--man>
Print the manual page.

=item B<-s,--safe>
Run in safe mode. This will not preform any bans, but instead display what would have happened. This is useful if you want to run this in read only mode. This will invoke info level logging

=item B<-v, --version> 
Display program version 


=back

=head1 CHANGELOG

B<0.1.0> 12-10-2013 Initial release. All future releases until there is a stable product will be under this version. 

=cut
