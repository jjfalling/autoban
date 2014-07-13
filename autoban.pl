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


use strict;
use warnings;
use Data::Dumper;
use Config::Simple;
use Pod::Usage;
use Getopt::Long;
use Fcntl qw(LOCK_EX LOCK_NB);
use File::NFSLock;
use Cwd 'abs_path';
use File::Basename;
use Time::HiRes qw(usleep ualarm gettimeofday tv_interval);
use Log::Log4perl qw(:easy);
use feature "switch";


#get offical elasticsearch module @ https://metacpan.org/pod/Search::Elasticsearch
use Search::Elasticsearch;
die "The Search::Elasticsearch module must be >= v1.11! You have v$Search::Elasticsearch::VERSION\n\n"
    unless $Search::Elasticsearch::VERSION >= 1.11;

#get the full path by using abs_path, then remove the name of the program from the path.
my $autobanPath = abs_path($0);
my $autobanFilename = basename(__FILE__);
$autobanPath =~ s/$autobanFilename//;

#Define config file
my $configFile = "$autobanPath/autoban.cfg";

#define program version
my $autobanVersion = "0.0.1";

my ($help, $man, $foreground, $loglevel, $version, $daemon);
our $safe; #<-- this should probally not be handled as a global....
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
    exit 1;
}

#set the log level via the flag or fall back to the config
my $autobanLogLevel;
if ($loglevel){
    $autobanLogLevel = $loglevel;
}
else {
    $autobanLogLevel = $autobanConfig->param('autoban.LogLevel');
}

# Before we do anything else, try to get an exclusive lock
my $lock = File::NFSLock->new($0, LOCK_EX|LOCK_NB); 

#set up the logging.
my $rootLoggerConfig;
#finish setting up logging
Log::Log4perl::init("$autobanPath/logging.cfg");

our $autobanLog = Log::Log4perl->get_logger();


unless ($foreground) {

    #we are not running in the foreground check if there is another copy of this program running and die if so
   outputHandler('FATALDIE', "autoban is already running and I will not run another demonized copy! To run autoban manually while the daemon is running, give the foreground flag. See help or the man page") unless $lock;
 
}



#Any output past this point should be handled by the logging system
outputHandler('INFO','autoban','');
outputHandler('INFO','autoban',"Starting autoban v.$autobanVersion, please wait...");
outputHandler('INFO','autoban','');


#check if running as root, if so give warning.
if ( $< == 0 ) {
    outputHandler('ERROR','autoban','');
    outputHandler('ERROR','autoban','********************************************************');
    outputHandler('ERROR','autoban','*    DANGERZONE: You are running autoban as root!      *');
    outputHandler('ERROR','autoban','*    This is probably a horrible idea security wise... *');
    outputHandler('ERROR','autoban','********************************************************');
    outputHandler('ERROR','autoban','');
}

#Define a HoHoHoL(?) to shove all of our data in. 
#I originally did this by ip instead of plugin, but I want to have the ability to specify routing between plugins and separate their data.
# the format will be data = {plugin} => {ipData} => [info about the ip]
#                                       {pluginData} => (varies by plugin)
our $data;


#create the shared es connection
our $es = Search::Elasticsearch->new(
    cxn_pool => $autobanConfig->param('autoban.cnx_pool'),
    nodes => [$autobanConfig->param('autoban.esNodes')],
    #log_to   => 'Stderr',
    #trace_to => 'Stderr',
    ) || $autobanLog->logdie("Cannot create new es instance: $es");
#TODO: the errorchecking ^^ will never happen as Search::Elasticsearch dies when it has an issue. Either I need to patch the module or figure out how to make it not kill us...

#look through the plugin directories and load the plugins
outputHandler('DEBUG','autoban','Checking for autoban index');


#TODO: when creating index, ensure autoban template exists and apply if not
#ensure the autoban index exists, if not, throw a warning and create it, exit if we cannot
#$es->indices->create(index=> $autobanConfig->param('autoban.esNodes'));
my $autobanIndexStatus = $es->indices->exists(
    index   => $autobanConfig->param('autoban.esAutobanIndex')
    );
unless ($autobanIndexStatus) {
   outputHandler('DEBUG','autoban',"autboan's index (", $autobanConfig->param('autoban.esAutobanIndex'), ") was not found. This is normal if this is the first time running autoban, otherwise something delete it. I am creating the index in elasticsearch now.\n");
    
    outputHandler('FATALDIE','autoban',"ERROR: could not create autoban index...") unless $es->indices->create(index=> $autobanConfig->param('autoban.esAutobanIndex'));
    outputHandler('DEBUG','autoban','autoban index created');
}
else {
    outputHandler('DEBUG','autoban','autoban index exists');
}


#when safemode is enabled, do not preform any actions. only gather data and report to the user. 
if ($safe) {
    outputHandler('INFO','autoban','Safe mode is enabled. No bans will be created');
}


#load and run plugins specified in config
foreach my $runPlugin ($autobanConfig->param('autoban.runPlugins')) {

    #ensure the request plugin exists
    unless (-e "$autobanPath/plugins/$runPlugin.pm") {
	outputHandler('FATALDIE','autoban',"Plugin $runPlugin was found! Plugin should be $autobanPath/plugins/$runPlugin.pm!");
    }
    require "$autobanPath/plugins/$runPlugin.pm";

    #work around strict not allowing string as a subroutine ref
    my $subref = \&$runPlugin;

    outputHandler('INFO','autoban','');
    outputHandler('INFO','autoban',"Running plugin $runPlugin");

    #get time just before running module
    my $modPluginTime = [gettimeofday];

    #try to run the function
    &$subref();
    
    #get amt of time the plugin took to run
    my $elapsedPluginTime = tv_interval ($modPluginTime);
    outputHandler('DEBUG','autoban',"Plugin $runPlugin took $elapsedPluginTime seconds to run");
    

}

#function to handle all output from this program (fingers crossed...) 
sub outputHandler {
    my $logType = $_[0];
    my $moduleName = $_[1];
    my $logOutput = $_[2];

    given ($logType){
	#I am using FATALDIE as a way to let other logging methods or tasks finish before we die
   	when ('FATALDIE') {$autobanLog->logdie("$moduleName: $logOutput")}  
	when ('FATAL') {$autobanLog->fatal("$moduleName: $logOutput")}  
	when ('ERROR') {$autobanLog->error("$moduleName: $logOutput")}  
	when ('WARN') {$autobanLog->warn("$moduleName: $logOutput")}  
	when ('INFO') {$autobanLog->info("$moduleName: $logOutput")}  
	when ('DEBUG') {$autobanLog->debug("$moduleName: $logOutput")} 
	when ('TRACE') {$autobanLog->trace("$moduleName: $logOutput")} 
	default  {$autobanLog->logcluck("$moduleName: AUTOBAN INTERNAL ERROR: unknown logType passed to outputHandler!")} 
    }

}



__END__

=head1 NAME

autoban - Realtime attack and abuse defence and intrusion prevention

=head1 SYNOPSIS

autoban [options]

     Options:
       -D,--daemon      run as a daemon
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

=item B<-D, --daemon> 
Run as a daeon

=item B<-f, --foreground>
Run in foreground. This will enable you to run autoban in the foreground, even if the daemon is running. This will also cause messages to go to stdout instead of the log file. 

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

B<0.0.1> 12-10-2013 Initial release. All future releases until there is a stable product will be under this version. 

=cut
