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

my ($help, $man, $foreground, $debug, $verbose, $version, $daemon);
our $safe;
my @plugins;

#TODO: fix whole debug vs verbose thing. 
Getopt::Long::Configure('bundling');
GetOptions
    ('h|help|?' => \$help, 
     'man' => \$man,
     "d|debug" => \$debug,
     "D|daemon" => \$daemon,
     "V|verbose" => \$verbose,     
     'f|foreground' => \$foreground,
     "v|version" => \$version,
     "s|safe" => \$safe) or pod2usage(2);

pod2usage(-verbose => 1) if $help;
pod2usage(-verbose => 3, -exitval => 0) if $man;

if ($version) {
    print "autoban $autobanVersion\n\n";
    exit;
}

# Before we do anything else, try to get an exclusive lock
my $lock = File::NFSLock->new($0, LOCK_EX|LOCK_NB); 

#unless we are running in the foreground, die if there is another copy
unless ($foreground) {
    die "\nERROR: I am already running and I will not run another demonized copy!\nTo run manually while the daemon is running, give the foreground flag. See help or the man page\n\n" unless $lock;
}


#check if config file exists, and if not exit
unless (-e $configFile) {
    print "\nERROR: $configFile was found! Please see the man page!\n";
    exit 1;
}

#this needs to not be a global....
our $autobanConfig = new Config::Simple(filename=>"$configFile");


print "\n\n";
print "Starting autoban v.$autobanVersion, please wait...\n\n";

if ($debug){
    print "\n\n**DEBUG: Debug output enabled\n";
}
elsif ($verbose){
    print "\n\nVerbose output enabled\n";
}


#check if running as root, if so give warning.
if ( $< == 0 ) {
    print "\n********************************************************\n";
    print "* DANGERZONE: You are running autoban as root!         *\n";
    print "* This is probably a horrible idea security wise...    *\n";
    print "********************************************************\n\n\n"; 
}

#Define a HoHoHoL(?) to shove all of our data in. 
#I originally did this by ip instead of plugin, but I want to have the ability to specify routing between plugins and separate their data.
# the format will be data = {plugin} => {ipData} => [info about the ip]
#                                       {pluginData} => (varies by plugin)
our $data;


#create the shared es instance
our $es = Search::Elasticsearch->new(
    cxn_pool => $autobanConfig->param('autoban.cnx_pool'),
    nodes => [$autobanConfig->param('autoban.esNodes')],
    #trace_to => 'Stderr',
    ) || die "Cannot create new es instance: \$es\n";


#look through the plugin directories and load the plugins
enhancedOutput("debug","**DEBUG: Checking for autoban index");


#TODO: when creating index, ensure autoban template exists and apply if not
#ensure the autoban index exists, if not, throw a warning and create it, exit if we cannot
#$es->indices->create(index=> $autobanConfig->param('autoban.esNodes'));
my $autobanIndexStatus = $es->indices->exists(
    index   => $autobanConfig->param('autoban.esAutobanIndex')
    );
unless ($autobanIndexStatus) {
    print "WARNING: autboan's index (", $autobanConfig->param('autoban.esAutobanIndex'), ") was not found. Creating it.\n";
    die "ERROR: could not create autoban index..." unless $es->indices->create(index=> $autobanConfig->param('autoban.esAutobanIndex'));
    enhancedOutput("debug","**DEBUG: autoban index created");
}
else {
    enhancedOutput("debug","**DEBUG: autoban index exists");
}



#when safemode is enabled, do not preform any actions. only gather data and report to the user. 
if ($safe) {
    print "\n\"And remember this: there is no more important safety rule than to wear these — safety glasses\" (Safe mode is enabled. no bans will be created)\n";
    #enable verbose mode (-v) as this option is rather useless without it since the user will not see what would have been done
    $verbose=1;

}


#load and run plugins specified in config
foreach my $runPlugin ($autobanConfig->param('autoban.runPlugins')) {

    #ensure the request plugin exists
    unless (-e "$autobanPath/plugins/$runPlugin.pm") {
	print "\nERROR: Plugin $runPlugin was found! Plugin should be $autobanPath/plugins/$runPlugin.pm!\n";
	exit 1;
    }
    require "$autobanPath/plugins/$runPlugin.pm";

    #work around strict not allowing string as a subroutine ref
    my $subref = \&$runPlugin;

    #try to run the function
    &$subref();


}


#This function will be used to give the user output, if they so desire
sub enhancedOutput {
    #we get two inputs, first is the type of message, second is the message
    my $outputType = $_[0];
    my $humanStatus = $_[1];
    my $prepend = $_[2];
    
    if (($debug) && ($outputType eq "debug" || $outputType eq "verbose")){
	print "$humanStatus\n";
    }
    elsif (($verbose) && ($outputType eq "verbose")){
	print "$humanStatus\n";	
    }
}


__END__

=head1 NAME

autoban - Realtime attack and abuse defence and intrusion prevention

=head1 SYNOPSIS

autoban [options]

     Options:
       -h,-help         brief help message
       -man             full documentation
       -d,--debug       enable debug mode
       -V,--verbose     enable verbose messages
       -D,--daemon      run as a daemon
       -f,--foreground  run in foreground
       -s,--safe        safe mode
       -v,--version     display version

=head1 DESCRIPTION

B<autoban> is used to analyze inputs, apply filters and push data to outputs


=head1 OPTIONS

No options are required

=over 8

=item B<-h, --help>
Print a brief help message and exits.

=item B<--man>
Print the manual page.

=item B<-d, --debug> 
Enable debug mode with a rather high amount of output (debug lines start with **DEBUG). This will supercede the verbose flag

=item B<-V, --verbose> 
Enable verbose messages

=item B<-D, --daemon> 
Run as a daeon

=item B<-f, --foreground>
Run in foreground. This will enable you to run autoban in the foreground, even if the daemon is running.

=item B<-s,--safe>
Run in safe mode. This will not preform any bans, but instead display what would have happened. This is useful if you want to run this in read only mode. This will invoke verbose mode (-v)

=item B<-v, --version> 
Display program version 

=back

=head1 CHANGELOG

B<0.1> 12-10-2013 Initial release. All other releases until there is a stable product will be under this version. 

=cut
