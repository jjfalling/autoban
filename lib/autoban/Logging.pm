########################################
package autoban::Logging;
########################################
#use strict;
use warnings;
use feature "switch";



#this configures the root logger with what appender and log level we want
########################################
sub ConfigRootLogger {
########################################

    my $logAppender;
    if ($autoban::foreground) {
	$logAppender='SCREEN';
	
    }else {
	$logAppender='LOGFILE';
    }

    return "$autoban::autobanLogLevel, $logAppender";
}


#function to handle all output from this program (fingers crossed...) 
########################################
sub OutputHandler {
########################################
    my $logType = $_[0];
    my $moduleName = $_[1];
    my $logOutput = $_[2];

    given ($logType){
	#I am using FATAL as a way to let other logging methods or tasks finish before we die
   	when ('FATALDIE') {$autoban::autobanLog->logdie("$moduleName: $logOutput")}  
	when ('FATAL') {$autoban::autobanLog->fatal("$moduleName: $logOutput")}  
	when ('ERROR') {$autoban::autobanLog->error("$moduleName: $logOutput")}  
	when ('WARN') {$autoban::autobanLog->warn("$moduleName: $logOutput")}  
	when ('INFO') {$autoban::autobanLog->info("$moduleName: $logOutput")}  
	when ('DEBUG') {$autoban::autobanLog->debug("$moduleName: $logOutput")} 
	when ('TRACE') {$autoban::autobanLog->trace("$moduleName: $logOutput")} 
	default  {$autoban::autobanLog->logcluck("$moduleName: AUTOBAN INTERNAL ERROR: unknown logType passed to OutputHandler!")} 
    }
}



1;
