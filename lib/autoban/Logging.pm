########################################
package autoban::Logging;
########################################
#taks based around logging

#****************************************************************************
#*   autoban -  autoban::Logging                                            *
#*                                                                          *
#*   Copyright (C) 2015 by Jeremy Falling except where noted.               *
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

#use strict;
use warnings;
use feature "switch";

#disable experimental warnings
no if $] >= 5.018, warnings => "experimental";

#this configures the root logger with what appender and log level we want
########################################
sub ConfigRootLogger {
########################################

    my $logAppender;
    if ($autoban::foreground) {
        $logAppender = 'SCREEN';

    }
    else {
        $logAppender = 'LOGFILE';
    }

    return "$autoban::autobanLogLevel, $logAppender";
}

#function to handle all output from this program (fingers crossed...)
########################################
sub OutputHandler {
########################################
    my $logType    = $_[0];
    my $moduleName = $_[1];
    my $logOutput  = $_[2];

    given ($logType) {
        when ('LOGCARP')    { $autoban::autobanLog->logcarp("$moduleName: $logOutput") }
        when ('LOGCLUCK')   { $autoban::autobanLog->logcluck("$moduleName: $logOutput") }
        when ('LOGCROAK')   { $autoban::autobanLog->logcroak("$moduleName: $logOutput") }
        when ('LOGCONFESS') { $autoban::autobanLog->logconfess("$moduleName: $logOutput") }
        when ('FATALDIE')   { $autoban::autobanLog->logdie("$moduleName: $logOutput") }
        when ('FATAL')      { $autoban::autobanLog->fatal("$moduleName: $logOutput") }
        when ('ERROR')      { $autoban::autobanLog->error("$moduleName: $logOutput") }
        when ('WARN')       { $autoban::autobanLog->warn("$moduleName: $logOutput") }
        when ('INFO')       { $autoban::autobanLog->info("$moduleName: $logOutput") }
        when ('DEBUG')      { $autoban::autobanLog->debug("$moduleName: $logOutput") }
        when ('TRACE')      { $autoban::autobanLog->trace("$moduleName: $logOutput") }
        when ('OFF')        { $autoban::autobanLog->off("$moduleName: $logOutput") }
        default             { $autoban::autobanLog->logcluck("$moduleName: AUTOBAN INTERNAL ERROR: unknown logType passed to OutputHandler!") }
    }
}

1;
