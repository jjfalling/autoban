#whitelist filter module

#****************************************************************************
#*   autoban - ip_whitelist filter                                          *
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


#this filter will REMOVE matched ips from all of the plugin data to keep them from being blocked. It does not remove active bans from the db.
#this plugin should be the first filter to run after all inputs have finished. 

sub ip_whitelist_filter {
    enhancedOutput("verbose","\n\nRunning whitelist_filter\n");

    use NetAddr::IP;


    #go though each plugin
    foreach my $currentPlugin (keys %{$data}) {

	enhancedOutput("debug","**DEBUG: Looking at plugin data for: $currentPlugin");

	#look at each ip address in the current plugin
	foreach my $currentIp (keys %{$data->{$currentPlugin}->{'ipData'}}) {

	    enhancedOutput("debug","**DEBUG: Checking $currentIp");
	    my $ipAddr = NetAddr::IP->new($currentIp);

	    #check if current ip is in any whitelist subnet
	    foreach my $currentWhitelistItem ($autobanConfig->param('whitelist-filter.whitelistips')) {

		my $network = NetAddr::IP->new($currentWhitelistItem);
		if ($ipAddr->within($network)) {

		    #ip is in whitelist, remove it from the current plugin's data set and move on to next ip
		    enhancedOutput("debug","**DEBUG: $currentIp is in whitelist, removing from data set");
		    delete $data->{$currentPlugin}->{'ipData'}->{$currentIp};
		    last;

		}
	    }
	}
    }
}

1;
