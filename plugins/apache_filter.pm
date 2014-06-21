#This plugin takes data from the nginx_es input and checks to see

#****************************************************************************
#*   autoban - apache filter                                                *
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

use warnings;

#TODO: move to config
my $banTheshold = 8;

sub apache_filter() {
    enhancedOutput("verbose","\n\nRunning apache_filter\n");
    apacheFlagForBan();
}


sub apacheFlagForBan() {



    #look through the list of ips, and 
    foreach my $ip (sort keys %{$data->{'apache-es-input'}->{'ipData'}}) {

	$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "";
	$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} = 0;

	

	if ($autobanConfig->param("apache-es-input.cookie")){
	    if ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'hasCookie'} ne "true" ) {$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "No cookie ,"; $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $autobanConfig->param("apache-filter.lowPenality"))}
	}
	
	if ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'hasUserAgent'} ne "true" ) {$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "No useragent ,"; $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $autobanConfig->param("apache-filter.highPenality"))}
	
	#if ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'isLoggedIn'} ne "true" ) {$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "Not logged in ,"; $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $autobanConfig->param("apache-filter.lowPenality"))}
	
	if ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'badResponsePercentage'} > $autobanConfig->param("apache-filter.badResponsePercentage") ) {$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "Bad to good response code ratio too high ,"; $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $autobanConfig->param("apache-filter.highPenality"))}
	
	if ($autobanConfig->param("apache-es-input.writeUrl")){
	    if ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'writeUrlPercentage'} > $autobanConfig->param("apache-filter.writeUrlPercentage")) {$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "Write to read ratio too high ,"; $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $autobanConfig->param("apache-filter.highPenality"))}
	}
	
	if ($autobanConfig->param("apache-es-input.internalComparison")){
	    if ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'internalComparison'} > $autobanConfig->param("apache-filter.internalComparison") ) {$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "Too many hits compared to internal comparison ,"; $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $autobanConfig->param("apache-filter.lowPenality"))}
	}

	$comment = substr(($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'}),0,-1);
	$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "apache-filter - Score: $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} Reason: " . "$comment";
       	

	#check if ip is at or above threashold for ban
	if ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} >= $autobanConfig->param("apache-filter.banThreshold")){ 
	    $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banFlag'} = "true";
	    enhancedOutput("verbose","Flagging IP: $ip for ban. COMMENT: $comment ");
	}
	else{
	    $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banFlag'} = "false";
	    enhancedOutput("debug","**DEBUG: IP: $ip COMMENT: $comment ");

	}

    }

    
    
}



#required to import
1;
