#This plugin takes data from the nginx_es input and checks to see

#****************************************************************************
#*   autoban - nginx filter                                                 *
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



sub nginx_filter() {
    enhancedOutput("verbose","\n\nRunning nginx_filter\n");
    nginxFlagForBan();
}


sub nginxFlagForBan() {


    #look through the list of ips, and 
    foreach my $ip (sort keys %{$data->{'nginx-es-input'}->{'ipData'}}) {

	$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "";
	$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} = 0;



	if ($autobanConfig->param("nginx-es-input.cookie")){
	    if ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'hasCookie'} ne "true" ) {$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "No cookie ,"; $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $autobanConfig->param("nginx-filter.lowPenality"))}
	}
	
	if ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'hasUserAgent'} ne "true" ) {$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "No useragent ,"; $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $autobanConfig->param("nginx-filter.highPenality"))}
	
	#if ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'isLoggedIn'} ne "true" ) {$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "Not logged in ,"; $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $autobanConfig->param("nginx-filter.lowPenality"))}
	
	if ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'badResponsePercentage'} >  $autobanConfig->param("nginx-filter.badResponsePercentage") ) {$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "Bad to good response code ratio too high ,"; $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $autobanConfig->param("nginx-filter.highPenality"))}
	
	if ($autobanConfig->param("nginx-es-input.writeUrl")){
	    if ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'writeUrlPercentage'} > $autobanConfig->param("nginx-filter.writeUrlPercentage") ) {$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "Write to read ratio too high ,"; $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $autobanConfig->param("nginx-filter.highPenality"))}
	}
	
	if ($autobanConfig->param("nginx-es-input.internalComparison")){
	    if ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'internalComparison'} > $autobanConfig->param("nginx-filter.internalComparison") ) {$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "Too many hits compared to internal comparison ,"; $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $autobanConfig->param("nginx-filter.lowPenality"))}
	}

	$comment = substr(($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'}),0,-1);
	$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "nginx-filter - Score: $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} Reason: " . "$comment";	
	

	#check if ip is at or above threashold for ban
	if ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} >= $autobanConfig->param("nginx-filter.banThreshold")){ 
	    $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banFlag'} = "true";
	    enhancedOutput("verbose","Flagging IP: $ip for ban. COMMENT: $comment ");

	}
	else{
	    $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banFlag'} = "false";
	    enhancedOutput("debug","**DEBUG: IP: $ip COMMENT: $comment ");

	}

    }

    
    
}



#required to import
1;
