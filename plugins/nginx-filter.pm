#This plugin takes data from the nginx_es input and checks to see

use warnings;

#TODO: move to config
my $high = 5;
my $low = 4;
my $banTheshold = 8;
 
sub nginx_filter() {
	debugOutput("\n**DEBUG: Running nginx_filter\n");
	nginxFlagForBan();
}



sub nginxFlagForBan() {




    #look through the list of ips, and 
    foreach my $ip (sort keys %{$data->{'nginx-es-input'}->{'ipData'}}) {

	$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "";
	$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} = 0;

        #skip anything marked as a crawler
        if ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'isCrawler'} eq "false" ) {

			if ($autobanConfig->param("nginx-es-input.cookie")){
            	if ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'hasCookie'} ne "true" ) {$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "No cookie ,"; $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $low)}
            }
            
            if ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'hasUserAgent'} ne "true" ) {$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "No useragent ,"; $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $high)}
            
            #if ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'isLoggedIn'} ne "true" ) {$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "Not logged in ,"; $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $low)}
            
            if ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'badResponsePercentage'} > 45 ) {$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "Bad to good response code ratio too high ,"; $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $high)}
            
            if ($autobanConfig->param("nginx-es-input.writeUrl")){
            	if ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'writeUrlPercentage'} > 60 ) {$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "Write to read ratio too high ,"; $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $high)}
            }
            
            if ($autobanConfig->param("nginx-es-input.internalComparison")){
            	if ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'internalComparison'} > 50 ) {$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "Too many hits compared to internal comparison ,"; $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $low)}
            }

			#$isp = isp_of_ip($ip) || '-';
			$comment = substr(($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'}),0,-1);
			$comment = "nginx-filter - Score: $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} Reason: " . "$comment";
			debugOutput("**DEBUG: IP: $ip COMMENT: $comment ");
	
        }

	    #check if ip is at or above threashold for ban
		if ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} >= $banTheshold){ 
			$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banFlag'} = "true";
		}
		else{
			$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banFlag'} = "false";
		}

    }

 
 
}



#required to import
1;
