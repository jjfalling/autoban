#This plugin takes data from the nginx_es input and checks to see

use warnings;

#TODO: move to config
my $high = 5;
my $low = 4;
my $banTheshold = 8;

sub apache_filter() {
    debugOutput("\n**DEBUG: Running apache_filter\n");
    apacheFlagForBan();
}



sub apacheFlagForBan() {




    #look through the list of ips, and 
    foreach my $ip (sort keys %{$data->{'apache-es-input'}->{'ipData'}}) {

	$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "";
	$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} = 0;

        #skip anything marked as a crawler
        if ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'isCrawler'} eq "false" ) {

	    if ($autobanConfig->param("apache-es-input.cookie")){
            	if ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'hasCookie'} ne "true" ) {$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "No cookie ,"; $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $low)}
	    }
            
            if ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'hasUserAgent'} ne "true" ) {$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "No useragent ,"; $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $high)}
            
            #if ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'isLoggedIn'} ne "true" ) {$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "Not logged in ,"; $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $low)}
            
            if ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'badResponsePercentage'} > 45 ) {$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "Bad to good response code ratio too high ,"; $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $high)}
            
            if ($autobanConfig->param("apache-es-input.writeUrl")){
            	if ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'writeUrlPercentage'} > 60 ) {$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "Write to read ratio too high ,"; $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $high)}
            }
            
            if ($autobanConfig->param("apache-es-input.internalComparison")){
            	if ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'internalComparison'} > 50 ) {$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'} = "$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'}" . "Too many hits compared to internal comparison ,"; $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} = ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} + $low)}
            }

	    #$isp = isp_of_ip($ip) || '-';
	    $comment = substr(($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banComment'}),0,-1);
	    $comment = "apache-filter - Score: $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} Reason: " . "$comment";
	    debugOutput("**DEBUG: IP: $ip COMMENT: $comment ");
	    
        }

	#check if ip is at or above threashold for ban
	if ($data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banScore'} >= $banTheshold){ 
	    $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banFlag'} = "true";
	}
	else{
	    $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'banFlag'} = "false";
	}

    }

    
    
}



#required to import
1;
