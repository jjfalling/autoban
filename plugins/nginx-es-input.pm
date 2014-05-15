#get nginx logs from elasticsearch

use Geo::IP::PurePerl;
use List::MoreUtils 'any';
use warnings;
#use strict;

my $facetedData;
my $result2;
my $high = 5;
my $low = 4;


#typically you want more then 5 or 10 min to normalize the data
my $dt_period = 'now-15m';
my $type = 'nginxAccess';
my $curlOutput;
my $curlExitCode;
my $num_purges;


sub nginx_es_input {

    debugOutput("\n**DEBUG: Running nginx_es_input\n");

    debugOutput("**DEBUG: Searching for the highest requesting ips");



    my $result = $es->search(
       	index => $autobanConfig->param('autoban.logstashIndex'),
	body  => {
	    facets => {
		ipFacet => {
		    terms => {
			field =>  $autobanConfig->param('nginx-es-input.facetFeild'),
			size => $autobanConfig->param('nginx-es-input.topIps'),
		    },
		    facet_filter => {
			and => [
			    {
				term => {
				    _type => $autobanConfig->param('nginx-es-input.logType')
				}
			    },
			    {
				range => {
				    '@timestamp' => {
					gte => $dt_period,
				    }
				}
			    }
			    ]
		    }
		}
	    }

	},
	#use size=0 to only give the faceted data
	size => 0
	);


    debugOutput("**DEBUG: Search took $result->{'took'}ms");


    #my (@bad, $facet);
    foreach my $res (@{$result->{'facets'}->{'ipFacet'}->{'terms'}}) {
	next if $res->{'term'} eq '-';
	$facetedData->{'ip'}->{$res->{'term'}} = $res->{'count'};
	my $ip = $res->{'term'};
	$ip =~ s/\.(\d{1,3})$//;
    }



    if ($autobanConfig->param("nginx-es-input.internalComparison")){
	$num_purges = $facetedData->{'ip'}->{'192.168.15.6'};
	if ($num_purges == 0){print "Looks like internal comparison has no data, using backup setting\n"; $num_purges = $autobanConfig->param("nginx-es-input.internalComparisonBackupCount");}
    }
    
    #get some data on these ips and their last x requests  
    gatherBasicIpInfo();

    #now, lets get the more... interesting data...
    #insepectPerdata();

    #look at ips, and add points against score
    #	debugOutput("**DEBUG: Note: Not listing any crawlers below");
    #	flagForBan();



    

}



sub gatherBasicIpInfo {
    #look at each ip found

    foreach my $ip (sort keys %{$facetedData->{'ip'}}) {
        #make a hash key/val for the current ip
        my $num_reqs = $facetedData->{'ip'}->{$ip};
        

        #possible issue if there is not a min of an empty string in the config file for this option
        if ($autobanConfig->param("nginx-es-input.internalComparison")){
	    my $perc = $num_reqs / $num_purges;
	    my $pretty_perc = sprintf("%.3f", $perc);
	    $pretty_perc *= 100;
	    $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'internalComparison'} = $pretty_perc;

	}

	
        #$data->{'nginx-es-input'}->{'ipData'}->{$ip}->$data->{$ip}->{'isCrawler'} = checkForCrawlers($ip);
        $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'hitCount'} = $num_reqs;
        
	debugOutput("**DEBUG: Inspecting $ip");

	#temp vars
	my ($isLoggedIn, $postMethodPercentage, $postPercentage, $badResponseCodePercent, $varyUserAgent, $hasCookie, $hasUserAgent);
	my $postActionCount = 0;
	my $tempBadResponseCount = 0; 
	my $writeUrlCount = 0;



	my $result2 = $es->search(
	    index => $autobanConfig->param('autoban.logstashIndex'),
	    size => $autobanConfig->param('nginx-es-input.maxNumOfResults'),
	    body  => {
		filter => {
		    and => [
			{
			    term => {
				_type => $autobanConfig->param('nginx-es-input.logType')
			    }
			},
			{
			    range => {
				'@timestamp' => {
				    gte => $dt_period,
				}
			    }
			}
			]
		},
			    query => {
				match => { 
				    $autobanConfig->param('nginx-es-input.facetFeild') => $ip
				}

			}
	    }
	    );


	debugOutput("**DEBUG: Search took $result2->{'took'}ms");


	#figure out how many results there are and if greater then maxNumOfResults
	my $total;
	if ($result2->{'hits'}->{'total'} >= $autobanConfig->param('nginx-es-input.maxNumOfResults')) {
	    $total = $autobanConfig->param('nginx-es-input.maxNumOfResults');
	}
	else {
	    $total = $result2->{'hits'}->{'total'};

	}

	#TODO: add login support (look for item field of $name=$value)
	#Look at each request for this ip
	my $i=0;
	while ($i < $total) {
	    
	    #get data for each request out.         
	    my $tempData = ($result2->{'hits'}->{'hits'}->[$i]);

	    #TODO: make all of this happen in the config 
	    if ($autobanConfig->param("nginx-es-input.cookie")){
		if ($tempData->{'_source'}->{'cookies'} =~ /$autobanConfig->param('nginx-es-input.cookie')/i){$hasCookie = "true";}
	    }

	    if ($tempData->{'_source'}->{'http_user_agent'} ne "-"){$hasUserAgent = "true";}
	    if ($tempData->{'_source'}->{'request_method'} =~ /post/i){$postActionCount++;}
	    if ($tempData->{'_source'}->{'status'} !~ /$autobanConfig->param('nginx-es-input.goodResponseCodes')/i){$tempBadResponseCount++;}
	    if ($tempData->{'_source'}->{'requested_uri'} =~ /$autobanConfig->param('nginx-es-input.writeUrl')/i){$writeUrlCount++;}
	    
	    $i++;
	}

	#put final data into hash
	if ($autobanConfig->param("nginx-es-input.cookie")){
	    $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'hasCookie'} = $hasCookie ||  "false";
	}

	$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'hasUserAgent'} = $hasUserAgent;

	$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'postMethodPercentage'} = getPercentage($autobanConfig->param('nginx-es-input.maxNumOfResults'), "$postActionCount");
	$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'badResponsePercentage'} = getPercentage($autobanConfig->param('nginx-es-input.maxNumOfResults'), "$tempBadResponseCount");
	$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'writeUrlPercentage'} = getPercentage($autobanConfig->param('nginx-es-input.maxNumOfResults'), "$writeUrlCount");
	$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'isCrawler'} = checkForCrawlers($ip);

    }
}


sub insepectPerdata {

    #look through the list of ips, and 
    foreach my $ip (sort keys %{$data}) {
	
        #skip anything marked as a crawler
        if ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'isCrawler'} eq "false" ) {

        }
        else {
	    debugOutput("**DEBUG: Skipping $ip as it appears to be a crawler\n");
	    
        }
    }
}



sub getPercentage {

    my ($first , $second) = (shift, shift);
    if ($second == 0){
        return 0;
	
    }
    else {
        my $perc = $second / $first;
        my $pretty_perc = sprintf("%.3f", $perc);
        $pretty_perc *= 100;
        return $pretty_perc;
    }

}


sub checkForCrawlers {
    my $ip = shift;
    return '' unless $ip;
    #ipv6 regex from http://download.dartware.com/thirdparty/test-ipv6-regex.pl
    return $ip unless $ip =~ /^(\d{1,3}\.){3}\d{1,3}$/ || $ip =~ qr/^(((?=(?>.*?::)(?!.*::)))(::)?([0-9A-F]{1,4}::?){0,5}|([0-9A-F]{1,4}:){6})(\2([0-9A-F]{1,4}(::?|$)){0,2}|((25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9])(\.|$)){4}|[0-9A-F]{1,4}:[0-9A-F]{1,4})(?<![^:]:)(?<!\.)\z/i;
    if ($ip =~ /172.21./){
        my $hostName = `host $ip`;
        $hostName =~ s/.*pointer //;
        return $hostName;
    }
    $isp = isp_of_ip($ip) || '-';

    #run through the array of crawler names, if there is a match, return true
    if ($isp =~ /$autobanConfig->param('nginx-filter.crawlers')/i){
	debugOutput("**DEBUG: $ip appears to be a crawler");
	return "true";
    }else{
	return "false";
    }
    
}

sub isp_of_ip {
    my $ip = shift;
    my $gi = Geo::IP::PurePerl->open($autobanConfig->param('nginx-filter.geoOrgDatabase'));
    return $gi->isp_by_addr($ip);
}




#required to import
1;


__END__


#TODO: All of this needs to be moved somewhere else. partly autoban, partly nginx.filter, partly nginx_ban.output



	#grab a new copy of the ban config on ops01 from the puppet repo
	our @denyArray;
	debugOutput("**DEBUG: Attempting to get current blockips.conf from the provided source");
	$curlOutput = `curl -s -6 https://atuin.falling.se/nginx/blockips.conf -o /tmp/blockips.conf`;
	$curlExitCode = $?;

	#if we couldnt, give an error
	if ( ($curlExitCode >> 8) != 0){
		print "\n\nError: could not fetch nginx ban file, trying to work around this... curl exit code: ", $curlExitCode >> 8,"\n";
	
	}
	else {
		#read the denyfile into an array
		debugOutput("**DEBUG: Was able to get blockips.conf. Reading the file into an array");
		open (DENYFILE, "/tmp/blockips.conf") or print "Error: Can't open nginx blockfile: $!";
		@denyArray = <DENYFILE>;
		close DENYFILE;
	}
	
	


sub checkForCrawlers {
    my $ip = shift;
    return '' unless $ip;
    #ipv6 regex from http://download.dartware.com/thirdparty/test-ipv6-regex.pl
    return $ip unless $ip =~ /^(\d{1,3}\.){3}\d{1,3}$/ || $ip =~ qr/^(((?=(?>.*?::)(?!.*::)))(::)?([0-9A-F]{1,4}::?){0,5}|([0-9A-F]{1,4}:){6})(\2([0-9A-F]{1,4}(::?|$)){0,2}|((25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9])(\.|$)){4}|[0-9A-F]{1,4}:[0-9A-F]{1,4})(?<![^:]:)(?<!\.)\z/i;
    if ($ip =~ /172.21./){
        my $hostName = `host $ip`;
        $hostName =~ s/.*pointer //;
        return $hostName;
    }
    $isp = isp_of_ip($ip) || '-';

    #run through the array of crawler names, if there is a match, return true
        if ($isp =~ /$crawlers/i){
        	debugOutput("**DEBUG: $ip appears to be a crawler");
        	return "true";
        }else{
        	return "false";
        }
    
}



	#run banning process
	my $banCount = 0;
	runBanning();
	
	if ($banCount == 0) {debugOutput("**DEBUG: I found nothing to ban on this run");}
	if (($opt_nodb) && $banCount > 0){print "\n\nPut the above nginx conf lines at the top of /opt/webroot/packages/centos/nginx/conf/sysban/blockips.conf on ops01\nThen run \"force-sysban-run.sh nodb\" on ops01 to push the file out\n\n";}



sub runBanning {

    debugOutput("\n\n");

    #TODO: put in config file
    my $banTheshold = 8;
    #look through the list of ips, and 
    foreach my $ip (sort keys %{$data}) {
        #strip the trailing comma from the string
        $comment = substr(($data->{$ip}->{'banComment'}),0,-1);
        $comment = "AutoBan - Score: $data->{$ip}->{'banScore'} Reason: " . "$comment";
		
        #if above threshold, ban!
        if ($data->{$ip}->{'banScore'} >= $banTheshold){ 
        
        	#if db bans are disabled, print in nginx conf form
			if ($opt_nodb) {
				if ( $curlOutput == 0) {
				
					#check if ip is banned by looking in existing blockips file.
                    my $match_found = any { /$ip/ } @denyArray; 
                    #a match should return 1
					if ( $match_found != 1 ) {
						print "deny $ip;\n";
						$banCount++;
					}
					else{
						debugOutput("**DEBUG: ip already banned in nginx conf: $ip");
					}
				}
				
				#we could not get the sysban config, so just print everything w/o checking
				else{
				
					print "deny $ip;\n";
					$banCount++;
				}

				
			}
			else {
			
				if (($curlExitCode >> 8) == 0) {
				
					#check if ip is banned by looking in existing blockips file.
					my $match_found = any { /$ip/ } @denyArray; 
					#a match should return 1. if there is no match, ban the ip
					if ( $match_found != 1 ) {
						print "Banning: $ip: $comment\n";
						#***REMOVE OR CHANGE this should return a hash with ip :  reason for ban
						#my $banResult = `sysban.pl --add  --what=ip --banlength=30d --value=$ip --note='$comment'  2>&1`;
						#if ($banResult =~ /CREATED/){print "$banResult\n";}else{print "ERROR: $banResult\n";}
						$banCount++;
					}
					else{
						debugOutput("**DEBUG: ip already banned in blockips.conf: $ip");
					}
				}
				
				#we could not get the sysban config, so just try to do a ban anyway...
				else{
				
					print "Banning: $ip: $comment\n";
					#TODO: make this return from hash
					my $banResult = `true'  2>&1`;
					if ($banResult =~ /CREATED/){print "$banResult\n";}else{print "ERROR: $banResult\n";}
					$banCount++;
				
				}

			}


        
        }

	
    }

}
