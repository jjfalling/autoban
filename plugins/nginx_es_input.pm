#get nginx logs from elasticsearch

#****************************************************************************
#*   autoban - nginx_es input                                               *
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

use List::MoreUtils 'any';
use warnings;
#use strict;

my $facetedData;
my $result2;
my $curlOutput;
my $curlExitCode;
my $num_purges;


sub nginx_es_input {

    outputHandler('INFO','nginx_es_input','Searching for the highest requesting ips');



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
					gte =>  $autobanConfig->param('nginx-es-input.searchPeriod')
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


    outputHandler('DEBUG','nginx_es_input',"Search took $result->{'took'}ms");


    #my (@bad, $facet);
    foreach my $res (@{$result->{'facets'}->{'ipFacet'}->{'terms'}}) {
	next if $res->{'term'} eq '-';
	$facetedData->{'ip'}->{$res->{'term'}} = $res->{'count'};
	my $ip = $res->{'term'};
	$ip =~ s/\.(\d{1,3})$//;
    }


    if ($autobanConfig->param("nginx-es-input.internalComparison")){
	#see if we have any data for the internalComparison, if not use internalComparisonBackupCount 
	if ($facetedData->{'ip'}->{$autobanConfig->param("nginx-es-input.internalComparison")}) {
	    $num_purges = $facetedData->{'ip'}->{$autobanConfig->param("nginx-es-input.internalComparison")};
	}
	else {
	    outputHandler('INFO','nginx_es_input','Looks like internal comparison has no data, using backup setting');
	    $num_purges = $autobanConfig->param("nginx-es-input.internalComparisonBackupCount");
	}

    }
    else {
	outputHandler('INFO','nginx_es_input','No internalComparison provided, skipping');
    }

    
    #get some data on these ips and their last x requests  
    gatherBasicIpInfo();

}



sub gatherBasicIpInfo {
    #look at each ip found

    outputHandler('DEBUG','nginx_es_input','Looking at each of the highest requesting ips');

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
        
	outputHandler('DEBUG','nginx_es_input',"Inspecting $ip");

	#temp vars
	my ($isLoggedIn, $postMethodPercentage, $postPercentage, $badResponseCodePercent, $varyUserAgent, $hasCookie);
	my $hasUserAgent = "false";
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
				    gte => $autobanConfig->param('nginx-es-input.searchPeriod')
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


	outputHandler('DEBUG','nginx_es_input',"Search took $result2->{'took'}ms");


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

	    if ($tempData->{'_source'}->{'http_user_agent'} ne "\"-\""){$hasUserAgent = "true";}
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




#required to import
1;

