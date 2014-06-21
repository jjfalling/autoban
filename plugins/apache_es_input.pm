#get nginx logs from elasticsearch

#****************************************************************************
#*   autoban - apache_es_input plugin                                       *
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

use Geo::IP::PurePerl;
use List::MoreUtils 'any';
use warnings;
#use strict;

my $facetedData;
my $result2;


#typically you want more then 5 or 10 min to normalize the data
my $curlOutput;
my $curlExitCode;
my $num_purges;


sub apache_es_input {

    enhancedOutput("verbose","\n\nRunning apache_es_input\n");

    enhancedOutput("verbose","Searching for the highest requesting ips");



    my $result = $es->search(
	index => $autobanConfig->param('autoban.logstashIndex'),
	body  => {
	    facets => {
		ipFacet => {
		    terms => {
			field =>  $autobanConfig->param('apache-es-input.facetFeild'),
			size => $autobanConfig->param('apache-es-input.topIps'),
		    },
		    facet_filter => {
			and => [
			    {
				term => {
				    _type => $autobanConfig->param('apache-es-input.logType')
				}
			    },
			    {
				range => {
				    '@timestamp' => {
					gte => $autobanConfig->param('apache-es-input.searchPeriod')
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


    enhancedOutput("debug","**DEBUG: Search took $result->{'took'}ms");



    #my (@bad, $facet);
    foreach my $res (@{$result->{'facets'}->{'ipFacet'}->{'terms'}}) {
	next if $res->{'term'} eq '-';
	$facetedData->{'ip'}->{$res->{'term'}} = $res->{'count'};
	my $ip = $res->{'term'};
	$ip =~ s/\.(\d{1,3})$//;
    }



    if ($autobanConfig->param("apache-es-input.internalComparison")){
	$num_purges = $facetedData->{'ip'}->{$autobanConfig->param("apache-es-input.internalComparison")};
	if ($num_purges == 0){print "Looks like internal comparison has no data, using backup setting\n"; $num_purges = $autobanConfig->param("apache-es-input.internalComparisonBackupCount");}
    }
    
    #get some data on these ips and their last x requests  
    gatherBasicIpInfoApache();	

}



sub gatherBasicIpInfoApache {
    #look at each ip found

    enhancedOutput("verbose","Looking at each of the highest requesting ips");

    foreach my $ip (sort keys %{$facetedData->{'ip'}}) {
        #make a hash key/val for the current ip
        my $num_reqs = $facetedData->{'ip'}->{$ip};
        

        #possible issue if there is not a min of an empty string in the config file for this option
        if ($autobanConfig->param("apache-es-input.internalComparison")){
	    my $perc = $num_reqs / $num_purges;
	    my $pretty_perc = sprintf("%.3f", $perc);
	    $pretty_perc *= 100;
	    $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'internalComparison'} = $pretty_perc;

	}

	
        #$data->{'apache-es-input'}->{'ipData'}->{$ip}->$data->{$ip}->{'isCrawler'} = checkForCrawlers($ip);
        $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'hitCount'} = $num_reqs;
        
	enhancedOutput("debug","**DEBUG: Inspecting $ip");

	#temp vars
	my ($isLoggedIn, $postMethodPercentage, $postPercentage, $badResponseCodePercent, $varyUserAgent, $hasCookie, $hasUserAgent);
	my $postActionCount = 0;
	my $tempBadResponseCount = 0; 
	my $writeUrlCount = 0;



	my $result2 = $es->search(
	    index => $autobanConfig->param('autoban.logstashIndex'),
	    size => $autobanConfig->param('apache-es-input.maxNumOfResults'),
	    body  => {
		filter => {
		    and => [
			{
			    term => {
				_type => $autobanConfig->param('apache-es-input.logType')
			    }
			},
			{
			    range => {
				'@timestamp' => {
				    gte => $autobanConfig->param('apache-es-input.searchPeriod')
				}
			    }
			}
			]
		},
			    query => {
				match => { 
				    $autobanConfig->param('apache-es-input.facetFeild') => $ip
				}

			}
	    }
	    );



	enhancedOutput("debug","**DEBUG: Search took $result2->{'took'}ms");


	#figure out how many results there are and if greater then maxNumOfResults
	my $total;
	if ($result2->{'hits'}->{'total'} >= $autobanConfig->param('apache-es-input.maxNumOfResults')) {
	    $total = $autobanConfig->param('apache-es-input.maxNumOfResults');
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
	    if ($autobanConfig->param("apache-es-input.cookie")){
		if ($tempData->{'_source'}->{'cookies'} =~ /$autobanConfig->param('apache-es-input.cookie')/i){$hasCookie = "true";}
	    }

	    if ($tempData->{'_source'}->{'agent'} ne "-"){$hasUserAgent = "true";}
	    if ($tempData->{'_source'}->{'verb'} =~ /post/i){$postActionCount++;}
	    if ($tempData->{'_source'}->{'response'} !~ /$autobanConfig->param('apache-es-input.goodResponseCodes')/i){$tempBadResponseCount++;}
	    if ($tempData->{'_source'}->{'request'} =~ /$autobanConfig->param('apache-es-input.writeUrl')/i){$writeUrlCount++;}
	    
	    $i++;
	    
	}

	#put final data into hash
	if ($autobanConfig->param("apache-es-input.cookie")){
	    $data->{'apache-es-input'}->{'ipData'}->{$ip}->{'hasCookie'} = $hasCookie ||  "false";
	}

	$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'hasUserAgent'} = $hasUserAgent;

	$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'postMethodPercentage'} = getPercentageApache($autobanConfig->param('apache-es-input.maxNumOfResults'), "$postActionCount");
	$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'badResponsePercentage'} = getPercentageApache($autobanConfig->param('apache-es-input.maxNumOfResults'), "$tempBadResponseCount");
	$data->{'apache-es-input'}->{'ipData'}->{$ip}->{'writeUrlPercentage'} = getPercentageApache($autobanConfig->param('apache-es-input.maxNumOfResults'), "$writeUrlCount");

    }
}




sub getPercentageApache {

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


