#get nginx logs from elasticsearch

#****************************************************************************
#*   autoban - nginx_es input                                               *
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

use List::MoreUtils 'any';
use warnings;

#use strict;

use Parallel::ForkManager;
use Hash::Merge::Simple qw(merge);

my $aggregatedData;
my $result2;
my $curlOutput;
my $curlExitCode;
my $num_purges = 0;

sub nginx_es_input {

    autoban::Logging::OutputHandler( 'INFO', 'nginx_es_input', 'Searching for the highest requesting ips' );

    #numbers must not be quoted. https://github.com/elasticsearch/elasticsearch/issues/6893
    my $result = $esLogging->search(
        index => $autobanConfig->param('autoban.logstashIndex'),

        #use search type count
        search_type => "count",
        body        => {
            aggs => {
                ipData => {
                    aggs => {
                        ips => {
                            terms => {
                                order => {
                                    _count => 'desc'
                                },
                                size  => int( $autobanConfig->param('nginx-es-input.topIps') ),
                                field => $autobanConfig->param('nginx-es-input.clientIpField')
                            }
                        }
                    },
                    filter => {
                        bool => {
                            must => [
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
                        }
                    }
                }
            }
        }
    );

    my $foundIps = keys @{ $result->{'aggregations'}->{'ipData'}->{'ips'}->{'buckets'} };
    autoban::Logging::OutputHandler( 'DEBUG', 'nginx_es_input', "Search took $result->{'took'}ms, returned $foundIps ips" );

    #go through each returned ip and store it and the hit count
    foreach my $res ( @{ $result->{'aggregations'}->{'ipData'}->{'ips'}->{'buckets'} } ) {
        next if $res->{'key'} eq '-';
        $aggregatedData->{'ip'}->{ $res->{'key'} } = $res->{'doc_count'};
        my $ip = $res->{'key'};
        $ip =~ s/\.(\d{1,3})$//;
    }

    if ( $autobanConfig->param("nginx-es-input.internalComparison") ) {

        #see if we have any data for the internalComparison, if not use internalComparisonBackupCount
        if ( $aggregatedData->{'ip'}->{ $autobanConfig->param("nginx-es-input.internalComparison") } ) {
            $num_purges = $aggregatedData->{'ip'}->{ $autobanConfig->param("nginx-es-input.internalComparison") };
        }
        else {
            autoban::Logging::OutputHandler( 'INFO', 'nginx_es_input', 'Looks like internal comparison has no data, using backup setting' );
            $num_purges = $autobanConfig->param("nginx-es-input.internalComparisonBackupCount");
        }

    }
    else {
        autoban::Logging::OutputHandler( 'INFO', 'nginx_es_input', 'No internalComparison provided, skipping' );
    }

    #get some data on these ips and their last x requests
    gatherBasicIpInfo();

}

sub gatherBasicIpInfo {

    #look at each ip found

    my $pm = Parallel::ForkManager->new( $autobanConfig->param('nginx-es-input.maxProcs') );
    autoban::Logging::OutputHandler( 'TRACE', 'nginx_es_input', "Running with a max of " . $autobanConfig->param('nginx-es-input.maxProcs') . " procs" );

    $pm->run_on_finish(
        sub {
            my ( $pid, $exit_code, $ident, $exit_signal, $core_dump, $retdat ) = @_;
            $data = merge( $data, $retdat );
        }
    );

    autoban::Logging::OutputHandler( 'DEBUG', 'nginx_es_input', 'Looking at each of the highest requesting ips' );

    foreach my $ip ( sort keys %{ $aggregatedData->{'ip'} } ) {
        $pm->start and next;    # do the fork

        my $localData;

        #make a hash key/val for the current ip
        my $num_reqs = $aggregatedData->{'ip'}->{$ip};

        #possible issue if there is not a min of an empty string in the config file for this option
        if ( $autobanConfig->param("nginx-es-input.internalComparison") ) {
            my $perc = $num_reqs / $num_purges;
            my $pretty_perc = sprintf( "%.3f", $perc );
            $pretty_perc *= 100;
            $localData->{'nginx-es-input'}->{'ipData'}->{$ip}->{'internalComparison'} = $pretty_perc;
            autoban::Logging::OutputHandler( 'TRACE', 'nginx_es_input', "$ip is $pretty_perc% of the traffic vs internal comparision" );

        }

        $localData->{'nginx-es-input'}->{'ipData'}->{$ip}->{'hitCount'} = $num_reqs;

        autoban::Logging::OutputHandler( 'DEBUG', 'nginx_es_input', "Inspecting $ip" );

        #temp vars
        my ( $isLoggedIn, $postMethodPercentage, $postPercentage, $badResponseCodePercent, $varyUserAgent, $hasCookie );
        my $hasUserAgent         = "false";
        my $postActionCount      = 0;
        my $tempBadResponseCount = 0;
        my $writeUrlCount        = 0;

        my $result2 = $esLogging->search(
            index => $autobanConfig->param('autoban.logstashIndex'),
            size  => $autobanConfig->param('nginx-es-input.maxNumOfResults'),
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
                        $autobanConfig->param('nginx-es-input.clientIpField') => $ip
                      }

                }
            }
        );

        autoban::Logging::OutputHandler( 'DEBUG', 'nginx_es_input', "Search for $ip took $result2->{'took'}ms" );

        #figure out how many results there are and if greater then maxNumOfResults
        my $total;
        if ( $result2->{'hits'}->{'total'} >= $autobanConfig->param('nginx-es-input.maxNumOfResults') ) {
            $total = $autobanConfig->param('nginx-es-input.maxNumOfResults');
        }
        else {
            $total = $result2->{'hits'}->{'total'};

        }

        #TODO: add login support (look for item field of $name=$value)
        #Look at each request for this ip
        my $i = 0;
        while ( $i < $total ) {

            my $tmpVar;    #seems that there is a problem using config object in regex, so push the current item into this var when needed
                           #get data for each request out.
            my $tempData = ( $result2->{'hits'}->{'hits'}->[$i] );

            #TODO: make all of this happen in the config
            if ( $autobanConfig->param("nginx-es-input.cookie") ) {
                $tmpVar = $autobanConfig->param('nginx-es-input.cookie');
                if ( $tempData->{'_source'}->{'cookies'} =~ /$tmpVar/i ) { $hasCookie = "true"; autoban::Logging::OutputHandler( 'TRACE', 'nginx_es_input', "$ip has cookie(s): " . $tempData->{'_source'}->{'cookies'} ) }
            }

            if ( $tempData->{'_source'}->{'http_user_agent'} ne "\"-\"" ) { $hasUserAgent = "true"; autoban::Logging::OutputHandler( 'TRACE', 'nginx_es_input', "$ip has useragent of " . $tempData->{'_source'}->{'http_user_agent'} ) }
            if ( $tempData->{'_source'}->{'request_method'} =~ /post/i ) { $postActionCount++; autoban::Logging::OutputHandler( 'TRACE', 'nginx_es_input', "$ip preformed post" ); }
            $tmpVar = $autobanConfig->param('nginx-es-input.goodResponseCodes');
            if ( $tempData->{'_source'}->{'status'} !~ /$tmpVar/i ) { $tempBadResponseCount++; autoban::Logging::OutputHandler( 'TRACE', 'nginx_es_input', "$ip bad status code: $tempData->{'_source'}->{'status'}" ); }
            $tmpVar = $autobanConfig->param('nginx-es-input.writeUrl');
            if ( $tempData->{'_source'}->{'requested_uri'} =~ /$tmpVar/i ) { $writeUrlCount++; autoban::Logging::OutputHandler( 'TRACE', 'nginx_es_input', "$ip write url: $tempData->{'_source'}->{'requested_uri'}" ); }

            $i++;
        }

        #put final data into hash
        if ( $autobanConfig->param("nginx-es-input.cookie") ) {
            $localData->{'nginx-es-input'}->{'ipData'}->{$ip}->{'hasCookie'} = $hasCookie || "false";
            autoban::Logging::OutputHandler( 'TRACE', 'nginx_es_input', "$ip has cookie(s): " . $localData->{'nginx-es-input'}->{'ipData'}->{$ip}->{'hasCookie'} );
        }

        $localData->{'nginx-es-input'}->{'ipData'}->{$ip}->{'hasUserAgent'} = $hasUserAgent;
        autoban::Logging::OutputHandler( 'TRACE', 'nginx_es_input', "$ip has useragnet: " . $localData->{'nginx-es-input'}->{'ipData'}->{$ip}->{'hasUserAgent'} );

        $localData->{'nginx-es-input'}->{'ipData'}->{$ip}->{'postMethodPercentage'} = getPercentage( $autobanConfig->param('nginx-es-input.maxNumOfResults'), "$postActionCount" );
        autoban::Logging::OutputHandler( 'TRACE', 'nginx_es_input', "$ip post percentage: " . $localData->{'nginx-es-input'}->{'ipData'}->{$ip}->{'postMethodPercentage'} . "%" );

        $localData->{'nginx-es-input'}->{'ipData'}->{$ip}->{'badResponsePercentage'} = getPercentage( $autobanConfig->param('nginx-es-input.maxNumOfResults'), "$tempBadResponseCount" );
        autoban::Logging::OutputHandler( 'TRACE', 'nginx_es_input', "$ip bad write percentage: " . $localData->{'nginx-es-input'}->{'ipData'}->{$ip}->{'badResponsePercentage'} . "%" );

        $localData->{'nginx-es-input'}->{'ipData'}->{$ip}->{'writeUrlPercentage'} = getPercentage( $autobanConfig->param('nginx-es-input.maxNumOfResults'), "$writeUrlCount" );
        autoban::Logging::OutputHandler( 'TRACE', 'nginx_es_input', "$ip write percentage: " . $localData->{'nginx-es-input'}->{'ipData'}->{$ip}->{'writeUrlPercentage'} . "%" );

        $pm->finish( 0, $localData );    # do the exit in the child process

    }

    $pm->wait_all_children;
}

sub getPercentage {

    my ( $first, $second ) = ( shift, shift );
    if ( $second == 0 ) {
        return 0;

    }
    else {
        my $perc = $second / $first;
        my $pretty_perc = sprintf( "%.3f", $perc );
        $pretty_perc *= 100;
        return $pretty_perc;
    }

}

#required to import
1;
