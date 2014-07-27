#this output generates a nginx ban list

#****************************************************************************
#*   autoban - nginx_ban output                                             *
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

#it also keeps a historical record in an elasticsearch index (yay! using es as a datastore! But I assume this data can be considered relatively ephemeral )
#the record in es will have the ip, epoch time ban was created, ban length, module name, and comment. 
#this way we take care of creating and expiring bans in nginx. 


use Parallel::ForkManager;
use Hash::Merge::Simple qw(merge);
use List::MoreUtils 'any';
use warnings;


my $aggregatedData;
my $result2;


sub nginx_ban_output {
    my @denyArray;
    my $nginxBanFileWritable=0;


    autoban::Logging::OutputHandler('DEBUG','nginx_ban_output',"looping through the ban ips");

    #get current GMT date in format YYYYMMDDHHMM, as an int
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime();
    #month is returned as 0-11, so add 1 to be human readable
    $mon=$mon+1;
    $year=$year+1900;
    my $currentDateTime = sprintf("%04d%02d%02d%02d%02d", $year, $mon, $mday, $hour, $min);
    $currentDateTime=int($currentDateTime);

    my $banCount=0;
    
    #setup es bulk helper
    my $bulkEs = $es->bulk_helper(
	index   =>  $autobanConfig->param('autoban.esAutobanIndex'),
	type => 'nginxBanOutput',
	max_count   => $autobanConfig->param('nginx-ban-output.maxCount'),
	max_size    => $autobanConfig->param('nginx-ban-output.maxSize'),
	#verbose     => 1,
	#on_success  => sub {print "DONE: OK\n";},  
	#on_error    => sub {print "DONE: ERROR\n";},         
	#on_conflict => sub {print "DONE: CONFLICT\n";}, 
	);


    my $pm = Parallel::ForkManager->new($autobanConfig->param('nginx-ban-output.maxProcs'));

    $pm->run_on_finish(sub{
	my ($pid,$exit_code,$ident,$exit_signal,$core_dump,@retdata)=@_;


	#look at number of bans for the current ip
	if ($retdata[0][1] == 0){

	    if ($safe) {
		autoban::Logging::OutputHandler('INFO','nginx_ban_output',"The following would have been banned: IP: $ip COMMENT: $data->{$plugin}->{'ipData'}->{$retdata[0][0]}->{'banComment'}");

	    }
	    else{

		#if the search returned no hits, then we need to create a new ban record
		autoban::Logging::OutputHandler('DEBUG','nginx_ban_output',"Found no active bans for $retdata[0][0], adding one");

		#create ban since there one does not exist for this ip
		my $ban_expires = $currentDateTime+$autobanConfig->param('nginx-ban-output.banLength');
		
		$bulkEs->create({
		    source => {
			ip => $retdata[0][0],
			ban_created => $currentDateTime,
			ban_expires => $ban_expires,
			ban_comment => $comment,
			inputPlugin => $plugin
		    }
				});		
	    }
	}
	elsif ($retdata[0][1] == 1 ){
	    autoban::Logging::OutputHandler('DEBUG','nginx_ban_output',"Found one active ban for $retdata[0][0]");
	    #we do nothing here since the ban is already active. 
	}
	else {
	    autoban::Logging::OutputHandler('WARN','nginx_ban_output',"Found multiple active bans for $retdata[0][0], I am not sure what to do with this yet or how this would sanely happen...");
	    #TODO: figure out how to handle this 
	}

	
		       });

    #check to see what inputs we are looking at
    foreach my $plugin ($autobanConfig->param('nginx-ban-output.plugins')){
	autoban::Logging::OutputHandler('DEBUG','nginx_ban_output',"Looking at input plugin: $plugin");

	foreach my $ip (sort keys %{$data->{$plugin}->{'ipData'}}) {
	    #strip the trailing comma from the string
	    $comment = substr(($data->{$plugin}->{'ipData'}->{$ip}->{'banComment'}),0,-1);
	    $comment = "AutoBan - Score: $data->{$plugin}->{'ipData'}->{$ip}->{'banScore'} Reason: " . "$comment";

	    $pm->start and next;
	    
	    #if above threshold, see if we should ban it
	    if ($data->{$plugin}->{'ipData'}->{$ip}->{'banScore'} >= $autobanConfig->param('nginx-ban-output.banTheshold')){
		$banCount=1;
		autoban::Logging::OutputHandler('DEBUG','nginx_ban_output',"IP $ip is above ban threshold, checking ban status");

		#search for active bans
		my $ipBanSearch = $es->search(
		    index => $autobanConfig->param('autoban.esAutobanIndex'),
		    body  => {
			filter => {
			    and => [
				{
				    term => {
					_type => 'nginxBanOutput'
				    }
				},
				{
				    range => {
					'ban_expires' => {
					    gte => $currentDateTime,
					}
				    }
				}
				]
			},
				    query => {
					match => { 
					    ip => $ip
					}

				}
		    }
		    );
		autoban::Logging::OutputHandler('DEBUG','nginx_ban_output',"Search for $ip took $ipBanSearch->{'took'}ms");

	        my @tempArray = ("$ip", "$ipBanSearch->{'hits'}->{'total'}");

		#exit, returning ip and hit count
		$pm->finish(0, \@tempArray);

	    }
	}

	$pm->wait_all_children;
	

	if ($banCount == 0){
	    autoban::Logging::OutputHandler('DEBUG','nginx_ban_output','I found nothing new to ban on this run');
	}	

    }

    #unless we are in safe mode or there are no bans, flush the bulk buffer
    unless ($safe) {
	if ($banCount >= 1){
	    autoban::Logging::OutputHandler('DEBUG','nginx_ban_output',"Bulk creating bans");
	    $bulkEs->flush;
	}
    }

    #If safe mode is on, do not generate ban file    
    if ($safe) {
	autoban::Logging::OutputHandler('DEBUG','nginx_ban_output','Not generating nginx ban file due to safe flag');
    }
    else{

	#Trying to work around an occasional longish delay between indexing and the documents being searchable by refreshing the index manually. This MAY be a bad idea, I dont know yet...
	$es->indices->refresh(
	    index => $autobanConfig->param('autoban.esAutobanIndex')
	    );

	#Run a facted search on active bans by ip. and sort for good measure. 
	autoban::Logging::OutputHandler('DEBUG','nginx_ban_output','Getting all active banned ips');

	my $activeBanResult = $es->search(
	    index => $autobanConfig->param('autoban.esAutobanIndex'),
	    #Use size=0 to only give the aggregation data
	    size => 0,
	    body => {
		aggs => {
		    ipData => {
			aggs => {
			    ips => {
				terms => {
				    field => "ip.raw"
				}
			    }
			},
			filter => {
			    bool => {
				must => [
				    {
					term => {
					    _type => 'nginxBanOutput'
					}
				    },
				    {
					range => {
					    'ban_expires' => {
						gte => $currentDateTime
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

	autoban::Logging::OutputHandler('DEBUG','nginx_ban_output',"Search took $activeBanResult->{'took'}ms, returned $activeBanResult->{'aggregations'}->{'ipData'}->{'doc_count'} banned ips");

	autoban::Logging::OutputHandler('DEBUG','nginx_ban_output','Generating nginx ban file');


	unless (-e $autobanConfig->param('nginx-ban-output.location')) {
	    autoban::Logging::OutputHandler('INFO','nginx_ban_output',"nginx ban file ". $autobanConfig->param('nginx-ban-output.location') ." does not exist, attempting to create\n");
	}

	unless (open NGINXBANFILE, ">", $autobanConfig->param('nginx-ban-output.location')) {
	    autoban::Logging::OutputHandler('ERROR','nginx_ban_output',"Cannot write to nginx ban file ". $autobanConfig->param('nginx-ban-output.location') . ": $!\n");
	}
	else {
	    
	    print NGINXBANFILE "#This file is generated by autoban\n";
	    foreach my $banedIps (@{$activeBanResult->{'aggregations'}->{'ipData'}->{'ips'}->{'buckets'}}) {
		next if $banedIps->{'key'} eq '-';
		autoban::Logging::OutputHandler('DEBUG','nginx_ban_output',"Adding $banedIps->{'key'} to nginx ban file");
		print NGINXBANFILE "deny $banedIps->{'key'};\n";
	    }
	    autoban::Logging::OutputHandler('DEBUG','nginx_ban_output','finished writing to nginx ban file, closing file');
	    close NGINXBANFILE;

	    #see if user provided a post run script and if so, run it. If not, then we just ignore this
	    unless ($autobanConfig->param("nginx-ban-output.postRunScript")) {
		autoban::Logging::OutputHandler('DEBUG','nginx_ban_output','No post script provided, skipping');
	    }
	    else {
		autoban::Logging::OutputHandler('DEBUG','nginx_ban_output','Post script provided, running it');
		my $tmpPostScript = $autobanConfig->param('nginx-ban-output.postRunScript');
		my $postScript = `$tmpPostScript`;
		my $postScriptExit = $?;
		unless ( $postScriptExit == 0) { print "Error running post script " . $autobanConfig->param('nginx-ban-output.postRunScript') .": exit code: $postScriptExit. $postScript\n";}
		autoban::Logging::OutputHandler('DEBUG','nginx_ban_output',"Post script output: $postScript");
	    }

	}
    }
}



#required to import
1;
