#this output generates a nginx ban list
#it also keeps a historical record in an elasticsearch index (yay! using es as a datastore! [This can be bad, just ask any es employee...] but I assume this data can be considered relatively ephemeral )
#the record in es will have the ip, epoch time ban was created, ban length, module name, and comment. 
#this way we take care of creating and expiring bans in nginx. 



use Geo::IP::PurePerl;
use List::MoreUtils 'any';
use warnings;


my $facetedData;
#you need to use the MaxMind GeoIP Organization Database. TODO: Migrate away from this?
my $geoOrgDatabase="/var/lib/GeoIP/GeoIPOrg.dat";
my $crawlers="microsoft|yandex|yahoo|google";
my $result2;
my $high = 5;
my $low = 4;
my $banTheshold = 9;


sub nginx_ban_output {
    enhancedOutput("verbose","\n\nRunning nginx_ban_output\n");
    my @denyArray;
    my $nginxBanFileWritable=0;


    debugOutput("**DEBUG: looping through the ban ips");


    #get current GMT date in format YYYYMMDDHHMM, as an int
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime();
    $year=$year+1900;
    my $currentDateTime = sprintf("%04d%02d%02d%02d%02d", $year, $mon, $mday, $hour, $min);
    $currentDateTime=int($currentDateTime);

    my $banCount=0;
    
    #check to see what inputs we are looking at
    foreach my $plugin ($autobanConfig->param('nginx-ban-output.plugins')){
	debugOutput("**DEBUG: looking at input plugin: $plugin");

	foreach my $ip (sort keys %{$data->{$plugin}->{'ipData'}}) {
	    #strip the trailing comma from the string
	    $comment = substr(($data->{$plugin}->{'ipData'}->{$ip}->{'banComment'}),0,-1);
	    $comment = "AutoBan - Score: $data->{$plugin}->{'ipData'}->{$ip}->{'banScore'} Reason: " . "$comment";

	    
	    #if above threshold, see if we should ban it
	    if ($data->{$plugin}->{'ipData'}->{$ip}->{'banScore'} >= $banTheshold){
		$banCount=1;
		debugOutput("**DEBUG: IP $ip is above ban threshold, checking ban status");


		# This is where the ban db will come into play. do some sort of query to get all active nginx banned ips and generate ban file.
		#This used to set the type to the input plugin name, but this seemed silly. instead we use this plugin name and tag with the input
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
		debugOutput("**DEBUG: Search took $ipBanSearch->{'took'}ms");

		#look at number of bans for the current ip
		if ($ipBanSearch->{'hits'}->{'total'} == 0){
		    #if the search returned no hits, then we need to create a new ban record
		    debugOutput("**DEBUG: Found no active bans for $ip, adding one");

		    #create ban since there one does not exist for this ip
		    my $ban_expires = $currentDateTime+$autobanConfig->param('nginx-ban-output.banLength');
		    
		    $es->index(
			index => $autobanConfig->param('autoban.esAutobanIndex'),
			type => 'nginxBanOutput',
			body => {
			    ip => $ip,
			    ban_created => $currentDateTime,
			    ban_expires => $ban_expires,
			    ban_comment => "$data->{$plugin}->{'ipData'}->{$ip}->{'banComment'}",
			    inputPlugin => "$plugin"
			}
			);
		}
		elsif ($ipBanSearch->{'hits'}->{'total'} == 1 ){
		    debugOutput("**DEBUG: Found one active ban for $ip");
		    #we do nothing here since the ban is already active. 
		}
		else {
		    debugOutput("**DEBUG: found multiple bans for $ip, not sure what to do with this...");
		    print "\nWARNING: more then one active ban exists for $ip\n";
		    #TODO: figure out how to handle this
		}	    

	    }
	}
	


	if ($banCount == 0){
	    debugOutput("**DEBUG: I found nothing new to ban on this run");
	}	


    }

    #run a facted search on active bans by ip. and sort for good measure. 
    debugOutput("**DEBUG: Getting all active banned ips");

    #adding a sleep to try to work around newly added data not showing up in the search. 
    sleep 5;

    my $activeBanResult = $es->search(
	index => $autobanConfig->param('autoban.esAutobanIndex'),
	body  => {
	    facets => {
		ipFacet => {
		    terms => {
			field => "ip.raw"
		    },
			    facet_filter => {
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
			}
		}
	    }

	},
	#use size=0 to only give the faceted data
	size => 0
	);
    debugOutput("**DEBUG: Search took $activeBanResult->{'took'}ms, returned $activeBanResult->{'facets'}->{'ipFacet'}->{'total'} banned ips");

    debugOutput("**DEBUG: attempting to open nginx ban file for writing");


    unless (-e $autobanConfig->param('nginx-ban-output.location')) {
	print "WARNING: nginx ban file ". $autobanConfig->param('nginx-ban-output.location') ." does not exist, attempting to create\n";
    }

    unless (open NGINXBANFILE, ">", $autobanConfig->param('nginx-ban-output.location')) {
	print "ERROR: Cannot write to nginx ban file ". $autobanConfig->param('nginx-ban-output.location') . ": $!\n";
    }
    else {
	
	print NGINXBANFILE "#This file is generated by autoban\n";

	foreach my $banedIps (@{$activeBanResult->{'facets'}->{'ipFacet'}->{'terms'}}) {
	    next if $banedIps->{'term'} eq '-';
	    debugOutput("**DEBUG: adding $banedIps->{'term'} to nginx ban file");
	    print NGINXBANFILE "deny $banedIps->{'term'};\n";
	}
	debugOutput("**DEBUG: finished writing to nginx ban file, closing file");
	close NGINXBANFILE;

	#see if user provided a post run script and if so, run it. If not, then we just ignore this
	unless ($autobanConfig->param("nginx-ban-output.postRunScript")) {
	    debugOutput("**DEBUG: no post script provided, skipping");
	}
	else {
	    debugOutput("**DEBUG: post script provided, running it");
	    my $tmpPostScript = $autobanConfig->param('nginx-ban-output.postRunScript');
	    my $postScript = `$tmpPostScript`;
	    my $postScriptExit = $?;
	    unless ( $postScriptExit == 0) { print "Error running post script " . $autobanConfig->param('nginx-ban-output.postRunScript') .": exit code: $postScriptExit. $postScript\n";}
	    debugOutput("**DEBUG: post script output: $postScript");
	}

    }

}




#required to import
1;
