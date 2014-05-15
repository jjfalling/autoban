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
    debugOutput("\n**DEBUG: Running nginx_ban_output\n");
    my @denyArray;
    my $curlOutput=1;

    #we attempt to get the current ban file so we can tell what is a new ban.
    # this was used as a sort of diff for manually updating the nginx file, but I think 
    # i should drop this and just use the ban db 
    #
    #debugOutput("**DEBUG: Attempting to get and read current nginx ban file");
    #$curlOutput = `curl -s http:/foo.host.lan/packages/centos/nginx/conf/sysban/nginxban.conf -o "$autobanConfig->param('nginx-ban-output.location')"; echo $?`;
    #if we couldnt, give an error
    #if ( $curlOutput != 0 ){
    #	print "\n\nError: could not fetch blockips.conf, trying to work around this... curl exit code: $curlOutput";
    #}

    #read the denyfile into an array
    #open( my $NGINXDENYFILE, "<", $autobanConfig->param('nginx-ban-output.location') ) || die "ERROR: Can't open nginx ban file: $!\n";
    #@denyArray = <$NGINXDENYFILE>;
    
    debugOutput("**DEBUG: looping through the ban ips");


    #get current GMT date in format YYYYMMDDHHMM, as an int
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime();
    $year=$year+1900;
    my $currentDateTime = sprintf("%04d%02d%02d%02d%02d", $year, $mon, $mday, $hour, $min);
    $currentDateTime=int($currentDateTime);

    my $banCount=0;
    foreach my $ip (sort keys %{$data->{'nginx-es-input'}->{'ipData'}}) {
	#strip the trailing comma from the string
	$comment = substr(($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'}),0,-1);
	$comment = "AutoBan - Score: $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} Reason: " . "$comment";

	
	#if above threshold, see if we should ban it
	if ($data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banScore'} >= $banTheshold){
	    $banCount=1;
	    debugOutput("**DEBUG: IP $ip is above ban threshold, checking ban status");

	    #plugin: nginx_ban.output
	    #ip: $ip
	    #ban_created: [some sane timestamp, in gmt] 
	    #ban_expires: [some sane timestamp, in gmt] 
	    #ban_comment: $data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'}

	    # This is where the ban db will come into play. do some sort of query to get all active nginx banned ips and generate ban file
	    #search for active bans
	    my $ipBanSearch = $es->search(
		index => $autobanConfig->param('autoban.esAutobanIndex'),
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
		    type => $autobanConfig->param('nginx-es-input.logType'),
		    body => {
			ip => $ip,
			ban_created => $currentDateTime,
			ban_expires => $ban_expires,
			ban_comment => "$data->{'nginx-es-input'}->{'ipData'}->{$ip}->{'banComment'}"
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
	debugOutput("**DEBUG: I found nothing to ban on this run");
    }
    else {
	#run a facted search on active bans by ip. and sort for good measure. 
      	debugOutput("**DEBUG: Getting all active banned ips");

	#adding a sleep to work around index lag
	sleep 2;

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
						_type => $autobanConfig->param('nginx-es-input.logType')
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
	if ( $activeBanResult->{'facets'}->{'ipFacet'}->{'total'} == 0){
	    debugOutput("**DEBUG: Search took $activeBanResult->{'took'}ms, and returned no banned ips. Skipping nginx ban file creation.");
	}
	else {
	    debugOutput("**DEBUG: Search took $activeBanResult->{'took'}ms, returned $activeBanResult->{'facets'}->{'ipFacet'}->{'total'} banned ips");
	    
	    #go through the returned data and build the nginx ban list

	    #my (@bad, $facet);
	    #    foreach my $res (@{$result->{'facets'}->{'ipFacet'}->{'terms'}}) {
	    #	next if $res->{'term'} eq '-';
	    #	$facetedData->{'ip'}->{$res->{'term'}} = $res->{'count'};
	    #	my $ip = $res->{'term'};
	    #	$ip =~ s/\.(\d{1,3})$//;
	    #    }
	    #foreach my $ip (sort keys %{$facetedData->{'ip'}}) {}

	    debugOutput("**DEBUG: attempting to open nginx ban file for writing");


	    unless (-e $autobanConfig->param('nginx-ban-output.location')) {
		print "WARNING: nginx ban file ". $autobanConfig->param('nginx-ban-output.location') ." does not exist, attempting to create\n";
	    }

	    unless (open NGINXBANFILE, ">", $autobanConfig->param('nginx-ban-output.location')) {
		print "ERROR: Cannot write to nginx ban file ". $autobanConfig->param('nginx-ban-output.location') . ": $!\n";
	    }
	    else {
		
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
    }

}

#required to import
1;