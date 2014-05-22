#whitelist filter module

#this filter will REMOVE matched ips from all of the plugin data to keep them from being blocked. It does not remove active bans from the db.
#this plugin should be the first filter to run after all inputs have finished. 

sub ip_whitelist_filter {
    enhancedOutput("verbose","\n\nRunning whitelist_filter\n");

    use NetAddr::IP;


    #go though each plugin
    foreach my $currentPlugin (keys %{$data}) {

	enhancedOutput("debug","**DEBUG: Looking at plugin data for: $currentPlugin");

	#look at each ip address in the current plugin
	foreach my $currentIp (keys %{$data->{$currentPlugin}->{'ipData'}}) {

	    enhancedOutput("debug","**DEBUG: Checking $currentIp");
	    my $ipAddr = NetAddr::IP->new($currentIp);

	    #check if current ip is in any whitelist subnet
	    foreach my $currentWhitelistItem ($autobanConfig->param('whitelist-filter.whitelistips')) {

		my $network = NetAddr::IP->new($currentWhitelistItem);
		if ($ipAddr->within($network)) {

		    #ip is in whitelist, remove it from the current plugin's data set and move on to next ip
		    enhancedOutput("debug","**DEBUG: $currentIp is in whitelist, removing from data set");
		    delete $data->{$currentPlugin}->{'ipData'}->{$currentIp};
		    last;

		}
	    }
	}
    }
}

1;
