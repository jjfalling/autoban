#whitelist filter module

#this filter will REMOVE matched ips from all of the plugin data to keep them from being blocked. It does not remove active bans from the db.
#this plugin should be the first filter to run after all inputs have finished. 

sub whitelist_filter {
    debugOutput("\n**DEBUG: Running whitelist_filter\n");

    use NetAddr::IP;


    #go though each plugin
    foreach my $currentPlugin (keys %{$data}) {

	debugOutput("**DEBUG: Looking at plugin data for: $currentPlugin");

	#look at each ip address in the current plugin
	foreach my $currentIp (keys %{$data->{$currentPlugin}->{'ipData'}}) {

	    debugOutput("**DEBUG: Checking $currentIp");
	    my $ipAddr = NetAddr::IP->new($currentIp);

	    #check if current ip is in any whitelist subnet
	    foreach my $currentWhitelistItem ($autobanConfig->param('whitelist-filter.whitelistips')) {

		my $network = NetAddr::IP->new($currentWhitelistItem);
		if ($ipAddr->within($network)) {

		    #ip is in whitelist, remove it from the current plugin's data set and move on to next ip
		    debugOutput("**DEBUG: $currentIp is in whitelist, removing from data set");
		    delete $data->{$currentPlugin}->{'ipData'}->{$currentIp};
		    last;

		}
	    }
	}
    }
}

1;
