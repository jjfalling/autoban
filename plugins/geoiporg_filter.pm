#The reason I use the org db and not the isp is that when ips are reassigned they show up in the org db, that way you get finer grain data on who actually uses the ip. However, I think this db only works with ipv4. 
#TODO: add geoip2 omni support?

use warnings;

sub geoiporg_filter {
    debugOutput("\n**DEBUG: Running geoiporg_filter\n");
    use Geo::IP::PurePerl;

    my $gi = Geo::IP::PurePerl->open($autobanConfig->param('geoiporg-filter.geoOrgDatabase'));

#print Dumper($autobanConfig->param('geoiporg-filter.whitelistOrgs'));

    #go though each plugin
    foreach my $currentPlugin (keys %{$data}) {

	debugOutput("**DEBUG: Looking at plugin data for: $currentPlugin");

	#look at each ip address in the current plugin
	foreach my $currentIp (keys %{$data->{$currentPlugin}->{'ipData'}}) {

	    debugOutput("**DEBUG: Checking $currentIp");
	    my $currentIpOrg = $gi->isp_by_addr($currentIp) || '-';

	    #run through the array of whitelist names, if there is a match, REMOVE it from the data hash
	    my $tempdata=$autobanConfig->param('geoiporg-filter.whitelistOrgs');
	    if ($currentIpOrg =~ /$tempdata/i)
	    {
		#ip is in whitelist, remove it from the current plugin's data set and move on to next ip
		debugOutput("**DEBUG: $currentIp is $currentIpOrg which is in whitelist, removing from data set");
		delete $data->{$currentPlugin}->{'ipData'}->{$currentIp};
	    }
	}
    }
}




#required to import
1;
