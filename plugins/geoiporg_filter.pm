#The reason I use the org db and not the isp is that when ips are reassigned they show up in the org db, that way you get finer grain data on who actually uses the ip. However, I think this db only works with ipv4.
#TODO: add geoip2 omni support?

#****************************************************************************
#*   autoban - geoiporg filter                                              *
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

use warnings;

sub geoiporg_filter {
    use Geo::IP::PurePerl;

    my $gi = Geo::IP::PurePerl->open( $autobanConfig->param('geoiporg-filter.geoOrgDatabase') );

    #go though each plugin
    foreach my $currentPlugin ( keys %{$data} ) {

        autoban::Logging::OutputHandler( 'INFO', 'geoiporg_filter', "Looking at plugin data for: $currentPlugin" );

        #look at each ip address in the current plugin
        foreach my $currentIp ( keys %{ $data->{$currentPlugin}->{'ipData'} } ) {

            autoban::Logging::OutputHandler( 'DEBUG', 'geoiporg_filter', "Checking $currentIp" );
            my $currentIpOrg = $gi->isp_by_addr($currentIp) || '-';

            #run through the array of whitelist names, if there is a match, REMOVE it from the data hash
            my $tempdata = $autobanConfig->param('geoiporg-filter.whitelistOrgs');
            if ( $currentIpOrg =~ /$tempdata/i ) {

                #ip is in whitelist, remove it from the current plugin's data set and move on to next ip
                autoban::Logging::OutputHandler( 'INFO', 'geoiporg_filter', "$currentIp is $currentIpOrg which is in whitelist, removing from data set" );
                delete $data->{$currentPlugin}->{'ipData'}->{$currentIp};
            }
            else {
                autoban::Logging::OutputHandler( 'TRACE', 'geoiporg_filter', "$currentIp is $currentIpOrg is not whitelisted" );

            }
        }
    }
}

#required to import
1;
