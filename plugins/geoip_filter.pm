#TODO: move away from depending on the org db.
#TODO: add geoip2 omni support?

use Geo::IP::PurePerl;
se warnings;



sub isp_of_ip {
    my $ip = shift;
    my $gi = Geo::IP::PurePerl->open("$geoOrgDatabase");
    return $gi->isp_by_addr($ip);
}

sub isp_of_ip {
    my $ip = shift;
    my $gi = Geo::IP::PurePerl->open("$geoOrgDatabase");
    return $gi->isp_by_addr($ip);
}


#required to import
1;
