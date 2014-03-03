#whitelist filter module
#this will more then likely be used within other modules. for the sake of effeciancy it should probally be used as early on as possible

#each whitelist item should have the ip or subnet and the module(s) that it should be whitelisted in

#allow both single ip and cdir notation
sub whitelist.filter {
	use NetAddr::IP;


        if ($ip->within(new NetAddr::IP "192.168.15.0/24")) {

		debugOutput("**DEBUG: $ip is in whitelist");
	}

}




1;
