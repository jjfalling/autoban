autoban
=======

The original version of autoban was developed at one of the internet's largest websites in order
to block abuse and attacks that caused downtime. 

Autoban works by analyzing logs stored in elasticsearch against filters and rules then generating ban or
block entries.



The current design is as follows (? denotes proposed and not yet created):


Inputs			→ 	 Filters	→		Outputs
[Nginx logs from ES]		[Whitelist]			[Nginx ban list]
[Apache logs from ES]		[Allow Rules]			[PfSense ip blocks?]
[Varnish logs from ES?]		[Blacklist?]			[Hosts.deny?]
				[Block Rules]			[Iptables?]
								[Apache deny?]
