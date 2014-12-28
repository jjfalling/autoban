#!/usr/bin/env perl

use strict;
use warnings;

use Data::Dumper;
use Config::Simple;

#get offical elasticsearch module @ https://metacpan.org/pod/Search::Elasticsearch
use Search::Elasticsearch;
#A recent version is required for some things we do
die "FATAL: The Search::Elasticsearch module must be >= v1.14! You have v$Search::Elasticsearch::VERSION\n\n"
    unless $Search::Elasticsearch::VERSION >= 1.14;


