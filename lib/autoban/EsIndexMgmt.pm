########################################
package autoban::EsIndexMgmt;
########################################
#Tasks based around the autoban index

#****************************************************************************
#*   autoban -  autoban::EsIndexMgmt                                        *
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

use strict;
use warnings;
use Data::Dumper;

#sanity checks around the autoban index
########################################
sub CheckAutobanIndex {
########################################

    #look through the plugin directories and load the plugins
    autoban::Logging::OutputHandler( 'DEBUG', 'autoban', 'Checking that autoban index exists' );

    #ensure the autoban index exists, if not, throw a warning and create it, exit if we cannot
    my $autobanIndexStatus;
    eval { $autobanIndexStatus = $autoban::es->indices->exists( index => $autoban::autobanConfig->param('autoban.esAutobanIndex') ); };
    autoban::Logging::OutputHandler( 'FATALDIE', 'autoban', "Problem connecting to elasticsearch: $@" ) if $@;

    #unless the autoban index exists, we create it
    unless ($autobanIndexStatus) {
        autoban::Logging::OutputHandler( 'WARN', 'autoban', "autboan's index was not found. This is normal if this is the first time running autoban, otherwise something deleted it!" );
        eval { $autoban::es->indices->create( index => $autoban::autobanConfig->param('autoban.esAutobanIndex') ); };
        autoban::Logging::OutputHandler( 'FATALDIE', 'autoban', "ERROR: could not create autoban index: $@" ) if $@;
        autoban::Logging::OutputHandler( 'DEBUG', 'autoban', 'autoban index created' );

    }
    else {
        autoban::Logging::OutputHandler( 'DEBUG', 'autoban', 'autoban index exists' );

        #ensure the autoban index is open
        my $autobanIndexState;
        eval { $autobanIndexState = $autoban::es->cluster->state( index => $autoban::autobanConfig->param('autoban.esAutobanIndex'), metric => 'metadata' ) };
        autoban::Logging::OutputHandler( 'ERROR', 'autoban', "Problem connecting to elasticsearch: $@" ) if $@;

        #if the index is not open, try to open it
        if ( $autobanIndexState->{'metadata'}->{'indices'}->{ $autoban::autobanConfig->param('autoban.esAutobanIndex') }->{'state'} ne 'open' ) {
            autoban::Logging::OutputHandler( 'WARN', 'autoban', "The autoban index is not open, attempting to open index" );

            eval { $autoban::es->indices->open( index => $autoban::autobanConfig->param('autoban.esAutobanIndex') ); };
            autoban::Logging::OutputHandler( 'FATALDIE', 'autoban', "Could not open autoban index: $@" ) if $@;
            autoban::Logging::OutputHandler( 'DEBUG', 'autoban', 'Opened autoban index' );

        }
        else {
            autoban::Logging::OutputHandler( 'DEBUG', 'autoban', 'autoban index is open' );

        }
    }
}

#this checks the health of the cluster
########################################
sub CheckClusterHealth {
########################################

    my $clusterHealth;

    #skip the check if the user disabled it
    unless ( $autoban::autobanConfig->param('autoban.minEsClusterHealth') eq 'off' ) {

        autoban::Logging::OutputHandler( 'DEBUG', 'autoban', 'Checking es cluster health' );
        eval { $clusterHealth = $autoban::es->cluster->health(); };
        autoban::Logging::OutputHandler( 'ERROR', 'autoban', "Problem connecting to elasticsearch: $@" ) if $@;

        if ( $autoban::autobanConfig->param('autoban.minEsClusterHealth') eq 'green' ) {
            unless ( $clusterHealth->{'status'} eq 'green' ) {
                autoban::Logging::OutputHandler( 'ERROR', 'autoban', "elasticsearch cluster is $clusterHealth->{'status'}, waiting for it to be green" );
            }
            else {
                autoban::Logging::OutputHandler( 'DEBUG', 'autoban', "elasticsearch cluster is $clusterHealth->{'status'}" );
                return "ok";
            }

        }
        elsif ( $autoban::autobanConfig->param('autoban.minEsClusterHealth') eq 'yellow' ) {
            unless ( ( $clusterHealth->{'status'} eq 'green' ) || ( $clusterHealth->{'status'} eq 'yellow' ) ) {
                autoban::Logging::OutputHandler( 'ERROR', 'autoban', "elasticsearch cluster is $clusterHealth->{'status'}, waiting for it to be at least yellow" );
            }
            else {
                autoban::Logging::OutputHandler( 'DEBUG', 'autoban', "elasticsearch cluster is $clusterHealth->{'status'}" );
                return "ok";
            }
        }
        else {
            autoban::Logging::OutputHandler( 'FATAL', 'autoban', "Invalid minEsClusterHealth setting: " . $autoban::autobanConfig->param('autoban.minEsClusterHealth') );

        }

    }

}

#this is the autoban index template
########################################
sub UpdateAutobanTemplate {
########################################

    eval { $autoban::es->indices->put_template( name => 'autoban', body => { template => $autoban::autobanConfig->param('autoban.esAutobanIndex'), settings => { 'index.analysis.analyzer.default.stopwords' => '_none_', 'index.analysis.analyzer.default.type' => 'standard', 'index.number_of_shards' => '3', 'index.number_of_replicas' => '1' }, 'mappings' => { '_default_' => { '_timestamp' => { 'enabled' => 'true', 'store' => 'true' }, 'properties' => { 'timestamp' => { 'type' => 'date', 'format' => 'date_time' }, }, 'dynamic_templates' => [ { 'string_fields' => { 'mapping' => { 'type' => 'multi_field', 'fields' => { 'raw' => { 'index' => 'not_analyzed', 'ignore_above' => 256, 'type' => 'string' }, '{name}' => { 'index' => 'analyzed', 'omit_norms' => 'true', 'type' => 'string' } } }, 'match' => '*', 'match_mapping_type' => 'string' } } ] } } } ); };

    #Die here if we cant create the index or update the template as there is nothing else we can do
    autoban::Logging::OutputHandler( 'FATALDIE', 'autoban', "Problem connecting to elasticsearch: $@" ) if $@;

}

1;
