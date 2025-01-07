package pf::UnifiedApi::Controller::Config::System;

=head1 NAME

pf::UnifiedApi::Controller::Config::System -

=cut

=head1 DESCRIPTION

pf::UnifiedApi::Controller::Config::System

=cut

use strict;
use warnings;
use Mojo::Base 'pf::UnifiedApi::Controller::RestRoute';
use pfappserver::Model::Enforcement;
use pfappserver::Form::Interface::Create;
use pf::UnifiedApi::Controller::Config;
use pf::error qw(is_success);
use pf::util;
use File::Slurp qw(read_file write_file);
use pf::util::dns;

sub model {
    require pfappserver::Model::Config::System;
    return pfappserver::Model::Config::System->new();
}

sub get_gateway {
    my ($self) = @_;
    $self->render(json => {item => $self->model->getDefaultGateway()}, status => 200);
}

sub put_gateway {
    my ($self) = @_;
    require pfappserver::Model::Interface;
    my $interfaces = pfappserver::Model::Interface->new->get('all');

    my $gateway = $self->get_json ? $self->get_json->{gateway} : undef;
    if($gateway) {
        my ($status, $status_msg) = $self->model->write_network_persistent($interfaces, $gateway);
        $self->render(json => {message => $status_msg}, status => $status);
    }
    else {
        $self->render(json => {message => "Missing the gateway in the request payload"}, status => 422)
    }
}

sub get_dns_servers {
    my ($self) = @_;
    $self->render(json => {dns_servers => pf::util::dns::get_resolv_dns_servers()});
}

sub put_dns_servers {
    my ($self) = @_;
    my $content = "# This file has been generated by PacketFence\n";
    my $servers = $self->get_json ? $self->get_json->{dns_servers} : undef;
    if($servers) {
        for my $server (@$servers) {
            $content .= "nameserver $server\n";
        }
        my $tmpfile = File::Temp->new()->filename;
        write_file($tmpfile, $content);
        pf_run("cat $tmpfile | sudo tee /etc/resolv.conf");
        my $saved_servers = $self->_get_dns_servers();
        
        if(scalar(@$servers) != scalar(@$saved_servers)) {
            $self->render(json => {message => "DNS servers haven't been saved properly"}, status => 500);
            return;
        }
        for(my $i=0; $i<scalar(@$servers); $i++) {
            if($servers->[$i] ne $saved_servers->[$i]) {
                $self->render(json => {message => "DNS servers haven't been saved properly"}, status => 500);
                return;
            }
        }

        # If we're here all the checks succeeded
        $self->render(json => {message => "DNS servers saved successfully"});
    }
    else {
        $self->render(json => {message => "Missing the DNS servers in the request payload"}, status => 422)
    }
}

sub _get_hostname {
    my ($self) = @_;
    my $hostname = safe_pf_run(qw(hostnamectl --static));
    chomp($hostname);
    return $hostname if defined($hostname);
}

sub get_hostname {
    my ($self) = @_;
    $self->render(json => {item => $self->_get_hostname}, status => 200);
}

sub put_hostname {
    my ($self) = @_;
    my $hostname = $self->get_json ? $self->get_json->{hostname} : undef;
    if($hostname) {
        safe_pf_run(qw(sudo hostnamectl set-hostname), $hostname);
        my $new_hostname = $self->_get_hostname();
        chomp($new_hostname);
        if($new_hostname eq $hostname) {
            $self->render(json => {message => "Changed hostname to: $hostname"}, status => 200);
        }
        else {
            $self->render(json => {message => "Failed to change hostname to: $hostname"}, status => 500);
        }
    }
    else {
        $self->render(json => {message => "Missing the hostname in the request payload"}, status => 422)
    }
}

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2024 Inverse inc.

=head1 LICENSE

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.

=cut

1;
