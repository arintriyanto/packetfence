package pf::domain::ntlm_cache;

=head1 NAME

pf::domain::ntlm_cache

=head1 DESCRIPTION

Controls the caching of the NT hashes for domains

=cut

use strict;
use warnings;

use pf::constants;
use pf::authentication;
use pf::config qw(%ConfigDomain);
use Net::LDAP::Control::Paged;
use Net::LDAP::Constant qw( LDAP_CONTROL_PAGED );
use Data::Dumper;
use pf::log;
use File::Slurp qw(write_file read_file);
use pf::file_paths qw($domains_ntlm_cache_users_dir);
use File::Spec::Functions;
use pf::domain;
use pf::util;
use File::Temp;
use pf::Redis;
use pf::constants::domain qw($NTLM_REDIS_CACHE_HOST $NTLM_REDIS_CACHE_PORT);

=head2 fetch_valid_users

Fetch the valid users (the ones that should be cached) for a domain

=cut

sub fetch_valid_users {
    my ($domain) = @_;
    my $logger = get_logger;
    my $config = $ConfigDomain{$domain};
    my $ldap_source = getAuthenticationSource($config->{ntlm_cache_source});

    return ($FALSE, "Invalid LDAP source $config->{ntlm_cache_source}") unless(defined($ldap_source));

    my $filter = $config->{ntlm_cache_filter};

    my ($connection, $LDAPServer, $LDAPServerPort ) = $ldap_source->_connect();

    if (!defined($connection)) {
        return ($FALSE, "Error communicating with the LDAP server");
    }

    my $page = Net::LDAP::Control::Paged->new(size => 1000) or die $!;
    my @users;
    my $cookie;
    while(1) {
        my $msg = $connection->search(
            base => $ldap_source->{basedn}, 
            filter => $filter, 
            control => [$page], 
            attrs => [$ldap_source->{usernameattribute}],
            scope => $ldap_source->{scope},
        );

        return ($FALSE, "Error contacting LDAP : ".$msg->error) if($msg->code);
        
        foreach my $entry($msg->entries) {
            my $username = lc($entry->get_value($ldap_source->{usernameattribute}));
            $logger->info("Account '$username' isn't locked or disabled. Will be included in the NTLM cache.");
            push @users, $username;
        }
        # Get cookie from paged control
        my($resp)  = $msg->control( LDAP_CONTROL_PAGED )  or last;
        $cookie    = $resp->cookie or last;
     
        # Set cookie in paged control
        $page->cookie($cookie);
    }
    return \@users;
}

=head2 generate_valid_users_file

Generate the list of valid users (for use by secretsdump.py) for a specific domain

=cut

sub generate_valid_users_file {
    my ($domain) = @_;
    my $logger = get_logger;
    my ($users, $msg) = fetch_valid_users($domain);
    if($users) {
        my $file = catfile($domains_ntlm_cache_users_dir, "$domain.valid-users.txt");
        write_file($file, join("\n", @$users));
        my $msg = "Successfully created valid users file ($file) with ".scalar(@$users)." entries.";
        $logger->info($msg);
        return ($file, $msg);
    }
    else {
        return ($FALSE, $msg);
    }
}

=head2 fetch_all_valid_hashes

Fetch the NT hashes of all the valid users of a domain

=cut

sub fetch_all_valid_hashes {
    my ($domain) = @_;
    my $logger = get_logger;
    my ($valid_users_file, $err) = generate_valid_users_file($domain);
    unless($valid_users_file) {
        my $msg = "Cannot generate valid users file ($err)";
        $logger->error($msg);
        return ($FALSE, $msg);
    }
    my $config = $ConfigDomain{$domain};
    my $source = getAuthenticationSource($config->{ntlm_cache_source});
    return ($FALSE, "Invalid LDAP source $config->{ntlm_cache_source}") unless(defined($source));
    
    my ($connection, $LDAPServer, $LDAPServerPort ) = $source->_connect();

    if (!defined($connection)) {
        return ($FALSE, "Error communicating with the LDAP server");
    }

    # We need to fetch the sAMAccountName of the DN in the AD source
    my $result = $connection->search(
        base => $source->{binddn}, 
        filter => '(sAMAccountName=*)', 
        attrs => ['sAMAccountName'],
    );

    return ($FALSE, "Cannot find sAMAccountName of user ".$source->{binddn}) unless($result->count > 0);

    my $tmpfile = File::Temp->new()->filename;
    my $ntds_file = $tmpfile.".ntds";

    my $sAMAccountName = $result->entry(0)->get_value('sAMAccountName');

    eval {
        my $command = "/usr/local/pf/addons/AD/secretsdump.py '".pf::domain::escape_bind_user_string($sAMAccountName)."':'".pf::domain::escape_bind_user_string($source->{password})."'@".$source->{host}." -just-dc-ntlm -output $tmpfile -usersfile $valid_users_file";
        $logger->debug("Executing sync command: $command");
        $result = pf_run($command, accepted_exit_status => [ 0 ]);
    };
    if (!defined($result) || $@) {
        return ($FALSE, "Can't generate hash list via secretsdump.py. Check logs for details.");
    }
    elsif($result =~ /Something wen't wrong/) {
        return ($FALSE, "Cannot synchronize users hashes. Command output: $result");
    }

    $logger->info("Generated NTDS file $ntds_file");
    return ($ntds_file);
}

=head2 populate_ntlm_redis_cache

Populate the redis NTLM cache for a domain

=cut

sub populate_ntlm_redis_cache {
    my ($domain) = @_;
    my $logger = get_logger;
    my $config = $ConfigDomain{$domain};

    my ($ntds_file, $err) = fetch_all_valid_hashes($domain);

    unless($ntds_file) {
        $logger->error($err);
        return ($FALSE, $err);
    }

    my $content = read_ntds_file($ntds_file);

    foreach my $line (split(/\n/, $content)) {
        my $info = extract_info_from_dump_line($line);
        insert_user_in_redis_cache($domain, $info->{username}, $info->{nthash});
    }
    return ($TRUE);
}

=head2 read_ntds_file

Returns the content of an NTDS file and deletes it at the same time

=cut

sub read_ntds_file {
    my ($ntds_file) = @_;
    my $content = read_file($ntds_file);
    # file isn't needed anymore
    unlink($ntds_file);
    return $content;
}

=head2 extract_info_from_dump_line

Extract the username and NT hash from a dump line

=cut

sub extract_info_from_dump_line {
    my ($line) = @_;
    my $data = [ split(':', $line) ];
    my $user = $data->[0];
    my $nthash = $data->[3];
    $user = [split(/\\/, $user)]->[-1];
    $user = lc($user);
    return {username => $user, nthash => $nthash};
}

=head2 insert_user_in_redis_cache

Insert a user/NT hash combination inside redis for a given domain

=cut

sub insert_user_in_redis_cache {
    my ($domain, $user, $nthash) = @_;
    my $logger = get_logger;
    my $config = $ConfigDomain{$domain};

    # pf::Redis has a cache for the connection
    my $redis = pf::Redis->new(server => "$NTLM_REDIS_CACHE_HOST:$NTLM_REDIS_CACHE_PORT", reconnect => 5);

    my $key = "NTHASH:$domain:$user";
    $logger->debug("Inserting '$key' => '$nthash'");
    $redis->set($key, $nthash, 'EX', $config->{ntlm_cache_expiry});
}

=head1 AUTHOR

Inverse inc. <info@inverse.ca>


=head1 COPYRIGHT

Copyright (C) 2005-2016 Inverse inc.

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

