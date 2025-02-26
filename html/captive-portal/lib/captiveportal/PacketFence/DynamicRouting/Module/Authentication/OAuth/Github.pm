package captiveportal::PacketFence::DynamicRouting::Module::Authentication::OAuth::Github;

=head1 NAME

captiveportal::DynamicRouting::Module::Authentication::OAuth::Github

=head1 DESCRIPTION

Github OAuth module

=cut

use Moose;
extends 'captiveportal::DynamicRouting::Module::Authentication::OAuth';

has '+source' => (
    isa => 'pf::Authentication::Source::GithubSource',
    lazy => 1,
    builder => '_build_source',
);

has '+token_scheme' => (default => "auth-header:token");

=head2 _extract_username_from_response

Create a generic username if no e-mail is in the response

=cut

sub _extract_username_from_response {
    my ($self, $info) = @_;
    return $info->{email} || $info->{login}.'@github';
}

sub _build_source {
    my ($self) = @_;
    return $self->app->profile->getSourceByType('Github');
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

__PACKAGE__->meta->make_immutable unless $ENV{"PF_SKIP_MAKE_IMMUTABLE"};

1;

