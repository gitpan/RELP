package RELP;

use 5.008008;
use strict;
use warnings;

use IO::Socket;

use Carp;

our $VERSION = '1.00';

use base qw( Class::Accessor );
__PACKAGE__->mk_ro_accessors( qw( 
    host port 
    socket 
    txnr 
    facility severity tag 
    timeout 
) );




my $LF = "\xA";
my $SP = "\x20";
my @MONTHS = qw( Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec );



sub new {
    my $class = shift;
    my %opts  = (
        'host'     => undef,
        'port'     => undef,
        'facility' => 16,
        'severity' => 5,
        'tag'      => undef,
        'timeout'  => 5,
        @_,
    );
    
    my $host     = $opts{ 'host' } or confess 'host is not specified';
    my $port     = $opts{ 'port' } or confess 'port is not specified';
    my $facility = $opts{ 'facility' };
    my $severity = $opts{ 'severity' };
    my $tag      = $opts{ 'tag' };
    my $timeout  = $opts{ 'timeout' };
    
    $tag = $0 unless defined $tag;
    
    my $self = {
        'host'     => $host,
        'port'     => $port,
        'facility' => $facility,
        'severity' => $severity,
        'tag'      => $tag,
        'timeout'  => $timeout,
    };
    
    $self = bless $self, $class;
    
    $self->connect();
    
    return $self;
}

sub connect {
    my $self = shift;
    
    my $socket = new IO::Socket::INET ( 
        PeerAddr => $self->host,
        PeerPort => $self->port, 
        Proto    => 'tcp', 
        Timeout  => $self->timeout(),
    );
    
    die "Could not create socket: $!\n" unless $socket;   
    
    $socket->autoflush(1);
    
    $self->{ 'socket' } = $socket;
    $self->{ 'txnr' }   = 0;
    
    $self->_open();
   
    return;
}

sub _build_frame {
    my $self = shift;
    my %opts = (
        'txnr'    => undef,
        'command' => undef,
        'data'    => undef,
        @_,
    );
    
    my $txnr    = $opts{ 'txnr' } or confess 'transaction number is not specified';
    my $command = $opts{ 'command' } or confess 'command is not specified';
    my $data    = $opts{ 'data' };
    
    my $header = $txnr . $SP . $command;
    if( defined $data ) {
        $header .= $SP . length( $data );
    }
    
    my $tailer = $LF;
    my $frame = $header .( $data ? $SP . $data : '' ) . $tailer;
    
    return $frame;
}

sub _send_frame {
    my $self  = shift;
    my $frame = shift;
    
    my $socket = $self->socket;
    
    die "diconnected" unless $socket->connected;
    
    local $SIG{ 'PIPE' } = sub {
        die "broked pipe" . shift;
    };

    $socket->send( $frame ) or die "cant send packet to server";
    
    return;
}

sub _recieve_frame {
    my $self  = shift;
    my $frame = shift;
    
    my $socket = $self->socket;
    die "diconnected" unless $socket->connected;    
    
    local $SIG{ 'PIPE' } = sub {
        die "broked pipe" . shift;
    };
    
    my $buff = <$socket>;
    
    die "no data recieved" unless defined $buff;
    
    my $result = undef;
    
    if( $buff =~ /^(\d+)$SP(\w+)$SP(\d+)(.*)$/ ) {
        my $tn   = $1;
        my $cmd  = $2;
        my $len  = $3;
        
        my $data = $4;
        
        if( $len ) {
            $data =~ s/^\s//;
            $data .="\n" if( $len > length( $data ) - 1 );
            while( $len > length( $data ) - 1 ) {
                $data .= <$socket>;
            }
        }
        
        $result = {
            'tn'   => $tn,
            'cmd'  => $cmd,
            'data' => $data,
        };
    } else {
        die "wrong frame format : " . $buff;
    }
    
    return $result;
}

sub _open {
    my $self = shift;
    
    my $tn = $self->txnr() + 1;

    my $data = $LF . 'relp_version=1';
    $data .= $LF . 'commands=syslog,rsp';
        
    my $frame = $self->_build_frame(
        'txnr'    => $tn,
        'command' => 'open',
        'data'    => $data,
    );
    
   
    $self->_send_frame( $frame );
    my $resp = $self->_recieve_frame();
    
    die "server close connection" if( $resp->{ 'cmd' } eq 'serverclose' );
    unless( $resp->{ 'data' } =~ /^200$SP/ ) {
        die "error";
    }
    
    $self->{ 'txnr' } = $tn;
    
    return;
}

sub _get_date {
    my $self = shift;
    
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time());
    
    my $mon_str = $MONTHS[ $mon ];
    
    for( $mday, $hour, $min, $sec ) {
        $_ = '0' . $_ if $_ < 10;
    }
    
    return $mon_str . ' ' . $mday . ' '.$hour.':'.$min.':'.$sec;
}

sub send {
    my $self = shift;
    my @opts = @_;
    
    my $msg      = undef;
    my $tag      = undef;
    my $date     = undef;
    my $facility = undef;
    my $severity = undef;

    confess "message is not specified" unless defined $opts[ 0 ];    
    if( ref $opts[ 0 ] eq 'HASH' ) {
        my $opts = $opts[ 0 ];
        $msg      = $opts->{ 'msg' } or confess "message is not specified";
        $tag      = $opts->{ 'tag' };
        $date     = $opts->{ 'date' };
        $facility = $opts->{ 'facility' };
        $severity = $opts->{ 'severity' };
    } elsif( ref $opts[ 0 ] ) {
        confess "wrong param";
    } else {
        $msg = $opts[ 0 ];
    }
    
    $tag = $self->tag() if( !defined $tag || length( $tag ) == 0 );
    $tag =~ s/\s/_/g;
    
    $facility = $self->facility() unless defined $facility;
    $severity = $self->severity() unless defined $severity;
    
    my $tn = $self->txnr() + 1;
    
    $date ||= $self->_get_date();
    
    my $pri_part = '<' .( $facility * 8 + $severity ). '>';
        
    my $data = $pri_part . $date . ' ' . $tag . ': ' . $msg;
    
    my $frame = $self->_build_frame(
        'txnr'    => $tn,
        'command' => 'syslog',
        'data'    => $data,
    );    
    
    $self->_send_frame( $frame );
    my $resp = $self->_recieve_frame();
    
    die "server close connection" if( $resp->{ 'cmd' } eq 'serverclose' );
    unless( $resp->{ 'data' } =~ /^200$SP/ ) {
        die "error";
    }    

    $self->{ 'txnr' } = $tn;  
    
    return;
}

1;

__END__

=head1 NAME

RELP - Send messages over "Reliable Event Logging Protocol"

=head1 SYNOPSIS

  use RELP;
  my $relp = new RELP(
      host => YYYYY,
      port => XXXXX,
  );
  $relp->send( 'message' );

=head1 DESCRIPTION

This is very simple perl interface to sending messager over RELP protocol. 
It may provide reliable message sending to rsyslog server.

=head1 METHODS

=head2 new( host => .., port => .. )

Create connection to server.

Parameters:

  host - server host
  port - server port

Return:

  RELP-based object

=head2 send( $message )

Send message to server

=head1 SEE ALSO

For more information about RELP protocol, librelp and rsyslog visit L<http://www.librelp.com/>, L<http://www.rsyslog.com/>.

=head1 AUTHOR

Ivan Trunaev, <itrunaev@cpan.org>

=head1 COPYRIGHT AND LICENSE

Copyright 2010 Ivan Trunaev <itrunaev@cpan.org>

This program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.  That means either (a) the GNU General Public
License or (b) the Artistic License.


=cut
