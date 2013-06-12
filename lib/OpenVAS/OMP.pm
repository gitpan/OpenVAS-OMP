#!/usr/bin/perl
#
# Filename:     OMP.pm
# Description:  Pure-Perl interface to the OpenVAS Management Protocol
# Creator:      Winfried Neessen <wn@neessen.net>
#
# $Id$
#
# Last modified: [ 2013-06-12 09:37:17 ]

## This is the OpenVAS::OMP package {{{
package OpenVAS::OMP;

### Global modules {{{
use strict;
use warnings;
use Carp;
use IO::Socket::SSL;
use XML::Simple qw( :strict );
# }}}

### Global variables {{{
our $VERSION = '0.03';
# }}}

### Constants definitions {{{
use constant CHUNK_SIZE		=> 8192;
use constant CONN_TIMEOUT	=> 30;
use constant DEFAULT_PORT	=> 9390;
use constant DEFAULT_HOST	=> 'localhost';
use constant DEFAULT_SSL_VERIFY	=> 0;
# }}}

#### Public methods

### Module constructor // new() {{{
sub new
{

	## Create class and read arguments
	my ( $class, %args ) = @_;
	my $self = bless {}, $class;

	## Read arguments
	$self->{ 'host' }	= delete( $args{ 'host' } ) || DEFAULT_HOST;
	$self->{ 'timeout' }	= delete( $args{ 'timeout' } ) || CONN_TIMEOUT;
	$self->{ 'port' }	= delete( $args{ 'port' } ) || DEFAULT_PORT;
	$self->{ 'ssl_verify' }	= delete( $args{ 'ssl_verify' } ) || DEFAULT_SSL_VERIFY;
	$self->{ 'username' }	= delete( $args{ 'username' } );
	$self->{ 'password' }	= delete( $args{ 'password' } );

	## Check for mantatory arguments
	croak( 'No host argument given' )
		unless( defined( $self->{ 'host' } ) and $self->{ 'host' } ne '' );
	croak( 'No port argument given' )
		unless( defined( $self->{ 'port' } ) and $self->{ 'port' } ne '' );
	croak( 'Unsupported value "' . $self->{ 'ssl_verify' } . '" for argument "ssl_verify".' )
		if( $self->{ 'ssl_verify' } < 0 or $self->{ 'ssl_verify' } > 1 );

	## Warn about unrecognized arguments
	carp( "Unrecognized arguments: @{ [ sort keys %args ] }" ) if %args;

	## Return object
	return $self;

}
# }}}

### Send a request (hashref) to the OMP and return a XML hashref (or raw XML) // commandHash() {{{
sub commandHash
{

	## Get object and arguments
	my ( $self, $cmdHash, $raw ) = @_;

	## cmdHash needs to be a hash/hashref
	croak( 'Method "commandHash()" requires the first argument to be a hash/hashref' )
		unless( ref( $cmdHash ) eq 'HASH' );

	## Convert command hash to XML
	my $cmdXML = XMLout( $cmdHash, NoEscape => 0, SuppressEmpty => 1, KeepRoot => 1, KeyAttr => 'command' );

	## Send commandXML to server
	my $response = $self->_sendSock( $cmdXML );

	## Close socket connection
	$self->{ 'socket' }->close();

	## Return RAW or hashref version
	if( defined( $raw ) )
	{
		return $response;
	} else {
		return XMLin( $response, ForceArray => 1, KeyAttr => 'command_response' );
	}

}
# }}}

### Send a request (pure XML) to the OMP and return a XML hashref (or raw XML) // commandXML() {{{
sub commandXML
{

	## Get object and arguments
	my ( $self, $cmdXML, $raw ) = @_;

	## cmdHash needs to be a hash/hashref
	croak( 'Method "commandXML()" requires the first argument to be a hash/hashref' )
		unless( defined( $cmdXML ) and ref( $cmdXML ) eq '' );

	## Send commandXML to server
	my $response = $self->_sendSock( $cmdXML );

	## Close socket connection
	$self->{ 'socket' }->close();

	## Return RAW or hashref version
	if( defined( $raw ) )
	{
		return $response;
	} else {
		return XMLin( $response, ForceArray => 1, KeyAttr => 'command_response' );
	}

}
# }}}

### Request version string from OMP server // getVersion() {{{
sub getVersion
{

	## Get object
	my $self = shift;

	## Connect and authenticate with OMP server
	$self->_connect();

	## Send commandXML to server
	$self->{ 'socket' }->syswrite( '<get_version/>' );
	my $response = XMLin( $self->_readSock, ForceArray => 1, KeyAttr => 'command_response' );

	## Check respone
	croak( 'getVersion failed: ' . $response->{ 'status_text' } )
		unless( defined( $response->{ 'status' } ) and $response->{ 'status' } eq '200' );
	
	## Return response
	print STDERR 'OMP server version: ' . $response->{ 'version' }->[0] . "\n";
	return $response->{ 'version' }->[0];

}
# }}}


#### Private methods

### Initiate a SSL connection with the server // _connect() {{{
sub _connect
{

	## Get object
	my $self = shift;

	## Create a SSL socket
	my $socket = IO::Socket::SSL->new
	(

		PeerHost	  => $self->{ 'host' },
		PeerPort	  => $self->{ 'port' },

		Timeout		  => $self->{ 'timeout' },
		Proto		  => 'tcp',

		SSL_verify_mode   => $self->{ 'ssl_verify' },
	
	) or croak( 'Unable to connect to host ' . $self->{ 'host' } . ':' . $self->{ 'port' } . ': ' . &IO::Socket::SSL::errstr );

	## Reference socket in the object
	$self->{ 'socket' } = \*$socket;

}
# }}}

### Authenticate with the OMP server // _authenticate() {{{
sub _authenticate
{

	## Get object
	my $self = shift;

	## Make sure the everything required is available
	croak( 'Not connected with the OMP server' )
		unless( defined( $self->{ 'socket' } ) and ref( $self->{ 'socket' } ) eq 'IO::Socket::SSL' );
	croak( 'Username or password not provided' )
		unless( defined( $self->{ 'username' } ) and defined( $self->{ 'password' } ) );

	## Generate XML authentication string
	my ( $auth, $authXML );
	$auth->{ 'authenticate' }->{ 'credentials' } = [ { 'username' => [ $self->{ 'username' } ], 'password' => [ $self->{ 'password' } ] } ];
	$authXML = XMLout( $auth, NoEscape => 0, SuppressEmpty => 1, KeepRoot => 1, KeyAttr => 'authenticate' );

	## Send authentication string to OMP server and read response
	$self->{ 'socket' }->syswrite( $authXML );
	my $response = $self->_readSock;

	## Check repsonse
	my $authResponse = XMLin( $response, ForceArray => 1, KeyAttr => 'authenticate_response' );
	if( defined( $authResponse->{ 'status' } ) and $authResponse->{ 'status' } eq '200' )
	{
		return 1;
	}
	elsif( defined( $authResponse->{ 'status' } ) and $authResponse->{ 'status' } ne '200' )
	{
		carp( 'Error: ' . $authResponse->{ 'status_text' } );
		return undef;
	}
	else 
	{
		carp( 'Unexpected failure.' );
		return undef;
	}

}
# }}}

### Send date to socket // _sendSock() {{{
sub _sendSock
{

	## Get object
	my ( $self, $cmdXML ) = @_;

	## Connect and authenticate with OMP server
	$self->_connect();
	$self->_authenticate();

	## Send commandXML to server
	$self->{ 'socket' }->syswrite( $cmdXML );
	my $response = $self->_readSock;

	## Return the server response
	return $response;

}
# }}}

### Read from socket // _readSock() {{{
sub _readSock
{

	## Get object
	my $self = shift;

	## Make sure we are connected to the OMP server
	croak( 'Not connected with the OMP server' )
		unless( defined( $self->{ 'socket' } ) and ref( $self->{ 'socket' } ) eq 'IO::Socket::SSL' );

	## Read from socket
	my ( $length, $response );
	do {

		$length = $self->{ 'socket' }->sysread( my $buffer, CHUNK_SIZE );
		undef $length if( $length == 0 );
		undef $length if( $length < CHUNK_SIZE );

		$response .= $buffer if defined( $buffer );

	} while ( $length );

	## Return the response
	return $response;

}
# }}}



1;
__END__

=head1 NAME

OpenVAS::OMP - Pure-perl interface to the OpenVAS Management Protocol

