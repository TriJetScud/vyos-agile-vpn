package Vyatta::AgileConfig;

use strict;
use lib "/opt/vyatta/share/perl5";
use Vyatta::Config;
use Vyatta::Misc;
use NetAddr::IP;

my $cfg_delim_begin = '### VyOS Agile VPN Begin ###';
my $cfg_delim_end = '### VyOS Agile VPN End ###';

my $CA_CERT_PATH = '/etc/ipsec.d/cacerts';
my $CRL_PATH = '/etc/ipsec.d/crls';
my $SERVER_CERT_PATH = '/etc/ipsec.d/certs';
my $SERVER_KEY_PATH = '/etc/ipsec.d/private';

my %fields = (
  _mode             => undef,
  _psk              => undef,
  _x509_cacert      => undef,
  _x509_rcacert      => undef,
  _x509_crl         => undef,
  _x509_s_cert      => undef,
  _x509_s_key       => undef,
  _x509_s_pass      => undef,
  _x509_t_key       => undef,
  _x509_r_id        => undef,
  _x509_l_id        => undef,
  _out_addr         => undef,
  _dhcp_if          => undef,
  _client_ip_pool   => undef,
  _client_ip6_pool  => undef,
  _auth_mode        => undef,
  _oper_mode        => undef,
  _mtu              => undef,
  _ike_lifetime     => undef,
  _inactivity       => undef,
  _ike_group        => undef,
  _esp_group        => undef,
  _auth_require     => undef,
  _fragmentation    => undef,
  _compat           => undef,
  _auth_local       => [],
  _auth_radius      => [],
  _auth_radius_keys => [],
  _dns              => [],
  _wins             => [],
  _is_empty         => 1,
);

sub new {
  my $that = shift;
  my $class = ref ($that) || $that;
  my $self = {
    %fields,
  };

  bless $self, $class;
  return $self;
}

sub setup {
  my ( $self ) = @_;
  my $config = new Vyatta::Config;

  $config->setLevel('vpn ipsec remote-access');
  my @nodes = $config->listNodes();
  if (scalar(@nodes) <= 0) {
    $self->{_is_empty} = 1;
    return 0;
  } else {
    $self->{_is_empty} = 0;
  }
  $self->{_dhcp_if} = $config->returnValue('dhcp-interface');
  $self->{_compat} = $config->returnValue('compatibility-mode');
  $self->{_mode} = $config->returnValue('ike-settings authentication mode');
  $self->{_psk} = $config->returnValue('ike-settings authentication pre-shared-secret');
  $self->{_fragmentation} = $config->returnValue('ike-settings fragmentation');
  $self->{_inactivity} = $config->returnValue('inactivity');
  $self->{_ike_lifetime} = $config->returnValue('ike-settings ike-lifetime');
  $self->{_oper_mode} = $config->returnValue('ike-settings operating-mode');
  $self->{_ike_group} = $config->returnValue('ike-settings proposal 1 encryption');
  $self->{_esp_group} = $config->returnValue('esp-settings proposal 1 encryption');
  my $pfx = 'ike-settings authentication x509';
  $self->{_x509_cacert} = $config->returnValue("$pfx ca-cert-file");
  $self->{_x509_rcacert} = $config->returnValue("$pfx remote-ca-cert-file");
  $self->{_x509_crl} = $config->returnValue("$pfx crl-file");
  $self->{_x509_s_cert} = $config->returnValue("$pfx server-cert-file");
  $self->{_x509_s_key} = $config->returnValue("$pfx server-key-file");
  $self->{_x509_s_pass} = $config->returnValue("$pfx server-key-password");
  $self->{_x509_t_key} = $config->returnValue("$pfx server-key-type");
  $self->{_x509_l_id} = $config->returnValue("$pfx local-id");
  $self->{_x509_r_id} = $config->returnValue("$pfx remote-id");
  
  $self->{_out_addr} = $config->returnValue('outside-address');
  $self->{_client_ip_pool} = $config->returnValue('client-ip-pool subnet');
  $self->{_client_ip6_pool} = $config->returnValue('client-ip-pool subnet6');
  $self->{_auth_mode} = $config->returnValue('authentication mode');
  $self->{_auth_require} = $config->returnValue('authentication require');
  $self->{_mtu} = $config->returnValue('mtu');
  $self->{_left_updown} = $config->returnValue('updown-script');

  my @users = $config->listNodes('authentication local-users username');
  foreach my $user (@users) {
    my $plvl = "authentication local-users username $user password";
    my $pass = $config->returnValue("$plvl");
    my $dlvl = "authentication local-users username $user disable";
    my $disable = 'enable';
    $disable = 'disable' if $config->exists("$dlvl");
    $self->{_auth_local} = [ @{$self->{_auth_local}}, $user, $pass, $disable];
  }

  my @rservers = $config->listNodes('authentication radius-server');
  foreach my $rserver (@rservers) {
    my $key = $config->returnValue(
                        "authentication radius-server $rserver key");
    $self->{_auth_radius} = [ @{$self->{_auth_radius}}, $rserver ];
    if (defined($key)) {
      $self->{_auth_radius_keys} = [ @{$self->{_auth_radius_keys}}, $key ];
    }
    # later we will check if the two lists have the same length
  }

  my $tmp = $config->returnValue('dns-servers server-1');
  if (defined($tmp)) {
    $self->{_dns} = [ @{$self->{_dns}}, $tmp ];
  }
  $tmp = $config->returnValue('dns-servers server-2');
  if (defined($tmp)) {
    $self->{_dns} = [ @{$self->{_dns}}, $tmp ];
  }
  
  $tmp = $config->returnValue('wins-servers server-1');
  if (defined($tmp)) {
    $self->{_wins} = [ @{$self->{_wins}}, $tmp ];
  }
  $tmp = $config->returnValue('wins-servers server-2');
  if (defined($tmp)) {
    $self->{_wins} = [ @{$self->{_wins}}, $tmp ];
  }

  return 0;
}

sub setupOrig {
  my ( $self ) = @_;
  my $config = new Vyatta::Config;

  $config->setLevel('vpn ipsec remote-access');
  my @nodes = $config->listOrigNodes();
  if (scalar(@nodes) <= 0) {
    $self->{_is_empty} = 1;
    return 0;
  } else {
    $self->{_is_empty} = 0;
  }
  $self->{_dhcp_if} = $config->returnOrigValue('dhcp-interface');
  $self->{_compat} = $config->returnOrigValue('compatibility-mode');
  $self->{_mode} = 'x509';
  $self->{_inactivity} = $config->returnOrigValue('inactivity');
  $self->{_fragmentation} = $config->returnOrigValue('ike-settings fragmentation');
  $self->{_ike_lifetime} = $config->returnOrigValue('ike-settings ike-lifetime');
  $self->{_oper_mode} = $config->returnOrigValue('ike-settings operating-mode');
  $self->{_ike_group} = $config->returnOrigValue('ike-settings proposal 1 encryption');
  $self->{_esp_group} = $config->returnOrigValue('esp-settings proposal 1 encryption');
  my $pfx = 'ike-settings authentication x509';
  $self->{_x509_cacert} = $config->returnOrigValue("$pfx ca-cert-file");
  $self->{_x509_rcacert} = $config->returnOrigValue("$pfx remote-ca-cert-file");
  $self->{_x509_crl} = $config->returnOrigValue("$pfx crl-file");
  $self->{_x509_s_cert} = $config->returnOrigValue("$pfx server-cert-file");
  $self->{_x509_s_key} = $config->returnOrigValue("$pfx server-key-file");
  $self->{_x509_s_pass} = $config->returnOrigValue("$pfx server-key-password");
  $self->{_x509_t_key} = $config->returnOrigValue("$pfx server-key-type");
  $self->{_x509_l_id} = $config->returnOrigValue("$pfx local-id");
  $self->{_x509_r_id} = $config->returnOrigValue("$pfx remote-id");
  
  $self->{_out_addr} = $config->returnOrigValue('outside-address');
  $self->{_client_ip_pool} = $config->returnOrigValue('client-ip-pool subnet');
  $self->{_client_ip6_pool} = $config->returnOrigValue('client-ip-pool subnet6');
  $self->{_auth_mode} = $config->returnOrigValue('authentication mode');
  $self->{_auth_require} = $config->returnValue('authentication require');
  $self->{_mtu} = $config->returnOrigValue('mtu');
  $self->{_left_updown} = $config->returnValue('updown-script');

  my @users = $config->listOrigNodes('authentication local-users username');
  foreach my $user (@users) {
    my $plvl = "authentication local-users username $user password";
    my $pass = $config->returnOrigValue("$plvl");
    my $dlvl = "authentication local-users username $user disable";
    my $disable = 'enable';
    $disable = 'disable' if $config->existsOrig("$dlvl");
    $self->{_auth_local} = [ @{$self->{_auth_local}}, $user, $pass, $disable];
  }

  my @rservers = $config->listOrigNodes('authentication radius-server');
  foreach my $rserver (@rservers) {
    my $key = $config->returnOrigValue(
                        "authentication radius-server $rserver key");
    $self->{_auth_radius} = [ @{$self->{_auth_radius}}, $rserver ];
    if (defined($key)) {
      $self->{_auth_radius_keys} = [ @{$self->{_auth_radius_keys}}, $key ];
    }
    # later we will check if the two lists have the same length
  }

  my $tmp = $config->returnOrigValue('dns-servers server-1');
  if (defined($tmp)) {
    $self->{_dns} = [ @{$self->{_dns}}, $tmp ];
  }
  $tmp = $config->returnOrigValue('dns-servers server-2');
  if (defined($tmp)) {
    $self->{_dns} = [ @{$self->{_dns}}, $tmp ];
  }
  
  $tmp = $config->returnOrigValue('wins-servers server-1');
  if (defined($tmp)) {
    $self->{_wins} = [ @{$self->{_wins}}, $tmp ];
  }
  $tmp = $config->returnOrigValue('wins-servers server-2');
  if (defined($tmp)) {
    $self->{_wins} = [ @{$self->{_wins}}, $tmp ];
  }

  return 0;
}

sub listsDiff {
  my @a = @{$_[0]};
  my @b = @{$_[1]};
  return 1 if ((scalar @a) != (scalar @b));
  while (my $a = shift @a) {
    my $b = shift @b;
    return 1 if ($a ne $b);
  }
  return 0;
}

sub globalIPsecChanged {
  my $config = new Vyatta::Config();
  $config->setLevel('vpn');
  # for now, treat it as changed if anything under ipsec changed
  return 1 if ($config->isChanged('ipsec'));
  return 0;
}

sub isDifferentFrom {
  my ($this, $that) = @_;

  return 1 if ($this->{_is_empty} ne $that->{_is_empty});
  return 1 if ($this->{_mode} ne $that->{_mode});
  return 1 if ($this->{_compat} ne $that->{_compat});
  return 1 if ($this->{_ike_lifetime} ne $that->{_ike_lifetime});
  return 1 if ($this->{_x509_cacert} ne $that->{_x509_cacert});
  return 1 if ($this->{_x509_rcacert} ne $that->{_x509_rcacert});
  return 1 if ($this->{_x509_crl} ne $that->{_x509_crl});
  return 1 if ($this->{_x509_s_cert} ne $that->{_x509_s_cert});
  return 1 if ($this->{_x509_s_key} ne $that->{_x509_s_key});
  return 1 if ($this->{_x509_s_pass} ne $that->{_x509_s_pass});
  return 1 if ($this->{_x509_t_key} ne $that->{_x509_t_key});
  return 1 if ($this->{_x509_l_id} ne $that->{_x509_l_id});
  return 1 if ($this->{_x509_r_id} ne $that->{_x509_r_id});
  return 1 if ($this->{_out_addr} ne $that->{_out_addr});
  return 1 if ($this->{_dhcp_if} ne $that->{_dhcp_if});
  return 1 if ($this->{_client_ip_pool} ne $that->{_client_ip_pool});
  return 1 if ($this->{_client_ip6_pool} ne $that->{_client_ip6_pool});
  return 1 if ($this->{_auth_mode} ne $that->{_auth_mode});
  return 1 if ($this->{_auth_require} ne $that->{_auth_require});
  return 1 if ($this->{_mtu} ne $that->{_mtu});
  return 1 if ($this->{_left_updown} ne $that->{_left_updown});
  return 1 if (listsDiff($this->{_auth_local}, $that->{_auth_local}));
  return 1 if (listsDiff($this->{_auth_radius}, $that->{_auth_radius}));
  return 1 if (listsDiff($this->{_auth_radius_keys},
                         $that->{_auth_radius_keys}));
  return 1 if (listsDiff($this->{_dns}, $that->{_dns}));
  return 1 if (listsDiff($this->{_wins}, $that->{_wins}));
  return 1 if (globalIPsecChanged());
  
  return 0;
}

sub needsRestart {
  my ($this, $that) = @_;

  return 1 if ($this->{_is_empty} ne $that->{_is_empty});
  return 1 if ($this->{_compat} ne $that->{_compat});
  return 1 if ($this->{_mode} ne $that->{_mode});
  return 1 if ($this->{_ike_lifetime} ne $that->{_ike_lifetime});
  return 1 if ($this->{_x509_cacert} ne $that->{_x509_cacert});
  return 1 if ($this->{_x509_rcacert} ne $that->{_x509_rcacert});
  return 1 if ($this->{_x509_crl} ne $that->{_x509_crl});
  return 1 if ($this->{_x509_s_cert} ne $that->{_x509_s_cert});
  return 1 if ($this->{_x509_s_key} ne $that->{_x509_s_key});
  return 1 if ($this->{_x509_s_pass} ne $that->{_x509_s_pass});
  return 1 if ($this->{_x509_t_key} ne $that->{_x509_t_key});
  return 1 if ($this->{_x509_l_id} ne $that->{_x509_l_id});
  return 1 if ($this->{_x509_r_id} ne $that->{_x509_r_id});
  return 1 if ($this->{_out_addr} ne $that->{_out_addr});
  return 1 if ($this->{_dhcp_if} ne $that->{_dhcp_if});
  return 1 if ($this->{_out_nexthop} ne $that->{_out_nexthop});
  return 1 if ($this->{_client_ip_start} ne $that->{_client_ip_start});
  return 1 if ($this->{_client_ip_stop} ne $that->{_client_ip_stop});
  return 1 if ($this->{_mtu} ne $that->{_mtu});
  return 1 if ($this->{_left_updown} ne $that->{_left_updown});
  return 1 if ($this->{_auth_mode} ne $that->{_auth_mode});
  return 1 if (globalIPsecChanged());
  
  return 0;
}

sub isEmpty {
  my ($self) = @_;
  return $self->{_is_empty};
}

sub setupX509IfNecessary {
  my ($self) = @_;
  return (undef, "IPsec authentication mode not defined")
    if (!defined($self->{_mode}));
  my $mode = $self->{_mode};
  if ($mode eq 'pre-shared-secret') {
    return;
  }

  return "\"ca-cert-file\" must be defined for X.509\n"
    if (!defined($self->{_x509_cacert}));
  return "\"server-cert-file\" must be defined for X.509\n"
    if (!defined($self->{_x509_s_cert}));
  return "\"server-key-file\" must be defined for X.509\n"
    if (!defined($self->{_x509_s_key}));

  return "Invalid ca-cert-file \"$self->{_x509_cacert}\""
    if (! -f $self->{_x509_cacert});
  return "Invalid remote-ca-cert-file \"$self->{_x509_rcacert}\""
    if (! -f $self->{_x509_rcacert});
  return "Invalid server-cert-file \"$self->{_x509_s_cert}\""
    if (! -f $self->{_x509_s_cert});
  return "Invalid server-key-file \"$self->{_x509_s_key}\""
    if (! -f $self->{_x509_s_key});

  if (defined($self->{_x509_crl})) {
    return "Invalid crl-file \"$self->{_x509_crl}\""
      if (! -f $self->{_x509_crl});
    system("cp -f $self->{_x509_crl} $CRL_PATH/");
    return "Cannot copy $self->{_x509_crl}" if ($? >> 8);
  }

  # perform more validation of the files

  system("cp -f $self->{_x509_cacert} $CA_CERT_PATH/");
  return "Cannot copy $self->{_x509_cacert}" if ($? >> 8);
  system("cp -f $self->{_x509_rcacert} $CA_CERT_PATH/");
  return "Cannot copy $self->{_x509_rcacert}" if ($? >> 8);
  system("cp -f $self->{_x509_s_cert} $SERVER_CERT_PATH/");
  return "Cannot copy $self->{_x509_s_cert}" if ($? >> 8);
  system("cp -f $self->{_x509_s_key} $SERVER_KEY_PATH/");
  return "Cannot copy $self->{_x509_s_key}" if ($? >> 8);

  return;
}

sub get_ipsec_secrets {
  my ($self) = @_;
  my $str;
  if ($self->{_mode} eq 'x509') {
    # X509
    my $key_file = $self->{_x509_s_key};
    my $key_pass = $self->{_x509_s_pass};
    my $key_type = $self->{_x509_t_key};
    my $key_str;
    return (undef, "\"server-key-file\" not defined")
      if (!defined($key_file));
    if ($key_type eq 'ecdsa') {
    $key_str = 'ECDSA';
    } else {
    $key_str = 'RSA';
    }
    my $pstr = (defined($key_pass) ? " \"$key_pass\"" : '');
    $key_file =~ s/^.*(\/[^\/]+)$/${SERVER_KEY_PATH}$1/;
    $str =<<EOS;
$cfg_delim_begin
: ${key_str} ${key_file}$pstr
$cfg_delim_end
EOS
  }
  if ($self->{_mode} eq 'pre-shared-secret') {
    # PSK
    my $key = $self->{_psk};
    my $oaddr = $self->{_out_addr};
    if (defined($self->{_dhcp_if})){
      return  (undef, "The specified interface is not configured for DHCP")
        if (!Vyatta::Misc::is_dhcp_enabled($self->{_dhcp_if},0));
      my $dhcpif = $self->{_dhcp_if};
      $oaddr = get_dhcp_addr($dhcpif);
    }
    return (undef, "IPsec pre-shared secret not defined") if (!defined($key));
    return (undef, "Outside address not defined") if (!defined($oaddr));
    $str = "$cfg_delim_begin\n";
    $oaddr = "#" if ($oaddr eq '');
    $str .= "$oaddr %any : PSK \"$key\"";
    $str .= " \#dhcp-ra-interface=$self->{_dhcp_if}\#" if (defined($self->{_dhcp_if}));
    $str .= "\n";
    $str .= "$cfg_delim_end\n";
  }
    return ($str, undef);
}
sub get_dhcp_addr{
  my ($if) = @_;
  my @dhcp_addr = Vyatta::Misc::getIP($if, 4);
  my $ifaceip = shift(@dhcp_addr); 
  @dhcp_addr = split(/\//, $ifaceip); 
  $ifaceip = $dhcp_addr[0];
  return ' ' if (!defined($ifaceip));
  return $ifaceip;
}

sub get_ra_conn {
  my ($self, $name) = @_;
  my $oaddr = $self->{_out_addr};
  if (defined($self->{_dhcp_if})){
    return  (undef, "The specified interface is not configured for DHCP")
      if (!Vyatta::Misc::is_dhcp_enabled($self->{_dhcp_if},0));
    my $dhcpif = $self->{_dhcp_if};
    $oaddr = get_dhcp_addr($dhcpif);
  }
  if (defined($self->{_dhcp_if}) && defined($self->{_out_addr})) {
	return (undef, "The options dhcp-interface and outside-address may not be defined together. Please use either dhcp-interface or outside-address");
  }
  # use strongSwan's %defaultroute macro if outside address is set to 0.0.0.0
  if (defined($self->{_out_addr}) && $self->{_out_addr} == "0.0.0.0") {
	$oaddr = "%defaultroute";
  }
  return (undef, "Outside address not defined") if (!defined($oaddr));
  return (undef, "Client IP Pool must be defined")
    if (!defined($self->{_client_ip_pool}));
  my $client_ip_pool = $self->{_client_ip_pool};
  my $client_ip6_pool;
  my $left_subnet_route = "0.0.0.0/0";
  my $auth_str;
  my $auth_mode;
  my $right_ca;
  my $server_id;
  my $esp_str;
  my $ike_str;
  return (undef, "IPsec authentication mode not defined")
    if (!defined($self->{_mode}));
  if (!defined($self->{_ike_group})) {
    $ike_str = "aes256gcm128-aes128gcm128-ecp384-ecp256-prfsha384-prfsha256,aes256-aes128-sha384-sha256-sha1-ecp384-ecp256-modp4096-modp3072-modp2048-prfsha384-prfsha256-prfsha1";
  } else {
    $ike_str = get_ike_proposals();
  }
  if (!defined($self->{_esp_group})) {
    $esp_str = "aes256gcm128-ecp384-ecp256-esn-noesn,aes256-aes128-sha1-ecp384-ecp256-modp4096-modp3072-modp2048-esn-noesn";
  } else {
    $esp_str = get_esp_proposals();
  }
  if (defined($self->{_client_ip6_pool})) {
    $client_ip6_pool = ",". $self->{_client_ip6_pool};
    $left_subnet_route .= "," . "::/0";
  }
  my $mode;
  if ($self->{_mode} eq 'pre-shared-secret') {
    $mode = "psk";
  } else {
    $mode = "pubkey";
  }
  my $fragmentation;
  if (defined($self->{_fragmentation}) && $self->{_fragmentation} eq 'enable') {
     $fragmentation = "  fragmentation=yes";
  }
  my $compat;
  if (!defined($self->{_compat}) || $self->{_compat} eq 'disable') {
     $compat = "!";
  }
  if (defined($self->{_x509_l_id})) {
     $server_id = "  leftid=" . $self->{_x509_l_id}. "\n";
  }
  if (defined($self->{_left_updown})) {
     $leftupdown = "  leftupdown=" . $self->{_left_updown}. "\n";
  }
  if (defined($self->{_x509_r_id})) {
     $server_id = $server_id . "  rightid=" . $self->{_x509_r_id};
  }
  if ($self->{_mode} eq 'x509') {
    my $server_cert = $self->{_x509_s_cert};
    return (undef, "\"server-cert-file\" not defined")
      if (!defined($server_cert));
    $server_cert =~ s/^.*(\/[^\/]+)$/${SERVER_CERT_PATH}$1/;
    $auth_str =<<EOS;
  leftauth=pubkey
  leftcert=$server_cert
  leftsendcert=always
EOS
  if (defined($self->{_x509_rcacert})) {
    my $remote_ca = $self->{_x509_rcacert};
    return (undef, "\"remote-ca-cert-file\" not defined")
      if (!defined($remote_ca));
    $remote_ca =~ s/^.*(\/[^\/]+)$/${CA_CERT_PATH}$1/;
    $right_ca = "rightca=" . $self->{_x509_rcacert};
    $right_ca = $right_ca . "\n  rightca2=" . $self->{_x509_rcacert};
  }
  }
  if ($self->{_mode} eq 'pre-shared-secret') {
    $auth_str = "  leftauth=psk\n";
  }
  my $str =<<EOS;
$cfg_delim_begin
conn $name
${auth_str}
  left=$oaddr
${server_id}
  leftsubnet=${left_subnet_route}
  leftfirewall=yes
  lefthostaccess=yes
${leftupdown}
  ike=${ike_str}${compat}
  esp=${esp_str}${compat}
${fragmentation}
  right=%any
  rightsourceip=${client_ip_pool}${client_ip6_pool}
  rekey=no
EOS
  if (defined($self->{_ike_lifetime})){
    $str .= "  ikelifetime=$self->{_ike_lifetime}\n";
  } else {
    $str .= "  ikelifetime=86400s\n";
  }
  if (defined($self->{_inactivity})) {
    $str .= "  inactivity=" . $self->{_inactivity} . "\n";
  } else {
    $str .= "  inactivity=28800s\n";
  }
  $str .= "\n";
  if ($self->{_oper_mode} eq 'ikev2-mobike') {
    # auth modes for client
    if ($self->{_mode} eq 'pre-shared-secret') {
      return(undef,"Pre-shared secrets are unsupported for IEKv2 Remote Access VPN's");
    }
    if ($self->{_auth_mode} eq 'x509') {
      $str .= <<EOS;
conn $name-pubkey
  also=$name
  ${right_ca}
  rightauth=pubkey
  keyexchange=ikev2
  mobike=yes
  auto=add

conn $name-eaptls
  also=$name-pubkey
  rightauth=eap-tls
  rightsendcert=never
  eap_identity=%any
  keyexchange=ikev2
  mobike=yes
  auto=add
EOS
    }
    if ($self->{_auth_mode} eq 'local') {
      $str .= <<EOS;
conn $name-mschapv2
  also=$name
  rightauth=eap-mschapv2
  eap_identity=%any
  keyexchange=ikev2
  mobike=yes
  auto=add
EOS
    }
    if ($self->{_auth_mode} eq 'radius') {
      $str .= <<EOS;
conn $name-radius
  also=$name
  rightauth=eap-radius
  eap_identity=%any
  keyexchange=ikev2
  mobike=yes
  auto=add
EOS
    }
  }
  if ($self->{_oper_mode} eq 'ikev1-xauth') {
    if ($self->{_auth_mode} eq 'x509') {
      return(undef, "X.509 user authentication is not supported with IKEv1 XAUTH Remote Access VPN");
    }
    if ($self->{_auth_mode} eq 'local') {
      $str .= <<EOS;
conn $name-xauth-local
  also=$name
  rightauth=$mode
  rightauth2=xauth
  keyexchange=ikev1
  auto=add
EOS
    }
    if ($self->{_auth_mode} eq 'radius') {
      $str .= <<EOS;
conn $name-xauth-radius
  also=$name
  rightauth=$mode
  rightauth2=xauth-eap
  keyexchange=ikev1
  auto=add
EOS
    }
  }
  if ($self->{_oper_mode} eq 'ikev1-hybrid') {
    if ($self->{_mode} eq 'pre-shared-secret') {
      return(undef,"Pre-shared secrets are not supported for IKEv1 XAUTH Hybrid Remote Access VPNs");
    }
    if ($self->{_auth_mode} eq 'x509') {
      return(undef, "X.509 user authentication is not supported with IKEv1 XAUTH Remote Access VPN");
    }
    if ($self->{_auth_mode} eq 'local') {
      $str .= <<EOS;
conn $name-xauth-hybrid-local
  also=$name
  rightauth=xauth
  keyexchange=ikev1
  auto=add
EOS
    }
    if ($self->{_auth_mode} eq 'radius') {
      $str .= <<EOS;
conn $name-xauth-hybrid-radius
  also=$name
  rightauth=xauth-eap
  keyexchange=ikev1
  auto=add
EOS
    }
  }
  $str .= "$cfg_delim_end\n";
  return ($str, undef);
}

sub get_strongswan_secrets {
  my ($self) = @_;
  return (undef, "Authentication mode must be specified")
    if (!defined($self->{_auth_mode}));
  my @users = @{$self->{_auth_local}};
  print "IKEv2 VPN warning: Local user authentication not defined\n"
    if ($self->{_auth_mode} eq 'local' && scalar(@users) == 0);
  my $mode = "EAP";
  if ($self->{_oper_mode} eq 'ikev1-xauth') {
    $mode = "XAUTH";
  }
  my $str = $cfg_delim_begin;
  if ($self->{_auth_mode} eq 'local') {
    while (scalar(@users) > 0) {
      my $user = shift @users;
      my $pass = shift @users;
	  my $disable = shift @users;
      if ($disable eq 'disable') {
      } else {
        $str .= ("\n$user : $mode \"$pass\"\n");
      }
    }
  }
  $str .= $cfg_delim_end . "\n";
  return ($str, undef);
}
sub get_strongswan_opts {
  my ($self) = @_;
  my @dns = @{$self->{_dns}};
  my @wins = @{$self->{_wins}};
  my $sstr;
  if (@dns) {
	  $sstr .= "\n\tdns =" ;
	  foreach my $d (@dns) {
		$sstr .= (" $d,");
	  }
	  #delete the last line
	  chop($sstr);
  }
  if (@wins) {
	  $sstr .= "\n\tnbns =";
	  foreach my $w (@wins) {
		$sstr .= (" $w,");
	  }
	  chop($sstr);
  }
  my $rstr = '';
  $rstr = <<EOS;
attr {
	$sstr
	load = yes
}
EOS

  return ($rstr, undef);
}

sub get_strongswan_radius {
  my ($self) = @_;
  my $mode = $self->{_auth_mode};
  return ("$cfg_delim_begin\n$cfg_delim_end\n", undef) if ($mode ne 'radius');
  
  my @auths = @{$self->{_auth_radius}};
  my @skeys = @{$self->{_auth_radius_keys}};
  return (undef, "No Radius servers specified") if ((scalar @auths) <= 0);
  return (undef, "Key must be specified for Radius server")
    if ((scalar @auths) != (scalar @skeys));

  my $authstr = '';
  my $server_num = 0;
  while ((scalar @auths) > 0) {
    
    my $auth = shift @auths;
	my $skey = shift @skeys;
	$authstr .=<<EOS;
		server${server_num} {
			address = $auth
			secret = $skey
		}
EOS
    $server_num++;
  }
my $radius_conf =<<EOS;
eap-radius {
	load = yes
	servers {
${authstr}
	}
}
EOS
  return ($radius_conf, undef);
}

sub get_dhcp_hook {
  my ($self, $dhcp_hook) = @_;
  return ("", undef) if (!defined($self->{_dhcp_if}));
  if (defined($self->{_dhcp_if}) && defined($self->{_out_addr})){
   return (undef, "Only one of dhcp-interface and outside-address can be defined.");
  }
  my $str =<<EOS;
#!/bin/sh
$cfg_delim_begin
CFGIFACE=$self->{_dhcp_if}
/opt/vyatta/bin/sudo-users/vyatta-l2tp-dhcp.pl --config_iface=\"\$CFGIFACE\" --interface=\"\$interface\" --new_ip=\"\$new_ip_address\" --reason=\"\$reason\" --old_ip=\"\$old_ip_address\"
$cfg_delim_end
EOS
  return ($str, undef);

}

sub removeCfg {
  my ($self, $file) = @_;
  system("sed -i '/$cfg_delim_begin/,/$cfg_delim_end/d' $file");
  if ($? >> 8) {
    print STDERR <<EOM;
IKEv2 VPN configuration error: Cannot remove old config from $file.
EOM
    return 0;
  }
  return 1;
}

sub writeCfg {
  my ($self, $file, $cfg, $append, $delim) = @_;
  my $op = ($append) ? '>>' : '>';
  my $WR = undef;
  if (!open($WR, "$op","$file")) {
    print STDERR <<EOM;
IKEv2 VPN configuration error: Cannot write config to $file.
EOM
    return 0;
  }
  if ($delim) {
    $cfg = "$cfg_delim_begin\n" . $cfg . "\n$cfg_delim_end\n";
  }
  print ${WR} "$cfg";
  close $WR;
  return 1;
}

sub maybeClustering {
  my ($self, $config, @interfaces) = @_;
  return 0 if (defined($self->{_dhcp_if}));
  return (!(Vyatta::Misc::isIPinInterfaces($config, $self->{_out_addr},
                                         @interfaces)));
}

sub print_str {
  my ($self) = @_;
  my $str = 'l2tp vpn';
  $str .= "\n  oaddr " . $self->{_out_addr};
  $str .= "\n  onexthop " . $self->{_out_nexthop};
  $str .= "\n  cip_start " . $self->{_client_ip_start};
  $str .= "\n  cip_stop " . $self->{_client_ip_stop};
  $str .= "\n  auth_mode " . $self->{_auth_mode};
  $str .= "\n  auth_local " . (join ",", @{$self->{_auth_local}});
  $str .= "\n  auth_radius " . (join ",", @{$self->{_auth_radius}});
  $str .= "\n  auth_radius_s " . (join ",", @{$self->{_auth_radius_keys}});
  $str .= "\n  dns " . (join ",", @{$self->{_dns}});
  $str .= "\n  wins " . (join ",", @{$self->{_wins}});
  $str .= "\n  empty " . $self->{_is_empty};
  $str .= "\n";

  return $str;
}

sub get_ike_proposals {
    #
    # Write IKE configuration from group
    #
	my $genout;
    my $vcVPN = new Vyatta::Config();
    $vcVPN->setLevel('vpn ipsec remote-access');
	my @ike_proposals = $vcVPN->listNodes("ike-settings proposal");

	my $first_ike_proposal = 1;
	foreach my $ike_proposal (@ike_proposals) {

		#
		# Get encryption, hash & Diffie-Hellman  key size
		#
		my $encryption = $vcVPN->returnValue("ike-settings proposal $ike_proposal encryption");
		my $hash = $vcVPN->returnValue("ike-settings proposal $ike_proposal hash");
		my $dh_group = $vcVPN->returnValue("ike-settings proposal $ike_proposal dh-group");

		#
		# Write separator if not first proposal
		#
		if ($first_ike_proposal) {
			$first_ike_proposal = 0;
		} else {
			$genout .= ",";
		}

		#
		# Write values
		#
		if (defined($encryption) && defined($hash)) {
			$genout .= "$encryption-$hash";
			if (defined($dh_group)) {
				my $cipher_out = get_dh_cipher_result($dh_group);
				if ($cipher_out eq 'unknown') {
					return undef;
				} else {
					$genout .= "-$cipher_out";
				}
			}
		}
	}
    return $genout;
}

sub get_esp_proposals {
	my $genout;
    my $vcVPN = new Vyatta::Config();
    $vcVPN->setLevel('vpn ipsec remote-access');
	my @esp_proposals =$vcVPN->listNodes("esp-settings proposal");
	my $first_esp_proposal = 1;
	foreach my $esp_proposal (@esp_proposals) {

		#
		# Get encryption, hash and PFS group settings
		#
		my $encryption = $vcVPN->returnValue("esp-settings proposal $esp_proposal encryption");
		my $hash = $vcVPN->returnValue("esp-settings proposal $esp_proposal hash");
		my $pfs = $vcVPN->returnValue("esp-settings proposal $esp_proposal dh-group");

		#
		# Write separator if not first proposal
		#
		if ($first_esp_proposal) {
			$first_esp_proposal = 0;
		} else {
			$genout .= ",";
		}
		if (defined($pfs)) {
			if ($pfs eq 'enable') {
				undef $pfs;
			} elsif ($pfs eq 'disable') {
				undef $pfs;
			} else {
				$pfs = get_dh_cipher_result($pfs);
			}
		}

		#
		# Write values
		#
		if (defined($encryption) && defined($hash)) {
			$genout .= "$encryption-$hash";
			if (defined($pfs)) {
				$genout .= "-$pfs";
			}
		}
	}
	return $genout;
}

sub get_dh_cipher_result { 
    my ($cipher) = @_;
    my $ciph_out;
    if ($cipher eq '2' || $cipher eq 'dh-group2') {
        $ciph_out = 'modp1024';
    } elsif ($cipher eq '5' || $cipher eq 'dh-group5') {
        $ciph_out = 'modp1536';
    } elsif ($cipher eq '14' || $cipher eq 'dh-group14') {
        $ciph_out = 'modp2048';
    } elsif ($cipher eq '15' || $cipher eq 'dh-group15') {
        $ciph_out = 'modp3072';
    } elsif ($cipher eq '16' || $cipher eq 'dh-group16') {
        $ciph_out = 'modp4096';
    } elsif ($cipher eq '17' || $cipher eq 'dh-group17') {
        $ciph_out = 'modp6144';
    } elsif ($cipher eq '18' || $cipher eq 'dh-group18') {
        $ciph_out = 'modp8192';
    } elsif ($cipher eq '19' || $cipher eq 'dh-group19') {
        $ciph_out = 'ecp256';
    } elsif ($cipher eq '20' || $cipher eq 'dh-group20') {
        $ciph_out = 'ecp384';
    } elsif ($cipher eq '21' || $cipher eq 'dh-group21') {
        $ciph_out = 'ecp521';
    } elsif ($cipher eq '22' || $cipher eq 'dh-group22') {
        $ciph_out = 'modp1024s160';
    } elsif ($cipher eq '23' || $cipher eq 'dh-group23') {
        $ciph_out = 'modp2048s224';
    } elsif ($cipher eq '24' || $cipher eq 'dh-group24') {
        $ciph_out = 'modp2048s256';
    } elsif ($cipher eq '25' || $cipher eq 'dh-group25') {
        $ciph_out = 'ecp192';
    } elsif ($cipher eq '26' || $cipher eq 'dh-group26') {
        $ciph_out = 'ecp224';
    } else {
        $ciph_out = 'unknown';
    }
    return $ciph_out;
}

1;

