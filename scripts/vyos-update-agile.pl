#!/usr/bin/perl

use strict;
use lib "/opt/vyatta/share/perl5";
use Vyatta::Config;
use Vyatta::AgileConfig;
use File::Copy;
use Data::Dumper;

my $RACONN_NAME = 'agile-remote-access';
## XXX only the part after the last '-' affects order of conn matching!!!?
my $RACONN_NAME_WIN = "${RACONN_NAME}-win-aaa";
my $RACONN_NAME_MAC = "${RACONN_NAME}-mac-zzz";
my $FILE_IPSEC_CFG = '/etc/ipsec.conf';
my $FILE_IPSEC_SECRETS = '/etc/ipsec.secrets';
my $FILE_IPSEC_RACONN = "/etc/ipsec.d/tunnels/$RACONN_NAME";
my $FILE_CHAP_SECRETS = '/etc/ppp/secrets/chap-ravpn';
my $IPSEC_CTL_FILE = '/var/run/charon.ctl';
my $STRONGSWAN_ATTR_CONF = '/etc/strongswan.d/charon/attr.conf';
my $STRONGSWAN_AGILE_CONF = '/etc/strongswan.d/charon/agile_attr.conf';
my $STRONGSWAN_RADIUS_CONF = '/etc/strongswan.d/charon/eap-radius.conf';
my $STRONGSWAN_RADIUS_AGILE_CONF = '/etc/strongswan.d/charon/agile_eap-radius.conf';

my $gconfig = new Vyatta::Config;
my $config = new Vyatta::AgileConfig;
my $oconfig = new Vyatta::AgileConfig;
$config->setup();
$oconfig->setupOrig();

if ($config->isEmpty()) {
  if (!$oconfig->isEmpty()) {
    # remove remote-access vpn connections
	system ("ipsec stroke down-nb $RACONN_NAME");
    system ("ipsec rereadall >&/dev/null");
    system ("ipsec reload >&/dev/null");
	
	if ( ! -f $STRONGSWAN_ATTR_CONF) {
		move("$STRONGSWAN_ATTR_CONF.noload", $STRONGSWAN_ATTR_CONF);
    if (-f $STRONGSWAN_AGILE_CONF) {
      unlink($STRONGSWAN_AGILE_CONF);
    }
	} if ( ! -f $STRONGSWAN_RADIUS_CONF) {
		move("$STRONGSWAN_RADIUS_CONF.noload" , $STRONGSWAN_RADIUS_CONF);
    if (-f $STRONGSWAN_RADIUS_AGILE_CONF) {
      unlink($STRONGSWAN_RADIUS_AGILE_CONF);
    }
	}
	if ( -f $FILE_IPSEC_RACONN ) {
		system("rm -f $FILE_IPSEC_RACONN");
	}
  }
  exit 0;
}

# required ipsec settings
## ipsec-interfaces
my @ipsec_ifs = $gconfig->returnValues('vpn ipsec ipsec-interfaces interface');
## nat-traversal
my $nat_traversal = $gconfig->returnValue('vpn ipsec nat-traversal');
## nat-networks
my @nat_nets = $gconfig->listNodes('vpn ipsec nat-networks allowed-network');

my ($ipsec_secrets, $ra_conn, $sswan_radius, $sswan_users, $err, $sswan_opts)
  = (undef, undef, undef, undef, undef, undef);
while (1) {
  ($ipsec_secrets, $err) = $config->get_ipsec_secrets();
  last if (defined($err));
  ($ra_conn, $err) = $config->get_ra_conn($RACONN_NAME);
  last if (defined($err));
  ($sswan_opts, $err) = $config->get_strongswan_opts();
  last if (defined($err));
  ($sswan_radius, $err) = $config->get_strongswan_radius();
  last if (defined($err));
  ($sswan_users, $err) = $config->get_strongswan_secrets();
  $err = $config->setupX509IfNecessary();
  last;
}
if (defined($err)) {
  print STDERR "IKEv2 VPN configuration error: $err.\n";
  exit 1;
}
# Build our attribute file
if ( -f $STRONGSWAN_ATTR_CONF ) {
  move($STRONGSWAN_ATTR_CONF, "$STRONGSWAN_ATTR_CONF.noload");
  system("touch $STRONGSWAN_AGILE_CONF");
}
# Build our eap-radius file if radius is needed
if ( -f $STRONGSWAN_RADIUS_CONF ) {
  move($STRONGSWAN_RADIUS_CONF, "$STRONGSWAN_RADIUS_CONF.noload");
  system("touch $STRONGSWAN_RADIUS_AGILE_CONF");
}
if ( ! -f $FILE_IPSEC_RACONN ) {
  system("touch $FILE_IPSEC_RACONN");
}

exit 1 if (!$config->removeCfg($FILE_IPSEC_CFG));
exit 1 if (!$config->removeCfg($FILE_IPSEC_SECRETS));
exit 1 if (!$config->removeCfg($FILE_IPSEC_RACONN));
exit 1 if (!$config->removeCfg($STRONGSWAN_AGILE_CONF));
exit 1 if (!$config->removeCfg($STRONGSWAN_RADIUS_AGILE_CONF));

my $ipsec_cfg = "include $FILE_IPSEC_RACONN";
exit 1 if (!$config->writeCfg($FILE_IPSEC_CFG, $ipsec_cfg, 1, 1));
exit 1 if (!$config->writeCfg($FILE_IPSEC_SECRETS, $ipsec_secrets, 1, 0));
exit 1 if (!$config->writeCfg($FILE_IPSEC_SECRETS, $sswan_users, 1, 0));
exit 1 if (!$config->writeCfg($FILE_IPSEC_RACONN, $ra_conn, 0, 0));
exit 1 if (!$config->writeCfg($STRONGSWAN_AGILE_CONF, $sswan_opts, 0, 1));
exit 1 if (!$config->writeCfg($STRONGSWAN_RADIUS_AGILE_CONF, $sswan_radius, 0, 1));

# wait for ipsec to settle
if (!($config->maybeClustering($gconfig, @ipsec_ifs))) {
  my $sleep = 0;
  while (! -e $IPSEC_CTL_FILE) {
    sleep 1;
    if (++$sleep > 10) {
      print STDERR "IKEv2 VPN configuration error: IPsec did not start.\n";
      exit 1;
    }
  }
}

if (!($config->isDifferentFrom($oconfig))) {
  # config not actually changed. do nothing.
  exit 0;
} else {
  system ("ipsec rereadall >&/dev/null");
  system ("ipsec reload >&/dev/null");
  if (-f '/usr/sbin/swanctl') {
    system ("swanctl -r >&/dev/null");
  }
}

exit 0;


