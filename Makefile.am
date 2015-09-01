cfgdir		 = $(datadir)/vyatta-cfg/templates
opdir		 = $(datadir)/vyatta-op/templates
share_perl5dir	 = $(datarootdir)/perl5/Vyatta
ravpnconfdir = $(sysconfdir)/ravpn
bin_sudo_usersdir = $(bindir)/sudo-users

sbin_SCRIPTS = scripts/vyos-update-agile.pl

share_perl5_DATA = lib/Vyatta/AgileConfig.pm

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates-cfg; $(cpiop) $(DESTDIR)$(cfgdir)
#	mkdir -p $(DESTDIR)$(opdir)
#	cd templates-op; $(cpiop) $(DESTDIR)$(opdir)
