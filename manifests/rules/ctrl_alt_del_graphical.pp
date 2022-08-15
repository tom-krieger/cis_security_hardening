# @summary 
#    Ensure the graphical user Ctrl-Alt-Delete key sequence is disabled
#
# The operating system must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed.
#
# Rationale:
# A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally 
# pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of 
# availability of systems due to unintentional reboot. In the graphical environment, risk of unintentional reboot 
# from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::ctrl_alt_del_graphical':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::ctrl_alt_del_graphical (
  Boolean $enforce = false
) {
  if $enforce {
    ensure_resource('file', '/etc/dconf/db/local.d', {
        ensure => directory,
        owner  => 'root',
        group  => 'root',
        mode   => '0755',
    })

    ensure_resource('file', '/etc/dconf/db/local.d/00-disable-CAD', {
        ensure => file,
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
    })

    ini_setting { 'ctrl-alt-del-graphical':
      ensure  => present,
      path    => '/etc/dconf/db/local.d/00-disable-CAD',
      section => 'org/gnome/settings-daemon/plugins/media-keys',
      setting => 'logout',
      value   => '',
      require => File['/etc/dconf/db/local.d/00-disable-CAD'],
    }
  }
}
