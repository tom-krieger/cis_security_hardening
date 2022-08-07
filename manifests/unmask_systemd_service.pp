# @summary 
#    Unmask a systemd service
#
# Execute a systemd command to unmask a service.
#
# @param service
#    The service to unmask
#
# @example
#   cis_security_hardening::unmask_systemd_service { 'namevar': 
#       service => 'umask', 
# }
define cis_security_hardening::unmask_systemd_service (
  Cis_security_hardening::Servicename $service,
) {
  exec { "unmask server ${service}-${title}":
    command => "systemctl unmask ${service}", #lint:ignore:security_class_or_define_parameter_in_exec
    path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
  }
}
