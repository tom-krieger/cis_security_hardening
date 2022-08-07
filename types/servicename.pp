# @summary
#    Check service name
#
type Cis_security_hardening::Servicename = Pattern[/^[a-zA-Z0-9\.\-_]+$/]
