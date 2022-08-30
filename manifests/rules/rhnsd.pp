# @summary 
#    Disable the rhnsd Daemon
#
# The rhnsd daemon polls the Red Hat Network web site for scheduled actions and, if there are, executes those actions.
#
# Rationale:
# Patch management policies may require that organizations test the impact of a patch before it is deployed in a production 
# environment. Having patches automatically deployed could have a negative impact on the environment. It is best to not allow 
# an action by default but only after appropriate consideration has been made. It is recommended that the service be disabled 
# unless the risk is understood and accepted or you are running your own satellite .
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::rhnsd':
#     enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::rhnsd (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_resource('service', 'rhnsd', {
        enable => false,
        ensure => stopped,
    })
  }
}
