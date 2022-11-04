# @summary Valid sshd PermitRootLogin values
#

type Cis_security_hardening::Sshd_root_login_values = Enum['yes', 'prohibit-password', 'without-password', 'forced-commands-only', 'no']
