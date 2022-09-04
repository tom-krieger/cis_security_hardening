# @summary Validate mountoption
#
# Check a mount option
type Cis_security_hardening::Mountoption = Pattern[/(^[\/a-zA-Z0-9]+$|^sec=[\/a-zA-Z0-9:]+$)/]
