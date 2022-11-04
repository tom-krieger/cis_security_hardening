# @summary Validate mountoption
#
# Check a mount option
type Cis_security_hardening::Mountoption = Pattern[/(^[\/a-zA-Z0-9]+$|^sec=[\/a-zA-Z0-9:]+$)|^size=[\/a-zA-Z0-9]+$|^fmask=[0-9]+$|^uid=[0-9]+$|^gid=[0-9]+$/] #lint:ignore:140chars
