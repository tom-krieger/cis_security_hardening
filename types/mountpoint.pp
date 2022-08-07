# @summary
#    Validate mountpoint
# Check a mountpoint with a regex
type Cis_security_hardening::Mountpoint = Pattern[/^[\/a-zA-Z0-9_-]+$/]
