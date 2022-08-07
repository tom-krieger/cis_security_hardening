# @summary
#    Check for only numbers and letters
#
type Cis_security_hardening::Numbers_letters = Pattern[
  /^[0-9a-zA-Z]+$/,
  /^$/,
]
