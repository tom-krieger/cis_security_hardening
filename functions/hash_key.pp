# @summary
#    Check if a hash contains a particular key
#
# @param hash
#    The hash to search
#
# @param key
#    The key to search
#
# @api private
function cis_security_hardening::hash_key(Hash $hash, String $key) >> Boolean {
  if $key in $hash {
    $ret = true
  } else {
    $ret = false
  }

  $ret
}
