# frozen_string_literal: true

require 'facter/cis_security_hardening/facts_redhat'
require 'facter/cis_security_hardening/facts_debian'
require 'facter/cis_security_hardening/facts_ubuntu'
require 'facter/cis_security_hardening/facts_sles'
require 'facter/cis_security_hardening/common_facts'
require 'pp'

Facter.add(:cis_security_hardening) do
  osfamily = Facter.value(:osfamily).downcase
  osystem = Facter.value(:operatingsystem).downcase
  distid = Facter.value(:lsbdistid)
  release = Facter.value(:operatingsystemmajrelease)
  ret = {}

  setcode do
    case osfamily
    when 'redhat'
      ret = facts_redhat(osfamily, distid, release)

    when 'debian'
      ret = if osystem == 'ubuntu'
              facts_ubuntu(osfamily, distid, release)
            else
              facts_debian(osfamily, distid, release)
            end

    when 'suse'
      ret = facts_sles(osfamily, distid, release)

    end

    ret¢['osname_lc'] = osfamily = Facter.value(:operatingsystem).downcase

    ret
  end
end
