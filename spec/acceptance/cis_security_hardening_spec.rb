require 'spec_helper_acceptance'

pp_basic = <<-PUPPETCODE
  include cis_security_hardening
PUPPETCODE

describe 'cis_security_hardening class' do
  describe 'with basic test' do
    it 'sets up the services' do
      idempotent_apply(pp_basic)

      expect(file('/usr/share/cis_security_hardening')).to be_directory
      expect(file('/usr/share/cis_security_hardening/logs')).to be_directory
    end
  end
end
