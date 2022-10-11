require 'spec_helper_acceptance'

pp_basic = <<-PUPPETCODE
  class { 'cis_security_hardening':
    verbose_logging => true,
    update_postrun_command => false,
  }
PUPPETCODE

describe 'cis_security_hardening class' do
  let(:hiera_config) { './spec/fixtures/hiera/hiera.yaml' }

  describe 'with basic test' do
    it 'sets up the services' do
      # idempotent_apply(pp_basic)

      # expect(file('/usr/share/cis_security_hardening')).to be_directory
      # expect(file('/usr/share/cis_security_hardening/logs')).to be_directory
    end
  end
end
