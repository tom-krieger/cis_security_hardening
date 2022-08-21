# frozen_string_literal: true

require 'spec_helper'

describe 'cis_security_hardening::reboot' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { 
        is_expected.to compile 

        is_expected.to contain_echo('reboot required')
          .with(
            'message'  => 'Automatic reboots are disabled. Please make sure to reboot as soon as possible!',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
