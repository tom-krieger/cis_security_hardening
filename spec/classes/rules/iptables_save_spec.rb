# frozen_string_literal: true

require 'spec_helper'

describe 'cis_security_hardening::rules::iptables_save' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it {
        is_expected.to compile

        if os_facts[:operatingsystem].casecmp('rocky').zero? || os_facts[:operatingsystem].casecmp('almalinux').zero?
          is_expected.to contain_exec('save iptables rules')
            .with(
              'command' => 'service iptables save',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )
        else
          is_expected.not_to contain_exec('save iptables rules')
        end
      }
    end
  end
end
