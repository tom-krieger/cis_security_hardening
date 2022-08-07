# frozen_string_literal: true

require 'spec_helper'

describe 'cis_security_hardening::unmask_systemd_service' do
  let(:title) { 'test' }
  let(:params) do
    {
      'service' => 'tmp.mount',
    }
  end

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it {
        is_expected.to compile
        is_expected.to contain_exec('unmask server tmp.mount-test')
          .with(
            'command' => 'systemctl unmask tmp.mount',
            'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          )
      }
    end
  end
end
