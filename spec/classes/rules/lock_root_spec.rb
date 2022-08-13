# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::lock_root' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it { 
          is_expected.to compile 

          if enforce 
            is_expected.to contain_exec('lock root account')
              .with(
                'command' => 'passwd -l root',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'unless'  => 'test -z "$(passwd -S root | grep \'root L\')"',
              )
          else
            is_expected.not_to contain_exec('lock root account')
          end
        }
      end
    end
  end
end
