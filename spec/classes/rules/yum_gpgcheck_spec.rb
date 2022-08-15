# frozen_string_literal: true

require 'spec_helper'
require 'pp'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::yum_gpgcheck' do
  enforce_options.each do |enforce|
    context "on RedHat with enforce = #{enforce}" do
      let(:params) do
        {
          'enforce' => enforce,
        }
      end
      let(:facts) { os_facts }

      os_facts = {
        osfamily: 'RedHat',
        operatingsystem: 'CentOS',
        architecture: 'x86_64',
        operatingsystemmajrelease: '8',
      }

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_file_line('yum_gpgcheck')
            .with(
              'ensure' => 'present',
              'path'   => '/etc/yum.conf',
              'line'   => 'gpgcheck=1',
              'match'  => '^gpgcheck',
            )

          pp os_facts[:osfamily]
          pp os_facts[:operatingsystemmajrelease]
          if os_facts[:osfamily].casecmp('redhat').zero? && os_facts[:operatingsystemmajrelease].to_s >= '8'
            is_expected.to contain_file_line('yum_gpgcheck dnf')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/dnf/dnf.conf',
                'line'   => 'gpgcheck=1',
                'match'  => '^gpgcheck',
              )
          end
        else
          is_expected.not_to contain_file_line('yum_gpgcheck')
          is_expected.not_to contain_file_line('yum_gpgcheck dnf')
        end
      }
    end
  end
end
