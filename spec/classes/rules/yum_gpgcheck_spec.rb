# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::yum_gpgcheck' do
  enforce_options.each do |enforce|
    context 'on RedHat' do
      let(:params) do
        {
          'enforce' => enforce,
        }
      end
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
        }
      end

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
        else
          is_expected.not_to contain_file_line('yum_gpgcheck')
        end
      }
    end
  end
end
