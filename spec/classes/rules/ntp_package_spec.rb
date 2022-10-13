# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::ntp_package' do
  enforce_options.each do |enforce|
    context 'on RedHat' do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          operatingsystemmajrelease: '7',
          architecture: 'x86_64',
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'pkg' => 'chrony',
        }
      end

      it {
        is_expected.to compile

        if enforce
          is_expected.to contain_package('chrony')
            .with(
              'ensure' => 'installed',
            )
        else
          is_expected.not_to contain_package('chrony')
        end
      }
    end
  end
end
