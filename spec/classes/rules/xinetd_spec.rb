# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::xinetd' do
  enforce_options.each do |enforce|
    context 'on RedHat' do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          operatingsystemmajrelease: '7',
          architecture: 'x86_64',
          os: {
            family: 'RedHat',
          }
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
        }
      end

      it {
        is_expected.to compile

        if enforce
          is_expected.to contain_package('xinetd')
            .with(
              'ensure' => 'purged',
            )
        else
          is_expected.not_to contain_package('xinetd')
        end
      }
    end
  end
end
