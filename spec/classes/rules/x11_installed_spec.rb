# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::x11_installed' do
  enforce_options.each do |enforce|
    context 'on RedHat' do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          operatingsystemmajrelease: '7',
          architecture: 'x86_64',
          cis_security_hardening: {
            'x11' => {
              'installed' => true,
              'packages' => ['xorg-x11-server-utils-7.7-20.el7.x86_64', 'xorg-x11-font-utils-7.5-21.el7.x86_64'],
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
        }
      end

      it {
        is_expected.to compile

        # if enforce
        #  is_expected.to contain_package('xorg-x11-server-utils-7.7-20.el7.x86_64')
        #    .with(
        #      'ensure' => 'absent',
        #    )
        # else
        #  is_expected.not_to contain_package('xorg-x11-server-utils-7.7-20.el7.x86_64')
        # end
      }
    end
  end
end
