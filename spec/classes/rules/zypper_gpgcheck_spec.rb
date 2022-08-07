# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::zypper_gpgcheck' do
  enforce_options.each do |enforce|
    on_supported_os.each do |os, _os_facts|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          {
            osfamily: 'Suse',
            operatingsystem: 'SLES',
            architecture: 'x86_64',
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
            is_expected.to contain_ini_setting('enable ggpcheck')
              .with(
                'ensure'  => 'present',
                'path'    => '/etc/zypp/zypp.conf',
                'section' => 'main',
                'setting' => 'gpgcheck',
                'value'   => '1',
              )
          else
            is_expected.not_to contain_ini_setting('enable ggpcheck')
          end
        }
      end
    end
  end
end
