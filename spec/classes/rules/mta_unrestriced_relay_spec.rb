# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::mta_unrestriced_relay' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_exec('restrict mail relay')
              .with(
                'command' => 'postconf -e \'smtpd_client_restrictions = permit_mynetworks,reject\'',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => 'test -z "$(postconf -n smtpd_client_restrictions | grep \'permit_mynetworks, reject\')"',
              )
          else
            is_expected.not_to contain_exec('restrict mail relay')
          end
        }
      end
    end
  end
end
