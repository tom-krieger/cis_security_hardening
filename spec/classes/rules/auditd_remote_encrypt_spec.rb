# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_remote_encrypt' do
  on_supported_os.each do |_os, os_facts|
    enforce_options.each do |enforce|
      context 'on RedHat' do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            file = if os_facts[:osfamily].casecmp('redhat').zero?
                     '/etc/audisp/audisp-remote.conf'
                   else
                     '/etc/audisp/plugins.d/au-remote.conf'
                   end
            is_expected.to contain_file_line('auditd remote encrypt')
              .with(
                'ensure'             => 'present',
                'path'               => file,
                'line'               => 'enable_krb5 = yes',
                'match'              => '^enable_krb5 =',
                'append_on_no_match' => true,
              )
          else
            is_expected.not_to contain_file_line('auditd remote encrypt')
          end
        }
      end
    end
  end
end
