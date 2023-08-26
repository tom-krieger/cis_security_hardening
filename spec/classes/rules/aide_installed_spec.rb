# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::aide_installed' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'aide_init_timeout' = 3600,
          }
        end

        it {
          is_expected.to compile

          if enforce
            if os_facts[:os]['name'].casecmp('ubuntu').zero? || os_facts[:os]['name'].casecmp('debian').zero?
              is_expected.to contain_package('aide')
                .that_notifies('Exec[aidedb-ubuntu-init]')

              is_expected.to contain_package('aide-common')
                .that_notifies('Exec[aidedb-ubuntu-init]')

              is_expected.to contain_exec('aidedb-ubuntu-init')
                .with(
                  command: 'aideinit',
                  path: ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
                  refreshonly: true,
                  logoutput: true,
                  timeout: 3600,
                )
                .that_notifies('Exec[rename_aidedb_ubuntu]')
                .that_requires(['Package[aide]', 'Package[aide-common]'])

              is_expected.to contain_exec('rename_aidedb_ubuntu')
                .with(
                  command: 'mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db',
                  creates: '/var/lib/aide/aide.db',
                  path: ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
                  logoutput: true,
                  refreshonly: true,
                )
                .that_requires(['Package[aide]', 'Package[aide-common]'])

            elsif os_facts[:os]['name'].casecmp('centos').zero? || os_facts[:os]['name'].casecmp('redhat').zero? ||
                  os_facts[:os]['name'].casecmp('almalinux').zero? || os_facts[:os]['name'].casecmp('rocky').zero?
              is_expected.to contain_package('aide')
                .that_notifies('Exec[aidedb]')

              is_expected.to contain_exec('aidedb')
                .with(
                  command: 'aide --init',
                  path: ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
                  refreshonly: true,
                )
                .that_notifies('Exec[rename_aidedb]')
                .that_requires('Package[aide]')

              is_expected.to contain_exec('rename_aidedb')
                .with(
                  command: 'mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz',
                  creates: '/var/lib/aide/aide.db.gz',
                  path: ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
                  logoutput: true,
                  refreshonly: true,
                )
                .that_requires('Package[aide]')
            elsif os_facts[:os]['name'].casecmp('sles').zero?
              is_expected.to contain_package('aide')
                .that_notifies('Exec[aidedb]')

              is_expected.to contain_exec('aidedb')
                .with(
                  command: 'aide --init',
                  path: ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
                  refreshonly: true,
                )
                .that_notifies('Exec[rename_aidedb]')
                .that_requires('Package[aide]')

              is_expected.to contain_exec('rename_aidedb')
                .with(
                  command: 'mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db',
                  creates: '/var/lib/aide/aide.db',
                  path: ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
                  logoutput: true,
                  refreshonly: true,
                )
                .that_requires('Package[aide]')
            end

          else
            is_expected.not_to contain_package('aide')
            is_expected.not_to contain_exec('aidedb')
            is_expected.not_to contain_exec('rename_aidedb')
          end
        }
      end
    end
  end
end
