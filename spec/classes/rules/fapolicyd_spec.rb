# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::fapolicyd' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'gid' => 'users',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_package('fapolicyd')
              .with(
                'ensure' => 'installed',
              )

            is_expected.to contain_file('/run/fapolicyd')
              .with(
                'ensure' => 'directory',
                'owner' => 'fapolicyd',
                'group' => 'users',
                'mode' => '0755',
              )
              .that_requires('Package[fapolicyd]')

            is_expected.to contain_file_line('fix fapolicyd gid')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/fapolicyd/fapolicyd.conf',
                'match'              => '^gid = fapolicyd',
                'line'               => 'gid = users',
                'append_on_no_match' => true,
              )
              .that_requires('Package[fapolicyd]')

            os_facts[:mountpoints].each do |mp, data|
              pp mp
              pp data['filesystem']
              next unless (['tmpfs', 'ext4', 'ext3', 'xfs'].include? data['filesystem']) && (mp !~ %r{^/run}) && (mp !~ %r{/sys})
              is_expected.to contain_concat__fragment("mount-#{mp}")
                .with(
                  'content' => "#{mp}\n",
                  'target'  => '/etc/fapolicyd/fapolicyd.mounts',
                )
            end
          else
            is_expected.not_to contain_package('fapolicyd')
            is_expected.not_to contain_file('/run/fapolicyd')
          end
        }
      end
    end
  end
end
