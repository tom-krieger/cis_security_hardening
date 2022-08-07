# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::motd_perms' do
  on_supported_os.each do |os, _os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) do
          {
            mountpoints: {
              '/dev/shm' => {
                'available' => '1.85 GiB',
              },
            },
            'cis_security_hardening' => {
              'motd' => {
                'content' => 'sdfsaddsa',
                'combined' => '0-0-420',
                'gid' => 0,
                'mode' => 420,
                'uid' => 0,
              },
              'issue' => {
                'os' => {
                  'content' => 'sadfg',
                  'combined' => '0-0-420',
                  'gid' => 0,
                  'mode' => 420,
                  'uid' => 0,
                },
                'net' => {
                  'content' => 'wqrt',
                  'combined' => '0-0-420',
                  'gid' => 0,
                  'mode' => 420,
                  'uid' => 0,
                },
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

          if enforce
            is_expected.to contain_file('/etc/motd')
              .with(
                'ensure' => 'present',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0644',
              )
          else
            is_expected.not_to contain_file('/etc/motd')
          end
        }
      end
    end
  end
end
