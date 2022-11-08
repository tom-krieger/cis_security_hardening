# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::motd_perms' do
  on_supported_os.each do |os, _os_facts|
    let(:facts) do
      {
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

    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce} no content" do
        let(:params) do
          {
            'enforce' => enforce,
            'content' => :undef,
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

      context "on #{os} with enforce = #{enforce} with content" do
        let(:params) do
          {
            'enforce' => enforce,
            'content' => 'testtest',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file('/etc/motd')
              .with(
                'ensure'  => 'present',
                'content' => 'testtest',
                'owner'   => 'root',
                'group'   => 'root',
                'mode'    => '0644',
              )
          else
            is_expected.not_to contain_file('/etc/motd')
          end
        }
      end
    end
  end
end
