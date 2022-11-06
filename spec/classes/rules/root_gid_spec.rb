# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::root_gid' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce} and root password" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'accounts' => {
                'root_gid' => 1,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'encrypted_root_password' => '$6$g456vnhfgh',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_user('root')
              .with(
                'ensure' => 'present',
                'gid'    => '0',
                'password' => '$6$g456vnhfgh',
              )
          else
            is_expected.not_to contain_user('root')
          end
        end
      end

      context "on #{os} with enforce = #{enforce} and no root password" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'accounts' => {
                'root_gid' => 1,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_user('root')
              .with(
                'ensure' => 'present',
                'gid'    => '0',
              )
          else
            is_expected.not_to contain_user('root')
          end
        end
      end
    end
  end
end
