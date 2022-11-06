# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::issue_net_perms' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce} with content undefined" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file('/etc/issue.net')
              .with(
                'ensure' => 'present',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0644',
              )
          else
            is_expected.not_to contain_file('/etc/issue.net')
          end
        }
      end

      context "on #{os} with enforce = #{enforce} with content defined" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'content' => 'test'
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file('/etc/issue.net')
              .with(
                'ensure'  => 'present',
                'content' => 'test',
                'owner'   => 'root',
                'group'   => 'root',
                'mode'    => '0644',
              )
          else
            is_expected.not_to contain_file('/etc/issue.net')
          end
        }
      end
    end
  end
end
