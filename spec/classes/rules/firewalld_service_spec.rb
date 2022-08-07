# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::firewalld_service' do
  enforce_options.each do |enforce|
    context 'on redHat' do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
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
          is_expected.to contain_service('firewalld')
            .with(
              'ensure' => 'running',
              'enable' => true,
            )
        else
          is_expected.not_to contain_service('firewalld')
        end
      }
    end
  end
end
