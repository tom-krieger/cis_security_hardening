# frozen_string_literal: true

require 'spec_helper'

describe 'cis_security_hardening::hash_key' do
  # please note that these tests are examples only
  # you will need to replace the params and return value
  # with your expectations

  h = {
    'key1' => 'value1',
    'key2' => 'value2'
  }

  it { is_expected.to run.with_params(h, 'key1').and_return(true) }
  it { is_expected.to run.with_params(h, 'key3').and_return(false) }
  it { is_expected.to run.with_params(nil, nil).and_raise_error(StandardError) }
end
