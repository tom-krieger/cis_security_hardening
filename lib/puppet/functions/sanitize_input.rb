# frozen_string_literal: true

require 'shellwords'

# sanitize_input.rb
# Uses Shellwords.escape to sabitize cmd.
Puppet::Functions.create_function(:sanitize_input) do
  dispatch :sanitize do
    param 'String', :cmd
    return_type 'String'
  end

  def sanitize(cmd)
    Shellwords.escape(cmd)
  end
end
