# frozen_string_literal: true

# check puppet agentpostrun command
def check_puppet_postrun_command
  val = Facter::Core::Execution.exec('puppet config print | grep postrun_command')
  check_value_string(val, 'none')
end
