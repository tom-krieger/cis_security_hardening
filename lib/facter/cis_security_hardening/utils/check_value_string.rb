# frozen_string_literal: true

# check a value and return a value depending on conditions

def check_value_string(val, default)
  if val.nil? || val.empty?
    default
  else
    val
  end
end
