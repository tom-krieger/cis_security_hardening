# frozen_string_literal: true

# check a value and return a value depending on conditions
def check_value_integer(val, default = 0)
  if val.nil? || val.empty?
    default.to_i
  else
    val.to_i
  end
end
