# frozen_string_literal: true

module PQCrypto
  module Internal
    module_function

    def binary_string(value)
      String(value).b
    end

    def frozen_binary_string(value)
      binary_string(value).freeze
    end

    def strict_boolean!(value, name:)
      return value if value.equal?(true) || value.equal?(false)

      raise ArgumentError, "#{name} must be true or false (got #{value.inspect})"
    end

    def safe_wipe(value)
      return unless value.is_a?(String) && !value.frozen?

      PQCrypto.secure_wipe(value)
    rescue ArgumentError
      nil
    end

    def constant_time_equal?(left, right)
      PQCrypto.__send__(:native_ct_equals, left, right)
    end
  end
end
