# frozen_string_literal: true

module PQCrypto
  module Internal
    module_function

    def binary_string(value)
      String(value).b
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
