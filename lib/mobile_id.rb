# frozen_string_literal: true

require 'securerandom'
require 'digest'
require 'httparty'
require 'active_support/core_ext/hash/indifferent_access'
require 'i18n'

require 'mobile_id/configuration'

if defined?(Rails)
  require 'mobile_id/railtie'
else
  I18n.load_path << Dir["#{File.expand_path('lib/mobile_id/locales')}/*.yml"]
end

module MobileId
  class Error < StandardError; end
  class MidSessionTimeoutError < Error; end
  class MidNotMidClientError < Error; end
  class MidUserCancellationError < Error; end
  class MidInvalidUserConfigurationError < Error; end
  class MidPhoneNotAvailableError < Error; end
  class MidDeliveryError < Error; end
  class MidSimError < Error; end
  class MidValidationError < Error; end

  LOCALES = %i[en et lt ru].freeze

  class << self
    attr_accessor :config
  end

  def self.configure
    self.config ||= Configuration.new
    yield(config)
  end
end

require 'mobile_id/cert'
require 'mobile_id/auth'
