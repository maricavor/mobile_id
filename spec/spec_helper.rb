# frozen_string_literal: true

require 'bundler/setup'
Bundler.setup

require 'pry'
require 'mobile_id'
require 'i18n'

I18n.config.available_locales = :en
I18n.load_path << Dir["#{File.expand_path('lib/mobile_id/locales')}/*.yml"]

RSpec.configure do |config|
  # Set MOBILE ID demo parameters
  config.before do
    MobileId.configure do |conf|
      conf.relying_party_uuid = '00000000-0000-0000-0000-000000000000'
      conf.relying_party_name = 'DEMO'
    end
  end
  config.expect_with(:rspec) { |c| c.syntax = :should }
end
