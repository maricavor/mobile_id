# frozen_string_literal: true

Gem::Specification.new do |s|
  s.name        = 'mobile_id'
  s.version     = '0.0.16'
  s.summary     = 'Estonia and Lithuania Mobile ID authentication'
  s.description = 'Ruby client for Estonia and Lithuania Mobile ID authentication'
  s.authors     = ['Priit Tark', 'Sergei Tsõganov']
  s.email       = ['priit@domify.io', 'sergei.tsoganov@internet.ee']
  s.files       = Dir.glob('{lib}/**/*') + %w[MIT-LICENSE README.md CHANGELOG.md]
  s.homepage    = 'https://github.com/maricavor/mobile_id'
  s.license     = 'MIT'
  s.add_runtime_dependency 'activesupport'
  s.add_runtime_dependency 'rest-client'
  s.add_runtime_dependency 'i18n'
  s.add_runtime_dependency 'openssl', '>= 2.2.0'
  s.add_development_dependency 'pry'
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'rubocop'
  s.add_development_dependency 'rubocop-rspec'
  s.metadata = {
    'changelog_uri' => 'https://github.com/maricavor/mobile_id/blob/main/CHANGELOG.md',
    'rubygems_mfa_required' => 'true'
  }
end
