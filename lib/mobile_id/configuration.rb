module MobileId
  class Configuration
    attr_accessor :relying_party_uuid, :relying_party_name, :host_url,
                  :truststore_path, :truststore_password, :logger, :tls_config

    def initialize
      @relying_party_uuid = '00000000-0000-0000-0000-000000000000'
      @relying_party_name = 'DEMO'
      @host_url = 'https://tsp.demo.sk.ee/mid-api'
      @truststore_path = nil
      @truststore_password = 'changeit'
      @logger = defined?(Rails) ? Rails.logger : Logger.new(STDOUT)
      @tls_config = nil
    end
  end
end
