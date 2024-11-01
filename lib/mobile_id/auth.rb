# frozen_string_literal: true

module MobileId
  class Auth
    # API documentation https://github.com/SK-EID/MID
    attr_accessor :config, :hash, :state, :result, :user_cert, :doc

    GSM_7_CHARACTERS = "@£$¥èéùìòÇØøÅåΔ_ΦΓΛΩΠΨΣΘΞ^{}[~]|€ÆæßÉ!\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà \r\n\\"

    def initialize(doc = SecureRandom.hex(40))
      @config = MobileId.config
      @doc = doc
      @hash = Digest::SHA256.digest(doc)
    end

    def authenticate!(phone:, personal_code:, phone_calling_code: nil, language: nil, display_text: nil)
      phone_calling_code ||= '+372'
      full_phone = "#{phone_calling_code}#{phone}"
      language ||=
        case I18n.locale
        when :et
          display_text ||= 'Autentimine'
          'EST'
        when :ru
          display_text ||= 'Аутентификация'
          'RUS'
        else
          display_text ||= 'Authentication'
          'ENG'
        end

      payload = {
        relyingPartyUUID: @config.relying_party_uuid,
        relyingPartyName: @config.relying_party_name,
        phoneNumber: full_phone.to_s.strip,
        nationalIdentityNumber: personal_code.to_s.strip,
        hash: Base64.strict_encode64(@hash),
        hashType: 'SHA256',
        language: language,
        displayText: display_text,
        displayTextFormat: contains_non_gsm7_characters?(display_text) ? 'UCS-2' : 'GSM-7'
      }

      response = RestClient::Request.execute(post_request_attrs("#{@config.host_url}/authentication", payload))

      raise Error, "#{I18n.t('mobile_id.some_error')}: #{response.response.class} #{response.code}" unless response.code == 200

      parsed_response = JSON.parse(response.body)

      ActiveSupport::HashWithIndifferentAccess.new(
        session_id: parsed_response['sessionID'],
        phone: phone,
        phone_calling_code: phone_calling_code,
        doc: @doc
      )
    rescue RestClient::RequestFailed, RestClient::SSLCertificateNotVerified => e
      raise Error, "#{I18n.t('mobile_id.some_error')}: #{e}"
    end

    def verify!(auth)
      long_poll!(session_id: auth['session_id'], doc: auth['doc'])

      ActiveSupport::HashWithIndifferentAccess.new(
        personal_code: personal_code,
        first_name: first_name,
        last_name: last_name,
        phone: auth['phone'],
        phone_calling_code: auth['phone_calling_code'],
        country: country,
        auth_provider: 'mobileid', # User::MOBILEID
        state: state,
        result: result,
        expiration_time: expiration_time
      )
    end

    def session_request(session_id)
      response = RestClient::Request.execute(get_request_attrs(@config.host_url + "/authentication/session/#{session_id}"))
      JSON.parse(response.body)
    rescue RestClient::RequestFailed => e
      raise Error, "#{I18n.t('mobile_id.some_error')}: #{e}"
    end

    def long_poll!(session_id:, doc:)
      response = nil

      # Retries until RUNNING state turns to COMPLETE
      30.times do |_i|
        response = session_request(session_id)
        break if response['state'] == 'COMPLETE'

        sleep 1
      end
      raise Error, "#{I18n.t('mobile_id.some_error')}: #{response.response.class} #{response.code}" if response['state'] != 'COMPLETE'

      if response['result'] != 'OK'
        message =
          case response['result']
          when 'TIMEOUT'
            raise MidSessionTimeoutError, I18n.t('mobile_id.timeout')
          when 'NOT_MID_CLIENT'
            raise MidNotMidClientError, I18n.t('mobile_id.user_is_not_mobile_id_client')
          when 'USER_CANCELLED'
            raise MidUserCancellationError, I18n.t('mobile_id.user_cancelled')
          when 'SIGNATURE_HASH_MISMATCH'
            raise MidInvalidUserConfigurationError, I18n.t('mobile_id.signature_hash_mismatch')
          when 'PHONE_ABSENT'
            raise MidPhoneNotAvailableError, I18n.t('mobile_id.phone_absent')
          when 'DELIVERY_ERROR'
            raise MidDeliveryError, I18n.t('mobile_id.delivery_error')
          when 'SIM_ERROR'
            raise MidSimError, I18n.t('mobile_id.sim_error')
          end
      end

      @user_cert = MobileId::Cert.new(response['cert'])
      @user_cert.verify_signature!(response['signature']['value'], @doc)
      @result = response['result']
      @state = response['state']
    end

    def verification_code
      binary = @hash.to_s.unpack1('B*')
      '%04d' % (binary[0...6] + binary[-7..]).to_i(2)
    end

    def given_name
      @user_cert.given_name
    end
    alias first_name given_name

    def surname
      @user_cert.surname
    end
    alias last_name surname

    def country
      @user_cert.country
    end

    def common_name
      @user_cert.common_name
    end

    def organizational_unit
      @user_cert.organizational_unit
    end

    def not_after
      @user_cert.cert.not_after
    end
    alias expiration_time not_after

    def serial_number
      @user_cert.serial_number
    end
    alias personal_code serial_number

    private

    def contains_non_gsm7_characters?(service_name)
      service_name.chars.any? { |char| !GSM_7_CHARACTERS.include?(char) }
    end

    def default_attrs
      attrs = {
        headers: { content_type: :json, accept: :json },
        timeout: 10
      }
      attrs.merge!(ssl_config) if @config.tls_config

      attrs
    end

    def get_request_attrs(url)
      default_attrs.merge(method: :get, url: url)
    end

    def post_request_attrs(url, params)
      default_attrs.merge(method: :post, url: url, payload: JSON.generate(params))
    end

    def ssl_config
      config = {
        ssl_version: @config.tls_config[:default_protocol],
        verify_ssl: OpenSSL::SSL::VERIFY_PEER,
        ssl_ciphers: @config.tls_config[:enabled_cipher_suites]
      }
      config.merge!(ssl_ca_file: @config.tls_config[:ca_file]) if @config.tls_config[:ca_file]

      config
    end
  end
end
