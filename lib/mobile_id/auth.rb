# frozen_string_literal: true

module MobileId
  class Auth
    # API documentation https://github.com/SK-EID/MID
    attr_accessor :hash, :state, :result, :user_cert, :doc

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

      options = {
        headers: {
          'Content-Type': 'application/json'
        },
        query: {},
        body: {
          relyingPartyUUID: @config.relying_party_uuid,
          relyingPartyName: @config.relying_party_name,
          phoneNumber: full_phone.to_s.strip,
          nationalIdentityNumber: personal_code.to_s.strip,
          hash: Base64.strict_encode64(@hash),
          hashType: 'SHA256',
          language: language,
          displayText: display_text,
          displayTextFormat: 'GSM-7' # or "UCS-2”
        }.to_json
      }

      response = HTTParty.post("#{@config.host_url}/authentication", options)
      raise Error, "#{I18n.t('mobile_id.some_error')} #{response}" unless response.code == 200

      ActiveSupport::HashWithIndifferentAccess.new(
        session_id: response['sessionID'],
        phone: phone,
        phone_calling_code: phone_calling_code,
        doc: @doc
      )
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
        result: result
      )
    end

    def session_request(session_id)
      response = HTTParty.get(@config.host_url + "/authentication/session/#{session_id}")
      raise Error, "#{I18n.t('mobile_id.some_error')} #{response.code} #{response}" if response.code != 200

      response
    end

    def long_poll!(session_id:, doc:)
      response = nil

      # Retries until RUNNING state turns to COMPLETE
      30.times do |_i|
        response = session_request(session_id)
        break if response['state'] == 'COMPLETE'

        sleep 1
      end
      raise Error, "#{I18n.t('mobile_id.some_error')} #{response.code} #{response}" if response['state'] != 'COMPLETE'

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

    def serial_number
      @user_cert.serial_number
    end
    alias personal_code serial_number
  end
end
