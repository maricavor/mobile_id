# frozen_string_literal: true

module MobileId
  class Cert
    attr_accessor :cert, :subject, :truststore

    def initialize(base64_cert)
      @cert = OpenSSL::X509::Certificate.new(Base64.decode64(base64_cert))
      verify!
      build_cert_subject
    end

    def verify!
      verify_certificate_trusted
      raise MidValidationError, 'User certificate is not valid [check_key]' unless @cert.public_key.check_key
      raise MidValidationError, 'User certificate is expired' unless (@cert.not_before...@cert.not_after).include?(Time.now)

      true
    end

    def verify_signature!(signature_base64, doc)
      signature = Base64.decode64(signature_base64)
      digest = OpenSSL::Digest::SHA256.new(doc)

      valid =
        begin
          cert.public_key.verify(digest, signature, doc)
        rescue OpenSSL::PKey::PKeyError
          der_signature = cvc_to_der(signature) # Probably signature is CVC encoded
          cert.public_key.verify(digest, der_signature, doc)
        end

      raise MidValidationError, 'We could not verify user signature' unless valid
    end

    def cvc_to_der(cvc)
      sign_hex = cvc.unpack1('H*')
      half = sign_hex.size / 2
      i = [OpenSSL::ASN1::Integer.new(sign_hex[0...half].to_i(16)),
           OpenSSL::ASN1::Integer.new(sign_hex[half..sign_hex.size].to_i(16))]
      seq = OpenSSL::ASN1::Sequence.new(i)
      seq.to_der
    end

    def given_name
      subject['GN'].tr(',', ' ')
    end
    alias first_name given_name

    def surname
      subject['SN'].tr(',', ' ')
    end
    alias last_name surname

    def country
      subject['C'].tr(',', ' ')
    end

    def common_name
      subject['CN']
    end

    def organizational_unit
      subject['OU']
    end

    def serial_number
      subject['serialNumber']
    end
    alias personal_code serial_number

    private

    def verify_certificate_trusted
      context = OpenSSL::X509::StoreContext.new(truststore, @cert)
      return if context.verify

      raise MidValidationError, "User certificate #{@cert.subject} is not trusted -> #{context.error_string}"
    end

    def truststore
      @truststore ||= build_store(
        load_pkcs12_certificates
      )
    end

    def build_cert_subject
      @subject = @cert.subject.to_utf8.split(/(?<!\\),+/).each_with_object({}) do |c, result|
        next unless c.include?('=')

        key, val = c.split('=')
        result[key] = val
      end
    end

    def load_pkcs12_certificates
      return test_store_certificates unless MobileId.config.truststore_path

      extract_trusted_certificates(pkcs12_truststore)
    end

    def extract_trusted_certificates(p12)
      p12.ca_certs.each_with_object([]) do |cert, trusted_certificates|
        common_name = cert.subject.to_a.find { |name, _, _| name == 'CN' }&.last
        next unless common_name

        trusted_certificates << OpenSSL::X509::Certificate.new(cert)
      end
    end

    def pkcs12_truststore
      OpenSSL::PKCS12.new(File.binread(MobileId.config.truststore_path), MobileId.config.truststore_password)
    rescue OpenSSL::PKCS12::PKCS12Error => e
      raise MidValidationError, "File at #{path} is not a valid PKCS12 file: #{e.message}"
    end

    def test_store_certificates
      [
        File.join(root_path, 'TEST_of_EE_Certification_Centre_Root_CA.pem.crt'),
        File.join(root_path, 'TEST_of_ESTEID-SK_2015.pem.crt')
      ]
    end

    def root_path
      @root_path ||= File.expand_path('certs', __dir__)
    end

    def build_store(certificates)
      OpenSSL::X509::Store.new.tap do |store|
        certificates.each do |cert|
          store.add_cert(cert)
        end
      end
    rescue OpenSSL::X509::StoreError => e
      raise MidValidationError, "Error building certificate store: #{e.message}"
    end
  end
end
