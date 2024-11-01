# frozen_string_literal: true

require 'spec_helper'

describe MobileId do
  before do
    @mid = MobileId::Auth.new
  end

  it 'inits hash' do
    @mid.hash.nil?.should == false
  end

  it 'has demo service url' do
    @mid.config.host_url.should == 'https://tsp.demo.sk.ee/mid-api'
  end

  it 'has demo service name' do
    @mid.config.relying_party_name.should == 'DEMO'
  end

  it 'has demo service uuid' do
    @mid.config.relying_party_uuid.should == '00000000-0000-0000-0000-000000000000'
  end

  it 'gets auth hash with session id' do
    auth = @mid.authenticate!(phone: '00000766', personal_code: '60001019906')
    auth[:session_id].nil?.should
    auth[:phone].should
    auth[:phone_calling_code].should == '+372'
  end

  it 'gets verified user attributes' do
    auth = @mid.authenticate!(phone: '00000766', personal_code: '60001019906')
    verify = @mid.verify!(auth)
    verify.should ==
      {
        'personal_code' => '60001019906',
        'first_name' => 'MARY ÄNN',
        'last_name' => 'O’CONNEŽ-ŠUSLIK TESTNUMBER',
        'phone' => '00000766',
        'phone_calling_code' => '+372',
        'auth_provider' => 'mobileid',
        'country' => 'EE',
        'result' => 'OK',
        'state' => 'COMPLETE',
        'expiration_time' => Time.new(2030, 12, 17, 23, 59, 59)
      }
  end

  it 'raises error with response code' do
    lambda {
      @mid.long_poll!(session_id: 'wrongid', doc: '')
    }.should raise_error(MobileId::Error, /There was some error: 400 Bad Request/)
  end

  it 'calculates verification code' do
    @mid = MobileId::Auth.new('test')
    @mid.verification_code.should == '5000'
  end
end
