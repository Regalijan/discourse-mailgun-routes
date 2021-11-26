# frozen_string_literal: true

require 'openssl'

class MailgunRoutesController < ApplicationController

  skip_before_action :redirect_to_login_if_required, :check_xhr,:verify_authenticity_token

  def receive
    if SiteSetting.mailgun_api_key.blank?
      render json: { :error => 'Receiving disabled' }, status: 406
    end

    params.require([:timestamp, :token, :signature, 'body-mime'])

    if params[:signature] != OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, SiteSetting.mailgun_api_key, [params[:timestamp], params[:token]].join)
      render json: { :error => 'Signature invalid' }, status: 406
    end

    email_raw = params['body-mime']
    retried = false

    begin
      Jobs.enqueue(:process_email, mail: email_raw, retry_on_rate_limit: true, source: :handle_mail)
    rescue JSON::GeneratorError, Encoding::UndefinedConversionError => e
      if not retried
        email_raw = email_raw.force_encoding('iso-8859-1').encode("UTF-8")
        retried = true
        retry
      else
        raise e
      end
    end

    render json: { :success => true }
  end
end
