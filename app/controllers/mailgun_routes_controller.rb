# frozen_string_literal: true

require 'openssl'

class MailgunRoutesController < ApplicationController

  skip_before_action :redirect_to_login_if_required, :check_xhr, :verify_authenticity_token

  def receive
    if SiteSetting.mailgun_api_key.blank?
      return render json: { :error => 'Receiving disabled' }, status: 503
    end

    params.require([:timestamp, :token, :signature, 'body-mime'])

    if params[:signature] != OpenSSL::HMAC.hexdigest(
      OpenSSL::Digest::SHA256.new,
      SiteSetting.mailgun_api_key,
      [params[:timestamp], params[:token]].join
    )
      return render json: { :error => 'Signature invalid' }, status: 401
    end

    email_raw = params['body-mime']
    email_domain = params[:from].split("@")[1]
    retried = false
    should_log = SiteSetting.mailgun_log_rejections
    spam_detect_method = SiteSetting.mailgun_spam_detection
    blocked_domains = SiteSetting.mailgun_blocked_domains.split("|")
    neutral_should_pass = SiteSetting.mailgun_consider_neutral_passing
    email_rejection_template = "Email from #{params[:from]} rejected because"

    if blocked_domains.include?(email_domain)
      if should_log
        Rails.logger.info "#{email_rejection_template} domain is blocked"
      end
      return render json: { :error => "Sending domain #{email_domain} is blocked" }, status: 406
    end

    if spam_detect_method != "none"
      spam_flag_header = email_raw.match(/^X-Mailgun-Sflag: (No|Yes)/im)
      spam_score_header = email_raw.match(/^X-Mailgun-Sscore: (-?\d{1,2}\.?\d?)/im)

      if not spam_flag_header or not spam_score_header
        if should_log
          Rails.logger.info "#{email_rejection_template} spam headers (X-Mailgun-Sflag / X-Mailgun-Sscore) are missing"
        end
        return render json: { :error => 'Missing spam headers' }, status: 406
      end

      dkim_header = email_raw.match(/X-Mailgun-Dkim-Check-Result: (Fail|Pass)/im)
      dkim_exclusions = SiteSetting.dkim_domain_exclusions.split("|")

      if not dkim_header and
        not dkim_exclusions.include?(email_domain) or
        dkim_header.captures[0].downcase == "fail"
        if should_log
          Rails.logger.info "#{email_rejection_template} DKIM validation failed and domain is not excluded"
        end
        return render json: { :error => 'DKIM did not validate' }, status: 406
      end

      spf_header = email_raw.match(/^X-Mailgun-Spf: (\w+)/im)
      spf_exclusions = SiteSetting.spf_domain_exclusions.split("|")

      if not spf_header and
        not spf_exclusions.include?(email_domain) or
        spf_header.captures[0].downcase == "fail" or
        !neutral_should_pass and
        spf_header.captures[0].downcase != "pass"
        
        if should_log
          Rails.logger.info "#{email_rejection_template} SPF validation failed and domain is not excluded"
        end
        return render json: { :error => 'SPF did not validate' }, status: 406
      end

      if spam_detect_method == "flag" and
        spam_flag_header.captures[0].downcase == "yes" or
        spam_detect_method == "score" and
        spam_score_header.captures[0].to_f >= SiteSetting.mailgun_spam_score
        if should_log
          Rails.logger.info "#{email_rejection_template} #{spam_detect_method == "flag" ? "spam flag was yes": "spam score from Mailgun was #{spam_score_header.captures[0]}, which was equal to or higher than the configured score of #{SiteSetting.mailgun_spam_score.to_s}"}"
        end
        return render json: { :error => 'Spam detected' }, status: 406
      end
    end

    begin
      Jobs.enqueue(:process_email, mail: email_raw, retry_on_rate_limit: true, source: "handle_mail")
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
