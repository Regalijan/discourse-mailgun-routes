# frozen_string_literal: true

# name: discourse-mailgun-routes
# about: Accept inbound email using mailgun routes
# version: 0.2
# author: Regalijan
# url: https://github.com/Regalijan/discourse-mailgun-routes

after_initialize do
  require File.expand_path('../app/controllers/mailgun_routes_controller', __FILE__)

  Discourse::Application.routes.append do
    post '/mailgun/routes/receive_mime' => 'mailgun_routes#receive'
  end
end
