require 'omniauth'
require 'net/http'

module OmniAuth
  module Strategies
    class HttpBasic
      include OmniAuth::Strategy

      args [:endpoint]

      option :title,          "Http Basic"
      option :username_label, "Username"
      option :password_label, "Password"


      option :headers, {}

      def request_phase
        OmniAuth::Form.build(
          :title => options.title,
          :url => callback_path,
          :username_label => options.username_label,
          :password_label => options.password_label
        ) do
          text_field options[:username_label], 'username'
          password_field options[:password_label], 'password'
        end.to_response
      end

      def callback_phase
        return fail!(:invalid_credentials) if !authentication_response
        return fail!(:invalid_credentials) if authentication_response.code.to_i >= 400
        super
      end

      protected

        # by default we use static uri. If dynamic uri is required, override
        # this method.
        def api_uri
          options.endpoint
        end

        def username
          request['username']
        end

        def password
          request['password']
        end

        def authentication_response
          unless @authentication_response
            return unless username && password

            uri = URI(api_uri)
            http = Net::HTTP.new(uri.host, uri.port)
            if uri.scheme == 'https'
              http.use_ssl = true
              http.verify_mode = OpenSSL::SSL::VERIFY_NONE
            end

            req = Net::HTTP::Get.new(uri.request_uri)
            req.basic_auth username, password
            @authentication_response = http.request(req)
          end

          @authentication_response
        end

    end
  end
end
