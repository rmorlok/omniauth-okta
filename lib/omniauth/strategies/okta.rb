# frozen_string_literal: true

require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Okta < OmniAuth::Strategies::OAuth2
      DEFAULT_SCOPE = %{openid profile email offline_access okta.users.read.self}.freeze

      option :name, 'okta'
      option :skip_jwt, false
      option :jwt_leeway, 60

      # These values can be set explicitly in the options, or can be overridden
      # by specifying either 'subdomain' or 'site' in the request parameters.
      option :client_options, {
        # subdomain:            'your-org',
        # site:                 'https://your-org.okta.com',
        # authorize_url:        'https://your-org.okta.com/oauth2/default/v1/authorize',
        # token_url:            'https://your-org.okta.com/oauth2/default/v1/token',
        # user_info_url:        'https://your-org.okta.com/oauth2/default/v1/userinfo',
        # authorization_server: 'default',
        response_type:        'id_token code',
        audience:             'api://default'
      }
      option :scope, DEFAULT_SCOPE

      uid { raw_info['sub'] }

      info do
        {
          name:       raw_info['name'],
          email:      raw_info['email'],
          first_name: raw_info['given_name'],
          last_name:  raw_info['family_name'],
          image:      raw_info['picture']
        }
      end

      extra do
        {
          site: site
        }.tap do |h|
          h[:raw_info] = raw_info unless skip_info?

          if access_token
            h[:id_token] = id_token

            if !options[:skip_jwt] && !id_token.nil?
              h[:id_info] = validated_token(id_token)
            end
          end
        end
      end

      def subdomain
        @subdomain ||= if default_client_options["subdomain"]
                         default_client_options["subdomain"]
                       elsif request.params["subdomain"] && !invalid_subdomain_param?
                         request.params["subdomain"]
                       end
      end

      def invalid_subdomain_param?
        request.params["subdomain"] && (request.params["subdomain"].include?("?") || request.params["subdomain"].include?("."))
      end

      def authorization_server
        @authorization_server ||= if default_client_options["authorization_server"]
                         default_client_options["authorization_server"]
                       elsif request.params["authorization_server"] && !invalid_authorization_server_param?
                         request.params["authorization_server"]
                       else
                         "default"
                       end
      end

      def authorization_server_url_fragment
        if authorization_server != "default"
          "/#{authorization_server}"
        else
          ""
        end
      end

      def invalid_authorization_server_param?
        request.params["authorization_server"] && (request.params["authorization_server"].include?("?") || request.params["authorization_server"].include?("."))
      end

      # Specifies the audience for the authorization server
      #
      # By default, this is +'default'+. If using a custom authorization
      # server, this will need to be set
      #
      # @return [String]
      def audience
        @audience ||= if default_client_options["audience"]
                        default_client_options["audience"]
                      elsif request.params["audience"] && !invalid_audience_param?
                        request.params["audience"]
                      else
                        "default"
                      end
      end

      def invalid_audience_param?
        request.params["audience"] && (request.params["audience"].include?("?") || request.params["audience"].include?("."))
      end

      def site
        @site ||= if default_client_options["site"]
                    default_client_options["site"]
                  elsif session["site"]
                    # This would be if this a return from auth and the site was set
                    # explicitly (via subdomain) on the initial request
                    session["site"]
                  elsif subdomain
                    # Set the site in session to be used on the flip side to this auth
                    session["site"] = "https://#{subdomain}.okta.com"
                  else
                    raise "Invalid Okta configuration. Could not compute Okta site URL"
                  end
      end

      def token_url
        @user_info_url = if default_client_options["token_url"]
                           default_client_options["token_url"]
                         else
                           "#{site}/oauth2#{authorization_server_url_fragment}/v1/token"
                         end
      end

      # Returns the qualified URL for the authorization server
      #
      # This is necessary in the case where there is a custom authorization server.
      #
      # Okta provides a default, by default.
      #
      # @return [String]
      def authorize_url
        @user_info_url = if default_client_options["authorize_url"]
                           default_client_options["authorize_url"]
                         else
                           "#{site}/oauth2#{authorization_server_url_fragment}/v1/authorize"
                         end
      end

      def user_info_url
        @user_info_url = if default_client_options["user_info_url"]
                           default_client_options["user_info_url"]
                         else
                           "#{site}/oauth2#{authorization_server_url_fragment}/v1/userinfo"
                         end
      end

      def callback_phase
        # Ensure site (base URL) is memoized
        site
        session.delete "site"
        super
      end

      def default_client_options
        options.fetch(:client_options)
      end

      def client_options
        default_client_options.merge(
          {
            site: site,
            authorize_url: authorize_url,
            token_url: token_url,
            user_info_url: user_info_url,
            authorization_server: authorization_server,
          }
        )
      end

      def client
        ::OAuth2::Client.new(options.client_id, options.client_secret, deep_symbolize(client_options))
      end

      alias :oauth2_access_token :access_token

      def access_token
        if oauth2_access_token
          ::OAuth2::AccessToken.new(client, oauth2_access_token.token, {
            refresh_token: oauth2_access_token.refresh_token,
            expires_in:    oauth2_access_token.expires_in,
            expires_at:    oauth2_access_token.expires_at
          })
        end
      end

      def raw_info
        @_raw_info ||= access_token.get(user_info_url).parsed || {}
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end

      def callback_url
        options[:redirect_uri] || (full_host + callback_path)
      end

      def id_token
        return if access_token.nil?

        access_token['id_token']
      end

      # Returns the qualified URL for the authorization server
      #
      # This is necessary in the case where there is a custom authorization server.
      #
      # Okta provides a default, by default.
      #
      # @return [String]
      def authorization_server_path
        authorization_server
      end

      # Specifies the audience for the authorization server
      #
      # By default, this is +'default'+. If using a custom authorization
      # server, this will need to be set
      #
      # @return [String]
      def authorization_server_audience
        audience
      end

      def validated_token(token)
        JWT.decode(token,
                   nil,
                   false,
                   verify_iss:        true,
                   verify_aud:        true,
                   iss:               authorization_server,
                   aud:               audience,
                   verify_sub:        true,
                   verify_expiration: true,
                   verify_not_before: true,
                   verify_iat:        true,
                   verify_jti:        false,
                   leeway:            options[:jwt_leeway]
        ).first
      end
    end
  end
end
