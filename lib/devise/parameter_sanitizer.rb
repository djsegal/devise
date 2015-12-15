module Devise
  # The +ParameterSanitizer+ deals with permitting specific parameters values
  # for each +Devise+ scope in the application.
  #
  # The sanitizer knows about Devise default parameters (like +password+ and
  # +password_confirmation+ for the `RegistrationsController`), and you can
  # extend or change the permitted parameters list on your controllers.
  #
  # === Permitting new parameters
  #
  # You can add new parameters to the permitted list using the +for+ method in
  # a +before_action+ method, for instance.
  #
  #    class ApplicationController < ActionController::Base
  #      before_action :configure_permitted_parameters, if: :devise_controller?
  #
  #      protected
  #
  #      def configure_permitted_parameters
  #        # Permit the `subscribe_newsletter` parameter along with the other
  #        # sign up parameters.
  #        devise_parameter_sanitizer.for(:sign_up) << :subscribe_newsletter
  #      end
  #    end
  #
  # Using a block yields an +ActionController::Parameters+ object so you can
  # permit nested parameters and have more control over how the parameters are
  # permitted in your controller.
  #
  #    def configure_permitted_parameters
  #      devise_parameter_sanitizer.for(:sign_up) do |user|
  #        user.permit(newsletter_preferences: [])
  #      end
  #    end
  class ParameterSanitizer
    DEFAULT_PERMITTED_ATTRIBUTES = {
      sign_in: [:password, :remember_me],
      sign_up: [:password, :password_confirmation],
      account_update: [:password, :password_confirmation, :current_password]
    }

    def initialize(resource_class, resource_name, params)
      @auth_keys      = extract_auth_keys(resource_class)
      @params         = params
      @resource_name  = resource_name
      @permitted      = {}

      DEFAULT_PERMITTED_ATTRIBUTES.each_pair do |operation, keys|
        permit(operation, keys: keys)
      end
    end

    # Sanitize the parameters for a specific +operation+.
    #
    # === Arguments
    #
    # * +operation+ - A +Symbol+ with the operation that the controller is
    #   performing, like +sign_up+, +sign_in+, etc.
    #
    # === Examples
    #
    #    # Inside the `RegistrationsController#create` action.
    #    resource = build_resource(devise_parameter_sanitizer.sanitize(:sign_up))
    #    resource.save
    #
    # Returns an +ActiveSupport::HashWithIndifferentAccess+ with the permitted
    # attributes.
    def sanitize(operation)
      permissions = @permitted[operation]

      if respond_to?(operation, true)
        deprecate_instance_method_sanitization(operation)
        return send(operation)
      end

      if permissions.respond_to?(:call)
        cast_to_hash permissions.call(default_params)
      elsif permissions.present?
        cast_to_hash permit_keys(default_params, permissions)
      else
        unknown_operation!(operation)
      end
    end

    def permit(operation, keys: nil, except: nil, &block)
      if block_given?
        @permitted[operation] = block
      end

      if keys.present?
        @permitted[operation] ||= @auth_keys.dup
        @permitted[operation].concat(keys)
      end

      if except.present?
        @permitted[operation] ||= @auth_keys.dup
        @permitted[operation] = @permitted[operation] - except
      end
    end

    def for(operation, &block)
      if block_given?
        deprecate_for_with_block(operation)
        permit(operation, &block)
      else
        deprecate_for_without_block(operation)
        @permitted[operation] or unknown_operation!(operation)
      end
    end

    private

    # Cast a sanitized +ActionController::Parameters+ to a +HashWithIndifferentAccess+
    # that can be used elsewhere.
    #
    # Returns an +ActiveSupport::HashWithIndifferentAccess+.
    def cast_to_hash(params)
      if params
        params.to_hash.with_indifferent_access
      end
    end

    def default_params
      @params.fetch(@resource_name, {})
    end

    def permit_keys(parameters, keys)
      parameters.permit(*keys)
    end

    def extract_auth_keys(klass)
      auth_keys = klass.authentication_keys

      auth_keys.respond_to?(:keys) ? auth_keys.keys : auth_keys
    end

    def unknown_operation!(operation)
      raise NotImplementedError, "Devise doesn't know how to sanitize parameters for #{operation}"
    end

    def deprecate_for_with_block(operation)
      ActiveSupport::Deprecation.warn(<<-MESSAGE.strip_heredoc)
        [Devise] Changing the sanitized parameters through "#{self.class.name}#for(#{operation}) is deprecated and it will be removed from Devise 4.1.
        Please use the `permit` method:

          devise_parameter_sanitizer.permit(:#{operation}) do |user|
            # Your block here.
          end
      MESSAGE
    end

    def deprecate_for_without_block(operation)
      ActiveSupport::Deprecation.warn(<<-MESSAGE.strip_heredoc)
        [Devise] Changing the sanitized parameters through "#{self.class.name}#for(#{operation}) is deprecated and it will be removed from Devise 4.1.
        Please use the `permit` method to add or remove any key:

          To add any new key, use the `keys` keyword argument:
          devise_parameter_sanitizer.permit(:#{operation}, keys: [:key1, key2, key3])

          To remove any existing key, use the `except` keyword argument:
          devise_parameter_sanitizer.permit(:#{operation}, except: [:email])
      MESSAGE
    end

    def deprecate_instance_method_sanitization(operation)
      ActiveSupport::Deprecation.warn(<<-MESSAGE.strip_heredoc)
        [Devise] Parameter sanitization through a "#{self.class.name}##{operation}" method is deprecated and it will be removed from Devise 4.1.
        Please use the `permit` method on your sanitizer `initialize` method.

          class #{self.class.name} < Devise::ParameterSanitizer
            def initialize(*)
              super
              permit(:#{operation}, keys: [:key1, :key2, :key3])
            end
          end
      MESSAGE
    end
  end
end
