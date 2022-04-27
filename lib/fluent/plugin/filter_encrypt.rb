require 'fluent/filter'
require 'openssl'
require 'base64'

module Fluent
  class EncryptFilter < Filter
    Fluent::Plugin.register_filter('encrypt', self)

    SUPPORTED_ALGORITHMS = {
      aes_256_gcm: { name: "AES-256-CBC", use_iv: false },
    }

    config_param :algorithm, :enum, list: SUPPORTED_ALGORITHMS.keys, default: :aes_256_cbc
    config_param :encrypt_key_hex, :string
    config_param :encrypt_iv_hex, :string, default: nil

    config_param :decrypt, :string, default: nil

    config_param :key,  :string, default: nil
    config_param :keys, :array, default: []

    attr_reader :target_keys

    def configure(conf)
      super

      @target_keys = @keys + [@key]
      if @target_keys.empty?
        raise Fluent::ConfigError, "no keys specified to be encrypted"
      end

      algorithm = SUPPORTED_ALGORITHMS[@algorithm]
      if algorithm[:use_iv] && !@encrypt_iv_hex
        raise Fluent::ConfigError, "Encryption algorithm #{@algorithm} requires 'encrypt_iv_hex'"
      end

      @enc_key = Base64.decode64(@encrypt_key_hex)
      @enc_iv = if @encrypt_iv_hex
                  Base64.decode64(@encrypt_iv_hex)
                else
                  nil
                end
      @enc_generator = ->(){
        enc = OpenSSL::Cipher.new(algorithm[:name])
        enc.encrypt
        enc.key = @enc_key
        enc.iv  = @enc_iv
        enc
      }
      @dec_generator = ->(){
        enc = OpenSSL::Cipher.new(algorithm[:name])
        enc.decrypt
        enc.key = @enc_key
        enc.iv  = @enc_iv
        enc
      }
    end

    def filter_stream(tag, es)
      new_es = MultiEventStream.new
      es.each do |time, record|
        r = record.dup
        record.each_pair do |key, value|
          if @target_keys.include?(key)
            if @decrypt
              r[key] = decrypt(value)
            else
              r[key] = encrypt(value)
            end
          end
        end
        new_es.add(time, r)
      end
      new_es
    end

    def encrypt(value)
      encrypted = ""
      enc = @enc_generator.call()
      encrypted << enc.update(value)
      encrypted << enc.final
      Base64.encode64(encrypted)
    end

    def decrypt(value)
      decrypted = ""
      dec = @dec_generator.call()
      decrypted << dec.update(Base64.decode64(value))
      decrypted << dec.final
      decrypted
    end
  end
end
