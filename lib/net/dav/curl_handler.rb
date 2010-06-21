module Net
  class DAV
    class CurlHandler < NetHttpHandler
      def verify_callback=(callback)
        super

        $stderr.puts "verify_callback not implemented in Curl::Easy"
      end

      def verify_server=(value)
        super
        curl = make_curl
        curl.ssl_verify_peer = value
        curl.ssl_verify_host = value
      end

      def make_curl(path = nil, headers = nil)
        unless @curl
          @curl = Curl::Easy.new
          @curl.timeout = @http.read_timeout
          @curl.follow_location = true
          @curl.max_redirects = MAX_REDIRECTS
          if disable_basic_auth
            @curl.http_auth_types = Curl::CURLAUTH_DIGEST
          end
        end

        if path
          @curl.url = @uri.merge(path).to_s
        end

        if headers
          headers.each_pair do |key, value|
            @curl.headers[key] = value
          end
        end

        if @user
          @curl.userpwd = "#{@user}:#{@pass}"
        else
          @curl.userpwd = nil
        end

        @curl
      end

      def check_response(curl)
        unless curl.response_code >= 200 && curl.response_code < 300
          header_block = curl.header_str.split(/\r?\n\r?\n/)[-1]
          msg = header_block.split(/\r?\n/)[0]
          msg.gsub!(/^HTTP\/\d+.\d+ /, '')
          
          raise Net::HTTPError.new(msg, nil)
        end
      end

      def request_sending_body(verb, path, body, headers)
        raise "unkown returning_body verb #{verb}" unless verb == :put

        curl = make_curl(path, headers)

        if block_given?
          curl.on_body do |frag|
            yield frag
            frag.length
          end
        end

        curl.http_put(body)

        check_response(curl)

        curl.body_str
      end

      def request_sending_stream(verb, path, stream, length, headers)
        raise "unkown returning_body verb #{verb}" unless verb == :put

        curl = make_curl(path, headers)

        if block_given?
          curl.on_body do |frag|
            yield frag
            frag.length
          end
        end

        curl.http_put(stream.read(length))

        check_response(curl)

        curl.body_str
      end

      def request_returning_body(verb, path, headers)
        raise "unkown returning_body verb #{verb}" unless verb == :get
        url = @uri.merge(path)
        curl = make_curl
        curl.url = url.to_s
        headers.each_pair { |key, value| curl.headers[key] = value } if headers
        if (@user)
          curl.userpwd = "#{@user}:#{@pass}"
        else
          curl.userpwd = nil
        end
        res = nil
        if block_given?
          curl.on_body do |frag|
            yield frag
            frag.length
          end
        end
        curl.perform
        unless curl.response_code >= 200 && curl.response_code < 300
          header_block = curl.header_str.split(/\r?\n\r?\n/)[-1]
          msg = header_block.split(/\r?\n/)[0]
          msg.gsub!(/^HTTP\/\d+.\d+ /, '')
          raise Net::HTTPError.new(msg, nil)
        end
        curl.body_str
      end

    end
  end
end