module Net
  class DAV
    class NetHttpHandler
      attr_writer :user, :pass

      attr_accessor :disable_basic_auth

      def verify_callback=(callback)
        @http.verify_callback = callback
      end

      def verify_server=(value)
        @http.verify_mode = value ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
      end

      def initialize(uri)
        @disable_basic_auth = false
        @uri = uri
        case @uri.scheme
        when "http"
          @http = Net::HTTP.new(@uri.host, @uri.port)
        when "https"
          @http = Net::HTTP.new(@uri.host, @uri.port)
          @http.use_ssl = true
          self.verify_server = true
        else
          raise "unknown uri scheme"
        end
      end

      def start(&block)
        @http.start(&block)
      end

      def read_timeout
        @http.read_timeout
      end

      def read_timeout=(sec)
        @http.read_timeout = sec
      end

      def open_timeout
        @http.read_timeout
      end

      def open_timeout=(sec)
        @http.read_timeout = sec
      end

      def request_sending_stream(verb, path, stream, length, headers)
        req =
          case verb
          when :put
            Net::HTTP::Put.new(path)
          else
            raise "unkown sending_stream verb #{verb}"
          end
        req.body_stream = stream
        req.content_length = length
        headers.each_pair { |key, value| req[key] = value } if headers
        req.content_type = 'text/xml; charset="utf-8"'
        res = handle_request(req, headers)
        res.body
      end

      def request_sending_body(verb, path, body, headers)
        req =
          case verb
          when :put
            Net::HTTP::Put.new(path)
          else
            raise "unkown sending_body verb #{verb}"
          end
        req.body = body
        headers.each_pair { |key, value| req[key] = value } if headers
        req.content_type = 'text/xml; charset="utf-8"'
        res = handle_request(req, headers)
        res.body
      end

      def request_returning_body(verb, path, headers, &block)
        req =
          case verb
          when :get
            Net::HTTP::Get.new(path)
          else
            raise "unkown returning_body verb #{verb}"
          end
        headers.each_pair { |key, value| req[key] = value } if headers
        res = handle_request(req, headers, MAX_REDIRECTS, &block)
        res.body
      end

      def request(verb, path, body, headers)
        req =
          case verb
          when :propfind
            Net::HTTP::Propfind.new(path)
          when :mkcol
            Net::HTTP::Mkcol.new(path)
          when :delete
            Net::HTTP::Delete.new(path)
          when :move
            Net::HTTP::Move.new(path)
          when :copy
            Net::HTTP::Copy.new(path)
          when :proppatch
            Net::HTTP::Proppatch.new(path)
          else
            raise "unkown verb #{verb}"
          end
        req.body = body
        headers.each_pair { |key, value| req[key] = value } if headers
        req.content_type = 'text/xml; charset="utf-8"'
        res = handle_request(req, headers)
        res
      end

      def handle_request(req, headers, limit = MAX_REDIRECTS, &block)
        # You should choose better exception.
        raise ArgumentError, 'HTTP redirect too deep' if limit == 0

        response = nil
        if block
          @http.request(req) {|res|
            # Only start returning a body if we will not retry
            res.read_body nil, &block if !res.is_a?(Net::HTTPUnauthorized) && !res.is_a?(Net::HTTPRedirection)
            response = res
          }
        else
          response = @http.request(req)
        end
        case response
        when Net::HTTPSuccess     then
          return response
        when Net::HTTPUnauthorized     then
          response.error! unless @user
          response.error! if req['authorization']
          new_req = clone_req(req.path, req, headers)
          if response['www-authenticate'] =~ /^Basic/
            if disable_basic_auth
              raise "server requested basic auth, but that is disabled"
            end
            new_req.basic_auth @user, @pass
          else
            digest_auth(new_req, @user, @pass, response)
          end
          return handle_request(new_req, headers, limit - 1, &block)
        when Net::HTTPRedirection then
          location = URI.parse(response['location'])
          if (@uri.scheme != location.scheme ||
              @uri.host != location.host ||
              @uri.port != location.port)
            raise ArgumentError, "cannot redirect to a different host #{@uri} => #{location}"
          end
          new_req = clone_req(location.path, req, headers)
          return handle_request(new_req, headers, limit - 1, &block)
        else
          response.error!
        end
      end

      def clone_req(path, req, headers)
        new_req = req.class.new(path)
        new_req.body = req.body if req.body
        new_req.body_stream = req.body_stream if req.body_stream
        headers.each_pair { |key, value| new_req[key] = value } if headers
        return new_req
      end

      CNONCE = Digest::MD5.hexdigest("%x" % (Time.now.to_i + rand(65535))).slice(0, 8)

      def digest_auth(request, user, password, response)
        # based on http://segment7.net/projects/ruby/snippets/digest_auth.rb
        @nonce_count = 0 if @nonce_count.nil?
        @nonce_count += 1

        raise "bad www-authenticate header" unless (response['www-authenticate'] =~ /^(\w+) (.*)/)

        params = {}
        $2.gsub(/(\w+)="(.*?)"/) { params[$1] = $2 }

        a_1 = "#{user}:#{params['realm']}:#{password}"
        a_2 = "#{request.method}:#{request.path}"
        request_digest = ''
        request_digest << Digest::MD5.hexdigest(a_1)
        request_digest << ':' << params['nonce']
        request_digest << ':' << ('%08x' % @nonce_count)
        request_digest << ':' << CNONCE
        request_digest << ':' << params['qop']
        request_digest << ':' << Digest::MD5.hexdigest(a_2)

        header = []
        header << "Digest username=\"#{user}\""
        header << "realm=\"#{params['realm']}\""
        header << "nonce=\"#{params['nonce']}\""
        header << "uri=\"#{request.path}\""
        header << "cnonce=\"#{CNONCE}\""
        header << "nc=#{'%08x' % @nonce_count}"
        header << "qop=#{params['qop']}"
        header << "response=\"#{Digest::MD5.hexdigest(request_digest)}\""
        header << "algorithm=\"MD5\""

        header = header.join(', ')
        request['Authorization'] = header
      end
    end
  end
end