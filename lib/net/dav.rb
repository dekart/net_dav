require 'net/https'
require 'uri'
require 'nokogiri'
require 'net/dav/item'
require 'net/dav/net_http_handler'
require 'net/dav/curl_handler'
require 'base64'
require 'digest/md5'
begin
  require 'curb'
rescue LoadError
end

module Net #:nodoc:
  # Implement a WebDAV client
  class DAV
    MAX_REDIRECTS = 10

    # Disable basic auth - to protect passwords from going in the clear
    # through a man-in-the-middle attack.
    def disable_basic_auth?
      @handler.disable_basic_auth
    end

    def disable_basic_auth=(value)
      @handler.disable_basic_auth = value
    end

    # Seconds to wait until reading one block (by one system call).
    # If the DAV object cannot read a block in this many seconds,
    # it raises a TimeoutError exception.
    #
    def read_timeout
      @handler.read_timeout
    end

    def read_timeout=(sec)
      @handler.read_timeout = sec
    end

    # Seconds to wait until connection is opened.
    # If the DAV object cannot open a connection in this many seconds,
    # it raises a TimeoutError exception.
    #
    def open_timeout
      @handler.read_timeout
    end

    def open_timeout=(sec)
      @handler.read_timeout = sec
    end

    # Creates a new Net::DAV object and opens the connection
    # to the host.  Yields the object to the block.
    #
    # Example:
    #
    #  res = Net::DAV.start(url) do |dav|
    #    dav.find(url.path) do |item|
    #      puts "#{item.uri} is size #{item.size}"
    #    end
    #  end
    def self.start(uri, options = nil, &block) # :yield: dav
      new(uri, options).start(&block)
    end

    # Creates a new Net::DAV object for the specified host
    # The path part of the URI is used to handle relative URLs
    # in subsequent requests.
    # You can pass :curl => false if you want to disable use
    # of the curb (libcurl) gem if present for acceleration
    def initialize(uri, options = nil)
      @have_curl = Curl rescue nil
      if options && options.has_key?(:curl) && !options[:curl]
        @have_curl = false
      end
      @uri = uri
      @uri = URI.parse(@uri) if @uri.is_a? String
      @handler = @have_curl ? CurlHandler.new(@uri) : NetHttpHandler.new(@uri)
    end

    # Opens the connection to the host.  Yields self to the block.
    #
    # Example:
    #
    #  res = Net::DAV.new(url).start do |dav|
    #    dav.find(url.path) do |item|
    #      puts item.inspect
    #    end
    #  end
    def start(&block) # :yield: dav
      @handler.start do
        return yield(self)
      end
    end

    # Set credentials for basic authentication
    def credentials(user, pass)
      @handler.user = user
      @handler.pass = pass
    end

    # Perform a PROPFIND request
    #
    # Example:
    #
    # Basic propfind:
    #
    #   properties = propfind('/path/')
    #
    # Get ACL for resource:
    #
    #  properties = propfind('/path/', :acl)
    #
    # Custom propfind:
    #
    #  properties = propfind('/path/', '<?xml version="1.0" encoding="utf-8"?>...')
    #
    # See http://webdav.org/specs/rfc3744.html#rfc.section.5.9 for more on
    # how to retrieve access control properties.
    def propfind(path,*options)
      headers = {'Depth' => '1'}
      if(options[0] == :acl)
        body = '<?xml version="1.0" encoding="utf-8" ?><D:propfind xmlns:D="DAV:"><D:prop><D:owner/>' +
                '<D:supported-privilege-set/><D:current-user-privilege-set/><D:acl/></D:prop></D:propfind>'
      else
        body = options[0]
      end
      if(!body)
        body = '<?xml version="1.0" encoding="utf-8"?><DAV:propfind xmlns:DAV="DAV:"><DAV:allprop/></DAV:propfind>'
      end
      res = @handler.request(:propfind, path, body, headers)
      Nokogiri::XML.parse(res.body)
    end

    # Find files and directories, yields Net::DAV::Item
    #
    # The :filename option can be a regexp or string, and is used
    # to filter the yielded items.
    #
    # If :suppress_errors is passed, exceptions that occurs when
    # reading directory information is ignored, and a warning is
    # printed out stderr instead.
    #
    # The default is to not traverse recursively, unless the :recursive
    # options is passed.
    #
    # Examples:
    #
    #  res = Net::DAV.start(url) do |dav|
    #    dav.find(url.path, :recursive => true) do |item|
    #      puts "#{item.type} #{item.uri}"
    #      puts item.content
    #    end
    #  end
    #
    #  dav = Net::DAV.new(url)
    #  dav.find(url.path, :filename => /\.html/, :suppress_errors => true)
    #    puts item.url.to_s
    #  end
    def find(path, options = {})
      path = @uri.merge(path).path
      namespaces = {'x' => "DAV:"}
      begin
        doc = propfind(path)
      rescue Net::ProtocolError => e
        msg = e.to_s + ": " + path.to_s
        if(options[:suppress_errors])then
          # Ignore dir if propfind returns an error
          warn("Warning: " + msg)
          return nil
        else
          raise e.class.new(msg, nil)
        end
      end
      path.sub!(/\/$/, '')
      doc./('.//x:response', namespaces).each do |item|
        uri = @uri.merge(item.xpath("x:href", namespaces).inner_text)
        size = item.%(".//x:getcontentlength", namespaces).inner_text rescue nil
        type = item.%(".//x:collection", namespaces) ? :directory : :file
        res = Item.new(self, uri, type, size)
        if type == :file then

          if(options[:filename])then
            search_term = options[:filename]
            filename = File.basename(uri.path)
            if(search_term.class == Regexp and search_term.match(filename))then
              yield res
            elsif(search_term.class == String and search_term == filename)then
              yield res
            end
          else
            yield res
          end

        elsif uri.path == path || uri.path == path + "/"
          # This is the top-level dir, skip it
        elsif options[:recursive] && type == :directory

          if(!options[:filename])then
            yield res
          end

          # This is a subdir, recurse
          find(uri.path, options) do |sub_res|
            yield sub_res
          end
        else
          if(!options[:filename])then
            yield res
          end
        end
      end
    end

    # Change the base URL for use in handling relative paths
    def cd(url)
      new_uri = @uri.merge(url)
      if new_uri.host != @uri.host || new_uri.port != @uri.port || new_uri.scheme != @uri.scheme
        raise Exception , "uri must have same scheme, host and port"
      end
      @uri = new_uri
    end

    # Get the content of a resource as a string
    #
    # If called with a block, yields each fragment of the
    # entity body in turn as a string as it is read from
    # the socket.  Note that in this case, the returned response
    # object will *not* contain a (meaningful) body.

    def get(path, &block)
      path = @uri.merge(path).path
      body = @handler.request_returning_body(:get, path, nil, &block)
      body
    end

    # Stores the content of a stream to a URL
    #
    # Example:
    # File.open(file, "r") do |stream|
    #   dav.put(url.path, stream, File.size(file))
    # end
    def put(path, stream, length)
      path = @uri.merge(path).path
      res = @handler.request_sending_stream(:put, path, stream, length, nil)
      res.body
    end

    # Stores the content of a string to a URL
    #
    # Example:
    #   dav.put(url.path, "hello world")
    #
    def put_string(path, str)
      path = @uri.merge(path).path

      @handler.request_sending_body(:put, path, str, nil)
    end

    # Delete request
    #
    # Example:
    #   dav.delete(uri.path)
    def delete(path)
      path = @uri.merge(path).path
      res = @handler.request(:delete, path, nil, nil)
      res.body
    end

    # Send a move request to the server.
    #
    # Example:
    #   dav.move(original_path, new_path)
    def move(path,destination)
      path = @uri.merge(path).path
      destination = @uri.merge(destination).to_s
      headers = {'Destination' => destination}
      res = @handler.request(:move, path, nil, headers)
      res.body
    end

    # Send a copy request to the server.
    #
    # Example:
    #   dav.copy(original_path, destination)
    def copy(path,destination)
      path = @uri.merge(path).path
      destination = @uri.merge(destination).to_s
      headers = {'Destination' => destination}
      res = @handler.request(:copy, path, nil, headers)
      res.body
    end

    # Do a proppatch request to the server to
    # update properties on resources or collections.
    #
    # Example:
    #   dav.proppatch(uri.path,"<d:creationdate>#{new_date}</d:creationdate>")
    def proppatch(path, xml_snippet)
      path = @uri.merge(path).path
      headers = {'Depth' => '1'}
      body =  '<?xml version="1.0"?>' +
      '<d:propertyupdate xmlns:d="DAV:">' +
      '<d:set>' +
          '<d:prop>' +
            xml_snippet +
          '</d:prop>' +
        '</d:set>' +
      '</d:propertyupdate>'
      res = @handler.request(:proppatch, path, body, headers)
      Nokogiri::XML.parse(res.body)
    end

    # Returns true if resource exists on server.
    #
    # Example:
    #   dav.exists?('https://www.example.com/collection/')  => true
    #   dav.exists?('/collection/')  => true
    def exists?(path)
      path = @uri.merge(path).path
      headers = {'Depth' => '1'}
      body = '<?xml version="1.0" encoding="utf-8"?><DAV:propfind xmlns:DAV="DAV:"><DAV:allprop/></DAV:propfind>'
      begin
        res = @handler.request(:propfind, path, body, headers)
      rescue
        return false
      end
      return (res.is_a? Net::HTTPSuccess)
    end

    # Makes a new directory (collection)
    def mkdir(path)
      path = @uri.merge(path).path
      res = @handler.request(:mkcol, path, nil, nil)
      res.body
    end

    def verify_callback=(callback)
      @handler.verify_callback = callback
    end

    def verify_server=(value)
      @handler.verify_server = value
    end

  end
end
