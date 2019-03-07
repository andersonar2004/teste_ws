#coding: utf-8
class ApostasOnline

  require 'net/http'
  require 'uri'
  require 'nokogiri'
  require 'open-uri'


  HOST = "https://www.apostasonline.com"
  DEBUG = true

  #"{\"loggedin\":true,\"username\":\"xxxxx\",\"balance\":\"200,72\",\"balance_not_formatted\":200.72,\"account_number\":\"123456\",\"currency\":\"BRL\",\"minimal_stake\":1.89,\"account_id\":123456}"
  @user_info = ''

  def main
    #checa autenticação
    unless check_logged()
      response = do_login(ENV['APOSTAS_USERNAME'], ENV['APOSTAS_PASSWORD'])
      check_logged()
    end
    #make_aposta(175807725, 4700296322, 1.92)
  end

  def check_logged()
    # recupera informações do usuário
    get_user_info()
    username = get_username()
    if username == ''
      p "Não está logado"
      false
    else
      p "LOGADO COMO #{username} SALDO #{get_balance()}"
      true
    end
  end

  def get_user_info()
    response = request_get('pt-BR/account/get_user_info.json', true)
    @user_info = JSON.parse(response.body)
    response
  end

  ######### MAIN METHODS
  #jQuery("span.user_name").text()
  def get_username() 
    res = ''
    if @user_info['loggedin'] == true
      res = @user_info['username']
    end
  end


  #jQuery("span#user_current_balance").text()
  def get_balance()
    res = ''
    if @user_info['loggedin'] == true
      res = @user_info['balance']
    end
  end

  def do_login(username, password)
    data_login = {"authenticity_token" => get_authenticity_token,
      "commit" => "Entrar",
      "user[password]" => password,
      "user[username]" => username,
      "utf8" => "✓" 
    }
    # request_post(path, authenticated=false, post_data=nil, request_headers={}})
    request_headers = {'Upgrade-Insecure-Requests' =>'1', 
                       'Content-Type' => 'application/x-www-form-urlencoded'}
    request_post('pt-BR/account/do_login', false, data_login, request_headers )
  end

  def make_aposta(outcome_id, price_id, stake)
    # Prepara as variáveis de header
    request_headers = get_osg_token
    request_headers['Content-Type'] = 'application/json;charset=UTF-8'
    #POST_DATA
    post_data = {"outcomes":[{"id":outcome_id,"priceId":price_id}],"singles":[{"outcomeId":outcome_id,"stake":stake,"isEachWay":false}]}
    #RESPONSE
    #{"id":132082486,"outcomes":[{"outcomeId":175790036,"eventDescription":"EC Agua Santa - Rio Claro EC","marketDescription":"Aposta sem empate","outcomeDescription":"EC Agua Santa","periodDescription":"Ao -Vivo 90 Min","price":1.15,"eachWayPrice":1.15}],"singles":[{"outcomeIds":[175790036],"isEachWay":false,"price":1.15,"eachWayPrice":1.15,"stake":10,"transaction":{"id":211832321,"createdDate":"2019-03-04T19:07:05.083+0000","status":"PROCESSED"},"errors":[]}],"multiple":null,"systems":[]}

    res = request_post('api/starbuck/betslip/', true, post_data, request_headers )
    p "RESULTADO DAS APOSTAS "
    p res.body
  end
  
  ########## UTIL METHODS

  # Carrega o cookie, 
  # master = true or false
  # quando true carrega o cookie do master
  def load_cookie(master=false)
    filename = "cookie#{(master==true) ? 'master' :''}.txt"
    if File.exists?(filename)
      saved_cookie = File.read(filename)
    else
      saved_cookie = ""
    end
    saved_cookie
  end

  def cookie_to_hash(cookie)
    hash = {}
    cookie.split('; ').map{|s| hash[s.split('=')[0]] = s.split('=')[1] }
    hash
  end

  # Salva o cookie retornado, atualiza os valores caso já tenha
  def save_cookie(cookie, master=false)
    filename = "cookie#{(master==true) ? 'master' :''}.txt"
    if load_cookie(master) != ''
      current_cookie = cookie_to_hash load_cookie(master)
      new_cookie = cookie_to_hash cookie
      new_cookie.map do |k,v| 
        current_cookie[k] = v 
        # p "atualizou current_cookie[#{k}] = #{v} " if DEBUG
      end
      cookie = current_cookie.collect{|k,v| "#{k}=#{v}"}.join('; ')
    end
    File.write(filename, cookie)
  end

  # Retorna o token de autenticidade que deve ser enviado no formulário
  def get_authenticity_token
    doc = Nokogiri::HTML( request_get('').body )
    # pega o primeiro que é de login o segundo é do form de mudança de timezone
    doc.css('input[name=authenticity_token]')[0].get_attribute('value')
  end

  def get_jwt_token(include_origin_id=false)
    response = request_get('', true)
    res1 = response.body.match /("jwt":")+([^"])+(")+/
    if include_origin_id
      res2 = response.body.match /(originId: )+(\d)+/
      [ res1[0].split(':')[1].gsub('"', ''),  res2[0].split(' ')[1] ]
    else
      res1[0].split(':')[1].gsub('"', '')
    end
  end

  # Retornar os tokens de autenticação para execução de apostas
  def get_osg_token()
    arr_jwt = get_jwt_token(true)
    {'x-osg-auth-token' => arr_jwt[0],
      'x-osg-language'  => 'pt-BR',
      'x-osg-origin-id' => arr_jwt[1] 
    }
  end
  

  # EXECUTA UMA REQUESIÇÃO HTTP
  # params
  # type = tipo de requisição POST , GET
  # authenticated = necessário autenticação true or false
  # post_data = hash do form de post {"commit" => "Entrar", ...}
  # request_headers = hash de alteração de cabeçalhos {"Cookie" => "cookie a ser alterado aqui"....}
  def request(type, url, authenticated=false, post_data={}, request_headers={}, limit=10 )
    # You should choose better exception.
    raise ArgumentError, 'HTTP redirect too deep' if limit == 0

    uri = URI.parse(url)
    if type =='POST'
        request = Net::HTTP::Post.new(uri)
    else
        request = Net::HTTP::Get.new(uri)
    end
    p "#{type} #{url}" if DEBUG
    
    # HEADERS PADRÃO
    request["Authority"] = HOST.gsub('https://','').gsub('http://','')
    request["Cache-Control"] = "max-age=0"
    request["Origin"] = HOST
    request["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
    request["Referer"] = "#{HOST}/"
    request["Accept-Language"] = "en-US,en;q=0.9,es;q=0.8,pt;q=0.7"
    request["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.109 Safari/537.36"
    #request["Upgrade-Insecure-Requests"] = "1"
    # Carrega o cookie armazenado no arquivo se for uma situação autenticável
    if authenticated
      request["Cookie"] = load_cookie
    end
    # HEADERS
    request_headers.each do |k,v|
        request[k] = v
    end
    
    # opções de POST
    if type=='POST'
        if request_headers.values.include?('application/json;charset=UTF-8')
          request.body = JSON.dump(post_data)
        else
          request.set_form_data(post_data) 
        end
        #p post_data.inspect if DEBUG
    end

    req_options = {
        use_ssl: uri.scheme == "https",
    }

    response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
    end
    
    cookie = response.response['set-cookie']
    unless (cookie.nil?)
      # p "Salvando COOKIE: #{response.response['set-cookie']}" if DEBUG
      # trata o padrão de setagem de cookie
      tmp = cookie.split(', ').collect{|s| s.split(';')[0]}.select{|s| s.include?('=')}.join('; ')
      save_cookie(tmp) 
    end
    
    # response.code
    # response.body
    p response.code if DEBUG
    File.write("#{Time.now.strftime('%s')}#{type}#{url[0..5]}.html", response.body) if DEBUG
    raise "Página não encontrada. #{url} " if response.code =='404'
    case response
    when Net::HTTPSuccess     then response
    when Net::HTTPRedirection then 
      p "REDIRECT TO: #{response['location']}"
      request('GET', response['location'], true, nil, {}, limit-1 )
    else
      response.error!
    end
  end

  # GET request padrão
  def request_get(path, authenticated=false, request_headers={} )
    #request(type, url, authenticated=false, post_data={}, request_headers={}})
    request('GET', "#{HOST}/#{path}", authenticated, {}, request_headers)
  end

  # POST request padrão
  def request_post(path, authenticated=false, post_data=nil, request_headers={} )
    request('POST', "#{HOST}/#{path}", authenticated, post_data, request_headers)
  end

  def generate_key
    Base64.strict_encode64(SecureRandom.random_bytes(16))
  end

end

class Event
  require 'json'

  

  def initialize(data_record)
    data = data_record.split("\u0002")
    flag = data[0].gsub("\u0014",'')
    tmp = flag.split("\u0001")[0]

    @id = flag.split("\u0001")[1]
    @url = tmp.split("!")[0]
    @code = tmp.split("!")[1]

    @titulo = JSON.parse(data[1])["pt_BR"]
    @placar = data[2]
    @tipo = data[5]
    @etapa = JSON.parse(data[6])["pt_BR"]
    @campeonato = JSON.parse(data[7])["pt_BR"]

    @mandante = JSON.parse(data[8])["pt_BR"]
    @visitante = JSON.parse(data[9])["pt_BR"]
    
    @hora = data[10]

    @timestamp = data[12]
  end

  def to_s
    "code #{@code} url #{@url} titulo #{@titulo}"
  end
end

require 'faye/websocket'
require 'eventmachine'

require 'permessage_deflate'
require 'active_support'

    EM.run {
      # query de observacao de aposta retorno
      #record separtor \x14
      
      username = '1838743'
      aol = ApostasOnline.new
      password = aol.get_jwt_token(false)

      cache = ActiveSupport::Cache::MemoryStore.new()
      
      ws_url = "wss://ws2.dsvcs.biz/diffusion?v=4&ty=WB&username=#{username}&password=#{password}"
      p "WS CONNECT TO #{ws_url}"
      key = aol.generate_key
      p "KEY #{key}"
      ws = Faye::WebSocket::Client.new( ws_url,[],
        { 
          :headers => { 'Origin'                   => 'https://www.apostasonline.com',
                        'Upgrade'                  => 'websocket',
                        'Connection'               => 'Upgrade',
                        'Sec-WebSocket-Key'        => key,
                        'Sec-WebSocket-Version'    => '13',
                        'Sec-WebSocket-Extensions' => 'permessage-deflate; client_max_window_bits'},
          :extensions => [PermessageDeflate]
        }
      )

      ws.on :open do |event|
        p [:open]
        initial_subs = [
          #'6OOffsideGaming/(Rank)*Sports/\d+',
          #'OffsideGaming/Sports/\d+/\d+',
          'OffsideGaming/(Rank)*Sports/240/\d+',
          #'OffsideGaming/Sports/\d+/\d+/Clock',
          'OffsideGaming/Quotes/1838743/pt-BR/'
        ]
        initial_subs.each do |url|
          p "ws.send \x16#{url}"
          ws.send("\x16#{url}")
        end
        # ws.send("\x16OffsideGaming/(Rank)*Sports/\\d+")
        # ws.send("\x16OffsideGaming/Sports/\\d+/\\d+")
        # ws.send("\x16OffsideGaming/(Rank)*Sports/364/\\d+")
        # ws.send("\x16OffsideGaming/(Rank)*Sports/1000/\\d+")
        # ws.send("\x16OffsideGaming/Sports/\\d+/\\d+/Clock")
        # ws.send("\x16OffsideGaming/Quotes/1838743/pt-BR/")
      end
        
    
      ws.on :message do |event|
        
        # tabela de separadores
        #apostas \u0014
        #clock   \u0019
        #cashout \u0015
        
        case event.data[0]
        when '4'
        # trata a primeira mensagem
          data = event.data.split("\x02")
          @reconnect_token = data[2]
          p "save reconnect token #{@reconnect_token}"
        when "\u0014"
          #apostas \u0014
          #p ['Tem aposta', event.data]
          data = event.data.split("\u0002")
          flag = data[0]
          { sport: /OffsideGaming\/(Rank)*Sports\/\d+$/,
            event: /OffsideGaming\/(Rank)*Sports\/\d+\/\d+$/,
            market: /OffsideGaming\/(Rank)*Sports\/\d+\/\d+\/Markets\/[a-zA-Z0-9]+/,
            outcome: /OffsideGaming\/(Rank)*Sports\/\d+\/\d+\/Markets\/[a-zA-Z0-9]+\/Selections\/\d\/\d+/,
            message: /OffsideGaming\/(Rank)*Sports\/\d+\/\d+\/Messages\/[a-zA-Z_]{5}\/\d+/,
            clock: /OffsideGaming\/(Rank)*Sports\/\d+\/\d+\/Clock/,
            scoreboard: /OffsideGaming\/(Rank)*Sports\/\d+\/\d+\/Scoreboard/,
            markets: /OffsideGaming\/(Rank)*Sports\/\d+\/\d+\/Markets\/[a-zA-Z0-9]+\//,
            bet: /OffsideGaming\/Outcomes\/\d+/,
            quote: /OffsideGaming\/Quotes\/.*/
          }.each do |k,v|
            tipo = flag.gsub("\u0014",'').split("!")[0]
            if tipo.match(v)
              p [k, tipo ]
              if k == :event
                e =  Event.new(event.data)
                p e.to_s
              end
            end
          end

        when "\u0015"
          p ['Cashout', event.data]
        when "\u0019"
          ws.send(data)
        else
          p [:message, event.data]
        end
        # expressões regulares de mensagens
        
      end

      ws.on(:error) do |event| 
        p [:error, event.inspect]
      end
    
      ws.on :close do |event|
        p [:close, event.code, event.reason]
        ws = nil
      end
    }
