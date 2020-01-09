# wst_analyzer
Webservice about threat intelligence [shodan, alienvault otx, whois supported]

## Instalation
### Pip

for install it (it's packetized):

```
pip3 install .
```

then for run it:

```
python3 run.py
```

create tokens.conf based on tokens.conf.example

### Docker

The application have been dockerized. To run the docker, you only have to execute the docker-compose:

```bash
$ docker-compose up -d
```

#### Proxy with docker
If you are behind a proxy, you must follow the next steps (In these examples, the proxy is a cntlm behind http://10.139.122.15:3128 ):

- Put the proxy address in the build-args of the compose. Example:
```config
# docker-compose.yml
version: '2'

services:
  wst_analyzer:
    build: 
      context: .
      args:
        HTTP_PROXY: http://10.139.122.15:3128
    env_file: .env
    ports:
      - "5000:5000"
    volumes:
      - .:/code
```

- Create a '.env' file. Example:
```bash
# .env
HTTP_PROXY=http://10.139.122.15:3128
HTTPS_PROXY=http://10.139.122.15:3128
http_proxy=http://10.139.122.15:3128
https_proxy=http://10.139.122.15:3128
debug=1
```
(Nota: Si lo vas a ejec)


## Options

If you are using it without the docker, only with flask, you can change the port number of the WS with the environment option `WST_PORT`.

For example, if you want to run it in the port 3232, you can execute like:

```
pip3 install .
export WST_PORT=3232
python3 src/wst_analyzer/webservice.py
```


## Usage

- all analyzers

http://localhost:5000/analyze/?ip=8.8.8.8

http://localhost:5000/analyze/?domain=www.google.com

- only whois:

http://localhost:5000/analyze/whois/?domain=www.google.com

- only alienvault otx:

http://localhost:5000/analyze/otx/?ip=8.8.8.8

- only shodan:

http://localhost:5000/analyze/shodan/?domain=www.google.com

Enjoy it!!!

## Contributors

Javier Gutiérrez Navío & Omar Rodríguez Soto (@orsoto)
