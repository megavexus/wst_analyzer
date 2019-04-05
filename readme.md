# wst_analyzer

Webservice about threat intelligence [shodan, alienvault otx, whois supported]

for install it (it's packetized):

```
pip install .
```

then for run it:

```
python run.py
```

create tokens.conf based on tokens.conf.example

Examples:

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

# Contributors

Javier Gutiérrez Navío & Omar Rodríguez Soto (@orsoto)
