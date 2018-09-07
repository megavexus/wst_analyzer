# wst_analyzer

for run it:

Windows:
```
cd src
set FLASK_APP=webservice.py
# en desarrollo
set FLASK_ENV=development
flask run
```

Linux:
```
cd src
export FLASK_APP=webservice.py
# en desarrollo
export FLASK_ENV=development
flask run
```

examples:

- all analyzers
http://localhost:5000/analyzer/ip?=8.8.8.8
http://localhost:5000/analyzer/?domain=www.google.com

- only whois:
http://localhost:5000/analyzer/whois/?domain=www.google.com

- only shodan:
http://localhost:5000/analyzer/shodan/?domain=www.google.com

enjoy it!
