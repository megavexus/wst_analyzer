from wst_analyzer.webservice import ws
import os

debug = os.environ.get('debug', False) == "1"
if debug:
    ws.debug = True
    
ws.run(host='0.0.0.0')