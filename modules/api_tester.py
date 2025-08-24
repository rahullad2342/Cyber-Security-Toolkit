#This script defines a function test_api to send HTTP GET or POST 
#  requests to a given URL and return the status code and JSON response.
#Sends GET or POST requests to an API and shows the response.
import requests #Used for making HTTP requests.

#method - HTTP request to sent.
#url - the target API endpoint.
def test_api(method, url, headers = None, data = None):
 #try-except block for error handling
    try:
        if method.upper() == "GET":
            res = requests.get(url, headers = headers)
        else: 
            res = requests.post(url, headers = headers, json = data)
        #return HTTP response code(e.g., 200,404,500) and also Parsed JSON 
        return res.status_code, res.json()
    #Exception Handling If something goes wrong(e.g., invalid URL)
    except Exception as e:
        return str(e), None