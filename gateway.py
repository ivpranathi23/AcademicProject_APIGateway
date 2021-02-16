#
# Simple API gateway in Python

#Project Title: Microblogging - API Gateway
#File Name: gateway.py
#Author: Venkata Pranathi Immaneni
#Date Modified: 24th Dec 2020
#Email: ivpranathi@csu.fullerton.edu

import sys

import flask
import requests, itertools
from flask import request, make_response

app = flask.Flask(__name__)
app.config.from_envvar('APP_CONFIG')

#Retrive all the processes of Users Service
users_processes = app.config['USERSPROCESS']

#Retrive all the processes of Timelines Service
timelines_processes = app.config['TIMELINESPROCESS']

#Roundrobin method - iterating the processes in a Roundrobin fashion
usersCycleList = [users_processes[0], users_processes[1], users_processes[2]]
users_Nodes = itertools.cycle(usersCycleList)

timelinesCycleList = [timelines_processes[0], timelines_processes[1], timelines_processes[2]]
timeLines_Nodes = itertools.cycle(timelinesCycleList)

# Creating a dict of the above arrays - for removing the server (if not working) from round robin cycle
#Dictionary to update the pool on the go - once a defected server is detected, its removed from the pool
serverPool = {'users': usersCycleList, 'timeline': timelinesCycleList}


@app.errorhandler(404)
def route_page(err):
    try:
        upstream = next(users_Nodes)

        #Get the path of the request and check whether it is from users service or timelines Service
        getRquestPath = flask.request.full_path
        
        #Initialising username and password with empty string, so that they are accessible throughout the function - beyond if-else
        username = ""
        password = ""
        
        if request.authorization:
        	username = request.authorization.username
        	password = request.authorization.password
        else:
        	return make_response('Could not verify, User Credentials Required - 401 UnAuthorized', 401, {'WWW-Authenticate' : 'Basic realm="Login Required"'})
	
	#If the method is GET - username and password are retrieved as args. If the method id POST, username and password are retrived as JSON
        
	# Authentication starts here ----
	#Create a json with username and password to call authenticate user method of Users service and validate the user
        createJSON = {"username": username, "password": password}
        response = requests.post(upstream + '/v1users/authenticateUser', json=createJSON)
        
            
	#If authentication is successfull, 200 Status code is received in response, else 404 error is received.

	#If the status code is 200, request is routed to the corresponding service, else corresponding error reponse is returned.
	#If the authentication failed, and if the create user is called, then corresponding create user is called
	#If the authenticate method is called explicility then no need to pass through the authentication again. SO SKIP THIS
	
        if (((response.status_code == 200) or ("createUser" in getRquestPath)) and ("authenticateUser" not in getRquestPath)):
        
            #Getting the nodes one after the other in round robin fashion
            if "v1users" in getRquestPath:
            	upstream = next(users_Nodes)

            elif "v1timelines" in getRquestPath:
            	upstream = next(timeLines_Nodes)
            	
            response = requests.request(
            flask.request.method,
            upstream + flask.request.full_path,
            data=flask.request.get_data(),
            headers=flask.request.headers,
            cookies=flask.request.cookies,
            stream=True,
        )

    except requests.exceptions.RequestException as e:
        app.log_exception(sys.exc_info())
       
        #If any exception arises remove the server from rotation
        
        index = serverPool['users'].index(upstream)
        del serverPool['users'][index]
        update_ServerPool()
        
        return flask.json.jsonify({
            'method': e.request.method,
            'url': e.request.url,
            'exception': type(e).__name__,
        }), 503


    headers = remove_item(
        response.headers,
        'Transfer-Encoding',
        'chunked'
    )

    #If status codes are in the range of 500 and 599 -
    #it means they are server related error.
    #So deleting the corresponding server from the pool
    #statusCodeVal = int(response.json().get('StatusCode'))   ---- Wrong -- Updated based on comments
   
    statusCodeVal = response.status_code

    if  statusCodeVal >= 500 and statusCodeVal < 600:
    	index = serverPool['users'].index(upstream)
    	del serverPool['users'][index]
    	update_ServerPool()

    return flask.Response(
        response=response.content,
        status=response.status_code,
        headers=headers,
        direct_passthrough=True,
    )
    
#Update server pool after deleting the one of the servers
def update_ServerPool():
    global timeLines_Nodes, users_Nodes
    timeLines_Nodes = itertools.cycle(serverPool['timeline'])
    users_Nodes = itertools.cycle(serverPool['users'])
    #print("**remaining nodes are***")
    #print(serverPool['users']

def remove_item(d, k, v):
    if k in d:
        if d[k].casefold() == v.casefold():
            del d[k]
    return dict(d)
