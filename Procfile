# foreman start -m gateway=1,Usersapi=3,Timelinesapi=3

gateway: FLASK_APP=gateway flask run -p $PORT
Usersapi: FLASK_APP=app flask run -p $PORT
Timelinesapi: FLASK_APP=timelinesApi  flask run -p $PORT
