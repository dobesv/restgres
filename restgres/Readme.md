RESTgres - An HTTP worker for PostgreSQL
----------------------------------------

This implements a worker for PostgreSQL that listens for HTTP connections and allow clients to
interact with the PostgreSQL server using a RESTful API rather than the proprietary API used
by libpq, psql, and so on.

Although the eventual goal is to provide all the capabilities of psql, libpq, and so on, this is
still early days.

API
---

=== `GET /`
=== `Accept: application/json`

Return the server version number and uptime.


Building
--------

Get dependencies if you haven't already:

    sudo apt-get install libpq-dev libevent-dev postgresql-server-dev-9.3
    git clone https://github.com/SpComb/evsql
    cd evsql
    cmake . && make
    cd -

Build it:

    make
    ls -l `pwd`/*.so
    
Edit your postgresql.conf to set up the worker:

	restgres.port = 8080
	restgres.max_connections = 100
	shared_preload_libraries = '/.../restgres/restgres.so'

Restart postgres:

	sudo service postgresql restart
	
Check if it is running:

	curl -v http://localhost:8080/

