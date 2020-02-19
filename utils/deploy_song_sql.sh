#!/bin/bash

sudo apt-get install postgresql-client-common pgadmin3

docker run --env POSTGRES_DB=song --env POSTGRES_USER=postgres --env POSTGRES_PASSWORD=password -v /home/ramela/git/genomic-data-playground/song-db-init:/docker-entrypoint-initdb.d -p 5432:5432 postgres:9.6&
