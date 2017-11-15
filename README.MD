Logparse
--------

It's use regex pattern from `PHP IDS` to detect attack


# Prepare

- Install `docker`, `docker-compose`
- Copy log file into `resources`


# Development with docker

```sh
$ docker-compose up -d
```

# Initdb

```sh
$ docker-compose exec app flask initdb
```


# Parse log

Waiting to app ready and run

```
$ docker-compose exec app python parse.py resources/filename.log
```
