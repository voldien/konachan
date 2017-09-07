# konachan #
----

The konachan program is a command line tool for query information from [konachan.net](https://konachan.net).
It uses HTTP/S for sending request a GET request to to [konachan.net](https://konachan.net). Where the konachan website returns
a HTTP/S response along with JSON data that later gets parsed by using the *json-c* library. The values is extracted by the attribute names.
To see more details of how konachan's API works, see [konachan API](https://konachan.net/help/api) .

For HTTPS, it uses TLSv1.2 for creating a secure connection and maintaining a secure connection with help of the OpenSSL library. 

# Motivation #
The intention of the project is to create a simple command line tool for query information from konachan. Where it should be easy to modify the behavior of the query and what information to query.

# Examples #
------
1. Get first search result with the tag 'cat', print out previews URL. ( preview URL is the default return value)
```
konachan -t "cat"
```

2. Get 42:th and 43:th search result in safe mode with the tag 'cat', print out* preview URL*. ( safe mode is by default enabled )
```
konachan -S -t "cat" -p 42 -l 2 -f "preview"
```

3. Get first search result with tag 'cat' with a non secure connection. ( Using only HTTP )
```
konachan -n -t "cat" -f "preview"
```

4. Get multiple attributes, print out *preview url* first, *score* second and *id* last with whitespace in between each attributes.
```
konachan -t "cat" -f "preview score id"
```

See *konachan(1)* for more details of what options are available.

# Dependencies #
---------
In order to compile the program, the following Debian packages is required.
```
apt-get install openssl-dev json-c-dev
```
## License ##
-------
This project is licensed under the GPL+3 License - see the [LICENSE](LICENSE) file for details.

