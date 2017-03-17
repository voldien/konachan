# konachan #
----

konachan is a terminal search tool for query information from [konachan](https://konachan.net).
It uses HTTP/S for sending request to konachan.com. Where konachan returns
a HTTP response along with JSON data that later gets parsed by using the json-c library. The values is extracted by the attribute names.
To see a more detailed explanation of konachan's API see [konachan API](https://konachan.com/help/api) 

For HTTPS, it uses TLSv1.2 for creating a secure connection and maintaining a secure connection with help of OpenSSL. 


## Examples ##
------
1. Get first search result with the tag 'cat', print out previews url. ( preview url is the default return value)
```
konachan -t "cat"
```

2. Get 42:th and 43:th search result in safe mode with the tag 'cat', print out* preview url*. ( safe mode is by default enabled )
```
konachan -S -t "cat" -p 42 -l 2 -f "preview"
```

3. Get first search result with tag 'cat' with a non secure connection. ( Using only HTTP )
```
konachan -n -t "cat" -f "preview"
```

4. Get multiple attributes, print out *preview url* first, *score* second and *id* last with Whitespace in between each attributes.
```
konachan -t "cat" -f "preview score id"
```

See konachan(1) for more details of what options are available.

## Dependencies ##
---------
In order to compile the program, the following Debian packages has to be installed.
```
apt-get install openssl-dev json-c-dev
```
