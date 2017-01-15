konachan
=========

konachan is a terminal search tool for query information from [konachan](https://konachan.net)
It uses HTTP/S for sending request to konachan.net. Where konachan returns
a file with json that later gets parsed by using json-c library. The values is exctracing by attributes names.
See a more detailed explaination of konachan's API see [konachan API](https://konachan.com/help/api) 

For HTTPS, it uses TLSv1.2 for creating a secure connection and maintaining a secure connection with help of OpenSSL. 


Examples
------
1. Get first search result with the tag 'cat' previews url. ( preview url is the default return value)
```
konachan -t "cat"
```

2. Get 42:th and 43:th search result in safe mode with the tag 'cat', with return result preview url. ( safe mode is by default enabled )
```
konachan -S -t "cat" -p 42 -l 2 -f "preview"
```

3. Get first search result with tag 'cat' with a non secure connection. ( Using only HTTP )
```
konachan -n -t "cat" -f "preview"
```

4. Get multiple attributes, returns preview url first, score second and id last with spaces inbetween.
```
konachan -t "cat" -f "preview score id"
```

See konachan(1) for more details of what options are available.

Dependencies
---------
In order to compile program the follwing debian packages has to be installed.
```
apt-get install openssl-dev json-c-dev
```
