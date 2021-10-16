![Frankenticket Logo](https://raw.githubusercontent.com/johndoe31415/frankenticket/master/htdocs/frankenticket.svg)

# frankenticket
This demonstration is intended to illustrate the crucial difference between
encryption and authentication. It creates a webservice in which a critical
vulnerability exists and comes with a handy webinterface so that students can
easily play around with the ciphertexts.

## Demo
You can view [a running implementation of this here](https://johndoe31415.github.io/frankenticket/) with .

## Setup for local CGI execution
1. Put the cgi-bin script in a CGI-executable directory.
2. Put the htdocs in a web directory.
3. Edit the key in `frankenticket.py` to a random value (the `config["key"]`
   value).
4. Have the endpoint in `index.html` point to your cgi script.

## Dependencies in local installation
Python3 and python3-cryptography are needed to execute the CGI script.

## Testing local CGI execution
First you can test your CGI script locally:

```
$ echo '{ "action": "login" }' | REQUEST_METHOD=POST ./frankenticket.py
Status: 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: POST
Access-Control-Allow-Headers: Content-Type
Content-Type: application/json

{"status": "ok", "ticket":
"043da13ce1301ae560970d5bbd13f7ae0aefdfb9237b605ad4779712996e0923f024de294b002c
2941a73e5a0f06744f4d2c9c4f25530ed5a4ac07d71fbef91795ef4c45c81df2ca30d68953ce8c6
6c6e02639d500a66e4290936ee74a21713a826ca41c221240448ed252742e1c1084",
"decrypted_ticket": "{\"info\": null, \"privs\": [\"read\"], \"timestamp\":
\"2021-10-16T08:58:11.098453Z\", \"username\": \"John Doe\"}           "}
```

Then you can test the implementation using cURL via the web service:

```
$ curl -d '{ "action": "login" }' https://my-server.com/cgi-bin/frankenticket.py
{"status": "ok", "ticket":
"327cf1120c40a123b23c302d8d2ac2e3741e8895c1d81002e2728ba2c576ada96fa17dd624c3b8
94cc5f1edff9dfc9fb63aab4cc297a5dc489d168e6635e420e44049ed0a4afe529da5aebdf9cee2
abb3fbedb04a9063ce35d3bbf32ac8d5b220ea5eae92f9452db4b2f936541c5fd21",
"decrypted_ticket": "{\"info\": null, \"privs\": [\"read\"], \"timestamp\":
\"2021-10-16T08:50:13.988858Z\", \"username\": \"John Doe\"}           "}
```

## Deployment on Amazon Lambda
Frankenticket can also runs on AWS Lambda. You can simply use the two files in
the `lambda/` subdirectory, deploy them onto Lambda and create a Web Gateway
HTTP API. Note that in this case the encryption used is not AES, but a custom
(broken) cipher because it limits the dependencies.

## License
My code is licensed under the GNU GPL-3. The Latin Modern Mono font is subject
to the terms of the [GUST font license](http://www.gust.org.pl/projects/e-foundry/latin-modern).
