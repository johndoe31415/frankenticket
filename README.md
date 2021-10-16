# frankenticket
This demonstration is intended to illustrate the crucial difference between
encryption and authentication. It creates a webservice in which a critical
vulnerability exists and comes with a handy webinterface so that students can
easily play around with the ciphertexts.

## Setup
1. Put the cgi-bin script in a CGI-executable directory.
2. Put the htdocs in a web directory.
3. Edit the key in `frankenticket.py` to a random value (the config["key"] value).
4. Have the endpoint in `index.html` point to your cgi script.

## Dependencies
Python3 and python3-cryptography is needed to execute the CGI script.

## Testing
You can test the implementation using cURL:

```
$ curl -d '{ "action": "login" }' https://my-server.com/cgi-bin/frankenticket.py
{"status": "ok", "ticket":
"327cf1120c40a123b23c302d8d2ac2e3741e8895c1d81002e2728ba2c576ada96fa17dd624c3b8
94cc5f1edff9dfc9fb63aab4cc297a5dc489d168e6635e420e44049ed0a4afe529da5aebdf9cee2
abb3fbedb04a9063ce35d3bbf32ac8d5b220ea5eae92f9452db4b2f936541c5fd21",
"decrypted_ticket": "{\"info\": null, \"privs\": [\"read\"], \"timestamp\":
\"2021-10-16T08:50:13.988858Z\", \"username\": \"John Doe\"}           "}
```

## License
My code is licensed under the GNU GPL-3. The Latin Modern Mono font is subject
to the terms of the [GUST font license](http://www.gust.org.pl/projects/e-foundry/latin-modern).
