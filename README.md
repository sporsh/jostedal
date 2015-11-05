# Jostedal

An implementation of the [STUN](http://tools.ietf.org/html/rfc5389) and [TURN](http://tools.ietf.org/html/rfc5766) protocols in Python using [Twisted](http://twistedmatrix.com).

The primary purpose of the project is to support testing of [ICE](https://en.wikipedia.org/wiki/Interactive_Connectivity_Establishment).  
Jostedal is named after the [Jostedal Glacier](https://en.wikipedia.org/wiki/Jostedal_Glacier) as a pun for ice :icecream:.

## Running a TURN server
A simple [example script](./scripts/jostedal) is provided to start a server:

```
jostedal INTERFACE [PORT [CONFIG-FILE]]
```

### Configuration
Configuration is read in from a JSON file (by default [config.json](./config.json)).

```json
{
    "software": "Jostedal",
    "realm": "pexip.com",

    "users": {
        "passuser": {
            "password": "password"
        },
        "keyuser": {
            "key": "1b5c8156a9eee41c062037663f54cbac"
        }
    }
}
```

The values of the `software` and `realm` attributes can be configured here.

Long term credentials can also be specified - using either plain text passwords or HMAC-SHA-1 keys.  
To generate HMAC-SHA-1 keys, you can use the [hmac](./scripts/hmac) script.

```
hmac USERNAME REALM [PASSWORD]
```

## Features
- [RFC 5389 STUN](http://tools.ietf.org/html/rfc5389)
- [RFC 5766 TURN](http://tools.ietf.org/html/rfc5766)

## License
[MIT](./LICENSE)
