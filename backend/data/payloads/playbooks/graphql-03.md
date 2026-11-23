<!-- source: GraphQL Injection/README.md | chunk 3/5 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->


You can also try to bruteforce known keywords, field and type names using wordlists such as [Escape-Technologies/graphql-wordlist](https://github.com/Escape-Technologies/graphql-wordlist) when the schema of a GraphQL API is not accessible.

### Enumerate Types Definition

Enumerate the definition of interesting types using the following GraphQL query, replacing "User" with the chosen type

```javascript
{__type (name: "User") {name fields{name type{name kind ofType{name kind}}}}}
```

### Enumerating Paths to a Target Type

When working with a GraphQL schema, especially after running an introspection query, it is not always obvious how a specific type can be accessed through queries. A given object (like `User`, `Admin`, or `Payment`) may be reachable through multiple entry points and nested relationships.

- [dee-see/graphql-path-enum](https://gitlab.com/dee-see/graphql-path-enum) - Tool that lists the different ways of reaching a given type in a GraphQL schema.

This tool takes the JSON output of an introspection query (which describes the full schema) and analyzes how types are connected. It then outputs different query paths that can be used to reach a specific target type. In practice, this means identifying all the possible ways a client could craft queries that eventually return that object, even if it is deeply nested or indirectly exposed.

```php
graphql-path-enum -i ./test_data/h1_introspection.json -t Skill
Found 27 ways to reach the "Skill" node from the "Query" node:
- Query (assignable_teams) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_check) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_check_response) -> ChecklistCheckResponse (checklist_check) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_checks) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (clusters) -> Cluster (weaknesses) -> Weakness (critical_reports) -> TeamMemberGroupConnection (edges) -> TeamMemberGroupEdge (node) -> TeamMemberGroup (team_members) -> TeamMember (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (embedded_submission_form) -> EmbeddedSubmissionForm (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (external_program) -> ExternalProgram (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (external_programs) -> ExternalProgram (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (job_listing) -> JobListing (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (job_listings) -> JobListing (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (me) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (pentest) -> Pentest (lead_pentester) -> Pentester (user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (pentests) -> Pentest (lead_pentester) -> Pentester (user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (query) -> Query (assignable_teams) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (query) -> Query (skills) -> Skill
```

## Methodology

GraphQL supports three main operation types: **queries**, **mutations**, and **subscriptions**.

### Queries

GraphQL queries are used to request specific fields from a schema, and the structure of your query directly mirrors the JSON response you will receive. At its simplest, querying data means selecting a root field (like `user`, `posts`, or `teams`) and then specifying which subfields you want returned. Unlike REST, you never get extra data, everything must be explicitly requested.

#### Basic Query

The simplest query uses the shorthand syntax, where the `query` keyword is omitted. You just define the fields you want starting from the root object.

```js
{
  user {
    id
    name
  }
}
```

This tells the server to return the `id` and `name` fields from the user object. The response will follow the exact same structure. If needed, the full syntax can be used with the query keyword, but in most cases the shorthand is enough and commonly seen in real-world traffic.

```js
query {
  user {
    id
    name
  }
}
```

![HTB Help - GraphQL injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/GraphQL%20Injection/Images/htb-help.png?raw=true)

#### Query with Arguments

To retrieve specific data, arguments can be passed to fields. These behave like function parameters and are often used for IDs, filters, or search queries.

```js
{
  user(id: "1") {
    name
    email
  }
}
```

This allows precise targeting of objects and is a common entry point for testing access control issues or IDOR-style vulnerabilities.

#### Nested Queries

GraphQL allows deep traversal of relationships in a single request. Instead of chaining multiple API calls, you can explore linked objects directly.

```js
{
  user(id: "1") {
    name
    posts {
      title
      comments {
        content
      }
    }
  }
}
```

### Mutations

A mutation is an operation used to change data on the server (create, update, or delete something).
Mutations work like function, you can use them to interact with the GraphQL endpoint.

```javascript
mutation{
  signIn(login:"Admin", password:"secretp@ssw0rd"){
      token
    }
}

mutation{
  addUser(id:"1", name:"Dan Abramov", email:"dan@dan.com") {
