
# Information Disclosure
## Identifying GraphQL Engine

We can identify the GraphQL engine used by the web application using the tool [graphw00f](https://github.com/dolevf/graphw00f) 
Graphw00f will send various GraphQL queries, including malformed queries, and can determine the GraphQL engine by observing the backend's behavior and error messages in response to these queries.

```bash
$ python3 main.py -d -f -t http://172.17.0.2

                +-------------------+
                |     graphw00f     |
                +-------------------+
                  ***            ***
                **                  **
              **                      **
    +--------------+              +--------------+
    |    Node X    |              |    Node Y    |
    +--------------+              +--------------+
                  ***            ***
                     **        **
                       **    **
                    +------------+
                    |   Node Z   |
                    +------------+

                graphw00f - v1.1.17
          The fingerprinting tool for GraphQL
           Dolev Farhi <dolev@lethalbit.com>
  
[*] Checking http://172.17.0.2/
[*] Checking http://172.17.0.2/graphql
[!] Found GraphQL at http://172.17.0.2/graphql
[*] Attempting to fingerprint...
[*] Discovered GraphQL Engine: (Graphene)
[!] Attack Surface Matrix: https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/graphene.md
[!] Technologies: Python
[!] Homepage: https://graphene-python.org
[*] Completed.
```

## Introspection

[Introspection](https://graphql.org/learn/introspection/) is a GraphQL feature that enables users to query the GraphQL API about the structure of the backend system. As such, users can use introspection queries to obtain all queries supported by the API schema. These introspection queries query the `__schema` field.

```json
{
  __schema {
    types {
      name
    }
  }
}
```

![[Pasted image 20260105134238.png]]

Now that we know a type, we can follow up and obtain the name of all of the type's fields with the following introspection query:

```json
{
  __type(name: "UserObject") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

![[Pasted image 20260105134733.png]]


Furthermore, we can obtain all the queries supported by the backend using this query:

```json
{
  __schema {
    queryType {
      fields {
        name
        description
      }
    }
  }
}
```

![[Pasted image 20260105134837.png]]

