## ident

Microservice for managing authentication and authorization for platform users and applications.

### Authentication

Consumers of this API will present a `bearer` authentication header (i.e., using a `JWT` token) for all requests. The `sub` of the authenticated caller must be a `User` when attempting to create or access `Application` APIs.

### Authorization

The `bearer` authorization header will be scoped to an authorized platform user or application. The `bearer` authorization header may contain a `sub` (see [RFC-7519 §§ 4.1.2](https://tools.ietf.org/html/rfc7519#section-4.1.2)) to further limit its authorized scope to a specific token or smart contract, wallet or other entity.

Certain APIs will be metered similarly to how AWS meters some of its webservices. Production applications will need a sufficient PRVD token balance to consume metered APIs (based on market conditions at the time of consumption, some quantity of PRVD tokens will be burned as a result of such metered API usage. *The PRVD token model and economics are in the process of being peer-reviewed and finalized; the documentation will be updated accordingly with specifics.*

---
The following APIs are exposed:


### Applications API

##### `GET /api/v1/applications`

Enumerate platform applications visible to the authorized caller.

```
[prvd@vpc ~]# curl -v https://ident.provide.services/api/v1/applications

> GET /api/v1/applications HTTP/1.1
> Host: ident.provide.services
> User-Agent: curl/7.54.0
> Accept: */*
>
< HTTP/1.1 200 OK
< Content-Type: application/json; charset=UTF-8
< Date: Sat, 13 Jan 2018 03:50:19 GMT
< Content-Length: 529
<
[
    {
        "id": "7255bfd3-a6eb-4493-ad99-5e8df7d52afc",
        "created_at": "2018-01-12T22:29:14.195441-05:00",
        "user_id": "7cc877a6-5a9e-4db1-a782-7abfca2743a4",
        "name": "Artcoin",
        "description": null,
        "config": null
    },
    {
        "id": "10fd7364-54e4-4de4-a5a1-3c0d5e78888f",
        "created_at": "2018-01-12T22:36:14.224792-05:00",
        "user_id": "7cc877a6-5a9e-4db1-a782-7abfca2743a4",
        "name": "unicorn",
        "description": null,
        "config": null
    }
]
```


##### `POST /api/v1/applications`

Create a new application on behalf of the authorized `User`, which MUST NOT have been created on behalf of an `Application`.

```
curl -v -XPOST -H "content-type: application/json" https://ident.provide.services/api/v1/applications -d '{"name": "Unicorn"}'

> POST /api/v1/applications HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.54.0
> Accept: */*
> Content-Length: 70
> Content-Type: application/json
>
* upload completely sent off: 70 out of 70 bytes
< HTTP/1.1 201 Created
< Content-Type: application/json; charset=UTF-8
< Date: Sat, 13 Jan 2018 05:46:33 GMT
< Content-Length: 257
<
{
    "id": "aac664e5-7461-4ac0-87ec-2780d1d38098",
    "created_at": "2018-01-13T00:46:33.165639-05:00",
    "user_id": "83420c49-1b45-4144-9eb8-7e3c09aa2111",
    "name": "Unicorn",
    "description": null,
    "config": null
}

```

### Tokens API

##### `GET /api/v1/tokens`

Enumerate previously authorized `Token`s for the authorized `User` or `Application`.

```
[prvd@vpc ~]# curl -v https://ident.provide.services/api/v1/tokens

> GET /api/v1/tokens HTTP/1.1
> Host: ident.provide.services
> User-Agent: curl/7.54.0
> Accept: */*
>
< HTTP/1.1 200 OK
< Content-Type: application/json; charset=UTF-8
< Date: Sat, 13 Jan 2018 03:51:52 GMT
< Content-Length: 1143
<
[
    {
        "id": "9878b890-4efa-41fe-bcff-ac8d8f39965c",
        "created_at": "2018-01-12T22:47:09.995048-05:00",
        "issued_at": "2018-01-12T22:47:09.994119-05:00",
        "expires_at": null,
        "secret": "51df5bba-4208-4b2f-b8b7-81969a02d43a",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7fSwiZXhwIjpudWxsLCJpYXQiOjE1MTU4MTUyMjksImp0aSI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCIsInN1YiI6InVzZXI6Y2VkNWMwNjAtNmNjMy00NmNkLTg5YjEtNWVmYzZiZDNhNjY1In0.uHfHhb-tInBeKITEm-bp2D4szwZdXkxUdy3PnQHjc7Y",
        "data": null
    },
    {
        "id": "3eb63678-86f1-4064-9a4c-4de4fd7c0865",
        "created_at": "2018-01-12T22:47:29.901568-05:00",
        "issued_at": "2018-01-12T22:47:29.901292-05:00",
        "expires_at": null,
        "secret": "2a8fcfd3-65bd-4f5b-bbc0-2cad3fc00ece",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7fSwiZXhwIjpudWxsLCJpYXQiOjE1MTU4MTUyNDksImp0aSI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCIsInN1YiI6InVzZXI6Y2VkNWMwNjAtNmNjMy00NmNkLTg5YjEtNWVmYzZiZDNhNjY1In0.i_4LQj2pMLfidy2rMDPbeWpXX2qF2hZsFg5t2nV1FtA",
        "data": null
    }
]
```


##### `POST /api/v1/tokens`

Authorize a `Token` on behalf of the authorized `User` or `Application`.

```
[prvd@vpc ~]# curl -v -XPOST -H 'content-type: application/json' https://ident.provide.services/api/v1/tokens -d '{"email": "hello@example.com", "password": "h3ll0pw"}'

> POST /api/v1/tokens HTTP/1.1
> Host: ident.provide.services
> User-Agent: curl/7.54.0
> Accept: */*
> Content-Length: 50
> Content-Type: application/json
>
* upload completely sent off: 50 out of 50 bytes
< HTTP/1.1 201 Created
< Content-Type: application/json; charset=UTF-8
< Date: Sat, 13 Jan 2018 03:57:50 GMT
< Content-Length: 607
<
{
    "user": {
        "id": "83420c49-1b45-4144-9eb8-7e3c09aa2111",
        "created_at": "2018-01-12T18:51:19.99177-05:00",
        "name": "kt",
        "email": "kyle@unmarked.io"
    },
    "token": {
        "id": "c0c81296-8587-4e12-bba2-40b6e91f1590",
        "secret": "843addaf-88f9-4b02-8675-0853a7a34e74",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7fSwiZXhwIjpudWxsLCJpYXQiOjE1MTU4MTU4NzAsImp0aSI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCIsInN1YiI6InVzZXI6ODM0MjBjNDktMWI0NS00MTQ0LTllYjgtN2UzYzA5YWEyMTExIn0.ZNkGppXioiuKe8SAKtakRLnAwm80cQZuaOHj0OMlgJY"
    }
}
```


##### `DELETE /api/v1/tokens/:id`

Destroy a previously authorized `Token` on behalf of the authorized `User` or `Application`.

```
[prvd@vpc ~]# curl -v -XDELETE https://ident.provide.services/api/v1/tokens/9878b890-4efa-41fe-bcff-ac8d8f39965c

> DELETE /api/v1/tokens/9878b890-4efa-41fe-bcff-ac8d8f39965c HTTP/1.1
> Host: ident.provide.services
> User-Agent: curl/7.54.0
> Accept: */*
>
< HTTP/1.1 204 No Content
< Content-Type: application/json; charset=UTF-8
< Date: Sat, 13 Jan 2018 04:01:16 GMT
<
```
