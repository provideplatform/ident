# ident

Microservice for managing authentication and authorization for platform users and applications.

## Authentication

Consumers of this API will present a `bearer` authentication header (i.e., using a `JWT` token) for all requests. The `sub` of the authenticated caller must reference a `User` when attempting to create or access `Application` APIs.

## Authorization

The `bearer` authorization header will be scoped to an authorized platform user or application. The `bearer` authorization header may contain a `sub` (see [RFC-7519 §§ 4.1.2](https://tools.ietf.org/html/rfc7519#section-4.1.2)) to further limit its authorized scope to a specific token or smart contract, wallet or other entity.

---

The following APIs are exposed:

## Status API

### `GET /api/vi/status`

Check the status of the _ident_ microservice. This will return a `204 No Content` if the service is up, and a `404 Not Found` otherwise. 

```console
$ curl -i https://ident.provide.services/status
HTTP/2 204
date: Tue, 09 Oct 2018 03:06:28 GMT
access-control-allow-credentials: true
access-control-allow-headers: Accept, Accept-Encoding, Authorization, Cache-Control, Content-Length, Content-Type, Origin, User-Agent, X-CSRF-Token, X-Requested-With
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
access-control-allow-origin: *
```

## Authentication API

### `POST /api/v1/authenticate`

Authorize a `Token` on behalf of the authorized `User` or `Application`.

```console
$ curl -i -H 'content-type: application/json' \
    https://ident.provide.services/api/v1/authenticate \
    -d '{"email": "user42@domain.tld", "password": "S00perS3cr3t"}'
HTTP/2 201
date: Mon, 08 Oct 2018 23:56:08 GMT
content-type: application/json; charset=UTF-8
content-length: 559
access-control-allow-credentials: true
access-control-allow-headers: Accept, Accept-Encoding, Authorization, Cache-Control, Content-Length, Content-Type, Origin, User-Agent, X-CSRF-Token, X-Requested-With
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
access-control-allow-origin: *

{
    "user": {
        "id": "3d9d62e8-0acf-47cd-b74f-52c1f96f8397",
        "created_at": "2018-10-08T23:34:18.70074Z",
        "name": "Doc U. Mentation",
        "email": "user42@domain.tld"
    },
    "token": {
        "id": "52d9caf3-0a56-4670-886e-8136b633d52b",
        "token": "yoUr-AutH-TOKeN-FrOm-sIgnINg-in"
    }
}
```

## Applications API

### `GET /api/v1/applications`

Enumerate platform `Application`s visible to the authorized caller.

```console
$ curl -i \
    -H 'Authorization: bearer yoUr-AutH-TOKeN-FrOm-sIgnINg-in' \
    https://ident.provide.services/api/v1/applications
HTTP/2 200
date: Tue, 09 Oct 2018 01:33:34 GMT
content-type: application/json; charset=UTF-8
content-length: 856
access-control-allow-credentials: true
access-control-allow-headers: Accept, Accept-Encoding, Authorization, Cache-Control, Content-Length, Content-Type, Origin, User-Agent, X-CSRF-Token, X-Requested-With
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
access-control-allow-origin: *
x-total-results-count: 2

[
    {
        "id": "cf6ae66a-7cba-48ce-bbd5-9dcd674267be",
        "created_at": "2018-10-09T01:28:52.704799Z",
        "network_id": "024ff1ef-7369-4dee-969c-1918c6edb5d4",
        "user_id": "3d9d62e8-0acf-47cd-b74f-52c1f96f8397",
        "name": "Enterprise Advantage",
        "description": null,
        "config": {
            "network_id": "024ff1ef-7369-4dee-969c-1918c6edb5d4"
        },
        "hidden": false
    },
    {
        "id": "6fd50c17-0d3f-463f-811e-0015e0373f1a",
        "created_at": "2018-10-09T01:30:05.575747Z",
        "network_id": "024ff1ef-7369-4dee-969c-1918c6edb5d4",
        "user_id": "3d9d62e8-0acf-47cd-b74f-52c1f96f8397",
        "name": "Process Turbo",
        "description": null,
        "config": {
            "network_id": "024ff1ef-7369-4dee-969c-1918c6edb5d4"
        },
        "hidden": false
    }
]
```

### `POST /api/v1/applications`

Create a new `Application` on behalf of the authorized platform `User`.

*A platform `User` is a user that was not created on behalf of an `Application`.*

```console
$ curl -i -H 'content-type: application/json' \
    -H 'Authorization: bearer yoUr-AutH-TOKeN-FrOm-sIgnINg-in' \
    https://ident.provide.services/api/v1/applications \
    -d '{"name": "SavvyApp"}'
HTTP/2 201
date: Tue, 09 Oct 2018 02:03:19 GMT
content-type: application/json; charset=UTF-8
content-length: 309
access-control-allow-credentials: true
access-control-allow-headers: Accept, Accept-Encoding, Authorization, Cache-Control, Content-Length, Content-Type, Origin, User-Agent, X-CSRF-Token, X-Requested-With
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
access-control-allow-origin: *

{
    "id": "77cb2094-9a99-4de6-ac86-bbd2353b49c8",
    "created_at": "2018-10-09T02:03:19.617250119Z",
    "network_id": "00000000-0000-0000-0000-000000000000",
    "user_id": "3d9d62e8-0acf-47cd-b74f-52c1f96f8397",
    "name": "SavvyExec",
    "description": null,
    "config": null,
    "hidden": false
}
```

### `GET /api/vi/applications/:id`

Retrieve the details of the specified `Application`.

```console
$ curl -i \
    -H 'Authorization: bearer yoUr-AutH-TOKeN-FrOm-sIgnINg-in' \
    https://ident.provide.services/api/v1/applications/cf6ae66a-7cba-48ce-bbd5-9dcd674267be
HTTP/2 200
date: Tue, 09 Oct 2018 05:43:27 GMT
content-type: application/json; charset=UTF-8
content-length: 381
access-control-allow-credentials: true
access-control-allow-headers: Accept, Accept-Encoding, Authorization, Cache-Control, Content-Length, Content-Type, Origin, User-Agent, X-CSRF-Token, X-Requested-With
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
access-control-allow-origin: *

{
    "id": "cf6ae66a-7cba-48ce-bbd5-9dcd674267be",
    "created_at": "2018-10-09T01:28:52.704799Z",
    "network_id": "024ff1ef-7369-4dee-969c-1918c6edb5d4",
    "user_id": "3d9d62e8-0acf-47cd-b74f-52c1f96f8397",
    "name": "Enterprise Advantage",
    "description": null,
    "config": {
        "network_id": "024ff1ef-7369-4dee-969c-1918c6edb5d4"
    },
    "hidden": false
}
```

### `PUT /api/vi/applications/:id`

Update details for the given `Application`.

```console
$ curl -i -XPUT \
    -H 'content-type: application/json' \
    -H 'Authorization: bearer yoUr-AutH-TOKeN-FrOm-sIgnINg-in' \
    https://ident.provide.services/api/v1/applications/6fd50c17-0d3f-463f-811e-0015e0373f1a \
    -d '{"name": "Turbo Process"}'
HTTP/2 204
date: Tue, 09 Oct 2018 05:45:44 GMT
access-control-allow-credentials: true
access-control-allow-headers: Accept, Accept-Encoding, Authorization, Cache-Control, Content-Length, Content-Type, Origin, User-Agent, X-CSRF-Token, X-Requested-With
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
access-control-allow-origin: *
```

### `GET /api/vi/applications/:id/tokens`

Fetch the `Token`s for the given `Application`.

```console
$ curl -i \
    -H 'Authorization: bearer yoUr-AutH-TOKeN-FrOm-sIgnINg-in' \
    https://ident.provide.services/api/v1/applications/cf6ae66a-7cba-48ce-bbd5-9dcd674267be/tokens
HTTP/2 200
date: Tue, 09 Oct 2018 05:51:25 GMT
content-type: application/json; charset=UTF-8
content-length: 514
access-control-allow-credentials: true
access-control-allow-headers: Accept, Accept-Encoding, Authorization, Cache-Control, Content-Length, Content-Type, Origin, User-Agent, X-CSRF-Token, X-Requested-With
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
access-control-allow-origin: *
x-total-results-count: 1

[
    {
        "id": "ba562b25-ff4e-4f9d-a332-31550ead9f41",
        "created_at": "2018-10-09T01:28:52.726631Z",
        "issued_at": "2018-10-09T01:28:52.725677Z",
        "expires_at": null,
        "token": "an-apPliCaTIOn-aPi-tOkEn",
        "data": null
    }
]
```

### `DELETE /api/vi/applications/:id`

Remove the specified `Application`. _Not yet implemented._

```console
$ curl -i -XDELETE \
    -H 'Authorization: bearer yoUr-AutH-TOKeN-FrOm-sIgnINg-in' \
    https://ident.provide.services/api/v1/applications/77cb2094-9a99-4de6-ac86-bbd2353b49c8
HTTP/2 501
date: Tue, 09 Oct 2018 05:48:08 GMT
content-type: application/json; charset=UTF-8
content-length: 37
access-control-allow-credentials: true
access-control-allow-headers: Accept, Accept-Encoding, Authorization, Cache-Control, Content-Length, Content-Type, Origin, User-Agent, X-CSRF-Token, X-Requested-With
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
access-control-allow-origin: *

{
    "message": "not implemented"
}
```

## Tokens API

### `GET /api/v1/tokens`

Enumerate previously authorized `Token`s for the authorized `User` or `Application`.

```console
$ curl -i \
    -H 'Authorization: bearer yoUr-AutH-TOKeN-FrOm-sIgnINg-in' \
    https://ident.provide.services/api/v1/tokens

HTTP/2 200
date: Tue, 09 Oct 2018 01:47:35 GMT
content-type: application/json; charset=UTF-8
access-control-allow-credentials: true
access-control-allow-headers: Accept, Accept-Encoding, Authorization, Cache-Control, Content-Length, Content-Type, Origin, User-Agent, X-CSRF-Token, X-Requested-With
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
access-control-allow-origin: *
x-total-results-count: 17

[
    {
        "id": "234da41d-0970-4561-bdf9-797ef6807fb5",
        "created_at": "2018-10-08T23:34:18.843828Z",
        "issued_at": "2018-10-08T23:34:18.842733Z",
        "expires_at": null,
        "token": "a-New-toKeN-VaLuE",
        "data": null
    },
   ...
    {
        "id": "84557020-0180-4e87-ae01-ffa05a587df4",
        "created_at": "2018-10-08T23:58:28.631901Z",
        "issued_at": "2018-10-08T23:58:28.630644Z",
        "expires_at": null,
        "token": "anOthEr-New-toKeN-VaLuE",
        "data": null
    }
]
```

### `POST /api/v1/tokens`

Authorize a `Token` on behalf of the authorized `User` or `Application`.

```console
$ curl -i -XPOST \
    -H 'content-type: application/json' \
    -H 'Authorization: bearer an-apPliCaTIOn-aPi-tOkEn' \
    https://ident.provide.services/api/v1/tokens \
    -d '{"name": "PurposeToken"}'
HTTP/2 201
date: Tue, 09 Oct 2018 02:47:26 GMT
content-type: application/json; charset=UTF-8
content-length: 484
access-control-allow-credentials: true
access-control-allow-headers: Accept, Accept-Encoding, Authorization, Cache-Control, Content-Length, Content-Type, Origin, User-Agent, X-CSRF-Token, X-Requested-With
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
access-control-allow-origin: *

{
    "id": "ed3d83ec-8b4f-4538-a240-bf759a2545ff",
    "created_at": "2018-10-09T02:47:25.981937848Z",
    "issued_at": "2018-10-09T02:47:25.980910555Z",
    "expires_at": null,
    "token": "a-New-toKeN-VaLuE",
    "data": null
}
```

### `DELETE /api/v1/tokens/:id`

Destroy a previously authorized `Token` on behalf of the authorized `User` or `Application`.

```console
$ curl -i -XDELETE \
    -H 'Authorization: bearer yoUr-AutH-TOKeN-FrOm-sIgnINg-in' \
    https://ident.provide.services/api/v1/tokens/84557020-0180-4e87-ae01-ffa05a587df4
HTTP/2 204
date: Tue, 09 Oct 2018 01:51:14 GMT
access-control-allow-credentials: true
access-control-allow-headers: Accept, Accept-Encoding, Authorization, Cache-Control, Content-Length, Content-Type, Origin, User-Agent, X-CSRF-Token, X-Requested-With
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
access-control-allow-origin: *
```

## Users API

### `GET /api/v1/users`

Enumerate previously created `User`s for the authorized `Application`. This method will return `401 Unauthorized` if the `bearer` authorization header does not resolve to an `Application`.

```console
$ curl -i \
    -H 'Authorization: bearer an-apPliCaTIOn-aPi-tOkEn' \
    https://ident.provide.services/api/v1/users
HTTP/2 200
date: Tue, 09 Oct 2018 02:29:47 GMT
content-type: application/json; charset=UTF-8
content-length: 547
access-control-allow-credentials: true
access-control-allow-headers: Accept, Accept-Encoding, Authorization, Cache-Control, Content-Length, Content-Type, Origin, User-Agent, X-CSRF-Token, X-Requested-With
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
access-control-allow-origin: *
x-total-results-count: 2

[
    {
        "id": "7fc90f5a-45e3-42ed-84b9-c13aed6481f1",
        "created_at": "2018-10-09T02:29:30.580961Z",
        "name": "EntArchitect",
        "email": "big-arch@example.com",
        "password": "$2a$10$TzD5muUNH0BFrfwwzsuthOlipQ45e5q3ba8l8wIB9ESPD4d5z/e5G"
    },
    {
        "id": "876e4fc6-b379-432c-8f76-7e42a955d527",
        "created_at": "2018-10-09T02:21:14.531578Z",
        "name": "SavvyExec",
        "email": "vip@example.com",
        "password": "$2a$10$5ebxXX.iWe7OMOHr5CGeye6.G/uj3sb4gRzXxyCEYI2B6KCFYRrz."
    }
]
```

### `POST /api/v1/users`

Create a new platform `User` or a `User` on behalf of an authorized `Application`.

```console
$ curl -i -H 'content-type: application/json' \
    -H 'Authorization: bearer an-apPliCaTIOn-aPi-tOkEn' \
    https://ident.provide.services/api/v1/users \
    -d '{"name": "SavvyExec", "email": "vip@example.com", password": "Str0ngPa55w0rd"}'
HTTP/2 201
date: Tue, 09 Oct 2018 02:21:14 GMT
content-type: application/json; charset=UTF-8
content-length: 162
access-control-allow-credentials: true
access-control-allow-headers: Accept, Accept-Encoding, Authorization, Cache-Control, Content-Length, Content-Type, Origin, User-Agent, X-CSRF-Token, X-Requested-With
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
access-control-allow-origin: *

{
    "id": "876e4fc6-b379-432c-8f76-7e42a955d527",
    "created_at": "2018-10-09T02:21:14.531577683Z",
    "name": "SavvyExec",
    "email": "vip@example.com"
}
```

### `PUT /api/vi/users/:id`

Update an existing `User` record. 

```console
$ curl -i -XPUT \
    -H 'content-type: application/json' \
    -H 'Authorization: bearer an-apPliCaTIOn-aPi-tOkEn' \
    https://ident.provide.services/api/v1/users/876e4fc6-b379-432c-8f76-7e42a955d527 \
    -d '{"name": "Professional Executive"}'
HTTP/2 204
date: Tue, 09 Oct 2018 03:21:53 GMT
access-control-allow-credentials: true
access-control-allow-headers: Accept, Accept-Encoding, Authorization, Cache-Control, Content-Length, Content-Type, Origin, User-Agent, X-CSRF-Token, X-Requested-With
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
access-control-allow-origin: *
```

### `DELETE /api/vi/users/:id`

Remove a `User` record. _Not yet implemented._

```console
$ curl -i -XDELETE \
    -H 'Authorization: bearer an-apPliCaTIOn-aPi-tOkEn' \
    https://ident.provide.services/api/v1/users/876e4fc6-b379-432c-8f76-7e42a955d527 
HTTP/2 501
date: Tue, 09 Oct 2018 03:25:37 GMT
content-type: application/json; charset=UTF-8
content-length: 37
access-control-allow-credentials: true
access-control-allow-headers: Accept, Accept-Encoding, Authorization, Cache-Control, Content-Length, Content-Type, Origin, User-Agent, X-CSRF-Token, X-Requested-With
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
access-control-allow-origin: *

{
    "message": "not implemented"
}
```
