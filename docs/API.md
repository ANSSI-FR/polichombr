# Polichombr API

Polichombr expose a HTTP api using the endpoint `/api/1.0/`

Example scripts are located in the folder [examples](https://github.com/ANSSI-FR/polichombr/tree/master/examples)

We also provides utilities modules in the folder [poliapi](https://github.com/ANSSI-FR/polichombr/tree/master/poliapi)

All arguments to POST requests should be passed in JSON form.


## Authentication

The API uses a token authentication mechanism.

You should request a token by posting the user's api key to ``/auth_token``,
and then forward the given token in each request using the `X-Api-Key` header.

If the token is invalid, the endpoint will return a 401 error.


## `/samples/`

* [POST] Create a new sample

  Arguments (in multipart/form-data):
	* `file` the sample file data (must be a file object, as used in `requests`)
	* `filename` the original filename
	* `tlp_level` [OPTIONAL] The sensibility level of the sample (see models/models.py for the enumeration)
* [GET] List all the samples

### `/samples/<hash>/`
Return a sample ID using the given hash
The hash can be a MD5, SHA1 or SHA256

### `/samples/<int:sid>/`
Return all informations about a given sample

#### `/samples/<int:sid>/download/`
Return the sample's binary file

#### `/samples/<int:sid>/families/`

#### `/samples/<int:sid>/abstract/`

#### `/samples/<int:sid>/matches/`


#### `/samples/<int:sid>/names/`
Example: getting all the renamed functions for the first sample
```
	curl -XGET http://127.0.0.1/api/1.0/samples/1/names/
```
Result:
```
{
	"names": [
	{
		"address": 4206256,
		"data": "TestName1",
		"timestamp": "2016-09-19T17:28:12.504460+00:00",
		"type": "idanames"
	},
	{
		"address": 4206262,
		"data": "TestName2",
		"timestamp": "2016-09-19T17:28:12.557204+00:00",
		"type": "idanames"
	}]
}
```

You can also filter by address or get all the names defined after a certain timestamp
*warning* The timestamp should be formatted with the string `%Y-%m-%dT%H:%M:%S.%f`.

Example:
```
	curl -XGET http://127.0.0.1/api/1.0/samples/1/names/?timestamp=2016-09-19T17:28:12.504460
```
Result:
```
{
	"names": [
	{
		"address": 4206262,
		"data": "TestName2",
		"timestamp": "2016-09-19T17:28:12.557204+00:00",
		"type": "idanames"
	}]
}
```

#### `/samples/<int:sid>/comments/`
Idem as the names, get the defined comments,
eventually filtered out by address or timestamp

#### `/samples/<int:sid>/structs/`
Example: get the defined structures for the first sample
```
	curl -XGET http://127.0.0.1/api/1.0/samples/1/names/
```
Result:
```
{
  "structs": [
    {
      "id": 13418,
      "members": [],
      "name": "TestStructure2",
      "size": 0,
      "timestamp": "2016-09-20T07:27:19.669853+00:00"
    },
    {
      "id": 13580,
      "members": [],
      "name": "TestStructure3",
      "size": 0,
      "timestamp": "2016-09-20T07:28:29.180566+00:00"
    }
  ]
}
```


## `/families/`
This endpoint list all the families in the database

Example:
```
	curl -X GET http://127.0.0.1:5000/api/1.0/families/
```

The data returned is in the format:
```
{
  "families": [
    {
      "TLP_sensibility": 1,
      "abstract": "# This is a markdown test abstract",
      "id": 1,
      "name": "TEST",
      "parent_id": null,
      "samples": [
        {
	  "id": 2
	}, {
	  "id": 3
	}
      ],
      "status": 3,
      "subfamilies": [
        {
	  "id": 2,
	  "name": "Test subfamily",
	  "status": 2,
	  "subfamilies": []
	}
      	]
    }, {
      "TLP_sensibility": 1,
      "abstract": "## This is a subfamily",
      "id": 3,
      "name": "Test subfamily",
      "parent_id": 1,
      "samples": [
        {
	  "id": 8
	}
       ],
      "status": 3,
      "subfamilies": []
	  "users": [{
        "id": 1,
        "nickname": "test"
      }
    ]

	  ]
    }
  ]
}
```

## `/family/`
 * [POST] : create a new family

 Arguments:
    * `name` : The new family name
    * `parent` : If it's a subfamily, the parent's name (optional)
    * `tlp_level`: The sensibility (optional)

  Returns:
    * The created family id

Example:
```
	curl -i -X POST -H "Content-Type: application/json" -d '{"name":"TEST", "tlp_level":1}' http://localhost:5000/api/1.0/family/
```
This command returns:
```
{
	"family": 1
}
```

To add a subfamily of `TEST`:
```
	curl -i -X POST -H "Content-Type: application/json" -d '{"name":"This is my subfamily", "parent":"TEST", "tlp_level":1}' http://localhost:5000/api/1.0/family/
```
Which returns another id.

 * [GET]  : nothing

## `/yaras/`
 Manage the yara rules

 * [GET]  : Get all the defined yara rules
```
	curl -XGET http://127.0.0.1/api/1.0/yaras/
```
Result:
```
{
  "yara_rules": [
    {
      "TLP_sensibility": 1,
      "creation_date": "2016-10-11T14:38:25.349681+00:00",
      "id": 1,
      "name": "test_MZ",
      "raw_rule": "rule test_MZ {\r\nstrings:\r\n $mz = {4D 5A}\r\ncondition:\r\n$mz at 0\r\n}",
      "version": 1
    },
    {
      "TLP_sensibility": 1,
      "creation_date": "2016-10-11T14:56:05.773325+00:00",
      "id": 2,
      "name": "test_2",
      "raw_rule": "rule TEST_YARA {\r\n  strings:\r\n    $test = \"TEST\" ascii nocase\r\n  condition:\r\n    1 of them\r\n}",
      "version": 2
    }
  ]
}
```

 * [POST] : create a new yara rule

 Arguments:
  * `name` : the rule name (should not be used)
  * `rule` : the yara rule text
  * `tlp_level` : the sensibility level

 Returns:
  * the created rule ID, or an error if somethings failed
Example:
```
	curl -i -X POST -H "Content-Type: application/json" -d '{"name":"TESTRULE", "rule":"rule TESTRULE{\n strings:\n $teststring=\"TEST\"\n}"}' condition:\n 1 of them\n }", "tlp_level":1}' http://localhost:5000/api/1.0/yaras/'
```
result:

```
{
	"id": 1
}
```

The script [create_yara.py](https://github.com/ANSSI-FR/polichombr/tree/master/examples/create_yara.py) can be used from the command line.

```
	python examples/create_yara.py test.yar "TEST MZ"
	Created rule TEST MZ with id 1
```

## `/machoc/`
 Get functions matching a specific machoc match
 * [GET] : Fetch functions

Arguments:
 * The machoc hash in integer form

Returns:
 * A list of matching functions

Example:
```
	curl -X GET http://localhost:5000/api/1.0/machoc/222275914
```

Result:
```

[
  {
    "address": 4208178,
    "id": 14,
    "machoc_hash": 222275914,
    "name": "sub_403632",
    "sample_id": 2
  },
  {
    "address": 4200048,
    "id": 32,
    "machoc_hash": 222275914,
    "name": "sub_401670",
    "sample_id": 2
  },
  {
    "address": 4213900,
    "id": 41,
    "machoc_hash": 222275914,
    "name": "sub_404c8c",
    "sample_id": 2
  },
  {
    "address": 4207824,
    "id": 64,
    "machoc_hash": 222275914,
    "name": "sub_4034d0",
    "sample_id": 2
  },
  {
    "address": 4211938,
    "id": 70,
    "machoc_hash": 222275914,
    "name": "sub_4044e2",
    "sample_id": 2
  },
  {
    "address": 4214017,
    "id": 84,
    "machoc_hash": 222275914,
    "name": "sub_404d01",
    "sample_id": 2
  }
]
```
