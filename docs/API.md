** Polichombr's API **

Polichombr expose a HTTP api using the endpoint `/api/1.0/`

Example scripts are located in the folder [examples](https://github.com/ANSSI-FR/polichombr/tree/master/examples)

We also provides utilities modules in the folder [poliapi](https://github.com/ANSSI-FR/polichombr/tree/master/poliapi)

All arguments to POST requests should be passed in JSON form.

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
Example:
getting all the renamed functions:
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
Example:
```
	curl -XGET http://127.0.0.1/api/1.0/samples/1/names/?timestamp=2016-09-19T17:28:12.504460+00:00
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
Get the defined structures.

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
	List all the families
## `/family/`
        [POST] : create a new family

        [GET]  : nothing

