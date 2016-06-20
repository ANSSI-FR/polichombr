# Polichombr's API

Polichombr expose a HTTP api using the endpoint `/api/1.0/`

Example scripts are located in the folder [tests](https://github.com/ANSSI-FR/polichombr/tree/master/tests)

## `/samples/`
List all the samples

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

#### `/samples/<int:sid>/comments/`

#### `/samples/<int:sid>/names/`


## `/families/`
	List all the families
## `/family/`
        [POST] : create a new family
        [GET]  : nothing

