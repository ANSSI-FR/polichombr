# With docker

**This feature is provided as a debug option, and should not be used for production**

To use polichombr as a docker container, we provide a *DockerFile*
in the root directory.

	mkdir -p PATH_TO_YOUR_DATA
	mkdir -p PATH_TO_YOUR_DATA/storage
	docker build -t polichombr .
	docker run -p 5001:5000 -v PATH_TO_YOUR_DATA/:/opt/data/ polichombr

The docker container creates the database in the specified volume, and will store
all the data in the `storage` directory in this volume.

The service will run automatically.

Please enjoy your new polichombr instance by accessing your host at port 5001 =)
