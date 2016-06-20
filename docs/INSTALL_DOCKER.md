# With docker

** This feature is experimental **
To use polichombr as a docker container, we provide a *DockerFile*
in the root directory.

	docker build -t polichombr .
	docker run -p 5001:5000 -v /home/user/poli_github/app.db:/opt/data/app.db polichombr

The docker container uses the local database (`app.db`) and will run automatically.

Please enjoy your new polichombr instance by accessing your host at port 5001 =)
