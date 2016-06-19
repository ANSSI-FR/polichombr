# With docker

** This feature is experimental **
To use polichombr as a docker container, we provide a *DockerFile*
in the root directory.

	docker build -t polichombr .
	docker run -p 5001:5000 -it polichombr bash

Once in the docker shell:
	./install.sh && ./run.py

Please enjoy yout new polichombr by accessing your host at port 5001 =)

Be aware, if you stop the container, you will lose the stored samples,
as changes are not remanent with the current volume options.
