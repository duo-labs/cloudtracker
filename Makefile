.DEFAULT_GOAL := help

SUPPORTED_VERSIONS=1 6
DEV_TARGETS = $(addprefix dev_elasticsearchv,${SUPPORTED_VERSIONS})

.PHONY: requirements_es1
requirements_es1: requirements.txt requirements-dev.txt
	# Replace the default elasticsearch versions with the ones that work with es v1.x
	# Create new files on disk that refer to the custom versions
	@sed -e 's/^elasticsearch==\(.*$$\)/elasticsearch==1.9.0/g' requirements.txt | sed -e 's/^elasticsearch_dsl==\(.*$$\)/elasticsearch_dsl==0.0.11/g' > requirements.es1.txt
	@sed -e 's/requirements\.txt/requirements.es1.txt/g' requirements-dev.txt > requirements-dev.es1.txt

.PHONY: requirements_es6
requirements_es6: requirements.txt requirements-dev.txt
	# Since es6 is the default, no need to make any changes
	# But make a copy so that the dev_elasticsearchv6 can be left generic
	@cp requirements.txt requirements.es6.txt
	@cp requirements-dev.txt requirements-dev.es6.txt

.PHONY: ${DEV_TARGETS}
${DEV_TARGETS}: dev_elasticsearchv%: requirements_es%
	@( \
		test -d ./venv || virtualenv ./venv; \
		. ./venv/bin/activate; \
		pip install --upgrade pip; \
		pip install -r requirements-dev.es$*.txt; \
	)
	@echo
	@echo "** You have configured your environment for elasticsearch v$* **"
	@echo '** Now you should `source ./venv/bin/activate` to activate your virtualenv **'
	@echo

.PHONY: clean
clean:
	# Delete the virtual environment
	@rm -rf ./venv
	# Get rid of any generated requirements.txt files
	@rm ./requirements*es*.txt

help:
	@printf "\033[36m%-20s\033[0m %s\n" "dev_elasticsearchv1" "Configures the environment for es v1"
	@printf "\033[36m%-20s\033[0m %s\n" "dev_elasticsearchv6" "Configures the environment for es v6"
	@printf "\033[36m%-20s\033[0m %s\n" "clean" "Clean build artifacts"
