#! /bin/bash
if [ -f .coverage ]; then
  rm .coverage
fi

nosetests tests/unit \
--with-coverage \
--cover-package=cloudtracker \
--cover-html \
--cover-html-dir=htmlcov