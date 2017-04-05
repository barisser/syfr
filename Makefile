prep:
	rm -rf venv && virtualenv venv && . venv/bin/activate && pip install -e . && python setup.py install

test:
	py.test -vvv -s syfr
