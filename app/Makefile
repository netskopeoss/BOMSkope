# Define the name of the virtual environment directory
VENV := venv

# Default target, when make executed without arguments
all: venv

# Ensure the virtual environment is activated and dependencies are installed
$(VENV)/bin/activate: requirements.txt
	python3 -m venv $(VENV)
	mkdir -p logs
	./$(VENV)/bin/pip install -r requirements.txt

# Run the init script using the virtual environment's Python
	./$(VENV)/bin/python init.py

# venv is a shortcut target
venv: $(VENV)/bin/activate

# Target to run the application
run: venv
	./$(VENV)/bin/python app.py

# Clean up the project
clean:
	rm -rf $(VENV)
	rm -f database.db
	rm -f logs/*
	find . -type f -name '*.pyc' -delete

.PHONY: all venv run clean