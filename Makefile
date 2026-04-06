.PHONY: install uninstall update dev

VENV := .venv

install:
	@bash install.sh

uninstall:
	@rm -f "$(HOME)/.local/bin/meridian"
	@echo "Removed ~/.local/bin/meridian"

update:
	@$(VENV)/bin/pip install --quiet -e .
	@echo "Updated"

dev:
	@echo "Run:  source $(VENV)/bin/activate"
