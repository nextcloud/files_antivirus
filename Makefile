# Makefile for building the project

app_name=files_antivirus
project_dir=$(CURDIR)/../$(app_name)
build_dir=$(CURDIR)/build
doc_files=README.md
src_files=admin.php
src_dirs=appinfo controller css img js l10n lib templates
all_src=$(src_files) $(src_dirs) $(doc_files)
appstore_dir=$(build_dir)/appstore


.PHONY: all
all: dist appstore


appstore: dist
	cd $(build_dir); tar cvzf $(app_name).tar.gz $(app_name)
	rm -Rf $(appstore_dir); mkdir -p $(appstore_dir)
	mv $(build_dir)/$(app_name).tar.gz $(appstore_dir)


$(build_dir)/$(app_name):
	rm -Rf $@; mkdir -p $@
	cp -R $(all_src) $@


.PHONY: dist
dist: $(build_dir)/$(app_name)


distclean:
	rm -rf $(build_dir)


clean:
	rm -rf $(build_dir)
